//! v2.0 Invariant Shield Phase 2 #3 Tier 2 integration tests (ADR-003).
//!
//! Drives the full pool-verifier TCP listener via a subprocess plus
//! an in-process axum bitcoind JSON-RPC mock. The subprocess is the
//! real release binary picked up via `CARGO_BIN_EXE_pool-verifier`;
//! the mock answers `getrawmempool` against a controlled set of
//! txids. This complements the unit-level eval tests in
//! `phase2_eval.rs` by exercising every wire-format and config-load
//! surface that production deployments hit.
//!
//! Tests are `#[ignore]` so the default `cargo test --workspace`
//! stays fast for the pre-commit checklist. Run explicitly with
//! `cargo test -p pool-verifier --test phase2_tcp -- --ignored`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict, VerdictReason};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const REGTEST_SEGWIT_BLOCK_HEX: &str = include_str!("fixtures/regtest_segwit_block.hex");

/// RAII guard for the integration test scratch directory. Composes
/// the path with pid plus nanos for collision safety, pre-cleans
/// before create, and tears down on `Drop` so a panicking test never
/// leaks the tree (R-160 pattern). Avoids pulling `tempfile` for
/// dependency-light tests.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> std::io::Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("rg-{label}-{pid}-{nanos}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `Drop` guard that kills the spawned pool-verifier subprocess so
/// a panicking test never leaks a process holding the listener port.
struct VerifierProcess {
    child: Child,
    _scratch: ScratchDir,
}

impl Drop for VerifierProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shared state for the bitcoind JSON-RPC mock.
#[derive(Clone)]
struct MockState {
    /// Reversed-hex (display-order) txids returned in `getrawmempool`
    /// responses. The verifier's `bitcoind_rpc` reverses these back
    /// to internal byte order before installing into the view, so
    /// callers must pre-reverse from `compute_txid().to_byte_array()`
    /// when seeding this list.
    display_hex_txids: Arc<std::sync::RwLock<Vec<String>>>,
    request_count: Arc<AtomicU64>,
    fail_next: Arc<AtomicBool>,
}

#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    #[allow(dead_code)]
    params: Value,
    #[serde(default)]
    id: Value,
}

async fn rpc_handler(
    State(state): State<MockState>,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);

    if state.fail_next.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "result": null,
                "error": {"code": -32603, "message": "mock-induced failure"},
                "id": req.id,
            })),
        );
    }

    if req.method != "getrawmempool" {
        return (
            StatusCode::OK,
            Json(json!({
                "result": null,
                "error": {"code": -32601, "message": "method not supported"},
                "id": req.id,
            })),
        );
    }

    let txids = state.display_hex_txids.read().expect("mock lock");
    (
        StatusCode::OK,
        Json(json!({
            "result": *txids,
            "error": null,
            "id": req.id,
        })),
    )
}

/// Pre-bind to discover a free port, then immediately drop the
/// listener so the subprocess can bind it. Race window is small
/// enough to be reliable in CI; a bind-failed subprocess surfaces as
/// an explicit test failure rather than a silent skip.
async fn discover_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

async fn spawn_mock(state: MockState) -> SocketAddr {
    let app = Router::new()
        .route("/", post(rpc_handler))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

fn write_policy_toml(scratch: &Path, mock_addr: SocketAddr) -> PathBuf {
    let policy_path = scratch.join("policy.toml");
    let toml = format!(
        r#"[policy]
protocol_version = 2
required_prevhash_len = 64
min_total_fees = 0
max_tx_count = 4294967295
low_mempool_tx = 0
high_mempool_tx = 0
min_avg_fee_lo = 0
min_avg_fee_mid = 0
min_avg_fee_hi = 0
reject_empty_templates = false
reject_coinbase_zero = false
unknown_mempool_as_high = true

[policy.safety]
max_weight_ratio = 0.999
enforce_weight_ratio = false
enforce_template_age = false
warn_sigops_ratio = 0.95
warn_coinbase_sigops_max = 400

[policy.mempool]
enforce = true
tolerance_pct = 4.0
poll_interval_secs = 1
max_stale_secs = 60
per_tx_detail = false
rpc_url = "http://{mock_addr}/"
rpc_user = "rg-test"
rpc_pass = "rg-test"
"#
    );
    let mut f = std::fs::File::create(&policy_path).expect("create policy.toml");
    f.write_all(toml.as_bytes()).expect("write policy.toml");
    policy_path
}

fn spawn_verifier(policy_path: &Path, tcp_port: u16, http_port: u16, scratch_dir: &Path) -> Child {
    let bin = env!("CARGO_BIN_EXE_pool-verifier");
    Command::new(bin)
        .env("VELDRA_POLICY_FILE", policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env("VELDRA_VERIFIER_CONFIG", scratch_dir.join("verifier.toml"))
        .env("VELDRA_LOG_FILTER", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier")
}

async fn wait_for_listener(port: u16, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("verifier TCP listener on 127.0.0.1:{port} never came up within {deadline:?}");
}

async fn wait_for_first_refresh(state: &MockState, deadline: Duration) {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if state.request_count.load(Ordering::SeqCst) >= 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("bitcoind mock never received a getrawmempool poll within {deadline:?}");
}

/// Send a `TemplatePropose` framed in a gateway-style
/// `InternalMessage` envelope, read one `TemplateVerdict` envelope
/// back. Returns the decoded verdict for assertions.
async fn round_trip_template(port: u16, template: TemplatePropose) -> TemplateVerdict {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect verifier TCP");
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let propose_env = InternalMessage {
        msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
        version: PROTOCOL_VERSION,
        payload: serde_json::to_value(&template).expect("serialize template"),
    };
    let mut line = serde_json::to_string(&propose_env).expect("serialize envelope");
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .expect("write template");
    write_half.flush().await.expect("flush");

    let mut buf = String::new();
    let n = reader.read_line(&mut buf).await.expect("read verdict line");
    assert!(n > 0, "expected verdict line, got EOF");

    let env: InternalMessage = serde_json::from_str(buf.trim()).expect("parse envelope");
    assert_eq!(
        env.msg_type,
        msg_types::TEMPLATE_VERDICT,
        "unexpected msg_type: {}",
        env.msg_type
    );
    serde_json::from_value(env.payload).expect("parse verdict payload")
}

/// Build a `TemplatePropose` against the regtest segwit fixture
/// plus the corresponding non-coinbase txid in display-order hex
/// (the shape bitcoind RPC emits).
fn regtest_segwit_template_and_display_hex() -> (TemplatePropose, Vec<String>) {
    let bytes =
        hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
    let weight =
        rg_consensus::re_derive_template_weight(&bytes).expect("regtest weight re-derives");
    let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
    let total_sigops = rg_consensus::total_sigops(&parsed);
    let coinbase_sigops = rg_consensus::coinbase_sigops(&parsed);
    let coinbase_value =
        rg_consensus::re_derive_coinbase_value(&bytes).expect("regtest coinbase value re-derives");
    let txids_internal = rg_consensus::template_txids(&parsed);

    let display_hex: Vec<String> = txids_internal
        .iter()
        .map(|t| {
            let mut bytes = *t;
            bytes.reverse();
            hex::encode(bytes)
        })
        .collect();

    let template = TemplatePropose {
        version: PROTOCOL_VERSION,
        id: 42,
        block_height: 102,
        prev_hash: "a".repeat(64),
        coinbase_value,
        tx_count: 2,
        total_fees: 0,
        observed_weight: None,
        created_at_unix_ms: None,
        total_sigops: Some(total_sigops),
        coinbase_sigops: Some(coinbase_sigops),
        template_weight: Some(weight),
        gateway_instance_id: None,
        raw_block_hex: Some(REGTEST_SEGWIT_BLOCK_HEX.trim().to_string()),
    };
    (template, display_hex)
}

fn make_mock_state(display_hex: Vec<String>) -> MockState {
    MockState {
        display_hex_txids: Arc::new(std::sync::RwLock::new(display_hex)),
        request_count: Arc::new(AtomicU64::new(0)),
        fail_next: Arc::new(AtomicBool::new(false)),
    }
}

async fn boot_verifier_with_mock(
    display_hex_txids: Vec<String>,
) -> (VerifierProcess, u16, MockState) {
    let mock_state = make_mock_state(display_hex_txids);
    let mock_addr = spawn_mock(mock_state.clone()).await;

    let verifier_port = discover_free_port().await;
    let http_port = discover_free_port().await;

    let scratch = ScratchDir::new("phase2-tcp").expect("create scratch dir");
    let policy_path = write_policy_toml(scratch.path(), mock_addr);
    let child = spawn_verifier(&policy_path, verifier_port, http_port, scratch.path());

    let proc = VerifierProcess {
        child,
        _scratch: scratch,
    };

    wait_for_listener(verifier_port, Duration::from_secs(15)).await;
    wait_for_first_refresh(&mock_state, Duration::from_secs(10)).await;
    // Give the verifier one extra poll cycle to install the snapshot.
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    (proc, verifier_port, mock_state)
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_happy_path_full_overlap_emits_accept() {
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let (_proc, port, _mock) = boot_verifier_with_mock(display_hex).await;

    let verdict = round_trip_template(port, template).await;

    assert!(
        verdict.accepted,
        "expected accept, got reason={:?} detail={:?}",
        verdict.reason_code, verdict.reason_detail
    );
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_fabrication_path_emits_tolerance_exceeded() {
    let (template, _display_hex) = regtest_segwit_template_and_display_hex();
    // Empty mempool view; template's 1 non-coinbase tx is unknown.
    let (_proc, port, _mock) = boot_verifier_with_mock(vec![]).await;

    let verdict = round_trip_template(port, template).await;

    assert!(!verdict.accepted, "expected reject, got accept");
    assert_eq!(
        verdict.reason_code,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded),
        "wrong reason_code: {:?}",
        verdict.reason_code
    );
    let detail = verdict.reason_detail.unwrap_or_default();
    assert!(
        detail.contains("mempool tolerance exceeded"),
        "detail must mention tolerance: {detail}"
    );
}

#[tokio::test]
#[ignore = "Tier 2: spawns pool-verifier subprocess; run with --ignored"]
async fn phase2_tcp_subsequent_template_uses_refreshed_view() {
    // Boot with empty mempool, replace the txid set, wait for poll,
    // assert the next template is accepted. Verifies the polling
    // task installs new snapshots without a process restart.
    let (template, display_hex) = regtest_segwit_template_and_display_hex();
    let (_proc, port, mock) = boot_verifier_with_mock(vec![]).await;

    // Confirm initial reject under empty view.
    let verdict_a = round_trip_template(port, template.clone()).await;
    assert!(!verdict_a.accepted);

    // Mutate the mock's view to include the template's tx.
    {
        let mut g = mock.display_hex_txids.write().expect("mock write lock");
        *g = display_hex;
    }

    // Wait two poll intervals plus install latency to make sure the
    // verifier picks up the new view.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    let verdict_b = round_trip_template(port, template).await;
    assert!(
        verdict_b.accepted,
        "expected accept after refresh, got reason={:?}",
        verdict_b.reason_code
    );
}

// Compile-time assertions that the test crate sees the symbols it
// imports. Catches a future visibility regression early without
// requiring the ignored Tier 2 tests to run.
#[allow(dead_code)]
fn _api_smoke() {
    let _ = HashSet::<[u8; 32]>::new();
    let _ = make_mock_state(vec![]);
}
