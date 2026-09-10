//! PB-42: the authenticated share relay, over a real socket.
//!
//! PB-37 was a signer and a verifier that disagreed for a month with CI green
//! throughout, and PB-42 records why it survived: `VELDRA_SHARE_UPSTREAM_SECRET`
//! is set NOWHERE. Not in a workflow, not in a compose file, not in `deploy/`.
//! The HMAC path is dead in every stack that runs, so nothing could have
//! caught it.
//!
//! PB-37 closed the contract at the UNIT level: `sv2_gateway`'s real signer
//! against this crate's real verifier, in process. That does not cover the
//! wire. A serialization change in axum, a middleware that rewrites the body,
//! or a content-encoding difference would pass that test and fail in
//! production. This spawns the real `template-manager` binary with the secret
//! set and POSTs a real signed share over a real TCP socket.
//!
//! The negative case is the important half. An integration test that only
//! checks the happy path cannot tell a working HMAC from a disabled one: with
//! verification switched off, `accepted: true` still comes back.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Child, Command};
use std::time::Duration;

const SECRET: &str = "pb42-wire-level-shared-secret";

/// A port nothing else holds. Bind, read, release, then hand it to the child.
///
/// There is an unavoidable gap between releasing the port and the child
/// binding it. Two of these running in parallel raced and produced one
/// intermittent readiness timeout during development, so `spawn_manager`
/// serialises allocate-spawn-ready under `SPAWN_LOCK` and retries with a fresh
/// port. An intermittent integration test is worse than none: it trains people
/// to re-run rather than read.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind 0");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
}

/// Serialises port allocation and bind across tests in this binary.
static SPAWN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Kills the child on drop so a failing assertion cannot leak a process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Boot the real binary with the HMAC secret set, and wait for it to serve.
///
/// No bitcoind is needed: `main` binds the HTTP listener before starting the
/// manager loop, so `/shares` is live while the RPC client fails in the
/// background.
async fn spawn_manager(dir: &std::path::Path) -> (ChildGuard, String) {
    let mut last = String::new();
    for attempt in 0..3 {
        let _held = SPAWN_LOCK.lock().await;
        match try_spawn(dir, attempt).await {
            Ok(v) => return v,
            Err(why) => last = why,
        }
    }
    panic!("template-manager never served /health across 3 attempts.\nLast attempt said:\n{last}");
}

/// One boot attempt. Returns the child's own output on failure, because a bare
/// "did not become ready" tells you nothing about why.
async fn try_spawn(dir: &std::path::Path, attempt: u32) -> Result<(ChildGuard, String), String> {
    let port = free_port().await;
    let cfg = dir.join(format!("manager{attempt}.toml"));
    let log = dir.join(format!("manager{attempt}.log"));
    std::fs::write(
        &cfg,
        format!(
            "[manager]\n\
             backend = \"bitcoind\"\n\
             poll_interval_secs = 3600\n\
             rpc_url = \"http://127.0.0.1:1\"\n\
             rpc_user = \"unused\"\n\
             http_listen_addr = \"127.0.0.1:{port}\"\n\
             coinbase_output_script_hex = \"51\"\n\
             extranonce_size = 4\n"
        ),
    )
    .expect("write config");

    let out = std::fs::File::create(&log).expect("create log");
    let err = out.try_clone().expect("clone log handle");
    let child = Command::new(env!("CARGO_BIN_EXE_template-manager"))
        .arg("--config")
        .arg(&cfg)
        .env("VELDRA_SHARE_UPSTREAM_SECRET", SECRET)
        .env("VELDRA_BITCOIND_RPC_PASS", "unused")
        .env("VELDRA_LOG_FILTER", "info")
        // VELDRA_API_SECRET deliberately unset so api_key_middleware admits
        // all and this test isolates the HMAC path. The binary refuses to boot
        // on an absent secret without this acknowledgement, which is
        // enforce_api_secret doing its job; the other integration suites set
        // the same flag for the same reason.
        .env_remove("VELDRA_API_SECRET")
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("spawn template-manager");
    let guard = ChildGuard(child);

    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    for _ in 0..100 {
        if client
            .get(format!("{base}/health"))
            .timeout(Duration::from_millis(200))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return Ok((guard, base));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let tail = std::fs::read_to_string(&log).unwrap_or_else(|e| format!("<no log: {e}>"));
    Err(format!("port {port}, child output:\n{tail}"))
}

/// A submission populated the way the gateway populates one, then signed with
/// the gateway's REAL signer. Nothing here re-implements the signature.
fn signed_submission() -> serde_json::Value {
    let mut sub = sv2_gateway::shares::ShareSubmission {
        share_id_hex: "aa".repeat(32),
        version: 0x2000_0000,
        prev_hash_wire_hex: "bb".repeat(32),
        prev_hash_display_hex: "bb".repeat(32),
        merkle_root_wire_hex: "cc".repeat(32),
        merkle_root_display_hex: "cc".repeat(32),
        ntime: 1_700_000_000,
        nbits: 0x1d00_ffff,
        nonce: 42,
        event_id_hex: "dd".repeat(32),
        worker_id: "pb42-worker".to_string(),
        validation_level: "full".to_string(),
        gateway_instance_id: "pb42-gw".to_string(),
        channel_id: 1,
        sequence_number: 7,
        job_id: 10,
        template_id: 100,
        block_height: 200,
        pool_account_id: None,
        timestamp_ms: 1_700_000_000_000,
        difficulty_u64: 1,
        difficulty_display: 1.0,
        source_instance_id: "pb42-src".to_string(),
        gateway_signature_hex: String::new(),
    };
    sv2_gateway::shares::sign_submission(SECRET.as_bytes(), &mut sub);
    assert!(
        !sub.gateway_signature_hex.is_empty(),
        "the gateway produced no signature; the rest of this test would pass \
         vacuously against a disabled verifier"
    );
    serde_json::to_value(&sub).expect("serialize submission")
}

async fn post_share(base: &str, body: &serde_json::Value) -> (bool, Option<String>) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/shares"))
        .json(body)
        .send()
        .await
        .expect("POST /shares");
    assert!(
        resp.status().is_success(),
        "POST /shares returned {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await.expect("decode response");
    (
        v["accepted"].as_bool().expect("accepted field"),
        v["reason"].as_str().map(str::to_string),
    )
}

fn scratch_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rg_pb42_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// The happy path, end to end over a socket: the gateway's real signer, the
/// wire, axum's extractor, and this crate's real verifier.
#[tokio::test]
async fn a_gateway_signed_share_is_accepted_over_the_wire() {
    let dir = scratch_dir();
    let (_child, base) = spawn_manager(&dir).await;

    let (accepted, reason) = post_share(&base, &signed_submission()).await;
    assert!(
        accepted,
        "a correctly signed share was rejected over the wire (reason {reason:?}). \
         The unit test passing while this fails means the break is in \
         serialization, the extractor, or middleware, not in the HMAC itself."
    );
}

/// The half that matters. Tamper ONE field after signing and the signature must
/// stop verifying. Without this, a verifier with checking switched off passes
/// the happy-path test above and looks identical to a working one.
#[tokio::test]
async fn a_tampered_body_is_rejected_over_the_wire() {
    let dir = scratch_dir();
    let (_child, base) = spawn_manager(&dir).await;

    let mut body = signed_submission();
    // Same event_id, same signature, different body: exactly the replay the
    // body hash exists to stop (PB-37).
    body["worker_id"] = serde_json::Value::String("someone-elses-worker".into());

    let (accepted, reason) = post_share(&base, &body).await;
    assert!(
        !accepted,
        "a body modified after signing was ACCEPTED. Either the body hash is \
         not bound, or signature verification is disabled on this path."
    );
    assert_eq!(
        reason.as_deref(),
        Some("invalid_gateway_signature"),
        "the rejection must carry the canonical reason_code so metrics and \
         dashboards can key off it"
    );
}
