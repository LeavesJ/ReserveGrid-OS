//! Boot-outcome tests for the shipped `deploy/policy-prod.toml`.
//!
//! `deploy/policy-prod.toml` is the file `docker-compose.setup-b.yml`
//! mounts at `/config/policy-prod.toml` on the Class M soak node, and
//! it ships `[policy.mempool] enforce = true` next to a placeholder
//! `rpc_url`. A placeholder is a non-empty string, so an emptiness
//! check passes it, the mempool view is never built, and the verifier
//! reports healthy while checking nothing. Invariant 4: a config
//! default that validates but cannot work is worse than a missing key,
//! because a missing key fails loudly at boot.
//!
//! These tests assert the boot outcome of the real binary, not an
//! internal predicate.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Repo-root-relative path to a shipped deploy artifact.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// Scratch cwd so the binary's `data/` bootstrap never dirties the
/// working tree. Removed on drop even when the test panics.
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("rg-{label}-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Boot the real `pool-verifier` against `policy_path` and report
/// whether it exited on its own, plus whatever it wrote to stderr.
/// Kills the child if it is still running at the deadline, so a
/// regression leaks neither a process nor a bound port.
fn boot_outcome(policy_path: &Path, tcp_port: u16, http_port: u16) -> (Option<i32>, String) {
    let scratch = ScratchDir::new("prodpolicy");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pool-verifier"))
        .current_dir(&scratch.path)
        .env("VELDRA_POLICY_FILE", policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env("VELDRA_VERIFIER_CONFIG", scratch.path.join("verifier.toml"))
        .env("VELDRA_LOG_FILTER", "info")
        .env_remove("VELDRA_BITCOIND_RPC_PASS")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };

    let output = child.wait_with_output().expect("collect child output");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (status.and_then(|s| s.code()), stderr)
}

/// The shipped production policy carries `enforce = true` with a
/// `TODO_SET_*` `rpc_url`. Starting in that state gives an operator a
/// verifier that answers `/health`, climbs `verdicts_total`, and runs
/// no Class M check at all. Startup must fail instead.
#[test]
fn shipped_prod_policy_with_placeholder_rpc_url_fails_boot() {
    let policy = repo_path("deploy/policy-prod.toml");
    assert!(
        policy.exists(),
        "deploy/policy-prod.toml missing at {}",
        policy.display()
    );

    let (code, stderr) = boot_outcome(&policy, 39_231, 39_232);

    assert_eq!(
        code,
        Some(1),
        "verifier must exit non-zero on a placeholder rpc_url with enforce = true; \
         stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("rpc_url"),
        "the boot failure must name the offending key; stderr was:\n{stderr}"
    );
}

// ── PB-45: readiness must be usable as a healthcheck ────────────────

/// Boot the real verifier and poll `/ready` until it answers or the deadline
/// passes. Returns the HTTP status and decoded body.
fn ready_outcome(policy_path: &Path, tcp_port: u16, http_port: u16) -> (u16, serde_json::Value) {
    let scratch = ScratchDir::new("pb45ready");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pool-verifier"))
        .current_dir(&scratch.path)
        .env("VELDRA_POLICY_FILE", policy_path)
        .env("VELDRA_VERIFIER_ADDR", format!("127.0.0.1:{tcp_port}"))
        .env("VELDRA_HTTP_ADDR", format!("127.0.0.1:{http_port}"))
        .env("VELDRA_API_SECRET_OPTIONAL", "1")
        .env("VELDRA_VERIFIER_CONFIG", scratch.path.join("verifier.toml"))
        .env("VELDRA_LOG_FILTER", "warn")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pool-verifier");

    let url = format!("http://127.0.0.1:{http_port}/ready");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = (0u16, serde_json::Value::Null);
    while Instant::now() < deadline {
        if let Ok(out) = Command::new("curl")
            .args([
                "-s",
                "-o",
                "-",
                "-w",
                "\n%{http_code}",
                "--max-time",
                "2",
                &url,
            ])
            .output()
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if let Some((body, code)) = text.rsplit_once('\n')
                && let Ok(code) = code.trim().parse::<u16>()
                && code != 0
            {
                let v = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
                last = (code, v);
                if code == 200 {
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = child.kill();
    let _ = child.wait();
    last
}

/// PB-45. A Phase 1 verifier (`[policy.mempool] enforce = false`, the shipped
/// default) must become READY.
///
/// Before this, `mempool_reachable` was pure freshness of
/// `LAST_MEMPOOL_OK_UNIX`, which a Phase 1 deployment never sets, so `/ready`
/// answered 503 forever. That is why all four compose stacks probed `/health`
/// instead, and `/health` is a hardcoded "ok" that cannot fail. The one signal
/// that would have surfaced PB-36 at deploy time was consumed by nothing.
#[test]
fn phase_one_verifier_becomes_ready() {
    let scratch = ScratchDir::new("pb45policy");
    let policy = scratch.path.join("phase1.toml");
    std::fs::write(
        &policy,
        "[policy]\n\
         protocol_version = 2\n\
         required_prevhash_len = 64\n\
         min_total_fees = 0\n\
         max_tx_count = 4294967295\n\
         min_avg_fee = 0\n\
         low_mempool_tx = 0\n\
         high_mempool_tx = 0\n\
         tx_count_mid_threshold = 0\n\
         tx_count_hi_threshold = 0\n\
         min_avg_fee_lo = 0\n\
         min_avg_fee_mid = 0\n\
         min_avg_fee_hi = 0\n\
         reject_empty_templates = false\n\
         reject_coinbase_zero = false\n\
         unknown_mempool_as_high = true\n\
         \n\
         [policy.safety]\n\
         max_weight_ratio = 0.999\n\
         enforce_weight_ratio = false\n\
         enforce_template_age = false\n",
    )
    .expect("write phase 1 policy");

    let (code, body) = ready_outcome(&policy, 39_241, 39_242);
    assert_eq!(
        code, 200,
        "a Phase 1 verifier must answer /ready with 200 so the endpoint is \
         usable as a container healthcheck. Body: {body}"
    );
    assert_eq!(
        body["ready"],
        serde_json::json!(true),
        "ready must be true with enforcement off. Body: {body}"
    );
    assert_eq!(
        body["mempool_enforced"],
        serde_json::json!(false),
        "the response must say enforcement is OFF, so a vacuously satisfied \
         mempool_reachable is never mistaken for a live poller. Body: {body}"
    );
    assert_eq!(
        body["policy_loaded"],
        serde_json::json!(true),
        "the policy loaded, so readiness must say so. Body: {body}"
    );
}
