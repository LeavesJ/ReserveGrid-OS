//! The `/api` request limit, observed through the real binary.
//!
//! The unit tests in `src/rate_limit.rs` drive the router with
//! `ConnectInfo` inserted by hand, so they cannot show two things this
//! test does: that `axum::serve` in `main.rs` really supplies the peer
//! address the limiter keys on, and that `[rate_limit]` in the TOML file
//! reaches the limiter. A regression in either one leaves every unit test
//! green and the service unlimited.
//!
//! Before the limiter existed the fourth `/api/dashboard/settings` call
//! returned 200 like the first three: `DashboardConfig` ignored the
//! unknown `[rate_limit]` table and nothing counted requests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// How long the dashboard gets to start answering `/healthz`. Generous
/// because the machines this runs on are often heavily loaded.
const BOOT_DEADLINE: Duration = Duration::from_secs(60);

/// RAII scratch directory, torn down on `Drop`.
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

/// `Drop` guard so a failing test never leaks a dashboard process.
struct DashboardProcess {
    child: Child,
}

impl DashboardProcess {
    fn kill_and_drain_stderr(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut buf = String::new();
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut buf);
        }
        buf
    }
}

impl Drop for DashboardProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback port nothing is bound to right now. The window between
/// dropping this listener and the dashboard binding the port is a race
/// in principle; the OS hands out ephemeral ports in sequence, so a
/// collision inside it has not been seen.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind 0")
        .local_addr()
        .expect("local addr")
        .port()
}

/// One HTTP/1.1 exchange with `Connection: close`. Returns the status
/// code and the raw response head, where the caller looks for headers.
async fn get(port: u16, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let head = text.split("\r\n\r\n").next().unwrap_or_default().to_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, head))
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

#[tokio::test]
async fn fourth_api_call_from_one_client_is_refused_by_the_real_binary() {
    let scratch = ScratchDir::new("dashboard-rate-limit");
    let port = free_port();

    // Every upstream is dead on purpose: /api/dashboard/settings is
    // answered locally, so no upstream is needed for the assertion, and
    // a dead one cannot make a call slow enough to leave the window.
    let config = format!(
        r#"listen = "127.0.0.1:{port}"
verifier_url = "http://127.0.0.1:1"
template_url = "http://127.0.0.1:1"
auth_url = "http://127.0.0.1:1"

[rate_limit]
api_per_minute = 3
"#
    );
    let config_path = scratch.path.join("dashboard.toml");
    std::fs::write(&config_path, config).expect("write config");

    let mut dashboard = DashboardProcess {
        child: Command::new(env!("CARGO_BIN_EXE_rg-dashboard"))
            .arg("--config")
            .arg(&config_path)
            .env("VELDRA_LOG_FILTER", "warn")
            .current_dir(&scratch.path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rg-dashboard"),
    };

    // /healthz is exempt from the limit, so polling it for readiness
    // spends none of the /api budget the assertions below count on.
    let started = Instant::now();
    loop {
        if let Ok((200, _)) = get(port, "/healthz").await {
            break;
        }
        if let Ok(Some(status)) = dashboard.child.try_wait() {
            panic!(
                "rg-dashboard exited during boot with {status}; stderr:\n{}",
                dashboard.kill_and_drain_stderr()
            );
        }
        assert!(
            started.elapsed() < BOOT_DEADLINE,
            "rg-dashboard did not answer /healthz within {BOOT_DEADLINE:?}; stderr:\n{}",
            dashboard.kill_and_drain_stderr()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for n in 1..=3 {
        let (status, head) = get(port, "/api/dashboard/settings").await.expect("request");
        assert_eq!(status, 200, "call {n} of 3 should be admitted:\n{head}");
    }

    let (status, head) = get(port, "/api/dashboard/settings").await.expect("request");
    assert_eq!(
        status, 429,
        "the 4th /api call inside one minute should be refused with api_per_minute = 3:\n{head}"
    );
    let retry_after: u64 = header(&head, "retry-after")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("429 without a numeric Retry-After:\n{head}"));
    assert!(
        (1..=60).contains(&retry_after),
        "Retry-After {retry_after} is outside 1..=60"
    );

    let (status, head) = get(port, "/healthz").await.expect("request");
    assert_eq!(status, 200, "/healthz is exempt from the limit:\n{head}");
}
