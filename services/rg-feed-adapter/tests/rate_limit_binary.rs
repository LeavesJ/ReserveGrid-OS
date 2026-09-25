//! The JSON-RPC request limit, observed through the real binary.
//!
//! The unit tests in `src/rate_limit.rs` insert `ConnectInfo` by hand, so
//! they cannot show that `main.rs` serves with connect-info (without it
//! every limited request is a 500), that `VELDRA_ADAPTER_RATE_LIMIT_PER_MINUTE`
//! reaches the limiter, or that a bad value stops the process instead of
//! falling back to the default. Env overrides are tested here and only
//! here, because `Command::env` is per child while `std::env::set_var` in
//! a unit test would race every other test in the binary.
//!
//! Before the limiter existed the fourth POST returned 200 like the first
//! three, and the process started normally with the variable set to `0`
//! or `abc`, because nothing read it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// How long the adapter gets to start answering `/health`, and how long a
/// misconfigured adapter gets to exit. Generous because the machines this
/// runs on are often heavily loaded.
const DEADLINE: Duration = Duration::from_secs(60);

const ENV_LIMIT: &str = "VELDRA_ADAPTER_RATE_LIMIT_PER_MINUTE";

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

/// `Drop` guard so a failing test never leaks an adapter process.
struct AdapterProcess {
    child: Child,
}

impl AdapterProcess {
    /// Boot the adapter on `port` with a dead feed and the given limit.
    /// The config path does not exist, so only defaults and env apply.
    fn spawn(scratch: &ScratchDir, port: u16, limit: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_rg-feed-adapter"))
            .arg("--config")
            .arg(scratch.path.join("absent.toml"))
            .env("VELDRA_ADAPTER_LISTEN", format!("127.0.0.1:{port}"))
            // Nothing listens on port 1. The feed loop retries with backoff
            // and the RPC server answers from an empty buffer meanwhile.
            .env("VELDRA_FEED_URL", "ws://127.0.0.1:1/ws")
            .env(ENV_LIMIT, limit)
            .env_remove("VELDRA_FEED_LICENSE_KEY")
            .env_remove("VELDRA_ALLOW_NON_LOOPBACK")
            .env("VELDRA_LOG_FILTER", "warn")
            .current_dir(&scratch.path)
            // Both piped: tracing writes to stdout, panics to stderr.
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rg-feed-adapter");
        Self { child }
    }

    /// Stop the adapter and return what it wrote, stdout (its log) then
    /// stderr.
    fn kill_and_drain_output(&mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut buf = String::new();
        if let Some(mut out) = self.child.stdout.take() {
            let _ = out.read_to_string(&mut buf);
        }
        if let Some(mut err) = self.child.stderr.take() {
            let _ = err.read_to_string(&mut buf);
        }
        buf
    }
}

impl Drop for AdapterProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback port nothing is bound to right now. The window between
/// dropping this listener and the adapter binding the port is a race in
/// principle; the OS hands out ephemeral ports in sequence, so a
/// collision inside it has not been seen.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind 0")
        .local_addr()
        .expect("local addr")
        .port()
}

/// One HTTP/1.1 exchange with `Connection: close`. Returns the status
/// code, the raw response head, and the body.
async fn exchange(port: u16, request: &str) -> std::io::Result<(u16, String, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, head.to_owned(), body.to_owned()))
}

async fn get_health(port: u16) -> std::io::Result<(u16, String, String)> {
    exchange(
        port,
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await
}

async fn post_rpc(port: u16) -> std::io::Result<(u16, String, String)> {
    let body = r#"{"jsonrpc":"1.0","id":1,"method":"getmempoolinfo","params":[]}"#;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange(port, &request).await
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

#[tokio::test]
async fn fourth_rpc_call_from_one_peer_is_refused_by_the_real_binary() {
    let scratch = ScratchDir::new("adapter-rate-limit");
    let port = free_port();
    let mut adapter = AdapterProcess::spawn(&scratch, port, "3");

    // /health is exempt from the limit, so polling it for readiness spends
    // none of the RPC budget the assertions below count on.
    let started = Instant::now();
    loop {
        if let Ok((200, _, _)) = get_health(port).await {
            break;
        }
        if let Ok(Some(status)) = adapter.child.try_wait() {
            panic!(
                "rg-feed-adapter exited during boot with {status}; output:\n{}",
                adapter.kill_and_drain_output()
            );
        }
        assert!(
            started.elapsed() < DEADLINE,
            "rg-feed-adapter did not answer /health within {DEADLINE:?}; output:\n{}",
            adapter.kill_and_drain_output()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    for n in 1..=3 {
        let (status, head, body) = post_rpc(port).await.expect("request");
        assert_eq!(
            status, 200,
            "RPC call {n} of 3 should be admitted:\n{head}\n\n{body}"
        );
    }

    let (status, head, body) = post_rpc(port).await.expect("request");
    assert_eq!(
        status, 429,
        "the 4th RPC call inside one minute should be refused with {ENV_LIMIT}=3:\n{head}\n\n{body}"
    );
    let retry_after: u64 = header(&head, "retry-after")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| panic!("429 without a numeric Retry-After:\n{head}"));
    assert!(
        (1..=60).contains(&retry_after),
        "Retry-After {retry_after} is outside 1..=60"
    );

    let (status, head, _) = get_health(port).await.expect("request");
    assert_eq!(status, 200, "/health is exempt from the limit:\n{head}");
}

/// A limit that cannot be used stops the process at startup. Falling back
/// to the default would hide the operator's typo (Invariant 3), and `0`
/// would otherwise refuse every call, since a window of length 0 is
/// always full.
#[tokio::test]
async fn unusable_limit_values_stop_the_process() {
    for bad in ["0", "abc", "-5", ""] {
        let scratch = ScratchDir::new("adapter-rate-limit-bad");
        let port = free_port();
        let mut adapter = AdapterProcess::spawn(&scratch, port, bad);

        let started = Instant::now();
        let status = loop {
            if let Ok(Some(status)) = adapter.child.try_wait() {
                break status;
            }
            if started.elapsed() >= DEADLINE {
                let health = get_health(port).await.map(|(s, _, _)| s).ok();
                panic!(
                    "{ENV_LIMIT}={bad:?} should stop the adapter, but it was still running \
                     after {DEADLINE:?}; /health answered {health:?}; output:\n{}",
                    adapter.kill_and_drain_output()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert!(
            !status.success(),
            "{ENV_LIMIT}={bad:?} exited with {status}, expected a failure"
        );
        // For the reason the test names, not any startup failure such as
        // a port already in use.
        let output = adapter.kill_and_drain_output();
        let why = if bad == "0" {
            "rate_limit_per_minute must be at least 1".to_owned()
        } else {
            format!("{ENV_LIMIT}={bad:?} is not a whole number")
        };
        assert!(
            output.contains(&why),
            "{ENV_LIMIT}={bad:?} should stop the adapter with {why:?}; output:\n{output}"
        );
    }
}
