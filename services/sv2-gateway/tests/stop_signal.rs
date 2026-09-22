//! PB-49 regression: SIGTERM stops the gateway through its drain path.
//!
//! SIGTERM is what docker stop, systemd and Kubernetes send. The gateway used
//! to handle only SIGINT, so a SIGTERM either killed it at once, wherever it
//! was, or, as PID 1 in its container, was ignored until docker's SIGKILL did
//! the same ten seconds later. Either way the main loop could die between an
//! accounting batch's WAL write and its lines.
//!
//! The observable is how the process ends: an exit through the drain arm
//! returns a clean exit code, and death by signal carries the signal number
//! instead. A gateway spawned by this test is not PID 1, so without the
//! handler SIGTERM's default action kills it and the test sees signal 15.

#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Read as _, Write as _};
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Long enough for a debug build to boot on a loaded CI runner.
const BOOT_DEADLINE: Duration = Duration::from_secs(30);
/// The drain path is a break out of the select loop; it needs no more.
const EXIT_DEADLINE: Duration = Duration::from_secs(10);

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

/// `Drop` guard so a failing test never leaks a gateway process.
struct GatewayProcess {
    child: Child,
}

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().expect("local addr").port()
}

/// One plain HTTP/1.1 GET of the liveness route; true on a 200.
fn health_ok(port: u16) -> bool {
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200")
}

#[test]
fn sigterm_exits_through_the_drain_path() {
    let scratch = ScratchDir::new("pb49-sigterm");
    let health_port = free_port();

    // Shadow mode: no miner listener and no Noise keypair. The verifier and
    // template source point at a closed port; the gateway retries both, which
    // is fine, because this test only needs its main loop running.
    let config = format!(
        r#"mode = "shadow"

[gateway]
listen_addr = "127.0.0.1:0"
health_addr = "127.0.0.1:{health_port}"
noise_keypair_path = "unused-in-shadow-mode.key"
authority_pubkey = "9095236f0477b38d1dabc5a098de5f19da2b1400c67cb7b3fd15904b4b9ab7b8"
template_url = "http://127.0.0.1:1"

[verifier]
addr = "127.0.0.1:1"
"#
    );
    let config_path = scratch.path.join("gateway.toml");
    std::fs::write(&config_path, config).expect("write config");

    let mut gateway = GatewayProcess {
        child: Command::new(env!("CARGO_BIN_EXE_sv2-gateway"))
            .arg("--config")
            .arg(&config_path)
            .env("VELDRA_API_SECRET_OPTIONAL", "1")
            .env("VELDRA_LOG_FILTER", "info")
            .current_dir(&scratch.path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sv2-gateway"),
    };

    // The SIGTERM handler is installed before the health server starts, so a
    // /healthz answer means a signal sent now cannot race the install.
    let booted = Instant::now();
    while !health_ok(health_port) {
        if let Some(status) = gateway.child.try_wait().expect("poll child") {
            panic!("the gateway exited during boot: {status:?}");
        }
        assert!(
            booted.elapsed() < BOOT_DEADLINE,
            "the gateway never served /healthz within {BOOT_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let sent = Command::new("kill")
        .arg("-TERM")
        .arg(gateway.child.id().to_string())
        .status()
        .expect("run kill");
    assert!(sent.success(), "kill -TERM failed: {sent:?}");

    let stopping = Instant::now();
    let status = loop {
        if let Some(status) = gateway.child.try_wait().expect("poll child") {
            break status;
        }
        assert!(
            stopping.elapsed() < EXIT_DEADLINE,
            "the gateway was still running {EXIT_DEADLINE:?} after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    let mut stdout = String::new();
    if let Some(mut out) = gateway.child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    assert_eq!(
        status.signal(),
        None,
        "the gateway died of signal {:?} instead of exiting through its drain path",
        status.signal()
    );
    assert_eq!(status.code(), Some(0), "unexpected exit: {status:?}");
    assert!(
        stdout
            .lines()
            .any(|l| l.contains("shutdown signal received") && l.contains("SIGTERM")),
        "the drain arm did not log that SIGTERM stopped it; stdout was:\n{stdout}"
    );
}
