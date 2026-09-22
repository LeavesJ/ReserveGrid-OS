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

use std::io::BufRead as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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

/// The gateway's log line once its main loop is running. The stop handler is
/// installed before anything else, so a signal sent after this line cannot
/// race the install. Waiting on the log, not on a health port, is deliberate:
/// a port picked free and handed to the gateway can be taken by another test
/// in between, which made this test time out under a full parallel run.
const IN_MAIN_LOOP: &str = "entering main loop";

/// Collect the child's stdout lines as they arrive, so the test can wait on
/// one and still read them all after the exit.
fn collect_stdout(child: &mut Child) -> (Arc<Mutex<Vec<String>>>, std::thread::JoinHandle<()>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let out = child.stdout.take().expect("piped stdout");
    let sink = Arc::clone(&lines);
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    (lines, reader)
}

#[test]
fn sigterm_exits_through_the_drain_path() {
    stops_through_the_drain_path("TERM", "SIGTERM");
}

/// PB-49 T2: SIGINT is a persistent handler too, so it is not missed while
/// the loop is busy inside an arm, and it ends the same way.
#[test]
fn sigint_exits_through_the_drain_path() {
    stops_through_the_drain_path("INT", "SIGINT");
}

fn stops_through_the_drain_path(kill_name: &str, logged: &str) {
    let scratch = ScratchDir::new("pb49-stop");

    // Shadow mode: no miner listener and no Noise keypair. The verifier and
    // template source point at a closed port; the gateway retries both, which
    // is fine, because this test only needs its main loop running.
    let config = r#"mode = "shadow"

[gateway]
listen_addr = "127.0.0.1:0"
health_addr = "127.0.0.1:0"
noise_keypair_path = "unused-in-shadow-mode.key"
authority_pubkey = "9095236f0477b38d1dabc5a098de5f19da2b1400c67cb7b3fd15904b4b9ab7b8"
template_url = "http://127.0.0.1:1"

[verifier]
addr = "127.0.0.1:1"
"#;
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
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sv2-gateway"),
    };
    let (lines, reader) = collect_stdout(&mut gateway.child);

    let booted = Instant::now();
    while !lines
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains(IN_MAIN_LOOP))
    {
        if let Some(status) = gateway.child.try_wait().expect("poll child") {
            panic!("the gateway exited during boot: {status:?}");
        }
        assert!(
            booted.elapsed() < BOOT_DEADLINE,
            "the gateway never reached its main loop within {BOOT_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let sent = Command::new("kill")
        .arg(format!("-{kill_name}"))
        .arg(gateway.child.id().to_string())
        .status()
        .expect("run kill");
    assert!(sent.success(), "kill -{kill_name} failed: {sent:?}");

    let stopping = Instant::now();
    let status = loop {
        if let Some(status) = gateway.child.try_wait().expect("poll child") {
            break status;
        }
        assert!(
            stopping.elapsed() < EXIT_DEADLINE,
            "the gateway was still running {EXIT_DEADLINE:?} after {logged}"
        );
        std::thread::sleep(Duration::from_millis(50));
    };

    reader.join().expect("stdout reader");
    let stdout = lines.lock().unwrap().join("\n");
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
            .any(|l| l.contains("shutdown signal received") && l.contains(logged)),
        "the drain arm did not log that {logged} stopped it; stdout was:\n{stdout}"
    );
    assert!(
        stdout.contains("accounting queues drained on stop"),
        "a requested stop must drain the accounting queues; stdout was:\n{stdout}"
    );
}
