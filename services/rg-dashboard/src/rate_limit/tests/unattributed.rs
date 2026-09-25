//! The once-a-minute warning for forwarding headers the limiter did not
//! use: `ClientAddr::note_unattributed`, and `LimitClass::sweep` logging
//! and resetting it. Before it existed, a dashboard behind a proxy it had
//! not been told about keyed every client by the proxy's address and said
//! nothing.

use super::*;
use std::io::Write;
use std::sync::Mutex;

/// Stands in for the proxy. TEST-NET-1, like the client addresses below.
const PROXY: &str = "192.0.2.1";
const XFF: (&str, &str) = ("x-forwarded-for", "203.0.113.40");

/// What a `fmt` subscriber wrote, so a test can read the log line.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Run one sweep and return what it logged.
fn sweep_log(class: &LimitClass) -> String {
    let out = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(out.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || class.sweep());
    String::from_utf8(out.0.lock().unwrap().clone()).unwrap()
}

#[tokio::test]
async fn unconfigured_proxy_shares_one_budget_and_is_noticed() {
    let (app, api) = app_with(THREE, DEAD);
    for n in 1..=3 {
        let xff = format!("203.0.113.{n}");
        assert_eq!(
            status(&app, SETTINGS, PROXY, &[("x-forwarded-for", xff.as_str())]).await,
            200
        );
    }
    assert_eq!(
        status(&app, SETTINGS, PROXY, &[("x-forwarded-for", "203.0.113.4")]).await,
        429,
        "a fourth client behind the same unconfigured proxy is refused"
    );
    assert_eq!(
        api.client.take_unattributed(),
        Some(Unattributed {
            last_peer: ip(PROXY),
            requests: 4
        })
    );
    assert_eq!(api.client.take_unattributed(), None, "taking it resets it");
}

#[tokio::test]
async fn each_forwarding_header_is_noticed() {
    for (name, value) in [
        ("x-forwarded-for", "203.0.113.41"),
        ("cf-connecting-ip", "203.0.113.41"),
        ("forwarded", "for=203.0.113.41"),
    ] {
        let (app, api) = app_with("", DEAD);
        assert_eq!(status(&app, SETTINGS, PROXY, &[(name, value)]).await, 200);
        assert_eq!(
            api.client.take_unattributed(),
            Some(Unattributed {
                last_peer: ip(PROXY),
                requests: 1
            }),
            "{name}"
        );
    }
}

#[tokio::test]
async fn direct_clients_and_used_headers_are_not_noticed() {
    let (app, api) = app_with(CF_TRUST, DEAD);
    assert_eq!(status(&app, SETTINGS, "198.51.100.40", &[]).await, 200);
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("cf-connecting-ip", "203.0.113.42")]
        )
        .await,
        200
    );
    assert_eq!(api.client.take_unattributed(), None);
}

#[tokio::test]
async fn untrusted_peer_and_unconfigured_header_are_noticed() {
    let (app, api) = app_with(CF_TRUST, DEAD);
    // A peer outside trusted_proxies: its header is ignored.
    status(
        &app,
        SETTINGS,
        "198.51.100.43",
        &[("cf-connecting-ip", "203.0.113.43")],
    )
    .await;
    // The trusted proxy, sending a header other than the configured one.
    status(
        &app,
        SETTINGS,
        "127.0.0.1",
        &[("x-forwarded-for", "203.0.113.44")],
    )
    .await;
    assert_eq!(
        api.client.take_unattributed(),
        Some(Unattributed {
            last_peer: ip("127.0.0.1"),
            requests: 2
        })
    );
}

#[tokio::test]
async fn sweep_logs_it_once_naming_the_address() {
    let (app, api) = app_with(THREE, DEAD);
    status(&app, SETTINGS, PROXY, &[XFF]).await;
    status(&app, "/api/health", PROXY, &[XFF]).await;

    let log = sweep_log(&api);
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains("forwarding header"), "{log}");
    assert!(log.contains(&format!("peer={PROXY}")), "{log}");
    assert!(
        log.contains("requests=2"),
        "the fanout class shares the count: {log}"
    );
    assert!(log.contains("trusted_proxies=0"), "{log}");

    let again = sweep_log(&api);
    assert!(
        !again.contains("forwarding header"),
        "one line per sweep, then reset: {again}"
    );
}
