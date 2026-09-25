//! Router-level tests for `rate_limit`, driven with `oneshot` and a
//! hand-inserted `ConnectInfo`. `tests/rate_limit_binary.rs` covers what
//! these cannot: the real `serve` path and the TOML file.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::AppState;
use crate::config::DashboardConfig;
use axum::Router;
use axum::body::Body;
use tokio::sync::mpsc;
use tower::ServiceExt as _;

/// Nothing listens on port 1, so every upstream call fails at once.
const DEAD: &str = "http://127.0.0.1:1";

/// The router exactly as `main` builds it, from a TOML fragment.
fn app_with(extra_toml: &str, auth_url: &str) -> (Router, Arc<LimitClass>) {
    let cfg: DashboardConfig = toml::from_str(&format!(
        "verifier_url = \"{DEAD}\"\ntemplate_url = \"{DEAD}\"\nauth_url = \"{auth_url}\"\n{extra_toml}"
    ))
    .expect("config");
    let client_addr = Arc::new(ClientAddr::from_config(&cfg.rate_limit));
    let api = LimitClass::new("api", cfg.rate_limit.api_per_minute, client_addr.clone());
    let fanout = LimitClass::new("fanout", FANOUT_PER_MINUTE, client_addr.clone());
    let state = Arc::new(AppState {
        config: cfg,
        client: reqwest::Client::new(),
        client_addr,
    });
    (crate::router(state, api.clone(), fanout), api)
}

fn app(extra_toml: &str) -> Router {
    app_with(extra_toml, DEAD).0
}

const THREE: &str = "[rate_limit]\napi_per_minute = 3";
const CF_TRUST: &str = "[rate_limit]\napi_per_minute = 3\ntrusted_proxies = [\"127.0.0.1\"]\nclient_ip_header = \"cf-connecting-ip\"";
const XFF_TRUST: &str = "[rate_limit]\napi_per_minute = 3\ntrusted_proxies = [\"127.0.0.1\"]\nclient_ip_header = \"x-forwarded-for\"";

async fn call(app: &Router, path: &str, peer: &str, headers: &[(&str, &str)]) -> Response {
    let mut req = axum::http::Request::builder().uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = req.body(Body::empty()).unwrap();
    let peer: IpAddr = peer.parse().unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
    app.clone().oneshot(req).await.unwrap()
}

async fn status(app: &Router, path: &str, peer: &str, headers: &[(&str, &str)]) -> u16 {
    call(app, path, peer, headers).await.status().as_u16()
}

const SETTINGS: &str = "/api/dashboard/settings";

/// Spend a client's whole `/api` budget of 3 and check the 4th is refused.
async fn exhaust(app: &Router, peer: &str, headers: &[(&str, &str)]) {
    for n in 1..=3 {
        assert_eq!(status(app, SETTINGS, peer, headers).await, 200, "call {n}");
    }
    assert_eq!(status(app, SETTINGS, peer, headers).await, 429, "call 4");
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.append(*k, HeaderValue::from_str(v).unwrap());
    }
    map
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn api_n_plus_one_gets_429_with_retry_after() {
    let app = app(THREE);
    for n in 1..=3 {
        assert_eq!(
            status(&app, SETTINGS, "198.51.100.7", &[]).await,
            200,
            "call {n}"
        );
    }
    let resp = call(&app, SETTINGS, "198.51.100.7", &[]).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = resp.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry_after), "Retry-After {retry_after}");
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["reason_code"], ReasonCode::RateLimited.as_str());
}

#[tokio::test]
async fn healthz_and_spa_stay_open_after_api_exhausted() {
    let app = app(THREE);
    exhaust(&app, "198.51.100.7", &[]).await;
    for _ in 0..50 {
        let resp = call(&app, "/healthz", "198.51.100.7", &[]).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }
    // 200 with frontend/dist built, 404 without it; never 429.
    for path in ["/", "/some/client/route", "/api/not-a-route"] {
        for _ in 0..10 {
            assert_ne!(status(&app, path, "198.51.100.7", &[]).await, 429, "{path}");
        }
    }
}

#[tokio::test]
async fn fanout_has_its_own_budget() {
    let app = app(THREE);
    exhaust(&app, "198.51.100.8", &[]).await;
    for n in 1..=FANOUT_PER_MINUTE {
        assert_eq!(
            status(&app, "/api/health", "198.51.100.8", &[]).await,
            200,
            "/api/health call {n}"
        );
    }
    assert_eq!(status(&app, "/api/health", "198.51.100.8", &[]).await, 429);
    assert_eq!(status(&app, "/healthz", "198.51.100.8", &[]).await, 200);
}

#[tokio::test]
async fn distinct_clients_distinct_buckets() {
    let app = app(THREE);
    exhaust(&app, "198.51.100.10", &[]).await;
    assert_eq!(status(&app, SETTINGS, "198.51.100.11", &[]).await, 200);
}

#[tokio::test]
async fn trusted_proxy_cf_header_keys_by_client() {
    let app = app(CF_TRUST);
    exhaust(&app, "127.0.0.1", &[("cf-connecting-ip", "203.0.113.1")]).await;
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("cf-connecting-ip", "203.0.113.2")]
        )
        .await,
        200,
        "another client behind the same proxy has its own budget"
    );
}

#[tokio::test]
async fn untrusted_peer_header_ignored() {
    let app = app(CF_TRUST);
    for n in 1..=3 {
        let spoof = format!("203.0.113.{n}");
        assert_eq!(
            status(
                &app,
                SETTINGS,
                "198.51.100.9",
                &[("cf-connecting-ip", spoof.as_str())]
            )
            .await,
            200
        );
    }
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "198.51.100.9",
            &[("cf-connecting-ip", "203.0.113.99")]
        )
        .await,
        429,
        "a peer that is not a trusted proxy cannot pick its bucket"
    );
}

#[tokio::test]
async fn xff_rightmost_untrusted_is_the_client() {
    let app = app(XFF_TRUST);
    for n in 1..=3 {
        let xff = format!("10.9.9.{n}, 203.0.113.5");
        assert_eq!(
            status(
                &app,
                SETTINGS,
                "127.0.0.1",
                &[("x-forwarded-for", xff.as_str())]
            )
            .await,
            200
        );
    }
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("x-forwarded-for", "10.9.9.9, 203.0.113.5")]
        )
        .await,
        429,
        "the client-written left side does not change the bucket"
    );

    // Trusted hops on the right are skipped.
    let xff = [("x-forwarded-for", "203.0.113.6, 127.0.0.1")];
    exhaust(&app, "127.0.0.1", &xff).await;
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("x-forwarded-for", "203.0.113.6")]
        )
        .await,
        429,
        "203.0.113.6, 127.0.0.1 keyed as 203.0.113.6"
    );

    let client = ClientAddr::from_config(&toml::from_str(
        "trusted_proxies = [\"127.0.0.1\", \"10.0.0.2\"]\nclient_ip_header = \"x-forwarded-for\"",
    )
    .unwrap());
    // Several header lines are one list, in order.
    let two_lines = headers(&[
        ("x-forwarded-for", "6.6.6.6"),
        ("x-forwarded-for", "203.0.113.7, 10.0.0.2"),
    ]);
    assert_eq!(
        client.resolve(ip("127.0.0.1"), &two_lines),
        ip("203.0.113.7")
    );
    // Every hop trusted: nobody else is named, so the peer is the client.
    let all_trusted = headers(&[("x-forwarded-for", "10.0.0.2, 127.0.0.1")]);
    assert_eq!(
        client.resolve(ip("127.0.0.1"), &all_trusted),
        ip("127.0.0.1")
    );
}

#[tokio::test]
async fn missing_or_garbage_header_falls_back_to_peer() {
    let app = app(CF_TRUST);
    assert_eq!(status(&app, SETTINGS, "127.0.0.1", &[]).await, 200);
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("cf-connecting-ip", "garbage")]
        )
        .await,
        200
    );
    assert_eq!(
        status(
            &app,
            SETTINGS,
            "127.0.0.1",
            &[("cf-connecting-ip", "999.1.1.1")]
        )
        .await,
        200
    );
    assert_eq!(
        status(&app, SETTINGS, "127.0.0.1", &[]).await,
        429,
        "all three unreadable headers were counted against the peer"
    );

    let client = ClientAddr::from_config(
        &toml::from_str(
            "trusted_proxies = [\"127.0.0.1\"]\nclient_ip_header = \"x-forwarded-for\"",
        )
        .unwrap(),
    );
    let peer = ip("127.0.0.1");
    for xff in [
        "203.0.113.5, garbage",
        "203.0.113.5, ",
        "",
        "not an address",
    ] {
        assert_eq!(
            client.resolve(peer, &headers(&[("x-forwarded-for", xff)])),
            peer,
            "{xff:?}"
        );
    }
    assert_eq!(
        client.resolve(
            peer,
            &headers(&[("x-forwarded-for", "garbage, 203.0.113.5")])
        ),
        ip("203.0.113.5"),
        "junk left of the client is never reached"
    );
    assert_eq!(client.resolve(peer, &HeaderMap::new()), peer);
}

#[tokio::test]
async fn ipv6_same_64_shares_bucket() {
    let app = app(THREE);
    assert_eq!(status(&app, SETTINGS, "2001:db8::1", &[]).await, 200);
    assert_eq!(status(&app, SETTINGS, "2001:db8::1", &[]).await, 200);
    assert_eq!(status(&app, SETTINGS, "2001:db8::2", &[]).await, 200);
    assert_eq!(
        status(&app, SETTINGS, "2001:db8::ffff:2", &[]).await,
        429,
        "one /64 is one bucket"
    );
    assert_eq!(status(&app, SETTINGS, "2001:db8:0:1::1", &[]).await, 200);

    exhaust(&app, "198.51.100.7", &[]).await;
    assert_eq!(
        status(&app, SETTINGS, "::ffff:198.51.100.7", &[]).await,
        429,
        "an IPv4-mapped address counts as the IPv4 address"
    );
}

#[tokio::test]
async fn missing_connect_info_is_a_500_not_a_bypass() {
    let app = app(THREE);
    let req = axum::http::Request::builder()
        .uri(SETTINGS)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn sweep_reports_and_resets_the_refusal_count() {
    let (app, api) = app_with(THREE, DEAD);
    exhaust(&app, "198.51.100.12", &[]).await;
    assert_eq!(status(&app, SETTINGS, "198.51.100.12", &[]).await, 429);
    assert_eq!(api.sweep(), 2);
    assert_eq!(api.sweep(), 0);
}

/// A stand-in rg-auth that reports the `x-forwarded-for` it received.
async fn capture_auth() -> (String, mpsc::UnboundedReceiver<Option<String>>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let upstream = Router::new().fallback(move |headers: HeaderMap| {
        let tx = tx.clone();
        async move {
            let xff = headers
                .get("x-forwarded-for")
                .map(|v| v.to_str().unwrap().to_owned());
            tx.send(xff).unwrap();
            "captured"
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    (url, rx)
}

#[tokio::test]
async fn auth_proxy_forwards_resolved_client_ip() {
    let (url, mut seen) = capture_auth().await;

    let (trusting, _) = app_with(CF_TRUST, &url);
    for path in ["/api/auth/x", "/api/keys/x"] {
        let resp = call(
            &trusting,
            path,
            "127.0.0.1",
            &[
                ("cf-connecting-ip", "203.0.113.9"),
                ("x-forwarded-for", "6.6.6.6"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(
            seen.recv().await.unwrap().as_deref(),
            Some("203.0.113.9"),
            "{path}: rg-auth sees the client the trusted proxy named, and only it"
        );
    }

    // No trust configured: the TCP peer, byte for byte what was sent
    // before the limiter existed, whatever the client's headers say.
    let (plain, _) = app_with("", &url);
    for path in ["/api/auth/x", "/api/keys/x"] {
        let resp = call(
            &plain,
            path,
            "198.51.100.20",
            &[
                ("cf-connecting-ip", "203.0.113.9"),
                ("x-forwarded-for", "6.6.6.6"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        assert_eq!(seen.recv().await.unwrap().as_deref(), Some("198.51.100.20"));
    }
}

#[test]
fn retry_after_rounds_up_inside_one_to_sixty() {
    assert_eq!(retry_after_secs(Duration::ZERO), 1);
    assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
    assert_eq!(retry_after_secs(Duration::from_millis(1_001)), 2);
    assert_eq!(retry_after_secs(Duration::from_secs(60)), 60);
    assert_eq!(retry_after_secs(Duration::from_secs(61)), 60);
}

#[test]
fn bucket_key_masks_ipv6_to_64_and_unmaps_ipv4() {
    assert_eq!(bucket_key(ip("198.51.100.7")), ip("198.51.100.7"));
    assert_eq!(bucket_key(ip("::ffff:198.51.100.7")), ip("198.51.100.7"));
    assert_eq!(bucket_key(ip("2001:db8::1:2:3:4")), ip("2001:db8::"));
    assert_eq!(bucket_key(ip("2001:db8:0:1:ffff::1")), ip("2001:db8:0:1::"));
}
