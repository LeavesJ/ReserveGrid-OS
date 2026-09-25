//! Per-peer request limit on the JSON-RPC endpoint.
//!
//! `POST /` answers `getblocktemplate` by cloning and serializing the whole
//! buffered template, so a flood of it costs real CPU and bandwidth, and the
//! adapter has no authentication. The limit is a
//! `reservegrid_common::rate_limit::RateLimiter` (a sliding 60 s log, the
//! same limiter rg-auth uses) keyed by the TCP peer and nothing else. The
//! adapter is never behind a proxy, so a forwarded-for header here could
//! only be a client choosing its own bucket, and none is read.
//!
//! `GET /health` is not limited: compose healthchecks poll it and three
//! services wait on it through `depends_on: service_healthy`, and it costs
//! one lock read.
//!
//! A refused call gets 429, `Retry-After` in whole seconds, and the
//! bitcoind error envelope every other reply uses, with `rate_limited` as
//! the message. All three callers treat a non-2xx status as an error, so the
//! body is for people reading logs. Each refusal is a `debug!` line; once a
//! minute a `warn!` carries the count, so a flood cannot fill the disk one
//! line per request.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use reservegrid_common::ReasonCode;
use reservegrid_common::rate_limit::RateLimiter;
use tracing::{debug, warn};

use crate::rpc::{RpcError, RpcResponse};

/// Peers tracked before the least recently seen is evicted. The same bound
/// rg-auth runs with.
const MAX_TRACKED_PEERS: usize = 10_000;

/// How often the refusal count is logged and idle peers are dropped.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// JSON-RPC 2.0 reserves -32000 to -32099 for implementation-defined
/// server errors; this is the first of them.
const RPC_SERVER_ERROR: i32 = -32000;

pub struct RpcLimit {
    limiter: RateLimiter,
    per_minute: u32,
    rejected: AtomicU64,
}

impl RpcLimit {
    pub fn new(per_minute: u32) -> Arc<Self> {
        Arc::new(Self {
            limiter: RateLimiter::with_config(MAX_TRACKED_PEERS, None),
            per_minute,
            rejected: AtomicU64::new(0),
        })
    }

    /// Log and reset the refusal count, and drop peers idle for two
    /// windows. Returns the count it logged.
    pub fn sweep(&self) -> u64 {
        let rejected = self.rejected.swap(0, Ordering::Relaxed);
        if rejected > 0 {
            warn!(
                reason_code = ReasonCode::RateLimited.as_str(),
                rejected, "JSON-RPC rate limiter rejected calls in the last minute"
            );
        }
        self.limiter.cleanup();
        rejected
    }
}

/// Run [`RpcLimit::sweep`] every [`SWEEP_EVERY`] for the life of the
/// process.
pub fn spawn_sweeper(limit: Arc<RpcLimit>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.tick().await; // the first tick completes at once
        loop {
            tick.tick().await;
            limit.sweep();
        }
    });
}

/// The middleware. It runs before the handler reads the body, so a flood
/// of 64 KiB bodies is refused without being buffered. `ConnectInfo` is an
/// extractor, not an optional extension: a server started without
/// connect-info fails every call with a 500 instead of letting it through
/// unlimited.
pub async fn enforce(
    State(limit): State<Arc<RpcLimit>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let peer = peer.ip().to_canonical();
    match limit.limiter.admit(peer, limit.per_minute) {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            let retry_after_secs = retry_after_secs(wait);
            limit.rejected.fetch_add(1, Ordering::Relaxed);
            debug!(
                reason_code = ReasonCode::RateLimited.as_str(),
                %peer,
                retry_after_secs,
                "JSON-RPC call rate limited"
            );
            too_many_requests(retry_after_secs)
        }
    }
}

/// Whole seconds, rounded up so a caller that waits this long is admitted,
/// and kept inside 1..=60 because the window is 60 s.
fn retry_after_secs(wait: Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).clamp(1, 60)
}

fn too_many_requests(retry_after_secs: u64) -> Response {
    // `id` is null because the body was never read, so the caller's id is
    // unknown; JSON-RPC answers an unidentifiable request the same way.
    let body = RpcResponse {
        result: None,
        error: Some(RpcError {
            code: RPC_SERVER_ERROR,
            message: ReasonCode::RateLimited.as_str().to_owned(),
        }),
        id: serde_json::Value::Null,
    };
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{FeedBuffer, SharedBuffer};
    use axum::Router;
    use axum::body::Body;
    use std::net::IpAddr;
    use tokio::sync::RwLock;
    use tower::ServiceExt as _;

    /// The router exactly as `main` builds it, with an empty feed buffer.
    fn app(per_minute: u32) -> (Router, Arc<RpcLimit>) {
        let buffer: SharedBuffer = Arc::new(RwLock::new(FeedBuffer::default()));
        let limit = RpcLimit::new(per_minute);
        (crate::router(buffer, limit.clone()), limit)
    }

    const GETMEMPOOLINFO: &str =
        r#"{"jsonrpc":"1.0","id":1,"method":"getmempoolinfo","params":[]}"#;

    async fn send(
        app: &Router,
        method: &str,
        path: &str,
        peer: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut req = axum::http::Request::builder().method(method).uri(path);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let body = if method == "POST" {
            Body::from(GETMEMPOOLINFO)
        } else {
            Body::empty()
        };
        let mut req = req.body(body).unwrap();
        let peer: IpAddr = peer.parse().unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer, 40_000)));
        app.clone().oneshot(req).await.unwrap()
    }

    async fn rpc(app: &Router, peer: &str, headers: &[(&str, &str)]) -> Response {
        send(app, "POST", "/", peer, headers).await
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn rpc_n_plus_one_gets_429() {
        let (app, _) = app(3);
        for n in 1..=3 {
            let resp = rpc(&app, "127.0.0.1", &[]).await;
            assert_eq!(resp.status(), StatusCode::OK, "call {n}");
            // The feed is empty, so the handler itself answers -28.
            assert_eq!(body_json(resp).await["error"]["code"], -28, "call {n}");
        }
        let resp = rpc(&app, "127.0.0.1", &[]).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = resp.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry_after), "Retry-After {retry_after}");
        let json = body_json(resp).await;
        assert_eq!(json["error"]["message"], ReasonCode::RateLimited.as_str());
        assert_eq!(json["error"]["code"], RPC_SERVER_ERROR);
        assert!(json["result"].is_null());
        assert!(json["id"].is_null());
    }

    #[tokio::test]
    async fn health_stays_200_after_rpc_exhausted() {
        let (app, _) = app(3);
        for _ in 0..4 {
            rpc(&app, "127.0.0.1", &[]).await;
        }
        assert_eq!(
            rpc(&app, "127.0.0.1", &[]).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        for _ in 0..50 {
            let resp = send(&app, "GET", "/health", "127.0.0.1", &[]).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn forwarded_headers_never_change_the_bucket() {
        let (app, _) = app(3);
        for n in 1..=3 {
            let spoof = format!("203.0.113.{n}");
            let resp = rpc(
                &app,
                "10.0.0.5",
                &[
                    ("x-forwarded-for", spoof.as_str()),
                    ("cf-connecting-ip", spoof.as_str()),
                ],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "call {n}");
        }
        let resp = rpc(
            &app,
            "10.0.0.5",
            &[
                ("x-forwarded-for", "203.0.113.99"),
                ("cf-connecting-ip", "203.0.113.99"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn distinct_peers_distinct_buckets() {
        let (app, _) = app(3);
        for _ in 0..3 {
            assert_eq!(rpc(&app, "172.18.0.4", &[]).await.status(), StatusCode::OK);
        }
        assert_eq!(
            rpc(&app, "172.18.0.4", &[]).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(rpc(&app, "172.18.0.5", &[]).await.status(), StatusCode::OK);
        // An IPv4-mapped peer is the IPv4 peer, not a fresh budget.
        assert_eq!(
            rpc(&app, "::ffff:172.18.0.4", &[]).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn missing_connect_info_is_a_500_not_a_bypass() {
        let (app, _) = app(3);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from(GETMEMPOOLINFO))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn sweep_reports_and_resets_the_refusal_count() {
        let (app, limit) = app(1);
        for _ in 0..3 {
            rpc(&app, "127.0.0.1", &[]).await;
        }
        assert_eq!(limit.sweep(), 2);
        assert_eq!(limit.sweep(), 0);
    }

    #[test]
    fn retry_after_rounds_up_inside_one_to_sixty() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1_001)), 2);
        assert_eq!(retry_after_secs(Duration::from_secs(60)), 60);
        assert_eq!(retry_after_secs(Duration::from_secs(61)), 60);
    }
}
