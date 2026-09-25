//! Per-client request limits on the dashboard's `/api` routes.
//!
//! Two classes, each its own `reservegrid_common::rate_limit::RateLimiter`
//! (a sliding 60 s log per client, the same limiter rg-auth uses):
//!
//! * `api`: every `/api/*` route except `/api/health`. The budget is
//!   `[rate_limit] api_per_minute`, 600 by default.
//! * `fanout`: `GET /api/health`, which costs 3 to 6 serial upstream
//!   probes per call, so it gets a smaller fixed budget of its own.
//!
//! `/healthz` and the embedded SPA are not limited. `/healthz` is a
//! constant the compose healthchecks poll, and a 429 there would mark the
//! container unhealthy; the SPA is served from memory with no upstream
//! call, and a cold page load fetches several assets in one burst.
//!
//! A refused request gets 429, `Retry-After` in whole seconds, and an
//! `ErrorResponse` with `reason_code: rate_limited`. Each refusal is a
//! `debug!` line; once a minute each class logs a `warn!` with the count,
//! so a flood cannot fill the disk one line per request.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use reservegrid_common::rate_limit::RateLimiter;
use reservegrid_common::{ErrorResponse, ReasonCode};
use tracing::{debug, warn};

use crate::config::{ClientIpHeader, RateLimitConfig};

/// `GET /api/health` calls per client per 60 s. The SPA calls it every
/// 10 s, plus every 5 s while the shadow-gate probe runs, so at most 18 a
/// minute per tab; 120 covers about six tabs. A constant, not a knob: it
/// has one value and nobody has needed another.
pub const FANOUT_PER_MINUTE: u32 = 120;

/// Clients tracked per class before the least recently seen is evicted.
/// The same bound rg-auth runs with.
const MAX_TRACKED_CLIENTS: usize = 10_000;

/// How often each class logs its refusal count and drops idle clients.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Works out which client a request came from.
///
/// This exists because the limiter middleware and the two rg-auth proxies
/// (`proxy_auth`, `proxy_keys`, which forward the address as
/// `x-forwarded-for`) all need the same answer.
#[derive(Debug)]
pub struct ClientAddr {
    /// Canonical form, so `::ffff:127.0.0.1` in the file matches a peer of
    /// `127.0.0.1` and the other way round.
    trusted_proxies: Vec<IpAddr>,
    header: Option<ClientIpHeader>,
}

impl ClientAddr {
    pub fn from_config(cfg: &RateLimitConfig) -> Self {
        Self {
            trusted_proxies: cfg
                .trusted_proxies
                .iter()
                .map(IpAddr::to_canonical)
                .collect(),
            header: cfg.client_ip_header,
        }
    }

    /// The client's address. Without trust configured, or from a peer that
    /// is not a trusted proxy, this is `peer` exactly as the socket gave it,
    /// so the rg-auth proxies send the same bytes they always did. From a
    /// trusted proxy it is the address named in the configured header, or
    /// `peer` when the header is missing or does not parse.
    pub fn resolve(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let Some(header) = self.header else {
            return peer;
        };
        if !self.trusted_proxies.contains(&peer.to_canonical()) {
            return peer;
        }
        let named = match header {
            ClientIpHeader::CfConnectingIp => headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<IpAddr>().ok()),
            ClientIpHeader::XForwardedFor => self.rightmost_untrusted(headers),
        };
        named.map_or(peer, |ip| ip.to_canonical())
    }

    /// Walk `x-forwarded-for` from the right, past the trusted proxies. The
    /// first address that is not one of them is the client: the proxy
    /// nearest to us appended it, and anything the client wrote itself sits
    /// further left and is never reached. rg-auth takes the leftmost entry
    /// instead, which the client controls. An entry that does not parse
    /// ends the walk with no answer rather than skipping ahead to one.
    fn rightmost_untrusted(&self, headers: &HeaderMap) -> Option<IpAddr> {
        let mut entries = Vec::new();
        for line in headers.get_all("x-forwarded-for") {
            entries.extend(line.to_str().ok()?.split(','));
        }
        for entry in entries.into_iter().rev() {
            let ip = entry.trim().parse::<IpAddr>().ok()?.to_canonical();
            if !self.trusted_proxies.contains(&ip) {
                return Some(ip);
            }
        }
        None
    }
}

/// One limited class of routes.
pub struct LimitClass {
    name: &'static str,
    limiter: RateLimiter,
    per_minute: u32,
    client: Arc<ClientAddr>,
    rejected: AtomicU64,
}

impl LimitClass {
    pub fn new(name: &'static str, per_minute: u32, client: Arc<ClientAddr>) -> Arc<Self> {
        Arc::new(Self {
            name,
            limiter: RateLimiter::with_config(MAX_TRACKED_CLIENTS, None),
            per_minute,
            client,
            rejected: AtomicU64::new(0),
        })
    }

    /// Log and reset the refusal count, and drop clients idle for two
    /// windows. Returns the count it logged.
    pub fn sweep(&self) -> u64 {
        let rejected = self.rejected.swap(0, Ordering::Relaxed);
        if rejected > 0 {
            warn!(
                reason_code = ReasonCode::RateLimited.as_str(),
                class = self.name,
                rejected,
                "rate limiter rejected requests in the last minute"
            );
        }
        self.limiter.cleanup();
        rejected
    }
}

/// Run [`LimitClass::sweep`] every [`SWEEP_EVERY`] for the life of the
/// process.
pub fn spawn_sweeper(class: Arc<LimitClass>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.tick().await; // the first tick completes at once
        loop {
            tick.tick().await;
            class.sweep();
        }
    });
}

/// The middleware. `ConnectInfo` is an extractor, not an optional
/// extension: a server started without connect-info fails every limited
/// request with a 500 instead of quietly letting it through unlimited.
pub async fn enforce(
    State(class): State<Arc<LimitClass>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let client = class.client.resolve(peer.ip(), req.headers());
    match class.limiter.admit(bucket_key(client), class.per_minute) {
        Ok(()) => next.run(req).await,
        Err(wait) => {
            let retry_after_secs = retry_after_secs(wait);
            class.rejected.fetch_add(1, Ordering::Relaxed);
            debug!(
                reason_code = ReasonCode::RateLimited.as_str(),
                class = class.name,
                %client,
                retry_after_secs,
                "request rate limited"
            );
            too_many_requests(retry_after_secs)
        }
    }
}

/// The key a client is counted under. IPv6 is masked to its /64, because
/// one host normally holds a whole /64 and per-address keys would give it
/// 2^64 budgets. An IPv4-mapped IPv6 address counts as the IPv4 address.
fn bucket_key(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Whole seconds, rounded up so a client that waits this long is admitted,
/// and kept inside 1..=60 because the window is 60 s.
fn retry_after_secs(wait: Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).clamp(1, 60)
}

fn too_many_requests(retry_after_secs: u64) -> Response {
    let body = ErrorResponse {
        reason_code: ReasonCode::RateLimited,
        reason_detail: "rate limit exceeded".into(),
        request_id: None,
    };
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    resp
}

#[cfg(test)]
mod tests;
