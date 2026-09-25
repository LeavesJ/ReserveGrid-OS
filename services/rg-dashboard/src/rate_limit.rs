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
//!
//! Also once a minute, a `warn!` names the connecting address of requests
//! that carried a forwarding header but were counted against that address.
//! Behind a reverse proxy the dashboard has not been told about, that is
//! every request, and every client shares the proxy's one budget; nothing
//! else would say so.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
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

/// Headers a reverse proxy sets to name the client it relays for. Only
/// their presence is checked, to notice a proxy nobody configured; which
/// one is read, if any, is `[rate_limit] client_ip_header`.
const FORWARDING_HEADERS: [&str; 3] = ["x-forwarded-for", "cf-connecting-ip", "forwarded"];

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
    /// What [`ClientAddr::note_unattributed`] has counted since the last
    /// [`ClientAddr::take_unattributed`].
    unattributed: Mutex<Option<Unattributed>>,
}

/// Requests that named a client in a forwarding header and were counted
/// against their TCP peer anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unattributed {
    /// The TCP peer of the most recent one.
    pub last_peer: IpAddr,
    /// How many since the last sweep, from any peer.
    pub requests: u64,
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
            unattributed: Mutex::new(None),
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

    /// Count a request that carries a forwarding header but was keyed by
    /// its TCP peer (`client` is `peer`). From an address that is not in
    /// `trusted_proxies`, or with no trust configured at all, that is
    /// usually a reverse proxy nobody told the dashboard about, and every
    /// client behind it then shares one budget, so one client at about 10
    /// requests a second locks the rest out of `/api`, login included. From
    /// a trusted proxy it is a proxy that did not send the configured
    /// header. A client that writes the header itself also lands here,
    /// which costs one log line a minute.
    fn note_unattributed(&self, peer: IpAddr, client: IpAddr, headers: &HeaderMap) {
        if client.to_canonical() != peer.to_canonical()
            || !FORWARDING_HEADERS.iter().any(|h| headers.contains_key(*h))
        {
            return;
        }
        let peer = peer.to_canonical();
        let mut slot = self
            .unattributed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let seen = slot.get_or_insert(Unattributed {
            last_peer: peer,
            requests: 0,
        });
        seen.last_peer = peer;
        seen.requests = seen.requests.saturating_add(1);
    }

    /// What [`Self::note_unattributed`] counted since the last call, and
    /// reset. Both classes' sweeps call this; whichever runs first logs.
    fn take_unattributed(&self) -> Option<Unattributed> {
        self.unattributed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
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

    /// Log and reset the refusal count, log any requests whose forwarding
    /// header went unused, and drop clients idle for two windows. Returns
    /// the refusal count it logged.
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
        if let Some(seen) = self.client.take_unattributed() {
            warn!(
                peer = %seen.last_peer,
                requests = seen.requests,
                trusted_proxies = self.client.trusted_proxies.len(),
                "requests in the last minute carried a forwarding header but were counted \
                 against the connecting address; if a reverse proxy is at that address, every \
                 client behind it shares one request budget: set [rate_limit] trusted_proxies \
                 and client_ip_header (docs/deployment-runbook.md, Dashboard request limits)"
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
    class
        .client
        .note_unattributed(peer.ip(), client, req.headers());
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
