//! Rate limiting middleware.
//!
//! Token bucket algorithm, keyed by client IP. Configurable via
//! `policy.rate_limit_requests_per_sec` and `policy.rate_limit_burst`.
//! Exceeded limits return `reason_code: rate_limited` with `Retry-After`.

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode};
use reservegrid_common::{ErrorResponse, ReasonCode};
use tokio::sync::Mutex;
use tracing::debug;

/// Default maximum number of per-IP token buckets kept in memory.
/// When the map exceeds this count, the least recently used entry is evicted.
pub const DEFAULT_MAX_IP_BUCKETS: usize = 10_000;

/// Shared rate limiter state.
#[derive(Clone)]
pub struct RateLimitState {
    pub requests_per_sec: u32,
    pub burst: u32,
    max_entries: usize,
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
}

impl RateLimitState {
    /// Create a new rate limiter with the given policy parameters.
    pub fn new(requests_per_sec: u32, burst: u32) -> Self {
        Self::with_max_entries(requests_per_sec, burst, DEFAULT_MAX_IP_BUCKETS)
    }

    /// Create a new rate limiter with an explicit per-IP bucket cap.
    pub fn with_max_entries(requests_per_sec: u32, burst: u32, max_entries: usize) -> Self {
        Self {
            requests_per_sec,
            burst,
            max_entries,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            last_refill: Instant::now(),
        }
    }

    /// Attempt to consume one token. Returns `true` if allowed.
    fn try_consume(&mut self, rate: u32, burst: u32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Refill tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * f64::from(rate)).min(f64::from(burst));

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Middleware that enforces per-IP token bucket rate limiting.
///
/// When no `ConnectInfo` is available (e.g., in tests without a real TCP
/// listener), the middleware allows the request through without rate limiting.
#[allow(clippy::significant_drop_tightening)]
pub async fn rate_limit_layer(
    State(state): State<RateLimitState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP; if unavailable, skip rate limiting.
    let client_ip = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());

    if let Some(ip) = client_ip {
        let mut buckets = state.buckets.lock().await;

        // Evict the least recently used entry when at capacity and the
        // incoming IP is not already tracked.
        if buckets.len() >= state.max_entries
            && !buckets.contains_key(&ip)
            && let Some(oldest_ip) = buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(ip, _)| *ip)
        {
            debug!(evicted_ip = %oldest_ip, map_size = buckets.len(), "IP rate limiter LRU eviction");
            buckets.remove(&oldest_ip);
        }

        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(state.burst));

        if !bucket.try_consume(state.requests_per_sec, state.burst) {
            return reject_rate_limited(state.requests_per_sec);
        }
    }

    next.run(req).await
}

fn reject_rate_limited(rate: u32) -> Response {
    let retry_after = if rate > 0 { 1 } else { 60 };

    let body = ErrorResponse {
        reason_code: ReasonCode::RateLimited,
        reason_detail: "rate limit exceeded".into(),
        request_id: None,
    };

    let mut resp = (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
    if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
        resp.headers_mut().insert("retry-after", val);
    }
    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_allows_burst() {
        let mut bucket = TokenBucket::new(3);
        assert!(bucket.try_consume(1, 3));
        assert!(bucket.try_consume(1, 3));
        assert!(bucket.try_consume(1, 3));
        // Burst exhausted
        assert!(!bucket.try_consume(1, 3));
    }

    #[tokio::test]
    async fn lru_eviction_caps_map_size() {
        let state = RateLimitState::with_max_entries(100, 10, 3);
        let mut buckets = state.buckets.lock().await;

        // Fill to capacity with 3 IPs.
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        let ip4: IpAddr = "10.0.0.4".parse().unwrap();

        buckets.insert(ip1, TokenBucket::new(10));
        // Backdate ip1 so it becomes the oldest.
        buckets.get_mut(&ip1).unwrap().last_refill = Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap();
        buckets.insert(ip2, TokenBucket::new(10));
        buckets.insert(ip3, TokenBucket::new(10));
        assert_eq!(buckets.len(), 3);

        // Simulate what the middleware does: evict oldest when at cap.
        if buckets.len() >= 3
            && !buckets.contains_key(&ip4)
            && let Some(oldest_ip) = buckets
                .iter()
                .min_by_key(|(_, b)| b.last_refill)
                .map(|(ip, _)| *ip)
        {
            buckets.remove(&oldest_ip);
        }
        buckets.insert(ip4, TokenBucket::new(10));

        assert_eq!(buckets.len(), 3);
        assert!(
            !buckets.contains_key(&ip1),
            "oldest IP should have been evicted"
        );
        assert!(buckets.contains_key(&ip4), "new IP should be present");
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(1);
        assert!(bucket.try_consume(100, 1)); // use the one token
        assert!(!bucket.try_consume(100, 1)); // empty

        // Simulate time passing by backdating last_refill
        bucket.last_refill = Instant::now()
            .checked_sub(std::time::Duration::from_millis(50))
            .unwrap();
        // 100 rps * 0.05s = 5 tokens refilled, capped at burst=1
        assert!(bucket.try_consume(100, 1));
    }
}
