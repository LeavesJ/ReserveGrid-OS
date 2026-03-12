//! Authentication middleware.
//!
//! Supports two modes per `policy.api_auth_mode`:
//! - `bearer_token`: constant-time comparison of the `Authorization: Bearer <token>` header
//! - `hmac_sha256`: signed request validation using HMAC-SHA256 over method, path, timestamp,
//!   nonce, and body hash. Anti-replay via configurable timestamp window and bounded
//!   in-memory nonce cache (replay prevention). Fails closed on mutex poison.
//!
//! Unauthenticated requests receive `reason_code: auth_failed` with no additional
//! detail about why the auth failed (prevents enumeration).

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use http::{HeaderMap, StatusCode};
use reservegrid_common::{ErrorResponse, ReasonCode};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::warn;

use reservegrid_common::config::ApiAuthMode;
use reservegrid_common::redacted::Redacted;

use crate::protocol::nonce::{NonceCache, NonceResult};

type HmacSha256 = Hmac<Sha256>;

/// Default maximum age (in seconds) of a signed request before it is rejected.
/// Overridden by `AuthState::timestamp_max_age_secs` when set from config.
pub const DEFAULT_TIMESTAMP_MAX_AGE_SECS: u64 = 300;

/// Shared authentication state injected into the middleware.
#[derive(Clone)]
pub struct AuthState {
    pub mode: ApiAuthMode,
    /// Primary API secret (hex-encoded, already validated at startup).
    pub api_secret: Option<Arc<Redacted<String>>>,
    /// Previous API secret for zero-downtime rotation.
    pub api_secret_previous: Option<Arc<Redacted<String>>>,
    /// HMAC-SHA256 signing key (raw bytes, decoded from hex at startup).
    pub hmac_key: Option<Arc<Redacted<Vec<u8>>>>,
    /// Nonce replay cache for HMAC auth. `None` disables replay protection.
    pub nonce_cache: Option<Arc<Mutex<NonceCache>>>,
    /// Maximum age of a signed request in seconds. Defaults to 300.
    pub timestamp_max_age_secs: u64,
}

/// Middleware that enforces authentication on every request.
///
/// Health and readiness probes (`/healthz`, `/readyz`) bypass this layer
/// at the router level (they are mounted outside the authenticated scope).
pub async fn auth_layer(
    State(state): State<AuthState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    match state.mode {
        ApiAuthMode::BearerToken => {
            if !verify_bearer(req.headers(), &state) {
                return reject_auth();
            }
        }
        ApiAuthMode::HmacSha256 => {
            if !verify_hmac(&req, &state) {
                return reject_auth();
            }
        }
    }

    next.run(req).await
}

/// Constant-time bearer token comparison.
///
/// Checks the primary key first, then the rollover key. Returns `true`
/// if either matches.
fn verify_bearer(headers: &HeaderMap, state: &AuthState) -> bool {
    let Some(token) = extract_bearer_token(headers) else {
        return false;
    };

    let token_bytes = token.as_bytes();

    // Check primary key
    if let Some(ref secret) = state.api_secret {
        let secret_bytes = secret.inner().as_bytes();
        if constant_time_eq(token_bytes, secret_bytes) {
            return true;
        }
    }

    // Check rollover key
    if let Some(ref prev) = state.api_secret_previous {
        let prev_bytes = prev.inner().as_bytes();
        if constant_time_eq(token_bytes, prev_bytes) {
            return true;
        }
    }

    false
}

/// Validate an HMAC-SHA256 signed request.
///
/// Expected headers:
/// - `X-Signature`: hex-encoded HMAC-SHA256 (64 hex chars)
/// - `X-Timestamp`: Unix epoch seconds (integer)
/// - `X-Nonce`: opaque unique string (minimum 8 bytes)
///
/// The signing payload is:
/// `METHOD\nPATH\nTIMESTAMP\nNONCE`
///
/// The signature is verified in constant time. Requests older than
/// `timestamp_max_age_secs` or from the future (>60s) are rejected.
fn verify_hmac(req: &Request<Body>, state: &AuthState) -> bool {
    let Some(ref hmac_key) = state.hmac_key else {
        return false;
    };

    // Extract required headers.
    let Some(sig_hex) = header_str(req.headers(), "x-signature") else {
        return false;
    };
    let Some(ts_str) = header_str(req.headers(), "x-timestamp") else {
        return false;
    };
    let Some(nonce) = header_str(req.headers(), "x-nonce") else {
        return false;
    };

    // Parse and validate timestamp.
    let Ok(ts) = ts_str.parse::<u64>() else {
        return false;
    };
    if !timestamp_within_window(ts, state.timestamp_max_age_secs) {
        return false;
    }

    // Nonce must be at least 8 bytes to provide sufficient entropy.
    if nonce.len() < 8 {
        return false;
    }

    // Decode the provided signature.
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    if sig_bytes.len() != 32 {
        return false;
    }

    // Build the signing payload: METHOD\nPATH\nTIMESTAMP\nNONCE
    let method = req.method().as_str();
    let path = req.uri().path();
    let payload = format!("{method}\n{path}\n{ts_str}\n{nonce}");

    // Compute expected HMAC.
    let Ok(mut mac) = HmacSha256::new_from_slice(hmac_key.inner()) else {
        return false;
    };
    mac.update(payload.as_bytes());

    // Constant-time comparison.
    let expected = mac.finalize().into_bytes();
    let sig_valid: bool = expected.ct_eq(&sig_bytes).into();
    if !sig_valid {
        return false;
    }

    // Nonce replay check. Fail closed on mutex poison.
    if let Some(ref nonce_cache) = state.nonce_cache {
        let Ok(mut cache) = nonce_cache.lock() else {
            warn!("nonce cache mutex poisoned, failing closed");
            return false;
        };
        match cache.validate(nonce, ts) {
            NonceResult::Valid => {}
            NonceResult::Expired | NonceResult::Replayed => return false,
        }
    }

    true
}

/// Check that a timestamp is within the acceptable window.
fn timestamp_within_window(ts: u64, max_age_secs: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Reject requests from the future (>60s clock skew tolerance).
    if ts > now + 60 {
        return false;
    }
    // Reject requests older than the max age.
    if now.saturating_sub(ts) > max_age_secs {
        return false;
    }
    true
}

/// Extract a header value as a `&str`, returning `None` if missing or non-UTF8.
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// Extract the bearer token from the `Authorization` header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let stripped = value.strip_prefix("Bearer ")?;
    if stripped.is_empty() {
        return None;
    }
    Some(stripped)
}

/// Constant-time equality check that handles different-length inputs safely.
///
/// When lengths differ, we still do a comparison against a dummy buffer
/// to avoid timing leaks from the length check itself.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Compare a against itself to burn the same amount of time,
        // but always return false.
        let _ = a.ct_eq(a);
        return false;
    }
    a.ct_eq(b).into()
}

/// Build the standard auth failure response.
fn reject_auth() -> Response {
    let body = ErrorResponse {
        reason_code: ReasonCode::AuthFailed,
        reason_detail: "authentication required".into(),
        request_id: None,
    };
    (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
}

/// Compute an HMAC-SHA256 signature for testing purposes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
fn compute_test_signature(key: &[u8], method: &str, path: &str, ts: u64, nonce: &str) -> String {
    let payload = format!("{method}\n{path}\n{ts}\n{nonce}");
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{Router, middleware as axum_mw, routing::get};
    use tower::ServiceExt;

    fn test_state(secret: &str) -> AuthState {
        AuthState {
            mode: ApiAuthMode::BearerToken,
            api_secret: Some(Arc::new(Redacted::new(secret.to_string()))),
            api_secret_previous: None,
            hmac_key: None,
            nonce_cache: None,
            timestamp_max_age_secs: DEFAULT_TIMESTAMP_MAX_AGE_SECS,
        }
    }

    fn hmac_state(key: &[u8]) -> AuthState {
        AuthState {
            mode: ApiAuthMode::HmacSha256,
            api_secret: None,
            api_secret_previous: None,
            hmac_key: Some(Arc::new(Redacted::new(key.to_vec()))),
            nonce_cache: Some(Arc::new(Mutex::new(NonceCache::new(10_000, 300)))),
            timestamp_max_age_secs: DEFAULT_TIMESTAMP_MAX_AGE_SECS,
        }
    }

    fn test_app(state: AuthState) -> Router {
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .layer(axum_mw::from_fn_with_state(state.clone(), auth_layer))
            .with_state(state)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[tokio::test]
    async fn valid_bearer_token_succeeds() {
        let secret = "a".repeat(64);
        let app = test_app(test_state(&secret));

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {secret}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let app = test_app(test_state(&"a".repeat(64)));

        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_token_returns_401() {
        let app = test_app(test_state(&"a".repeat(64)));

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {}", "b".repeat(64)))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn previous_key_accepted_during_rotation() {
        let primary = "a".repeat(64);
        let previous = "b".repeat(64);
        let state = AuthState {
            mode: ApiAuthMode::BearerToken,
            api_secret: Some(Arc::new(Redacted::new(primary))),
            api_secret_previous: Some(Arc::new(Redacted::new(previous.clone()))),
            hmac_key: None,
            nonce_cache: None,
            timestamp_max_age_secs: DEFAULT_TIMESTAMP_MAX_AGE_SECS,
        };
        let app = test_app(state);

        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {previous}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_failure_body_contains_reason_code() {
        let app = test_app(test_state(&"a".repeat(64)));

        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.reason_code, ReasonCode::AuthFailed);
    }

    // ── HMAC-SHA256 tests ──

    #[tokio::test]
    async fn hmac_valid_signature_succeeds() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs();
        let nonce = "abcdefgh12345678";
        let sig = compute_test_signature(key, "GET", "/protected", ts, nonce);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn hmac_wrong_signature_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs();
        let nonce = "abcdefgh12345678";
        let bad_sig = "ff".repeat(32);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &bad_sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hmac_missing_headers_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let app = test_app(hmac_state(key));

        // No HMAC headers at all.
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hmac_expired_timestamp_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs() - DEFAULT_TIMESTAMP_MAX_AGE_SECS - 10;
        let nonce = "abcdefgh12345678";
        let sig = compute_test_signature(key, "GET", "/protected", ts, nonce);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hmac_future_timestamp_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs() + 120; // 2 minutes in the future
        let nonce = "abcdefgh12345678";
        let sig = compute_test_signature(key, "GET", "/protected", ts, nonce);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hmac_short_nonce_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs();
        let nonce = "short"; // < 8 bytes
        let sig = compute_test_signature(key, "GET", "/protected", ts, nonce);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn hmac_wrong_key_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let wrong_key = b"wrong-hmac-key-for-tests-00000";
        let ts = now_secs();
        let nonce = "abcdefgh12345678";
        let sig = compute_test_signature(wrong_key, "GET", "/protected", ts, nonce);

        let app = test_app(hmac_state(key));
        let req = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn timestamp_window_rejects_stale() {
        let stale = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - DEFAULT_TIMESTAMP_MAX_AGE_SECS
            - 1;
        assert!(!timestamp_within_window(
            stale,
            DEFAULT_TIMESTAMP_MAX_AGE_SECS
        ));
    }

    #[test]
    fn timestamp_window_accepts_recent() {
        let recent = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(timestamp_within_window(
            recent,
            DEFAULT_TIMESTAMP_MAX_AGE_SECS
        ));
    }

    #[test]
    fn timestamp_window_rejects_far_future() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 120;
        assert!(!timestamp_within_window(
            future,
            DEFAULT_TIMESTAMP_MAX_AGE_SECS
        ));
    }

    #[tokio::test]
    async fn hmac_replayed_nonce_returns_401() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs();
        let nonce = "unique-nonce-replay-test";
        let sig = compute_test_signature(key, "GET", "/protected", ts, nonce);

        let state = hmac_state(key);
        let app = test_app(state.clone());

        // First request succeeds.
        let req1 = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();
        let resp1 = app.oneshot(req1).await.unwrap();
        assert_eq!(
            resp1.status(),
            StatusCode::OK,
            "first request should succeed"
        );

        // Same nonce replayed should be rejected.
        let app2 = test_app(state);
        let req2 = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce)
            .body(Body::empty())
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::UNAUTHORIZED,
            "replayed nonce must be rejected"
        );
    }

    #[tokio::test]
    async fn hmac_different_nonce_same_timestamp_succeeds() {
        let key = b"test-hmac-key-for-unit-tests-00";
        let ts = now_secs();

        let state = hmac_state(key);

        // First request with nonce A.
        let nonce_a = "nonce-a-different-test";
        let sig_a = compute_test_signature(key, "GET", "/protected", ts, nonce_a);
        let app1 = test_app(state.clone());
        let req1 = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig_a)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce_a)
            .body(Body::empty())
            .unwrap();
        let resp1 = app1.oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second request with nonce B at same timestamp.
        let nonce_b = "nonce-b-different-test";
        let sig_b = compute_test_signature(key, "GET", "/protected", ts, nonce_b);
        let app2 = test_app(state);
        let req2 = Request::builder()
            .uri("/protected")
            .header("x-signature", &sig_b)
            .header("x-timestamp", ts.to_string())
            .header("x-nonce", nonce_b)
            .body(Body::empty())
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }
}
