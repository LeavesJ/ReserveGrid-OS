//! Health and readiness probes for the SV2 gateway.
//!
//! `/healthz` is a liveness probe (200 if process is running).
//! `/readyz` returns 200 when all readiness conditions are met per the
//! scope document's truth table, or 503 with details on which conditions
//! are not satisfied.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{Json, extract::State, response::IntoResponse};
use http::StatusCode;
use reservegrid_common::reason::GatewayReason;
use serde::Serialize;

/// Readiness conditions tracked atomically.
///
/// Each flag corresponds to a row in the v1.0.0 scope readiness truth table.
#[derive(Clone)]
pub struct ReadinessState {
    /// Verifier TCP stream connected and not stale.
    pub verifier_connected: Arc<AtomicBool>,
    /// Verifier policy loaded (verifier `/ready` returned 200).
    pub policy_loaded: Arc<AtomicBool>,
    /// Upstream template source responded within staleness window.
    pub upstream_reachable: Arc<AtomicBool>,
    /// Noise NX credentials loaded and valid.
    pub noise_cert_loaded: Arc<AtomicBool>,
    /// SV2 miner-facing port accepting connections.
    pub listener_bound: Arc<AtomicBool>,
    /// Share upstream endpoint reachable (configurable).
    pub share_upstream_reachable: Arc<AtomicBool>,
    /// Shutdown drain in progress.
    pub draining: Arc<AtomicBool>,
    /// Degraded mode active (inline enforcement temporarily suspended).
    pub degraded: Arc<AtomicBool>,
}

impl ReadinessState {
    /// Create a new readiness state with all conditions unmet.
    pub fn new() -> Self {
        Self {
            verifier_connected: Arc::new(AtomicBool::new(false)),
            policy_loaded: Arc::new(AtomicBool::new(false)),
            upstream_reachable: Arc::new(AtomicBool::new(false)),
            noise_cert_loaded: Arc::new(AtomicBool::new(false)),
            listener_bound: Arc::new(AtomicBool::new(false)),
            share_upstream_reachable: Arc::new(AtomicBool::new(false)),
            draining: Arc::new(AtomicBool::new(false)),
            degraded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Check whether all required conditions for readiness are met.
    ///
    /// `requires_listener` should be true for inline and observe modes,
    /// false for shadow mode.
    pub fn is_ready(&self, requires_listener: bool) -> bool {
        if self.draining.load(Ordering::SeqCst) {
            return false;
        }
        let base = self.verifier_connected.load(Ordering::SeqCst)
            && self.policy_loaded.load(Ordering::SeqCst)
            && self.upstream_reachable.load(Ordering::SeqCst);
        if requires_listener {
            base && self.noise_cert_loaded.load(Ordering::SeqCst)
                && self.listener_bound.load(Ordering::SeqCst)
        } else {
            base
        }
    }

    /// Mark the service as draining (shutdown in progress).
    pub fn set_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// Enter degraded mode (inline enforcement temporarily suspended).
    pub fn set_degraded(&self) {
        self.degraded.store(true, Ordering::SeqCst);
    }

    /// Exit degraded mode (enforcement resumed).
    pub fn clear_degraded(&self) {
        self.degraded.store(false, Ordering::SeqCst);
    }

    /// Whether the gateway is currently in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }
}

impl Default for ReadinessState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    degraded: Option<bool>,
}

/// Liveness probe: returns 200 if the process is running.
#[allow(clippy::unused_async)]
pub async fn healthz() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        reason_code: None,
        degraded: None,
    })
}

/// Readiness probe: returns 200 when fully operational, 503 otherwise.
///
/// In production, the `requires_listener` flag is derived from the gateway
/// mode at router construction time. For this handler, we default to true
/// (inline/observe). Shadow mode wires a different handler.
#[allow(clippy::unused_async)]
pub async fn readyz(State(state): State<ReadinessState>) -> impl IntoResponse {
    // Draining always wins: the process is shutting down regardless of
    // degraded state, so load balancers must stop sending traffic.
    if state.draining.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                reason_code: Some(GatewayReason::ShutdownDrain.as_str()),
                degraded: None,
            }),
        );
    }
    let is_degraded = state.is_degraded();
    // Degraded gateway is still ready (miners stay connected) but
    // enforcement is suspended. The probe returns 200 with a degraded
    // flag so load balancers and dashboards can distinguish the state.
    if state.is_ready(true) || is_degraded {
        let status = if is_degraded { "degraded" } else { "ok" };
        (
            StatusCode::OK,
            Json(HealthResponse {
                status,
                reason_code: None,
                degraded: Some(is_degraded),
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                reason_code: Some(GatewayReason::StartupPending.as_str()),
                degraded: None,
            }),
        )
    }
}

/// Readiness probe variant for shadow mode (no listener required).
#[allow(clippy::unused_async)]
pub async fn readyz_shadow(State(state): State<ReadinessState>) -> impl IntoResponse {
    if state.is_ready(false) {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                reason_code: None,
                degraded: None,
            }),
        )
    } else if state.draining.load(Ordering::SeqCst) {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                reason_code: Some(GatewayReason::ShutdownDrain.as_str()),
                degraded: None,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                reason_code: Some(GatewayReason::StartupPending.as_str()),
                degraded: None,
            }),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt;

    fn test_app(state: ReadinessState) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .with_state(state)
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let app = test_app(ReadinessState::new());
        let req = axum::extract::Request::builder()
            .uri("/healthz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_503_when_not_ready() {
        let app = test_app(ReadinessState::new());
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_returns_200_when_all_conditions_met() {
        let state = ReadinessState::new();
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        state.noise_cert_loaded.store(true, Ordering::SeqCst);
        state.listener_bound.store(true, Ordering::SeqCst);

        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_503_during_drain() {
        let state = ReadinessState::new();
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        state.noise_cert_loaded.store(true, Ordering::SeqCst);
        state.listener_bound.store(true, Ordering::SeqCst);
        state.set_draining();

        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn shadow_readiness_does_not_require_listener() {
        let state = ReadinessState::new();
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        // noise_cert_loaded and listener_bound are false
        assert!(state.is_ready(false));
        assert!(!state.is_ready(true));
    }

    #[test]
    fn degraded_flag_lifecycle() {
        let state = ReadinessState::new();
        assert!(!state.is_degraded());
        state.set_degraded();
        assert!(state.is_degraded());
        state.clear_degraded();
        assert!(!state.is_degraded());
    }

    #[tokio::test]
    async fn readyz_returns_200_when_degraded() {
        let state = ReadinessState::new();
        // Not all conditions met, but degraded flag is set.
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        state.set_degraded();

        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["degraded"], true);
    }

    #[tokio::test]
    async fn readyz_returns_ok_after_recovery() {
        let state = ReadinessState::new();
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        state.noise_cert_loaded.store(true, Ordering::SeqCst);
        state.listener_bound.store(true, Ordering::SeqCst);
        // Enter then exit degraded mode.
        state.set_degraded();
        state.clear_degraded();

        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["degraded"], false);
    }

    #[tokio::test]
    async fn draining_takes_precedence_over_degraded() {
        let state = ReadinessState::new();
        state.verifier_connected.store(true, Ordering::SeqCst);
        state.policy_loaded.store(true, Ordering::SeqCst);
        state.upstream_reachable.store(true, Ordering::SeqCst);
        state.noise_cert_loaded.store(true, Ordering::SeqCst);
        state.listener_bound.store(true, Ordering::SeqCst);
        state.set_degraded();
        state.set_draining();

        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Drain should override degraded and return 503.
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
