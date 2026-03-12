//! Health and readiness probe endpoints.
//!
//! `GET /healthz` returns 200 if the process is running (liveness probe).
//! `GET /readyz` returns 200 when the service is fully operational, or 503
//! when it is in shutdown drain mode or upstream is unreachable.
//!
//! Neither endpoint exposes version numbers, config values, or internal state.
//! Both are excluded from authentication and rate limiting at the router level.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::{Json, extract::State, response::IntoResponse};
use http::StatusCode;
use reservegrid_common::reason::GatewayReason;
use serde::Serialize;

/// Shared readiness state, toggled during shutdown drain.
#[derive(Clone)]
pub struct ReadinessState {
    /// Set to `false` when the service begins graceful shutdown.
    pub ready: Arc<AtomicBool>,
}

impl ReadinessState {
    /// Create a new readiness state that starts as ready.
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Mark the service as not ready (used during shutdown drain).
    pub fn set_not_ready(&self) {
        self.ready.store(false, Ordering::SeqCst);
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
}

/// Liveness probe: returns 200 if the process is running.
#[allow(clippy::unused_async)] // Axum handlers must be async
pub async fn healthz() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        reason_code: None,
    })
}

/// Readiness probe: returns 200 when fully operational, 503 otherwise.
#[allow(clippy::unused_async)] // Axum handlers must be async
pub async fn readyz(State(state): State<ReadinessState>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) {
        (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok",
                reason_code: None,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                reason_code: Some(GatewayReason::ShutdownDrain.as_str()),
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
    async fn readyz_returns_200_when_ready() {
        let app = test_app(ReadinessState::new());
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_returns_503_during_shutdown() {
        let state = ReadinessState::new();
        state.set_not_ready();
        let app = test_app(state);
        let req = axum::extract::Request::builder()
            .uri("/readyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["status"], "not_ready");
        assert_eq!(parsed["reason_code"], "shutdown_drain");
    }
}
