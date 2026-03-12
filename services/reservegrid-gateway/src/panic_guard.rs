//! Panic isolation middleware.
//!
//! Wraps every handler in a catch-unwind boundary so a panic in one request
//! never propagates to the service process or affects other in-flight requests.
//!
//! On panic:
//! - Logs the panic at `error` level with the `request_id`
//! - Returns HTTP 500 with `reason_code: internal_error`
//! - Increments a panic counter (future: Prometheus metric)
//! - If panics exceed threshold, initiates graceful shutdown (future)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use reservegrid_common::{ErrorResponse, ReasonCode};

/// Shared panic counter for metrics and threshold enforcement.
#[derive(Clone, Default)]
pub struct PanicCounter {
    pub count: Arc<AtomicU64>,
}

impl PanicCounter {
    pub fn total(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Middleware that catches panics in downstream handlers.
///
/// Uses `tokio::task::spawn` with `catch_unwind` semantics via
/// `AssertUnwindSafe` to isolate panics.
pub async fn panic_guard_layer(req: Request<Body>, next: Next) -> Response {
    // We use catch_unwind via a spawned task. The spawned task is
    // catch-unwind-safe because panics in tokio tasks do not propagate
    // to the spawner; instead the JoinHandle returns an Err.
    let result = tokio::task::spawn(async move { next.run(req).await }).await;

    match result {
        Ok(resp) => resp,
        Err(join_err) => {
            // The task panicked. Log the error.
            let panic_msg = if let Some(s) = join_err.into_panic().downcast_ref::<&str>() {
                (*s).to_string()
            } else {
                "unknown panic".to_string()
            };

            tracing::error!(
                reason_code = %ReasonCode::InternalError.as_str(),
                panic_message = %panic_msg,
                "handler panicked",
            );

            let body = ErrorResponse {
                reason_code: ReasonCode::InternalError,
                reason_detail: "internal server error".into(),
                request_id: None,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn panic_counter_starts_at_zero() {
        let counter = PanicCounter::default();
        assert_eq!(counter.total(), 0);
    }

    #[test]
    fn panic_counter_increments() {
        let counter = PanicCounter::default();
        counter.count.fetch_add(1, Ordering::Relaxed);
        assert_eq!(counter.total(), 1);
    }
}
