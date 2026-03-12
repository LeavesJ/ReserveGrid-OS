//! Shared Prometheus / `OpenMetrics` helpers.
//!
//! Each service creates its own [`prometheus_client::registry::Registry`],
//! registers its counters and gauges, then serves the registry via
//! [`render_metrics`] on a `GET /metrics` route.

use std::sync::Arc;

use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

/// Encode the `Registry` into `OpenMetrics` text format.
///
/// Returns `(status_code, content_type, body)` suitable for an axum handler.
/// Kept framework-agnostic so callers can wrap in their own response type.
pub fn render_metrics(registry: &Registry) -> (u16, &'static str, String) {
    let mut buf = String::with_capacity(4096);
    // `encode` writes OpenMetrics text exposition format.
    match encode(&mut buf, registry) {
        Ok(()) => (
            200,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
            buf,
        ),
        Err(_) => (
            500,
            "text/plain; charset=utf-8",
            "metrics encoding failed\n".into(),
        ),
    }
}

/// Type alias used as an axum `Extension` layer for the metrics registry.
pub type SharedRegistry = Arc<Registry>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use prometheus_client::metrics::counter::Counter;

    #[test]
    fn render_empty_registry() {
        let reg = Registry::default();
        let (status, ct, body) = render_metrics(&reg);
        assert_eq!(status, 200);
        assert!(ct.contains("openmetrics-text"));
        assert!(body.contains("# EOF"));
    }

    #[test]
    fn render_counter() {
        let mut reg = Registry::default();
        let counter = Counter::<u64>::default();
        reg.register("test_total", "a test counter", counter.clone());
        counter.inc();
        counter.inc();
        let (status, _, body) = render_metrics(&reg);
        assert_eq!(status, 200);
        assert!(body.contains("test_total"));
        assert!(body.contains('2'));
    }
}
