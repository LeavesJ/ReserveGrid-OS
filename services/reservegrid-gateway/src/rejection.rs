//! Rejection logging contract.
//!
//! Every rejection in the gateway produces a structured log event with
//! at minimum: `reason_code`, `request_id`, `client_id` (redacted if
//! configured), and the policy context that triggered the rejection.
//!
//! This module provides the `log_rejection` helper that all middleware
//! and handlers use to ensure the observability contract is met.

use reservegrid_common::ReasonCode;

/// Log a rejection event with the mandatory observability fields.
///
/// All parameters are captured as structured tracing fields so they
/// appear as first-class keys in JSON log output and can be aggregated
/// by dashboards and alerting rules.
pub fn log_rejection(
    reason_code: ReasonCode,
    request_id: Option<&str>,
    client_id: Option<&str>,
    detail: &str,
) {
    tracing::warn!(
        reason_code = reason_code.as_str(),
        request_id = request_id.unwrap_or("unknown"),
        client_id = client_id.unwrap_or("unknown"),
        reason_detail = detail,
        "request rejected",
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Smoke test: calling `log_rejection` does not panic.
    #[test]
    fn log_rejection_does_not_panic() {
        // No subscriber installed, but tracing is designed to be safe in that case.
        log_rejection(
            ReasonCode::AuthFailed,
            Some("01945abc-def0-7000-8000-000000000001"),
            Some("[REDACTED]"),
            "missing Authorization header",
        );
    }

    #[test]
    fn log_rejection_with_none_fields() {
        log_rejection(ReasonCode::RateLimited, None, None, "burst exceeded");
    }
}
