//! Canonical error response types.
//!
//! Every rejection surfaced to an external client uses `ErrorResponse`.
//! `reason_code` is the stable machine contract. `reason_detail` is human
//! readable and may change between releases.

use serde::{Deserialize, Serialize};

use crate::reason::ReasonCode;

/// Wire format for error responses on the gateway HTTP API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Stable, machine-parseable reason code.
    pub reason_code: ReasonCode,

    /// Human-readable detail. May change between releases.
    pub reason_detail: String,

    /// Server-generated request ID for traceability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn error_response_serde_round_trip() {
        let resp = ErrorResponse {
            reason_code: ReasonCode::AuthFailed,
            reason_detail: "missing Authorization header".into(),
            request_id: Some("01945abc-def0-7000-8000-000000000001".into()),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ErrorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.reason_code, ReasonCode::AuthFailed);
        assert_eq!(back.reason_detail, resp.reason_detail);
        assert_eq!(back.request_id, resp.request_id);
    }

    #[test]
    fn error_response_omits_null_request_id() {
        let resp = ErrorResponse {
            reason_code: ReasonCode::RateLimited,
            reason_detail: "exceeded burst".into(),
            request_id: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(
            !json.contains("request_id"),
            "null request_id should be omitted"
        );
    }

    #[test]
    fn error_response_reason_code_is_snake_case_in_json() {
        let resp = ErrorResponse {
            reason_code: ReasonCode::PayloadTooLarge,
            reason_detail: "body exceeded limit".into(),
            request_id: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(
            json.contains("\"payload_too_large\""),
            "reason_code should serialize as snake_case: {json}",
        );
    }
}
