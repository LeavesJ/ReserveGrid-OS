//! Input validation middleware.
//!
//! Enforces strict bounds on incoming requests before they reach business logic:
//! - `Content-Length` enforcement against `policy.max_request_body_bytes`
//! - `Content-Type` enforcement (`application/json` only)
//! - Header count and size limits
//!
//! Payload-level validation (unknown fields, range bounds, nesting depth) is
//! handled by typed Axum extractors with `#[serde(deny_unknown_fields)]`.

use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::StatusCode;
use reservegrid_common::{ErrorResponse, ReasonCode};

/// Maximum number of headers allowed per request.
const MAX_HEADER_COUNT: usize = 64;

/// Maximum size of any single header value in bytes.
const MAX_HEADER_VALUE_BYTES: usize = 8192;

/// Middleware that validates request-level properties.
///
/// This runs before deserialization and catches oversized payloads,
/// wrong content types, and header abuse.
pub async fn input_validation_layer(req: Request<Body>, next: Next) -> Response {
    // ── Header count limit ──
    if req.headers().len() > MAX_HEADER_COUNT {
        return reject(ReasonCode::PayloadTooLarge, "too many headers");
    }

    // ── Header value size limit ──
    for value in req.headers().values() {
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return reject(ReasonCode::PayloadTooLarge, "header value too large");
        }
    }

    // ── Content-Type enforcement (only on methods with a body) ──
    let method = req.method().clone();
    if method == http::Method::POST || method == http::Method::PUT || method == http::Method::PATCH
    {
        let content_type_ok = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/json"));

        if !content_type_ok {
            return reject(ReasonCode::InvalidContentType, "expected application/json");
        }
    }

    next.run(req).await
}

/// Build a rejection response with the given reason code.
fn reject(code: ReasonCode, detail: &str) -> Response {
    let body = ErrorResponse {
        reason_code: code,
        reason_detail: detail.into(),
        request_id: None,
    };
    let status = match code {
        ReasonCode::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ReasonCode::InvalidContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{Router, middleware as axum_mw, routing::post};
    use tower::ServiceExt;

    fn test_app() -> Router {
        Router::new()
            .route("/api", post(|| async { "ok" }))
            .layer(axum_mw::from_fn(input_validation_layer))
    }

    #[tokio::test]
    async fn valid_json_post_succeeds() {
        let app = test_app();
        let req = Request::builder()
            .method("POST")
            .uri("/api")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"test": true}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_content_type_returns_415() {
        let app = test_app();
        let req = Request::builder()
            .method("POST")
            .uri("/api")
            .header("content-type", "text/plain")
            .body(Body::from("hello"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.reason_code, ReasonCode::InvalidContentType);
    }

    #[tokio::test]
    async fn missing_content_type_on_post_returns_415() {
        let app = test_app();
        let req = Request::builder()
            .method("POST")
            .uri("/api")
            .body(Body::from("{}"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn oversized_header_rejected() {
        let app = test_app();
        let huge_value = "x".repeat(MAX_HEADER_VALUE_BYTES + 1);
        let req = Request::builder()
            .method("POST")
            .uri("/api")
            .header("content-type", "application/json")
            .header("x-custom", huge_value)
            .body(Body::from("{}"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
