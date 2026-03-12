//! Request ID middleware.
//!
//! Assigns a UUID v7 `request_id` to every incoming request and propagates
//! it in the `X-Request-Id` response header and the tracing span.

use axum::{extract::Request, middleware::Next, response::Response};
use http::HeaderValue;

/// Header name for the server-generated request identifier.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Middleware that generates a UUID v7 request ID and attaches it to
/// both the response headers and the current tracing span.
pub async fn request_id_layer(req: Request, next: Next) -> Response {
    let id = uuid::Uuid::now_v7().to_string();
    let span = tracing::Span::current();
    span.record("request_id", &id);

    let mut resp = next.run(req).await;

    if let Ok(val) = HeaderValue::from_str(&id) {
        resp.headers_mut().insert(REQUEST_ID_HEADER, val);
    }

    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{Router, middleware as axum_mw, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    #[tokio::test]
    async fn response_contains_request_id_header() {
        let app = Router::new()
            .route("/ping", get(|| async { "pong" }))
            .layer(axum_mw::from_fn(request_id_layer));

        let req = Request::builder()
            .uri("/ping")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().contains_key(REQUEST_ID_HEADER),
            "missing {REQUEST_ID_HEADER} header",
        );
        let val = resp
            .headers()
            .get(REQUEST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap();
        // UUID v7 is 36 chars with hyphens
        assert_eq!(val.len(), 36, "request_id should be a UUID");
    }
}
