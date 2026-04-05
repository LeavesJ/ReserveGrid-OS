//! Security response headers middleware.
//!
//! Applies the headers from Appendix B unconditionally to every response.

use axum::{extract::Request, middleware::Next, response::Response};
use http::HeaderValue;

/// Apply all mandatory security headers to the response.
pub async fn security_headers_layer(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    );

    resp
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{Router, middleware as axum_mw, routing::get};
    use tower::ServiceExt;

    #[tokio::test]
    async fn all_security_headers_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(axum_mw::from_fn(security_headers_layer));

        let req = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        let h = resp.headers();

        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            h.get("strict-transport-security").unwrap(),
            "max-age=63072000; includeSubDomains"
        );
        assert_eq!(h.get("cache-control").unwrap(), "no-store");
        assert_eq!(
            h.get("content-security-policy").unwrap(),
            "default-src 'none'"
        );
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        assert!(
            h.get("permissions-policy").is_some(),
            "missing permissions-policy header"
        );
    }
}
