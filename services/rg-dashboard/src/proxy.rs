use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::AppState;

/// Proxy requests to the pool-verifier.
/// Routes: `/api/verifier/{path}` to `{verifier_url}/{path}`
pub async fn proxy_verifier(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    proxy_to(
        &state.client,
        &state.config.verifier_url,
        &path,
        uri.query(),
        method,
        headers,
        body,
        None,
    )
    .await
}

/// Proxy requests to the template-manager.
/// Routes: `/api/templates/{path}` to `{template_url}/{path}`
pub async fn proxy_templates(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    proxy_to(
        &state.client,
        &state.config.template_url,
        &path,
        uri.query(),
        method,
        headers,
        body,
        None,
    )
    .await
}

/// Proxy requests to `rg-auth`.
/// Routes: `/api/auth/{path}` to `{auth_url}/auth/{path}`
///
/// Forwards `x-forwarded-for` so rg-auth rate limiting sees the real client IP
/// instead of the proxy's loopback address.
pub async fn proxy_auth(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let upstream_path = format!("auth/{path}");
    proxy_to(
        &state.client,
        &state.config.auth_url,
        &upstream_path,
        uri.query(),
        method,
        headers,
        body,
        Some(addr.ip()),
    )
    .await
}

/// Proxy requests to rg-auth `/keys/*`.
/// Routes: `/api/keys/{path}` to `{auth_url}/keys/{path}`
pub async fn proxy_keys(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let upstream_path = format!("keys/{path}");
    proxy_to(
        &state.client,
        &state.config.auth_url,
        &upstream_path,
        uri.query(),
        method,
        headers,
        body,
        Some(addr.ip()),
    )
    .await
}

/// Proxy requests to the sv2-gateway.
/// Routes: `/api/gateway/{path}` to `{gateway_url}/{path}`
pub async fn proxy_gateway(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    match &state.config.gateway_url {
        Some(url) => {
            proxy_to(
                &state.client,
                url,
                &path,
                uri.query(),
                method,
                headers,
                body,
                None,
            )
            .await
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_url not configured",
        )
            .into_response(),
    }
}

/// Aggregate health from all configured services.
/// Returns JSON with `services` array containing name, status, and `latency_ms` per service.
pub async fn health_aggregate(State(state): State<Arc<AppState>>) -> Response {
    let mut results = Vec::new();

    // Built-in service health checks
    let checks = [
        (
            "pool-verifier",
            format!("{}/health", state.config.verifier_url),
        ),
        (
            "template-manager",
            format!("{}/health", state.config.template_url),
        ),
        ("rg-auth", format!("{}/auth/health", state.config.auth_url)),
    ];

    for (name, url) in &checks {
        let result = probe_health(&state.client, name, url).await;
        results.push(result);
    }

    // First-class gateway health when gateway_url is configured.
    if let Some(gw_url) = &state.config.gateway_url {
        let result = probe_health(&state.client, "sv2-gateway", &format!("{gw_url}/healthz")).await;
        results.push(result);
    }

    // Configured health probes (additional gateways, etc.)
    for probe in &state.config.health_probes {
        let url = format!("{}/healthz", probe.url);
        let result = probe_health(&state.client, &probe.name, &url).await;
        results.push(result);
    }

    let body = serde_json::json!({ "services": results });
    (StatusCode::OK, axum::Json(body)).into_response()
}

#[allow(clippy::cast_possible_truncation)] // 5s timeout caps millis well within u64
async fn probe_health(client: &Client, name: &str, url: &str) -> serde_json::Value {
    let start = std::time::Instant::now();
    match client
        .get(url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let latency = start.elapsed().as_millis() as u64;
            serde_json::json!({
                "name": name,
                "status": "ok",
                "latency_ms": latency,
            })
        }
        Ok(resp) => {
            let latency = start.elapsed().as_millis() as u64;
            warn!(service = name, status = %resp.status(), "health check returned non-200");
            serde_json::json!({
                "name": name,
                "status": "degraded",
                "latency_ms": latency,
            })
        }
        Err(e) => {
            let latency = start.elapsed().as_millis() as u64;
            warn!(service = name, error = %e, "health check failed");
            serde_json::json!({
                "name": name,
                "status": "down",
                "latency_ms": latency,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn proxy_to(
    client: &Client,
    base_url: &str,
    path: &str,
    query: Option<&str>,
    method: Method,
    headers: HeaderMap,
    body: Body,
    forwarded_ip: Option<std::net::IpAddr>,
) -> Response {
    let url = match query {
        Some(q) => format!("{base_url}/{path}?{q}"),
        None => format!("{base_url}/{path}"),
    };
    debug!(upstream = %url, method = %method, "proxying request");

    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read request body");
            return (StatusCode::BAD_REQUEST, "request body too large").into_response();
        }
    };

    let mut req = client.request(method, &url);

    // Forward select headers.
    for key in ["content-type", "authorization", "accept"] {
        if let Some(val) = headers.get(key) {
            req = req.header(key, val);
        }
    }

    // Forward client IP so upstream rate limiting sees the real address.
    if let Some(ip) = forwarded_ip {
        req = req.header("x-forwarded-for", ip.to_string());
    }

    if !body_bytes.is_empty() {
        req = req.body(body_bytes);
    }

    match req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let resp_headers = resp.headers().clone();
            match resp.bytes().await {
                Ok(bytes) => {
                    let mut response = (status, bytes.to_vec()).into_response();
                    // Forward content-type from upstream
                    if let Some(ct) = resp_headers.get("content-type") {
                        response.headers_mut().insert("content-type", ct.clone());
                    }
                    response
                }
                Err(e) => {
                    warn!(error = %e, upstream = %url, "failed to read upstream response");
                    (StatusCode::BAD_GATEWAY, "upstream read error").into_response()
                }
            }
        }
        Err(e) => {
            warn!(error = %e, upstream = %url, "upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                format!("upstream unavailable: {url}"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn proxy_module_compiles() {
        // Compilation test; integration tests require running services.
    }
}
