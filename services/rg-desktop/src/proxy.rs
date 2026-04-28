//! Tauri IPC commands that replace the `rg-dashboard` HTTP reverse proxy.
//!
//! Each command forwards a request to the appropriate compose backend service
//! and returns the response as JSON. The frontend calls these via
//! `invoke("proxy_request", { service, path, method, body })` instead of
//! `fetch("/api/verifier/stats")`.

use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};

use crate::AppState;

/// Unified proxy command. Replaces all individual `proxy_verifier`,
/// `proxy_templates`, `proxy_gateway` handlers from `rg-dashboard`.
///
/// # Arguments
/// * `service` — one of "verifier", "templates", "gateway"
/// * `path` — the path after the service prefix (e.g. "stats", "latest", "settings")
/// * `method` — "GET" or "POST"
/// * `body` — optional JSON body for POST requests
///
/// # Returns
/// JSON response from the upstream service, or an error object.
#[tauri::command]
pub async fn proxy_request(
    state: tauri::State<'_, Arc<AppState>>,
    service: String,
    path: String,
    method: Option<String>,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let base_url = match service.as_str() {
        "verifier" => &state.config.verifier_url,
        "templates" => &state.config.template_url,
        "gateway" => {
            let Some(ref url) = state.config.gateway_url else {
                return Err("gateway_url not configured".to_string());
            };
            url
        }
        other => {
            warn!(service = %other, "unknown service requested");
            return Err("unknown service".to_string());
        }
    };

    let url = format!("{base_url}/{path}");
    let http_method = method.as_deref().unwrap_or("GET");

    debug!(service = %service, path = %path, method = %http_method, "proxying IPC request");

    let mut req = match http_method {
        "POST" => state.client.post(&url),
        "GET" => state.client.get(&url),
        "PUT" => state.client.put(&url),
        "DELETE" => state.client.delete(&url),
        other => {
            warn!(method = %other, "unsupported HTTP method");
            return Err("unsupported method".to_string());
        }
    };

    req = req.header("content-type", "application/json");

    if let Some(json_body) = body {
        req = req.json(&json_body);
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();

            if status >= 400 {
                warn!(service = %service, path = %path, %status, "upstream returned error");
                return Err(format!("upstream returned {status}"));
            }

            // Try to parse as JSON; if not, wrap in a value.
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(json) => Ok(json),
                Err(_) => Ok(serde_json::json!({ "raw": text })),
            }
        }
        Err(e) => {
            warn!(service = %service, path = %path, error = %e, "upstream request failed");
            Err("upstream unavailable".to_string())
        }
    }
}

/// Health check aggregating all configured services.
/// Replaces `health_aggregate` from `rg-dashboard/src/proxy.rs`.
#[tauri::command]
pub async fn health_check(
    state: tauri::State<'_, Arc<AppState>>,
) -> Result<serde_json::Value, String> {
    let mut results = Vec::new();

    // Core services.
    let checks = vec![
        (
            "pool-verifier",
            format!("{}/health", state.config.verifier_url),
        ),
        (
            "template-manager",
            format!("{}/health", state.config.template_url),
        ),
    ];

    for (name, url) in &checks {
        let result = probe_health(&state.client, name, url).await;
        results.push(result);
    }

    // Shadow feed pipeline health when feed_adapter_url is configured.
    if let Some(ref fa_url) = state.config.feed_adapter_url {
        let result = probe_health(
            &state.client,
            "rg-feed-adapter",
            &format!("{fa_url}/health"),
        )
        .await;
        results.push(result);
    }

    // Optional gateway.
    if let Some(ref gw_url) = state.config.gateway_url {
        let result = probe_health(&state.client, "sv2-gateway", &format!("{gw_url}/healthz")).await;
        results.push(result);
    }

    // Additional health probes from config.
    for probe in &state.config.health_probes {
        let url = format!("{}/healthz", probe.url);
        let result = probe_health(&state.client, &probe.name, &url).await;
        results.push(result);
    }

    Ok(serde_json::json!({ "services": results }))
}

/// Dashboard settings exposed to the frontend.
/// Replaces `dashboard_get_settings` from `rg-dashboard`.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // tauri::command requires owned params
pub fn get_dashboard_settings(state: tauri::State<'_, Arc<AppState>>) -> serde_json::Value {
    let log_level = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let log_format = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());
    let deploy_mode = std::env::var("VELDRA_MODE").unwrap_or_else(|_| "shadow".into());

    // Internal service URLs are intentionally omitted; infrastructure
    // details should not be exposed to the webview frontend.
    serde_json::json!({
        "log_level": log_level,
        "log_format": log_format,
        "deploy_mode": deploy_mode,
        "gateway_configured": state.config.gateway_url.is_some(),
        "client": "rg-desktop",
    })
}

#[allow(clippy::cast_possible_truncation)]
async fn probe_health(client: &reqwest::Client, name: &str, url: &str) -> serde_json::Value {
    let start = Instant::now();
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
            warn!(service = name, status = %resp.status(), "health check non-200");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn proxy_module_compiles() {
        // Compilation smoke test; integration tests require running services.
    }
}
