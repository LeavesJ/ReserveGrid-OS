use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Extension, Router, middleware,
    routing::{get, post},
};
use tokio::net::TcpListener;
use tracing::info;

use crate::dashboard;
use crate::handlers::{
    self, BootConfigSnapshot, ConfigFilePath, RuntimeSettings, SharedRuntimeSettings,
};
use crate::ingress::api_key_middleware;
use crate::metrics;
use crate::state::AppState;
use crate::types::LogReloadHandle;
use crate::verdicts::VerdictLog;

/// Run the HTTP server with public and protected routes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_http_server(
    bind_addr: String,
    verdict_log: VerdictLog,
    ui_mode: String,
    app_state: AppState,
    log_reload: LogReloadHandle,
    config_file: PathBuf,
    metrics_registry: reservegrid_common::metrics::SharedRegistry,
    metrics: metrics::SharedVerifierMetrics,
) -> anyhow::Result<()> {
    // Public routes: /health and /ready bypass API key auth.
    let public = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::readiness_check))
        .route("/metrics", get(metrics::verifier_metrics_handler));

    // Protected routes: require API key when VELDRA_API_SECRET is set.
    let protected = Router::new()
        .route("/", get(dashboard::ui_index))
        .route("/ui", get(dashboard::ui_index))
        .route("/verdicts", get(handlers::get_verdicts))
        .route("/verdicts/log", get(handlers::get_verdict_log))
        .route("/verdicts.csv", get(handlers::get_verdicts_csv))
        .route("/stats", get(handlers::get_stats))
        .route("/policy", get(handlers::get_policy))
        .route("/policy/apply", post(handlers::apply_policy))
        .route("/policy/apply_toml", post(handlers::apply_policy_toml))
        .route("/mempool", get(handlers::get_mempool_proxy))
        .route("/meta", get(handlers::get_meta))
        .route("/settings", get(handlers::get_settings))
        .route("/settings/apply", post(handlers::apply_settings))
        .route("/settings/save", post(handlers::save_settings))
        .layer(middleware::from_fn(api_key_middleware));

    let boot_log_level = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let boot_mempool_url = std::env::var("VELDRA_MEMPOOL_URL").unwrap_or_default();
    let boot_log_format = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into());

    let runtime_settings: SharedRuntimeSettings =
        Arc::new(std::sync::RwLock::new(RuntimeSettings {
            log_level: boot_log_level.clone(),
            mempool_url: boot_mempool_url.clone(),
        }));

    // Snapshot of the config values at boot for pending_restart detection.
    let boot_snapshot: BootConfigSnapshot = Arc::new(handlers::VerifierDiskConfig {
        log_level: boot_log_level,
        log_format: boot_log_format,
        mempool_url: boot_mempool_url,
    });

    let config_path: ConfigFilePath = Arc::new(config_file);

    // Ensure parent directory exists for the config file.
    if let Some(parent) = config_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let app = public
        .merge(protected)
        .with_state(app_state.clone())
        .layer(Extension(verdict_log))
        .layer(Extension(ui_mode))
        .layer(Extension(Arc::new(log_reload)))
        .layer(Extension(runtime_settings))
        .layer(Extension(boot_snapshot))
        .layer(Extension(config_path))
        .layer(Extension(metrics_registry))
        .layer(Extension(metrics));

    let addr: std::net::SocketAddr = bind_addr.parse()?;

    let cert_path = std::env::var("VELDRA_TLS_CERT").ok();
    let key_path = std::env::var("VELDRA_TLS_KEY").ok();

    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            info!(addr = %addr, tls = "file-based", "HTTPS listening");
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await?;
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        (None, None) if std::env::var("VELDRA_TLS_SELF_SIGNED").as_deref() == Ok("1") => {
            info!(addr = %addr, tls = "self-signed", "HTTPS listening");
            tracing::warn!("self-signed certificate active, not suitable for production");
            let (cert_pem, key_pem) = crate::ingress::generate_self_signed_cert()?;
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem).await?;
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        _ => {
            info!(addr = %addr, tls = "none", "HTTP listening");
            let listener = TcpListener::bind(&bind_addr).await?;
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }

    Ok(())
}
