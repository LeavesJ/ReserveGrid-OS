mod db;
mod email;
mod handlers;
mod password;
mod rate_limit;
mod session;

use axum::{
    Json, Router,
    extract::State,
    http::HeaderValue,
    routing::{get, post},
};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tracing::{error, info, warn};

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: db::DbPool,
    pub smtp: Option<email::SmtpConfig>,
    pub admin_email: String,
    pub site_url: String,
    pub auth_url: String,
    pub session_ttl_hours: u64,
    pub rate_limiter: Arc<rate_limit::RateLimiter>,
    /// Multiplier applied to all per-endpoint rate limits. Default 1.
    /// Set higher in integration test environments to avoid false 429s.
    pub rate_limit_multiplier: u32,
    /// When true, trust `x-forwarded-for` header for client IP extraction.
    /// Enable only when rg-auth sits behind a trusted reverse proxy.
    pub trust_proxy: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured logging via tracing. Respects VELDRA_LOG_FILTER (default: info).
    let filter = env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    let bind_addr = env::var("VELDRA_AUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:3030".to_string());
    let db_path = env::var("VELDRA_AUTH_DB").unwrap_or_else(|_| "data/auth.db".to_string());
    let admin_email =
        env::var("VELDRA_AUTH_ADMIN_EMAIL").unwrap_or_else(|_| "admin@localhost".to_string());
    let site_url = env::var("VELDRA_AUTH_SITE_URL")
        .unwrap_or_else(|_| "http://localhost:8084".to_string())
        .trim_end_matches('/')
        .to_string();
    let auth_url = env::var("VELDRA_AUTH_URL").unwrap_or_else(|_| format!("http://{bind_addr}"));
    let allowed_origin = env::var("VELDRA_AUTH_ALLOWED_ORIGIN").unwrap_or_else(|_| {
        warn!("VELDRA_AUTH_ALLOWED_ORIGIN not set; defaulting to http://localhost:8084");
        "http://localhost:8084".to_string()
    });
    let session_ttl_hours: u64 = env::var("VELDRA_AUTH_SESSION_TTL_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(168); // 7 days

    let rate_max_ips: usize = env::var("VELDRA_AUTH_RATE_MAX_IPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let rate_global_ceiling: Option<u32> = env::var("VELDRA_AUTH_RATE_GLOBAL_CEILING")
        .ok()
        .and_then(|s| s.parse().ok());
    let rate_limit_multiplier: u32 = env::var("VELDRA_AUTH_RATE_LIMIT_MULTIPLIER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .max(1);
    let trust_proxy = env::var("VELDRA_AUTH_TRUST_PROXY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    info!(
        db = %db_path,
        admin = %admin_email,
        site = %site_url,
        origin = %allowed_origin,
        rate_max_ips = rate_max_ips,
        rate_global_ceiling = ?rate_global_ceiling,
        rate_limit_multiplier = rate_limit_multiplier,
        trust_proxy = trust_proxy,
        "rg-auth config loaded",
    );

    let pool = db::init(&db_path)?;
    let smtp = email::SmtpConfig::from_env();
    if smtp.is_none() {
        info!("SMTP not configured, emails will print to stdout");
    }

    let rate_limiter = Arc::new(rate_limit::RateLimiter::with_config(
        rate_max_ips,
        rate_global_ceiling,
    ));

    let state = AppState {
        db: pool.clone(),
        smtp,
        admin_email,
        site_url,
        auth_url,
        session_ttl_hours,
        rate_limiter: rate_limiter.clone(),
        rate_limit_multiplier,
        trust_proxy,
    };

    // Start background cleanup tasks
    tokio::spawn(cleanup_task(pool, rate_limiter));

    let cors = build_cors(&allowed_origin)?;

    let app = Router::new()
        .route("/auth/health", get(handlers::health))
        .route("/auth/register", post(handlers::register))
        .route("/auth/verify", get(handlers::verify_email))
        .route("/auth/login", post(handlers::login))
        .route("/auth/logout", post(handlers::logout))
        .route("/auth/session", get(handlers::session_check))
        .route("/auth/approve", get(handlers::approve))
        .route("/auth/deny", get(handlers::deny))
        .route("/auth/forgot-password", post(handlers::forgot_password))
        .route("/auth/reset-password", post(handlers::reset_password))
        .route("/auth/settings", get(auth_get_settings))
        // License key endpoints
        .route("/api/keys/validate", post(handlers::validate_key))
        .route("/auth/keys", get(handlers::list_keys))
        .route("/auth/keys/generate", post(handlers::generate_key))
        .route("/auth/keys/revoke", post(handlers::revoke_key))
        .with_state(state)
        .layer(cors)
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "rg-auth listening");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn auth_get_settings(State(state): State<AppState>) -> Json<serde_json::Value> {
    let log_level = env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let log_format = env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into());
    let smtp_host = env::var("VELDRA_AUTH_SMTP_HOST").unwrap_or_default();
    let smtp_port: u16 = env::var("VELDRA_AUTH_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let smtp_user = env::var("VELDRA_AUTH_SMTP_USER").unwrap_or_default();
    let smtp_pass_set = env::var("VELDRA_AUTH_SMTP_PASS").is_ok();

    let bind_addr = env::var("VELDRA_AUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:3030".into());
    let db_path = env::var("VELDRA_AUTH_DB").unwrap_or_else(|_| "data/auth.db".into());

    Json(serde_json::json!({
        "log_level": log_level,
        "log_format": log_format,
        "bind_addr": bind_addr,
        "db_path": db_path,
        "session_ttl_hours": state.session_ttl_hours,
        "admin_email": state.admin_email,
        "site_url": state.site_url,
        "auth_url": state.auth_url,
        "allowed_origin": env::var("VELDRA_AUTH_ALLOWED_ORIGIN").unwrap_or_else(|_| "http://localhost:8084".into()),
        "smtp_host": smtp_host,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_pass_set": smtp_pass_set,
        "smtp_configured": state.smtp.is_some(),
        "rate_max_ips": env::var("VELDRA_AUTH_RATE_MAX_IPS").unwrap_or_else(|_| "10000".into()),
        "rate_global_ceiling": env::var("VELDRA_AUTH_RATE_GLOBAL_CEILING").unwrap_or_else(|_| "none".into()),
        "trust_proxy": state.trust_proxy,
    }))
}

/// Background task that periodically cleans up expired sessions and stale rate limit entries.
async fn cleanup_task(pool: db::DbPool, rate_limiter: Arc<rate_limit::RateLimiter>) {
    // Cleanup expired sessions every hour
    let session_cleanup = tokio::spawn({
        let pool = pool.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                if let Ok(conn) = pool.lock()
                    && let Err(e) = db::cleanup_expired_sessions(&conn)
                {
                    error!(error = ?e, "session cleanup failed");
                }
            }
        }
    });

    // Cleanup stale rate limit entries every 5 minutes
    let rate_limit_cleanup = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            rate_limiter.cleanup();
        }
    });

    // Wait for either task to finish (they won't in normal operation)
    let _ = tokio::join!(session_cleanup, rate_limit_cleanup);
}

fn build_cors(allowed_origin: &str) -> anyhow::Result<CorsLayer> {
    if allowed_origin == "*" {
        anyhow::bail!("VELDRA_AUTH_ALLOWED_ORIGIN=\"*\" is not allowed; set a specific origin");
    }
    let header_value: HeaderValue = allowed_origin
        .parse()
        .map_err(|_| anyhow::anyhow!("VELDRA_AUTH_ALLOWED_ORIGIN must be a valid header value"))?;
    let origin = AllowOrigin::exact(header_value);

    Ok(CorsLayer::new()
        .allow_origin(origin)
        .allow_methods(AllowMethods::any())
        .allow_headers(AllowHeaders::any()))
}
