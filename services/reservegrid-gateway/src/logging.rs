//! Structured logging setup for the gateway.
//!
//! Configures `tracing-subscriber` with two output modes:
//! - JSON (production): machine-parseable structured logs
//! - Pretty (development): human-readable colored output
//!
//! Controlled by `VELDRA_LOG_FORMAT` (`json` or `pretty`, default `json`) and
//! `VELDRA_LOG_FILTER` (an `EnvFilter` directive, default `info`).

use tracing_subscriber::{EnvFilter, fmt};

/// Initialize the global tracing subscriber.
///
/// Reads `VELDRA_LOG_FORMAT` and `VELDRA_LOG_FILTER` from the environment.
/// This function must be called exactly once at startup.
///
/// # Panics
///
/// Panics if the global subscriber has already been set.
pub fn init() {
    let filter =
        EnvFilter::try_from_env("VELDRA_LOG_FILTER").unwrap_or_else(|_| EnvFilter::new("info"));

    let format = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "json".into());

    match format.as_str() {
        "pretty" => {
            fmt::Subscriber::builder()
                .with_env_filter(filter)
                .pretty()
                .init();
        }
        _ => {
            // Default to JSON for production
            fmt::Subscriber::builder()
                .with_env_filter(filter)
                .json()
                .init();
        }
    }
}

/// Initialize a no-op subscriber for tests that want tracing but no output.
///
/// Safe to call multiple times; subsequent calls are silently ignored.
#[cfg(test)]
pub fn init_test() {
    let _ = fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::new("off"))
        .try_init();
}
