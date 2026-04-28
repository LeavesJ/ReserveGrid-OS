//! `rg-desktop`: `ReserveGrid` OS native desktop client.
//!
//! Tauri application that replaces `rg-dashboard` (HTTP reverse proxy + embedded SPA)
//! with native IPC commands. The React frontend calls Tauri commands instead of
//! `fetch("/api/...")`, and the Rust backend forwards requests to compose services.
//!
//! Auth is replaced by offline license key validation on app startup.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod license;
mod proxy;
mod tray;
mod update;

use std::sync::Arc;
use tauri::{Manager, RunEvent, WindowEvent};
use tracing::info;

/// Shared application state accessible from all IPC commands.
pub struct AppState {
    pub config: config::DesktopConfig,
    pub client: reqwest::Client,
    pub license: license::LicenseInfo,
}

fn main() {
    // Structured logging — same env vars as the rest of the stack.
    let filter = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| String::from("info"));
    tracing_subscriber::fmt().with_env_filter(&filter).init();

    let cfg = match config::DesktopConfig::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    info!(
        verifier = %redact_url_credentials(&cfg.verifier_url),
        templates = %redact_url_credentials(&cfg.template_url),
        feed_adapter = ?cfg.feed_adapter_url.as_deref(),
        "starting rg-desktop"
    );

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to build HTTP client");
            std::process::exit(1);
        }
    };

    // License key: loaded from config, validated on startup.
    // If no key is present, the app opens to the onboarding screen.
    let license = license::LicenseInfo::load_from_config(&cfg);

    let state = Arc::new(AppState {
        config: cfg,
        client,
        license,
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            proxy::proxy_request,
            proxy::health_check,
            proxy::get_dashboard_settings,
            license::get_license_status,
            license::set_license_key,
            license::clear_license,
            update::check_for_update,
            update::install_update,
        ])
        .setup(|app| {
            let state = app.state::<Arc<AppState>>();
            info!(
                license_valid = state.license.is_valid(),
                "rg-desktop ready"
            );

            // System tray — the handle must stay alive or macOS drops
            // the event handlers while keeping the icon visible but inert.
            match tray::setup_tray(app.handle()) {
                Ok(tray_handle) => { app.manage(tray_handle); }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to initialize system tray, continuing without it");
                }
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "tauri runtime error");
            std::process::exit(1);
        })
        .run(|app, event| {
            match event {
                RunEvent::WindowEvent {
                    label,
                    event: WindowEvent::CloseRequested { api, .. },
                    ..
                } => {
                    // Always hide the window instead of destroying it.
                    // This covers both the red X button and Cmd+Q.
                    // The only way to fully exit is the tray "Quit ReserveGrid"
                    // menu item, which calls std::process::exit() directly.
                    api.prevent_close();
                    if let Some(window) = app.get_webview_window(&label) {
                        let _ = window.hide();
                    }
                    info!(window = %label, "window hidden to tray");
                }
                RunEvent::ExitRequested { api, .. } => {
                    // Always prevent the event-driven exit path. The process
                    // stays alive so the system tray remains visible. The tray
                    // "Quit ReserveGrid" menu item bypasses this with
                    // std::process::exit().
                    api.prevent_exit();
                }
                _ => {}
            }
        });
}

/// Redact userinfo from URLs so credentials never appear in logs.
fn redact_url_credentials(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after_scheme = &url[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            return format!(
                "{}://***@{}",
                &url[..scheme_end],
                &after_scheme[at_pos + 1..]
            );
        }
    }
    url.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn binary_compiles() {
        // Compilation smoke test.
    }
}
