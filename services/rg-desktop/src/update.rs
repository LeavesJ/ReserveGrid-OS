//! In-app update checking and installation.
//!
//! Wraps `tauri-plugin-updater` behind two IPC commands:
//! - `check_for_update` — queries the configured endpoint, returns version
//!   info and release notes if a newer version is available.
//! - `install_update` — downloads and installs a previously discovered
//!   update, then prompts the user to relaunch.
//!
//! The update endpoint and signing public key are configured in
//! `tauri.conf.json` under `plugins.updater`.

use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;
use tracing::{info, warn};

/// Response payload for the `check_for_update` IPC command.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheckResult {
    /// Whether a newer version is available.
    pub update_available: bool,
    /// The new version string (e.g. "1.2.0"), if available.
    pub version: Option<String>,
    /// Release notes / changelog body, if the endpoint provides them.
    pub body: Option<String>,
    /// Current app version for display.
    pub current_version: String,
}

/// Tauri IPC command: check for a newer version.
///
/// Queries the update endpoint configured in `tauri.conf.json`. Returns
/// immediately with the result; does not download anything.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<UpdateCheckResult, String> {
    let current_version = app
        .config()
        .version
        .clone()
        .unwrap_or_else(|| "unknown".into());

    info!("checking for updates (current: {current_version})");

    let updater = app.updater().map_err(|e| {
        warn!(error = %e, "failed to initialize updater");
        format!("updater not available: {e}")
    })?;

    let update = updater.check().await.map_err(|e| {
        warn!(error = %e, "update check failed");
        format!("update check failed: {e}")
    })?;

    if let Some(u) = update {
        info!(
            new_version = %u.version,
            "update available"
        );
        Ok(UpdateCheckResult {
            update_available: true,
            version: Some(u.version.clone()),
            body: u.body.clone(),
            current_version,
        })
    } else {
        info!("no update available, already on latest");
        Ok(UpdateCheckResult {
            update_available: false,
            version: None,
            body: None,
            current_version,
        })
    }
}

/// Tauri IPC command: download and install a pending update.
///
/// Downloads the update bundle, verifies the signature against the pubkey
/// in `tauri.conf.json`, and installs it. On success the app should be
/// relaunched for the new version to take effect.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<String, String> {
    info!("downloading and installing update");

    let updater = app.updater().map_err(|e| {
        warn!(error = %e, "failed to initialize updater");
        format!("updater not available: {e}")
    })?;

    let update = updater.check().await.map_err(|e| {
        warn!(error = %e, "update check failed during install");
        format!("update check failed: {e}")
    })?;

    let Some(update) = update else {
        return Err("no update available".into());
    };

    let version = update.version.clone();

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| {
            warn!(error = %e, "update install failed");
            format!("install failed: {e}")
        })?;

    info!(version = %version, "update installed, relaunch required");
    Ok(format!("v{version} installed. Relaunch to apply."))
}
