//! System tray integration for `ReserveGrid` OS.
//!
//! Shows the Veldra mark icon in the OS tray with a right-click menu:
//! - "Open Dashboard" — brings the main window to focus
//! - "Quit" — exits the app
//!
//! The tray icon provides a persistent presence even when the window is closed,
//! signaling that `ReserveGrid` is running.

use tauri::{
    AppHandle, Manager,
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_updater::UpdaterExt;
use tracing::{info, warn};

/// Show and focus the main window. Handles the hidden state left by
/// the `CloseRequested` handler in main.rs.
///
/// On macOS, a background process must activate itself before it can
/// bring windows to the foreground. The `WebviewWindow::show()` call
/// handles activation internally.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        info!("main window restored from tray");
    } else {
        tracing::warn!("main window not found, cannot restore");
    }
}

/// Build and attach the system tray icon.
///
/// Called during `tauri::Builder::setup`. Uses the app's default icon
/// (from `tauri.conf.json` bundle icons).
/// Returns the `TrayIcon` handle. The caller MUST keep this alive (e.g. via
/// `app.manage()`) or macOS will garbage-collect the event handlers while
/// the icon remains visually present but inert.
pub fn setup_tray(app: &AppHandle) -> Result<tauri::tray::TrayIcon, Box<dyn std::error::Error>> {
    let open_item = MenuItemBuilder::with_id("open", "Open Dashboard").build(app)?;
    let update_item = MenuItemBuilder::with_id("check_update", "Check for Updates…").build(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit ReserveGrid").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&open_item)
        .item(&update_item)
        .separator()
        .item(&quit_item)
        .build()?;

    let tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("ReserveGrid OS")
        .on_menu_event(move |app, event| {
            match event.id().as_ref() {
                "open" => {
                    show_main_window(app);
                }
                "check_update" => {
                    info!("update check requested from tray");
                    let handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        match handle.updater() {
                            Ok(updater) => match updater.check().await {
                                Ok(Some(update)) => {
                                    info!(version = %update.version, "update available (from tray)");
                                    show_main_window(&handle);
                                }
                                Ok(None) => {
                                    info!("no update available (from tray)");
                                }
                                Err(e) => {
                                    warn!(error = %e, "tray update check failed");
                                }
                            },
                            Err(e) => {
                                warn!(error = %e, "updater not available");
                            }
                        }
                    });
                }
                "quit" => {
                    info!("quit requested from tray");
                    // Hard exit. std::process::exit bypasses the RunEvent
                    // handlers that prevent close/exit, so this is the only
                    // code path that actually terminates the process.
                    std::process::exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            // Left click on the tray icon opens the dashboard directly.
            if matches!(event, TrayIconEvent::Click { .. }) {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    info!("system tray initialized");
    Ok(tray)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn tray_module_compiles() {
        // Compilation smoke test.
    }
}
