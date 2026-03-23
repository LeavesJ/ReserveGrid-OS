//! Desktop client configuration.
//!
//! Loads from `$VELDRA_DESKTOP_CONFIG` or `~/.config/reservegrid/desktop.toml`.
//! Falls back to localhost defaults for development.

use serde::Deserialize;
use std::path::PathBuf;
use tracing::info;

/// Configuration for the desktop client.
///
/// Service URLs point to the compose backend stack. The desktop app
/// communicates with these directly (no HTTP proxy layer in between).
#[derive(Debug, Clone, Deserialize)]
pub struct DesktopConfig {
    /// Base URL of the pool-verifier HTTP API.
    #[serde(default = "default_verifier_url")]
    pub verifier_url: String,

    /// Base URL of the template-manager HTTP API.
    #[serde(default = "default_template_url")]
    pub template_url: String,

    /// Base URL of the sv2-gateway HTTP API.
    #[serde(default = "default_gateway_url_opt")]
    pub gateway_url: Option<String>,

    /// License key string. Can also be set via `VELDRA_LICENSE_KEY` env var.
    #[serde(default)]
    pub license_key: Option<String>,

    /// Additional health probe endpoints.
    #[serde(default)]
    pub health_probes: Vec<HealthProbe>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthProbe {
    pub name: String,
    pub url: String,
}

fn default_verifier_url() -> String {
    "http://127.0.0.1:8081".to_string()
}

fn default_template_url() -> String {
    "http://127.0.0.1:8082".to_string()
}

fn default_gateway_url() -> String {
    "http://127.0.0.1:8080".to_string()
}

fn default_gateway_url_opt() -> Option<String> {
    Some(default_gateway_url())
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            verifier_url: default_verifier_url(),
            template_url: default_template_url(),
            gateway_url: Some(default_gateway_url()),
            license_key: None,
            health_probes: Vec::new(),
        }
    }
}

impl DesktopConfig {
    /// Load configuration from file or environment, falling back to defaults.
    ///
    /// Search order:
    /// 1. `VELDRA_DESKTOP_CONFIG` env var (explicit path)
    /// 2. `~/.config/reservegrid/desktop.toml` (XDG convention)
    /// 3. Built-in defaults (localhost URLs, no license key)
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::find_config_path();

        let mut cfg = match path {
            Some(p) => {
                info!(path = %p.display(), "loading desktop config");
                let contents = std::fs::read_to_string(&p).map_err(|e| ConfigError::Io {
                    path: p.display().to_string(),
                    source: e,
                })?;
                toml::from_str::<Self>(&contents).map_err(|e| ConfigError::Parse {
                    path: p.display().to_string(),
                    source: e,
                })?
            }
            None => {
                info!("no config file found, using defaults");
                Self::default()
            }
        };

        // Environment overrides — same VELDRA_ prefix convention.
        if let Ok(v) = std::env::var("VELDRA_VERIFIER_URL") {
            cfg.verifier_url = v;
        }
        if let Ok(v) = std::env::var("VELDRA_TEMPLATE_URL") {
            cfg.template_url = v;
        }
        if let Ok(v) = std::env::var("VELDRA_GATEWAY_URL") {
            cfg.gateway_url = Some(v);
        }
        if let Ok(v) = std::env::var("VELDRA_LICENSE_KEY") {
            cfg.license_key = Some(v);
        }

        Ok(cfg)
    }

    fn find_config_path() -> Option<PathBuf> {
        // Explicit env var takes priority.
        if let Ok(p) = std::env::var("VELDRA_DESKTOP_CONFIG") {
            let path = PathBuf::from(p);
            if path.exists() {
                return Some(path);
            }
        }

        // XDG config directory.
        if let Some(config_dir) = dirs::config_dir() {
            let path = config_dir.join("reservegrid").join("desktop.toml");
            if path.exists() {
                return Some(path);
            }
        }

        None
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: String,
        source: std::io::Error,
    },
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot read config {path}: {source}"),
            Self::Parse { path, source } => write!(f, "invalid config {path}: {source}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_localhost_urls() {
        let cfg = DesktopConfig::default();
        assert!(cfg.verifier_url.contains("127.0.0.1:8081"));
        assert!(cfg.template_url.contains("127.0.0.1:8082"));
        assert!(cfg.gateway_url.as_deref().unwrap_or("").contains("127.0.0.1:8080"));
        assert!(cfg.license_key.is_none());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
verifier_url = "http://pool-server:8080"
template_url = "http://pool-server:8082"
license_key = "veldra_lic_test123"
"#;
        let cfg: DesktopConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.verifier_url, "http://pool-server:8080");
        assert_eq!(cfg.license_key.as_deref(), Some("veldra_lic_test123"));
    }
}
