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

#[allow(clippy::unnecessary_wraps)] // serde default must match the field type
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

        let mut cfg = if let Some(p) = path {
            info!(path = %p.display(), "loading desktop config");
            let contents = std::fs::read_to_string(&p).map_err(|e| ConfigError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
            toml::from_str::<Self>(&contents).map_err(|e| ConfigError::Parse {
                path: p.display().to_string(),
                source: e,
            })?
        } else {
            info!("no config file found, using defaults");
            Self::default()
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

    /// Resolve the config file path for writing. Returns the first existing
    /// path, or the XDG default if no file exists yet.
    fn writable_config_path() -> Result<PathBuf, ConfigError> {
        // Explicit env var takes priority (even if the file doesn't exist yet).
        if let Ok(p) = std::env::var("VELDRA_DESKTOP_CONFIG") {
            return Ok(PathBuf::from(p));
        }

        // XDG default.
        let config_dir = dirs::config_dir().ok_or_else(|| ConfigError::Io {
            path: "(config dir)".into(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "platform config directory not available",
            ),
        })?;

        Ok(config_dir.join("reservegrid").join("desktop.toml"))
    }

    /// Persist a license key to the config file. Reads the existing TOML,
    /// sets the `license_key` field, and writes it back. Creates the file
    /// and parent directories if they do not exist. Other fields are preserved.
    pub fn save_license_key(key: &str) -> Result<(), ConfigError> {
        let path = Self::writable_config_path()?;

        let mut table: toml::value::Table = if path.exists() {
            let contents = std::fs::read_to_string(&path).map_err(|e| ConfigError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            contents
                .parse::<toml::Value>()
                .map_err(|e| ConfigError::Parse {
                    path: path.display().to_string(),
                    source: e,
                })?
                .as_table()
                .cloned()
                .unwrap_or_default()
        } else {
            toml::value::Table::new()
        };

        table.insert(
            "license_key".into(),
            toml::Value::String(key.to_string()),
        );

        let output = toml::to_string_pretty(&table).map_err(|e| ConfigError::Serialize {
            path: path.display().to_string(),
            source: e,
        })?;

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigError::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }

        std::fs::write(&path, output).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        info!(path = %path.display(), "license key persisted to config file");
        Ok(())
    }

    /// Remove the license key from the config file. If the file does not
    /// exist, this is a no-op.
    pub fn clear_license_key() -> Result<(), ConfigError> {
        let path = Self::writable_config_path()?;
        if !path.exists() {
            return Ok(());
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        let mut table: toml::value::Table = contents
            .parse::<toml::Value>()
            .map_err(|e| ConfigError::Parse {
                path: path.display().to_string(),
                source: e,
            })?
            .as_table()
            .cloned()
            .unwrap_or_default();

        table.remove("license_key");

        let output = toml::to_string_pretty(&table).map_err(|e| ConfigError::Serialize {
            path: path.display().to_string(),
            source: e,
        })?;

        std::fs::write(&path, output).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;

        info!(path = %path.display(), "license key cleared from config file");
        Ok(())
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
    Serialize {
        path: String,
        source: toml::ser::Error,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                tracing::warn!(path, error = %source, "config I/O error");
                write!(f, "cannot read config file")
            }
            Self::Parse { path, source } => {
                tracing::warn!(path, error = %source, "config parse error");
                write!(f, "invalid config file")
            }
            Self::Serialize { path, source } => {
                tracing::warn!(path, error = %source, "config serialize error");
                write!(f, "cannot write config file")
            }
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
        assert!(
            cfg.gateway_url
                .as_deref()
                .unwrap_or("")
                .contains("127.0.0.1:8080")
        );
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

    #[test]
    fn save_license_key_creates_new_file() {
        let dir = std::env::temp_dir().join(format!("rg-test-{}", std::process::id()));
        let path = dir.join("desktop.toml");
        // SAFETY: tests run with --test-threads=1 to avoid env var races.
        unsafe { std::env::set_var("VELDRA_DESKTOP_CONFIG", &path) };

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::create_dir_all(&dir);

        DesktopConfig::save_license_key("veldra_lic_abc").expect("save");

        let contents = std::fs::read_to_string(&path).expect("read");
        let cfg: DesktopConfig = toml::from_str(&contents).expect("parse");
        assert_eq!(cfg.license_key.as_deref(), Some("veldra_lic_abc"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        unsafe { std::env::remove_var("VELDRA_DESKTOP_CONFIG") };
    }

    #[test]
    fn save_license_key_preserves_existing_fields() {
        let dir = std::env::temp_dir().join(format!("rg-test-preserve-{}", std::process::id()));
        let path = dir.join("desktop.toml");
        let _ = std::fs::create_dir_all(&dir);

        let existing = r#"verifier_url = "http://custom:9999"
template_url = "http://custom:8888"
"#;
        std::fs::write(&path, existing).expect("write seed");
        // SAFETY: tests run with --test-threads=1 to avoid env var races.
        unsafe { std::env::set_var("VELDRA_DESKTOP_CONFIG", &path) };

        DesktopConfig::save_license_key("veldra_lic_xyz").expect("save");

        let contents = std::fs::read_to_string(&path).expect("read");
        let cfg: DesktopConfig = toml::from_str(&contents).expect("parse");
        assert_eq!(cfg.verifier_url, "http://custom:9999");
        assert_eq!(cfg.template_url, "http://custom:8888");
        assert_eq!(cfg.license_key.as_deref(), Some("veldra_lic_xyz"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        unsafe { std::env::remove_var("VELDRA_DESKTOP_CONFIG") };
    }

    #[test]
    fn clear_license_key_removes_field() {
        let dir = std::env::temp_dir().join(format!("rg-test-clear-{}", std::process::id()));
        let path = dir.join("desktop.toml");
        let _ = std::fs::create_dir_all(&dir);

        let existing = r#"verifier_url = "http://custom:9999"
license_key = "veldra_lic_old"
"#;
        std::fs::write(&path, existing).expect("write seed");
        // SAFETY: tests run with --test-threads=1 to avoid env var races.
        unsafe { std::env::set_var("VELDRA_DESKTOP_CONFIG", &path) };

        DesktopConfig::clear_license_key().expect("clear");

        let contents = std::fs::read_to_string(&path).expect("read");
        let cfg: DesktopConfig = toml::from_str(&contents).expect("parse");
        assert!(cfg.license_key.is_none());
        assert_eq!(cfg.verifier_url, "http://custom:9999");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        unsafe { std::env::remove_var("VELDRA_DESKTOP_CONFIG") };
    }

    #[test]
    fn clear_license_key_noop_when_no_file() {
        // SAFETY: tests run with --test-threads=1 to avoid env var races.
        unsafe {
            std::env::set_var(
                "VELDRA_DESKTOP_CONFIG",
                "/tmp/rg-nonexistent-config-path.toml",
            );
        }
        let result = DesktopConfig::clear_license_key();
        assert!(result.is_ok());
        unsafe { std::env::remove_var("VELDRA_DESKTOP_CONFIG") };
    }
}
