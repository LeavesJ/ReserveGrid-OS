use serde::Deserialize;
use std::path::Path;

/// Dashboard configuration loaded from TOML.
///
/// All backend URLs are required. The dashboard proxies every API request
/// through itself so the browser never sees internal service addresses.
#[derive(Debug, Deserialize)]
pub struct DashboardConfig {
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Base URL of the pool-verifier HTTP API (e.g. `http://pool-verifier:8080`).
    pub verifier_url: String,

    /// Base URL of the template-manager HTTP API (e.g. `http://template-manager:8082`).
    pub template_url: String,

    /// Base URL of the rg-auth HTTP API (e.g. `http://rg-auth:8083`).
    pub auth_url: String,

    /// Base URL of the sv2-gateway HTTP API (e.g. `http://sv2-gateway:8080`).
    /// Optional for backward compatibility; when absent, gateway settings
    /// and health are sourced from `health_probes`.
    #[serde(default)]
    pub gateway_url: Option<String>,

    /// Base URL of the `rg-feed-adapter` HTTP API (e.g. `http://rg-feed-adapter:18444`).
    /// Required in shadow mode so the dashboard can probe feed pipeline health
    /// and gate access until the shadow services are ready.
    #[serde(default)]
    pub feed_adapter_url: Option<String>,

    /// Health probe URLs for services that only expose /healthz.
    /// Keys are display names, values are base URLs.
    #[serde(default)]
    pub health_probes: Vec<HealthProbe>,
}

#[derive(Debug, Deserialize)]
pub struct HealthProbe {
    pub name: String,
    pub url: String,
}

fn default_listen() -> String {
    "127.0.0.1:8084".to_string()
}

impl DashboardConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let cfg: Self = toml::from_str(&contents).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            source: e,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.verifier_url.is_empty() {
            return Err(ConfigError::Missing("verifier_url"));
        }
        if self.template_url.is_empty() {
            return Err(ConfigError::Missing("template_url"));
        }
        if self.auth_url.is_empty() {
            return Err(ConfigError::Missing("auth_url"));
        }
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
    Missing(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                // Log the full detail server-side; public message omits path and OS error.
                tracing::warn!(path, error = %source, "config I/O error");
                write!(f, "cannot read config file")
            }
            Self::Parse { path, source } => {
                tracing::warn!(path, error = %source, "config parse error");
                write!(f, "invalid config file")
            }
            Self::Missing(field) => write!(f, "missing required config field: {field}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
verifier_url = "http://verifier:8080"
template_url = "http://template:8082"
auth_url = "http://auth:8083"
"#;
        let cfg: DashboardConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.listen, "127.0.0.1:8084");
        assert_eq!(cfg.verifier_url, "http://verifier:8080");
        assert!(cfg.health_probes.is_empty());
        assert!(cfg.feed_adapter_url.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
listen = "127.0.0.1:9000"
verifier_url = "http://verifier:8080"
template_url = "http://template:8082"
auth_url = "http://auth:8083"
feed_adapter_url = "http://rg-feed-adapter:18444"

[[health_probes]]
name = "sv2-gateway"
url = "http://sv2-gw:3000"

[[health_probes]]
name = "reservegrid-gateway"
url = "http://rg-gw:3001"
"#;
        let cfg: DashboardConfig = toml::from_str(toml).expect("parse");
        assert_eq!(cfg.listen, "127.0.0.1:9000");
        assert_eq!(cfg.health_probes.len(), 2);
        assert_eq!(cfg.health_probes[0].name, "sv2-gateway");
        assert_eq!(
            cfg.feed_adapter_url.as_deref(),
            Some("http://rg-feed-adapter:18444")
        );
    }

    #[test]
    fn missing_verifier_url_rejected() {
        let toml = r#"
template_url = "http://template:8082"
auth_url = "http://auth:8083"
verifier_url = ""
"#;
        let cfg: DashboardConfig = toml::from_str(toml).expect("parse");
        assert!(cfg.validate().is_err());
    }
}
