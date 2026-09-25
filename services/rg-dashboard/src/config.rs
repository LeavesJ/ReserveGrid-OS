use serde::Deserialize;
use std::net::IpAddr;
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

    /// Request limits per client. Optional; omitting the table gives the
    /// defaults, which are correct for a production operator.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

/// The `[rate_limit]` table.
///
/// Unknown keys are refused, so a typo such as `api_per_min` fails the load
/// instead of silently leaving the default in place.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests per client per 60 s across `/api/*`, except `/api/health`,
    /// which has its own fixed budget. The SPA polls about 84 of these a
    /// minute per open tab with every hook mounted, so 600 is about seven
    /// tabs, or several operators behind one NAT. Must be at least 1.
    #[serde(default = "default_api_per_minute")]
    pub api_per_minute: u32,

    /// Exact addresses (no CIDR) of reverse proxies allowed to name the
    /// client through `client_ip_header`. A request from any other peer is
    /// keyed by its own address and its headers are ignored.
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,

    /// Which header a trusted proxy puts the client address in. Required
    /// when `trusted_proxies` is set, refused when it is not.
    #[serde(default)]
    pub client_ip_header: Option<ClientIpHeader>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            api_per_minute: default_api_per_minute(),
            trusted_proxies: Vec::new(),
            client_ip_header: None,
        }
    }
}

/// A header a trusted reverse proxy sets to the client's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientIpHeader {
    /// `cf-connecting-ip`: one address, set and overwritten at Cloudflare's
    /// edge, which is what cloudflared forwards.
    CfConnectingIp,
    /// `x-forwarded-for`: a list, read from the right, skipping trusted
    /// proxies, so whatever the client wrote on the left is never reached.
    XForwardedFor,
}

#[derive(Debug, Deserialize)]
pub struct HealthProbe {
    pub name: String,
    pub url: String,
}

fn default_listen() -> String {
    "127.0.0.1:8084".to_string()
}

fn default_api_per_minute() -> u32 {
    600
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
        let rl = &self.rate_limit;
        // A limit of 0 would refuse every /api request: a window that may
        // hold nothing is always full.
        if rl.api_per_minute == 0 {
            return Err(ConfigError::Invalid(
                "rate_limit.api_per_minute must be at least 1",
            ));
        }
        match (rl.trusted_proxies.is_empty(), rl.client_ip_header) {
            (false, None) => Err(ConfigError::Invalid(
                "rate_limit.trusted_proxies is set but rate_limit.client_ip_header is not",
            )),
            (true, Some(_)) => Err(ConfigError::Invalid(
                "rate_limit.client_ip_header is set but rate_limit.trusted_proxies is empty, so it would never be read",
            )),
            _ => Ok(()),
        }
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
    Invalid(&'static str),
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
            Self::Invalid(why) => write!(f, "invalid config: {why}"),
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

    const URLS: &str = r#"
verifier_url = "http://verifier:8080"
template_url = "http://template:8082"
auth_url = "http://auth:8083"
"#;

    fn parse(extra: &str) -> Result<DashboardConfig, toml::de::Error> {
        toml::from_str(&format!("{URLS}\n{extra}"))
    }

    #[test]
    fn no_rate_limit_table_gives_production_defaults() {
        let cfg = parse("").expect("parse");
        assert_eq!(cfg.rate_limit.api_per_minute, 600);
        assert!(cfg.rate_limit.trusted_proxies.is_empty());
        assert_eq!(cfg.rate_limit.client_ip_header, None);
        cfg.validate().expect("defaults validate");
    }

    #[test]
    fn shipped_configs_still_load() {
        for (name, text) in [
            (
                "config/default.toml",
                include_str!("../config/default.toml"),
            ),
            (
                "dev/dashboard.toml",
                include_str!("../../../dev/dashboard.toml"),
            ),
        ] {
            let cfg: DashboardConfig =
                toml::from_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            cfg.validate().unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(cfg.rate_limit.api_per_minute, 600, "{name}");
        }
    }

    #[test]
    fn rate_limit_override_parses() {
        let cfg = parse(
            r#"
[rate_limit]
api_per_minute = 42
trusted_proxies = ["127.0.0.1", "::1"]
client_ip_header = "cf-connecting-ip"
"#,
        )
        .expect("parse");
        assert_eq!(cfg.rate_limit.api_per_minute, 42);
        assert_eq!(
            cfg.rate_limit.trusted_proxies,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(
            cfg.rate_limit.client_ip_header,
            Some(ClientIpHeader::CfConnectingIp)
        );
        cfg.validate().expect("validate");

        let xff = parse(
            "[rate_limit]\ntrusted_proxies = [\"10.0.0.2\"]\nclient_ip_header = \"x-forwarded-for\"",
        )
        .expect("parse");
        assert_eq!(
            xff.rate_limit.client_ip_header,
            Some(ClientIpHeader::XForwardedFor)
        );
        xff.validate().expect("validate");
    }

    #[test]
    fn zero_api_per_minute_rejected() {
        let cfg = parse("[rate_limit]\napi_per_minute = 0").expect("parse");
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn proxies_without_header_rejected() {
        let cfg = parse("[rate_limit]\ntrusted_proxies = [\"127.0.0.1\"]").expect("parse");
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn header_without_proxies_rejected() {
        let cfg = parse("[rate_limit]\nclient_ip_header = \"cf-connecting-ip\"").expect("parse");
        assert!(matches!(cfg.validate(), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn unknown_header_name_rejected() {
        let err = parse(
            "[rate_limit]\ntrusted_proxies = [\"127.0.0.1\"]\nclient_ip_header = \"x-real-ip\"",
        );
        assert!(err.is_err(), "x-real-ip is not a supported header");
    }

    #[test]
    fn unknown_key_in_rate_limit_rejected() {
        let err = parse("[rate_limit]\napi_per_min = 10");
        assert!(
            err.is_err(),
            "a misspelt key must not fall back to the default"
        );
    }

    #[test]
    fn invalid_ip_in_trusted_proxies_rejected() {
        for bad in ["10.0.0.0/8", "localhost", "300.1.1.1"] {
            let err = parse(&format!(
                "[rate_limit]\ntrusted_proxies = [\"{bad}\"]\nclient_ip_header = \"x-forwarded-for\""
            ));
            assert!(err.is_err(), "{bad} is not an exact IP address");
        }
    }
}
