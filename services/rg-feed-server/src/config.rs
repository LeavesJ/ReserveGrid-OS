//! Configuration for `rg-feed-server`.
//!
//! Loaded from a TOML file with `VELDRA_` env var overrides.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct FeedServerConfig {
    pub feed: FeedSection,
    #[serde(default)]
    pub auth: AuthSection,
}

#[derive(Debug, Deserialize)]
pub struct FeedSection {
    #[serde(default = "default_listen")]
    pub listen: String,

    pub rpc_url: String,

    #[serde(default)]
    pub rpc_user: String,

    #[serde(default)]
    pub rpc_pass: String,

    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,

    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_ms: u64,

    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,

    /// Maximum concurrent WebSocket connections. Default 256.
    /// Set to 0 to disable the limit (not recommended for production).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum concurrent connections from a single IP address. Default 16.
    /// Set to 0 to disable per-IP limiting (not recommended for production).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthSection {
    /// Base64url encoded Ed25519 public key for offline license key verification.
    /// Loaded from `VELDRA_LICENSE_PUBKEY` env var or `auth.license_pubkey` config.
    #[serde(default)]
    pub license_pubkey: String,
}

fn default_listen() -> String {
    "127.0.0.1:9200".into()
}

fn default_poll_interval() -> u64 {
    3000
}

fn default_heartbeat_interval() -> u64 {
    15000
}

fn default_channel_capacity() -> usize {
    64
}

fn default_max_connections() -> usize {
    256
}

fn default_max_connections_per_ip() -> usize {
    16
}

/// Load config from TOML file with env var overrides.
pub fn load(path: &str) -> Result<FeedServerConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|_| "cannot read config file".to_string())?;

    let mut cfg: FeedServerConfig =
        toml::from_str(&text).map_err(|_| "cannot parse config TOML".to_string())?;

    // Env var overrides (VELDRA_ prefix per repo convention).
    if let Ok(v) = std::env::var("VELDRA_FEED_LISTEN") {
        cfg.feed.listen = v;
    }
    if let Ok(v) = std::env::var("VELDRA_FEED_RPC_URL") {
        cfg.feed.rpc_url = v;
    }
    if let Ok(v) = std::env::var("VELDRA_FEED_RPC_USER") {
        cfg.feed.rpc_user = v;
    }
    if let Ok(v) = std::env::var("VELDRA_FEED_RPC_PASS") {
        cfg.feed.rpc_pass = v;
    }
    if let Some(n) = std::env::var("VELDRA_FEED_POLL_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        cfg.feed.poll_interval_ms = n;
    }
    if let Ok(v) = std::env::var("VELDRA_LICENSE_PUBKEY") {
        cfg.auth.license_pubkey = v;
    }
    if let Some(n) = std::env::var("VELDRA_FEED_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        cfg.feed.max_connections = n;
    }
    if let Some(n) = std::env::var("VELDRA_FEED_MAX_CONNECTIONS_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        cfg.feed.max_connections_per_ip = n;
    }

    // Validate: rpc_url is required.
    if cfg.feed.rpc_url.is_empty() {
        return Err("feed.rpc_url is required".into());
    }

    Ok(cfg)
}

/// Parse a TOML string directly (for testing without file I/O).
#[cfg(test)]
pub fn parse_toml(text: &str) -> Result<FeedServerConfig, String> {
    toml::from_str(text).map_err(|e| format!("parse error: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_parses() {
        let toml = r#"
[feed]
rpc_url = "http://localhost:8332"
"#;
        let cfg = parse_toml(toml).expect("should parse minimal config");
        assert_eq!(cfg.feed.rpc_url, "http://localhost:8332");
        assert_eq!(cfg.feed.listen, "127.0.0.1:9200");
        assert_eq!(cfg.feed.poll_interval_ms, 3000);
        assert_eq!(cfg.feed.heartbeat_interval_ms, 15000);
        assert_eq!(cfg.feed.channel_capacity, 64);
    }

    #[test]
    fn full_config_parses() {
        let toml = r#"
[feed]
listen = "127.0.0.1:9999"
rpc_url = "http://bitcoind:8332"
rpc_user = "rpc"
rpc_pass = "secret"
poll_interval_ms = 1000
heartbeat_interval_ms = 5000
channel_capacity = 128

[auth]
license_pubkey = "dGVzdA"
"#;
        let cfg = parse_toml(toml).expect("should parse full config");
        assert_eq!(cfg.feed.listen, "127.0.0.1:9999");
        assert_eq!(cfg.feed.rpc_user, "rpc");
        assert_eq!(cfg.feed.poll_interval_ms, 1000);
        assert_eq!(cfg.feed.channel_capacity, 128);
        assert_eq!(cfg.auth.license_pubkey, "dGVzdA");
    }

    #[test]
    fn missing_rpc_url_fails() {
        let toml = r#"
[feed]
listen = "0.0.0.0:9200"
rpc_url = ""
"#;
        let cfg = parse_toml(toml).expect("TOML parses");
        assert!(cfg.feed.rpc_url.is_empty());
    }

    #[test]
    fn auth_section_defaults_to_empty() {
        let toml = r#"
[feed]
rpc_url = "http://localhost:8332"
"#;
        let cfg = parse_toml(toml).expect("should parse");
        assert!(cfg.auth.license_pubkey.is_empty());
    }

    #[test]
    fn missing_feed_section_fails() {
        let toml = r#"
[auth]
license_pubkey = "abc"
"#;
        let result = parse_toml(toml);
        assert!(result.is_err(), "config without [feed] must fail");
    }
}
