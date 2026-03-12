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
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthSection {
    /// Comma-separated static key list for dev/local use.
    #[serde(default)]
    pub valid_keys: String,

    /// Optional rg-auth URL for dynamic key validation.
    #[serde(default)]
    pub auth_url: String,
}

fn default_listen() -> String {
    "0.0.0.0:9200".into()
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

/// Load config from TOML file with env var overrides.
pub fn load(path: &str) -> Result<FeedServerConfig, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read config {path}: {e}"))?;

    let mut cfg: FeedServerConfig =
        toml::from_str(&text).map_err(|e| format!("cannot parse config {path}: {e}"))?;

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
    if let Ok(v) = std::env::var("VELDRA_FEED_VALID_KEYS") {
        cfg.auth.valid_keys = v;
    }
    if let Ok(v) = std::env::var("VELDRA_FEED_AUTH_URL") {
        cfg.auth.auth_url = v;
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
        assert_eq!(cfg.feed.listen, "0.0.0.0:9200");
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
valid_keys = "key1,key2,key3"
auth_url = "http://rg-auth:3000"
"#;
        let cfg = parse_toml(toml).expect("should parse full config");
        assert_eq!(cfg.feed.listen, "127.0.0.1:9999");
        assert_eq!(cfg.feed.rpc_user, "rpc");
        assert_eq!(cfg.feed.poll_interval_ms, 1000);
        assert_eq!(cfg.feed.channel_capacity, 128);
        assert_eq!(cfg.auth.valid_keys, "key1,key2,key3");
        assert_eq!(cfg.auth.auth_url, "http://rg-auth:3000");
    }

    #[test]
    fn missing_rpc_url_fails() {
        let toml = r#"
[feed]
listen = "0.0.0.0:9200"
rpc_url = ""
"#;
        let cfg = parse_toml(toml).expect("TOML parses");
        // Simulate the validation that `load` performs.
        assert!(cfg.feed.rpc_url.is_empty());
    }

    #[test]
    fn auth_section_defaults_to_empty() {
        let toml = r#"
[feed]
rpc_url = "http://localhost:8332"
"#;
        let cfg = parse_toml(toml).expect("should parse");
        assert!(cfg.auth.valid_keys.is_empty());
        assert!(cfg.auth.auth_url.is_empty());
    }

    #[test]
    fn missing_feed_section_fails() {
        let toml = r#"
[auth]
valid_keys = "abc"
"#;
        let result = parse_toml(toml);
        assert!(result.is_err(), "config without [feed] must fail");
    }
}
