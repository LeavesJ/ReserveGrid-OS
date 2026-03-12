use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
pub struct ConfigFile {
    pub adapter: Option<AdapterSection>,
}

#[derive(Deserialize)]
pub struct AdapterSection {
    pub listen: Option<String>,
    pub feed_url: Option<String>,
    pub license_key: Option<String>,
}

/// Resolved adapter configuration. Env vars override file values.
pub struct AdapterConfig {
    pub listen: String,
    pub feed_url: String,
    pub license_key: String,
}

impl AdapterConfig {
    /// Load config from TOML file, then apply env var overrides.
    ///
    /// Env vars:
    ///   `VELDRA_ADAPTER_LISTEN`   → listen address
    ///   `VELDRA_FEED_URL`         → WebSocket feed URL
    ///   `VELDRA_FEED_LICENSE_KEY` → license key (empty = unauthenticated)
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let (file_listen, file_url, file_key) = if Path::new(path).exists() {
            let text = std::fs::read_to_string(path)?;
            let file: ConfigFile = toml::from_str(&text)?;
            let sec = file.adapter.unwrap_or(AdapterSection {
                listen: None,
                feed_url: None,
                license_key: None,
            });
            (sec.listen, sec.feed_url, sec.license_key)
        } else {
            tracing::warn!(path, "config file not found, using defaults and env vars");
            (None, None, None)
        };

        let listen = std::env::var("VELDRA_ADAPTER_LISTEN")
            .ok()
            .or(file_listen)
            .unwrap_or_else(|| "127.0.0.1:18444".into());

        let feed_url = std::env::var("VELDRA_FEED_URL")
            .ok()
            .or(file_url)
            .unwrap_or_else(|| "ws://127.0.0.1:9100/ws".into());

        let license_key = std::env::var("VELDRA_FEED_LICENSE_KEY")
            .ok()
            .or(file_key)
            .unwrap_or_default();

        Ok(Self {
            listen,
            feed_url,
            license_key,
        })
    }
}
