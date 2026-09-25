use serde::Deserialize;
use std::env::VarError;
use std::path::Path;

/// Env var that overrides `[adapter] rate_limit_per_minute`.
pub const ENV_RATE_LIMIT: &str = "VELDRA_ADAPTER_RATE_LIMIT_PER_MINUTE";

/// JSON-RPC calls per peer per 60 s when neither the file nor the env sets
/// one. The callers at their shipped intervals send about 54 a minute in
/// total (template-manager and rg-feed-server 24 each, pool-verifier 6),
/// about 740 at 1 s polling with every call retried three times. On
/// loopback they all share one peer address and so one budget, which is
/// why this is well above their sum.
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 1200;

#[derive(Deserialize)]
pub struct ConfigFile {
    pub adapter: Option<AdapterSection>,
}

#[derive(Deserialize, Default)]
pub struct AdapterSection {
    pub listen: Option<String>,
    pub feed_url: Option<String>,
    pub license_key: Option<String>,
    pub rate_limit_per_minute: Option<u32>,
}

/// Resolved adapter configuration. Env vars override file values.
pub struct AdapterConfig {
    pub listen: String,
    pub feed_url: String,
    pub license_key: String,
    pub rate_limit_per_minute: u32,
}

impl AdapterConfig {
    /// Load config from TOML file, then apply env var overrides.
    ///
    /// Env vars:
    ///   `VELDRA_ADAPTER_LISTEN`   → listen address
    ///   `VELDRA_FEED_URL`         → WebSocket feed URL
    ///   `VELDRA_FEED_LICENSE_KEY` → license key (empty = unauthenticated)
    ///   `VELDRA_ADAPTER_RATE_LIMIT_PER_MINUTE` → JSON-RPC calls per peer
    ///   per minute; unparsable or 0 is an error, never the default
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let sec = if Path::new(path).exists() {
            let text = std::fs::read_to_string(path)?;
            let file: ConfigFile = toml::from_str(&text)?;
            file.adapter.unwrap_or_default()
        } else {
            tracing::warn!(path, "config file not found, using defaults and env vars");
            AdapterSection::default()
        };

        let rate_limit_per_minute =
            rate_limit_per_minute(std::env::var(ENV_RATE_LIMIT), sec.rate_limit_per_minute)?;

        let listen = std::env::var("VELDRA_ADAPTER_LISTEN")
            .ok()
            .or(sec.listen)
            .unwrap_or_else(|| "127.0.0.1:18444".into());

        let feed_url = std::env::var("VELDRA_FEED_URL")
            .ok()
            .or(sec.feed_url)
            .unwrap_or_else(|| "ws://127.0.0.1:9100/ws".into());

        let license_key = std::env::var("VELDRA_FEED_LICENSE_KEY")
            .ok()
            .or(sec.license_key)
            .unwrap_or_default();

        Ok(Self {
            listen,
            feed_url,
            license_key,
            rate_limit_per_minute,
        })
    }
}

/// The env value if the variable is set, else the file value, else the
/// default. A set variable that is not a whole number, or a 0 from either
/// source, is an error: a window that may hold nothing refuses every call,
/// and a typo must stop the process rather than quietly run the default
/// (Invariant 3). Takes the env lookup as a value so the tests can cover
/// it without `set_var`, which would race every other test in the binary.
fn rate_limit_per_minute(env: Result<String, VarError>, file: Option<u32>) -> Result<u32, String> {
    let limit = match env {
        Ok(v) => v
            .parse::<u32>()
            .map_err(|e| format!("{ENV_RATE_LIMIT}={v:?} is not a whole number: {e}"))?,
        Err(VarError::NotPresent) => file.unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE),
        Err(VarError::NotUnicode(_)) => return Err(format!("{ENV_RATE_LIMIT} is not valid UTF-8")),
    };
    if limit == 0 {
        return Err("rate_limit_per_minute must be at least 1".into());
    }
    Ok(limit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn config_file_value_parses() {
        let file: ConfigFile =
            toml::from_str("[adapter]\nrate_limit_per_minute = 5").expect("parse");
        assert_eq!(file.adapter.unwrap().rate_limit_per_minute, Some(5));

        let file: ConfigFile =
            toml::from_str("[adapter]\nlisten = \"127.0.0.1:1\"").expect("parse");
        let missing = file.adapter.unwrap().rate_limit_per_minute;
        assert_eq!(missing, None);
        assert_eq!(
            rate_limit_per_minute(Err(VarError::NotPresent), missing),
            Ok(DEFAULT_RATE_LIMIT_PER_MINUTE)
        );
        assert_eq!(DEFAULT_RATE_LIMIT_PER_MINUTE, 1200);
    }

    #[test]
    fn config_file_value_that_is_not_a_count_fails_the_parse() {
        for bad in ["-1", "\"many\"", "1.5"] {
            let text = format!("[adapter]\nrate_limit_per_minute = {bad}");
            assert!(toml::from_str::<ConfigFile>(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn env_overrides_file_and_file_overrides_default() {
        assert_eq!(rate_limit_per_minute(Ok("7".into()), Some(5)), Ok(7));
        assert_eq!(
            rate_limit_per_minute(Err(VarError::NotPresent), Some(5)),
            Ok(5)
        );
    }

    #[test]
    fn zero_or_unparsable_is_an_error_not_the_default() {
        for bad in ["0", "abc", "-5", "", " 5", "5000000000"] {
            assert!(
                rate_limit_per_minute(Ok(bad.into()), Some(5)).is_err(),
                "env {bad:?}"
            );
        }
        assert!(rate_limit_per_minute(Err(VarError::NotPresent), Some(0)).is_err());
        assert!(rate_limit_per_minute(Err(VarError::NotUnicode("\u{fffd}".into())), None).is_err());
    }
}
