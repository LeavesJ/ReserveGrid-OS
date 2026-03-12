//! Configuration schema, validation, and environment overlay.
//!
//! The `[policy]` TOML table is the single source of runtime configuration.
//! Every field has an explicit type, a documented range, and no implicit default
//! that could weaken security. Required fields cause a startup failure if missing.
//!
//! Environment variables (`VELDRA_*`) override TOML values. Secret fields
//! (`VELDRA_API_SECRET`, `VELDRA_HMAC_KEY`) are never read from TOML.

use std::path::PathBuf;

use serde::Deserialize;
use tracing::{info, warn};

use crate::redacted::Redacted;

// ── TLS mode ──

/// Controls whether TLS is required on the HTTP listener.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS is mandatory on all bind addresses.
    #[default]
    Required,
    /// TLS is disabled only when bound to loopback (`127.0.0.1` or `::1`).
    /// Binding to any other address with this mode is a startup error.
    OptionalLocalOnly,
}

// ── Auth mode ──

/// Selects the authentication scheme for protected endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiAuthMode {
    /// Bearer token validated via constant-time comparison.
    BearerToken,
    /// HMAC-SHA256 request signing with nonce and timestamp.
    HmacSha256,
}

// ── Policy config ──

/// Deserialized from the `[policy]` table in the TOML config file.
///
/// Required fields have no `Option` wrapper and no `#[serde(default)]`.
/// Optional fields use `Option<T>` with explicit defaults applied in
/// `validated()`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    // ── Block 3.1: core policy ──
    /// Maximum template age in seconds before rejection.
    pub max_template_age_secs: u64,

    /// Maximum allowed sigops per template.
    pub max_sigops: u32,

    /// Maximum allowed weight per template.
    pub max_weight: u64,

    /// Sustained request rate limit (requests per second per client).
    pub rate_limit_requests_per_sec: u32,

    /// Burst capacity above the sustained rate.
    pub rate_limit_burst: u32,

    /// TLS enforcement mode. Defaults to `required`.
    #[serde(default)]
    pub tls_mode: TlsMode,

    /// Authentication scheme for protected endpoints.
    pub api_auth_mode: ApiAuthMode,

    // ── Block 5.5: input validation ──
    /// Maximum request body size in bytes. Default 1 MiB.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,

    // ── Block 9.1: connection hardening ──
    /// Maximum concurrent connections. Default 1024.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Read timeout for incoming requests in seconds. Default 30.
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u32,

    /// Wall-clock deadline per handler in seconds. Default 10.
    #[serde(default = "default_handler_deadline_secs")]
    pub handler_deadline_secs: u32,

    // ── Block 9.2: panic isolation ──
    /// Panic threshold per minute before graceful shutdown. Default 5.
    #[serde(default = "default_max_panics_per_minute")]
    pub max_panics_per_minute: u32,

    // ── Block 9.3: graceful shutdown ──
    /// Drain period in seconds during graceful shutdown. Default 30.
    #[serde(default = "default_shutdown_drain_secs")]
    pub shutdown_drain_secs: u32,

    // ── Block 9.4: health probes ──
    /// Upstream health check interval in seconds. Default 30.
    #[serde(default = "default_upstream_health_interval_secs")]
    pub upstream_health_interval_secs: u32,

    // ── Block 10.1: replay prevention ──
    /// Timestamp acceptance window in seconds. Default 30.
    #[serde(default = "default_request_timestamp_window_secs")]
    pub request_timestamp_window_secs: u32,

    /// Maximum nonce cache entries. Default `100_000`.
    #[serde(default = "default_nonce_cache_size")]
    pub nonce_cache_size: u32,

    // ── Block 10.2: timing normalization ──
    /// Minimum response delay in milliseconds on rejection paths. Default 50.
    #[serde(default = "default_min_response_delay_ms")]
    pub min_response_delay_ms: u32,

    // ── Block 10.4: data directory ──
    /// Writable directory for runtime data (nonce cache, logs).
    pub data_dir: PathBuf,
}

// ── Defaults (explicit, no magic) ──

const fn default_max_request_body_bytes() -> u64 {
    1_048_576
}
const fn default_max_connections() -> u32 {
    1024
}
const fn default_request_timeout_secs() -> u32 {
    30
}
const fn default_handler_deadline_secs() -> u32 {
    10
}
const fn default_max_panics_per_minute() -> u32 {
    5
}
const fn default_shutdown_drain_secs() -> u32 {
    30
}
const fn default_upstream_health_interval_secs() -> u32 {
    30
}
const fn default_request_timestamp_window_secs() -> u32 {
    30
}
const fn default_nonce_cache_size() -> u32 {
    100_000
}
const fn default_min_response_delay_ms() -> u32 {
    50
}

// ── Validation ──

/// Errors produced by `validate_config()`.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("policy.max_template_age_secs must be > 0, got {0}")]
    MaxTemplateAgeZero(u64),

    #[error("policy.max_sigops must be > 0, got {0}")]
    MaxSigopsZero(u32),

    #[error("policy.max_weight must be > 0, got {0}")]
    MaxWeightZero(u64),

    #[error("policy.rate_limit_requests_per_sec must be > 0, got {0}")]
    RateLimitZero(u32),

    #[error("policy.rate_limit_burst must be >= rate_limit_requests_per_sec ({rps}), got {burst}")]
    BurstBelowRate { rps: u32, burst: u32 },

    #[error("policy.request_timeout_secs must be > 0, got {0}")]
    RequestTimeoutZero(u32),

    #[error(
        "policy.handler_deadline_secs ({deadline}) must be <= request_timeout_secs ({timeout})"
    )]
    DeadlineExceedsTimeout { deadline: u32, timeout: u32 },

    #[error("policy.data_dir does not exist or is not a directory: {0}")]
    DataDirInvalid(PathBuf),

    #[error("policy.max_request_body_bytes must be > 0, got {0}")]
    MaxRequestBodyZero(u64),

    #[error("policy.nonce_cache_size must be > 0, got {0}")]
    NonceCacheZero(u32),

    #[error("TOML parse error: {0}")]
    TomlParse(String),

    #[error(
        "secret detected in TOML config key '{key}'; secrets must come from environment variables, never from config files"
    )]
    SecretInToml { key: String },
}

impl PolicyConfig {
    /// Parse a `[policy]` table from TOML text.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::TomlParse` if deserialization fails (missing
    /// required fields, unknown fields, type mismatches).
    pub fn from_toml(toml_text: &str) -> Result<Self, ConfigError> {
        /// Wrapper for the `[policy]` table.
        #[derive(Deserialize)]
        struct Wrapper {
            policy: PolicyConfig,
        }

        let wrapper: Wrapper =
            toml::from_str(toml_text).map_err(|e| ConfigError::TomlParse(e.to_string()))?;
        Ok(wrapper.policy)
    }

    /// Validate all invariants. Call on startup before accepting traffic.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant as a `ConfigError`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_template_age_secs == 0 {
            return Err(ConfigError::MaxTemplateAgeZero(self.max_template_age_secs));
        }
        if self.max_sigops == 0 {
            return Err(ConfigError::MaxSigopsZero(self.max_sigops));
        }
        if self.max_weight == 0 {
            return Err(ConfigError::MaxWeightZero(self.max_weight));
        }
        if self.rate_limit_requests_per_sec == 0 {
            return Err(ConfigError::RateLimitZero(self.rate_limit_requests_per_sec));
        }
        if self.rate_limit_burst < self.rate_limit_requests_per_sec {
            return Err(ConfigError::BurstBelowRate {
                rps: self.rate_limit_requests_per_sec,
                burst: self.rate_limit_burst,
            });
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError::RequestTimeoutZero(self.request_timeout_secs));
        }
        if self.handler_deadline_secs > self.request_timeout_secs {
            return Err(ConfigError::DeadlineExceedsTimeout {
                deadline: self.handler_deadline_secs,
                timeout: self.request_timeout_secs,
            });
        }
        if self.max_request_body_bytes == 0 {
            return Err(ConfigError::MaxRequestBodyZero(self.max_request_body_bytes));
        }
        if self.nonce_cache_size == 0 {
            return Err(ConfigError::NonceCacheZero(self.nonce_cache_size));
        }
        if !self.data_dir.is_dir() {
            return Err(ConfigError::DataDirInvalid(self.data_dir.clone()));
        }
        Ok(())
    }

    /// Apply `VELDRA_*` environment variable overrides.
    ///
    /// Secret keys (`VELDRA_API_SECRET`, `VELDRA_HMAC_KEY`) are NOT handled
    /// here; they are loaded separately into `Redacted<String>` wrappers by
    /// `load_secrets()`.
    ///
    /// Logs which keys were overridden (never logs values of secret-adjacent
    /// fields).
    pub fn apply_env_overrides(&mut self) {
        macro_rules! override_u64 {
            ($env:literal, $field:ident) => {
                if let Ok(val) = std::env::var($env) {
                    if let Ok(parsed) = val.parse::<u64>() {
                        info!(key = $env, "config override from environment");
                        self.$field = parsed;
                    } else {
                        warn!(key = $env, value = %val, "ignoring non-numeric env override");
                    }
                }
            };
        }
        macro_rules! override_u32 {
            ($env:literal, $field:ident) => {
                if let Ok(val) = std::env::var($env) {
                    if let Ok(parsed) = val.parse::<u32>() {
                        info!(key = $env, "config override from environment");
                        self.$field = parsed;
                    } else {
                        warn!(key = $env, value = %val, "ignoring non-numeric env override");
                    }
                }
            };
        }

        override_u64!("VELDRA_MAX_TEMPLATE_AGE_SECS", max_template_age_secs);
        override_u32!("VELDRA_MAX_SIGOPS", max_sigops);
        override_u64!("VELDRA_MAX_WEIGHT", max_weight);
        override_u32!("VELDRA_RATE_LIMIT_RPS", rate_limit_requests_per_sec);
        override_u32!("VELDRA_RATE_LIMIT_BURST", rate_limit_burst);
        override_u64!("VELDRA_MAX_REQUEST_BODY_BYTES", max_request_body_bytes);
        override_u32!("VELDRA_MAX_CONNECTIONS", max_connections);
        override_u32!("VELDRA_REQUEST_TIMEOUT_SECS", request_timeout_secs);
        override_u32!("VELDRA_HANDLER_DEADLINE_SECS", handler_deadline_secs);
        override_u32!("VELDRA_MAX_PANICS_PER_MINUTE", max_panics_per_minute);
        override_u32!("VELDRA_SHUTDOWN_DRAIN_SECS", shutdown_drain_secs);
        override_u32!(
            "VELDRA_UPSTREAM_HEALTH_INTERVAL_SECS",
            upstream_health_interval_secs
        );
        override_u32!(
            "VELDRA_REQUEST_TIMESTAMP_WINDOW_SECS",
            request_timestamp_window_secs
        );
        override_u32!("VELDRA_NONCE_CACHE_SIZE", nonce_cache_size);
        override_u32!("VELDRA_MIN_RESPONSE_DELAY_MS", min_response_delay_ms);

        if let Ok(val) = std::env::var("VELDRA_DATA_DIR") {
            info!(key = "VELDRA_DATA_DIR", "config override from environment");
            self.data_dir = PathBuf::from(val);
        }
    }
}

// ── Secret loading ──

/// Minimum API key length in bytes (before hex encoding).
pub const MIN_API_KEY_BYTES: usize = 32;

/// Minimum API key hex string length (2 hex chars per byte).
pub const MIN_API_KEY_HEX_LEN: usize = MIN_API_KEY_BYTES * 2;

/// Runtime secrets loaded from environment variables.
///
/// All fields are wrapped in `Redacted<String>` so that `Debug`/`Display`
/// never leak key material. `Debug` is implemented manually to delegate
/// to each field's `Redacted` wrapper.
pub struct Secrets {
    /// Primary API key (`VELDRA_API_SECRET`).
    pub api_secret: Option<Redacted<String>>,

    /// Previous API key for zero-downtime rotation
    /// (`VELDRA_API_SECRET_PREVIOUS`).
    pub api_secret_previous: Option<Redacted<String>>,

    /// HMAC signing key (`VELDRA_HMAC_KEY`).
    pub hmac_key: Option<Redacted<String>>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field(
                "api_secret",
                &self.api_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "api_secret_previous",
                &self.api_secret_previous.as_ref().map(|_| "[REDACTED]"),
            )
            .field("hmac_key", &self.hmac_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Secret-loading validation errors.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("VELDRA_API_SECRET is too short: got {got} hex chars, need >= {min}")]
    ApiSecretTooShort { got: usize, min: usize },

    #[error("VELDRA_API_SECRET is not valid hex")]
    ApiSecretNotHex,

    #[error("VELDRA_API_SECRET_PREVIOUS is too short: got {got} hex chars, need >= {min}")]
    ApiSecretPreviousTooShort { got: usize, min: usize },

    #[error("VELDRA_API_SECRET_PREVIOUS is not valid hex")]
    ApiSecretPreviousNotHex,

    #[error("VELDRA_HMAC_KEY is too short: got {got} hex chars, need >= {min}")]
    HmacKeyTooShort { got: usize, min: usize },

    #[error("VELDRA_HMAC_KEY is not valid hex")]
    HmacKeyNotHex,

    #[error("api_auth_mode is bearer_token but VELDRA_API_SECRET is not set")]
    BearerTokenMissingSecret,

    #[error("api_auth_mode is hmac_sha256 but VELDRA_HMAC_KEY is not set")]
    HmacMissingKey,
}

/// Validate that a hex key string meets minimum length and is valid hex.
fn validate_hex_key(val: &str, min_hex_len: usize) -> Result<(), (usize, bool)> {
    if val.len() < min_hex_len {
        return Err((val.len(), true));
    }
    if !val.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((val.len(), false));
    }
    Ok(())
}

impl Secrets {
    /// Load secrets from environment variables and validate them.
    ///
    /// `auth_mode` determines which secrets are mandatory.
    ///
    /// # Errors
    ///
    /// Returns `SecretError` if a required secret is missing, too short,
    /// or not valid hex.
    pub fn from_env(auth_mode: ApiAuthMode) -> Result<Self, SecretError> {
        let api_secret = std::env::var("VELDRA_API_SECRET").ok();
        let api_secret_previous = std::env::var("VELDRA_API_SECRET_PREVIOUS").ok();
        let hmac_key = std::env::var("VELDRA_HMAC_KEY").ok();

        // Validate primary API secret if present
        if let Some(ref val) = api_secret {
            validate_hex_key(val, MIN_API_KEY_HEX_LEN).map_err(|(got, is_short)| {
                if is_short {
                    SecretError::ApiSecretTooShort {
                        got,
                        min: MIN_API_KEY_HEX_LEN,
                    }
                } else {
                    SecretError::ApiSecretNotHex
                }
            })?;
        }

        // Validate previous API secret if present
        if let Some(ref val) = api_secret_previous {
            validate_hex_key(val, MIN_API_KEY_HEX_LEN).map_err(|(got, is_short)| {
                if is_short {
                    SecretError::ApiSecretPreviousTooShort {
                        got,
                        min: MIN_API_KEY_HEX_LEN,
                    }
                } else {
                    SecretError::ApiSecretPreviousNotHex
                }
            })?;
        }

        // Validate HMAC key if present
        if let Some(ref val) = hmac_key {
            validate_hex_key(val, MIN_API_KEY_HEX_LEN).map_err(|(got, is_short)| {
                if is_short {
                    SecretError::HmacKeyTooShort {
                        got,
                        min: MIN_API_KEY_HEX_LEN,
                    }
                } else {
                    SecretError::HmacKeyNotHex
                }
            })?;
        }

        // Enforce that the required secret for the auth mode is present
        match auth_mode {
            ApiAuthMode::BearerToken => {
                if api_secret.is_none() {
                    return Err(SecretError::BearerTokenMissingSecret);
                }
            }
            ApiAuthMode::HmacSha256 => {
                if hmac_key.is_none() {
                    return Err(SecretError::HmacMissingKey);
                }
            }
        }

        Ok(Self {
            api_secret: api_secret.map(Redacted::new),
            api_secret_previous: api_secret_previous.map(Redacted::new),
            hmac_key: hmac_key.map(Redacted::new),
        })
    }
}

/// Heuristic check: does a TOML string value look like it might be a secret?
///
/// Returns `true` if the value is long enough and has high Shannon entropy,
/// which suggests it could be a key accidentally placed in the config file.
fn looks_like_secret(value: &str) -> bool {
    // Short values are unlikely to be keys
    if value.len() < 32 {
        return false;
    }
    // All hex chars and long enough: suspicious
    if value.len() >= MIN_API_KEY_HEX_LEN && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Shannon entropy check: high entropy strings are suspicious
    let mut freq = [0u32; 256];
    for b in value.bytes() {
        freq[b as usize] += 1;
    }
    #[allow(clippy::cast_precision_loss)] // entropy heuristic; precision loss irrelevant
    let len = value.len() as f64;
    let entropy: f64 = freq
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / len;
            -p * p.log2()
        })
        .sum();
    // English text ~4.0 bits, random hex ~4.0, random base64 ~5.5
    // A threshold of 4.5 catches most generated keys while allowing
    // normal config values through.
    entropy > 4.5
}

/// Scan raw TOML text for secret-like values in key-related fields.
///
/// Returns `Err` if any field whose name contains "key", "secret", "token",
/// or "password" has a value that passes the `looks_like_secret` heuristic.
fn walk_toml_for_secrets(table: &toml::Table, prefix: &str) -> Result<(), ConfigError> {
    let suspect_names = ["key", "secret", "token", "password", "credential"];
    for (key, value) in table {
        let full_key = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::String(s) => {
                let lower = key.to_ascii_lowercase();
                if suspect_names.iter().any(|n| lower.contains(n)) && looks_like_secret(s) {
                    return Err(ConfigError::SecretInToml { key: full_key });
                }
            }
            toml::Value::Table(inner) => {
                walk_toml_for_secrets(inner, &full_key)?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn check_toml_for_secrets(toml_text: &str) -> Result<(), ConfigError> {
    let table: toml::Table =
        toml::from_str(toml_text).map_err(|e| ConfigError::TomlParse(e.to_string()))?;
    walk_toml_for_secrets(&table, "")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guards all tests that touch process-global env vars so they do not race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn valid_toml() -> String {
        r#"
[policy]
max_template_age_secs = 30
max_sigops = 80000
max_weight = 4000000
rate_limit_requests_per_sec = 100
rate_limit_burst = 200
api_auth_mode = "bearer_token"
data_dir = "/tmp"
"#
        .to_string()
    }

    #[test]
    fn parse_valid_config() {
        let cfg = PolicyConfig::from_toml(&valid_toml()).expect("parse");
        assert_eq!(cfg.max_template_age_secs, 30);
        assert_eq!(cfg.max_sigops, 80000);
        assert_eq!(cfg.api_auth_mode, ApiAuthMode::BearerToken);
        assert_eq!(cfg.tls_mode, TlsMode::Required);
        // Defaults applied
        assert_eq!(cfg.max_request_body_bytes, 1_048_576);
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.handler_deadline_secs, 10);
    }

    #[test]
    fn reject_missing_required_field() {
        let toml = r"
[policy]
max_template_age_secs = 30
";
        let err = PolicyConfig::from_toml(toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::TomlParse(_)),
            "expected TomlParse, got {err:?}"
        );
    }

    #[test]
    fn reject_unknown_field() {
        let toml = format!("{}\n{}", valid_toml().trim(), "bogus_field = 42");
        let err = PolicyConfig::from_toml(&toml).unwrap_err();
        assert!(
            matches!(err, ConfigError::TomlParse(_)),
            "expected TomlParse for unknown field, got {err:?}"
        );
    }

    #[test]
    fn validate_catches_zero_max_template_age() {
        let toml = valid_toml().replace("max_template_age_secs = 30", "max_template_age_secs = 0");
        let cfg = PolicyConfig::from_toml(&toml).expect("parse");
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ConfigError::MaxTemplateAgeZero(0)),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_catches_burst_below_rate() {
        let toml = valid_toml().replace("rate_limit_burst = 200", "rate_limit_burst = 10");
        let cfg = PolicyConfig::from_toml(&toml).expect("parse");
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ConfigError::BurstBelowRate { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_catches_deadline_exceeds_timeout() {
        let toml = format!(
            "{}\n{}",
            valid_toml().trim(),
            "" // defaults: handler_deadline=10, request_timeout=30 — OK
        );
        let mut cfg = PolicyConfig::from_toml(&toml).expect("parse");
        cfg.handler_deadline_secs = 60;
        cfg.request_timeout_secs = 30;
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ConfigError::DeadlineExceedsTimeout { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn tls_mode_defaults_to_required() {
        let cfg = PolicyConfig::from_toml(&valid_toml()).expect("parse");
        assert_eq!(cfg.tls_mode, TlsMode::Required);
    }

    #[test]
    fn tls_mode_optional_local_only() {
        let toml = valid_toml().replace(
            "api_auth_mode",
            "tls_mode = \"optional_local_only\"\napi_auth_mode",
        );
        let cfg = PolicyConfig::from_toml(&toml).expect("parse");
        assert_eq!(cfg.tls_mode, TlsMode::OptionalLocalOnly);
    }

    #[test]
    fn reject_unknown_tls_mode() {
        let toml = valid_toml().replace("api_auth_mode", "tls_mode = \"yolo\"\napi_auth_mode");
        let err = PolicyConfig::from_toml(&toml).unwrap_err();
        assert!(matches!(err, ConfigError::TomlParse(_)));
    }

    #[test]
    fn secret_detection_catches_hex_key_in_toml() {
        let hex_secret = "a".repeat(64);
        let toml_with_secret = format!(
            "[policy]\nmax_template_age_secs = 30\nmax_sigops = 80000\nmax_weight = 4000000\nrate_limit_requests_per_sec = 100\nrate_limit_burst = 200\napi_auth_mode = \"bearer_token\"\ndata_dir = \"/tmp\"\napi_key = \"{hex_secret}\""
        );
        let err = check_toml_for_secrets(&toml_with_secret).unwrap_err();
        assert!(matches!(err, ConfigError::SecretInToml { .. }));
    }

    #[test]
    fn secret_detection_allows_normal_values() {
        let result = check_toml_for_secrets(&valid_toml());
        assert!(result.is_ok());
    }

    // SAFETY: env var tests must run serially (cargo test runs them in
    // separate threads but each test uses a unique env var name or the
    // test is self-contained). Rust 2024 marks set_var/remove_var as
    // unsafe because concurrent mutation is UB; we accept this in tests.

    #[test]
    fn secrets_from_env_rejects_short_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("VELDRA_API_SECRET", "abcd1234") };
        let err = Secrets::from_env(ApiAuthMode::BearerToken).unwrap_err();
        unsafe { std::env::remove_var("VELDRA_API_SECRET") };
        assert!(matches!(err, SecretError::ApiSecretTooShort { .. }));
    }

    #[test]
    fn secrets_from_env_rejects_non_hex() {
        let _guard = ENV_LOCK.lock().unwrap();
        let non_hex = "g".repeat(64);
        unsafe { std::env::set_var("VELDRA_API_SECRET", &non_hex) };
        let err = Secrets::from_env(ApiAuthMode::BearerToken).unwrap_err();
        unsafe { std::env::remove_var("VELDRA_API_SECRET") };
        assert!(matches!(err, SecretError::ApiSecretNotHex));
    }

    #[test]
    fn secrets_from_env_rejects_missing_bearer_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("VELDRA_API_SECRET") };
        let err = Secrets::from_env(ApiAuthMode::BearerToken).unwrap_err();
        assert!(matches!(err, SecretError::BearerTokenMissingSecret));
    }

    #[test]
    fn secrets_from_env_rejects_missing_hmac_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("VELDRA_HMAC_KEY") };
        let err = Secrets::from_env(ApiAuthMode::HmacSha256).unwrap_err();
        assert!(matches!(err, SecretError::HmacMissingKey));
    }

    #[test]
    fn secrets_from_env_accepts_valid_bearer() {
        let _guard = ENV_LOCK.lock().unwrap();
        let valid_key = "a".repeat(64);
        unsafe { std::env::set_var("VELDRA_API_SECRET", &valid_key) };
        let secrets = Secrets::from_env(ApiAuthMode::BearerToken).expect("should succeed");
        assert!(secrets.api_secret.is_some());
        // Verify Redacted wrapper does not leak the key
        let debug = format!("{:?}", secrets.api_secret.as_ref().expect("present"));
        assert_eq!(debug, "[REDACTED]");
        unsafe { std::env::remove_var("VELDRA_API_SECRET") };
    }

    #[test]
    fn env_overlay_overrides_field() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = PolicyConfig::from_toml(&valid_toml()).expect("parse");
        assert_eq!(cfg.max_sigops, 80000);
        unsafe { std::env::set_var("VELDRA_MAX_SIGOPS", "42000") };
        cfg.apply_env_overrides();
        unsafe { std::env::remove_var("VELDRA_MAX_SIGOPS") };
        assert_eq!(cfg.max_sigops, 42000);
    }

    #[test]
    fn env_overlay_ignores_non_numeric() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut cfg = PolicyConfig::from_toml(&valid_toml()).expect("parse");
        unsafe { std::env::set_var("VELDRA_MAX_SIGOPS", "not_a_number") };
        cfg.apply_env_overrides();
        unsafe { std::env::remove_var("VELDRA_MAX_SIGOPS") };
        assert_eq!(cfg.max_sigops, 80000); // unchanged
    }

    #[test]
    fn looks_like_secret_catches_hex_string() {
        let hex = "a".repeat(64);
        assert!(looks_like_secret(&hex));
    }

    #[test]
    fn looks_like_secret_ignores_short_strings() {
        assert!(!looks_like_secret("hello"));
        assert!(!looks_like_secret(""));
    }

    #[test]
    fn looks_like_secret_ignores_normal_paths() {
        assert!(!looks_like_secret("/etc/ssl/certs/ca-certificates.crt"));
    }
}
