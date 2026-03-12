//! License key validation for observe-mode feed connections.
//!
//! Two validation backends:
//!
//! 1. **Static list**: `VELDRA_FEED_VALID_KEYS` env var or `auth.valid_keys`
//!    config field. Comma-separated keys. Suitable for dev and small deployments.
//!
//! 2. **rg-auth remote**: When `auth.auth_url` is configured, keys are validated
//!    via `POST {auth_url}/api/keys/validate`. This is the production path once
//!    the license key model is built in rg-auth.
//!
//! If both are configured, static list is checked first (fast path). Remote
//! validation is only attempted if the key is not in the static list.

use std::collections::HashSet;
use std::sync::Arc;

use tracing::{info, warn};

/// Shared key validator, cheap to clone.
#[derive(Clone)]
pub struct KeyValidator {
    inner: Arc<Inner>,
}

struct Inner {
    static_keys: HashSet<String>,
    auth_url: Option<String>,
    client: reqwest::Client,
}

impl KeyValidator {
    /// Build a validator from config.
    pub fn new(valid_keys_csv: &str, auth_url: &str) -> Self {
        let static_keys: HashSet<String> = valid_keys_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        let auth_url = if auth_url.is_empty() {
            None
        } else {
            Some(auth_url.trim_end_matches('/').to_string())
        };

        if static_keys.is_empty() && auth_url.is_none() {
            warn!(
                "no license keys configured and no auth_url set; all connections will be rejected"
            );
        } else {
            info!(
                static_keys = static_keys.len(),
                auth_url = auth_url.as_deref().unwrap_or("(none)"),
                "key validator initialized"
            );
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            inner: Arc::new(Inner {
                static_keys,
                auth_url,
                client,
            }),
        }
    }

    /// Validate a license key. Returns `true` if the key is authorized.
    pub async fn validate(&self, key: &str) -> bool {
        if key.is_empty() {
            return false;
        }

        // Fast path: static key list.
        if self.inner.static_keys.contains(key) {
            return true;
        }

        // Slow path: remote validation via rg-auth.
        if let Some(ref url) = self.inner.auth_url {
            return self.validate_remote(url, key).await;
        }

        false
    }

    async fn validate_remote(&self, auth_url: &str, key: &str) -> bool {
        let url = format!("{auth_url}/api/keys/validate");

        let resp = self
            .inner
            .client
            .post(&url)
            .json(&serde_json::json!({ "key": key }))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                // Parse {"valid": true/false}.
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    body.get("valid")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            Ok(r) => {
                warn!(status = %r.status(), "auth key validation returned non-success");
                false
            }
            Err(e) => {
                warn!(error = %e, "auth key validation request failed");
                false
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn validator_static(keys: &str) -> KeyValidator {
        KeyValidator::new(keys, "")
    }

    #[tokio::test]
    async fn empty_key_always_rejected() {
        let v = validator_static("abc,def");
        assert!(!v.validate("").await);
    }

    #[tokio::test]
    async fn static_key_accepted() {
        let v = validator_static("key_alpha, key_beta, key_gamma");
        assert!(v.validate("key_alpha").await);
        assert!(v.validate("key_beta").await);
        assert!(v.validate("key_gamma").await);
    }

    #[tokio::test]
    async fn unknown_key_rejected_no_remote() {
        let v = validator_static("valid_key");
        assert!(!v.validate("invalid_key").await);
    }

    #[tokio::test]
    async fn no_keys_no_url_rejects_all() {
        let v = validator_static("");
        assert!(!v.validate("anything").await);
    }

    #[tokio::test]
    async fn whitespace_trimmed_from_keys() {
        let v = validator_static("  spaced_key  , another ");
        assert!(v.validate("spaced_key").await);
        assert!(v.validate("another").await);
    }

    #[tokio::test]
    async fn unreachable_remote_falls_back_to_reject() {
        // auth_url points to a port that nothing listens on.
        let v = KeyValidator::new("", "http://127.0.0.1:1");
        assert!(!v.validate("some_key").await);
    }
}
