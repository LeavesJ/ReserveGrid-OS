//! License key validation for observe-mode feed connections.
//!
//! Three validation backends, checked in order:
//!
//! 1. **Signed key (primary)**: Keys with the `veldra_lic_` prefix are verified
//!    offline via Ed25519 signature, expiry timestamp, and tier check (must be
//!    at least `observe_paid`). Requires `VELDRA_LICENSE_PUBKEY` to be set.
//!
//! 2. **Static list**: `VELDRA_FEED_VALID_KEYS` env var or `auth.valid_keys`
//!    config field. Comma-separated keys. Suitable for dev and small deployments.
//!
//! 3. **rg-auth remote**: When `auth.auth_url` is configured, keys are validated
//!    via `POST {auth_url}/api/keys/validate`. Fallback for legacy `veldra_<hex>`
//!    keys during migration. Will be removed in v1.1.0.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

use tracing::{info, warn};

/// Minimum tier required for feed access. Keys with a lower tier are rejected
/// even if the signature is valid.
const MIN_FEED_TIER: &str = "observe_paid";

/// Tiers that satisfy the minimum feed access requirement.
/// Order does not matter; membership check only.
const ALLOWED_TIERS: &[&str] = &["observe_paid", "inline_licensed"];

/// License key payload. Must stay in sync with `rg-auth/src/session.rs` and
/// `rg-desktop/src/license.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub org_id: String,
    pub tier: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Shared key validator, cheap to clone.
#[derive(Clone)]
pub struct KeyValidator {
    inner: Arc<Inner>,
}

struct Inner {
    verifying_key: Option<VerifyingKey>,
    static_keys: HashSet<String>,
    auth_url: Option<String>,
    client: reqwest::Client,
}

/// Result of a successful signed key validation, returned so callers can log
/// the tier and org without re-parsing.
#[derive(Debug)]
pub struct ValidatedKey {
    pub org_id: String,
    pub tier: String,
}

impl KeyValidator {
    /// Build a validator from config. `pubkey_b64` is the base64url encoded
    /// 32 byte Ed25519 public key (from `VELDRA_LICENSE_PUBKEY`). Pass an
    /// empty string to disable signature verification.
    pub fn new(pubkey_b64: &str, valid_keys_csv: &str, auth_url: &str) -> Self {
        let verifying_key = load_verifying_key(pubkey_b64);

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

        if verifying_key.is_none() && static_keys.is_empty() && auth_url.is_none() {
            warn!(
                "no license pubkey, no static keys, and no auth_url; all connections will be rejected"
            );
        } else {
            info!(
                has_pubkey = verifying_key.is_some(),
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
                verifying_key,
                static_keys,
                auth_url,
                client,
            }),
        }
    }

    /// Validate a license key. Returns `Some(ValidatedKey)` on success with
    /// the org and tier extracted from the payload (for signed keys) or
    /// placeholder values (for static/remote keys).
    pub async fn validate(&self, key: &str) -> Option<ValidatedKey> {
        if key.is_empty() {
            return None;
        }

        // Primary path: signed veldra_lic_ keys verified offline.
        if key.starts_with("veldra_lic_") {
            if let Some(ref vk) = self.inner.verifying_key {
                return Self::validate_signed(key, vk);
            }
            // No pubkey configured; fall through to legacy paths.
            warn!("received veldra_lic_ key but VELDRA_LICENSE_PUBKEY is not set");
        }

        // Legacy path 1: static key list.
        if self.inner.static_keys.contains(key) {
            return Some(ValidatedKey {
                org_id: "static".into(),
                tier: "static".into(),
            });
        }

        // Legacy path 2: remote validation via rg-auth.
        if let Some(ref url) = self.inner.auth_url
            && self.validate_remote(url, key).await
        {
            return Some(ValidatedKey {
                org_id: "remote".into(),
                tier: "remote".into(),
            });
        }

        None
    }

    /// Verify a signed `veldra_lic_` key offline. Checks signature, expiry,
    /// and tier in that order.
    fn validate_signed(key: &str, vk: &VerifyingKey) -> Option<ValidatedKey> {
        let body = key.strip_prefix("veldra_lic_")?;
        let dot_pos = body.rfind('.')?;
        let payload_b64 = &body[..dot_pos];
        let sig_b64 = &body[dot_pos + 1..];

        // Decode and verify signature.
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
        if sig_bytes.len() != SIGNATURE_LENGTH {
            warn!("signed key rejected: signature wrong length");
            return None;
        }
        let mut sig_array = [0u8; SIGNATURE_LENGTH];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        if vk.verify(payload_b64.as_bytes(), &signature).is_err() {
            warn!("signed key rejected: signature verification failed");
            return None;
        }

        // Decode payload.
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
        let payload: LicensePayload = serde_json::from_slice(&payload_bytes).ok()?;

        // Check expiry.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if payload.expires_at < now {
            warn!(
                org_id = %payload.org_id,
                expires_at = payload.expires_at,
                "signed key rejected: expired"
            );
            return None;
        }

        // Check tier >= observe_paid.
        if !ALLOWED_TIERS.contains(&payload.tier.as_str()) {
            warn!(
                org_id = %payload.org_id,
                tier = %payload.tier,
                min_tier = MIN_FEED_TIER,
                "signed key rejected: tier insufficient for feed access"
            );
            return None;
        }

        Some(ValidatedKey {
            org_id: payload.org_id,
            tier: payload.tier,
        })
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

/// Load an Ed25519 verifying key from a base64url encoded 32 byte public key.
fn load_verifying_key(b64: &str) -> Option<VerifyingKey> {
    if b64.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(b64).ok()?;
    if bytes.len() != 32 {
        warn!(
            "VELDRA_LICENSE_PUBKEY has wrong length ({} bytes, expected 32)",
            bytes.len()
        );
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    match VerifyingKey::from_bytes(&arr) {
        Ok(vk) => Some(vk),
        Err(e) => {
            warn!(error = %e, "VELDRA_LICENSE_PUBKEY is not a valid Ed25519 public key");
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn pubkey_b64(vk: &VerifyingKey) -> String {
        URL_SAFE_NO_PAD.encode(vk.to_bytes())
    }

    fn sign_test_key(sk: &SigningKey, org: &str, tier: &str, expires_at: u64) -> String {
        let payload = LicensePayload {
            org_id: org.into(),
            tier: tier.into(),
            issued_at: 0,
            expires_at,
            features: vec![],
        };
        let json = serde_json::to_string(&payload).unwrap();
        let b64 = URL_SAFE_NO_PAD.encode(json.as_bytes());
        let sig = sk.sign(b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("veldra_lic_{b64}.{sig_b64}")
    }

    fn validator_with_pubkey(vk: &VerifyingKey) -> KeyValidator {
        KeyValidator::new(&pubkey_b64(vk), "", "")
    }

    fn validator_static(keys: &str) -> KeyValidator {
        KeyValidator::new("", keys, "")
    }

    #[tokio::test]
    async fn empty_key_always_rejected() {
        let v = validator_static("abc,def");
        assert!(v.validate("").await.is_none());
    }

    #[tokio::test]
    async fn static_key_accepted() {
        let v = validator_static("key_alpha, key_beta, key_gamma");
        assert!(v.validate("key_alpha").await.is_some());
        assert!(v.validate("key_beta").await.is_some());
        assert!(v.validate("key_gamma").await.is_some());
    }

    #[tokio::test]
    async fn unknown_key_rejected_no_remote() {
        let v = validator_static("valid_key");
        assert!(v.validate("invalid_key").await.is_none());
    }

    #[tokio::test]
    async fn no_keys_no_url_rejects_all() {
        let v = validator_static("");
        assert!(v.validate("anything").await.is_none());
    }

    #[tokio::test]
    async fn whitespace_trimmed_from_keys() {
        let v = validator_static("  spaced_key  , another ");
        assert!(v.validate("spaced_key").await.is_some());
        assert!(v.validate("another").await.is_some());
    }

    #[tokio::test]
    async fn unreachable_remote_falls_back_to_reject() {
        let v = KeyValidator::new("", "", "http://127.0.0.1:1");
        assert!(v.validate("some_key").await.is_none());
    }

    #[tokio::test]
    async fn signed_key_observe_paid_accepted() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_test", "observe_paid", 9_999_999_999);
        let result = v.validate(&key).await;
        assert!(result.is_some());
        let vk_result = result.unwrap();
        assert_eq!(vk_result.org_id, "org_test");
        assert_eq!(vk_result.tier, "observe_paid");
    }

    #[tokio::test]
    async fn signed_key_inline_licensed_accepted() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_inline", "inline_licensed", 9_999_999_999);
        assert!(v.validate(&key).await.is_some());
    }

    #[tokio::test]
    async fn signed_key_observe_free_rejected() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_free", "observe_free", 9_999_999_999);
        assert!(v.validate(&key).await.is_none());
    }

    #[tokio::test]
    async fn signed_key_expired_rejected() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_expired", "observe_paid", 1);
        assert!(v.validate(&key).await.is_none());
    }

    #[tokio::test]
    async fn signed_key_wrong_signer_rejected() {
        let (_, vk) = test_keypair();
        let other_sk = SigningKey::from_bytes(&[99u8; 32]);
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&other_sk, "org_bad", "observe_paid", 9_999_999_999);
        assert!(v.validate(&key).await.is_none());
    }

    #[tokio::test]
    async fn signed_key_tampered_payload_rejected() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_good", "observe_paid", 9_999_999_999);

        // Tamper with the payload.
        let body = key.strip_prefix("veldra_lic_").unwrap();
        let dot = body.rfind('.').unwrap();
        let sig_part = &body[dot..];
        let tampered_json = r#"{"org_id":"org_evil","tier":"inline_licensed","issued_at":0,"expires_at":9999999999,"features":[]}"#;
        let tampered_b64 = URL_SAFE_NO_PAD.encode(tampered_json.as_bytes());
        let tampered_key = format!("veldra_lic_{tampered_b64}{sig_part}");
        assert!(v.validate(&tampered_key).await.is_none());
    }

    #[tokio::test]
    async fn load_verifying_key_valid() {
        let (_, vk) = test_keypair();
        let b64 = pubkey_b64(&vk);
        assert!(load_verifying_key(&b64).is_some());
    }

    #[tokio::test]
    async fn load_verifying_key_empty_returns_none() {
        assert!(load_verifying_key("").is_none());
    }

    #[tokio::test]
    async fn load_verifying_key_wrong_length_returns_none() {
        let b64 = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(load_verifying_key(&b64).is_none());
    }
}
