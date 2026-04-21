//! License key validation for observe-mode feed connections.
//!
//! Keys with the `veldra_lic_` prefix are verified offline via Ed25519
//! signature, expiry timestamp, and tier check (must be at least
//! `observe_paid`). Requires `VELDRA_LICENSE_PUBKEY` to be set.
//!
//! v1.1.0 removed the static key list and rg-auth remote callback
//! fallbacks. All keys must be Ed25519 signed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
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
    /// empty string to disable signature verification (all keys rejected).
    pub fn new(pubkey_b64: &str) -> Self {
        let verifying_key = load_verifying_key(pubkey_b64);

        if verifying_key.is_none() {
            warn!("VELDRA_LICENSE_PUBKEY not set; all feed connections will be rejected");
        } else {
            info!("key validator initialized with Ed25519 pubkey");
        }

        Self {
            inner: Arc::new(Inner { verifying_key }),
        }
    }

    /// Validate a license key. Returns `Some(ValidatedKey)` on success with
    /// the org and tier extracted from the signed payload.
    pub fn validate(&self, key: &str) -> Option<ValidatedKey> {
        if key.is_empty() {
            return None;
        }

        let vk = self.inner.verifying_key.as_ref()?;
        Self::validate_signed(key, vk)
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
        KeyValidator::new(&pubkey_b64(vk))
    }

    #[test]
    fn empty_key_always_rejected() {
        let (_, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        assert!(v.validate("").is_none());
    }

    #[test]
    fn no_pubkey_rejects_all() {
        let v = KeyValidator::new("");
        assert!(v.validate("anything").is_none());
    }

    #[test]
    fn unsigned_key_rejected() {
        let (_, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        assert!(v.validate("some_plain_key").is_none());
    }

    #[test]
    fn signed_key_observe_paid_accepted() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_test", "observe_paid", 9_999_999_999);
        let result = v.validate(&key);
        assert!(result.is_some());
        let vk_result = result.unwrap();
        assert_eq!(vk_result.org_id, "org_test");
        assert_eq!(vk_result.tier, "observe_paid");
    }

    #[test]
    fn signed_key_inline_licensed_accepted() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_inline", "inline_licensed", 9_999_999_999);
        assert!(v.validate(&key).is_some());
    }

    #[test]
    fn signed_key_shadow_rejected() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_free", "shadow", 9_999_999_999);
        assert!(v.validate(&key).is_none());
    }

    #[test]
    fn signed_key_expired_rejected() {
        let (sk, vk) = test_keypair();
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&sk, "org_expired", "observe_paid", 1);
        assert!(v.validate(&key).is_none());
    }

    #[test]
    fn signed_key_wrong_signer_rejected() {
        let (_, vk) = test_keypair();
        let other_sk = SigningKey::from_bytes(&[99u8; 32]);
        let v = validator_with_pubkey(&vk);
        let key = sign_test_key(&other_sk, "org_bad", "observe_paid", 9_999_999_999);
        assert!(v.validate(&key).is_none());
    }

    #[test]
    fn signed_key_tampered_payload_rejected() {
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
        assert!(v.validate(&tampered_key).is_none());
    }

    #[test]
    fn load_verifying_key_valid() {
        let (_, vk) = test_keypair();
        let b64 = pubkey_b64(&vk);
        assert!(load_verifying_key(&b64).is_some());
    }

    #[test]
    fn load_verifying_key_empty_returns_none() {
        assert!(load_verifying_key("").is_none());
    }

    #[test]
    fn load_verifying_key_wrong_length_returns_none() {
        let b64 = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(load_verifying_key(&b64).is_none());
    }
}
