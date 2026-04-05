//! Offline license key validation.
//!
//! License keys are signed tokens issued by veldra.org. The desktop app
//! validates them against an embedded public key with zero network dependency.
//!
//! Key format (v1): `veldra_lic_{base64url_payload}.{base64url_signature}`
//!
//! Payload (JSON):
//! ```json
//! {
//!   "org_id": "org_abc123",
//!   "tier": "inline",
//!   "issued_at": 1711100000,
//!   "expires_at": 1742636000,
//!   "features": ["gateway", "exporter"]
//! }
//! ```
//!
//! Ed25519 signature verification uses a public key embedded at compile
//! time via `VELDRA_LICENSE_PUBKEY` env var (base64). In debug builds,
//! signature verification is skipped if no public key is configured.
//! Release builds require a valid public key and signature.

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use tracing::{info, warn};

/// Compile-time env var with fallback to empty string.
/// `option_env!` returns `Option<&str>`; this unwraps to `""` if unset.
macro_rules! env_or_empty {
    ($name:expr) => {
        match option_env!($name) {
            Some(v) => v,
            None => "",
        }
    };
}

use crate::config::DesktopConfig;

/// Decoded license key payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub org_id: String,
    pub tier: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Runtime license state.
#[derive(Debug)]
pub struct LicenseInfo {
    /// Raw key string as entered by the operator.
    raw_key: RwLock<Option<String>>,
    /// Decoded payload if the key is valid.
    payload: RwLock<Option<LicensePayload>>,
}

impl LicenseInfo {
    /// Load license key from config or env var and validate it.
    pub fn load_from_config(cfg: &DesktopConfig) -> Self {
        let info = Self {
            raw_key: RwLock::new(None),
            payload: RwLock::new(None),
        };

        if let Some(key) = &cfg.license_key {
            match info.validate_and_store(key) {
                Ok(()) => info!("license key validated successfully"),
                Err(e) => warn!(error = %e, "license key validation failed"),
            }
        } else {
            info!("no license key configured, app will show onboarding");
        }

        info
    }

    /// Validate a license key string and store it if valid.
    fn validate_and_store(&self, key: &str) -> Result<(), LicenseError> {
        let payload = Self::parse_key(key)?;
        Self::check_expiry(&payload)?;
        Self::verify_signature(key)?;

        let Ok(mut raw) = self.raw_key.write() else {
            return Err(LicenseError::Internal("lock poisoned"));
        };
        *raw = Some(key.to_string());
        drop(raw);

        let Ok(mut pl) = self.payload.write() else {
            return Err(LicenseError::Internal("lock poisoned"));
        };
        *pl = Some(payload);

        Ok(())
    }

    /// Parse the key prefix and extract the JSON payload.
    fn parse_key(key: &str) -> Result<LicensePayload, LicenseError> {
        let body = key
            .strip_prefix("veldra_lic_")
            .ok_or(LicenseError::InvalidPrefix)?;

        let dot_pos = body.rfind('.').ok_or(LicenseError::MissingSignature)?;
        let payload_b64 = &body[..dot_pos];

        let payload_bytes =
            base64url_decode(payload_b64).map_err(|()| LicenseError::InvalidBase64)?;
        let payload: LicensePayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| LicenseError::InvalidPayload)?;

        Ok(payload)
    }

    /// Check that the key has not expired.
    fn check_expiry(payload: &LicensePayload) -> Result<(), LicenseError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if payload.expires_at < now {
            return Err(LicenseError::Expired {
                expired_at: payload.expires_at,
            });
        }
        Ok(())
    }

    /// Verify the Ed25519 signature against the embedded public key.
    ///
    /// The public key is baked in at compile time from the
    /// `VELDRA_LICENSE_PUBKEY` env var (base64-encoded 32 bytes).
    /// In debug builds, verification is skipped when no key is configured.
    /// Release builds fail hard if the key is missing or the signature
    /// does not verify.
    fn verify_signature(key: &str) -> Result<(), LicenseError> {
        use ed25519_dalek::Verifier;

        // Public key embedded at compile time. Empty string means not configured.
        const PUBKEY_B64: &str = env_or_empty!("VELDRA_LICENSE_PUBKEY");

        if PUBKEY_B64.is_empty() {
            #[cfg(debug_assertions)]
            {
                warn!(
                    "VELDRA_LICENSE_PUBKEY not set, skipping signature verification (debug build)"
                );
                return Ok(());
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(LicenseError::Internal(
                    "VELDRA_LICENSE_PUBKEY not compiled in, cannot verify license",
                ));
            }
        }

        let pubkey_bytes = base64url_decode(PUBKEY_B64)
            .map_err(|()| LicenseError::Internal("compiled-in public key is invalid base64"))?;

        if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(LicenseError::Internal(
                "compiled-in public key has wrong length",
            ));
        }

        let mut pk_array = [0u8; PUBLIC_KEY_LENGTH];
        pk_array.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| LicenseError::Internal("compiled-in public key is invalid"))?;

        // Extract payload and signature from the key string.
        let body = key
            .strip_prefix("veldra_lic_")
            .ok_or(LicenseError::InvalidPrefix)?;
        let dot_pos = body.rfind('.').ok_or(LicenseError::MissingSignature)?;
        let payload_b64 = &body[..dot_pos];
        let sig_b64 = &body[dot_pos + 1..];

        let sig_bytes = base64url_decode(sig_b64).map_err(|()| LicenseError::SignatureInvalid)?;

        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(LicenseError::SignatureInvalid);
        }

        let mut sig_array = [0u8; SIGNATURE_LENGTH];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);

        // The signed message is the base64url-encoded payload (not the decoded JSON).
        // This ensures the signature covers the exact bytes the issuer signed.
        verifying_key
            .verify(payload_b64.as_bytes(), &signature)
            .map_err(|_| LicenseError::SignatureInvalid)?;

        info!("license signature verified");
        Ok(())
    }

    /// Whether the app has a valid, non-expired license.
    pub fn is_valid(&self) -> bool {
        let Ok(pl) = self.payload.read() else {
            return false;
        };
        if let Some(payload) = pl.as_ref() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            payload.expires_at >= now
        } else {
            false
        }
    }

    /// Clear the stored license key (sign out).
    pub fn clear(&self) {
        if let Ok(mut raw) = self.raw_key.write() {
            *raw = None;
        }
        if let Ok(mut pl) = self.payload.write() {
            *pl = None;
        }
    }

    /// Get the current license tier (`observe_free`, `observe_paid`, `inline_licensed`).
    pub fn tier(&self) -> Option<String> {
        let Ok(pl) = self.payload.read() else {
            return None;
        };
        pl.as_ref().map(|p| p.tier.clone())
    }
}

/// Tauri IPC command: get current license status.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // tauri::command requires owned params
pub fn get_license_status(
    state: tauri::State<'_, std::sync::Arc<crate::AppState>>,
) -> serde_json::Value {
    let valid = state.license.is_valid();
    let tier = state.license.tier();
    let has_key = state
        .license
        .raw_key
        .read()
        .map(|k| k.is_some())
        .unwrap_or(false);

    serde_json::json!({
        "has_key": has_key,
        "valid": valid,
        "tier": tier,
    })
}

/// Tauri IPC command: set a new license key (from onboarding UI).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // tauri::command requires owned params
pub fn set_license_key(
    state: tauri::State<'_, std::sync::Arc<crate::AppState>>,
    key: String,
) -> Result<serde_json::Value, String> {
    match state.license.validate_and_store(&key) {
        Ok(()) => {
            info!("license key updated via onboarding");
            if let Err(e) = DesktopConfig::save_license_key(&key) {
                warn!(error = %e, "failed to persist license key to config file");
            }
            Ok(serde_json::json!({
                "ok": true,
                "tier": state.license.tier(),
            }))
        }
        Err(e) => {
            warn!(error = %e, "license key validation failed via IPC");
            // Validation errors (prefix, base64, payload, expired, signature)
            // are safe for the user. Internal errors are not.
            let msg = match &e {
                LicenseError::Internal(_) => "license validation error".to_string(),
                other => format!("{other}"),
            };
            Err(msg)
        }
    }
}

/// Tauri IPC command: clear the license key (sign out).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // tauri::command requires owned params
pub fn clear_license(
    state: tauri::State<'_, std::sync::Arc<crate::AppState>>,
) -> serde_json::Value {
    state.license.clear();
    if let Err(e) = DesktopConfig::clear_license_key() {
        warn!(error = %e, "failed to remove license key from config file");
    }
    info!("license key cleared (sign out)");
    serde_json::json!({ "ok": true })
}

#[derive(Debug)]
pub enum LicenseError {
    InvalidPrefix,
    MissingSignature,
    InvalidBase64,
    InvalidPayload,
    Expired {
        expired_at: u64,
    },
    #[allow(dead_code)]
    SignatureInvalid,
    Internal(&'static str),
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "key must start with 'veldra_lic_'"),
            Self::MissingSignature => write!(f, "key is missing signature component"),
            Self::InvalidBase64 => write!(f, "key payload is not valid base64url"),
            Self::InvalidPayload => write!(f, "key payload is not valid JSON"),
            Self::Expired { expired_at } => write!(f, "key expired at timestamp {expired_at}"),
            Self::SignatureInvalid => write!(f, "key signature verification failed"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for LicenseError {}

/// Minimal base64url decoder (no padding).
/// Avoids adding a dependency for a trivial operation.
fn base64url_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Convert base64url to standard base64.
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    // Add padding.
    let padded = match standard.len() % 4 {
        2 => format!("{standard}=="),
        3 => format!("{standard}="),
        0 => standard,
        _ => return Err(()),
    };

    // Decode using a simple lookup table.
    base64_decode_standard(&padded)
}

fn base64_decode_standard(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[allow(clippy::cast_possible_truncation)] // TABLE has 64 entries; index always fits u8
    fn lookup(c: u8) -> Result<u8, ()> {
        TABLE
            .iter()
            .position(|&x| x == c)
            .map(|p| p as u8)
            .ok_or(())
    }

    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    for chunk in bytes.chunks(4) {
        if chunk.len() != 4 {
            return Err(());
        }

        let (a, b) = (chunk[0], chunk[1]);
        let (c, d) = (chunk[2], chunk[3]);

        let va = lookup(a)?;
        let vb = lookup(b)?;

        out.push((va << 2) | (vb >> 4));

        if c != b'=' {
            let vc = lookup(c)?;
            out.push(((vb & 0x0F) << 4) | (vc >> 2));
            if d != b'=' {
                let vd = lookup(d)?;
                out.push(((vc & 0x03) << 6) | vd);
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        let input = r#"{"org_id":"test","tier":"inline","issued_at":0,"expires_at":9999999999}"#;
        let encoded = base64url_encode(input.as_bytes());
        let decoded = base64url_decode(&encoded).expect("decode");
        assert_eq!(decoded, input.as_bytes());
    }

    #[test]
    fn parse_valid_key() {
        let payload =
            r#"{"org_id":"org_test","tier":"inline","issued_at":0,"expires_at":9999999999}"#;
        let encoded = base64url_encode(payload.as_bytes());
        let key = format!("veldra_lic_{encoded}.fakesig");
        let result = LicenseInfo::parse_key(&key);
        assert!(result.is_ok());
        let pl = result.unwrap();
        assert_eq!(pl.org_id, "org_test");
        assert_eq!(pl.tier, "inline");
    }

    #[test]
    fn reject_missing_prefix() {
        let result = LicenseInfo::parse_key("invalid_key_abc.sig");
        assert!(result.is_err());
    }

    #[test]
    fn reject_expired_key() {
        let payload = LicensePayload {
            org_id: "test".into(),
            tier: "inline".into(),
            issued_at: 0,
            expires_at: 1,
            features: vec![],
        };
        assert!(LicenseInfo::check_expiry(&payload).is_err());
    }

    #[test]
    fn ed25519_sign_and_verify_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate a test keypair.
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();

        let payload_json = r#"{"org_id":"org_test","tier":"inline","issued_at":0,"expires_at":9999999999,"features":["gateway"]}"#;
        let payload_b64 = base64url_encode(payload_json.as_bytes());

        // Sign the base64url payload (same as production path).
        let sig = sk.sign(payload_b64.as_bytes());
        let sig_b64 = base64url_encode(&sig.to_bytes());

        let key = format!("veldra_lic_{payload_b64}.{sig_b64}");

        // Extract and verify manually (mirrors verify_signature logic).
        let body = key.strip_prefix("veldra_lic_").unwrap();
        let dot = body.rfind('.').unwrap();
        let msg = &body[..dot];
        let sig_part = &body[dot + 1..];

        let sig_bytes = base64url_decode(sig_part).unwrap();
        let mut sig_arr = [0u8; SIGNATURE_LENGTH];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        use ed25519_dalek::Verifier;
        assert!(vk.verify(msg.as_bytes(), &signature).is_ok());
    }

    #[test]
    fn ed25519_reject_tampered_payload() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);

        let payload_json = r#"{"org_id":"org_legit","tier":"inline","issued_at":0,"expires_at":9999999999,"features":[]}"#;
        let payload_b64 = base64url_encode(payload_json.as_bytes());
        let sig = sk.sign(payload_b64.as_bytes());
        let sig_b64 = base64url_encode(&sig.to_bytes());

        // Tamper: change org_id in the encoded payload.
        let tampered_json = r#"{"org_id":"org_evil","tier":"inline","issued_at":0,"expires_at":9999999999,"features":[]}"#;
        let tampered_b64 = base64url_encode(tampered_json.as_bytes());

        let tampered_key = format!("veldra_lic_{tampered_b64}.{sig_b64}");

        // Verification should fail because signature was for the original payload.
        let body = tampered_key.strip_prefix("veldra_lic_").unwrap();
        let dot = body.rfind('.').unwrap();
        let msg = &body[..dot];
        let sig_part = &body[dot + 1..];

        let vk = sk.verifying_key();
        let sig_bytes = base64url_decode(sig_part).unwrap();
        let mut sig_arr = [0u8; SIGNATURE_LENGTH];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        use ed25519_dalek::Verifier;
        assert!(vk.verify(msg.as_bytes(), &signature).is_err());
    }

    /// Helper: base64url encode for tests.
    fn base64url_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = if chunk.len() > 1 {
                chunk[1] as usize
            } else {
                0
            };
            let b2 = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            out.push(TABLE[b0 >> 2] as char);
            out.push(TABLE[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
            if chunk.len() > 1 {
                out.push(TABLE[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
            }
            if chunk.len() > 2 {
                out.push(TABLE[b2 & 0x3F] as char);
            }
        }
        out
    }
}
