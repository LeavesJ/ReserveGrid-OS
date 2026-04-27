use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// License key payload. Must stay in sync with the `LicensePayload`
/// definition in `rg-desktop/src/license.rs`. Changes to field names
/// or types are a protocol compatibility break.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    pub org_id: String,
    pub tier: String,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Default license validity period: 365 days in seconds.
const DEFAULT_LICENSE_DURATION_SECS: u64 = 365 * 24 * 60 * 60;

/// Build and sign a license key in `veldra_lic_` format.
///
/// The output is `veldra_lic_{base64url_payload}.{base64url_signature}`.
/// The signed message is the base64url encoded payload bytes (the ASCII
/// string, not the raw JSON). This matches the verification contract in
/// `rg-desktop/src/license.rs`.
pub fn sign_license_key(
    signing_key: &SigningKey,
    org_id: &str,
    tier: &str,
    features: &[String],
) -> String {
    sign_license_key_with_duration(
        signing_key,
        org_id,
        tier,
        features,
        DEFAULT_LICENSE_DURATION_SECS,
    )
}

/// Build and sign a license key with a custom validity duration.
pub fn sign_license_key_with_duration(
    signing_key: &SigningKey,
    org_id: &str,
    tier: &str,
    features: &[String],
    duration_secs: u64,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let payload = LicensePayload {
        org_id: org_id.to_string(),
        tier: tier.to_string(),
        issued_at: now,
        expires_at: now + duration_secs,
        features: features.to_vec(),
    };

    // LicensePayload is String/u64/Vec<String> and always serializes.
    #[allow(clippy::expect_used)]
    let payload_json = serde_json::to_string(&payload).expect("LicensePayload serializes");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // Sign the base64url string bytes, not the raw JSON.
    let signature = signing_key.sign(payload_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    format!("veldra_lic_{payload_b64}.{sig_b64}")
}

/// Parse a `veldra_lic_` key and extract the payload without verifying
/// the signature. Use `verify_license_key` for full validation.
#[allow(dead_code)] // pub API for rg-feed-server and future callers
pub fn parse_license_payload(key: &str) -> Option<LicensePayload> {
    let body = key.strip_prefix("veldra_lic_")?;
    let dot_pos = body.rfind('.')?;
    let payload_b64 = &body[..dot_pos];
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Verify a `veldra_lic_` key's Ed25519 signature and return the payload.
///
/// Returns `None` if the prefix is wrong, the base64 is invalid, the
/// signature does not verify, or the payload cannot be deserialized.
pub fn verify_license_key(key: &str, verifying_key: &VerifyingKey) -> Option<LicensePayload> {
    use ed25519_dalek::{SIGNATURE_LENGTH, Signature, Verifier};

    let body = key.strip_prefix("veldra_lic_")?;
    let dot_pos = body.rfind('.')?;
    let payload_b64 = &body[..dot_pos];
    let sig_b64 = &body[dot_pos + 1..];

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return None;
    }

    let mut sig_array = [0u8; SIGNATURE_LENGTH];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    // Verify over the base64url string, matching the signing path above.
    verifying_key
        .verify(payload_b64.as_bytes(), &signature)
        .ok()?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    serde_json::from_slice(&payload_bytes).ok()
}

/// Load an Ed25519 signing key from a base64 encoded 32 byte seed.
///
/// Returns `None` if the input is empty, not valid base64, or not
/// exactly 32 bytes after decoding.
pub fn load_signing_key(b64_seed: &str) -> Option<SigningKey> {
    if b64_seed.is_empty() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(b64_seed).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Some(SigningKey::from_bytes(&seed))
}

// ── Session token utilities (unchanged) ─────────────────────────

/// Generate a cryptographically random 32-byte hex token (64 hex chars).
///
/// Uses `OsRng` directly for defense in depth: session tokens are
/// security-critical and must use the OS CSPRNG without intermediary layers.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

/// SHA-256 hash a token for storage at rest. The raw token is returned to the
/// client; only the hash is persisted in the database. If the database leaks,
/// session tokens cannot be recovered.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic test keypair from a fixed seed.
    fn test_keypair() -> SigningKey {
        let seed = [42u8; 32];
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn token_length() {
        let t = generate_token();
        assert_eq!(t.len(), 64); // 32 bytes -> 64 hex chars
    }

    #[test]
    fn tokens_are_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_is_hex() {
        let t = generate_token();
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signed_key_has_correct_prefix() {
        let sk = test_keypair();
        let key = sign_license_key(&sk, "org_test", "observe_paid", &[]);
        assert!(
            key.starts_with("veldra_lic_"),
            "key must start with veldra_lic_ prefix, got: {key}"
        );
    }

    #[test]
    fn signed_key_has_dot_separator() {
        let sk = test_keypair();
        let key = sign_license_key(&sk, "org_test", "observe_paid", &[]);
        let body = key.strip_prefix("veldra_lic_").unwrap();
        assert!(body.contains('.'), "key body must contain a dot separator");
    }

    #[test]
    fn signed_key_roundtrip_verify() {
        let sk = test_keypair();
        let vk = sk.verifying_key();
        let key = sign_license_key(&sk, "org_roundtrip", "inline_licensed", &["gateway".into()]);
        let payload = verify_license_key(&key, &vk).expect("signature must verify");
        assert_eq!(payload.org_id, "org_roundtrip");
        assert_eq!(payload.tier, "inline_licensed");
        assert_eq!(payload.features, vec!["gateway".to_string()]);
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let sk = test_keypair();
        let vk = sk.verifying_key();
        let key = sign_license_key(&sk, "org_good", "observe_paid", &[]);

        // Tamper: replace org_id in the base64 payload
        let body = key.strip_prefix("veldra_lic_").unwrap();
        let dot = body.rfind('.').unwrap();
        let sig_part = &body[dot..]; // includes the dot

        let tampered_json = r#"{"org_id":"org_evil","tier":"inline_licensed","issued_at":0,"expires_at":9999999999,"features":[]}"#;
        let tampered_b64 = URL_SAFE_NO_PAD.encode(tampered_json.as_bytes());
        let tampered_key = format!("veldra_lic_{tampered_b64}{sig_part}");

        assert!(
            verify_license_key(&tampered_key, &vk).is_none(),
            "tampered key must fail verification"
        );
    }

    #[test]
    fn wrong_key_fails_verify() {
        let sk = test_keypair();
        let wrong_signer = SigningKey::from_bytes(&[99u8; 32]);
        let wrong_verifier = wrong_signer.verifying_key();
        let key = sign_license_key(&sk, "org_test", "observe_paid", &[]);
        assert!(
            verify_license_key(&key, &wrong_verifier).is_none(),
            "key signed by different keypair must fail"
        );
    }

    #[test]
    fn parse_payload_without_verification() {
        let sk = test_keypair();
        let key = sign_license_key(&sk, "org_parse", "shadow", &["exporter".into()]);
        let payload = parse_license_payload(&key).expect("must parse");
        assert_eq!(payload.org_id, "org_parse");
        assert_eq!(payload.tier, "shadow");
        assert_eq!(payload.features, vec!["exporter".to_string()]);
    }

    #[test]
    fn parse_payload_rejects_bad_prefix() {
        assert!(parse_license_payload("veldra_abc123.sig").is_none());
    }

    #[test]
    fn load_signing_key_roundtrip() {
        let sk = test_keypair();
        let b64 = URL_SAFE_NO_PAD.encode(sk.to_bytes());
        let loaded = load_signing_key(&b64).expect("must load from base64 seed");
        assert_eq!(loaded.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn load_signing_key_rejects_empty() {
        assert!(load_signing_key("").is_none());
    }

    #[test]
    fn load_signing_key_rejects_wrong_length() {
        let b64 = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert!(load_signing_key(&b64).is_none());
    }

    #[test]
    fn hash_token_deterministic() {
        let t = "test_token_abc";
        assert_eq!(hash_token(t), hash_token(t));
    }

    #[test]
    fn hash_token_different_inputs() {
        assert_ne!(hash_token("aaa"), hash_token("bbb"));
    }

    #[test]
    fn hash_token_is_64_hex() {
        let h = hash_token("test");
        assert_eq!(h.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn custom_duration_key() {
        let sk = test_keypair();
        let vk = sk.verifying_key();
        let key = sign_license_key_with_duration(&sk, "org_short", "observe_paid", &[], 3600);
        let payload = verify_license_key(&key, &vk).expect("must verify");
        let delta = payload.expires_at - payload.issued_at;
        assert_eq!(delta, 3600, "custom duration must be reflected in payload");
    }
}
