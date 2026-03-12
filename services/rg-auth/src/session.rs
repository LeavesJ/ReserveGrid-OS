use rand::Rng;
use std::fmt::Write;

/// Generate a cryptographically random 32-byte hex token (64 hex chars).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex_encode(&bytes)
}

/// Generate a license key for rg-feed-server authentication.
/// Format: `veldra_<40 hex chars>` (20 random bytes, prefixed for easy identification).
pub fn generate_license_key() -> String {
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill(&mut bytes);
    format!("veldra_{}", hex_encode(&bytes))
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

    #[test]
    fn token_length() {
        let t = generate_token();
        assert_eq!(t.len(), 64); // 32 bytes → 64 hex chars
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
    fn license_key_format() {
        let k = generate_license_key();
        assert!(
            k.starts_with("veldra_"),
            "key must start with veldra_ prefix"
        );
        // "veldra_" is 7 chars, 20 bytes = 40 hex chars → total 47
        assert_eq!(k.len(), 47);
        assert!(k[7..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn license_keys_are_unique() {
        let k1 = generate_license_key();
        let k2 = generate_license_key();
        assert_ne!(k1, k2);
    }
}
