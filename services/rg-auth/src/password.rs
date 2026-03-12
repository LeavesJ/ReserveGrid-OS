use anyhow::{Context, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

/// Hash a plaintext password with argon2id.
pub fn hash(plaintext: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))
        .context("hash password")?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against an argon2 hash string.
pub fn verify(plaintext: &str, hash_str: &str) -> Result<bool> {
    let parsed =
        PasswordHash::new(hash_str).map_err(|e| anyhow::anyhow!("parse password hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify() {
        let h = hash("correct-horse-battery-staple").unwrap();
        assert!(verify("correct-horse-battery-staple", &h).unwrap());
        assert!(!verify("wrong-password", &h).unwrap());
    }

    #[test]
    fn different_salts() {
        let h1 = hash("same").unwrap();
        let h2 = hash("same").unwrap();
        // Same plaintext produces different hashes (unique salts).
        assert_ne!(h1, h2);
        assert!(verify("same", &h1).unwrap());
        assert!(verify("same", &h2).unwrap());
    }
}
