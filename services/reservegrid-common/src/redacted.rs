//! Redaction wrapper for secret-bearing values.
//!
//! `Redacted<T>` wraps a value so that `Debug` and `Display` emit `[REDACTED]`
//! instead of the inner value. Business logic accesses the raw value via `.inner()`.
//! The inner value is zeroed on drop when `T: Zeroize`.

use std::fmt;

use zeroize::Zeroize;

/// A wrapper that prevents secrets from leaking into logs, debug output, or
/// serialized forms.
///
/// # Usage
/// ```
/// use reservegrid_common::redacted::Redacted;
///
/// let secret = Redacted::new("super_secret_key".to_string());
/// assert_eq!(format!("{secret:?}"), "[REDACTED]");
/// assert_eq!(secret.inner(), "super_secret_key");
/// ```
pub struct Redacted<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Redacted<T> {
    /// Wrap a value in a redaction guard.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Access the raw inner value. Use only in business logic paths that
    /// genuinely need the secret (e.g., key comparison). Never pass the
    /// return value to logging, serialization, or display.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for Redacted<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_value() {
        let secret = Redacted::new("my_api_key_12345".to_string());
        let debug_output = format!("{secret:?}");
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("my_api_key"));
    }

    #[test]
    fn display_never_leaks_value() {
        let secret = Redacted::new("my_api_key_12345".to_string());
        let display_output = format!("{secret}");
        assert_eq!(display_output, "[REDACTED]");
    }

    #[test]
    fn inner_returns_actual_value() {
        let secret = Redacted::new("the_real_secret".to_string());
        assert_eq!(secret.inner(), "the_real_secret");
    }
}
