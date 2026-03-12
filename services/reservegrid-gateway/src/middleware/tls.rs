//! TLS configuration.
//!
//! Default mode is TLS required. The config option
//! `policy.tls_mode = "optional_local_only"` disables TLS only when the
//! bind address is `127.0.0.1` or `::1`. Any other address with TLS
//! disabled causes a startup error.

use std::net::SocketAddr;

use reservegrid_common::config::TlsMode;

/// Error returned when TLS configuration is invalid.
#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("TLS is optional_local_only but bind address {0} is not loopback")]
    NonLoopbackWithoutTls(SocketAddr),
}

/// Validate that the TLS mode is compatible with the bind address.
///
/// Returns `Ok(true)` when TLS should be enabled, `Ok(false)` when it
/// may be skipped (loopback only), or `Err` when the combination is invalid.
///
/// # Errors
///
/// Returns `TlsConfigError::NonLoopbackWithoutTls` if TLS is set to
/// `optional_local_only` but the bind address is not a loopback address.
pub fn validate_tls(mode: TlsMode, bind: SocketAddr) -> Result<bool, TlsConfigError> {
    match mode {
        TlsMode::Required => Ok(true),
        TlsMode::OptionalLocalOnly => {
            if bind.ip().is_loopback() {
                Ok(false)
            } else {
                Err(TlsConfigError::NonLoopbackWithoutTls(bind))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn required_mode_always_returns_true() {
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();

        assert!(validate_tls(TlsMode::Required, loopback).unwrap());
        assert!(validate_tls(TlsMode::Required, public).unwrap());
    }

    #[test]
    fn optional_local_allows_loopback() {
        let lo4: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let lo6: SocketAddr = "[::1]:8080".parse().unwrap();

        assert!(!validate_tls(TlsMode::OptionalLocalOnly, lo4).unwrap());
        assert!(!validate_tls(TlsMode::OptionalLocalOnly, lo6).unwrap());
    }

    #[test]
    fn optional_local_rejects_non_loopback() {
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let specific: SocketAddr = "192.168.1.1:8080".parse().unwrap();

        assert!(validate_tls(TlsMode::OptionalLocalOnly, public).is_err());
        assert!(validate_tls(TlsMode::OptionalLocalOnly, specific).is_err());
    }
}
