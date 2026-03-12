//! Deployment mode enum shared across all `ReserveGrid` services.
//!
//! The mode determines data source, enforcement behavior, feature surface,
//! and which services start. Set via `VELDRA_MODE` env var or `mode` field
//! in TOML config.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The three deployment modes of `ReserveGrid`.
///
/// - `Shadow`: free tier. Demo feed, limited dashboard, no enforcement.
/// - `Observe`: paid tier. Real mainnet reference feed, full dashboard, log-only.
/// - `Inline`: production. Operator bitcoind, full enforcement, miner connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployMode {
    Shadow,
    Observe,
    Inline,
}

impl DeployMode {
    /// Stable string representation for configs, logs, and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Observe => "observe",
            Self::Inline => "inline",
        }
    }

    /// Whether the verifier should enforce (reject) or only observe (log).
    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Inline)
    }

    /// Whether the gateway should accept miner connections.
    pub fn accepts_miners(self) -> bool {
        matches!(self, Self::Inline)
    }

    /// Whether verdicts should be persisted to the WAL.
    pub fn persist_verdicts(self) -> bool {
        matches!(self, Self::Observe | Self::Inline)
    }
}

impl fmt::Display for DeployMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeployMode {
    type Err = InvalidMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "shadow" => Ok(Self::Shadow),
            "observe" => Ok(Self::Observe),
            "inline" => Ok(Self::Inline),
            _ => Err(InvalidMode(s.to_string())),
        }
    }
}

/// Error returned when an unrecognized mode string is provided.
#[derive(Debug)]
pub struct InvalidMode(pub String);

impl fmt::Display for InvalidMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid deploy mode '{}': expected shadow, observe, or inline",
            self.0
        )
    }
}

impl std::error::Error for InvalidMode {}

/// Read deploy mode from `VELDRA_MODE` env var, falling back to the provided
/// default. Returns an error if the env var is set but contains an invalid value.
pub fn mode_from_env(default: DeployMode) -> Result<DeployMode, InvalidMode> {
    match std::env::var("VELDRA_MODE") {
        Ok(val) => val.parse(),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_str() {
        for mode in [DeployMode::Shadow, DeployMode::Observe, DeployMode::Inline] {
            let s = mode.as_str();
            let parsed: DeployMode = s.parse().unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn case_insensitive_parse() {
        assert_eq!("SHADOW".parse::<DeployMode>().unwrap(), DeployMode::Shadow);
        assert_eq!(
            "Observe".parse::<DeployMode>().unwrap(),
            DeployMode::Observe
        );
        assert_eq!("INLINE".parse::<DeployMode>().unwrap(), DeployMode::Inline);
    }

    #[test]
    fn invalid_mode_errors() {
        assert!("pilot".parse::<DeployMode>().is_err());
        assert!("".parse::<DeployMode>().is_err());
    }

    #[test]
    fn behavior_flags() {
        assert!(!DeployMode::Shadow.is_enforcing());
        assert!(!DeployMode::Observe.is_enforcing());
        assert!(DeployMode::Inline.is_enforcing());

        assert!(!DeployMode::Shadow.accepts_miners());
        assert!(!DeployMode::Observe.accepts_miners());
        assert!(DeployMode::Inline.accepts_miners());

        assert!(!DeployMode::Shadow.persist_verdicts());
        assert!(DeployMode::Observe.persist_verdicts());
        assert!(DeployMode::Inline.persist_verdicts());
    }

    #[test]
    fn serde_round_trip() {
        let json = serde_json::to_string(&DeployMode::Shadow).unwrap();
        assert_eq!(json, "\"shadow\"");
        let parsed: DeployMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, DeployMode::Shadow);
    }

    /// Verify that `DeployMode` and `GatewayMode` serialize to the same
    /// canonical strings. The two enums serve different roles (verifier vs
    /// gateway behavior flags), but they must agree on variant names so
    /// config files, dashboards, and metrics never use divergent labels.
    #[test]
    fn deploy_mode_and_gateway_mode_strings_are_aligned() {
        use rg_protocol::gateway::GatewayMode;

        let pairs = [
            (DeployMode::Shadow, GatewayMode::Shadow),
            (DeployMode::Observe, GatewayMode::Observe),
            (DeployMode::Inline, GatewayMode::Inline),
        ];
        for (dm, gm) in &pairs {
            assert_eq!(
                dm.as_str(),
                gm.as_str(),
                "DeployMode::{dm:?} and GatewayMode::{gm:?} must produce identical strings"
            );
        }
    }
}
