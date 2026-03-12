use serde::{Deserialize, Serialize};

pub mod gateway;

pub const PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplatePropose {
    pub version: u16,
    pub id: u64,

    pub block_height: u32,

    /// 64 hex chars (32 bytes). Keep as String for now to avoid custom serde,
    /// but validate length and hex in the verifier.
    pub prev_hash: String,

    pub coinbase_value: u64,
    pub tx_count: u32,
    pub total_fees: u64,

    /// Forward compatible fields. Older senders omit them.
    #[serde(default)]
    pub observed_weight: Option<u64>,

    #[serde(default)]
    pub created_at_unix_ms: Option<u64>,

    /// Consensus safety fields (v0.2.2). Older senders omit them.
    #[serde(default)]
    pub total_sigops: Option<u32>,

    #[serde(default)]
    pub coinbase_sigops: Option<u32>,

    #[serde(default)]
    pub template_weight: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateVerdict {
    pub version: u16,
    pub id: u64,

    pub accepted: bool,

    /// Machine readable reason for rejects.
    #[serde(default)]
    pub reason_code: Option<VerdictReason>,

    /// Human readable detail (log lines, thresholds, etc).
    #[serde(default)]
    pub reason_detail: Option<String>,

    /// Useful for "traceable rejects": what policy decision was applied.
    #[serde(default)]
    pub policy_context: Option<PolicyContext>,
}

/// Canonical machine-readable reason codes for template rejections.
///
/// `rg-protocol` is the **single source of truth** for these codes.
/// The `#[serde(rename_all = "snake_case")]` attribute and the `as_str()`
/// method MUST agree — verified by tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictReason {
    /// template.version != `PROTOCOL_VERSION` or `policy.protocol_version`
    ProtocolVersionMismatch,

    /// `prev_hash` not hex
    InvalidPrevHash,

    /// `prev_hash` length != `required_prevhash_len`
    PrevHashLenMismatch,

    /// `coinbase_value` == 0 and `reject_coinbase_zero` enabled (non-empty templates)
    CoinbaseValueZeroRejected,

    /// `tx_count` == 0 and `reject_empty_templates` enabled
    EmptyTemplateRejected,

    /// `tx_count` > `max_tx_count`
    TxCountExceeded,

    /// `total_fees` < `min_total_fees`
    TotalFeesBelowMinimum,

    /// (`total_fees` / `tx_count`) < effective min avg fee
    AvgFeeBelowMinimum,

    /// policy file could not be parsed/validated
    PolicyLoadError,

    /// verifier could not fetch mempool stats (degraded / fallback path)
    MempoolBackendUnavailable,

    /// unexpected internal failure
    InternalError,

    // ── v0.2.2 consensus safety ──
    /// template weight / `max_block_weight` > `safety.max_weight_ratio`
    WeightRatioExceeded,

    /// template age > `safety.max_template_age_ms`
    TemplateStale,

    /// `total_sigops` approaching consensus limit (observe only in 0.2.2)
    SigopsBudgetWarning,

    /// `coinbase_sigops` outside expected range (observe only in 0.2.2)
    CoinbaseSigopsAbnormal,
}

impl VerdictReason {
    /// Every variant, for exhaustive iteration in tests and mappings.
    pub const ALL: &[VerdictReason] = &[
        VerdictReason::ProtocolVersionMismatch,
        VerdictReason::InvalidPrevHash,
        VerdictReason::PrevHashLenMismatch,
        VerdictReason::CoinbaseValueZeroRejected,
        VerdictReason::EmptyTemplateRejected,
        VerdictReason::TxCountExceeded,
        VerdictReason::TotalFeesBelowMinimum,
        VerdictReason::AvgFeeBelowMinimum,
        VerdictReason::PolicyLoadError,
        VerdictReason::MempoolBackendUnavailable,
        VerdictReason::InternalError,
        VerdictReason::WeightRatioExceeded,
        VerdictReason::TemplateStale,
        VerdictReason::SigopsBudgetWarning,
        VerdictReason::CoinbaseSigopsAbnormal,
    ];

    /// All canonical `snake_case` reason code strings, for test enumeration
    /// and schema validation. Order matches `ALL`.
    pub const ALL_CODES: &[&str] = &[
        "protocol_version_mismatch",
        "invalid_prev_hash",
        "prev_hash_len_mismatch",
        "coinbase_value_zero_rejected",
        "empty_template_rejected",
        "tx_count_exceeded",
        "total_fees_below_minimum",
        "avg_fee_below_minimum",
        "policy_load_error",
        "mempool_backend_unavailable",
        "internal_error",
        "weight_ratio_exceeded",
        "template_stale",
        "sigops_budget_warning",
        "coinbase_sigops_abnormal",
    ];

    /// Returns all canonical `snake_case` reason code strings.
    /// Convenience wrapper over `ALL_CODES`.
    pub fn all_codes() -> &'static [&'static str] {
        Self::ALL_CODES
    }

    /// Canonical `snake_case` string for this reason code.
    ///
    /// This is the stable contract for logs, exports, dashboards, and metrics.
    /// Must match `#[serde(rename_all = "snake_case")]` — enforced by tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            VerdictReason::ProtocolVersionMismatch => "protocol_version_mismatch",
            VerdictReason::InvalidPrevHash => "invalid_prev_hash",
            VerdictReason::PrevHashLenMismatch => "prev_hash_len_mismatch",
            VerdictReason::CoinbaseValueZeroRejected => "coinbase_value_zero_rejected",
            VerdictReason::EmptyTemplateRejected => "empty_template_rejected",
            VerdictReason::TxCountExceeded => "tx_count_exceeded",
            VerdictReason::TotalFeesBelowMinimum => "total_fees_below_minimum",
            VerdictReason::AvgFeeBelowMinimum => "avg_fee_below_minimum",
            VerdictReason::PolicyLoadError => "policy_load_error",
            VerdictReason::MempoolBackendUnavailable => "mempool_backend_unavailable",
            VerdictReason::InternalError => "internal_error",
            VerdictReason::WeightRatioExceeded => "weight_ratio_exceeded",
            VerdictReason::TemplateStale => "template_stale",
            VerdictReason::SigopsBudgetWarning => "sigops_budget_warning",
            VerdictReason::CoinbaseSigopsAbnormal => "coinbase_sigops_abnormal",
        }
    }
}

impl std::fmt::Display for VerdictReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyContext {
    #[serde(default)]
    pub fee_tier: Option<String>, // "low" | "mid" | "high" or "unknown"

    #[serde(default)]
    pub min_avg_fee_used: Option<u64>,

    #[serde(default)]
    pub min_total_fees_used: Option<u64>,

    #[serde(default)]
    pub reject_coinbase_zero: Option<bool>,

    #[serde(default)]
    pub unknown_mempool_as_high: Option<bool>,

    #[serde(default)]
    pub max_weight_ratio: Option<f64>,

    #[serde(default)]
    pub max_template_age_ms: Option<u64>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn as_str_matches_serde_for_all_variants() {
        for variant in VerdictReason::ALL {
            let serde_json = serde_json::to_string(variant).unwrap();
            let expected = format!("\"{}\"", variant.as_str());
            assert_eq!(
                serde_json, expected,
                "as_str() drift for {variant:?}: serde={serde_json} as_str={expected}",
            );
        }
    }

    #[test]
    fn all_constant_covers_every_variant() {
        // If a variant is added to the enum but not to ALL, this count will
        // mismatch and the serde round-trip test below will not cover it.
        assert_eq!(
            VerdictReason::ALL.len(),
            15,
            "VerdictReason::ALL length mismatch — did you add a variant?"
        );
    }

    #[test]
    fn serde_round_trip_all_variants() {
        for variant in VerdictReason::ALL {
            let json = serde_json::to_string(variant).unwrap();
            let back: VerdictReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back, "serde round-trip failed for {variant:?}");
        }
    }

    #[test]
    fn display_matches_as_str() {
        for variant in VerdictReason::ALL {
            assert_eq!(
                variant.to_string(),
                variant.as_str(),
                "Display drift for {variant:?}",
            );
        }
    }

    #[test]
    fn all_strings_are_snake_case() {
        for variant in VerdictReason::ALL {
            let s = variant.as_str();
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "reason code {variant:?} is not snake_case: {s}",
            );
        }
    }

    #[test]
    fn all_codes_matches_all_variants() {
        assert_eq!(
            VerdictReason::ALL.len(),
            VerdictReason::ALL_CODES.len(),
            "ALL and ALL_CODES length mismatch"
        );
        for (variant, code) in VerdictReason::ALL
            .iter()
            .zip(VerdictReason::ALL_CODES.iter())
        {
            assert_eq!(variant.as_str(), *code, "ALL_CODES drift for {variant:?}");
        }
    }

    #[test]
    fn all_codes_fn_returns_all_codes_const() {
        assert_eq!(VerdictReason::all_codes(), VerdictReason::ALL_CODES);
    }
}
