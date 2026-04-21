use std::time::{SystemTime, UNIX_EPOCH};

use rg_consensus::ConsensusViolation;
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, VerdictReason};
use serde::{Deserialize, Serialize};

/// Bitcoin consensus constants.
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
pub const MAX_BLOCK_SIGOPS: u32 = 80_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum FeeTier {
    Low,
    Mid,
    High,
}

impl FeeTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeeTier::Low => "low",
            FeeTier::Mid => "mid",
            FeeTier::High => "high",
        }
    }
}

/// An observe only safety finding that did not cause rejection.
#[derive(Debug, Clone)]
pub struct SafetyWarning {
    pub reason: VerdictReason,
    pub detail: String,
}

/// Result of policy evaluation against a template.
///
/// `reason` carries the canonical `rg_protocol::VerdictReason` directly —
/// no intermediate local enum, no mapping step.
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// `None` = accepted. `Some(reason)` = rejected.
    pub reason: Option<VerdictReason>,
    /// Human-readable detail string (thresholds, actual values).
    pub detail: Option<String>,
    /// Fee tier selected for this evaluation.
    pub fee_tier: FeeTier,
    /// Effective minimum average fee used for the decision.
    pub min_avg_fee_used: u64,
    /// Observe only safety warnings (never cause rejection on their own).
    pub warnings: Vec<SafetyWarning>,
    /// `true` when the v2.0 Invariant Shield pass was reached but the
    /// template omitted `raw_block_hex`. The caller increments
    /// `verifier_shield_skipped_total` to make the Phase 1 rollout
    /// visibility explicit. `false` for rejected-before-shield and for
    /// shield-ran paths (agreed or rejected).
    pub shield_skipped: bool,
}

fn default_max_weight_ratio() -> f64 {
    0.999
}

fn default_warn_sigops_ratio() -> f64 {
    0.95
}

fn default_warn_coinbase_sigops_max() -> u32 {
    400
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySafety {
    #[serde(default = "default_max_weight_ratio")]
    pub max_weight_ratio: f64,

    #[serde(default)]
    pub enforce_weight_ratio: bool,

    #[serde(default)]
    pub max_template_age_ms: Option<u64>,

    #[serde(default)]
    pub enforce_template_age: bool,

    #[serde(default = "default_warn_sigops_ratio")]
    pub warn_sigops_ratio: f64,

    #[serde(default = "default_warn_coinbase_sigops_max")]
    pub warn_coinbase_sigops_max: u32,
}

impl Default for PolicySafety {
    fn default() -> Self {
        Self {
            max_weight_ratio: default_max_weight_ratio(),
            enforce_weight_ratio: false,
            max_template_age_ms: None,
            enforce_template_age: false,
            warn_sigops_ratio: default_warn_sigops_ratio(),
            warn_coinbase_sigops_max: default_warn_coinbase_sigops_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,

    #[serde(default = "default_required_prevhash_len")]
    pub required_prevhash_len: usize,

    #[serde(default)]
    pub min_total_fees: u64,

    #[serde(default = "default_max_tx_count")]
    pub max_tx_count: u32,

    #[serde(default = "default_low_mempool_tx")]
    pub low_mempool_tx: u64,

    #[serde(default = "default_high_mempool_tx")]
    pub high_mempool_tx: u64,

    #[serde(default)]
    pub min_avg_fee_lo: u64,
    #[serde(default)]
    pub min_avg_fee_mid: u64,
    #[serde(default)]
    pub min_avg_fee_hi: u64,

    #[serde(default = "default_reject_empty_templates")]
    pub reject_empty_templates: bool,

    #[serde(default = "default_reject_coinbase_zero")]
    pub reject_coinbase_zero: bool,

    #[serde(default = "default_unknown_mempool_as_high")]
    pub unknown_mempool_as_high: bool,

    #[serde(default)]
    pub safety: PolicySafety,
}

fn default_protocol_version() -> u16 {
    PROTOCOL_VERSION
}

fn default_required_prevhash_len() -> usize {
    64
}

fn default_max_tx_count() -> u32 {
    10_000
}

fn default_low_mempool_tx() -> u64 {
    50
}

fn default_high_mempool_tx() -> u64 {
    500
}

fn default_reject_empty_templates() -> bool {
    true
}

fn default_reject_coinbase_zero() -> bool {
    false
}

fn default_unknown_mempool_as_high() -> bool {
    true
}

fn is_hex(s: &str) -> bool {
    s.as_bytes().iter().all(|&b| b.is_ascii_hexdigit())
}

/// Check basic template validity: version, `prev_hash`, and basic constraints.
fn check_basic_validity(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    if template.version != cfg.protocol_version {
        return Some(EvalResult {
            reason: Some(VerdictReason::ProtocolVersionMismatch),
            detail: Some(format!(
                "protocol_version got={} expected={}",
                template.version, cfg.protocol_version
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if template.prev_hash.len() != cfg.required_prevhash_len {
        return Some(EvalResult {
            reason: Some(VerdictReason::PrevHashLenMismatch),
            detail: Some(format!(
                "prev_hash len={} expected={}",
                template.prev_hash.len(),
                cfg.required_prevhash_len
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if !is_hex(&template.prev_hash) {
        return Some(EvalResult {
            reason: Some(VerdictReason::InvalidPrevHash),
            detail: Some("prev_hash contains non-hex characters".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    None
}

/// Check template constraints: tx count, total fees, and average fees.
fn check_template_constraints(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    if cfg.reject_empty_templates && template.tx_count == 0 {
        return Some(EvalResult {
            reason: Some(VerdictReason::EmptyTemplateRejected),
            detail: Some("empty template rejected by policy".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if cfg.reject_coinbase_zero && template.coinbase_value == 0 && template.tx_count > 0 {
        return Some(EvalResult {
            reason: Some(VerdictReason::CoinbaseValueZeroRejected),
            detail: Some("coinbase_value=0 rejected by policy".to_string()),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if template.tx_count > cfg.max_tx_count {
        return Some(EvalResult {
            reason: Some(VerdictReason::TxCountExceeded),
            detail: Some(format!(
                "tx_count={} > max_tx_count={}",
                template.tx_count, cfg.max_tx_count
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if template.total_fees < cfg.min_total_fees {
        return Some(EvalResult {
            reason: Some(VerdictReason::TotalFeesBelowMinimum),
            detail: Some(format!(
                "total_fees={} < min_total_fees={}",
                template.total_fees, cfg.min_total_fees
            )),
            fee_tier,
            min_avg_fee_used,
            warnings: vec![],
            shield_skipped: false,
        });
    }

    if min_avg_fee_used > 0 && template.tx_count > 0 {
        // Ceiling division so rounding never makes a below-threshold
        // average appear to pass. Without this, a template with
        // total_fees=15001 and tx_count=3 yields avg=5000 (floor)
        // instead of 5001, silently bypassing a min_avg_fee=5001 policy.
        let tx = u64::from(template.tx_count);
        let avg = template.total_fees.div_ceil(tx);
        if avg < min_avg_fee_used {
            return Some(EvalResult {
                reason: Some(VerdictReason::AvgFeeBelowMinimum),
                detail: Some(format!(
                    "avg_fee={avg} < min_avg_fee_used={min_avg_fee_used}"
                )),
                fee_tier,
                min_avg_fee_used,
                warnings: vec![],
                shield_skipped: false,
            });
        }
    }

    None
}

/// Check consensus safety constraints: weight ratio, template age, sigops.
fn check_safety_constraints(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    now_ms: u64,
    warnings: &mut Vec<SafetyWarning>,
    fee_tier: FeeTier,
    min_avg_fee_used: u64,
) -> Option<EvalResult> {
    // Weight ratio: use template_weight (canonical) or observed_weight (legacy)
    let effective_weight = template.template_weight.or(template.observed_weight);
    if let Some(weight) = effective_weight {
        #[allow(clippy::cast_precision_loss)]
        let ratio = weight as f64 / MAX_BLOCK_WEIGHT as f64;
        if ratio > cfg.safety.max_weight_ratio {
            let detail = format!(
                "weight_ratio={:.4} > max_weight_ratio={:.4} (weight={} max={})",
                ratio, cfg.safety.max_weight_ratio, weight, MAX_BLOCK_WEIGHT
            );
            if cfg.safety.enforce_weight_ratio {
                return Some(EvalResult {
                    reason: Some(VerdictReason::WeightRatioExceeded),
                    detail: Some(detail),
                    fee_tier,
                    min_avg_fee_used,
                    warnings: warnings.clone(),
                    shield_skipped: false,
                });
            }
            warnings.push(SafetyWarning {
                reason: VerdictReason::WeightRatioExceeded,
                detail,
            });
        }
    }

    // Template staleness
    if let (Some(created), Some(max_age)) =
        (template.created_at_unix_ms, cfg.safety.max_template_age_ms)
    {
        let age_ms = now_ms.saturating_sub(created);
        if age_ms > max_age {
            let detail = format!("template_age_ms={age_ms} > max_template_age_ms={max_age}");
            if cfg.safety.enforce_template_age {
                return Some(EvalResult {
                    reason: Some(VerdictReason::TemplateStale),
                    detail: Some(detail),
                    fee_tier,
                    min_avg_fee_used,
                    warnings: warnings.clone(),
                    shield_skipped: false,
                });
            }
            warnings.push(SafetyWarning {
                reason: VerdictReason::TemplateStale,
                detail,
            });
        }
    }

    // Sigops budget warning (observe only in 0.2.2)
    if let Some(sigops) = template.total_sigops {
        #[allow(clippy::cast_precision_loss)]
        let ratio = f64::from(sigops) / f64::from(MAX_BLOCK_SIGOPS);
        if ratio > cfg.safety.warn_sigops_ratio {
            warnings.push(SafetyWarning {
                reason: VerdictReason::SigopsBudgetWarning,
                detail: format!(
                    "sigops_ratio={:.4} > warn_sigops_ratio={:.4} (sigops={} max={})",
                    ratio, cfg.safety.warn_sigops_ratio, sigops, MAX_BLOCK_SIGOPS
                ),
            });
        }
    }

    // Coinbase sigops anomaly (observe only in 0.2.2)
    if let Some(cb_sigops) = template.coinbase_sigops
        && cb_sigops > cfg.safety.warn_coinbase_sigops_max
    {
        warnings.push(SafetyWarning {
            reason: VerdictReason::CoinbaseSigopsAbnormal,
            detail: format!(
                "coinbase_sigops={cb_sigops} > warn_coinbase_sigops_max={}",
                cfg.safety.warn_coinbase_sigops_max
            ),
        });
    }

    None
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |_| 0,
        |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
    )
}

impl PolicyConfig {
    pub fn default_with_protocol(protocol_version: u16) -> Self {
        PolicyConfig {
            protocol_version,
            required_prevhash_len: 64,
            min_total_fees: 0,
            max_tx_count: 10_000,
            low_mempool_tx: 50,
            high_mempool_tx: 500,
            min_avg_fee_lo: 0,
            min_avg_fee_mid: 500,
            min_avg_fee_hi: 2_000,
            reject_empty_templates: true,
            reject_coinbase_zero: false,
            unknown_mempool_as_high: true,
            safety: PolicySafety::default(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::anyhow;

        if self.protocol_version != PROTOCOL_VERSION {
            anyhow::bail!(
                "policy.protocol_version={} does not match binary PROTOCOL_VERSION={}",
                self.protocol_version,
                PROTOCOL_VERSION
            );
        }

        if self.required_prevhash_len == 0 {
            return Err(anyhow!("required_prevhash_len must be > 0"));
        }

        if self.max_tx_count == 0 {
            return Err(anyhow!("max_tx_count must be > 0"));
        }

        if self.low_mempool_tx > self.high_mempool_tx {
            return Err(anyhow!(
                "low_mempool_tx ({}) must be <= high_mempool_tx ({})",
                self.low_mempool_tx,
                self.high_mempool_tx
            ));
        }

        // Fee tier ordering: lo <= mid <= hi. Inverted tiers silently
        // produce confusing rejection patterns.
        if self.min_avg_fee_lo > self.min_avg_fee_mid {
            return Err(anyhow!(
                "min_avg_fee_lo ({}) must be <= min_avg_fee_mid ({})",
                self.min_avg_fee_lo,
                self.min_avg_fee_mid
            ));
        }
        if self.min_avg_fee_mid > self.min_avg_fee_hi {
            return Err(anyhow!(
                "min_avg_fee_mid ({}) must be <= min_avg_fee_hi ({})",
                self.min_avg_fee_mid,
                self.min_avg_fee_hi
            ));
        }

        if !(self.safety.max_weight_ratio.is_finite()
            && self.safety.max_weight_ratio > 0.0
            && self.safety.max_weight_ratio <= 1.0)
        {
            return Err(anyhow!(
                "safety.max_weight_ratio ({}) must be a finite number in (0, 1]",
                self.safety.max_weight_ratio
            ));
        }

        if !(self.safety.warn_sigops_ratio.is_finite()
            && self.safety.warn_sigops_ratio > 0.0
            && self.safety.warn_sigops_ratio <= 1.0)
        {
            return Err(anyhow!(
                "safety.warn_sigops_ratio ({}) must be a finite number in (0, 1]",
                self.safety.warn_sigops_ratio
            ));
        }

        Ok(())
    }

    pub fn effective_min_avg_fee_dynamic(&self, mempool_tx: Option<u64>) -> (u64, FeeTier) {
        match mempool_tx {
            Some(tx) => {
                if tx < self.low_mempool_tx {
                    (self.min_avg_fee_lo, FeeTier::Low)
                } else if tx < self.high_mempool_tx {
                    (self.min_avg_fee_mid, FeeTier::Mid)
                } else {
                    (self.min_avg_fee_hi, FeeTier::High)
                }
            }
            None => {
                if self.unknown_mempool_as_high {
                    (self.min_avg_fee_hi, FeeTier::High)
                } else {
                    (self.min_avg_fee_mid, FeeTier::Mid)
                }
            }
        }
    }
}

/// Outcome of the v2.0 Invariant Shield pass (ADR-002 Phase 1).
///
/// The shield is the last stage of `evaluate_dynamic`. It re-derives
/// consensus critical values from the raw block bytes supplied on the
/// wire as `raw_block_hex` and compares them against the declared
/// template fields. The outcome feeds back into `EvalResult` plus the
/// `verifier_shield_skipped_total` metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldOutcome {
    /// Template omitted `raw_block_hex`. Shield pass did not run. The
    /// caller counts the skip so Phase 1 rollout coverage is observable.
    Skipped,
    /// Shield ran and every re-derivation agreed with the declared
    /// value. Template continues toward acceptance.
    Agreed,
    /// Shield ran and detected a disagreement. The carried reason is a
    /// canonical `v2_invariant_*` `VerdictReason` and the detail string
    /// is human readable only.
    Rejected {
        reason: VerdictReason,
        detail: String,
    },
}

/// Map a `ConsensusViolation` returned by the rg-consensus facade to
/// the canonical `VerdictReason` variant that mirrors the same
/// `snake_case` reason code string. The mapping is exhaustive by
/// construction; reason code drift across crates is caught by the
/// `snake_case` round trip tests in `rg-protocol` and `rg-consensus`.
///
/// `ConsensusViolation::NotImplemented` is a shield-disabled sentinel
/// and MUST NOT reach this function once Phase 1 has landed. If it
/// does, the facade has been misconfigured; we surface it as
/// `InternalError` so the observability pipeline flags the drift
/// rather than silently routing a sentinel onto the wire.
fn consensus_violation_to_verdict_reason(v: &ConsensusViolation) -> VerdictReason {
    match v {
        ConsensusViolation::DecodeFailed { .. } => VerdictReason::V2InvariantDecodeFailed,
        ConsensusViolation::CoinbaseValueMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseValueMismatch
        }
        ConsensusViolation::TemplateWeightMismatch { .. } => {
            VerdictReason::V2InvariantTemplateWeightMismatch
        }
        ConsensusViolation::MerkleRootMismatch { .. } => {
            VerdictReason::V2InvariantMerkleRootMismatch
        }
        ConsensusViolation::WitnessCommitmentMissing => {
            VerdictReason::V2InvariantWitnessCommitmentMissing
        }
        ConsensusViolation::WitnessCommitmentMismatch { .. } => {
            VerdictReason::V2InvariantWitnessCommitmentMismatch
        }
        ConsensusViolation::SigopsMismatch { .. } => VerdictReason::V2InvariantSigopsMismatch,
        ConsensusViolation::CoinbaseSigopsMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseSigopsMismatch
        }
        ConsensusViolation::TxCountMismatch { .. } => VerdictReason::V2InvariantTxCountMismatch,
        ConsensusViolation::CoinbaseScriptLength => VerdictReason::V2InvariantCoinbaseScriptLength,
        ConsensusViolation::CoinbaseOutputCount => VerdictReason::V2InvariantCoinbaseOutputCount,
        ConsensusViolation::CoinbaseBip34Missing => VerdictReason::V2InvariantCoinbaseBip34Missing,
        ConsensusViolation::CoinbaseHeightMismatch { .. } => {
            VerdictReason::V2InvariantCoinbaseHeightMismatch
        }
        ConsensusViolation::WeightExceedsMax => VerdictReason::V2InvariantWeightExceedsMax,
        ConsensusViolation::SigopsExceedMax => VerdictReason::V2InvariantSigopsExceedMax,
        ConsensusViolation::NonCoinbaseNullPrevout => VerdictReason::V2InvariantNontcbNullPrevout,
        ConsensusViolation::HeaderVersionLow => VerdictReason::V2InvariantHeaderVersionLow,
        ConsensusViolation::DuplicateTx => VerdictReason::V2InvariantDuplicateTx,
        ConsensusViolation::NotImplemented => VerdictReason::InternalError,
    }
}

/// Run the v2.0 Invariant Shield pass against a template.
///
/// Phase 1 scope: only the fields the wire already carries declared
/// values for are checked against re-derived values. That is:
/// `coinbase_value` (always) and `template_weight` (when present).
/// The remaining invariants need declared wire fields to compare
/// against and land in Phase 1b.
///
/// When `raw_block_hex` is `None` the shield is silently skipped and
/// the caller increments `verifier_shield_skipped_total` via the
/// `shield_skipped` field on `EvalResult`. When the hex decode fails
/// the shield emits `v2_invariant_decode_failed` so bad gateway
/// encodings surface loudly rather than silently bypassing the shield.
pub fn check_invariant_shield(template: &TemplatePropose) -> ShieldOutcome {
    let Some(hex_str) = template.raw_block_hex.as_deref() else {
        return ShieldOutcome::Skipped;
    };

    let raw_block = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(e) => {
            return ShieldOutcome::Rejected {
                reason: VerdictReason::V2InvariantDecodeFailed,
                detail: format!("raw_block_hex decode failed: {e}"),
            };
        }
    };

    // Coinbase value re-derivation is always comparable.
    match rg_consensus::re_derive_coinbase_value(&raw_block) {
        Ok(re_derived) => {
            if re_derived != template.coinbase_value {
                return ShieldOutcome::Rejected {
                    reason: VerdictReason::V2InvariantCoinbaseValueMismatch,
                    detail: format!(
                        "coinbase_value declared={} re_derived={}",
                        template.coinbase_value, re_derived
                    ),
                };
            }
        }
        Err(v) => {
            return ShieldOutcome::Rejected {
                reason: consensus_violation_to_verdict_reason(&v),
                detail: v.to_string(),
            };
        }
    }

    // Template weight re-derivation only runs when the sender declared
    // a value. Senders that omit template_weight still benefit from the
    // coinbase value check above.
    if let Some(declared) = template.template_weight {
        match rg_consensus::re_derive_template_weight(&raw_block) {
            Ok(re_derived) => {
                if re_derived != declared {
                    return ShieldOutcome::Rejected {
                        reason: VerdictReason::V2InvariantTemplateWeightMismatch,
                        detail: format!(
                            "template_weight declared={declared} re_derived={re_derived}"
                        ),
                    };
                }
            }
            Err(v) => {
                return ShieldOutcome::Rejected {
                    reason: consensus_violation_to_verdict_reason(&v),
                    detail: v.to_string(),
                };
            }
        }
    }

    ShieldOutcome::Agreed
}

/// Convenience wrapper: evaluate with no mempool context.
pub fn evaluate(template: &TemplatePropose, cfg: &PolicyConfig) -> EvalResult {
    evaluate_dynamic(template, cfg, None, now_unix_ms())
}

/// Core policy evaluation. Returns an `EvalResult` whose `reason` field
/// carries the canonical `rg_protocol::VerdictReason` directly — no
/// intermediate local enum, no mapping layer.
///
/// `now_ms` is the current unix timestamp in milliseconds, passed explicitly
/// to keep the function deterministic for testing.
pub fn evaluate_dynamic(
    template: &TemplatePropose,
    cfg: &PolicyConfig,
    mempool_tx: Option<u64>,
    now_ms: u64,
) -> EvalResult {
    let (min_avg_fee_used, fee_tier) = cfg.effective_min_avg_fee_dynamic(mempool_tx);

    // Check basic validity (version, prev_hash)
    if let Some(result) = check_basic_validity(template, cfg, fee_tier, min_avg_fee_used) {
        return result;
    }

    // Check template constraints (tx count, total fees, avg fees)
    if let Some(result) = check_template_constraints(template, cfg, fee_tier, min_avg_fee_used) {
        return result;
    }

    // ── v0.2.2 consensus safety checks ──
    let mut warnings: Vec<SafetyWarning> = Vec::new();
    if let Some(result) = check_safety_constraints(
        template,
        cfg,
        now_ms,
        &mut warnings,
        fee_tier,
        min_avg_fee_used,
    ) {
        return result;
    }

    // ── v2.0 Invariant Shield (ADR-002 Phase 1) ──
    // Runs after safety so earlier policy rejects short circuit first
    // and the shield only sees templates that have already passed every
    // prior check. Strictly additive: templates that omit raw_block_hex
    // bypass the shield without altering the prior verdict path.
    let shield_skipped = match check_invariant_shield(template) {
        ShieldOutcome::Skipped => true,
        ShieldOutcome::Agreed => false,
        ShieldOutcome::Rejected { reason, detail } => {
            return EvalResult {
                reason: Some(reason),
                detail: Some(detail),
                fee_tier,
                min_avg_fee_used,
                warnings,
                shield_skipped: false,
            };
        }
    };

    EvalResult {
        reason: None,
        detail: None,
        fee_tier,
        min_avg_fee_used,
        warnings,
        shield_skipped,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rg_protocol::VerdictReason;

    /// Helper: build a valid `TemplatePropose` with sensible defaults.
    fn base_template() -> TemplatePropose {
        TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 1,
            block_height: 100,
            prev_hash: "a".repeat(64),
            coinbase_value: 5000,
            tx_count: 10,
            total_fees: 50_000,
            observed_weight: None,
            created_at_unix_ms: None,
            total_sigops: None,
            coinbase_sigops: None,
            template_weight: None,
            gateway_instance_id: None,
            raw_block_hex: None,
        }
    }

    // --- tier_naming_consistent ---

    #[test]
    fn fee_tier_as_str_returns_canonical_values() {
        assert_eq!(FeeTier::Low.as_str(), "low");
        assert_eq!(FeeTier::Mid.as_str(), "mid");
        assert_eq!(FeeTier::High.as_str(), "high");
    }

    #[test]
    fn fee_tier_as_str_only_canonical() {
        let valid = ["low", "mid", "high"];
        for tier in [FeeTier::Low, FeeTier::Mid, FeeTier::High] {
            assert!(
                valid.contains(&tier.as_str()),
                "FeeTier::{:?} returned non-canonical: {}",
                tier,
                tier.as_str()
            );
        }
    }

    // --- policy_context_tier_values ---

    #[test]
    fn eval_result_fee_tier_is_canonical() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let template = base_template();

        let valid_tiers = ["low", "mid", "high"];
        let ts = now_unix_ms();

        for mempool_tx in [Some(0), Some(100), Some(1000), None] {
            let result = evaluate_dynamic(&template, &cfg, mempool_tx, ts);
            assert!(
                valid_tiers.contains(&result.fee_tier.as_str()),
                "Non-canonical tier for mempool_tx={:?}: {}",
                mempool_tx,
                result.fee_tier.as_str()
            );
        }
    }

    // --- eval_result_exhaustive: every policy rejection is a valid VerdictReason ---

    #[test]
    #[allow(clippy::too_many_lines)]
    fn eval_result_reasons_are_all_valid_verdict_reasons() {
        let cfg = PolicyConfig {
            protocol_version: PROTOCOL_VERSION,
            required_prevhash_len: 64,
            min_total_fees: 100,
            max_tx_count: 5,
            low_mempool_tx: 10,
            high_mempool_tx: 100,
            min_avg_fee_lo: 0,
            min_avg_fee_mid: 500,
            min_avg_fee_hi: 2000,
            reject_empty_templates: true,
            reject_coinbase_zero: true,
            unknown_mempool_as_high: true,
            safety: PolicySafety::default(),
        };

        let ts = now_unix_ms();

        // Trigger each policy rejection reason.
        let cases: Vec<(TemplatePropose, VerdictReason)> = vec![
            // ProtocolVersionMismatch
            (
                TemplatePropose {
                    version: 99,
                    id: 1,
                    ..base_template()
                },
                VerdictReason::ProtocolVersionMismatch,
            ),
            // PrevHashLenMismatch
            (
                TemplatePropose {
                    id: 2,
                    prev_hash: "aa".to_string(),
                    ..base_template()
                },
                VerdictReason::PrevHashLenMismatch,
            ),
            // InvalidPrevHash
            (
                TemplatePropose {
                    id: 3,
                    prev_hash: "g".repeat(64),
                    ..base_template()
                },
                VerdictReason::InvalidPrevHash,
            ),
            // EmptyTemplateRejected
            (
                TemplatePropose {
                    id: 4,
                    tx_count: 0,
                    total_fees: 0,
                    ..base_template()
                },
                VerdictReason::EmptyTemplateRejected,
            ),
            // CoinbaseValueZeroRejected
            (
                TemplatePropose {
                    id: 5,
                    coinbase_value: 0,
                    tx_count: 1,
                    total_fees: 5000,
                    ..base_template()
                },
                VerdictReason::CoinbaseValueZeroRejected,
            ),
            // TxCountExceeded
            (
                TemplatePropose {
                    id: 6,
                    tx_count: 100,
                    total_fees: 500_000,
                    ..base_template()
                },
                VerdictReason::TxCountExceeded,
            ),
            // TotalFeesBelowMinimum
            (
                TemplatePropose {
                    id: 7,
                    tx_count: 1,
                    total_fees: 0,
                    ..base_template()
                },
                VerdictReason::TotalFeesBelowMinimum,
            ),
            // AvgFeeBelowMinimum (use high tier: mempool_tx=None, unknown_as_high=true)
            (
                TemplatePropose {
                    id: 8,
                    tx_count: 1,
                    total_fees: 200,
                    ..base_template()
                },
                VerdictReason::AvgFeeBelowMinimum,
            ),
        ];

        for (template, expected_reason) in &cases {
            let result = evaluate_dynamic(template, &cfg, None, ts);
            assert_eq!(
                result.reason,
                Some(*expected_reason),
                "Template id={} expected {:?} got {:?}",
                template.id,
                expected_reason,
                result.reason
            );
            if let Some(reason) = &result.reason {
                assert!(
                    VerdictReason::ALL_CODES.contains(&reason.as_str()),
                    "reason {:?} as_str={} not in ALL_CODES",
                    reason,
                    reason.as_str()
                );
            }
        }
    }

    // --- accepted path returns None reason ---

    #[test]
    fn accepted_template_has_no_reason() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let template = base_template();
        let result = evaluate(&template, &cfg);
        assert!(
            result.reason.is_none(),
            "accepted template should have reason=None"
        );
        assert!(
            result.detail.is_none(),
            "accepted template should have detail=None"
        );
    }

    // ── v0.2.2 consensus safety tests ──

    #[test]
    fn weight_ratio_exceeded_enforced() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_999_000), // ratio = 0.99975, exceeds 0.999
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert_eq!(result.reason, Some(VerdictReason::WeightRatioExceeded));
    }

    #[test]
    fn weight_ratio_exceeded_observe_only() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: false,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_999_000),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none(), "observe only should not reject");
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::WeightRatioExceeded
        );
    }

    #[test]
    fn weight_ratio_under_limit_no_warning() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_weight_ratio: 0.999,
                enforce_weight_ratio: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            template_weight: Some(3_000_000), // ratio = 0.75, well under limit
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn template_stale_enforced() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(5_000),
                enforce_template_age: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let now = now_unix_ms();
        let template = TemplatePropose {
            created_at_unix_ms: Some(now.saturating_sub(10_000)), // 10s old, limit is 5s
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now);
        assert_eq!(result.reason, Some(VerdictReason::TemplateStale));
    }

    #[test]
    fn template_stale_observe_only() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(5_000),
                enforce_template_age: false,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let now = now_unix_ms();
        let template = TemplatePropose {
            created_at_unix_ms: Some(now.saturating_sub(10_000)),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now);
        assert!(result.reason.is_none(), "observe only should not reject");
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].reason, VerdictReason::TemplateStale);
    }

    #[test]
    fn sigops_warning_fires_above_threshold() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_sigops_ratio: 0.95,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            total_sigops: Some(77_000), // 96.25% of 80,000
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::SigopsBudgetWarning
        );
    }

    #[test]
    fn sigops_warning_silent_below_threshold() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_sigops_ratio: 0.95,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            total_sigops: Some(64_000), // 80% of 80,000
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn coinbase_sigops_anomaly_detection() {
        let cfg = PolicyConfig {
            safety: PolicySafety {
                warn_coinbase_sigops_max: 400,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };

        let template = TemplatePropose {
            coinbase_sigops: Some(500),
            ..base_template()
        };

        let result = evaluate_dynamic(&template, &cfg, None, now_unix_ms());
        assert!(result.reason.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].reason,
            VerdictReason::CoinbaseSigopsAbnormal
        );
    }

    #[test]
    fn new_fields_backward_compatible_serde() {
        // TemplatePropose without the v0.2.2 fields should deserialize fine.
        let json = r#"{
            "version": 2,
            "id": 1,
            "block_height": 100,
            "prev_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "coinbase_value": 5000,
            "tx_count": 10,
            "total_fees": 50000
        }"#;
        let t: TemplatePropose = serde_json::from_str(json).unwrap();
        assert!(t.total_sigops.is_none());
        assert!(t.coinbase_sigops.is_none());
        assert!(t.template_weight.is_none());
        assert!(t.observed_weight.is_none());
        assert!(t.created_at_unix_ms.is_none());
        assert!(t.raw_block_hex.is_none());
    }

    // ── v2.0 Invariant Shield tests (ADR-002 Phase 1) ──

    /// Mainnet genesis block raw hex. Hardcoded rather than serialized
    /// via rust-bitcoin at test time so pool-verifier keeps depending
    /// only on `rg-consensus` at its facade boundary (ADR-002). The
    /// facade itself verifies that this constant round-trips through
    /// `re_derive_*` to the expected coinbase value and weight.
    const GENESIS_RAW_HEX: &str = concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
        "4b1e5e4a29ab5f49ffff001d1dac2b7c01010000000100000000000000000000",
        "00000000000000000000000000000000000000000000ffffffff4d04ffff001d",
        "0104455468652054696d65732030332f4a616e2f32303039204368616e63656c",
        "6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f75742066",
        "6f722062616e6b73ffffffff0100f2052a0100000043410467",
        "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649",
        "f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac",
        "00000000",
    );

    /// Genesis coinbase value: the 50 BTC subsidy at height 0.
    const GENESIS_COINBASE_SATS: u64 = 50 * 100_000_000;

    /// Compute the genesis block weight through the facade itself.
    /// Using `re_derive_template_weight` here keeps pool-verifier free
    /// of a direct `bitcoin` dev-dependency and exercises the same
    /// code path the shield runs in production.
    fn genesis_weight_via_facade() -> u64 {
        let bytes = hex::decode(GENESIS_RAW_HEX).expect("GENESIS_RAW_HEX decodes");
        rg_consensus::re_derive_template_weight(&bytes).expect("genesis weight re-derives")
    }

    #[test]
    fn genesis_raw_hex_constant_round_trips_through_facade() {
        // Sanity check the hardcoded constant: if the hex ever drifts,
        // every downstream shield test breaks with a cryptic decode
        // failure. This test names the drift clearly.
        let bytes = hex::decode(GENESIS_RAW_HEX).expect("GENESIS_RAW_HEX decodes");
        let coinbase = rg_consensus::re_derive_coinbase_value(&bytes)
            .expect("coinbase value re-derives from GENESIS_RAW_HEX");
        assert_eq!(coinbase, GENESIS_COINBASE_SATS);
    }

    #[test]
    fn shield_skipped_without_raw_block_hex() {
        let outcome = check_invariant_shield(&base_template());
        assert_eq!(outcome, ShieldOutcome::Skipped);
    }

    #[test]
    fn shield_decode_failed_on_bad_hex() {
        let t = TemplatePropose {
            raw_block_hex: Some("not_hex_at_all".to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantDecodeFailed);
            }
            other => panic!("expected Rejected(V2InvariantDecodeFailed) got {other:?}"),
        }
    }

    #[test]
    fn shield_decode_failed_on_garbage_bytes() {
        // Valid hex that does not deserialize as a block.
        let t = TemplatePropose {
            raw_block_hex: Some("ffffffffffffff".to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantDecodeFailed);
            }
            other => panic!("expected Rejected(V2InvariantDecodeFailed) got {other:?}"),
        }
    }

    #[test]
    fn shield_coinbase_value_mismatch_rejects() {
        let t = TemplatePropose {
            // Declared coinbase != genesis 50 BTC.
            coinbase_value: 1,
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, detail } => {
                assert_eq!(reason, VerdictReason::V2InvariantCoinbaseValueMismatch);
                assert!(
                    detail.contains("declared=1"),
                    "detail missing declared value: {detail}"
                );
            }
            other => panic!("expected Rejected(V2InvariantCoinbaseValueMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_template_weight_mismatch_rejects() {
        let weight = genesis_weight_via_facade();
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            template_weight: Some(weight + 1),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        match check_invariant_shield(&t) {
            ShieldOutcome::Rejected { reason, .. } => {
                assert_eq!(reason, VerdictReason::V2InvariantTemplateWeightMismatch);
            }
            other => panic!("expected Rejected(V2InvariantTemplateWeightMismatch) got {other:?}"),
        }
    }

    #[test]
    fn shield_agrees_on_genesis_happy_path() {
        let weight = genesis_weight_via_facade();
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            template_weight: Some(weight),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        assert_eq!(check_invariant_shield(&t), ShieldOutcome::Agreed);
    }

    #[test]
    fn shield_agrees_when_template_weight_absent() {
        // No declared template_weight means the weight re-derivation
        // is skipped; the coinbase value check must still pass alone.
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            template_weight: None,
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        assert_eq!(check_invariant_shield(&t), ShieldOutcome::Agreed);
    }

    #[test]
    fn shield_does_not_override_earlier_safety_rejection() {
        // Shield runs after safety. A stale template that also carries
        // a valid raw_block_hex must still reject with TemplateStale,
        // not propagate an Agreed outcome past safety.
        let cfg = PolicyConfig {
            safety: PolicySafety {
                max_template_age_ms: Some(1_000),
                enforce_template_age: true,
                ..PolicySafety::default()
            },
            ..PolicyConfig::default_with_protocol(PROTOCOL_VERSION)
        };
        let now = now_unix_ms();
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            created_at_unix_ms: Some(now.saturating_sub(5_000)),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        let result = evaluate_dynamic(&t, &cfg, None, now);
        assert_eq!(result.reason, Some(VerdictReason::TemplateStale));
        // Shield never ran because safety short-circuited first.
        assert!(!result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_sets_shield_skipped_when_hex_absent() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let result = evaluate(&base_template(), &cfg);
        assert!(result.reason.is_none());
        assert!(result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_clears_shield_skipped_when_shield_runs() {
        let weight = genesis_weight_via_facade();
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let t = TemplatePropose {
            coinbase_value: GENESIS_COINBASE_SATS,
            template_weight: Some(weight),
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        let result = evaluate(&t, &cfg);
        assert!(result.reason.is_none());
        assert!(!result.shield_skipped);
    }

    #[test]
    fn evaluate_dynamic_emits_shield_reject_as_verdict_reason() {
        let cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
        let t = TemplatePropose {
            coinbase_value: 1,
            raw_block_hex: Some(GENESIS_RAW_HEX.to_string()),
            ..base_template()
        };
        let result = evaluate(&t, &cfg);
        assert_eq!(
            result.reason,
            Some(VerdictReason::V2InvariantCoinbaseValueMismatch)
        );
        assert!(!result.shield_skipped);
    }

    #[test]
    fn shield_violation_mapping_is_distinct_across_invariants() {
        // Catch silent collapses to a single VerdictReason across the
        // 18 shield variants. NotImplemented is the shield-disabled
        // sentinel and intentionally routes to InternalError.
        let mut seen: Vec<VerdictReason> = ConsensusViolation::ALL
            .iter()
            .filter(|v| !matches!(v, ConsensusViolation::NotImplemented))
            .map(consensus_violation_to_verdict_reason)
            .collect();
        let before = seen.len();
        seen.sort_by_key(VerdictReason::as_str);
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "consensus_violation_to_verdict_reason collapsed two variants onto one reason"
        );
    }
}
