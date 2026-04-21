//! v2.0 Invariant Shield facade.
//!
//! `rg-consensus` re-derives consensus critical values from raw block
//! bytes. Callers compare the re-derived value against the declared
//! value supplied by the template-manager and emit the matching
//! `v2_invariant_*` reason code on mismatch.
//!
//! # Design invariants (ADR-002)
//!
//! 1. No upstream parser type crosses the API boundary. The facade
//!    returns only `u64`, `u32`, `[u8; 32]`, `Option<[u8; 32]>`.
//! 2. Every error variant maps to a single canonical `snake_case`
//!    reason code string with the `v2_invariant_` prefix. The
//!    mapping is exhaustive and tested.
//! 3. Reason code strings are owned by `rg-protocol::VerdictReason`
//!    and `reservegrid-common::ReasonCode`. The `as_reason_code()`
//!    method returns the canonical string; the enum variant is
//!    matched to the same `snake_case` string by the downstream
//!    round-trip tests.
//!
//! During scaffolding the five public functions return
//! [`ConsensusViolation::NotImplemented`]. Callers may link against
//! the real symbols today; once rust-bitcoin lands behind this
//! facade the function bodies swap in without any caller-visible
//! surface change.

#![forbid(unsafe_code)]

use std::fmt;

// ─────────────────────────────────────────────────────────────────────
// ConsensusViolation: the single error type crossing the facade
// ─────────────────────────────────────────────────────────────────────

/// Every failure mode the Invariant Shield can report.
///
/// Each variant maps 1:1 to a canonical reason code string under the
/// `v2_invariant_` prefix. The mapping lives in
/// [`ConsensusViolation::as_reason_code`] and is the authoritative
/// source for this crate. `rg-protocol::VerdictReason` and
/// `reservegrid-common::ReasonCode` mirror the same strings; drift is
/// caught by `snake_case` round-trip tests in those crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusViolation {
    /// Raw block bytes failed to deserialize.
    DecodeFailed {
        /// Human readable decode detail (does not cross the wire).
        detail: &'static str,
    },

    /// Coinbase value disagrees with re-derived.
    CoinbaseValueMismatch { declared: u64, re_derived: u64 },

    /// Declared template weight disagrees with re-derived.
    TemplateWeightMismatch { declared: u64, re_derived: u64 },

    /// Merkle root does not match re-derived.
    MerkleRootMismatch {
        declared: [u8; 32],
        re_derived: [u8; 32],
    },

    /// Witness commitment missing when segwit transactions are present.
    WitnessCommitmentMissing,

    /// Witness commitment value does not match re-derived.
    WitnessCommitmentMismatch {
        declared: [u8; 32],
        re_derived: [u8; 32],
    },

    /// Total sigops disagrees with re-derived.
    SigopsMismatch { declared: u32, re_derived: u32 },

    /// Coinbase sigops disagrees with re-derived.
    CoinbaseSigopsMismatch { declared: u32, re_derived: u32 },

    /// Transaction count disagrees with re-derived.
    TxCountMismatch { declared: u32, re_derived: u32 },

    /// Coinbase script length outside BIP-34 constraints.
    CoinbaseScriptLength,

    /// Coinbase output count outside protocol constraints.
    CoinbaseOutputCount,

    /// Coinbase missing height push (BIP-34).
    CoinbaseBip34Missing,

    /// Coinbase height push disagrees with header height.
    CoinbaseHeightMismatch { declared: u32, re_derived: u32 },

    /// Block weight exceeds consensus maximum.
    WeightExceedsMax,

    /// Block sigops exceed consensus maximum.
    SigopsExceedMax,

    /// Non coinbase transaction carries a null prevout.
    NonCoinbaseNullPrevout,

    /// Block header version below active soft fork floor.
    HeaderVersionLow,

    /// Duplicate transaction in block body.
    DuplicateTx,

    /// Facade is scaffolded but the underlying parser is not yet
    /// wired. Callers treat this as a shield-disabled signal and MUST
    /// NOT emit a `v2_invariant_*` reason code from it; the dedicated
    /// `as_reason_code()` mapping routes it to a degraded sentinel
    /// for observability.
    NotImplemented,
}

impl ConsensusViolation {
    /// Every variant, for exhaustive iteration in tests and mappings.
    /// Order matches [`ConsensusViolation::ALL_CODES`].
    pub const ALL: &[ConsensusViolation] = &[
        ConsensusViolation::DecodeFailed {
            detail: "enumeration_placeholder",
        },
        ConsensusViolation::CoinbaseValueMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::TemplateWeightMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::MerkleRootMismatch {
            declared: [0; 32],
            re_derived: [0; 32],
        },
        ConsensusViolation::WitnessCommitmentMissing,
        ConsensusViolation::WitnessCommitmentMismatch {
            declared: [0; 32],
            re_derived: [0; 32],
        },
        ConsensusViolation::SigopsMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::CoinbaseSigopsMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::TxCountMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::CoinbaseScriptLength,
        ConsensusViolation::CoinbaseOutputCount,
        ConsensusViolation::CoinbaseBip34Missing,
        ConsensusViolation::CoinbaseHeightMismatch {
            declared: 0,
            re_derived: 0,
        },
        ConsensusViolation::WeightExceedsMax,
        ConsensusViolation::SigopsExceedMax,
        ConsensusViolation::NonCoinbaseNullPrevout,
        ConsensusViolation::HeaderVersionLow,
        ConsensusViolation::DuplicateTx,
        ConsensusViolation::NotImplemented,
    ];

    /// All canonical reason code strings carried by the 18 shield
    /// violation variants. `NotImplemented` intentionally routes to a
    /// separate degraded sentinel and is not in this list.
    ///
    /// This list is the single source of truth compared against
    /// `rg-protocol::VerdictReason` during cross-crate drift tests.
    pub const ALL_CODES: &[&str] = &[
        "v2_invariant_decode_failed",
        "v2_invariant_coinbase_value_mismatch",
        "v2_invariant_template_weight_mismatch",
        "v2_invariant_merkle_root_mismatch",
        "v2_invariant_witness_commitment_missing",
        "v2_invariant_witness_commitment_mismatch",
        "v2_invariant_sigops_mismatch",
        "v2_invariant_coinbase_sigops_mismatch",
        "v2_invariant_tx_count_mismatch",
        "v2_invariant_coinbase_script_length",
        "v2_invariant_coinbase_output_count",
        "v2_invariant_coinbase_bip34_missing",
        "v2_invariant_coinbase_height_mismatch",
        "v2_invariant_weight_exceeds_max",
        "v2_invariant_sigops_exceed_max",
        "v2_invariant_nontcb_null_prevout",
        "v2_invariant_header_version_low",
        "v2_invariant_duplicate_tx",
    ];

    /// Degraded sentinel emitted when the shield is scaffolded but
    /// the parser is not wired. Kept distinct from the 18 invariant
    /// codes so dashboards can alert on "shield disabled" separately
    /// from "shield disagreed".
    pub const NOT_IMPLEMENTED_CODE: &str = "v2_invariant_not_implemented";

    /// Canonical `snake_case` reason code string for this violation.
    ///
    /// The 18 invariant variants map to the canonical strings in
    /// [`ConsensusViolation::ALL_CODES`]. `NotImplemented` maps to
    /// [`ConsensusViolation::NOT_IMPLEMENTED_CODE`] so it never
    /// collides with a real invariant mismatch in export data.
    pub fn as_reason_code(&self) -> &'static str {
        match self {
            ConsensusViolation::DecodeFailed { .. } => "v2_invariant_decode_failed",
            ConsensusViolation::CoinbaseValueMismatch { .. } => {
                "v2_invariant_coinbase_value_mismatch"
            }
            ConsensusViolation::TemplateWeightMismatch { .. } => {
                "v2_invariant_template_weight_mismatch"
            }
            ConsensusViolation::MerkleRootMismatch { .. } => "v2_invariant_merkle_root_mismatch",
            ConsensusViolation::WitnessCommitmentMissing => {
                "v2_invariant_witness_commitment_missing"
            }
            ConsensusViolation::WitnessCommitmentMismatch { .. } => {
                "v2_invariant_witness_commitment_mismatch"
            }
            ConsensusViolation::SigopsMismatch { .. } => "v2_invariant_sigops_mismatch",
            ConsensusViolation::CoinbaseSigopsMismatch { .. } => {
                "v2_invariant_coinbase_sigops_mismatch"
            }
            ConsensusViolation::TxCountMismatch { .. } => "v2_invariant_tx_count_mismatch",
            ConsensusViolation::CoinbaseScriptLength => "v2_invariant_coinbase_script_length",
            ConsensusViolation::CoinbaseOutputCount => "v2_invariant_coinbase_output_count",
            ConsensusViolation::CoinbaseBip34Missing => "v2_invariant_coinbase_bip34_missing",
            ConsensusViolation::CoinbaseHeightMismatch { .. } => {
                "v2_invariant_coinbase_height_mismatch"
            }
            ConsensusViolation::WeightExceedsMax => "v2_invariant_weight_exceeds_max",
            ConsensusViolation::SigopsExceedMax => "v2_invariant_sigops_exceed_max",
            ConsensusViolation::NonCoinbaseNullPrevout => "v2_invariant_nontcb_null_prevout",
            ConsensusViolation::HeaderVersionLow => "v2_invariant_header_version_low",
            ConsensusViolation::DuplicateTx => "v2_invariant_duplicate_tx",
            ConsensusViolation::NotImplemented => Self::NOT_IMPLEMENTED_CODE,
        }
    }
}

impl fmt::Display for ConsensusViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_reason_code())
    }
}

impl std::error::Error for ConsensusViolation {}

// ─────────────────────────────────────────────────────────────────────
// Facade API
//
// The five functions below are the load-bearing surface per ADR-002
// Option A. Callers MUST depend on `rg-consensus::re_derive_*`, never
// on any upstream parser crate directly.
// ─────────────────────────────────────────────────────────────────────

/// Re-derive the total coinbase output value from the raw block
/// bytes. Callers compare against the declared coinbase value and
/// emit `v2_invariant_coinbase_value_mismatch` on disagreement.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] if the bytes cannot
/// be parsed, or [`ConsensusViolation::NotImplemented`] during
/// scaffolding.
pub fn re_derive_coinbase_value(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let _ = raw_block;
    Err(ConsensusViolation::NotImplemented)
}

/// Re-derive block weight from the raw block bytes per BIP-141
/// accounting (base size times 3 plus total size).
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// [`ConsensusViolation::NotImplemented`] during scaffolding.
pub fn re_derive_template_weight(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let _ = raw_block;
    Err(ConsensusViolation::NotImplemented)
}

/// Re-derive the transaction merkle root from the block body.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// [`ConsensusViolation::NotImplemented`] during scaffolding.
pub fn re_derive_merkle_root(raw_block: &[u8]) -> Result<[u8; 32], ConsensusViolation> {
    let _ = raw_block;
    Err(ConsensusViolation::NotImplemented)
}

/// Re-derive the witness commitment. Returns `None` when the block
/// contains no segwit transactions and therefore requires no
/// commitment; returns `Some` with the 32 byte commitment otherwise.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// [`ConsensusViolation::NotImplemented`] during scaffolding.
pub fn re_derive_witness_commitment(
    raw_block: &[u8],
) -> Result<Option<[u8; 32]>, ConsensusViolation> {
    let _ = raw_block;
    Err(ConsensusViolation::NotImplemented)
}

/// Count total sigops in the block using legacy plus witness
/// accounting. Callers compare against the declared sigops count.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// [`ConsensusViolation::NotImplemented`] during scaffolding.
pub fn count_sigops(raw_block: &[u8]) -> Result<u32, ConsensusViolation> {
    let _ = raw_block;
    Err(ConsensusViolation::NotImplemented)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The 18 shield variants must each map to a distinct canonical
    /// code listed in `ALL_CODES`, and `ALL_CODES` must have length 18.
    #[test]
    fn all_codes_has_eighteen_invariant_entries() {
        assert_eq!(
            ConsensusViolation::ALL_CODES.len(),
            18,
            "ALL_CODES length must match ADR-002 Phase 1 check set"
        );
    }

    #[test]
    fn all_has_nineteen_entries_scaffold_plus_shield() {
        // 18 shield variants plus NotImplemented sentinel.
        assert_eq!(
            ConsensusViolation::ALL.len(),
            19,
            "ALL length drift: did you add a variant?"
        );
    }

    #[test]
    fn every_variant_has_distinct_reason_code() {
        let mut codes: Vec<&'static str> = ConsensusViolation::ALL
            .iter()
            .map(ConsensusViolation::as_reason_code)
            .collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(
            before,
            codes.len(),
            "reason code drift: two variants share a canonical string"
        );
    }

    #[test]
    fn all_codes_are_snake_case_with_prefix() {
        for code in ConsensusViolation::ALL_CODES {
            assert!(
                code.starts_with("v2_invariant_"),
                "ALL_CODES entry missing v2_invariant_ prefix: {code}"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "ALL_CODES entry is not snake_case: {code}"
            );
        }
    }

    #[test]
    fn not_implemented_code_is_outside_all_codes() {
        // NotImplemented is a degraded sentinel, not a real
        // invariant mismatch. It must not collide with the 18.
        assert!(
            !ConsensusViolation::ALL_CODES.contains(&ConsensusViolation::NOT_IMPLEMENTED_CODE),
            "NOT_IMPLEMENTED_CODE must be distinct from the 18 shield codes",
        );
        assert!(
            ConsensusViolation::NOT_IMPLEMENTED_CODE.starts_with("v2_invariant_"),
            "NOT_IMPLEMENTED_CODE must share the v2_invariant_ prefix",
        );
    }

    #[test]
    fn facade_returns_not_implemented_during_scaffold() {
        let empty: &[u8] = &[];
        assert!(matches!(
            re_derive_coinbase_value(empty),
            Err(ConsensusViolation::NotImplemented)
        ));
        assert!(matches!(
            re_derive_template_weight(empty),
            Err(ConsensusViolation::NotImplemented)
        ));
        assert!(matches!(
            re_derive_merkle_root(empty),
            Err(ConsensusViolation::NotImplemented)
        ));
        assert!(matches!(
            re_derive_witness_commitment(empty),
            Err(ConsensusViolation::NotImplemented)
        ));
        assert!(matches!(
            count_sigops(empty),
            Err(ConsensusViolation::NotImplemented)
        ));
    }
}
