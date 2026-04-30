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
//! ADR-002 Phase 1 action item #3 landed 2026-04-21: the five
//! public functions below now re-derive against rust-bitcoin
//! 0.32.8. The `NotImplemented` variant remains in the enum as a
//! shield-disabled sentinel for callers that opt to link against
//! the facade without wiring a parser; no facade function emits it.

#![forbid(unsafe_code)]

use std::fmt;

use bitcoin::Block;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256d;

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

    /// A specific template transaction is not present in the
    /// verifier's mempool view (Phase 2 Class M check).
    ///
    /// Per ADR-003, the per-tx detail mode emits one verdict record
    /// per missing tx with the txid in `reason_detail`. The default
    /// aggregate mode emits a single
    /// [`ConsensusViolation::MempoolToleranceExceeded`] when the
    /// unknown ratio crosses the configured tolerance threshold.
    MempoolTxUnknown {
        /// Transaction id of the missing tx, internal byte order.
        txid: [u8; 32],
    },

    /// The number of template transactions absent from the
    /// verifier's mempool view exceeded the configured tolerance
    /// threshold (Phase 2 Class M check).
    ///
    /// Aggregate-mode counterpart to `MempoolTxUnknown`. The default
    /// 4% threshold lives in `policy.toml` as `mempool_tolerance_pct`;
    /// see ADR-003 D-18.2 for tuning rationale.
    MempoolToleranceExceeded {
        /// Number of template txs not found in the verifier's view.
        unknown_count: u32,
        /// Total number of transactions in the template (excluding coinbase).
        total: u32,
    },

    /// Bitcoind RPC has been unreachable beyond the configured
    /// fail-stale window (Phase 2 Class M check).
    ///
    /// Per ADR-003 D-18.4, the verifier serves the last known
    /// mempool view up to `mempool_max_stale_secs` (default 60s).
    /// Beyond that, the Phase 2 check is skipped and templates fall
    /// through to Phase 1 behavior; this variant accompanies the
    /// resulting verdict to record the degraded path.
    MempoolUnavailable,

    /// The mempool view age exceeded the staleness threshold during
    /// a refresh attempt that did not yet trigger fail-stale
    /// (Phase 2 Class M check).
    ///
    /// Observability variant. Fires when a refresh is overdue but
    /// the view is still being served because the configured
    /// `mempool_max_stale_secs` window has not yet expired.
    MempoolViewStale {
        /// Age of the served mempool view in seconds.
        age_secs: u64,
    },

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
        ConsensusViolation::MempoolTxUnknown { txid: [0; 32] },
        ConsensusViolation::MempoolToleranceExceeded {
            unknown_count: 0,
            total: 0,
        },
        ConsensusViolation::MempoolUnavailable,
        ConsensusViolation::MempoolViewStale { age_secs: 0 },
        ConsensusViolation::NotImplemented,
    ];

    /// All canonical reason code strings carried by the 22 shield
    /// violation variants (18 Phase 1 + 4 Phase 2 Class M).
    /// `NotImplemented` intentionally routes to a separate degraded
    /// sentinel and is not in this list.
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
        "v2_invariant_mempool_tx_unknown",
        "v2_invariant_mempool_tolerance_exceeded",
        "v2_invariant_mempool_unavailable",
        "v2_invariant_mempool_view_stale",
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
            ConsensusViolation::MempoolTxUnknown { .. } => "v2_invariant_mempool_tx_unknown",
            ConsensusViolation::MempoolToleranceExceeded { .. } => {
                "v2_invariant_mempool_tolerance_exceeded"
            }
            ConsensusViolation::MempoolUnavailable => "v2_invariant_mempool_unavailable",
            ConsensusViolation::MempoolViewStale { .. } => "v2_invariant_mempool_view_stale",
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
/// be parsed.
pub fn re_derive_coinbase_value(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let coinbase = block
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    Ok(coinbase.output.iter().map(|o| o.value.to_sat()).sum())
}

/// Re-derive block weight from the raw block bytes per BIP-141
/// accounting (base size times 3 plus total size).
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn re_derive_template_weight(raw_block: &[u8]) -> Result<u64, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    Ok(block.weight().to_wu())
}

/// Re-derive the transaction merkle root from the block body.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure or
/// on an empty block body with no merkle root.
pub fn re_derive_merkle_root(raw_block: &[u8]) -> Result<[u8; 32], ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let root = block
        .compute_merkle_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "merkle_root_empty_block",
        })?;
    Ok(root.to_byte_array())
}

/// Re-derive the witness commitment. Returns `None` when the block
/// contains no segwit transactions and therefore requires no
/// commitment; returns `Some` with the 32 byte commitment otherwise.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn re_derive_witness_commitment(
    raw_block: &[u8],
) -> Result<Option<[u8; 32]>, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;

    // BIP-141: a block carries a witness commitment iff any non
    // coinbase transaction contains witness data. The coinbase
    // witness holds only the reserved value, not true segwit data.
    let has_segwit = block
        .txdata
        .iter()
        .skip(1)
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));

    if !has_segwit {
        return Ok(None);
    }

    let witness_root = block
        .witness_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "witness_root_empty_block",
        })?;

    // BIP-141: witness reserved value is the first (and only)
    // stack element of the coinbase input witness. Missing or
    // malformed witness stacks fall back to 32 zero bytes; the
    // caller flags the resulting commitment mismatch via its own
    // invariant code. The shield only derives; it does not judge.
    let coinbase = block
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let reserved: [u8; 32] = coinbase
        .input
        .first()
        .and_then(|i| i.witness.iter().next())
        .and_then(|w| <[u8; 32]>::try_from(w).ok())
        .unwrap_or([0u8; 32]);

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root.to_byte_array());
    buf[32..].copy_from_slice(&reserved);
    Ok(Some(sha256d::Hash::hash(&buf).to_byte_array()))
}

/// Count total sigops in the block using legacy plus witness
/// accounting. Callers compare against the declared sigops count.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
///
/// # TODO
///
/// Phase 1 counts legacy sigops only (`Script::count_sigops_legacy`
/// across every `script_sig` and `script_pubkey`). Accurate
/// BIP-141 sigop cost (P2SH scale plus witness scale factor) is a
/// follow up; see `Script::count_sigops` and the sigop cost docs
/// in rust-bitcoin. A legacy count is not a strict upper bound for
/// BIP-141 cost on the same block, so a caller emitting
/// `v2_invariant_sigops_mismatch` against an accurate declared
/// count may surface a false positive until this is tightened.
pub fn count_sigops(raw_block: &[u8]) -> Result<u32, ConsensusViolation> {
    let block: Block = deserialize(raw_block).map_err(|_| ConsensusViolation::DecodeFailed {
        detail: "block_deserialize",
    })?;
    let mut total: u64 = 0;
    for tx in &block.txdata {
        for input in &tx.input {
            total = total.saturating_add(input.script_sig.count_sigops_legacy() as u64);
        }
        for output in &tx.output {
            total = total.saturating_add(output.script_pubkey.count_sigops_legacy() as u64);
        }
    }
    Ok(u32::try_from(total).unwrap_or(u32::MAX))
}

// ─────────────────────────────────────────────────────────────────────
// ParsedBlock and single-parse facade (ADR-002 Phase 1 #4b)
//
// `ParsedBlock` is an opaque newtype around `bitcoin::Block`. The
// pool-verifier shield calls `parse_block` once per template and
// passes the resulting `ParsedBlock` to every per-invariant check.
// This avoids the N-deserializations cost of the older `&[u8]`
// facade when running many checks against the same template.
//
// R-154 dep narrowness: `ParsedBlock` does not expose `bitcoin`
// types. Callers receive only `u32`, `[u8; 32]`, and
// `Result<(), ConsensusViolation>`. The newtype's inner field stays
// private so no caller can extract a `bitcoin::Block`.
// ─────────────────────────────────────────────────────────────────────

/// Parsed block wrapper. Construct via [`parse_block`]. Pass by
/// reference into the per-invariant check and re-derive functions.
///
/// The inner `bitcoin::Block` is private and never crosses the
/// crate boundary. Adding a public method that returns `&Block` or
/// `Block` would breach ADR-002 Option A. Add scoped accessors
/// instead.
pub struct ParsedBlock(Block);

/// Deserialize a raw block once. Subsequent shield checks operate
/// on the returned [`ParsedBlock`] without re-parsing.
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] on parse failure.
pub fn parse_block(raw: &[u8]) -> Result<ParsedBlock, ConsensusViolation> {
    deserialize(raw)
        .map(ParsedBlock)
        .map_err(|_| ConsensusViolation::DecodeFailed {
            detail: "block_deserialize",
        })
}

// ─── Class S: standalone internal-consistency checks ───────────────

/// Verify the block header `merkle_root` matches the `sha256d`
/// merkle root computed over the block body.
///
/// Catches tampering of the header field independent of any
/// declared value in `TemplatePropose`.
///
/// # Errors
///
/// Returns [`ConsensusViolation::MerkleRootMismatch`] when the
/// header value disagrees with the body computation. Returns
/// [`ConsensusViolation::DecodeFailed`] on an empty block body
/// where no merkle root can be computed.
pub fn check_merkle_root_internal(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let computed = block
        .0
        .compute_merkle_root()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "merkle_root_empty_block",
        })?;
    let declared = block.0.header.merkle_root;
    if declared != computed {
        return Err(ConsensusViolation::MerkleRootMismatch {
            declared: declared.to_byte_array(),
            re_derived: computed.to_byte_array(),
        });
    }
    Ok(())
}

/// Verify the coinbase witness commitment matches the BIP-141
/// witness root commitment computed over the block body.
///
/// Three outcomes:
/// - Legacy block (no segwit transactions): returns `Ok(())`.
/// - Segwit transactions present, commitment in coinbase
///   `OP_RETURN` matches the computed value: returns `Ok(())`.
/// - Segwit transactions present and commitment missing: returns
///   [`ConsensusViolation::WitnessCommitmentMissing`].
/// - Segwit transactions present and commitment disagrees with
///   computed value: returns [`ConsensusViolation::WitnessCommitmentMismatch`].
///
/// # Errors
///
/// Returns [`ConsensusViolation::DecodeFailed`] when the block has
/// no coinbase or no witness root computable.
pub fn check_witness_commitment_internal(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;

    // BIP-141: a block carries a witness commitment iff any non
    // coinbase transaction contains witness data.
    let has_segwit = block
        .0
        .txdata
        .iter()
        .skip(1)
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));

    let declared = extract_witness_commitment_from_coinbase(coinbase);

    match (has_segwit, declared) {
        (false, _) => Ok(()),
        (true, None) => Err(ConsensusViolation::WitnessCommitmentMissing),
        (true, Some(decl)) => {
            let witness_root = block
                .0
                .witness_root()
                .ok_or(ConsensusViolation::DecodeFailed {
                    detail: "witness_root_empty_block",
                })?;

            // BIP-141: witness reserved value is the first stack
            // element of the coinbase input witness. Missing or
            // malformed falls back to 32 zero bytes.
            let reserved: [u8; 32] = coinbase
                .input
                .first()
                .and_then(|i| i.witness.iter().next())
                .and_then(|w| <[u8; 32]>::try_from(w).ok())
                .unwrap_or([0u8; 32]);

            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&witness_root.to_byte_array());
            buf[32..].copy_from_slice(&reserved);
            let computed = sha256d::Hash::hash(&buf).to_byte_array();

            if decl == computed {
                Ok(())
            } else {
                Err(ConsensusViolation::WitnessCommitmentMismatch {
                    declared: decl,
                    re_derived: computed,
                })
            }
        }
    }
}

/// Verify the coinbase script begins with a BIP-34 height push.
///
/// The shield does not validate the height value here; that is the
/// declaration-mismatch check via [`bip34_height`]. This function
/// only enforces presence: a coinbase that omits the BIP-34 push
/// breaches the post-block-227836 consensus rule.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseBip34Missing`] when the
/// coinbase script does not begin with a valid integer push, or
/// [`ConsensusViolation::DecodeFailed`] on a malformed coinbase.
pub fn check_coinbase_bip34_present(block: &ParsedBlock) -> Result<(), ConsensusViolation> {
    let _ = bip34_height(block)?;
    Ok(())
}

// ─── Class D: re-derive accessors for declared-mismatch checks ─────

/// Number of transactions in the block. Caller compares against
/// `TemplatePropose.tx_count` and emits
/// `v2_invariant_tx_count_mismatch` on disagreement.
///
/// The conversion saturates to `u32::MAX`; any block with more than
/// 4 billion transactions is structurally impossible under the
/// current weight limit.
pub fn tx_count(block: &ParsedBlock) -> u32 {
    u32::try_from(block.0.txdata.len()).unwrap_or(u32::MAX)
}

/// Total legacy sigops summed across every input `script_sig` and
/// every output `script_pubkey` in the block.
///
/// Unit semantics match [`count_sigops`]: legacy count, not BIP-141
/// sigop cost. Callers comparing against `TemplatePropose.total_sigops`
/// must populate the declared field with the same legacy count to
/// avoid false mismatches. BIP-141 cost is a Phase 1.5 concern.
pub fn total_sigops(block: &ParsedBlock) -> u32 {
    let mut total: u64 = 0;
    for tx in &block.0.txdata {
        for input in &tx.input {
            total = total.saturating_add(input.script_sig.count_sigops_legacy() as u64);
        }
        for output in &tx.output {
            total = total.saturating_add(output.script_pubkey.count_sigops_legacy() as u64);
        }
    }
    u32::try_from(total).unwrap_or(u32::MAX)
}

/// Legacy sigops summed across the coinbase transaction only.
/// Caller compares against `TemplatePropose.coinbase_sigops` and
/// emits `v2_invariant_coinbase_sigops_mismatch` on disagreement.
///
/// Unit semantics match [`total_sigops`].
pub fn coinbase_sigops(block: &ParsedBlock) -> u32 {
    let Some(coinbase) = block.0.txdata.first() else {
        return 0;
    };
    let mut total: u64 = 0;
    for input in &coinbase.input {
        total = total.saturating_add(input.script_sig.count_sigops_legacy() as u64);
    }
    for output in &coinbase.output {
        total = total.saturating_add(output.script_pubkey.count_sigops_legacy() as u64);
    }
    u32::try_from(total).unwrap_or(u32::MAX)
}

/// Extract the BIP-34 block height from the coinbase script.
///
/// BIP-34 mandates that the coinbase script begins with a serialized
/// `CScriptNum` push of the block height. This function decodes that
/// push and returns the height as a `u32`.
///
/// # Errors
///
/// Returns [`ConsensusViolation::CoinbaseBip34Missing`] when the
/// coinbase script does not begin with a valid integer push or the
/// integer is negative. Returns [`ConsensusViolation::DecodeFailed`]
/// when the block has no coinbase.
pub fn bip34_height(block: &ParsedBlock) -> Result<u32, ConsensusViolation> {
    let coinbase = block
        .0
        .txdata
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "block_has_no_coinbase",
        })?;
    let input = coinbase
        .input
        .first()
        .ok_or(ConsensusViolation::DecodeFailed {
            detail: "coinbase_has_no_input",
        })?;
    let bytes = input.script_sig.as_bytes();
    decode_bip34_height(bytes).ok_or(ConsensusViolation::CoinbaseBip34Missing)
}

// ─── Internal helpers ──────────────────────────────────────────────

/// Locate the first BIP-141 witness commitment output in a coinbase.
/// Returns the 32-byte commitment when present.
///
/// Format per BIP-141: `OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed <32 bytes>`.
/// The first matching output wins.
fn extract_witness_commitment_from_coinbase(coinbase: &bitcoin::Transaction) -> Option<[u8; 32]> {
    const OP_RETURN: u8 = 0x6a;
    const OP_PUSHBYTES_36: u8 = 0x24;
    const MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

    for output in &coinbase.output {
        let bytes = output.script_pubkey.as_bytes();
        if bytes.len() >= 38
            && bytes[0] == OP_RETURN
            && bytes[1] == OP_PUSHBYTES_36
            && bytes[2..6] == MAGIC
        {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[6..38]);
            return Some(out);
        }
    }
    None
}

/// Decode a BIP-34 minimal `CScriptNum` push from the start of a
/// coinbase script. Returns `None` for missing, oversized, negative,
/// or non-minimal encodings.
///
/// Layout: opcode byte indicating push length (`0x01`..=`0x04`),
/// followed by that many little endian bytes representing a signed
/// integer. The most significant byte's high bit is the sign;
/// negative heights are rejected.
fn decode_bip34_height(script: &[u8]) -> Option<u32> {
    let len_byte = *script.first()?;
    // Reject opcodes outside the direct push range. BIP-34 uses
    // CScriptNum which serializes 1..=4 bytes for any block height
    // up to ~2^31. Block heights past that are far beyond the
    // foreseeable chain.
    if !(0x01..=0x04).contains(&len_byte) {
        return None;
    }
    let len = len_byte as usize;
    if script.len() < 1 + len {
        return None;
    }
    let payload = &script[1..=len];
    // Reject negative (sign bit on the MSB of the most significant
    // byte) and reject zero-length / leading-zero non-minimal forms.
    let last = *payload.last()?;
    if last & 0x80 != 0 {
        return None;
    }
    if len > 1 && last == 0 && (payload[len - 2] & 0x80 == 0) {
        // Non-minimal encoding: leading zero is only allowed when
        // disambiguating a sign bit. We saw last byte == 0 with the
        // previous byte's MSB clear, so the leading zero is redundant.
        return None;
    }
    let mut value: u64 = 0;
    for (i, &b) in payload.iter().enumerate() {
        let mask: u64 = if i == len - 1 { 0x7f } else { 0xff };
        value |= (u64::from(b) & mask) << (i * 8);
    }
    u32::try_from(value).ok()
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The 22 shield variants (18 Phase 1 plus 4 Phase 2 Class M)
    /// must each map to a distinct canonical code listed in
    /// `ALL_CODES`, and `ALL_CODES` must have length 22.
    #[test]
    fn all_codes_has_twenty_two_invariant_entries() {
        assert_eq!(
            ConsensusViolation::ALL_CODES.len(),
            22,
            "ALL_CODES length must match ADR-002 Phase 1 + ADR-003 Phase 2 check set"
        );
    }

    #[test]
    fn all_has_twenty_three_entries_scaffold_plus_shield() {
        // 22 shield variants plus NotImplemented sentinel.
        assert_eq!(
            ConsensusViolation::ALL.len(),
            23,
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

    /// Helper: serialize the mainnet genesis block to the on wire
    /// form the facade expects.
    fn genesis_bytes() -> Vec<u8> {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        use bitcoin::consensus::serialize;
        serialize(&genesis_block(Network::Bitcoin))
    }

    #[test]
    fn garbage_bytes_surface_decode_failed_on_every_function() {
        let junk: &[u8] = &[0xff; 16];
        assert!(matches!(
            re_derive_coinbase_value(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_template_weight(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_merkle_root(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            re_derive_witness_commitment(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
        assert!(matches!(
            count_sigops(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
    }

    #[test]
    fn genesis_coinbase_value_is_fifty_btc() {
        let bytes = genesis_bytes();
        let v = re_derive_coinbase_value(&bytes).expect("genesis parses");
        assert_eq!(v, 50 * 100_000_000, "genesis coinbase value in sats");
    }

    #[test]
    fn genesis_weight_matches_rust_bitcoin() {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        let bytes = genesis_bytes();
        let declared = genesis_block(Network::Bitcoin).weight().to_wu();
        let re_derived = re_derive_template_weight(&bytes).expect("genesis parses");
        assert_eq!(declared, re_derived);
    }

    #[test]
    fn genesis_merkle_root_matches_rust_bitcoin() {
        use bitcoin::Network;
        use bitcoin::blockdata::constants::genesis_block;
        let bytes = genesis_bytes();
        let declared = genesis_block(Network::Bitcoin)
            .compute_merkle_root()
            .expect("genesis has a merkle root")
            .to_byte_array();
        let re_derived = re_derive_merkle_root(&bytes).expect("genesis parses");
        assert_eq!(declared, re_derived);
    }

    #[test]
    fn genesis_has_no_witness_commitment() {
        let bytes = genesis_bytes();
        let c = re_derive_witness_commitment(&bytes).expect("genesis parses");
        assert!(
            c.is_none(),
            "pre segwit genesis must not carry a commitment"
        );
    }

    #[test]
    fn genesis_legacy_sigops_is_small() {
        let bytes = genesis_bytes();
        let n = count_sigops(&bytes).expect("genesis parses");
        // Genesis coinbase carries one scriptSig push and a single
        // P2PK output: legacy sigops are strictly bounded.
        assert!(n < 10, "genesis legacy sigops unexpectedly large: {n}");
    }

    // ── ParsedBlock single-parse tests (Phase 1 #4b I-A) ──────────

    #[test]
    fn parse_block_accepts_genesis() {
        let bytes = genesis_bytes();
        let _block = parse_block(&bytes).expect("genesis parses");
    }

    #[test]
    fn parse_block_rejects_junk() {
        let junk: &[u8] = &[0xff; 16];
        assert!(matches!(
            parse_block(junk),
            Err(ConsensusViolation::DecodeFailed { .. })
        ));
    }

    #[test]
    fn check_merkle_root_internal_passes_on_genesis() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        check_merkle_root_internal(&block).expect("genesis merkle root agrees");
    }

    #[test]
    fn check_merkle_root_internal_rejects_tampered_header() {
        // Tamper byte 36 of the serialized block (start of merkle
        // root in the header). Re-parsing produces a block whose
        // declared merkle root no longer matches the body hash.
        let mut bytes = genesis_bytes();
        bytes[36] ^= 0x01;
        let block = parse_block(&bytes).unwrap();
        assert!(matches!(
            check_merkle_root_internal(&block),
            Err(ConsensusViolation::MerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn check_witness_commitment_internal_passes_on_legacy_block() {
        // Genesis is pre-segwit; the check returns Ok regardless of
        // any commitment presence in the coinbase script.
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        check_witness_commitment_internal(&block).expect("legacy block needs no commitment");
    }

    #[test]
    fn tx_count_on_genesis_is_one() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        assert_eq!(tx_count(&block), 1);
    }

    #[test]
    fn total_sigops_on_genesis_matches_count_sigops() {
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        let parsed_total = total_sigops(&block);
        let raw_total = count_sigops(&bytes).unwrap();
        assert_eq!(
            parsed_total, raw_total,
            "ParsedBlock total_sigops must agree with count_sigops"
        );
    }

    #[test]
    fn coinbase_sigops_on_genesis_equals_total() {
        // Genesis has exactly one transaction (the coinbase). All
        // sigops are coinbase sigops.
        let bytes = genesis_bytes();
        let block = parse_block(&bytes).unwrap();
        assert_eq!(coinbase_sigops(&block), total_sigops(&block));
    }

    #[test]
    fn decode_bip34_height_decodes_valid_pushes() {
        // 1-byte: push 0x42 -> 66
        assert_eq!(decode_bip34_height(&[0x01, 0x42]), Some(66));
        // 2-byte little endian: push 0x3412 -> 0x1234 = 4660
        assert_eq!(decode_bip34_height(&[0x02, 0x34, 0x12]), Some(0x1234));
        // 3-byte: push 0x563412 -> 0x123456 = 1193046
        assert_eq!(
            decode_bip34_height(&[0x03, 0x56, 0x34, 0x12]),
            Some(0x0012_3456)
        );
        // 4-byte covers up to ~2^31. Block 800000 = 0x000c3500.
        assert_eq!(
            decode_bip34_height(&[0x03, 0x00, 0x35, 0x0c]),
            Some(800_000)
        );
    }

    #[test]
    fn decode_bip34_height_rejects_negative_msb() {
        // Sign bit on the MSB of the most significant byte: rejected.
        assert_eq!(decode_bip34_height(&[0x01, 0x80]), None);
        assert_eq!(decode_bip34_height(&[0x02, 0x00, 0x80]), None);
    }

    #[test]
    fn decode_bip34_height_rejects_non_minimal_zero_padding() {
        // Last byte == 0 with the previous byte's MSB clear is
        // non-minimal: rejected.
        assert_eq!(decode_bip34_height(&[0x02, 0x42, 0x00]), None);
    }

    #[test]
    fn decode_bip34_height_rejects_invalid_opcode() {
        // 0x05 is outside the direct-push range we accept.
        assert_eq!(
            decode_bip34_height(&[0x05, 0x00, 0x00, 0x00, 0x00, 0x00]),
            None
        );
        // OP_0 (0x00) is rejected: BIP-34 requires an integer push.
        assert_eq!(decode_bip34_height(&[0x00]), None);
    }

    #[test]
    fn decode_bip34_height_handles_truncated_script() {
        // Length byte says push 4 but only 2 bytes follow.
        assert_eq!(decode_bip34_height(&[0x04, 0x00, 0x00]), None);
        // Empty script.
        assert_eq!(decode_bip34_height(&[]), None);
    }

    #[test]
    fn extract_witness_commitment_finds_well_formed_op_return() {
        use bitcoin::Transaction;
        use bitcoin::consensus::deserialize;
        // Build a fake coinbase whose first output is a textbook
        // witness commitment: OP_RETURN(0x6a) PUSH36(0x24)
        // magic(0xaa21a9ed) + 32 commitment bytes.
        let bytes = genesis_bytes();
        let block: Block = deserialize(&bytes).unwrap();
        let mut coinbase: Transaction = block.txdata[0].clone();
        let mut commit = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        let expected: [u8; 32] = [0x42; 32];
        commit.extend_from_slice(&expected);
        coinbase.output.push(bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from(commit),
        });
        assert_eq!(
            extract_witness_commitment_from_coinbase(&coinbase),
            Some(expected)
        );
    }

    #[test]
    fn extract_witness_commitment_returns_none_on_legacy_coinbase() {
        // Genesis coinbase has no OP_RETURN witness commitment.
        let bytes = genesis_bytes();
        let block: Block = deserialize(&bytes).unwrap();
        let coinbase = &block.txdata[0];
        assert_eq!(extract_witness_commitment_from_coinbase(coinbase), None);
    }
}
