//! v2.0 Invariant Shield Phase 2 #3 Tier 1 integration tests (ADR-003).
//!
//! Exercises `policy::evaluate_dynamic_phase2` end-to-end against
//! controlled mempool snapshots constructed via the
//! `pool_verifier::mempool_view::MempoolView::install_at` injection
//! seam. Tier 2 in `phase2_tcp.rs` reuses the same regtest segwit
//! fixture and drives the full pool-verifier TCP listener via a
//! subprocess plus an in-process bitcoind JSON-RPC mock.
//!
//! Per ADR-003 #3 acceptance, this file covers three of the four
//! originally-listed scenarios. The fourth (per-tx detail mode) is
//! deferred to Phase 2 #3.5 because the wiring has not landed yet:
//! `check_invariant_shield_inner` does not read
//! `[policy.mempool] per_tx_detail`, and the ingress writer currently
//! emits one `TemplateVerdict` per accepted `TemplatePropose`.
//! Multi-verdict-per-template emission is a protocol surface change
//! that gets its own commit.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashSet;
use std::sync::Arc;

use pool_verifier::mempool_view::{MempoolSnapshot, MempoolState, MempoolView};
use pool_verifier::policy::{PolicyConfig, ShieldOutcome, evaluate_dynamic_phase2};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, VerdictReason};

const REGTEST_SEGWIT_BLOCK_HEX: &str = include_str!("fixtures/regtest_segwit_block.hex");

/// Build a fresh snapshot at age 0 carrying the supplied txids in
/// internal byte order.
fn fresh_snapshot(txids: Vec<[u8; 32]>) -> MempoolSnapshot {
    MempoolSnapshot {
        state: MempoolState::Fresh,
        txids: Arc::new(txids.into_iter().collect()),
        age_secs: 0,
        size: 0,
    }
}

/// Build a `TemplatePropose` against the regtest segwit fixture with
/// every Phase 1 invariant declared correctly so the shield reaches
/// the Class M check. Re-derives weight and sigops via the facade so
/// the test never hand-encodes counts that drift if the sigop
/// accounting changes (R-148 / R-154 facade narrowness).
fn regtest_segwit_template() -> (TemplatePropose, Vec<[u8; 32]>) {
    let bytes =
        hex::decode(REGTEST_SEGWIT_BLOCK_HEX.trim()).expect("REGTEST_SEGWIT_BLOCK_HEX decodes");
    let weight =
        rg_consensus::re_derive_template_weight(&bytes).expect("regtest weight re-derives");
    let parsed = rg_consensus::parse_block(&bytes).expect("regtest block parses");
    let total_sigops = rg_consensus::total_sigops(&parsed);
    let coinbase_sigops = rg_consensus::coinbase_sigops(&parsed);
    let txids = rg_consensus::template_txids(&parsed);

    let coinbase_value =
        rg_consensus::re_derive_coinbase_value(&bytes).expect("regtest coinbase value re-derives");

    let template = TemplatePropose {
        version: PROTOCOL_VERSION,
        id: 1,
        block_height: 102,
        prev_hash: "a".repeat(64),
        coinbase_value,
        tx_count: 2,
        total_fees: 0,
        observed_weight: None,
        created_at_unix_ms: None,
        total_sigops: Some(total_sigops),
        coinbase_sigops: Some(coinbase_sigops),
        template_weight: Some(weight),
        gateway_instance_id: None,
        raw_block_hex: Some(REGTEST_SEGWIT_BLOCK_HEX.trim().to_string()),
    };
    (template, txids)
}

fn permissive_policy() -> PolicyConfig {
    let mut cfg = PolicyConfig::default_with_protocol(PROTOCOL_VERSION);
    cfg.required_prevhash_len = 64;
    cfg.min_total_fees = 0;
    cfg.reject_empty_templates = false;
    cfg.reject_coinbase_zero = false;
    cfg.unknown_mempool_as_high = true;
    cfg.safety.max_template_age_ms = None;
    cfg
}

#[test]
fn phase2_happy_path_full_overlap_emits_agreed() {
    let (template, txids) = regtest_segwit_template();
    let snapshot = fresh_snapshot(txids);
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert!(
        result.reason.is_none(),
        "expected Agreed, got reason={:?} detail={:?}",
        result.reason,
        result.detail
    );
}

#[test]
fn phase2_fabrication_path_above_threshold_emits_tolerance_exceeded() {
    let (template, _txids) = regtest_segwit_template();
    // Empty mempool view but the template has 1 non-coinbase tx.
    // 1/1 = 100% unknown, well above the 4% default threshold.
    let snapshot = fresh_snapshot(vec![]);
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert_eq!(
        result.reason,
        Some(VerdictReason::V2InvariantMempoolToleranceExceeded),
        "expected V2InvariantMempoolToleranceExceeded, got {:?} detail={:?}",
        result.reason,
        result.detail
    );
    let detail = result.detail.expect("ToleranceExceeded carries detail");
    assert!(
        detail.contains("1/1 txs unknown"),
        "detail must surface the unknown ratio, got: {detail}"
    );
    assert!(
        detail.contains("sample=["),
        "detail must surface representative txids, got: {detail}"
    );
}

#[test]
fn phase2_below_threshold_unknown_still_agrees() {
    // 1 unknown of 100 = 1%, below 4%. Synthesize a 100-tx view with
    // 99 overlapping the template plus 1 fabricated.
    let mut mempool: HashSet<[u8; 32]> = (0u8..99).map(|b| [b; 32]).collect();
    let template_txids: Vec<[u8; 32]> = {
        let mut v: Vec<[u8; 32]> = (0u8..99).map(|b| [b; 32]).collect();
        v.push([0xff; 32]);
        v
    };
    mempool.insert([0xee; 32]);
    let snapshot = MempoolSnapshot {
        state: MempoolState::Fresh,
        txids: Arc::new(mempool),
        age_secs: 0,
        size: 0,
    };

    let outcome = pool_verifier::mempool_view::evaluate(&snapshot, &template_txids, 4.0);
    match outcome {
        pool_verifier::mempool_view::MempoolCheckOutcome::Agreed {
            unknown_count,
            total,
        } => {
            assert_eq!(unknown_count, 1);
            assert_eq!(total, 100);
        }
        other => panic!("expected Agreed below threshold, got {other:?}"),
    }
}

/// `MempoolView::install_at` lets the test seed the refresh
/// timestamp so the fail-stale state machine can be driven without
/// wall-clock time. Verifies all three states.
#[tokio::test]
async fn phase2_view_state_machine_drives_fresh_stale_degraded() {
    let max_stale_secs = 60;
    let view = Arc::new(MempoolView::new(max_stale_secs));

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .expect("clock available");

    // Fresh: install at now, snapshot must report Fresh.
    let txids: HashSet<[u8; 32]> = HashSet::from([[1u8; 32]]);
    view.install_at(txids.clone(), now_ms).await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Fresh);
    assert_eq!(snap.size, 1);

    // Stale: install with a refresh timestamp 90s in the past
    // (between max_stale_secs and 2 * max_stale_secs).
    view.install_at(txids.clone(), now_ms.saturating_sub(90_000))
        .await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Stale);
    assert!(
        snap.age_secs >= 90,
        "expected age >= 90, got {}",
        snap.age_secs
    );

    // Degraded: install with a refresh timestamp 130s in the past
    // (past 2 * max_stale_secs).
    view.install_at(txids, now_ms.saturating_sub(130_000)).await;
    let snap = view.snapshot().await;
    assert_eq!(snap.state, MempoolState::Degraded);
}

/// Ensures the shield bypasses Class M when the view is Degraded
/// rather than rejecting. `verifier_phase2_degraded_total` is the
/// observability surface for this path; the verdict itself is Agreed.
#[test]
fn phase2_degraded_view_skips_check_and_agrees() {
    let (template, _txids) = regtest_segwit_template();
    let snapshot = MempoolSnapshot {
        state: MempoolState::Degraded,
        txids: Arc::new(HashSet::new()),
        age_secs: 999,
        size: 0,
    };
    let cfg = permissive_policy();
    let now_ms = 0;

    let result = evaluate_dynamic_phase2(&template, &cfg, Some(&snapshot), Some(100), now_ms);

    assert!(
        result.reason.is_none(),
        "Degraded view must skip Class M and agree, got reason={:?} detail={:?}",
        result.reason,
        result.detail
    );
}

/// Phase 1 + Phase 2 toggle: passing `mempool_snapshot = None` must
/// reproduce `evaluate_dynamic` exactly (no Class M attempt).
#[test]
fn phase2_disabled_falls_through_to_phase1() {
    let (template, _txids) = regtest_segwit_template();
    let cfg = permissive_policy();
    let now_ms = 0;

    let with_none = evaluate_dynamic_phase2(&template, &cfg, None, Some(100), now_ms);
    let phase1 = pool_verifier::policy::evaluate_dynamic(&template, &cfg, Some(100), now_ms);

    assert_eq!(with_none.reason, phase1.reason);
    assert_eq!(with_none.detail, phase1.detail);
}

/// Defensive: `ShieldOutcome::Rejected` produced by the Phase 2 path
/// always carries a non-empty `detail` so dashboards can surface the
/// unknown ratio without separate lookups.
#[test]
fn phase2_rejected_carries_machine_readable_detail() {
    let (template, _txids) = regtest_segwit_template();
    let outcome = pool_verifier::policy::check_invariant_shield_with_mempool(
        &template,
        &fresh_snapshot(vec![]),
        4.0,
    );
    match outcome {
        ShieldOutcome::Rejected { reason, detail } => {
            assert_eq!(reason, VerdictReason::V2InvariantMempoolToleranceExceeded);
            assert!(!detail.is_empty(), "detail must not be empty");
            assert!(detail.contains("mempool tolerance exceeded"));
        }
        other => panic!("expected Rejected, got {other:?}"),
    }
}
