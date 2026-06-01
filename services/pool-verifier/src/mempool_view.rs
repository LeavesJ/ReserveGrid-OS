//! Verifier-side mempool view subscription for the v2.0 Invariant
//! Shield Phase 2 Class M check (ADR-003).
//!
//! Polls bitcoind `getrawmempool` periodically and serves the
//! resulting `HashSet<Txid>` to the shield. Implements the D3
//! fail-stale state machine: serves the last known view up to
//! `max_stale_secs` after a refresh failure, then degrades.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::bitcoind_rpc::{BitcoindClient, RpcError};

/// Operational state of the mempool view from the shield's
/// perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolState {
    /// View was refreshed within `max_stale_secs`. Class M check
    /// runs against the current `HashSet<Txid>`.
    Fresh,
    /// View has not been refreshed within `max_stale_secs` but the
    /// last known view is still being served. Class M check runs
    /// against the stale set with a `MempoolViewStale` advisory.
    /// Caller may choose to log the advisory without rejecting.
    Stale,
    /// A previously primed view aged out past `2 * max_stale_secs`:
    /// bitcoind has been unreachable beyond the fail-stale window.
    /// Class M check is skipped, templates fall through to Phase 1
    /// behavior, and `verifier_phase2_degraded_total` increments per
    /// template so operators can alert on a steady-state outage.
    Degraded,
    /// No successful refresh has happened since startup, so the view
    /// has never been primed. Class M is skipped exactly as for
    /// `Degraded`, but this is the boot window rather than a runtime
    /// degradation, so it does NOT increment
    /// `verifier_phase2_degraded_total`. Keeping the two distinct
    /// stops boot-time alerts from flapping (PB-13, R-173).
    Unprimed,
}

/// Snapshot of the verifier's mempool view at a point in time.
///
/// Cheap to clone for read consumers: `txids` is wrapped in `Arc`
/// so the shield does not hold the write lock during per-template
/// containment checks.
#[derive(Debug, Clone)]
pub struct MempoolSnapshot {
    pub state: MempoolState,
    pub txids: Arc<HashSet<[u8; 32]>>,
    pub age_secs: u64,
    pub size: usize,
}

/// Owns the polling task and the latest view.
pub struct MempoolView {
    inner: Arc<RwLock<MempoolViewInner>>,
}

struct MempoolViewInner {
    txids: Arc<HashSet<[u8; 32]>>,
    last_refresh_unix_ms: Option<u64>,
    max_stale_secs: u64,
    /// `true` once at least one refresh has succeeded since startup.
    /// Before that, the view is `Unprimed` regardless of clock age.
    primed: bool,
}

impl MempoolView {
    /// Construct an unprimed view. Call
    /// [`MempoolView::spawn_polling_task`] to begin refreshing it.
    pub fn new(max_stale_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MempoolViewInner {
                txids: Arc::new(HashSet::new()),
                last_refresh_unix_ms: None,
                max_stale_secs,
                primed: false,
            })),
        }
    }

    /// Read the current view as a snapshot. The returned
    /// [`MempoolSnapshot`] is cheap to clone and does not hold any
    /// lock; per-template checks operate against it without
    /// blocking the polling task.
    pub async fn snapshot(&self) -> MempoolSnapshot {
        let now_ms = unix_ms_now();
        let inner = self.inner.read().await;
        let (state, age_secs) = match inner.last_refresh_unix_ms {
            Some(last) if inner.primed => {
                let age_ms = now_ms.saturating_sub(last);
                let age_secs = age_ms / 1000;
                if age_secs > inner.max_stale_secs.saturating_mul(2) {
                    (MempoolState::Degraded, age_secs)
                } else if age_secs > inner.max_stale_secs {
                    (MempoolState::Stale, age_secs)
                } else {
                    (MempoolState::Fresh, age_secs)
                }
            }
            _ => (MempoolState::Unprimed, 0),
        };
        MempoolSnapshot {
            state,
            txids: Arc::clone(&inner.txids),
            age_secs,
            size: inner.txids.len(),
        }
    }

    /// Replace the view with a new txid set. Updates the refresh
    /// timestamp and marks the view as primed.
    pub async fn install(&self, txids: HashSet<[u8; 32]>) {
        self.install_at(txids, unix_ms_now()).await;
    }

    /// Replace the view with a new txid set, attributing the refresh
    /// to the caller-supplied unix timestamp in milliseconds. The
    /// production polling task calls [`MempoolView::install`] which
    /// stamps `unix_ms_now()`. Integration tests use this entry point
    /// to drive the fail-stale state machine deterministically without
    /// waiting on wall-clock time. R-160 friendly: takes a timestamp
    /// rather than a Duration so the test owns the clock model.
    pub async fn install_at(&self, txids: HashSet<[u8; 32]>, last_refresh_unix_ms: u64) {
        let mut inner = self.inner.write().await;
        inner.txids = Arc::new(txids);
        inner.last_refresh_unix_ms = Some(last_refresh_unix_ms);
        inner.primed = true;
    }

    /// Spawn a tokio task that polls bitcoind every `poll_interval`.
    /// Returns immediately; the task runs in the background until
    /// the program exits or the returned `MempoolView` is dropped
    /// and no other clones remain.
    pub fn spawn_polling_task(
        self: Arc<Self>,
        client: BitcoindClient,
        poll_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                poll_interval_secs = poll_interval.as_secs(),
                "Phase 2 mempool view polling task started"
            );
            loop {
                match client.get_raw_mempool().await {
                    Ok(txids) => {
                        let set: HashSet<[u8; 32]> = txids.into_iter().collect();
                        let size = set.len();
                        self.install(set).await;
                        debug!(size, "mempool view refreshed");
                    }
                    Err(RpcError::Http(e)) if e.is_timeout() => {
                        warn!(error = %e, "mempool refresh timed out; serving last view");
                    }
                    Err(e) => {
                        error!(error = %e, "mempool refresh failed; serving last view");
                    }
                }
                tokio::time::sleep(poll_interval).await;
            }
        })
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Outcome of a Class M (mempool) check against a template's tx set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolCheckOutcome {
    /// Mempool view was Fresh or Stale and every template tx (or
    /// at least 100% minus tolerance) was present in the view.
    Agreed { unknown_count: u32, total: u32 },
    /// Aggregate unknown ratio crossed the configured tolerance
    /// threshold. Detail surfaces representative txids; full per-tx
    /// emission is the caller's responsibility under per-tx detail
    /// mode.
    ToleranceExceeded {
        unknown_count: u32,
        total: u32,
        sample_unknown: Vec<[u8; 32]>,
    },
    /// View was Stale at the moment of check. Caller may treat this
    /// as advisory (not a hard reject); the shield short-circuit
    /// chain decides per policy.
    Stale { age_secs: u64 },
    /// View is Degraded. Class M is skipped; caller increments
    /// `verifier_phase2_degraded_total`.
    Skipped,
}

/// Cap on the number of representative unknown txids surfaced when
/// the aggregate threshold is exceeded. Bounded so the verdict
/// detail string stays under typical export field budgets.
pub const SAMPLE_UNKNOWN_CAP: usize = 10;

/// Run the Class M check against a template's transaction set.
///
/// `tolerance_pct` is the operator-tunable threshold from
/// `policy.toml` (default 4.0). `template_txids` is the non-coinbase
/// txid list returned by `rg_consensus::template_txids`.
pub fn evaluate(
    snapshot: &MempoolSnapshot,
    template_txids: &[[u8; 32]],
    tolerance_pct: f64,
) -> MempoolCheckOutcome {
    match snapshot.state {
        MempoolState::Degraded | MempoolState::Unprimed => return MempoolCheckOutcome::Skipped,
        // Stale falls through to evaluate; caller decides whether to
        // treat as advisory. We still count and surface the age for
        // the per-verdict detail. Fresh is the normal path.
        MempoolState::Stale | MempoolState::Fresh => {}
    }

    let total = u32::try_from(template_txids.len()).unwrap_or(u32::MAX);
    if total == 0 {
        // Empty (coinbase-only) block trivially agrees.
        return match snapshot.state {
            MempoolState::Stale => MempoolCheckOutcome::Stale {
                age_secs: snapshot.age_secs,
            },
            _ => MempoolCheckOutcome::Agreed {
                unknown_count: 0,
                total: 0,
            },
        };
    }

    let mut unknown: Vec<[u8; 32]> = Vec::new();
    for txid in template_txids {
        if !snapshot.txids.contains(txid) {
            unknown.push(*txid);
        }
    }
    let unknown_count = u32::try_from(unknown.len()).unwrap_or(u32::MAX);

    let ratio_pct = (f64::from(unknown_count) / f64::from(total)) * 100.0;
    if ratio_pct > tolerance_pct {
        let mut sample = unknown;
        sample.truncate(SAMPLE_UNKNOWN_CAP);
        return MempoolCheckOutcome::ToleranceExceeded {
            unknown_count,
            total,
            sample_unknown: sample,
        };
    }

    match snapshot.state {
        MempoolState::Stale => MempoolCheckOutcome::Stale {
            age_secs: snapshot.age_secs,
        },
        _ => MempoolCheckOutcome::Agreed {
            unknown_count,
            total,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn snapshot_with(state: MempoolState, txids: Vec<[u8; 32]>) -> MempoolSnapshot {
        MempoolSnapshot {
            state,
            txids: Arc::new(txids.into_iter().collect()),
            age_secs: 0,
            size: 0,
        }
    }

    fn txid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn empty_template_agrees_under_fresh_view() {
        let snap = snapshot_with(MempoolState::Fresh, vec![txid(1), txid(2)]);
        let outcome = evaluate(&snap, &[], 4.0);
        assert_eq!(
            outcome,
            MempoolCheckOutcome::Agreed {
                unknown_count: 0,
                total: 0
            }
        );
    }

    #[test]
    fn full_overlap_agrees() {
        let snap = snapshot_with(MempoolState::Fresh, vec![txid(1), txid(2), txid(3)]);
        let template = [txid(1), txid(2)];
        let outcome = evaluate(&snap, &template, 4.0);
        assert_eq!(
            outcome,
            MempoolCheckOutcome::Agreed {
                unknown_count: 0,
                total: 2
            }
        );
    }

    #[test]
    fn under_threshold_unknown_still_agrees() {
        // 1 unknown of 100 = 1%, below 4% threshold.
        let mut mempool = vec![];
        for i in 0..100u8 {
            mempool.push(txid(i));
        }
        let snap = snapshot_with(MempoolState::Fresh, mempool);
        let mut template: Vec<[u8; 32]> = (0u8..99).map(txid).collect();
        template.push(txid(200)); // not in mempool
        let outcome = evaluate(&snap, &template, 4.0);
        match outcome {
            MempoolCheckOutcome::Agreed {
                unknown_count,
                total,
            } => {
                assert_eq!(unknown_count, 1);
                assert_eq!(total, 100);
            }
            other => panic!("expected Agreed, got {other:?}"),
        }
    }

    #[test]
    fn above_threshold_returns_tolerance_exceeded() {
        // 5 unknown of 100 = 5%, above 4% threshold.
        let mempool: Vec<[u8; 32]> = (0u8..100).map(txid).collect();
        let snap = snapshot_with(MempoolState::Fresh, mempool);
        let mut template: Vec<[u8; 32]> = (0u8..95).map(txid).collect();
        // 5 unknown txids
        for i in 200u8..205 {
            template.push(txid(i));
        }
        let outcome = evaluate(&snap, &template, 4.0);
        match outcome {
            MempoolCheckOutcome::ToleranceExceeded {
                unknown_count,
                total,
                sample_unknown,
            } => {
                assert_eq!(unknown_count, 5);
                assert_eq!(total, 100);
                assert_eq!(sample_unknown.len(), 5);
            }
            other => panic!("expected ToleranceExceeded, got {other:?}"),
        }
    }

    #[test]
    fn sample_capped_at_ten_when_many_unknown() {
        let mempool: Vec<[u8; 32]> = vec![txid(0)];
        // 50 unknown txids in template, sample capped at 10
        let template: Vec<[u8; 32]> = (1u8..=50).map(txid).collect();
        let snap = snapshot_with(MempoolState::Fresh, mempool);
        let outcome = evaluate(&snap, &template, 4.0);
        match outcome {
            MempoolCheckOutcome::ToleranceExceeded { sample_unknown, .. } => {
                assert_eq!(sample_unknown.len(), SAMPLE_UNKNOWN_CAP);
            }
            other => panic!("expected ToleranceExceeded, got {other:?}"),
        }
    }

    #[test]
    fn degraded_state_skips_check() {
        let snap = snapshot_with(MempoolState::Degraded, vec![]);
        let template = [txid(1)];
        let outcome = evaluate(&snap, &template, 4.0);
        assert_eq!(outcome, MempoolCheckOutcome::Skipped);
    }

    #[test]
    fn stale_state_returns_stale_when_under_threshold() {
        let mempool: Vec<[u8; 32]> = (0u8..10).map(txid).collect();
        let mut snap = snapshot_with(MempoolState::Stale, mempool);
        snap.age_secs = 75;
        let template: Vec<[u8; 32]> = (0u8..10).map(txid).collect();
        let outcome = evaluate(&snap, &template, 4.0);
        match outcome {
            MempoolCheckOutcome::Stale { age_secs } => {
                assert_eq!(age_secs, 75);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[test]
    fn stale_state_still_rejects_above_threshold() {
        // Even with a stale view, exceeding the threshold should
        // still trigger ToleranceExceeded; the stale advisory does
        // not give cover for tampering.
        let mempool: Vec<[u8; 32]> = vec![txid(0)];
        let mut snap = snapshot_with(MempoolState::Stale, mempool);
        snap.age_secs = 75;
        let template: Vec<[u8; 32]> = (1u8..=20).map(txid).collect();
        let outcome = evaluate(&snap, &template, 4.0);
        assert!(matches!(
            outcome,
            MempoolCheckOutcome::ToleranceExceeded { .. }
        ));
    }
}
