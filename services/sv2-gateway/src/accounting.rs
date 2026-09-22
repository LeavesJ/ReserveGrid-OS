//! The accounting stream: the two NDJSON events an accepted share produces,
//! written in the order that makes a crash cost a duplicate rather than a gap.
//!
//! Event 1 is `ShareAcceptedEvent`, Event 2 is `ShareForwardResultEvent`, and
//! the WAL records which accepted shares still owe an Event 2 (see
//! `docs/WAL_CONTRACT.md`). The order of "write the line" and "write the WAL
//! record" decides what a crash between the two leaves behind:
//!
//! * **Event 1: pending record durable FIRST, then the line.** A crash in
//!   between leaves a pending record with no accepted line, so the restart
//!   emits a synthetic `process_crash_recovery` Event 2 for a share whose
//!   Event 1 never appeared: an extra line a consumer can see and discard.
//!   The other order leaves an accepted line with no pending record, and that
//!   share never gets an Event 2 at all.
//! * **Event 2: the line FIRST, then the completed record.** A crash in between
//!   leaves the share pending, so the restart emits a synthetic Event 2 beside
//!   the real one: a duplicate, told apart by its `process_crash_recovery`
//!   reason code. The other order, which the gateway used until PB-44's T2
//!   review, marked the share complete and then died or failed compaction
//!   before logging it, and nothing ever emitted that Event 2. With batching
//!   that was up to a whole batch of shares at once.
//!
//! So Event 2 is delivered AT LEAST once and never zero times, with the WAL
//! enabled (`wal_path` set, which the shipped `deploy/gateway-prod.toml` does;
//! the built-in default is off) and with `VELDRA_LOG_FILTER` admitting the
//! `share_events` target that carries the lines. A line counts as emitted when
//! the process has written it to stdout: the gateway's tracing writer is
//! synchronous and flushes per line, so it survives the process dying but not
//! the host losing power, which the WAL's fdatasync does.
//!
//! Both functions drain everything already queued behind the item that woke the
//! arm (`wal::take_queued`), so one WAL write and one sync cover the batch
//! (PB-44).
//!
//! This module exists because `main.rs`'s two select arms need a home a test
//! can drive: `main.rs` is the first caller and this file's tests are the
//! second. That is the doctrine's stated override, a seam a test is blocked on.

use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::Receiver;
use tracing::error;

use crate::shares::{ShareAcceptedEvent, ShareForwardResultEvent};
use crate::upstream::ShareForwardResult;
use crate::wal::{ShareWal, take_queued};

/// The WAL as the gateway's main loop holds it.
pub type SharedWal = Arc<Mutex<ShareWal>>;

/// Drain a batch of accounting events starting at `first`, make the accepted
/// shares' pending records durable, and emit the lines.
///
/// Rejected events are emitted at once: they owe no Event 2 and touch no WAL.
/// Accepted events are emitted only after their pending records are durable.
/// On a WAL failure the accepted lines of this batch are NOT emitted, and the
/// error comes back for the caller to treat as fatal.
///
/// Returns the batch so the caller can do its per-share bookkeeping.
pub async fn record_accepted(
    rx: &mut Receiver<ShareAcceptedEvent>,
    first: ShareAcceptedEvent,
    wal: Option<&SharedWal>,
    emit: &mut (dyn FnMut(&str) + Send),
) -> (Vec<ShareAcceptedEvent>, std::io::Result<()>) {
    let events = take_queued(rx, first);
    let is_accepted = |evt: &ShareAcceptedEvent| evt.sv2_response == "success";

    for evt in events.iter().filter(|evt| !is_accepted(evt)) {
        emit_json(emit, evt, &evt.share_id_hex);
    }

    let accepted: Vec<(String, String)> = events
        .iter()
        .filter(|evt| is_accepted(evt))
        .map(|evt| (evt.share_id_hex.clone(), evt.event_id_hex.clone()))
        .collect();
    if let Some(wal) = wal
        && !accepted.is_empty()
        && let Err(e) = with_wal(wal, "mark_pending", move |w| w.mark_pending(&accepted)).await
    {
        return (events, Err(e));
    }

    for evt in events.iter().filter(|evt| is_accepted(evt)) {
        emit_json(emit, evt, &evt.share_id_hex);
    }
    (events, Ok(()))
}

/// Drain a batch of forward results starting at `first`, emit their Event 2
/// lines, and only then mark the shares complete in the WAL.
///
/// Every line of the batch is emitted before the WAL is touched, so a WAL
/// failure (including a compaction failure after the completed records are
/// already durable) can cost a duplicate on restart but never a missing line.
///
/// Returns the batch so the caller can do its per-share bookkeeping.
pub async fn record_forwarded(
    rx: &mut Receiver<ShareForwardResult>,
    first: ShareForwardResult,
    wal: Option<&SharedWal>,
    emit: &mut (dyn FnMut(&str) + Send),
) -> (Vec<ShareForwardResult>, std::io::Result<()>) {
    let results = take_queued(rx, first);

    for r in &results {
        let evt = ShareForwardResultEvent::from_relay(
            &r.share_id_hex,
            &r.event_id_hex,
            r.forwarded,
            r.upstream_accepted,
            r.upstream_http_status,
            r.upstream_error.clone(),
            r.reason_code.clone(),
        );
        emit_json(emit, &evt, &r.share_id_hex);
    }

    let recorded = match wal {
        Some(wal) => {
            let completed: Vec<(String, String)> = results
                .iter()
                .map(|r| (r.share_id_hex.clone(), r.event_id_hex.clone()))
                .collect();
            with_wal(wal, "mark_completed", move |w| w.mark_completed(&completed)).await
        }
        None => Ok(()),
    };
    (results, recorded)
}

/// Drain both accounting channels through the same two functions the main
/// loop uses, so a stop does not discard the shares miners were already told
/// were accepted (PB-49 T2).
///
/// It runs until one pass finds both queues empty, so it also takes what the
/// connection handlers send while they stop; the caller tells them to stop
/// first, or the queues may never empty. `deadline` bounds it anyway. It is
/// checked between batches, so no batch is cut in half, and passing it is
/// returned as a `TimedOut` error naming what is still queued.
///
/// Stops at the first WAL failure and returns it. Returns how many accounting
/// events and forward results it drained.
pub async fn drain_on_stop(
    events: &mut Receiver<ShareAcceptedEvent>,
    results: &mut Receiver<ShareForwardResult>,
    wal: Option<&SharedWal>,
    emit: &mut (dyn FnMut(&str) + Send),
    deadline: tokio::time::Instant,
) -> (usize, usize, std::io::Result<()>) {
    let (mut drained_events, mut drained_results) = (0, 0);
    loop {
        if tokio::time::Instant::now() >= deadline {
            let left = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "the accounting drain passed its deadline with {} events and {} forward \
                     results still queued",
                    events.len(),
                    results.len()
                ),
            );
            return (drained_events, drained_results, Err(left));
        }
        let mut moved = false;
        if let Ok(first) = events.try_recv() {
            let (batch, recorded) = record_accepted(events, first, wal, emit).await;
            drained_events += batch.len();
            moved = true;
            if recorded.is_err() {
                return (drained_events, drained_results, recorded);
            }
        }
        if let Ok(first) = results.try_recv() {
            let (batch, recorded) = record_forwarded(results, first, wal, emit).await;
            drained_results += batch.len();
            moved = true;
            if recorded.is_err() {
                return (drained_events, drained_results, recorded);
            }
        }
        if !moved {
            return (drained_events, drained_results, Ok(()));
        }
    }
}

/// Run `f` against the WAL on the blocking pool, folding a poisoned mutex and a
/// failed join into the same `io::Error` a failed write produces, so the caller
/// has one failure to handle.
async fn with_wal<F>(wal: &SharedWal, op: &'static str, f: F) -> std::io::Result<()>
where
    F: FnOnce(&mut ShareWal) -> std::io::Result<()> + Send + 'static,
{
    let wal = Arc::clone(wal);
    match tokio::task::spawn_blocking(move || {
        let mut w = wal
            .lock()
            .map_err(|_| std::io::Error::other(format!("wal mutex poisoned in {op}")))?;
        f(&mut w)
    })
    .await
    {
        Ok(result) => result,
        Err(join) => Err(std::io::Error::other(format!(
            "wal {op} spawn_blocking: {join}"
        ))),
    }
}

/// Serialize one accounting event and emit it. These structs hold only
/// strings, integers and options, so serialization cannot fail today; if a
/// field ever makes it fail, that is logged rather than skipped in silence.
fn emit_json<T: serde::Serialize>(
    emit: &mut (dyn FnMut(&str) + Send),
    value: &T,
    share_id_hex: &str,
) {
    match serde_json::to_string(value) {
        Ok(line) => emit(&line),
        Err(e) => error!(
            share_id = %share_id_hex,
            error = %e,
            "accounting event failed to serialize; line not emitted"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn scratch_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rg_accounting_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.ndjson"));
        cleanup(&path);
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let tmp = path.with_extension("wal.tmp");
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn shared(wal: ShareWal) -> SharedWal {
        Arc::new(Mutex::new(wal))
    }

    fn id(n: u32) -> String {
        format!("{n:064x}")
    }

    fn accounting_event(n: u32, accepted: bool) -> ShareAcceptedEvent {
        ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: id(n),
            event_id_hex: id(n + 1_000),
            sv2_response: if accepted { "success" } else { "error" },
            reason_code: None,
            reason_detail: None,
            worker_id: "w".to_string(),
            channel_id: 1,
            sequence_number: n,
            job_id: 1,
            block_height: 1,
            timestamp_ms: 0,
            difficulty_u64: 1,
        }
    }

    fn forward_result(n: u32) -> ShareForwardResult {
        ShareForwardResult {
            share_id_hex: id(n),
            event_id_hex: id(n + 1_000),
            forwarded: true,
            upstream_accepted: Some(true),
            upstream_http_status: Some(200),
            upstream_error: None,
            reason_code: None,
        }
    }

    /// Lines emitted during a call, in order.
    fn collector(lines: &mut Vec<String>) -> impl FnMut(&str) + Send + '_ {
        move |line: &str| lines.push(line.to_string())
    }

    fn emitted_ids(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["share_id_hex"].as_str().unwrap().to_string()
            })
            .collect()
    }

    /// PB-44 T2 blocker. Compaction fails AFTER the batch's completed records
    /// are durable. Before the fix the loop broke before logging, the restart
    /// read those shares as complete, and their Event 2 lines were gone for
    /// good. Now every line is emitted before the WAL is touched.
    #[tokio::test]
    async fn a_compaction_failure_after_durable_completion_loses_no_forward_line() {
        let path = scratch_path("compaction_fails");
        let wal = shared(ShareWal::open(&path, 3).unwrap());
        let ids: Vec<(String, String)> = (0..5).map(|n| (id(n), id(n + 1_000))).collect();
        wal.lock().unwrap().mark_pending(&ids).unwrap();
        // A directory where compaction wants its temp file makes it fail.
        std::fs::create_dir_all(path.with_extension("wal.tmp")).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        for n in 1..5 {
            tx.try_send(forward_result(n)).unwrap();
        }
        let mut lines = Vec::new();
        let (batch, recorded) = record_forwarded(
            &mut rx,
            forward_result(0),
            Some(&wal),
            &mut collector(&mut lines),
        )
        .await;

        assert_eq!(batch.len(), 5, "the whole queue is one batch");
        assert!(recorded.is_err(), "compaction must have failed");
        assert_eq!(
            emitted_ids(&lines),
            (0..5).map(id).collect::<Vec<_>>(),
            "every Event 2 line must be out before the WAL can fail"
        );

        drop(wal);
        let _ = std::fs::remove_dir_all(path.with_extension("wal.tmp"));
        let mut reopened = ShareWal::open(&path, 3).unwrap();
        assert_eq!(
            reopened.recover().synthetic_events.len(),
            0,
            "the completions are durable, so recovery owes nothing: the lines above are the record"
        );
        cleanup(&path);
    }

    /// The order itself, which the failure-injection tests cannot see because a
    /// function that emits after the WAL still emits. A crash is what the order
    /// protects against, so this reads the WAL file at the instant each line is
    /// emitted: an Event 2 line must go out while its completion is NOT yet on
    /// disk, or a crash between the two loses it.
    #[tokio::test]
    async fn every_forward_line_is_out_before_its_completion_is_on_disk() {
        let path = scratch_path("forward_order");
        let wal = shared(ShareWal::open(&path, 0).unwrap());
        let ids: Vec<(String, String)> = (0..3).map(|n| (id(n), id(n + 1_000))).collect();
        wal.lock().unwrap().mark_pending(&ids).unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        for n in 1..3 {
            tx.try_send(forward_result(n)).unwrap();
        }
        let wal_path = path.clone();
        let mut completion_already_on_disk = Vec::new();
        let mut watch = |line: &str| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let share = v["share_id_hex"].as_str().unwrap().to_string();
            let on_disk = std::fs::read_to_string(&wal_path).unwrap_or_default();
            completion_already_on_disk.push(
                on_disk
                    .lines()
                    .any(|l| l.contains("\"completed\"") && l.contains(&share)),
            );
        };
        record_forwarded(&mut rx, forward_result(0), Some(&wal), &mut watch)
            .await
            .1
            .unwrap();

        assert_eq!(completion_already_on_disk, vec![false, false, false]);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            on_disk
                .lines()
                .filter(|l| l.contains("\"completed\""))
                .count(),
            3,
            "and the completions did land afterwards, so the check above was armed"
        );
        cleanup(&path);
    }

    /// The Event 1 half of the order: an accepted line goes out only once its
    /// pending record is on disk, so a crash between the two cannot leave an
    /// accepted share that no restart will ever give an Event 2.
    #[tokio::test]
    async fn every_accepted_line_waits_for_its_pending_record_on_disk() {
        let path = scratch_path("accepted_order");
        let wal = shared(ShareWal::open(&path, 0).unwrap());

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        for n in 1..3 {
            tx.try_send(accounting_event(n, true)).unwrap();
        }
        let wal_path = path.clone();
        let mut pending_on_disk = Vec::new();
        let mut watch = |line: &str| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let share = v["share_id_hex"].as_str().unwrap().to_string();
            let on_disk = std::fs::read_to_string(&wal_path).unwrap_or_default();
            pending_on_disk.push(
                on_disk
                    .lines()
                    .any(|l| l.contains("\"pending\"") && l.contains(&share)),
            );
        };
        record_accepted(&mut rx, accounting_event(0, true), Some(&wal), &mut watch)
            .await
            .1
            .unwrap();

        assert_eq!(pending_on_disk, vec![true, true, true]);
        cleanup(&path);
    }

    /// A pending record that cannot be made durable must not be preceded by
    /// its accepted line, and a rejected share never touches the WAL.
    #[tokio::test]
    async fn an_accepted_line_waits_for_its_pending_record() {
        let path = scratch_path("pending_fails");
        let wal = shared(ShareWal::open(&path, 1000).unwrap());
        wal.lock().unwrap().fail_writes_for_test();

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tx.try_send(accounting_event(1, true)).unwrap();
        let mut lines = Vec::new();
        let (_, recorded) = record_accepted(
            &mut rx,
            accounting_event(0, false),
            Some(&wal),
            &mut collector(&mut lines),
        )
        .await;

        assert!(recorded.is_err(), "the pending write must have failed");
        assert_eq!(
            emitted_ids(&lines),
            vec![id(0)],
            "the rejected line goes out, the accepted one must not"
        );
        cleanup(&path);
    }

    #[tokio::test]
    async fn only_accepted_shares_get_a_pending_record() {
        let path = scratch_path("pending_set");
        let wal = shared(ShareWal::open(&path, 1000).unwrap());

        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tx.try_send(accounting_event(1, true)).unwrap();
        tx.try_send(accounting_event(2, false)).unwrap();
        let mut lines = Vec::new();
        let (batch, recorded) = record_accepted(
            &mut rx,
            accounting_event(0, true),
            Some(&wal),
            &mut collector(&mut lines),
        )
        .await;

        recorded.unwrap();
        assert_eq!(batch.len(), 3);
        assert_eq!(
            wal.lock().unwrap().pending_count(),
            2,
            "two accepted, one rejected: a rejected share owes no Event 2"
        );
        let mut all = emitted_ids(&lines);
        all.sort();
        assert_eq!(
            all,
            vec![id(0), id(1), id(2)],
            "every event is emitted once"
        );
        cleanup(&path);
    }

    /// PB-44: each arm pays ONE sync for everything already queued.
    #[tokio::test]
    async fn a_queued_burst_costs_one_sync_per_arm() {
        let path = scratch_path("one_sync");
        let wal = shared(ShareWal::open(&path, 0).unwrap());

        let (etx, mut erx) = tokio::sync::mpsc::channel(16);
        for n in 1..6 {
            etx.try_send(accounting_event(n, true)).unwrap();
        }
        let mut lines = Vec::new();
        record_accepted(
            &mut erx,
            accounting_event(0, true),
            Some(&wal),
            &mut collector(&mut lines),
        )
        .await
        .1
        .unwrap();
        assert_eq!(
            wal.lock().unwrap().syncs_for_test(),
            1,
            "six accepted events, one sync"
        );

        let (rtx, mut rrx) = tokio::sync::mpsc::channel(16);
        for n in 1..6 {
            rtx.try_send(forward_result(n)).unwrap();
        }
        record_forwarded(
            &mut rrx,
            forward_result(0),
            Some(&wal),
            &mut collector(&mut lines),
        )
        .await
        .1
        .unwrap();
        let w = wal.lock().unwrap();
        assert_eq!(w.syncs_for_test(), 2, "six forward results, one more sync");
        assert_eq!(w.pending_count(), 0);
        drop(w);
        cleanup(&path);
    }

    /// With the WAL disabled, the shipped built-in default, both functions
    /// still emit every line: the WAL decides durability, not whether the
    /// accounting stream exists.
    #[tokio::test]
    async fn without_a_wal_every_line_is_still_emitted() {
        let (etx, mut erx) = tokio::sync::mpsc::channel(16);
        etx.try_send(accounting_event(1, false)).unwrap();
        let mut lines = Vec::new();
        record_accepted(
            &mut erx,
            accounting_event(0, true),
            None,
            &mut collector(&mut lines),
        )
        .await
        .1
        .unwrap();
        let (rtx, mut rrx) = tokio::sync::mpsc::channel(16);
        rtx.try_send(forward_result(1)).unwrap();
        record_forwarded(
            &mut rrx,
            forward_result(0),
            None,
            &mut collector(&mut lines),
        )
        .await
        .1
        .unwrap();
        assert_eq!(lines.len(), 4, "two Event 1 lines and two Event 2 lines");
    }

    /// PB-49 T2: a requested stop drains both queues, so shares already acknowledged
    /// to miners reach the accounting stream and the WAL.
    #[tokio::test]
    async fn a_stop_drains_both_accounting_queues() {
        let path = scratch_path("drain_on_stop");
        let wal = shared(ShareWal::open(&path, 0).unwrap());
        let (etx, mut erx) = tokio::sync::mpsc::channel(16);
        let (rtx, mut rrx) = tokio::sync::mpsc::channel(16);
        for n in 0..3 {
            etx.try_send(accounting_event(n, true)).unwrap();
        }
        for n in 0..2 {
            rtx.try_send(forward_result(n)).unwrap();
        }
        let mut lines = Vec::new();
        let (events, results, drained) = drain_on_stop(
            &mut erx,
            &mut rrx,
            Some(&wal),
            &mut collector(&mut lines),
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .await;
        drained.unwrap();
        assert_eq!((events, results), (3, 2));
        assert_eq!(lines.len(), 5, "every queued event and result is emitted");
        assert_eq!(
            wal.lock().unwrap().pending_count(),
            1,
            "three accepted, two forwarded: one still owes an Event 2"
        );
        assert!(
            erx.try_recv().is_err() && rrx.try_recv().is_err(),
            "both queues empty"
        );
        cleanup(&path);
    }

    /// PB-49 T2: a producer that never stops cannot hold the exit open. Every
    /// line emitted here queues another event, so the queue never empties and
    /// only the deadline ends the drain, reported rather than swallowed.
    #[tokio::test]
    async fn a_drain_that_never_empties_stops_at_its_deadline() {
        let (etx, mut erx) = tokio::sync::mpsc::channel(16);
        let (_rtx, mut rrx) = tokio::sync::mpsc::channel::<ShareForwardResult>(16);
        etx.try_send(accounting_event(0, false)).unwrap();
        let mut n = 0;
        let mut refill = move |_: &str| {
            n += 1;
            etx.try_send(accounting_event(n, false))
                .expect("room for the next event");
        };
        let started = tokio::time::Instant::now();
        let (events, _, drained) = drain_on_stop(
            &mut erx,
            &mut rrx,
            None,
            &mut refill,
            started + std::time::Duration::from_millis(20),
        )
        .await;
        let err = drained.expect_err("a queue that never empties must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(events > 0, "it drained before the deadline");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the deadline was not honoured: {:?}",
            started.elapsed()
        );
    }

    /// PB-44's end-to-end claim against BOTH arms on one select loop, the shape
    /// `main.rs` runs: a producer enqueues for forward and then sends the
    /// accounting event with `try_send`, as the handler does; a relay answers
    /// after `relay_ms`; one loop drives `record_accepted` and
    /// `record_forwarded`. The real WAL with compaction on at the production
    /// threshold, so compaction cost and any orphan build-up are in the number.
    ///
    /// `cargo test -p sv2-gateway --lib two_arm_load -- --ignored --nocapture`
    #[test]
    #[ignore = "a measurement, not an assertion: depends on this filesystem's fdatasync cost"]
    fn two_arm_load_on_one_select_loop() {
        for (rate, relay_ms) in [(1_000, 1), (3_000, 1), (3_000, 10), (10_000, 1)] {
            let r = two_arm_run(rate, relay_ms, std::time::Duration::from_secs(4));
            println!(
                "PB-44 two-arm, offered {rate}/s, relay {relay_ms}ms: offered {}, accounting \
                 events dropped {}, forward queue full {}, pending records left after drain {}",
                r.offered, r.dropped, r.forward_full, r.pending_after_drain
            );
        }
    }

    struct LoadReport {
        offered: u64,
        dropped: u64,
        forward_full: u64,
        pending_after_drain: usize,
    }

    fn two_arm_run(rate: u64, relay_ms: u64, window: std::time::Duration) -> LoadReport {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let path = scratch_path(&format!("two_arm_{rate}_{relay_ms}"));
            let wal = shared(ShareWal::open(&path, 1000).unwrap());
            let (fwd_tx, mut fwd_rx) = tokio::sync::mpsc::channel::<u32>(10_000);
            let (res_tx, mut res_rx) = tokio::sync::mpsc::channel::<ShareForwardResult>(1000);
            let (evt_tx, mut evt_rx) = tokio::sync::mpsc::channel::<ShareAcceptedEvent>(4096);

            let relay = tokio::spawn(async move {
                while let Some(n) = fwd_rx.recv().await {
                    let res_tx = res_tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(relay_ms)).await;
                        let _ = res_tx.send(forward_result(n)).await;
                    });
                }
            });

            let loop_wal = Arc::clone(&wal);
            let main_loop = tokio::spawn(async move {
                let mut sink = |_: &str| {};
                let (mut results_open, mut events_open) = (true, true);
                while results_open || events_open {
                    tokio::select! {
                        r = res_rx.recv(), if results_open => match r {
                            Some(first) => {
                                record_forwarded(&mut res_rx, first, Some(&loop_wal), &mut sink)
                                    .await.1.unwrap();
                            }
                            None => results_open = false,
                        },
                        e = evt_rx.recv(), if events_open => match e {
                            Some(first) => {
                                record_accepted(&mut evt_rx, first, Some(&loop_wal), &mut sink)
                                    .await.1.unwrap();
                            }
                            None => events_open = false,
                        },
                    }
                }
            });

            let (mut offered, mut dropped, mut forward_full) = (0u64, 0u64, 0u64);
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(1));
            let start = std::time::Instant::now();
            while start.elapsed() < window {
                tick.tick().await;
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    clippy::cast_precision_loss
                )]
                let due = (start.elapsed().as_secs_f64() * rate as f64) as u64;
                while offered < due {
                    let n = u32::try_from(offered).unwrap();
                    offered += 1;
                    if fwd_tx.try_send(n).is_err() {
                        forward_full += 1;
                        continue;
                    }
                    if evt_tx.try_send(accounting_event(n, true)).is_err() {
                        dropped += 1;
                    }
                }
            }
            // Close the producer side and let the loop drain BOTH channels to
            // empty, so anything still pending afterwards is an orphan rather
            // than a share whose forward result is merely still in flight.
            drop(fwd_tx);
            drop(evt_tx);
            main_loop.await.unwrap();
            relay.await.unwrap();
            let pending_after_drain = wal.lock().unwrap().pending_count();
            cleanup(&path);
            LoadReport {
                offered,
                dropped,
                forward_full,
                pending_after_drain,
            }
        })
    }
}
