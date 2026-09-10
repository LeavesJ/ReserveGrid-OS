//! Write-ahead log (WAL) for crash-durable share event delivery.
//!
//! "Crash-durable" here means what it says, as of PB-39. Every append is
//! followed by `sync_data` (fdatasync), and compaction syncs the replacement
//! file before the rename and the parent directory after it, so a record that
//! `mark_pending` returned `Ok` for survives power loss and a host reset, not
//! only a process crash. Before PB-39 this module flushed and never synced,
//! while its own doc comments promised an fsync, so the guarantee an operator
//! read here was one the code did not provide.
//!
//! The share lifecycle emits two NDJSON events per accepted share:
//! 1. `ShareAcceptedEvent` (Event 1): share validated, SV2 ACK sent to miner
//! 2. `ShareForwardResultEvent` (Event 2): upstream relay outcome
//!
//! A crash between Event 1 and Event 2 creates orphaned accepted events that
//! permanently violate the 1:1 join invariant. The WAL persists the
//! `(share_id_hex, event_id_hex)` of each pending forward, and on startup,
//! emits synthetic `ShareForwardResultEvent` with `process_crash_recovery`
//! reason code for any entries that lack a completion marker.
//!
//! File format: one JSON object per line (NDJSON). Each entry is either a
//! `"pending"` record, written when the main loop receives the share's
//! accepted event (the handler has already queued the share for forward by
//! then), or a `"completed"` record written after the forward result arrives.
//! Records are written in batches with one sync per batch (PB-44). Periodic
//! compaction rewrites only the pending entries.
//!
//! The WAL is optional. When `wal_path` is empty the gateway operates without
//! persistence (suitable for regtest and development).

use std::collections::HashMap;
use std::io::{BufRead, Write as IoWrite};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use reservegrid_common::reason::GatewayReason;

use crate::shares::ShareForwardResultEvent;

/// WAL entry persisted as NDJSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalRecord {
    /// `"pending"` or `"completed"`.
    status: WalStatus,
    /// Share identity (join key).
    share_id_hex: String,
    /// Event identity (join key).
    event_id_hex: String,
    /// Timestamp (ms) when this record was written.
    timestamp_ms: u64,
}

/// WAL record status discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WalStatus {
    Pending,
    Completed,
}

/// Durable write-ahead log for in-flight share forwards.
///
/// Thread safety: the WAL is intended to be used from a single async task
/// (the main event loop). It does not implement interior mutability or
/// locking. If concurrent access is needed, wrap in a `tokio::sync::Mutex`.
pub struct ShareWal {
    path: PathBuf,
    /// In-memory index of pending (not yet completed) entries.
    pending: HashMap<(String, String), u64>,
    /// Append handle to the WAL file.
    writer: std::io::BufWriter<std::fs::File>,
    /// Number of completed records written since last compaction.
    completed_since_compaction: usize,
    /// Compaction threshold: compact when `completed_since_compaction` exceeds
    /// this value. 0 disables auto-compaction.
    compaction_threshold: usize,
    /// Syncs issued by `append_records`. Test-only instrumentation and this
    /// file's one structural override: fsync is not observable in-process,
    /// and PB-44's claim is that a batch costs one sync, so this counter is
    /// the only way a test can hold the code to it.
    #[cfg(test)]
    syncs: usize,
}

/// Result of WAL recovery on startup.
pub struct WalRecovery {
    /// Synthetic forward events for orphaned accepted shares.
    pub synthetic_events: Vec<ShareForwardResultEvent>,
    /// Number of entries that were already completed (discarded).
    pub completed_count: usize,
}

/// Current unix time in milliseconds.
#[allow(clippy::cast_possible_truncation)]
fn unix_ms_now() -> u64 {
    // Truncation from u128 to u64 is safe: u64 millis overflows in ~584 million years.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Most records one WAL write covers (PB-44).
///
/// One batch is at most about 230 KB of NDJSON at the 221-byte record the
/// PB-39 bench measured, and one fdatasync. The bound keeps a flood from
/// holding the select loop away from its template and shutdown arms for
/// longer than one such write, while still amortising the sync roughly a
/// thousandfold at the load where per-record syncing used to overflow the
/// accounting queue.
pub const WAL_BATCH_MAX: usize = 1024;

/// `first`, plus whatever is already queued behind it, up to
/// [`WAL_BATCH_MAX`] items. Never waits: it takes only what is there.
///
/// This exists because the gateway's `share_event_rx` and `share_result_rx`
/// arms both need it (PB-44). Each turns one wakeup into one WAL write and
/// one sync, so the sync is paid per batch instead of per share.
pub fn take_queued<T>(rx: &mut tokio::sync::mpsc::Receiver<T>, first: T) -> Vec<T> {
    let mut batch = vec![first];
    while batch.len() < WAL_BATCH_MAX {
        match rx.try_recv() {
            Ok(item) => batch.push(item),
            Err(_) => break,
        }
    }
    batch
}

impl ShareWal {
    /// Open or create the WAL file at `path`.
    ///
    /// If the file exists, its contents are parsed to rebuild the in-memory
    /// pending index. Use `recover()` afterward to emit synthetic events for
    /// orphaned entries.
    pub fn open(path: &Path, compaction_threshold: usize) -> std::io::Result<Self> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Read existing entries to build the pending index.
        // Use direct open instead of exists() check to avoid TOCTOU races.
        let pending = match Self::read_pending_index(path) {
            Ok(idx) => idx,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };

        // Open for append.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = std::io::BufWriter::new(file);

        Ok(Self {
            path: path.to_path_buf(),
            pending,
            writer,
            completed_since_compaction: 0,
            compaction_threshold,
            #[cfg(test)]
            syncs: 0,
        })
    }

    /// Parse the WAL file and return the set of entries still pending.
    fn read_pending_index(path: &Path) -> std::io::Result<HashMap<(String, String), u64>> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut pending: HashMap<(String, String), u64> = HashMap::new();

        for (lineno, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!(line = lineno + 1, error = %e, "wal: skipping unreadable line");
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            let record: WalRecord = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    warn!(line = lineno + 1, error = %e, "wal: skipping malformed record");
                    continue;
                }
            };
            let key = (record.share_id_hex, record.event_id_hex);
            match record.status {
                WalStatus::Pending => {
                    pending.insert(key, record.timestamp_ms);
                }
                WalStatus::Completed => {
                    pending.remove(&key);
                }
            }
        }

        Ok(pending)
    }

    /// Emit synthetic `ShareForwardResultEvent` for each orphaned pending entry,
    /// then clear the pending index and compact the WAL.
    ///
    /// Call this once at startup before entering the main event loop.
    pub fn recover(&mut self) -> WalRecovery {
        let orphaned_count = self.pending.len();
        let mut synthetic_events = Vec::with_capacity(orphaned_count);

        for ((share_id_hex, event_id_hex), _ts) in self.pending.drain() {
            let reason = GatewayReason::ProcessCrashRecovery.as_str().to_string();
            let evt = ShareForwardResultEvent {
                event_type: "share_forward_result",
                share_id_hex,
                event_id_hex,
                forwarded: false,
                upstream_accepted: None,
                upstream_http_status: None,
                upstream_error: Some("process crashed before forward completed".to_string()),
                reason_code: Some(reason),
                timestamp_ms: unix_ms_now(),
            };
            synthetic_events.push(evt);
        }

        if orphaned_count > 0 {
            info!(
                orphaned = orphaned_count,
                "wal: recovered orphaned share events with process_crash_recovery"
            );
            // Compact: the pending set is empty, so truncate the WAL.
            if let Err(e) = self.compact_inner() {
                error!(error = %e, "wal: compaction after recovery failed");
            }
        }

        WalRecovery {
            synthetic_events,
            completed_count: 0,
        }
    }

    /// Record a batch of accepted shares as pending, with ONE write and ONE
    /// sync for the whole batch (PB-44).
    ///
    /// The gateway's main loop calls this when it receives the shares'
    /// accepted events. The handler queues each share for forward before it
    /// emits that event, and ACKs the miner without waiting for this write.
    ///
    /// Returns `Err` if the append or fsync fails; the in-memory pending
    /// index is **not** updated for any share in the batch in that case.
    /// Callers must treat a failure as fatal to share durability: silently
    /// proceeding would leave the shares orphaned with no recovery record on
    /// disk, permanently breaking the 1:1 accepted-to-forward-result join
    /// invariant.
    pub fn mark_pending<S: AsRef<str>, E: AsRef<str>>(
        &mut self,
        shares: &[(S, E)],
    ) -> std::io::Result<()> {
        let now = unix_ms_now();
        let records: Vec<WalRecord> = shares
            .iter()
            .map(|(share_id_hex, event_id_hex)| WalRecord {
                status: WalStatus::Pending,
                share_id_hex: share_id_hex.as_ref().to_string(),
                event_id_hex: event_id_hex.as_ref().to_string(),
                timestamp_ms: now,
            })
            .collect();
        self.append_records(&records)?;
        for record in records {
            self.pending.insert(
                (record.share_id_hex, record.event_id_hex),
                record.timestamp_ms,
            );
        }
        Ok(())
    }

    /// Record a batch of share forwards as completed, with ONE write and ONE
    /// sync for the whole batch (PB-44).
    ///
    /// Removes the entries from the pending index and triggers compaction if
    /// the threshold is reached.
    ///
    /// Returns `Err` if the append, fsync, or (when threshold reached)
    /// compaction fails. The in-memory pending entries are removed up front
    /// so that repeated retries remain idempotent; callers treat a failure as
    /// fatal, same as `mark_pending`.
    pub fn mark_completed<S: AsRef<str>, E: AsRef<str>>(
        &mut self,
        shares: &[(S, E)],
    ) -> std::io::Result<()> {
        let now = unix_ms_now();
        let mut records = Vec::with_capacity(shares.len());
        for (share_id_hex, event_id_hex) in shares {
            let key = (
                share_id_hex.as_ref().to_string(),
                event_id_hex.as_ref().to_string(),
            );
            // Always write the completed record even if the pending entry is
            // missing: the select! loop can deliver a forward result before
            // the share's accounting event. That record does NOT neutralise a
            // pending line written after it. Replay runs in file order and the
            // late mark_pending re-inserts the entry. That is PB-47, open; an
            // earlier version of this comment claimed the opposite.
            let _ = self.pending.remove(&key);
            records.push(WalRecord {
                status: WalStatus::Completed,
                share_id_hex: key.0,
                event_id_hex: key.1,
                timestamp_ms: now,
            });
        }
        self.append_records(&records)?;
        self.completed_since_compaction += records.len();
        if self.compaction_threshold > 0
            && self.completed_since_compaction >= self.compaction_threshold
        {
            self.compact_inner()?;
        }
        Ok(())
    }

    /// Number of entries currently pending (not yet completed).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Append a batch of NDJSON records with one flush and one sync.
    ///
    /// Every record and its trailing newline go into a single buffer before
    /// `write_all`, so a crash cannot leave a partial (newline-less) line
    /// that would merge with the next record on recovery. An empty batch
    /// writes and syncs nothing.
    fn append_records(&mut self, records: &[WalRecord]) -> std::io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut buf = String::new();
        for record in records {
            buf.push_str(
                &serde_json::to_string(record)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
            );
            buf.push('\n');
        }
        self.writer.write_all(buf.as_bytes())?;
        self.writer.flush()?;
        // PB-39: flush() only pushes the BufWriter into the kernel, which
        // survives a process crash but not power loss or a host reset. The
        // module called itself crash-durable and two doc comments promised an
        // fsync that was never performed. `sync_data` is the fdatasync(2) that
        // makes those claims true; it syncs the file length as well as the
        // bytes, which is all an append-only log needs, and skips the
        // timestamp metadata `sync_all` would also push.
        //
        // MEASURED rather than assumed, on two filesystems, because the cost
        // is real and PB-39 asked for a number instead of a guess:
        //
        //   node ext4 (/dev/sda1, the deployment target), 2000 appends of a
        //     221-byte record: 174,361/s with flush alone, 2,340/s with
        //     fdatasync. Mean 0.002ms against 0.412ms, p99 0.009ms against
        //     0.791ms.
        //   this repo's own `bench_append_cost_on_this_filesystem` through the
        //     real code on macOS APFS: 229/s, 4.359ms each.
        //
        // Both sit orders of magnitude below the flush-only figure, which is
        // the evidence that the syscall is doing physical work rather than
        // being elided. Measure before trusting any host: fdatasync is a
        // no-op on tmpfs, and an earlier version of this measurement was
        // silently benchmarking RAM because /tmp on the node is tmpfs.
        //
        // WHERE THE COST LANDS. Both callers run inside spawn_blocking, and
        // neither touches a miner's ACK path or blocks the async reactor: the
        // handler writes SubmitShares.Success itself and never waits on the
        // WAL. But they sit on two arms of the SAME main select loop,
        // mark_pending on share_event_rx and mark_completed on share_result_rx,
        // and each `.await` suspends that one loop, so the sync rate IS the
        // rate the loop drains accounting events. PB-39 paid one sync per
        // record, two per accepted share, which on the node's 0.412ms capped
        // the loop near 1,170 accepted shares/s; past that, share_event_tx
        // overflowed and dropped accounting events (PB-44).
        //
        // PB-44 part 2 makes the unit of work a BATCH. Each arm takes every
        // record already queued behind the one that woke it (`take_queued`,
        // up to WAL_BATCH_MAX) and pays one sync for all of them. Nothing
        // waits to fill a batch, so batching delays no record's sync; under
        // load the batch grows and the sync cost per share falls with it,
        // instead of capping throughput.
        //
        // Compaction still runs inline on the same loop every
        // wal_compaction_threshold (1000 in prod) completions, adding a full
        // rewrite plus sync_all plus a directory fsync to the same budget.
        //
        // NOT GUARDED BY A TEST, deliberately. Removing this line reddens
        // nothing: fsync is not observable in-process, and a throughput
        // threshold would be a flaky test rather than a guard, since it would
        // fail on tmpfs and on CI runners. The bench above is the re-checkable
        // artifact; this comment is the reason it exists. What a test DOES
        // hold is the batching: `a_batch_costs_one_sync` counts syncs.
        self.writer.get_ref().sync_data()?;
        #[cfg(test)]
        {
            self.syncs += 1;
        }
        Ok(())
    }

    /// Compact the WAL by rewriting only the pending entries.
    ///
    /// Writes to a temporary file then atomically renames. The in-memory
    /// index is the source of truth.
    fn compact_inner(&mut self) -> std::io::Result<()> {
        let tmp_path = self.path.with_extension("wal.tmp");
        {
            let tmp_file = std::fs::File::create(&tmp_path)?;
            let mut tmp_writer = std::io::BufWriter::new(tmp_file);
            for ((share_id_hex, event_id_hex), ts) in &self.pending {
                let record = WalRecord {
                    status: WalStatus::Pending,
                    share_id_hex: share_id_hex.clone(),
                    event_id_hex: event_id_hex.clone(),
                    timestamp_ms: *ts,
                };
                let line = serde_json::to_string(&record)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                tmp_writer.write_all(line.as_bytes())?;
                tmp_writer.write_all(b"\n")?;
            }
            tmp_writer.flush()?;
            // PB-39, and this is the worse half of it. rename(2) is atomic in
            // the directory entry, but without syncing the replacement first a
            // power loss can leave the WAL name pointing at a file whose
            // contents never reached storage. That does not lose the most
            // recent record, it loses EVERY pending record at once, because
            // compaction rewrites the whole file.
            tmp_writer.get_ref().sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        // The rename itself is metadata in the parent directory and is not
        // durable until the directory is synced. Without this the file can
        // survive while the name change does not, and recovery reads the
        // pre-compaction log.
        if let Some(dir) = self.path.parent() {
            // A directory opened read-only is the portable way to fsync one.
            // Best effort: a filesystem that refuses this (some network mounts)
            // must not take down the gateway, and the data sync above already
            // holds.
            match std::fs::File::open(dir) {
                Ok(d) => {
                    if let Err(e) = d.sync_all() {
                        warn!(error = %e, "wal: parent directory sync failed after compaction");
                    }
                }
                Err(e) => warn!(error = %e, "wal: could not open parent directory to sync"),
            }
        }

        // Re-open append handle.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = std::io::BufWriter::new(file);
        self.completed_since_compaction = 0;

        info!(pending = self.pending.len(), "wal: compacted");
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn temp_wal_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("rg_wal_tests");
        let _ = std::fs::create_dir_all(&dir);
        dir.join(format!("{name}.ndjson"))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("wal.tmp"));
    }

    #[test]
    fn empty_wal_opens_clean() {
        let path = temp_wal_path("empty_open");
        cleanup(&path);
        let wal = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn mark_pending_then_completed() {
        let path = temp_wal_path("pending_completed");
        cleanup(&path);
        let mut wal = ShareWal::open(&path, 100).unwrap();
        wal.mark_pending(&[("aaa", "bbb")]).unwrap();
        assert_eq!(wal.pending_count(), 1);
        wal.mark_completed(&[("aaa", "bbb")]).unwrap();
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn recovery_emits_synthetic_events() {
        let path = temp_wal_path("recovery");
        cleanup(&path);

        // Phase 1: write pending entries and drop (simulate crash).
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            wal.mark_pending(&[("share1", "event1")]).unwrap();
            wal.mark_pending(&[("share2", "event2")]).unwrap();
            wal.mark_completed(&[("share1", "event1")]).unwrap();
            // share2 is still pending when we "crash".
        }

        // Phase 2: reopen and recover.
        let mut wal = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal.pending_count(), 1);

        let recovery = wal.recover();
        assert_eq!(recovery.synthetic_events.len(), 1);
        assert_eq!(recovery.synthetic_events[0].share_id_hex, "share2");
        assert_eq!(recovery.synthetic_events[0].event_id_hex, "event2");
        assert_eq!(
            recovery.synthetic_events[0].reason_code.as_deref(),
            Some("process_crash_recovery")
        );
        assert!(!recovery.synthetic_events[0].forwarded);

        // After recovery, pending is empty.
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn compaction_rewrites_only_pending() {
        let path = temp_wal_path("compaction");
        cleanup(&path);

        let mut wal = ShareWal::open(&path, 2).unwrap(); // threshold = 2
        wal.mark_pending(&[("s1", "e1")]).unwrap();
        wal.mark_pending(&[("s2", "e2")]).unwrap();
        wal.mark_pending(&[("s3", "e3")]).unwrap();

        // Complete two entries to trigger compaction.
        wal.mark_completed(&[("s1", "e1")]).unwrap();
        wal.mark_completed(&[("s2", "e2")]).unwrap();
        // Compaction should have fired.

        // Verify: reopen and check only s3 remains.
        drop(wal);
        let wal2 = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal2.pending_count(), 1);
        cleanup(&path);
    }

    #[test]
    fn duplicate_completion_is_harmless() {
        let path = temp_wal_path("dup_complete");
        cleanup(&path);
        let mut wal = ShareWal::open(&path, 100).unwrap();
        wal.mark_pending(&[("s1", "e1")]).unwrap();
        wal.mark_completed(&[("s1", "e1")]).unwrap();
        // Second completion should be a no-op.
        wal.mark_completed(&[("s1", "e1")]).unwrap();
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn malformed_lines_skipped() {
        let path = temp_wal_path("malformed");
        cleanup(&path);

        // Write a valid pending entry followed by garbage.
        {
            let mut f = std::fs::File::create(&path).unwrap();
            let record = WalRecord {
                status: WalStatus::Pending,
                share_id_hex: "s1".to_string(),
                event_id_hex: "e1".to_string(),
                timestamp_ms: 1000,
            };
            let line = serde_json::to_string(&record).unwrap();
            std::io::Write::write_all(&mut f, line.as_bytes()).unwrap();
            std::io::Write::write_all(&mut f, b"\n").unwrap();
            std::io::Write::write_all(&mut f, b"not valid json\n").unwrap();
        }

        let wal = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal.pending_count(), 1);
        cleanup(&path);
    }

    #[test]
    fn recovery_with_no_orphans_is_noop() {
        let path = temp_wal_path("no_orphans");
        cleanup(&path);

        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            wal.mark_pending(&[("s1", "e1")]).unwrap();
            wal.mark_completed(&[("s1", "e1")]).unwrap();
        }

        let mut wal = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal.pending_count(), 0);
        let recovery = wal.recover();
        assert!(recovery.synthetic_events.is_empty());
        cleanup(&path);
    }

    // ── PB-39: the durability the module claims must be observable ──
    //
    // Every test above this point goes through the `Wal` API, so none of
    // them can tell a record that reached the file from one still sitting
    // in the BufWriter. That is exactly the gap PB-39 names: the module
    // called itself crash-durable and two doc comments promised an fsync
    // that was never performed.
    //
    // What in-process tests CAN establish is that `Ok` means the bytes left
    // the process. They cannot establish that fdatasync reached the platter,
    // because that needs a power cut. That half is verified by measurement
    // instead: on the node's ext4 root, appends run at 174,361/s with flush
    // alone and 2,340/s with fdatasync. A 75x cost is proof the syscall is
    // doing physical work rather than being a no-op, which is the strongest
    // available evidence short of pulling the plug. See
    // `bench_append_cost_on_this_filesystem` below to re-measure anywhere.

    /// Read the WAL file with a handle that knows nothing about the `Wal`
    /// struct, which is the only way to see past its `BufWriter`.
    fn read_wal_file_independently(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn mark_pending_is_on_disk_before_it_returns() {
        let path = temp_wal_path("pb39_pending_visible");
        cleanup(&path);
        {
            let mut wal = ShareWal::open(&path, 1000).unwrap();
            wal.mark_pending(&[("aa".repeat(32).as_str(), "bb".repeat(32).as_str())])
                .unwrap();

            // Deliberately do NOT drop the Wal. If the record is only in the
            // BufWriter, this read misses it and the "callers must treat a
            // failure as fatal to share durability" contract is a fiction.
            let contents = read_wal_file_independently(&path);
            assert!(
                contents.contains(&"aa".repeat(32)),
                "mark_pending returned Ok but the record is not in the file \
                 while the Wal is still open. The durability contract says a \
                 crash between this write and the forward result is \
                 recoverable; it is not. File held: {contents:?}"
            );
        }
        cleanup(&path);
    }

    #[test]
    fn compaction_result_is_on_disk_before_it_returns() {
        let path = temp_wal_path("pb39_compaction_visible");
        cleanup(&path);
        {
            let mut wal = ShareWal::open(&path, 2).unwrap();
            wal.mark_pending(&[("11".repeat(32).as_str(), "aa".repeat(32).as_str())])
                .unwrap();
            wal.mark_pending(&[("22".repeat(32).as_str(), "bb".repeat(32).as_str())])
                .unwrap();
            // Two completions trip the threshold and force compaction.
            wal.mark_completed(&[("11".repeat(32).as_str(), "aa".repeat(32).as_str())])
                .unwrap();
            wal.mark_completed(&[("22".repeat(32).as_str(), "bb".repeat(32).as_str())])
                .unwrap();

            let contents = read_wal_file_independently(&path);
            assert!(
                !contents.contains(&"11".repeat(32)),
                "compaction ran but the completed record is still on disk: \
                 {contents:?}"
            );
            assert!(
                wal.pending_count() == 0,
                "both shares completed, so nothing should be pending"
            );
        }
        cleanup(&path);
    }

    /// Re-measure the durability cost wherever this is run. Ignored by
    /// default because it is a measurement, not an assertion: fdatasync is a
    /// no-op on tmpfs and near-free on some virtualised storage, so a
    /// threshold here would be a flaky test rather than a guard.
    ///
    /// Run with:
    /// `cargo test -p sv2-gateway --lib bench_append_cost -- --ignored --nocapture`
    #[test]
    #[ignore = "a measurement, not an assertion: fdatasync is a no-op on tmpfs"]
    fn bench_append_cost_on_this_filesystem() {
        let path = temp_wal_path("pb39_bench");
        cleanup(&path);
        let n = 2000;
        let mut wal = ShareWal::open(&path, usize::MAX).unwrap();
        let start = std::time::Instant::now();
        for i in 0..n {
            wal.mark_pending(&[(&format!("{i:064x}"), &format!("{:064x}", i * 7))])
                .unwrap();
        }
        let elapsed = start.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let per_sec = f64::from(n) / elapsed.as_secs_f64();
        println!(
            "PB-39 append cost: {n} records in {elapsed:?} = {per_sec:.0}/s, \
             {:.3}ms each. On the node's ext4 the python equivalent measured \
             174,361/s without fdatasync and 2,340/s with it; a result near \
             the high number means the sync is not reaching storage here.",
            elapsed.as_secs_f64() * 1000.0 / f64::from(n)
        );
        // PB-44: the same records, 64 to a batch, so one sync per 64.
        let batched_path = temp_wal_path("pb44_bench");
        cleanup(&batched_path);
        let mut batched_wal = ShareWal::open(&batched_path, usize::MAX).unwrap();
        let ids: Vec<(String, String)> = (0..n)
            .map(|i| (format!("{i:064x}"), format!("{:064x}", i * 7)))
            .collect();
        let start = std::time::Instant::now();
        for chunk in ids.chunks(64) {
            batched_wal.mark_pending(chunk).unwrap();
        }
        let batched = start.elapsed();
        #[allow(clippy::cast_precision_loss)]
        let batched_per_sec = f64::from(n) / batched.as_secs_f64();
        println!(
            "PB-44 batched: {n} records, 64 per sync, in {batched:?} = \
             {batched_per_sec:.0}/s, {:.1}x the per-record rate above.",
            batched_per_sec / per_sec
        );
        cleanup(&batched_path);
        cleanup(&path);
    }

    #[test]
    fn multiple_crash_cycles() {
        let path = temp_wal_path("multi_crash");
        cleanup(&path);

        // Crash 1: leave s1 pending.
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            wal.mark_pending(&[("s1", "e1")]).unwrap();
        }

        // Recovery 1: s1 recovered.
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            let r = wal.recover();
            assert_eq!(r.synthetic_events.len(), 1);
            assert_eq!(r.synthetic_events[0].share_id_hex, "s1");
        }

        // Crash 2: leave s2 pending.
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            wal.mark_pending(&[("s2", "e2")]).unwrap();
        }

        // Recovery 2: only s2 recovered (s1 was cleaned up).
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            let r = wal.recover();
            assert_eq!(r.synthetic_events.len(), 1);
            assert_eq!(r.synthetic_events[0].share_id_hex, "s2");
        }

        cleanup(&path);
    }

    /// When the underlying writer returns an I/O error, `mark_pending` and
    /// `mark_completed` must propagate the error (not swallow it) so the
    /// gateway can halt before silently losing share durability.
    ///
    /// Linux-only: relies on `/dev/full`, which always returns `ENOSPC` on
    /// write. Skipped on other platforms.
    #[cfg(target_os = "linux")]
    #[test]
    fn mark_pending_propagates_write_failure() {
        use std::fs::OpenOptions;

        let dev_full_path = std::path::Path::new("/dev/full");
        if !dev_full_path.exists() {
            // Sandbox without /dev/full; skip rather than fail.
            return;
        }
        let Ok(file) = OpenOptions::new().write(true).open(dev_full_path) else {
            // not permitted in this sandbox; skip
            return;
        };
        let writer = std::io::BufWriter::new(file);

        // Hand-construct a WAL pointed at a throwaway tmp path but with the
        // writer replaced by /dev/full. open() itself can't fail here because
        // the path is writable; we only substitute the append handle.
        let path = temp_wal_path("dev_full");
        cleanup(&path);
        let mut wal = ShareWal {
            path: path.clone(),
            pending: HashMap::new(),
            writer,
            completed_since_compaction: 0,
            compaction_threshold: 0,
            syncs: 0,
        };

        let err = wal
            .mark_pending(&[("share-x", "event-x")])
            .expect_err("write to /dev/full must fail");
        // ENOSPC maps to ErrorKind::StorageFull on recent toolchains and to
        // WriteZero/Other on older ones. Assert propagation rather than the
        // specific kind so this test survives stdlib churn.
        let kind = err.kind();
        assert!(
            matches!(
                kind,
                std::io::ErrorKind::WriteZero
                    | std::io::ErrorKind::Other
                    | std::io::ErrorKind::StorageFull
            ) || err.raw_os_error() == Some(libc_enospc()),
            "unexpected error kind from /dev/full write: {kind:?} ({err})",
        );
        // In-memory pending must NOT have been updated on failure.
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    /// ENOSPC on Linux. Hardcoded rather than pulling in libc for one constant.
    #[cfg(target_os = "linux")]
    fn libc_enospc() -> i32 {
        28
    }

    #[test]
    fn a_batch_costs_one_sync() {
        let path = temp_wal_path("pb44_one_sync");
        cleanup(&path);
        let mut wal = ShareWal::open(&path, usize::MAX).unwrap();
        let ids: Vec<(String, String)> = (0..64)
            .map(|i| (format!("{i:064x}"), format!("{:064x}", i + 1000)))
            .collect();
        wal.mark_pending(&ids).unwrap();
        assert_eq!(
            wal.syncs, 1,
            "64 pending records must cost ONE sync, not one each (PB-44)"
        );
        assert_eq!(wal.pending_count(), 64);
        wal.mark_completed(&ids).unwrap();
        assert_eq!(wal.syncs, 2, "64 completions must cost exactly one more");
        assert_eq!(wal.pending_count(), 0);
        cleanup(&path);
    }

    #[test]
    fn a_whole_batch_is_on_disk_before_it_returns() {
        let path = temp_wal_path("pb44_batch_visible");
        cleanup(&path);
        let ids: Vec<(String, String)> = (0..3)
            .map(|i| (format!("{i:064x}"), format!("{:064x}", i + 7)))
            .collect();
        {
            let mut wal = ShareWal::open(&path, 1000).unwrap();
            wal.mark_pending(&ids).unwrap();
            // Read past the still-open Wal's BufWriter, as the PB-39 test does.
            let contents = read_wal_file_independently(&path);
            for (share_id, _) in &ids {
                assert!(
                    contents.contains(share_id.as_str()),
                    "mark_pending returned Ok but {share_id} is not on disk: {contents:?}"
                );
            }
            assert_eq!(
                contents.lines().count(),
                3,
                "one line per record, none merged: {contents:?}"
            );
        }
        let reopened = ShareWal::open(&path, 1000).unwrap();
        assert_eq!(
            reopened.pending_count(),
            3,
            "replay reads every record back"
        );
        cleanup(&path);
    }

    #[test]
    fn take_queued_takes_what_is_queued_and_stops_at_the_bound() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<usize>(WAL_BATCH_MAX + 16);
        for i in 0..5 {
            tx.try_send(i).unwrap();
        }
        let first = rx.try_recv().unwrap();
        assert_eq!(
            take_queued(&mut rx, first),
            vec![0, 1, 2, 3, 4],
            "takes everything queued, in order"
        );
        assert!(rx.try_recv().is_err(), "and leaves nothing behind");

        for i in 0..WAL_BATCH_MAX + 5 {
            tx.try_send(i).unwrap();
        }
        let first = rx.try_recv().unwrap();
        assert_eq!(
            take_queued(&mut rx, first).len(),
            WAL_BATCH_MAX,
            "never more than the bound"
        );
        let mut left = 0;
        while rx.try_recv().is_ok() {
            left += 1;
        }
        assert_eq!(left, 5, "the rest stays queued for the next wakeup");
    }

    /// PB-44's end-to-end claim, measured on whatever filesystem this runs
    /// on. A producer offers accounting events into an mpsc(4096), the
    /// capacity the gateway gives `share_event_tx`, with `try_send` exactly as
    /// the handler does. A consumer drains it the way the main loop does,
    /// paying the WAL inside `spawn_blocking` once per event (before PB-44)
    /// or once per `take_queued` batch (after). This models the select arm
    /// rather than running `main.rs`; the channel, the WAL and `take_queued`
    /// are the real ones.
    ///
    /// `cargo test -p sv2-gateway --lib offered_load -- --ignored --nocapture`
    #[test]
    #[ignore = "a measurement, not an assertion: depends on this filesystem's fdatasync cost"]
    fn offered_load_drops_with_and_without_batching() {
        for batched in [false, true] {
            let (offered, dropped, drained) =
                offered_load_run(batched, 3, std::time::Duration::from_secs(4));
            println!(
                "PB-44 offered load, {}: offered {offered}, drained {drained}, dropped {dropped}",
                if batched {
                    "batched"
                } else {
                    "one sync per event"
                }
            );
        }
    }

    /// Offer `per_ms` events every millisecond for `window`, then report
    /// (offered, dropped at the queue, drained by the consumer in the window).
    fn offered_load_run(
        batched: bool,
        per_ms: u64,
        window: std::time::Duration,
    ) -> (u64, u64, u64) {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let path = temp_wal_path(if batched {
                "pb44_load_batched"
            } else {
                "pb44_load_single"
            });
            cleanup(&path);
            let wal = Arc::new(Mutex::new(ShareWal::open(&path, 1000).unwrap()));
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(4096);
            let drained = Arc::new(AtomicU64::new(0));

            let consumer = {
                let drained = Arc::clone(&drained);
                tokio::spawn(async move {
                    while let Some(first) = rx.recv().await {
                        let batch = if batched {
                            take_queued(&mut rx, first)
                        } else {
                            vec![first]
                        };
                        let n = u64::try_from(batch.len()).unwrap();
                        let wal = Arc::clone(&wal);
                        tokio::task::spawn_blocking(move || {
                            wal.lock().unwrap().mark_pending(&batch)
                        })
                        .await
                        .unwrap()
                        .unwrap();
                        drained.fetch_add(n, Ordering::Relaxed);
                    }
                })
            };

            let (mut offered, mut dropped) = (0u64, 0u64);
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(1));
            let start = tokio::time::Instant::now();
            while start.elapsed() < window {
                tick.tick().await;
                for _ in 0..per_ms {
                    let id = format!("{offered:064x}");
                    offered += 1;
                    if tx.try_send((id.clone(), id)).is_err() {
                        dropped += 1;
                    }
                }
            }
            consumer.abort();
            cleanup(&path);
            (offered, dropped, drained.load(Ordering::Relaxed))
        })
    }
}
