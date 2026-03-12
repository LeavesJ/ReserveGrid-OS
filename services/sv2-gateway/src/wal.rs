//! Write-ahead log (WAL) for crash-durable share event delivery.
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
//! `"pending"` record written before enqueuing to the forward channel, or a
//! `"completed"` record written after the forward result arrives. Periodic
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
        let pending = if path.exists() {
            Self::read_pending_index(path)?
        } else {
            HashMap::new()
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

    /// Record a share as pending (about to be enqueued for forwarding).
    ///
    /// Must be called before `try_send` to the forward channel so that a
    /// crash between this write and the forward result is recoverable.
    pub fn mark_pending(&mut self, share_id_hex: &str, event_id_hex: &str) {
        let record = WalRecord {
            status: WalStatus::Pending,
            share_id_hex: share_id_hex.to_string(),
            event_id_hex: event_id_hex.to_string(),
            timestamp_ms: unix_ms_now(),
        };
        if let Err(e) = self.append_record(&record) {
            error!(
                share_id = %share_id_hex,
                error = %e,
                "wal: failed to write pending record"
            );
            return;
        }
        self.pending.insert(
            (share_id_hex.to_string(), event_id_hex.to_string()),
            record.timestamp_ms,
        );
    }

    /// Record a share forward as completed.
    ///
    /// Removes the entry from the pending index and triggers compaction if
    /// the threshold is reached.
    pub fn mark_completed(&mut self, share_id_hex: &str, event_id_hex: &str) {
        let key = (share_id_hex.to_string(), event_id_hex.to_string());
        // Always write the completed record even if the pending entry is
        // missing. This guards against a select! ordering race where
        // mark_completed fires before mark_pending in the main loop. On
        // recovery the completed record neutralises the pending one
        // regardless of write order.
        let _ = self.pending.remove(&key);
        let record = WalRecord {
            status: WalStatus::Completed,
            share_id_hex: share_id_hex.to_string(),
            event_id_hex: event_id_hex.to_string(),
            timestamp_ms: unix_ms_now(),
        };
        if let Err(e) = self.append_record(&record) {
            error!(
                share_id = %share_id_hex,
                error = %e,
                "wal: failed to write completed record"
            );
        }
        self.completed_since_compaction += 1;
        if self.compaction_threshold > 0
            && self.completed_since_compaction >= self.compaction_threshold
            && let Err(e) = self.compact_inner()
        {
            error!(error = %e, "wal: auto-compaction failed");
        }
    }

    /// Number of entries currently pending (not yet completed).
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Append a single NDJSON record and flush.
    ///
    /// The JSON and trailing newline are combined into a single buffer
    /// before calling `write_all` so a crash cannot leave a partial
    /// (newline-less) line that would merge with the next record on
    /// recovery.
    fn append_record(&mut self, record: &WalRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;
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
        }
        std::fs::rename(&tmp_path, &self.path)?;

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
        wal.mark_pending("aaa", "bbb");
        assert_eq!(wal.pending_count(), 1);
        wal.mark_completed("aaa", "bbb");
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
            wal.mark_pending("share1", "event1");
            wal.mark_pending("share2", "event2");
            wal.mark_completed("share1", "event1");
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
        wal.mark_pending("s1", "e1");
        wal.mark_pending("s2", "e2");
        wal.mark_pending("s3", "e3");

        // Complete two entries to trigger compaction.
        wal.mark_completed("s1", "e1");
        wal.mark_completed("s2", "e2");
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
        wal.mark_pending("s1", "e1");
        wal.mark_completed("s1", "e1");
        // Second completion should be a no-op.
        wal.mark_completed("s1", "e1");
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
            wal.mark_pending("s1", "e1");
            wal.mark_completed("s1", "e1");
        }

        let mut wal = ShareWal::open(&path, 100).unwrap();
        assert_eq!(wal.pending_count(), 0);
        let recovery = wal.recover();
        assert!(recovery.synthetic_events.is_empty());
        cleanup(&path);
    }

    #[test]
    fn multiple_crash_cycles() {
        let path = temp_wal_path("multi_crash");
        cleanup(&path);

        // Crash 1: leave s1 pending.
        {
            let mut wal = ShareWal::open(&path, 100).unwrap();
            wal.mark_pending("s1", "e1");
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
            wal.mark_pending("s2", "e2");
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
}
