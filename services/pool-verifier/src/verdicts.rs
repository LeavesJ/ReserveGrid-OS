use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader as StdBufReader, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use reservegrid_common::DeployMode;
use serde::{Deserialize, Serialize};

/// Represents a single verdict logged to memory and disk.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LoggedVerdict {
    pub(crate) log_id: u64,
    pub(crate) template_id: u64,
    pub(crate) height: u32,
    pub(crate) total_fees: u64,
    pub(crate) tx_count: u32,
    pub(crate) accepted: bool,

    // Back-compat + UI
    pub(crate) reason: Option<String>,

    // New structured fields (old NDJSON lines will still parse)
    #[serde(default)]
    pub(crate) reason_code: Option<String>,
    #[serde(default)]
    pub(crate) reason_detail: Option<String>,

    pub(crate) timestamp: u64,

    pub(crate) min_avg_fee_used: u64,
    pub(crate) fee_tier: String, // "low" | "mid" | "high"
    #[serde(default)]
    pub(crate) tier_source: String, // "measured" | "fallback"
    pub(crate) avg_fee_sats_per_tx: u64,

    // v0.2.2 consensus safety fields
    #[serde(default)]
    pub(crate) template_weight: Option<u64>,
    #[serde(default)]
    pub(crate) total_sigops: Option<u32>,
    #[serde(default)]
    pub(crate) coinbase_sigops: Option<u32>,
    #[serde(default)]
    pub(crate) created_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub(crate) safety_warnings: Vec<String>,
}

/// Statistics response for the API.
#[derive(Serialize)]
pub(crate) struct StatsResponse {
    pub(crate) total: u64,
    pub(crate) accepted: u64,
    pub(crate) rejected: u64,
    pub(crate) by_reason: BTreeMap<String, u64>,
    pub(crate) by_tier: BTreeMap<String, u64>,
    pub(crate) last: Option<LoggedVerdict>,
}

/// Shared verdict log in memory.
pub(crate) type VerdictLog = Arc<Mutex<Vec<LoggedVerdict>>>;

/// Shared log ID counter.
pub(crate) type LogIdCounter = Arc<AtomicU64>;

/// Deploy mode for verdict persistence.
pub(crate) static DEPLOY_MODE: OnceLock<DeployMode> = OnceLock::new();

/// Track count of verdict write errors.
pub(crate) static LOG_WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// Last time mempool was successfully contacted.
pub(crate) static LAST_MEMPOOL_OK_UNIX: AtomicU64 = AtomicU64::new(0);

/// Path to the verdict log file on disk.
pub(crate) const VERDICT_LOG_PATH: &str = "data/verdicts.log";

/// Maximum size of a single verdict log file before rotation.
pub(crate) const VERDICT_LOG_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Number of rotated verdict log files to keep.
pub(crate) const VERDICT_LOG_ROTATIONS: usize = 5;

/// Load verdicts from disk into memory.
pub(crate) fn load_verdict_log() -> (VerdictLog, LogIdCounter) {
    let mut list = Vec::new();
    let mut max_id = 0u64;

    if let Ok(file) = File::open(VERDICT_LOG_PATH) {
        let reader = StdBufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<LoggedVerdict>(line) {
                max_id = max_id.max(v.log_id);
                list.push(v);
            }
        }
    }

    let log = Arc::new(Mutex::new(list));
    let counter = Arc::new(AtomicU64::new(max_id + 1));
    (log, counter)
}

/// Rotate verdict log if it exceeds max size.
pub(crate) fn rotate_verdict_log_if_needed() {
    let Ok(meta) = std::fs::metadata(VERDICT_LOG_PATH) else {
        return;
    };

    if meta.len() < VERDICT_LOG_MAX_BYTES {
        return;
    }

    for i in (1..=VERDICT_LOG_ROTATIONS).rev() {
        let src = if i == 1 {
            VERDICT_LOG_PATH.to_string()
        } else {
            format!("{VERDICT_LOG_PATH}.{}", i - 1)
        };
        let dst = format!("{VERDICT_LOG_PATH}.{i}");

        if std::path::Path::new(&src).exists() {
            let _ = std::fs::remove_file(&dst);
            let _ = std::fs::rename(&src, &dst);
        }
    }
}

/// Append a verdict to the disk log, respecting deploy mode.
pub(crate) fn append_verdict_to_disk(v: &LoggedVerdict) {
    let mode = DEPLOY_MODE.get().copied().unwrap_or(DeployMode::Shadow);
    if !mode.persist_verdicts() {
        return;
    }

    let res = (|| {
        rotate_verdict_log_if_needed();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(VERDICT_LOG_PATH)?;

        let line = serde_json::to_string(v)?;
        writeln!(file, "{line}")?;

        file.flush()?;
        file.sync_data()?;

        Ok::<(), anyhow::Error>(())
    })();

    if res.is_err() {
        LOG_WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Get current timestamp in seconds since `UNIX_EPOCH`.
pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Get current timestamp in milliseconds since `UNIX_EPOCH`.
pub(crate) fn current_timestamp_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}
