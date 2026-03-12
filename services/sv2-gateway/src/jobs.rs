//! Job table and template-to-job translation.
//!
//! The job table maps `job_id` to the full job record containing all fields
//! needed for share validation and `share_id` computation. Jobs are created
//! from accepted (inline) or received (observe) templates.
//!
//! The job ID is a gateway-global monotonic `u32` counter. On exhaustion
//! the gateway enters degraded mode and refuses new jobs.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use sha2::{Digest, Sha256};
use tracing::{debug, error, warn};

// ─────────────────────────────────────────────────────────────────────
// Job ID allocator
// ─────────────────────────────────────────────────────────────────────

/// Global monotonic job ID counter. Unique per gateway process lifetime.
pub struct JobIdAllocator {
    next: AtomicU32,
    exhausted: std::sync::atomic::AtomicBool,
}

impl JobIdAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU32::new(1),
            exhausted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Allocate the next job ID. Returns `None` if exhausted.
    pub fn allocate(&self) -> Option<u32> {
        if self.exhausted.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == u32::MAX {
            self.exhausted.store(true, Ordering::Relaxed);
            error!("job_id counter exhausted; gateway must restart to resume");
            None
        } else {
            Some(id)
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }
}

impl Default for JobIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Job record
// ─────────────────────────────────────────────────────────────────────

/// A single job record in the job table.
///
/// Contains all fields needed for `NewMiningJob` construction,
/// `SetNewPrevHash` activation, share validation, and `share_id` computation.
#[derive(Debug, Clone)]
pub struct JobRecord {
    /// Gateway-assigned job ID.
    pub job_id: u32,

    /// Template ID from the upstream template source.
    pub template_id: u64,

    /// Block height for this job.
    pub block_height: u32,

    /// Block version (from template `block_version`).
    pub version: u32,

    /// Previous block hash in SV2 wire byte order (32 bytes, LE).
    pub prev_hash: [u8; 32],

    /// Compact difficulty target from the block header.
    pub nbits: u32,

    /// Coinbase transaction prefix (before extranonce).
    pub coinbase_tx_prefix: Vec<u8>,

    /// Coinbase transaction suffix (after extranonce).
    pub coinbase_tx_suffix: Vec<u8>,

    /// Merkle path: array of 32-byte sibling hashes from leaf to root.
    pub merkle_path: Vec<[u8; 32]>,

    /// The `activation_min_ntime` computed at activation time.
    /// `effective_min_ntime = max(template.min_ntime, template.curtime)` clamped.
    pub activation_min_ntime: u32,

    /// Raw template `min_ntime` (MTP derived) for telemetry.
    pub raw_min_ntime: u32,

    /// Raw template `curtime` for telemetry.
    pub raw_curtime: u32,

    /// Source instance ID from template-manager.
    pub source_instance_id: String,

    /// Whether this job has been activated by a `SetNewPrevHash`.
    pub activated: bool,

    /// Instant this job record was created.
    pub created_at: Instant,
}

impl JobRecord {
    /// Compute the merkle root for a given extranonce prefix.
    ///
    /// Algorithm: `SHA256d(prefix || extranonce || suffix)` then walk merkle path.
    pub fn compute_merkle_root(&self, extranonce_prefix: &[u8]) -> [u8; 32] {
        compute_merkle_root(
            &self.coinbase_tx_prefix,
            extranonce_prefix,
            &self.coinbase_tx_suffix,
            &self.merkle_path,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────
// Merkle root computation (normative, matches scope doc)
// ─────────────────────────────────────────────────────────────────────

/// Compute the merkle root from coinbase parts and merkle path.
///
/// 1. Assemble coinbase: `prefix || extranonce || suffix`
/// 2. Compute coinbase txid: `SHA256d(coinbase_bytes)`
/// 3. Walk merkle path: `current = SHA256d(current || path_element)`
///
/// Path elements are used as-is (no byte reversal per scope doc).
pub fn compute_merkle_root(
    coinbase_tx_prefix: &[u8],
    extranonce_prefix: &[u8],
    coinbase_tx_suffix: &[u8],
    merkle_path: &[[u8; 32]],
) -> [u8; 32] {
    // Step 1: Assemble coinbase transaction.
    let mut coinbase = Vec::with_capacity(
        coinbase_tx_prefix.len() + extranonce_prefix.len() + coinbase_tx_suffix.len(),
    );
    coinbase.extend_from_slice(coinbase_tx_prefix);
    coinbase.extend_from_slice(extranonce_prefix);
    coinbase.extend_from_slice(coinbase_tx_suffix);

    // Step 2: coinbase txid = SHA256d(coinbase).
    let mut current = sha256d(&coinbase);

    // Step 3: Walk merkle path from leaf to root.
    for sibling in merkle_path {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&current);
        combined[32..].copy_from_slice(sibling);
        current = sha256d(&combined);
    }

    current
}

/// Double SHA256 (`SHA256d`).
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

// ─────────────────────────────────────────────────────────────────────
// effective_min_ntime computation (normative)
// ─────────────────────────────────────────────────────────────────────

/// Compute the effective `min_ntime` for `SetNewPrevHash.min_ntime`.
///
/// `effective = min(max(template_min_ntime, template_curtime), gateway_now + skew_allowance)`
///
/// This prevents both MTP lag and clock-skew issues.
pub fn effective_min_ntime(
    template_min_ntime: u32,
    template_curtime: u32,
    gateway_now: u32,
    skew_allowance: u32,
) -> u32 {
    let unclamped = template_min_ntime.max(template_curtime);
    let ceiling = gateway_now.saturating_add(skew_allowance);
    unclamped.min(ceiling)
}

// ─────────────────────────────────────────────────────────────────────
// Job table
// ─────────────────────────────────────────────────────────────────────

/// Bounded job table with LRU eviction by creation time.
///
/// Jobs older than `retention_ms` are eligible for eviction.
/// The table uses a `BTreeMap` keyed by `job_id` (monotonic, so
/// iteration order matches creation order).
pub struct JobTable {
    jobs: BTreeMap<u32, JobRecord>,
    retention_ms: u64,
    max_entries: usize,
}

impl JobTable {
    pub fn new(retention_ms: u64, max_entries: usize) -> Self {
        Self {
            jobs: BTreeMap::new(),
            retention_ms,
            max_entries,
        }
    }

    /// Insert a job record. Evicts stale entries if the table is full.
    pub fn insert(&mut self, job: JobRecord) {
        self.evict_stale();
        if self.jobs.len() >= self.max_entries {
            // Remove the oldest entry (smallest job_id).
            if let Some(&oldest_id) = self.jobs.keys().next() {
                debug!(evicted_job_id = oldest_id, "job table LRU eviction");
                self.jobs.remove(&oldest_id);
            }
        }
        let job_id = job.job_id;
        self.jobs.insert(job_id, job);
    }

    /// Look up a job by ID.
    pub fn get(&self, job_id: u32) -> Option<&JobRecord> {
        self.jobs.get(&job_id)
    }

    /// Remove all jobs older than `retention_ms`.
    pub fn evict_stale(&mut self) {
        let now = Instant::now();
        let retention = std::time::Duration::from_millis(self.retention_ms);
        self.jobs
            .retain(|_, j| now.duration_since(j.created_at) < retention);
    }

    /// Number of jobs in the table.
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    /// The most recently inserted job (highest `job_id`).
    pub fn latest(&self) -> Option<&JobRecord> {
        self.jobs.values().next_back()
    }

    /// The most recently inserted job for a given `prev_hash`.
    pub fn latest_for_prevhash(&self, prev_hash: &[u8; 32]) -> Option<&JobRecord> {
        self.jobs.values().rev().find(|j| &j.prev_hash == prev_hash)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Template dedup cache
// ─────────────────────────────────────────────────────────────────────

/// Bounded LRU cache for template deduplication.
///
/// Key: `(source_instance_id, template_id)`.
/// Prevents redundant verifier submissions.
pub struct TemplateDedupCache {
    seen: std::collections::HashSet<(String, u64)>,
    max_entries: usize,
    /// Current `source_instance_id`. On change, the cache resets.
    current_source: Option<String>,
}

impl TemplateDedupCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            max_entries,
            current_source: None,
        }
    }

    /// Check if a template has been seen before. Returns `true` if it
    /// is a duplicate (should be skipped).
    pub fn is_duplicate(&mut self, source_instance_id: &str, template_id: u64) -> bool {
        // Reset on source_instance_id change.
        if self.current_source.as_deref() != Some(source_instance_id) {
            debug!(
                old = ?self.current_source,
                new = source_instance_id,
                "source_instance_id changed; resetting dedup cache"
            );
            self.seen.clear();
            self.current_source = Some(source_instance_id.to_string());
        }

        if self
            .seen
            .contains(&(source_instance_id.to_string(), template_id))
        {
            return true;
        }

        // Evict all entries if full (HashSet has no insertion order, so a
        // partial eviction would be arbitrary; full clear is deterministic).
        if self.seen.len() >= self.max_entries {
            warn!(count = self.seen.len(), "dedup cache full; clearing");
            self.seen.clear();
        }

        self.seen
            .insert((source_instance_id.to_string(), template_id));
        false
    }

    /// Remove a specific template from the dedup cache, allowing it to be
    /// re-submitted if upstream re-sends it. Used when evicting pending
    /// templates to keep the dedup cache coupled to the pending store.
    pub fn remove(&mut self, source_instance_id: &str, template_id: u64) {
        self.seen
            .remove(&(source_instance_id.to_string(), template_id));
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_job(job_id: u32) -> JobRecord {
        JobRecord {
            job_id,
            template_id: 100,
            block_height: 800_000,
            version: 0x2000_0000,
            prev_hash: [0xAA; 32],
            nbits: 0x1703_ffff,
            coinbase_tx_prefix: vec![0x01, 0x00, 0x00, 0x00],
            coinbase_tx_suffix: vec![0xFF, 0xFF, 0xFF, 0xFF],
            merkle_path: vec![],
            activation_min_ntime: 1_700_000_000,
            raw_min_ntime: 1_700_000_000,
            raw_curtime: 1_700_000_001,
            source_instance_id: "test-instance".into(),
            activated: false,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn job_id_allocator_monotonic() {
        let alloc = JobIdAllocator::new();
        assert_eq!(alloc.allocate(), Some(1));
        assert_eq!(alloc.allocate(), Some(2));
        assert!(!alloc.is_exhausted());
    }

    #[test]
    fn job_table_insert_and_get() {
        let mut table = JobTable::new(300_000, 1000);
        let job = test_job(1);
        table.insert(job);
        assert_eq!(table.len(), 1);
        assert!(table.get(1).is_some());
        assert!(table.get(99).is_none());
    }

    #[test]
    fn job_table_lru_eviction() {
        let mut table = JobTable::new(300_000, 3);
        table.insert(test_job(1));
        table.insert(test_job(2));
        table.insert(test_job(3));
        // Fourth insert should evict job 1 (oldest).
        table.insert(test_job(4));
        assert!(table.get(1).is_none());
        assert!(table.get(4).is_some());
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn job_table_latest() {
        let mut table = JobTable::new(300_000, 100);
        table.insert(test_job(5));
        table.insert(test_job(10));
        table.insert(test_job(7));
        assert_eq!(table.latest().unwrap().job_id, 10);
    }

    #[test]
    fn job_table_latest_for_prevhash() {
        let mut table = JobTable::new(300_000, 100);
        let mut j1 = test_job(1);
        j1.prev_hash = [0x11; 32];
        table.insert(j1);

        let mut j2 = test_job(2);
        j2.prev_hash = [0x22; 32];
        table.insert(j2);

        let mut j3 = test_job(3);
        j3.prev_hash = [0x11; 32];
        table.insert(j3);

        let result = table.latest_for_prevhash(&[0x11; 32]);
        assert_eq!(result.unwrap().job_id, 3);
    }

    // ── Merkle root tests ──

    #[test]
    fn merkle_root_single_tx_block() {
        // Empty merkle path: root == coinbase txid.
        let prefix = vec![0x01, 0x00];
        let extranonce = [0x42, 0x00, 0x00, 0x00];
        let suffix = vec![0xFF, 0xFF];

        let root = compute_merkle_root(&prefix, &extranonce, &suffix, &[]);

        // Recompute manually.
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&prefix);
        coinbase.extend_from_slice(&extranonce);
        coinbase.extend_from_slice(&suffix);
        let expected = sha256d(&coinbase);

        assert_eq!(root, expected);
    }

    #[test]
    fn merkle_root_different_extranonce_different_root() {
        let prefix = vec![0x01];
        let suffix = vec![0xFF];
        let path = [[0xBB; 32]];

        let root_a = compute_merkle_root(&prefix, &[0x01, 0x00, 0x00, 0x00], &suffix, &path);
        let root_b = compute_merkle_root(&prefix, &[0x02, 0x00, 0x00, 0x00], &suffix, &path);

        assert_ne!(
            root_a, root_b,
            "different extranonce must produce different merkle root"
        );
    }

    // ── effective_min_ntime tests ──

    #[test]
    fn effective_min_ntime_mtp_lag() {
        // template.min_ntime lags behind curtime.
        let result = effective_min_ntime(1_700_000_000, 1_700_003_600, 1_700_003_610, 60);
        assert_eq!(result, 1_700_003_600); // max(mtp, curtime) = curtime, within ceiling
    }

    #[test]
    fn effective_min_ntime_clock_skew_clamp() {
        // template.curtime is far ahead of gateway clock.
        let result = effective_min_ntime(1_700_000_000, 1_700_099_999, 1_700_000_010, 60);
        // ceiling = 1_700_000_010 + 60 = 1_700_000_070
        assert_eq!(result, 1_700_000_070);
    }

    #[test]
    fn effective_min_ntime_normal_case() {
        // MTP and curtime are close, gateway clock agrees.
        let result = effective_min_ntime(1_700_000_000, 1_700_000_001, 1_700_000_005, 60);
        assert_eq!(result, 1_700_000_001); // max(mtp, curtime) = curtime, within ceiling
    }

    // ── Template dedup cache tests ──

    #[test]
    fn dedup_cache_detects_duplicates() {
        let mut cache = TemplateDedupCache::new(100);
        assert!(!cache.is_duplicate("src1", 1));
        assert!(cache.is_duplicate("src1", 1));
        assert!(!cache.is_duplicate("src1", 2));
    }

    #[test]
    fn dedup_cache_resets_on_source_change() {
        let mut cache = TemplateDedupCache::new(100);
        assert!(!cache.is_duplicate("src1", 1));
        assert!(cache.is_duplicate("src1", 1)); // duplicate
        assert!(!cache.is_duplicate("src2", 1)); // new source, not duplicate
    }
}
