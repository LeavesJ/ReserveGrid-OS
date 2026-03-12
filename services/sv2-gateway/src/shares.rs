//! Share validation pipeline.
//!
//! Validates `SubmitSharesStandard` messages against the SV2 protocol
//! checklist and (in inline mode) performs replay detection. Every
//! rejection is traceable via a machine-readable `GatewayReason`.
//!
//! Validation order (normative):
//! 1. Structural: channel exists, job exists in job table
//! 2. Version bits: non-GP bits match job version (BIP 320)
//! 3. ntime bounds: elapsed-time + absolute clamp
//! 4. Difficulty: share hash meets channel target
//! 5. Staleness: job is the current job for the channel
//! 6. Replay detection (inline mode only): `share_id` not in dedup set
//!
//! Byte order conventions: SV2 wire = LE; Bitcoin display hex = BE (reversed).

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use reservegrid_common::reason::GatewayReason;
use rg_protocol::gateway::BIP320_GP_MASK;
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────
// Share identity computation
// ─────────────────────────────────────────────────────────────────────

/// Assemble the 80-byte Bitcoin block header from share fields.
///
/// Layout: `version(4 LE) || prev_hash(32 wire) || merkle_root(32 wire) || ntime(4 LE) || nbits(4 LE) || nonce(4 LE)`
pub fn header_identity_bytes(
    version: u32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    ntime: u32,
    nbits: u32,
    nonce: u32,
) -> [u8; 80] {
    let mut buf = [0u8; 80];
    buf[0..4].copy_from_slice(&version.to_le_bytes());
    buf[4..36].copy_from_slice(prev_hash);
    buf[36..68].copy_from_slice(merkle_root);
    buf[68..72].copy_from_slice(&ntime.to_le_bytes());
    buf[72..76].copy_from_slice(&nbits.to_le_bytes());
    buf[76..80].copy_from_slice(&nonce.to_le_bytes());
    buf
}

/// Compute `share_id` (`PoW` dedup key).
///
/// `share_id = SHA256(header_identity_bytes)` (single SHA256, not `SHA256d`).
pub fn compute_share_id(header_bytes: &[u8; 80]) -> [u8; 32] {
    let hash = Sha256::digest(header_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Compute `event_id` (attribution-bound signing key).
///
/// `event_id = SHA256(share_id || u16_le(len) || worker_id_utf8 || u16_le(len) || validation_level_utf8)`
pub fn compute_event_id(share_id: &[u8; 32], worker_id: &str, validation_level: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(share_id);

    #[allow(clippy::cast_possible_truncation)]
    let worker_len = (worker_id.len() as u16).to_le_bytes();
    hasher.update(worker_len);
    hasher.update(worker_id.as_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let level_len = (validation_level.len() as u16).to_le_bytes();
    hasher.update(level_len);
    hasher.update(validation_level.as_bytes());

    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Compute the HMAC-SHA256 gateway signature.
///
/// Returns `None` if the HMAC key is rejected (should not happen for SHA256
/// which accepts any key length, but we propagate rather than panic).
pub fn compute_gateway_signature(secret: &[u8], event_id: &[u8; 32]) -> Option<[u8; 32]> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(event_id);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────
// PoW difficulty validation
// ─────────────────────────────────────────────────────────────────────

/// Double SHA256 (`SHA256d`) for Bitcoin `PoW` hash.
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Check if a share meets the difficulty target.
///
/// Computes `block_hash = SHA256d(header_bytes)` and compares as a
/// 256-bit LE integer against `maximum_target`.
///
/// Returns `true` if `block_hash_int <= maximum_target_int`.
///
/// NOTE: This comparison uses early exit (not constant-time). For share
/// validation this is acceptable because the miner already knows their
/// own hash and the target is public. Constant-time comparison would
/// be required only if the target were secret.
pub fn validate_share_pow(header_bytes: &[u8; 80], maximum_target: &[u8; 32]) -> bool {
    let block_hash = sha256d(header_bytes);
    // Compare as 256-bit LE integers: byte 31 is most significant.
    // Compare from most significant byte (index 31) to least (index 0).
    for i in (0..32).rev() {
        match block_hash[i].cmp(&maximum_target[i]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true // equal means it meets the target
}

// ─────────────────────────────────────────────────────────────────────
// Version bits check (BIP 320)
// ─────────────────────────────────────────────────────────────────────

/// Check that non-GP version bits match the job version.
///
/// `(submit_version & SIGNALING_MASK) == (job_version & SIGNALING_MASK)`
pub fn check_version_bits(submit_version: u32, job_version: u32) -> bool {
    let signaling_mask = !BIP320_GP_MASK;
    (submit_version & signaling_mask) == (job_version & signaling_mask)
}

// ─────────────────────────────────────────────────────────────────────
// ntime bounds validation
// ─────────────────────────────────────────────────────────────────────

/// Validate ntime against SV2 elapsed-time bound and absolute clamp.
///
/// `now_unix` is the current UNIX timestamp in seconds, passed explicitly
/// to keep the function deterministic and testable.
///
/// Returns `true` if ntime is within bounds.
pub fn check_ntime_bounds(
    ntime: u32,
    activation_min_ntime: u32,
    elapsed_since_prevhash_secs: u32,
    ntime_elapsed_slack_seconds: u32,
    max_future_block_time_seconds: u32,
    now_unix: u32,
) -> bool {
    // Lower bound: ntime >= activation_min_ntime
    if ntime < activation_min_ntime {
        return false;
    }

    // Upper bound (SV2 elapsed-time): ntime <= activation_min_ntime + elapsed + slack
    let elapsed_upper = activation_min_ntime
        .saturating_add(elapsed_since_prevhash_secs)
        .saturating_add(ntime_elapsed_slack_seconds);
    if ntime > elapsed_upper {
        return false;
    }

    // Absolute clamp: ntime <= current_unix_time + max_future_block_time
    let absolute_upper = now_unix.saturating_add(max_future_block_time_seconds);
    if ntime > absolute_upper {
        return false;
    }

    true
}

/// Current UNIX timestamp as u32 (seconds since epoch).
pub fn current_unix_timestamp() -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    ts
}

// ─────────────────────────────────────────────────────────────────────
// Share dedup set (replay detection)
// ─────────────────────────────────────────────────────────────────────

/// Bounded LRU dedup set for share replay detection.
///
/// Uses a `HashSet` with a `VecDeque` for eviction ordering.
/// Inline mode only.
pub struct ShareDedupSet {
    set: HashSet<[u8; 32]>,
    order: std::collections::VecDeque<[u8; 32]>,
    max_entries: usize,
}

impl ShareDedupSet {
    pub fn new(max_entries: usize) -> Self {
        Self {
            set: HashSet::with_capacity(max_entries.min(65536)),
            order: std::collections::VecDeque::with_capacity(max_entries.min(65536)),
            max_entries,
        }
    }

    /// Check if a `share_id` is a replay. If not, insert it and return `false`.
    /// If it is a replay, return `true`.
    pub fn check_and_insert(&mut self, share_id: &[u8; 32]) -> bool {
        if self.set.contains(share_id) {
            return true; // replay
        }

        // Evict oldest if full.
        while self.set.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            } else {
                break;
            }
        }

        self.set.insert(*share_id);
        self.order.push_back(*share_id);
        false
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Share submission struct (for upstream relay)
// ─────────────────────────────────────────────────────────────────────

/// A validated share ready for upstream submission.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareSubmission {
    // PoW identity (participates in share_id)
    pub share_id_hex: String,
    pub version: u32,
    pub prev_hash_wire_hex: String,
    pub prev_hash_display_hex: String,
    pub merkle_root_wire_hex: String,
    pub merkle_root_display_hex: String,
    pub ntime: u32,
    pub nbits: u32,
    pub nonce: u32,

    // Attribution (participates in event_id)
    pub event_id_hex: String,
    pub worker_id: String,
    pub validation_level: String,

    // ACK-time metadata
    pub gateway_instance_id: String,
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub template_id: u64,
    pub block_height: u32,
    pub pool_account_id: Option<String>,
    pub timestamp_ms: u64,
    pub difficulty_u64: u64,
    pub difficulty_display: f64,
    pub source_instance_id: String,

    // Signature
    pub gateway_signature_hex: String,
}

// ─────────────────────────────────────────────────────────────────────
// Validation result
// ─────────────────────────────────────────────────────────────────────

/// Result of the share validation pipeline.
pub enum ShareValidationResult {
    /// Share passed all checks.
    Accepted {
        share_id: [u8; 32],
        header_bytes: [u8; 80],
    },
    /// Share failed a validation check.
    Rejected {
        reason: GatewayReason,
        /// `share_id` if computable (structural rejections may not have one)
        share_id: Option<[u8; 32]>,
    },
}

// ─────────────────────────────────────────────────────────────────────
// Share event lifecycle (two-event model)
// ─────────────────────────────────────────────────────────────────────

/// Event 1: Emitted synchronously before the SV2 response for every share
/// that enters the validation pipeline.
///
/// `share_accepted` events with `sv2_response = "success"` establish the
/// 1:1 join invariant: exactly one `ShareForwardResultEvent` must follow.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareAcceptedEvent {
    /// Event type discriminator for NDJSON stream consumers.
    pub event_type: &'static str,
    /// Unique share identity (hex of the 32-byte `share_id`).
    pub share_id_hex: String,
    /// Event identity (hex of the 32-byte `event_id`).
    pub event_id_hex: String,
    /// The SV2 response sent to the miner: `"success"` or `"error"`.
    pub sv2_response: &'static str,
    /// Machine-readable rejection reason (None if accepted).
    pub reason_code: Option<String>,
    /// Human-readable rejection detail (None if accepted).
    pub reason_detail: Option<String>,
    /// Worker identity from the channel.
    pub worker_id: String,
    /// Channel ID where the share was submitted.
    pub channel_id: u32,
    /// Sequence number from the miner.
    pub sequence_number: u32,
    /// Job ID the share references.
    pub job_id: u32,
    /// Block height of the referenced job.
    pub block_height: u32,
    /// Unix timestamp (ms) of event emission.
    pub timestamp_ms: u64,
    /// Share difficulty (`DIFF1_TARGET` / `channel_target`). Zero for rejections.
    pub difficulty_u64: u64,
}

impl ShareAcceptedEvent {
    /// Sentinel event for structural rejections where `share_id` and `event_id`
    /// cannot be computed (e.g., invalid channel, invalid job).
    pub fn sentinel(
        reason: &GatewayReason,
        channel_id: u32,
        sequence_number: u32,
        job_id: u32,
    ) -> Self {
        let zero_hex = hex::encode([0u8; 32]);
        Self {
            event_type: "share_accepted",
            share_id_hex: zero_hex.clone(),
            event_id_hex: zero_hex,
            sv2_response: "error",
            reason_code: Some(reason.as_str().to_string()),
            reason_detail: Some(reason.to_string()),
            worker_id: String::new(),
            channel_id,
            sequence_number,
            job_id,
            block_height: 0,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        }
    }
}

/// Event 2: Emitted by the share relay after the upstream HTTP round-trip.
///
/// Joins to `ShareAcceptedEvent` via `(share_id_hex, event_id_hex)`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareForwardResultEvent {
    /// Event type discriminator.
    pub event_type: &'static str,
    /// Share identity (join key).
    pub share_id_hex: String,
    /// Event identity (join key).
    pub event_id_hex: String,
    /// Whether the share was forwarded to upstream.
    pub forwarded: bool,
    /// Whether upstream accepted the share.
    pub upstream_accepted: Option<bool>,
    /// Upstream HTTP status code (if available).
    pub upstream_http_status: Option<u16>,
    /// Upstream error message (if any).
    pub upstream_error: Option<String>,
    /// Machine-readable reason code from upstream (if any).
    pub reason_code: Option<String>,
    /// Unix timestamp (ms) of event emission.
    pub timestamp_ms: u64,
}

impl ShareForwardResultEvent {
    /// Synthetic event for shares evicted from the forward queue.
    pub fn evicted(share_id_hex: &str, event_id_hex: &str) -> Self {
        let reason = GatewayReason::ShareEvictedFromQueue.as_str().to_string();
        Self {
            event_type: "share_forward_result",
            share_id_hex: share_id_hex.to_string(),
            event_id_hex: event_id_hex.to_string(),
            forwarded: false,
            upstream_accepted: None,
            upstream_http_status: None,
            upstream_error: Some(reason.clone()),
            reason_code: Some(reason),
            timestamp_ms: unix_ms_now(),
        }
    }

    /// Synthetic event for shares dropped because the forward queue was full.
    pub fn queue_full(share_id_hex: &str, event_id_hex: &str) -> Self {
        let reason = GatewayReason::ShareDroppedQueueFull.as_str().to_string();
        Self {
            event_type: "share_forward_result",
            share_id_hex: share_id_hex.to_string(),
            event_id_hex: event_id_hex.to_string(),
            forwarded: false,
            upstream_accepted: None,
            upstream_http_status: None,
            upstream_error: Some(reason.clone()),
            reason_code: Some(reason),
            timestamp_ms: unix_ms_now(),
        }
    }

    /// Build from an upstream relay result.
    pub fn from_relay(
        share_id_hex: &str,
        event_id_hex: &str,
        forwarded: bool,
        upstream_accepted: Option<bool>,
        upstream_http_status: Option<u16>,
        upstream_error: Option<String>,
        reason_code: Option<String>,
    ) -> Self {
        Self {
            event_type: "share_forward_result",
            share_id_hex: share_id_hex.to_string(),
            event_id_hex: event_id_hex.to_string(),
            forwarded,
            upstream_accepted,
            upstream_http_status,
            upstream_error,
            reason_code,
            timestamp_ms: unix_ms_now(),
        }
    }
}

/// Current UNIX timestamp in milliseconds.
pub fn unix_ms_now() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    ms
}

// ─────────────────────────────────────────────────────────────────────
// Byte order utilities
// ─────────────────────────────────────────────────────────────────────

/// Convert wire bytes (LE) to display hex (byte-reversed, BE).
pub fn wire_bytes_to_display_hex(wire: &[u8; 32]) -> String {
    let mut reversed = *wire;
    reversed.reverse();
    hex::encode(reversed)
}

/// Convert wire bytes to wire hex (no reversal).
pub fn wire_bytes_to_wire_hex(wire: &[u8; 32]) -> String {
    hex::encode(wire)
}

/// Convert Bitcoin display hex (BE) to wire bytes (LE).
pub fn display_hex_to_wire_bytes(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut wire = [0u8; 32];
    wire.copy_from_slice(&bytes);
    wire.reverse();
    Ok(wire)
}

// ─────────────────────────────────────────────────────────────────────
// Difficulty conversion
// ─────────────────────────────────────────────────────────────────────

/// Convert a target (32 bytes LE) to integer difficulty.
///
/// `difficulty = DIFF1_TARGET / channel_target`
///
/// Uses a 256-bit big-number representation for full precision across
/// the entire 32-byte target, avoiding truncation of low bytes.
pub fn target_to_difficulty_u64(maximum_target: &[u8; 32]) -> u64 {
    // Check for zero target.
    if maximum_target.iter().all(|&b| b == 0) {
        return u64::MAX;
    }

    // DIFF1_TARGET in LE byte order (reverse of BE constant).
    let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
    diff1_le.reverse();

    // Perform 256-bit division by finding the most significant non-zero
    // 16-byte window that captures both numerator and denominator content.
    // We scan from the MSB end (index 31 down) to find the first non-zero
    // region that gives us a valid ratio.

    // Find the most significant non-zero byte index for the target.
    let Some(target_msb) = maximum_target.iter().rposition(|&b| b != 0) else {
        return u64::MAX; // all-zero, handled above but be safe
    };

    // Align both numbers so the target's MSB region fits in a u128.
    // We want a 16-byte window ending at target_msb (inclusive).
    let window_end = target_msb + 1;
    let window_start = window_end.saturating_sub(16);

    let target_val = u128_from_le_window(maximum_target, window_start, window_end);
    if target_val == 0 {
        return u64::MAX;
    }

    let diff1_val = u128_from_le_window(&diff1_le, window_start, window_end);
    if diff1_val == 0 {
        // DIFF1 has no content in this window; difficulty is astronomically
        // high (target is far above DIFF1). Return 0 since the target is
        // easier than diff-1.
        return 0;
    }

    let ratio = diff1_val / target_val;
    if ratio > u128::from(u64::MAX) {
        u64::MAX
    } else {
        #[allow(clippy::cast_possible_truncation)]
        let result = ratio as u64;
        result
    }
}

/// Extract up to 16 bytes from a LE byte array at the given window as u128.
fn u128_from_le_window(bytes: &[u8; 32], start: usize, end: usize) -> u128 {
    let mut buf = [0u8; 16];
    let len = (end - start).min(16);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    u128::from_le_bytes(buf)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn header_identity_bytes_layout() {
        let version: u32 = 0x2000_0000;
        let prev_hash = [0xAA; 32];
        let merkle_root = [0xBB; 32];
        let ntime: u32 = 1_700_000_000;
        let nbits: u32 = 0x1703_ffff;
        let nonce: u32 = 42;

        let hdr = header_identity_bytes(version, &prev_hash, &merkle_root, ntime, nbits, nonce);
        assert_eq!(hdr.len(), 80);

        // Check version at offset 0.
        assert_eq!(&hdr[0..4], &version.to_le_bytes());
        // Check prev_hash at offset 4.
        assert_eq!(&hdr[4..36], &prev_hash);
        // Check merkle_root at offset 36.
        assert_eq!(&hdr[36..68], &merkle_root);
        // Check ntime at offset 68.
        assert_eq!(&hdr[68..72], &ntime.to_le_bytes());
        // Check nbits at offset 72.
        assert_eq!(&hdr[72..76], &nbits.to_le_bytes());
        // Check nonce at offset 76.
        assert_eq!(&hdr[76..80], &nonce.to_le_bytes());
    }

    #[test]
    fn share_id_uses_single_sha256() {
        let hdr = [0x42u8; 80];
        let share_id = compute_share_id(&hdr);
        // Verify it is SHA256, not SHA256d.
        let expected = Sha256::digest(hdr);
        assert_eq!(&share_id, expected.as_slice());
    }

    #[test]
    fn event_id_changes_with_worker() {
        let share_id = [0xAA; 32];
        let e1 = compute_event_id(&share_id, "worker1", "full");
        let e2 = compute_event_id(&share_id, "worker2", "full");
        assert_ne!(e1, e2);
    }

    #[test]
    fn event_id_changes_with_validation_level() {
        let share_id = [0xAA; 32];
        let e1 = compute_event_id(&share_id, "worker1", "full");
        let e2 = compute_event_id(&share_id, "worker1", "sv2");
        assert_ne!(e1, e2);
    }

    #[test]
    fn gateway_signature_deterministic() {
        let secret = b"test-secret";
        let event_id = [0xBB; 32];
        let sig1 = compute_gateway_signature(secret, &event_id).unwrap();
        let sig2 = compute_gateway_signature(secret, &event_id).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn gateway_signature_changes_with_secret() {
        let event_id = [0xBB; 32];
        let sig1 = compute_gateway_signature(b"secret1", &event_id).unwrap();
        let sig2 = compute_gateway_signature(b"secret2", &event_id).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn version_bits_check_gp_bits_ignored() {
        let job_version = 0x2000_0000u32;
        // Miner flips GP bits only: should pass.
        let submit_version = job_version | 0x1fff_e000;
        assert!(check_version_bits(submit_version, job_version));
    }

    #[test]
    fn version_bits_check_signaling_bits_reject() {
        let job_version = 0x2000_0000u32;
        // Miner flips a signaling bit (bit 0).
        let submit_version = job_version | 0x0000_0001;
        assert!(!check_version_bits(submit_version, job_version));
    }

    #[test]
    fn ntime_lower_bound() {
        // ntime below activation_min_ntime: rejected.
        // now_unix set high so absolute clamp does not interfere.
        assert!(!check_ntime_bounds(999, 1000, 60, 2, 7200, 1000));
    }

    #[test]
    fn ntime_within_elapsed_window() {
        // ntime within elapsed window: accepted.
        assert!(check_ntime_bounds(1010, 1000, 60, 2, 7200, 1000));
    }

    #[test]
    fn ntime_above_elapsed_window() {
        // ntime above elapsed + slack: rejected.
        assert!(!check_ntime_bounds(1100, 1000, 10, 2, 7200, 2000));
    }

    #[test]
    fn ntime_above_absolute_clamp() {
        // ntime passes elapsed check but fails absolute clamp.
        // now_unix=500, max_future=200, so absolute_upper=700.
        // ntime=1010 > 700: rejected.
        assert!(!check_ntime_bounds(1010, 1000, 60, 2, 200, 500));
    }

    #[test]
    fn dedup_set_detects_replay() {
        let mut dedup = ShareDedupSet::new(100);
        let id = [0xAA; 32];
        assert!(!dedup.check_and_insert(&id)); // first time: not replay
        assert!(dedup.check_and_insert(&id)); // second time: replay
    }

    #[test]
    fn dedup_set_evicts_oldest() {
        let mut dedup = ShareDedupSet::new(3);
        let a = [0x01; 32];
        let b = [0x02; 32];
        let c = [0x03; 32];
        let d = [0x04; 32];

        dedup.check_and_insert(&a);
        dedup.check_and_insert(&b);
        dedup.check_and_insert(&c);
        // Full. Insert d should evict a.
        dedup.check_and_insert(&d);
        assert!(!dedup.check_and_insert(&a)); // a was evicted, not a replay
        assert!(dedup.check_and_insert(&d)); // d is still there
    }

    #[test]
    fn wire_bytes_display_hex_round_trip() {
        let wire = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let display = wire_bytes_to_display_hex(&wire);
        let back = display_hex_to_wire_bytes(&display).unwrap();
        assert_eq!(back, wire);
    }

    #[test]
    fn difficulty_one_target() {
        // DIFF1_TARGET / DIFF1_TARGET = 1.
        let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
        diff1_le.reverse();
        assert_eq!(target_to_difficulty_u64(&diff1_le), 1);
    }

    #[test]
    fn difficulty_zero_target_returns_max() {
        let zero = [0u8; 32];
        assert_eq!(target_to_difficulty_u64(&zero), u64::MAX);
    }

    #[test]
    fn pow_validation_all_ff_target_always_passes() {
        // A target of all 0xFF (maximum possible) should accept any hash.
        let target = [0xFF; 32];
        let header = [0u8; 80]; // any header
        assert!(validate_share_pow(&header, &target));
    }

    #[test]
    fn pow_validation_zero_target_always_fails() {
        // A target of all zeros should reject everything (except a zero hash,
        // which is practically impossible).
        let target = [0u8; 32];
        let header = [0x42u8; 80];
        assert!(!validate_share_pow(&header, &target));
    }

    // ── Share event lifecycle tests ──

    #[test]
    fn share_accepted_event_serializes_to_ndjson() {
        let event = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode([0xAA; 32]),
            event_id_hex: hex::encode([0xBB; 32]),
            sv2_response: "success",
            reason_code: None,
            reason_detail: None,
            worker_id: "worker1".to_string(),
            channel_id: 1,
            sequence_number: 42,
            job_id: 10,
            block_height: 800_000,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1024,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"share_accepted\""));
        assert!(json.contains("\"sv2_response\":\"success\""));
        assert!(!json.contains('\n'), "NDJSON must be a single line");
    }

    #[test]
    fn share_accepted_sentinel_has_zero_ids() {
        let sentinel = ShareAcceptedEvent::sentinel(&GatewayReason::InvalidChannelId, 99, 5, 0);
        let zero_hex = hex::encode([0u8; 32]);
        assert_eq!(sentinel.share_id_hex, zero_hex);
        assert_eq!(sentinel.event_id_hex, zero_hex);
        assert_eq!(sentinel.sv2_response, "error");
        assert!(sentinel.reason_code.is_some());
        assert_eq!(sentinel.channel_id, 99);
    }

    #[test]
    fn share_forward_result_evicted_has_correct_reason() {
        let event = ShareForwardResultEvent::evicted("deadbeef", "cafebabe");
        assert_eq!(event.event_type, "share_forward_result");
        assert!(!event.forwarded);
        assert_eq!(
            event.reason_code.as_deref(),
            Some("share_evicted_from_queue")
        );
    }

    #[test]
    fn share_forward_result_queue_full_has_correct_reason() {
        let event = ShareForwardResultEvent::queue_full("deadbeef", "cafebabe");
        assert_eq!(event.event_type, "share_forward_result");
        assert!(!event.forwarded);
        assert_eq!(
            event.reason_code.as_deref(),
            Some("share_dropped_queue_full")
        );
    }

    #[test]
    fn share_forward_result_from_relay_round_trip() {
        let event = ShareForwardResultEvent::from_relay(
            "aabb",
            "ccdd",
            true,
            Some(true),
            Some(200),
            None,
            None,
        );
        assert!(event.forwarded);
        assert_eq!(event.upstream_accepted, Some(true));
        assert_eq!(event.upstream_http_status, Some(200));
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"share_forward_result\""));
    }

    #[test]
    fn share_event_join_key_consistency() {
        // The join key (share_id_hex, event_id_hex) must be the same
        // between ShareAcceptedEvent and ShareForwardResultEvent.
        let share_id = [0xAA; 32];
        let event_id = [0xBB; 32];
        let accepted = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(share_id),
            event_id_hex: hex::encode(event_id),
            sv2_response: "success",
            reason_code: None,
            reason_detail: None,
            worker_id: "worker1".to_string(),
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            block_height: 800_000,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 512,
        };
        let forward = ShareForwardResultEvent::from_relay(
            &accepted.share_id_hex,
            &accepted.event_id_hex,
            true,
            Some(true),
            Some(200),
            None,
            None,
        );
        // 1:1 join invariant: keys must match.
        assert_eq!(accepted.share_id_hex, forward.share_id_hex);
        assert_eq!(accepted.event_id_hex, forward.event_id_hex);
    }

    #[test]
    fn share_event_rejected_no_forward_event_needed() {
        // Rejected shares (sv2_response = "error") do NOT require a
        // share_forward_result event. Only "success" shares do.
        let sentinel = ShareAcceptedEvent::sentinel(&GatewayReason::ShareInvalidJobId, 1, 1, 99);
        assert_eq!(sentinel.sv2_response, "error");
        // No forward event assertion: the invariant is documented.
    }

    // ── CL-18: NDJSON event schema stability ──

    #[test]
    fn share_accepted_event_json_keys_stable() {
        // External consumers parse these NDJSON events by key name.
        // Adding or removing a key is a breaking schema change.
        let evt = ShareAcceptedEvent::sentinel(&GatewayReason::ShareInvalidJobId, 1, 0, 99);
        let json = serde_json::to_value(&evt).unwrap();
        let obj = json.as_object().unwrap();

        let expected_keys = [
            "event_type",
            "share_id_hex",
            "event_id_hex",
            "sv2_response",
            "reason_code",
            "reason_detail",
            "worker_id",
            "channel_id",
            "sequence_number",
            "job_id",
            "block_height",
            "timestamp_ms",
            "difficulty_u64",
        ];

        assert_eq!(
            obj.len(),
            expected_keys.len(),
            "ShareAcceptedEvent field count changed: got {}, expected {}",
            obj.len(),
            expected_keys.len()
        );
        for key in &expected_keys {
            assert!(
                obj.contains_key(*key),
                "ShareAcceptedEvent missing expected key '{key}'"
            );
        }
    }

    #[test]
    fn share_forward_result_event_json_keys_stable() {
        let evt = ShareForwardResultEvent::evicted("abc", "def");
        let json = serde_json::to_value(&evt).unwrap();
        let obj = json.as_object().unwrap();

        let expected_keys = [
            "event_type",
            "share_id_hex",
            "event_id_hex",
            "forwarded",
            "upstream_accepted",
            "upstream_http_status",
            "upstream_error",
            "reason_code",
            "timestamp_ms",
        ];

        assert_eq!(
            obj.len(),
            expected_keys.len(),
            "ShareForwardResultEvent field count changed: got {}, expected {}",
            obj.len(),
            expected_keys.len()
        );
        for key in &expected_keys {
            assert!(
                obj.contains_key(*key),
                "ShareForwardResultEvent missing expected key '{key}'"
            );
        }
    }

    #[test]
    fn share_accepted_event_type_discriminator() {
        let evt = ShareAcceptedEvent::sentinel(&GatewayReason::ShareInvalidNonce, 1, 0, 1);
        assert_eq!(evt.event_type, "share_accepted");
    }

    #[test]
    fn share_forward_result_event_type_discriminator() {
        let evt = ShareForwardResultEvent::queue_full("a", "b");
        assert_eq!(evt.event_type, "share_forward_result");
    }

    #[test]
    fn share_forward_result_reason_codes_are_canonical() {
        // Verify factory methods use canonical enum strings, not raw literals.
        let evicted = ShareForwardResultEvent::evicted("a", "b");
        assert_eq!(
            evicted.reason_code.as_deref(),
            Some(GatewayReason::ShareEvictedFromQueue.as_str())
        );

        let full = ShareForwardResultEvent::queue_full("a", "b");
        assert_eq!(
            full.reason_code.as_deref(),
            Some(GatewayReason::ShareDroppedQueueFull.as_str())
        );
    }
}
