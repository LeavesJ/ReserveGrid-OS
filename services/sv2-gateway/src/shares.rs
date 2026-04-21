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

/// Compute the HMAC-SHA256 gateway signature over `event_id || body_hash`.
///
/// `body_hash` is the SHA-256 of the canonical JSON body (serialized with
/// `gateway_signature_hex` set to the empty string). Including the body hash
/// prevents replay attacks with modified bodies.
///
/// Returns `None` if the HMAC key is rejected (should not happen for SHA256
/// which accepts any key length, but we propagate rather than panic).
pub fn compute_gateway_signature(
    secret: &[u8],
    event_id: &[u8; 32],
    body_hash: &[u8; 32],
) -> Option<[u8; 32]> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(event_id);
    mac.update(body_hash);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    Some(out)
}

/// Sign a [`ShareSubmission`] by computing the body hash and HMAC signature.
///
/// Serializes the submission with an empty `gateway_signature_hex`, hashes the
/// canonical JSON, then computes `HMAC(secret, event_id || body_hash)`. Returns
/// the hex-encoded signature, or an empty string if signing is disabled or fails.
pub fn sign_submission(secret: &[u8], submission: &mut ShareSubmission) {
    if secret.is_empty() {
        return;
    }
    // Ensure signature is empty for canonical serialization.
    submission.gateway_signature_hex = String::new();
    let Ok(canonical_json) = serde_json::to_vec(submission) else {
        return;
    };
    let body_hash: [u8; 32] = Sha256::digest(&canonical_json).into();

    let mut event_id = [0u8; 32];
    if let Ok(decoded) = hex::decode(&submission.event_id_hex)
        && decoded.len() == 32
    {
        event_id.copy_from_slice(&decoded);
    }

    submission.gateway_signature_hex = compute_gateway_signature(secret, &event_id, &body_hash)
        .map(hex::encode)
        .unwrap_or_default();
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

/// Event 3: Emitted when the gateway enters or exits degraded mode.
///
/// Degradation occurs when the verifier heartbeat is lost for longer
/// than the configured threshold. Recovery occurs when a `HeartbeatAck`
/// arrives while degraded. The `unenforced_jobs` field counts how many
/// jobs were broadcast without verdict enforcement during the degraded
/// window (populated only on recovery).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModeTransitionEvent {
    /// Event type discriminator for NDJSON stream consumers.
    pub event_type: &'static str,
    /// Transition direction: `"degraded"` or `"recovered"`.
    pub direction: &'static str,
    /// Unix timestamp (ms) of the transition.
    pub timestamp_ms: u64,
    /// Duration of the degraded window in milliseconds.
    /// Zero on degradation entry; populated on recovery.
    pub degraded_duration_ms: u64,
    /// Number of jobs broadcast without verdict enforcement during the
    /// degraded window. Zero on degradation entry; populated on recovery.
    pub unenforced_jobs: u64,
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
/// Uses 256-bit binary long division for full precision. The result
/// is capped at `u64::MAX`.
pub fn target_to_difficulty_u64(maximum_target: &[u8; 32]) -> u64 {
    if maximum_target.iter().all(|&b| b == 0) {
        return u64::MAX;
    }

    let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
    diff1_le.reverse();

    let n = u256_from_le(&diff1_le);
    let d = u256_from_le(maximum_target);

    // If target > DIFF1, difficulty is 0.
    if u256_gt(&d, &n) {
        return 0;
    }
    if u256_eq(&d, &n) {
        return 1;
    }

    let n_bits = u256_bits(&n);
    let d_bits = u256_bits(&d);
    if d_bits > n_bits {
        return 0;
    }

    let max_shift = n_bits - d_bits;
    if max_shift > 63 {
        return u64::MAX;
    }

    let mut remainder = n;
    let mut quotient: u64 = 0;

    for shift in (0..=max_shift).rev() {
        let shifted_d = u256_shl(&d, shift);
        if u256_gte(&remainder, &shifted_d) {
            remainder = u256_sub(&remainder, &shifted_d);
            quotient |= 1u64 << shift;
        }
    }

    quotient
}

// ── 256-bit arithmetic helpers (lo, hi) representation ──

type U256 = (u128, u128); // (lo, hi)

fn u256_from_le(bytes: &[u8; 32]) -> U256 {
    let mut lo_buf = [0u8; 16];
    let mut hi_buf = [0u8; 16];
    lo_buf.copy_from_slice(&bytes[0..16]);
    hi_buf.copy_from_slice(&bytes[16..32]);
    (u128::from_le_bytes(lo_buf), u128::from_le_bytes(hi_buf))
}

fn u256_bits(v: &U256) -> u32 {
    if v.1 != 0 {
        128 + (128 - v.1.leading_zeros())
    } else if v.0 != 0 {
        128 - v.0.leading_zeros()
    } else {
        0
    }
}

fn u256_shl(v: &U256, shift: u32) -> U256 {
    if shift == 0 {
        return *v;
    }
    if shift >= 256 {
        return (0, 0);
    }
    if shift >= 128 {
        (0, v.0 << (shift - 128))
    } else {
        let lo = v.0 << shift;
        let hi = (v.1 << shift) | (v.0 >> (128 - shift));
        (lo, hi)
    }
}

fn u256_gte(a: &U256, b: &U256) -> bool {
    match a.1.cmp(&b.1) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => a.0 >= b.0,
    }
}

fn u256_gt(a: &U256, b: &U256) -> bool {
    match a.1.cmp(&b.1) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => a.0 > b.0,
    }
}

fn u256_eq(a: &U256, b: &U256) -> bool {
    a.0 == b.0 && a.1 == b.1
}

fn u256_sub(a: &U256, b: &U256) -> U256 {
    let (lo, borrow) = a.0.overflowing_sub(b.0);
    let hi = a.1.wrapping_sub(b.1).wrapping_sub(u128::from(borrow));
    (lo, hi)
}

fn u256_or(a: &U256, b: &U256) -> U256 {
    (a.0 | b.0, a.1 | b.1)
}

/// Convert a difficulty value back to a 32-byte LE target.
///
/// `target = DIFF1_TARGET / difficulty`. Returns `[0xFF; 32]` for
/// difficulty 0 (no difficulty, accept everything).
///
/// Uses 256-bit binary long division for exact results. The divisor
/// (difficulty) is at most u64, so the quotient is a full 256-bit value.
pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty == 0 {
        return [0xFF; 32];
    }

    let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
    diff1_le.reverse();

    let n = u256_from_le(&diff1_le);
    let d = (u128::from(difficulty), 0u128); // U256 with only lo set

    let n_bits = u256_bits(&n);
    let d_bits = u256_bits(&d);
    if d_bits > n_bits {
        return [0u8; 32];
    }

    let max_shift = n_bits - d_bits;

    // The quotient can be up to 256 bits. We accumulate it in a U256.
    let mut remainder = n;
    let mut quotient: U256 = (0, 0);

    for shift in (0..=max_shift).rev() {
        let shifted_d = u256_shl(&d, shift);
        if u256_gte(&remainder, &shifted_d) {
            remainder = u256_sub(&remainder, &shifted_d);
            // Set bit `shift` in quotient.
            let bit = u256_shl(&(1, 0), shift);
            quotient = u256_or(&quotient, &bit);
        }
    }

    let mut target = [0u8; 32];
    target[0..16].copy_from_slice(&quotient.0.to_le_bytes());
    target[16..32].copy_from_slice(&quotient.1.to_le_bytes());
    target
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
        let body_hash = [0xCC; 32];
        let sig1 = compute_gateway_signature(secret, &event_id, &body_hash).unwrap();
        let sig2 = compute_gateway_signature(secret, &event_id, &body_hash).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn gateway_signature_changes_with_secret() {
        let event_id = [0xBB; 32];
        let body_hash = [0xCC; 32];
        let sig1 = compute_gateway_signature(b"secret1", &event_id, &body_hash).unwrap();
        let sig2 = compute_gateway_signature(b"secret2", &event_id, &body_hash).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn gateway_signature_changes_with_body_hash() {
        let secret = b"test-secret";
        let event_id = [0xBB; 32];
        let hash1 = [0xCC; 32];
        let hash2 = [0xDD; 32];
        let sig1 = compute_gateway_signature(secret, &event_id, &hash1).unwrap();
        let sig2 = compute_gateway_signature(secret, &event_id, &hash2).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn sign_submission_populates_signature() {
        let mut sub = ShareSubmission {
            share_id_hex: hex::encode([0xAA; 32]),
            version: 0x2000_0000,
            prev_hash_wire_hex: hex::encode([0u8; 32]),
            prev_hash_display_hex: hex::encode([0u8; 32]),
            merkle_root_wire_hex: hex::encode([0u8; 32]),
            merkle_root_display_hex: hex::encode([0u8; 32]),
            ntime: 1_700_000_000,
            nbits: 0x1d00_ffff,
            nonce: 42,
            event_id_hex: hex::encode([0xBB; 32]),
            worker_id: "worker1".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "gw-1".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            template_id: 100,
            block_height: 800_000,
            pool_account_id: None,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "src-1".to_string(),
            gateway_signature_hex: String::new(),
        };
        sign_submission(b"my-secret", &mut sub);
        assert!(!sub.gateway_signature_hex.is_empty());
        assert_eq!(sub.gateway_signature_hex.len(), 64); // 32 bytes hex
    }

    #[test]
    fn sign_submission_empty_secret_leaves_empty_sig() {
        let mut sub = ShareSubmission {
            share_id_hex: hex::encode([0xAA; 32]),
            version: 0x2000_0000,
            prev_hash_wire_hex: hex::encode([0u8; 32]),
            prev_hash_display_hex: hex::encode([0u8; 32]),
            merkle_root_wire_hex: hex::encode([0u8; 32]),
            merkle_root_display_hex: hex::encode([0u8; 32]),
            ntime: 1_700_000_000,
            nbits: 0x1d00_ffff,
            nonce: 42,
            event_id_hex: hex::encode([0xBB; 32]),
            worker_id: "worker1".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "gw-1".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            template_id: 100,
            block_height: 800_000,
            pool_account_id: None,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "src-1".to_string(),
            gateway_signature_hex: String::new(),
        };
        sign_submission(b"", &mut sub);
        assert!(sub.gateway_signature_hex.is_empty());
    }

    #[test]
    fn sign_submission_is_deterministic_and_body_sensitive() {
        let make_sub = || ShareSubmission {
            share_id_hex: hex::encode([0xAA; 32]),
            version: 0x2000_0000,
            prev_hash_wire_hex: hex::encode([0u8; 32]),
            prev_hash_display_hex: hex::encode([0u8; 32]),
            merkle_root_wire_hex: hex::encode([0u8; 32]),
            merkle_root_display_hex: hex::encode([0u8; 32]),
            ntime: 1_700_000_000,
            nbits: 0x1d00_ffff,
            nonce: 42,
            event_id_hex: hex::encode([0xBB; 32]),
            worker_id: "worker1".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "gw-1".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            template_id: 100,
            block_height: 800_000,
            pool_account_id: None,
            timestamp_ms: 1_700_000_000_000,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "src-1".to_string(),
            gateway_signature_hex: String::new(),
        };

        // Same input produces same signature.
        let mut s1 = make_sub();
        let mut s2 = make_sub();
        sign_submission(b"secret", &mut s1);
        sign_submission(b"secret", &mut s2);
        assert_eq!(s1.gateway_signature_hex, s2.gateway_signature_hex);

        // Different body field produces different signature.
        let mut s3 = make_sub();
        s3.nonce = 99;
        sign_submission(b"secret", &mut s3);
        assert_ne!(s1.gateway_signature_hex, s3.gateway_signature_hex);
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

    // ── difficulty_to_target tests ──

    #[test]
    fn difficulty_to_target_zero_returns_all_ff() {
        let target = difficulty_to_target(0);
        assert_eq!(target, [0xFF; 32]);
    }

    #[test]
    fn difficulty_to_target_one_returns_diff1() {
        let target = difficulty_to_target(1);
        let mut diff1_le = rg_protocol::gateway::DIFF1_TARGET_BE;
        diff1_le.reverse();
        assert_eq!(target, diff1_le);
    }

    #[test]
    fn difficulty_to_target_round_trip() {
        // Verify that target_to_difficulty(difficulty_to_target(d)) ≈ d
        // for several values. Integer division may lose precision, so we
        // accept a tolerance of 1.
        for &d in &[1u64, 2, 100, 1000, 65536, 1_000_000, u64::MAX / 2] {
            let target = difficulty_to_target(d);
            let round_tripped = target_to_difficulty_u64(&target);
            let diff = round_tripped.abs_diff(d);
            assert!(
                diff <= 1,
                "round-trip failed for d={d}: got {round_tripped}, diff={diff}",
            );
        }
    }

    #[test]
    fn difficulty_to_target_higher_difficulty_gives_lower_target() {
        let t1 = difficulty_to_target(100);
        let t2 = difficulty_to_target(1000);
        // As a 256-bit LE integer, t2 should be smaller than t1.
        // Compare MSB first.
        let cmp = t1.iter().rev().cmp(t2.iter().rev());
        assert_eq!(cmp, std::cmp::Ordering::Greater);
    }

    // ── ModeTransitionEvent tests ──

    #[test]
    fn mode_transition_event_degraded_key_set() {
        let evt = ModeTransitionEvent {
            event_type: "mode_transition",
            direction: "degraded",
            timestamp_ms: 1_700_000_000_000,
            degraded_duration_ms: 0,
            unenforced_jobs: 2,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        let expected_keys = [
            "event_type",
            "direction",
            "timestamp_ms",
            "degraded_duration_ms",
            "unenforced_jobs",
        ];
        for key in &expected_keys {
            assert!(
                obj.contains_key(*key),
                "ModeTransitionEvent missing expected key '{key}'",
            );
        }
        assert_eq!(obj["event_type"], "mode_transition");
        assert_eq!(obj["direction"], "degraded");
        assert_eq!(obj["degraded_duration_ms"], 0);
        assert_eq!(obj["unenforced_jobs"], 2);
    }

    #[test]
    fn mode_transition_event_recovered_key_set() {
        let evt = ModeTransitionEvent {
            event_type: "mode_transition",
            direction: "recovered",
            timestamp_ms: 1_700_000_010_000,
            degraded_duration_ms: 10_000,
            unenforced_jobs: 5,
        };
        let json = serde_json::to_string(&evt).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj["direction"], "recovered");
        assert_eq!(obj["degraded_duration_ms"], 10_000);
        assert_eq!(obj["unenforced_jobs"], 5);
    }
}
