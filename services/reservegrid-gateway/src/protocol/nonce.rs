//! Replay attack prevention via nonce + timestamp validation.
//!
//! All HMAC-signed requests must include a `timestamp` (Unix epoch seconds)
//! and a `nonce` (random 16-byte hex string). The server enforces:
//! - Reject timestamps outside `request_timestamp_window_secs` of server clock
//! - Reject duplicate nonces within the timestamp window
//!
//! Nonce tracking uses an in-memory bounded cache. Entries expire when they
//! fall outside the timestamp window.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum allowed nonce length in bytes. Prevents memory abuse from
/// oversized nonce strings.
pub const MAX_NONCE_LENGTH: usize = 256;

/// Nonce cache for replay prevention.
///
/// Bounded by `max_entries`. Oldest entries are evicted when the cache is full.
pub struct NonceCache {
    /// Maps nonce string to the timestamp it was seen at.
    entries: HashMap<String, u64>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
    /// Acceptance window in seconds.
    window_secs: u64,
}

/// Result of validating a nonce + timestamp pair.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceResult {
    /// The request is valid and has been recorded.
    Valid,
    /// The timestamp is outside the acceptance window.
    Expired,
    /// The nonce has been seen before within the window.
    Replayed,
}

impl NonceCache {
    /// Create a new nonce cache.
    pub fn new(max_entries: usize, window_secs: u64) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries.min(1024)),
            max_entries,
            window_secs,
        }
    }

    /// Validate a nonce + timestamp pair.
    ///
    /// Returns `NonceResult::Valid` if the request should be accepted,
    /// or an appropriate rejection reason otherwise.
    pub fn validate(&mut self, nonce: &str, request_timestamp: u64) -> NonceResult {
        // Reject oversized nonces to prevent memory abuse.
        if nonce.len() > MAX_NONCE_LENGTH {
            return NonceResult::Expired; // Reuse Expired to avoid adding a new variant
        }

        let now = current_epoch_secs();

        // Check timestamp window
        let diff = now.abs_diff(request_timestamp);

        if diff > self.window_secs {
            return NonceResult::Expired;
        }

        // Evict expired entries
        self.evict_expired(now);

        // Check for replay
        if self.entries.contains_key(nonce) {
            return NonceResult::Replayed;
        }

        // Evict oldest if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        // Record the nonce
        self.entries.insert(nonce.to_string(), request_timestamp);

        NonceResult::Valid
    }

    /// Remove entries older than the window.
    fn evict_expired(&mut self, now: u64) {
        self.entries
            .retain(|_, ts| now.saturating_sub(*ts) <= self.window_secs);
    }

    /// Remove the oldest entry by timestamp.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, ts)| **ts)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_nonce_accepted() {
        let mut cache = NonceCache::new(100, 30);
        let now = current_epoch_secs();
        assert_eq!(cache.validate("abc123", now), NonceResult::Valid);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let mut cache = NonceCache::new(100, 30);
        let now = current_epoch_secs();
        assert_eq!(cache.validate("abc123", now), NonceResult::Valid);
        assert_eq!(cache.validate("abc123", now), NonceResult::Replayed);
    }

    #[test]
    fn expired_timestamp_rejected() {
        let mut cache = NonceCache::new(100, 30);
        let old = current_epoch_secs() - 60;
        assert_eq!(cache.validate("abc123", old), NonceResult::Expired);
        assert!(cache.is_empty());
    }

    #[test]
    fn future_timestamp_outside_window_rejected() {
        let mut cache = NonceCache::new(100, 30);
        let future = current_epoch_secs() + 60;
        assert_eq!(cache.validate("abc123", future), NonceResult::Expired);
    }

    #[test]
    fn oversized_nonce_rejected() {
        let mut cache = NonceCache::new(100, 30);
        let now = current_epoch_secs();
        let big_nonce = "x".repeat(MAX_NONCE_LENGTH + 1);
        assert_eq!(cache.validate(&big_nonce, now), NonceResult::Expired);
        assert!(cache.is_empty(), "oversized nonce must not be stored");
    }

    #[test]
    fn capacity_evicts_oldest() {
        let mut cache = NonceCache::new(2, 300);
        let now = current_epoch_secs();
        assert_eq!(cache.validate("first", now - 10), NonceResult::Valid);
        assert_eq!(cache.validate("second", now - 5), NonceResult::Valid);
        assert_eq!(cache.len(), 2);

        // Third entry should evict "first" (oldest)
        assert_eq!(cache.validate("third", now), NonceResult::Valid);
        assert_eq!(cache.len(), 2);

        // "first" was evicted, so it should be accepted again
        assert_eq!(cache.validate("first", now), NonceResult::Valid);
    }
}
