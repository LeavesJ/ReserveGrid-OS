//! Standard mining channel management.
//!
//! Each SV2 TCP connection may open up to `max_channels_per_conn` standard
//! mining channels. Extended channels are rejected with
//! `GatewayReason::ExtendedChannelUnsupported`.
//!
//! Channel state tracks the per-channel extranonce prefix, current job pointer,
//! difficulty target, and ntime tracking for share validation.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use reservegrid_common::reason::GatewayReason;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{debug, warn};

// ─────────────────────────────────────────────────────────────────────
// Channel ID allocator
// ─────────────────────────────────────────────────────────────────────

/// Global monotonic channel ID allocator. Channel IDs are unique across
/// the gateway process lifetime. Resets on restart.
pub struct ChannelIdAllocator {
    next: AtomicU32,
    exhausted: std::sync::atomic::AtomicBool,
}

impl ChannelIdAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicU32::new(1), // 0 is reserved for group_channel_id
            exhausted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Allocate the next channel ID. Returns `None` if exhausted.
    /// Once exhausted, all subsequent calls return `None` (no wraparound).
    pub fn allocate(&self) -> Option<u32> {
        if self.exhausted.load(Ordering::Relaxed) {
            return None;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        if id == u32::MAX {
            self.exhausted.store(true, Ordering::Relaxed);
            None
        } else {
            Some(id)
        }
    }
}

impl Default for ChannelIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Extranonce allocator
// ─────────────────────────────────────────────────────────────────────

/// Allocates unique extranonce prefixes per channel.
///
/// The prefix length is configurable (default 4 bytes for standard channels).
/// Each channel gets a unique prefix so that coinbase txids (and therefore
/// merkle roots) differ across channels. The monotonic counter occupies the
/// first 4 bytes; remaining bytes are zero-padded for longer prefixes.
///
/// Extended channels typically request larger extranonce space (8+ bytes)
/// so the miner has room for its own nonce search space after the prefix.
pub struct ExtranonceAllocator {
    next: AtomicU32,
    exhausted: std::sync::atomic::AtomicBool,
    /// Prefix length in bytes. The first 4 bytes contain the counter value;
    /// bytes beyond 4 are zero-filled (reserved for future hierarchical
    /// allocation). Valid range: 2..=8.
    prefix_len: usize,
}

impl ExtranonceAllocator {
    /// Create an allocator that produces 4-byte prefixes (standard channels).
    pub fn new() -> Self {
        Self::with_prefix_len(4)
    }

    /// Create an allocator with a specific prefix length.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_len` is outside the range 2..=8.
    pub fn with_prefix_len(prefix_len: usize) -> Self {
        assert!(
            (2..=8).contains(&prefix_len),
            "extranonce prefix_len must be 2..=8, got {prefix_len}"
        );
        Self {
            next: AtomicU32::new(1),
            exhausted: std::sync::atomic::AtomicBool::new(false),
            prefix_len,
        }
    }

    /// Configured prefix length in bytes.
    pub fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    /// Allocate a variable-length extranonce prefix. Returns `None` if
    /// exhausted. Once exhausted, all subsequent calls return `None`
    /// (no wraparound).
    pub fn allocate(&self) -> Option<Vec<u8>> {
        if self.exhausted.load(Ordering::Relaxed) {
            return None;
        }
        let val = self.next.fetch_add(1, Ordering::Relaxed);
        if val == u32::MAX {
            self.exhausted.store(true, Ordering::Relaxed);
            None
        } else {
            let mut prefix = vec![0u8; self.prefix_len];
            let counter_bytes = val.to_le_bytes();
            let copy_len = self.prefix_len.min(4);
            prefix[..copy_len].copy_from_slice(&counter_bytes[..copy_len]);
            Some(prefix)
        }
    }
}

impl Default for ExtranonceAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Per-channel share rate limiter (token bucket)
// ─────────────────────────────────────────────────────────────────────

/// Token bucket rate limiter for share submissions on a single channel.
///
/// Tokens refill at `rate` tokens per second up to a burst capacity equal
/// to the rate (one second of burst). Each accepted share consumes one
/// token. When the bucket is empty, the share is rejected with
/// `GatewayReason::ShareRateLimited`.
///
/// A rate of 0 means unlimited (no enforcement).
#[derive(Debug)]
pub struct ShareRateLimiter {
    /// Maximum tokens per second. 0 means unlimited.
    rate: u32,
    /// Current token count (fractional to avoid quantization drift).
    tokens: f64,
    /// Last refill instant.
    last_refill: Instant,
}

impl ShareRateLimiter {
    /// Create a new rate limiter with the given shares per second limit.
    /// Pass 0 to disable rate limiting.
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            tokens: f64::from(rate),
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `true` if the share is allowed,
    /// `false` if rate limited.
    pub fn try_acquire(&mut self) -> bool {
        if self.rate == 0 {
            return true;
        }
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    ///
    /// Both `as_secs_f64()` and `f64::from(u32)` produce finite values,
    /// so `added` cannot be NaN or Inf. The `.min(cap)` clamp ensures
    /// the bucket never exceeds burst capacity even after a long pause.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let cap = f64::from(self.rate);
        let added = (elapsed.as_secs_f64() * cap).min(cap);
        self.tokens = (self.tokens + added).min(cap);
        self.last_refill = now;
    }
}

// ─────────────────────────────────────────────────────────────────────
// Channel kind (standard vs extended)
// ─────────────────────────────────────────────────────────────────────

/// Distinguishes standard and extended mining channels.
///
/// Standard channels receive pool-constructed coinbases with a fixed
/// extranonce prefix. Extended channels allow miner-controlled coinbase
/// construction with a larger, variable extranonce space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelKind {
    /// Pool assigns coinbase; miner receives `NewMiningJob`.
    Standard,
    /// Miner constructs coinbase; receives `NewExtendedMiningJob`.
    Extended {
        /// Minimum extranonce size the miner requested at channel open.
        min_extranonce_size: u16,
        /// Actual extranonce size granted by the gateway (prefix + miner
        /// portion). The first `prefix_len` bytes are the gateway-assigned
        /// prefix; the remainder is the miner's nonce search space.
        extranonce_size: u16,
    },
}

impl ChannelKind {
    /// Returns `true` for extended channels.
    pub fn is_extended(&self) -> bool {
        matches!(self, Self::Extended { .. })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Variable difficulty (vardiff) state
// ─────────────────────────────────────────────────────────────────────

/// Per-channel vardiff tracking. When enabled, the gateway adjusts the
/// channel's share target to maintain a stable shares-per-minute rate.
///
/// After each accepted share, `shares_since_retarget` is incremented. When
/// `retarget_start.elapsed() >= retarget_interval`, the gateway computes:
///
///   `observed_rate = shares_since_retarget / elapsed_secs * 60`
///   `ratio = observed_rate / target_shares_per_min`
///   `new_diff = current_difficulty * ratio`, clamped to `[min, max]` and
///   bounded by `max_adjustment_factor`.
///
/// On retarget, a `SetTarget` message is sent and `maximum_target` is updated.
#[derive(Debug)]
pub struct VardiffState {
    /// Shares accepted since the last retarget (or channel open).
    pub shares_since_retarget: u64,
    /// Monotonic instant when the current retarget window started.
    pub retarget_start: Instant,
    /// Current difficulty (DIFF1 / target). Updated on each retarget.
    pub current_difficulty: u64,
    /// Target shares per minute. From config.
    pub target_shares_per_min: f64,
    /// Retarget evaluation interval.
    pub retarget_interval: Duration,
    /// Minimum allowed difficulty.
    pub min_difficulty: u64,
    /// Maximum allowed difficulty.
    pub max_difficulty: u64,
    /// Maximum multiplicative adjustment factor per retarget (e.g., 4.0
    /// means difficulty can at most quadruple or quarter in one step).
    pub max_adjustment_factor: f64,
}

impl VardiffState {
    /// Create a new vardiff state from config and initial difficulty.
    pub fn new(
        initial_difficulty: u64,
        target_shares_per_min: f64,
        retarget_interval: Duration,
        min_difficulty: u64,
        max_difficulty: u64,
        max_adjustment_factor: f64,
    ) -> Self {
        Self {
            shares_since_retarget: 0,
            retarget_start: Instant::now(),
            current_difficulty: initial_difficulty,
            target_shares_per_min,
            retarget_interval,
            min_difficulty,
            max_difficulty,
            max_adjustment_factor,
        }
    }

    /// Record an accepted share. Returns `true` if the retarget interval
    /// has elapsed and a retarget evaluation should occur.
    pub fn record_share(&mut self) -> bool {
        self.shares_since_retarget += 1;
        self.retarget_start.elapsed() >= self.retarget_interval
    }

    /// Evaluate retarget and return the new difficulty if it changed.
    /// Resets the window regardless of whether difficulty changed.
    ///
    /// Returns `Some(new_difficulty)` when the difficulty should be updated,
    /// `None` when no change is warranted (ratio close to 1.0).
    pub fn evaluate_retarget(&mut self) -> Option<u64> {
        let elapsed = self.retarget_start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();
        if elapsed_secs < 1.0 {
            // Interval too short for a meaningful measurement; reset and skip.
            self.shares_since_retarget = 0;
            self.retarget_start = Instant::now();
            return None;
        }

        #[allow(clippy::cast_precision_loss)] // u64→f64 acceptable for rate estimation
        let observed_rate = (self.shares_since_retarget as f64) / elapsed_secs * 60.0;
        let ratio = if self.target_shares_per_min > 0.0 {
            observed_rate / self.target_shares_per_min
        } else {
            1.0
        };

        // Clamp ratio to max_adjustment_factor.
        let clamped_ratio = ratio
            .max(1.0 / self.max_adjustment_factor)
            .min(self.max_adjustment_factor);

        // No change if ratio is within 5% of 1.0.
        if (clamped_ratio - 1.0).abs() < 0.05 {
            self.shares_since_retarget = 0;
            self.retarget_start = Instant::now();
            return None;
        }

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let raw_new = (self.current_difficulty as f64 * clamped_ratio) as u64;
        let new_diff = raw_new.max(self.min_difficulty).min(self.max_difficulty);

        if new_diff == self.current_difficulty {
            self.shares_since_retarget = 0;
            self.retarget_start = Instant::now();
            return None;
        }

        self.current_difficulty = new_diff;
        self.shares_since_retarget = 0;
        self.retarget_start = Instant::now();
        Some(new_diff)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Per-channel state
// ─────────────────────────────────────────────────────────────────────

/// State for a single mining channel (standard or extended).
#[derive(Debug)]
pub struct ChannelState {
    /// Unique channel ID assigned at channel open.
    pub channel_id: u32,

    /// The extranonce prefix assigned to this channel. Variable length:
    /// 4 bytes for standard channels, configurable for extended.
    pub extranonce_prefix: Vec<u8>,

    /// Whether this is a standard or extended channel.
    pub kind: ChannelKind,

    /// Worker identity from `OpenStandardMiningChannel.user_identity`
    /// or `OpenExtendedMiningChannel.user_identity`.
    pub worker_id: String,

    /// Pool account ID resolved from miner auth (if `prefix_map` mode).
    pub pool_account_id: Option<String>,

    /// The channel's share acceptance target (from `SetTarget`).
    /// V1.0.0 uses static difficulty: set once at channel open.
    pub maximum_target: [u8; 32],

    /// The `job_id` of the currently active job for this channel.
    /// Updated on `SetNewPrevHash` or immediately active `NewMiningJob`
    /// / `NewExtendedMiningJob`.
    pub current_job_id: Option<u32>,

    /// Monotonic timestamp (ms) when the last `SetNewPrevHash` was written
    /// to this channel's TCP send buffer. Used for ntime elapsed-time bound.
    pub prevhash_sent_monotonic_ms: Option<u64>,

    /// The `activation_min_ntime` from the last `SetNewPrevHash` sent
    /// on this channel.
    pub activation_min_ntime: Option<u32>,

    /// Group channel ID (always 0 for V1.0.0 single-group).
    pub group_channel_id: u32,

    /// Wall-clock instant the channel was opened.
    pub opened_at: Instant,

    /// Whether the channel is closed (pending cleanup).
    pub closed: bool,

    /// Per-channel share submission rate limiter.
    pub rate_limiter: ShareRateLimiter,

    /// Per-channel variable difficulty state. `None` when vardiff is disabled.
    pub vardiff: Option<VardiffState>,
}

impl ChannelState {
    /// Create a new standard channel at open time.
    pub fn new(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        worker_id: String,
        pool_account_id: Option<String>,
        maximum_target: [u8; 32],
        max_shares_per_second: u32,
    ) -> Self {
        Self {
            channel_id,
            extranonce_prefix,
            kind: ChannelKind::Standard,
            worker_id,
            pool_account_id,
            maximum_target,
            current_job_id: None,
            prevhash_sent_monotonic_ms: None,
            activation_min_ntime: None,
            group_channel_id: 0,
            opened_at: Instant::now(),
            closed: false,
            rate_limiter: ShareRateLimiter::new(max_shares_per_second),
            vardiff: None,
        }
    }

    /// Create a new extended channel at open time.
    #[allow(clippy::too_many_arguments)]
    pub fn new_extended(
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        worker_id: String,
        pool_account_id: Option<String>,
        maximum_target: [u8; 32],
        max_shares_per_second: u32,
        min_extranonce_size: u16,
        extranonce_size: u16,
    ) -> Self {
        Self {
            channel_id,
            extranonce_prefix,
            kind: ChannelKind::Extended {
                min_extranonce_size,
                extranonce_size,
            },
            worker_id,
            pool_account_id,
            maximum_target,
            current_job_id: None,
            prevhash_sent_monotonic_ms: None,
            activation_min_ntime: None,
            group_channel_id: 0,
            opened_at: Instant::now(),
            closed: false,
            rate_limiter: ShareRateLimiter::new(max_shares_per_second),
            vardiff: None,
        }
    }

    /// Record that a `SetNewPrevHash` was sent on this channel.
    pub fn record_prevhash_sent(&mut self, job_id: u32, activation_min_ntime: u32) {
        self.current_job_id = Some(job_id);
        self.activation_min_ntime = Some(activation_min_ntime);
        // Use monotonic clock for elapsed-time ntime bound.
        self.prevhash_sent_monotonic_ms = Some(monotonic_ms());
    }

    /// Record that an immediately active `NewMiningJob` (same prevhash)
    /// was sent on this channel. Updates `current_job_id` but not the
    /// prevhash tracking (prevhash did not change).
    pub fn record_active_job_sent(&mut self, job_id: u32) {
        self.current_job_id = Some(job_id);
    }

    /// Compute elapsed seconds since prevhash was sent on this channel.
    /// Returns `None` if no prevhash has been sent yet.
    pub fn elapsed_since_prevhash_secs(&self) -> Option<u32> {
        self.prevhash_sent_monotonic_ms.map(|sent_ms| {
            let now_ms = monotonic_ms();
            let elapsed_ms = now_ms.saturating_sub(sent_ms);
            #[allow(clippy::cast_possible_truncation)]
            let secs = (elapsed_ms / 1000) as u32;
            secs
        })
    }
}

/// Monotonic milliseconds since an arbitrary epoch (process start).
/// Uses `Instant::now()` relative to a lazily initialized baseline.
fn monotonic_ms() -> u64 {
    use std::sync::OnceLock;
    static BASELINE: OnceLock<Instant> = OnceLock::new();
    let baseline = BASELINE.get_or_init(Instant::now);
    #[allow(clippy::cast_possible_truncation)]
    let ms = baseline.elapsed().as_millis() as u64;
    ms
}

// ─────────────────────────────────────────────────────────────────────
// Channel manager (per-connection)
// ─────────────────────────────────────────────────────────────────────

/// Manages channels for a single TCP connection.
pub struct ConnectionChannels {
    /// Active channels keyed by `channel_id`.
    channels: HashMap<u32, ChannelState>,
    /// Maximum channels allowed on this connection.
    max_channels: u32,
}

impl ConnectionChannels {
    pub fn new(max_channels: u32) -> Self {
        Self {
            channels: HashMap::new(),
            max_channels,
        }
    }

    /// Open a new standard mining channel.
    ///
    /// Returns the new `ChannelState` reference on success, or a
    /// `GatewayReason` explaining why the open was rejected.
    pub fn open_channel(
        &mut self,
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        worker_id: String,
        pool_account_id: Option<String>,
        maximum_target: [u8; 32],
        max_shares_per_second: u32,
    ) -> Result<&ChannelState, GatewayReason> {
        if self.channels.len() >= self.max_channels as usize {
            warn!(
                channel_count = self.channels.len(),
                max = self.max_channels,
                "channel limit exceeded"
            );
            return Err(GatewayReason::ChannelLimitExceeded);
        }

        let state = ChannelState::new(
            channel_id,
            extranonce_prefix,
            worker_id,
            pool_account_id,
            maximum_target,
            max_shares_per_second,
        );

        debug!(channel_id, worker_id = %state.worker_id, "channel opened");
        let entry = self.channels.entry(channel_id).or_insert(state);
        Ok(entry)
    }

    /// Open a new extended mining channel.
    ///
    /// Returns the new `ChannelState` reference on success, or a
    /// `GatewayReason` explaining why the open was rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn open_extended_channel(
        &mut self,
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
        worker_id: String,
        pool_account_id: Option<String>,
        maximum_target: [u8; 32],
        max_shares_per_second: u32,
        min_extranonce_size: u16,
        extranonce_size: u16,
    ) -> Result<&ChannelState, GatewayReason> {
        if self.channels.len() >= self.max_channels as usize {
            warn!(
                channel_count = self.channels.len(),
                max = self.max_channels,
                "channel limit exceeded"
            );
            return Err(GatewayReason::ChannelLimitExceeded);
        }

        let state = ChannelState::new_extended(
            channel_id,
            extranonce_prefix,
            worker_id,
            pool_account_id,
            maximum_target,
            max_shares_per_second,
            min_extranonce_size,
            extranonce_size,
        );

        debug!(
            channel_id,
            worker_id = %state.worker_id,
            "extended mining channel opened",
        );
        let entry = self.channels.entry(channel_id).or_insert(state);
        Ok(entry)
    }

    /// Look up a channel by ID. Returns `None` if not found or closed.
    pub fn get(&self, channel_id: u32) -> Option<&ChannelState> {
        self.channels.get(&channel_id).filter(|c| !c.closed)
    }

    /// Mutable lookup for updating channel state.
    pub fn get_mut(&mut self, channel_id: u32) -> Option<&mut ChannelState> {
        self.channels.get_mut(&channel_id).filter(|c| !c.closed)
    }

    /// Close a channel. Marks it as closed rather than removing immediately
    /// to allow pending share responses to reference the channel state.
    pub fn close_channel(&mut self, channel_id: u32) -> bool {
        if let Some(ch) = self.channels.get_mut(&channel_id)
            && !ch.closed
        {
            ch.closed = true;
            debug!(channel_id, "channel closed");
            return true;
        }
        false
    }

    /// Iterate over all open (non-closed) channels.
    pub fn iter_open(&self) -> impl Iterator<Item = &ChannelState> {
        self.channels.values().filter(|c| !c.closed)
    }

    /// Mutable iterator over all open channels.
    pub fn iter_open_mut(&mut self) -> impl Iterator<Item = &mut ChannelState> {
        self.channels.values_mut().filter(|c| !c.closed)
    }

    /// Number of open channels.
    pub fn open_count(&self) -> usize {
        self.channels.values().filter(|c| !c.closed).count()
    }

    /// Remove all closed channels (housekeeping).
    pub fn gc_closed(&mut self) {
        self.channels.retain(|_, c| !c.closed);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Hashrate estimation (sliding window difficulty accumulator)
// ─────────────────────────────────────────────────────────────────────

/// Sliding window accumulator for hashrate estimation.
///
/// Stores `(timestamp_ms, difficulty)` tuples in a ring buffer and evicts
/// entries older than `window_ms`. The hashrate formula is:
///
///   `H/s = sum_of_difficulties * 2^32 / elapsed_seconds`
///
/// Returned as TH/s (divide by 1e12).
#[derive(Debug, Clone)]
pub struct HashrateWindow {
    /// Ring buffer of (`unix_ms`, `difficulty_u64`) for accepted shares.
    samples: VecDeque<(u64, u64)>,
    /// Window duration in milliseconds.
    window_ms: u64,
}

impl HashrateWindow {
    pub fn new(window_ms: u64) -> Self {
        Self {
            samples: VecDeque::new(),
            window_ms,
        }
    }

    /// Record an accepted share and return the updated hashrate in TH/s.
    pub fn record(&mut self, now_ms: u64, difficulty: u64) -> f64 {
        self.samples.push_back((now_ms, difficulty));
        self.evict(now_ms);
        self.compute(now_ms)
    }

    /// Recompute hashrate without adding a sample (for periodic refresh).
    #[allow(dead_code)]
    pub fn current(&mut self, now_ms: u64) -> f64 {
        self.evict(now_ms);
        self.compute(now_ms)
    }

    fn evict(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(&(ts, _)) = self.samples.front() {
            if ts < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn compute(&self, now_ms: u64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let sum_diff: u128 = self.samples.iter().map(|&(_, d)| u128::from(d)).sum();
        // Use elapsed span from the oldest sample to now, clamped to at
        // least 1 second to avoid division spikes on the first share.
        let oldest_ts = self.samples.front().map_or(now_ms, |&(ts, _)| ts);
        let elapsed_ms = now_ms.saturating_sub(oldest_ts).max(1000);
        #[allow(clippy::cast_precision_loss)] // u64 → f64 acceptable for timing
        let elapsed_secs = elapsed_ms as f64 / 1000.0;
        // H/s = sum_diff * 2^32 / elapsed_secs
        // TH/s = H/s / 1e12
        #[allow(clippy::cast_precision_loss)] // u128 → f64 acceptable for hashrate estimate
        let hashrate_hs = (sum_diff as f64) * 4_294_967_296.0 / elapsed_secs;
        hashrate_hs / 1e12
    }
}

// ─────────────────────────────────────────────────────────────────────
// Global channel registry (cross-connection, for HTTP /channels API)
// ─────────────────────────────────────────────────────────────────────

/// Point-in-time snapshot of a single mining channel, serializable for
/// the HTTP `/channels` endpoint consumed by the dashboard `MinersPage`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelSnapshot {
    pub channel_id: u32,
    pub worker_id: String,
    pub peer_addr: String,
    pub opened_at_unix_ms: u64,
    pub shares_submitted: u64,
    pub shares_accepted: u64,
    pub last_share_at_unix_ms: u64,
    /// Estimated hashrate in TH/s from sliding window accumulator.
    pub hashrate_th: f64,
    /// Internal sliding window state (not serialized to JSON).
    #[serde(skip)]
    pub hashrate_window: HashrateWindow,
}

/// Process-wide channel registry shared across all connection handler tasks.
/// Uses `tokio::sync::RwLock` so that the HTTP handler can snapshot without
/// blocking the hot share-validation path for more than a `HashMap` clone.
pub struct GlobalChannelRegistry {
    channels: RwLock<HashMap<u32, ChannelSnapshot>>,
}

pub type SharedChannelRegistry = Arc<GlobalChannelRegistry>;

impl GlobalChannelRegistry {
    pub fn new() -> Self {
        Self {
            channels: RwLock::new(HashMap::new()),
        }
    }

    /// Register a newly opened channel.
    pub async fn register(&self, snap: ChannelSnapshot) {
        let mut map = self.channels.write().await;
        map.insert(snap.channel_id, snap);
    }

    /// Update share counters and hashrate estimate for a channel.
    pub async fn update_share(&self, channel_id: u32, accepted: bool, difficulty: u64) {
        let mut map = self.channels.write().await;
        if let Some(entry) = map.get_mut(&channel_id) {
            entry.shares_submitted += 1;
            let now = unix_ms_now();
            if accepted {
                entry.shares_accepted += 1;
                entry.hashrate_th = entry.hashrate_window.record(now, difficulty);
            }
            entry.last_share_at_unix_ms = now;
        }
    }

    /// Remove a channel when the connection closes or the channel is closed.
    pub async fn unregister(&self, channel_id: u32) {
        let mut map = self.channels.write().await;
        map.remove(&channel_id);
    }

    /// Clone all snapshots for the HTTP API response.
    pub async fn snapshot_all(&self) -> Vec<ChannelSnapshot> {
        let map = self.channels.read().await;
        map.values().cloned().collect()
    }
}

impl Default for GlobalChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Current wall-clock time as Unix milliseconds.
fn unix_ms_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    #[allow(clippy::cast_possible_truncation)] // millis fits u64 until year 584M
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Helper to create a `ChannelSnapshot` from handler context at channel open.
pub fn snapshot_from_open(
    channel_id: u32,
    worker_id: &str,
    peer_addr: SocketAddr,
) -> ChannelSnapshot {
    ChannelSnapshot {
        channel_id,
        worker_id: worker_id.to_string(),
        peer_addr: peer_addr.to_string(),
        opened_at_unix_ms: unix_ms_now(),
        shares_submitted: 0,
        shares_accepted: 0,
        last_share_at_unix_ms: 0,
        hashrate_th: 0.0,
        hashrate_window: HashrateWindow::new(300_000), // 5-minute window
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn default_target() -> [u8; 32] {
        let mut t = [0u8; 32];
        // Set a reasonable share target (difficulty ~1).
        t[28] = 0xFF;
        t[29] = 0xFF;
        t
    }

    #[test]
    fn channel_id_allocator_monotonic() {
        let alloc = ChannelIdAllocator::new();
        assert_eq!(alloc.allocate(), Some(1));
        assert_eq!(alloc.allocate(), Some(2));
        assert_eq!(alloc.allocate(), Some(3));
    }

    #[test]
    fn extranonce_allocator_unique() {
        let alloc = ExtranonceAllocator::new();
        let a = alloc.allocate().unwrap();
        let b = alloc.allocate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn connection_channels_open_and_get() {
        let mut mgr = ConnectionChannels::new(4);
        let result = mgr.open_channel(
            1,
            vec![0, 0, 0, 1],
            "worker1".to_string(),
            None,
            default_target(),
            0,
        );
        assert!(result.is_ok());
        assert!(mgr.get(1).is_some());
        assert_eq!(mgr.open_count(), 1);
    }

    #[test]
    fn connection_channels_limit_enforced() {
        let mut mgr = ConnectionChannels::new(2);
        mgr.open_channel(1, vec![0, 0, 0, 1], "w1".into(), None, default_target(), 0)
            .unwrap();
        mgr.open_channel(2, vec![0, 0, 0, 2], "w2".into(), None, default_target(), 0)
            .unwrap();
        let err = mgr
            .open_channel(3, vec![0, 0, 0, 3], "w3".into(), None, default_target(), 0)
            .unwrap_err();
        assert_eq!(err, GatewayReason::ChannelLimitExceeded);
    }

    #[test]
    fn connection_channels_close_and_gc() {
        let mut mgr = ConnectionChannels::new(4);
        mgr.open_channel(1, vec![0, 0, 0, 1], "w1".into(), None, default_target(), 0)
            .unwrap();
        mgr.open_channel(2, vec![0, 0, 0, 2], "w2".into(), None, default_target(), 0)
            .unwrap();

        assert!(mgr.close_channel(1));
        assert_eq!(mgr.open_count(), 1);
        assert!(mgr.get(1).is_none()); // closed channels not visible

        mgr.gc_closed();
        assert_eq!(mgr.channels.len(), 1);
    }

    #[test]
    fn channel_state_prevhash_tracking() {
        let mut ch = ChannelState::new(
            1,
            vec![0, 0, 0, 1],
            "miner".into(),
            None,
            default_target(),
            0,
        );
        assert!(ch.current_job_id.is_none());
        assert!(ch.elapsed_since_prevhash_secs().is_none());

        ch.record_prevhash_sent(42, 1_700_000_000);
        assert_eq!(ch.current_job_id, Some(42));
        assert_eq!(ch.activation_min_ntime, Some(1_700_000_000));
        // Elapsed should be very small (just created)
        assert!(ch.elapsed_since_prevhash_secs().unwrap() < 2);
    }

    #[test]
    fn channel_state_active_job_update() {
        let mut ch = ChannelState::new(
            1,
            vec![0, 0, 0, 1],
            "miner".into(),
            None,
            default_target(),
            0,
        );
        ch.record_prevhash_sent(10, 1_700_000_000);
        ch.record_active_job_sent(11);
        assert_eq!(ch.current_job_id, Some(11));
        // prevhash tracking unchanged
        assert_eq!(ch.activation_min_ntime, Some(1_700_000_000));
    }

    #[test]
    fn monotonic_ms_increases() {
        let a = monotonic_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let b = monotonic_ms();
        assert!(b >= a);
    }

    #[test]
    fn close_channel_idempotent() {
        let mut mgr = ConnectionChannels::new(4);
        mgr.open_channel(1, vec![0, 0, 0, 1], "w1".into(), None, default_target(), 0)
            .unwrap();
        assert!(mgr.close_channel(1));
        assert!(!mgr.close_channel(1)); // already closed
    }

    // ── ShareRateLimiter tests ──

    #[test]
    fn rate_limiter_zero_means_unlimited() {
        let mut rl = ShareRateLimiter::new(0);
        for _ in 0..10_000 {
            assert!(rl.try_acquire());
        }
    }

    #[test]
    fn rate_limiter_allows_burst_up_to_rate() {
        let mut rl = ShareRateLimiter::new(5);
        for i in 0..5 {
            assert!(rl.try_acquire(), "burst token {i} should be available");
        }
        // 6th share within the same instant should be rejected.
        assert!(!rl.try_acquire(), "should be rate limited after burst");
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut rl = ShareRateLimiter::new(10);
        // Drain all tokens.
        for _ in 0..10 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire());
        // Simulate passage of time by backdating last_refill.
        rl.last_refill -= std::time::Duration::from_millis(200);
        // 200ms at 10/sec = 2 tokens refilled.
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
    }

    #[test]
    fn rate_limiter_caps_at_burst() {
        let mut rl = ShareRateLimiter::new(5);
        // Backdate by 10 seconds, but tokens should cap at 5 (the rate).
        rl.last_refill -= std::time::Duration::from_secs(10);
        rl.tokens = 0.0;
        rl.refill();
        assert!(
            rl.tokens <= 5.0,
            "tokens should cap at rate, got {}",
            rl.tokens
        );
    }

    #[test]
    fn rate_limiter_one_per_second() {
        let mut rl = ShareRateLimiter::new(1);
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
        // After 1 second, one more token.
        rl.last_refill -= std::time::Duration::from_secs(1);
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire());
    }

    #[test]
    fn channel_state_has_rate_limiter() {
        let ch = ChannelState::new(
            1,
            vec![0, 0, 0, 1],
            "miner".into(),
            None,
            default_target(),
            100,
        );
        // Rate limiter should be initialized with 100 tokens.
        assert_eq!(ch.rate_limiter.rate, 100);
    }

    // ── GlobalChannelRegistry tests ──

    #[tokio::test]
    async fn registry_register_and_snapshot() {
        let reg = GlobalChannelRegistry::new();
        let snap = ChannelSnapshot {
            channel_id: 1,
            worker_id: "w1".into(),
            peer_addr: "127.0.0.1:9999".into(),
            opened_at_unix_ms: 1000,
            shares_submitted: 0,
            shares_accepted: 0,
            last_share_at_unix_ms: 0,
            hashrate_th: 0.0,
            hashrate_window: HashrateWindow::new(300_000),
        };
        reg.register(snap).await;
        let all = reg.snapshot_all().await;
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].channel_id, 1);
    }

    #[tokio::test]
    async fn registry_update_share_counters() {
        let reg = GlobalChannelRegistry::new();
        let snap = ChannelSnapshot {
            channel_id: 5,
            worker_id: "w5".into(),
            peer_addr: "10.0.0.1:3333".into(),
            opened_at_unix_ms: 2000,
            shares_submitted: 0,
            shares_accepted: 0,
            last_share_at_unix_ms: 0,
            hashrate_th: 0.0,
            hashrate_window: HashrateWindow::new(300_000),
        };
        reg.register(snap).await;
        reg.update_share(5, true, 1024).await;
        reg.update_share(5, false, 0).await;
        let all = reg.snapshot_all().await;
        assert_eq!(all[0].shares_submitted, 2);
        assert_eq!(all[0].shares_accepted, 1);
        assert!(
            all[0].hashrate_th > 0.0,
            "hashrate should be nonzero after accepted share"
        );
    }

    #[tokio::test]
    async fn registry_unregister_removes_channel() {
        let reg = GlobalChannelRegistry::new();
        let snap = ChannelSnapshot {
            channel_id: 10,
            worker_id: "w10".into(),
            peer_addr: "10.0.0.2:3333".into(),
            opened_at_unix_ms: 3000,
            shares_submitted: 0,
            shares_accepted: 0,
            last_share_at_unix_ms: 0,
            hashrate_th: 0.0,
            hashrate_window: HashrateWindow::new(300_000),
        };
        reg.register(snap).await;
        reg.unregister(10).await;
        let all = reg.snapshot_all().await;
        assert!(all.is_empty());
    }

    // ── HashrateWindow tests ──

    #[test]
    fn hashrate_window_empty_returns_zero() {
        let mut w = HashrateWindow::new(300_000);
        assert!((w.current(1_000_000) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn hashrate_window_single_share() {
        let mut w = HashrateWindow::new(300_000);
        let now = 1_000_000u64;
        let hr = w.record(now, 1);
        // With one sample the elapsed is clamped to 1s.
        // H/s = 1 * 2^32 / 1 = 4_294_967_296
        // TH/s = 4_294_967_296 / 1e12 ≈ 0.004295
        let expected = 4_294_967_296.0 / 1e12;
        assert!(
            (hr - expected).abs() < 1e-9,
            "expected {expected}, got {hr}"
        );
    }

    #[test]
    fn hashrate_window_accumulation() {
        let mut w = HashrateWindow::new(300_000);
        // Two shares 10 seconds apart, each with difficulty 500.
        w.record(100_000, 500);
        let hr = w.record(110_000, 500);
        // sum_diff = 1000, elapsed = 110_000 - 100_000 = 10_000 ms = 10s
        // H/s = 1000 * 2^32 / 10 = 429_496_729_600
        // TH/s = 429_496_729_600 / 1e12 ≈ 0.4295
        let expected = 1000.0 * 4_294_967_296.0 / 10.0 / 1e12;
        assert!(
            (hr - expected).abs() < 1e-9,
            "expected {expected}, got {hr}"
        );
    }

    #[test]
    fn hashrate_window_eviction() {
        let mut w = HashrateWindow::new(10_000); // 10s window
        // Share at t=0
        w.record(100_000, 1000);
        // Share at t=5s (within window)
        w.record(105_000, 1000);
        // Share at t=15s (first share should be evicted)
        let hr = w.record(115_000, 1000);
        // After eviction: samples at 105_000 and 115_000 with diff 1000 each.
        // sum_diff = 2000, elapsed = 115_000 - 105_000 = 10s
        // H/s = 2000 * 2^32 / 10 = 858_993_459_200
        // TH/s ≈ 0.8590
        let expected = 2000.0 * 4_294_967_296.0 / 10.0 / 1e12;
        assert!(
            (hr - expected).abs() < 1e-9,
            "expected {expected}, got {hr}"
        );
    }

    #[test]
    fn hashrate_window_all_evicted_returns_zero() {
        let mut w = HashrateWindow::new(5_000); // 5s window
        w.record(100_000, 1000);
        // 10s later, sample is outside window
        let hr = w.current(110_000);
        assert!((hr - 0.0).abs() < f64::EPSILON);
    }

    // ── ExtranonceAllocator variable-length tests ──

    #[test]
    fn extranonce_allocator_default_is_4_bytes() {
        let alloc = ExtranonceAllocator::new();
        assert_eq!(alloc.prefix_len(), 4);
        let prefix = alloc.allocate().unwrap();
        assert_eq!(prefix.len(), 4);
        assert_eq!(prefix, vec![1, 0, 0, 0]); // counter=1, LE
    }

    #[test]
    fn extranonce_allocator_2_byte_prefix() {
        let alloc = ExtranonceAllocator::with_prefix_len(2);
        assert_eq!(alloc.prefix_len(), 2);
        let a = alloc.allocate().unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a, vec![1, 0]); // counter=1 truncated to 2 bytes
        let b = alloc.allocate().unwrap();
        assert_eq!(b, vec![2, 0]);
        assert_ne!(a, b);
    }

    #[test]
    fn extranonce_allocator_8_byte_prefix() {
        let alloc = ExtranonceAllocator::with_prefix_len(8);
        assert_eq!(alloc.prefix_len(), 8);
        let prefix = alloc.allocate().unwrap();
        assert_eq!(prefix.len(), 8);
        // First 4 bytes are counter=1 LE, remaining 4 are zero-padded.
        assert_eq!(prefix, vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "extranonce prefix_len must be 2..=8")]
    fn extranonce_allocator_rejects_prefix_len_0() {
        ExtranonceAllocator::with_prefix_len(0);
    }

    #[test]
    #[should_panic(expected = "extranonce prefix_len must be 2..=8")]
    fn extranonce_allocator_rejects_prefix_len_1() {
        ExtranonceAllocator::with_prefix_len(1);
    }

    #[test]
    #[should_panic(expected = "extranonce prefix_len must be 2..=8")]
    fn extranonce_allocator_rejects_prefix_len_9() {
        ExtranonceAllocator::with_prefix_len(9);
    }

    // ── ChannelKind tests ──

    #[test]
    fn channel_kind_standard_not_extended() {
        let kind = ChannelKind::Standard;
        assert!(!kind.is_extended());
    }

    #[test]
    fn channel_kind_extended_is_extended() {
        let kind = ChannelKind::Extended {
            min_extranonce_size: 8,
            extranonce_size: 16,
        };
        assert!(kind.is_extended());
    }

    #[test]
    fn channel_state_new_is_standard() {
        let ch = ChannelState::new(
            1,
            vec![0, 0, 0, 1],
            "miner".into(),
            None,
            default_target(),
            0,
        );
        assert_eq!(ch.kind, ChannelKind::Standard);
        assert!(!ch.kind.is_extended());
    }

    #[test]
    fn channel_state_new_extended() {
        let ch = ChannelState::new_extended(
            1,
            vec![0, 0, 0, 0, 0, 0, 0, 1],
            "ext-miner".into(),
            None,
            default_target(),
            0,
            8,
            16,
        );
        assert!(ch.kind.is_extended());
        assert_eq!(ch.extranonce_prefix.len(), 8);
        match ch.kind {
            ChannelKind::Extended {
                min_extranonce_size,
                extranonce_size,
            } => {
                assert_eq!(min_extranonce_size, 8);
                assert_eq!(extranonce_size, 16);
            }
            ChannelKind::Standard => panic!("expected Extended channel kind"),
        }
    }

    #[test]
    fn open_extended_channel_on_connection() {
        let mut mgr = ConnectionChannels::new(4);
        let result = mgr.open_extended_channel(
            1,
            vec![0, 0, 0, 0, 0, 0, 0, 1],
            "ext-worker".into(),
            None,
            default_target(),
            0,
            8,
            16,
        );
        assert!(result.is_ok());
        let ch = mgr.get(1).unwrap();
        assert!(ch.kind.is_extended());
        assert_eq!(mgr.open_count(), 1);
    }

    #[test]
    fn mixed_standard_and_extended_channels() {
        let mut mgr = ConnectionChannels::new(4);
        mgr.open_channel(1, vec![0, 0, 0, 1], "std".into(), None, default_target(), 0)
            .unwrap();
        mgr.open_extended_channel(
            2,
            vec![0, 0, 0, 0, 0, 0, 0, 2],
            "ext".into(),
            None,
            default_target(),
            0,
            8,
            16,
        )
        .unwrap();
        assert_eq!(mgr.open_count(), 2);
        assert!(!mgr.get(1).unwrap().kind.is_extended());
        assert!(mgr.get(2).unwrap().kind.is_extended());
    }

    // ── Vardiff tests ──

    #[test]
    fn vardiff_state_no_retarget_before_interval() {
        let mut vd = VardiffState::new(1000, 20.0, Duration::from_secs(90), 1, u64::MAX, 4.0);
        // Record shares but interval has not elapsed.
        for _ in 0..100 {
            let should_retarget = vd.record_share();
            if should_retarget {
                // Should not happen within first instant.
                break;
            }
        }
        assert_eq!(vd.shares_since_retarget, 100);
    }

    #[test]
    fn vardiff_state_evaluate_no_change_near_target() {
        let mut vd = VardiffState::new(
            1000,
            20.0,
            Duration::from_millis(1), // tiny interval for test
            1,
            u64::MAX,
            4.0,
        );
        // Simulate exactly 20 shares per minute: in 1 second, that
        // is 20/60 = 0.333 shares. But we will set shares manually.
        vd.shares_since_retarget = 1;
        // Force retarget_start to 3 seconds ago so rate = 1/3*60 = 20/min.
        vd.retarget_start = Instant::now().checked_sub(Duration::from_secs(3)).unwrap();
        let result = vd.evaluate_retarget();
        // Rate is exactly on target, so no change.
        assert!(result.is_none());
    }

    #[test]
    fn vardiff_state_evaluate_increases_difficulty() {
        let mut vd = VardiffState::new(1000, 20.0, Duration::from_millis(1), 1, u64::MAX, 4.0);
        // Simulate way too many shares: 100 in 3 seconds = 2000/min.
        // ratio = 2000/20 = 100, clamped to 4.0.
        vd.shares_since_retarget = 100;
        vd.retarget_start = Instant::now().checked_sub(Duration::from_secs(3)).unwrap();
        let result = vd.evaluate_retarget();
        assert!(result.is_some());
        let new_diff = result.unwrap();
        assert_eq!(new_diff, 4000); // 1000 * 4.0 (max factor)
    }

    #[test]
    fn vardiff_state_evaluate_decreases_difficulty() {
        let mut vd = VardiffState::new(1000, 20.0, Duration::from_millis(1), 1, u64::MAX, 4.0);
        // Simulate too few shares: 1 in 60 seconds = 1/min.
        // ratio = 1/20 = 0.05, clamped to 1/4 = 0.25.
        vd.shares_since_retarget = 1;
        vd.retarget_start = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        let result = vd.evaluate_retarget();
        assert!(result.is_some());
        let new_diff = result.unwrap();
        assert_eq!(new_diff, 250); // 1000 * 0.25
    }

    #[test]
    fn vardiff_state_clamps_to_min_max() {
        let mut vd = VardiffState::new(10, 20.0, Duration::from_millis(1), 5, 100, 4.0);
        // Drive difficulty down: 0 shares in 60 seconds.
        vd.shares_since_retarget = 0;
        vd.retarget_start = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        let result = vd.evaluate_retarget();
        // 10 * (0 / 20) = 0, clamped to 10 * (1/4) = 2, then clamped to min 5.
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 5);

        // Drive difficulty up past max.
        vd.current_difficulty = 50;
        vd.shares_since_retarget = 1000;
        vd.retarget_start = Instant::now().checked_sub(Duration::from_secs(3)).unwrap();
        let result = vd.evaluate_retarget();
        // 50 * 4.0 = 200, clamped to max 100.
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn extended_channel_open_close_gc_lifecycle() {
        let mut mgr = ConnectionChannels::new(4);
        mgr.open_extended_channel(
            1,
            vec![0, 0, 0, 0, 0, 0, 0, 1],
            "ext-worker".into(),
            None,
            default_target(),
            0,
            8,
            16,
        )
        .unwrap();
        assert_eq!(mgr.open_count(), 1);

        // Close the channel. get() filters closed channels.
        assert!(mgr.close_channel(1));
        assert_eq!(mgr.open_count(), 0);
        assert!(mgr.get(1).is_none());

        // Idempotent close returns false.
        assert!(!mgr.close_channel(1));

        // GC removes the closed entry from internal storage.
        mgr.gc_closed();

        // Re-open with same ID succeeds after GC.
        let result = mgr.open_extended_channel(
            1,
            vec![0, 0, 0, 0, 0, 0, 0, 2],
            "ext-worker-2".into(),
            None,
            default_target(),
            0,
            8,
            16,
        );
        assert!(result.is_ok());
        assert_eq!(mgr.open_count(), 1);
    }

    #[test]
    fn extended_channel_vardiff_field_works() {
        let mut ch = ChannelState::new_extended(
            1,
            vec![0, 0, 0, 0, 0, 0, 0, 1],
            "ext-worker".into(),
            None,
            default_target(),
            0,
            8,
            16,
        );
        assert!(ch.vardiff.is_none());
        ch.vardiff = Some(VardiffState::new(
            1000,
            20.0,
            Duration::from_secs(90),
            1,
            u64::MAX,
            4.0,
        ));
        assert!(ch.vardiff.is_some());
        assert_eq!(ch.vardiff.as_ref().unwrap().current_difficulty, 1000);
    }

    #[test]
    fn channel_state_vardiff_initially_none() {
        let ch = ChannelState::new(
            1,
            vec![0, 0, 0, 1],
            "miner".into(),
            None,
            default_target(),
            0,
        );
        assert!(ch.vardiff.is_none());
    }
}
