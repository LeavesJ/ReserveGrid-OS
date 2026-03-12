use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::warn;

/// Per-IP state: sliding window of request timestamps.
struct IpWindow {
    timestamps: VecDeque<Instant>,
}

/// Internal mutable state behind the mutex.
struct LimiterState {
    ips: HashMap<IpAddr, IpWindow>,
    /// Global sliding window for aggregate ceiling enforcement.
    global_timestamps: VecDeque<Instant>,
}

/// Hardened sliding-window rate limiter.
///
/// Replaces the original fixed-bucket implementation with:
///
/// 1. Sliding window instead of fixed minute boundary (eliminates burst
///    doubling at bucket edges).
/// 2. Fail closed on mutex poison (deny all requests when lock is corrupted).
/// 3. Bounded IP tracking with LRU eviction (prevents memory exhaustion from
///    distributed IP floods).
/// 4. Optional global aggregate ceiling across all IPs per window.
pub struct RateLimiter {
    /// Maximum number of tracked IPs before LRU eviction.
    max_tracked_ips: usize,
    /// Global requests per window ceiling. `None` disables global limiting.
    global_ceiling: Option<u32>,
    /// Sliding window duration.
    window: Duration,
    /// Protected mutable state.
    state: Mutex<LimiterState>,
}

impl RateLimiter {
    /// Creates a rate limiter with default settings:
    /// 10,000 max tracked IPs, no global ceiling, 60 second window.
    pub fn new() -> Self {
        Self::with_config(10_000, None)
    }

    /// Creates a rate limiter with explicit configuration.
    ///
    /// # Arguments
    ///
    /// * `max_tracked_ips` - Maximum IPs tracked before LRU eviction
    /// * `global_ceiling` - Optional global request ceiling per window
    pub fn with_config(max_tracked_ips: usize, global_ceiling: Option<u32>) -> Self {
        Self {
            max_tracked_ips,
            global_ceiling,
            window: Duration::from_secs(60),
            state: Mutex::new(LimiterState {
                ips: HashMap::new(),
                global_timestamps: VecDeque::new(),
            }),
        }
    }

    /// Checks if a request from the given IP is allowed under the rate limit.
    ///
    /// Uses a sliding window: counts requests within the last 60 seconds.
    /// Returns `false` (deny) if the per-IP limit or global ceiling is
    /// exceeded, or if the internal lock is poisoned (fail closed).
    pub fn check(&self, ip: IpAddr, max_per_window: u32) -> bool {
        let now = Instant::now();

        let Ok(mut state) = self.state.lock() else {
            warn!("rate limiter mutex poisoned, failing closed");
            return false;
        };

        // Prune and check global ceiling.
        if let Some(ceiling) = self.global_ceiling {
            Self::prune_window(&mut state.global_timestamps, now, self.window);
            if state.global_timestamps.len() >= ceiling as usize {
                return false;
            }
        }

        // Get or create per-IP window.
        let ip_window = state.ips.entry(ip).or_insert_with(|| IpWindow {
            timestamps: VecDeque::new(),
        });

        // Prune expired timestamps from this IP's window.
        Self::prune_window(&mut ip_window.timestamps, now, self.window);

        // Check per-IP limit.
        if ip_window.timestamps.len() >= max_per_window as usize {
            return false;
        }

        // Record the request.
        ip_window.timestamps.push_back(now);
        if self.global_ceiling.is_some() {
            state.global_timestamps.push_back(now);
        }

        // LRU eviction when a new IP pushes us past the cap.
        if state.ips.len() > self.max_tracked_ips {
            Self::evict_oldest(&mut state.ips);
        }

        true
    }

    /// Removes entries whose most recent request is older than two windows.
    ///
    /// Call periodically to prevent gradual memory growth from IPs that
    /// made a single request and never returned.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let stale_threshold = self.window * 2;

        let Ok(mut state) = self.state.lock() else {
            return;
        };

        state.ips.retain(|_, w| {
            w.timestamps
                .back()
                .is_some_and(|t| now.duration_since(*t) < stale_threshold)
        });

        Self::prune_window(&mut state.global_timestamps, now, self.window);
    }

    /// Removes timestamps older than `window` from the front of the deque.
    fn prune_window(deque: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while let Some(&front) = deque.front() {
            if now.duration_since(front) >= window {
                deque.pop_front();
            } else {
                break;
            }
        }
    }

    /// Evicts the IP with the oldest most-recent timestamp.
    fn evict_oldest(ips: &mut HashMap<IpAddr, IpWindow>) {
        let oldest = ips
            .iter()
            .filter_map(|(ip, w)| w.timestamps.back().map(|t| (*ip, *t)))
            .min_by_key(|(_, t)| *t);

        if let Some((ip, _)) = oldest {
            ips.remove(&ip);
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_new_ip_allowed() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::LOCALHOST.into();

        assert!(limiter.check(ip, 5));
    }

    #[test]
    fn test_rate_limit_enforced() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 1).into();
        let max = 3;

        assert!(limiter.check(ip, max)); // 1st
        assert!(limiter.check(ip, max)); // 2nd
        assert!(limiter.check(ip, max)); // 3rd
        assert!(!limiter.check(ip, max)); // 4th, blocked
        assert!(!limiter.check(ip, max)); // 5th, blocked
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = RateLimiter::new();
        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let max = 2;

        assert!(limiter.check(ip1, max));
        assert!(limiter.check(ip1, max));
        assert!(!limiter.check(ip1, max));

        // ip2 is independent
        assert!(limiter.check(ip2, max));
        assert!(limiter.check(ip2, max));
        assert!(!limiter.check(ip2, max));
    }

    #[test]
    fn test_cleanup_removes_old_entries() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(172, 16, 0, 1).into();

        assert!(limiter.check(ip, 5));

        // Backdate the timestamp beyond 2x window to simulate staleness.
        {
            let mut state = limiter.state.lock().unwrap();
            if let Some(w) = state.ips.get_mut(&ip)
                && let Some(ts) = w.timestamps.front_mut()
            {
                *ts = Instant::now()
                    .checked_sub(Duration::from_secs(180))
                    .unwrap();
            }
        }

        assert_eq!(limiter.state.lock().unwrap().ips.len(), 1);
        limiter.cleanup();
        assert_eq!(limiter.state.lock().unwrap().ips.len(), 0);
    }

    #[test]
    fn test_cleanup_keeps_recent_entries() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(172, 16, 0, 2).into();

        assert!(limiter.check(ip, 5));

        // Backdate to 30 seconds ago (within the 2x window threshold).
        {
            let mut state = limiter.state.lock().unwrap();
            if let Some(w) = state.ips.get_mut(&ip)
                && let Some(ts) = w.timestamps.front_mut()
            {
                *ts = Instant::now().checked_sub(Duration::from_secs(30)).unwrap();
            }
        }

        limiter.cleanup();
        assert_eq!(limiter.state.lock().unwrap().ips.len(), 1);
    }

    #[test]
    fn test_global_ceiling_enforced() {
        let limiter = RateLimiter::with_config(10_000, Some(5));
        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let ip3: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();

        // Each IP gets up to 10/window, but global ceiling is 5.
        assert!(limiter.check(ip1, 10)); // global 1
        assert!(limiter.check(ip1, 10)); // global 2
        assert!(limiter.check(ip2, 10)); // global 3
        assert!(limiter.check(ip2, 10)); // global 4
        assert!(limiter.check(ip3, 10)); // global 5
        assert!(!limiter.check(ip3, 10)); // global 6, blocked
    }

    #[test]
    fn test_lru_eviction() {
        let limiter = RateLimiter::with_config(2, None);
        let ip1: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(10, 0, 0, 2).into();
        let ip3: IpAddr = Ipv4Addr::new(10, 0, 0, 3).into();

        assert!(limiter.check(ip1, 10));
        assert!(limiter.check(ip2, 10));
        // At this point we have 2 IPs tracked (at capacity).

        assert!(limiter.check(ip3, 10));
        // ip3 insert should trigger eviction of the oldest (ip1).

        let state = limiter.state.lock().unwrap();
        assert_eq!(state.ips.len(), 2);
        assert!(!state.ips.contains_key(&ip1));
        assert!(state.ips.contains_key(&ip2));
        assert!(state.ips.contains_key(&ip3));
    }

    #[test]
    fn test_fail_closed_on_poison() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::LOCALHOST.into();

        // Poison the mutex by panicking inside a lock scope.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = limiter.state.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        // After poison, check must return false (fail closed).
        assert!(!limiter.check(ip, 100));
    }

    #[test]
    fn test_window_rollover_allows_requests_again() {
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 50).into();
        let max = 3;

        // Fill the window completely.
        for _ in 0..max {
            assert!(limiter.check(ip, max));
        }
        assert!(!limiter.check(ip, max)); // blocked

        // Backdate all timestamps beyond the 60s window to simulate expiry.
        {
            let mut state = limiter.state.lock().unwrap();
            if let Some(w) = state.ips.get_mut(&ip) {
                let old = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
                for ts in &mut w.timestamps {
                    *ts = old;
                }
            }
        }

        // After window rollover the same IP should be accepted again.
        assert!(limiter.check(ip, max));
    }

    #[test]
    fn test_sliding_window_no_boundary_doubling() {
        // With the old fixed-bucket approach, a burst at the boundary could
        // allow 2x the limit. The sliding window prevents this.
        let limiter = RateLimiter::new();
        let ip: IpAddr = Ipv4Addr::new(192, 168, 1, 100).into();
        let max = 5;

        // Fill the window.
        for _ in 0..max {
            assert!(limiter.check(ip, max));
        }

        // The 6th request must be denied even though no time has passed.
        assert!(!limiter.check(ip, max));
    }
}
