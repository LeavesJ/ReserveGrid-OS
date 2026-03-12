//! Response timing normalization.
//!
//! Enforces a minimum response time on rejection paths to prevent
//! timing side-channel leakage from the verification pipeline.
//!
//! If a rejection completes in less than `min_response_delay_ms`, the
//! handler sleeps for the remaining duration before responding.

use std::time::{Duration, Instant};

/// Enforce a minimum response delay.
///
/// Call this after the handler produces a response but before sending it.
/// If the elapsed time since `start` is less than `min_delay`, this function
/// sleeps for the remainder.
pub async fn enforce_min_delay(start: Instant, min_delay: Duration) {
    let elapsed = start.elapsed();
    if let Some(remaining) = min_delay.checked_sub(elapsed) {
        tokio::time::sleep(remaining).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enforce_min_delay_pads_fast_responses() {
        let start = Instant::now();
        let min_delay = Duration::from_millis(50);

        enforce_min_delay(start, min_delay).await;

        let total = start.elapsed();
        assert!(
            total >= min_delay,
            "total elapsed {total:?} should be >= {min_delay:?}",
        );
    }

    #[tokio::test]
    async fn enforce_min_delay_noop_for_slow_responses() {
        let start = Instant::now();
        // Simulate a slow handler
        tokio::time::sleep(Duration::from_millis(10)).await;
        let min_delay = Duration::from_millis(5);

        let before = Instant::now();
        enforce_min_delay(start, min_delay).await;
        let padding = before.elapsed();

        // Should have added negligible time since we already exceeded the minimum
        assert!(
            padding < Duration::from_millis(5),
            "padding {padding:?} should be minimal for slow responses",
        );
    }
}
