//! Bitcoind poller: periodically calls `getblocktemplate` and `getmempoolinfo`
//! via JSON-RPC, then broadcasts NDJSON frames to all connected WebSocket
//! clients via a tokio broadcast channel.
//!
//! Wire format is identical to `rg-demo-feed`:
//! ```json
//! {"type":"blocktemplate","ts":1709000000,"data":{...GBT response...}}
//! {"type":"mempoolinfo","ts":1709000000,"data":{...mempool response...}}
//! {"type":"heartbeat","ts":1709000000,"data":{}}
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Shared state for health checks.
pub struct FeedState {
    /// Whether the last poll succeeded.
    pub rpc_ok: AtomicBool,
    /// Unix timestamp (seconds) of the last successful poll.
    pub last_poll_ts: AtomicU64,
    /// Block height from the last successful template.
    pub last_height: AtomicU64,
}

impl FeedState {
    pub fn new() -> Self {
        Self {
            rpc_ok: AtomicBool::new(false),
            last_poll_ts: AtomicU64::new(0),
            last_height: AtomicU64::new(0),
        }
    }
}

/// Runs the polling loop. Never returns unless the broadcast channel closes.
pub async fn run_poller(
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    poll_interval: Duration,
    tx: broadcast::Sender<Arc<String>>,
    state: Arc<FeedState>,
) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let has_auth = !rpc_user.is_empty();

    info!(
        rpc_url = %rpc_url,
        poll_ms = u64::try_from(poll_interval.as_millis()).unwrap_or(u64::MAX),
        auth = has_auth,
        "bitcoind poller started"
    );

    let mut interval = tokio::time::interval(poll_interval);

    loop {
        interval.tick().await;

        let ts = now_ts();

        // Poll getblocktemplate.
        match rpc_call(
            &client,
            &rpc_url,
            &rpc_user,
            &rpc_pass,
            "getblocktemplate",
            json!([{"rules": ["segwit"]}]),
        )
        .await
        {
            Ok(data) => {
                state.rpc_ok.store(true, Ordering::Relaxed);
                state.last_poll_ts.store(ts, Ordering::Relaxed);

                if let Some(height) = data.get("height").and_then(serde_json::Value::as_u64) {
                    state.last_height.store(height, Ordering::Relaxed);
                }

                let frame = json!({
                    "type": "blocktemplate",
                    "ts": ts,
                    "data": data,
                });

                if let Ok(line) = serde_json::to_string(&frame) {
                    let _ = tx.send(Arc::new(line));
                }
            }
            Err(e) => {
                state.rpc_ok.store(false, Ordering::Relaxed);
                warn!(error = %e, "getblocktemplate failed");
            }
        }

        // Poll getmempoolinfo.
        match rpc_call(
            &client,
            &rpc_url,
            &rpc_user,
            &rpc_pass,
            "getmempoolinfo",
            json!([]),
        )
        .await
        {
            Ok(data) => {
                let frame = json!({
                    "type": "mempoolinfo",
                    "ts": ts,
                    "data": data,
                });

                if let Ok(line) = serde_json::to_string(&frame) {
                    let _ = tx.send(Arc::new(line));
                }
            }
            Err(e) => {
                warn!(error = %e, "getmempoolinfo failed");
            }
        }
    }
}

/// Make a JSON-RPC call to bitcoind.
async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    user: &str,
    pass: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let body = json!({
        "jsonrpc": "1.0",
        "id": method,
        "method": method,
        "params": params,
    });

    let mut req = client.post(url).json(&body);
    if !user.is_empty() {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("rpc request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("rpc returned HTTP {}", resp.status()));
    }

    let envelope: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("rpc response parse failed: {e}"))?;

    if let Some(err) = envelope.get("error").filter(|v| !v.is_null()) {
        return Err(format!("rpc error: {err}"));
    }

    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| "rpc response missing 'result' field".into())
}

pub fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn feed_state_defaults() {
        let state = FeedState::new();
        assert!(!state.rpc_ok.load(Ordering::Relaxed));
        assert_eq!(state.last_poll_ts.load(Ordering::Relaxed), 0);
        assert_eq!(state.last_height.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn feed_state_stores_and_reads() {
        let state = FeedState::new();
        state.rpc_ok.store(true, Ordering::Relaxed);
        state.last_poll_ts.store(1_234_567_890, Ordering::Relaxed);
        state.last_height.store(890_000, Ordering::Relaxed);

        assert!(state.rpc_ok.load(Ordering::Relaxed));
        assert_eq!(state.last_poll_ts.load(Ordering::Relaxed), 1_234_567_890);
        assert_eq!(state.last_height.load(Ordering::Relaxed), 890_000);
    }

    #[test]
    fn now_ts_returns_reasonable_epoch() {
        let ts = now_ts();
        // Must be after 2024-01-01 (1704067200) and before 2040 (2208988800).
        assert!(ts > 1_704_067_200, "now_ts {ts} should be after 2024");
        assert!(ts < 2_208_988_800, "now_ts {ts} should be before 2040");
    }
}
