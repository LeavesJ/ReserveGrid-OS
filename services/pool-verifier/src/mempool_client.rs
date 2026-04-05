use serde::Deserialize;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Default mempool HTTP client timeout in milliseconds.
const DEFAULT_MEMPOOL_TIMEOUT_MS: u64 = 900;

pub(crate) fn mempool_timeout_ms() -> u64 {
    std::env::var("VELDRA_MEMPOOL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMPOOL_TIMEOUT_MS)
}

fn client() -> &'static reqwest::Client {
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(mempool_timeout_ms()))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

#[derive(Deserialize)]
struct MempoolSnapshot {
    // template-manager /mempool => "tx_count"
    // older/alt shapes may use "count" or "size"
    #[serde(default, alias = "tx_count", alias = "count", alias = "size")]
    tx_count: u64,

    // unix seconds if provided
    #[serde(default)]
    timestamp: Option<u64>,
}

pub fn mempool_url_from_env() -> Option<String> {
    std::env::var("VELDRA_MEMPOOL_URL").ok()
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

pub async fn fetch_mempool_tx_count(url: &str) -> Option<u64> {
    let resp = match client().get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(url = %url, error = ?e, "mempool HTTP fetch failed");
            return None;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        warn!(url = %url, status = %status, "mempool non-success HTTP status");
        return None;
    }

    let snapshot = match resp.json::<MempoolSnapshot>().await {
        Ok(s) => s,
        Err(e) => {
            warn!(url = %url, error = ?e, "mempool JSON parse error");
            return None;
        }
    };

    if let Some(ts) = snapshot.timestamp {
        let age = now_unix_secs().saturating_sub(ts);
        if age > 30 {
            warn!(url = %url, age_secs = age, "mempool snapshot is stale");
        }
    }

    Some(snapshot.tx_count)
}
