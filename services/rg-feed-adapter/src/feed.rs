// WebSocket feed reader. Connects to rg-demo-feed or rg-feed-server,
// deserializes NDJSON frames, and buffers the latest data for the RPC handler.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{info, warn};

use crate::SharedBuffer;

/// Maximum reconnect backoff in seconds. Capped at 10s to limit the
/// template gap miners experience during feed outages.
const MAX_BACKOFF_SECS: u64 = 10;

/// Run the feed reader loop forever. Reconnects on disconnect with
/// exponential backoff capped at `MAX_BACKOFF_SECS`.
pub async fn run_feed_loop(feed_url: String, license_key: String, buffer: SharedBuffer) {
    let mut backoff_secs: u64 = 1;

    loop {
        info!(url = %feed_url, "connecting to feed");

        match connect_and_read(&feed_url, &license_key, &buffer).await {
            Ok(()) => {
                info!("feed connection closed cleanly");
            }
            Err(e) => {
                warn!(error = %e, backoff_secs, "feed connection failed");
            }
        }

        // Mark disconnected
        {
            let mut guard = buffer.write().await;
            guard.feed_connected = false;
        }

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

async fn connect_and_read(
    feed_url: &str,
    license_key: &str,
    buffer: &SharedBuffer,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut request = feed_url.into_client_request()?;

    // Attach license key as Bearer token if provided.
    if !license_key.is_empty() {
        let val = format!("Bearer {license_key}");
        request.headers_mut().insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&val)?,
        );
    }

    let (ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
    info!("feed connected");

    {
        let mut guard = buffer.write().await;
        guard.feed_connected = true;
    }

    let (_write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        let msg = msg_result?;

        match msg {
            Message::Text(text) => {
                if let Err(e) = process_frame(&text, buffer).await {
                    warn!(error = %e, "failed to process feed frame");
                }
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(frame) => {
                if let Some(cf) = &frame {
                    info!(code = %cf.code, reason = %cf.reason, "feed sent close frame");
                }
                break;
            }
            Message::Binary(_) | Message::Frame(_) => {
                warn!("unexpected binary/frame message from feed, ignoring");
            }
        }
    }

    Ok(())
}

/// Feed frame envelope.
#[derive(serde::Deserialize)]
struct FeedFrame {
    #[serde(rename = "type")]
    frame_type: String,
    #[allow(dead_code)]
    ts: Option<u64>,
    data: Option<serde_json::Value>,
}

async fn process_frame(
    text: &str,
    buffer: &SharedBuffer,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let frame: FeedFrame = serde_json::from_str(text)?;

    match frame.frame_type.as_str() {
        "blocktemplate" => {
            if let Some(data) = frame.data {
                let mut guard = buffer.write().await;
                guard.block_template = Some(data);
                guard.last_template_ts = Some(Instant::now());
                tracing::debug!("buffered new blocktemplate");
            }
        }
        "mempoolinfo" => {
            if let Some(data) = frame.data {
                let mut guard = buffer.write().await;
                guard.mempool_info = Some(data);
                tracing::debug!("buffered new mempoolinfo");
            }
        }
        "heartbeat" => {
            tracing::trace!("feed heartbeat");
        }
        other => {
            warn!(frame_type = other, "unknown feed frame type, ignoring");
        }
    }

    Ok(())
}
