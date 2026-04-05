// rg-demo-feed: streams synthetic but realistic Bitcoin template data over
// WebSocket. Designed to give shadow-mode operators a compelling first
// impression of what ReserveGrid OS flags.
//
// Each connected client receives the same broadcast stream of templates.
// Templates cycle through normal and anomalous scenarios so every verifier
// policy detection fires at least once per loop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{error, info, warn};

mod scenarios;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "rg-demo-feed",
    about = "Synthetic Bitcoin template feed for shadow mode"
)]
struct Cli {
    /// Listen address for WebSocket connections.
    #[arg(
        long,
        env = "VELDRA_DEMO_FEED_LISTEN",
        default_value = "127.0.0.1:9100"
    )]
    listen: String,

    /// Interval between template emissions in milliseconds.
    #[arg(long, env = "VELDRA_DEMO_FEED_INTERVAL_MS", default_value = "5000")]
    interval_ms: u64,

    /// Broadcast channel capacity (number of buffered frames per client).
    #[arg(long, default_value = "64")]
    channel_capacity: usize,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let filter = std::env::var("VELDRA_LOG_FILTER").unwrap_or_else(|_| "info".into());
    let fmt = std::env::var("VELDRA_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());

    let subscriber = tracing_subscriber::fmt().with_env_filter(&filter);
    if fmt == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }

    let cli = Cli::parse();

    let addr: SocketAddr = cli.listen.parse().unwrap_or_else(|e| {
        error!(listen = %cli.listen, error = %e, "invalid listen address");
        std::process::exit(1);
    });

    let (tx, _rx) = broadcast::channel::<Arc<String>>(cli.channel_capacity);

    // Spawn the scenario generator task.
    let gen_tx = tx.clone();
    let interval = Duration::from_millis(cli.interval_ms);
    tokio::spawn(async move {
        scenarios::run_scenario_loop(gen_tx, interval).await;
    });

    // Accept WebSocket connections.
    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%addr, error = %e, "failed to bind");
        std::process::exit(1);
    });

    if !addr.ip().is_loopback() {
        warn!(
            %addr,
            "demo feed binding to non-loopback address; ensure network access is intentional"
        );
    }

    info!(%addr, interval_ms = cli.interval_ms, "rg-demo-feed listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };

        let rx = tx.subscribe();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, rx, peer).await {
                info!(%peer, error = %e, "client disconnected");
            }
        });
    }
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    mut rx: broadcast::Receiver<Arc<String>>,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_config = WebSocketConfig {
        max_message_size: Some(1024 * 1024), // 1 MiB
        max_frame_size: Some(256 * 1024),    // 256 KiB
        ..WebSocketConfig::default()
    };

    let ws_stream = tokio_tungstenite::accept_async_with_config(stream, Some(ws_config)).await?;
    info!(%peer, "client connected");

    let (mut writer, mut reader) = ws_stream.split();

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(frame) => {
                        writer.send(Message::Text((*frame).clone())).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(%peer, skipped = n, "client lagging, dropped frames");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = reader.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        writer.send(Message::Pong(data)).await?;
                    }
                    Some(Ok(_)) => {} // ignore client text/binary
                    Some(Err(e)) => return Err(e.into()),
                }
            }
        }
    }

    info!(%peer, "client disconnected cleanly");
    Ok(())
}
