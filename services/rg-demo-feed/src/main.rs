// rg-demo-feed: streams synthetic but realistic Bitcoin template data over
// WebSocket. Designed to give shadow-mode operators a compelling first
// impression of what ReserveGrid OS flags.
//
// Each connected client receives the same broadcast stream of templates.
// Templates cycle through normal and anomalous scenarios so every verifier
// policy detection fires at least once per loop.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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

    /// Maximum concurrent WebSocket connections. Default 128.
    /// Set to 0 to disable (not recommended for production).
    #[arg(long, env = "VELDRA_DEMO_FEED_MAX_CONNECTIONS", default_value = "128")]
    max_connections: usize,

    /// Maximum concurrent connections from a single IP address. Default 8.
    /// Set to 0 to disable per-IP limiting.
    #[arg(
        long,
        env = "VELDRA_DEMO_FEED_MAX_CONNECTIONS_PER_IP",
        default_value = "8"
    )]
    max_connections_per_ip: usize,
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

    let listener = bind_demo_listener(addr).await;

    run_demo_accept_loop(
        listener, addr, &cli, tx,
    )
    .await;
}

/// Bind with SEC-006 non-loopback guard.
async fn bind_demo_listener(addr: SocketAddr) -> TcpListener {
    if !addr.ip().is_loopback() {
        let allow =
            std::env::var("VELDRA_ALLOW_NON_LOOPBACK").ok().as_deref() == Some("1");
        if !allow {
            error!(
                %addr,
                "refusing to bind to non-loopback address; \
                 set VELDRA_ALLOW_NON_LOOPBACK=1 to override"
            );
            std::process::exit(1);
        }
        warn!(
            %addr,
            "demo feed binding to non-loopback address \
             (VELDRA_ALLOW_NON_LOOPBACK=1)"
        );
    }

    TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%addr, error = %e, "failed to bind");
        std::process::exit(1);
    })
}

/// Accept connections with global and per-IP limits.
async fn run_demo_accept_loop(
    listener: TcpListener,
    addr: SocketAddr,
    cli: &Cli,
    tx: broadcast::Sender<Arc<String>>,
) {
    let max_conns = cli.max_connections;
    let max_conns_per_ip = cli.max_connections_per_ip;
    let active_conns = Arc::new(AtomicUsize::new(0));
    let per_ip_conns: Arc<tokio::sync::Mutex<HashMap<IpAddr, usize>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    info!(
        %addr,
        interval_ms = cli.interval_ms,
        max_connections = max_conns,
        max_connections_per_ip = max_conns_per_ip,
        "rg-demo-feed listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };

        if max_conns > 0 {
            let current = active_conns.load(Ordering::Relaxed);
            if current >= max_conns {
                warn!(
                    %peer,
                    active = current,
                    max = max_conns,
                    "connection rejected: at capacity"
                );
                drop(stream);
                continue;
            }
        }

        let peer_ip = peer.ip();
        if max_conns_per_ip > 0 {
            let mut ip_map = per_ip_conns.lock().await;
            let count = ip_map.entry(peer_ip).or_insert(0);
            if *count >= max_conns_per_ip {
                warn!(
                    %peer,
                    ip_count = *count,
                    max = max_conns_per_ip,
                    "connection rejected: per-IP limit reached"
                );
                drop(stream);
                continue;
            }
            *count += 1;
        }

        active_conns.fetch_add(1, Ordering::Relaxed);

        let rx = tx.subscribe();
        let conns = active_conns.clone();
        let ip_conns = per_ip_conns.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, rx, peer).await {
                info!(%peer, error = %e, "client disconnected");
            }
            conns.fetch_sub(1, Ordering::Relaxed);
            let mut ip_map = ip_conns.lock().await;
            if let Some(count) = ip_map.get_mut(&peer_ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ip_map.remove(&peer_ip);
                }
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
