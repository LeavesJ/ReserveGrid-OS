//! `rg-feed-server`: authenticated mainnet Bitcoin template feed for observe mode.
//!
//! Connects to a real bitcoind via JSON-RPC, polls `getblocktemplate` and
//! `getmempoolinfo`, and broadcasts NDJSON frames to authenticated WebSocket
//! clients. License keys are validated on the WebSocket handshake via the
//! `Authorization: Bearer <key>` header.
//!
//! Wire format is identical to `rg-demo-feed` so `rg-feed-adapter` works
//! with either feed without configuration changes beyond the URL.

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
use tokio_tungstenite::tungstenite::handshake::server::{
    Callback, ErrorResponse, Request, Response,
};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{error, info, warn};

mod auth;
mod config;
mod feed;

use auth::KeyValidator;
use feed::FeedState;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "rg-feed-server",
    about = "Authenticated mainnet template feed for observe mode"
)]
struct Cli {
    /// Path to the config TOML file.
    #[arg(
        short,
        long,
        env = "VELDRA_FEED_SERVER_CONFIG",
        default_value = "config/default.toml"
    )]
    config: String,
}

// ---------------------------------------------------------------------------
// WebSocket handshake callback: validates Bearer token at upgrade time
// ---------------------------------------------------------------------------

/// Maximum bearer token length to prevent memory abuse. Signed license keys
/// (`veldra_lic_`) are roughly 300+ chars, so 512 gives comfortable headroom.
const MAX_TOKEN_LENGTH: usize = 512;

struct AuthCallback {
    validator: KeyValidator,
    /// Written during the handshake; read after accept to identify the client.
    validated: std::sync::Mutex<Option<auth::ValidatedKey>>,
}

impl Callback for &AuthCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let auth_header = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
            let trimmed = stripped.trim();
            if trimmed.len() > MAX_TOKEN_LENGTH {
                ""
            } else {
                trimmed
            }
        } else {
            ""
        };

        let Some(vk) = self.validator.validate(token) else {
            let mut err = http::Response::new(Some(
                "unauthorized: invalid or missing license key".to_string(),
            ));
            *err.status_mut() = http::StatusCode::UNAUTHORIZED;
            return Err(err);
        };

        if let Ok(mut guard) = self.validated.lock() {
            *guard = Some(vk);
        }

        Ok(response)
    }
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

    let cfg = match config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to load config");
            std::process::exit(1);
        }
    };

    let addr: SocketAddr = cfg.feed.listen.parse().unwrap_or_else(|e| {
        error!(listen = %cfg.feed.listen, error = %e, "invalid listen address");
        std::process::exit(1);
    });

    let validator = KeyValidator::new(&cfg.auth.license_pubkey);
    let feed_state = Arc::new(FeedState::new());

    let (tx, _rx) = broadcast::channel::<Arc<String>>(cfg.feed.channel_capacity);

    // Spawn the bitcoind poller.
    let poller_tx = tx.clone();
    let poller_state = feed_state.clone();
    let rpc_url = cfg.feed.rpc_url.clone();
    let rpc_user = cfg.feed.rpc_user.clone();
    let rpc_pass = cfg.feed.rpc_pass.clone();
    let poll_interval = Duration::from_millis(cfg.feed.poll_interval_ms);

    tokio::spawn(async move {
        feed::run_poller(
            rpc_url,
            rpc_user,
            rpc_pass,
            poll_interval,
            poller_tx,
            poller_state,
        )
        .await;
    });

    // Spawn heartbeat emitter.
    let heartbeat_tx = tx.clone();
    let heartbeat_interval = Duration::from_millis(cfg.feed.heartbeat_interval_ms);
    tokio::spawn(async move {
        run_heartbeat(heartbeat_tx, heartbeat_interval).await;
    });

    let listener = bind_listener(addr).await;

    run_accept_loop(listener, addr, &cfg, tx, validator, feed_state).await;
}

/// Accept connections with global and per-IP limits.
#[allow(clippy::too_many_arguments)]
async fn run_accept_loop(
    listener: TcpListener,
    addr: SocketAddr,
    cfg: &config::FeedServerConfig,
    tx: broadcast::Sender<Arc<String>>,
    validator: KeyValidator,
    feed_state: Arc<FeedState>,
) {
    let max_conns = cfg.feed.max_connections;
    let max_conns_per_ip: usize = cfg.feed.max_connections_per_ip;
    let active_conns = Arc::new(AtomicUsize::new(0));
    let per_ip_conns: Arc<tokio::sync::Mutex<HashMap<IpAddr, usize>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    info!(
        %addr,
        max_connections = max_conns,
        max_connections_per_ip = max_conns_per_ip,
        "rg-feed-server listening"
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
        let val = validator.clone();
        let state = feed_state.clone();
        let conns = active_conns.clone();
        let ip_conns = per_ip_conns.clone();

        tokio::spawn(async move {
            handle_connection(stream, rx, peer, val, state).await;
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

/// Bind the TCP listener with SEC-006 non-loopback guard.
async fn bind_listener(addr: SocketAddr) -> TcpListener {
    // SEC-006: block non-loopback bind unless explicitly opted in.
    if !addr.ip().is_loopback() {
        let allow_non_loopback =
            std::env::var("VELDRA_ALLOW_NON_LOOPBACK").ok().as_deref() == Some("1");
        if !allow_non_loopback {
            error!(
                %addr,
                "refusing to bind to non-loopback address; \
                 set VELDRA_ALLOW_NON_LOOPBACK=1 to override"
            );
            std::process::exit(1);
        }
        warn!(
            %addr,
            "binding to non-loopback address (VELDRA_ALLOW_NON_LOOPBACK=1)"
        );
    }

    TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%addr, error = %e, "failed to bind");
        std::process::exit(1);
    })
}

#[allow(clippy::too_many_lines)] // Single logical unit: handshake → auth → relay loop.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    mut rx: broadcast::Receiver<Arc<String>>,
    peer: SocketAddr,
    validator: KeyValidator,
    state: Arc<FeedState>,
) {
    // Perform WebSocket handshake with inline auth validation.
    // Unauthenticated clients are rejected during the HTTP upgrade (401)
    // before a WebSocket connection is established.
    let auth_cb = AuthCallback {
        validator,
        validated: std::sync::Mutex::new(None),
    };

    // tokio-tungstenite 0.26: WebSocketConfig is #[non_exhaustive]; use builder.
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(1024 * 1024)) // 1 MiB
        .max_frame_size(Some(256 * 1024)); // 256 KiB

    let ws_stream =
        match tokio_tungstenite::accept_hdr_async_with_config(stream, &auth_cb, Some(ws_config))
            .await
        {
            Ok(ws) => ws,
            Err(e) => {
                info!(%peer, error = %e, "websocket handshake rejected or failed");
                return;
            }
        };

    // If we reach here the handshake succeeded, meaning auth passed.
    let Some(validated) = auth_cb.validated.lock().ok().and_then(|mut g| g.take()) else {
        error!(%peer, "BUG: handshake succeeded but validated key is missing");
        return;
    };

    info!(
        %peer,
        org_id = %validated.org_id,
        tier = %validated.tier,
        "client authenticated"
    );

    let (mut writer, mut reader) = ws_stream.split();

    // Send initial state snapshot so the client does not wait for the next poll.
    if state.rpc_ok.load(Ordering::Relaxed) {
        let status_frame = serde_json::json!({
            "type": "status",
            "ts": feed::now_ts(),
            "data": {
                "height": state.last_height.load(Ordering::Relaxed),
                "rpc_ok": true,
            },
        });
        // tokio-tungstenite 0.26: Message::Text takes Utf8Bytes.
        if let Ok(msg) = serde_json::to_string(&status_frame)
            && let Err(e) = writer.send(Message::Text(msg.into())).await
        {
            warn!(%peer, error = %e, "failed to send initial status frame");
            return;
        }
    }

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(frame) => {
                        if writer.send(Message::Text((*frame).clone().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(%peer, skipped = n, "client lagging, dropped frames");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = reader.next() => {
                match incoming {
                    Some(Ok(Message::Ping(data))) => {
                        if writer.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {} // ignore client text/binary
                }
            }
        }
    }

    info!(%peer, "client disconnected");
}

async fn run_heartbeat(tx: broadcast::Sender<Arc<String>>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        let frame = serde_json::json!({
            "type": "heartbeat",
            "ts": feed::now_ts(),
            "data": {},
        });
        if let Ok(line) = serde_json::to_string(&frame) {
            let _ = tx.send(Arc::new(line));
        }
    }
}
