//! Verifier NDJSON TCP stream connection.
//!
//! Maintains a persistent TCP connection to the pool-verifier, sending
//! `template_propose` messages and receiving `template_verdict` responses.
//! `Heartbeat/heartbeat_ack` pairs keep the connection alive and drive the
//! readiness probe.
//!
//! When TLS is configured (`tls_config` present in `VerifierStreamConfig`),
//! the raw TCP stream is wrapped with `tokio_rustls::TlsConnector` using
//! mTLS client certificates. The NDJSON framing is unchanged.

use std::sync::Arc;
use std::time::Duration;

use rg_protocol::gateway::{InternalMessage, MAX_INTERNAL_LINE_BYTES, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};

use crate::health::ReadinessState;

// ─────────────────────────────────────────────────────────────────────
// Message types flowing through the stream
// ─────────────────────────────────────────────────────────────────────

/// Outbound message to send to the verifier.
#[derive(Debug)]
pub enum VerifierOutbound {
    /// Propose a template for verification.
    TemplatePropose(TemplatePropose),
    /// Send a heartbeat.
    Heartbeat,
}

/// Inbound message received from the verifier.
#[derive(Debug, Clone)]
pub enum VerifierInbound {
    /// A verdict on a previously proposed template.
    TemplateVerdict(TemplateVerdict),
    /// Heartbeat acknowledgment (verifier is alive).
    HeartbeatAck,
}

// ─────────────────────────────────────────────────────────────────────
// Verifier connection task
// ─────────────────────────────────────────────────────────────────────

/// TLS configuration for the verifier channel (mTLS).
pub struct VerifierTlsConfig {
    /// TLS connector built from CA cert + client cert/key.
    pub connector: tokio_rustls::TlsConnector,
    /// Server name for SNI and certificate verification.
    pub server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
}

/// Configuration for the verifier connection.
pub struct VerifierStreamConfig {
    /// TCP address of the verifier.
    pub addr: String,
    /// Reconnect delay on disconnect.
    pub reconnect_delay: Duration,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Health probe staleness threshold.
    pub health_probe_staleness_ms: u64,
    /// Optional TLS configuration. When `Some`, the TCP stream is wrapped
    /// with mTLS before NDJSON framing begins.
    pub tls_config: Option<VerifierTlsConfig>,
}

/// Run the verifier connection loop.
///
/// Connects to the verifier, reads NDJSON lines, dispatches verdicts
/// via the `verdict_tx` broadcast channel, and sends outbound messages
/// from `outbound_rx`. Reconnects automatically on failure.
///
/// Updates `readiness_state.verifier_connected` and `readiness_state.policy_loaded`.
#[allow(clippy::too_many_lines)] // Single async select loop; splitting obscures flow.
pub async fn run_verifier_stream(
    config: VerifierStreamConfig,
    outbound_rx: mpsc::Receiver<VerifierOutbound>,
    verdict_tx: broadcast::Sender<VerifierInbound>,
    readiness: Arc<ReadinessState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut outbound_rx = outbound_rx;

    loop {
        // Check for shutdown.
        if *shutdown.borrow() {
            info!("verifier stream shutting down");
            return;
        }

        info!(addr = %config.addr, "connecting to verifier");
        readiness
            .verifier_connected
            .store(false, std::sync::atomic::Ordering::SeqCst);

        let tcp_stream = match TcpStream::connect(&config.addr).await {
            Ok(s) => {
                info!(addr = %config.addr, "TCP connected to verifier");
                s
            }
            Err(e) => {
                warn!(
                    addr = %config.addr,
                    error = %e,
                    "failed to connect to verifier; retrying"
                );
                tokio::select! {
                    () = tokio::time::sleep(config.reconnect_delay) => continue,
                    _ = shutdown.changed() => return,
                }
            }
        };

        // Wrap with TLS if configured, then run the I/O loop on the
        // resulting (reader, writer) pair. The NDJSON framing is identical
        // regardless of the transport layer.
        let io_result = if let Some(ref tls) = config.tls_config {
            match tls
                .connector
                .connect(tls.server_name.clone(), tcp_stream)
                .await
            {
                Ok(tls_stream) => {
                    info!(addr = %config.addr, "TLS handshake succeeded (mTLS)");
                    readiness
                        .verifier_connected
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let (reader, writer) = tokio::io::split(tls_stream);
                    run_io_loop(
                        reader,
                        writer,
                        &mut outbound_rx,
                        &verdict_tx,
                        &readiness,
                        &config,
                        &mut shutdown,
                    )
                    .await
                }
                Err(e) => {
                    warn!(
                        addr = %config.addr,
                        error = %e,
                        "TLS handshake failed; retrying"
                    );
                    IoLoopOutcome::Disconnected
                }
            }
        } else {
            readiness
                .verifier_connected
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let (reader, writer) = tcp_stream.into_split();
            run_io_loop(
                reader,
                writer,
                &mut outbound_rx,
                &verdict_tx,
                &readiness,
                &config,
                &mut shutdown,
            )
            .await
        };

        if matches!(io_result, IoLoopOutcome::Shutdown) {
            return;
        }

        // Disconnected; mark unhealthy and reconnect.
        readiness
            .verifier_connected
            .store(false, std::sync::atomic::Ordering::SeqCst);
        readiness
            .policy_loaded
            .store(false, std::sync::atomic::Ordering::SeqCst);

        tokio::select! {
            () = tokio::time::sleep(config.reconnect_delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Outcome of a single connection's I/O loop.
enum IoLoopOutcome {
    /// Connection was lost (EOF, error, or TLS failure). Caller should reconnect.
    Disconnected,
    /// Graceful shutdown requested. Caller should exit.
    Shutdown,
}

/// Inner I/O loop that is transport-agnostic. Accepts any `AsyncRead + AsyncWrite`
/// pair, so the same logic serves both plaintext TCP and TLS streams.
async fn run_io_loop<R, W>(
    reader: R,
    mut writer: W,
    outbound_rx: &mut mpsc::Receiver<VerifierOutbound>,
    verdict_tx: &broadcast::Sender<VerifierInbound>,
    readiness: &ReadinessState,
    config: &VerifierStreamConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> IoLoopOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line_buf = String::new();
    let mut heartbeat_interval = tokio::time::interval(config.heartbeat_interval);
    let mut malformed_count: u32 = 0;

    loop {
        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                match result {
                    Ok(0) => {
                        warn!("verifier connection closed (EOF)");
                        return IoLoopOutcome::Disconnected;
                    }
                    Ok(n) if n > MAX_INTERNAL_LINE_BYTES => {
                        warn!(bytes = n, "verifier line too large; dropping");
                        malformed_count += 1;
                        if malformed_count >= 3 {
                            error!("3 malformed lines from verifier; disconnecting");
                            return IoLoopOutcome::Disconnected;
                        }
                        line_buf.clear();
                    }
                    Ok(_) => {
                        match serde_json::from_str::<InternalMessage>(line_buf.trim()) {
                            Ok(msg) => {
                                dispatch_inbound(&msg, verdict_tx, readiness);
                            }
                            Err(e) => {
                                warn!(error = %e, line = %line_buf.trim(), "malformed verifier message");
                                malformed_count += 1;
                                if malformed_count >= 3 {
                                    error!("3 malformed lines; disconnecting");
                                    return IoLoopOutcome::Disconnected;
                                }
                            }
                        }
                        line_buf.clear();
                    }
                    Err(e) => {
                        warn!(error = %e, "verifier read error");
                        return IoLoopOutcome::Disconnected;
                    }
                }
            }

            msg = outbound_rx.recv() => {
                if let Some(outbound) = msg {
                    let line = match serialize_outbound(&outbound) {
                        Ok(l) => l,
                        Err(e) => {
                            error!(error = %e, "failed to serialize outbound message");
                            continue;
                        }
                    };
                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                        warn!(error = %e, "verifier write error");
                        return IoLoopOutcome::Disconnected;
                    }
                    if let Err(e) = writer.flush().await {
                        warn!(error = %e, "verifier flush error");
                        return IoLoopOutcome::Disconnected;
                    }
                } else {
                    info!("outbound channel closed; shutting down verifier stream");
                    return IoLoopOutcome::Shutdown;
                }
            }

            _ = heartbeat_interval.tick() => {
                let hb = match serialize_outbound(&VerifierOutbound::Heartbeat) {
                    Ok(line) => line,
                    Err(e) => {
                        error!(error = %e, "heartbeat serialization failed");
                        continue;
                    }
                };
                if let Err(e) = writer.write_all(hb.as_bytes()).await {
                    warn!(error = %e, "heartbeat write failed");
                    return IoLoopOutcome::Disconnected;
                }
                if let Err(e) = writer.flush().await {
                    warn!(error = %e, "heartbeat flush failed");
                    return IoLoopOutcome::Disconnected;
                }
                debug!("heartbeat sent");
            }

            _ = shutdown.changed() => {
                info!("shutdown signal received; closing verifier stream");
                return IoLoopOutcome::Shutdown;
            }
        }
    }
}

/// Dispatch an inbound message from the verifier.
fn dispatch_inbound(
    msg: &InternalMessage,
    verdict_tx: &broadcast::Sender<VerifierInbound>,
    readiness: &ReadinessState,
) {
    match msg.msg_type.as_str() {
        msg_types::TEMPLATE_VERDICT => {
            match serde_json::from_value::<TemplateVerdict>(msg.payload.clone()) {
                Ok(verdict) => {
                    debug!(
                        template_id = verdict.id,
                        accepted = verdict.accepted,
                        "received template verdict"
                    );
                    if verdict_tx.send(VerifierInbound::TemplateVerdict(verdict)).is_err() {
                        warn!("verdict_tx has no receivers; template verdict dropped");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "failed to parse template_verdict payload");
                }
            }
        }
        msg_types::HEARTBEAT_ACK => {
            debug!("received heartbeat_ack");
            readiness
                .policy_loaded
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if verdict_tx.send(VerifierInbound::HeartbeatAck).is_err() {
                warn!("verdict_tx has no receivers; heartbeat ack dropped");
            }
        }
        other => {
            debug!(msg_type = other, "unknown verifier message type; ignoring");
        }
    }
}

/// Serialize an outbound message as an NDJSON line.
fn serialize_outbound(msg: &VerifierOutbound) -> Result<String, serde_json::Error> {
    let internal = match msg {
        VerifierOutbound::TemplatePropose(tp) => InternalMessage {
            msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(tp)?,
        },
        VerifierOutbound::Heartbeat => InternalMessage {
            msg_type: msg_types::HEARTBEAT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        },
    };
    let mut line = serde_json::to_string(&internal)?;
    line.push('\n');
    Ok(line)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn serialize_heartbeat() {
        let msg = VerifierOutbound::Heartbeat;
        let line = serialize_outbound(&msg).unwrap();
        assert!(line.contains("heartbeat"));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn serialize_template_propose() {
        let tp = TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 42,
            block_height: 800_000,
            prev_hash: "aa".repeat(32),
            coinbase_value: 625_000_000,
            tx_count: 100,
            total_fees: 50_000_000,
            observed_weight: Some(3_900_000),
            created_at_unix_ms: Some(1_700_000_000_000),
            total_sigops: Some(10000),
            coinbase_sigops: Some(4),
            template_weight: Some(3_950_000),
            gateway_instance_id: Some("test-gw-01".to_string()),
        };
        let msg = VerifierOutbound::TemplatePropose(tp);
        let line = serialize_outbound(&msg).unwrap();
        assert!(line.contains("template_propose"));
        assert!(line.contains("800000"));
    }

    #[test]
    fn dispatch_verdict_parses_correctly() {
        let verdict = TemplateVerdict {
            version: PROTOCOL_VERSION,
            id: 42,
            accepted: true,
            reason_code: None,
            reason_detail: None,
            policy_context: None,
        };
        let msg = InternalMessage {
            msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(&verdict).unwrap(),
        };

        let (tx, mut rx) = broadcast::channel(16);
        let readiness = ReadinessState::new();

        dispatch_inbound(&msg, &tx, &readiness);

        let received = rx.try_recv().unwrap();
        match received {
            VerifierInbound::TemplateVerdict(v) => {
                assert_eq!(v.id, 42);
                assert!(v.accepted);
            }
            VerifierInbound::HeartbeatAck => panic!("expected TemplateVerdict"),
        }
    }

    #[test]
    fn dispatch_heartbeat_ack_sets_policy_loaded() {
        let msg = InternalMessage {
            msg_type: msg_types::HEARTBEAT_ACK.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        };

        let (tx, _rx) = broadcast::channel(16);
        let readiness = ReadinessState::new();
        assert!(
            !readiness
                .policy_loaded
                .load(std::sync::atomic::Ordering::SeqCst)
        );

        dispatch_inbound(&msg, &tx, &readiness);

        assert!(
            readiness
                .policy_loaded
                .load(std::sync::atomic::Ordering::SeqCst)
        );
    }
}
