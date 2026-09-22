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

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use reservegrid_common::reason::GatewayReason;
use rg_protocol::gateway::{InternalMessage, MAX_INTERNAL_LINE_BYTES, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
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

        // Add jitter (0..50% of base delay) to prevent thundering herd
        // when multiple gateways reconnect after a verifier restart.
        let jitter_ms = {
            use std::hash::{Hash, Hasher};
            let mut h = std::hash::DefaultHasher::new();
            std::time::Instant::now().hash(&mut h);
            let base_ms = config.reconnect_delay.as_millis() / 2;
            let half = u64::try_from(base_ms).unwrap_or(u64::MAX);
            h.finish() % half.max(1)
        };
        let delay = config.reconnect_delay + Duration::from_millis(jitter_ms);

        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// Heartbeat intervals the verifier may stay silent before the gateway drops
/// the connection and reconnects (PB-51).
///
/// A live verifier answers every heartbeat with an ack and sends a verdict for
/// every template, so it is never silent for long: its longest gap is one
/// template evaluation, a few seconds at most. A path that black-holes, with
/// no FIN or reset ever arriving, used to leave this loop waiting forever:
/// heartbeat writes still land in the kernel's send buffer, the gateway ran
/// degraded (unenforced) because no ack came back, and nothing reconnected
/// until TCP's retransmissions gave up, about 15 minutes on Linux by default.
///
/// The check runs on each heartbeat tick, so detection takes three to four
/// intervals: 6 to 8 s at the 2 s default. Time spent blocked writing a
/// template does not count as silence, because the verifier cannot answer a
/// template it is still receiving; a write that stops moving bytes altogether
/// is failed by `StallGuard` after the same three intervals.
const READ_DEADLINE_BEATS: u32 = 3;

/// A writer that fails a write which has moved no bytes for `stall` (PB-51).
///
/// Without it, a write to a black-holed verifier (a template larger than the
/// kernel's send buffer, which every mainnet `raw_block_hex` is) parks the
/// I/O loop inside that write, where no silence check can run, until TCP gives
/// up. A slow link is not a stall: every byte the peer accepts restarts the
/// clock, so only a write that makes no progress at all is failed. The same
/// idea as the verifier's `IdleTimeout`, which bounds progress in both
/// directions for one budget; this bounds only how long one write may wait,
/// and is a copy of the idea rather than a shared type until a third caller
/// wants it.
struct StallGuard<W> {
    inner: W,
    stall: Duration,
    blocked: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<W> StallGuard<W> {
    fn new(inner: W, stall: Duration) -> Self {
        Self {
            inner,
            stall,
            blocked: None,
        }
    }

    /// The inner writer is not ready: fail once it has been so for `stall`.
    fn poll_stalled(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Error> {
        let stall = self.stall;
        let sleep = self
            .blocked
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        match sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("the verifier accepted no bytes for {stall:?}"),
            )),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for StallGuard<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                this.blocked = None;
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_stalled(cx).map(Err),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(r) => {
                this.blocked = None;
                Poll::Ready(r)
            }
            Poll::Pending => this.poll_stalled(cx).map(Err),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Outcome of a single connection's I/O loop.
enum IoLoopOutcome {
    /// Connection was lost (EOF, error, or TLS failure). Caller should reconnect.
    Disconnected,
    /// Graceful shutdown requested. Caller should exit.
    Shutdown,
}

/// Result of one bounded NDJSON line read (PB-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedLine {
    /// A complete line: newline-terminated within the budget, or a final
    /// unterminated line at EOF that stayed under the budget.
    Line,
    /// Clean EOF with no pending bytes.
    Eof,
    /// The peer spent the whole budget without sending a newline. The
    /// caller drops the connection.
    OverLimit,
}

/// Longest prefix of a rejected line that reaches the log.
///
/// A malformed line is bounded by `MAX_INTERNAL_LINE_BYTES` but that
/// bound is 20 MiB, and the three-strike counter lets a peer spend
/// three of them before the connection drops. Logging the line whole
/// would hand a hostile verifier 60 MiB of log write amplification per
/// connection off 60 MiB of send, which is the same asymmetry PB-23
/// closed on the read side. PB-19 widened this 20x when it raised the
/// line budget from 1 MiB for `raw_block_hex`.
const LOG_SAMPLE_BYTES: usize = 512;

/// Bound a line before it reaches a log field, on a char boundary so
/// the output stays valid UTF-8, marking any truncation so a reader
/// never mistakes a sample for the whole message.
fn log_sample(line: &str) -> std::borrow::Cow<'_, str> {
    if line.len() <= LOG_SAMPLE_BYTES {
        return std::borrow::Cow::Borrowed(line);
    }
    let mut end = LOG_SAMPLE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!(
        "{} (truncated, {} bytes total)",
        &line[..end],
        line.len()
    ))
}

/// Render `value` into at most `LOG_SAMPLE_BYTES`, marking any truncation
/// and keeping the true length, so the output has the same shape
/// `log_sample` gives a borrowed line.
///
/// This exists because capping the `line` field alone left the same
/// amplification open through the sibling field on the same `warn!`.
/// `serde_json::Error`'s `Display` embeds the offending input verbatim:
/// a type mismatch against `InternalMessage::version` on a hostile line
/// renders as `invalid type: string "AAA...", expected u16` carrying the
/// whole value. Measured, a 1,000,042 byte line yields a 1,000,062 byte
/// error message, so the error tracks the line rather than bounding it.
///
/// The value is streamed through a capping sink instead of being
/// rendered with `to_string()` and then cut, so a hostile line never
/// gets a second full-size copy. serde has already paid for the first
/// one inside `from_str`, and that allocation is not ours to avoid.
fn log_display(value: impl std::fmt::Display) -> String {
    use std::fmt::Write as _;

    /// Keeps at most `LOG_SAMPLE_BYTES`, cut on a char boundary, while
    /// counting every byte offered so the true length survives.
    struct Capped {
        kept: String,
        offered: usize,
    }

    impl std::fmt::Write for Capped {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.offered += s.len();
            let mut room = LOG_SAMPLE_BYTES
                .saturating_sub(self.kept.len())
                .min(s.len());
            // Same char-boundary walk as `log_sample`, and load bearing
            // for the same reason: the cut point is attacker-chosen.
            while room > 0 && !s.is_char_boundary(room) {
                room -= 1;
            }
            self.kept.push_str(&s[..room]);
            Ok(())
        }
    }

    let mut sink = Capped {
        kept: String::new(),
        offered: 0,
    };
    // Writing to a String sink cannot fail; a Display impl that returns
    // Err would simply yield the prefix it managed to write.
    let _ = write!(sink, "{value}");
    let Capped { mut kept, offered } = sink;
    if offered > kept.len() {
        let _ = write!(kept, " (truncated, {offered} bytes total)");
    }
    kept
}

/// Read one newline-terminated line into `buf`, enforcing `max_bytes`
/// per line via `AsyncReadExt::take` so a verifier that never sends a
/// newline can never grow the gateway's line buffer without bound
/// (PB-23).
///
/// Cancel-safe (PB-52), which matters because this read is a branch of the
/// I/O loop's `select!`, raced against the heartbeat tick and outbound
/// messages. It used `read_line`, which tokio documents as not cancel-safe:
/// when another branch won mid-line, the bytes already read were lost, the
/// rest of the line then parsed as garbage, and a verdict never reached the
/// gateway. `read_until` appends partial bytes to `buf`, which lives in the
/// loop, so the next call resumes the same line. The budget is charged
/// against `buf.len()` for that reason: a resumed line keeps its budget.
async fn read_bounded_line<R>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: u64,
) -> std::io::Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let already = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    let remaining = max_bytes.saturating_sub(already);
    if remaining == 0 {
        // `take(0)` would report `Ok(0)`, indistinguishable from EOF.
        return Ok(BoundedLine::OverLimit);
    }
    let n = (&mut *reader)
        .take(remaining)
        .read_until(b'\n', buf)
        .await?;
    if n == 0 && buf.is_empty() {
        return Ok(BoundedLine::Eof);
    }
    if u64::try_from(n).unwrap_or(u64::MAX) >= remaining && !buf.ends_with(b"\n") {
        return Ok(BoundedLine::OverLimit);
    }
    Ok(BoundedLine::Line)
}

/// Inner I/O loop that is transport-agnostic. Accepts any `AsyncRead + AsyncWrite`
/// pair, so the same logic serves both plaintext TCP and TLS streams.
#[allow(clippy::too_many_lines)] // One select loop; its arms read top to bottom.
async fn run_io_loop<R, W>(
    reader: R,
    writer: W,
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
    let mut line_buf: Vec<u8> = Vec::new();
    let mut heartbeat_interval = tokio::time::interval(config.heartbeat_interval);
    let read_deadline = config
        .heartbeat_interval
        .saturating_mul(READ_DEADLINE_BEATS);
    let mut writer = StallGuard::new(writer, read_deadline);
    // When the verifier was last heard from, moved later by any time spent
    // blocked writing a template to it (PB-51).
    let mut last_heard = tokio::time::Instant::now();
    // Set when a tick has found the verifier past the deadline and the loop
    // has given the runtime one turn before believing it (PB-51 T2).
    let mut rechecking = false;
    let mut malformed_count: u32 = 0;
    // PB-23: per-line byte budget, shared with the verifier's ingress.
    let max_line_bytes = u64::try_from(MAX_INTERNAL_LINE_BYTES).unwrap_or(u64::MAX);

    loop {
        tokio::select! {
            // Reads first (PB-51 T2): after any stall, a verdict already in
            // the socket must be seen before the silence check on a catch-up
            // tick, or a live verifier is dropped with its answer unread.
            biased;

            result = read_bounded_line(&mut reader, &mut line_buf, max_line_bytes) => {
                match result {
                    Ok(BoundedLine::Eof) => {
                        warn!("verifier connection closed (EOF)");
                        return IoLoopOutcome::Disconnected;
                    }
                    Ok(BoundedLine::OverLimit) => {
                        // PB-23: the read stops at the budget, so the rest of
                        // this line is still unread on the wire. A bounded
                        // reader cannot resync to the next newline without
                        // consuming an unbounded tail, so the previous
                        // skip-then-three-strikes policy would now be a lie:
                        // the next read would return the middle of this line,
                        // not the next message. Drop the connection instead,
                        // matching the verifier ingress (PB-18b). The outer
                        // loop reconnects. The three-strike counter still
                        // governs malformed-but-bounded lines below, where
                        // framing is intact and resync is honest.
                        error!(
                            reason_code = GatewayReason::InternalLineTooLarge.as_str(),
                            max_bytes = MAX_INTERNAL_LINE_BYTES,
                            "verifier line exceeded MAX_INTERNAL_LINE_BYTES without a newline; disconnecting"
                        );
                        return IoLoopOutcome::Disconnected;
                    }
                    Ok(BoundedLine::Line) => {
                        last_heard = tokio::time::Instant::now();
                        // Parsed from the bytes, so invalid UTF-8 anywhere,
                        // including inside a JSON string, is a malformed
                        // strike rather than silently replaced (PB-52 T2).
                        match serde_json::from_slice::<InternalMessage>(line_buf.trim_ascii()) {
                            Ok(msg) => {
                                dispatch_inbound(&msg, verdict_tx, readiness);
                            }
                            Err(e) => {
                                let text = String::from_utf8_lossy(&line_buf);
                                warn!(
                                    error = %log_display(&e),
                                    line = %log_sample(text.trim()),
                                    "malformed verifier message"
                                );
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
                    let writing_since = tokio::time::Instant::now();
                    if let Err(e) = writer.write_all(line.as_bytes()).await {
                        warn!(error = %e, "verifier write error");
                        return IoLoopOutcome::Disconnected;
                    }
                    if let Err(e) = writer.flush().await {
                        warn!(error = %e, "verifier flush error");
                        return IoLoopOutcome::Disconnected;
                    }
                    // The verifier cannot answer while it is still receiving,
                    // so time spent blocked in this write is not its silence.
                    // An instant write excuses nothing, which keeps a small
                    // template from hiding a black hole (PB-51 T2).
                    last_heard = (last_heard + writing_since.elapsed()).min(tokio::time::Instant::now());
                } else {
                    info!("outbound channel closed; shutting down verifier stream");
                    return IoLoopOutcome::Shutdown;
                }
            }

            _ = heartbeat_interval.tick() => {
                // PB-51: a verifier that has sent nothing for several
                // heartbeats is unreachable, whatever the socket says.
                let silent = last_heard.elapsed();
                if silent > read_deadline {
                    if !rechecking {
                        // A stall can leave this task already scheduled by a
                        // tick when a verdict reaches the kernel, and tokio
                        // reports a socket readable only once its driver has
                        // turned. One yield is that turn; the reads-first
                        // order then takes the verdict ahead of the immediate
                        // recheck. A verifier that is gone fails the recheck,
                        // so detection is no slower (PB-51 T2).
                        rechecking = true;
                        heartbeat_interval.reset_immediately();
                        tokio::task::yield_now().await;
                        continue;
                    }
                    warn!(
                        silent_ms = u64::try_from(silent.as_millis()).unwrap_or(u64::MAX),
                        deadline_ms = u64::try_from(read_deadline.as_millis()).unwrap_or(u64::MAX),
                        "verifier sent nothing for {READ_DEADLINE_BEATS} heartbeat intervals; reconnecting"
                    );
                    return IoLoopOutcome::Disconnected;
                }
                rechecking = false;
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
                    if verdict_tx
                        .send(VerifierInbound::TemplateVerdict(verdict))
                        .is_err()
                    {
                        warn!("verdict_tx has no receivers; template verdict dropped");
                    }
                }
                Err(e) => {
                    // Reached with an envelope that parsed: `payload` is a
                    // `Value`, so it accepts anything and the typing failure
                    // lands here carrying the payload in the message. Unlike
                    // the malformed-line path above there is no strike
                    // counter on this one, so a peer can repeat it for the
                    // life of the connection.
                    warn!(error = %log_display(&e), "failed to parse template_verdict payload");
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
            // `msg_type` is a peer-supplied `String` bounded only by the
            // line budget, and this arm has no strike counter either.
            debug!(msg_type = %log_sample(other), "unknown verifier message type; ignoring");
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
    use tokio::io::{AsyncReadExt, ReadBuf};

    // ── PB-23: log write amplification ──

    #[test]
    fn log_sample_passes_short_lines_through_untouched() {
        let line = r#"{"kind":"verdict","id":7}"#;
        assert_eq!(log_sample(line), line);
        // Borrowed, so the common path allocates nothing.
        assert!(matches!(log_sample(line), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn log_sample_caps_a_hostile_line_and_marks_it() {
        // A malformed line may be up to MAX_INTERNAL_LINE_BYTES, and
        // three of them land before the connection drops.
        let line = "x".repeat(MAX_INTERNAL_LINE_BYTES);
        let out = log_sample(&line);
        assert!(
            out.len() < LOG_SAMPLE_BYTES + 64,
            "20 MiB line reached the log as {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"), "truncation must be visible");
        assert!(
            out.contains(&MAX_INTERNAL_LINE_BYTES.to_string()),
            "the real length must survive into the log"
        );
    }

    #[test]
    fn log_sample_truncates_on_a_char_boundary() {
        // A naive `&line[..LOG_SAMPLE_BYTES]` panics when the cap
        // lands mid-codepoint, which an attacker picks deliberately.
        // 3-byte chars mean 512 is never a boundary.
        let line = "\u{4e16}".repeat(MAX_INTERNAL_LINE_BYTES / 3);
        let out = log_sample(&line);
        assert!(out.contains("truncated"));
        assert!(out.len() < LOG_SAMPLE_BYTES + 64);
    }

    #[test]
    fn log_sample_boundary_is_exact() {
        let exact = "y".repeat(LOG_SAMPLE_BYTES);
        assert_eq!(log_sample(&exact), exact, "at the cap, pass through");
        let over = "y".repeat(LOG_SAMPLE_BYTES + 1);
        assert!(
            log_sample(&over).contains("truncated"),
            "one over, truncate"
        );
    }

    /// A line that is valid JSON but fails `InternalMessage` typing, with
    /// `body` landing in the `version` field. `version` is a `u16`, so
    /// serde renders `invalid type: string "<body>", expected u16` and
    /// carries the whole body into the error message.
    fn hostile_typed_line(body: &str) -> String {
        format!(r#"{{"msg_type":"x","version":"{body}","payload":{{}}}}"#)
    }

    #[test]
    fn log_display_passes_short_errors_through_untouched() {
        let e = serde_json::from_str::<InternalMessage>("{").unwrap_err();
        assert_eq!(log_display(&e), e.to_string());
    }

    #[test]
    fn log_display_caps_a_hostile_serde_error() {
        let line = hostile_typed_line(&"A".repeat(1_000_000));
        let e = serde_json::from_str::<InternalMessage>(&line).unwrap_err();

        // The premise: serde does not truncate, so the error tracks the
        // line rather than bounding it. Capping `line` alone left this
        // open through the sibling field on the same `warn!`.
        let uncapped = e.to_string().len();
        assert!(
            uncapped > 1_000_000,
            "expected the error to carry the line, got {uncapped} bytes"
        );

        let out = log_display(&e);
        assert!(
            out.len() < LOG_SAMPLE_BYTES + 64,
            "error field reached the log as {} bytes",
            out.len()
        );
        assert!(out.contains("truncated"), "truncation must be visible");
        assert!(
            out.contains(&uncapped.to_string()),
            "the real length must survive into the log"
        );
    }

    #[test]
    fn log_display_truncates_on_a_char_boundary() {
        // 3-byte chars, so the 512 cap never lands on a boundary. A naive
        // slice here panics, remotely triggerable on attacker-chosen input.
        let line = hostile_typed_line(&"\u{4e16}".repeat(400_000));
        let e = serde_json::from_str::<InternalMessage>(&line).unwrap_err();
        let out = log_display(&e);
        assert!(out.contains("truncated"));
        assert!(out.len() < LOG_SAMPLE_BYTES + 64);
    }

    /// Sink that collects everything a `tracing` subscriber writes, so a
    /// test can assert on the bytes that actually reach a log rather than
    /// on the capping helpers called in isolation.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn hostile_inbound_lines_emit_bounded_log_records() {
        // The claim PB-23's log half actually needs to make, asserted on
        // the emitted records and through the real `run_io_loop`: a
        // hostile line must not buy log write amplification through ANY
        // field of the record it triggers, on ANY inbound path. Testing
        // `log_sample` alone covered one field of one of these three.
        let big = "A".repeat(1_000_000);

        // 1. Fails `InternalMessage` typing. Three-strike counter applies,
        //    and the whole line reaches `error` as well as `line`.
        let malformed = hostile_typed_line(&big);
        // 2. Envelope parses, `TemplateVerdict` typing fails on the
        //    payload. No strike counter on this path.
        let bad_payload =
            format!(r#"{{"msg_type":"template_verdict","version":1,"payload":{{"id":"{big}"}}}}"#);
        // 3. Envelope parses, `msg_type` itself is the hostile string.
        //    No strike counter on this path either.
        let unknown_type = format!(r#"{{"msg_type":"{big}","version":1,"payload":{{}}}}"#);

        let stream = format!("{malformed}\n{bad_payload}\n{unknown_type}\n");
        let sent = stream.len();

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            // The unknown-type arm logs at DEBUG, so the default INFO
            // filter would hide it and the assertion would pass vacuously.
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        {
            let _guard = tracing::subscriber::set_default(subscriber);
            let (outcome, received) = drive_io_loop(stream.as_bytes()).await;
            // One malformed line is under the three-strike threshold and
            // the other two parse as envelopes, so the loop reads on and
            // leaves through EOF. The strike policy is unchanged here.
            assert!(matches!(outcome, IoLoopOutcome::Disconnected));
            assert!(received.is_empty(), "nothing should have been dispatched");
        }

        let emitted = captured.0.lock().unwrap().len();
        assert!(
            emitted < 8192,
            "{sent} bytes of hostile input produced {emitted} bytes of \
             log; every peer-controlled field must be capped at \
             {LOG_SAMPLE_BYTES}"
        );
    }

    // ── PB-23 harness ──

    /// Reader that emits `remaining` newline-free bytes and then EOF,
    /// counting every byte it actually hands the caller. That counter is
    /// the PB-23 measurement: how much of a hostile line the gateway pulls
    /// into memory before the per-line budget stops it. Asserting on an
    /// eventual error would not distinguish "rejected the line" from
    /// "buffered 24 MiB and then rejected the line".
    struct CountingReader {
        remaining: usize,
        delivered: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            let chunk = [b'a'; 8192];
            let n = buf.remaining().min(me.remaining).min(chunk.len());
            if n == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            buf.put_slice(&chunk[..n]);
            me.remaining -= n;
            me.delivered.fetch_add(n, AtomicOrdering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    /// Drive one connection's I/O loop over `reader` to completion and
    /// collect everything it dispatched. The heartbeat interval is set an
    /// hour out so the only traffic is what the test feeds in.
    async fn drive_io_loop<R>(reader: R) -> (IoLoopOutcome, Vec<VerifierInbound>)
    where
        R: AsyncRead + Unpin,
    {
        // Both senders must stay alive: dropping either would make the
        // loop exit through its shutdown path instead of the read path.
        let (_outbound_tx, mut outbound_rx) = mpsc::channel::<VerifierOutbound>(4);
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (verdict_tx, mut verdict_rx) = broadcast::channel(64);
        let readiness = ReadinessState::new();
        let config = VerifierStreamConfig {
            addr: "test".to_string(),
            reconnect_delay: Duration::from_millis(1),
            heartbeat_interval: Duration::from_secs(3600),
            health_probe_staleness_ms: 1000,
            tls_config: None,
        };

        let outcome = run_io_loop(
            reader,
            tokio::io::sink(),
            &mut outbound_rx,
            &verdict_tx,
            &readiness,
            &config,
            &mut shutdown,
        )
        .await;

        let mut received = Vec::new();
        while let Ok(msg) = verdict_rx.try_recv() {
            received.push(msg);
        }
        (outcome, received)
    }

    /// One NDJSON `heartbeat_ack` line.
    fn heartbeat_ack_line() -> String {
        let msg = InternalMessage {
            msg_type: msg_types::HEARTBEAT_ACK.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::json!({}),
        };
        format!("{}\n", serde_json::to_string(&msg).unwrap())
    }

    /// One NDJSON `template_verdict` line carrying `detail` bytes of
    /// human-readable detail.
    fn verdict_line(id: u64, detail: &str) -> String {
        let verdict = TemplateVerdict {
            version: PROTOCOL_VERSION,
            id,
            accepted: false,
            reason_code: None,
            reason_detail: Some(detail.to_string()),
            policy_context: None,
        };
        let msg = InternalMessage {
            msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
            version: PROTOCOL_VERSION,
            payload: serde_json::to_value(&verdict).unwrap(),
        };
        format!("{}\n", serde_json::to_string(&msg).unwrap())
    }

    /// A `template_propose` line carrying a mainnet-sized `raw_block_hex`:
    /// 8 MiB of hex, the worst case a 4,000,000 WU block serializes to.
    /// This is the reason `MAX_INTERNAL_LINE_BYTES` is 20 MiB and not 1 MiB.
    fn mainnet_propose_line() -> String {
        let tp = TemplatePropose {
            version: PROTOCOL_VERSION,
            id: 1,
            block_height: 800_000,
            prev_hash: "aa".repeat(32),
            coinbase_value: 625_000_000,
            tx_count: 3000,
            total_fees: 50_000_000,
            observed_weight: Some(3_900_000),
            created_at_unix_ms: Some(1_700_000_000_000),
            total_sigops: Some(10000),
            coinbase_sigops: Some(4),
            template_weight: Some(3_950_000),
            gateway_instance_id: Some("test-gw-01".to_string()),
            raw_block_hex: Some("ab".repeat(4 * 1024 * 1024)),
        };
        serialize_outbound(&VerifierOutbound::TemplatePropose(tp)).unwrap()
    }

    fn verdict_ids(received: &[VerifierInbound]) -> Vec<u64> {
        received
            .iter()
            .filter_map(|m| match m {
                VerifierInbound::TemplateVerdict(v) => Some(v.id),
                VerifierInbound::HeartbeatAck => None,
            })
            .collect()
    }

    /// PB-52: a heartbeat tick that lands while a verdict line is half
    /// received must not cost the verdict. The read races the heartbeat and
    /// outbound arms in one `select!`, and `read_line` is not cancel-safe:
    /// tokio's own docs say the partially read data "is lost".
    #[tokio::test]
    async fn a_heartbeat_tick_mid_line_does_not_cost_the_verdict() {
        let (mut verifier_side, gateway_side) = tokio::io::duplex(64 * 1024);
        let first = verdict_line(1, "split across a heartbeat");
        let second = verdict_line(2, "whole");
        let feeder = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            let (head, tail) = first.split_at(first.len() / 2);
            verifier_side.write_all(head.as_bytes()).await.unwrap();
            // Two 50 ms heartbeat ticks fire before the rest arrives, and
            // 120 ms stays inside PB-51's three-beat read deadline (150 ms).
            tokio::time::sleep(Duration::from_millis(120)).await;
            verifier_side.write_all(tail.as_bytes()).await.unwrap();
            verifier_side.write_all(second.as_bytes()).await.unwrap();
            // Closing the verifier side ends the loop with EOF.
        });
        let (outcome, received) = drive_with(
            gateway_side,
            tokio::io::sink(),
            Duration::from_millis(50),
            |_| {},
        )
        .await;
        feeder.await.unwrap();
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert_eq!(
            verdict_ids(&received),
            vec![1, 2],
            "a verdict split across a heartbeat tick was lost"
        );
    }

    /// PB-51: a verifier that goes silent, socket open, is dropped after
    /// `READ_DEADLINE_BEATS` heartbeat intervals so the outer loop reconnects.
    /// It used to be waited on forever. Paused time pins the moment: the
    /// fourth tick is the first past the deadline, and its recheck (PB-51 T2)
    /// drops at once rather than a heartbeat later.
    #[tokio::test(start_paused = true)]
    async fn a_silent_verifier_is_dropped_after_three_heartbeats() {
        let (verifier_side, gateway_side) = tokio::io::duplex(64 * 1024);
        let start = tokio::time::Instant::now();
        let (outcome, _) = tokio::time::timeout(
            Duration::from_secs(5),
            drive_with(
                gateway_side,
                tokio::io::sink(),
                Duration::from_millis(30),
                |_| {},
            ),
        )
        .await
        .expect("a silent verifier was waited on forever");
        let took = start.elapsed();
        drop(verifier_side);
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(
            took >= Duration::from_millis(90),
            "dropped after {took:?}, before three 30 ms heartbeats had passed"
        );
        assert!(
            took <= Duration::from_millis(120),
            "dropped after {took:?}; the recheck waited for another heartbeat"
        );
    }

    /// PB-51, the other side: a verifier that keeps answering is never
    /// dropped, however long the connection lives.
    #[tokio::test]
    async fn a_verifier_that_answers_is_never_dropped() {
        let (mut verifier_side, gateway_side) = tokio::io::duplex(64 * 1024);
        let feeder = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt as _;
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                verifier_side
                    .write_all(heartbeat_ack_line().as_bytes())
                    .await
                    .unwrap();
            }
        });
        let (outcome, received) = drive_with(
            gateway_side,
            tokio::io::sink(),
            Duration::from_millis(30),
            |_| {},
        )
        .await;
        feeder.await.unwrap();
        assert!(
            matches!(outcome, IoLoopOutcome::Disconnected),
            "ends on EOF"
        );
        let acks = received
            .iter()
            .filter(|m| matches!(m, VerifierInbound::HeartbeatAck))
            .count();
        assert_eq!(acks, 20, "dropped before the verifier stopped answering");
    }

    /// A propose whose `raw_block_hex` makes it `bytes` long on the wire.
    fn propose_of(id: u64, bytes: usize) -> VerifierOutbound {
        VerifierOutbound::TemplatePropose(TemplatePropose {
            version: PROTOCOL_VERSION,
            id,
            block_height: 800_000,
            prev_hash: "a".repeat(64),
            coinbase_value: 312_500_000,
            tx_count: 1,
            total_fees: 0,
            observed_weight: None,
            created_at_unix_ms: None,
            total_sigops: None,
            coinbase_sigops: None,
            template_weight: None,
            gateway_instance_id: None,
            raw_block_hex: Some("0".repeat(bytes)),
        })
    }

    /// Drive the loop with a chosen writer and heartbeat; `feed` gets a
    /// clone of the outbound sender to queue proposes as the gateway's main
    /// loop would. The original is held until the loop returns, as the main
    /// loop holds it, so a closed channel cannot end the loop first.
    async fn drive_with<R, W>(
        reader: R,
        writer: W,
        heartbeat: Duration,
        feed: impl FnOnce(mpsc::Sender<VerifierOutbound>),
    ) -> (IoLoopOutcome, Vec<VerifierInbound>)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<VerifierOutbound>(64);
        feed(outbound_tx.clone());
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let (verdict_tx, mut verdict_rx) = broadcast::channel(256);
        let readiness = ReadinessState::new();
        let config = VerifierStreamConfig {
            addr: "test".to_string(),
            reconnect_delay: Duration::from_millis(1),
            heartbeat_interval: heartbeat,
            health_probe_staleness_ms: 1000,
            tls_config: None,
        };
        let outcome = run_io_loop(
            reader,
            writer,
            &mut outbound_rx,
            &verdict_tx,
            &readiness,
            &config,
            &mut shutdown,
        )
        .await;
        drop(outbound_tx);
        let mut received = Vec::new();
        while let Ok(msg) = verdict_rx.try_recv() {
            received.push(msg);
        }
        (outcome, received)
    }

    /// Accepts `cap` bytes, then never again: a peer behind a black hole once
    /// the kernel's send buffer is full.
    struct BlackHole {
        cap: usize,
    }

    impl AsyncWrite for BlackHole {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.cap == 0 {
                return Poll::Pending;
            }
            let n = buf.len().min(this.cap);
            this.cap -= n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Passes at most `chunk` bytes every `every` to `inner`: a live verifier
    /// on a slow link.
    struct SlowLink<W> {
        inner: W,
        chunk: usize,
        every: Duration,
        next: Pin<Box<tokio::time::Sleep>>,
    }

    impl<W: AsyncWrite + Unpin> AsyncWrite for SlowLink<W> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.next.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let n = buf.len().min(this.chunk);
            let written = Pin::new(&mut this.inner).poll_write(cx, &buf[..n]);
            if written.is_ready() {
                let every = this.every;
                this.next
                    .as_mut()
                    .reset(tokio::time::Instant::now() + every);
            }
            written
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// PB-51 T2 blocker: a black-holed verifier with a template in flight.
    /// The write parks once the send buffer is full, and the silence check
    /// on the heartbeat arm cannot run while the loop sits in the write, so
    /// the stall itself has to end it.
    #[tokio::test]
    async fn a_black_hole_with_a_template_in_flight_is_dropped() {
        let (_verifier_side, gateway_side) = tokio::io::duplex(64 * 1024);
        let start = tokio::time::Instant::now();
        let (outcome, _) = tokio::time::timeout(
            Duration::from_secs(3),
            drive_with(
                gateway_side,
                BlackHole { cap: 64 * 1024 },
                Duration::from_millis(30),
                |tx| {
                    tx.try_send(propose_of(1, 1024 * 1024)).unwrap();
                },
            ),
        )
        .await
        .expect("a black hole with a template in flight was waited on forever");
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// PB-51 T2: a live verifier on a slow link is not silent while it is
    /// receiving a template, and must not be dropped for it. The verifier
    /// here behaves as the real one does: it says nothing until the whole
    /// template has arrived, then answers it and the heartbeats after it.
    /// The first cut counted the write's duration as silence, so the first
    /// tick after the write dropped it with the verdict unread.
    #[tokio::test]
    async fn a_live_verifier_on_a_slow_link_is_not_dropped() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
        let (verifier_in, gateway_out) = tokio::io::duplex(64 * 1024);
        let (mut verifier_out, gateway_in) = tokio::io::duplex(64 * 1024);
        let verifier = tokio::spawn(async move {
            let mut lines = BufReader::new(verifier_in);
            let mut line = Vec::new();
            lines.read_until(b'\n', &mut line).await.unwrap();
            assert!(line.len() > 1024 * 1024, "the template arrives first");
            tokio::time::sleep(Duration::from_millis(20)).await;
            verifier_out
                .write_all(verdict_line(7, "after a slow write").as_bytes())
                .await
                .unwrap();
            for _ in 0..5 {
                line.clear();
                lines.read_until(b'\n', &mut line).await.unwrap();
                verifier_out
                    .write_all(heartbeat_ack_line().as_bytes())
                    .await
                    .unwrap();
            }
        });
        let slow = SlowLink {
            inner: gateway_out,
            chunk: 16 * 1024,
            every: Duration::from_millis(10),
            next: Box::pin(tokio::time::sleep(Duration::ZERO)),
        };
        let (outcome, received) = drive_with(gateway_in, slow, Duration::from_millis(50), |tx| {
            tx.try_send(propose_of(7, 1024 * 1024)).unwrap();
        })
        .await;
        verifier.await.unwrap();
        assert!(
            matches!(outcome, IoLoopOutcome::Disconnected),
            "ends when the verifier hangs up"
        );
        assert_eq!(
            verdict_ids(&received),
            vec![7],
            "the verifier was dropped during or after a slow write"
        );
    }

    /// PB-51 T2: small templates written instantly into a black hole must not
    /// hide it. Only time actually spent blocked in a write is excused.
    #[tokio::test]
    async fn small_templates_do_not_hide_a_black_hole() {
        let (_verifier_side, gateway_side) = tokio::io::duplex(64 * 1024);
        let (outcome, _) = tokio::time::timeout(
            Duration::from_secs(3),
            drive_with(
                gateway_side,
                tokio::io::sink(),
                Duration::from_millis(30),
                |tx| {
                    tokio::spawn(async move {
                        for id in 0.. {
                            if tx.send(propose_of(id, 64)).await.is_err() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    });
                },
            ),
        )
        .await
        .expect("small instant writes hid a silent verifier");
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
    }

    /// PB-51 T2: when the loop resumes after a stall past the deadline, a
    /// verdict already waiting in the socket is read before a catch-up tick
    /// can drop the connection. Unbiased, the reviewer's probe lost it 37
    /// times in 60.
    ///
    /// Real sockets, because an in-memory duplex wakes the reader the moment
    /// it is written, which no TCP socket does. The stall is the runtime
    /// thread blocked, as a starved gateway's is. With reads first and no
    /// recheck this still lost the verdict about once in 60 trials: the case
    /// the next test pins down deterministically.
    #[tokio::test]
    async fn a_verdict_already_waiting_beats_the_silence_check() {
        use std::io::Write as _;
        for trial in 0..20 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let mut verifier =
                std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            accepted.set_nonblocking(true).unwrap();
            let (gateway_in, _gateway_out) = tokio::net::TcpStream::from_std(accepted)
                .unwrap()
                .into_split();
            let run = tokio::spawn(drive_with(
                gateway_in,
                tokio::io::sink(),
                Duration::from_millis(20),
                |_| {},
            ));
            tokio::task::yield_now().await;
            verifier
                .write_all(verdict_line(trial, "waiting").as_bytes())
                .unwrap();
            // Past the 60 ms deadline with the loop unable to run.
            std::thread::sleep(Duration::from_millis(80));
            drop(verifier);
            let (_, received) = run.await.unwrap();
            assert_eq!(
                verdict_ids(&received),
                vec![trial],
                "trial {trial}: the silence check ran before a waiting verdict was read"
            );
        }
    }

    /// A socket whose line has reached the kernel but not the runtime. Once
    /// `arrived` is set, the first poll returns `Pending` and asks to be
    /// polled again, as tokio does until its driver has recorded the
    /// readiness; later polls return the line, then EOF.
    struct UnseenReadiness {
        arrived: Arc<AtomicBool>,
        seen: bool,
        line: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for UnseenReadiness {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if !this.arrived.load(AtomicOrdering::SeqCst) {
                // Nothing yet; the loop's ticks keep it polled.
                return Poll::Pending;
            }
            if !this.seen {
                this.seen = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = buf.remaining().min(this.line.len() - this.pos);
            buf.put_slice(&this.line[this.pos..this.pos + n]);
            this.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// PB-51 T2: the case reads-first alone does not cover. A tick schedules
    /// the loop, the runtime stalls past the deadline, and a verdict reaches
    /// the kernel meanwhile; when the loop runs, the tick is ready and the
    /// socket is not yet. The recheck gives the runtime one turn to see it.
    /// Paused time, so every trial takes exactly this path.
    #[tokio::test(start_paused = true)]
    async fn a_verdict_the_runtime_has_not_yet_seen_beats_the_silence_check() {
        for trial in 0..30 {
            let arrived = Arc::new(AtomicBool::new(false));
            let reader = UnseenReadiness {
                arrived: Arc::clone(&arrived),
                seen: false,
                line: verdict_line(trial, "unseen").into_bytes(),
                pos: 0,
            };
            let run = tokio::spawn(drive_with(
                reader,
                tokio::io::sink(),
                Duration::from_millis(20),
                |_| {},
            ));
            // The loop starts, and its first tick is armed.
            tokio::task::yield_now().await;
            arrived.store(true, AtomicOrdering::SeqCst);
            // The stall: the clock passes the 60 ms deadline before the loop,
            // already scheduled by that tick, runs again.
            tokio::time::advance(Duration::from_millis(100)).await;
            let (_, received) = run.await.unwrap();
            assert_eq!(
                verdict_ids(&received),
                vec![trial],
                "trial {trial}: a verdict the runtime had not yet seen was counted as silence"
            );
        }
    }

    /// PB-52 T2: invalid UTF-8 inside a JSON string is a malformed line, not
    /// replacement characters dispatched as a verdict.
    #[tokio::test]
    async fn invalid_utf8_inside_a_verdict_is_struck_not_rewritten() {
        let mut bytes = Vec::new();
        for id in 0..3 {
            let line = verdict_line(id, "@@").into_bytes();
            let at = line.windows(2).position(|w| w == b"@@").unwrap();
            bytes.extend_from_slice(&line[..at]);
            bytes.extend_from_slice(&[0xFF, 0xFE]);
            bytes.extend_from_slice(&line[at + 2..]);
        }
        let (outcome, received) = drive_io_loop(bytes.as_slice()).await;
        assert!(
            matches!(outcome, IoLoopOutcome::Disconnected),
            "three strikes"
        );
        assert!(
            received.is_empty(),
            "invalid UTF-8 was rewritten and dispatched: {received:?}"
        );
    }

    // ── PB-23: the read must be bounded before the allocation, not after ──

    #[tokio::test]
    async fn oversize_line_is_not_pulled_past_the_budget() {
        // A verifier (hostile or broken) that never sends a newline. The
        // gateway must stop pulling at MAX_INTERNAL_LINE_BYTES. The old
        // read_line call pulled all 24 MiB and only then compared n to the
        // constant, so the bound was enforced after the allocation it
        // exists to prevent.
        let sent = MAX_INTERNAL_LINE_BYTES + 4 * 1024 * 1024;
        let delivered = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: sent,
            delivered: Arc::clone(&delivered),
        };

        let (outcome, received) = drive_io_loop(reader).await;
        let pulled = delivered.load(AtomicOrdering::SeqCst);

        // Slack of one BufReader refill (8 KiB capacity): `take` truncates
        // the slice it hands out, but the inner BufReader may already have
        // filled its buffer past the cut. 64 KiB covers that generously
        // and still fails loudly on a 24 MiB pull.
        assert!(
            pulled <= MAX_INTERNAL_LINE_BYTES + 64 * 1024,
            "pulled {pulled} bytes into memory for a single line; \
             budget is {MAX_INTERNAL_LINE_BYTES}, peer sent {sent}"
        );
        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(received.is_empty(), "nothing should have been dispatched");
    }

    #[tokio::test]
    async fn oversize_line_drops_the_connection_immediately() {
        // Deliberate policy change (PB-23). Once the read is bounded the
        // rest of the oversize line is still unread on the wire, so the old
        // "skip it and disconnect on the third" path could not honestly
        // resume at the next message. The connection drops on the first
        // oversize line, so the following well-formed heartbeat_ack is
        // never dispatched. Under the unbounded read it was.
        let tail = format!("\n{}", heartbeat_ack_line());
        let delivered = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            remaining: MAX_INTERNAL_LINE_BYTES + 4 * 1024 * 1024,
            delivered,
        }
        .chain(tail.as_bytes());

        let (outcome, received) = drive_io_loop(reader).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(
            received.is_empty(),
            "an oversize line must end the connection, not be skipped: got {received:?}"
        );
    }

    #[tokio::test]
    async fn read_bounded_line_keeps_the_buffer_within_budget() {
        // Unit-level mirror of the pool-verifier test: 200 newline-free
        // bytes against a 64-byte budget.
        let data = vec![b'a'; 200];
        let mut reader = BufReader::new(data.as_slice());
        let mut buf = Vec::new();
        let r = read_bounded_line(&mut reader, &mut buf, 64).await.unwrap();
        assert_eq!(r, BoundedLine::OverLimit);
        assert!(
            buf.len() <= 64,
            "buffer must stay within budget, got {} bytes",
            buf.len()
        );
    }

    #[tokio::test]
    async fn read_bounded_line_accepts_an_exact_budget_line() {
        // An 8-byte line whose final byte is the newline fits an 8-byte
        // budget exactly; the next call reports EOF.
        let data: &[u8] = b"1234567\n";
        let mut reader = BufReader::new(data);
        let mut buf = Vec::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::Line
        );
        assert_eq!(buf, b"1234567\n");
        buf.clear();
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::Eof
        );
    }

    #[tokio::test]
    async fn read_bounded_line_charges_the_budget_against_a_dirty_buffer() {
        // The budget covers the whole line, not one call: a buffer that
        // already holds the budget's worth of a newline-free line is over
        // the limit before any further read.
        let data: &[u8] = b"more bytes\n";
        let mut reader = BufReader::new(data);
        let mut buf = b"a".repeat(8);
        assert_eq!(
            read_bounded_line(&mut reader, &mut buf, 8).await.unwrap(),
            BoundedLine::OverLimit
        );
        assert_eq!(buf.len(), 8, "no further bytes may be appended");
    }

    // ── PB-23: what must NOT regress ──

    #[tokio::test]
    async fn mainnet_sized_raw_block_hex_lines_round_trip() {
        // Three consecutive 8 MiB-payload lines prove the budget resets per
        // line rather than accumulating across the connection, and that a
        // legitimate mainnet block never trips the bound. The trailing
        // heartbeat_ack is the witness: it only arrives if all three big
        // lines were consumed whole.
        let big = mainnet_propose_line();
        assert!(
            big.len() < MAX_INTERNAL_LINE_BYTES,
            "mainnet propose line is {} bytes, budget is {MAX_INTERNAL_LINE_BYTES}",
            big.len()
        );
        let mut stream = String::new();
        for _ in 0..3 {
            stream.push_str(&big);
        }
        stream.push_str(&heartbeat_ack_line());

        let (outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected)); // EOF
        assert_eq!(received.len(), 1, "expected the trailing heartbeat_ack");
        assert!(matches!(received[0], VerifierInbound::HeartbeatAck));
    }

    #[tokio::test]
    async fn multi_megabyte_verdict_line_survives_intact() {
        // Content preservation, not just "did not error": a 9 MiB verdict
        // line must arrive with every byte of its detail.
        let detail = "d".repeat(9 * 1024 * 1024);
        let stream = verdict_line(77, &detail);

        let (_outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert_eq!(received.len(), 1);
        match &received[0] {
            VerifierInbound::TemplateVerdict(v) => {
                assert_eq!(v.id, 77);
                assert_eq!(v.reason_detail.as_deref().map(str::len), Some(detail.len()));
            }
            VerifierInbound::HeartbeatAck => panic!("expected TemplateVerdict"),
        }
    }

    #[tokio::test]
    async fn two_malformed_lines_do_not_disconnect() {
        // The three-strike policy for malformed-but-bounded lines is
        // untouched by PB-23.
        let stream = format!("not json\n{{\"nope\":1}}\n{}", heartbeat_ack_line());

        let (_outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert_eq!(received.len(), 1, "the ack after two strikes must arrive");
        assert!(matches!(received[0], VerifierInbound::HeartbeatAck));
    }

    #[tokio::test]
    async fn three_malformed_lines_disconnect_on_the_third() {
        let stream = format!("not json\nstill not\nnope\n{}", heartbeat_ack_line());

        let (outcome, received) = drive_io_loop(stream.as_bytes()).await;

        assert!(matches!(outcome, IoLoopOutcome::Disconnected));
        assert!(
            received.is_empty(),
            "the third strike must disconnect before the ack is read"
        );
    }

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
            raw_block_hex: None,
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
