//! Per-connection SV2 session handler.
//!
//! After the Noise NX handshake completes (in `accept_loop`), each TCP
//! connection is handed off to [`run_connection`] which drives the full
//! SV2 session lifecycle:
//!
//! 1. `SetupConnection` exchange (validate protocol version 2 + flags).
//! 2. Channel open (`OpenStandardMiningChannel` -> auth check -> allocate
//!    `channel_id` + extranonce -> Success + `SetTarget` + initial `NewMiningJob`;
//!    reject Extended channels with close).
//! 3. Steady-state `select!` loop:
//!    - `job_rx` broadcast: distribute `NewMiningJob` + optional `SetNewPrevHash`
//!    - `transport.read_frame()`: handle `SubmitSharesStandard`,
//!      `OpenStandardMiningChannel` (additional channels), `CloseChannel`
//!    - Shutdown signal -> drain and disconnect.
//! 4. `DisconnectEvent` emission with telemetry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reservegrid_common::reason::GatewayReason;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

use crate::channels::{
    ChannelIdAllocator, ConnectionChannels, ExtranonceAllocator, SharedChannelRegistry,
    snapshot_from_open,
};
use crate::connection::{DisconnectEvent, PeerState};
use crate::jobs::JobTable;
use crate::shares::{
    self, ShareAcceptedEvent, ShareDedupSet, ShareSubmission, check_ntime_bounds,
    check_version_bits, compute_event_id, compute_gateway_signature, compute_share_id,
    current_unix_timestamp, header_identity_bytes, unix_ms_now, validate_share_pow,
};
use crate::sv2_codec::{
    self, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};
use crate::transport::{Sv2FrameHeader, Sv2Transport};

// ─────────────────────────────────────────────────────────────────────
// Job broadcast payload
// ─────────────────────────────────────────────────────────────────────

/// Payload broadcast from the main event loop to all connection handlers
/// when a verified job is ready for distribution.
#[derive(Debug, Clone)]
pub struct JobBroadcast {
    /// The gateway-assigned job ID.
    pub job_id: u32,
    /// Block version (with BIP 320 GP bits set as desired).
    pub version: u32,
    /// Coinbase transaction prefix (before extranonce).
    pub coinbase_tx_prefix: Vec<u8>,
    /// Coinbase transaction suffix (after extranonce).
    pub coinbase_tx_suffix: Vec<u8>,
    /// Merkle path: sibling hashes from coinbase leaf to root.
    pub merkle_path: Vec<[u8; 32]>,
    /// If `Some`, this job is tied to a new prevhash and the handler must
    /// also send `SetNewPrevHash`.
    pub prevhash_update: Option<PrevhashUpdate>,
    /// When `Some`, this is an intra-block refresh (same prevhash, new job)
    /// and `min_ntime` should be set on the `NewMiningJob`.
    pub min_ntime: Option<u32>,
}

/// Prevhash change accompanying a job broadcast.
#[derive(Debug, Clone)]
pub struct PrevhashUpdate {
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
}

// ─────────────────────────────────────────────────────────────────────
// Handler errors
// ─────────────────────────────────────────────────────────────────────

/// Reasons a connection handler terminates.
#[derive(Debug)]
pub enum HandlerExit {
    /// Peer sent invalid `SetupConnection`.
    SetupRejected(String),
    /// Peer closed the connection or transport error.
    TransportError(crate::transport::TransportError),
    /// Gateway is shutting down.
    Shutdown,
    /// Peer did not open any channel within the timeout.
    ChannelOpenTimeout,
    /// Codec error decoding a message.
    CodecError(sv2_codec::Sv2CodecError),
}

impl std::fmt::Display for HandlerExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerExit::SetupRejected(s) => write!(f, "setup rejected: {s}"),
            HandlerExit::TransportError(e) => write!(f, "transport: {e}"),
            HandlerExit::Shutdown => write!(f, "shutdown"),
            HandlerExit::ChannelOpenTimeout => write!(f, "channel open timeout"),
            HandlerExit::CodecError(e) => write!(f, "codec: {e}"),
        }
    }
}

impl HandlerExit {
    /// Map this exit reason to a canonical `GatewayReason` for disconnect telemetry.
    pub fn as_gateway_reason(&self) -> GatewayReason {
        match self {
            HandlerExit::SetupRejected(_) => GatewayReason::SetupConnectionRejected,
            HandlerExit::TransportError(_) => GatewayReason::PeerTransportError,
            HandlerExit::Shutdown => GatewayReason::ShutdownDrain,
            HandlerExit::ChannelOpenTimeout => GatewayReason::ChannelOpenTimeout,
            HandlerExit::CodecError(_) => GatewayReason::FrameDecodeError,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Connection handler
// ─────────────────────────────────────────────────────────────────────

/// Configuration for a single connection handler.
pub struct HandlerConfig {
    /// Maximum standard mining channels per connection.
    pub max_channels_per_conn: u32,
    /// Share acceptance target for new channels (static difficulty V1.0.0).
    pub channel_target: [u8; 32],
    /// Timeout for the initial channel open after `SetupConnection`.
    pub channel_open_timeout: Duration,
    /// Ntime elapsed slack in seconds (absorbs network latency).
    pub ntime_elapsed_slack_seconds: u32,
    /// Max future block time in seconds (Bitcoin consensus default 7200).
    pub max_future_block_time_seconds: u32,
    /// Share deduplication window size (inline mode replay detection).
    pub share_dedup_window_size: usize,
    /// Maximum share submissions per second per channel. 0 means unlimited.
    pub max_shares_per_second_per_channel: u32,
    /// Gateway instance identifier embedded in share submissions.
    pub gateway_instance_id: String,
    /// HMAC secret bytes for signing share event IDs. Empty disables signing.
    pub share_hmac_secret: Vec<u8>,
}

/// All resources needed to run a single connection handler.
pub struct ConnectionContext {
    pub transport: Sv2Transport,
    pub peer: SocketAddr,
    pub config: Arc<HandlerConfig>,
    pub channel_id_alloc: Arc<ChannelIdAllocator>,
    pub extranonce_alloc: Arc<ExtranonceAllocator>,
    pub job_table: Arc<tokio::sync::RwLock<JobTable>>,
    pub latest_job: Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    pub job_rx: broadcast::Receiver<Arc<JobBroadcast>>,
    pub share_event_tx: mpsc::Sender<ShareAcceptedEvent>,
    pub share_forward_tx: mpsc::Sender<ShareSubmission>,
    pub shutdown: watch::Receiver<bool>,
    pub permit: tokio::sync::OwnedSemaphorePermit,
    pub channel_registry: SharedChannelRegistry,
}

/// Run the full SV2 session lifecycle for one connection.
///
/// This function is spawned as an async task per accepted TCP connection,
/// after the Noise NX handshake has already completed. On every exit path
/// a structured `DisconnectEvent` is emitted for observability.
pub async fn run_connection(ctx: ConnectionContext) -> HandlerExit {
    let ConnectionContext {
        mut transport,
        peer,
        config,
        channel_id_alloc,
        extranonce_alloc,
        job_table,
        latest_job,
        mut job_rx,
        share_event_tx,
        share_forward_tx,
        mut shutdown,
        permit: _permit,
        channel_registry,
    } = ctx;
    let peer_state = PeerState::new(peer);
    let mut share_dedup = ShareDedupSet::new(config.share_dedup_window_size);

    let (exit, opened_channel_ids) = run_connection_inner(
        &mut transport,
        peer,
        &peer_state,
        &config,
        &channel_id_alloc,
        &extranonce_alloc,
        &job_table,
        &latest_job,
        &mut job_rx,
        &share_event_tx,
        &share_forward_tx,
        &mut shutdown,
        &mut share_dedup,
        &channel_registry,
    )
    .await;

    // Unregister all channels that were opened on this connection.
    for ch_id in opened_channel_ids {
        channel_registry.unregister(ch_id).await;
    }

    // Emit structured disconnect event for every exit path.
    let reason = exit.as_gateway_reason();
    peer_state.set_disconnect_reason(reason);
    DisconnectEvent::from_peer(&peer_state, reason).log();

    exit
}

/// Inner session lifecycle, extracted so `run_connection` can unconditionally
/// emit a `DisconnectEvent` after this returns.
///
/// Returns the handler exit reason and a list of channel IDs that were opened
/// during this connection (for global registry cleanup).
#[allow(clippy::too_many_arguments)]
async fn run_connection_inner(
    transport: &mut Sv2Transport,
    peer: SocketAddr,
    peer_state: &PeerState,
    config: &Arc<HandlerConfig>,
    channel_id_alloc: &Arc<ChannelIdAllocator>,
    extranonce_alloc: &Arc<ExtranonceAllocator>,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    job_rx: &mut broadcast::Receiver<Arc<JobBroadcast>>,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    shutdown: &mut watch::Receiver<bool>,
    share_dedup: &mut ShareDedupSet,
    channel_registry: &SharedChannelRegistry,
) -> (HandlerExit, Vec<u32>) {
    let mut opened_ids: Vec<u32> = Vec::new();

    // ── Stage 1: SetupConnection ──
    let setup_result = handle_setup_connection(transport, peer_state).await;
    if let Err(exit) = setup_result {
        return (exit, opened_ids);
    }

    // ── Stage 2+3: Channel open + steady-state loop ──
    let mut channels = ConnectionChannels::new(config.max_channels_per_conn);

    // Wait for first channel open or timeout.
    let first_channel = tokio::time::timeout(
        config.channel_open_timeout,
        wait_for_channel_open(
            transport,
            peer_state,
            &mut channels,
            channel_id_alloc,
            extranonce_alloc,
            config,
            latest_job,
            channel_registry,
            peer,
            &mut opened_ids,
        ),
    )
    .await;

    match first_channel {
        Err(_elapsed) => {
            warn!(peer = %peer, "no channel open within timeout");
            return (HandlerExit::ChannelOpenTimeout, opened_ids);
        }
        Ok(Err(exit)) => return (exit, opened_ids),
        Ok(Ok(())) => {}
    }

    // ── Stage 3: Steady-state select loop ──
    loop {
        tokio::select! {
            // New job from main event loop.
            job_result = job_rx.recv() => {
                match job_result {
                    Ok(job) => {
                        if let Err(exit) = distribute_job(transport, &mut channels, &job).await {
                            return (exit, opened_ids);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(peer = %peer, lagged = n, "job broadcast lagged; catching up");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!(peer = %peer, "job broadcast closed; shutting down handler");
                        return (HandlerExit::Shutdown, opened_ids);
                    }
                }
            }
            // Incoming SV2 frame from miner.
            frame_result = transport.read_frame() => {
                match frame_result {
                    Ok((header, payload)) => {
                        let action = handle_miner_frame(
                            transport,
                            peer_state,
                            &mut channels,
                            channel_id_alloc,
                            extranonce_alloc,
                            config,
                            job_table,
                            latest_job,
                            share_dedup,
                            share_event_tx,
                            share_forward_tx,
                            &header,
                            &payload,
                            channel_registry,
                            peer,
                            &mut opened_ids,
                        ).await;
                        match action {
                            FrameAction::Continue => {}
                            FrameAction::Disconnect(exit) => return (exit, opened_ids),
                        }
                    }
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "transport read error");
                        return (HandlerExit::TransportError(e), opened_ids);
                    }
                }
            }
            // Shutdown signal.
            _ = shutdown.changed() => {
                info!(peer = %peer, "handler received shutdown signal");
                return (HandlerExit::Shutdown, opened_ids);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Stage 1: SetupConnection
// ─────────────────────────────────────────────────────────────────────

/// Best-effort: encode and send a `SetupConnection.Error` frame. Failures are
/// logged at debug level and swallowed because the connection is about to close.
async fn send_setup_error(transport: &mut Sv2Transport, flags: u32) {
    let err_msg = sv2_codec::SetupConnectionError {
        flags,
        error_code: "unsupported-protocol".to_string(),
    };
    if let Ok(err_payload) = err_msg.encode()
        && let Err(e) = transport
            .write_frame(0x0000, MESSAGE_TYPE_SETUP_CONNECTION_ERROR, &err_payload)
            .await
    {
        debug!(error = %e, "best-effort SetupConnection.Error write failed");
    }
}

async fn handle_setup_connection(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
) -> Result<(), HandlerExit> {
    let (header, payload) = transport
        .read_frame()
        .await
        .map_err(HandlerExit::TransportError)?;

    // Reject non-base-protocol extension types (lower 15 bits must be 0).
    if header.extension_type & 0x7FFF != 0 {
        let reason = format!(
            "unsupported extension_type 0x{:04x}; only base mining protocol (0x0000/0x8000) is supported",
            header.extension_type,
        );
        return Err(HandlerExit::SetupRejected(reason));
    }

    if header.msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        let reason = format!(
            "expected SetupConnection (0x{:02x}), got 0x{:02x}",
            MESSAGE_TYPE_SETUP_CONNECTION, header.msg_type,
        );
        send_setup_error(transport, 0).await;
        return Err(HandlerExit::SetupRejected(reason));
    }

    let setup = match sv2_codec::SetupConnection::decode(&payload) {
        Ok(s) => s,
        Err(e) => {
            send_setup_error(transport, 0).await;
            return Err(HandlerExit::CodecError(e));
        }
    };

    // Validate: protocol must be MiningProtocol (0), version range must include 2.
    if setup.protocol != 0 {
        send_setup_error(transport, 0).await;
        return Err(HandlerExit::SetupRejected(format!(
            "protocol {} is not MiningProtocol",
            setup.protocol,
        )));
    }

    if setup.min_version > 2 || setup.max_version < 2 {
        send_setup_error(transport, setup.flags).await;
        return Err(HandlerExit::SetupRejected(format!(
            "version range [{}, {}] does not include 2",
            setup.min_version, setup.max_version,
        )));
    }

    debug!(
        peer = %peer_state.peer_addr,
        vendor = %setup.vendor,
        firmware = %setup.firmware,
        "SetupConnection accepted",
    );

    // Send SetupConnection.Success.
    let success = sv2_codec::SetupConnectionSuccess {
        used_version: 2,
        flags: 0, // No special flags in V1.0.0.
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(
            0x0000,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            &success_payload,
        )
        .await
        .map_err(HandlerExit::TransportError)?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Stage 2: Channel open
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn wait_for_channel_open(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> Result<(), HandlerExit> {
    loop {
        let (header, payload) = transport
            .read_frame()
            .await
            .map_err(HandlerExit::TransportError)?;

        // Reject non-base-protocol extension types.
        if header.extension_type & 0x7FFF != 0 {
            warn!(
                peer = %peer_state.peer_addr,
                extension_type = header.extension_type,
                "unsupported extension_type; disconnecting",
            );
            return Err(HandlerExit::SetupRejected(format!(
                "unsupported extension_type 0x{:04x}",
                header.extension_type,
            )));
        }

        match header.msg_type {
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
                handle_open_standard_channel(
                    transport,
                    peer_state,
                    channels,
                    channel_id_alloc,
                    extranonce_alloc,
                    config,
                    latest_job,
                    &payload,
                    channel_registry,
                    peer,
                    opened_ids,
                )
                .await?;
                return Ok(());
            }
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                // Extended channels not supported in V1.0.0. Close connection.
                let close = sv2_codec::CloseChannel {
                    channel_id: 0,
                    reason_code: GatewayReason::ExtendedChannelUnsupported
                        .as_str()
                        .to_string(),
                };
                if let Ok(close_payload) = close.encode()
                    && let Err(e) = transport
                        .write_frame(0x8000, MESSAGE_TYPE_CLOSE_CHANNEL, &close_payload)
                        .await
                {
                    debug!(error = %e, "best-effort CloseChannel write failed");
                }
                return Err(HandlerExit::SetupRejected(
                    "extended channels not supported".to_string(),
                ));
            }
            other => {
                debug!(
                    peer = %peer_state.peer_addr,
                    msg_type = other,
                    "unexpected message before channel open; ignoring",
                );
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_open_standard_channel(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    payload: &[u8],
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> Result<(), HandlerExit> {
    let open_req = match sv2_codec::OpenStandardMiningChannel::decode(payload) {
        Ok(r) => r,
        Err(e) => {
            // Best effort: send OpenMiningChannel.Error with request_id=0 since
            // the decode failed and we cannot extract the real request_id.
            let err = sv2_codec::OpenMiningChannelError {
                request_id: 0,
                error_code: "unsupported-protocol".to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                    .await
            {
                debug!(error = %we, "best-effort OpenMiningChannel.Error write failed");
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // Allocate channel ID and extranonce.
    let Some(channel_id) = channel_id_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "channel_id allocation exhausted; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "channel_id allocator exhausted".to_string(),
        ));
    };

    let Some(extranonce) = extranonce_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "extranonce allocation exhausted; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "extranonce allocator exhausted".to_string(),
        ));
    };

    // Register in connection channels.
    if let Err(reason) = channels.open_channel(
        channel_id,
        extranonce,
        open_req.user_identity.clone(),
        None,
        config.channel_target,
        config.max_shares_per_second_per_channel,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            reason = %reason,
            "channel registration failed; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(format!(
            "channel registration failed: {reason}"
        )));
    }

    // Register in global channel registry for HTTP /channels API.
    channel_registry
        .register(snapshot_from_open(
            channel_id,
            &open_req.user_identity,
            peer,
        ))
        .await;
    opened_ids.push(channel_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id,
        worker = %open_req.user_identity,
        "standard mining channel opened",
    );

    // Send OpenStandardMiningChannel.Success.
    let success = sv2_codec::OpenStandardMiningChannelSuccess {
        request_id: open_req.request_id,
        channel_id,
        target: config.channel_target,
        extranonce_prefix: extranonce.to_vec(),
        group_channel_id: 0,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(
            0x0000,
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            &success_payload,
        )
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send SetTarget for this channel.
    let set_target = sv2_codec::SetTarget {
        channel_id,
        maximum_target: config.channel_target,
    };
    let set_target_payload = set_target.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SET_TARGET, &set_target_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send initial NewMiningJob if one is available (WP-6).
    if let Some(ref job) = *latest_job.read().await {
        // Compute per-channel merkle root using this channel's extranonce.
        let merkle_root = crate::jobs::compute_merkle_root(
            &job.coinbase_tx_prefix,
            &extranonce,
            &job.coinbase_tx_suffix,
            &job.merkle_path,
        );
        let new_job = sv2_codec::NewMiningJob {
            channel_id,
            job_id: job.job_id,
            min_ntime: job.min_ntime,
            version: job.version,
            merkle_root,
        };
        let job_payload = new_job.encode().map_err(HandlerExit::CodecError)?;
        transport
            .write_frame(0x8000, MESSAGE_TYPE_NEW_MINING_JOB, &job_payload)
            .await
            .map_err(HandlerExit::TransportError)?;

        if let Some(ref ph) = job.prevhash_update {
            let set_prev = sv2_codec::SetNewPrevHash {
                channel_id,
                job_id: job.job_id,
                prev_hash: ph.prev_hash,
                min_ntime: ph.min_ntime,
                nbits: ph.nbits,
            };
            let ph_payload = set_prev.encode().map_err(HandlerExit::CodecError)?;
            transport
                .write_frame(0x8000, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, &ph_payload)
                .await
                .map_err(HandlerExit::TransportError)?;

            // Update channel state with prevhash tracking.
            if let Some(ch) = channels.get_mut(channel_id) {
                ch.record_prevhash_sent(job.job_id, ph.min_ntime);
            }
        }

        if let Some(ch) = channels.get_mut(channel_id) {
            ch.record_active_job_sent(job.job_id);
        }

        info!(
            peer = %peer_state.peer_addr,
            channel_id,
            job_id = job.job_id,
            "sent initial NewMiningJob on channel open",
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Stage 3: Steady-state miner frame dispatch
// ─────────────────────────────────────────────────────────────────────

enum FrameAction {
    Continue,
    Disconnect(HandlerExit),
}

/// Reject an extended mining channel open request. Extended channels are not
/// supported; send a best-effort `CloseChannel` and disconnect.
async fn reject_extended_channel(transport: &mut Sv2Transport) -> FrameAction {
    let close = sv2_codec::CloseChannel {
        channel_id: 0,
        reason_code: GatewayReason::ExtendedChannelUnsupported
            .as_str()
            .to_string(),
    };
    if let Ok(close_payload) = close.encode()
        && let Err(e) = transport
            .write_frame(0x8000, MESSAGE_TYPE_CLOSE_CHANNEL, &close_payload)
            .await
    {
        debug!(error = %e, "best-effort CloseChannel write failed");
    }
    FrameAction::Disconnect(HandlerExit::SetupRejected(
        "extended channels not supported".to_string(),
    ))
}

/// Handle a miner-initiated `CloseChannel`. Unregisters the channel and
/// disconnects if no channels remain open.
async fn handle_close_channel(
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_registry: &SharedChannelRegistry,
    payload: &[u8],
) -> FrameAction {
    match sv2_codec::CloseChannel::decode(payload) {
        Ok(close) => {
            debug!(
                peer = %peer_state.peer_addr,
                channel_id = close.channel_id,
                reason = %close.reason_code,
                "miner closed channel",
            );
            channels.close_channel(close.channel_id);
            channel_registry.unregister(close.channel_id).await;
            if channels.open_count() == 0 {
                info!(
                    peer = %peer_state.peer_addr,
                    "all channels closed; disconnecting",
                );
                return FrameAction::Disconnect(HandlerExit::Shutdown);
            }
            FrameAction::Continue
        }
        Err(e) => {
            warn!(
                peer = %peer_state.peer_addr,
                error = %e,
                "failed to decode CloseChannel; disconnecting",
            );
            FrameAction::Disconnect(HandlerExit::CodecError(e))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_miner_frame(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    share_dedup: &mut ShareDedupSet,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    header: &Sv2FrameHeader,
    payload: &[u8],
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> FrameAction {
    // Reject non-base-protocol extension types.
    if header.extension_type & 0x7FFF != 0 {
        warn!(
            peer = %peer_state.peer_addr,
            extension_type = header.extension_type,
            "unsupported extension_type in steady-state frame; disconnecting",
        );
        return FrameAction::Disconnect(HandlerExit::SetupRejected(format!(
            "unsupported extension_type 0x{:04x}",
            header.extension_type,
        )));
    }

    match header.msg_type {
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => {
            match handle_submit_shares(
                transport,
                peer_state,
                channels,
                config,
                job_table,
                share_dedup,
                share_event_tx,
                share_forward_tx,
                payload,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
            // Additional channel open on existing connection.
            match handle_open_standard_channel(
                transport,
                peer_state,
                channels,
                channel_id_alloc,
                extranonce_alloc,
                config,
                latest_job,
                payload,
                channel_registry,
                peer,
                opened_ids,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
            reject_extended_channel(transport).await
        }
        MESSAGE_TYPE_CLOSE_CHANNEL => {
            handle_close_channel(peer_state, channels, channel_registry, payload).await
        }
        other => {
            debug!(
                peer = %peer_state.peer_addr,
                msg_type = other,
                "unhandled message type; ignoring",
            );
            FrameAction::Continue
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Share submission
// ─────────────────────────────────────────────────────────────────────

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_precision_loss
)]
async fn handle_submit_shares(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    config: &HandlerConfig,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    share_dedup: &mut ShareDedupSet,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    payload: &[u8],
) -> Result<(), HandlerExit> {
    let share = match sv2_codec::SubmitSharesStandard::decode(payload) {
        Ok(s) => s,
        Err(e) => {
            // Best effort: send SubmitShares.Error with zeroed IDs since the
            // decode failed and we cannot extract channel_id or sequence_number.
            let err = sv2_codec::SubmitSharesError {
                channel_id: 0,
                sequence_number: 0,
                error_code: GatewayReason::FrameDecodeError
                    .to_sv2_error_code()
                    .to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, &err_payload)
                    .await
            {
                debug!(error = %we, "best-effort SubmitShares.Error write failed");
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // ── Step 0: Validate channel exists ──
    let Some(_channel) = channels.get(share.channel_id) else {
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::InvalidChannelId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // ── Step 0.5: Per-channel share rate limit ──
    // Use get_mut to update the token bucket. The borrow is released
    // immediately after the check so subsequent immutable reads work.
    if let Some(ch) = channels.get_mut(share.channel_id)
        && !ch.rate_limiter.try_acquire()
    {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: per-channel rate limit exceeded",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareRateLimited,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareRateLimited,
        )
        .await;
    }

    // Re-acquire immutable borrow after rate limiter mutation.
    // Channel cannot disappear between step 0 and step 0.5 because
    // we hold the only mutable reference to ConnectionChannels and
    // close_channel is not called in between. The unwrap_or_else
    // with InvalidChannelId covers any impossible edge case.
    let Some(channel) = channels.get(share.channel_id) else {
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // Snapshot channel state before releasing the borrow.
    let channel_target = channel.maximum_target;
    let channel_extranonce = channel.extranonce_prefix;
    let activation_min_ntime = channel.activation_min_ntime;
    let elapsed_secs = channel.elapsed_since_prevhash_secs();
    let worker_id = channel.worker_id.clone();

    // ── Step 1: Validate job_id is in job table ──
    let table = job_table.read().await;
    let Some(job) = table.get(share.job_id) else {
        drop(table);
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareInvalidJobId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareInvalidJobId,
        )
        .await;
    };

    // Snapshot job fields we need for validation.
    let job_version = job.version;
    let job_prev_hash = job.prev_hash;
    let job_nbits = job.nbits;
    let job_activation_min_ntime = job.activation_min_ntime;
    let job_block_height = job.block_height;
    let job_coinbase_prefix = job.coinbase_tx_prefix.clone();
    let job_coinbase_suffix = job.coinbase_tx_suffix.clone();
    let job_merkle_path = job.merkle_path.clone();
    let job_template_id = job.template_id;
    let job_source_instance_id = job.source_instance_id.clone();
    drop(table);

    // ── Step 2: Validate version bits (BIP 320) ──
    if !check_version_bits(share.version, job_version) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_version = share.version,
            job_version,
            "share rejected: version bit violation",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::VersionBitViolation,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::VersionBitViolation,
        )
        .await;
    }

    // ── Step 3: Validate ntime bounds ──
    let effective_min_ntime = activation_min_ntime.unwrap_or(job_activation_min_ntime);
    let effective_elapsed = elapsed_secs.unwrap_or(0);
    let now_unix = current_unix_timestamp();

    if !check_ntime_bounds(
        share.ntime,
        effective_min_ntime,
        effective_elapsed,
        config.ntime_elapsed_slack_seconds,
        config.max_future_block_time_seconds,
        now_unix,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            ntime = share.ntime,
            min_ntime = effective_min_ntime,
            elapsed = effective_elapsed,
            "share rejected: ntime out of range",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::NtimeOutOfRange,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::NtimeOutOfRange,
        )
        .await;
    }

    // ── Step 4: Build 80-byte header and validate PoW ──
    let merkle_root = crate::jobs::compute_merkle_root(
        &job_coinbase_prefix,
        &channel_extranonce,
        &job_coinbase_suffix,
        &job_merkle_path,
    );

    let header_bytes = header_identity_bytes(
        share.version,
        &job_prev_hash,
        &merkle_root,
        share.ntime,
        job_nbits,
        share.nonce,
    );

    if !validate_share_pow(&header_bytes, &channel_target) {
        debug!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: difficulty below target",
        );
        // PoW failed but we can still compute share_id for the event.
        let sid = compute_share_id(&header_bytes);
        let eid = compute_event_id(&sid, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(sid),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(
                GatewayReason::ShareDifficultyBelowTarget
                    .as_str()
                    .to_string(),
            ),
            reason_detail: Some(GatewayReason::ShareDifficultyBelowTarget.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareDifficultyBelowTarget,
        )
        .await;
    }

    // ── Step 5: Replay detection ──
    let share_id = compute_share_id(&header_bytes);
    if share_dedup.check_and_insert(&share_id) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_id_hex = hex::encode(share_id),
            "share rejected: replay detected",
        );
        let eid = compute_event_id(&share_id, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(share_id),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(GatewayReason::ShareReplayDetected.as_str().to_string()),
            reason_detail: Some(GatewayReason::ShareReplayDetected.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareReplayDetected,
        )
        .await;
    }

    // ── Share accepted ──
    peer_state.record_frame_decoded();

    let difficulty = shares::target_to_difficulty_u64(&channel_target);
    let share_id_hex = hex::encode(share_id);
    let event_id = compute_event_id(&share_id, &worker_id, "full");
    let event_id_hex = hex::encode(event_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id = share.channel_id,
        job_id = share.job_id,
        seq = share.sequence_number,
        difficulty,
        share_id_hex = %share_id_hex,
        "share accepted",
    );

    // Emit share_accepted event (success).
    let evt = ShareAcceptedEvent {
        event_type: "share_accepted",
        share_id_hex: share_id_hex.clone(),
        event_id_hex: event_id_hex.clone(),
        sv2_response: "success",
        reason_code: None,
        reason_detail: None,
        worker_id: worker_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        block_height: job_block_height,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
    };
    if let Err(e) = share_event_tx.try_send(evt) {
        warn!(error = %e, "share_event_tx full; share event dropped");
    }

    // Enqueue for upstream relay.
    let prev_hash_wire = job_prev_hash;
    let mut prev_hash_display = job_prev_hash;
    prev_hash_display.reverse();

    let mut merkle_root_display = merkle_root;
    merkle_root_display.reverse();

    let submission = ShareSubmission {
        share_id_hex: share_id_hex.clone(),
        version: share.version,
        prev_hash_wire_hex: hex::encode(prev_hash_wire),
        prev_hash_display_hex: hex::encode(prev_hash_display),
        merkle_root_wire_hex: hex::encode(merkle_root),
        merkle_root_display_hex: hex::encode(merkle_root_display),
        ntime: share.ntime,
        nbits: job_nbits,
        nonce: share.nonce,
        event_id_hex,
        worker_id,
        validation_level: "full".to_string(),
        gateway_instance_id: config.gateway_instance_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        template_id: job_template_id,
        block_height: job_block_height,
        pool_account_id: None,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
        difficulty_display: difficulty as f64,
        source_instance_id: job_source_instance_id,
        gateway_signature_hex: if config.share_hmac_secret.is_empty() {
            String::new()
        } else {
            compute_gateway_signature(&config.share_hmac_secret, &event_id)
                .map(hex::encode)
                .unwrap_or_default()
        },
    };
    if let Err(e) = share_forward_tx.try_send(submission) {
        warn!(error = %e, "share_forward_tx full; share submission dropped");
    }

    let success = sv2_codec::SubmitSharesSuccess {
        channel_id: share.channel_id,
        last_sequence_number: share.sequence_number,
        new_submits_accepted_count: 1,
        new_shares_sum: difficulty,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, &success_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    Ok(())
}

/// Send a `SubmitShares.Error` response with the appropriate SV2 wire code.
async fn send_share_error(
    transport: &mut Sv2Transport,
    channel_id: u32,
    sequence_number: u32,
    reason: GatewayReason,
) -> Result<(), HandlerExit> {
    let err = sv2_codec::SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: reason.to_sv2_error_code().to_string(),
    };
    let err_payload = err.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, &err_payload)
        .await
        .map_err(HandlerExit::TransportError)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Job distribution
// ─────────────────────────────────────────────────────────────────────

async fn distribute_job(
    transport: &mut Sv2Transport,
    channels: &mut ConnectionChannels,
    job: &JobBroadcast,
) -> Result<(), HandlerExit> {
    for ch in channels.iter_open_mut() {
        // Compute per-channel merkle root using the channel's unique extranonce.
        let merkle_root = crate::jobs::compute_merkle_root(
            &job.coinbase_tx_prefix,
            &ch.extranonce_prefix,
            &job.coinbase_tx_suffix,
            &job.merkle_path,
        );
        let new_job = sv2_codec::NewMiningJob {
            channel_id: ch.channel_id,
            job_id: job.job_id,
            min_ntime: job.min_ntime,
            version: job.version,
            merkle_root,
        };
        let job_payload = new_job.encode().map_err(HandlerExit::CodecError)?;
        transport
            .write_frame(0x8000, MESSAGE_TYPE_NEW_MINING_JOB, &job_payload)
            .await
            .map_err(HandlerExit::TransportError)?;

        // If there's a prevhash update, send SetNewPrevHash.
        if let Some(ref ph) = job.prevhash_update {
            let set_prev = sv2_codec::SetNewPrevHash {
                channel_id: ch.channel_id,
                job_id: job.job_id,
                prev_hash: ph.prev_hash,
                min_ntime: ph.min_ntime,
                nbits: ph.nbits,
            };
            let ph_payload = set_prev.encode().map_err(HandlerExit::CodecError)?;
            transport
                .write_frame(0x8000, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, &ph_payload)
                .await
                .map_err(HandlerExit::TransportError)?;

            ch.record_prevhash_sent(job.job_id, ph.min_ntime);
        }

        ch.record_active_job_sent(job.job_id);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn handler_exit_display() {
        let exit = HandlerExit::SetupRejected("bad protocol".to_string());
        let s = format!("{exit}");
        assert!(s.contains("setup rejected"), "got: {s}");
    }

    #[test]
    fn job_broadcast_clone() {
        let job = JobBroadcast {
            job_id: 1,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0x01, 0x00, 0x00, 0x00],
            coinbase_tx_suffix: vec![0xFF, 0xFF, 0xFF, 0xFF],
            merkle_path: vec![],
            prevhash_update: Some(PrevhashUpdate {
                prev_hash: [0xBB; 32],
                min_ntime: 1_700_000_000,
                nbits: 0x1703_4219,
            }),
            min_ntime: None,
        };
        let cloned = job.clone();
        assert_eq!(cloned.job_id, 1);
        assert!(cloned.prevhash_update.is_some());
    }

    #[test]
    fn handler_config_fields() {
        let config = HandlerConfig {
            max_channels_per_conn: 256,
            channel_target: [0xFF; 32],
            channel_open_timeout: Duration::from_secs(30),
            ntime_elapsed_slack_seconds: 2,
            max_future_block_time_seconds: 7200,
            share_dedup_window_size: 10_000,
            max_shares_per_second_per_channel: 0,
            gateway_instance_id: "test-gw".to_string(),
            share_hmac_secret: Vec::new(),
        };
        assert_eq!(config.max_channels_per_conn, 256);
        assert_eq!(config.ntime_elapsed_slack_seconds, 2);
        assert_eq!(config.gateway_instance_id, "test-gw");
    }
}
