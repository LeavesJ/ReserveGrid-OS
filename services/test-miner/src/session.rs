//! SV2 mining session lifecycle.
//!
//! Implements the full SV2 standard mining channel client flow:
//! 1. `SetupConnection` exchange
//! 2. `OpenStandardMiningChannel` + `SetTarget` receipt
//! 3. Steady-state: receive jobs, submit shares on a timer

use sv2_gateway::sv2_codec::{
    self, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_MINING_JOB, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};
use tracing::{debug, error, info, warn};

use crate::error::MinerError;
use crate::transport::MinerTransport;

// ─────────────────────────────────────────────────────────────────────
// Session state
// ─────────────────────────────────────────────────────────────────────

struct ChannelState {
    channel_id: u32,
    #[allow(dead_code)]
    target: [u8; 32],
    #[allow(dead_code)]
    extranonce_prefix: Vec<u8>,
}

struct JobState {
    job_id: u32,
    version: u32,
    #[allow(dead_code)]
    merkle_root: [u8; 32],
}

struct PrevHashState {
    #[allow(dead_code)]
    prev_hash: [u8; 32],
    min_ntime: u32,
    #[allow(dead_code)]
    nbits: u32,
}

/// Session configuration (from CLI).
pub struct SessionConfig {
    pub worker_name: String,
    pub share_interval_ms: u64,
    pub num_shares: u32,
    /// Maximum seconds to wait for the first `NewMiningJob` before aborting.
    /// Zero means wait indefinitely.
    pub job_timeout_secs: u64,
}

// ─────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────

/// Run the full SV2 mining session. Returns the number of shares accepted.
pub async fn run(
    transport: &mut MinerTransport,
    config: &SessionConfig,
) -> Result<u32, MinerError> {
    // Stage 1: SetupConnection.
    setup_connection(transport).await?;

    // Stage 2: OpenStandardMiningChannel.
    let channel = open_channel(transport, &config.worker_name).await?;

    // Stage 3: Steady-state loop.
    let accepted = steady_state(transport, &channel, config).await?;

    // Send CloseChannel.
    let close = sv2_codec::CloseChannel {
        channel_id: channel.channel_id,
        reason_code: "session_complete".to_string(),
    };
    let close_payload = close.encode()?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_CLOSE_CHANNEL, &close_payload)
        .await?;
    info!(accepted, "session complete, CloseChannel sent");

    Ok(accepted)
}

// ─────────────────────────────────────────────────────────────────────
// Stage 1: SetupConnection
// ─────────────────────────────────────────────────────────────────────

async fn setup_connection(transport: &mut MinerTransport) -> Result<(), MinerError> {
    let setup = sv2_codec::SetupConnection {
        protocol: 0, // MiningProtocol
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: "localhost".to_string(),
        endpoint_port: 3333,
        vendor: "reservegrid-test-miner".to_string(),
        hardware_version: "0.1".to_string(),
        firmware: "0.1.0".to_string(),
        device_id: "test-001".to_string(),
    };
    let payload = setup.encode()?;
    transport
        .write_frame(0x0000, MESSAGE_TYPE_SETUP_CONNECTION, &payload)
        .await?;
    debug!("sent SetupConnection");

    // Read response.
    let (header, resp_payload) = transport.read_frame().await?;
    match header.msg_type {
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS => {
            let success = sv2_codec::SetupConnectionSuccess::decode(&resp_payload)?;
            info!(
                used_version = success.used_version,
                "SetupConnection accepted"
            );
            if success.used_version != 2 {
                warn!(
                    used_version = success.used_version,
                    "unexpected SV2 protocol version"
                );
                return Err(MinerError::Protocol(
                    "unexpected SV2 protocol version".to_string(),
                ));
            }
            Ok(())
        }
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR => {
            let err = sv2_codec::SetupConnectionError::decode(&resp_payload)?;
            warn!(error_code = %err.error_code, "SetupConnection rejected by gateway");
            Err(MinerError::Protocol(
                "SetupConnection rejected by gateway".to_string(),
            ))
        }
        other => {
            warn!(
                msg_type = format!("0x{other:02x}"),
                "unexpected response to SetupConnection"
            );
            Err(MinerError::Protocol(
                "unexpected response to SetupConnection".to_string(),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Stage 2: OpenStandardMiningChannel
// ─────────────────────────────────────────────────────────────────────

async fn open_channel(
    transport: &mut MinerTransport,
    worker_name: &str,
) -> Result<ChannelState, MinerError> {
    let open = sv2_codec::OpenStandardMiningChannel {
        request_id: 1,
        user_identity: worker_name.to_string(),
        nominal_hash_rate: 1.0,
        max_target: [0xff; 32],
    };
    let payload = open.encode()?;
    transport
        .write_frame(
            0x0000,
            sv2_codec::MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            &payload,
        )
        .await?;
    debug!(worker = worker_name, "sent OpenStandardMiningChannel");

    // Read OpenStandardMiningChannelSuccess.
    let (header, resp_payload) = transport.read_frame().await?;
    match header.msg_type {
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
            let success = sv2_codec::OpenStandardMiningChannelSuccess::decode(&resp_payload)?;
            info!(
                channel_id = success.channel_id,
                extranonce_len = success.extranonce_prefix.len(),
                "channel opened",
            );

            let channel = ChannelState {
                channel_id: success.channel_id,
                target: success.target,
                extranonce_prefix: success.extranonce_prefix,
            };

            // Gateway sends SetTarget immediately after success.
            let (set_target_hdr, set_target_payload) = transport.read_frame().await?;
            if set_target_hdr.msg_type == MESSAGE_TYPE_SET_TARGET {
                let st = sv2_codec::SetTarget::decode(&set_target_payload)?;
                debug!(channel_id = st.channel_id, "received SetTarget");
            } else {
                warn!(
                    msg_type = set_target_hdr.msg_type,
                    "expected SetTarget after channel open, got different message",
                );
            }

            Ok(channel)
        }
        MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR => {
            let err = sv2_codec::OpenMiningChannelError::decode(&resp_payload)?;
            warn!(error_code = %err.error_code, "OpenStandardMiningChannel rejected by gateway");
            Err(MinerError::Protocol(
                "OpenStandardMiningChannel rejected by gateway".to_string(),
            ))
        }
        other => {
            warn!(
                msg_type = format!("0x{other:02x}"),
                "unexpected response to OpenStandardMiningChannel"
            );
            Err(MinerError::Protocol(
                "unexpected response to OpenStandardMiningChannel".to_string(),
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Stage 3: Steady state
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
async fn steady_state(
    transport: &mut MinerTransport,
    channel: &ChannelState,
    config: &SessionConfig,
) -> Result<u32, MinerError> {
    let mut current_job: Option<JobState> = None;
    let mut current_prevhash: Option<PrevHashState> = None;
    let mut sequence_number: u32 = 0;
    let mut shares_accepted: u32 = 0;
    let mut shares_submitted: u32 = 0;
    let share_limit = config.num_shares;

    let share_interval = tokio::time::Duration::from_millis(config.share_interval_ms);
    let mut share_timer = tokio::time::interval(share_interval);
    // The first tick fires immediately; skip it so we wait for a job first.
    share_timer.tick().await;

    // Deadline for receiving the first job. Zero means wait indefinitely.
    let job_deadline = if config.job_timeout_secs > 0 {
        let dur = tokio::time::Duration::from_secs(config.job_timeout_secs);
        Some(tokio::time::Instant::now() + dur)
    } else {
        None
    };

    info!(
        job_timeout_secs = config.job_timeout_secs,
        "entering steady-state loop, waiting for jobs",
    );

    loop {
        tokio::select! {
            frame_result = transport.read_frame() => {
                let (header, payload) = frame_result?;
                match header.msg_type {
                    MESSAGE_TYPE_NEW_MINING_JOB => {
                        let job = sv2_codec::NewMiningJob::decode(&payload)?;
                        info!(
                            job_id = job.job_id,
                            version = format!("0x{:08x}", job.version),
                            "received NewMiningJob",
                        );
                        current_job = Some(JobState {
                            job_id: job.job_id,
                            version: job.version,
                            merkle_root: job.merkle_root,
                        });
                    }
                    MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH => {
                        let ph = sv2_codec::SetNewPrevHash::decode(&payload)?;
                        info!(
                            job_id = ph.job_id,
                            min_ntime = ph.min_ntime,
                            nbits = format!("0x{:08x}", ph.nbits),
                            "received SetNewPrevHash",
                        );
                        current_prevhash = Some(PrevHashState {
                            prev_hash: ph.prev_hash,
                            min_ntime: ph.min_ntime,
                            nbits: ph.nbits,
                        });
                    }
                    MESSAGE_TYPE_SET_TARGET => {
                        let st = sv2_codec::SetTarget::decode(&payload)?;
                        debug!(channel_id = st.channel_id, "received SetTarget update");
                    }
                    MESSAGE_TYPE_CLOSE_CHANNEL => {
                        let close = sv2_codec::CloseChannel::decode(&payload)?;
                        warn!(
                            channel_id = close.channel_id,
                            reason = %close.reason_code,
                            "gateway closed channel",
                        );
                        return Ok(shares_accepted);
                    }
                    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS => {
                        let success = sv2_codec::SubmitSharesSuccess::decode(&payload)?;
                        shares_accepted += success.new_submits_accepted_count;
                        info!(
                            seq = success.last_sequence_number,
                            accepted_total = shares_accepted,
                            "share accepted",
                        );
                        if share_limit > 0 && shares_accepted >= share_limit {
                            info!("reached share limit, finishing");
                            return Ok(shares_accepted);
                        }
                    }
                    MESSAGE_TYPE_SUBMIT_SHARES_ERROR => {
                        let err = sv2_codec::SubmitSharesError::decode(&payload)?;
                        error!(
                            seq = err.sequence_number,
                            error_code = %err.error_code,
                            "share rejected",
                        );
                    }
                    other => {
                        debug!(msg_type = format!("0x{other:02x}"), "unhandled message type");
                    }
                }
            }
            _ = share_timer.tick() => {
                // Submit a share if we have a job and prevhash.
                if let (Some(job), Some(ph)) = (&current_job, &current_prevhash) {
                    // Use min_ntime from SetNewPrevHash rather than wall clock.
                    // In regtest, getblocktemplate's mintime can lag wall clock
                    // by hours or days (blocks mined in prior sessions). The
                    // gateway's ntime check bounds ntime to
                    //   min_ntime + elapsed_since_prevhash + slack
                    // so using current wall clock fails when the gap is large.
                    // min_ntime is always within the valid window.
                    let ntime = ph.min_ntime;
                    let nonce: u32 = rand::random();
                    let share = sv2_codec::SubmitSharesStandard {
                        channel_id: channel.channel_id,
                        sequence_number,
                        job_id: job.job_id,
                        nonce,
                        ntime,
                        version: job.version,
                    };
                    let share_payload = share.encode()?;
                    transport
                        .write_frame(
                            0x8000,
                            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
                            &share_payload,
                        )
                        .await?;
                    debug!(
                        seq = sequence_number,
                        job_id = job.job_id,
                        nonce = format!("0x{nonce:08x}"),
                        ntime,
                        "submitted share",
                    );
                    sequence_number += 1;
                    shares_submitted += 1;

                    // The response (Success/Error) will arrive on the read
                    // branch of the select loop above.

                    if share_limit > 0 && shares_submitted >= share_limit {
                        // Wait for remaining responses before exiting.
                        // Give the gateway a moment to respond.
                        debug!("all shares submitted, waiting for final responses");
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        // Drain any remaining responses.
                        while let Ok(Ok((header, payload))) = tokio::time::timeout(
                            tokio::time::Duration::from_millis(200),
                            transport.read_frame(),
                        ).await {
                            if header.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS {
                                if let Ok(success) = sv2_codec::SubmitSharesSuccess::decode(&payload) {
                                    shares_accepted += success.new_submits_accepted_count;
                                    info!(
                                        seq = success.last_sequence_number,
                                        accepted_total = shares_accepted,
                                        "share accepted (drain)",
                                    );
                                }
                            } else if header.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_ERROR
                                && let Ok(err) = sv2_codec::SubmitSharesError::decode(&payload)
                            {
                                error!(
                                    seq = err.sequence_number,
                                    error_code = %err.error_code,
                                    "share rejected (drain)",
                                );
                            }
                        }
                        return Ok(shares_accepted);
                    }
                } else {
                    debug!("share timer fired but no job/prevhash available yet");
                    if let Some(deadline) = job_deadline
                        && tokio::time::Instant::now() >= deadline
                    {
                        error!(
                            timeout_secs = config.job_timeout_secs,
                            "no job received within timeout; aborting",
                        );
                        return Err(MinerError::Protocol(
                            "timed out waiting for first NewMiningJob".to_string(),
                        ));
                    }
                }
            }
        }
    }
}
