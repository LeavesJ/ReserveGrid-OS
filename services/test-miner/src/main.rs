//! `ReserveGrid` OS test-miner: SV2 standard mining client for regtest validation.
//!
//! Connects to the sv2-gateway over Noise NX, opens a standard mining channel,
//! receives jobs, and submits shares with random nonces. Validates the full
//! SV2 protocol pipeline without requiring real mining hardware.
//!
//! Usage:
//!   test-miner --authority-pubkey <64hex> [--gateway-addr 127.0.0.1:3333]

mod error;
mod session;
mod transport;

use std::process::ExitCode;

use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::session::SessionConfig;
use crate::transport::MinerTransport;

#[derive(Parser)]
#[command(
    name = "test-miner",
    about = "SV2 test mining client for ReserveGrid OS"
)]
struct Cli {
    /// Gateway SV2 listen address (host:port, supports DNS hostnames).
    #[arg(long, default_value = "127.0.0.1:3333", env = "VELDRA_GATEWAY_ADDR")]
    gateway_addr: String,

    /// Gateway Noise authority public key (64 lowercase hex chars).
    #[arg(long, env = "VELDRA_AUTHORITY_PUBKEY")]
    authority_pubkey: String,

    /// Worker identity string sent in `OpenStandardMiningChannel`.
    #[arg(long, default_value = "test-worker")]
    worker_name: String,

    /// Interval between share submissions in milliseconds.
    #[arg(long, default_value = "2000")]
    share_interval_ms: u64,

    /// Number of shares to submit before exiting (0 = unlimited).
    #[arg(long, default_value = "10")]
    num_shares: u32,

    /// Maximum seconds to wait for the first mining job (0 = no timeout).
    #[arg(long, default_value = "60")]
    job_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let cli = Cli::parse();

    info!(
        gateway = %cli.gateway_addr,
        worker = %cli.worker_name,
        num_shares = cli.num_shares,
        share_interval_ms = cli.share_interval_ms,
        "starting test-miner",
    );

    // Warn if gateway address appears non-loopback.
    if let Some(host) = cli.gateway_addr.rsplit(':').nth(1) {
        let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
        if !is_loopback {
            warn!(
                addr = %cli.gateway_addr,
                "gateway address is not loopback; traffic traverses the network",
            );
        }
    }

    // Validate authority pubkey format.
    if cli.authority_pubkey.len() != 64 {
        error!(
            len = cli.authority_pubkey.len(),
            "authority_pubkey must be exactly 64 hex characters",
        );
        return ExitCode::FAILURE;
    }

    // Connect and handshake.
    let mut transport =
        match MinerTransport::connect(&cli.gateway_addr, &cli.authority_pubkey).await {
            Ok(t) => t,
            Err(e) => {
                error!(error = %e, "failed to connect to gateway");
                return ExitCode::FAILURE;
            }
        };

    // Run SV2 session.
    let session_config = SessionConfig {
        worker_name: cli.worker_name.clone(),
        share_interval_ms: cli.share_interval_ms,
        num_shares: cli.num_shares,
        job_timeout_secs: cli.job_timeout_secs,
    };

    match session::run(&mut transport, &session_config).await {
        Ok(accepted) => {
            info!(
                accepted,
                submitted = cli.num_shares,
                "session finished successfully",
            );
            if cli.num_shares > 0 && accepted < cli.num_shares {
                error!(
                    accepted,
                    expected = cli.num_shares,
                    "not all shares were accepted",
                );
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            error!(error = %e, "session failed");
            ExitCode::FAILURE
        }
    }
}
