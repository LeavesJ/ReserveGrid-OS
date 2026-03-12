//! sv2-gateway: SV2 Mining Protocol miner-facing gateway.
//!
//! Accepts SV2 connections from miners, completes Noise NX handshake,
//! decodes binary frames, manages channels, distributes jobs gated by
//! verifier verdicts, validates shares, and relays them upstream.
//!
//! Three deployment modes (controlled by config):
//! - `inline`: full verification enforcement
//! - `observe`: data-plane telemetry, no verdict gating
//! - `shadow`: out-of-band audit, no miner connections

pub mod channels;
pub mod config;
pub mod connection;
pub mod handler;
pub mod health;
pub mod jobs;
pub mod shares;
pub mod sv2_codec;
pub mod transport;
pub mod upstream;
pub mod verifier_stream;
pub mod wal;
