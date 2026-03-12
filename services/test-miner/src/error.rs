//! Error types for the test-miner.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MinerError {
    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("codec error: {0}")]
    Codec(#[from] sv2_gateway::sv2_codec::Sv2CodecError),
}
