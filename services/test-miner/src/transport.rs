//! Noise NX initiator transport for the test-miner.
//!
//! Connects to the sv2-gateway as the Noise NX initiator, completes the
//! handshake, and provides encrypted SV2 frame read/write over the resulting
//! `NoiseCodec`.
//!
//! Wire format (identical to gateway responder):
//!   Noise frame: `[u16 BE length][encrypted_chunk]`
//!   SV2 frame (inside decrypted stream): `[u16 LE ext][u8 msg_type][u24 LE len][payload]`

use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator, NoiseCodec};
use secp256k1::XOnlyPublicKey;
use sv2_gateway::transport::{SV2_FRAME_HEADER_SIZE, Sv2FrameHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::error::MinerError;

/// Maximum accepted Noise frame size in bytes.
///
/// SV2 messages are small (job payloads, share submissions). A 64 KiB cap
/// prevents a malicious or buggy peer from forcing large heap allocations.
/// The SV2 spec uses u16 length headers (max 65535), so this is a tighter
/// operational bound that still accommodates any legitimate SV2 message.
const MAX_NOISE_FRAME_BYTES: usize = 65_535;

// ─────────────────────────────────────────────────────────────────────
// MinerTransport
// ─────────────────────────────────────────────────────────────────────

/// Encrypted SV2 transport from the miner (initiator) side.
pub struct MinerTransport {
    stream: TcpStream,
    codec: NoiseCodec,
}

impl MinerTransport {
    /// Perform Noise NX handshake as the initiator and return a ready transport.
    ///
    /// `addr` accepts any tokio-resolvable address string (e.g. `"127.0.0.1:3333"`
    /// or `"sv2-gateway:3333"` for Docker DNS).
    pub async fn connect(addr: &str, authority_pubkey_hex: &str) -> Result<Self, MinerError> {
        // Parse authority public key.
        let pubkey_bytes = hex::decode(authority_pubkey_hex).map_err(|e| {
            warn!(error = %e, "authority_pubkey is not valid hex");
            MinerError::Handshake("invalid authority_pubkey hex encoding".to_string())
        })?;
        if pubkey_bytes.len() != 32 {
            warn!(
                got = pubkey_bytes.len(),
                expected = 32,
                "authority_pubkey length mismatch"
            );
            return Err(MinerError::Handshake(
                "authority_pubkey must be exactly 32 bytes".to_string(),
            ));
        }
        let authority_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes).map_err(|e| {
            warn!(error = %e, "authority_pubkey is not a valid x-only public key");
            MinerError::Handshake("invalid authority public key".to_string())
        })?;

        // TCP connect.
        info!(addr = %addr, "connecting to gateway");
        let mut stream = TcpStream::connect(addr).await.map_err(|e| {
            warn!(addr = %addr, error = %e, "TCP connect failed");
            MinerError::Handshake("TCP connect failed".to_string())
        })?;

        // Create Noise NX initiator with the gateway's authority public key.
        let mut initiator = Initiator::from_raw_k(authority_pubkey.serialize()).map_err(|e| {
            warn!(error = ?e, "Noise initiator creation failed");
            MinerError::Handshake("Noise initiator creation failed".to_string())
        })?;

        // Step 0: generate and send 64-byte ephemeral key.
        let first_message = initiator.step_0().map_err(|e| {
            warn!(error = ?e, "Noise handshake step 0 failed");
            MinerError::Handshake("Noise handshake step 0 failed".to_string())
        })?;
        stream.write_all(&first_message).await.map_err(|e| {
            warn!(error = %e, "failed to write ephemeral key");
            MinerError::Handshake("failed to write ephemeral key".to_string())
        })?;
        stream.flush().await.map_err(|e| {
            warn!(error = %e, "flush failed during handshake");
            MinerError::Handshake("flush failed during handshake".to_string())
        })?;
        debug!("sent 64-byte ephemeral key");

        // Read responder's 170-byte response.
        let mut response = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut response).await.map_err(|e| {
            warn!(error = %e, "failed to read handshake response");
            MinerError::Handshake("failed to read handshake response".to_string())
        })?;
        debug!("received handshake response");

        // Step 2: process response, obtain encrypted codec.
        let codec = initiator.step_2(response).map_err(|e| {
            warn!(error = ?e, "Noise handshake step 2 failed");
            MinerError::Handshake("Noise handshake step 2 failed".to_string())
        })?;

        info!("Noise NX handshake complete");
        Ok(Self { stream, codec })
    }

    /// Send an SV2 frame (builds header, encrypts, writes noise frame).
    pub async fn write_frame(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), MinerError> {
        let header = Sv2FrameHeader {
            extension_type,
            msg_type,
            #[allow(clippy::cast_possible_truncation)]
            msg_length: payload.len() as u32,
        };
        let mut frame_data = Vec::with_capacity(SV2_FRAME_HEADER_SIZE + payload.len());
        frame_data.extend_from_slice(&header.to_bytes());
        frame_data.extend_from_slice(payload);

        // Encrypt in place.
        self.codec.encrypt(&mut frame_data).map_err(|e| {
            warn!(error = ?e, "frame encryption failed");
            MinerError::Transport("frame encryption failed".to_string())
        })?;

        // Write noise frame: 2-byte BE length + encrypted data.
        let len_bytes = u16::try_from(frame_data.len())
            .map_err(|_| MinerError::Transport("frame too large".to_string()))?
            .to_be_bytes();
        self.stream.write_all(&len_bytes).await.map_err(|e| {
            warn!(error = %e, "write frame length failed");
            MinerError::Transport("write frame failed".to_string())
        })?;
        self.stream.write_all(&frame_data).await.map_err(|e| {
            warn!(error = %e, "write frame data failed");
            MinerError::Transport("write frame failed".to_string())
        })?;
        self.stream.flush().await.map_err(|e| {
            warn!(error = %e, "flush failed after frame write");
            MinerError::Transport("write frame failed".to_string())
        })?;

        Ok(())
    }

    /// Read one SV2 frame (reads noise frame, decrypts, parses header).
    pub async fn read_frame(&mut self) -> Result<(Sv2FrameHeader, Vec<u8>), MinerError> {
        // Read 2-byte BE length.
        let mut len_buf = [0u8; 2];
        self.stream.read_exact(&mut len_buf).await.map_err(|e| {
            warn!(error = %e, "read frame length failed");
            MinerError::Transport("read frame failed".to_string())
        })?;
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        if frame_len == 0 {
            return Err(MinerError::Transport("zero-length frame".to_string()));
        }
        if frame_len > MAX_NOISE_FRAME_BYTES {
            return Err(MinerError::Transport(
                "frame exceeds size limit".to_string(),
            ));
        }

        // Read encrypted data.
        let mut encrypted = vec![0u8; frame_len];
        self.stream.read_exact(&mut encrypted).await.map_err(|e| {
            warn!(error = %e, "read frame data failed");
            MinerError::Transport("read frame failed".to_string())
        })?;

        // Decrypt in place.
        self.codec.decrypt(&mut encrypted).map_err(|e| {
            warn!(error = ?e, "frame decryption failed");
            MinerError::Transport("frame decryption failed".to_string())
        })?;

        // Parse SV2 frame header.
        if encrypted.len() < SV2_FRAME_HEADER_SIZE {
            warn!(
                got = encrypted.len(),
                expected = SV2_FRAME_HEADER_SIZE,
                "decrypted frame too short for SV2 header",
            );
            return Err(MinerError::Transport(
                "decrypted frame too short".to_string(),
            ));
        }
        let mut hdr_bytes = [0u8; SV2_FRAME_HEADER_SIZE];
        hdr_bytes.copy_from_slice(&encrypted[..SV2_FRAME_HEADER_SIZE]);
        let header = Sv2FrameHeader::parse(&hdr_bytes);
        let payload = encrypted[SV2_FRAME_HEADER_SIZE..].to_vec();

        Ok((header, payload))
    }
}
