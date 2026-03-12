//! SV2 Noise NX transport layer.
//!
//! Handles the Noise NX handshake (gateway is the responder) and provides
//! encrypted frame I/O over a TCP connection. Does not interpret SV2 message
//! semantics; that responsibility belongs to the connection and channel modules.
//!
//! Wire format after handshake (each "noise frame"):
//!   `[length: u16 BE] [encrypted_chunk]`
//!
//! where `encrypted_chunk = plaintext || 16-byte AEAD MAC`.
//! Max encrypted chunk is 65535 bytes, so max plaintext per noise frame is
//! 65535 minus the 16-byte MAC = 65519 bytes.
//!
//! SV2 frame header (inside the decrypted stream):
//!   `[extension_type: u16 LE] [msg_type: u8] [msg_length: u24 LE]`
//!
//! The SV2 payload follows the 6-byte header. Large payloads may span
//! multiple noise frames.

use std::path::Path;
use std::time::Duration;

use noise_sv2::{ELLSWIFT_ENCODING_SIZE, NoiseCodec, Responder};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, instrument, warn};

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

/// AEAD MAC length for Noise encryption (`ChaChaPoly1305`).
const AEAD_MAC_LEN: usize = 16;

/// Maximum size of a single noise frame on the wire (2-byte length field max).
const MAX_NOISE_FRAME_LEN: usize = 65535;

/// Maximum plaintext bytes per noise frame (frame max minus MAC).
const MAX_NOISE_PLAINTEXT_LEN: usize = MAX_NOISE_FRAME_LEN - AEAD_MAC_LEN;

/// SV2 frame header size: 2 (`extension_type`) + 1 (`msg_type`) + 3 (`msg_length`).
pub const SV2_FRAME_HEADER_SIZE: usize = 6;

/// Maximum SV2 message payload (sanity bound). 16 MiB matches SRI defaults.
const MAX_SV2_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

/// Transport layer errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// TCP I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Noise handshake cryptographic failure.
    #[error("noise handshake failed")]
    NoiseHandshake,

    /// Handshake did not complete within the configured timeout.
    #[error("noise handshake timeout after {0:?}")]
    HandshakeTimeout(Duration),

    /// Noise AEAD decryption failure (tampered or corrupt frame).
    #[error("noise decrypt failed")]
    NoiseDecrypt,

    /// Noise AEAD encryption failure.
    #[error("noise encrypt failed")]
    NoiseEncrypt,

    /// Received a noise frame with zero length.
    #[error("empty noise frame")]
    EmptyFrame,

    /// SV2 message payload exceeds the sanity bound.
    #[error("sv2 payload too large: {0} bytes (max {MAX_SV2_PAYLOAD_LEN})")]
    PayloadTooLarge(usize),

    /// Connection closed by peer during frame read.
    #[error("connection reset by peer")]
    ConnectionReset,
}

/// Alias for transport results.
pub type Result<T> = std::result::Result<T, TransportError>;

// ─────────────────────────────────────────────────────────────────────
// Parsed SV2 frame header
// ─────────────────────────────────────────────────────────────────────

/// Parsed SV2 frame header (6 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sv2FrameHeader {
    /// Extension type field. Bit 15 indicates channel message.
    pub extension_type: u16,
    /// SV2 message type discriminator.
    pub msg_type: u8,
    /// Payload length in bytes (24-bit, max 16 MiB).
    pub msg_length: u32,
}

impl Sv2FrameHeader {
    /// Parse a 6-byte SV2 frame header.
    pub fn parse(buf: &[u8; SV2_FRAME_HEADER_SIZE]) -> Self {
        let extension_type = u16::from_le_bytes([buf[0], buf[1]]);
        let msg_type = buf[2];
        let msg_length = u32::from_le_bytes([buf[3], buf[4], buf[5], 0]);
        Self {
            extension_type,
            msg_type,
            msg_length,
        }
    }

    /// Serialize to 6 bytes.
    pub fn to_bytes(&self) -> [u8; SV2_FRAME_HEADER_SIZE] {
        let ext = self.extension_type.to_le_bytes();
        let len_bytes = self.msg_length.to_le_bytes();
        [
            ext[0],
            ext[1],
            self.msg_type,
            len_bytes[0],
            len_bytes[1],
            len_bytes[2],
        ]
    }

    /// Whether this is a channel message (bit 15 of `extension_type` set).
    pub fn is_channel_message(&self) -> bool {
        self.extension_type & 0x8000 != 0
    }

    /// Extract the `channel_id` from the first 4 bytes of the payload.
    /// Only valid when `is_channel_message()` is true.
    pub fn channel_id_from_payload(payload: &[u8]) -> Option<u32> {
        if payload.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            payload[0], payload[1], payload[2], payload[3],
        ]))
    }
}

// ─────────────────────────────────────────────────────────────────────
// Sv2Transport: encrypted frame I/O
// ─────────────────────────────────────────────────────────────────────

/// Encrypted SV2 transport over a TCP connection.
///
/// After a successful Noise NX handshake, this struct provides
/// `read_frame()` and `write_frame()` for SV2 message exchange.
pub struct Sv2Transport {
    stream: TcpStream,
    codec: NoiseCodec,
    /// Decrypted data buffer (may contain partial SV2 frames across reads).
    read_buf: Vec<u8>,
}

impl Sv2Transport {
    /// Wrap a TCP stream and a completed `NoiseCodec` into an SV2 transport.
    fn new(stream: TcpStream, codec: NoiseCodec) -> Self {
        Self {
            stream,
            codec,
            read_buf: Vec::with_capacity(4096),
        }
    }

    /// Read the next complete SV2 frame from the encrypted stream.
    ///
    /// Returns the parsed header and the payload bytes.
    /// Blocks until a full frame is available or an error occurs.
    pub async fn read_frame(&mut self) -> Result<(Sv2FrameHeader, Vec<u8>)> {
        // Ensure we have at least the 6-byte SV2 header in the buffer.
        while self.read_buf.len() < SV2_FRAME_HEADER_SIZE {
            self.read_noise_frame().await?;
        }

        // Parse the header to learn the payload length.
        let header = {
            let mut hdr_bytes = [0u8; SV2_FRAME_HEADER_SIZE];
            hdr_bytes.copy_from_slice(&self.read_buf[..SV2_FRAME_HEADER_SIZE]);
            Sv2FrameHeader::parse(&hdr_bytes)
        };

        let payload_len = header.msg_length as usize;
        if payload_len > MAX_SV2_PAYLOAD_LEN {
            return Err(TransportError::PayloadTooLarge(payload_len));
        }

        let total_frame_len = SV2_FRAME_HEADER_SIZE + payload_len;

        // Read enough noise frames to fill the SV2 frame.
        while self.read_buf.len() < total_frame_len {
            self.read_noise_frame().await?;
        }

        // Extract the payload.
        let payload = self.read_buf[SV2_FRAME_HEADER_SIZE..total_frame_len].to_vec();
        // Drain the consumed bytes. This shifts remaining data to the front.
        self.read_buf.drain(..total_frame_len);

        Ok((header, payload))
    }

    /// Write a complete SV2 frame to the encrypted stream.
    ///
    /// Constructs the 6-byte header, concatenates the payload, splits into
    /// noise frame chunks, encrypts each, and writes them.
    pub async fn write_frame(
        &mut self,
        extension_type: u16,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<()> {
        // SV2 msg_length is a 24-bit field; payload is pre-validated by callers.
        #[allow(clippy::cast_possible_truncation)]
        let msg_length = payload.len() as u32;
        let header = Sv2FrameHeader {
            extension_type,
            msg_type,
            msg_length,
        };

        let mut frame_data = Vec::with_capacity(SV2_FRAME_HEADER_SIZE + payload.len());
        frame_data.extend_from_slice(&header.to_bytes());
        frame_data.extend_from_slice(payload);

        // Split into noise-frame-sized chunks and encrypt each.
        for chunk in frame_data.chunks(MAX_NOISE_PLAINTEXT_LEN) {
            let mut encrypted = chunk.to_vec();
            self.codec
                .encrypt(&mut encrypted)
                .map_err(|_| TransportError::NoiseEncrypt)?;

            // Write noise frame: 2-byte BE length + encrypted data.
            // Encrypted chunk size is bounded by MAX_NOISE_PLAINTEXT_LEN + AEAD_MAC_LEN
            // which is always within u16 range.
            #[allow(clippy::cast_possible_truncation)]
            let len_bytes = (encrypted.len() as u16).to_be_bytes();
            self.stream.write_all(&len_bytes).await?;
            self.stream.write_all(&encrypted).await?;
        }

        self.stream.flush().await?;
        Ok(())
    }

    /// Read one noise frame from the wire, decrypt it, and append
    /// the plaintext to `self.read_buf`.
    async fn read_noise_frame(&mut self) -> Result<()> {
        // Read 2-byte big-endian length.
        let mut len_buf = [0u8; 2];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => TransportError::ConnectionReset,
                _ => TransportError::Io(e),
            })?;
        let frame_len = u16::from_be_bytes(len_buf) as usize;

        if frame_len == 0 {
            return Err(TransportError::EmptyFrame);
        }

        // Read the encrypted chunk.
        let mut encrypted = vec![0u8; frame_len];
        self.stream
            .read_exact(&mut encrypted)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => TransportError::ConnectionReset,
                _ => TransportError::Io(e),
            })?;

        // Decrypt in place.
        self.codec
            .decrypt(&mut encrypted)
            .map_err(|_| TransportError::NoiseDecrypt)?;

        self.read_buf.extend_from_slice(&encrypted);
        Ok(())
    }

    /// Access the underlying TCP stream for address information.
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Noise NX handshake
// ─────────────────────────────────────────────────────────────────────

/// Perform the Noise NX responder handshake on `stream`.
///
/// 1. Read 64-byte `ElligatorSwift` ephemeral public key from initiator.
/// 2. Call `Responder::step_1` to produce the 170-byte response and `NoiseCodec`.
/// 3. Send response.
/// 4. Return the transport ready for encrypted SV2 frame I/O.
///
/// The entire handshake is wrapped in a `tokio::time::timeout`.
#[instrument(skip_all, fields(peer = %stream.peer_addr().map_or_else(|_| "unknown".to_string(), |a| a.to_string())))]
pub async fn perform_handshake(
    mut stream: TcpStream,
    authority_keypair: &Keypair,
    cert_validity_secs: u32,
    timeout: Duration,
) -> Result<Sv2Transport> {
    let result = tokio::time::timeout(timeout, async {
        // Create a fresh responder for this connection.
        // noise_sv2 generates ephemeral + static keys internally.
        let mut responder = Responder::new(*authority_keypair, cert_validity_secs);

        // Step 0: Read initiator's 64-byte ElligatorSwift ephemeral key.
        let mut initiator_ephemeral = [0u8; ELLSWIFT_ENCODING_SIZE];
        stream
            .read_exact(&mut initiator_ephemeral)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => TransportError::ConnectionReset,
                _ => TransportError::Io(e),
            })?;

        debug!("received initiator ephemeral key");

        // Step 1: Responder processes ephemeral key, produces response + codec.
        let (response, codec) = responder
            .step_1(initiator_ephemeral)
            .map_err(|_| TransportError::NoiseHandshake)?;

        // Send the response back to the initiator.
        stream.write_all(&response).await?;
        stream.flush().await?;

        debug!("handshake complete, transport encrypted");

        Ok(Sv2Transport::new(stream, codec))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_elapsed) => {
            warn!(timeout_ms = timeout.as_millis(), "handshake timed out");
            Err(TransportError::HandshakeTimeout(timeout))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Authority key loading
// ─────────────────────────────────────────────────────────────────────

/// Error loading Noise NX authority credentials.
#[derive(Debug, thiserror::Error)]
pub enum KeyLoadError {
    /// Failed to read a key or certificate file from disk.
    #[error("io error reading {path}: {source}")]
    FileRead {
        path: String,
        source: std::io::Error,
    },

    /// The secret key file does not contain exactly 32 bytes.
    #[error("authority secret key must be exactly 32 bytes, got {0}")]
    InvalidSecretKeyLength(usize),

    /// The secret key bytes are not a valid secp256k1 scalar.
    #[error("invalid secp256k1 secret key: {0}")]
    InvalidSecretKey(String),

    /// The authority pubkey hex string is malformed.
    #[error("authority_pubkey must be 64 hex characters (x-only pubkey), got {0}")]
    InvalidPubkeyHex(String),

    /// The loaded keypair's public key does not match `authority_pubkey`.
    #[error("keypair pubkey {actual} does not match config authority_pubkey {expected}")]
    PubkeyMismatch { expected: String, actual: String },
}

/// Loaded Noise NX authority credentials, validated and ready for handshake.
#[derive(Clone)]
pub struct AuthorityCredentials {
    /// The authority keypair used by `Responder::new()` to sign per-connection
    /// certificates.
    pub keypair: Keypair,

    /// Certificate validity in seconds. Each connection gets a fresh cert.
    pub cert_validity_secs: u32,
}

/// Load the Noise NX authority keypair from disk and validate against the
/// configured authority public key.
///
/// The secret key file must contain exactly 32 raw bytes (the secp256k1 scalar).
/// The `authority_pubkey_hex` must be 64 lowercase hex characters encoding the
/// x-only public key. The loaded keypair's x-only public key must match.
///
/// Returns `KeyLoadError` on any failure (fail-closed).
pub fn load_authority_credentials(
    secret_key_path: &Path,
    authority_pubkey_hex: &str,
    cert_validity_secs: u32,
) -> std::result::Result<AuthorityCredentials, KeyLoadError> {
    // 1. Read secret key bytes from file.
    let sk_bytes = std::fs::read(secret_key_path).map_err(|e| KeyLoadError::FileRead {
        path: secret_key_path.display().to_string(),
        source: e,
    })?;

    if sk_bytes.len() != 32 {
        return Err(KeyLoadError::InvalidSecretKeyLength(sk_bytes.len()));
    }

    // 2. Parse as secp256k1 secret key.
    let secret_key = SecretKey::from_slice(&sk_bytes)
        .map_err(|e| KeyLoadError::InvalidSecretKey(e.to_string()))?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &secret_key);

    // 3. Parse the expected x-only public key from config.
    if authority_pubkey_hex.len() != 64 {
        return Err(KeyLoadError::InvalidPubkeyHex(format!(
            "length {} (expected 64)",
            authority_pubkey_hex.len()
        )));
    }

    let pubkey_bytes = hex::decode(authority_pubkey_hex)
        .map_err(|e| KeyLoadError::InvalidPubkeyHex(e.to_string()))?;

    let expected_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| KeyLoadError::InvalidPubkeyHex(e.to_string()))?;

    // 4. Verify the loaded keypair matches the config pubkey.
    let (actual_pubkey, _parity) = keypair.x_only_public_key();
    if actual_pubkey != expected_pubkey {
        return Err(KeyLoadError::PubkeyMismatch {
            expected: authority_pubkey_hex.to_string(),
            actual: hex::encode(actual_pubkey.serialize()),
        });
    }

    Ok(AuthorityCredentials {
        keypair,
        cert_validity_secs,
    })
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sv2_frame_header_round_trip() {
        let header = Sv2FrameHeader {
            extension_type: 0x8001,
            msg_type: 0x1a,
            msg_length: 128,
        };
        let bytes = header.to_bytes();
        let parsed = Sv2FrameHeader::parse(&bytes);
        assert_eq!(header, parsed);
    }

    #[test]
    fn sv2_frame_header_channel_bit() {
        let channel_msg = Sv2FrameHeader {
            extension_type: 0x8000,
            msg_type: 0x15,
            msg_length: 0,
        };
        assert!(channel_msg.is_channel_message());

        let non_channel = Sv2FrameHeader {
            extension_type: 0x0000,
            msg_type: 0x00,
            msg_length: 0,
        };
        assert!(!non_channel.is_channel_message());
    }

    #[test]
    fn sv2_frame_header_24bit_length() {
        // Verify msg_length uses only 24 bits (max 16_777_215).
        let header = Sv2FrameHeader {
            extension_type: 0,
            msg_type: 0,
            msg_length: 0x00FF_FFFF,
        };
        let bytes = header.to_bytes();
        let parsed = Sv2FrameHeader::parse(&bytes);
        assert_eq!(parsed.msg_length, 0x00FF_FFFF);
    }

    #[test]
    fn channel_id_from_payload_extracts_le_u32() {
        let payload = [0x01, 0x00, 0x00, 0x00, 0xAA, 0xBB];
        assert_eq!(Sv2FrameHeader::channel_id_from_payload(&payload), Some(1));
    }

    #[test]
    fn channel_id_from_payload_too_short() {
        let payload = [0x01, 0x00, 0x00];
        assert_eq!(Sv2FrameHeader::channel_id_from_payload(&payload), None);
    }

    #[test]
    fn noise_plaintext_max_is_frame_minus_mac() {
        assert_eq!(MAX_NOISE_PLAINTEXT_LEN, MAX_NOISE_FRAME_LEN - AEAD_MAC_LEN);
        assert_eq!(MAX_NOISE_PLAINTEXT_LEN, 65519);
    }

    #[tokio::test]
    async fn full_noise_handshake_and_frame_exchange() {
        use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
        use secp256k1::Secp256k1;
        use tokio::net::TcpListener;

        let secp = Secp256k1::new();
        let authority_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let authority_pubkey = authority_kp.x_only_public_key().0;

        // Bind a listener on localhost.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let authority_kp_clone = authority_kp;

        // Spawn the responder (gateway side).
        let responder_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut transport =
                perform_handshake(stream, &authority_kp_clone, 3600, Duration::from_secs(5))
                    .await
                    .unwrap();

            // Read a frame from initiator.
            let (header, payload) = transport.read_frame().await.unwrap();
            assert_eq!(header.msg_type, 0x00); // SetupConnection
            assert_eq!(payload, b"hello");

            // Send a frame back.
            transport.write_frame(0x0000, 0x01, b"world").await.unwrap();
        });

        // Initiator side.
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Create an initiator with the authority public key.
        let mut initiator = Initiator::from_raw_k(authority_pubkey.serialize()).unwrap();

        // Step 0: Initiator generates ephemeral key and sends it.
        let first_message = initiator.step_0().unwrap();
        stream.write_all(&first_message).await.unwrap();
        stream.flush().await.unwrap();

        // Read responder's response.
        let mut response = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut response).await.unwrap();

        // Step 2: Initiator processes the response.
        let mut codec = initiator.step_2(response).unwrap();

        // Send an SV2 frame: header + payload, encrypted.
        let header = Sv2FrameHeader {
            extension_type: 0x0000,
            msg_type: 0x00,
            msg_length: 5,
        };
        let mut frame_data = Vec::new();
        frame_data.extend_from_slice(&header.to_bytes());
        frame_data.extend_from_slice(b"hello");
        codec.encrypt(&mut frame_data).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (frame_data.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&frame_data).await.unwrap();
        stream.flush().await.unwrap();

        // Read response frame.
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut encrypted_resp = vec![0u8; resp_len];
        stream.read_exact(&mut encrypted_resp).await.unwrap();
        codec.decrypt(&mut encrypted_resp).unwrap();

        // Parse the response SV2 frame.
        let mut resp_hdr_bytes = [0u8; SV2_FRAME_HEADER_SIZE];
        resp_hdr_bytes.copy_from_slice(&encrypted_resp[..SV2_FRAME_HEADER_SIZE]);
        let resp_header = Sv2FrameHeader::parse(&resp_hdr_bytes);
        assert_eq!(resp_header.msg_type, 0x01); // SetupConnection.Success
        assert_eq!(&encrypted_resp[SV2_FRAME_HEADER_SIZE..], b"world");

        responder_handle.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_timeout_fires() {
        use tokio::net::TcpListener;

        let secp = secp256k1::Secp256k1::new();
        let authority_kp = Keypair::new(&secp, &mut rand::thread_rng());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect but never send the ephemeral key.
        let _client = TcpStream::connect(addr).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();

        let result =
            perform_handshake(stream, &authority_kp, 3600, Duration::from_millis(50)).await;

        assert!(matches!(result, Err(TransportError::HandshakeTimeout(_))));
    }

    #[test]
    fn load_credentials_valid_keypair() {
        let secp = secp256k1::Secp256k1::new();
        let kp = Keypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _) = kp.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());

        // Write secret key to a temp file.
        let dir = std::env::temp_dir().join("rg_test_keys");
        let _ = std::fs::create_dir_all(&dir);
        let sk_path = dir.join("test_authority.key");
        std::fs::write(&sk_path, kp.secret_key().secret_bytes()).unwrap();

        let creds = load_authority_credentials(&sk_path, &pubkey_hex, 3600).unwrap();
        assert_eq!(creds.keypair.x_only_public_key().0, xonly);
        assert_eq!(creds.cert_validity_secs, 3600);

        let _ = std::fs::remove_file(&sk_path);
    }

    #[test]
    fn load_credentials_missing_file() {
        let result = load_authority_credentials(
            Path::new("/nonexistent/path/key.bin"),
            &"aa".repeat(32),
            3600,
        );
        assert!(matches!(result, Err(KeyLoadError::FileRead { .. })));
    }

    #[test]
    fn load_credentials_wrong_length() {
        let dir = std::env::temp_dir().join("rg_test_keys");
        let _ = std::fs::create_dir_all(&dir);
        let sk_path = dir.join("test_short.key");
        std::fs::write(&sk_path, [0u8; 16]).unwrap();

        let result = load_authority_credentials(&sk_path, &"aa".repeat(32), 3600);
        assert!(matches!(
            result,
            Err(KeyLoadError::InvalidSecretKeyLength(16))
        ));

        let _ = std::fs::remove_file(&sk_path);
    }

    #[test]
    fn load_credentials_pubkey_mismatch() {
        let secp = secp256k1::Secp256k1::new();
        let kp = Keypair::new(&secp, &mut rand::thread_rng());

        let dir = std::env::temp_dir().join("rg_test_keys");
        let _ = std::fs::create_dir_all(&dir);
        let sk_path = dir.join("test_mismatch.key");
        std::fs::write(&sk_path, kp.secret_key().secret_bytes()).unwrap();

        // Use a different keypair's pubkey.
        let other_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let (other_xonly, _) = other_kp.x_only_public_key();
        let wrong_hex = hex::encode(other_xonly.serialize());

        let result = load_authority_credentials(&sk_path, &wrong_hex, 3600);
        assert!(matches!(result, Err(KeyLoadError::PubkeyMismatch { .. })));

        let _ = std::fs::remove_file(&sk_path);
    }

    #[test]
    fn load_credentials_invalid_pubkey_hex() {
        let secp = secp256k1::Secp256k1::new();
        let kp = Keypair::new(&secp, &mut rand::thread_rng());

        let dir = std::env::temp_dir().join("rg_test_keys");
        let _ = std::fs::create_dir_all(&dir);
        let sk_path = dir.join("test_badhex.key");
        std::fs::write(&sk_path, kp.secret_key().secret_bytes()).unwrap();

        // Too short.
        let result = load_authority_credentials(&sk_path, "abcd", 3600);
        assert!(matches!(result, Err(KeyLoadError::InvalidPubkeyHex(_))));

        // Not hex.
        let result = load_authority_credentials(&sk_path, &"zz".repeat(32), 3600);
        assert!(matches!(result, Err(KeyLoadError::InvalidPubkeyHex(_))));

        let _ = std::fs::remove_file(&sk_path);
    }
}
