//! SV2 Mining Protocol message codec.
//!
//! Owned representations of SV2 messages used by the gateway, with manual
//! binary encode/decode against the SV2 wire format. These structs are
//! lifetime-free so they can be sent across async task boundaries.
//!
//! Wire format conventions (SV2 spec):
//! - All integer fields are little-endian.
//! - `STR0_255`: 1-byte length prefix followed by UTF-8 bytes.
//! - `U256`: 32 bytes, little-endian.
//! - `B0_32`: 1-byte length prefix followed by raw bytes (max 32).
//! - `OPTION<T>`: 1 byte (0=none, 1=some) followed by T if present.
//! - `bool`: 1 byte (0 or 1).
//! - `f32`: 4 bytes, IEEE 754 little-endian.

use thiserror::Error;

// Re-export message type constants from the upstream crates so callers
// do not need to depend on mining_sv2 / common_messages_sv2 directly.
pub use common_messages_sv2::{
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
pub use mining_sv2::{
    MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, MESSAGE_TYPE_NEW_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_SET_TARGET, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};

// ─────────────────────────────────────────────────────────────────────
// Codec errors
// ─────────────────────────────────────────────────────────────────────

/// Errors during SV2 message encoding or decoding.
#[derive(Debug, Error)]
pub enum Sv2CodecError {
    /// Not enough bytes in the buffer to decode the message.
    #[error("buffer underflow: need {need} bytes, have {have}")]
    BufferUnderflow { need: usize, have: usize },

    /// A string field exceeded the `STR0_255` maximum of 255 bytes.
    #[error("string too long: {len} bytes (max 255)")]
    StringTooLong { len: usize },

    /// A `B0_32` field exceeded 32 bytes.
    #[error("bytes field too long: {len} bytes (max 32)")]
    BytesTooLong { len: usize },

    /// A decoded string was not valid UTF-8.
    #[error("invalid utf8 in string field: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// An option discriminant was neither 0 nor 1.
    #[error("invalid option discriminant: {0}")]
    InvalidOptionTag(u8),
}

type Result<T> = std::result::Result<T, Sv2CodecError>;

// ─────────────────────────────────────────────────────────────────────
// Wire primitives (private helpers)
// ─────────────────────────────────────────────────────────────────────

/// Cursor-based reader for decoding fields from a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn ensure(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            return Err(Sv2CodecError::BufferUnderflow {
                need: n,
                have: self.remaining(),
            });
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.ensure(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16> {
        self.ensure(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.ensure(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> Result<u64> {
        self.ensure(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_f32(&mut self) -> Result<f32> {
        self.ensure(4)?;
        let v = f32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_u256(&mut self) -> Result<[u8; 32]> {
        self.ensure(32)?;
        let mut v = [0u8; 32];
        v.copy_from_slice(&self.buf[self.pos..self.pos + 32]);
        self.pos += 32;
        Ok(v)
    }

    fn read_str0_255(&mut self) -> Result<String> {
        let len = self.read_u8()? as usize;
        self.ensure(len)?;
        let bytes = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(String::from_utf8(bytes)?)
    }

    fn read_b0_32(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u8()? as usize;
        if len > 32 {
            return Err(Sv2CodecError::BytesTooLong { len });
        }
        self.ensure(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn read_option_u32(&mut self) -> Result<Option<u32>> {
        let tag = self.read_u8()?;
        match tag {
            0 => Ok(None),
            1 => Ok(Some(self.read_u32()?)),
            other => Err(Sv2CodecError::InvalidOptionTag(other)),
        }
    }
}

/// Buffer writer for encoding.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(128),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_f32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u256(&mut self, v: &[u8; 32]) {
        self.buf.extend_from_slice(v);
    }

    fn write_str0_255(&mut self, s: &str) -> Result<()> {
        if s.len() > 255 {
            return Err(Sv2CodecError::StringTooLong { len: s.len() });
        }
        #[allow(clippy::cast_possible_truncation)]
        self.write_u8(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn write_b0_32(&mut self, b: &[u8]) -> Result<()> {
        if b.len() > 32 {
            return Err(Sv2CodecError::BytesTooLong { len: b.len() });
        }
        #[allow(clippy::cast_possible_truncation)]
        self.write_u8(b.len() as u8);
        self.buf.extend_from_slice(b);
        Ok(())
    }

    fn write_option_u32(&mut self, v: Option<u32>) {
        match v {
            None => self.write_u8(0),
            Some(val) => {
                self.write_u8(1);
                self.write_u32(val);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Owned message structs
// ─────────────────────────────────────────────────────────────────────

/// `SetupConnection` (`msg_type` 0x00, non-channel).
#[derive(Debug, Clone)]
pub struct SetupConnection {
    /// Must be 0 (`MiningProtocol`).
    pub protocol: u8,
    pub min_version: u16,
    pub max_version: u16,
    pub flags: u32,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub vendor: String,
    pub hardware_version: String,
    pub firmware: String,
    pub device_id: String,
}

/// `SetupConnection.Success` (`msg_type` 0x01, non-channel).
#[derive(Debug, Clone)]
pub struct SetupConnectionSuccess {
    pub used_version: u16,
    pub flags: u32,
}

/// `SetupConnection.Error` (`msg_type` 0x02, non-channel).
#[derive(Debug, Clone)]
pub struct SetupConnectionError {
    pub flags: u32,
    pub error_code: String,
}

/// `OpenStandardMiningChannel` (`msg_type` 0x10, non-channel).
#[derive(Debug, Clone)]
pub struct OpenStandardMiningChannel {
    pub request_id: u32,
    pub user_identity: String,
    pub nominal_hash_rate: f32,
    /// 32 bytes LE.
    pub max_target: [u8; 32],
}

/// `OpenStandardMiningChannel.Success` (`msg_type` 0x11, non-channel).
#[derive(Debug, Clone)]
pub struct OpenStandardMiningChannelSuccess {
    pub request_id: u32,
    pub channel_id: u32,
    /// 32 bytes LE.
    pub target: [u8; 32],
    /// Up to 32 bytes.
    pub extranonce_prefix: Vec<u8>,
    pub group_channel_id: u32,
}

/// `OpenMiningChannel.Error` (`msg_type` 0x12, non-channel).
#[derive(Debug, Clone)]
pub struct OpenMiningChannelError {
    pub request_id: u32,
    pub error_code: String,
}

/// `NewMiningJob` (`msg_type` 0x15, channel message).
#[derive(Debug, Clone)]
pub struct NewMiningJob {
    pub channel_id: u32,
    pub job_id: u32,
    pub min_ntime: Option<u32>,
    pub version: u32,
    /// 32 bytes LE.
    pub merkle_root: [u8; 32],
}

/// `SetNewPrevHash` (`msg_type` 0x20, channel message).
#[derive(Debug, Clone)]
pub struct SetNewPrevHash {
    pub channel_id: u32,
    pub job_id: u32,
    /// 32 bytes LE.
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
}

/// `SetTarget` (`msg_type` 0x21, channel message).
#[derive(Debug, Clone)]
pub struct SetTarget {
    pub channel_id: u32,
    /// 32 bytes LE.
    pub maximum_target: [u8; 32],
}

/// `SubmitSharesStandard` (`msg_type` 0x1a, channel message).
#[derive(Debug, Clone)]
pub struct SubmitSharesStandard {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub job_id: u32,
    pub nonce: u32,
    pub ntime: u32,
    pub version: u32,
}

/// `SubmitShares.Success` (`msg_type` 0x1c, channel message).
#[derive(Debug, Clone)]
pub struct SubmitSharesSuccess {
    pub channel_id: u32,
    pub last_sequence_number: u32,
    pub new_submits_accepted_count: u32,
    pub new_shares_sum: u64,
}

/// `SubmitShares.Error` (`msg_type` 0x1d, channel message).
#[derive(Debug, Clone)]
pub struct SubmitSharesError {
    pub channel_id: u32,
    pub sequence_number: u32,
    pub error_code: String,
}

/// `CloseChannel` (`msg_type` 0x18, channel message).
#[derive(Debug, Clone)]
pub struct CloseChannel {
    pub channel_id: u32,
    pub reason_code: String,
}

// ─────────────────────────────────────────────────────────────────────
// Decode functions
// ─────────────────────────────────────────────────────────────────────

impl SetupConnection {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.protocol);
        w.write_u16(self.min_version);
        w.write_u16(self.max_version);
        w.write_u32(self.flags);
        w.write_str0_255(&self.endpoint_host)?;
        w.write_u16(self.endpoint_port);
        w.write_str0_255(&self.vendor)?;
        w.write_str0_255(&self.hardware_version)?;
        w.write_str0_255(&self.firmware)?;
        w.write_str0_255(&self.device_id)?;
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload (after frame header).
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            protocol: r.read_u8()?,
            min_version: r.read_u16()?,
            max_version: r.read_u16()?,
            flags: r.read_u32()?,
            endpoint_host: r.read_str0_255()?,
            endpoint_port: r.read_u16()?,
            vendor: r.read_str0_255()?,
            hardware_version: r.read_str0_255()?,
            firmware: r.read_str0_255()?,
            device_id: r.read_str0_255()?,
        })
    }
}

impl SetupConnectionSuccess {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u16(self.used_version);
        w.write_u32(self.flags);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            used_version: r.read_u16()?,
            flags: r.read_u32()?,
        })
    }
}

impl SetupConnectionError {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.flags);
        w.write_str0_255(&self.error_code)?;
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            flags: r.read_u32()?,
            error_code: r.read_str0_255()?,
        })
    }
}

impl OpenStandardMiningChannel {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.request_id);
        w.write_str0_255(&self.user_identity)?;
        w.write_f32(self.nominal_hash_rate);
        w.write_u256(&self.max_target);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            request_id: r.read_u32()?,
            user_identity: r.read_str0_255()?,
            nominal_hash_rate: r.read_f32()?,
            max_target: r.read_u256()?,
        })
    }
}

impl OpenStandardMiningChannelSuccess {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.request_id);
        w.write_u32(self.channel_id);
        w.write_u256(&self.target);
        w.write_b0_32(&self.extranonce_prefix)?;
        w.write_u32(self.group_channel_id);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            request_id: r.read_u32()?,
            channel_id: r.read_u32()?,
            target: r.read_u256()?,
            extranonce_prefix: r.read_b0_32()?,
            group_channel_id: r.read_u32()?,
        })
    }
}

impl OpenMiningChannelError {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.request_id);
        w.write_str0_255(&self.error_code)?;
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            request_id: r.read_u32()?,
            error_code: r.read_str0_255()?,
        })
    }
}

impl NewMiningJob {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u32(self.job_id);
        w.write_option_u32(self.min_ntime);
        w.write_u32(self.version);
        w.write_u256(&self.merkle_root);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            job_id: r.read_u32()?,
            min_ntime: r.read_option_u32()?,
            version: r.read_u32()?,
            merkle_root: r.read_u256()?,
        })
    }
}

impl SetNewPrevHash {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u32(self.job_id);
        w.write_u256(&self.prev_hash);
        w.write_u32(self.min_ntime);
        w.write_u32(self.nbits);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            job_id: r.read_u32()?,
            prev_hash: r.read_u256()?,
            min_ntime: r.read_u32()?,
            nbits: r.read_u32()?,
        })
    }
}

impl SetTarget {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u256(&self.maximum_target);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            maximum_target: r.read_u256()?,
        })
    }
}

impl SubmitSharesStandard {
    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            sequence_number: r.read_u32()?,
            job_id: r.read_u32()?,
            nonce: r.read_u32()?,
            ntime: r.read_u32()?,
            version: r.read_u32()?,
        })
    }

    /// Encode to SV2 binary payload (for test symmetry).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u32(self.sequence_number);
        w.write_u32(self.job_id);
        w.write_u32(self.nonce);
        w.write_u32(self.ntime);
        w.write_u32(self.version);
        Ok(w.into_bytes())
    }
}

impl SubmitSharesSuccess {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u32(self.last_sequence_number);
        w.write_u32(self.new_submits_accepted_count);
        w.write_u64(self.new_shares_sum);
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            last_sequence_number: r.read_u32()?,
            new_submits_accepted_count: r.read_u32()?,
            new_shares_sum: r.read_u64()?,
        })
    }
}

impl SubmitSharesError {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_u32(self.sequence_number);
        w.write_str0_255(&self.error_code)?;
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            sequence_number: r.read_u32()?,
            error_code: r.read_str0_255()?,
        })
    }
}

impl CloseChannel {
    /// Encode to SV2 binary payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u32(self.channel_id);
        w.write_str0_255(&self.reason_code)?;
        Ok(w.into_bytes())
    }

    /// Decode from SV2 binary payload.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        Ok(Self {
            channel_id: r.read_u32()?,
            reason_code: r.read_str0_255()?,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn setup_connection_round_trip() {
        let msg = SetupConnection {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: "pool.example.com".to_string(),
            endpoint_port: 3333,
            vendor: "TestMiner".to_string(),
            hardware_version: "1.0".to_string(),
            firmware: "2.0".to_string(),
            device_id: "dev-001".to_string(),
        };
        // Encode manually for decode test.
        let mut w = Writer::new();
        w.write_u8(msg.protocol);
        w.write_u16(msg.min_version);
        w.write_u16(msg.max_version);
        w.write_u32(msg.flags);
        w.write_str0_255(&msg.endpoint_host).unwrap();
        w.write_u16(msg.endpoint_port);
        w.write_str0_255(&msg.vendor).unwrap();
        w.write_str0_255(&msg.hardware_version).unwrap();
        w.write_str0_255(&msg.firmware).unwrap();
        w.write_str0_255(&msg.device_id).unwrap();
        let encoded = w.into_bytes();

        let decoded = SetupConnection::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol, 0);
        assert_eq!(decoded.min_version, 2);
        assert_eq!(decoded.max_version, 2);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.endpoint_host, "pool.example.com");
        assert_eq!(decoded.endpoint_port, 3333);
        assert_eq!(decoded.vendor, "TestMiner");
        assert_eq!(decoded.device_id, "dev-001");
    }

    #[test]
    fn setup_connection_success_round_trip() {
        let msg = SetupConnectionSuccess {
            used_version: 2,
            flags: 0x01,
        };
        let encoded = msg.encode().unwrap();
        let decoded = SetupConnectionSuccess::decode(&encoded).unwrap();
        assert_eq!(decoded.used_version, 2);
        assert_eq!(decoded.flags, 0x01);
    }

    #[test]
    fn open_standard_mining_channel_round_trip() {
        let msg = OpenStandardMiningChannel {
            request_id: 42,
            user_identity: "worker.1".to_string(),
            nominal_hash_rate: 100.0,
            max_target: [0xFF; 32],
        };
        // Manually encode to test decode.
        let mut w = Writer::new();
        w.write_u32(msg.request_id);
        w.write_str0_255(&msg.user_identity).unwrap();
        w.write_f32(msg.nominal_hash_rate);
        w.write_u256(&msg.max_target);
        let encoded = w.into_bytes();

        let decoded = OpenStandardMiningChannel::decode(&encoded).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.user_identity, "worker.1");
        assert!((decoded.nominal_hash_rate - 100.0).abs() < f32::EPSILON);
        assert_eq!(decoded.max_target, [0xFF; 32]);
    }

    #[test]
    fn open_standard_mining_channel_success_round_trip() {
        let msg = OpenStandardMiningChannelSuccess {
            request_id: 42,
            channel_id: 1,
            target: [0x01; 32],
            extranonce_prefix: vec![0xAA, 0xBB, 0xCC, 0xDD],
            group_channel_id: 0,
        };
        let encoded = msg.encode().unwrap();
        let decoded = OpenStandardMiningChannelSuccess::decode(&encoded).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.target, [0x01; 32]);
        assert_eq!(decoded.extranonce_prefix, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(decoded.group_channel_id, 0);
    }

    #[test]
    fn new_mining_job_round_trip_with_min_ntime() {
        let msg = NewMiningJob {
            channel_id: 5,
            job_id: 100,
            min_ntime: Some(1_700_000_000),
            version: 0x2000_0000,
            merkle_root: [0xAB; 32],
        };
        let encoded = msg.encode().unwrap();
        let decoded = NewMiningJob::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 5);
        assert_eq!(decoded.job_id, 100);
        assert_eq!(decoded.min_ntime, Some(1_700_000_000));
        assert_eq!(decoded.version, 0x2000_0000);
        assert_eq!(decoded.merkle_root, [0xAB; 32]);
    }

    #[test]
    fn new_mining_job_round_trip_no_min_ntime() {
        let msg = NewMiningJob {
            channel_id: 1,
            job_id: 1,
            min_ntime: None,
            version: 0x2000_0000,
            merkle_root: [0x00; 32],
        };
        let encoded = msg.encode().unwrap();
        let decoded = NewMiningJob::decode(&encoded).unwrap();
        assert_eq!(decoded.min_ntime, None);
    }

    #[test]
    fn set_new_prev_hash_round_trip() {
        let msg = SetNewPrevHash {
            channel_id: 1,
            job_id: 50,
            prev_hash: [0xDE; 32],
            min_ntime: 1_700_000_000,
            nbits: 0x1703_4219,
        };
        let encoded = msg.encode().unwrap();
        let decoded = SetNewPrevHash::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.job_id, 50);
        assert_eq!(decoded.prev_hash, [0xDE; 32]);
        assert_eq!(decoded.min_ntime, 1_700_000_000);
        assert_eq!(decoded.nbits, 0x1703_4219);
    }

    #[test]
    fn set_target_round_trip() {
        let msg = SetTarget {
            channel_id: 3,
            maximum_target: [0x00; 32],
        };
        let encoded = msg.encode().unwrap();
        let decoded = SetTarget::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 3);
        assert_eq!(decoded.maximum_target, [0x00; 32]);
    }

    #[test]
    fn submit_shares_standard_round_trip() {
        let msg = SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 7,
            job_id: 42,
            nonce: 0xDEAD_BEEF,
            ntime: 1_700_000_100,
            version: 0x2000_0000,
        };
        let encoded = msg.encode().unwrap();
        let decoded = SubmitSharesStandard::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.job_id, 42);
        assert_eq!(decoded.nonce, 0xDEAD_BEEF);
        assert_eq!(decoded.ntime, 1_700_000_100);
        assert_eq!(decoded.version, 0x2000_0000);
    }

    #[test]
    fn submit_shares_success_round_trip() {
        let msg = SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 7,
            new_submits_accepted_count: 3,
            new_shares_sum: 1_000_000,
        };
        let encoded = msg.encode().unwrap();
        let decoded = SubmitSharesSuccess::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.last_sequence_number, 7);
        assert_eq!(decoded.new_submits_accepted_count, 3);
        assert_eq!(decoded.new_shares_sum, 1_000_000);
    }

    #[test]
    fn submit_shares_error_round_trip() {
        let msg = SubmitSharesError {
            channel_id: 1,
            sequence_number: 7,
            error_code: "stale-share".to_string(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = SubmitSharesError::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.error_code, "stale-share");
    }

    #[test]
    fn close_channel_round_trip() {
        let msg = CloseChannel {
            channel_id: 2,
            reason_code: "miner-disconnect".to_string(),
        };
        let encoded = msg.encode().unwrap();
        let decoded = CloseChannel::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, 2);
        assert_eq!(decoded.reason_code, "miner-disconnect");
    }

    #[test]
    fn string_too_long_rejected() {
        let long_str = "x".repeat(256);
        let msg = CloseChannel {
            channel_id: 1,
            reason_code: long_str,
        };
        assert!(msg.encode().is_err());
    }

    #[test]
    fn buffer_underflow_detected() {
        let short_buf = [0u8; 3];
        let result = SubmitSharesStandard::decode(&short_buf);
        assert!(result.is_err());
    }

    #[test]
    fn message_type_constants_match_spec() {
        assert_eq!(MESSAGE_TYPE_SETUP_CONNECTION, 0x00);
        assert_eq!(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, 0x01);
        assert_eq!(MESSAGE_TYPE_SETUP_CONNECTION_ERROR, 0x02);
        assert_eq!(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, 0x10);
        assert_eq!(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, 0x11);
        assert_eq!(MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, 0x12);
        assert_eq!(MESSAGE_TYPE_NEW_MINING_JOB, 0x15);
        assert_eq!(MESSAGE_TYPE_CLOSE_CHANNEL, 0x18);
        assert_eq!(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, 0x1a);
        assert_eq!(MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, 0x1c);
        assert_eq!(MESSAGE_TYPE_SUBMIT_SHARES_ERROR, 0x1d);
        assert_eq!(MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, 0x20);
        assert_eq!(MESSAGE_TYPE_SET_TARGET, 0x21);
    }
}
