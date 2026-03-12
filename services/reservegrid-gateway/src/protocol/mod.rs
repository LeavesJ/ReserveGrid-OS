//! Protocol hardening primitives.
//!
//! Replay prevention (nonce + timestamp), response timing normalization,
//! and cryptographic algorithm negotiation.

pub mod nonce;
pub mod timing;
