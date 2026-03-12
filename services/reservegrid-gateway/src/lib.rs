//! reservegrid-gateway: SV2 Mining Protocol endpoint for miners.
//!
//! Miner-facing SV2 gateway for the reservegrid-os stack.
//! Phase 0 provides the middleware skeleton: TLS, authentication,
//! rate limiting, request tracing, input validation, and security headers.
//!
//! Phase 1 adds SV2 transport, job distribution, channel management,
//! and the share handling pipeline.

pub mod health;
pub mod logging;
pub mod middleware;
pub mod panic_guard;
pub mod protocol;
pub mod rejection;
pub mod shutdown;
