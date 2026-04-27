//! Re-export the shared rate limiter from `reservegrid-common`.
//!
//! The implementation was extracted to the common crate in v1.1.0 (S-3)
//! so sv2-gateway, rg-feed-server, and template-manager can share it.
pub use reservegrid_common::rate_limit::RateLimiter;
