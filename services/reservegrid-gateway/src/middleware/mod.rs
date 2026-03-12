//! Gateway middleware stack.
//!
//! Each submodule implements a single concern as a `tower::Layer` or
//! axum extractor. The router applies them in this order (outermost first):
//!
//! 1. Security headers (always applied)
//! 2. Request tracing (assigns `request_id`, opens tracing span)
//! 3. Rate limiting (token bucket per client)
//! 4. Authentication (bearer token or HMAC-SHA256)
//! 5. Input validation (body size, content-type, depth limits)

pub mod auth;
pub mod headers;
pub mod input;
pub mod rate_limit;
pub mod request_id;
pub mod tls;
