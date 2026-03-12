use std::sync::atomic::AtomicBool;

/// Opaque handle that allows runtime log-level changes via `reload`.
pub type LogReloadHandle =
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>;

/// Track whether policy loaded successfully at startup.
pub static POLICY_LOADED_OK: AtomicBool = AtomicBool::new(false);
