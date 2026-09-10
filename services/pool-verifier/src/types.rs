use std::sync::atomic::AtomicBool;

/// Opaque handle that allows runtime log-level changes via `reload`.
pub type LogReloadHandle =
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>;

/// Track whether policy loaded successfully at startup.
pub static POLICY_LOADED_OK: AtomicBool = AtomicBool::new(false);

/// PB-45. Whether `[policy.mempool] enforce = true` actually wired the Phase 2
/// view at startup, set once from `build_phase2_mempool_view`'s result.
///
/// Readiness needs it because `mempool_reachable` was computed purely from the
/// freshness of `LAST_MEMPOOL_OK_UNIX`, which is never set when the view is not
/// wired. A Phase 1 deployment therefore reported `ready: false` forever, which
/// is why both compose stacks probed `/health` (hardcoded "ok") instead and the
/// only signal that would have surfaced PB-36 at deploy time was consumed by
/// nothing.
pub static MEMPOOL_ENFORCED: AtomicBool = AtomicBool::new(false);
