//! Graceful shutdown and connection drain.
//!
//! Implements the shutdown sequence triggered by `SIGTERM` or `SIGINT`:
//! 1. Stop accepting new connections
//! 2. Set `/readyz` to 503 via `ReadinessState`
//! 3. Wait for in-flight requests up to `shutdown_drain_secs`
//! 4. Exit cleanly
//!
//! The actual signal handling and drain coordination are wired up in the
//! service entrypoint. This module provides the building blocks.

use std::time::Duration;

use crate::health::ReadinessState;

/// Execute the graceful shutdown sequence.
///
/// Sets the readiness state to not-ready, then waits for the drain period
/// to allow in-flight requests to complete. The Axum `GracefulShutdown`
/// handle (or `tokio::signal`) controls when the listener actually stops.
pub async fn drain(readiness: &ReadinessState, drain_secs: u32) {
    tracing::info!("initiating graceful shutdown, drain period = {drain_secs}s");

    // 1. Mark not ready so load balancers stop routing
    readiness.set_not_ready();

    // 2. Wait for drain period
    tokio::time::sleep(Duration::from_secs(u64::from(drain_secs))).await;

    tracing::info!("drain period complete, shutting down");
}

/// Returns a future that resolves on `SIGTERM` or `SIGINT`.
///
/// On non-Unix platforms, only `ctrl_c` is available.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap_or_else(|e| {
                tracing::error!("failed to register SIGTERM handler: {e}");
                panic!("SIGTERM handler registration failed");
            });

        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("received ctrl-c");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_sets_not_ready() {
        let state = ReadinessState::new();
        assert!(state.ready.load(std::sync::atomic::Ordering::SeqCst));

        // Use 0 drain seconds so the test completes instantly
        drain(&state, 0).await;

        assert!(!state.ready.load(std::sync::atomic::Ordering::SeqCst));
    }
}
