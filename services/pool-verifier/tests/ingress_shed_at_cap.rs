//! PB-31 root fix: shed at cap, against the real binary.
//!
//! A pool whose gateways share one NAT address fills that address's
//! per-IP ceiling. When one gateway's path dies silently, its old socket
//! holds a slot nothing will ever write to again, and the gateway's own
//! reconnect is refused by that slot. Before this fix the slot came back
//! only at the idle budget, 60 s at the shipped default, measured at
//! 60.08 s. Now the dead socket ends itself once it has been silent for
//! twice its learned heartbeat interval while the address is full.
//!
//! What these tests hold the binary to:
//! * the replacement is refused while the dead socket is inside its
//!   threshold, and admitted once past it, long before the idle budget;
//! * the live gateways sharing the address are never shed, although the
//!   address is full the whole time;
//! * with room at the address, a silent socket keeps its slot, and sheds
//!   only once the address fills.
//!
//! Heartbeats every 500 ms learn the 3 s floor (`SHED_FLOOR`); the idle
//! budget is 40 s, so an idle reap cannot pass for a shed inside these
//! windows.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

mod common;

use common::{
    BootOptions, Conn, boot_verifier, closed_within, connect, heartbeat, sample_value,
    scrape_metrics,
};

const PER_IP: u32 = 3;
const IDLE_SECS: u64 = 40;
const BEAT: Duration = Duration::from_millis(500);
const ACK: Duration = Duration::from_secs(3);
/// `SHED_FLOOR`, which 500 ms heartbeats learn.
const LEARNED: Duration = Duration::from_secs(3);
/// Half a second of slack under `LEARNED` for timer and scheduling jitter.
const EARLIEST: Duration = Duration::from_millis(2_500);

/// A gateway that keeps heartbeating until told to stop, and reports
/// whether any heartbeat went unanswered. A live peer's heartbeats never
/// failing is how these tests see that it was not shed.
fn live_gateway(mut conn: Conn, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<(Conn, u32)> {
    tokio::spawn(async move {
        let mut missed = 0;
        while !stop.load(Ordering::Relaxed) {
            if !heartbeat(&mut conn, ACK).await {
                missed += 1;
            }
            tokio::time::sleep(BEAT).await;
        }
        (conn, missed)
    })
}

/// Connect and complete one heartbeat, proving admission. Refusal looks
/// like a completed TCP handshake followed by EOF, which `heartbeat`
/// reports as false.
async fn try_admit(addr: &str) -> Option<Conn> {
    let mut conn = connect(addr, Duration::from_secs(10)).await;
    heartbeat(&mut conn, ACK).await.then_some(conn)
}

/// Heartbeat enough for the verifier to learn the cadence, then go silent
/// with the socket still open: a gateway whose path died without a FIN.
async fn learn_then_die(conn: &mut Conn) -> Instant {
    for _ in 0..4 {
        assert!(
            heartbeat(conn, ACK).await,
            "a live heartbeat went unanswered"
        );
        tokio::time::sleep(BEAT).await;
    }
    assert!(heartbeat(conn, ACK).await);
    Instant::now()
}

#[tokio::test]
async fn a_dead_gateway_at_a_full_address_makes_way_for_its_reconnect() {
    let mut booted = boot_verifier(BootOptions {
        label: "pb31-shed",
        max_connections: 8,
        max_connections_per_ip: Some(PER_IP),
        idle_timeout_secs: Some(IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    let stop = Arc::new(AtomicBool::new(false));
    let a = live_gateway(
        try_admit(&addr).await.expect("A admitted"),
        Arc::clone(&stop),
    );
    let b = live_gateway(
        try_admit(&addr).await.expect("B admitted"),
        Arc::clone(&stop),
    );
    let mut dead = try_admit(&addr).await.expect("C admitted");
    let died = learn_then_die(&mut dead).await;

    // The reconnect: refused while the dead socket holds the last slot,
    // admitted once it sheds. Retrying every 250 ms, faster than a real
    // gateway, so the admission time measures the shed rather than a
    // retry interval.
    let mut refusals = 0u32;
    let replacement = loop {
        if let Some(conn) = try_admit(&addr).await {
            break conn;
        }
        refusals += 1;
        assert!(
            died.elapsed() < Duration::from_secs(IDLE_SECS / 2),
            "the replacement was still refused {:?} after the death; the doubling is back",
            died.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let waited = died.elapsed();

    assert!(
        refusals >= 1,
        "the address was never full, so this proved nothing"
    );
    assert!(
        waited >= EARLIEST,
        "admitted after {waited:?}, before the dead socket reached its threshold"
    );
    assert!(
        waited <= LEARNED + Duration::from_secs(2),
        "admitted after {waited:?}; the shed should free the slot at the learned {LEARNED:?}"
    );
    assert!(
        closed_within(&mut dead, Duration::from_secs(2)).await,
        "the dead socket's connection was not ended"
    );

    stop.store(true, Ordering::Relaxed);
    let (_a, missed_a) = a.await.unwrap();
    let (_b, missed_b) = b.await.unwrap();
    assert_eq!(
        (missed_a, missed_b),
        (0, 0),
        "a live gateway at the full address lost a heartbeat: it was shed"
    );

    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_shed_at_cap_total"),
        1
    );
    assert_eq!(
        sample_value(&body, "verifier_connections_reaped_idle_total"),
        0,
        "an idle reap is not the fix"
    );
    assert!(sample_value(&body, "verifier_connections_refused_per_ip_total") >= 1);
    drop(replacement);
    assert!(
        booted.exit_status().is_none(),
        "the verifier died under the test"
    );
}

#[tokio::test]
async fn a_silent_connection_keeps_its_slot_until_its_address_fills() {
    let mut booted = boot_verifier(BootOptions {
        label: "pb31-room",
        max_connections: 8,
        max_connections_per_ip: Some(PER_IP),
        idle_timeout_secs: Some(IDLE_SECS),
        ..BootOptions::default()
    })
    .await;
    let addr = booted.v4_addr();

    let stop = Arc::new(AtomicBool::new(false));
    let a = live_gateway(
        try_admit(&addr).await.expect("A admitted"),
        Arc::clone(&stop),
    );
    let mut quiet = try_admit(&addr).await.expect("C admitted");
    learn_then_die(&mut quiet).await;

    // Two of three slots taken: past its threshold with room at the
    // address, the silent connection must keep its slot.
    assert!(
        !closed_within(&mut quiet, LEARNED + Duration::from_millis(1_500)).await,
        "shed with room at its address"
    );
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_shed_at_cap_total"),
        0
    );

    // The third slot fills the address: the silent connection, already
    // past its threshold, sheds on its next recheck.
    let filler = live_gateway(
        try_admit(&addr).await.expect("the filler admitted"),
        Arc::clone(&stop),
    );
    assert!(
        closed_within(&mut quiet, Duration::from_secs(3)).await,
        "past its threshold at a now-full address, it never shed"
    );

    stop.store(true, Ordering::Relaxed);
    assert_eq!(a.await.unwrap().1, 0, "a live gateway was shed");
    assert_eq!(filler.await.unwrap().1, 0, "the filler was shed");
    let body = scrape_metrics(booted.http_port).await;
    assert_eq!(
        sample_value(&body, "verifier_connections_shed_at_cap_total"),
        1
    );
    assert_eq!(
        sample_value(&body, "verifier_connections_reaped_idle_total"),
        0
    );
    assert!(
        booted.exit_status().is_none(),
        "the verifier died under the test"
    );
}
