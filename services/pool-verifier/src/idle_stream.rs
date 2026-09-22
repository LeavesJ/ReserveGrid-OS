//! No-progress deadline for one ingress socket (PB-27).
//!
//! PB-26 released an ingress permit only when the peer's socket reported
//! EOF or RST. A peer that connected and never spoke therefore held its
//! slot for the life of the process, and 32 such sockets locked out
//! every legitimate stream. The reported measurement: eight silent
//! sockets against a cap of eight kept a legitimate peer out for the
//! full 45 s of the probe.
//!
//! The budget here is **idle since last progress**, never total
//! connection age. That distinction is the launch gate, not a nicety: a
//! 20 MiB `raw_block_hex` line is why `MAX_INTERNAL_LINE_BYTES` is
//! 20 MiB at all, and over a slow link one line legitimately takes
//! longer than any budget an operator would set against squatters.
//! Wrapping the whole read in one `tokio::time::timeout` would reap that
//! transfer; resetting the deadline on every byte that actually moves
//! does not.
//!
//! One deadline covers both directions, because the wrapper sits under
//! `tokio::io::split` and both halves poll through it. That is what
//! catches the second reported shape, a peer that floods templates and
//! never reads its verdicts: the read side sees progress, but the
//! connection task is parked inside `write_all` against a receive window
//! the peer will never drain, so no read is polled and the deadline
//! fires on the stalled write.
//!
//! The wrapper is applied to the raw `TcpStream` before the TLS
//! acceptor, so it also covers a peer that opens TCP and never sends a
//! `ClientHello`. PB-26 takes the permit before the handshake on purpose
//! and that ordering is preserved.
//!
//! **Shed at cap (PB-31).** A second, shorter deadline applies only while
//! the connection's source address is full. A gateway whose path dies
//! silently (a NAT that reboots and remaps, a host that resets without a
//! FIN) leaves a socket nothing will ever write to again, and it held its
//! per-IP slot for the whole idle budget while the gateway's reconnect was
//! refused by that very slot. So a connection that has been silent for
//! its shed threshold, while its address sits at the per-IP ceiling,
//! ends itself, freeing its slot for whoever connects next from that
//! address. Usually that is the gateway being refused; the shed does not
//! check that anyone is waiting.
//!
//! This bounds that doubling; it does not delete it, and nothing based on
//! silence can. A dead socket and a live gateway between two heartbeats
//! look identical on the wire, so the threshold has to outlast a live
//! peer's longest normal silence. The verifier cannot read the gateway's
//! heartbeat setting, so it learns it: `HeartbeatCadence` counts a
//! connection's heartbeats and sets the threshold to twice the time since the
//! connection started divided by the intervals seen, never under
//! `SHED_FLOOR`. For sv2-gateway that estimate can never fall below the real
//! interval, however late or bunched the verifier's reads are (see the type).
//! The two estimators before it, the largest recent interval and then the
//! same with short intervals ignored, both learned too short a threshold from
//! reads that arrived bunched, and each got a live gateway shed in a T2
//! review. Until four heartbeats are seen, and forever for a peer that never
//! heartbeats, the threshold is `shed_fallback(idle)`, 15 s at the shipped
//! 60 s budget.
//!
//! What the shed helps, and what it does not. It helps when a gateway's old
//! path is dead and its new one is refused: a NAT remap that answers the
//! gateway's next write with a reset, a gateway host that crashes and comes
//! back, or a path that black-holes, which sv2-gateway gives up on after
//! three to four heartbeats of silence, or up to about seven when the black
//! hole swallows a template mid-write, and reconnects from (PB-51). It does
//! not touch refusals by the global cap, and with the per-IP ceiling
//! disabled (`0`) there is no full address and so no shed.
//!
//! Only this connection's own task ever ends it and releases its slot,
//! so the per-IP count is decremented by its owner alone: there is no
//! eviction race, and no newcomer is ever admitted over the ceiling. The
//! newcomer is still refused until the shed happens, and gets in on its
//! next retry.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use reservegrid_common::per_ip::PerIpConnectionTracker;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// No learned threshold goes below this. It keeps a peer that heartbeats
/// very fast from being shed by one late segment: a single TCP
/// retransmission on a WAN is a few hundred milliseconds, and this leaves
/// several.
pub(crate) const SHED_FLOOR: Duration = Duration::from_secs(3);

/// How often a connection already past its shed threshold looks again at
/// whether its address has filled. Under the gateway's 2 s minimum
/// reconnect delay, so a slot freed this way is normally open by the
/// refused gateway's next attempt.
pub(crate) const SHED_RECHECK: Duration = Duration::from_millis(500);

/// Heartbeats before a cadence is trusted: four, so three intervals.
const CADENCE_LEARN_AFTER: u32 = 4;

/// The threshold for a connection with no learned cadence: a quarter of
/// the idle budget, never under 10 s. That is 15 s at the shipped 60 s,
/// three times the heartbeat interval sv2-gateway shipped with before
/// 2.0.0, so an older gateway is safe before its cadence is learned. At an
/// idle budget of 10 s or less it is not shorter than the budget, and
/// shedding never happens before the idle reap would.
pub(crate) fn shed_fallback(idle: Duration) -> Duration {
    (idle / 4).max(Duration::from_secs(10))
}

/// What a connection needs to shed itself at a full address (PB-31).
pub(crate) struct ShedAtCap {
    /// The ingress's own tracker, so "full" is the same count the accept
    /// loop refuses on.
    pub(crate) per_ip: PerIpConnectionTracker,
    /// This connection's source address.
    pub(crate) ip: IpAddr,
    /// Silence, in milliseconds, after which this connection yields its
    /// slot while its address is full. Written by `HeartbeatCadence` from
    /// the message loop, read here.
    pub(crate) after_ms: Arc<AtomicU64>,
    /// Set when the connection shed itself, so the task can count it apart
    /// from an idle reap.
    pub(crate) shed: Arc<AtomicBool>,
}

impl ShedAtCap {
    fn after(&self) -> Duration {
        Duration::from_millis(self.after_ms.load(Ordering::Relaxed))
    }

    /// At the ceiling right now. A disabled ceiling is never full, and a
    /// poisoned tracker counts as empty, so neither ever sheds; the idle
    /// budget still reclaims the slot.
    fn address_full(&self) -> bool {
        let max = self.per_ip.max_per_ip();
        max != 0 && self.per_ip.count_for(self.ip) >= max
    }
}

/// Learns a peer's heartbeat interval from its heartbeats, and publishes the
/// shed threshold that follows from it (PB-31).
///
/// The verifier cannot read the gateway's `heartbeat_interval_ms`, and the
/// heartbeat payload is empty, so the interval is observed rather than
/// configured. That is also what lets a gateway still on the pre-2.0.0
/// default of 5 s and one on the current 2 s share a verifier safely: each
/// connection gets a threshold fitted to its own peer.
///
/// **The estimate is an upper bound on the interval, whatever the reads look
/// like.** It is `(latest arrival - connection start) / (heartbeats - 1)`.
/// sv2-gateway sends heartbeats from a `tokio::time::interval`, which never
/// fires ahead of its schedule: a late tick fires late, and missed ticks
/// catch up but never get ahead. Over TLS its first heartbeat goes out after
/// the handshake, so after this connection started. So heartbeat `n` is sent
/// no earlier than `start + (n - 1) * H` and read no earlier than that, and
/// the estimate is never below `H`, however late, bunched, or
/// reordered-in-time the verifier's reads are. That is the property the
/// earlier estimators lacked: they measured intervals between READS, which a
/// busy verifier compresses. Delays only make this estimate larger, which
/// errs toward keeping a connection.
///
/// Over plaintext, which the gateway allows with a warning, its interval
/// starts at TCP connect, so a verifier that accepts `D` late can learn
/// `H - D / (n - 1)`. At 2 s the 3 s floor keeps that from ever shedding a
/// live peer; at 5 s it takes an accept more than 7.5 s late (PB-31 final
/// review, measured).
///
/// A peer that sends heartbeats faster than it later goes on to, which no
/// fixed-interval timer does, can learn a threshold shorter than its later
/// silences. It is treated like any other quiet connection at a full
/// address, which J accepted for diagnostic connections.
pub(crate) struct HeartbeatCadence {
    after_ms: Arc<AtomicU64>,
    started: Instant,
    heartbeats: u32,
}

impl HeartbeatCadence {
    /// `started` must not be after the peer's first heartbeat could be sent:
    /// the connection's own start, taken before its TLS handshake.
    pub(crate) fn new(after_ms: Arc<AtomicU64>, started: Instant) -> Self {
        Self {
            after_ms,
            started,
            heartbeats: 0,
        }
    }

    /// A heartbeat arrived at `now`.
    pub(crate) fn observe(&mut self, now: Instant) {
        self.heartbeats = self.heartbeats.saturating_add(1);
        if self.heartbeats < CADENCE_LEARN_AFTER {
            return;
        }
        let per_interval = now.saturating_duration_since(self.started) / (self.heartbeats - 1);
        let after = (per_interval * 2).max(SHED_FLOOR);
        let ms = u64::try_from(after.as_millis()).unwrap_or(u64::MAX);
        self.after_ms.store(ms, Ordering::Relaxed);
    }
}

/// Wraps a stream with a deadline that only advances when bytes move.
pub(crate) struct IdleTimeout<S> {
    inner: S,
    idle: Duration,
    deadline: Pin<Box<Sleep>>,
    /// When a byte last moved, in either direction.
    last_progress: Instant,
    /// Set when the deadline fired, so the connection task can tell a
    /// reap from a peer that closed on its own and count it. Shared with
    /// the accept loop because the stream itself is consumed by
    /// `tokio::io::split` and by the TLS acceptor.
    reaped: Arc<AtomicBool>,
    /// The shed-at-cap rule, when the ingress enforces a per-IP ceiling.
    shed: Option<ShedAtCap>,
}

impl<S> IdleTimeout<S> {
    /// Wrap `inner`, arming the first deadline at `idle` from now.
    pub(crate) fn new(inner: S, idle: Duration, reaped: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
            last_progress: Instant::now(),
            reaped,
            shed: None,
        }
    }

    /// Also end the connection early when it has been silent past its
    /// shed threshold while its address is full (PB-31).
    pub(crate) fn with_shed_at_cap(mut self, shed: ShedAtCap) -> Self {
        self.shed = Some(shed);
        let first = self.first_look();
        self.deadline.as_mut().reset(first);
        self
    }

    /// When the deadline should next fire after progress at
    /// `last_progress`: the shed threshold if that comes first, else the
    /// idle budget.
    fn first_look(&self) -> Instant {
        let idle = self.last_progress + self.idle;
        match &self.shed {
            Some(shed) => (self.last_progress + shed.after()).min(idle),
            None => idle,
        }
    }

    /// Bytes moved: push the deadline out.
    fn made_progress(&mut self) {
        self.last_progress = Instant::now();
        let next = self.first_look();
        self.deadline.as_mut().reset(next);
    }

    /// The inner stream is not ready. Either a budget is spent, in which
    /// case the connection ends with a `TimedOut` error the caller
    /// surfaces, or the timer registers the waker and we stay pending.
    fn poll_no_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        loop {
            if self.deadline.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let now = Instant::now();
            let silent = now.saturating_duration_since(self.last_progress);
            if silent >= self.idle {
                self.reaped.store(true, Ordering::Relaxed);
                return Poll::Ready(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ingress connection made no progress within the idle budget",
                ));
            }
            let idle_at = self.last_progress + self.idle;
            let next = match &self.shed {
                Some(shed) => {
                    let after = shed.after();
                    if silent >= after && shed.address_full() {
                        shed.shed.store(true, Ordering::Relaxed);
                        return Poll::Ready(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "ingress connection yielded its slot: silent at a full address",
                        ));
                    }
                    // Not yet past the threshold (it may have been learned
                    // after this deadline was armed), or past it with room
                    // at the address: look again, never later than idle.
                    let at = if silent < after {
                        self.last_progress + after
                    } else {
                        now + SHED_RECHECK
                    };
                    at.min(idle_at)
                }
                None => idle_at,
            };
            // Re-armed in the future, so the next poll registers the waker
            // and returns pending.
            self.deadline.as_mut().reset(next);
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeout<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // A ready read with nothing filled is EOF, which is not
                // progress; the caller ends the connection on it anyway.
                if buf.filled().len() > before {
                    this.made_progress();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeout<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.made_progress();
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            // Deliberately no `made_progress` here. A `TcpStream` flush
            // is a no-op that returns ready without moving a byte, so
            // resetting on it would let a caller that flushes in a loop
            // hold the deadline open forever.
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => this.poll_no_progress(cx).map(Err),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::IdleTimeout;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A peer that connects and sends nothing must be ended by the
    /// deadline, and the flag must say the deadline is why.
    #[tokio::test]
    async fn silent_peer_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_millis(150), reaped.clone());

        // Outer bound so a budget that never fires fails this test
        // instead of hanging the suite.
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the deadline never fired; a silent peer would hold its slot forever")
            .expect_err("must time out");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            reaped.load(Ordering::Relaxed),
            "the reap must be reportable"
        );
    }

    /// The launch-gate semantics in miniature: a peer that drips bytes
    /// for several multiples of the budget, never pausing longer than
    /// the budget, must not be reaped. A total-connection-age budget
    /// fails this.
    #[tokio::test]
    async fn drip_that_outlasts_the_budget_is_not_reaped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let idle = Duration::from_millis(200);
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, idle, reaped.clone());

        let writer = tokio::spawn(async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                if client.write_all(b"x").await.is_err() {
                    break;
                }
            }
            // Hold the socket open so the read below ends on the
            // deadline rather than on EOF.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut got = 0usize;
        let mut buf = [0u8; 4];
        while got < 10 {
            let n = stream
                .read(&mut buf)
                .await
                .expect("drip must not be reaped");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        assert!(
            !reaped.load(Ordering::Relaxed),
            "a peer making progress must never be reaped"
        );
        writer.abort();
    }

    /// A write that cannot drain must also hit the deadline, which is
    /// the peer-that-never-reads shape.
    #[tokio::test]
    async fn stalled_write_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_millis(150), reaped.clone());

        // Push until the client's unread receive window and the server's
        // send buffer are both full, then the write parks.
        let payload = vec![0u8; 256 * 1024];
        let err = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match stream.write_all(&payload).await {
                    Ok(()) => {}
                    Err(e) => break e,
                }
            }
        })
        .await
        .expect("the deadline never fired on a write the peer will never drain");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(reaped.load(Ordering::Relaxed));
        drop(client);
    }

    // ── PB-31: shed at cap ──────────────────────────────────────────────

    use super::{HeartbeatCadence, SHED_FLOOR, ShedAtCap};
    use reservegrid_common::per_ip::PerIpConnectionTracker;
    use std::sync::atomic::AtomicU64;

    /// A connected pair; the server side is what the ingress wraps.
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    fn shed_rule(per_ip: &PerIpConnectionTracker, after: Duration) -> (ShedAtCap, Arc<AtomicBool>) {
        let shed = Arc::new(AtomicBool::new(false));
        let rule = ShedAtCap {
            per_ip: per_ip.clone(),
            ip: "127.0.0.1".parse().unwrap(),
            after_ms: Arc::new(AtomicU64::new(u64::try_from(after.as_millis()).unwrap())),
            shed: Arc::clone(&shed),
        };
        (rule, shed)
    }

    /// The fix itself: silent past the threshold while its address is at
    /// the ceiling, the connection ends itself long before the idle budget.
    #[tokio::test]
    async fn a_silent_connection_at_a_full_address_sheds_itself() {
        let (_client, server) = pair().await;
        let per_ip = PerIpConnectionTracker::new(1);
        let _slot = per_ip.try_accept("127.0.0.1".parse().unwrap()).unwrap();
        let (rule, shed) = shed_rule(&per_ip, Duration::from_millis(150));
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream =
            IdleTimeout::new(server, Duration::from_secs(5), reaped.clone()).with_shed_at_cap(rule);

        let start = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("a silent connection at a full address never shed; the doubling is back")
            .expect_err("must end");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(shed.load(Ordering::Relaxed), "the shed must be reportable");
        assert!(
            !reaped.load(Ordering::Relaxed),
            "a shed is not an idle reap"
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// With room at the address nothing is waiting for the slot, so a quiet
    /// connection keeps it until the idle budget, exactly as before PB-31.
    #[tokio::test]
    async fn a_silent_connection_with_room_at_its_address_is_not_shed() {
        let (_client, server) = pair().await;
        let per_ip = PerIpConnectionTracker::new(2);
        let _slot = per_ip.try_accept("127.0.0.1".parse().unwrap()).unwrap();
        let (rule, shed) = shed_rule(&per_ip, Duration::from_millis(150));
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_millis(800), reaped.clone())
            .with_shed_at_cap(rule);

        let start = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the idle budget never fired")
            .expect_err("must end");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            !shed.load(Ordering::Relaxed),
            "shed with room at the address"
        );
        assert!(
            reaped.load(Ordering::Relaxed),
            "ended by the idle budget instead"
        );
        assert!(start.elapsed() >= Duration::from_millis(700));
    }

    /// Past the threshold with room, then the address fills: the next
    /// recheck sheds it, without waiting for new silence or the idle budget.
    #[tokio::test]
    async fn a_silent_connection_sheds_once_its_address_fills() {
        let (_client, server) = pair().await;
        let per_ip = PerIpConnectionTracker::new(2);
        let _slot = per_ip.try_accept("127.0.0.1".parse().unwrap()).unwrap();
        let (rule, shed) = shed_rule(&per_ip, Duration::from_millis(150));
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream = IdleTimeout::new(server, Duration::from_secs(10), reaped.clone())
            .with_shed_at_cap(rule);

        let filler = {
            let per_ip = per_ip.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(600)).await;
                let slot = per_ip.try_accept("127.0.0.1".parse().unwrap()).unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(slot);
            })
        };
        let start = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
            .await
            .expect("never shed after the address filled")
            .expect_err("must end");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(shed.load(Ordering::Relaxed));
        assert!(
            start.elapsed() >= Duration::from_millis(550),
            "shed before the address was full"
        );
        filler.abort();
    }

    /// A live peer at a full address, never silent as long as its
    /// threshold, is never shed however long it stays.
    #[tokio::test]
    async fn a_live_peer_at_a_full_address_is_never_shed() {
        let (mut client, server) = pair().await;
        let per_ip = PerIpConnectionTracker::new(1);
        let _slot = per_ip.try_accept("127.0.0.1".parse().unwrap()).unwrap();
        let (rule, shed) = shed_rule(&per_ip, Duration::from_millis(300));
        let reaped = Arc::new(AtomicBool::new(false));
        let mut stream =
            IdleTimeout::new(server, Duration::from_secs(5), reaped.clone()).with_shed_at_cap(rule);

        let writer = tokio::spawn(async move {
            for _ in 0..12 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                if client.write_all(b"x").await.is_err() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut got = 0usize;
        let mut buf = [0u8; 4];
        while got < 12 {
            let n = stream.read(&mut buf).await.expect("a live peer was shed");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        assert!(!shed.load(Ordering::Relaxed));
        writer.abort();
    }

    fn cadence(started: tokio::time::Instant) -> (HeartbeatCadence, Arc<AtomicU64>) {
        let after_ms = Arc::new(AtomicU64::new(15_000));
        (
            HeartbeatCadence::new(Arc::clone(&after_ms), started),
            after_ms,
        )
    }

    /// The fallback holds until four heartbeats are seen; then the threshold
    /// is twice the interval, never under the floor.
    #[test]
    fn the_cadence_learns_twice_the_interval() {
        let learned = |step_ms: u64, beats: u64| {
            let t = tokio::time::Instant::now();
            let (mut c, after_ms) = cadence(t);
            for i in 0..beats {
                c.observe(t + Duration::from_millis(step_ms * i));
            }
            after_ms.load(Ordering::Relaxed)
        };
        assert_eq!(
            learned(2_000, 3),
            15_000,
            "three heartbeats are not a cadence"
        );
        assert_eq!(learned(2_000, 4), 4_000, "2 s heartbeats shed after 4 s");
        assert_eq!(learned(5_000, 4), 10_000, "a pre-2.0.0 gateway's 5 s");
        assert_eq!(
            learned(500, 4),
            u64::try_from(SHED_FLOOR.as_millis()).unwrap(),
            "fast heartbeats stop at the floor"
        );
    }

    /// The property the estimator exists for (PB-31 T2, twice): heartbeats
    /// SENT on a fixed interval, as sv2-gateway sends them, and READ with any
    /// delay at all, never teach a threshold under twice the interval. Each
    /// pattern is a list of read delays, one per heartbeat; the reviews' shed
    /// reproductions were all reads bunched like these.
    #[test]
    fn late_or_bunched_reads_never_lower_it_below_twice_the_interval() {
        let patterns: [&[u64]; 6] = [
            // the first reads held back, then read out together
            &[9_000, 5_000, 1_000, 0, 0, 0, 0, 0],
            // one slow read in the middle, the rest on time
            &[0, 0, 0, 7_000, 3_000, 0, 0, 0],
            // every read a little late, by varying amounts
            &[300, 1_900, 200, 2_600, 100, 2_400, 0, 1_700],
            // a backlog drained at connect, then steady
            &[20_000, 18_000, 16_000, 14_000, 12_000, 10_000, 0, 0],
            // on time throughout
            &[0; 8],
            // late by a constant
            &[4_000; 8],
        ];
        for interval_ms in [1_000u64, 2_000, 5_000, 10_000] {
            for delays in patterns {
                let t = tokio::time::Instant::now();
                let (mut c, after_ms) = cadence(t);
                for (n, delay) in delays.iter().enumerate() {
                    let sent = interval_ms * u64::try_from(n).unwrap();
                    c.observe(t + Duration::from_millis(sent + delay));
                    if n + 1 < usize::try_from(super::CADENCE_LEARN_AFTER).unwrap() {
                        continue; // still the fallback, which is not learned
                    }
                    let learned = after_ms.load(Ordering::Relaxed);
                    assert!(
                        learned >= 2 * interval_ms,
                        "a {interval_ms} ms gateway read with delays {delays:?} learned \
                         {learned} ms after heartbeat {n}: it would be shed between beats"
                    );
                }
            }
        }
    }

    /// The fallback for a peer with no learned cadence: a quarter of the
    /// idle budget, never under 10 s. At the shipped 60 s that is 15 s; at a
    /// budget of 10 s or less it is not shorter than the budget.
    #[test]
    fn the_fallback_is_a_quarter_of_the_idle_budget_never_under_ten_seconds() {
        use super::shed_fallback;
        assert_eq!(
            shed_fallback(Duration::from_secs(60)),
            Duration::from_secs(15)
        );
        assert_eq!(
            shed_fallback(Duration::from_secs(120)),
            Duration::from_secs(30)
        );
        assert_eq!(
            shed_fallback(Duration::from_secs(20)),
            Duration::from_secs(10)
        );
        assert_eq!(
            shed_fallback(Duration::from_secs(8)),
            Duration::from_secs(10)
        );
    }
}
