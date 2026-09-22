//! Whole miner sessions through `run_connection`: a real socket, a real
//! Noise handshake, `SetupConnection`, a standard channel, then whatever a
//! test needs the miner to do or not do.
//!
//! The handler's other tests call its frame handlers directly, which cannot
//! see how the steady-state loop behaves over time: whether a session that
//! goes quiet ever ends (PB-48), or what a job broadcast does to a frame that
//! is half received (PB-50).

use std::time::Instant;

use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator, NoiseCodec};
use secp256k1::Keypair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::*;

/// The miner end of a session.
pub(super) struct Miner {
    stream: TcpStream,
    codec: NoiseCodec,
}

impl Miner {
    /// One SV2 frame, encrypted and length-prefixed, ready for the wire.
    pub(super) fn frame(&mut self, msg_type: u8, body: &[u8]) -> Vec<u8> {
        #[allow(clippy::cast_possible_truncation)]
        let hdr = Sv2FrameHeader {
            extension_type: 0x0000,
            msg_type,
            msg_length: body.len() as u32,
        };
        let mut frame = hdr.to_bytes().to_vec();
        frame.extend_from_slice(body);
        self.codec.encrypt(&mut frame).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let mut wire = (frame.len() as u16).to_be_bytes().to_vec();
        wire.extend_from_slice(&frame);
        wire
    }

    pub(super) async fn send(&mut self, msg_type: u8, body: &[u8]) {
        let wire = self.frame(msg_type, body);
        self.write_raw(&wire).await;
    }

    pub(super) async fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    /// The next frame, or `None` on EOF, a reset, or `wait` elapsing.
    pub(super) async fn recv(&mut self, wait: Duration) -> Option<(Sv2FrameHeader, Vec<u8>)> {
        tokio::time::timeout(wait, async {
            let mut len = [0u8; 2];
            self.stream.read_exact(&mut len).await.ok()?;
            let mut encrypted = vec![0u8; u16::from_be_bytes(len) as usize];
            self.stream.read_exact(&mut encrypted).await.ok()?;
            self.codec.decrypt(&mut encrypted).ok()?;
            let mut hdr = [0u8; crate::transport::SV2_FRAME_HEADER_SIZE];
            hdr.copy_from_slice(&encrypted[..crate::transport::SV2_FRAME_HEADER_SIZE]);
            Some((
                Sv2FrameHeader::parse(&hdr),
                encrypted[crate::transport::SV2_FRAME_HEADER_SIZE..].to_vec(),
            ))
        })
        .await
        .ok()
        .flatten()
    }

    /// Read frames until one of `msg_type` arrives; `None` if the session
    /// ended or went quiet for `wait` first.
    pub(super) async fn recv_until(&mut self, msg_type: u8, wait: Duration) -> Option<Vec<u8>> {
        loop {
            let (hdr, body) = self.recv(wait).await?;
            if hdr.msg_type == msg_type {
                return Some(body);
            }
        }
    }
}

/// A live session: the miner end, the gateway's job broadcaster, and the
/// handler task, which ends when `run_connection` returns.
pub(super) struct Session {
    pub(super) miner: Miner,
    pub(super) jobs: broadcast::Sender<Arc<JobBroadcast>>,
    pub(super) handler: JoinHandle<(HandlerExit, Instant)>,
    _shutdown: watch::Sender<bool>,
    _share_forward_rx: mpsc::Receiver<ShareSubmission>,
    _share_event_rx: mpsc::Receiver<ShareAcceptedEvent>,
}

pub(super) fn session_config() -> HandlerConfig {
    HandlerConfig {
        max_channels_per_conn: 4,
        channel_target: [0xFF; 32],
        channel_open_timeout: Duration::from_secs(5),
        ntime_elapsed_slack_seconds: 3600,
        max_future_block_time_seconds: 7200,
        share_dedup_window_size: 128,
        max_shares_per_second_per_channel: 0,
        gateway_instance_id: "session-test-gw".to_string(),
        share_hmac_secret: Arc::new(std::sync::RwLock::new(Vec::new())),
        extended_channels_enabled: true,
        extranonce_prefix_len: 2,
        vardiff_enabled: false,
        vardiff_target_shares_per_min: 20.0,
        vardiff_retarget_interval: Duration::from_secs(60),
        vardiff_min_difficulty: 1,
        vardiff_max_difficulty: u64::MAX,
        vardiff_max_adjustment_factor: 4.0,
    }
}

/// A job for the broadcaster; its contents only need to encode.
pub(super) fn job(job_id: u32) -> Arc<JobBroadcast> {
    Arc::new(JobBroadcast {
        job_id,
        version: 0x2000_0000,
        coinbase_tx_prefix: vec![0x01; 64],
        coinbase_tx_suffix: vec![0x02; 64],
        merkle_path: vec![[0x03; 32]; 4],
        prevhash_update: None,
        min_ntime: None,
    })
}

/// Open a session with one standard channel and return once the miner has
/// its `SetTarget`.
pub(super) async fn open_session(config: HandlerConfig) -> Session {
    use crate::transport::perform_handshake;

    let secp = secp256k1::Secp256k1::new();
    let authority_kp = Keypair::new(&secp, &mut rand::thread_rng());
    let authority_pubkey = authority_kp.x_only_public_key().0;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (jobs, job_rx) = broadcast::channel::<Arc<JobBroadcast>>(64);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let (share_forward_tx, share_forward_rx) = mpsc::channel(1024);
    let (share_event_tx, share_event_rx) = mpsc::channel(1024);
    let permit = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();

    let handler = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let transport = perform_handshake(stream, &authority_kp, 3600, Duration::from_secs(5))
            .await
            .unwrap();
        let exit = run_connection(ConnectionContext {
            transport,
            peer,
            config: Arc::new(config),
            channel_id_alloc: Arc::new(ChannelIdAllocator::new()),
            extranonce_alloc: Arc::new(ExtranonceAllocator::new()),
            job_table: Arc::new(tokio::sync::RwLock::new(JobTable::new(300_000, 64))),
            latest_job: Arc::new(tokio::sync::RwLock::new(None)),
            job_rx,
            share_event_tx,
            share_forward_tx,
            shutdown: shutdown_rx,
            permit,
            channel_registry: Arc::new(crate::channels::GlobalChannelRegistry::new()),
            vardiff_retarget_up: Counter::default(),
            vardiff_retarget_down: Counter::default(),
            share_events_dropped: Counter::default(),
            share_forward_queue_full: Counter::default(),
        })
        .await;
        (exit, Instant::now())
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut initiator = Initiator::from_raw_k(authority_pubkey.serialize()).unwrap();
    stream
        .write_all(&initiator.step_0().unwrap())
        .await
        .unwrap();
    let mut response = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
    stream.read_exact(&mut response).await.unwrap();
    let codec = initiator.step_2(response).unwrap();
    let mut miner = Miner { stream, codec };

    let setup = sv2_codec::SetupConnection {
        protocol: 0,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: "127.0.0.1".to_string(),
        endpoint_port: addr.port(),
        vendor: "session-test".to_string(),
        hardware_version: String::new(),
        firmware: String::new(),
        device_id: String::new(),
    };
    miner
        .send(MESSAGE_TYPE_SETUP_CONNECTION, &setup.encode().unwrap())
        .await;
    miner
        .recv_until(
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            Duration::from_secs(5),
        )
        .await
        .expect("SetupConnection.Success");

    let open = sv2_codec::OpenStandardMiningChannel {
        request_id: 1,
        user_identity: "w1".to_string(),
        nominal_hash_rate: 1.0,
        max_target: [0xFF; 32],
    };
    miner
        .send(
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
            &open.encode().unwrap(),
        )
        .await;
    miner
        .recv_until(MESSAGE_TYPE_SET_TARGET, Duration::from_secs(5))
        .await
        .expect("SetTarget after the channel opened");

    Session {
        miner,
        jobs,
        handler,
        _shutdown: shutdown,
        _share_forward_rx: share_forward_rx,
        _share_event_rx: share_event_rx,
    }
}

/// PB-48's measurement: how long the gateway keeps a session whose miner
/// has gone completely silent, socket still open, with and without jobs
/// being broadcast to it. Bounded at `WINDOW`; "still held" at the end
/// means the handler never ended on its own.
///
/// Measured 2026-09-22: still held at 45 s in both cases. That is also the
/// right answer after PB-48, and this test cannot see the fix. The miner
/// here is silent but its kernel is alive and answering, which is what a
/// quiet, healthy miner looks like in the shipped config (no vardiff, no
/// channel target, so shares are rare). PB-48's fix is for a peer whose
/// host or path has VANISHED, which only the kernel can see: keepalive and
/// `TCP_USER_TIMEOUT` (`transport::configure_miner_socket`). Reproducing a
/// vanished peer on loopback needs a packet filter and root.
///
/// `cargo test -p sv2-gateway --lib pb48_measure -- --ignored --nocapture`
#[tokio::test]
#[ignore = "a measurement: it waits out its window"]
async fn pb48_measure_how_long_a_silent_miner_is_held() {
    const WINDOW: Duration = Duration::from_secs(45);
    for with_jobs in [false, true] {
        let session = open_session(session_config()).await;
        let start = Instant::now();
        let mut job_id = 1;
        let ended = loop {
            if session.handler.is_finished() {
                break Some(start.elapsed());
            }
            if start.elapsed() >= WINDOW {
                break None;
            }
            if with_jobs {
                let _ = session.jobs.send(job(job_id));
                job_id += 1;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        println!(
            "PB-48 silent miner, jobs {}: {}",
            if with_jobs {
                "every 200 ms, never read"
            } else {
                "none"
            },
            match ended {
                Some(t) => format!("session ended after {t:?}"),
                None => format!("still held at {WINDOW:?}"),
            }
        );
        session.handler.abort();
    }
}

/// Read frames until a reply to a share arrives, either kind.
async fn share_reply(miner: &mut Miner, wait: Duration) -> Option<u8> {
    loop {
        let (hdr, _) = miner.recv(wait).await?;
        if hdr.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS
            || hdr.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_ERROR
        {
            return Some(hdr.msg_type);
        }
    }
}

/// PB-50: a job broadcast that lands while a miner's frame is half received
/// must not cost the frame. The steady-state loop selects between the job
/// channel and `read_frame`, so a job cancels an in-flight read; the read
/// must resume where it stopped, not lose the bytes it had consumed.
#[tokio::test]
async fn a_job_arriving_mid_frame_does_not_cost_the_frame() {
    let mut session = open_session(session_config()).await;
    let share = sv2_codec::SubmitSharesStandard {
        channel_id: 1,
        sequence_number: 1,
        job_id: 999,
        nonce: 0,
        ntime: 0,
        version: 0x2000_0000,
    };

    // Control: the same split with no job in between is answered, so a
    // failure below is the job's doing, not the split's.
    let control = session.miner.frame(
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
        &share.encode().unwrap(),
    );
    session.miner.write_raw(&control[..1]).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    session.miner.write_raw(&control[1..]).await;
    assert!(
        share_reply(&mut session.miner, Duration::from_secs(3))
            .await
            .is_some(),
        "a split frame with no job in between went unanswered: the harness is wrong"
    );

    for split in [1, 2, 9] {
        let wire = session.miner.frame(
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
            &share.encode().unwrap(),
        );
        session.miner.write_raw(&wire[..split]).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.jobs.send(job(split.try_into().unwrap())).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.miner.write_raw(&wire[split..]).await;
        assert!(
            share_reply(&mut session.miner, Duration::from_secs(3))
                .await
                .is_some(),
            "a job broadcast during a frame split after {split} byte(s) cost the frame: \
             the session gave no reply to the share"
        );
    }
    assert!(!session.handler.is_finished(), "the session ended");
}
