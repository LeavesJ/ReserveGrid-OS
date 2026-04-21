use anyhow::Result;
use clap::{Parser, ValueEnum};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{PROTOCOL_VERSION, TemplatePropose, TemplateVerdict, VerdictReason};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

/// Load scenario controls what kind of templates are generated.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Scenario {
    /// All templates are valid (default).
    Valid,
    /// Random mix of valid and invalid templates (controlled by `--reject-ratio`).
    Mixed,
    /// All templates have invalid `prev_hash` (short or non-hex).
    RejectPrevhash,
    /// All templates have `total_fees = 0` (requires `min_total_fees > 0` in policy).
    RejectFees,
    /// All templates have `tx_count = 0` (requires `reject_empty_templates = true`).
    RejectEmpty,
    /// All templates have `coinbase_value = 0` (requires `reject_coinbase_zero = true`).
    RejectCoinbase,
    /// All templates have stale `created_at_unix_ms` (requires `enforce_template_age = true`).
    Stale,
}

#[derive(Parser, Debug)]
#[command(name = "rg-load-test")]
#[command(about = "Load testing tool for pool-verifier TCP endpoint")]
struct Args {
    /// Pool verifier TCP address (env: `VELDRA_LOAD_TARGET`)
    #[arg(long, env = "VELDRA_LOAD_TARGET", default_value = "127.0.0.1:5001")]
    target: String,

    /// Number of parallel TCP connections (env: `VELDRA_LOAD_CONCURRENCY`)
    #[arg(long, env = "VELDRA_LOAD_CONCURRENCY", default_value = "10")]
    concurrency: u32,

    /// Templates per second total across all connections (env: `VELDRA_LOAD_RATE`)
    #[arg(long, env = "VELDRA_LOAD_RATE", default_value = "100")]
    rate: u32,

    /// Duration in seconds to run (env: `VELDRA_LOAD_DURATION`)
    #[arg(long, env = "VELDRA_LOAD_DURATION", default_value = "30")]
    duration: u64,

    /// Use `InternalMessage` envelope format (default: raw `TemplatePropose`)
    #[arg(long)]
    envelope: bool,

    /// Load scenario controlling what templates are generated (env: `VELDRA_LOAD_SCENARIO`)
    #[arg(
        long,
        env = "VELDRA_LOAD_SCENARIO",
        value_enum,
        default_value = "valid"
    )]
    scenario: Scenario,

    /// Fraction of templates that are invalid in `mixed` mode, 0.0 to 1.0 (env: `VELDRA_LOAD_REJECT_RATIO`)
    #[arg(long, env = "VELDRA_LOAD_REJECT_RATIO", default_value = "0.3")]
    reject_ratio: f64,

    /// How far back (in ms) to set `created_at_unix_ms` in `stale` mode (env: `VELDRA_LOAD_STALE_OFFSET`)
    #[arg(long, env = "VELDRA_LOAD_STALE_OFFSET", default_value = "60000")]
    stale_offset_ms: u64,
}

/// In-flight send timestamps keyed by `template_id` for latency correlation.
type InflightMap = Arc<Mutex<HashMap<u64, Instant>>>;

/// Per `reason_code` counters for rejection breakdown.
type ReasonCounts = Arc<Mutex<HashMap<String, u64>>>;

/// Shared metrics across all worker connections
#[derive(Debug, Clone)]
struct Metrics {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    accepted: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    total_latency_ms: Arc<AtomicU64>,
    max_latency_ms: Arc<AtomicU64>,
    latencies: Arc<Mutex<Vec<u64>>>,
    reason_counts: ReasonCounts,
}

impl Metrics {
    fn new() -> Self {
        Self {
            sent: Arc::new(AtomicU64::new(0)),
            received: Arc::new(AtomicU64::new(0)),
            accepted: Arc::new(AtomicU64::new(0)),
            rejected: Arc::new(AtomicU64::new(0)),
            total_latency_ms: Arc::new(AtomicU64::new(0)),
            max_latency_ms: Arc::new(AtomicU64::new(0)),
            latencies: Arc::new(Mutex::new(Vec::new())),
            reason_counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn increment_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    fn record_reason(&self, reason: VerdictReason) {
        if let Ok(mut map) = self.reason_counts.lock() {
            *map.entry(reason.as_str().to_owned()).or_insert(0) += 1;
        }
    }

    fn record_latency(&self, latency_ms: u64) {
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        // Update max using CAS loop
        let mut current = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > current {
            match self.max_latency_ms.compare_exchange_weak(
                current,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        if let Ok(mut v) = self.latencies.lock() {
            v.push(latency_ms);
        }
    }

    fn get_stats(&self) -> (u64, u64, u64, u64, f64, u64) {
        let sent = self.sent.load(Ordering::Relaxed);
        let received = self.received.load(Ordering::Relaxed);
        let accepted = self.accepted.load(Ordering::Relaxed);
        let rejected = self.rejected.load(Ordering::Relaxed);

        #[allow(clippy::cast_precision_loss)]
        let avg_latency = if received > 0 {
            self.total_latency_ms.load(Ordering::Relaxed) as f64 / received as f64
        } else {
            0.0
        };

        let max_latency = self.max_latency_ms.load(Ordering::Relaxed);

        (sent, received, accepted, rejected, avg_latency, max_latency)
    }

    fn get_p99_latency(&self) -> u64 {
        if let Ok(latencies) = self.latencies.lock() {
            if latencies.is_empty() {
                return 0;
            }
            let mut sorted = latencies.clone();
            sorted.sort_unstable();
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let p99_idx = (sorted.len() as f64 * 0.99) as usize;
            sorted[p99_idx.min(sorted.len() - 1)]
        } else {
            0
        }
    }

    fn get_reason_breakdown(&self) -> Vec<(String, u64)> {
        if let Ok(map) = self.reason_counts.lock() {
            let mut v: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v
        } else {
            Vec::new()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Validate inputs before any arithmetic.
    if args.concurrency == 0 {
        error!("--concurrency must be at least 1");
        std::process::exit(1);
    }
    if args.rate == 0 {
        error!("--rate must be at least 1");
        std::process::exit(1);
    }

    // Warn if target address appears non-loopback.
    if let Some(host) = args.target.rsplit(':').nth(1) {
        let is_loopback = host == "127.0.0.1" || host == "::1" || host == "localhost";
        if !is_loopback {
            warn!(
                target = %args.target,
                "target address is not loopback; traffic traverses the network",
            );
        }
    }

    info!(
        target = %args.target,
        concurrency = args.concurrency,
        rate = args.rate,
        duration = args.duration,
        envelope = args.envelope,
        scenario = ?args.scenario,
        reject_ratio = args.reject_ratio,
        stale_offset_ms = args.stale_offset_ms,
        "starting load test",
    );

    let metrics = Metrics::new();
    let start = Instant::now();
    let test_duration = Duration::from_secs(args.duration);

    // Spawn concurrent worker tasks
    let mut join_set = JoinSet::new();
    for worker_id in 0..args.concurrency {
        let target = args.target.clone();
        let metrics = metrics.clone();
        let rate_per_worker = args.rate / args.concurrency;
        let envelope = args.envelope;
        let scenario = args.scenario;
        let reject_ratio = args.reject_ratio;
        let stale_offset_ms = args.stale_offset_ms;

        join_set.spawn(async move {
            run_worker(
                worker_id,
                target,
                metrics,
                rate_per_worker,
                test_duration,
                envelope,
                scenario,
                reject_ratio,
                stale_offset_ms,
            )
            .await
        });
    }

    // Wait for all workers to complete
    let mut any_error = false;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!(error = %e, "worker error");
                any_error = true;
            }
            Err(e) => {
                error!(error = %e, "task join error");
                any_error = true;
            }
        }
    }

    let elapsed = start.elapsed();
    let (sent, received, accepted, rejected, avg_latency, max_latency) = metrics.get_stats();
    let p99_latency = metrics.get_p99_latency();

    info!("Load test completed in {:.2}s", elapsed.as_secs_f64());
    info!(
        total_sent = sent,
        total_received = received,
        accepted = accepted,
        rejected = rejected,
        avg_latency_ms = format!("{:.2}", avg_latency),
        max_latency_ms = max_latency,
        p99_latency_ms = p99_latency,
        "Summary"
    );

    // Print rejection reason breakdown if any rejections occurred
    let breakdown = metrics.get_reason_breakdown();
    if !breakdown.is_empty() {
        info!("Rejection breakdown by reason_code:");
        for (reason, count) in &breakdown {
            info!(reason_code = %reason, count = count, "  reject");
        }
    }

    std::process::exit(i32::from(any_error));
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn run_worker(
    worker_id: u32,
    target: String,
    metrics: Metrics,
    rate_per_worker: u32,
    duration: Duration,
    use_envelope: bool,
    scenario: Scenario,
    reject_ratio: f64,
    stale_offset_ms: u64,
) -> Result<()> {
    let stream = TcpStream::connect(&target).await.map_err(|e| {
        warn!(worker_id, target = %target, error = %e, "TCP connect failed");
        anyhow::anyhow!("worker {worker_id}: TCP connect failed")
    })?;

    info!(worker_id, target = %target, "connected");

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut buf = String::new();
    let inflight: InflightMap = Arc::new(Mutex::new(HashMap::new()));

    // Calculate delay between messages in microseconds
    let delay_micros = if rate_per_worker > 0 {
        1_000_000 / u64::from(rate_per_worker)
    } else {
        1_000_000
    };
    let delay = Duration::from_micros(delay_micros);

    let start = Instant::now();
    let seed = u64::from(worker_id) << 32 | u64::from(std::process::id());
    let mut rng = ChaCha12Rng::seed_from_u64(seed);
    let mut template_id: u64 = u64::from(worker_id) << 32;

    // Spawn a task to read verdicts and correlate latency
    let reader_metrics = metrics.clone();
    let reader_inflight = inflight.clone();
    let reader_handle = {
        tokio::spawn(async move {
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = buf.trim();

                        // Try to parse InternalMessage first
                        let verdict =
                            if let Ok(env) = serde_json::from_str::<InternalMessage>(trimmed) {
                                if env.msg_type == msg_types::TEMPLATE_VERDICT {
                                    match serde_json::from_value::<TemplateVerdict>(env.payload) {
                                        Ok(v) => Some(v),
                                        Err(e) => {
                                            warn!(error = %e, "failed to parse verdict payload");
                                            None
                                        }
                                    }
                                } else {
                                    None
                                }
                            } else {
                                // Try raw TemplateVerdict
                                serde_json::from_str::<TemplateVerdict>(trimmed).ok()
                            };

                        if let Some(verdict) = verdict {
                            reader_metrics.increment_received();
                            if verdict.accepted {
                                reader_metrics.increment_accepted();
                            } else {
                                reader_metrics.increment_rejected();
                                if let Some(reason) = verdict.reason_code {
                                    reader_metrics.record_reason(reason);
                                }
                            }
                            // Correlate latency from inflight map
                            if let Ok(mut map) = reader_inflight.lock()
                                && let Some(sent_at) = map.remove(&verdict.id)
                            {
                                #[allow(clippy::cast_possible_truncation)]
                                let latency_ms = sent_at.elapsed().as_micros() as u64 / 1000;
                                reader_metrics.record_latency(latency_ms);
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "reader I/O error");
                        break;
                    }
                }
            }
        })
    };

    // Send templates in a loop
    while start.elapsed() < duration {
        let proposal = generate_for_scenario(
            template_id,
            &mut rng,
            scenario,
            reject_ratio,
            stale_offset_ms,
        );

        let json_line = if use_envelope {
            let env = InternalMessage {
                msg_type: msg_types::TEMPLATE_PROPOSE.to_string(),
                version: PROTOCOL_VERSION,
                payload: serde_json::to_value(&proposal)?,
            };
            serde_json::to_string(&env)?
        } else {
            serde_json::to_string(&proposal)?
        };

        // Record send time for latency correlation
        if let Ok(mut map) = inflight.lock() {
            map.insert(template_id, Instant::now());
        }

        // Send the message
        match writer.write_all(json_line.as_bytes()).await {
            Ok(()) => {
                if let Err(e) = writer.write_all(b"\n").await {
                    warn!(worker_id, error = %e, "write failed");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    warn!(worker_id, error = %e, "flush failed");
                    break;
                }
                metrics.increment_sent();
            }
            Err(e) => {
                warn!(worker_id, error = %e, "write failed");
                break;
            }
        }

        template_id = template_id.wrapping_add(1);

        // Sleep before next send
        tokio::time::sleep(delay).await;
    }

    // Close writer and wait for reader to finish
    drop(writer);
    let _ = reader_handle.await;

    info!(worker_id = worker_id, "Worker completed");
    Ok(())
}

/// Route to the correct generator based on scenario.
fn generate_for_scenario(
    template_id: u64,
    rng: &mut ChaCha12Rng,
    scenario: Scenario,
    reject_ratio: f64,
    stale_offset_ms: u64,
) -> TemplatePropose {
    use rand::Rng as _;

    match scenario {
        Scenario::Valid => generate_valid(template_id, rng),
        Scenario::RejectPrevhash => generate_bad_prevhash(template_id, rng),
        Scenario::RejectFees => generate_zero_fees(template_id, rng),
        Scenario::RejectEmpty => generate_empty_template(template_id, rng),
        Scenario::RejectCoinbase => generate_zero_coinbase(template_id, rng),
        Scenario::Stale => generate_stale(template_id, rng, stale_offset_ms),
        Scenario::Mixed => {
            let roll: f64 = rng.r#gen();
            if roll < reject_ratio {
                // Pick a random rejection type
                match rng.gen_range(0..5u8) {
                    0 => generate_bad_prevhash(template_id, rng),
                    1 => generate_zero_fees(template_id, rng),
                    2 => generate_empty_template(template_id, rng),
                    3 => generate_zero_coinbase(template_id, rng),
                    _ => generate_stale(template_id, rng, stale_offset_ms),
                }
            } else {
                generate_valid(template_id, rng)
            }
        }
    }
}

// ── Generator functions ──

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        * 1000
}

fn generate_valid(template_id: u64, rng: &mut ChaCha12Rng) -> TemplatePropose {
    use rand::Rng as RngTrait;

    TemplatePropose {
        version: 2,
        id: template_id,
        block_height: 800_000 + rng.gen_range(0..1_000_000),
        prev_hash: generate_random_hash(rng),
        coinbase_value: 625_000_000 + rng.gen_range(0..50_000),
        tx_count: rng.gen_range(1000..5000),
        total_fees: rng.gen_range(100_000..5_000_000),
        observed_weight: Some(3_000_000),
        created_at_unix_ms: Some(now_unix_ms()),
        total_sigops: Some(5000),
        coinbase_sigops: Some(100),
        template_weight: Some(3_000_000),
        gateway_instance_id: Some("rg-load-test".to_string()),
        // Load test carries no real block bytes; the shield pass is
        // skipped for synthetic templates (ADR-002 Phase 1).
        raw_block_hex: None,
    }
}

/// Short `prev_hash` (32 chars instead of 64) triggers `prev_hash_len_mismatch`.
fn generate_bad_prevhash(template_id: u64, rng: &mut ChaCha12Rng) -> TemplatePropose {
    use rand::Rng as RngTrait;

    let mut t = generate_valid(template_id, rng);
    // Alternate between short hash and non-hex hash
    if rng.gen_bool(0.5) {
        t.prev_hash = t.prev_hash[..32].to_owned(); // 32 chars, not 64
    } else {
        // Replace first 4 chars with non-hex to trigger `invalid_prev_hash`
        let mut bad = String::from("zzzz");
        bad.push_str(&t.prev_hash[4..]);
        t.prev_hash = bad;
    }
    t
}

/// `total_fees = 0` triggers `total_fees_below_minimum` when `min_total_fees > 0`.
fn generate_zero_fees(template_id: u64, rng: &mut ChaCha12Rng) -> TemplatePropose {
    let mut t = generate_valid(template_id, rng);
    t.total_fees = 0;
    t
}

/// `tx_count = 0` triggers `empty_template_rejected` when `reject_empty_templates = true`.
fn generate_empty_template(template_id: u64, rng: &mut ChaCha12Rng) -> TemplatePropose {
    let mut t = generate_valid(template_id, rng);
    t.tx_count = 0;
    t.total_fees = 0;
    t
}

/// `coinbase_value = 0` with nonzero `tx_count` triggers `coinbase_value_zero_rejected`
/// when `reject_coinbase_zero = true`.
fn generate_zero_coinbase(template_id: u64, rng: &mut ChaCha12Rng) -> TemplatePropose {
    let mut t = generate_valid(template_id, rng);
    t.coinbase_value = 0;
    t
}

/// Stale `created_at_unix_ms` triggers `template_stale` when
/// `enforce_template_age = true` and `max_template_age_ms` is set.
fn generate_stale(
    template_id: u64,
    rng: &mut ChaCha12Rng,
    stale_offset_ms: u64,
) -> TemplatePropose {
    let mut t = generate_valid(template_id, rng);
    t.created_at_unix_ms = Some(now_unix_ms().saturating_sub(stale_offset_ms));
    t
}

fn generate_random_hash(rng: &mut ChaCha12Rng) -> String {
    use rand::Rng as RngTrait;

    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut hash = String::with_capacity(64);
    for _ in 0..64 {
        hash.push(HEX_CHARS[rng.gen_range(0..16)] as char);
    }
    hash
}
