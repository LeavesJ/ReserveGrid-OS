use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::io::BufReader as StdBuf;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::mempool_client;
use crate::metrics::VerdictLabels;
use crate::state::AppState;
use crate::verdicts::{
    LAST_MEMPOOL_OK_UNIX, LogIdCounter, LoggedVerdict, VerdictLog, append_verdict_to_disk,
    current_timestamp, current_timestamp_ms,
};
use pool_verifier::mempool_view::MempoolState;
use rg_protocol::gateway::{InternalMessage, msg_types};
use rg_protocol::{
    PROTOCOL_VERSION, PolicyContext, TemplatePropose, TemplateVerdict, VerdictReason,
};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, timeout};

/// Build an optional `TlsAcceptor` for the verifier TCP channel.
///
/// Env vars:
/// - `VELDRA_VERIFIER_TLS_CERT`: path to server certificate PEM
/// - `VELDRA_VERIFIER_TLS_KEY`: path to server private key PEM
/// - `VELDRA_VERIFIER_TLS_CLIENT_CA`: path to CA PEM for client certificate
///   verification (mTLS). When set, connecting clients must present a valid
///   certificate signed by this CA.
///
/// Returns `Ok(None)` when none of the env vars are set (plaintext mode).
pub(crate) fn build_tcp_tls_acceptor() -> Result<Option<TlsAcceptor>, String> {
    use std::env;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::server::WebPkiClientVerifier;

    let cert_path = env::var("VELDRA_VERIFIER_TLS_CERT").ok();
    let key_path = env::var("VELDRA_VERIFIER_TLS_KEY").ok();

    let (Some(cert_path), Some(key_path)) = (&cert_path, &key_path) else {
        match (&cert_path, &key_path) {
            (None, None) => return Ok(None),
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "VELDRA_VERIFIER_TLS_CERT and VELDRA_VERIFIER_TLS_KEY must both be set or \
                     both be unset"
                        .to_string(),
                );
            }
            _ => unreachable!(),
        }
    };
    let cert_path = cert_path.clone();
    let key_path = key_path.clone();

    // Load server certificate chain.
    let cert_pem = std::fs::read(&cert_path).map_err(|e| format!("read cert {cert_path}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut StdBuf::new(cert_pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse server cert: {e}"))?;

    // Load server private key.
    let key_pem = std::fs::read(&key_path).map_err(|e| format!("read key {key_path}: {e}"))?;
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut StdBuf::new(key_pem.as_slice()))
            .map_err(|e| format!("parse server key: {e}"))?
            .ok_or_else(|| format!("no private key found in {key_path}"))?;

    // Optional: client CA for mTLS.
    let client_verifier = if let Ok(ca_path) = std::env::var("VELDRA_VERIFIER_TLS_CLIENT_CA") {
        let ca_pem = std::fs::read(&ca_path).map_err(|e| format!("read client CA: {e}"))?;
        let ca_certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut StdBuf::new(ca_pem.as_slice()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("parse client CA: {e}"))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
        for cert in &ca_certs {
            root_store
                .add(cert.clone())
                .map_err(|e| format!("add client CA: {e}"))?;
        }
        Some(
            WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| format!("build client verifier: {e}"))?,
        )
    } else {
        None
    };

    let mut server_config = if let Some(verifier) = client_verifier {
        tokio_rustls::rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("build server config (mTLS): {e}"))?
    } else {
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("build server config (TLS): {e}"))?
    };
    server_config.alpn_protocols = vec![b"rg-ndjson".to_vec()];

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

/// Generate a self-signed certificate for testing/development.
pub(crate) fn generate_self_signed_cert() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

/// System error boundary: reason codes not produced by policy evaluation.
///
/// `VerdictReason::PolicyLoadError`       — emitted when policy lock is poisoned
///                                          or policy state is unavailable.
/// `VerdictReason::MempoolBackendUnavailable` — reserved for future fail-closed
///                                          mode. Currently, missing mempool triggers
///                                          degraded-mode tier selection.
/// `VerdictReason::InternalError`         — emitted on unexpected handler failures
///                                          (e.g., serialize errors).
pub(crate) async fn run_tcp_server(
    app_state: AppState,
    addr: String,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    tls_acceptor: Option<TlsAcceptor>,
    metrics: Arc<crate::metrics::VerifierMetrics>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr).await?;
    let tls_mode = if tls_acceptor.is_some() {
        "tls"
    } else {
        "plaintext"
    };
    info!(addr = %addr, tls = tls_mode, "TCP listening");
    if tls_acceptor.is_none() && !addr.starts_with("127.0.0.1") && !addr.starts_with("[::1]") {
        tracing::warn!(
            addr = %addr,
            "TCP verifier is running without TLS on a non-loopback address. \
             Templates and verdicts will be sent in plaintext. Set \
             VELDRA_VERIFIER_TLS_CERT and VELDRA_VERIFIER_TLS_KEY for production."
        );
    }

    loop {
        let (tcp_stream, _peer) = listener.accept().await?;
        let state_clone = app_state.clone();
        let log = verdict_log.clone();
        let url_clone = mempool_url.clone();
        let id_ctr = log_id_counter.clone();
        let acceptor = tls_acceptor.clone();
        let conn_metrics = metrics.clone();

        tokio::spawn(async move {
            // Upgrade to TLS if configured, then split into reader/writer.
            if let Some(acceptor) = acceptor {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        let (reader, writer) = tokio::io::split(tls_stream);
                        handle_tcp_connection(
                            reader,
                            writer,
                            state_clone,
                            log,
                            url_clone,
                            id_ctr,
                            conn_metrics,
                        )
                        .await;
                    }
                    Err(e) => {
                        warn!(error = %e, "TLS accept failed");
                    }
                }
            } else {
                let (reader, writer) = tcp_stream.into_split();
                handle_tcp_connection(
                    reader,
                    writer,
                    state_clone,
                    log,
                    url_clone,
                    id_ctr,
                    conn_metrics,
                )
                .await;
            }
        });
    }
}

/// Handles a single TCP connection (plaintext or TLS) by reading NDJSON lines
/// and dispatching template proposals.
#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_tcp_connection<R, W>(
    reader: R,
    mut writer: W,
    app_state: AppState,
    verdict_log: VerdictLog,
    mempool_url: Option<String>,
    log_id_counter: LogIdCounter,
    metrics: Arc<crate::metrics::VerifierMetrics>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_log = crate::verdicts::verdict_log_max_entries();

    let state_clone = app_state;
    let url_clone = mempool_url;
    let id_ctr = log_id_counter;
    let log = verdict_log;
    {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        // Track whether this client uses InternalMessage envelope format
        // (sv2-gateway) vs raw TemplatePropose (template-manager).
        // Auto-detected on the first successfully parsed line.
        let mut uses_envelope: Option<bool> = None;

        loop {
            line.clear();
            let _n = match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    warn!(error = ?e, "tcp read error");
                    break;
                }
            };

            let trimmed = line.trim();

            // Try InternalMessage envelope first (gateway protocol).
            let propose: TemplatePropose =
                if let Ok(env) = serde_json::from_str::<InternalMessage>(trimmed) {
                    if uses_envelope.is_none() {
                        uses_envelope = Some(true);
                    }
                    match env.msg_type.as_str() {
                        msg_types::TEMPLATE_PROPOSE => {
                            match serde_json::from_value::<TemplatePropose>(env.payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!(error = ?e, "template_propose payload parse error");
                                    continue;
                                }
                            }
                        }
                        msg_types::HEARTBEAT => {
                            // Respond with heartbeat_ack in envelope format.
                            let ack = InternalMessage {
                                msg_type: msg_types::HEARTBEAT_ACK.to_string(),
                                version: PROTOCOL_VERSION,
                                payload: serde_json::json!({}),
                            };
                            if let Ok(json) = serde_json::to_string(&ack) {
                                if let Err(e) = writer.write_all(json.as_bytes()).await {
                                    warn!(error = %e, "heartbeat ack write failed");
                                    return;
                                }
                                if let Err(e) = writer.write_all(b"\n").await {
                                    warn!(error = %e, "heartbeat ack newline write failed");
                                    return;
                                }
                                if let Err(e) = writer.flush().await {
                                    warn!(error = %e, "heartbeat ack flush failed");
                                    return;
                                }
                            }
                            continue;
                        }
                        other => {
                            warn!(msg_type = other, "unknown internal message type; ignoring");
                            continue;
                        }
                    }
                } else {
                    // Fallback: try raw TemplatePropose (template-manager protocol).
                    match serde_json::from_str::<TemplatePropose>(trimmed) {
                        Ok(p) => {
                            if uses_envelope.is_none() {
                                uses_envelope = Some(false);
                            }
                            p
                        }
                        Err(e) => {
                            warn!(error = ?e, "template JSON parse error");
                            continue;
                        }
                    }
                };

            let mempool_tx_count: Option<u64> = if let Some(ref url) = url_clone {
                let result = timeout(
                    Duration::from_millis(600),
                    mempool_client::fetch_mempool_tx_count(url),
                )
                .await
                .ok() // Result<Option<u64>, Elapsed> -> Option<Option<u64>>
                .flatten(); // Option<Option<u64>> -> Option<u64>
                if result.is_some() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    LAST_MEMPOOL_OK_UNIX.store(now, Ordering::Relaxed);
                }
                result
            } else {
                None
            };

            // System error boundary: recover from poisoned lock.
            // Extract config synchronously so the RwLockReadGuard is
            // dropped before any .await (RwLockReadGuard is !Send).
            let (cfg_opt, is_poisoned) = match state_clone.policy.read() {
                Ok(holder) => (Some(holder.config.clone()), false),
                Err(_poisoned) => {
                    error!("policy lock poisoned, rejecting template (fail-closed)");
                    (None, true)
                }
            };

            if is_poisoned {
                // Emit PolicyLoadError verdict and skip normal evaluation.
                let verdict = TemplateVerdict {
                    version: PROTOCOL_VERSION,
                    id: propose.id,
                    accepted: false,
                    reason_code: Some(VerdictReason::PolicyLoadError),
                    reason_detail: Some("policy lock poisoned".to_string()),
                    policy_context: None,
                };
                let log_id: u64 = id_ctr.fetch_add(1, Ordering::Relaxed);
                let logged = LoggedVerdict {
                    log_id,
                    template_id: propose.id,
                    height: propose.block_height,
                    total_fees: propose.total_fees,
                    tx_count: propose.tx_count,
                    accepted: false,
                    reason: Some(VerdictReason::PolicyLoadError.as_str().to_string()),
                    reason_code: Some(VerdictReason::PolicyLoadError.as_str().to_string()),
                    reason_detail: Some("policy lock poisoned".to_string()),
                    timestamp: current_timestamp(),
                    min_avg_fee_used: 0,
                    fee_tier: "unknown".to_string(),
                    tier_source: "fallback".to_string(),
                    avg_fee_sats_per_tx: 0,
                    template_weight: None,
                    total_sigops: None,
                    coinbase_sigops: None,
                    created_at_unix_ms: None,
                    safety_warnings: vec![],
                };
                metrics.templates_evaluated_total.inc();
                metrics
                    .verdicts_total
                    .get_or_create(&VerdictLabels {
                        accepted: "false".into(),
                        reason_code: logged
                            .reason_code
                            .clone()
                            .unwrap_or_else(|| "unknown".into()),
                    })
                    .inc();
                {
                    let mut guard = log
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.push(logged.clone());
                    if guard.len() > max_log {
                        let excess = guard.len() - max_log;
                        guard.drain(0..excess);
                    }
                }
                let logged_for_disk = logged.clone();
                tokio::task::spawn_blocking(move || {
                    append_verdict_to_disk(&logged_for_disk);
                });
                let json = if uses_envelope == Some(true) {
                    let env = InternalMessage {
                        msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
                        version: PROTOCOL_VERSION,
                        payload: serde_json::to_value(&verdict).unwrap_or_default(),
                    };
                    serde_json::to_string(&env)
                } else {
                    serde_json::to_string(&verdict)
                };
                if let Ok(j) = json {
                    if let Err(e) = writer.write_all(j.as_bytes()).await {
                        warn!(error = %e, "verdict write failed");
                        return;
                    }
                    if let Err(e) = writer.write_all(b"\n").await {
                        warn!(error = %e, "verdict newline write failed");
                        return;
                    }
                    if let Err(e) = writer.flush().await {
                        warn!(error = %e, "verdict flush failed");
                        return;
                    }
                }
                continue;
            }

            // cfg_opt is always Some here because the is_poisoned branch
            // above hits `continue` before reaching this point.
            let Some(cfg) = cfg_opt else { continue };

            let tier_source = if mempool_tx_count.is_some() {
                "measured"
            } else {
                "fallback"
            };

            let now_ms = current_timestamp_ms();
            // Phase 2 path: if AppState carries a mempool view, snapshot
            // it and evaluate with Class M wired. Phase 1 path otherwise.
            let eval = if let Some(view) = state_clone.mempool_view.as_ref() {
                let snap = view.snapshot().await;
                pool_verifier::policy::evaluate_dynamic_phase2(
                    &propose,
                    &cfg,
                    Some(&snap),
                    mempool_tx_count,
                    now_ms,
                )
            } else {
                pool_verifier::policy::evaluate_dynamic(&propose, &cfg, mempool_tx_count, now_ms)
            };

            let accepted = eval.reason.is_none();

            // reason_code string comes from rg-protocol — single source of truth.
            let reason_code_str: Option<String> =
                eval.reason.as_ref().map(|r| r.as_str().to_string());

            // ── Phase 2 Class M observability (ADR-003) ──
            // Increments verifier_phase2_checks_total{result} based on
            // the verdict's reason code and the mempool view state. Only
            // fires when the Phase 2 path was taken (mempool_view present
            // in AppState). Degraded, a primed view that aged out,
            // increments verifier_phase2_degraded_total; Unprimed, the
            // boot window before the first poll, does not (PB-13). Mempool
            // view gauges are refreshed on each snapshot read so
            // dashboards see freshness without an extra polling loop.
            if let Some(view) = state_clone.mempool_view.as_ref() {
                let snap = view.snapshot().await;
                metrics
                    .mempool_view_age_seconds
                    .set(i64::try_from(snap.age_secs).unwrap_or(i64::MAX));
                metrics
                    .mempool_view_size
                    .set(i64::try_from(snap.size).unwrap_or(i64::MAX));
                let result_label = match (eval.reason.as_ref(), snap.state) {
                    (
                        Some(
                            rg_protocol::VerdictReason::V2InvariantMempoolToleranceExceeded
                            | rg_protocol::VerdictReason::V2InvariantMempoolTxUnknown,
                        ),
                        _,
                    ) => "rejected",
                    (_, MempoolState::Degraded) => {
                        metrics.phase2_degraded_total.inc();
                        "skipped"
                    }
                    // PB-13: the boot window before the first successful
                    // poll is Unprimed, not Degraded. Class M is skipped
                    // the same way, but it must NOT increment
                    // phase2_degraded_total or boot-time alerts flap. Its
                    // own result label keeps the prime window observable
                    // via phase2_checks_total.
                    (_, MempoolState::Unprimed) => "unprimed",
                    (_, MempoolState::Stale) => "stale",
                    _ => "agreed",
                };
                metrics
                    .phase2_checks_total
                    .get_or_create(&crate::metrics::Phase2CheckLabels {
                        result: result_label.to_string(),
                    })
                    .inc();
            }

            let reason_detail_str: Option<String> = eval.detail.clone();

            let avg_fee = crate::handlers::compute_avg_fee_sats_per_tx(&propose);

            // Emit structured warnings for observe only safety findings.
            let safety_warning_codes: Vec<String> = eval
                .warnings
                .iter()
                .map(|w| {
                    warn!(
                        template_id = propose.id,
                        height = propose.block_height,
                        warning = w.reason.as_str(),
                        detail = %w.detail,
                        "safety warning"
                    );
                    w.reason.as_str().to_string()
                })
                .collect();

            let policy_ctx = PolicyContext {
                fee_tier: Some(eval.fee_tier.as_str().to_string()),
                min_avg_fee_used: Some(eval.min_avg_fee_used),
                min_total_fees_used: Some(cfg.min_total_fees),
                reject_coinbase_zero: Some(cfg.reject_coinbase_zero),
                unknown_mempool_as_high: Some(cfg.unknown_mempool_as_high),
                max_weight_ratio: Some(cfg.safety.max_weight_ratio),
                max_template_age_ms: cfg.safety.max_template_age_ms,
            };

            let verdict = TemplateVerdict {
                version: PROTOCOL_VERSION,
                id: propose.id,
                accepted,
                reason_code: eval.reason,
                reason_detail: eval.detail.clone(),
                policy_context: Some(policy_ctx),
            };

            let log_id: u64 = id_ctr.fetch_add(1, Ordering::Relaxed);

            let logged = LoggedVerdict {
                log_id,
                template_id: propose.id,
                height: propose.block_height,
                total_fees: propose.total_fees,
                tx_count: propose.tx_count,
                accepted,

                // UI string: prefer reason_code; fallback to detail; fallback to ok.
                reason: reason_code_str
                    .clone()
                    .or_else(|| reason_detail_str.clone())
                    .or(Some("ok".to_string())),

                reason_code: reason_code_str,
                reason_detail: reason_detail_str,

                timestamp: current_timestamp(),

                min_avg_fee_used: eval.min_avg_fee_used,
                fee_tier: eval.fee_tier.as_str().to_string(),
                tier_source: tier_source.to_string(),
                avg_fee_sats_per_tx: avg_fee,

                template_weight: propose.template_weight.or(propose.observed_weight),
                total_sigops: propose.total_sigops,
                coinbase_sigops: propose.coinbase_sigops,
                created_at_unix_ms: propose.created_at_unix_ms,
                safety_warnings: safety_warning_codes,
            };

            metrics.templates_evaluated_total.inc();
            metrics
                .verdicts_total
                .get_or_create(&VerdictLabels {
                    accepted: accepted.to_string(),
                    reason_code: logged.reason_code.clone().unwrap_or_else(|| "ok".into()),
                })
                .inc();

            // ADR-002 Phase 1: count templates that reached the v2.0 Invariant
            // Shield pass but omitted `raw_block_hex`. Dashboards use this to
            // measure rollout coverage of gateways that ship raw block bytes.
            if eval.shield_skipped {
                metrics.shield_skipped_total.inc();
            }

            {
                let mut guard = log
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.push(logged.clone());
                if guard.len() > max_log {
                    let excess = guard.len() - max_log;
                    guard.drain(0..excess);
                }
            }

            let logged_for_disk = logged.clone();
            tokio::task::spawn_blocking(move || {
                append_verdict_to_disk(&logged_for_disk);
            });

            let json = if uses_envelope == Some(true) {
                let env = InternalMessage {
                    msg_type: msg_types::TEMPLATE_VERDICT.to_string(),
                    version: PROTOCOL_VERSION,
                    payload: serde_json::to_value(&verdict).unwrap_or_default(),
                };
                serde_json::to_string(&env)
            } else {
                serde_json::to_string(&verdict)
            };
            let json = match json {
                Ok(j) => j,
                Err(e) => {
                    error!(error = ?e, "serialize verdict error");
                    break;
                }
            };

            if writer.write_all(json.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    }
}

/// API key middleware for protecting routes.
///
/// When `VELDRA_API_SECRET` is set (enforced at startup unless opted out),
/// every non-public request must carry `Authorization: Bearer <secret>`.
/// No localhost bypass: all callers are treated equally.
pub(crate) async fn api_key_middleware(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Response {
    use std::env;

    // If VELDRA_API_SECRET_OPTIONAL=1 was set and no secret exists, allow all.
    let expected = match env::var("VELDRA_API_SECRET") {
        Ok(k) if !k.is_empty() => k,
        _ => return next.run(req).await,
    };

    // Check Authorization header: "Bearer <key>" or raw key.
    let authorized = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            let stripped = v.strip_prefix("Bearer ").unwrap_or(v);
            stripped.as_bytes().ct_eq(expected.as_bytes()).into()
        });

    if authorized {
        next.run(req).await
    } else {
        tracing::warn!(
            peer = %addr,
            path = %req.uri().path(),
            "api_key_auth_failed"
        );
        (StatusCode::UNAUTHORIZED, "missing or invalid api key").into_response()
    }
}
