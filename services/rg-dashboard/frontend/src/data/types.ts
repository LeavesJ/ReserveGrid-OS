/**
 * Canonical data types matching backend JSON response schemas.
 *
 * Source of truth:
 *   pool-verifier  → LoggedVerdict, StatsResponse, PolicyConfig
 *   template-manager → LatestTemplate, MempoolStats
 *   sv2-gateway    → HealthResponse
 *   rg-auth        → session check
 */

/* ── pool-verifier: GET /verdicts ── */
export interface Verdict {
  log_id: number;
  template_id: number;
  height: number;
  total_fees: number;
  tx_count: number;
  accepted: boolean;
  reason: string | null;
  reason_code: string | null;
  reason_detail: string | null;
  fee_tier: "low" | "mid" | "high";
  tier_source: "measured" | "fallback";
  min_avg_fee_used: number;
  avg_fee_sats_per_tx: number;
  template_weight: number | null;
  total_sigops: number | null;
  coinbase_sigops: number | null;
  timestamp: number;
  created_at_unix_ms: number | null;
  safety_warnings: string[];
}

/* ── pool-verifier: GET /stats ── */
export interface VerdictStats {
  total: number;
  accepted: number;
  rejected: number;
  by_reason: Record<string, number>;
  by_tier: Record<string, number>;
  last: Verdict | null;
}

/* ── pool-verifier: GET /policy ── */
export interface PolicyConfig {
  protocol_version: number;
  required_prevhash_len: number;
  min_total_fees: number;
  max_tx_count: number;
  low_mempool_tx: number;
  high_mempool_tx: number;
  min_avg_fee_lo: number;
  min_avg_fee_mid: number;
  min_avg_fee_hi: number;
  max_weight_ratio: number;
  enforce_weight_ratio: boolean;
  max_template_age_ms: number;
  enforce_template_age: boolean;
  warn_sigops_ratio: number;
  warn_coinbase_sigops_max: number;
  reject_empty_templates: boolean;
  reject_coinbase_zero: boolean;
  unknown_mempool_as_high: boolean;
  debug: string;
}

/* ── pool-verifier: POST /policy/apply ── */
export interface PolicyApplyRequest {
  low_mempool_tx?: number;
  high_mempool_tx?: number;
  min_avg_fee_lo?: number;
  min_avg_fee_mid?: number;
  min_avg_fee_hi?: number;
  min_total_fees?: number;
  max_tx_count?: number;
}

/* ── template-manager: GET /latest ── */
export interface LatestTemplate {
  template_id: number;
  block_height: number;
  block_version: number;
  prev_hash: string;
  nbits: number;
  nbits_hex: string;
  min_ntime: number;
  curtime: number;
  coinbase_value: number;
  coinbase_tx_prefix: string;
  coinbase_tx_suffix: string;
  merkle_path: string[];
  tx_count: number;
  total_fees: number;
  source_instance_id: string;
  observed_weight: number | null;
  template_weight: number | null;
  total_sigops: number | null;
  coinbase_sigops: number | null;
}

/* ── template-manager: GET /mempool ── */
export interface MempoolStats {
  loaded_from: string;
  tx_count: number;
  bytes: number;
  usage: number;
  max: number;
  min_relay_fee: number;
  timestamp: number;
}

/* ── rg-dashboard: GET /api/health ── */
export interface ServiceHealth {
  name: string;
  status: "ok" | "degraded" | "down";
  latency_ms: number;
}

export interface HealthResponse {
  services: ServiceHealth[];
}

/* ── rg-auth: GET /auth/session ── */
export type AccountTier = "observe_free" | "observe_paid" | "inline_licensed";

export interface SessionUser {
  id: number;
  name: string;
  email: string;
  org: string;
  tier: AccountTier;
}

export interface SessionCheck {
  valid: boolean;
  user?: SessionUser;
}

/* ── rg-auth: POST /auth/login ── */
export interface LoginResponse {
  ok: boolean;
  token: string;
  user: SessionUser;
}

/* ── Deploy mode ── */
export type DeployMode = "shadow" | "observe" | "inline";

/** Feature capabilities derived from deploy mode. */
export interface ModeCapabilities {
  /** Policy editing and apply are available (observe + inline). */
  canEditPolicy: boolean;
  /** CSV export of verdicts is available (observe + inline). */
  canExportCsv: boolean;
  /** Dry-run simulation is available (observe + inline). */
  canDryRun: boolean;
  /** Miners page is visible (inline only). */
  canViewMiners: boolean;
  /** Settings mutation (save) is available (observe + inline). */
  canEditSettings: boolean;
}

export function modeCapabilities(mode: DeployMode): ModeCapabilities {
  return {
    canEditPolicy: mode !== "shadow",
    canExportCsv: mode !== "shadow",
    canDryRun: mode !== "shadow",
    canViewMiners: mode === "inline",
    canEditSettings: mode !== "shadow",
  };
}

/* ── pool-verifier: GET /settings ── */
export interface VerifierSettings {
  log_level: string;
  log_format: string;
  deploy_mode: DeployMode;
  dash_mode: string;
  mempool_url: string;
  api_key_set: boolean;
  tls_enabled: boolean;
  tls_self_signed: boolean;
  mtls_client_ca_set: boolean;
  tcp_addr: string;
  http_addr: string;
  policy_file: string;
  pending_restart: boolean;
}

/* ── sv2-gateway: GET /settings ── */
export interface GatewaySettings {
  log_level: string;
  log_format: string;
  gateway_mode: string;
  listen_addr: string;
  health_addr: string;
  max_connections: number;
  max_channels_per_conn: number;
  max_worker_id_bytes: number;
  template_poll_interval_ms: number;
  max_template_age_ms: number;
  prevhash_verdict_timeout_ms: number;
  prevhash_stale_hold_ms: number;
  upstream_stale_max_ms: number;
  upstream_failure_policy: string;
  share_dedup_window_size: number;
  ntime_elapsed_slack_seconds: number;
  max_future_block_time_seconds: number;
  miner_auth: string;
  job_retention_ms: number;
  channel_target_hex: string;
  max_shares_per_second_per_channel: number;
  noise_cert_validity_secs: number;
  noise_handshake_timeout_ms: number;
  noise_keypair_path: string;
  noise_keypair_reload_sighup: boolean;
  noise_keypair_poll_interval_secs: number;
  wal_path: string;
  wal_compaction_threshold: number;
  template_url: string;
  gateway_instance_id: string;
  verifier_addr: string;
  verifier_tls_enabled: boolean;
  verifier_tls_server_name: string;
  verifier_health_probe_staleness_ms: number;
  share_upstream_url: string;
  share_upstream_secret_set: boolean;
  share_upstream_retries: number;
  share_upstream_queue_size: number;
  share_upstream_max_in_flight: number;
  share_upstream_drop_policy: string;
  share_upstream_rate_limit: number | null;
  pending_restart: boolean;
}

/* ── template-manager: GET /settings ── */
export interface TemplateSettings {
  log_level: string;
  log_format: string;
  backend: string;
  poll_interval_secs: number;
  coinbase_output_script_hex: string;
  extranonce_size: number;
  http_listen_addr: string;
  verifier_tcp_addr: string;
  rpc_url: string;
  rpc_user: string;
  rpc_pass_set: boolean;
  stratum_addr: string;
  stratum_auth_set: boolean;
  pending_restart: boolean;
}

/* ── rg-auth: GET /auth/settings ── */
export interface AuthSettings {
  log_level: string;
  log_format: string;
  bind_addr: string;
  db_path: string;
  session_ttl_hours: number;
  admin_email: string;
  site_url: string;
  auth_url: string;
  allowed_origin: string;
  smtp_host: string;
  smtp_port: number;
  smtp_user: string;
  smtp_pass_set: boolean;
  smtp_configured: boolean;
}

/* ── rg-dashboard: GET /api/dashboard/settings ── */
export interface DashboardSettings {
  log_level: string;
  log_format: string;
  deploy_mode: DeployMode;
  listen: string;
  verifier_url: string;
  template_url: string;
  auth_url: string;
  gateway_url: string;
}

/* ── Derived: acceptance rate computed client-side ── */
export function acceptanceRate(stats: VerdictStats): number {
  if (stats.total === 0) return 100;
  return (stats.accepted / stats.total) * 100;
}
