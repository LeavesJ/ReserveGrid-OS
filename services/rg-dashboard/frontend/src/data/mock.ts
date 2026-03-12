/**
 * Mock data for offline/development rendering.
 * Hooks fall back to these when the backend is unreachable.
 */

import type {
  ServiceHealth, Verdict,
  VerifierSettings, GatewaySettings, TemplateSettings, AuthSettings,
  DashboardSettings,
} from "./types";

export interface SimpleMempoolStats {
  tx_count: number;
  bytes: number;
  usage: number;
  max: number;
  min_relay_fee: number;
}

export interface SimpleTemplateInfo {
  template_id: number;
  block_height: number;
  block_version: number;
  prev_hash: string;
  coinbase_value: number;
  tx_count: number;
  total_fees: number;
  template_weight: number;
  total_sigops: number;
  coinbase_sigops: number;
  age_ms: number;
}

export interface SimplePolicyConfig {
  low_mempool_tx: number;
  high_mempool_tx: number;
  min_avg_fee_lo: number;
  min_avg_fee_mid: number;
  min_avg_fee_hi: number;
  min_total_fees: number;
  max_tx_count: number;
  max_weight_ratio: number;
  enforce_weight_ratio: boolean;
  max_template_age_ms: number;
  enforce_template_age: boolean;
  warn_sigops_ratio: number;
}

export interface MinerConnection {
  worker_name: string;
  channel_id: number;
  connected_at: number;
  shares_submitted: number;
  shares_accepted: number;
  last_share_at: number;
  hashrate_th: number;
}

export const MOCK_SERVICES: ServiceHealth[] = [
  { name: "sv2-gateway", status: "ok", latency_ms: 2 },
  { name: "template-manager", status: "ok", latency_ms: 8 },
  { name: "pool-verifier", status: "ok", latency_ms: 4 },
  { name: "rg-auth", status: "ok", latency_ms: 3 },
  { name: "rg-dashboard", status: "ok", latency_ms: 1 },
];

export const MOCK_MEMPOOL: SimpleMempoolStats = {
  tx_count: 48291,
  bytes: 142_000_000,
  usage: 284_000_000,
  max: 300_000_000,
  min_relay_fee: 1000,
};

export const MOCK_POLICY: SimplePolicyConfig = {
  low_mempool_tx: 5000,
  high_mempool_tx: 25000,
  min_avg_fee_lo: 1200,
  min_avg_fee_mid: 2400,
  min_avg_fee_hi: 4800,
  min_total_fees: 50000,
  max_tx_count: 10000,
  max_weight_ratio: 0.98,
  enforce_weight_ratio: true,
  max_template_age_ms: 30000,
  enforce_template_age: false,
  warn_sigops_ratio: 0.8,
};

export const MOCK_TEMPLATE: SimpleTemplateInfo = {
  template_id: 847293,
  block_height: 891204,
  block_version: 0x20000000,
  prev_hash: "00000000000000000002a7c4f...",
  coinbase_value: 328125000,
  tx_count: 3847,
  total_fees: 15625000,
  template_weight: 3992140,
  total_sigops: 12847,
  coinbase_sigops: 4,
  age_ms: 2400,
};

const REASON_CODES = [
  null, null, null, null, null, null, null,
  "total_fees_below_minimum",
  "weight_ratio_exceeded",
  "template_stale",
  "sigops_budget_warning",
];

function generateVerdicts(count: number): Verdict[] {
  const now = Date.now();
  return Array.from({ length: count }, (_, i) => {
    const reason = REASON_CODES[Math.floor(Math.random() * REASON_CODES.length)];
    const accepted = reason === null;
    const height = 891204 - Math.floor(i / 3);
    const avgFee = 2000 + Math.floor(Math.random() * 6000);
    return {
      log_id: count - i,
      template_id: 847293 - i,
      height,
      total_fees: 12_000_000 + Math.floor(Math.random() * 8_000_000),
      tx_count: 2000 + Math.floor(Math.random() * 3000),
      accepted,
      reason: reason ? `Policy threshold exceeded for ${reason}` : null,
      reason_code: reason,
      reason_detail: reason ? `Policy threshold exceeded for ${reason}` : null,
      fee_tier: (["low", "mid", "high"] as const)[Math.floor(Math.random() * 3)],
      tier_source: Math.random() > 0.2 ? "measured" as const : "fallback" as const,
      min_avg_fee_used: avgFee > 4000 ? 4800 : avgFee > 2000 ? 2400 : 1200,
      avg_fee_sats_per_tx: avgFee,
      template_weight: 3_800_000 + Math.floor(Math.random() * 200_000),
      total_sigops: 10000 + Math.floor(Math.random() * 5000),
      coinbase_sigops: 4,
      timestamp: now - i * 12000,
      created_at_unix_ms: now - i * 12000,
      safety_warnings: Math.random() > 0.9 ? ["sigops_ratio_high"] : [],
    };
  });
}

export const MOCK_VERDICTS = generateVerdicts(50);

export const MOCK_STATS = {
  total: 12847,
  accepted: 11293,
  rejected: 1554,
  acceptance_rate: 87.9,
  by_reason: {
    total_fees_below_minimum: 823,
    weight_ratio_exceeded: 412,
    template_stale: 247,
    sigops_budget_warning: 72,
  } as Record<string, number>,
  by_tier: { low: 3291, mid: 5842, high: 3714 },
};

export const MOCK_VERIFIER_SETTINGS: VerifierSettings = {
  log_level: "info",
  log_format: "json",
  deploy_mode: "inline",
  dash_mode: "inline",
  mempool_url: "",
  api_key_set: false,
  tls_enabled: false,
  tls_self_signed: false,
  mtls_client_ca_set: false,
  tcp_addr: "127.0.0.1:5001",
  http_addr: "127.0.0.1:8080",
  policy_file: "config/policy.toml",
  pending_restart: false,
};

export const MOCK_GATEWAY_SETTINGS: GatewaySettings = {
  log_level: "info",
  log_format: "json",
  gateway_mode: "inline",
  listen_addr: "0.0.0.0:3333",
  health_addr: "0.0.0.0:8080",
  max_connections: 1024,
  max_channels_per_conn: 256,
  max_worker_id_bytes: 128,
  template_poll_interval_ms: 3000,
  max_template_age_ms: 30000,
  prevhash_verdict_timeout_ms: 50,
  prevhash_stale_hold_ms: 5000,
  upstream_stale_max_ms: 30000,
  upstream_failure_policy: "fail_closed",
  share_dedup_window_size: 10000,
  ntime_elapsed_slack_seconds: 2,
  max_future_block_time_seconds: 7200,
  miner_auth: "Open",
  job_retention_ms: 300000,
  channel_target_hex: "",
  max_shares_per_second_per_channel: 0,
  noise_cert_validity_secs: 3600,
  noise_handshake_timeout_ms: 5000,
  noise_keypair_path: "./certs/noise.key",
  noise_keypair_reload_sighup: true,
  noise_keypair_poll_interval_secs: 0,
  wal_path: "",
  wal_compaction_threshold: 1000,
  template_url: "",
  gateway_instance_id: "gw-mock-01",
  verifier_addr: "127.0.0.1:9100",
  verifier_tls_enabled: false,
  verifier_tls_server_name: "localhost",
  verifier_health_probe_staleness_ms: 10000,
  share_upstream_url: "",
  share_upstream_secret_set: false,
  share_upstream_retries: 2,
  share_upstream_queue_size: 50000,
  share_upstream_max_in_flight: 256,
  share_upstream_drop_policy: "drop_new",
  share_upstream_rate_limit: null,
  pending_restart: false,
};

export const MOCK_TEMPLATE_SETTINGS: TemplateSettings = {
  log_level: "info",
  log_format: "json",
  backend: "bitcoind",
  poll_interval_secs: 1,
  coinbase_output_script_hex: "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
  extranonce_size: 8,
  http_listen_addr: "0.0.0.0:8082",
  verifier_tcp_addr: "127.0.0.1:8080",
  rpc_url: "http://127.0.0.1:8332",
  rpc_user: "rpcuser",
  rpc_pass_set: true,
  stratum_addr: "",
  stratum_auth_set: false,
  pending_restart: false,
};

export const MOCK_AUTH_SETTINGS: AuthSettings = {
  log_level: "info",
  log_format: "json",
  bind_addr: "127.0.0.1:3030",
  db_path: "data/auth.db",
  session_ttl_hours: 168,
  admin_email: "admin@localhost",
  site_url: "http://localhost:8000",
  auth_url: "http://127.0.0.1:3030",
  allowed_origin: "*",
  smtp_host: "",
  smtp_port: 0,
  smtp_user: "",
  smtp_pass_set: false,
  smtp_configured: false,
};

export const MOCK_DASHBOARD_SETTINGS: DashboardSettings = {
  log_level: "info",
  log_format: "pretty",
  deploy_mode: "inline",
  listen: "0.0.0.0:8084",
  verifier_url: "http://pool-verifier:8081",
  template_url: "http://template-manager:8082",
  auth_url: "http://rg-auth:3030",
  gateway_url: "http://sv2-gateway:8080",
};

export const MOCK_MINERS: MinerConnection[] = [
  { worker_name: "antminer-s21-rack1.01", channel_id: 2, connected_at: Date.now() - 86400000, shares_submitted: 48291, shares_accepted: 48103, last_share_at: Date.now() - 1200, hashrate_th: 200 },
  { worker_name: "antminer-s21-rack1.02", channel_id: 3, connected_at: Date.now() - 86400000, shares_submitted: 47102, shares_accepted: 46998, last_share_at: Date.now() - 3400, hashrate_th: 198 },
  { worker_name: "antminer-s21-rack2.01", channel_id: 4, connected_at: Date.now() - 43200000, shares_submitted: 24011, shares_accepted: 23944, last_share_at: Date.now() - 800, hashrate_th: 201 },
  { worker_name: "whatsminer-m56s.01", channel_id: 5, connected_at: Date.now() - 72000000, shares_submitted: 39102, shares_accepted: 38987, last_share_at: Date.now() - 5100, hashrate_th: 212 },
  { worker_name: "whatsminer-m56s.02", channel_id: 6, connected_at: Date.now() - 72000000, shares_submitted: 38400, shares_accepted: 38291, last_share_at: Date.now() - 2200, hashrate_th: 210 },
];
