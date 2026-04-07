/**
 * API polling hooks for all rg-dashboard proxy endpoints.
 *
 * Each hook fetches on a fixed interval and falls back to mock data
 * when the backend is unreachable so the SPA renders during development.
 *
 * When running inside the Tauri desktop client, all fetch calls route
 * through IPC commands instead of HTTP. The `tauriFetch` adapter handles
 * this transparently.
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { tauriFetch } from "../tauri-bridge";
import type {
  HealthResponse, ServiceHealth, VerdictStats,
  Verdict, PolicyConfig, MempoolStats, LatestTemplate,
  VerifierSettings, GatewaySettings, TemplateSettings, AuthSettings,
  DashboardSettings, SessionUser, LoginResponse,
} from "../data/types";
import type { MinerConnection } from "../data/mock";
import {
  MOCK_SERVICES, MOCK_STATS, MOCK_VERDICTS,
  MOCK_TEMPLATE, MOCK_MEMPOOL, MOCK_POLICY,
  MOCK_VERIFIER_SETTINGS, MOCK_GATEWAY_SETTINGS,
  MOCK_TEMPLATE_SETTINGS, MOCK_AUTH_SETTINGS,
  MOCK_DASHBOARD_SETTINGS,
  MOCK_MINERS,
} from "../data/mock";

/* ── Auth token (module-level, shared by all fetchers) ── */

let _authToken: string | null = null;
export function setAuthToken(t: string | null) { _authToken = t; }
export function getAuthToken(): string | null { return _authToken; }

let _onUnauthorized: (() => void) | null = null;
export function setOnUnauthorized(cb: (() => void) | null) { _onUnauthorized = cb; }

function authHeaders(): Record<string, string> {
  if (_authToken) return { Authorization: `Bearer ${_authToken}` };
  return {};
}

/* ── Generic fetcher ── */

async function fetchJson<T>(url: string, timeoutMs = 5000): Promise<T | null> {
  try {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), timeoutMs);
    const resp = await tauriFetch(url, { headers: authHeaders(), signal: ctrl.signal });
    clearTimeout(id);
    if (resp.status === 401) { _onUnauthorized?.(); return null; }
    if (!resp.ok) return null;
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}

async function postJson<T>(url: string, body: unknown, timeoutMs = 5000): Promise<T | null> {
  try {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), timeoutMs);
    const resp = await tauriFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    clearTimeout(id);
    if (resp.status === 401) { _onUnauthorized?.(); return null; }
    if (!resp.ok) return null;
    const text = await resp.text();
    if (!text) return "" as unknown as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      return text as unknown as T;
    }
  } catch {
    return null;
  }
}

/* ── Generic poll hook ── */

function usePoll<T>(url: string, fallback: T, intervalMs: number): { data: T; live: boolean } {
  const [data, setData] = useState<T>(fallback);
  const [live, setLive] = useState(false);
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;

  const poll = useCallback(async () => {
    const result = await fetchJson<T>(url);
    if (result !== null) {
      setData(result);
      setLive(true);
    } else {
      setLive(false);
    }
  }, [url]);

  useEffect(() => {
    poll();
    const handle = setInterval(poll, intervalMs);
    return () => clearInterval(handle);
  }, [poll, intervalMs]);

  return { data, live };
}

/* ── Service health: GET /api/health (10s) ── */

export function useHealth(): { services: ServiceHealth[]; live: boolean } {
  const { data, live } = usePoll<HealthResponse>(
    "/api/health",
    { services: MOCK_SERVICES },
    10_000,
  );
  return { services: data.services, live };
}

/* ── Verdict stats: GET /api/verifier/stats (5s) ── */

const MOCK_STATS_RESPONSE: VerdictStats = {
  total: MOCK_STATS.total,
  accepted: MOCK_STATS.accepted,
  rejected: MOCK_STATS.rejected,
  by_reason: MOCK_STATS.by_reason,
  by_tier: MOCK_STATS.by_tier,
  last: null,
};

export function useStats(): { stats: VerdictStats; live: boolean } {
  const { data, live } = usePoll<VerdictStats>(
    "/api/verifier/stats",
    MOCK_STATS_RESPONSE,
    5_000,
  );
  return { stats: data, live };
}

/* ── Verdicts list: GET /api/verifier/verdicts (5s) ── */

export function useVerdicts(): { verdicts: Verdict[]; live: boolean } {
  const { data, live } = usePoll<Verdict[]>(
    "/api/verifier/verdicts",
    MOCK_VERDICTS,
    5_000,
  );
  return { verdicts: data, live };
}

/* ── Policy: GET /api/verifier/policy (30s) ── */

const MOCK_POLICY_FULL: PolicyConfig = {
  protocol_version: 1,
  required_prevhash_len: 32,
  min_total_fees: MOCK_POLICY.min_total_fees,
  max_tx_count: MOCK_POLICY.max_tx_count,
  low_mempool_tx: MOCK_POLICY.low_mempool_tx,
  high_mempool_tx: MOCK_POLICY.high_mempool_tx,
  min_avg_fee_lo: MOCK_POLICY.min_avg_fee_lo,
  min_avg_fee_mid: MOCK_POLICY.min_avg_fee_mid,
  min_avg_fee_hi: MOCK_POLICY.min_avg_fee_hi,
  max_weight_ratio: MOCK_POLICY.max_weight_ratio,
  enforce_weight_ratio: MOCK_POLICY.enforce_weight_ratio,
  max_template_age_ms: MOCK_POLICY.max_template_age_ms,
  enforce_template_age: MOCK_POLICY.enforce_template_age,
  warn_sigops_ratio: MOCK_POLICY.warn_sigops_ratio,
  warn_coinbase_sigops_max: 20,
  reject_empty_templates: true,
  reject_coinbase_zero: true,
  unknown_mempool_as_high: false,
  debug: "",
};

export function usePolicy(): { policy: PolicyConfig; live: boolean } {
  // Synced to 5s to match verdict polling; avoids showing new rejections
  // while the policy display is still 25s stale.
  const { data, live } = usePoll<PolicyConfig>(
    "/api/verifier/policy",
    MOCK_POLICY_FULL,
    5_000,
  );
  return { policy: data, live };
}

/* ── Policy apply: POST /api/verifier/policy/apply ── */

export async function applyPolicy(patch: Record<string, number | boolean>): Promise<{ ok: boolean; error?: string }> {
  const result = await postJson<string>("/api/verifier/policy/apply", patch);
  if (result !== null) return { ok: true };
  return { ok: false, error: "Failed to apply policy" };
}

/* ── Latest template: GET /api/templates/latest (3s) ── */

const MOCK_LATEST: LatestTemplate = {
  template_id: MOCK_TEMPLATE.template_id,
  block_height: MOCK_TEMPLATE.block_height,
  block_version: MOCK_TEMPLATE.block_version,
  prev_hash: MOCK_TEMPLATE.prev_hash,
  nbits: 0x1a0a7c4f,
  nbits_hex: "1a0a7c4f",
  min_ntime: 0,
  curtime: Math.floor(Date.now() / 1000),
  coinbase_value: MOCK_TEMPLATE.coinbase_value,
  coinbase_tx_prefix: "",
  coinbase_tx_suffix: "",
  merkle_path: [],
  tx_count: MOCK_TEMPLATE.tx_count,
  total_fees: MOCK_TEMPLATE.total_fees,
  source_instance_id: "bitcoind-0",
  observed_weight: null,
  template_weight: MOCK_TEMPLATE.template_weight,
  total_sigops: MOCK_TEMPLATE.total_sigops,
  coinbase_sigops: MOCK_TEMPLATE.coinbase_sigops,
};

export function useLatestTemplate(): { template: LatestTemplate; live: boolean } {
  const { data, live } = usePoll<LatestTemplate>(
    "/api/templates/latest",
    MOCK_LATEST,
    3_000,
  );
  return { template: data, live };
}

/* ── Mempool: GET /api/templates/mempool (10s) ── */

const MOCK_MEMPOOL_FULL: MempoolStats = {
  loaded_from: "mock",
  tx_count: MOCK_MEMPOOL.tx_count,
  bytes: MOCK_MEMPOOL.bytes,
  usage: MOCK_MEMPOOL.usage,
  max: MOCK_MEMPOOL.max,
  min_relay_fee: MOCK_MEMPOOL.min_relay_fee,
  timestamp: Date.now(),
};

export function useMempool(): { mempool: MempoolStats; live: boolean } {
  const { data, live } = usePoll<MempoolStats>(
    "/api/templates/mempool",
    MOCK_MEMPOOL_FULL,
    10_000,
  );
  return { mempool: data, live };
}

/* ── Verifier settings: GET /api/verifier/settings (30s) ── */

export function useVerifierSettings(): { settings: VerifierSettings; live: boolean } {
  const { data, live } = usePoll<VerifierSettings>(
    "/api/verifier/settings",
    MOCK_VERIFIER_SETTINGS,
    30_000,
  );
  return { settings: data, live };
}

/* ── Gateway settings: GET /api/gateway/settings (30s) ── */

export function useGatewaySettings(): { settings: GatewaySettings; live: boolean } {
  const { data, live } = usePoll<GatewaySettings>(
    "/api/gateway/settings",
    MOCK_GATEWAY_SETTINGS,
    30_000,
  );
  return { settings: data, live };
}

/* ── Template settings: GET /api/templates/settings (30s) ── */

export function useTemplateSettings(): { settings: TemplateSettings; live: boolean } {
  const { data, live } = usePoll<TemplateSettings>(
    "/api/templates/settings",
    MOCK_TEMPLATE_SETTINGS,
    30_000,
  );
  return { settings: data, live };
}

/* ── Auth settings: GET /api/auth/settings (30s) ── */

export function useAuthSettings(): { settings: AuthSettings; live: boolean } {
  const { data, live } = usePoll<AuthSettings>(
    "/api/auth/settings",
    MOCK_AUTH_SETTINGS,
    30_000,
  );
  return { settings: data, live };
}

/* ── Dashboard settings: GET /api/dashboard/settings (30s) ── */

export function useDashboardSettings(): { settings: DashboardSettings; live: boolean } {
  const { data, live } = usePoll<DashboardSettings>(
    "/api/dashboard/settings",
    MOCK_DASHBOARD_SETTINGS,
    30_000,
  );
  return { settings: data, live };
}

/* ── Verifier settings apply: POST /api/verifier/settings/apply ── */

export async function applyVerifierSettings(patch: Record<string, string>): Promise<{ ok: boolean; error?: string }> {
  const result = await postJson<string>("/api/verifier/settings/apply", patch);
  if (result !== null) return { ok: true };
  return { ok: false, error: "Failed to apply settings" };
}

/* ── Settings save (persist to disk): POST /api/{service}/settings/save ── */

interface SaveResponse {
  ok: boolean;
  restart_required?: boolean;
  error?: string;
}

export async function saveVerifierSettings(patch: Record<string, unknown>): Promise<SaveResponse> {
  const result = await postJson<SaveResponse>("/api/verifier/settings/save", patch);
  if (result !== null && typeof result === "object" && "ok" in result) return result;
  if (result !== null) return { ok: true, restart_required: true };
  return { ok: false, error: "Failed to save verifier settings" };
}

export async function saveGatewaySettings(patch: Record<string, unknown>): Promise<SaveResponse> {
  const result = await postJson<SaveResponse>("/api/gateway/settings/save", patch);
  if (result !== null && typeof result === "object" && "ok" in result) return result;
  if (result !== null) return { ok: true, restart_required: true };
  return { ok: false, error: "Failed to save gateway settings" };
}

export async function saveTemplateSettings(patch: Record<string, unknown>): Promise<SaveResponse> {
  const result = await postJson<SaveResponse>("/api/templates/settings/save", patch);
  if (result !== null && typeof result === "object" && "ok" in result) return result;
  if (result !== null) return { ok: true, restart_required: true };
  return { ok: false, error: "Failed to save template settings" };
}

/* ── Miners (channels): GET /api/gateway/channels (5s) ── */

interface ChannelSnapshot {
  channel_id: number;
  worker_id: string;
  peer_addr: string;
  opened_at_unix_ms: number;
  shares_submitted: number;
  shares_accepted: number;
  last_share_at_unix_ms: number;
  hashrate_th: number;
}

function mapChannelsToMiners(channels: ChannelSnapshot[]): MinerConnection[] {
  return channels.map((c) => ({
    worker_name: c.worker_id,
    channel_id: c.channel_id,
    connected_at: c.opened_at_unix_ms,
    shares_submitted: c.shares_submitted,
    shares_accepted: c.shares_accepted,
    last_share_at: c.last_share_at_unix_ms,
    hashrate_th: c.hashrate_th,
  }));
}

export function useMiners(): { miners: MinerConnection[]; live: boolean } {
  const { data, live } = usePoll<ChannelSnapshot[]>(
    "/api/gateway/channels",
    [],
    5_000,
  );
  const miners = live ? mapChannelsToMiners(data) : MOCK_MINERS;
  return { miners, live };
}

/* ── Registration + email verification ── */

export interface RegisterResponse {
  ok: boolean;
  message?: string;
  error?: string;
  code?: string;
}

export async function register(
  email: string, name: string, org: string, password: string
): Promise<RegisterResponse> {
  try {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), 10_000);
    const resp = await tauriFetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, name, org, password }),
      signal: ctrl.signal,
    });
    clearTimeout(id);
    const body = await resp.json().catch(() => null) as { ok?: boolean; error?: string; detail?: string; message?: string } | null;
    if (resp.ok && body?.ok) return { ok: true, message: body.message };
    return { ok: false, error: body?.detail ?? body?.error ?? `Registration failed (${resp.status})` };
  } catch {
    return { ok: false, error: "Network error" };
  }
}

export async function verifyEmail(token: string): Promise<{ ok: boolean; message: string }> {
  try {
    const resp = await tauriFetch(`/api/auth/verify?token=${encodeURIComponent(token)}`);
    const body = await resp.json().catch(() => null) as { ok?: boolean; message?: string; detail?: string } | null;
    if (resp.ok && body?.ok) return { ok: true, message: body.message ?? "Email verified." };
    return { ok: false, message: body?.detail ?? body?.message ?? "Verification failed" };
  } catch {
    return { ok: false, message: "Network error" };
  }
}

/* ── Forgot / reset password ── */

export async function forgotPassword(email: string): Promise<{ ok: boolean; message: string }> {
  const result = await postJson<{ ok?: boolean; message?: string }>("/api/auth/forgot-password", { email });
  if (result !== null && typeof result === "object" && "ok" in result) {
    return { ok: !!result.ok, message: result.message ?? "" };
  }
  return { ok: false, message: "Network error" };
}

export async function resetPassword(token: string, password: string): Promise<{ ok: boolean; message: string }> {
  try {
    const ctrl = new AbortController();
    const id = setTimeout(() => ctrl.abort(), 10_000);
    const resp = await tauriFetch("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password }),
      signal: ctrl.signal,
    });
    clearTimeout(id);
    const body = await resp.json().catch(() => null) as { ok?: boolean; message?: string; detail?: string } | null;
    if (resp.ok && body?.ok) return { ok: true, message: body.message ?? "Password reset successful." };
    return { ok: false, message: body?.detail ?? body?.message ?? "Reset failed" };
  } catch {
    return { ok: false, message: "Network error" };
  }
}

/* ── Session management ── */

export function useSession(): {
  user: SessionUser | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  loading: boolean;
  error: string | null;
} {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSession = useCallback(() => {
    setAuthToken(null);
    setUser(null);
  }, []);

  useEffect(() => {
    setOnUnauthorized(clearSession);
    return () => setOnUnauthorized(null);
  }, [clearSession]);

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    try {
      const ctrl = new AbortController();
      const id = setTimeout(() => ctrl.abort(), 10_000);
      const resp = await tauriFetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        signal: ctrl.signal,
      });
      clearTimeout(id);
      if (!resp.ok) {
        const body = await resp.json().catch(() => null) as { detail?: string; code?: string } | null;
        const code = body?.code;
        if (code === "email_not_verified") throw new Error("Please verify your email first.");
        if (code === "pending_approval") throw new Error("Your account is pending admin approval.");
        if (code === "access_denied") throw new Error("Your access request was denied.");
        throw new Error(body?.detail ?? `Login failed (${resp.status})`);
      }
      const data = (await resp.json()) as LoginResponse;
      setAuthToken(data.token);
      setUser(data.user);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Network error";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    const token = getAuthToken();
    clearSession();
    if (token) {
      tauriFetch("/api/auth/logout", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {});
    }
  }, [clearSession]);

  return { user, login, logout, loading, error };
}
