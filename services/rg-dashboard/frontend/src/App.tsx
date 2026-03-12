import { useState, useEffect, useRef } from "react";
import {
  LayoutDashboard, FileText, Shield, Settings, Pickaxe,
  Database, AlertTriangle, Eye, Download, Search, Activity,
  Wifi, WifiOff, Lock, Unlock, LogOut, CheckCircle, Mail, Loader2, KeyRound,
} from "lucide-react";
import { Toggle } from "./components/Toggle";
import {
  useHealth, useStats, useVerdicts, usePolicy,
  useLatestTemplate, useMempool, applyPolicy,
  useVerifierSettings, useGatewaySettings,
  useTemplateSettings, useAuthSettings,
  useDashboardSettings,
  saveVerifierSettings, saveGatewaySettings, saveTemplateSettings,
  useMiners, useSession,
  register, verifyEmail,
  forgotPassword, resetPassword,
} from "./hooks/useApi";
import type {
  ServiceHealth, VerdictStats, Verdict, PolicyConfig,
  LatestTemplate, MempoolStats, DeployMode, ModeCapabilities,
} from "./data/types";
import { acceptanceRate as calcAcceptRate, modeCapabilities } from "./data/types";

/* ── Forge Line design tokens ── */
const V = {
  bg:           "#06090f",
  bgAlt:        "#0a0e18",
  navy:         "#080e1a",
  navyMid:      "#0c1526",
  navyLight:    "#111d35",
  panel:        "#0f1520",
  panelLight:   "#1a2230",
  amber:        "#d4943c",
  amberLight:   "#e8b060",
  amberDim:     "#b07828",
  amberGlow:    "rgba(212,148,60,.35)",
  amberGlowSm:  "rgba(212,148,60,.15)",
  steel:        "#8899ad",
  steelDim:     "#6b7d91",
  ink:          "#e2e8f0",
  inkMuted:     "rgba(226,232,240,.6)",
  inkSubtle:    "rgba(226,232,240,.35)",
  border:       "rgba(226,232,240,.07)",
  borderMd:     "rgba(226,232,240,.11)",
  borderBright: "rgba(226,232,240,.18)",
  success:      "#22c55e",
  successGlow:  "rgba(74,222,128,.25)",
  warning:      "#f59e0b",
  error:        "#ef4444",
};

/* ── Shared primitives ── */

function StatusDot({ status }: { status: ServiceHealth["status"] }) {
  const colors = { ok: V.success, degraded: V.warning, down: V.error };
  const glows = {
    ok: `0 0 6px ${V.successGlow}`,
    degraded: "0 0 6px rgba(245,158,11,.3)",
    down: "0 0 6px rgba(239,68,68,.3)",
  };
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: colors[status], boxShadow: glows[status] }}
    />
  );
}

function formatSats(sats: number) {
  if (sats >= 100_000_000) return `${(sats / 100_000_000).toFixed(3)} BTC`;
  return `${sats.toLocaleString()} sat`;
}

/** Format TH/s with adaptive unit (TH/s, PH/s, EH/s). */
function fmtHashrate(th: number): string {
  if (th <= 0) return "0 TH/s";
  if (th < 1000) return `${th.toFixed(2)} TH/s`;
  if (th < 1_000_000) return `${(th / 1000).toFixed(2)} PH/s`;
  return `${(th / 1_000_000).toFixed(2)} EH/s`;
}

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function Card({ children, className = "", hover = false, glow = false }: {
  children: React.ReactNode; className?: string; hover?: boolean; glow?: boolean;
}) {
  return (
    <div
      className={`rounded-xl transition-all duration-200 ${hover ? "hover:-translate-y-0.5" : ""} ${className}`}
      style={{
        background: V.panel,
        border: `1px solid ${V.borderMd}`,
        ...(glow ? { boxShadow: `0 0 30px ${V.amberGlowSm}` } : {}),
      }}
    >
      {children}
    </div>
  );
}

function GlowLine() {
  return (
    <div
      className="h-px w-full"
      style={{ background: `linear-gradient(90deg, transparent, ${V.amberGlow}, transparent)` }}
    />
  );
}

function AccentText({ children }: { children: React.ReactNode }) {
  return (
    <span
      style={{
        background: `linear-gradient(135deg, ${V.amberLight} 0%, ${V.amber} 60%, ${V.steel} 100%)`,
        WebkitBackgroundClip: "text",
        WebkitTextFillColor: "transparent",
        backgroundClip: "text",
      }}
    >
      {children}
    </span>
  );
}

function Btn({ children, variant = "default", className = "", onClick, disabled = false }: {
  children: React.ReactNode; variant?: "default" | "primary" | "glow" | "outline";
  className?: string; onClick?: () => void; disabled?: boolean;
}) {
  const base = "inline-flex items-center justify-center gap-2 h-9 px-4 rounded-lg text-xs font-semibold transition-all duration-200 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed";
  const styles: Record<string, React.CSSProperties> = {
    default: { background: "rgba(226,232,240,.05)", color: V.ink, border: `1px solid ${V.borderMd}` },
    primary: { background: V.amber, color: "#fff", border: `1px solid ${V.amber}` },
    glow: { background: `linear-gradient(135deg, ${V.amber} 0%, ${V.amberLight} 100%)`, border: "none", color: "#0a0e18", fontWeight: 700 },
    outline: { background: "transparent", border: `1px solid ${V.borderBright}`, color: V.inkMuted },
  };
  return (
    <button className={`${base} ${className}`} style={styles[variant]} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

function LiveBadge({ live }: { live: boolean }) {
  if (live) {
    return (
      <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded" style={{
        color: V.success, background: "rgba(34,197,94,.08)", border: "1px solid rgba(34,197,94,.2)",
      }}>
        <Wifi className="w-3 h-3" /> LIVE
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded" style={{
      color: V.warning, background: "rgba(245,158,11,.08)", border: "1px solid rgba(245,158,11,.2)",
    }}>
      <WifiOff className="w-3 h-3" /> MOCK
    </span>
  );
}

/* ── Navigation ── */

type Page = "overview" | "verdicts" | "policy" | "templates" | "miners" | "settings";

const NAV: { id: Page; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: "overview",  label: "Overview",   icon: LayoutDashboard },
  { id: "verdicts",  label: "Verdicts",   icon: FileText },
  { id: "templates", label: "Templates",  icon: Database },
  { id: "policy",    label: "Policy",     icon: Shield },
  { id: "miners",    label: "Miners",     icon: Pickaxe },
  { id: "settings",  label: "Settings",   icon: Settings },
];

/* ── Metric card ── */

function MetricCard({ label, value, sub, accent = false }: {
  label: string; value: string; sub?: string; accent?: boolean;
}) {
  return (
    <Card hover>
      <div className="p-4">
        <p className="text-[11px] uppercase tracking-wider mb-1.5" style={{ color: V.inkSubtle, fontFamily: "var(--mono)" }}>{label}</p>
        <p className="text-2xl font-bold" style={{
          fontFamily: "var(--mono)",
          ...(accent
            ? { background: `linear-gradient(135deg, ${V.amberLight}, ${V.amber})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }
            : { color: V.ink })
        }}>{value}</p>
        {sub && <p className="text-[11px] mt-1" style={{ color: V.steelDim }}>{sub}</p>}
      </div>
    </Card>
  );
}

/* ── Pages ── */

function OverviewPage({ services, stats, verdicts, template, mempool, onNavigate }: {
  services: ServiceHealth[];
  stats: VerdictStats;
  verdicts: Verdict[];
  template: LatestTemplate;
  mempool: MempoolStats;
  onNavigate: (page: Page) => void;
}) {
  const rate = calcAcceptRate(stats);
  const { miners } = useMiners();
  const totalHash = miners.reduce((a, m) => a + m.hashrate_th, 0);
  return (
    <div className="space-y-6">
      {/* Metrics row */}
      <div className="grid grid-cols-5 gap-4">
        <MetricCard label="Acceptance" value={`${rate.toFixed(1)}%`} sub={`${stats.accepted.toLocaleString()} / ${stats.total.toLocaleString()}`} accent />
        <MetricCard label="Rejections" value={stats.rejected.toLocaleString()} sub={`${Object.keys(stats.by_reason).length} reason codes`} />
        <MetricCard label="Block Height" value={template.block_height.toLocaleString()} sub={`${template.tx_count.toLocaleString()} txns`} />
        <MetricCard label="Hashrate" value={fmtHashrate(totalHash)} sub={`${miners.length} workers`} />
        <MetricCard label="Mempool" value={mempool.tx_count.toLocaleString()} sub={`${(mempool.usage / mempool.max * 100).toFixed(0)}% capacity`} />
      </div>

      {/* Service health */}
      <div>
        <p className="text-xs font-medium mb-3" style={{ color: V.steel }}>Service Health</p>
        <div className="grid grid-cols-5 gap-3">
          {services.map((s) => (
            <Card key={s.name} hover>
              <div className="p-3 flex items-center gap-3">
                <StatusDot status={s.status} />
                <div className="min-w-0">
                  <p className="text-xs truncate" style={{ fontFamily: "var(--mono)", color: V.ink }}>{s.name}</p>
                  <p className="text-[10px]" style={{ color: V.steelDim }}>{s.latency_ms}ms</p>
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>

      <GlowLine />

      <div className="grid grid-cols-3 gap-5">
        {/* Recent verdicts */}
        <Card className="col-span-2">
          <div className="p-4 pb-2 flex items-center justify-between">
            <p className="text-sm font-medium" style={{ color: V.ink }}>Recent Verdicts</p>
            <span className="text-[10px] cursor-pointer hover:underline" style={{ color: V.amberLight }} onClick={() => onNavigate("verdicts")}>View all</span>
          </div>
          <div className="px-4 pb-3 space-y-0.5">
            {verdicts.slice(0, 8).map((v) => (
              <div key={v.log_id} className="flex items-center gap-3 py-1.5 px-2 rounded-lg text-xs transition-colors hover:bg-white/[.04]" style={{ cursor: "pointer" }}>
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: v.accepted ? V.success : V.error }} />
                <span className="w-12 shrink-0" style={{ fontFamily: "var(--mono)", color: V.steelDim }}>#{v.log_id}</span>
                <span className="w-20 shrink-0" style={{ color: V.ink }}>{v.height.toLocaleString()}</span>
                <span className="flex-1 truncate" style={{ fontFamily: "var(--mono)", color: V.steelDim }}>{v.reason_code ?? "accepted"}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded shrink-0" style={{
                  fontFamily: "var(--mono)",
                  color: v.fee_tier === "high" ? V.success : v.fee_tier === "mid" ? V.amberLight : V.warning,
                  background: v.fee_tier === "high" ? "rgba(34,197,94,.08)" : v.fee_tier === "mid" ? "rgba(212,148,60,.08)" : "rgba(245,158,11,.08)",
                  border: `1px solid ${v.fee_tier === "high" ? "rgba(34,197,94,.2)" : v.fee_tier === "mid" ? "rgba(212,148,60,.2)" : "rgba(245,158,11,.2)"}`,
                }}>{v.fee_tier}</span>
                <span className="w-16 text-right shrink-0" style={{ color: V.steelDim }}>{timeAgo(v.timestamp)}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Right column */}
        <div className="space-y-4">
          <Card>
            <div className="p-4 pb-2">
              <p className="text-sm font-medium" style={{ color: V.ink }}>Rejection Reasons</p>
            </div>
            <div className="px-4 pb-4 space-y-3">
              {Object.entries(stats.by_reason).map(([code, count]) => {
                const pct = stats.rejected > 0 ? (count / stats.rejected) * 100 : 0;
                return (
                  <div key={code}>
                    <div className="flex justify-between text-xs mb-1">
                      <span style={{ fontFamily: "var(--mono)", color: V.steel }}>{code}</span>
                      <span style={{ color: V.steelDim }}>{pct.toFixed(0)}%</span>
                    </div>
                    <div className="h-1 rounded-full overflow-hidden" style={{ background: V.panelLight }}>
                      <div className="h-full rounded-full" style={{
                        width: `${pct}%`,
                        background: `linear-gradient(90deg, ${V.amber}, ${V.amberLight})`,
                      }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>

          <Card>
            <div className="p-4 pb-2">
              <p className="text-sm font-medium" style={{ color: V.ink }}>Mempool</p>
            </div>
            <div className="px-4 pb-4 space-y-2">
              <div className="flex justify-between text-xs">
                <span style={{ color: V.steelDim }}>{mempool.tx_count.toLocaleString()} tx</span>
                <span style={{ fontFamily: "var(--mono)", color: V.ink }}>{mempool.max > 0 ? (mempool.usage / mempool.max * 100).toFixed(0) : "0"}%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: V.panelLight }}>
                <div className="h-full rounded-full" style={{
                  width: `${mempool.max > 0 ? (mempool.usage / mempool.max) * 100 : 0}%`,
                  background: `linear-gradient(90deg, ${V.amberDim}, ${V.amber})`,
                }} />
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function VerdictsPage({ verdicts, caps }: { verdicts: Verdict[]; caps: ModeCapabilities }) {
  const [filter, setFilter] = useState("");
  const filtered = filter
    ? verdicts.filter(v => (v.reason_code ?? "").includes(filter))
    : verdicts;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium" style={{ color: V.ink }}>Verdicts</h2>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: V.steelDim }} />
            <input
              placeholder="Filter by reason_code..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="h-8 text-xs pl-8 w-64 rounded-lg outline-none transition-colors"
              style={{ background: V.panel, border: `1px solid ${V.borderMd}`, color: V.ink, fontFamily: "var(--mono)" }}
            />
          </div>
          {caps.canExportCsv && (
            <a href="/api/verifier/verdicts.csv" download>
              <Btn variant="outline" className="gap-1.5"><Download className="w-3 h-3" /> CSV</Btn>
            </a>
          )}
        </div>
      </div>

      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: `1px solid ${V.borderMd}` }}>
                {["ID", "Height", "Verdict", "Reason Code", "Tier", "Total Fees", "Avg Fee", "Txns", "Weight", "Age"].map((h, i) => (
                  <th key={h} className={`text-[10px] font-medium uppercase tracking-wider py-2.5 px-3 text-left ${i >= 5 ? "text-right" : ""}`}
                    style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((v) => (
                <tr key={v.log_id}
                  className="transition-colors cursor-pointer hover:bg-white/[.03]"
                  style={{ borderBottom: `1px solid ${V.border}` }}>
                  <td className="py-2 px-3" style={{ fontFamily: "var(--mono)", color: V.steelDim }}>{v.log_id}</td>
                  <td className="py-2 px-3" style={{ color: V.ink }}>{v.height.toLocaleString()}</td>
                  <td className="py-2 px-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{
                      fontFamily: "var(--mono)",
                      color: v.accepted ? V.success : V.error,
                      background: v.accepted ? "rgba(34,197,94,.08)" : "rgba(239,68,68,.08)",
                      border: `1px solid ${v.accepted ? "rgba(34,197,94,.2)" : "rgba(239,68,68,.2)"}`,
                    }}>{v.accepted ? "ACCEPT" : "REJECT"}</span>
                  </td>
                  <td className="py-2 px-3" style={{ fontFamily: "var(--mono)", color: V.steelDim }}>{v.reason_code ?? "\u2014"}</td>
                  <td className="py-2 px-3">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{
                      fontFamily: "var(--mono)",
                      color: v.fee_tier === "high" ? V.success : v.fee_tier === "mid" ? V.amberLight : V.warning,
                      background: v.fee_tier === "high" ? "rgba(34,197,94,.08)" : v.fee_tier === "mid" ? "rgba(212,148,60,.08)" : "rgba(245,158,11,.08)",
                      border: `1px solid ${v.fee_tier === "high" ? "rgba(34,197,94,.2)" : v.fee_tier === "mid" ? "rgba(212,148,60,.2)" : "rgba(245,158,11,.2)"}`,
                    }}>{v.fee_tier}</span>
                  </td>
                  <td className="py-2 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.steel }}>{formatSats(v.total_fees)}</td>
                  <td className="py-2 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.steel }}>{v.avg_fee_sats_per_tx.toLocaleString()}</td>
                  <td className="py-2 px-3 text-right" style={{ color: V.steel }}>{v.tx_count.toLocaleString()}</td>
                  <td className="py-2 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.steel }}>{v.template_weight ? `${(v.template_weight / 4_000_000 * 100).toFixed(1)}%` : "\u2014"}</td>
                  <td className="py-2 px-3 text-right" style={{ color: V.steelDim }}>{timeAgo(v.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function PolicyPage({ policy, verdicts, mempool, live, caps }: {
  policy: PolicyConfig; verdicts: Verdict[]; mempool: MempoolStats; live: boolean; caps: ModeCapabilities;
}) {
  const [local, setLocal] = useState(policy);
  const [applying, setApplying] = useState(false);
  const [applyResult, setApplyResult] = useState<string | null>(null);
  const [userEdited, setUserEdited] = useState(false);
  const prevPolicyRef = useRef(policy);

  /* Re-sync local state from server when policy changes and user has not edited */
  useEffect(() => {
    if (prevPolicyRef.current !== policy) {
      if (!userEdited) setLocal(policy);
      prevPolicyRef.current = policy;
    }
  }, [policy, userEdited]);

  const setLocalEdited = (next: PolicyConfig) => {
    setUserEdited(true);
    setLocal(next);
  };

  const currentRejects = verdicts.filter(v => !v.accepted).length;
  const wouldReject = verdicts.filter(v => {
    if (v.avg_fee_sats_per_tx < local.min_avg_fee_lo && v.fee_tier === "low") return true;
    if (v.avg_fee_sats_per_tx < local.min_avg_fee_mid && v.fee_tier === "mid") return true;
    if (v.avg_fee_sats_per_tx < local.min_avg_fee_hi && v.fee_tier === "high") return true;
    return false;
  }).length;
  const delta = wouldReject - currentRejects;

  const handleApply = async () => {
    setApplying(true);
    setApplyResult(null);
    /* Send only fields that differ from the live server state */
    const patch: Record<string, number | boolean> = {};
    const diffKeys: (keyof PolicyConfig)[] = [
      "low_mempool_tx", "high_mempool_tx",
      "min_avg_fee_lo", "min_avg_fee_mid", "min_avg_fee_hi",
      "min_total_fees", "max_tx_count",
      "reject_empty_templates", "reject_coinbase_zero",
      "enforce_weight_ratio", "enforce_template_age",
      "max_weight_ratio", "max_template_age_ms",
      "warn_sigops_ratio", "warn_coinbase_sigops_max",
    ];
    for (const k of diffKeys) {
      if (local[k] !== policy[k]) {
        patch[k] = local[k] as number | boolean;
      }
    }
    const result = await applyPolicy(patch);
    setApplying(false);
    const msg = result.ok ? "Policy applied." : (result.error ?? "Unknown error");
    setApplyResult(msg);
    if (result.ok) {
      setUserEdited(false);
      setTimeout(() => setApplyResult(null), 4000);
    }
  };

  const inputStyle: React.CSSProperties = {
    background: V.navyMid, border: `1px solid ${V.borderMd}`, color: V.ink,
    fontFamily: "var(--mono)", height: 32, fontSize: 12,
    borderRadius: 8, padding: "0 10px", outline: "none", width: "100%",
  };

  const mempoolTier = mempool.tx_count >= local.high_mempool_tx
    ? "high" : mempool.tx_count >= local.low_mempool_tx ? "mid" : "low";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium" style={{ color: V.ink }}>Policy Rules</h2>
        <div className="flex items-center gap-2">
          {applyResult && (
            <span className="text-[10px] px-2 py-1 rounded" style={{
              color: applyResult === "Policy applied." ? V.success : V.error,
              background: applyResult === "Policy applied." ? "rgba(34,197,94,.08)" : "rgba(239,68,68,.08)",
            }}>{applyResult}</span>
          )}
          <Btn variant="glow" onClick={handleApply} disabled={applying || !live || !userEdited || !caps.canEditPolicy}>
            {applying ? "Applying..." : "Apply Changes"}
          </Btn>
        </div>
      </div>

      {/* Dry run preview (hidden in shadow mode) */}
      {caps.canDryRun && delta !== 0 && (
        <div className="flex items-center gap-3 p-3 rounded-xl" style={{
          background: delta > 0 ? "rgba(245,158,11,.06)" : "rgba(34,197,94,.06)",
          border: `1px solid ${delta > 0 ? "rgba(245,158,11,.15)" : "rgba(34,197,94,.15)"}`,
        }}>
          <Eye className="w-4 h-4 shrink-0" style={{ color: V.amberLight }} />
          <p className="text-xs">
            <span className="font-medium" style={{ color: V.ink }}>Dry run: </span>
            <span style={{ color: V.steel }}>
              {Math.abs(delta)} {delta > 0 ? "more" : "fewer"} of the last {verdicts.length} verdicts would have been rejected.
            </span>
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-5">
        {/* Fee thresholds */}
        <Card>
          <div className="p-4 pb-3">
            <p className="text-sm font-medium" style={{ color: V.ink }}>Fee Thresholds</p>
          </div>
          <div className="px-4 pb-4 space-y-4">
            {([
              { key: "min_avg_fee_lo" as const, label: "Min avg fee (low tier)", unit: "sat/tx" },
              { key: "min_avg_fee_mid" as const, label: "Min avg fee (mid tier)", unit: "sat/tx" },
              { key: "min_avg_fee_hi" as const, label: "Min avg fee (high tier)", unit: "sat/tx" },
              { key: "min_total_fees" as const, label: "Min total fees", unit: "sat" },
            ]).map(({ key, label, unit }) => (
              <div key={key} className="space-y-1.5">
                <label className="text-xs" style={{ color: V.steel }}>{label}</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    value={local[key]}
                    onChange={(e) => setLocalEdited({ ...local, [key]: Number(e.target.value) })}
                    disabled={!caps.canEditPolicy}
                    style={{ ...inputStyle, opacity: caps.canEditPolicy ? 1 : 0.5 }}
                  />
                  <span className="text-[10px] shrink-0" style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>{unit}</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Enforcement */}
        <Card>
          <div className="p-4 pb-3">
            <p className="text-sm font-medium" style={{ color: V.ink }}>Enforcement Rules</p>
          </div>
          <div className="px-4 pb-4 space-y-5">
            {([
              { key: "reject_empty_templates" as const, label: "Reject empty templates", desc: "Reject templates with zero transactions" },
              { key: "reject_coinbase_zero" as const, label: "Reject zero coinbase", desc: "Reject templates where coinbase value is zero" },
              { key: "enforce_weight_ratio" as const, label: "Weight ratio enforcement", desc: `Reject templates exceeding ${(local.max_weight_ratio * 100).toFixed(0)}% weight ratio` },
              { key: "enforce_template_age" as const, label: "Template age enforcement", desc: `Reject templates older than ${local.max_template_age_ms}ms` },
            ]).map(({ key, label, desc }) => (
              <div key={key}>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs" style={{ color: V.ink }}>{label}</p>
                    <p className="text-[10px] mt-0.5" style={{ color: V.steelDim }}>{desc}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] px-1.5 py-0.5 rounded" style={{
                      fontFamily: "var(--mono)",
                      color: local[key] ? V.error : V.steelDim,
                      background: local[key] ? "rgba(239,68,68,.08)" : "rgba(226,232,240,.04)",
                      border: `1px solid ${local[key] ? "rgba(239,68,68,.2)" : V.border}`,
                    }}>{local[key] ? "ENFORCE" : "OBSERVE"}</span>
                    <Toggle checked={local[key]} onCheckedChange={(val) => setLocalEdited({ ...local, [key]: val })} disabled={!caps.canEditPolicy} />
                  </div>
                </div>
                <div className="h-px mt-4" style={{ background: V.border }} />
              </div>
            ))}

            <div className="space-y-4 pt-1">
              {([
                { key: "max_weight_ratio" as const, label: "Max weight ratio", step: "0.01" },
                { key: "max_template_age_ms" as const, label: "Max template age (ms)", step: "1000" },
                { key: "warn_sigops_ratio" as const, label: "Sigops warning ratio", step: "0.05" },
              ]).map(({ key, label, step }) => (
                <div key={key} className="space-y-1.5">
                  <label className="text-xs" style={{ color: V.steel }}>{label}</label>
                  <input
                    type="number"
                    step={step}
                    value={local[key]}
                    onChange={(e) => setLocalEdited({ ...local, [key]: Number(e.target.value) })}
                    disabled={!caps.canEditPolicy}
                    style={{ ...inputStyle, opacity: caps.canEditPolicy ? 1 : 0.5 }}
                  />
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Tier boundaries */}
      <Card>
        <div className="p-4 pb-3">
          <p className="text-sm font-medium" style={{ color: V.ink }}>Mempool Tier Boundaries</p>
        </div>
        <div className="px-4 pb-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-xs" style={{ color: V.steel }}>Low/Mid boundary (tx count)</label>
              <input type="number" value={local.low_mempool_tx}
                onChange={e => setLocalEdited({ ...local, low_mempool_tx: Number(e.target.value) })}
                disabled={!caps.canEditPolicy}
                style={{ ...inputStyle, opacity: caps.canEditPolicy ? 1 : 0.5 }} />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs" style={{ color: V.steel }}>Mid/High boundary (tx count)</label>
              <input type="number" value={local.high_mempool_tx}
                onChange={e => setLocalEdited({ ...local, high_mempool_tx: Number(e.target.value) })}
                disabled={!caps.canEditPolicy}
                style={{ ...inputStyle, opacity: caps.canEditPolicy ? 1 : 0.5 }} />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 text-[10px]" style={{ color: V.steelDim }}>
            <Activity className="w-3 h-3" />
            Current mempool: {mempool.tx_count.toLocaleString()} tx (tier: <span style={{ color: V.amberLight, fontFamily: "var(--mono)" }}>{mempoolTier}</span>)
          </div>
        </div>
      </Card>
    </div>
  );
}

function TemplatesPage({ template, mempool }: {
  template: LatestTemplate; mempool: MempoolStats;
}) {
  return (
    <div className="space-y-5">
      <h2 className="text-lg font-medium" style={{ color: V.ink }}>Templates</h2>
      <Card>
        <div className="p-4 pb-2">
          <p className="text-sm font-medium" style={{ color: V.ink }}>Latest Template</p>
        </div>
        <div className="px-4 pb-4">
          <div className="grid grid-cols-4 gap-4">
            {([
              ["Block Height", template.block_height.toLocaleString()],
              ["Total Fees", formatSats(template.total_fees)],
              ["Coinbase Value", formatSats(template.coinbase_value)],
              ["Transactions", template.tx_count.toLocaleString()],
              ["Weight", template.template_weight ? `${(template.template_weight / 4_000_000 * 100).toFixed(1)}%` : "\u2014"],
              ["Total Sigops", template.total_sigops?.toLocaleString() ?? "\u2014"],
              ["Coinbase Sigops", template.coinbase_sigops?.toString() ?? "\u2014"],
              ["Source", template.source_instance_id],
            ] as const).map(([k, v]) => (
              <div key={k} className="space-y-1">
                <p className="text-[10px] uppercase tracking-wider" style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>{k}</p>
                <p className="text-sm font-semibold" style={{ fontFamily: "var(--mono)", color: V.ink }}>{v}</p>
              </div>
            ))}
          </div>
          <GlowLine />
          <div className="mt-3 grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <p className="text-[10px] uppercase tracking-wider" style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>Prev Hash</p>
              <p className="text-xs break-all" style={{ fontFamily: "var(--mono)", color: V.steel }}>{template.prev_hash}</p>
            </div>
            <div className="space-y-1">
              <p className="text-[10px] uppercase tracking-wider" style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>Merkle Path</p>
              <p className="text-xs" style={{ fontFamily: "var(--mono)", color: V.steel }}>{template.merkle_path.length} branches</p>
            </div>
          </div>
        </div>
      </Card>

      <Card>
        <div className="p-4 pb-2">
          <p className="text-sm font-medium" style={{ color: V.ink }}>Mempool Status</p>
        </div>
        <div className="px-4 pb-4 space-y-3">
          <div className="flex justify-between text-xs">
            <span style={{ color: V.steelDim }}>{mempool.tx_count.toLocaleString()} transactions</span>
            <span style={{ fontFamily: "var(--mono)", color: V.ink }}>{mempool.max > 0 ? (mempool.usage / mempool.max * 100).toFixed(0) : "0"}%</span>
          </div>
          <div className="h-2 rounded-full overflow-hidden" style={{ background: V.panelLight }}>
            <div className="h-full rounded-full" style={{
              width: `${mempool.max > 0 ? (mempool.usage / mempool.max) * 100 : 0}%`,
              background: `linear-gradient(90deg, ${V.amberDim}, ${V.amber}, ${V.amberLight})`,
              boxShadow: `0 0 12px ${V.amberGlowSm}`,
            }} />
          </div>
          <div className="grid grid-cols-4 gap-4 text-xs">
            {([
              ["Transactions", mempool.tx_count.toLocaleString()],
              ["Size", `${(mempool.bytes / 1_000_000).toFixed(0)} MB`],
              ["Min Relay Fee", `${mempool.min_relay_fee} sat/kB`],
              ["Source", mempool.loaded_from],
            ] as const).map(([k, v]) => (
              <div key={k}>
                <p className="text-[10px]" style={{ color: V.steelDim }}>{k}</p>
                <p style={{ fontFamily: "var(--mono)", color: V.ink }}>{v}</p>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

function MinersPage() {
  const { miners } = useMiners();
  const totalHash = miners.reduce((a, m) => a + m.hashrate_th, 0);
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium" style={{ color: V.ink }}>Connected Miners</h2>
        <span className="text-xs px-2.5 py-1 rounded-lg" style={{
          fontFamily: "var(--mono)", color: V.steel,
          background: "rgba(226,232,240,.04)", border: `1px solid ${V.border}`,
        }}>{miners.length} workers · {fmtHashrate(totalHash)}</span>
      </div>
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr style={{ borderBottom: `1px solid ${V.borderMd}` }}>
                {["Worker", "Channel", "TH/s", "Shares", "Accept %", "Connected", "Last Share"].map((h, i) => (
                  <th key={h} className={`text-[10px] font-medium uppercase tracking-wider py-2.5 px-3 ${i >= 1 ? "text-right" : "text-left"}`}
                    style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {miners.map((m) => (
                <tr key={m.channel_id} className="transition-colors hover:bg-white/[.03]"
                  style={{ borderBottom: `1px solid ${V.border}` }}>
                  <td className="py-2.5 px-3" style={{ fontFamily: "var(--mono)", color: V.ink }}>{m.worker_name}</td>
                  <td className="py-2.5 px-3 text-right" style={{ color: V.steelDim }}>{m.channel_id}</td>
                  <td className="py-2.5 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.ink }}>{fmtHashrate(m.hashrate_th)}</td>
                  <td className="py-2.5 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.steel }}>{m.shares_submitted.toLocaleString()}</td>
                  <td className="py-2.5 px-3 text-right" style={{ fontFamily: "var(--mono)", color: V.success }}>{((m.shares_accepted / m.shares_submitted) * 100).toFixed(2)}%</td>
                  <td className="py-2.5 px-3 text-right" style={{ color: V.steelDim }}>{timeAgo(m.connected_at)}</td>
                  <td className="py-2.5 px-3 text-right" style={{ color: V.steelDim }}>{timeAgo(m.last_share_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

/* ── Settings sub-components ── */

function RestartBadge() {
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded" style={{
      color: V.warning, background: "rgba(245,158,11,.1)",
      border: "1px solid rgba(245,158,11,.2)",
    }}>
      restart required
    </span>
  );
}

function SecretIndicator({ configured }: { configured: boolean }) {
  return configured ? (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: V.success }}>
      <Lock className="w-3 h-3" /> configured
    </span>
  ) : (
    <span className="flex items-center gap-1 text-[10px]" style={{ color: V.steelDim }}>
      <Unlock className="w-3 h-3" /> not set
    </span>
  );
}

function SettingsRow({ label, children, readOnly = false }: {
  label: string; children: React.ReactNode; readOnly?: boolean;
}) {
  return (
    <div className="flex items-center gap-3 py-2">
      <label className="text-[11px] w-52 shrink-0" style={{ color: readOnly ? V.steelDim : V.steel, fontFamily: "var(--mono)" }}>
        {label}
      </label>
      <div className="flex-1">{children}</div>
    </div>
  );
}

function SettingsInput({ value, onChange, disabled = false, mono = true }: {
  value: string; onChange?: (v: string) => void; disabled?: boolean; mono?: boolean;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={onChange ? (e) => onChange(e.target.value) : undefined}
      readOnly={!onChange || disabled}
      disabled={disabled}
      className="w-full"
      style={{
        background: disabled ? V.navy : V.navyMid,
        border: `1px solid ${V.borderMd}`,
        color: disabled ? V.steelDim : V.ink,
        fontFamily: mono ? "var(--mono)" : "var(--sans)",
        height: 32, fontSize: 12, borderRadius: 8, padding: "0 10px", outline: "none",
      }}
    />
  );
}

function SettingsSelect({ value, options, onChange, disabled = false }: {
  value: string; options: string[]; onChange?: (v: string) => void; disabled?: boolean;
}) {
  return (
    <select
      value={value}
      onChange={onChange ? (e) => onChange(e.target.value) : undefined}
      disabled={disabled}
      style={{
        background: disabled ? V.navy : V.navyMid,
        border: `1px solid ${V.borderMd}`,
        color: disabled ? V.steelDim : V.ink,
        fontFamily: "var(--mono)",
        height: 32, fontSize: 12, borderRadius: 8, padding: "0 10px", outline: "none",
        width: "100%", cursor: disabled ? "not-allowed" : "pointer",
      }}
    >
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function SettingsPage({ caps }: { caps: ModeCapabilities }) {
  const { settings: vs, live: vsLive } = useVerifierSettings();
  const { settings: gs, live: gsLive } = useGatewaySettings();
  const { settings: tmpl, live: tmplLive } = useTemplateSettings();
  const { settings: as_, live: asLive } = useAuthSettings();
  const { settings: ds, live: dsLive } = useDashboardSettings();

  /* ── Pool Verifier editable state ── */
  const [editVsLogLevel, setEditVsLogLevel] = useState(vs.log_level);
  const [editVsLogFormat, setEditVsLogFormat] = useState(vs.log_format);
  const [editVsMempool, setEditVsMempool] = useState(vs.mempool_url);
  const [vsSaveResult, setVsSaveResult] = useState<string | null>(null);

  const vsHasEdits = editVsLogLevel !== vs.log_level || editVsLogFormat !== vs.log_format || editVsMempool !== vs.mempool_url;

  const prevVsLogLevelRef = useRef(vs.log_level);
  const prevVsLogFormatRef = useRef(vs.log_format);
  const prevVsMempoolRef = useRef(vs.mempool_url);
  useEffect(() => {
    if (vs.log_level !== prevVsLogLevelRef.current) {
      if (editVsLogLevel === prevVsLogLevelRef.current) setEditVsLogLevel(vs.log_level);
      prevVsLogLevelRef.current = vs.log_level;
    }
    if (vs.log_format !== prevVsLogFormatRef.current) {
      if (editVsLogFormat === prevVsLogFormatRef.current) setEditVsLogFormat(vs.log_format);
      prevVsLogFormatRef.current = vs.log_format;
    }
    if (vs.mempool_url !== prevVsMempoolRef.current) {
      if (editVsMempool === prevVsMempoolRef.current) setEditVsMempool(vs.mempool_url);
      prevVsMempoolRef.current = vs.mempool_url;
    }
  }, [vs.log_level, vs.log_format, vs.mempool_url, editVsLogLevel, editVsLogFormat, editVsMempool]);

  const handleSaveVerifierSettings = async () => {
    const patch: Record<string, unknown> = {};
    if (editVsLogLevel !== vs.log_level) patch.log_level = editVsLogLevel;
    if (editVsLogFormat !== vs.log_format) patch.log_format = editVsLogFormat;
    if (editVsMempool !== vs.mempool_url) patch.mempool_url = editVsMempool;
    const result = await saveVerifierSettings(patch);
    const msg = result.ok ? "Settings saved." : (result.error ?? "Unknown error");
    setVsSaveResult(msg);
    if (result.ok) setTimeout(() => setVsSaveResult(null), 4000);
  };

  /* ── SV2 Gateway editable state ── */
  const [editGsMaxConnections, setEditGsMaxConnections] = useState(String(gs.max_connections));
  const [editGsMaxChannelsPerConn, setEditGsMaxChannelsPerConn] = useState(String(gs.max_channels_per_conn));
  const [editGsMaxWorkerIdBytes, setEditGsMaxWorkerIdBytes] = useState(String(gs.max_worker_id_bytes));
  const [editGsTemplatePollMs, setEditGsTemplatePollMs] = useState(String(gs.template_poll_interval_ms));
  const [editGsMaxTemplateAgeMs, setEditGsMaxTemplateAgeMs] = useState(String(gs.max_template_age_ms));
  const [editGsPrevhashVerdictMs, setEditGsPrevhashVerdictMs] = useState(String(gs.prevhash_verdict_timeout_ms));
  const [editGsPrevhashStaleHoldMs, setEditGsPrevhashStaleHoldMs] = useState(String(gs.prevhash_stale_hold_ms));
  const [editGsUpstreamStaleMaxMs, setEditGsUpstreamStaleMaxMs] = useState(String(gs.upstream_stale_max_ms));
  const [editGsUpstreamFailurePolicy, setEditGsUpstreamFailurePolicy] = useState(gs.upstream_failure_policy);
  const [editGsShareDedupWindow, setEditGsShareDedupWindow] = useState(String(gs.share_dedup_window_size));
  const [editGsNtimeSlackSecs, setEditGsNtimeSlackSecs] = useState(String(gs.ntime_elapsed_slack_seconds));
  const [editGsMaxFutureBlockSecs, setEditGsMaxFutureBlockSecs] = useState(String(gs.max_future_block_time_seconds));
  const [editGsJobRetentionMs, setEditGsJobRetentionMs] = useState(String(gs.job_retention_ms));
  const [editGsChannelTargetHex, setEditGsChannelTargetHex] = useState(gs.channel_target_hex || "");
  const [editGsMaxSharesPerSec, setEditGsMaxSharesPerSec] = useState(String(gs.max_shares_per_second_per_channel));
  const [editGsNoiseCertValiditySecs, setEditGsNoiseCertValiditySecs] = useState(String(gs.noise_cert_validity_secs));
  const [editGsNoiseHandshakeMs, setEditGsNoiseHandshakeMs] = useState(String(gs.noise_handshake_timeout_ms));
  const [editGsNoiseKeypairReloadSighup, setEditGsNoiseKeypairReloadSighup] = useState(gs.noise_keypair_reload_sighup);
  const [editGsNoiseKeypairPollSecs, setEditGsNoiseKeypairPollSecs] = useState(String(gs.noise_keypair_poll_interval_secs));
  const [editGsWalCompactionThreshold, setEditGsWalCompactionThreshold] = useState(String(gs.wal_compaction_threshold));
  const [gsSaveResult, setGsSaveResult] = useState<string | null>(null);

  const gsHasEdits = editGsMaxConnections !== String(gs.max_connections)
    || editGsMaxChannelsPerConn !== String(gs.max_channels_per_conn)
    || editGsMaxWorkerIdBytes !== String(gs.max_worker_id_bytes)
    || editGsTemplatePollMs !== String(gs.template_poll_interval_ms)
    || editGsMaxTemplateAgeMs !== String(gs.max_template_age_ms)
    || editGsPrevhashVerdictMs !== String(gs.prevhash_verdict_timeout_ms)
    || editGsPrevhashStaleHoldMs !== String(gs.prevhash_stale_hold_ms)
    || editGsUpstreamStaleMaxMs !== String(gs.upstream_stale_max_ms)
    || editGsUpstreamFailurePolicy !== gs.upstream_failure_policy
    || editGsShareDedupWindow !== String(gs.share_dedup_window_size)
    || editGsNtimeSlackSecs !== String(gs.ntime_elapsed_slack_seconds)
    || editGsMaxFutureBlockSecs !== String(gs.max_future_block_time_seconds)
    || editGsJobRetentionMs !== String(gs.job_retention_ms)
    || editGsChannelTargetHex !== (gs.channel_target_hex || "")
    || editGsMaxSharesPerSec !== String(gs.max_shares_per_second_per_channel)
    || editGsNoiseCertValiditySecs !== String(gs.noise_cert_validity_secs)
    || editGsNoiseHandshakeMs !== String(gs.noise_handshake_timeout_ms)
    || editGsNoiseKeypairReloadSighup !== gs.noise_keypair_reload_sighup
    || editGsNoiseKeypairPollSecs !== String(gs.noise_keypair_poll_interval_secs)
    || editGsWalCompactionThreshold !== String(gs.wal_compaction_threshold);

  const prevGsRef = useRef({ max_connections: gs.max_connections, max_channels_per_conn: gs.max_channels_per_conn });
  useEffect(() => {
    if (gs.max_connections !== prevGsRef.current.max_connections && editGsMaxConnections === String(prevGsRef.current.max_connections)) {
      setEditGsMaxConnections(String(gs.max_connections));
    }
    if (gs.max_channels_per_conn !== prevGsRef.current.max_channels_per_conn && editGsMaxChannelsPerConn === String(prevGsRef.current.max_channels_per_conn)) {
      setEditGsMaxChannelsPerConn(String(gs.max_channels_per_conn));
    }
    prevGsRef.current = { max_connections: gs.max_connections, max_channels_per_conn: gs.max_channels_per_conn };
  }, [gs.max_connections, gs.max_channels_per_conn, editGsMaxConnections, editGsMaxChannelsPerConn]);

  const handleSaveGatewaySettings = async () => {
    const patch: Record<string, unknown> = {};
    if (editGsMaxConnections !== String(gs.max_connections)) patch.max_connections = parseInt(editGsMaxConnections, 10);
    if (editGsMaxChannelsPerConn !== String(gs.max_channels_per_conn)) patch.max_channels_per_conn = parseInt(editGsMaxChannelsPerConn, 10);
    if (editGsMaxWorkerIdBytes !== String(gs.max_worker_id_bytes)) patch.max_worker_id_bytes = parseInt(editGsMaxWorkerIdBytes, 10);
    if (editGsTemplatePollMs !== String(gs.template_poll_interval_ms)) patch.template_poll_interval_ms = parseInt(editGsTemplatePollMs, 10);
    if (editGsMaxTemplateAgeMs !== String(gs.max_template_age_ms)) patch.max_template_age_ms = parseInt(editGsMaxTemplateAgeMs, 10);
    if (editGsPrevhashVerdictMs !== String(gs.prevhash_verdict_timeout_ms)) patch.prevhash_verdict_timeout_ms = parseInt(editGsPrevhashVerdictMs, 10);
    if (editGsPrevhashStaleHoldMs !== String(gs.prevhash_stale_hold_ms)) patch.prevhash_stale_hold_ms = parseInt(editGsPrevhashStaleHoldMs, 10);
    if (editGsUpstreamStaleMaxMs !== String(gs.upstream_stale_max_ms)) patch.upstream_stale_max_ms = parseInt(editGsUpstreamStaleMaxMs, 10);
    if (editGsUpstreamFailurePolicy !== gs.upstream_failure_policy) patch.upstream_failure_policy = editGsUpstreamFailurePolicy;
    if (editGsShareDedupWindow !== String(gs.share_dedup_window_size)) patch.share_dedup_window_size = parseInt(editGsShareDedupWindow, 10);
    if (editGsNtimeSlackSecs !== String(gs.ntime_elapsed_slack_seconds)) patch.ntime_elapsed_slack_seconds = parseInt(editGsNtimeSlackSecs, 10);
    if (editGsMaxFutureBlockSecs !== String(gs.max_future_block_time_seconds)) patch.max_future_block_time_seconds = parseInt(editGsMaxFutureBlockSecs, 10);
    if (editGsJobRetentionMs !== String(gs.job_retention_ms)) patch.job_retention_ms = parseInt(editGsJobRetentionMs, 10);
    if (editGsChannelTargetHex !== (gs.channel_target_hex || "")) patch.channel_target_hex = editGsChannelTargetHex || null;
    if (editGsMaxSharesPerSec !== String(gs.max_shares_per_second_per_channel)) patch.max_shares_per_second_per_channel = parseInt(editGsMaxSharesPerSec, 10);
    if (editGsNoiseCertValiditySecs !== String(gs.noise_cert_validity_secs)) patch.noise_cert_validity_secs = parseInt(editGsNoiseCertValiditySecs, 10);
    if (editGsNoiseHandshakeMs !== String(gs.noise_handshake_timeout_ms)) patch.noise_handshake_timeout_ms = parseInt(editGsNoiseHandshakeMs, 10);
    if (editGsNoiseKeypairReloadSighup !== gs.noise_keypair_reload_sighup) patch.noise_keypair_reload_sighup = editGsNoiseKeypairReloadSighup;
    if (editGsNoiseKeypairPollSecs !== String(gs.noise_keypair_poll_interval_secs)) patch.noise_keypair_poll_interval_secs = parseInt(editGsNoiseKeypairPollSecs, 10);
    if (editGsWalCompactionThreshold !== String(gs.wal_compaction_threshold)) patch.wal_compaction_threshold = parseInt(editGsWalCompactionThreshold, 10);

    if (Object.keys(patch).length === 0) {
      setGsSaveResult("No changes to save.");
      setTimeout(() => setGsSaveResult(null), 4000);
      return;
    }

    const result = await saveGatewaySettings(patch);
    const msg = result.ok ? "Settings saved." : (result.error ?? "Unknown error");
    setGsSaveResult(msg);
    if (result.ok) setTimeout(() => setGsSaveResult(null), 4000);
  };

  /* ── Template Manager editable state ── */
  const [editTmplBackend, setEditTmplBackend] = useState(tmpl.backend);
  const [editTmplPollIntervalSecs, setEditTmplPollIntervalSecs] = useState(String(tmpl.poll_interval_secs));
  const [editTmplCoinbaseScriptHex, setEditTmplCoinbaseScriptHex] = useState(tmpl.coinbase_output_script_hex);
  const [editTmplExtraNonceSize, setEditTmplExtraNonceSize] = useState(String(tmpl.extranonce_size));
  const [editTmplRpcUrl, setEditTmplRpcUrl] = useState(tmpl.rpc_url);
  const [editTmplRpcUser, setEditTmplRpcUser] = useState(tmpl.rpc_user);
  const [editTmplStratumAddr, setEditTmplStratumAddr] = useState(tmpl.stratum_addr || "");
  const [tmplSaveResult, setTmplSaveResult] = useState<string | null>(null);

  const tmplHasEdits = editTmplBackend !== tmpl.backend
    || editTmplPollIntervalSecs !== String(tmpl.poll_interval_secs)
    || editTmplCoinbaseScriptHex !== tmpl.coinbase_output_script_hex
    || editTmplExtraNonceSize !== String(tmpl.extranonce_size)
    || editTmplRpcUrl !== tmpl.rpc_url
    || editTmplRpcUser !== tmpl.rpc_user
    || editTmplStratumAddr !== (tmpl.stratum_addr || "");

  const prevTmplRef = useRef({ backend: tmpl.backend, poll_interval_secs: tmpl.poll_interval_secs });
  useEffect(() => {
    if (tmpl.backend !== prevTmplRef.current.backend && editTmplBackend === prevTmplRef.current.backend) {
      setEditTmplBackend(tmpl.backend);
    }
    if (tmpl.poll_interval_secs !== prevTmplRef.current.poll_interval_secs && editTmplPollIntervalSecs === String(prevTmplRef.current.poll_interval_secs)) {
      setEditTmplPollIntervalSecs(String(tmpl.poll_interval_secs));
    }
    prevTmplRef.current = { backend: tmpl.backend, poll_interval_secs: tmpl.poll_interval_secs };
  }, [tmpl.backend, tmpl.poll_interval_secs, editTmplBackend, editTmplPollIntervalSecs]);

  const handleSaveTemplateSettings = async () => {
    const patch: Record<string, unknown> = {};
    if (editTmplBackend !== tmpl.backend) patch.backend = editTmplBackend;
    if (editTmplPollIntervalSecs !== String(tmpl.poll_interval_secs)) patch.poll_interval_secs = parseInt(editTmplPollIntervalSecs, 10);
    if (editTmplCoinbaseScriptHex !== tmpl.coinbase_output_script_hex) patch.coinbase_output_script_hex = editTmplCoinbaseScriptHex;
    if (editTmplExtraNonceSize !== String(tmpl.extranonce_size)) patch.extranonce_size = parseInt(editTmplExtraNonceSize, 10);
    if (editTmplRpcUrl !== tmpl.rpc_url) patch.rpc_url = editTmplRpcUrl;
    if (editTmplRpcUser !== tmpl.rpc_user) patch.rpc_user = editTmplRpcUser;
    if (editTmplStratumAddr !== (tmpl.stratum_addr || "")) patch.stratum_addr = editTmplStratumAddr || null;

    if (Object.keys(patch).length === 0) {
      setTmplSaveResult("No changes to save.");
      setTimeout(() => setTmplSaveResult(null), 4000);
      return;
    }

    const result = await saveTemplateSettings(patch);
    const msg = result.ok ? "Settings saved." : (result.error ?? "Unknown error");
    setTmplSaveResult(msg);
    if (result.ok) setTimeout(() => setTmplSaveResult(null), 4000);
  };

  const sectionHeader = (title: string, live: boolean, pendingRestart: boolean) => (
    <div className="flex items-center gap-3 px-5 pt-4 pb-2">
      <h3 className="text-sm font-semibold" style={{ color: V.ink }}>{title}</h3>
      {pendingRestart && <RestartBadge />}
      {live ? (
        <span className="ml-auto flex items-center gap-1 text-[10px]" style={{ color: V.success }}>
          <Wifi className="w-3 h-3" /> live
        </span>
      ) : (
        <span className="ml-auto flex items-center gap-1 text-[10px]" style={{ color: V.warning }}>
          <WifiOff className="w-3 h-3" /> mock
        </span>
      )}
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-medium" style={{ color: V.ink }}>Settings</h2>
        <span className="text-[10px]" style={{ color: V.steelDim }}>
          Changes are saved to disk. Restart service to apply.
        </span>
      </div>

      {/* ── Card 1: Pool Verifier (editable) ── */}
      <Card>
        {sectionHeader("Pool Verifier", vsLive, vs.pending_restart)}
        <div className="px-5 pb-4">
          {vs.pending_restart && (
            <div className="mx-5 mb-2 px-3 py-2 rounded text-[11px]" style={{ background: "#1a1400", color: V.warning, border: `1px solid ${V.warning}33` }}>
              Config saved to disk. Restart this service to apply changes.
            </div>
          )}
          <SettingsRow label="log_level">
            <SettingsSelect
              value={editVsLogLevel}
              options={["trace", "debug", "info", "warn", "error"]}
              onChange={setEditVsLogLevel}
            />
          </SettingsRow>
          <SettingsRow label="log_format">
            <SettingsSelect
              value={editVsLogFormat}
              options={["json", "text", "pretty"]}
              onChange={setEditVsLogFormat}
            />
          </SettingsRow>
          <SettingsRow label="deploy_mode" readOnly>
            <SettingsInput value={vs.deploy_mode} disabled />
          </SettingsRow>
          <SettingsRow label="mempool_url">
            <SettingsInput value={editVsMempool} onChange={setEditVsMempool} />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="tcp_addr" readOnly>
              <SettingsInput value={vs.tcp_addr} disabled />
            </SettingsRow>
            <SettingsRow label="http_addr" readOnly>
              <SettingsInput value={vs.http_addr} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="policy_file" readOnly>
            <SettingsInput value={vs.policy_file} disabled />
          </SettingsRow>
          <SettingsRow label="api_key" readOnly>
            <SecretIndicator configured={vs.api_key_set} />
          </SettingsRow>
          <SettingsRow label="tls_enabled" readOnly>
            <Toggle checked={vs.tls_enabled} onCheckedChange={() => {}} disabled />
          </SettingsRow>
          <SettingsRow label="tls_self_signed" readOnly>
            <Toggle checked={vs.tls_self_signed} onCheckedChange={() => {}} disabled />
          </SettingsRow>
          <SettingsRow label="mtls_client_ca" readOnly>
            <SecretIndicator configured={vs.mtls_client_ca_set} />
          </SettingsRow>
          <div className="flex items-center gap-3 mt-3 pt-3" style={{ borderTop: `1px solid ${V.border}` }}>
            <Btn variant="glow" onClick={handleSaveVerifierSettings} disabled={!vsHasEdits || !caps.canEditSettings}>
              Save
            </Btn>
            {vsSaveResult && (
              <span className="text-[10px]" style={{
                color: vsSaveResult === "Settings saved." ? V.success : V.error,
              }}>
                {vsSaveResult}
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* ── Card 2: SV2 Gateway (editable) ── */}
      <Card>
        {sectionHeader("SV2 Gateway", gsLive, gs.pending_restart)}
        <div className="px-5 pb-4">
          {gs.pending_restart && (
            <div className="mx-5 mb-2 px-3 py-2 rounded text-[11px]" style={{ background: "#1a1400", color: V.warning, border: `1px solid ${V.warning}33` }}>
              Config saved to disk. Restart this service to apply changes.
            </div>
          )}
          <SettingsRow label="gateway_mode" readOnly>
            <SettingsInput value={gs.gateway_mode} disabled />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="listen_addr" readOnly>
              <SettingsInput value={gs.listen_addr} disabled />
            </SettingsRow>
            <SettingsRow label="health_addr" readOnly>
              <SettingsInput value={gs.health_addr} disabled />
            </SettingsRow>
            <SettingsRow label="max_connections">
              <SettingsInput value={editGsMaxConnections} onChange={setEditGsMaxConnections} />
            </SettingsRow>
            <SettingsRow label="max_channels_per_conn">
              <SettingsInput value={editGsMaxChannelsPerConn} onChange={setEditGsMaxChannelsPerConn} />
            </SettingsRow>
            <SettingsRow label="max_worker_id_bytes">
              <SettingsInput value={editGsMaxWorkerIdBytes} onChange={setEditGsMaxWorkerIdBytes} />
            </SettingsRow>
            <SettingsRow label="miner_auth" readOnly>
              <SettingsInput value={gs.miner_auth} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="template_url" readOnly>
            <SettingsInput value={gs.template_url || "(env fallback)"} disabled />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="template_poll_ms">
              <SettingsInput value={editGsTemplatePollMs} onChange={setEditGsTemplatePollMs} />
            </SettingsRow>
            <SettingsRow label="max_template_age_ms">
              <SettingsInput value={editGsMaxTemplateAgeMs} onChange={setEditGsMaxTemplateAgeMs} />
            </SettingsRow>
          </div>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="prevhash_verdict_ms">
              <SettingsInput value={editGsPrevhashVerdictMs} onChange={setEditGsPrevhashVerdictMs} />
            </SettingsRow>
            <SettingsRow label="prevhash_stale_hold_ms">
              <SettingsInput value={editGsPrevhashStaleHoldMs} onChange={setEditGsPrevhashStaleHoldMs} />
            </SettingsRow>
            <SettingsRow label="upstream_stale_max_ms">
              <SettingsInput value={editGsUpstreamStaleMaxMs} onChange={setEditGsUpstreamStaleMaxMs} />
            </SettingsRow>
            <SettingsRow label="upstream_failure">
              <SettingsSelect
                value={editGsUpstreamFailurePolicy}
                options={["fail_closed", "fail_open"]}
                onChange={setEditGsUpstreamFailurePolicy}
              />
            </SettingsRow>
          </div>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="share_dedup_window">
              <SettingsInput value={editGsShareDedupWindow} onChange={setEditGsShareDedupWindow} />
            </SettingsRow>
            <SettingsRow label="shares_rate_limit">
              <SettingsInput value={editGsMaxSharesPerSec} onChange={setEditGsMaxSharesPerSec} />
            </SettingsRow>
            <SettingsRow label="ntime_slack_secs">
              <SettingsInput value={editGsNtimeSlackSecs} onChange={setEditGsNtimeSlackSecs} />
            </SettingsRow>
            <SettingsRow label="max_future_block_s">
              <SettingsInput value={editGsMaxFutureBlockSecs} onChange={setEditGsMaxFutureBlockSecs} />
            </SettingsRow>
            <SettingsRow label="job_retention_ms">
              <SettingsInput value={editGsJobRetentionMs} onChange={setEditGsJobRetentionMs} />
            </SettingsRow>
            <SettingsRow label="channel_target_hex">
              <SettingsInput value={editGsChannelTargetHex} onChange={setEditGsChannelTargetHex} />
            </SettingsRow>
          </div>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="noise_cert_validity">
              <SettingsInput value={editGsNoiseCertValiditySecs} onChange={setEditGsNoiseCertValiditySecs} />
            </SettingsRow>
            <SettingsRow label="noise_handshake_ms">
              <SettingsInput value={editGsNoiseHandshakeMs} onChange={setEditGsNoiseHandshakeMs} />
            </SettingsRow>
          </div>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="noise_sighup_reload">
              <Toggle checked={editGsNoiseKeypairReloadSighup} onCheckedChange={setEditGsNoiseKeypairReloadSighup} />
            </SettingsRow>
            <SettingsRow label="noise_poll_secs">
              <SettingsInput value={editGsNoiseKeypairPollSecs} onChange={setEditGsNoiseKeypairPollSecs} />
            </SettingsRow>
          </div>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="wal_path" readOnly>
              <SettingsInput value={gs.wal_path || "(disabled)"} disabled />
            </SettingsRow>
            <SettingsRow label="wal_compaction">
              <SettingsInput value={editGsWalCompactionThreshold} onChange={setEditGsWalCompactionThreshold} />
            </SettingsRow>
          </div>
          <SettingsRow label="gateway_instance_id" readOnly>
            <SettingsInput value={gs.gateway_instance_id} disabled />
          </SettingsRow>
          <SettingsRow label="verifier_addr" readOnly>
            <SettingsInput value={gs.verifier_addr} disabled />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="verifier_tls" readOnly>
              <Toggle checked={gs.verifier_tls_enabled} onCheckedChange={() => {}} disabled />
            </SettingsRow>
            <SettingsRow label="verifier_tls_sni" readOnly>
              <SettingsInput value={gs.verifier_tls_server_name} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="verifier_staleness_ms" readOnly>
            <SettingsInput value={String(gs.verifier_health_probe_staleness_ms)} disabled />
          </SettingsRow>
          <SettingsRow label="share_upstream_url" readOnly>
            <SettingsInput value={gs.share_upstream_url || "(none)"} disabled />
          </SettingsRow>
          <SettingsRow label="share_upstream_secret" readOnly>
            <SecretIndicator configured={gs.share_upstream_secret_set} />
          </SettingsRow>
          {gs.share_upstream_url && (
            <div className="grid grid-cols-2 gap-x-6">
              <SettingsRow label="upstream_retries" readOnly>
                <SettingsInput value={String(gs.share_upstream_retries)} disabled />
              </SettingsRow>
              <SettingsRow label="upstream_queue_size" readOnly>
                <SettingsInput value={String(gs.share_upstream_queue_size)} disabled />
              </SettingsRow>
              <SettingsRow label="upstream_in_flight" readOnly>
                <SettingsInput value={String(gs.share_upstream_max_in_flight)} disabled />
              </SettingsRow>
              <SettingsRow label="upstream_drop_policy" readOnly>
                <SettingsInput value={gs.share_upstream_drop_policy} disabled />
              </SettingsRow>
              <SettingsRow label="upstream_rate_limit" readOnly>
                <SettingsInput value={gs.share_upstream_rate_limit !== null ? String(gs.share_upstream_rate_limit) : "unlimited"} disabled />
              </SettingsRow>
            </div>
          )}
          <div className="flex items-center gap-3 mt-3 pt-3" style={{ borderTop: `1px solid ${V.border}` }}>
            <Btn variant="glow" onClick={handleSaveGatewaySettings} disabled={!gsHasEdits || !caps.canEditSettings}>
              Save
            </Btn>
            {gsSaveResult && (
              <span className="text-[10px]" style={{
                color: gsSaveResult === "Settings saved." ? V.success : V.error,
              }}>
                {gsSaveResult}
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* ── Card 3: Template Manager (editable) ── */}
      <Card>
        {sectionHeader("Template Manager", tmplLive, tmpl.pending_restart)}
        <div className="px-5 pb-4">
          {tmpl.pending_restart && (
            <div className="mx-5 mb-2 px-3 py-2 rounded text-[11px]" style={{ background: "#1a1400", color: V.warning, border: `1px solid ${V.warning}33` }}>
              Config saved to disk. Restart this service to apply changes.
            </div>
          )}
          <SettingsRow label="backend">
            <SettingsSelect
              value={editTmplBackend}
              options={["bitcoind", "stratum"]}
              onChange={setEditTmplBackend}
            />
          </SettingsRow>
          <SettingsRow label="poll_interval_secs">
            <SettingsInput value={editTmplPollIntervalSecs} onChange={setEditTmplPollIntervalSecs} />
          </SettingsRow>
          <SettingsRow label="coinbase_script_hex">
            <SettingsInput value={editTmplCoinbaseScriptHex} onChange={setEditTmplCoinbaseScriptHex} />
          </SettingsRow>
          <SettingsRow label="extranonce_size">
            <SettingsInput value={editTmplExtraNonceSize} onChange={setEditTmplExtraNonceSize} />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="http_listen_addr" readOnly>
              <SettingsInput value={tmpl.http_listen_addr} disabled />
            </SettingsRow>
            <SettingsRow label="verifier_tcp_addr" readOnly>
              <SettingsInput value={tmpl.verifier_tcp_addr} disabled />
            </SettingsRow>
          </div>
          {editTmplBackend === "bitcoind" && (
            <>
              <SettingsRow label="rpc_url">
                <SettingsInput value={editTmplRpcUrl} onChange={setEditTmplRpcUrl} />
              </SettingsRow>
              <SettingsRow label="rpc_user">
                <SettingsInput value={editTmplRpcUser} onChange={setEditTmplRpcUser} />
              </SettingsRow>
              <SettingsRow label="rpc_password" readOnly>
                <SecretIndicator configured={tmpl.rpc_pass_set} />
              </SettingsRow>
            </>
          )}
          {editTmplBackend === "stratum" && (
            <>
              <SettingsRow label="stratum_addr">
                <SettingsInput value={editTmplStratumAddr} onChange={setEditTmplStratumAddr} />
              </SettingsRow>
              <SettingsRow label="stratum_auth" readOnly>
                <SecretIndicator configured={tmpl.stratum_auth_set} />
              </SettingsRow>
            </>
          )}
          <SettingsRow label="log_level" readOnly>
            <SettingsInput value={tmpl.log_level} disabled />
          </SettingsRow>
          <SettingsRow label="log_format" readOnly>
            <SettingsInput value={tmpl.log_format} disabled />
          </SettingsRow>
          <div className="flex items-center gap-3 mt-3 pt-3" style={{ borderTop: `1px solid ${V.border}` }}>
            <Btn variant="glow" onClick={handleSaveTemplateSettings} disabled={!tmplHasEdits || !caps.canEditSettings}>
              Save
            </Btn>
            {tmplSaveResult && (
              <span className="text-[10px]" style={{
                color: tmplSaveResult === "Settings saved." ? V.success : V.error,
              }}>
                {tmplSaveResult}
              </span>
            )}
          </div>
        </div>
      </Card>

      {/* ── Card 4: Authentication (read-only) ── */}
      <Card>
        {sectionHeader("Authentication", asLive, false)}
        <div className="px-5 pb-4">
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="bind_addr" readOnly>
              <SettingsInput value={as_.bind_addr} disabled />
            </SettingsRow>
            <SettingsRow label="db_path" readOnly>
              <SettingsInput value={as_.db_path} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="session_ttl_hours" readOnly>
            <SettingsInput value={String(as_.session_ttl_hours)} disabled />
          </SettingsRow>
          <SettingsRow label="admin_email" readOnly>
            <SettingsInput value={as_.admin_email} disabled />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="site_url" readOnly>
              <SettingsInput value={as_.site_url} disabled />
            </SettingsRow>
            <SettingsRow label="auth_url" readOnly>
              <SettingsInput value={as_.auth_url} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="allowed_origin" readOnly>
            <SettingsInput value={as_.allowed_origin} disabled />
          </SettingsRow>
          <SettingsRow label="smtp_host" readOnly>
            <SettingsInput value={as_.smtp_host || "(none)"} disabled />
          </SettingsRow>
          <div className="grid grid-cols-2 gap-x-6">
            <SettingsRow label="smtp_port" readOnly>
              <SettingsInput value={String(as_.smtp_port)} disabled />
            </SettingsRow>
            <SettingsRow label="smtp_user" readOnly>
              <SettingsInput value={as_.smtp_user || "(none)"} disabled />
            </SettingsRow>
          </div>
          <SettingsRow label="smtp_password" readOnly>
            <SecretIndicator configured={as_.smtp_pass_set} />
          </SettingsRow>
          <SettingsRow label="smtp_configured" readOnly>
            <Toggle checked={as_.smtp_configured} onCheckedChange={() => {}} disabled />
          </SettingsRow>
          <SettingsRow label="log_level" readOnly>
            <SettingsInput value={as_.log_level} disabled />
          </SettingsRow>
        </div>
      </Card>

      {/* ── Card 5: Dashboard (read-only) ── */}
      <Card>
        {sectionHeader("Dashboard", dsLive, false)}
        <div className="px-5 pb-4">
          <SettingsRow label="listen" readOnly>
            <SettingsInput value={ds.listen} disabled />
          </SettingsRow>
          <SettingsRow label="log_level" readOnly>
            <SettingsInput value={ds.log_level} disabled />
          </SettingsRow>
          <SettingsRow label="log_format" readOnly>
            <SettingsInput value={ds.log_format} disabled />
          </SettingsRow>
          <SettingsRow label="verifier_url" readOnly>
            <SettingsInput value={ds.verifier_url} disabled />
          </SettingsRow>
          <SettingsRow label="template_url" readOnly>
            <SettingsInput value={ds.template_url} disabled />
          </SettingsRow>
          <SettingsRow label="auth_url" readOnly>
            <SettingsInput value={ds.auth_url} disabled />
          </SettingsRow>
          <SettingsRow label="gateway_url" readOnly>
            <SettingsInput value={ds.gateway_url || "(none)"} disabled />
          </SettingsRow>
        </div>
      </Card>
    </div>
  );
}

/* ── Login page ── */

function LoginPage({ onLogin, loading, error, onRegister, onForgot }: {
  onLogin: (email: string, password: string) => Promise<void>;
  loading: boolean;
  error: string | null;
  onRegister: () => void;
  onForgot: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onLogin(email, password);
  };

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 rounded-lg"
        style={{ background: V.panel, border: `1px solid ${V.border}` }}
      >
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold tracking-wide" style={{ color: V.amber }}>
            ReserveGrid OS
          </h1>
          <p className="mt-1 text-xs" style={{ color: V.steelDim }}>Sign in to continue</p>
        </div>

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Email</label>
        <input
          type="email"
          required
          autoFocus
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-4 rounded text-sm outline-none"
          style={{
            background: V.bgAlt,
            border: `1px solid ${V.borderMd}`,
            color: V.ink,
            fontFamily: "var(--mono)",
          }}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Password</label>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-5 rounded text-sm outline-none"
          style={{
            background: V.bgAlt,
            border: `1px solid ${V.borderMd}`,
            color: V.ink,
            fontFamily: "var(--mono)",
          }}
        />

        {error && (
          <p className="mb-4 text-xs" style={{ color: V.error }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 rounded text-sm font-medium transition-opacity"
          style={{
            background: V.amber,
            color: V.bg,
            opacity: loading ? 0.6 : 1,
            cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Signing in\u2026" : "Sign In"}
        </button>

        <p className="text-xs text-center mt-4" style={{ color: V.steelDim }}>
          No account?{" "}
          <button type="button" onClick={onRegister} className="underline" style={{ color: V.amber }}>
            Register
          </button>
        </p>
        <p className="text-xs text-center mt-2" style={{ color: V.steelDim }}>
          <button type="button" onClick={onForgot} className="underline" style={{ color: V.steelDim }}>
            Forgot password?
          </button>
        </p>
      </form>
    </div>
  );
}

/* ── Register page ── */

function RegisterPage({ onBack }: { onBack: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    setLoading(true);
    setError(null);
    const result = await register(email, name, org, password);
    setLoading(false);
    if (result.ok) {
      setSuccess(true);
    } else {
      setError(result.error ?? "Registration failed");
    }
  };

  const inputStyle = {
    background: V.bgAlt,
    border: `1px solid ${V.borderMd}`,
    color: V.ink,
    fontFamily: "var(--mono)",
  };

  if (success) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
        <div className="w-full max-w-sm p-8 rounded-lg text-center" style={{ background: V.panel, border: `1px solid ${V.border}` }}>
          <Mail className="w-10 h-10 mx-auto mb-4" style={{ color: V.amber }} />
          <h2 className="text-base font-semibold mb-2" style={{ color: V.ink }}>Check your email</h2>
          <p className="text-xs mb-6" style={{ color: V.steel }}>
            We sent a verification link to <span style={{ color: V.ink, fontFamily: "var(--mono)" }}>{email}</span>.
            Click the link to verify your address, then wait for admin approval.
          </p>
          <button
            type="button"
            onClick={onBack}
            className="text-xs underline"
            style={{ color: V.amber }}
          >
            Back to login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 rounded-lg"
        style={{ background: V.panel, border: `1px solid ${V.border}` }}
      >
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold tracking-wide" style={{ color: V.amber }}>
            ReserveGrid OS
          </h1>
          <p className="mt-1 text-xs" style={{ color: V.steelDim }}>Create an account</p>
        </div>

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Full Name</label>
        <input
          type="text"
          required
          autoFocus
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-3 rounded text-sm outline-none"
          style={inputStyle}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Email</label>
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-3 rounded text-sm outline-none"
          style={inputStyle}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Organization</label>
        <input
          type="text"
          required
          value={org}
          onChange={(e) => setOrg(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-3 rounded text-sm outline-none"
          style={inputStyle}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Password</label>
        <input
          type="password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
          placeholder="8 characters minimum"
          className="w-full px-3 py-2 mb-3 rounded text-sm outline-none"
          style={inputStyle}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Confirm Password</label>
        <input
          type="password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-5 rounded text-sm outline-none"
          style={inputStyle}
        />

        {error && (
          <p className="mb-4 text-xs" style={{ color: V.error }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 rounded text-sm font-medium transition-opacity"
          style={{
            background: V.amber,
            color: V.bg,
            opacity: loading ? 0.6 : 1,
            cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Registering\u2026" : "Register"}
        </button>

        <p className="text-xs text-center mt-4" style={{ color: V.steelDim }}>
          Already have an account?{" "}
          <button type="button" onClick={onBack} className="underline" style={{ color: V.amber }}>
            Sign in
          </button>
        </p>
      </form>
    </div>
  );
}

/* ── Verify page ── */

function VerifyPage({ token, onBack }: { token: string; onBack: () => void }) {
  const [status, setStatus] = useState<"loading" | "ok" | "error">("loading");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    verifyEmail(token).then((result) => {
      if (cancelled) return;
      setStatus(result.ok ? "ok" : "error");
      setMessage(result.message);
    });
    return () => { cancelled = true; };
  }, [token]);

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
      <div className="w-full max-w-sm p-8 rounded-lg text-center" style={{ background: V.panel, border: `1px solid ${V.border}` }}>
        {status === "loading" && (
          <>
            <Loader2 className="w-8 h-8 mx-auto mb-4 animate-spin" style={{ color: V.amber }} />
            <p className="text-xs" style={{ color: V.steel }}>Verifying your email&hellip;</p>
          </>
        )}
        {status === "ok" && (
          <>
            <CheckCircle className="w-10 h-10 mx-auto mb-4" style={{ color: V.success }} />
            <h2 className="text-base font-semibold mb-2" style={{ color: V.ink }}>Email Verified</h2>
            <p className="text-xs mb-6" style={{ color: V.steel }}>
              {message || "Your email has been verified. Your account is now pending admin approval."}
            </p>
          </>
        )}
        {status === "error" && (
          <>
            <AlertTriangle className="w-10 h-10 mx-auto mb-4" style={{ color: V.error }} />
            <h2 className="text-base font-semibold mb-2" style={{ color: V.ink }}>Verification Failed</h2>
            <p className="text-xs mb-6" style={{ color: V.steel }}>
              {message || "The verification link is invalid or expired."}
            </p>
          </>
        )}
        {status !== "loading" && (
          <button
            type="button"
            onClick={() => { window.history.replaceState({}, "", window.location.pathname); onBack(); }}
            className="text-xs underline"
            style={{ color: V.amber }}
          >
            Back to login
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Forgot password page ── */

function ForgotPasswordPage({ onBack }: { onBack: () => void }) {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const result = await forgotPassword(email);
    setLoading(false);
    if (result.ok) {
      setSent(true);
    } else {
      setError(result.message || "Something went wrong");
    }
  };

  if (sent) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
        <div className="w-full max-w-sm p-8 rounded-lg text-center" style={{ background: V.panel, border: `1px solid ${V.border}` }}>
          <Mail className="w-10 h-10 mx-auto mb-4" style={{ color: V.amber }} />
          <h2 className="text-base font-semibold mb-2" style={{ color: V.ink }}>Check your email</h2>
          <p className="text-xs mb-6" style={{ color: V.steel }}>
            If <span style={{ color: V.ink, fontFamily: "var(--mono)" }}>{email}</span> is registered, you will receive a password reset link.
          </p>
          <button type="button" onClick={onBack} className="text-xs underline" style={{ color: V.amber }}>
            Back to login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 rounded-lg"
        style={{ background: V.panel, border: `1px solid ${V.border}` }}
      >
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold tracking-wide" style={{ color: V.amber }}>
            ReserveGrid OS
          </h1>
          <p className="mt-1 text-xs" style={{ color: V.steelDim }}>Reset your password</p>
        </div>

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Email</label>
        <input
          type="email"
          required
          autoFocus
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-5 rounded text-sm outline-none"
          style={{
            background: V.bgAlt,
            border: `1px solid ${V.borderMd}`,
            color: V.ink,
            fontFamily: "var(--mono)",
          }}
        />

        {error && (
          <p className="mb-4 text-xs" style={{ color: V.error }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 rounded text-sm font-medium transition-opacity"
          style={{
            background: V.amber,
            color: V.bg,
            opacity: loading ? 0.6 : 1,
            cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Sending\u2026" : "Send Reset Link"}
        </button>

        <p className="text-xs text-center mt-4" style={{ color: V.steelDim }}>
          <button type="button" onClick={onBack} className="underline" style={{ color: V.amber }}>
            Back to login
          </button>
        </p>
      </form>
    </div>
  );
}

/* ── Reset password page ── */

function ResetPasswordPage({ token, onBack }: { token: string; onBack: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    setLoading(true);
    setError(null);
    const result = await resetPassword(token, password);
    setLoading(false);
    if (result.ok) {
      setSuccess(true);
    } else {
      setError(result.message || "Reset failed");
    }
  };

  const inputStyle = {
    background: V.bgAlt,
    border: `1px solid ${V.borderMd}`,
    color: V.ink,
    fontFamily: "var(--mono)",
  };

  if (success) {
    return (
      <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
        <div className="w-full max-w-sm p-8 rounded-lg text-center" style={{ background: V.panel, border: `1px solid ${V.border}` }}>
          <KeyRound className="w-10 h-10 mx-auto mb-4" style={{ color: V.success }} />
          <h2 className="text-base font-semibold mb-2" style={{ color: V.ink }}>Password Reset</h2>
          <p className="text-xs mb-6" style={{ color: V.steel }}>
            Your password has been updated. You can now sign in with your new password.
          </p>
          <button
            type="button"
            onClick={() => { window.history.replaceState({}, "", window.location.pathname); onBack(); }}
            className="text-xs underline"
            style={{ color: V.amber }}
          >
            Back to login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center justify-center min-h-screen" style={{ background: V.bg }}>
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-sm p-8 rounded-lg"
        style={{ background: V.panel, border: `1px solid ${V.border}` }}
      >
        <div className="mb-6 text-center">
          <h1 className="text-lg font-semibold tracking-wide" style={{ color: V.amber }}>
            ReserveGrid OS
          </h1>
          <p className="mt-1 text-xs" style={{ color: V.steelDim }}>Set a new password</p>
        </div>

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>New Password</label>
        <input
          type="password"
          required
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
          placeholder="8 characters minimum"
          className="w-full px-3 py-2 mb-3 rounded text-sm outline-none"
          style={inputStyle}
        />

        <label className="block mb-1 text-xs" style={{ color: V.steel }}>Confirm Password</label>
        <input
          type="password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          disabled={loading}
          className="w-full px-3 py-2 mb-5 rounded text-sm outline-none"
          style={inputStyle}
        />

        {error && (
          <p className="mb-4 text-xs" style={{ color: V.error }}>{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 rounded text-sm font-medium transition-opacity"
          style={{
            background: V.amber,
            color: V.bg,
            opacity: loading ? 0.6 : 1,
            cursor: loading ? "wait" : "pointer",
          }}
        >
          {loading ? "Resetting\u2026" : "Reset Password"}
        </button>

        <p className="text-xs text-center mt-4" style={{ color: V.steelDim }}>
          <button type="button" onClick={() => { window.history.replaceState({}, "", window.location.pathname); onBack(); }} className="underline" style={{ color: V.amber }}>
            Back to login
          </button>
        </p>
      </form>
    </div>
  );
}

/* ── Main layout ── */

type AuthView = "login" | "register" | "verify" | "forgot" | "reset";

export default function App() {
  const { user, login, logout, loading: authLoading, error: authError } = useSession();
  const [authView, setAuthView] = useState<AuthView>(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has("verify")) return "verify";
    if (params.has("reset")) return "reset";
    return "login";
  });

  const verifyToken = new URLSearchParams(window.location.search).get("verify") ?? "";
  const resetToken = new URLSearchParams(window.location.search).get("reset") ?? "";

  if (!user) {
    if (authView === "register") return <RegisterPage onBack={() => setAuthView("login")} />;
    if (authView === "verify") return <VerifyPage token={verifyToken} onBack={() => setAuthView("login")} />;
    if (authView === "forgot") return <ForgotPasswordPage onBack={() => setAuthView("login")} />;
    if (authView === "reset") return <ResetPasswordPage token={resetToken} onBack={() => setAuthView("login")} />;
    return <LoginPage onLogin={login} loading={authLoading} error={authError} onRegister={() => setAuthView("register")} onForgot={() => setAuthView("forgot")} />;
  }

  return <Dashboard user={user} onLogout={logout} />;
}

/* ── Dashboard (rendered only when authenticated) ── */

function Dashboard({ user, onLogout }: { user: { name: string; email: string; org: string }; onLogout: () => Promise<void> }) {
  const [page, setPage] = useState<Page>("overview");

  const { services, live: healthLive } = useHealth();
  const { stats, live: statmplLive } = useStats();
  const { verdicts, live: verdictmplLive } = useVerdicts();
  const { policy, live: policyLive } = usePolicy();
  const { template, live: templateLive } = useLatestTemplate();
  const { mempool, live: mempoolLive } = useMempool();

  const { settings: dashSettings } = useDashboardSettings();
  const deployMode: DeployMode = dashSettings.deploy_mode ?? "shadow";
  const caps = modeCapabilities(deployMode);
  const visibleNav = NAV.filter((item) => {
    if (item.id === "miners" && !caps.canViewMiners) return false;
    return true;
  });

  const anyLive = healthLive || statmplLive || verdictmplLive || policyLive || templateLive || mempoolLive;
  const degradedCount = services.filter(s => s.status !== "ok").length;

  return (
    <div className="h-screen flex flex-col" style={{ background: V.bg, color: V.ink, fontFamily: "var(--sans)" }}>
      {/* Top bar */}
      <div className="h-11 flex items-center px-5 text-xs shrink-0"
        style={{
          background: "rgba(8,14,26,.85)",
          backdropFilter: "blur(20px) saturate(1.4)",
          borderBottom: `1px solid ${V.border}`,
        }}>
        <span className="text-sm font-bold tracking-wide">
          <AccentText>ReserveGrid</AccentText>
        </span>
        <span className="mx-2" style={{ color: V.steelDim }}>/</span>
        <span style={{ color: V.steel }}>OS</span>

        {/* Grafana style health strip */}
        <div className="flex items-center gap-4 ml-8">
          {services.map((s) => (
            <span key={s.name} className="flex items-center gap-1.5" style={{ color: V.steelDim }}>
              <StatusDot status={s.status} />
              <span className="text-[10px]" style={{ fontFamily: "var(--mono)" }}>{s.name}</span>
            </span>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-4">
          <span className="text-[10px] px-2 py-0.5 rounded font-medium" style={{
            fontFamily: "var(--mono)",
            color: deployMode === "inline" ? V.success : deployMode === "observe" ? V.amberLight : V.steelDim,
            background: deployMode === "inline" ? "rgba(34,197,94,.08)" : deployMode === "observe" ? "rgba(212,148,60,.08)" : "rgba(226,232,240,.04)",
            border: `1px solid ${deployMode === "inline" ? "rgba(34,197,94,.2)" : deployMode === "observe" ? "rgba(212,148,60,.2)" : V.border}`,
          }}>{deployMode.toUpperCase()}</span>
          <LiveBadge live={anyLive} />
          {degradedCount > 0 && (
            <span className="flex items-center gap-1.5" style={{ color: V.warning }}>
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>{degradedCount} degraded</span>
            </span>
          )}
          <span style={{ color: V.steelDim, fontFamily: "var(--mono)" }}>
            Block {template.block_height.toLocaleString()}
          </span>
          <div className="h-4 w-px" style={{ background: V.borderMd }} />
          <span style={{ color: V.steel }}>{user.email}</span>
          <button
            onClick={onLogout}
            className="flex items-center justify-center p-1 rounded transition-colors hover:bg-white/[.06]"
            style={{ color: V.steelDim }}
            title="Sign out"
          >
            <LogOut className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <GlowLine />

      <div className="flex flex-1 overflow-hidden">
        {/* Left nav */}
        <nav className="w-48 shrink-0 py-3" style={{ background: V.bgAlt, borderRight: `1px solid ${V.border}` }}>
          {visibleNav.map((item) => {
            const Icon = item.icon;
            const active = page === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setPage(item.id)}
                className="w-full flex items-center gap-2.5 px-4 py-2 text-xs transition-all duration-150 hover:bg-white/[.03]"
                style={{
                  color: active ? V.amberLight : V.steelDim,
                  background: active ? "rgba(212,148,60,.08)" : undefined,
                  borderLeft: active ? `2px solid ${V.amber}` : "2px solid transparent",
                  fontWeight: active ? 600 : 400,
                }}
              >
                <Icon className="w-4 h-4 shrink-0" />
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6" style={{ maxWidth: 1200 }}>
            {deployMode === "shadow" && (
              <div className="mb-4 flex items-center gap-3 p-3 rounded-xl" style={{
                background: "rgba(226,232,240,.04)",
                border: `1px solid ${V.border}`,
              }}>
                <Eye className="w-4 h-4 shrink-0" style={{ color: V.steelDim }} />
                <p className="text-xs" style={{ color: V.steel }}>
                  Shadow mode uses synthetic demo data. Policy editing, CSV export, and miner views are disabled.
                  Upgrade to <span style={{ color: V.amberLight }}>observe</span> for real mainnet data.
                </p>
              </div>
            )}
            {page === "overview" && <OverviewPage services={services} stats={stats} verdicts={verdicts} template={template} mempool={mempool} onNavigate={setPage} />}
            {page === "verdicts" && <VerdictsPage verdicts={verdicts} caps={caps} />}
            {page === "policy" && <PolicyPage policy={policy} verdicts={verdicts} mempool={mempool} live={policyLive} caps={caps} />}
            {page === "templates" && <TemplatesPage template={template} mempool={mempool} />}
            {page === "miners" && caps.canViewMiners && <MinersPage />}
            {page === "settings" && <SettingsPage caps={caps} />}
          </div>
        </div>
      </div>
    </div>
  );
}
