# Three Mode Architecture Spec

**Status:** Implemented
**Version:** v1.1.0
**Date:** 2026-03-10

## Overview

ReserveGrid OS operates in three deployment modes. Each mode represents a distinct trust level, data source, and feature surface. The same binary stack powers all three modes. A single config key (`mode = "shadow" | "observe" | "inline"`) selects the active mode at startup.

## Mode Summary

```
Shadow  → free,  demo feed,       limited dashboard,  no enforcement
Observe → paid,  reference feed,  full dashboard,     log-only verdicts
Inline  → prod,  operator bitcoind, full dashboard,   active enforcement
```

## Data Flow Per Mode

### Shadow

```
rg-demo-feed (Veldra-hosted, public)
      │  WebSocket (unauthenticated)
      ▼
rg-feed-adapter (operator-side)
      │  bitcoind JSON-RPC impersonation
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (observe-only verdicts)
      │
      ▼
rg-dashboard (limited features)
```

### Observe

```
rg-feed-server (Veldra-hosted, authenticated)
      │  WebSocket (license key auth)
      ▼
rg-feed-adapter (operator-side)
      │  bitcoind JSON-RPC impersonation
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (observe-only verdicts)
      │
      ▼
rg-dashboard (full features)
```

### Inline

```
operator bitcoind (operator-owned)
      │  bitcoind JSON-RPC (native)
      ▼
template-manager
      │  TCP TemplatePropose
      ▼
pool-verifier (enforcing verdicts)
      │
      ▼
sv2-gateway ←→ miners
      │
      ▼
rg-dashboard (full features)
```

## New Services

### rg-demo-feed

Lightweight Veldra-hosted service that streams synthetic but realistic Bitcoin template data over WebSocket. Purpose is to give shadow users a compelling first impression of what ReserveGrid flags.

**Hosting:** Veldra infrastructure (demo.veldra.org or feed-demo.veldra.org)
**Auth:** None. Public endpoint.
**Protocol:** WebSocket, NDJSON frames.

**What it streams:**

Every frame is one of two types, matching the two bitcoind RPCs that template-manager calls:

```json
{"type": "blocktemplate", "data": { ... GBT-shaped response ... }}
{"type": "mempoolinfo", "data": { ... getmempoolinfo-shaped response ... }}
```

**Data characteristics:**
- Synthetic transactions with realistic fee distributions
- Curated edge cases that trigger policy detections:
  - Fee anomalies (total fees below minimum, average fee below tier thresholds)
  - Sigops budget warnings (templates near the sigops limit)
  - Weight ratio violations (templates exceeding configured weight ratio)
  - Stale template scenarios (high template age)
  - Empty template injection (zero transaction templates)
  - Zero coinbase templates
- Block height increments at realistic intervals (roughly every 10 minutes)
- Prev hash changes on each new block
- Deterministic seed option for reproducible demos

**Implementation:** Rust binary using tokio + tungstenite. Single binary, stateless. Reads a scenario manifest (TOML) that defines the sequence of templates and edge cases. Can also run in "live loop" mode cycling through scenarios indefinitely.

**Workspace crate:** `services/rg-demo-feed/`

### rg-feed-server

Veldra-hosted service that streams real mainnet Bitcoin data over WebSocket. This is the paid observe-mode data source.

**Hosting:** Veldra infrastructure (feed.veldra.org)
**Auth:** License key validated on WebSocket handshake.
**Protocol:** WebSocket, NDJSON frames. Same frame format as rg-demo-feed.

**What it streams:**
- Live `getblocktemplate` responses from a Veldra-operated mainnet bitcoind
- Live `getmempoolinfo` snapshots
- Data is IDENTICAL to what the operator's own bitcoind would produce

**Auth flow:**
1. Operator registers at veldra.org, gets approved, receives a signed license key (format: `veldra_lic_<base64url_payload>.<base64url_signature>`)
2. Operator sets `VELDRA_FEED_LICENSE_KEY` in their local config (same key used for OS tier gating)
3. rg-feed-adapter connects to feed.veldra.org and sends key in the WebSocket handshake header (`Authorization: Bearer <key>`)
4. rg-feed-server validates key by verifying the Ed25519 signature and checking that the embedded tier is >= `observe_paid`
5. On success, streaming begins. On failure, connection closes with reason.

**Backend data source:** A dedicated mainnet bitcoind node operated by Veldra. Polls `getblocktemplate` and `getmempoolinfo` at configurable interval (default: 2 seconds) and fans out to all connected WebSocket clients.

**Rate limiting:** Per-key connection limit (1 concurrent connection per license key). Prevents key sharing.

**Workspace crate:** `services/rg-feed-server/`

### rg-feed-adapter

Operator-side binary that translates WebSocket feed data into bitcoind JSON-RPC responses. Runs locally alongside template-manager and masquerades as a bitcoind node.

**Purpose:** template-manager already knows how to poll bitcoind via JSON-RPC. The adapter speaks that same interface so template-manager requires zero code changes regardless of data source.

**Interface:**
- Listens on a local HTTP port (default: 127.0.0.1:18444)
- Responds to JSON-RPC method `getblocktemplate` with the latest template from the feed
- Responds to JSON-RPC method `getmempoolinfo` with the latest mempool snapshot from the feed
- All other RPC methods return a clean error

**Configuration:**

```toml
[adapter]
listen = "127.0.0.1:18444"
feed_url = "wss://demo.veldra.org/ws"   # shadow
# feed_url = "wss://feed.veldra.org/ws" # observe
license_key = ""                         # empty for shadow, required for observe
```

Env var overrides:
- `VELDRA_FEED_URL` → feed_url
- `VELDRA_FEED_LICENSE_KEY` → license_key
- `VELDRA_ADAPTER_LISTEN` → listen

**Behavior:**
- Connects to the feed WebSocket on startup
- Buffers the latest `blocktemplate` and `mempoolinfo` frames in memory
- When template-manager polls `getblocktemplate`, adapter returns the buffered template
- When template-manager polls `getmempoolinfo`, adapter returns the buffered mempool snapshot
- Reconnects automatically on WebSocket disconnect (exponential backoff, max 30s)
- Health endpoint at `/health` returns `{"status":"ok","feed_connected":true,"last_template_age_ms":1234}`

**Auth handling:**
- If `license_key` is non-empty, sends it in the WebSocket handshake `Authorization` header
- If empty, connects without auth (shadow mode demo feed)

**Workspace crate:** `services/rg-feed-adapter/`

## Mode Configuration

### Config Shape

The mode is set in the service config files. Each service reads a `mode` field from its TOML config or from the `VELDRA_MODE` env var.

```toml
# Top-level mode selector. Affects all services.
mode = "shadow"  # or "observe" or "inline"
```

**Env var:** `VELDRA_MODE=shadow|observe|inline`

### What Mode Controls

| Behavior | Shadow | Observe | Inline |
|---|---|---|---|
| Data source | rg-demo-feed (public) | rg-feed-server (authenticated) | operator bitcoind |
| template-manager target | rg-feed-adapter | rg-feed-adapter | bitcoind directly |
| Verifier enforcement | observe-only | observe-only | enforcing |
| Gateway active | no | no | yes |
| Dashboard policy editing | disabled | enabled | enabled |
| Dashboard settings mutation | disabled | enabled | enabled |
| Dashboard CSV export | disabled | enabled | enabled |
| Dashboard dry-run preview | disabled | enabled | enabled |
| Verdict persistence (WAL) | in-memory only | disk WAL | disk WAL |
| License key required | no | yes | no (own infra) |
| Miner connections accepted | no | no | yes |

### Dashboard Feature Gating

The dashboard reads `VELDRA_MODE` at startup and applies feature gates in the frontend.

**Shadow (limited):**
- Overview: full (read-only KPIs, acceptance rate, recent verdicts)
- Verdicts: view-only (no CSV export, no search)
- Templates: view-only (current template inspection)
- Miners: hidden (no miners in shadow/observe)
- Policy: view-only (shows current policy, no edit, no dry-run)
- Settings: all read-only

**Observe (full except miners):**
- Overview: full
- Verdicts: full (CSV export, search, filters)
- Templates: full
- Miners: hidden (no miners in observe)
- Policy: full (edit, apply, dry-run preview)
- Settings: editable sections enabled
- Note: Miners page hidden because observe mode has no gateway/miners

**Inline (full):**
- All features enabled
- Miners page visible (connected workers, hashrate, shares)

### Verifier Mode Behavior

pool-verifier already has a `dash_mode` concept. This maps to:

| VELDRA_MODE | Verifier behavior |
|---|---|
| shadow | Log verdicts, do not forward to gateway, in-memory only |
| observe | Log verdicts, persist to WAL, do not forward to gateway |
| inline | Log verdicts, persist to WAL, forward accept/reject to gateway |

### Gateway Behavior

| VELDRA_MODE | Gateway behavior |
|---|---|
| shadow | Does not start |
| observe | Does not start |
| inline | Full operation: accepts miners, broadcasts jobs, processes shares |

## Operator Journey

### Shadow (zero to first verdict in under 5 minutes)

1. Download ReserveGrid OS binary bundle from veldra.org
2. Run `rg-feed-adapter` (defaults to demo feed, no config needed)
3. Run `template-manager` pointed at the adapter (`rpc_url = "http://127.0.0.1:18444"`)
4. Run `pool-verifier` with `mode = "shadow"`
5. Run `rg-dashboard` with `mode = "shadow"`
6. Open browser to localhost:8084
7. See synthetic templates flowing, verdicts appearing, policy detections highlighted

No bitcoind. No account. No license key. No miners.

### Observe (evaluate with real mainnet data)

1. Register at veldra.org, get admin approval, receive signed license key via email (or retrieve from /license/)
2. Configure rg-feed-adapter: `feed_url = "wss://feed.veldra.org/ws"`, `license_key = "veldra_lic_..."`
3. Set `mode = "observe"` in all service configs
4. Start the stack (same binaries as shadow)
5. See real mainnet templates, real verdicts, real policy behavior
6. Edit policy, run dry-runs, tune thresholds against live data
7. Export verdict history for analysis

### Inline (production enforcement)

1. Stop rg-feed-adapter (no longer needed)
2. Point template-manager at operator's own bitcoind: `rpc_url = "http://bitcoind:8332"`
3. Set `mode = "inline"` in all service configs
4. Start the full stack including sv2-gateway
5. Connect miners to the gateway
6. ReserveGrid now enforces policy on live templates with real hashrate

## Feed Protocol Spec

### Wire Format

Both rg-demo-feed and rg-feed-server use the same wire format:

- Transport: WebSocket (wss://)
- Framing: One NDJSON line per WebSocket text message
- Each message has a `type` field and a `data` field

### Message Types

**`blocktemplate`** — mirrors bitcoind `getblocktemplate` response shape:

```json
{
  "type": "blocktemplate",
  "ts": 1741500000,
  "data": {
    "version": 536870912,
    "previousblockhash": "000000000000000000023a...",
    "transactions": [
      {
        "data": "02000000...",
        "txid": "abc123...",
        "hash": "def456...",
        "fee": 15000,
        "sigops": 4,
        "weight": 1200
      }
    ],
    "coinbaseaux": {"flags": ""},
    "coinbasevalue": 312500000,
    "coinbasetxn": {
      "data": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff",
      "sigops": 1
    },
    "target": "000000000000000000047...",
    "mintime": 1741499900,
    "curtime": 1741500000,
    "bits": "17034219",
    "height": 890001,
    "default_witness_commitment": "6a24aa21a9ed...",
    "sizelimit": 1000000,
    "sigoplimit": 80000,
    "weightlimit": 4000000,
    "rules": ["segwit"],
    "capabilities": ["proposal"],
    "vbavailable": {},
    "vbrequired": 0,
    "longpollid": "000000000000000000023a...1741500000",
    "mutable": ["time", "transactions", "prevblock"],
    "noncerange": "00000000ffffffff"
  }
}
```

**`mempoolinfo`** — mirrors bitcoind `getmempoolinfo` response shape:

```json
{
  "type": "mempoolinfo",
  "ts": 1741500000,
  "data": {
    "loaded": true,
    "size": 45231,
    "bytes": 28419832,
    "usage": 112847392,
    "total_fee": 2.45,
    "maxmempool": 300000000,
    "mempoolminfee": 0.00001000,
    "minrelaytxfee": 0.00001000
  }
}
```

**`heartbeat`** — keep-alive, sent every 30 seconds:

```json
{
  "type": "heartbeat",
  "ts": 1741500000
}
```

### Handshake

1. Client connects to WebSocket endpoint
2. If authenticated feed: client sends `Authorization: Bearer <license_key>` in HTTP upgrade headers
3. Server validates (or skips validation for demo feed)
4. Server sends initial `blocktemplate` and `mempoolinfo` immediately
5. Subsequent messages sent as new data arrives

### Error Codes

Connection close reasons (WebSocket close codes):

| Code | Reason |
|---|---|
| 4001 | invalid_license_key |
| 4002 | license_expired |
| 4003 | concurrent_connection_limit |
| 4004 | feed_unavailable |

## Workspace Layout

```
services/
  rg-demo-feed/          # synthetic demo data server
    Cargo.toml
    Dockerfile
    src/
      main.rs
      scenarios.rs        # scenario functions (normal, low_fees, high_sigops, etc.)
    scenarios/            # reserved for future TOML scenario manifests (currently empty)

  rg-feed-server/        # mainnet reference feed server
    Cargo.toml
    Dockerfile
    src/
      main.rs

  rg-feed-adapter/       # local WebSocket-to-RPC adapter
    Cargo.toml
    Dockerfile
    src/
      main.rs
    config/
      shadow.toml         # pre-configured for demo feed
      observe.toml        # pre-configured for reference feed

  template-manager/      # polls bitcoind (or adapter) via JSON-RPC
  pool-verifier/         # reads VELDRA_MODE for enforcement behavior
  sv2-gateway/           # skips startup when mode != inline
  rg-dashboard/          # React SPA with auth, feature gating based on VELDRA_MODE
  rg-auth/               # user auth, license key model, admin approval
  rg-protocol/           # shared protocol types
```

## Implementation Order

All items below are complete as of 2026-03-10.

1. **rg-feed-adapter** — DONE. Shadow and observe both work with the existing stack. template-manager needs zero changes.
2. **rg-demo-feed** — DONE. Synthetic data with six curated edge case scenarios coded in `scenarios.rs`.
3. **Mode gating in pool-verifier and sv2-gateway** — DONE. Enforcement behavior per mode.
4. **Dashboard feature gating** — DONE. React SPA reads VELDRA_MODE, gates UI accordingly. Auth flow with registration, email verification, and admin approval.
5. **rg-feed-server** — DONE. Wraps a real mainnet bitcoind for observe mode.
6. **License key model in rg-auth** — DONE. Key generation produces signed `veldra_lic_<base64url_payload>.<base64url_sig>` format (EX-046, EX-047). Ed25519 signing key loaded from `VELDRA_LICENSE_SIGNING_KEY` Fly secret. Validation endpoint verifies signature, expiry, and revocation status. Old `veldra_<hex>` format retired.

## Version Targets

All work in this spec is v1.0.0 scope. The three mode architecture, feed services, mode gating, and dashboard feature gates are pre-release design that must land before the initial publish.

- **v1.0.0:** rg-feed-adapter, rg-demo-feed, rg-feed-server, mode gating across all services, dashboard feature gates. Shadow, observe, and inline all functional.
- **v1.0.1:** Security hardening (111 findings across 14 services, done), unified signed license key format (EX-046/047/048, rg-auth done, rg-feed-server done), desktop key persistence (done), website license page copy-to-clipboard (done), auth.veldra.org deployment (done).
- **v1.0.2:** Config.rs unsafe lint fix, dev passkey bypass (SHA-256 hashed, debug-only), in-app auto-updater (Tauri updater + Settings card + tray menu), stale-diff bug fix across all 4 dashboard save handlers, version bumps, website content refresh.
- **v1.1.0:** Automatic mode degradation (inline→observe on verifier unreachable), extended channels + vardiff (PB-6), full per-IP rate limiter module, gateway Phase 1, policy model economic improvements.

## Risks and Edge Cases

1. **Feed adapter latency.** The adapter adds one hop between the feed and template-manager. If the adapter buffers stale data, template-manager will evaluate old templates. Mitigation: adapter health endpoint exposes `last_template_age_ms`. template-manager's stale template detection already handles this.

2. **Demo feed realism.** If the synthetic data is too clean, operators will not see value. If it's too noisy, it will look fake. Mitigation: curate scenarios based on real mainnet anomalies observed during testing. Version the scenario manifests.

3. **Feed server as single point of failure for observe.** If feed.veldra.org goes down, observe-mode operators lose data. Mitigation: adapter reconnects automatically. Dashboard shows "feed disconnected" state. Operators already understand this is an evaluation mode, not production.

4. **License key leaking.** An operator could share their key. Mitigation: one concurrent connection per key. Server-side connection tracking.

5. **Mode drift.** If services disagree on mode (e.g. verifier thinks inline, gateway thinks observe), behavior is undefined. Mitigation: all services read `VELDRA_MODE` from the same env var. Dashboard health page shows mode per service.
