#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# dev-os-test.sh  — Full ReserveGrid OS integration test via docker compose
#
# Brings up the entire stack, seeds regtest with spendable UTXOs, pumps
# mempool traffic, and verifies every service endpoint is healthy. Designed
# to be idempotent: safe to re-run without manual cleanup.
#
# Usage:
#   ./scripts/dev-os-test.sh              # default: seed + traffic + verify
#   SKIP_BUILD=1 ./scripts/dev-os-test.sh # skip rebuild, just test running stack
#   TRAFFIC_CYCLES=0 ./scripts/dev-os-test.sh  # skip traffic generation
#   TEARDOWN=1 ./scripts/dev-os-test.sh   # bring stack down when done
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# ── Configuration ─────────────────────────────────────────────────────────────
# Docker compose service ports (host-mapped)
BTC_RPC_PORT="${BTC_RPC_PORT:-18443}"
BTC_RPC_USER="${VELDRA_BITCOIND_RPC_USER:-${BTC_RPC_USER:-reservegrid}}"
BTC_RPC_PASS="${VELDRA_BITCOIND_RPC_PASS:-${BTC_RPC_PASS:?Set VELDRA_BITCOIND_RPC_PASS or BTC_RPC_PASS}}"

VERIFIER_HTTP="http://localhost:8081"
TEMPLATE_HTTP="http://localhost:8082"
GATEWAY_HEALTH="http://localhost:8080"
AUTH_HTTP="http://localhost:3030"
DASHBOARD_HTTP="http://localhost:8084"

# Traffic knobs
TRAFFIC_CYCLES="${TRAFFIC_CYCLES:-5}"   # 0 = skip traffic
TRAFFIC_SLEEP="${TRAFFIC_SLEEP:-2}"     # seconds between cycles
TXS_PER_CYCLE="${TXS_PER_CYCLE:-10}"
TX_AMOUNT="${TX_AMOUNT:-0.001}"

# Behavior
SKIP_BUILD="${SKIP_BUILD:-0}"
TEARDOWN="${TEARDOWN:-0}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'

log()  { printf "${CYN}[os-test]${RST} %s\n" "$*"; }
ok()   { printf "${GRN}[  OK  ]${RST} %s\n" "$*"; }
warn() { printf "${YLW}[ WARN ]${RST} %s\n" "$*"; }
fail() { printf "${RED}[ FAIL ]${RST} %s\n" "$*"; }

WALLET_NAME="${WALLET_NAME:-ostest}"

# Find the bitcoind container name dynamically
BTC_CONTAINER=""
btc_container() {
  if [[ -z "${BTC_CONTAINER}" ]]; then
    BTC_CONTAINER="$(docker compose ps -q bitcoind 2>/dev/null)"
    if [[ -z "${BTC_CONTAINER}" ]]; then
      fail "bitcoind container not found"
      exit 1
    fi
  fi
  echo "${BTC_CONTAINER}"
}

btc() {
  docker exec "$(btc_container)" bitcoin-cli \
    -regtest \
    -rpcuser="${BTC_RPC_USER}" \
    -rpcpassword="${BTC_RPC_PASS}" \
    -rpcwallet="${WALLET_NAME}" \
    "$@"
}

# Bare btc call without -rpcwallet (for createwallet/loadwallet)
btc_no_wallet() {
  docker exec "$(btc_container)" bitcoin-cli \
    -regtest \
    -rpcuser="${BTC_RPC_USER}" \
    -rpcpassword="${BTC_RPC_PASS}" \
    "$@"
}

# Retry a command up to N times with sleep between attempts.
# Usage: retry <max_attempts> <sleep_secs> <command...>
retry() {
  local max="$1" sleep_s="$2"; shift 2
  local attempt=1
  while [[ "${attempt}" -le "${max}" ]]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    attempt=$((attempt + 1))
    sleep "${sleep_s}"
  done
  return 1
}

# Wait for an HTTP endpoint to return 200.
# Usage: wait_http <label> <url> <timeout_secs>
wait_http() {
  local label="$1" url="$2" timeout="${3:-${TIMEOUT_SECS}}"
  local elapsed=0
  while [[ "${elapsed}" -lt "${timeout}" ]]; do
    if curl -sf "${url}" >/dev/null 2>&1; then
      ok "${label} ready (${elapsed}s)"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  fail "${label} not ready after ${timeout}s (${url})"
  return 1
}

cleanup() {
  if [[ "${TEARDOWN}" == "1" ]]; then
    log "tearing down stack..."
    docker compose down --remove-orphans 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ── Phase 1: Build and Start ─────────────────────────────────────────────────
log "ReserveGrid OS Integration Test"
log "================================"

if [[ "${SKIP_BUILD}" != "1" ]]; then
  log "building all services..."
  docker compose build 2>&1 | tail -5
  ok "docker compose build"
fi

log "starting stack..."
docker compose up -d 2>&1 | tail -5
ok "docker compose up -d"

# ── Phase 2: Wait for Services ───────────────────────────────────────────────
log ""
log "waiting for services to become healthy..."

# bitcoind RPC requires POST with auth; use docker exec healthcheck instead
wait_btc() {
  local timeout="${1:-60}" elapsed=0
  while [[ "${elapsed}" -lt "${timeout}" ]]; do
    if btc_no_wallet getblockchaininfo >/dev/null 2>&1; then
      ok "bitcoind RPC ready (${elapsed}s)"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  fail "bitcoind RPC not ready after ${timeout}s"
  return 1
}
wait_btc 60
wait_http "pool-verifier"     "${VERIFIER_HTTP}/health"
wait_http "template-manager"  "${TEMPLATE_HTTP}/health"
wait_http "sv2-gateway"       "${GATEWAY_HEALTH}/healthz"
wait_http "rg-auth"           "${AUTH_HTTP}/auth/health"
wait_http "rg-dashboard"      "${DASHBOARD_HTTP}/healthz"

# ── Phase 3: Seed Regtest ────────────────────────────────────────────────────
log ""
log "seeding regtest wallet..."

# Create or load wallet (idempotent).
# Use btc_no_wallet since the wallet does not exist yet for -rpcwallet.
if ! btc_no_wallet loadwallet "${WALLET_NAME}" >/dev/null 2>&1; then
  btc_no_wallet createwallet "${WALLET_NAME}" >/dev/null 2>&1 || true
fi
ok "wallet '${WALLET_NAME}' ready"

# Mine 110 blocks for coinbase maturity
MINING_ADDR="$(btc getnewaddress mining bech32)"
btc generatetoaddress 110 "${MINING_ADDR}" >/dev/null
ok "mined 110 blocks (coinbase maturity)"

# Warm up UTXOs: split into 30 outputs for parallel spending
for i in $(seq 1 30); do
  addr="$(btc getnewaddress warmup bech32)"
  btc -named sendtoaddress address="${addr}" amount=0.1 fee_rate=1 avoid_reuse=false >/dev/null
done
btc generatetoaddress 1 "${MINING_ADDR}" >/dev/null
ok "UTXO warmup complete (30 confirmed outputs)"

# ── Phase 4: Mempool Traffic ─────────────────────────────────────────────────
if [[ "${TRAFFIC_CYCLES}" -gt 0 ]]; then
  log ""
  log "generating mempool traffic (${TRAFFIC_CYCLES} cycles, ${TXS_PER_CYCLE} txs each)..."

  for cycle in $(seq 1 "${TRAFFIC_CYCLES}"); do
    for _ in $(seq 1 "${TXS_PER_CYCLE}"); do
      addr="$(btc getnewaddress traffic bech32)"
      fee_rate=$((RANDOM % 50 + 1))
      btc -named sendtoaddress \
        address="${addr}" \
        amount="${TX_AMOUNT}" \
        fee_rate="${fee_rate}.0" \
        avoid_reuse=false >/dev/null 2>&1 || true
    done

    # Occasionally mine a block (every other cycle)
    if (( cycle % 2 == 0 )); then
      btc generatetoaddress 1 "${MINING_ADDR}" >/dev/null
    fi

    printf "  cycle %d/%d  txs=%d\n" "${cycle}" "${TRAFFIC_CYCLES}" "${TXS_PER_CYCLE}"
    sleep "${TRAFFIC_SLEEP}"
  done
  ok "traffic generation complete"
else
  log "skipping traffic generation (TRAFFIC_CYCLES=0)"
fi

# ── Phase 5: Rejection Scenarios ──────────────────────────────────────────────
# Hot-patch the running policy to trigger specific rejection reason_codes,
# then pump a few more templates through to collect rejected verdicts.
# Restores the default (permissive) policy at the end.
SKIP_REJECTIONS="${SKIP_REJECTIONS:-0}"

if [[ "${SKIP_REJECTIONS}" != "1" ]]; then
  log ""
  log "running rejection scenarios..."

  # Save current policy so we can restore it
  ORIGINAL_POLICY="$(curl -sf "${VERIFIER_HTTP}/policy" 2>/dev/null)"

  # ── Scenario A: empty_template_rejected ──────────────────────────────────
  # Mine all pending transactions so next template is empty, then reject it.
  log "  scenario A: empty_template_rejected"
  btc generatetoaddress 3 "${MINING_ADDR}" >/dev/null 2>&1 || true
  sleep 1
  curl -sf -X POST "${VERIFIER_HTTP}/policy/apply" \
    -H "Content-Type: application/json" \
    -d '{"reject_empty_templates": true}' >/dev/null 2>&1
  # Wait for template-manager to poll an empty template through the verifier
  sleep 4
  ok "  scenario A applied (reject_empty_templates=true)"

  # ── Scenario B: total_fees_below_minimum ─────────────────────────────────
  # Restore empty rejection off, set absurd min_total_fees, send low-fee txs.
  log "  scenario B: total_fees_below_minimum"
  curl -sf -X POST "${VERIFIER_HTTP}/policy/apply" \
    -H "Content-Type: application/json" \
    -d '{"reject_empty_templates": false, "min_total_fees": 999999999}' >/dev/null 2>&1
  # Send a few transactions to generate a template with fees below the threshold
  for _ in $(seq 1 3); do
    addr="$(btc getnewaddress reject_b bech32)"
    btc -named sendtoaddress address="${addr}" amount=0.001 fee_rate=1.0 avoid_reuse=false >/dev/null 2>&1 || true
  done
  sleep 4
  ok "  scenario B applied (min_total_fees=999999999)"

  # ── Scenario C: tx_count_exceeded ────────────────────────────────────────
  log "  scenario C: tx_count_exceeded"
  curl -sf -X POST "${VERIFIER_HTTP}/policy/apply" \
    -H "Content-Type: application/json" \
    -d '{"min_total_fees": 0, "max_tx_count": 1}' >/dev/null 2>&1
  # Existing mempool txs will produce templates with tx_count > 1
  sleep 4
  ok "  scenario C applied (max_tx_count=1)"

  # ── Scenario D: avg_fee_below_minimum ────────────────────────────────────
  log "  scenario D: avg_fee_below_minimum"
  curl -sf -X POST "${VERIFIER_HTTP}/policy/apply" \
    -H "Content-Type: application/json" \
    -d '{"max_tx_count": 4294967295, "min_avg_fee_lo": 999999, "min_avg_fee_mid": 999999, "min_avg_fee_hi": 999999}' >/dev/null 2>&1
  sleep 4
  ok "  scenario D applied (min_avg_fee=999999 all tiers)"

  # ── Restore default (permissive) policy ──────────────────────────────────
  log "  restoring default policy..."
  curl -sf -X POST "${VERIFIER_HTTP}/policy/apply" \
    -H "Content-Type: application/json" \
    -d '{"min_total_fees": 0, "max_tx_count": 4294967295, "min_avg_fee_lo": 0, "min_avg_fee_mid": 0, "min_avg_fee_hi": 0, "reject_empty_templates": false}' >/dev/null 2>&1
  ok "  default policy restored"

  # Check that we got some rejections
  REJECTION_COUNT="$(curl -sf "${VERIFIER_HTTP}/stats" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('rejected',0))" 2>/dev/null || echo "?")"
  if [[ "${REJECTION_COUNT}" != "0" && "${REJECTION_COUNT}" != "?" ]]; then
    ok "collected ${REJECTION_COUNT} rejections across 4 scenarios"
  else
    warn "no rejections recorded (REJECTION_COUNT=${REJECTION_COUNT})"
  fi
else
  log "skipping rejection scenarios (SKIP_REJECTIONS=1)"
fi

# ── Phase 6: Verify Endpoints ────────────────────────────────────────────────
log ""
log "verifying service endpoints..."

PASS=0
TOTAL=0

check() {
  local label="$1" url="$2"
  TOTAL=$((TOTAL + 1))
  local status
  status="$(curl -sf -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || echo "000")"
  if [[ "${status}" == "200" ]]; then
    ok "${label} → ${status}"
    PASS=$((PASS + 1))
  else
    fail "${label} → ${status} (${url})"
  fi
}

check "verifier /health"           "${VERIFIER_HTTP}/health"
check "verifier /stats"            "${VERIFIER_HTTP}/stats"
check "verifier /verdicts"         "${VERIFIER_HTTP}/verdicts"
check "verifier /policy"           "${VERIFIER_HTTP}/policy"
check "template-manager /health"   "${TEMPLATE_HTTP}/health"
check "template-manager /latest"   "${TEMPLATE_HTTP}/latest"
check "template-manager /mempool"  "${TEMPLATE_HTTP}/mempool"
check "sv2-gateway /healthz"       "${GATEWAY_HEALTH}/healthz"
check "rg-auth /auth/health"       "${AUTH_HTTP}/auth/health"
check "dashboard /healthz"         "${DASHBOARD_HTTP}/healthz"
check "dashboard /api/health"      "${DASHBOARD_HTTP}/api/health"
check "dashboard SPA"              "${DASHBOARD_HTTP}/"

# ── Phase 7: Mempool Snapshot ────────────────────────────────────────────────
log ""
log "mempool snapshot:"
curl -sf "${TEMPLATE_HTTP}/mempool" 2>/dev/null | python3 -m json.tool 2>/dev/null || warn "mempool endpoint unavailable"

# ── Phase 8: Dashboard Proxy Check ───────────────────────────────────────────
log ""
log "dashboard proxy check (verifier stats via dashboard):"
curl -sf "${DASHBOARD_HTTP}/api/verifier/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || warn "dashboard proxy unavailable"

# ── Summary ──────────────────────────────────────────────────────────────────
log ""
log "================================"
if [[ "${PASS}" -eq "${TOTAL}" ]]; then
  ok "ALL CHECKS PASSED (${PASS}/${TOTAL})"
else
  fail "CHECKS: ${PASS}/${TOTAL} passed"
  exit 1
fi

log ""
log "Dashboard: ${DASHBOARD_HTTP}"
log "Stack is running. Use TEARDOWN=1 to stop, or: docker compose down"
