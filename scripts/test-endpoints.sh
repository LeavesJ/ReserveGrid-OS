#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test-endpoints.sh — Service endpoint contract verification
#
# Verifies that every HTTP endpoint in the ReserveGrid OS stack returns the
# expected status code and response shape. Designed to run against a live
# stack (regtest or shadow mode) after services are healthy.
#
# Tests cover:
#   pool-verifier  (8081): /health, /settings, /stats, /verdicts, /policy, /meta
#   template-manager (8082): /health, /settings, /latest, /mempool
#   sv2-gateway    (8080): /healthz, /settings, /channels
#   rg-auth        (3030): /auth/health, /auth/settings
#   rg-dashboard   (8084): /healthz (proxy + static)
#
# Usage:
#   ./scripts/test-endpoints.sh                         # default ports
#   VERIFIER=http://custom:8081 ./scripts/test-endpoints.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERIFIER="${VERIFIER:-http://localhost:8081}"
TEMPLATE="${TEMPLATE:-http://localhost:8082}"
GATEWAY="${GATEWAY:-http://localhost:8080}"
AUTH="${AUTH:-http://localhost:3030}"
DASHBOARD="${DASHBOARD:-http://localhost:8084}"

PASSED=0
FAILED=0
SKIPPED=0

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'

pass() { printf "${GRN}[PASS]${RST} %s\n" "$*"; PASSED=$((PASSED + 1)); }
fail() { printf "${RED}[FAIL]${RST} %s\n" "$*"; FAILED=$((FAILED + 1)); }
skip() { printf "${YLW}[SKIP]${RST} %s\n" "$*"; SKIPPED=$((SKIPPED + 1)); }
info() { printf "${CYN}[INFO]${RST} %s\n" "$*"; }

# check_endpoint URL EXPECTED_STATUS DESCRIPTION [REQUIRED_FIELD]
check_endpoint() {
  local url="$1"
  local expected="$2"
  local desc="$3"
  local field="${4:-}"

  local resp
  resp=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo -e "\n000")
  local status
  status=$(echo "$resp" | tail -1)
  local body
  body=$(echo "$resp" | sed '$d')

  if [[ "$status" != "$expected" ]]; then
    if [[ "$status" == "000" ]]; then
      skip "${desc}: service unreachable"
    else
      fail "${desc}: got ${status}, expected ${expected}"
    fi
    return
  fi

  if [[ -n "$field" ]]; then
    local has_field
    has_field=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if '$field' in d else 'no')" 2>/dev/null || echo "no")
    if [[ "$has_field" == "yes" ]]; then
      pass "${desc}"
    else
      fail "${desc}: missing field '${field}' in response"
    fi
  else
    pass "${desc}"
  fi
}

# check_text_endpoint URL EXPECTED_STATUS DESCRIPTION EXPECTED_BODY
# For endpoints that return plain text instead of JSON.
check_text_endpoint() {
  local url="$1"
  local expected="$2"
  local desc="$3"
  local expected_body="${4:-}"

  local resp
  resp=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo -e "\n000")
  local status
  status=$(echo "$resp" | tail -1)
  local body
  body=$(echo "$resp" | sed '$d')

  if [[ "$status" != "$expected" ]]; then
    if [[ "$status" == "000" ]]; then
      skip "${desc}: service unreachable"
    else
      fail "${desc}: got ${status}, expected ${expected}"
    fi
    return
  fi

  if [[ -n "$expected_body" ]]; then
    if [[ "$body" == "$expected_body" ]]; then
      pass "${desc}"
    else
      fail "${desc}: expected body '${expected_body}', got '${body}'"
    fi
  else
    pass "${desc}"
  fi
}

# check_json_array URL EXPECTED_STATUS DESCRIPTION
check_json_array() {
  local url="$1"
  local expected="$2"
  local desc="$3"

  local resp
  resp=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo -e "\n000")
  local status
  status=$(echo "$resp" | tail -1)
  local body
  body=$(echo "$resp" | sed '$d')

  if [[ "$status" != "$expected" ]]; then
    if [[ "$status" == "000" ]]; then
      skip "${desc}: service unreachable"
    else
      fail "${desc}: got ${status}, expected ${expected}"
    fi
    return
  fi

  local is_array
  is_array=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if isinstance(d,list) else 'no')" 2>/dev/null || echo "no")
  if [[ "$is_array" == "yes" ]]; then
    pass "${desc}"
  else
    fail "${desc}: expected JSON array"
  fi
}

# ── pool-verifier ────────────────────────────────────────────────────────────

info "pool-verifier (${VERIFIER})"
check_text_endpoint "${VERIFIER}/health" 200 "PV /health"       "ok"
check_endpoint "${VERIFIER}/settings"  200 "PV /settings"       "log_level"
check_endpoint "${VERIFIER}/stats"     200 "PV /stats"          "total"
check_endpoint "${VERIFIER}/policy"    200 "PV /policy"         "min_total_fees"
check_endpoint "${VERIFIER}/meta"      200 "PV /meta"           "mode"
check_json_array "${VERIFIER}/verdicts" 200 "PV /verdicts"

# ── template-manager ─────────────────────────────────────────────────────────

info "template-manager (${TEMPLATE})"
check_text_endpoint "${TEMPLATE}/health"       200 "TM /health"            "ok"
check_endpoint "${TEMPLATE}/settings"          200 "TM /settings"          "backend"
check_endpoint "${TEMPLATE}/latest"             200 "TM /latest"            "block_height"
check_endpoint "${TEMPLATE}/mempool"            200 "TM /mempool"            "tx_count"

# ── sv2-gateway ──────────────────────────────────────────────────────────────

info "sv2-gateway (${GATEWAY})"
check_endpoint "${GATEWAY}/healthz"   200 "GW /healthz"   "status"
check_endpoint "${GATEWAY}/settings"  200 "GW /settings"  "gateway_mode"
check_json_array "${GATEWAY}/channels" 200 "GW /channels"

# ── rg-auth ──────────────────────────────────────────────────────────────────

info "rg-auth (${AUTH})"
check_endpoint "${AUTH}/auth/health"    200 "AUTH /auth/health"
check_endpoint "${AUTH}/auth/settings"  200 "AUTH /auth/settings" "bind_addr"

# ── rg-dashboard ─────────────────────────────────────────────────────────────

info "rg-dashboard (${DASHBOARD})"
check_endpoint "${DASHBOARD}/healthz"  200 "DASH /healthz"

# ── Dashboard proxy verification ─────────────────────────────────────────────
# Verify the dashboard proxies API calls to backend services correctly.

info "Dashboard proxy endpoints (${DASHBOARD})"
check_endpoint "${DASHBOARD}/api/health"            200 "DASH /api/health"             "services"
check_endpoint "${DASHBOARD}/api/verifier/stats"    200 "DASH /api/verifier/stats"     "total"
check_endpoint "${DASHBOARD}/api/verifier/settings" 200 "DASH /api/verifier/settings"  "log_level"
check_endpoint "${DASHBOARD}/api/templates/latest"  200 "DASH /api/templates/latest"   "block_height"
check_endpoint "${DASHBOARD}/api/gateway/settings"  200 "DASH /api/gateway/settings"   "gateway_mode"
check_endpoint "${DASHBOARD}/api/auth/settings"     200 "DASH /api/auth/settings"      "bind_addr"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
printf "  Endpoint Tests: ${GRN}%d passed${RST}" "$PASSED"
if [[ $FAILED -gt 0 ]]; then
  printf ", ${RED}%d failed${RST}" "$FAILED"
fi
if [[ $SKIPPED -gt 0 ]]; then
  printf ", ${YLW}%d skipped${RST}" "$SKIPPED"
fi
echo ""
echo "════════════════════════════════════════════════════════════"

if [[ $FAILED -gt 0 ]]; then
  exit 1
fi
exit 0
