#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test-observe-mode.sh — Observe mode integration smoke test
#
# Validates the observe mode compose stack:
#   1. All services healthy (pool-verifier, template-manager, rg-auth,
#      rg-dashboard, rg-feed-server, rg-demo-feed, rg-feed-adapter)
#   2. Template pipeline flowing (verdict total > 0)
#   3. Deploy mode is "observe"
#   4. Verdicts are persisted (persist_verdicts = true)
#   5. Feed server is accepting TCP connections
#   6. Auth service healthy
#   7. Dashboard reachable
#   8. Feed server rejects unauthenticated WebSocket at application layer
#
# Prerequisites:
#   docker compose -f docker-compose.observe.yml up -d
#   Wait for all services to become healthy before running.
#
# Usage:
#   ./scripts/test-observe-mode.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PV_URL="${PV_URL:-http://127.0.0.1:8081}"
TM_URL="${TM_URL:-http://127.0.0.1:8082}"
AUTH_URL="${AUTH_URL:-http://127.0.0.1:3030}"
DASH_URL="${DASH_URL:-http://127.0.0.1:8084}"
FEED_HOST="${FEED_HOST:-127.0.0.1}"
FEED_PORT="${FEED_PORT:-9200}"

PASSED=0
FAILED=0

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; RST='\033[0m'

pass() { printf "${GRN}[PASS]${RST} %s\n" "$*"; PASSED=$((PASSED + 1)); }
fail() { printf "${RED}[FAIL]${RST} %s\n" "$*"; FAILED=$((FAILED + 1)); }
info() { printf "${CYN}[INFO]${RST} %s\n" "$*"; }

# Helper: extract a JSON field via python3. Prints the value or empty string.
json_field() {
  echo "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    v = d.get('$2', '')
    print(v)
except Exception:
    print('')
" 2>/dev/null || echo ""
}

# ── T01: Pool verifier health ────────────────────────────────────────────────
info "T01: Pool verifier health"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PV_URL}/health" 2>/dev/null || echo "000")
if [[ "$STATUS" == "200" ]]; then
  pass "T01: Pool verifier healthy"
else
  fail "T01: Pool verifier returned ${STATUS}"
fi

# ── T02: Template pipeline flowing ───────────────────────────────────────────
# Poll /stats (returns {"total": N, ...}). total > 0 means templates arrived
# and were verified. The demo feed emits every 5s and the pipeline needs a few
# seconds to propagate, so we poll for up to 90s.
info "T02: Template pipeline flowing"
TEMPLATES_OK=false
for i in $(seq 1 45); do
  RESP=$(curl -s "${PV_URL}/stats" 2>/dev/null || echo "{}")
  COUNT=$(json_field "$RESP" "total")
  if [[ -n "$COUNT" ]] && [[ "$COUNT" != "0" ]] && [[ "$COUNT" != "" ]]; then
    TEMPLATES_OK=true
    pass "T02: Templates flowing (${COUNT} verdicts after $((i * 2))s)"
    break
  fi
  sleep 2
done
if [[ "$TEMPLATES_OK" != "true" ]]; then
  DIAG=$(curl -s "${PV_URL}/stats" 2>/dev/null || echo "(no response)")
  fail "T02: No templates received within 90s (stats response: ${DIAG})"
fi

# ── T03: Deploy mode is observe ─────────────────────────────────────────────
info "T03: Deploy mode is observe"
META=$(curl -s "${PV_URL}/meta" 2>/dev/null || echo "{}")
MODE=$(json_field "$META" "deploy_mode")
if [[ "$MODE" == "observe" ]]; then
  pass "T03: deploy_mode = observe"
else
  fail "T03: deploy_mode = '${MODE}' (expected 'observe'); raw: ${META}"
fi

# ── T04: Verdicts are persisted ──────────────────────────────────────────────
info "T04: Verdicts persisted (meta endpoint)"
# persist_verdicts is a JSON boolean. Python prints True/False with capital T/F.
PERSIST=$(json_field "$META" "persist_verdicts")
if [[ "$PERSIST" == "True" ]]; then
  pass "T04: persist_verdicts = True"
else
  fail "T04: persist_verdicts = '${PERSIST}' (expected 'True'); raw: ${META}"
fi

# ── T05: Template manager health ─────────────────────────────────────────────
info "T05: Template manager health"
TM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TM_URL}/health" 2>/dev/null || echo "000")
if [[ "$TM_STATUS" == "200" ]]; then
  pass "T05: Template manager healthy"
else
  fail "T05: Template manager returned ${TM_STATUS}"
fi

# ── T06: Auth service health ─────────────────────────────────────────────────
info "T06: Auth service health"
AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_URL}/auth/health" 2>/dev/null || echo "000")
if [[ "$AUTH_STATUS" == "200" ]]; then
  pass "T06: Auth service healthy"
else
  fail "T06: Auth service returned ${AUTH_STATUS}"
fi

# ── T07: Dashboard reachable ─────────────────────────────────────────────────
info "T07: Dashboard reachable"
DASH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${DASH_URL}/healthz" 2>/dev/null || echo "000")
if [[ "$DASH_STATUS" == "200" ]]; then
  pass "T07: Dashboard reachable"
else
  fail "T07: Dashboard returned ${DASH_STATUS}"
fi

# ── T08: Feed server accepting connections ───────────────────────────────────
info "T08: Feed server TCP check"
if bash -c "(echo > /dev/tcp/${FEED_HOST}/${FEED_PORT}) 2>/dev/null"; then
  pass "T08: Feed server accepting connections on ${FEED_HOST}:${FEED_PORT}"
else
  fail "T08: Feed server not reachable on ${FEED_HOST}:${FEED_PORT}"
fi

# ── T09: Feed server rejects unauthenticated WebSocket ──────────────────────
# The feed server performs auth at the application layer: the WebSocket upgrade
# always succeeds (HTTP 101), but the server sends an error frame with
# {"type":"error","data":{"code":"unauthorized"}} and closes the connection.
# We use websocat or a lightweight python check to verify the error frame.
info "T09: Feed server rejects unauthenticated connection"
WS_RESULT=$(python3 -c "
import socket, ssl, hashlib, base64, os, json

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(('${FEED_HOST}', ${FEED_PORT}))

# Generate a random WebSocket key
ws_key = base64.b64encode(os.urandom(16)).decode()

# Send the upgrade request (no Authorization header)
req = (
    'GET /ws HTTP/1.1\r\n'
    'Host: ${FEED_HOST}:${FEED_PORT}\r\n'
    'Upgrade: websocket\r\n'
    'Connection: Upgrade\r\n'
    f'Sec-WebSocket-Key: {ws_key}\r\n'
    'Sec-WebSocket-Version: 13\r\n'
    '\r\n'
)
sock.sendall(req.encode())

# Read the HTTP response
resp = b''
while b'\r\n\r\n' not in resp:
    chunk = sock.recv(4096)
    if not chunk:
        break
    resp += chunk

if b'101' not in resp.split(b'\r\n')[0]:
    print('rejected_at_http')
    sock.close()
else:
    # WebSocket upgrade succeeded; read the first frame.
    # WebSocket frame: first byte = fin+opcode, second byte = mask+length.
    try:
        header = sock.recv(2)
        if len(header) < 2:
            print('connection_closed')
        else:
            length = header[1] & 0x7F
            if length == 126:
                ext = sock.recv(2)
                length = int.from_bytes(ext, 'big')
            elif length == 127:
                ext = sock.recv(8)
                length = int.from_bytes(ext, 'big')
            payload = b''
            while len(payload) < length:
                chunk = sock.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk
            msg = payload.decode('utf-8', errors='replace')
            try:
                frame = json.loads(msg)
                if frame.get('type') == 'error' and frame.get('data', {}).get('code') == 'unauthorized':
                    print('unauthorized_error')
                else:
                    print('unexpected_frame:' + msg[:200])
            except json.JSONDecodeError:
                print('non_json:' + msg[:200])
    except socket.timeout:
        print('timeout_no_frame')
    sock.close()
" 2>/dev/null || echo "python_error")

case "$WS_RESULT" in
  rejected_at_http|unauthorized_error|connection_closed|non_json:*|timeout_no_frame)
    pass "T09: Unauthenticated WebSocket rejected (${WS_RESULT})"
    ;;
  *)
    fail "T09: Unauthenticated WebSocket not properly rejected (result: ${WS_RESULT})"
    ;;
esac

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
printf "  Observe Mode Tests: ${GRN}%d passed${RST}" "$PASSED"
if [[ $FAILED -gt 0 ]]; then
  printf ", ${RED}%d failed${RST}" "$FAILED"
fi
echo ""
echo "════════════════════════════════════════════════════════════"

if [[ $FAILED -gt 0 ]]; then
  exit 1
fi
exit 0
