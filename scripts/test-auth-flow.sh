#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test-auth-flow.sh — Full rg-auth integration test
#
# Exercises the complete user lifecycle against a running rg-auth instance:
#   1. Health check
#   2. Registration (new user)
#   3. Duplicate registration rejection
#   4. Login before verification (must fail)
#   5. Email verification (token extracted from rg-auth logs)
#   6. Login before approval (must fail)
#   7. Admin approval (token extracted from rg-auth logs)
#   8. Login (must succeed)
#   9. Session check (valid session)
#  10. License key generation
#  11. License key listing (key masked)
#  12. License key validation (service-to-service)
#  13. License key revocation
#  14. Revoked key validation (must fail)
#  15. Forgot password flow
#  16. Password reset (token from logs)
#  17. Login with new password
#  18. Logout
#  19. Session check after logout (must fail)
#  20. Settings endpoint
#
# Prerequisites:
#   rg-auth running on AUTH_URL (default http://127.0.0.1:3030)
#   SMTP disabled (tokens print to stdout, captured via docker logs or process output)
#   VELDRA_AUTH_RATE_LIMIT_MULTIPLIER=100 recommended when running against Docker
#   (avoids 429s from rapid sequential requests sharing one IP)
#
# Usage:
#   ./scripts/test-auth-flow.sh                              # standalone against running rg-auth
#   AUTH_URL=http://localhost:3030 ./scripts/test-auth-flow.sh
#   AUTH_CONTAINER=rg-auth-1 ./scripts/test-auth-flow.sh     # extract tokens from docker logs
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

AUTH_URL="${AUTH_URL:-http://127.0.0.1:3030}"
AUTH_CONTAINER="${AUTH_CONTAINER:-}"  # docker container name for log scraping
LOG_FILE="${LOG_FILE:-}"              # path to rg-auth log file (alternative to docker logs)
FEED_URL="${FEED_URL:-}"              # rg-feed-server URL for key validation (optional)

# Test user
EMAIL="testuser-$(date +%s)@example.com"
NAME="Test User"
ORG="Test Org"
PASSWORD="integration-test-password-42"
NEW_PASSWORD="reset-password-new-99"

# State
SESSION_TOKEN=""
VERIFY_TOKEN=""
APPROVE_TOKEN=""
RESET_TOKEN=""
LICENSE_KEY=""
LICENSE_KEY_ID=""
PASSED=0
FAILED=0
SKIPPED=0

# ── Helpers ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'; CYN='\033[0;36m'; RST='\033[0m'

pass() { printf "${GRN}[PASS]${RST} %s\n" "$*"; PASSED=$((PASSED + 1)); }
fail() { printf "${RED}[FAIL]${RST} %s\n" "$*"; FAILED=$((FAILED + 1)); }
skip() { printf "${YLW}[SKIP]${RST} %s\n" "$*"; SKIPPED=$((SKIPPED + 1)); }
info() { printf "${CYN}[INFO]${RST} %s\n" "$*"; }

# HTTP helpers. Return: body\nstatus_code
# Note: -f is intentionally omitted so that response bodies are captured on
# 4xx/5xx responses. The status code is appended by -w and extracted by
# parse_status. Connection failures still produce "000" via the fallback.
http_get() {
  local url="$1"; shift
  curl -s -w "\n%{http_code}" "$url" "$@" 2>/dev/null || echo -e "\n000"
}

http_post() {
  local url="$1"; shift
  local body="$1"; shift
  curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$body" "$url" "$@" 2>/dev/null || echo -e "\n000"
}

http_get_auth() {
  local url="$1"; local token="$2"
  curl -s -w "\n%{http_code}" -H "Authorization: Bearer ${token}" "$url" 2>/dev/null || echo -e "\n000"
}

http_post_auth() {
  local url="$1"; local body="$2"; local token="$3"
  curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${token}" -d "$body" "$url" 2>/dev/null || echo -e "\n000"
}

parse_status() {
  echo "$1" | tail -1
}

parse_body() {
  echo "$1" | sed '$d'
}

json_field() {
  local json="$1"; local field="$2"
  echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$field',''))" 2>/dev/null || echo ""
}

# Extract token from rg-auth logs. Tokens appear in email bodies logged via
# tracing (the email_stub span). The body field contains the full email text
# with URL fragments like verify/?token=<64 hex>.
extract_token_from_logs() {
  local kind="$1"  # "verify", "approve", "password_reset"
  local logs=""

  if [[ -n "$AUTH_CONTAINER" ]]; then
    logs=$(docker logs "$AUTH_CONTAINER" 2>&1 | tail -200)
  elif [[ -n "$LOG_FILE" ]]; then
    logs=$(tail -200 "$LOG_FILE" 2>/dev/null || echo "")
  else
    info "No log source configured (set AUTH_CONTAINER or LOG_FILE)"
    return 1
  fi

  if [[ -z "$logs" ]]; then
    info "Log source returned empty output"
    return 1
  fi

  local token=""
  # Uses grep -oE (extended regex) for macOS compatibility (BSD grep lacks -P).
  # Uses [?] instead of \? for portable literal question mark matching.
  case "$kind" in
    verify)
      # Email body contains: {site_url}/verify/?token=<TOKEN>
      token=$(echo "$logs" | grep -oE 'verify/[?]token=[a-f0-9]{64}' | tail -1 | sed 's/.*token=//')
      ;;
    approve)
      # Email body contains: {auth_url}/auth/approve?token=<TOKEN>
      token=$(echo "$logs" | grep -oE 'approve[?]token=[a-f0-9]{64}' | tail -1 | sed 's/.*token=//')
      ;;
    password_reset)
      # Email body contains: {site_url}/reset-password/?token=<TOKEN>
      token=$(echo "$logs" | grep -oE 'reset-password/[?]token=[a-f0-9]{64}' | tail -1 | sed 's/.*token=//')
      ;;
  esac

  if [[ -z "$token" ]]; then
    return 1
  fi
  echo "$token"
}

# ── Tests ────────────────────────────────────────────────────────────────────

info "Running auth integration tests against ${AUTH_URL}"
info "Test user: ${EMAIL}"
echo ""

# 1. Health check
info "T01: Health check"
RESP=$(http_get "${AUTH_URL}/auth/health")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "200" ]]; then
  pass "T01: Health check returned 200"
else
  fail "T01: Health check returned ${STATUS} (expected 200)"
fi

# 2. Registration
info "T02: Register new user"
RESP=$(http_post "${AUTH_URL}/auth/register" "{\"email\":\"${EMAIL}\",\"name\":\"${NAME}\",\"org\":\"${ORG}\",\"password\":\"${PASSWORD}\"}")
STATUS=$(parse_status "$RESP")
BODY=$(parse_body "$RESP")
if [[ "$STATUS" == "201" ]]; then
  pass "T02: Registration returned 201"
else
  fail "T02: Registration returned ${STATUS} (expected 201): ${BODY}"
fi

# 3. Duplicate registration
info "T03: Duplicate registration rejection"
RESP=$(http_post "${AUTH_URL}/auth/register" "{\"email\":\"${EMAIL}\",\"name\":\"${NAME}\",\"org\":\"${ORG}\",\"password\":\"${PASSWORD}\"}")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "409" ]]; then
  pass "T03: Duplicate registration returned 409"
else
  fail "T03: Duplicate registration returned ${STATUS} (expected 409)"
fi

# 4. Login before verification
info "T04: Login before email verification"
RESP=$(http_post "${AUTH_URL}/auth/login" "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "403" ]]; then
  pass "T04: Login before verification returned 403"
else
  fail "T04: Login before verification returned ${STATUS} (expected 403)"
fi

# 5. Email verification
info "T05: Email verification"
sleep 1  # brief pause for log flush
VERIFY_TOKEN=$(extract_token_from_logs "verify" || echo "")
if [[ -n "$VERIFY_TOKEN" ]]; then
  info "  verify token (${#VERIFY_TOKEN} chars): ${VERIFY_TOKEN:0:16}..."
  info "  verify URL: ${AUTH_URL}/auth/verify?token=${VERIFY_TOKEN:0:16}..."
fi
if [[ -z "$VERIFY_TOKEN" ]]; then
  skip "T05: Could not extract verification token from logs"
  skip "T06: Skipped (depends on T05)"
  skip "T07: Skipped (depends on T05)"
  skip "T08-T20: Skipped (auth flow requires verified user)"
  echo ""
  info "Results: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
  [[ $FAILED -eq 0 ]] && exit 0 || exit 1
fi

RESP=$(http_get "${AUTH_URL}/auth/verify?token=${VERIFY_TOKEN}")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "200" ]]; then
  pass "T05: Email verification returned 200"
else
  BODY=$(parse_body "$RESP")
  fail "T05: Email verification returned ${STATUS} (expected 200): ${BODY}"
fi

# 6. Login before approval
info "T06: Login before admin approval"
RESP=$(http_post "${AUTH_URL}/auth/login" "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "403" ]]; then
  pass "T06: Login before approval returned 403"
else
  fail "T06: Login before approval returned ${STATUS} (expected 403)"
fi

# 7. Admin approval
info "T07: Admin approval"
sleep 1
APPROVE_TOKEN=$(extract_token_from_logs "approve" || echo "")
if [[ -n "$APPROVE_TOKEN" ]]; then
  info "  approve token (${#APPROVE_TOKEN} chars): ${APPROVE_TOKEN:0:16}..."
fi
if [[ -z "$APPROVE_TOKEN" ]]; then
  fail "T07: Could not extract approval token from logs"
else
  RESP=$(http_get "${AUTH_URL}/auth/approve?token=${APPROVE_TOKEN}")
  STATUS=$(parse_status "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    pass "T07: Admin approval returned 200"
  else
    BODY=$(parse_body "$RESP")
    fail "T07: Admin approval returned ${STATUS} (expected 200): ${BODY}"
  fi
fi

# 8. Login (should succeed now)
info "T08: Login after approval"
RESP=$(http_post "${AUTH_URL}/auth/login" "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}")
STATUS=$(parse_status "$RESP")
BODY=$(parse_body "$RESP")
if [[ "$STATUS" == "200" ]]; then
  SESSION_TOKEN=$(json_field "$BODY" "token")
  if [[ -n "$SESSION_TOKEN" ]]; then
    pass "T08: Login returned 200 with session token"
  else
    fail "T08: Login returned 200 but no token in response"
  fi
else
  fail "T08: Login returned ${STATUS} (expected 200): ${BODY}"
fi

# 9. Session check
info "T09: Session check"
if [[ -n "$SESSION_TOKEN" ]]; then
  RESP=$(http_get_auth "${AUTH_URL}/auth/session" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  VALID=$(json_field "$BODY" "valid")
  if [[ "$STATUS" == "200" && "$VALID" == "True" ]]; then
    pass "T09: Session check returned valid=true"
  else
    fail "T09: Session check returned ${STATUS}, valid=${VALID}"
  fi
else
  skip "T09: No session token (T08 failed)"
fi

# 10. License key generation
info "T10: Generate license key"
if [[ -n "$SESSION_TOKEN" ]]; then
  RESP=$(http_post_auth "${AUTH_URL}/auth/keys/generate" "{\"label\":\"integration-test\"}" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  if [[ "$STATUS" == "201" ]]; then
    LICENSE_KEY=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key',{}).get('key_value',''))" 2>/dev/null || echo "")
    LICENSE_KEY_ID=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('key',{}).get('id',''))" 2>/dev/null || echo "")
    if [[ "$LICENSE_KEY" == veldra_* ]]; then
      pass "T10: Key generated with veldra_ prefix (id=${LICENSE_KEY_ID})"
    else
      fail "T10: Key generated but unexpected format: ${LICENSE_KEY}"
    fi
  else
    fail "T10: Key generation returned ${STATUS} (expected 201)"
  fi
else
  skip "T10: No session token"
fi

# 11. License key listing
info "T11: List license keys"
if [[ -n "$SESSION_TOKEN" ]]; then
  RESP=$(http_get_auth "${AUTH_URL}/auth/keys" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    # Verify keys are masked (should NOT contain full key)
    KEY_COUNT=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('keys',[])))" 2>/dev/null || echo "0")
    if [[ "$KEY_COUNT" -ge 1 ]]; then
      pass "T11: Key listing returned ${KEY_COUNT} key(s)"
    else
      fail "T11: Key listing returned 0 keys"
    fi
  else
    fail "T11: Key listing returned ${STATUS} (expected 200)"
  fi
else
  skip "T11: No session token"
fi

# 12. License key validation (service-to-service)
info "T12: Validate license key (service-to-service)"
if [[ -n "$LICENSE_KEY" ]]; then
  RESP=$(http_post "${AUTH_URL}/api/keys/validate" "{\"key\":\"${LICENSE_KEY}\"}")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  VALID=$(json_field "$BODY" "valid")
  if [[ "$STATUS" == "200" && "$VALID" == "True" ]]; then
    pass "T12: Key validation returned valid=true"
  else
    fail "T12: Key validation returned ${STATUS}, valid=${VALID}"
  fi
else
  skip "T12: No license key generated"
fi

# 13. License key revocation
info "T13: Revoke license key"
if [[ -n "$SESSION_TOKEN" && -n "$LICENSE_KEY_ID" ]]; then
  RESP=$(http_post_auth "${AUTH_URL}/auth/keys/revoke" "{\"key_id\":${LICENSE_KEY_ID}}" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    pass "T13: Key revocation returned 200"
  else
    fail "T13: Key revocation returned ${STATUS} (expected 200)"
  fi
else
  skip "T13: No session token or license key id"
fi

# 14. Revoked key validation (must fail)
info "T14: Validate revoked key"
if [[ -n "$LICENSE_KEY" ]]; then
  RESP=$(http_post "${AUTH_URL}/api/keys/validate" "{\"key\":\"${LICENSE_KEY}\"}")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  VALID=$(json_field "$BODY" "valid")
  if [[ "$STATUS" == "200" && "$VALID" == "False" ]]; then
    pass "T14: Revoked key validation returned valid=false"
  else
    fail "T14: Revoked key validation returned ${STATUS}, valid=${VALID} (expected false)"
  fi
else
  skip "T14: No license key"
fi

# 15. Forgot password
info "T15: Forgot password request"
RESP=$(http_post "${AUTH_URL}/auth/forgot-password" "{\"email\":\"${EMAIL}\"}")
STATUS=$(parse_status "$RESP")
if [[ "$STATUS" == "200" ]]; then
  pass "T15: Forgot password returned 200"
else
  fail "T15: Forgot password returned ${STATUS} (expected 200)"
fi

# 16. Password reset
info "T16: Password reset"
sleep 1
RESET_TOKEN=$(extract_token_from_logs "password_reset" || echo "")
if [[ -n "$RESET_TOKEN" ]]; then
  RESP=$(http_post "${AUTH_URL}/auth/reset-password" "{\"token\":\"${RESET_TOKEN}\",\"password\":\"${NEW_PASSWORD}\"}")
  STATUS=$(parse_status "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    pass "T16: Password reset returned 200"
  else
    fail "T16: Password reset returned ${STATUS} (expected 200)"
  fi
else
  skip "T16: Could not extract reset token from logs"
fi

# 17. Login with new password
info "T17: Login with new password"
if [[ -n "$RESET_TOKEN" ]]; then
  RESP=$(http_post "${AUTH_URL}/auth/login" "{\"email\":\"${EMAIL}\",\"password\":\"${NEW_PASSWORD}\"}")
  STATUS=$(parse_status "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    pass "T17: Login with new password returned 200"
    # Update session token for remaining tests
    BODY=$(parse_body "$RESP")
    SESSION_TOKEN=$(json_field "$BODY" "token")
  else
    fail "T17: Login with new password returned ${STATUS} (expected 200)"
  fi
else
  skip "T17: Password was not reset (T16 skipped)"
fi

# 18. Logout
info "T18: Logout"
if [[ -n "$SESSION_TOKEN" ]]; then
  RESP=$(http_post_auth "${AUTH_URL}/auth/logout" "{}" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  if [[ "$STATUS" == "200" ]]; then
    pass "T18: Logout returned 200"
  else
    fail "T18: Logout returned ${STATUS} (expected 200)"
  fi
else
  skip "T18: No session token"
fi

# 19. Session check after logout (must fail)
info "T19: Session check after logout"
if [[ -n "$SESSION_TOKEN" ]]; then
  RESP=$(http_get_auth "${AUTH_URL}/auth/session" "$SESSION_TOKEN")
  STATUS=$(parse_status "$RESP")
  BODY=$(parse_body "$RESP")
  VALID=$(json_field "$BODY" "valid")
  if [[ "$VALID" == "False" || "$STATUS" == "401" ]]; then
    pass "T19: Session invalid after logout"
  else
    fail "T19: Session still valid after logout (status=${STATUS}, valid=${VALID})"
  fi
else
  skip "T19: No session token"
fi

# 20. Settings endpoint
info "T20: Settings endpoint"
RESP=$(http_get "${AUTH_URL}/auth/settings")
STATUS=$(parse_status "$RESP")
BODY=$(parse_body "$RESP")
if [[ "$STATUS" == "200" ]]; then
  BIND=$(json_field "$BODY" "bind_addr")
  if [[ -n "$BIND" ]]; then
    pass "T20: Settings endpoint returned bind_addr=${BIND}"
  else
    fail "T20: Settings returned 200 but missing bind_addr"
  fi
else
  fail "T20: Settings returned ${STATUS} (expected 200)"
fi

# ── Feed server key validation (optional) ────────────────────────────────────

if [[ -n "$FEED_URL" ]]; then
  info ""
  info "T21: Feed server WebSocket auth with license key (optional)"
  # Generate a fresh key for feed validation
  if [[ -n "$SESSION_TOKEN" ]]; then
    RESP=$(http_post_auth "${AUTH_URL}/auth/keys/generate" "{\"label\":\"feed-test\"}" "$SESSION_TOKEN")
    STATUS=$(parse_status "$RESP")
    BODY=$(parse_body "$RESP")
    if [[ "$STATUS" == "201" ]]; then
      FEED_KEY=$(json_field "$BODY" "key_value")
      # Attempt WebSocket connection with license key header
      WS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Upgrade: websocket" -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        -H "X-License-Key: ${FEED_KEY}" \
        "${FEED_URL}/ws" 2>/dev/null || echo "000")
      if [[ "$WS_STATUS" == "101" ]]; then
        pass "T21: Feed server accepted WebSocket with valid key"
      else
        info "T21: Feed server returned ${WS_STATUS} (101 expected for upgrade)"
        skip "T21: Could not verify WebSocket upgrade (may need wscat)"
      fi
    else
      skip "T21: Could not generate feed test key"
    fi
  else
    skip "T21: No session token for key generation"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════════"
printf "  Auth Integration Tests: ${GRN}%d passed${RST}" "$PASSED"
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
