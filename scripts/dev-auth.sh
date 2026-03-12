#!/usr/bin/env bash
set -euo pipefail
# ── dev-auth.sh ─────────────────────────────────────
# Start rg-auth for local development.
# SMTP is not required — emails print to stdout.
# ────────────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_BIN="${ROOT_DIR}/target/debug/rg-auth"

if [[ ! -f "$AUTH_BIN" ]]; then
  echo "[dev-auth] Building rg-auth..."
  cargo build -p rg-auth
fi

mkdir -p "${ROOT_DIR}/data"

export VELDRA_AUTH_ADDR="${VELDRA_AUTH_ADDR:-127.0.0.1:3030}"
export VELDRA_AUTH_DB="${VELDRA_AUTH_DB:-${ROOT_DIR}/data/auth.db}"
export VELDRA_AUTH_ADMIN_EMAIL="${VELDRA_AUTH_ADMIN_EMAIL:-admin@localhost}"
export VELDRA_AUTH_SITE_URL="${VELDRA_AUTH_SITE_URL:-http://localhost:8000}"
export VELDRA_AUTH_URL="${VELDRA_AUTH_URL:-http://127.0.0.1:3030}"
export VELDRA_AUTH_ALLOWED_ORIGIN="${VELDRA_AUTH_ALLOWED_ORIGIN:-*}"
export VELDRA_AUTH_SESSION_TTL_HOURS="${VELDRA_AUTH_SESSION_TTL_HOURS:-168}"

echo "────────────────────────────────────────"
echo "  rg-auth dev server"
echo "  addr:   ${VELDRA_AUTH_ADDR}"
echo "  db:     ${VELDRA_AUTH_DB}"
echo "  admin:  ${VELDRA_AUTH_ADMIN_EMAIL}"
echo "  origin: ${VELDRA_AUTH_ALLOWED_ORIGIN}"
echo "────────────────────────────────────────"
echo ""
echo "  Observe page: open with ?auth=http://${VELDRA_AUTH_ADDR}"
echo "  SMTP not configured — verification emails print to stdout."
echo ""

exec "$AUTH_BIN"
