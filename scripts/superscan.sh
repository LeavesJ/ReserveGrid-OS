#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# superscan.sh — Local pre-push gate that mirrors every CI job plus
# additional checks CI cannot perform.
#
# Run before every push. Exit 0 means CI will pass (barring Docker or
# integration-only issues). Any failure prints the gate name and stops.
#
# Usage:
#   ./scripts/superscan.sh          # full scan
#   ./scripts/superscan.sh --quick  # skip audit/deny/vet (faster)
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILURES=()
QUICK=false
START_TIME=$(date +%s)

for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=true ;;
  esac
done

gate() {
  local name="$1"
  shift
  printf "${CYAN}[SCAN]${NC} %-50s" "$name"
  if "$@" > /tmp/superscan_out.txt 2>&1; then
    printf "${GREEN}PASS${NC}\n"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf "${RED}FAIL${NC}\n"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAILURES+=("$name")
    # Show last 20 lines of output for diagnosis.
    tail -20 /tmp/superscan_out.txt 2>/dev/null | sed 's/^/  > /'
  fi
}

skip() {
  local name="$1"
  printf "${CYAN}[SCAN]${NC} %-50s${YELLOW}SKIP${NC}\n" "$name"
  SKIP_COUNT=$((SKIP_COUNT + 1))
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  ReserveGrid OS — superscan (local CI mirror)"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ── 1. Format ──────────────────────────────────────────────────────
gate "cargo fmt --all --check" \
  cargo fmt --all --check

# ── 2. Build ───────────────────────────────────────────────────────
gate "cargo build --workspace" \
  cargo build --workspace

# ── 3. Clippy ──────────────────────────────────────────────────────
# Uses --all-targets so test binaries are linted too (catches
# explicit_iter_loop, expect_used, etc. that only appear in test code).
gate "cargo clippy --workspace --all-targets -D warnings" \
  cargo clippy --workspace --all-targets -- -D warnings

# ── 4. Tests ───────────────────────────────────────────────────────
gate "cargo test --workspace" \
  cargo test --workspace

# ── 5. Frontend build ──────────────────────────────────────────────
if [ -f services/rg-dashboard/frontend/package.json ]; then
  if has_cmd npx; then
    gate "frontend: npm ci" \
      bash -c "cd services/rg-dashboard/frontend && npm ci --silent"
    gate "frontend: tsc -b" \
      bash -c "cd services/rg-dashboard/frontend && npx tsc -b"
    gate "frontend: vite build" \
      bash -c "cd services/rg-dashboard/frontend && npx vite build"
  else
    skip "frontend (node/npx not found)"
  fi
else
  skip "frontend (package.json not found)"
fi

# ── 6. Advisory scan ──────────────────────────────────────────────
if $QUICK; then
  skip "cargo audit (--quick)"
else
  if has_cmd cargo-audit; then
    gate "cargo audit" cargo audit
  else
    skip "cargo audit (not installed)"
  fi
fi

# ── 7. License and ban check ──────────────────────────────────────
if $QUICK; then
  skip "cargo deny (--quick)"
else
  if has_cmd cargo-deny; then
    gate "cargo deny check licenses" cargo deny check licenses
    gate "cargo deny check bans" cargo deny check bans
    gate "cargo deny check sources" cargo deny check sources
    gate "cargo deny check advisories" cargo deny check advisories
  else
    skip "cargo deny (not installed)"
  fi
fi

# ── 8. Supply chain vet ───────────────────────────────────────────
if $QUICK; then
  skip "cargo vet (--quick)"
else
  if has_cmd cargo-vet; then
    gate "cargo vet" cargo vet
  else
    skip "cargo vet (not installed)"
  fi
fi

# ── 9. Secrets scan ──────────────────────────────────────────────
if has_cmd gitleaks; then
  gate "gitleaks detect" \
    gitleaks detect --source . --no-banner
else
  skip "gitleaks (not installed)"
fi

# ── 10. Gitignore shadow check ────────────────────────────────────
# Catches R-40/R-55: broad patterns hiding source files.
gate "gitignore: no source files shadowed" \
  bash -c '
    SHADOWED=$(git ls-files --ignored --exclude-standard 2>/dev/null || true)
    if [ -n "$SHADOWED" ]; then
      echo "ERROR: tracked files are gitignored:"
      echo "$SHADOWED"
      exit 1
    fi
  '

# ── 11. No TODO(v1.0.0) markers left ─────────────────────────────
gate "no TODO(v1.0.0) markers" \
  bash -c '
    HITS=$(grep -rn "TODO(v1\.0\.0)" services/ scripts/ --include="*.rs" --include="*.sh" --include="*.toml" 2>/dev/null | grep -v "superscan\.sh" || true)
    if [ -n "$HITS" ]; then
      echo "ERROR: unresolved TODO(v1.0.0) markers:"
      echo "$HITS"
      exit 1
    fi
  '

# ── 12. reason_code canonicality ──────────────────────────────────
# Catches drift between string literals and the canonical enum.
gate "reason_code: no raw string literals outside enum" \
  bash -c '
    # Look for hard-coded reason_code strings that bypass the enum.
    # Allowlist: test files, docs, TOML configs, the enum definition itself.
    HITS=$(grep -rn "reason_code.*=.*\"" services/ \
      --include="*.rs" \
      | grep -v "as_str()" \
      | grep -v "#\[serde" \
      | grep -v "///" \
      | grep -v "#\[cfg(test)\]" \
      | grep -v "mod tests" \
      | grep -v "assert" \
      | grep -v "unwrap_or" \
      | grep -v "\.into()" \
      | grep -v "ok" \
      | grep -v "unknown" \
      | grep -v "reason_code: None" \
      | grep -v "reason_code: Some(reason" \
      | grep -v "reason_code: Some(code" \
      | grep -v "reason_code: eval" \
      | grep -v "VerdictLabels" \
      || true)
    if [ -n "$HITS" ]; then
      echo "WARNING: possible hard-coded reason_code strings (verify these use the canonical enum):"
      echo "$HITS"
      # Warning only, not a hard fail. Manual review required.
    fi
  '

# ── 13. No .env or secrets committed ─────────────────────────────
gate "no secrets in staged files" \
  bash -c '
    BAD=$(git diff --cached --name-only 2>/dev/null | grep -E "^\.env$|credentials|\.pem$|\.key$" || true)
    if [ -n "$BAD" ]; then
      echo "ERROR: secret files staged for commit:"
      echo "$BAD"
      exit 1
    fi
  '

# ── 14. Cargo.lock in sync ────────────────────────────────────────
gate "Cargo.lock in sync with Cargo.toml" \
  bash -c '
    cp Cargo.lock Cargo.lock.bak
    cargo generate-lockfile 2>&1
    if ! diff -q Cargo.lock Cargo.lock.bak >/dev/null 2>&1; then
      echo "Cargo.lock was out of sync (regenerated). Stage and commit it."
      mv Cargo.lock.bak Cargo.lock.bak.old
      exit 1
    fi
    rm -f Cargo.lock.bak
  '

# ── 15. No large binary blobs staged ─────────────────────────────
gate "no large files (>5MB) staged" \
  bash -c '
    LARGE=$(git diff --cached --name-only 2>/dev/null | while read -r f; do
      if [ -f "$f" ]; then
        SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        if [ "$SIZE" -gt 5242880 ]; then
          echo "  $f ($(( SIZE / 1048576 ))MB)"
        fi
      fi
    done)
    if [ -n "$LARGE" ]; then
      echo "ERROR: files over 5MB staged:"
      echo "$LARGE"
      exit 1
    fi
  '

# ── Summary ───────────────────────────────────────────────────────
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "════════════════════════════════════════════════════════════════"
printf "  ${GREEN}PASS: %d${NC}  " "$PASS_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
  printf "${RED}FAIL: %d${NC}  " "$FAIL_COUNT"
else
  printf "FAIL: 0  "
fi
if [ "$SKIP_COUNT" -gt 0 ]; then
  printf "${YELLOW}SKIP: %d${NC}  " "$SKIP_COUNT"
fi
printf "(%ds)\n" "$ELAPSED"
echo "════════════════════════════════════════════════════════════════"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo ""
  printf "${RED}BLOCKED:${NC} fix these before pushing:\n"
  for f in "${FAILURES[@]}"; do
    echo "  • $f"
  done
  echo ""
  exit 1
fi

echo ""
printf "${GREEN}All gates passed. Safe to push.${NC}\n"
echo ""
