#!/usr/bin/env bash
# ReserveGrid OS mechanical gate.
#
# Every check here used to be a prose rule in docs/lessons.md that the model was
# asked to remember. It is a script now so it fails loudly instead.
#
#   ./scripts/gate.sh           full gate (fmt, clippy, test, guards)
#   ./scripts/gate.sh --quick   skip the test suite
#
# Exit 0 means every check passed. Exit 1 lists what did not.
# Mirrors .github/workflows/ci.yml; keep the two in step.

set -uo pipefail

# Root of the tree being gated. Defaults to this script's parent, which is
# right when it is invoked as <repo>/scripts/gate.sh. FELIX_GATE_ROOT
# overrides it, because Felix stores the canonical copy OUTSIDE any repo
# and cd's to the checkout being gated first: without the override this
# would resolve to the Felix projects directory and report a verdict about
# the wrong tree, which is a false pass.
REPO_ROOT="${FELIX_GATE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_ROOT" || exit 2

QUICK=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

FAILED=""
pass() { printf '  %-18s ok\n' "$1"; }
fail() { printf '  %-18s FAIL\n' "$1"; FAILED="$FAILED $1"; }
note() { printf '  %-18s %s\n' "" "$1"; }

# Cargo excludes rg-desktop from headless jobs: the Tauri crate needs a display
# and system webkit. CI does the same. Do not drop this flag.
# shellcheck disable=SC2086  # CARGO_SCOPE is two flags and must word split.
CARGO_SCOPE="--workspace --exclude rg-desktop"

echo "gate: $REPO_ROOT"

# --------------------------------------------------------------- logs --------
# Every log below is this run's own, made by mktemp, never a path another gate
# can open. They were fixed paths under /tmp shared by every gate on the
# machine, and several sessions gate worktrees at once: each opened the file
# with O_TRUNC and wrote at its own offset, so a gate could print another
# tree's clippy errors or failing tests. Measured 2026-09-21 on Felix's own
# gate, which printed "2645 passed" for a suite that had passed 2586. The
# verdict was never wrong, being each command's exit status; the evidence
# under it could belong to another run. A log is deleted once nothing points
# at it, and kept on a failure, where its path is printed.
LOG_DIR="${TMPDIR:-/tmp}"; LOG_DIR="${LOG_DIR%/}"
newlog() {
  local f
  f="$(mktemp "$LOG_DIR/rg-gate-$2.XXXXXX" 2>/dev/null)" && [ -n "$f" ] || return 1
  printf -v "$1" '%s' "$f"
}

# ---------------------------------------------------------------- fmt --------
# R-166: run the formatter, do not --check and hand-chase its complaints.
# Rustfmt rewrites in place, so the gate reports what it touched for staging.
# Ask rustfmt what it WOULD rewrite, then rewrite, and report only what IT named.
#
# This used to run the formatter and then report `git diff --name-only --
# '*.rs'`, which conflates "rustfmt rewrote this" with "this file has
# uncommitted work". Mid-task that is every .rs file being edited, so the check
# went red and listed files rustfmt never touched. Elenchus's gate had the same
# defect and fixed it 2026-08-05. --check prints `Diff in <path>:<line>:` once
# per hunk, the path absolute and canonical, so /tmp arrives as /private/tmp on
# macOS: checked 2026-09-21 against rustfmt on toolchains 1.85, 1.92 (the
# pin) and stable. A file with two hunks is named twice and listed once.
FMT_CHECK_LOG=""; FMT_LOG=""
if ! newlog FMT_CHECK_LOG fmt-check || ! newlog FMT_LOG fmt; then
  fail fmt
  note "could not make a log file under $LOG_DIR"
  rm -f "$FMT_CHECK_LOG"
else
  cargo fmt --all -- --check >"$FMT_CHECK_LOG" 2>&1
  FMT_CHECK_STATUS=$?
  WOULD_FMT="$(FMT_P="$(pwd -P)/" FMT_L="$REPO_ROOT/" awk '
    /^Diff in .*:[0-9]+:$/ {
      p = substr($0, 9); sub(/:[0-9]+:$/, "", p)
      if (index(p, ENVIRON["FMT_P"]) == 1) p = substr(p, length(ENVIRON["FMT_P"]) + 1)
      else if (index(p, ENVIRON["FMT_L"]) == 1) p = substr(p, length(ENVIRON["FMT_L"]) + 1)
      if (!seen[p]++) print p
    }' "$FMT_CHECK_LOG")"
  if ! cargo fmt --all >"$FMT_LOG" 2>&1; then
    fail fmt
    tail -20 "$FMT_LOG" | sed 's/^/    /'
    note "full log: $FMT_LOG"
    rm -f "$FMT_CHECK_LOG"
  elif [ "$FMT_CHECK_STATUS" -eq 0 ]; then
    pass fmt
    rm -f "$FMT_CHECK_LOG" "$FMT_LOG"
  elif [ -n "$WOULD_FMT" ]; then
    fail fmt
    note "rustfmt rewrote $(printf '%s\n' "$WOULD_FMT" | wc -l | tr -d ' ') file(s); review and stage them"
    printf '%s\n' "$WOULD_FMT" | sed 's/^/    /'
    rm -f "$FMT_CHECK_LOG" "$FMT_LOG"
  else
    # rustfmt wanted changes but this parse did not recognise its output. The
    # `Diff in` shape is coupled to the rustfmt version, so its failure mode
    # must be a loud gate, never a silent green one.
    fail fmt
    note "cargo fmt --check exited $FMT_CHECK_STATUS but no filename parsed"
    note "full log: $FMT_CHECK_LOG"
    note "the Diff in parse above needs updating for this rustfmt"
    rm -f "$FMT_LOG"
  fi
fi

# ------------------------------------------------------------- clippy --------
# --all-targets is load bearing: it covers integration tests in tests/, which
# lib-only and bin-only invocations skip. --workspace is load bearing: per crate
# invocations skip cross crate doc references.
CLIPPY_LOG=""
if ! newlog CLIPPY_LOG clippy; then
  fail clippy
  note "could not make a log file under $LOG_DIR"
elif cargo clippy $CARGO_SCOPE --all-targets -- -D warnings >"$CLIPPY_LOG" 2>&1; then
  pass clippy
  rm -f "$CLIPPY_LOG"
else
  fail clippy
  grep -E '^(error|warning)' "$CLIPPY_LOG" | head -20 | sed 's/^/    /'
  note "full log: $CLIPPY_LOG"
fi

# --------------------------------------------------------------- test --------
TEST_LOG=""
if [ "$QUICK" -eq 1 ]; then
  printf '  %-18s skipped (--quick)\n' test
elif ! newlog TEST_LOG test; then
  fail test
  note "could not make a log file under $LOG_DIR"
elif cargo test $CARGO_SCOPE >"$TEST_LOG" 2>&1; then
  pass test
  rm -f "$TEST_LOG"
else
  fail test
  grep -E '^(test .* FAILED|failures:|error)' "$TEST_LOG" | head -20 | sed 's/^/    /'
  note "full log: $TEST_LOG"
fi

# ------------------------------------------------------------ secrets --------
# gitleaks is already pinned in .pre-commit-config.yaml. If it is not installed
# the gate says so rather than quietly passing a check it never ran.
LEAKS_LOG=""
if ! command -v gitleaks >/dev/null 2>&1; then
  fail secrets
  note "gitleaks not installed; brew install gitleaks"
elif ! newlog LEAKS_LOG leaks; then
  fail secrets
  note "could not make a log file under $LOG_DIR"
elif gitleaks protect --staged --no-banner >"$LEAKS_LOG" 2>&1; then
  pass secrets
  rm -f "$LEAKS_LOG"
else
  fail secrets
  tail -20 "$LEAKS_LOG" | sed 's/^/    /'
  note "full log: $LEAKS_LOG"
fi

# ------------------------------------------------------- private-docs --------
# TP-3 / R-144. docs/ is a MIXED directory: the ADRs, runbooks, deployment
# runbook, TYPE_BOUNDARIES, WAL_CONTRACT, and architecture write-ups are tracked
# on purpose. The private set is the enumerated block in .gitignore. Gitignore
# alone does not help a file that is already tracked, so git ls-files is the
# authoritative check. This pattern covers all 20 entries of that block, and is
# verified empty against the current tree. Extend it when you add a private doc.
#
# Deliberately NOT `git ls-files --cached --ignored`: rg-dashboard tracks two
# source files under a frontend data/ path that a broad ignore rule also
# matches, so that oracle is red on a clean tree and nobody would trust it.
TRACKED_PRIVATE="$(git ls-files | grep -iE 'pitch|founder|linkedin|meeting|bizlog|execlog|testlog|devlog|lesson|blocker|deep_scan|session_handoff|smoke_test|one-pager|outreach|architecture-comparison|^docs/site/|^docs/superpowers/|\.pdf$')"
if [ -z "$TRACKED_PRIVATE" ]; then
  pass private-docs
else
  fail private-docs
  printf '%s\n' "$TRACKED_PRIVATE" | sed 's/^/    /'
  note "git rm -r --cached <path> to untrack"
fi

# ---------------------------------------------------------- inversion --------
# R-162. A dirty tree after a completion claim is a bug, not a todo. Three
# consecutive CI rescues came from entry point callers landing without their
# supporting modules.
DIRTY="$(git status --short | grep -v '^??')"
if [ -z "$DIRTY" ]; then
  pass inversion
else
  printf '  %-18s dirty\n' inversion
  printf '%s\n' "$DIRTY" | sed 's/^/    /'
  note "fine mid-task; before claiming done, commit these or write a named hold reason in docs/DEVLOG.md"
fi

# ----------------------------------------------------------- verdict --------
echo
if [ -z "$FAILED" ]; then
  echo "gate: pass"
  exit 0
fi
echo "gate: FAIL ($(echo "$FAILED" | tr -s ' ' | sed 's/^ //'))"
exit 1
