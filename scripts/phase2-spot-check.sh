#!/usr/bin/env bash
# phase2-spot-check.sh
#
# Captures the four ADR-003 Phase 2 metric counters from the
# verifier's /metrics endpoint, computes deltas against the baseline
# JSON written by phase2-baseline.sh, and lists every Class M
# tolerance-exceeded rejection from the verdict log so the operator
# can cross-reference each candidate false positive against the
# pool's block-found feed.
#
# Run at T+0 (immediately after phase2-baseline.sh on the start
# day), T+1, T+3, T+5, and T+7 per
# docs/runbooks/phase2-shadow-soak.md.
#
# Usage:
#   scripts/phase2-spot-check.sh [--metrics-url URL] [--baseline PATH]
#                                [--verdict-log PATH] [--max-rejections N]
#
# Defaults:
#   --metrics-url     http://127.0.0.1:8081/metrics
#   --baseline        ./data/phase2-baseline.json
#   --verdict-log     ./data/verdicts.log
#   --max-rejections  50  (per call; bump if a window has more)
#
# Output is human readable; pipe to a log for the DEVLOG entry.
# Exit code 0 on success, 1 on stale baseline or unreachable metrics,
# 2 on bad arg, 3 on missing dependency.

set -euo pipefail

METRICS_URL="${VELDRA_PHASE2_METRICS_URL:-http://127.0.0.1:8081/metrics}"
BASELINE_PATH="${VELDRA_PHASE2_BASELINE_PATH:-./data/phase2-baseline.json}"
VERDICT_LOG="${VELDRA_VERDICT_LOG:-./data/verdicts.log}"
MAX_REJECTIONS=50

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-url)    METRICS_URL="$2"; shift 2 ;;
    --baseline)       BASELINE_PATH="$2"; shift 2 ;;
    --verdict-log)    VERDICT_LOG="$2"; shift 2 ;;
    --max-rejections) MAX_REJECTIONS="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# //; s/^#//'
      exit 0
      ;;
    *)
      echo "phase2-spot-check.sh: unknown arg '$1'" >&2
      exit 2
      ;;
  esac
done

for tool in curl jq awk; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "phase2-spot-check.sh: $tool is required but not on PATH" >&2
    exit 3
  fi
done

if [[ ! -f "$BASELINE_PATH" ]]; then
  echo "phase2-spot-check.sh: baseline not found at $BASELINE_PATH" >&2
  echo "  run scripts/phase2-baseline.sh first (T-1 day step)" >&2
  exit 1
fi

# Re-fetch /metrics. Same parser as phase2-baseline.sh; kept inline
# so the spot-check script stays self-contained and runnable from
# any deploy location without sourcing a shared lib.
METRICS_TEXT="$(curl --silent --show-error --fail --max-time 10 "$METRICS_URL")"

parse_counter_with_label() {
  local name="$1"
  local label="$2"
  echo "$METRICS_TEXT" \
    | awk -v name="$name" -v label="$label" '
        $0 ~ /^#/ { next }
        index($0, name "{result=\"" label "\"}") == 1 ||
        index($0, name "_total{result=\"" label "\"}") == 1 {
          print $NF; exit
        }
      '
}
parse_counter() {
  local name="$1"
  echo "$METRICS_TEXT" \
    | awk -v name="$name" '
        $0 ~ /^#/ { next }
        index($0, name " ") == 1 || index($0, name "_total ") == 1 {
          print $NF; exit
        }
      '
}

CUR_AGREED="$(parse_counter_with_label verifier_phase2_checks_total agreed)"
CUR_REJECTED="$(parse_counter_with_label verifier_phase2_checks_total rejected)"
CUR_SKIPPED="$(parse_counter_with_label verifier_phase2_checks_total skipped)"
CUR_STALE="$(parse_counter_with_label verifier_phase2_checks_total stale)"
CUR_DEGRADED="$(parse_counter verifier_phase2_degraded_total)"
CUR_VIEW_AGE="$(parse_counter verifier_mempool_view_age_seconds)"
CUR_VIEW_SIZE="$(parse_counter verifier_mempool_view_size)"

CUR_AGREED="${CUR_AGREED:-0}"
CUR_REJECTED="${CUR_REJECTED:-0}"
CUR_SKIPPED="${CUR_SKIPPED:-0}"
CUR_STALE="${CUR_STALE:-0}"
CUR_DEGRADED="${CUR_DEGRADED:-0}"
CUR_VIEW_AGE="${CUR_VIEW_AGE:-0}"
CUR_VIEW_SIZE="${CUR_VIEW_SIZE:-0}"

BASE_AGREED="$(jq -r '.counters.verifier_phase2_checks_total_agreed' "$BASELINE_PATH")"
BASE_REJECTED="$(jq -r '.counters.verifier_phase2_checks_total_rejected' "$BASELINE_PATH")"
BASE_SKIPPED="$(jq -r '.counters.verifier_phase2_checks_total_skipped' "$BASELINE_PATH")"
BASE_STALE="$(jq -r '.counters.verifier_phase2_checks_total_stale' "$BASELINE_PATH")"
BASE_DEGRADED="$(jq -r '.counters.verifier_phase2_degraded_total' "$BASELINE_PATH")"
BASE_AT="$(jq -r '.captured_at' "$BASELINE_PATH")"

DELTA_AGREED=$((CUR_AGREED - BASE_AGREED))
DELTA_REJECTED=$((CUR_REJECTED - BASE_REJECTED))
DELTA_SKIPPED=$((CUR_SKIPPED - BASE_SKIPPED))
DELTA_STALE=$((CUR_STALE - BASE_STALE))
DELTA_DEGRADED=$((CUR_DEGRADED - BASE_DEGRADED))
TOTAL_CLASSM=$((DELTA_AGREED + DELTA_REJECTED + DELTA_SKIPPED + DELTA_STALE))

NOW="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

echo "═══ ADR-003 Phase 2 #6 spot check at $NOW ═══"
echo "  baseline captured_at: $BASE_AT"
echo "  metrics_url:          $METRICS_URL"
echo
echo "Class M check counters (delta since baseline):"
printf "  agreed    %10d  (current %d)\n" "$DELTA_AGREED"   "$CUR_AGREED"
printf "  rejected  %10d  (current %d)\n" "$DELTA_REJECTED" "$CUR_REJECTED"
printf "  skipped   %10d  (current %d)\n" "$DELTA_SKIPPED"  "$CUR_SKIPPED"
printf "  stale     %10d  (current %d)\n" "$DELTA_STALE"    "$CUR_STALE"
printf "  total     %10d\n"               "$TOTAL_CLASSM"
echo
printf "  degraded  %10d  (current %d)\n" "$DELTA_DEGRADED" "$CUR_DEGRADED"
printf "  view_age  %10ss\n"              "$CUR_VIEW_AGE"
printf "  view_size %10s\n"               "$CUR_VIEW_SIZE"

if (( DELTA_DEGRADED > 0 )); then
  echo
  echo "WARNING: verifier_phase2_degraded_total grew by $DELTA_DEGRADED since baseline."
  echo "  bitcoind RPC was unavailable for at least one window during the soak."
  echo "  per the runbook, sustained degraded windows invalidate the soak; investigate"
  echo "  the bitcoind side and consider restarting the soak from T+0."
fi

if (( DELTA_REJECTED == 0 )); then
  echo
  echo "Zero Class M rejections in the window so far. PASS condition holds."
  exit 0
fi

echo
echo "═══ Candidate false positives (last $MAX_REJECTIONS Class M rejections) ═══"
echo
echo "Each row below is a Class M rejection. Cross-reference each against the"
echo "pool's block-found feed for the same block_height per the runbook FP review:"
echo "  pool mined the block AT this height with same coinbase => CONFIRMED FP, count it"
echo "  different pool mined that height                      => ambiguous, do NOT count"
echo "  no block at that height yet                           => stale template, do NOT count"
echo

if [[ ! -f "$VERDICT_LOG" ]]; then
  echo "  (verdict log not found at $VERDICT_LOG; check the runbook's verdict log path)"
  exit 0
fi

jq -c \
  --arg n "$MAX_REJECTIONS" \
  'select(.reason_code == "v2_invariant_mempool_tolerance_exceeded")
   | {
       ts:        (.timestamp // .ts // null),
       id:        .id,
       height:    (.block_height // .height // null),
       detail:    .reason_detail
     }' \
  "$VERDICT_LOG" \
  | tail -n "$MAX_REJECTIONS" \
  | nl -ba
