#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BTC_CLI="${ROOT_DIR}/scripts/dev-bitcoin-cli.sh"

UI_WAIT_SECS="${UI_WAIT_SECS:-2}"
RUNS="${RUNS:-0}" # 0 = infinite, else run N cycles

VERIFIER_HTTP_ADDR="${VERIFIER_HTTP_ADDR:-127.0.0.1:8081}"
MANAGER_HTTP_ADDR="${MANAGER_HTTP_ADDR:-127.0.0.1:8082}"

AMOUNT="${AMOUNT:-0.05}"
LOW_FEE="${LOW_FEE:-1.0}"     # sat/vB
HIGH_FEE="${HIGH_FEE:-25.0}"  # sat/vB

LOW_COUNT="${LOW_COUNT:-12}"
MID_COUNT="${MID_COUNT:-30}"
STRESS_COUNT="${STRESS_COUNT:-120}"

HOLD_SECS="${HOLD_SECS:-2}"

# Mine between sub-batches to avoid too many unconfirmed ancestors.
# Critical rule: never mine after the final sub-batch, so the mempool is nonzero at phase end.
MINE_EVERY_SENDS="${MINE_EVERY_SENDS:-20}"

btc_cli() { "${BTC_CLI}" "$@"; }
wait_ui() { sleep "${UI_WAIT_SECS}"; }

require_http_ok() {
  local url="$1"
  for _ in {1..40}; do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "[demo-phases] ERROR: endpoint not ready: ${url}" >&2
  exit 1
}

require_stack_ready() {
  require_http_ok "http://${VERIFIER_HTTP_ADDR}/health"
  require_http_ok "http://${MANAGER_HTTP_ADDR}/health"
}

json_get_int() {
  # usage: json_get_int "<json>" "<key>" "<default>"
  local json="$1"
  local key="$2"
  local def="$3"

  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$key" --argjson d "$def" '.[$k] // $d' <<<"$json"
    return 0
  fi

  python3 - <<'PY' <<<"$json"
import sys, json
j = json.load(sys.stdin)
# args are not passed; this is a jq-less fallback for known fields only.
print(j.get("size", 0))
PY
}

btc_mempool_size() {
  local raw
  raw="$(btc_cli getmempoolinfo)"
  # prefer jq; python fallback prints .size only (acceptable because we only need mempool size here)
  if command -v jq >/dev/null 2>&1; then
    jq -r '.size // 0' <<<"$raw"
  else
    python3 - <<'PY' <<<"$raw"
import sys, json
j = json.load(sys.stdin)
print(j.get("size", 0))
PY
  fi
}

mgr_mempool_size() {
  # Best-effort: manager may be down or returning non-JSON; do not gate on this.
  local raw
  if ! raw="$(curl -fsS "http://${MANAGER_HTTP_ADDR}/mempool" 2>/dev/null)"; then
    echo 0
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -r '.tx_count // 0' <<<"$raw" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

btc_print_diag() {
  echo "[demo-phases][diag] getblockchaininfo:" >&2
  btc_cli getblockchaininfo 2>/dev/null | (command -v jq >/dev/null 2>&1 && jq '{chain,blocks,headers,initialblockdownload}' || cat) >&2 || true

  echo "[demo-phases][diag] getmempoolinfo:" >&2
  btc_cli getmempoolinfo 2>/dev/null >&2 || true

  echo "[demo-phases][diag] getwalletinfo:" >&2
  btc_cli getwalletinfo 2>/dev/null | (command -v jq >/dev/null 2>&1 && jq '{walletname,balance,unconfirmed_balance,immature_balance,txcount}' || cat) >&2 || true

  echo "[demo-phases][diag] listunspent (count):" >&2
  if command -v jq >/dev/null 2>&1; then
    btc_cli listunspent 2>/dev/null | jq 'length' >&2 || true
  else
    btc_cli listunspent 2>/dev/null | wc -l >&2 || true
  fi
}

wait_mempool_ge() {
  local want="$1"
  local tries="${2:-80}"
  local cur

  for _ in $(seq 1 "${tries}"); do
    cur="$(btc_mempool_size)"
    if [[ "${cur}" -ge "${want}" ]]; then return 0; fi
    sleep 0.25
  done

  echo "[demo-phases] ERROR: mempool did not reach >= ${want} tx (btc_last=$(btc_mempool_size) mgr_last=$(mgr_mempool_size))" >&2
  btc_print_diag
  exit 1
}

ensure_mempool_nonzero() {
  local target="${1:-1}"
  local cur
  cur="$(btc_mempool_size)"
  if [[ "${cur}" -ge "${target}" ]]; then
    return 0
  fi
  send_one "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge "${target}" 80
}

gbt_tx_count() {
  local raw
  # Standard GBT request; segwit rule is fine on modern cores.
  raw="$(btc_cli getblocktemplate '{"rules":["segwit"]}')"
  if command -v jq >/dev/null 2>&1; then
    jq -r '(.transactions // []) | length' <<<"$raw"
  else
    python3 - <<'PY' <<<"$raw"
import sys, json
j=json.load(sys.stdin)
print(len(j.get("transactions", [])))
PY
  fi
}

wait_gbt_nonempty() {
  local want="${1:-1}"          # number of mempool txs in template
  local tries="${2:-80}"
  for _ in $(seq 1 "$tries"); do
    local n
    n="$(gbt_tx_count)"
    if [[ "$n" -ge "$want" ]]; then return 0; fi
    sleep 0.25
  done
  echo "[demo-phases] ERROR: getblocktemplate stayed empty (gbt_tx_count=$(gbt_tx_count), mempool_size=$(btc_mempool_size))" >&2
  exit 1
}


mine_n() {
  local n="$1"
  local addr
  addr="$(btc_cli getnewaddress)"
  btc_cli -named generatetoaddress nblocks="$n" address="$addr" >/dev/null
}

balance() { btc_cli getbalance; }

require_spendable() {
  local bal
  bal="$(balance)"
  if ! awk -v b="$bal" 'BEGIN{ exit !(b > 1.0) }'; then
    echo "[demo-phases] ERROR: insufficient spendable balance (${bal}). Run dev-regtest.sh first." >&2
    btc_print_diag
    exit 1
  fi
}

phase() {
  local name="$1"
  echo
  echo "============================================================"
  echo "[demo-phases] PHASE: ${name}"
  echo "============================================================"
}

hold_for_templates() {
  local label="$1"
  local btc_sz mgr_sz
  btc_sz="$(btc_mempool_size)"
  mgr_sz="$(mgr_mempool_size)"
  echo "[demo-phases] hold ${HOLD_SECS}s (${label}) mempool_size btc=${btc_sz} mgr=${mgr_sz}"
  sleep "${HOLD_SECS}"
}

send_one() {
  local fee_rate_req="$1"
  local amount="$2"

  local fee_rate
  fee_rate="$(awk -v r="$fee_rate_req" 'BEGIN{ if (r < 1.0) printf("%.3f", 1.0); else printf("%.3f", r) }')"

  local to txid
  to="$(btc_cli getnewaddress)"
  txid="$(btc_cli -named sendtoaddress address="$to" amount="$amount" fee_rate="$fee_rate" avoid_reuse=false)"

  if [[ -z "${txid}" || "${txid}" == "null" ]]; then
    echo "[demo-phases] ERROR: sendtoaddress returned empty txid (fee_rate=${fee_rate} amount=${amount})" >&2
    btc_print_diag
    exit 1
  fi
}

send_batch_mine_cadence() {
  local count="$1"
  local fee_rate="$2"
  local amount="$3"

  local cadence="${MINE_EVERY_SENDS}"
  if [[ "${cadence}" -le 0 ]]; then cadence=0; fi

  echo "[demo-phases] send_batch count=${count} amount=${amount} fee_rate=${fee_rate} sat/vB (mine every ${cadence}, never after last chunk)"

  # No cadence means: just send all, leave mempool nonzero.
  if [[ "${cadence}" -eq 0 ]] || [[ "${count}" -le "${cadence}" ]]; then
    for _ in $(seq 1 "${count}"); do
      send_one "${fee_rate}" "${amount}"
    done
    return 0
  fi

  # Chunked sending: mine after each full chunk except the final chunk.
  local sent=0
  while [[ "${sent}" -lt "${count}" ]]; do
    local remaining=$((count - sent))
    local chunk="${cadence}"
    if [[ "${remaining}" -lt "${chunk}" ]]; then
      chunk="${remaining}"
    fi

    for _ in $(seq 1 "${chunk}"); do
      send_one "${fee_rate}" "${amount}"
    done
    sent=$((sent + chunk))

    # Mine only between chunks, never after the final chunk.
    if [[ "${sent}" -lt "${count}" ]]; then
      mine_n 1
      wait_ui
    fi
  done
}

send_batch_no_mine() {
  local count="$1"
  local fee_rate="$2"
  local amount="$3"

  echo "[demo-phases] send_batch_no_mine count=${count} amount=${amount} fee_rate=${fee_rate} sat/vB (no mining)"
  for _ in $(seq 1 "${count}"); do
    send_one "${fee_rate}" "${amount}"
  done
}

echo "[demo-phases] starting demo loop..."
require_stack_ready
require_spendable

i=0
while true; do
  i=$((i+1))
  if [[ "${RUNS}" != "0" ]] && [[ "${i}" -gt "${RUNS}" ]]; then
    echo "[demo-phases] completed RUNS=${RUNS}"
    exit 0
  fi

  phase "A: empty-template rejection showcase (single event)"
  mine_n 1
  sleep 0.5
  wait_ui

  phase "B: low-fee only (forces fee-based rejects because no high-fee tx exist)"
  send_batch_mine_cadence "${LOW_COUNT}" "${LOW_FEE}" "${AMOUNT}"
  wait_mempool_ge 1
  ensure_mempool_nonzero 1
  wait_gbt_nonempty 1
  hold_for_templates "low-fee-only window"
  mine_n 1
  wait_ui
  ensure_mempool_nonzero 1

  phase "C: high-fee only (expect Ok)"
  send_batch_mine_cadence "${LOW_COUNT}" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 1
  ensure_mempool_nonzero 1
  wait_gbt_nonempty 1
  hold_for_templates "high-fee-only window"
  mine_n 1
  wait_ui
  ensure_mempool_nonzero 1

  phase "D: tier flip (build mempool, then hold; mixed strategy depends on your policy)"
  send_batch_mine_cadence "${MID_COUNT}" "${LOW_FEE}" "${AMOUNT}"
  send_batch_mine_cadence "$((MID_COUNT / 3))" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 10
  ensure_mempool_nonzero 10
  wait_gbt_nonempty 10
  hold_for_templates "tier-flip window"
  mine_n 1
  wait_ui
  ensure_mempool_nonzero 1

  phase "E: txcount stress (expect tx_count_exceeded when max_tx_count is low)"
  send_batch_no_mine "${STRESS_COUNT}" "${HIGH_FEE}" "${AMOUNT}"
  wait_mempool_ge 40 120
  hold_for_templates "stress window"
  mine_n 1
  wait_ui

done
