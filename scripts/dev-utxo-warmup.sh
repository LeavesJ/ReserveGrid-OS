#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BTC_CLI="${ROOT_DIR}/scripts/dev-bitcoin-cli.sh"
btc_cli(){ "${BTC_CLI}" "$@"; }

UTXO_WARMUP_COUNT="${UTXO_WARMUP_COUNT:-40}"
UTXO_WARMUP_AMOUNT="${UTXO_WARMUP_AMOUNT:-0.12}"
FEE="${FEE:-25.0}" # sat/vB

mine1() {
  local addr
  addr="$(btc_cli getnewaddress)"
  btc_cli -named generatetoaddress nblocks=1 address="$addr" >/dev/null
}

send_one() {
  local to txid
  to="$(btc_cli getnewaddress)"
  txid="$(btc_cli -named sendtoaddress address="$to" amount="$UTXO_WARMUP_AMOUNT" fee_rate="$FEE" avoid_reuse=false)"
  [[ -n "$txid" && "$txid" != "null" ]]
}

per_batch=10
made=0
while [[ "$made" -lt "$UTXO_WARMUP_COUNT" ]]; do
  batch=$((UTXO_WARMUP_COUNT - made))
  [[ "$batch" -gt "$per_batch" ]] && batch="$per_batch"
  for _ in $(seq 1 "$batch"); do send_one; done
  mine1
  made=$((made + batch))
done

echo "[utxo-warmup] done: created ${UTXO_WARMUP_COUNT} confirmed UTXOs"
