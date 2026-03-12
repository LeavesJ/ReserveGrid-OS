// Scenario generator: produces a looping sequence of synthetic GBT responses
// that trigger every verifier policy detection at least once per cycle.
//
// Each scenario is a function that returns a (blocktemplate, mempoolinfo) pair
// as raw JSON values. The generator emits them as NDJSON over the broadcast
// channel.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use serde_json::json;
use tokio::sync::broadcast;
use tracing::info;

/// Number of seconds since unix epoch (approximate, not critical for demo).
fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Generate a fake 64-char hex hash based on a seed.
fn fake_hash(seed: u64) -> String {
    format!("{seed:016x}{seed:016x}{seed:016x}{seed:016x}")
}

/// Generate a fake 64-char txid.
fn fake_txid(block: u64, idx: usize) -> String {
    let a = block.wrapping_mul(31).wrapping_add(idx as u64);
    fake_hash(a)
}

/// A single synthetic transaction for the GBT `transactions` array.
fn make_tx(block_height: u64, idx: usize, fee: u64, weight: u64, sigops: u32) -> serde_json::Value {
    json!({
        "data": format!("02000000{:08x}00deadbeef", idx),
        "txid": fake_txid(block_height, idx),
        "hash": fake_txid(block_height, idx + 10000),
        "depends": [],
        "fee": fee,
        "sigops": sigops,
        "weight": weight,
    })
}

/// Build a complete GBT response matching the `bitcoincore-rpc` crate's
/// `GetBlockTemplateResult` struct. Every field the crate requires during
/// deserialization is included so template-manager can parse the response
/// without "missing field" errors.
fn build_gbt(
    height: u64,
    txs: &[serde_json::Value],
    coinbase_value: u64,
    coinbase_sigops: u32,
    extras: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    let ts = now_ts();
    let mut tpl = json!({
        "version": 536_870_912_u64,
        "previousblockhash": fake_hash(height.wrapping_sub(1)),
        "transactions": txs,
        "coinbaseaux": {"flags": ""},
        "coinbasevalue": coinbase_value,
        "target": "00000000000000000004b000000000000000000000000000000000000000000000",
        "mintime": ts - 60,
        "curtime": ts,
        "bits": "17034219",
        "height": height,
        "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
        "sizelimit": 1_000_000,
        "sigoplimit": 80_000,
        "weightlimit": 4_000_000,
        "coinbasetxn": {
            "data": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff",
            "sigops": coinbase_sigops
        },
        // Fields required by bitcoincore-rpc GetBlockTemplateResult that
        // real bitcoind returns but were missing from the synthetic feed.
        "rules": ["segwit"],
        "capabilities": ["proposal"],
        "vbavailable": {},
        "vbrequired": 0,
        "longpollid": format!("{}00000000000000{}", fake_hash(height), ts),
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
    });
    // Merge scenario-specific extra fields (template_weight, total_sigops, etc.).
    if let Some(obj) = tpl.as_object_mut() {
        for (k, v) in extras {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    tpl
}

// ---------------------------------------------------------------------------
// Scenario definitions
// ---------------------------------------------------------------------------

/// Normal healthy template: ~2000 txs, reasonable fees, well within limits.
fn scenario_normal(height: u64) -> (serde_json::Value, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let tx_count = 1800 + rng.gen_range(0..400);
    let mut txs = Vec::with_capacity(tx_count);
    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;
    let mut total_sigops: u32 = 0;

    for i in 0..tx_count {
        let fee = 3000 + rng.gen_range(0..15000);
        let weight = 400 + rng.gen_range(0..2400);
        let sigops = rng.gen_range(1..8);
        total_fees += fee;
        total_weight += weight;
        total_sigops += sigops;
        txs.push(make_tx(height, i, fee, weight, sigops));
    }

    let tpl = build_gbt(
        height,
        &txs,
        312_500_000 + total_fees,
        1,
        &[
            ("template_weight", json!(total_weight)),
            ("total_sigops", json!(total_sigops)),
        ],
    );

    let mempool = json!({
        "loaded": true,
        "size": 45000 + rng.gen_range(0..10000),
        "bytes": 28_000_000 + rng.gen_range(0..5_000_000_i64),
        "usage": 110_000_000 + rng.gen_range(0..20_000_000_i64),
        "total_fee": 2.5,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00001,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

/// Edge case: empty template (zero transactions). Triggers `empty_template_rejected`.
fn scenario_empty_template(height: u64) -> (serde_json::Value, serde_json::Value) {
    let tpl = build_gbt(height, &[], 312_500_000, 1, &[]);

    let mempool = json!({
        "loaded": true,
        "size": 200,
        "bytes": 100_000,
        "usage": 500_000,
        "total_fee": 0.001,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00001,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

/// Edge case: low fees in high-mempool regime. Triggers `avg_fee_below_minimum`.
fn scenario_low_fees(height: u64) -> (serde_json::Value, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let tx_count = 1500;
    let mut txs = Vec::with_capacity(tx_count);
    let mut total_fees: u64 = 0;

    for i in 0..tx_count {
        // Deliberately low fees: average well below typical min_avg_fee_hi of 2000
        let fee = 100 + rng.gen_range(0..300);
        total_fees += fee;
        txs.push(make_tx(height, i, fee, 800, 2));
    }

    let tpl = build_gbt(height, &txs, 312_500_000 + total_fees, 1, &[]);

    // High mempool to push into high fee tier
    let mempool = json!({
        "loaded": true,
        "size": 85_000,
        "bytes": 60_000_000,
        "usage": 200_000_000,
        "total_fee": 5.0,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00005,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

/// Edge case: sigops near budget limit. Triggers `sigops_budget_warning`.
fn scenario_high_sigops(height: u64) -> (serde_json::Value, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let tx_count = 800;
    let mut txs = Vec::with_capacity(tx_count);
    let mut total_fees: u64 = 0;
    let mut total_sigops: u32 = 0;

    for i in 0..tx_count {
        let fee = 5000 + rng.gen_range(0..10000);
        // Push sigops very high: ~96 per tx to land near 80,000 limit
        let sigops = 90 + rng.gen_range(0..12);
        total_fees += fee;
        total_sigops += sigops;
        txs.push(make_tx(height, i, fee, 1200, sigops));
    }

    let tpl = build_gbt(
        height,
        &txs,
        312_500_000 + total_fees,
        450,
        &[("total_sigops", json!(total_sigops))],
    );

    let mempool = json!({
        "loaded": true,
        "size": 30_000,
        "bytes": 18_000_000,
        "usage": 80_000_000,
        "total_fee": 3.0,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00001,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

/// Edge case: coinbase value is zero with transactions present.
/// Triggers `coinbase_value_zero_rejected` (if policy enables it).
fn scenario_zero_coinbase(height: u64) -> (serde_json::Value, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let tx_count = 500;
    let mut txs = Vec::with_capacity(tx_count);

    for i in 0..tx_count {
        let fee = 5000 + rng.gen_range(0..5000);
        txs.push(make_tx(height, i, fee, 800, 2));
    }

    let tpl = build_gbt(height, &txs, 0, 1, &[]);

    let mempool = json!({
        "loaded": true,
        "size": 40_000,
        "bytes": 25_000_000,
        "usage": 100_000_000,
        "total_fee": 2.0,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00001,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

/// Edge case: weight near the 4M limit. Triggers `weight_ratio_exceeded`
/// (if policy enforces it).
fn scenario_heavy_weight(height: u64) -> (serde_json::Value, serde_json::Value) {
    let mut rng = rand::thread_rng();
    let tx_count = 600;
    let mut txs = Vec::with_capacity(tx_count);
    let mut total_fees: u64 = 0;
    let mut total_weight: u64 = 0;

    for i in 0..tx_count {
        let fee = 8000 + rng.gen_range(0..10000);
        // Very heavy transactions
        let weight = 6000 + rng.gen_range(0..1000);
        total_fees += fee;
        total_weight += weight;
        txs.push(make_tx(height, i, fee, weight, 3));
    }

    let tpl = build_gbt(
        height,
        &txs,
        312_500_000 + total_fees,
        1,
        &[("template_weight", json!(total_weight))],
    );

    let mempool = json!({
        "loaded": true,
        "size": 50_000,
        "bytes": 35_000_000,
        "usage": 130_000_000,
        "total_fee": 3.5,
        "maxmempool": 300_000_000,
        "mempoolminfee": 0.00002,
        "minrelaytxfee": 0.00001,
    });

    (tpl, mempool)
}

// ---------------------------------------------------------------------------
// Scenario loop
// ---------------------------------------------------------------------------

/// Cycle of scenarios in display order. The loop runs continuously,
/// incrementing block height on each "normal" scenario to simulate
/// block progression.
const SCENARIO_NAMES: &[&str] = &[
    "normal",
    "normal",
    "normal",
    "low_fees",
    "normal",
    "normal",
    "high_sigops",
    "normal",
    "empty_template",
    "normal",
    "normal",
    "zero_coinbase",
    "normal",
    "heavy_weight",
    "normal",
    "normal",
];

pub async fn run_scenario_loop(tx: broadcast::Sender<Arc<String>>, interval: Duration) {
    let mut height: u64 = 890_000;
    let mut cycle_idx: usize = 0;

    info!(
        scenario_count = SCENARIO_NAMES.len(),
        start_height = height,
        "scenario loop starting"
    );

    loop {
        let name = SCENARIO_NAMES[cycle_idx % SCENARIO_NAMES.len()];

        let (tpl, mempool) = match name {
            "empty_template" => scenario_empty_template(height),
            "low_fees" => scenario_low_fees(height),
            "high_sigops" => scenario_high_sigops(height),
            "zero_coinbase" => scenario_zero_coinbase(height),
            "heavy_weight" => scenario_heavy_weight(height),
            // "normal" and any unknown name fall through to the default.
            _ => scenario_normal(height),
        };

        let ts = now_ts();

        // Emit blocktemplate frame
        let tpl_frame = serde_json::json!({
            "type": "blocktemplate",
            "ts": ts,
            "data": tpl,
        });
        if let Ok(s) = serde_json::to_string(&tpl_frame) {
            let _ = tx.send(Arc::new(s));
        }

        // Emit mempoolinfo frame
        let mem_frame = serde_json::json!({
            "type": "mempoolinfo",
            "ts": ts,
            "data": mempool,
        });
        if let Ok(s) = serde_json::to_string(&mem_frame) {
            let _ = tx.send(Arc::new(s));
        }

        tracing::debug!(scenario = name, height, "emitted template");

        // Advance height on every iteration to simulate block progression.
        // In reality blocks arrive every ~10 minutes; the demo compresses time.
        cycle_idx += 1;
        if name == "normal" {
            height += 1;
        }

        tokio::time::sleep(interval).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// R-56 required GBT fields that template-manager's deserializer expects.
    const REQUIRED_GBT_FIELDS: &[&str] = &[
        "version",
        "previousblockhash",
        "transactions",
        "coinbaseaux",
        "coinbasevalue",
        "coinbasetxn",
        "target",
        "mintime",
        "curtime",
        "bits",
        "height",
        "default_witness_commitment",
        "sizelimit",
        "sigoplimit",
        "weightlimit",
        "rules",
        "capabilities",
        "vbavailable",
        "vbrequired",
        "longpollid",
        "mutable",
        "noncerange",
    ];

    /// Required fields on each transaction in the GBT transactions array.
    const REQUIRED_TX_FIELDS: &[&str] =
        &["data", "txid", "hash", "depends", "fee", "sigops", "weight"];

    /// Required fields on the mempoolinfo response.
    const REQUIRED_MEMPOOL_FIELDS: &[&str] = &[
        "loaded",
        "size",
        "bytes",
        "usage",
        "total_fee",
        "maxmempool",
        "mempoolminfee",
        "minrelaytxfee",
    ];

    fn assert_gbt_schema(tpl: &serde_json::Value, label: &str) {
        let obj = tpl
            .as_object()
            .unwrap_or_else(|| panic!("{label}: GBT must be an object"));
        for field in REQUIRED_GBT_FIELDS {
            assert!(
                obj.contains_key(*field),
                "{label}: missing GBT field '{field}'"
            );
        }

        // coinbasetxn must have data and sigops.
        let cbtxn = obj
            .get("coinbasetxn")
            .unwrap_or_else(|| panic!("{label}: missing coinbasetxn"));
        assert!(
            cbtxn.get("data").is_some(),
            "{label}: coinbasetxn missing 'data'"
        );
        assert!(
            cbtxn.get("sigops").is_some(),
            "{label}: coinbasetxn missing 'sigops'"
        );

        // transactions entries must have required fields.
        if let Some(txs) = obj
            .get("transactions")
            .and_then(serde_json::Value::as_array)
        {
            for (i, tx) in txs.iter().enumerate() {
                for field in REQUIRED_TX_FIELDS {
                    assert!(
                        tx.get(*field).is_some(),
                        "{label}: tx[{i}] missing field '{field}'"
                    );
                }
            }
        }
    }

    fn assert_mempool_schema(mempool: &serde_json::Value, label: &str) {
        let obj = mempool
            .as_object()
            .unwrap_or_else(|| panic!("{label}: mempool must be an object"));
        for field in REQUIRED_MEMPOOL_FIELDS {
            assert!(
                obj.contains_key(*field),
                "{label}: missing mempool field '{field}'"
            );
        }
    }

    #[test]
    fn scenario_normal_produces_valid_gbt() {
        let (tpl, mempool) = scenario_normal(890_000);
        assert_gbt_schema(&tpl, "normal");
        assert_mempool_schema(&mempool, "normal");

        let txs = tpl["transactions"].as_array().expect("transactions array");
        assert!(!txs.is_empty(), "normal scenario must produce transactions");
        assert!(
            tpl["coinbasevalue"].as_u64().unwrap_or(0) > 0,
            "normal coinbasevalue must be positive"
        );
    }

    #[test]
    fn scenario_empty_template_has_zero_transactions() {
        let (tpl, mempool) = scenario_empty_template(890_001);
        assert_gbt_schema(&tpl, "empty_template");
        assert_mempool_schema(&mempool, "empty_template");

        let txs = tpl["transactions"].as_array().expect("transactions array");
        assert!(txs.is_empty(), "empty_template must have zero transactions");
    }

    #[test]
    fn scenario_low_fees_has_low_average_fee() {
        let (tpl, mempool) = scenario_low_fees(890_002);
        assert_gbt_schema(&tpl, "low_fees");
        assert_mempool_schema(&mempool, "low_fees");

        let txs = tpl["transactions"].as_array().expect("transactions array");
        let total_fees: u64 = txs.iter().map(|tx| tx["fee"].as_u64().unwrap_or(0)).sum();
        let avg = total_fees / txs.len() as u64;
        assert!(avg < 2000, "low_fees avg fee {avg} should be below 2000");
    }

    #[test]
    fn scenario_high_sigops_near_budget() {
        let (tpl, mempool) = scenario_high_sigops(890_003);
        assert_gbt_schema(&tpl, "high_sigops");
        assert_mempool_schema(&mempool, "high_sigops");

        let txs = tpl["transactions"].as_array().expect("transactions array");
        let total_sigops: u64 = txs
            .iter()
            .map(|tx| tx["sigops"].as_u64().unwrap_or(0))
            .sum();
        assert!(
            total_sigops > 60_000,
            "high_sigops total {total_sigops} should exceed 60000"
        );
    }

    #[test]
    fn scenario_zero_coinbase_has_zero_value() {
        let (tpl, mempool) = scenario_zero_coinbase(890_004);
        assert_gbt_schema(&tpl, "zero_coinbase");
        assert_mempool_schema(&mempool, "zero_coinbase");

        assert_eq!(
            tpl["coinbasevalue"].as_u64(),
            Some(0),
            "coinbasevalue must be zero"
        );
        let txs = tpl["transactions"].as_array().expect("transactions array");
        assert!(!txs.is_empty(), "zero_coinbase must have transactions");
    }

    #[test]
    fn scenario_heavy_weight_produces_high_weight() {
        let (tpl, mempool) = scenario_heavy_weight(890_005);
        assert_gbt_schema(&tpl, "heavy_weight");
        assert_mempool_schema(&mempool, "heavy_weight");

        let tw = tpl
            .get("template_weight")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert!(
            tw > 3_000_000,
            "heavy_weight template_weight {tw} should exceed 3M"
        );
    }

    #[test]
    fn fake_hash_produces_64_hex_chars() {
        let h = fake_hash(42);
        assert_eq!(h.len(), 64, "fake_hash must be 64 chars");
        assert!(
            h.chars().all(|c| c.is_ascii_hexdigit()),
            "fake_hash must be hex"
        );
    }

    #[test]
    fn make_tx_includes_depends_field() {
        let tx = make_tx(890_000, 0, 5000, 800, 2);
        assert!(tx.get("depends").is_some(), "tx must have depends field");
        let deps = tx["depends"].as_array().expect("depends must be an array");
        assert!(deps.is_empty(), "synthetic tx depends must be empty");
    }

    #[test]
    fn build_gbt_merges_extras() {
        let tpl = build_gbt(1, &[], 100, 1, &[("custom_field", json!(42))]);
        assert_eq!(
            tpl.get("custom_field").and_then(serde_json::Value::as_u64),
            Some(42)
        );
    }

    #[test]
    fn all_scenario_names_are_handled() {
        for name in SCENARIO_NAMES {
            let (tpl, mempool) = match *name {
                "empty_template" => scenario_empty_template(1),
                "low_fees" => scenario_low_fees(1),
                "high_sigops" => scenario_high_sigops(1),
                "zero_coinbase" => scenario_zero_coinbase(1),
                "heavy_weight" => scenario_heavy_weight(1),
                _ => scenario_normal(1),
            };
            assert_gbt_schema(&tpl, name);
            assert_mempool_schema(&mempool, name);
        }
    }
}
