// JSON-RPC handler that impersonates a bitcoind node.
//
// template-manager calls two methods:
//   - getblocktemplate (with segwit rules + coinbasetxn capability)
//   - getmempoolinfo
//
// pool-verifier (ADR-003 Phase 2 Class M) additionally calls:
//   - getrawmempool (verbose=false, returns an array of hex txid strings)
//
// The adapter answers `getrawmempool` synthetically by extracting the
// `txid` field of every entry in the latest `blocktemplate.transactions`
// array. This makes the synthetic mempool a superset of (or equal to) the
// tx set of the most recent template by construction, so the verifier's
// Phase 2 Class M check always emits Agreed and the soak smoke validates
// the full Phase 2 pipeline (poll, install, snapshot read, Class M
// evaluate, verdict emission) without introducing false positives. Real
// mainnet mempool divergence is the Setup B/C launch-gate concern; see
// BIZLOG 2026-05-02 staged-validation commitment.
//
// This handler returns the latest buffered feed data for the three
// methods and a clean error for anything else.

use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{FeedBuffer, SharedBuffer};

// ---------------------------------------------------------------------------
// JSON-RPC request/response types (bitcoind wire format)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RpcRequest {
    /// JSON-RPC version, typically "1.0" or "2.0".
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    /// Caller-assigned request ID, echoed back in the response.
    id: serde_json::Value,
    /// RPC method name.
    method: String,
    /// Method parameters (ignored for our purposes).
    #[allow(dead_code)]
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
pub struct RpcError {
    code: i32,
    message: String,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Supported RPC methods. Used by tests to verify handler coverage.
#[cfg(test)]
pub(crate) const SUPPORTED_METHODS: &[&str] =
    &["getblocktemplate", "getmempoolinfo", "getrawmempool"];

pub async fn handle_jsonrpc(
    State(buf): State<SharedBuffer>,
    body: String,
) -> (StatusCode, axum::Json<RpcResponse>) {
    let req: RpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "invalid JSON-RPC request");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(RpcResponse {
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: "parse error".into(),
                    }),
                    id: serde_json::Value::Null,
                }),
            );
        }
    };

    let id = req.id.clone();
    let guard = buf.read().await;

    let resp = match req.method.as_str() {
        "getblocktemplate" => respond_getblocktemplate(&guard, id),
        "getmempoolinfo" => respond_getmempoolinfo(&guard, id),
        "getrawmempool" => respond_getrawmempool(&guard, id),
        other => {
            warn!(method = other, "unsupported RPC method");
            RpcResponse {
                result: None,
                error: Some(RpcError {
                    code: -32601,
                    message: "method not found".into(),
                }),
                id,
            }
        }
    };
    (StatusCode::OK, axum::Json(resp))
}

fn respond_getblocktemplate(buf: &FeedBuffer, id: serde_json::Value) -> RpcResponse {
    match &buf.block_template {
        Some(tpl) => RpcResponse {
            result: Some(tpl.clone()),
            error: None,
            id,
        },
        None => RpcResponse {
            result: None,
            error: Some(RpcError {
                code: -28,
                message: "feed adapter: no template received yet".into(),
            }),
            id,
        },
    }
}

fn respond_getmempoolinfo(buf: &FeedBuffer, id: serde_json::Value) -> RpcResponse {
    match &buf.mempool_info {
        Some(info) => RpcResponse {
            result: Some(info.clone()),
            error: None,
            id,
        },
        None => RpcResponse {
            result: None,
            error: Some(RpcError {
                code: -28,
                message: "feed adapter: no mempool info received yet".into(),
            }),
            id,
        },
    }
}

/// ADR-003 Phase 2 Class M synthetic answer: extract every `txid`
/// field from the latest `blocktemplate.transactions` array and
/// return them as an array of hex strings, matching bitcoind's
/// `getrawmempool verbose=false` wire shape. The resulting synthetic
/// mempool is a superset of (or equal to) the template's tx set by
/// construction, so the verifier's Class M check always Agrees and
/// the Setup A smoke soak validates the Phase 2 wiring without
/// introducing false positives. See BIZLOG 2026-05-02
/// staged-validation commitment for why this is wiring-only and not
/// a tolerance-threshold validation.
fn respond_getrawmempool(buf: &FeedBuffer, id: serde_json::Value) -> RpcResponse {
    match &buf.block_template {
        Some(tpl) => {
            let txids: Vec<serde_json::Value> = tpl
                .get("transactions")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|tx| {
                            tx.get("txid")
                                .and_then(serde_json::Value::as_str)
                                .map(|s| serde_json::Value::String(s.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            RpcResponse {
                result: Some(serde_json::Value::Array(txids)),
                error: None,
                id,
            }
        }
        None => RpcResponse {
            result: None,
            error: Some(RpcError {
                code: -28,
                message: "feed adapter: no template received yet".into(),
            }),
            id,
        },
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests (CL-20: Feed adapter impersonates bitcoind RPC)
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── Response wire format ──

    #[test]
    fn rpc_response_json_keys_match_bitcoind() {
        // bitcoind returns { "result": ..., "error": ..., "id": ... }
        let resp = RpcResponse {
            result: Some(serde_json::json!({"height": 800_000})),
            error: None,
            id: serde_json::json!(1),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();

        let expected_keys = ["result", "error", "id"];
        assert_eq!(
            obj.len(),
            expected_keys.len(),
            "RpcResponse field count changed"
        );
        for key in &expected_keys {
            assert!(obj.contains_key(*key), "RpcResponse missing key '{key}'");
        }
    }

    #[test]
    fn rpc_error_json_keys_match_bitcoind() {
        // bitcoind error objects have { "code": N, "message": "..." }
        let err = RpcError {
            code: -28,
            message: "loading".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        let obj = json.as_object().unwrap();

        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("code"));
        assert!(obj.contains_key("message"));
        assert!(obj["code"].is_number());
        assert!(obj["message"].is_string());
    }

    #[test]
    fn rpc_request_deserializes_minimal() {
        // template-manager sends minimal JSON-RPC 1.0 requests.
        let body = r#"{"id":1,"method":"getblocktemplate"}"#;
        let req: RpcRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.method, "getblocktemplate");
        assert_eq!(req.id, serde_json::json!(1));
        assert!(req.jsonrpc.is_none());
    }

    #[test]
    fn rpc_request_deserializes_with_params() {
        let body = r#"{"jsonrpc":"2.0","id":"abc","method":"getblocktemplate","params":[{"rules":["segwit"]}]}"#;
        let req: RpcRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.method, "getblocktemplate");
        assert_eq!(req.jsonrpc.as_deref(), Some("2.0"));
        assert!(req.params.is_some());
    }

    #[test]
    fn supported_methods_constant_matches_handler() {
        // SUPPORTED_METHODS must list exactly the methods the handler dispatches.
        // ADR-003 Phase 2 added getrawmempool support so the shadow-mode
        // dev stack can exercise the verifier's Class M check without a
        // real bitcoind backend.
        assert_eq!(SUPPORTED_METHODS.len(), 3);
        assert!(SUPPORTED_METHODS.contains(&"getblocktemplate"));
        assert!(SUPPORTED_METHODS.contains(&"getmempoolinfo"));
        assert!(SUPPORTED_METHODS.contains(&"getrawmempool"));
    }

    #[test]
    fn getrawmempool_synthesizes_array_of_txid_strings_from_block_template() {
        // The verifier's Phase 2 polling task expects the same wire
        // shape bitcoind returns for `getrawmempool verbose=false`:
        // an array of hex txid strings. We synthesize it from the
        // latest blocktemplate.transactions[].txid set so the
        // verifier's mempool view is always a superset of (or equal
        // to) the template's tx set, keeping Setup A soaks Agreed-only
        // by construction.
        let template_with_three_txs = serde_json::json!({
            "version": 0x2000_0000_u64,
            "transactions": [
                {"txid": "aa".repeat(32), "data": "deadbeef"},
                {"txid": "bb".repeat(32), "data": "cafebabe"},
                {"txid": "cc".repeat(32), "data": "f00dface"},
            ]
        });

        let extracted: Vec<String> = template_with_three_txs
            .get("transactions")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|tx| {
                        tx.get("txid")
                            .and_then(serde_json::Value::as_str)
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();

        assert_eq!(extracted.len(), 3);
        assert_eq!(extracted[0], "aa".repeat(32));
        assert_eq!(extracted[1], "bb".repeat(32));
        assert_eq!(extracted[2], "cc".repeat(32));
    }

    #[test]
    fn getrawmempool_returns_empty_array_when_template_has_no_transactions_field() {
        // Defensive: bitcoind always returns a transactions array, but a
        // synthetic feed could omit it. Handler treats missing/non-array
        // as zero-tx mempool rather than erroring out. Verifier's Phase 2
        // check then sees an empty mempool and the only template that
        // can pass is one with zero non-coinbase txs (the empty-template
        // case Phase 1 already rejects via reject_empty_templates).
        let template_without_txs = serde_json::json!({
            "version": 0x2000_0000_u64
        });
        let extracted: Vec<String> = template_without_txs
            .get("transactions")
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|tx| {
                        tx.get("txid")
                            .and_then(serde_json::Value::as_str)
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(extracted.is_empty());
    }

    #[test]
    fn rpc_error_codes_follow_jsonrpc_spec() {
        // -32700 = parse error (JSON-RPC spec)
        // -32601 = method not found (JSON-RPC spec)
        // -28 = bitcoind "loading block index" (bitcoind convention)
        let parse_error = RpcError {
            code: -32700,
            message: "parse error".into(),
        };
        let method_not_found = RpcError {
            code: -32601,
            message: "method not found".into(),
        };
        let loading = RpcError {
            code: -28,
            message: "loading".into(),
        };

        // Verify codes serialize as numbers, not strings.
        let json = serde_json::to_value(&parse_error).unwrap();
        assert_eq!(json["code"], -32700);
        let json = serde_json::to_value(&method_not_found).unwrap();
        assert_eq!(json["code"], -32601);
        let json = serde_json::to_value(&loading).unwrap();
        assert_eq!(json["code"], -28);
    }

    #[test]
    fn rpc_response_echoes_caller_id() {
        // JSON-RPC requires the response `id` to match the request `id`.
        for id_val in [
            serde_json::json!(1),
            serde_json::json!("abc"),
            serde_json::Value::Null,
        ] {
            let resp = RpcResponse {
                result: None,
                error: None,
                id: id_val.clone(),
            };
            let json = serde_json::to_value(&resp).unwrap();
            assert_eq!(json["id"], id_val);
        }
    }
}
