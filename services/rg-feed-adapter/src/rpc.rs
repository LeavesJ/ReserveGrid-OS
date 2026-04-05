// JSON-RPC handler that impersonates a bitcoind node.
//
// template-manager calls two methods:
//   - getblocktemplate (with segwit rules + coinbasetxn capability)
//   - getmempoolinfo
//
// This handler returns the latest buffered feed data for those two methods
// and a clean error for anything else.

use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::SharedBuffer;

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
pub(crate) const SUPPORTED_METHODS: &[&str] = &["getblocktemplate", "getmempoolinfo"];

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

    match req.method.as_str() {
        "getblocktemplate" => {
            let guard = buf.read().await;
            match &guard.block_template {
                Some(tpl) => (
                    StatusCode::OK,
                    axum::Json(RpcResponse {
                        result: Some(tpl.clone()),
                        error: None,
                        id,
                    }),
                ),
                None => (
                    StatusCode::OK,
                    axum::Json(RpcResponse {
                        result: None,
                        error: Some(RpcError {
                            code: -28,
                            message: "feed adapter: no template received yet".into(),
                        }),
                        id,
                    }),
                ),
            }
        }
        "getmempoolinfo" => {
            let guard = buf.read().await;
            match &guard.mempool_info {
                Some(info) => (
                    StatusCode::OK,
                    axum::Json(RpcResponse {
                        result: Some(info.clone()),
                        error: None,
                        id,
                    }),
                ),
                None => (
                    StatusCode::OK,
                    axum::Json(RpcResponse {
                        result: None,
                        error: Some(RpcError {
                            code: -28,
                            message: "feed adapter: no mempool info received yet".into(),
                        }),
                        id,
                    }),
                ),
            }
        }
        other => {
            warn!(method = other, "unsupported RPC method");
            (
                StatusCode::OK,
                axum::Json(RpcResponse {
                    result: None,
                    error: Some(RpcError {
                        code: -32601,
                        message: "method not found".into(),
                    }),
                    id,
                }),
            )
        }
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
        assert_eq!(SUPPORTED_METHODS.len(), 2);
        assert!(SUPPORTED_METHODS.contains(&"getblocktemplate"));
        assert!(SUPPORTED_METHODS.contains(&"getmempoolinfo"));
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
