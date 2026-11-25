use crate::tools::{call_tool, tool_definitions};
use anyhow::Result;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rpc_mcp_core::{constant_time_eq, extract_bearer_token};
use rpc_mcp_core::path_guard::AllowedRoots;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct FsServerConfig {
    pub host: String,
    pub port: u16,
    pub bearer_token: String,
    pub allowed_roots: AllowedRoots,
}

struct FsState {
    cfg: FsServerConfig,
}

fn check_auth(headers: &HeaderMap, expected_token: &str) -> bool {
    let Some(raw) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = extract_bearer_token(raw) else {
        return false;
    };
    constant_time_eq(token, expected_token)
}

async fn healthz(State(state): State<Arc<FsState>>) -> impl IntoResponse {
    let ok = !state.cfg.allowed_roots.roots().is_empty();
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": ok,
            "upstream": format!("{}:{}", state.cfg.host, state.cfg.port),
            "detail": if ok { "rust filesystem MCP ready" } else { "no valid allowed roots" }
        })),
    )
}

async fn mcp_delete(
    State(state): State<Arc<FsState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "ok": false, "error": "unauthorized" }))).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn mcp_post(
    State(state): State<Arc<FsState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "unauthorized" })),
        )
            .into_response();
    }

    let method = payload.get("method").and_then(Value::as_str).unwrap_or("");
    let id = payload.get("id").cloned();

    // JSON-RPC notifications (no id) return 202 Accepted
    if id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let id = id.unwrap();

    let mut session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let body = match method {
        "initialize" => {
            let client_ver = payload
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-06-18");
            let sid = session_id.get_or_insert_with(|| Uuid::new_v4().to_string()).clone();
            let _ = sid;
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": client_ver,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "rpc-mcp-fs", "version": env!("CARGO_PKG_VERSION") }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_definitions() }
        }),
        "tools/call" => {
            let name = payload
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = payload
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = call_tool(&state.cfg.allowed_roots, name, args).await;
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };

    let mut resp = (StatusCode::OK, Json(body)).into_response();
    if let Some(sid) = session_id {
        if let Ok(val) = HeaderValue::from_str(&sid) {
            resp.headers_mut().insert("mcp-session-id", val);
        }
    }
    resp
}

pub fn build_router(cfg: FsServerConfig) -> Router {
    let state = Arc::new(FsState { cfg });
    Router::new()
        .route("/healthz", get(healthz))
        .route("/mcp", post(mcp_post).delete(mcp_delete))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .with_state(state)
}

pub async fn serve_fs_mcp(cfg: FsServerConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let app = build_router(cfg);
    let listener = TcpListener::bind(addr).await?;
    info!("READY rpc-mcp-fs listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
