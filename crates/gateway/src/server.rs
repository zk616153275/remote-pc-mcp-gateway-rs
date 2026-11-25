use crate::audit::AuditLog;
use crate::lanes::ServiceLanes;
use crate::oauth::{OAuthConfig, OAuthService, Platform};
use crate::recovery::{wait_tool_definition, TaskJournal};
use crate::vision::{inspect_image_tool_definition, run_inspect_image, VisionConfig};
use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, options, post};
use axum::{Json, Router};
use reqwest::Client;
use rpc_mcp_core::git_policy::validate_readonly_git_args;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;
use uuid::Uuid;

const READ_ONLY_FS: &[&str] = &[
    "list_allowed_directories",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "directory_tree_limited",
    "search_files",
    "grep_files",
    "read_file",
    "read_text_file",
    "read_multiple_files",
    "read_media_file",
    "read_file_lines",
    "get_file_info",
];

const WRITE_FS: &[&str] = &[
    "write_file",
    "edit_file",
    "edit_file_at_line",
    "create_directory",
    "move_file",
];

#[derive(Clone)]
pub struct GatewayServerConfig {
    pub host: String,
    pub port: u16,
    pub secret: String,
    pub mode: String,
    pub enable_commands: bool,
    pub enable_chrome: bool,
    pub fs_url: String,
    pub fs_token: String,
    pub workbench_url: String,
    pub workbench_token: String,
    pub chrome_url: String,
    pub chrome_token: String,
    pub workspace_root: String,
    pub instance_label: String,
    pub oauth: OAuthConfig,
    pub audit_log: Option<PathBuf>,
    pub task_dir: Option<PathBuf>,
    pub vision: VisionConfig,
}

impl GatewayServerConfig {
    pub fn mcp_path(&self) -> String {
        if self.secret.is_empty() {
            "/mcp".to_string()
        } else {
            format!("/{}/mcp", self.secret.trim_matches('/'))
        }
    }
}

#[derive(Clone)]
pub struct GatewayHandle {
    oauth: Arc<OAuthService>,
}

impl GatewayHandle {
    pub fn set_issuer(&self, issuer: impl Into<String>) {
        self.oauth.set_issuer(issuer);
    }

    pub fn issuer(&self) -> String {
        self.oauth.issuer()
    }
}

struct GatewayState {
    cfg: GatewayServerConfig,
    oauth: Arc<OAuthService>,
    lanes: ServiceLanes,
    audit: AuditLog,
    journal: TaskJournal,
    http: Client,
}

fn sanitize_schema_for_google(val: &mut Value) {
    match val {
        Value::Object(map) => {
            map.remove("additionalProperties");
            map.remove("$schema");
            for v in map.values_mut() {
                sanitize_schema_for_google(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                sanitize_schema_for_google(v);
            }
        }
        _ => {}
    }
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn git_tools() -> Vec<Value> {
    let defs = [
        ("git_status", "Read git status for the configured workspace. Read-only."),
        ("git_diff", "Read git diff for the configured workspace. Read-only."),
        ("git_log", "Read recent git history for the configured workspace. Read-only."),
        ("git_show", "Read a git object or commit for the configured workspace. Read-only."),
    ];
    defs.into_iter()
        .map(|(name, desc)| {
            json!({
                "name": name,
                "description": desc,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cwd": { "type": "string" },
                        "extra_args": { "type": "array", "items": { "type": "string" } }
                    },
                    "additionalProperties": false
                },
                "annotations": { "readOnlyHint": true, "destructiveHint": false }
            })
        })
        .collect()
}

fn command_tools() -> Vec<Value> {
    vec![
        json!({
            "name": "run_command",
            "description": "Run a PowerShell 7 command through AI Workbench supervised by a Windows Job Object.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "commandLine": { "type": "string", "minLength": 1, "maxLength": 16384 },
                    "cwd": { "type": "string" },
                    "timeout": { "type": "integer", "minimum": 1, "maximum": 600 }
                },
                "required": ["commandLine"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true }
        }),
        json!({
            "name": "workbench_status",
            "description": "Inspect the gateway command and its Windows process tree before review.",
            "inputSchema": {
                "type": "object",
                "properties": { "task_id": { "type": "string" } },
                "required": ["task_id"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true }
        }),
        json!({
            "name": "workbench_stop",
            "description": "Stop only this gateway command and its child process tree.",
            "inputSchema": {
                "type": "object",
                "properties": { "task_id": { "type": "string" } },
                "required": ["task_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "workbench_review",
            "description": "Complete resource review using the latest revision.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "task_id": { "type": "string" },
                    "revision": { "type": "string" }
                },
                "required": ["task_id", "revision"],
                "additionalProperties": false
            }
        }),
    ]
}

impl GatewayState {
    async fn upstream_rpc(&self, url: &str, token: &str, method: &str, params: Value) -> Result<Value> {
        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
            }));
        if !token.is_empty() {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        let data: Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("upstream HTTP {status}");
        }
        if let Some(err) = data.get("error") {
            anyhow::bail!("{}", err["message"].as_str().unwrap_or("upstream RPC error"));
        }
        Ok(data.get("result").cloned().unwrap_or(Value::Null))
    }

    async fn workbench_post(&self, route: &str, payload: Value) -> Result<Value> {
        let base = self
            .cfg
            .workbench_url
            .trim_end_matches('/')
            .trim_end_matches("/mcp");
        let url = format!("{base}{route}");
        let mut req = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .json(&payload);
        if !self.cfg.workbench_token.is_empty() {
            req = req.header("authorization", format!("Bearer {}", self.cfg.workbench_token));
        }
        let resp = req.send().await?;
        let status = resp.status();
        let data: Value = resp.json().await?;
        if !status.is_success() {
            anyhow::bail!("workbench HTTP {status}");
        }
        Ok(data)
    }

    async fn list_tools(&self, platform: Platform) -> Vec<Value> {
        let mut all = Vec::new();
        let readwrite = self.cfg.mode.eq_ignore_ascii_case("readwrite");

        // 1. Upstream FS tools
        if let Ok(res) = self
            .upstream_rpc(&self.cfg.fs_url, &self.cfg.fs_token, "tools/list", json!({}))
            .await
        {
            if let Some(arr) = res.get("tools").and_then(Value::as_array) {
                for item in arr {
                    let Some(raw_name) = item.get("name").and_then(Value::as_str) else {
                        continue;
                    };
                    let is_ro = READ_ONLY_FS.contains(&raw_name);
                    let is_rw = WRITE_FS.contains(&raw_name);
                    if !is_ro && !(readwrite && is_rw) {
                        continue;
                    }
                    let ns_name = format!("fs_{raw_name}");
                    if platform == Platform::Google && ns_name == "fs_read_media_file" {
                        continue;
                    }
                    let mut tool = item.clone();
                    tool["name"] = json!(ns_name);
                    tool["annotations"] = json!({
                        "readOnlyHint": is_ro,
                        "destructiveHint": !is_ro
                    });
                    all.push(tool);
                }
            }
        }

        // 2. Git & Command tools (via Workbench)
        if self.cfg.enable_commands {
            all.extend(git_tools());
            if readwrite {
                all.extend(command_tools());
            }
        }

        // 3. Optional Chrome MCP tools
        if self.cfg.enable_chrome && !self.cfg.chrome_url.is_empty() {
            if let Ok(res) = self
                .upstream_rpc(
                    &self.cfg.chrome_url,
                    &self.cfg.chrome_token,
                    "tools/list",
                    json!({}),
                )
                .await
            {
                if let Some(arr) = res.get("tools").and_then(Value::as_array) {
                    for item in arr {
                        let Some(raw_name) = item.get("name").and_then(Value::as_str) else {
                            continue;
                        };
                        if raw_name == "select_page" {
                            continue;
                        }
                        let mut tool = item.clone();
                        let ns_name = format!("chrome_{raw_name}");
                        tool["name"] = json!(ns_name);
                        if platform == Platform::Google && ns_name == "chrome_take_screenshot" {
                            let desc = tool
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            tool["description"] = json!(format!(
                                "{desc} In Google Gemini Web, inline image blocks are stripped to {{}}; always pass an explicit absolute filePath inside an allowed directory."
                            ));
                        }
                        all.push(tool);
                    }
                }
            }
        }

        // 4. Recovery wait tool + optional Google Gemini inspect_image tool
        all.push(wait_tool_definition());
        if platform == Platform::Google && self.cfg.vision.is_enabled() {
            all.push(inspect_image_tool_definition());
        }

        if platform == Platform::Google {
            for tool in &mut all {
                if let Some(schema) = tool.get_mut("inputSchema") {
                    sanitize_schema_for_google(schema);
                }
            }
        }

        all
    }

    async fn call_tool(&self, platform: Platform, owner: &str, name: &str, args: Value) -> Value {
        let lane = ServiceLanes::lane_for_tool(name);
        let _permit = match self.lanes.acquire(lane).await {
            Ok(p) => p,
            Err(e) => return json!({ "isError": true, "content": [{ "type": "text", "text": e }] }),
        };

        self.audit.record(
            "tool_call",
            json!({ "tool": name, "lane": lane, "owner": owner }),
        );

        if name == "wait" {
            let task_id = args.get("task_id").and_then(Value::as_str).unwrap_or("");
            let wait_ms = args
                .get("wait_ms")
                .and_then(Value::as_u64)
                .unwrap_or(500)
                .clamp(100, 20_000);
            if task_id.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(wait_ms.min(2000))).await;
                return json!({ "content": [{ "type": "text", "text": "{\"status\":\"ready\"}" }] });
            }
            if let Some(rec) = self.journal.get(task_id, owner) {
                if let Some(res) = rec.result {
                    return res;
                }
                return json!({ "content": [{ "type": "text", "text": serde_json::to_string(&rec).unwrap_or_default() }] });
            }
            return json!({ "isError": true, "content": [{ "type": "text", "text": format!("Unknown task_id: {task_id}") }] });
        }

        if name == "inspect_image" {
            if platform != Platform::Google {
                return json!({ "isError": true, "content": [{ "type": "text", "text": "inspect_image is only exposed to Google Gemini sessions" }] });
            }
            return run_inspect_image(&self.http, &self.cfg.vision, &args).await;
        }

        // Google Gemini image-block stripping protection
        if platform == Platform::Google && name == "fs_read_media_file" {
            return json!({
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": "Google Gemini Web strips MCP image content blocks to an empty object ({}). Do NOT call fs_read_media_file."
                }]
            });
        }

        if let Some(fs_tool) = name.strip_prefix("fs_") {
            let readwrite = self.cfg.mode.eq_ignore_ascii_case("readwrite");
            let allowed = READ_ONLY_FS.contains(&fs_tool)
                || (readwrite && WRITE_FS.contains(&fs_tool));
            if !allowed {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("Tool not allowed in current mode: {name}") }]
                });
            }
            return match self
                .upstream_rpc(
                    &self.cfg.fs_url,
                    &self.cfg.fs_token,
                    "tools/call",
                    json!({ "name": fs_tool, "arguments": args }),
                )
                .await
            {
                Ok(res) => res,
                Err(e) => json!({ "isError": true, "content": [{ "type": "text", "text": e.to_string() }] }),
            };
        }

        if let Some(chrome_tool) = name.strip_prefix("chrome_") {
            if !self.cfg.enable_chrome {
                return json!({ "isError": true, "content": [{ "type": "text", "text": "Chrome MCP is disabled" }] });
            }
            if platform == Platform::Google && chrome_tool == "take_screenshot" {
                let has_path = args
                    .get("filePath")
                    .and_then(Value::as_str)
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !has_path {
                    return json!({
                        "isError": true,
                        "content": [{
                            "type": "text",
                            "text": "Google Gemini Web strips inline MCP image blocks to {}. Pass an explicit absolute filePath inside an allowed directory."
                        }]
                    });
                }
            }
            return match self
                .upstream_rpc(
                    &self.cfg.chrome_url,
                    &self.cfg.chrome_token,
                    "tools/call",
                    json!({ "name": chrome_tool, "arguments": args }),
                )
                .await
            {
                Ok(res) => res,
                Err(e) => json!({ "isError": true, "content": [{ "type": "text", "text": e.to_string() }] }),
            };
        }

        // Git read-only tools & run_command via Workbench
        if matches!(name, "git_status" | "git_diff" | "git_log" | "git_show" | "run_command") {
            if !self.cfg.enable_commands {
                return json!({ "isError": true, "content": [{ "type": "text", "text": "Command execution is disabled" }] });
            }
            let cwd = args
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(&self.cfg.workspace_root)
                .to_string();
            let timeout = args.get("timeout").and_then(Value::as_u64).unwrap_or(60).clamp(1, 600);

            let cmd_line = if name == "run_command" {
                match args.get("commandLine").and_then(Value::as_str) {
                    Some(c) if !c.trim().is_empty() => c.to_string(),
                    _ => return json!({ "isError": true, "content": [{ "type": "text", "text": "commandLine is required" }] }),
                }
            } else {
                let sub = name.strip_prefix("git_").unwrap();
                let extra: Vec<String> = args
                    .get("extra_args")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                    .unwrap_or_default();
                if let Err(e) = validate_readonly_git_args(&extra) {
                    return json!({ "isError": true, "content": [{ "type": "text", "text": e.to_string() }] });
                }
                let mut parts = vec!["git".to_string(), sub.to_string()];
                parts.extend(extra);
                let quoted: Vec<String> = parts.iter().map(|s| ps_quote(s)).collect();
                format!("& {}; exit $LASTEXITCODE", quoted.join(" "))
            };

            let task_id = Uuid::new_v4().to_string();
            let session_id = hex::encode(Sha256::digest(
                format!("{}:{owner}:{task_id}", self.cfg.instance_label).as_bytes(),
            ));
            let hook = match self
                .workbench_post(
                    "/hook",
                    json!({ "phase": "begin", "agent": "mcp-gateway", "sessionId": session_id, "turnId": task_id }),
                )
                .await
            {
                Ok(v) => v,
                Err(e) => return json!({ "isError": true, "content": [{ "type": "text", "text": e.to_string() }] }),
            };
            let Some(ctx_id) = hook.get("contextId").and_then(Value::as_str) else {
                return json!({ "isError": true, "content": [{ "type": "text", "text": "workbench hook returned no contextId" }] });
            };

            return match self
                .upstream_rpc(
                    &self.cfg.workbench_url,
                    &self.cfg.workbench_token,
                    "tools/call",
                    json!({
                        "name": "run_command",
                        "arguments": {
                            "contextId": ctx_id,
                            "taskName": "网关远程命令",
                            "name": name,
                            "command": cmd_line,
                            "cwd": cwd,
                            "requestId": task_id,
                            "timeoutSeconds": timeout,
                            "waitMs": (timeout * 1000).min(15_000)
                        }
                    }),
                )
                .await
            {
                Ok(res) => res,
                Err(e) => json!({ "isError": true, "content": [{ "type": "text", "text": e.to_string() }] }),
            };
        }

        json!({ "isError": true, "content": [{ "type": "text", "text": format!("Unknown tool: {name}") }] })
    }
}

async fn cors_preflight() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    let h = resp.headers_mut();
    h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    h.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("authorization, content-type, accept, mcp-protocol-version"),
    );
    resp
}

async fn healthz(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "rpc-mcp-gateway",
        "issuer": state.oauth.issuer(),
        "mcpPath": state.cfg.mcp_path(),
        "lanes": state.lanes.stats()
    }))
}

async fn well_known_prm(State(state): State<Arc<GatewayState>>) -> Response {
    state.oauth.handle_well_known_protected_resource()
}

async fn well_known_as(State(state): State<Arc<GatewayState>>) -> Response {
    state.oauth.handle_well_known_auth_server()
}

async fn oauth_register(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<Value>,
) -> Response {
    state.oauth.handle_register(body)
}

async fn oauth_authorize_get(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let lang = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state.oauth.handle_authorize(false, params, lang)
}

async fn oauth_authorize_post(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let lang = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state.oauth.handle_authorize(true, params, lang)
}

async fn oauth_token(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    state.oauth.handle_token(&body, &headers)
}

async fn mcp_handler(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let identity = if state.oauth.enabled() {
        match state.oauth.authenticate_bearer(&headers) {
            Some(id) => id,
            None => {
                let mut resp = (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "unauthorized" })),
                )
                    .into_response();
                if let Ok(val) = HeaderValue::from_str(&state.oauth.challenge_header()) {
                    resp.headers_mut().insert("www-authenticate", val);
                }
                return resp;
            }
        }
    } else {
        crate::oauth::AuthIdentity {
            client_id: "local".into(),
            platform: Platform::OpenAi,
        }
    };

    let Ok(payload) = serde_json::from_str::<Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "jsonrpc": "2.0", "error": { "code": -32700, "message": "Parse error" } })),
        )
            .into_response();
    };

    let id = payload.get("id").cloned();
    if id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let id = id.unwrap();
    let method = payload.get("method").and_then(Value::as_str).unwrap_or("");

    let resp_body = match method {
        "initialize" => {
            let ver = payload
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-06-18");
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": ver,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "rpc-mcp-gateway", "version": env!("CARGO_PKG_VERSION") }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => {
            let tools = state.list_tools(identity.platform).await;
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tools }
            })
        }
        "tools/call" => {
            let name = payload
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = payload
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let res = state
                .call_tool(identity.platform, &identity.client_id, name, args)
                .await;
            json!({ "jsonrpc": "2.0", "id": id, "result": res })
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };

    (StatusCode::OK, Json(resp_body)).into_response()
}

pub fn build_router(cfg: GatewayServerConfig) -> (Router, GatewayHandle) {
    let mut oauth_cfg = cfg.oauth.clone();
    oauth_cfg.mcp_path = cfg.mcp_path();
    let oauth = OAuthService::new(oauth_cfg);
    let handle = GatewayHandle {
        oauth: Arc::clone(&oauth),
    };
    let mcp_path = cfg.mcp_path();
    let state = Arc::new(GatewayState {
        audit: AuditLog::new(cfg.audit_log.clone()),
        journal: TaskJournal::new(cfg.task_dir.clone()),
        lanes: ServiceLanes::default_lanes(),
        http: Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client"),
        cfg,
        oauth,
    });

    let router = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/.well-known/oauth-protected-resource",
            get(well_known_prm).options(cors_preflight),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*rest}",
            get(well_known_prm).options(cors_preflight),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(well_known_as).options(cors_preflight),
        )
        .route(
            "/.well-known/oauth-authorization-server/{*rest}",
            get(well_known_as).options(cors_preflight),
        )
        .route(
            "/.well-known/openid-configuration",
            get(well_known_as).options(cors_preflight),
        )
        .route(
            "/oauth/register",
            post(oauth_register).options(cors_preflight),
        )
        .route(
            "/oauth/authorize",
            get(oauth_authorize_get)
                .post(oauth_authorize_post)
                .options(cors_preflight),
        )
        .route("/oauth/token", post(oauth_token).options(cors_preflight))
        .route(&mcp_path, post(mcp_handler).options(cors_preflight))
        .route("/", options(cors_preflight))
        .with_state(state);

    (router, handle)
}

pub async fn serve_gateway(cfg: GatewayServerConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let mcp_path = cfg.mcp_path();
    let (app, _handle) = build_router(cfg);
    let listener = TcpListener::bind(addr).await?;
    info!("READY rpc-mcp-gateway listening on http://{addr}{mcp_path}");
    axum::serve(listener, app).await?;
    Ok(())
}
