use crate::job_runner::{CommandSpec, CommandStatus};
use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use rpc_mcp_core::delete_guard::{DeleteGuard, GuardDecision};
use rpc_mcp_core::{constant_time_eq, write_atomic_string};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct WorkbenchConfig {
    pub host: String,
    pub port: u16,
    pub bearer_token: String,
    pub state_root: PathBuf,
    pub pwsh_path: String,
    pub enable_delete_guard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionRecord {
    session_key: String,
    agent: String,
    session_id: String,
    context_id: String,
    task_id: String,
    turn_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskCommandRef {
    command_id: String,
    request_id: String,
    name: String,
    cwd: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TaskRecord {
    task_id: String,
    tag_id: String,
    context_id: String,
    name: String,
    reviewed_revision: Option<String>,
    commands: Vec<TaskCommandRef>,
}

pub struct WorkbenchEngine {
    root: PathBuf,
    pwsh_path: String,
    delete_guard: DeleteGuard,
    lock: Mutex<()>,
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    hex::encode(h.finalize())
}

fn is_terminal(state: &str) -> bool {
    matches!(state, "exited" | "stopped" | "failed" | "interrupted")
}

#[cfg(windows)]
fn is_command_locked(cmd_dir: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    let lock_path = cmd_dir.join("owner.lock");
    if !lock_path.exists() {
        return false;
    }
    match OpenOptions::new().read(true).write(true).share_mode(0).open(&lock_path) {
        Ok(_) => false,
        Err(_) => true,
    }
}

#[cfg(not(windows))]
fn is_command_locked(_cmd_dir: &Path) -> bool {
    false
}

impl WorkbenchEngine {
    pub fn new(root: PathBuf, pwsh_path: String, enable_delete_guard: bool) -> Result<Self> {
        for sub in ["commands", "contexts", "sessions", "tasks", "delete-guard"] {
            fs::create_dir_all(root.join(sub))?;
        }
        let delete_guard = DeleteGuard::new(root.join("delete-guard"), enable_delete_guard);
        Ok(Self {
            root,
            pwsh_path,
            delete_guard,
            lock: Mutex::new(()),
        })
    }

    fn session_file(&self, key: &str) -> PathBuf {
        self.root.join("sessions").join(format!("s_{}.json", &key[..32]))
    }

    fn context_file(&self, context_id: &str) -> PathBuf {
        self.root.join("contexts").join(format!("{context_id}.json"))
    }

    fn task_file(&self, task_id: &str) -> PathBuf {
        self.root.join("tasks").join(format!("{task_id}.json"))
    }

    fn command_dir(&self, command_id: &str) -> PathBuf {
        self.root.join("commands").join(command_id)
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> Option<T> {
        let raw = fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn write_json<T: Serialize>(&self, path: &Path, val: &T) -> Result<()> {
        let raw = serde_json::to_string_pretty(val)?;
        write_atomic_string(path, &raw)?;
        Ok(())
    }

    pub fn hook(&self, body: &Value) -> Result<Value> {
        let _g = self.lock.lock().unwrap();
        let phase = body.get("phase").and_then(Value::as_str).unwrap_or("lookup");
        let agent = body.get("agent").and_then(Value::as_str).unwrap_or("mcp-gateway");
        let session_id = body
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("sessionId is required"))?;
        let turn_id = body
            .get("turnId")
            .and_then(Value::as_str)
            .unwrap_or("turn");
        let session_key = sha256_hex(&format!("{agent}:{session_id}"));
        let s_file = self.session_file(&session_key);

        match phase {
            "begin" => {
                if let Some(mut existing) = self.read_json::<SessionRecord>(&s_file) {
                    existing.turn_id = turn_id.to_string();
                    self.write_json(&s_file, &existing)?;
                    return Ok(json!({ "contextId": existing.context_id, "taskId": existing.task_id }));
                }
                let context_id = format!("x_{}", &sha256_hex(&format!("ctx:{session_key}"))[..32]);
                let task_id = format!("t_{}", &sha256_hex(&format!("task:{session_key}"))[..32]);
                let rec = SessionRecord {
                    session_key: session_key.clone(),
                    agent: agent.to_string(),
                    session_id: session_id.to_string(),
                    context_id: context_id.clone(),
                    task_id: task_id.clone(),
                    turn_id: turn_id.to_string(),
                };
                self.write_json(&s_file, &rec)?;
                self.write_json(&self.context_file(&context_id), &rec)?;
                let task = TaskRecord {
                    task_id: task_id.clone(),
                    tag_id: task_id.clone(),
                    context_id: context_id.clone(),
                    name: "Workbench Task".to_string(),
                    reviewed_revision: None,
                    commands: Vec::new(),
                };
                self.write_json(&self.task_file(&task_id), &task)?;
                Ok(json!({ "contextId": context_id, "taskId": task_id }))
            }
            "lookup" => {
                if let Some(existing) = self.read_json::<SessionRecord>(&s_file) {
                    Ok(json!({ "contextId": existing.context_id, "taskId": existing.task_id }))
                } else {
                    Ok(json!({ "contextId": Value::Null }))
                }
            }
            "complete" => {
                let Some(existing) = self.read_json::<SessionRecord>(&s_file) else {
                    return Ok(json!({ "required": false }));
                };
                let task_view = self.build_task_view(&existing.task_id)?;
                let any_active = task_view["commands"]
                    .as_array()
                    .map(|arr| {
                        arr.iter().any(|c| {
                            let st = c["state"].as_str().unwrap_or("");
                            let procs = c["processes"].as_array().map(|p| !p.is_empty()).unwrap_or(false);
                            let ports = c["ports"].as_array().map(|p| !p.is_empty()).unwrap_or(false);
                            !is_terminal(st) || procs || ports || c["timedOut"].as_bool().unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
                if !any_active {
                    if let Some(mut task) = self.read_json::<TaskRecord>(&self.task_file(&existing.task_id)) {
                        task.reviewed_revision = task_view["revision"].as_str().map(String::from);
                        let _ = self.write_json(&self.task_file(&existing.task_id), &task);
                    }
                }
                Ok(json!({ "required": any_active }))
            }
            other => anyhow::bail!("unsupported hook phase: {other}"),
        }
    }

    fn read_command_state(&self, command_id: &str) -> Value {
        let dir = self.command_dir(command_id);
        let locked = is_command_locked(&dir);
        if let Some(st) = self.read_json::<CommandStatus>(&dir.join("status.json")) {
            let mut state = st.state.clone();
            if state == "running" && !locked {
                state = "interrupted".to_string();
            }
            return json!({
                "commandId": st.command_id,
                "state": state,
                "exitCode": st.exit_code,
                "timedOut": st.timed_out,
                "processes": st.processes,
                "ports": st.ports,
                "settling": false,
                "stale": false,
                "startedAt": st.started_at,
                "updatedAt": st.updated_at,
                "finishedAt": st.finished_at,
                "error": st.error,
            });
        }
        json!({
            "commandId": command_id,
            "state": if locked { "running" } else { "starting" },
            "exitCode": Value::Null,
            "timedOut": false,
            "processes": [],
            "ports": [],
            "settling": locked,
            "stale": false,
        })
    }

    fn build_task_view(&self, task_id: &str) -> Result<Value> {
        let task: TaskRecord = self
            .read_json(&self.task_file(task_id))
            .ok_or_else(|| anyhow::anyhow!("task not found: {task_id}"))?;
        let mut commands = Vec::new();
        for c in &task.commands {
            let mut st = self.read_command_state(&c.command_id);
            if let Some(obj) = st.as_object_mut() {
                obj.insert("requestId".into(), json!(c.request_id));
                obj.insert("name".into(), json!(c.name));
                obj.insert("cwd".into(), json!(c.cwd));
            }
            commands.push(st);
        }
        let rev_payload = serde_json::to_string(&commands)?;
        let revision = sha256_hex(&rev_payload)[..16].to_string();
        let review_required = task.reviewed_revision.as_deref() != Some(revision.as_str());
        Ok(json!({
            "taskId": task.task_id,
            "tagId": task.tag_id,
            "name": task.name,
            "revision": revision,
            "reviewRequired": review_required,
            "commands": commands,
        }))
    }

    fn spawn_job_runner(&self, cmd_dir: &Path) -> Result<()> {
        let exe = std::env::current_exe()?;
        let mut cmd = Command::new(exe);
        cmd.arg("job-runner")
            .arg(cmd_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x00000008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
        }
        let _child = cmd.spawn()?;
        Ok(())
    }

    fn read_output_chunk(
        &self,
        command_id: &str,
        offset: u64,
        max_bytes: usize,
        want_entries: bool,
    ) -> Value {
        let dir = self.command_dir(command_id);
        let state = self.read_command_state(command_id);
        let log_path = dir.join("output.jsonl");
        let mut next_offset = offset;
        let mut text = String::new();
        let mut entries = Vec::new();
        let mut has_more = false;
        let mut truncated = false;

        if let Ok(mut f) = fs::File::open(&log_path) {
            let file_len = f.metadata().map(|m| m.len()).unwrap_or(0);
            if offset > file_len {
                next_offset = 0;
                truncated = true;
            }
            if f.seek(SeekFrom::Start(next_offset)).is_ok() {
                let to_read = ((file_len.saturating_sub(next_offset)) as usize).min(max_bytes);
                let mut buf = vec![0u8; to_read];
                if let Ok(n) = f.read(&mut buf) {
                    let slice = &buf[..n];
                    if let Some(last_nl) = slice.iter().rposition(|&b| b == b'\n') {
                        next_offset += (last_nl + 1) as u64;
                        let chunk = String::from_utf8_lossy(&slice[..last_nl]);
                        for line in chunk.lines() {
                            if let Ok(val) = serde_json::from_str::<Value>(line) {
                                if let Some(t) = val.get("text").and_then(Value::as_str) {
                                    text.push_str(t);
                                    if want_entries {
                                        entries.push(val);
                                    }
                                }
                            }
                        }
                    }
                    has_more = next_offset < file_len;
                }
            }
        }

        let mut resp = json!({
            "commandId": command_id,
            "state": state["state"],
            "exitCode": state["exitCode"],
            "timedOut": state["timedOut"],
            "settling": state["settling"],
            "nextOffset": next_offset,
            "hasMore": has_more,
            "truncated": truncated,
            "text": text,
        });
        if want_entries {
            resp["entries"] = json!(entries);
        }
        resp
    }

    pub async fn call_tool(&self, name: &str, args: &Value) -> Result<Value> {
        match name {
            "run_command" => {
                let context_id = args["contextId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("contextId is required"))?;
                let cmd_name = args["name"].as_str().unwrap_or("command");
                let command = args["command"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("command is required"))?;
                let cwd = args["cwd"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("cwd is required"))?;
                let request_id = args["requestId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("requestId is required"))?;
                let wait_ms = args["waitMs"].as_u64().unwrap_or(0).min(15_000);
                let timeout_seconds = args["timeoutSeconds"].as_u64().map(|v| v.clamp(1, 600));
                let want_entries = args["entries"].as_bool().unwrap_or(false);

                // Delete Guard check
                match self.delete_guard.check(command, Path::new(cwd)) {
                    GuardDecision::BlockFirstAttempt { message, .. } => {
                        anyhow::bail!("{message}");
                    }
                    GuardDecision::Allow | GuardDecision::AllowConfirmedOnce { .. } => {}
                }

                let command_id = {
                    let _g = self.lock.lock().unwrap();
                    let ctx: SessionRecord = self
                        .read_json(&self.context_file(context_id))
                        .ok_or_else(|| anyhow::anyhow!("unknown contextId: {context_id}"))?;
                    let mut task: TaskRecord = self
                        .read_json(&self.task_file(&ctx.task_id))
                        .ok_or_else(|| anyhow::anyhow!("task missing"))?;
                    if let Some(tn) = args.get("taskName").and_then(Value::as_str) {
                        if task.commands.is_empty() && !tn.trim().is_empty() {
                            task.name = tn.to_string();
                        }
                    }
                    if let Some(existing) = task.commands.iter().find(|c| c.request_id == request_id)
                    {
                        existing.command_id.clone()
                    } else {
                        let cid = format!("c_{}", Uuid::new_v4());
                        let dir = self.command_dir(&cid);
                        fs::create_dir_all(&dir)?;
                        let spec = CommandSpec {
                            command_id: cid.clone(),
                            command: command.to_string(),
                            cwd: cwd.to_string(),
                            pwsh: self.pwsh_path.clone(),
                            timeout_seconds,
                        };
                        self.write_json(&dir.join("spec.json"), &spec)?;
                        task.commands.push(TaskCommandRef {
                            command_id: cid.clone(),
                            request_id: request_id.to_string(),
                            name: cmd_name.to_string(),
                            cwd: cwd.to_string(),
                            created_at: Utc::now().to_rfc3339(),
                        });
                        task.reviewed_revision = None;
                        self.write_json(&self.task_file(&ctx.task_id), &task)?;
                        self.spawn_job_runner(&dir)?;
                        cid
                    }
                };

                if wait_ms > 0 {
                    let deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_millis(wait_ms);
                    loop {
                        let st = self.read_command_state(&command_id);
                        if is_terminal(st["state"].as_str().unwrap_or("")) {
                            break;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                    }
                }

                let state = self.read_command_state(&command_id);
                let out = self.read_output_chunk(&command_id, 0, 65536, want_entries);
                Ok(json!({
                    "commandId": command_id,
                    "state": state["state"],
                    "exitCode": state["exitCode"],
                    "timedOut": state["timedOut"],
                    "processes": state["processes"],
                    "ports": state["ports"],
                    "error": state["error"],
                    "output": out,
                }))
            }

            "get_task_status" => {
                let context_id = args["contextId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("contextId is required"))?;
                let ctx: SessionRecord = self
                    .read_json(&self.context_file(context_id))
                    .ok_or_else(|| anyhow::anyhow!("unknown contextId: {context_id}"))?;
                let view = self.build_task_view(&ctx.task_id)?;
                Ok(json!({ "tasks": [view] }))
            }

            "get_command_output" => {
                let command_id = args["commandId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("commandId is required"))?;
                let offset = args["offset"].as_u64().unwrap_or(0);
                let max_bytes = args["maxBytes"].as_u64().unwrap_or(65536).clamp(1024, 65536) as usize;
                let wait_ms = args["waitMs"].as_u64().unwrap_or(0).min(15_000);
                let want_entries = args["entries"].as_bool().unwrap_or(false);

                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
                loop {
                    let out = self.read_output_chunk(command_id, offset, max_bytes, want_entries);
                    let got_data = out["nextOffset"].as_u64().unwrap_or(offset) > offset;
                    let term = is_terminal(out["state"].as_str().unwrap_or(""));
                    if got_data || term || tokio::time::Instant::now() >= deadline {
                        return Ok(out);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
                }
            }

            "stop_command" => {
                let command_id = args["commandId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("commandId is required"))?;
                let dir = self.command_dir(command_id);
                if dir.exists() {
                    write_atomic_string(
                        &dir.join("stop.json"),
                        &json!({ "requestedAt": Utc::now().to_rfc3339() }).to_string(),
                    )?;
                    let deadline =
                        tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                    while tokio::time::Instant::now() < deadline {
                        let st = self.read_command_state(command_id);
                        if is_terminal(st["state"].as_str().unwrap_or(""))
                            && !is_command_locked(&dir)
                        {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
                Ok(self.read_command_state(command_id))
            }

            "complete_review" => {
                let context_id = args["contextId"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("contextId is required"))?;
                let revision = args["revision"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("revision is required"))?;
                let _g = self.lock.lock().unwrap();
                let ctx: SessionRecord = self
                    .read_json(&self.context_file(context_id))
                    .ok_or_else(|| anyhow::anyhow!("unknown contextId: {context_id}"))?;
                let view = self.build_task_view(&ctx.task_id)?;
                let current_rev = view["revision"].as_str().unwrap_or("");
                if current_rev != revision {
                    anyhow::bail!(
                        "stale revision: expected {current_rev}, got {revision}; inspect status again"
                    );
                }
                let mut task: TaskRecord = self
                    .read_json(&self.task_file(&ctx.task_id))
                    .ok_or_else(|| anyhow::anyhow!("task missing"))?;
                task.reviewed_revision = Some(current_rev.to_string());
                self.write_json(&self.task_file(&ctx.task_id), &task)?;
                Ok(json!({ "reviewRequired": false, "revision": current_rev }))
            }

            other => anyhow::bail!("unknown workbench tool: {other}"),
        }
    }

    pub fn prune(&self) -> Value {
        let _g = self.lock.lock().unwrap();
        json!({ "pruned": 0 })
    }
}

struct WbState {
    cfg: WorkbenchConfig,
    engine: Arc<WorkbenchEngine>,
}

fn check_auth(headers: &HeaderMap, expected: &str) -> bool {
    let Some(raw) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(token.trim(), expected)
}

async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "service": "rpc-mcp-workbench" })),
    )
}

async fn handle_hook(
    State(state): State<Arc<WbState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }
    match state.engine.hook(&body) {
        Ok(val) => (StatusCode::OK, Json(val)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn handle_prune(State(state): State<Arc<WbState>>, headers: HeaderMap) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }
    (StatusCode::OK, Json(state.engine.prune())).into_response()
}

async fn handle_mcp_delete(State(state): State<Arc<WbState>>, headers: HeaderMap) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_mcp_or_panel(
    State(state): State<Arc<WbState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }
    let id = body.get("id").cloned().unwrap_or(json!(1));
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "rpc-mcp-workbench", "version": env!("CARGO_PKG_VERSION") }
            }
        }),
        "tools/call" => {
            let name = body.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
            let args = body
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match state.engine.call_tool(name, &args).await {
                Ok(val) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": serde_json::to_string(&val).unwrap_or_default() }]
                    }
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{ "type": "text", "text": e.to_string() }]
                    }
                }),
            }
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };
    (StatusCode::OK, Json(result)).into_response()
}

pub fn build_router(cfg: WorkbenchConfig, engine: Arc<WorkbenchEngine>) -> Router {
    let state = Arc::new(WbState { cfg, engine });
    Router::new()
        .route("/healthz", get(healthz))
        .route("/hook", post(handle_hook))
        .route("/prune", post(handle_prune))
        .route("/panel", post(handle_mcp_or_panel))
        .route("/mcp", post(handle_mcp_or_panel).delete(handle_mcp_delete))
        .with_state(state)
}

pub async fn serve_workbench(cfg: WorkbenchConfig) -> Result<()> {
    let engine = Arc::new(WorkbenchEngine::new(
        cfg.state_root.clone(),
        cfg.pwsh_path.clone(),
        cfg.enable_delete_guard,
    )?);
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let app = build_router(cfg, engine);
    let listener = TcpListener::bind(addr).await?;
    info!("READY rpc-mcp-workbench listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// Keep HashMap import clean for future panel extensions
#[allow(dead_code)]
type _UnusedMap = HashMap<String, Value>;
