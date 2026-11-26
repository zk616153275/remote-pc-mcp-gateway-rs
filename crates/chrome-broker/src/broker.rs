use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rpc_mcp_core::audit::{summarize_target, AuditLog, AuditMeta};
use rpc_mcp_core::{constant_time_eq, extract_bearer_token};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ChromeBrokerConfig {
    pub host: String,
    pub port: u16,
    pub bearer_token: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    pub audit_log: Option<PathBuf>,
}

impl ChromeBrokerConfig {
    /// Default configuration supervising upstream `chrome-devtools-mcp@latest` (1.14+)
    /// connected to a shared local Chrome debugging endpoint.
    pub fn default_npx(port: u16, cdp_port: u16) -> Self {
        let cmd = if cfg!(windows) {
            "npx.cmd".to_string()
        } else {
            "npx".to_string()
        };
        Self {
            host: "127.0.0.1".into(),
            port,
            bearer_token: None,
            command: cmd,
            args: vec![
                "-y".into(),
                "chrome-devtools-mcp@latest".into(),
                "--browserUrl".into(),
                format!("http://127.0.0.1:{cdp_port}"),
            ],
            timeout_ms: 120_000,
            audit_log: None,
        }
    }
}

#[cfg(windows)]
struct WinJobGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
unsafe impl Send for WinJobGuard {}
#[cfg(windows)]
unsafe impl Sync for WinJobGuard {}

#[cfg(windows)]
impl WinJobGuard {
    fn attach_child(child: &Child) -> Option<Self> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let raw_handle = child.raw_handle()?;
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut limit: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limit as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                CloseHandle(job);
                return None;
            }
            if AssignProcessToJobObject(job, raw_handle as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self { handle: job })
        }
    }
}

#[cfg(windows)]
impl Drop for WinJobGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

struct RunningSidecar {
    child: Child,
    stdin: Arc<Mutex<ChildStdin>>,
    pending: PendingMap,
    #[cfg(windows)]
    _job: Option<WinJobGuard>,
}

pub struct SidecarBackend {
    cfg: ChromeBrokerConfig,
    inner: Mutex<Option<RunningSidecar>>,
    next_id: AtomicU64,
    generation: AtomicU64,
}

impl SidecarBackend {
    pub fn new(cfg: ChromeBrokerConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            inner: Mutex::new(None),
            next_id: AtomicU64::new(1),
            generation: AtomicU64::new(0),
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    async fn ensure_started(&self) -> Result<(Arc<Mutex<ChildStdin>>, PendingMap)> {
        let mut guard = self.inner.lock().await;
        if let Some(ref mut running) = *guard {
            if running.child.try_wait().ok().flatten().is_none() {
                return Ok((Arc::clone(&running.stdin), Arc::clone(&running.pending)));
            }
            warn!("Chrome sidecar exited unexpectedly; respawning");
            *guard = None;
        }

        let mut cmd = Command::new(&self.cfg.command);
        cmd.args(&self.cfg.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn chrome sidecar: {}", self.cfg.command))?;

        #[cfg(windows)]
        let job = WinJobGuard::attach_child(&child);

        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut err_lines = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = err_lines.next_line().await {
                    if !line.trim().is_empty() {
                        warn!("chrome sidecar stderr: {line}");
                    }
                }
            });
        }

        let stdin = Arc::new(Mutex::new(
            child.stdin.take().context("missing sidecar stdin")?,
        ));
        let stdout = child.stdout.take().context("missing sidecar stdout")?;
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

        let pending_reader = Arc::clone(&pending);
        let stdin_pong = Arc::clone(&stdin);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let oversized = line.len() > MAX_RESPONSE_BYTES;
                let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if msg.get("method").is_some() && msg.get("id").is_some() {
                    let reply = if msg["method"] == "ping" {
                        json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {} })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": { "code": -32601, "message": "Client capability unavailable" }
                        })
                    };
                    let mut w = stdin_pong.lock().await;
                    let _ = w.write_all(format!("{reply}\n").as_bytes()).await;
                    let _ = w.flush().await;
                    continue;
                }
                if let Some(id) = msg.get("id").and_then(Value::as_u64) {
                    if let Some(tx) = pending_reader.lock().await.remove(&id) {
                        if oversized {
                            let _ = tx.send(Err(
                                "RESPONSE_TOO_LARGE: Chrome result exceeds 8 MiB; use a smaller capture"
                                    .into(),
                            ));
                        } else if let Some(err) = msg.get("error") {
                            let _ = tx.send(Err(
                                err["message"]
                                    .as_str()
                                    .unwrap_or("Chrome sidecar error")
                                    .to_string(),
                            ));
                        } else {
                            let _ = tx.send(Ok(msg.get("result").cloned().unwrap_or(Value::Null)));
                        }
                    }
                }
            }
            // Fail any remaining waiters on EOF
            let mut map = pending_reader.lock().await;
            for (_, tx) in map.drain() {
                let _ = tx.send(Err("Chrome MCP sidecar exited unexpectedly".into()));
            }
        });

        // Perform MCP handshake while STILL holding `guard` so concurrent callers
        // cannot race before initialize completes, and failed handshakes do not cache a dead sidecar.
        let init_params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "rpc-mcp-chrome-broker", "version": env!("CARGO_PKG_VERSION") }
        });
        if let Err(e) = self
            .send_rpc(&stdin, &pending, "initialize", init_params, 15_000)
            .await
        {
            let _ = child.kill().await;
            return Err(e);
        }

        {
            let mut w = stdin.lock().await;
            let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
            if let Err(e) = w.write_all(format!("{notif}\n").as_bytes()).await {
                let _ = child.kill().await;
                return Err(e.into());
            }
            if let Err(e) = w.flush().await {
                let _ = child.kill().await;
                return Err(e.into());
            }
        }

        let gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        info!("Chrome MCP sidecar started and initialized (generation={gen})");

        *guard = Some(RunningSidecar {
            child,
            stdin: Arc::clone(&stdin),
            pending: Arc::clone(&pending),
            #[cfg(windows)]
            _job: job,
        });

        Ok((stdin, pending))
    }

    async fn send_rpc(
        &self,
        stdin: &Arc<Mutex<ChildStdin>>,
        pending: &PendingMap,
        method: &str,
        params: Value,
        timeout_ms: u64,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        pending.lock().await.insert(id, tx);

        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        });
        let write_res: Result<()> = async {
            let mut w = stdin.lock().await;
            w.write_all(format!("{req}\n").as_bytes()).await?;
            w.flush().await?;
            Ok(())
        }
        .await;
        if let Err(e) = write_res {
            pending.lock().await.remove(&id);
            return Err(e);
        }

        match tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await {
            Ok(Ok(Ok(val))) => Ok(val),
            Ok(Ok(Err(e))) => anyhow::bail!("{e}"),
            Ok(Err(_)) => anyhow::bail!("Chrome sidecar channel dropped"),
            Err(_) => {
                pending.lock().await.remove(&id);
                anyhow::bail!("Chrome MCP call timed out after {timeout_ms}ms");
            }
        }
    }

    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let (stdin, pending) = self.ensure_started().await?;
        let res = self
            .send_rpc(&stdin, &pending, method, params, self.cfg.timeout_ms)
            .await;
        if res.is_err() {
            // Recycle wedged sidecar if it exited
            let mut guard = self.inner.lock().await;
            if let Some(ref mut r) = *guard {
                if r.child.try_wait().ok().flatten().is_some() {
                    *guard = None;
                }
            }
        }
        res
    }

    pub async fn shutdown(&self) {
        let mut guard = self.inner.lock().await;
        if let Some(mut r) = guard.take() {
            let _ = r.child.kill().await;
        }
    }
}

struct BrokerState {
    cfg: ChromeBrokerConfig,
    backend: Arc<SidecarBackend>,
    audit: AuditLog,
}

fn check_auth(headers: &HeaderMap, token: &Option<String>) -> bool {
    let Some(expected) = token else {
        return true;
    };
    if expected.is_empty() {
        return true;
    }
    let Some(got) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
    else {
        return false;
    };
    constant_time_eq(got, expected)
}

async fn healthz(State(state): State<Arc<BrokerState>>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "service": "rpc-mcp-chrome-broker",
        "generation": state.backend.generation()
    }))
}

async fn mcp_delete(State(state): State<Arc<BrokerState>>, headers: HeaderMap) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn mcp_post(
    State(state): State<Arc<BrokerState>>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    if !check_auth(&headers, &state.cfg.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response();
    }

    let id = payload.get("id").cloned();
    if id.is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let id = id.unwrap();
    let method = payload.get("method").and_then(Value::as_str).unwrap_or("");

    let body = match method {
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
                    "serverInfo": { "name": "rpc-mcp-chrome-broker", "version": env!("CARGO_PKG_VERSION") }
                }
            })
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        "tools/list" => match state.backend.rpc("tools/list", json!({})).await {
            Ok(mut res) => {
                // In stateless shared-browser mode, strip select_page to enforce explicit pageId isolation
                if let Some(arr) = res.get_mut("tools").and_then(Value::as_array_mut) {
                    arr.retain(|t| t.get("name").and_then(Value::as_str) != Some("select_page"));
                }
                json!({ "jsonrpc": "2.0", "id": id, "result": res })
            }
            Err(e) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32000, "message": e.to_string() }
            }),
        },
        "tools/call" => {
            let params = payload.get("params").cloned().unwrap_or_else(|| json!({}));
            if params.get("name").and_then(Value::as_str) == Some("select_page") {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "isError": true,
                        "content": [{ "type": "text", "text": "select_page is disabled in shared-browser mode; pass an explicit pageId to each tool." }]
                    }
                })
            } else {
                let raw_name = params.get("name").and_then(Value::as_str).unwrap_or("unknown");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let meta = AuditMeta::from_header_values(
                    headers.get("x-mcp-platform").and_then(|v| v.to_str().ok()),
                    headers.get("x-mcp-owner").and_then(|v| v.to_str().ok()),
                    headers.get("x-mcp-tool").and_then(|v| v.to_str().ok()),
                );
                let tool_name = meta
                    .tool_override
                    .unwrap_or_else(|| format!("chrome_{raw_name}"));
                let target = summarize_target(&args);
                state.audit.record(
                    "tool_call",
                    json!({
                        "tool": tool_name,
                        "lane": "chrome",
                        "owner": meta.owner,
                        "platform": meta.platform,
                        "target": target,
                        "source": "local-chrome"
                    }),
                );
                match state.backend.rpc("tools/call", params).await {
                    Ok(res) => json!({ "jsonrpc": "2.0", "id": id, "result": res }),
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
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("Method not found: {other}") }
        }),
    };

    (StatusCode::OK, Json(body)).into_response()
}

pub fn build_router(cfg: ChromeBrokerConfig) -> (Router, Arc<SidecarBackend>) {
    let backend = SidecarBackend::new(cfg.clone());
    let audit = AuditLog::new(cfg.audit_log.clone());
    let state = Arc::new(BrokerState {
        cfg,
        backend: Arc::clone(&backend),
        audit,
    });
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/mcp", post(mcp_post).delete(mcp_delete))
        .with_state(state);
    (router, backend)
}

pub async fn serve_chrome_broker(cfg: ChromeBrokerConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port).parse()?;
    let (app, backend) = build_router(cfg);
    let listener = TcpListener::bind(addr).await?;
    info!("READY rpc-mcp-chrome-broker listening on http://{addr}");
    let res = axum::serve(listener, app).await;
    backend.shutdown().await;
    res?;
    Ok(())
}
