#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use base64::Engine;
use chrono::{DateTime, Local, Utc};
use rand::RngCore;
use rpc_mcp_bridge::{
    start_cloudflare_tunnel, start_ssh_reverse_tunnel, CloudflareOptions, RunningSshTunnel,
    RunningTunnel, SshTunnelOptions, SshTunnelState,
};
use rpc_mcp_chrome_broker::{
    build_router as build_chrome_router, ChromeBrokerConfig, SidecarBackend,
};
use rpc_mcp_core::config::AppConfig;
use rpc_mcp_core::instance_lock::InstanceLock;
use rpc_mcp_core::path_guard::AllowedRoots;
use rpc_mcp_core::write_atomic_string;
use rpc_mcp_fs::{build_router as build_fs_router, FsServerConfig};
use rpc_mcp_gateway::{
    build_router as build_gw_router, GatewayServerConfig, OAuthConfig, VisionConfig,
};
use rpc_mcp_workbench::{
    build_router as build_wb_router, run_job_runner, WorkbenchConfig, WorkbenchEngine,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{error, info};

const MAX_LOG_LINES: usize = 300;
const MAX_ACTIVITY_ITEMS: usize = 80;

#[cfg(windows)]
mod single_instance {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateMutexW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE,
        INFINITE,
    };

    const MUTEX_NAME: &str = "Local\\RemotePcMcpGatewayGuiMutex";
    const WAKE_EVENT_NAME: &str = "Local\\RemotePcMcpGatewayGuiWakeEvent";

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct GuiSingleInstance {
        handles: Mutex<Option<(HANDLE, HANDLE)>>,
        closing: Arc<AtomicBool>,
        listener_started: AtomicBool,
    }

    unsafe impl Send for GuiSingleInstance {}
    unsafe impl Sync for GuiSingleInstance {}

    impl GuiSingleInstance {
        /// Returns `Some(guard)` if this is the primary GUI instance.
        /// When `wait_for_restart` is true, retries briefly to allow the dying old instance
        /// to finish releasing the named mutex before giving up.
        /// Returns `None` if another instance is already running (after signaling it to wake up).
        pub fn acquire_or_signal_existing_with_retry(wait_for_restart: bool) -> Option<Self> {
            let mutex_w = to_wide(MUTEX_NAME);
            let event_w = to_wide(WAKE_EVENT_NAME);
            let max_attempts = if wait_for_restart { 100 } else { 1 };

            for attempt in 0..max_attempts {
                unsafe {
                    let mutex = CreateMutexW(std::ptr::null(), 0, mutex_w.as_ptr());
                    if mutex.is_null() {
                        return None;
                    }
                    if GetLastError() == ERROR_ALREADY_EXISTS {
                        CloseHandle(mutex);
                        if wait_for_restart && attempt + 1 < max_attempts {
                            std::thread::sleep(Duration::from_millis(50));
                            continue;
                        }
                        let ev = OpenEventW(EVENT_MODIFY_STATE, 0, event_w.as_ptr());
                        if !ev.is_null() {
                            SetEvent(ev);
                            CloseHandle(ev);
                        }
                        return None;
                    }
                    let wake_event = CreateEventW(std::ptr::null(), 0, 0, event_w.as_ptr());
                    return Some(Self {
                        handles: Mutex::new(Some((mutex, wake_event))),
                        closing: Arc::new(AtomicBool::new(false)),
                        listener_started: AtomicBool::new(false),
                    });
                }
            }
            None
        }

        pub fn start_wake_listener<F: Fn() + Send + 'static>(&self, on_wake: F) {
            let wake_raw = match self.handles.lock() {
                Ok(guard) => match *guard {
                    Some((_, ev)) if !ev.is_null() => ev as usize,
                    _ => return,
                },
                Err(_) => return,
            };
            if self
                .listener_started
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return;
            }
            let closing = Arc::clone(&self.closing);
            std::thread::spawn(move || {
                let handle = wake_raw as HANDLE;
                loop {
                    let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
                    if closing.load(Ordering::SeqCst) || wait != WAIT_OBJECT_0 {
                        break;
                    }
                    on_wake();
                }
                unsafe {
                    CloseHandle(handle);
                }
            });
        }

        /// Explicitly releases the named mutex so a newly spawned instance can acquire it immediately,
        /// and cleanly signals the wake listener thread to exit without closing its handle mid-wait.
        pub fn release(&self) {
            self.closing.store(true, Ordering::SeqCst);
            let taken = self.handles.lock().ok().and_then(|mut g| g.take());
            if let Some((mutex, wake_event)) = taken {
                unsafe {
                    if !mutex.is_null() {
                        CloseHandle(mutex);
                    }
                    if !wake_event.is_null() {
                        if self.listener_started.load(Ordering::SeqCst) {
                            // Wake the listener thread so it breaks out of WaitForSingleObject and closes the handle itself.
                            SetEvent(wake_event);
                        } else {
                            CloseHandle(wake_event);
                        }
                    }
                }
            }
        }
    }

    impl Drop for GuiSingleInstance {
        fn drop(&mut self) {
            self.release();
        }
    }
}

fn random_secret(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    B64_URL.encode(buf)
}

fn repo_root() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("config").is_dir() || cwd.join("Cargo.toml").is_file() {
            return cwd;
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent();
        for _ in 0..4 {
            if let Some(d) = dir {
                if d.join("config").is_dir() || d.join("Cargo.toml").is_file() {
                    return d.to_path_buf();
                }
                dir = d.parent();
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn config_path() -> PathBuf {
    repo_root().join("config").join("config.local.json")
}

fn state_root() -> PathBuf {
    repo_root().join("state")
}

fn normalize_mode(mode: &str) -> String {
    match mode.trim() {
        "vps-ssh" | "vps" => "vps".to_string(),
        "cloudflare-named" => "cloudflare-named".to_string(),
        "local" => "local".to_string(),
        "" => "cloudflare-quick".to_string(),
        other => other.to_string(),
    }
}

fn is_vps_mode(mode: &str) -> bool {
    matches!(mode.trim(), "vps" | "vps-ssh")
}

fn ensure_secrets(cfg: &mut AppConfig) {
    if cfg.instance_label.is_empty() {
        cfg.instance_label = "My-Windows-PC".into();
    }
    if cfg.language.is_empty() {
        cfg.language = "zh".into();
    }
    if cfg.connection_mode.is_empty() {
        cfg.connection_mode = "cloudflare-quick".into();
    }
    if cfg.gateway.secret.is_empty() || cfg.gateway.secret == "GENERATE_ON_FIRST_RUN" {
        cfg.gateway.secret = random_secret(18);
    }
    if cfg.gateway.oauth_signing_key.is_empty()
        || cfg.gateway.oauth_signing_key == "GENERATE_ON_FIRST_RUN"
    {
        cfg.gateway.oauth_signing_key = random_secret(32);
    }
    if cfg.gateway.approval_key.is_empty() || cfg.gateway.approval_key == "GENERATE_ON_FIRST_RUN" {
        cfg.gateway.approval_key = random_secret(16);
    }
    if cfg.tokens.fs_token.is_empty() || cfg.tokens.fs_token == "GENERATE_ON_FIRST_RUN" {
        cfg.tokens.fs_token = random_secret(24);
    }
    if cfg.tokens.workbench_token.is_empty()
        || cfg.tokens.workbench_token == "GENERATE_ON_FIRST_RUN"
    {
        cfg.tokens.workbench_token = random_secret(24);
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogEntry {
    time: String,
    level: String,
    source: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityEntry {
    id: String,
    time: String,
    category: String, // "fs" | "cmd" | "chrome" | "security"
    platform: String, // "Gemini" | "ChatGPT" | "AI Client" | "Delete Guard"
    tool: String,
    target: String,
    full_target: String,
    cwd: String,
    command_id: String,
    is_error: bool,
    source: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PortInfo {
    fs_port: u16,
    workbench_port: u16,
    gateway_port: u16,
    chrome_port: u16,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandDetail {
    command_id: String,
    command: String,
    cwd: String,
    state: String,
    exit_code: Option<i32>,
    timed_out: bool,
    started_at: String,
    finished_at: String,
    output: String,
}

#[derive(Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct ActivityStats {
    total: usize,
    fs_count: usize,
    cmd_count: usize,
    chrome_count: usize,
    security_count: usize,
}

struct RunningStack {
    _instance_lock: InstanceLock,
    handles: Vec<JoinHandle<()>>,
    tunnel: Option<RunningTunnel>,
    ssh_tunnel: Option<RunningSshTunnel>,
    chrome_backend: Option<Arc<SidecarBackend>>,
    connection_mode: String,
    tunnel_detail: String,
    public_origin: String,
    mcp_url: String,
    approval_key: String,
    fs_ok: bool,
    wb_ok: bool,
    gw_ok: bool,
    chrome_ok: bool,
    ports: PortInfo,
    fake_ip_bypassed: bool,
}

struct ActivityCache {
    audit_path: PathBuf,
    audit_sig: Option<(SystemTime, u64)>,
    dg_sig: Option<(SystemTime, u64)>,
    items: Vec<ActivityEntry>,
    stats: ActivityStats,
}

struct GuiState {
    stack: Mutex<Option<RunningStack>>,
    starting: AtomicBool,
    restarting: AtomicBool,
    attached_logged: AtomicBool,
    last_error: Mutex<Option<String>>,
    logs: Mutex<VecDeque<LogEntry>>,
    env_cache: EnvCheck,
    activity_cache: std::sync::Mutex<Option<ActivityCache>>,
    http: reqwest::Client,
}

impl Default for GuiState {
    fn default() -> Self {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(350))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            stack: Mutex::new(None),
            starting: AtomicBool::new(false),
            restarting: AtomicBool::new(false),
            attached_logged: AtomicBool::new(false),
            last_error: Mutex::new(None),
            logs: Mutex::new(VecDeque::new()),
            env_cache: check_env(),
            activity_cache: std::sync::Mutex::new(None),
            http,
        }
    }
}

impl GuiState {
    async fn stop_all(&self) {
        let mut guard = self.stack.lock().await;
        if let Some(mut s) = guard.take() {
            for h in &s.handles {
                h.abort();
            }
            for h in s.handles {
                let _ = tokio::time::timeout(Duration::from_millis(500), h).await;
            }
            if let Some(ref backend) = s.chrome_backend {
                backend.shutdown().await;
            }
            if let Some(ref mut t) = s.tunnel {
                let _ = t.child.kill().await;
            }
            if let Some(ref mut st) = s.ssh_tunnel {
                st.shutdown().await;
            }
            drop(s._instance_lock);
            let _ = mark_runtime_status_stopped(&state_root().join("runtime-status.json"));
            *self.last_error.lock().await = None;
            self.push_log("info", "BOOT", "全部本地服务、Sidecar 与隧道已安全停止")
                .await;
        }
    }

    async fn push_log(&self, level: &str, source: &str, msg: impl Into<String>) {
        let mut logs = self.logs.lock().await;
        if logs.len() >= MAX_LOG_LINES {
            logs.pop_front();
        }
        logs.push_back(LogEntry {
            time: Local::now().format("%H:%M:%S").to_string(),
            level: level.to_string(),
            source: source.to_string(),
            message: msg.into(),
        });
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvCheck {
    pwsh_ok: bool,
    cloudflared_ok: bool,
    ssh_ok: bool,
    node_ok: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSnapshot {
    running: bool,
    managed_by: String, // "gui" | "external" | "none"
    connection_mode: String,
    tunnel_detail: String,
    public_origin: String,
    mcp_url: String,
    approval_key: String,
    fs_ok: bool,
    workbench_ok: bool,
    gateway_ok: bool,
    chrome_ok: bool,
    ports: PortInfo,
    fake_ip_bypassed: bool,
    last_error: Option<String>,
    env: EnvCheck,
    logs: Vec<LogEntry>,
    activities: Vec<ActivityEntry>,
    stats: ActivityStats,
}

struct ExternalProbe {
    fs_ok: bool,
    workbench_ok: bool,
    gateway_ok: bool,
    chrome_ok: bool,
    connection_mode: String,
    tunnel_detail: String,
    public_origin: String,
    mcp_url: String,
    approval_key: String,
}

#[allow(clippy::too_many_arguments)]
fn write_gui_runtime_status(
    path: &Path,
    cfg: &AppConfig,
    connection_mode: &str,
    public_origin: &str,
    mcp_url: &str,
    tunnel_detail: &str,
    tunnel_pid: Option<u32>,
    gw_ok: bool,
    chrome_ok: bool,
) {
    let now = Utc::now().to_rfc3339();
    let pid = std::process::id();
    let payload = json!({
        "pid": pid,
        "managedBy": "gui",
        "phase": "running",
        "mode": connection_mode,
        "publicOrigin": public_origin,
        "mcpUrl": mcp_url,
        "approvalKey": cfg.gateway.approval_key,
        "startedAt": now,
        "updatedAt": now,
        "services": {
            "fsMcp": { "ok": true, "port": cfg.local_ports.fs_bearer, "pid": pid },
            "workbench": { "ok": true, "port": cfg.local_ports.workbench, "pid": pid },
            "gateway": { "ok": gw_ok, "port": cfg.gateway.local_port, "pid": if gw_ok { Value::from(pid) } else { Value::Null } },
            "chromeMcp": { "ok": chrome_ok, "port": cfg.local_ports.chrome_mcp, "pid": pid },
            "tunnel": { "ok": tunnel_pid.is_some(), "detail": tunnel_detail, "pid": tunnel_pid }
        }
    });
    if let Ok(text) = serde_json::to_string_pretty(&payload) {
        let _ = write_atomic_string(path, &text);
    }
}

fn mark_runtime_status_stopped(path: &Path) -> std::io::Result<()> {
    let payload = json!({
        "phase": "stopped",
        "updatedAt": Utc::now().to_rfc3339(),
    });
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into());
    write_atomic_string(path, &text)
}

async fn ping_healthz(client: &reqwest::Client, port: u16) -> bool {
    let url = format!("http://127.0.0.1:{port}/healthz");
    match client.get(&url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

async fn probe_external_backend(
    client: &reqwest::Client,
    cfg: &AppConfig,
) -> Option<ExternalProbe> {
    let (fs_ok, workbench_ok, gateway_ok, chrome_ok) = tokio::join!(
        ping_healthz(client, cfg.local_ports.fs_bearer),
        ping_healthz(client, cfg.local_ports.workbench),
        ping_healthz(client, cfg.gateway.local_port),
        ping_healthz(client, cfg.local_ports.chrome_mcp),
    );
    if !(fs_ok || workbench_ok || gateway_ok) {
        return None;
    }

    let rt_path = state_root().join("runtime-status.json");
    let rt: Value = std::fs::read_to_string(&rt_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let mode_raw = rt
        .get("mode")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&cfg.connection_mode);
    let connection_mode = normalize_mode(mode_raw);

    let mut public_origin = rt
        .get("publicOrigin")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut mcp_url = rt
        .get("mcpUrl")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let approval_key = rt
        .get("approvalKey")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&cfg.gateway.approval_key)
        .to_string();

    if public_origin.is_empty() {
        if is_vps_mode(&connection_mode) && !cfg.vps.domain.trim().is_empty() {
            let dom = cfg
                .vps
                .domain
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            public_origin = format!("https://{dom}");
        } else if connection_mode == "cloudflare-named"
            && !cfg.cloudflare.public_hostname.trim().is_empty()
        {
            let dom = cfg
                .cloudflare
                .public_hostname
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/');
            public_origin = format!("https://{dom}");
        } else if gateway_ok {
            public_origin = format!("http://127.0.0.1:{}", cfg.gateway.local_port);
        }
    }

    if mcp_url.is_empty() && !public_origin.is_empty() && !cfg.gateway.secret.is_empty() {
        mcp_url = format!("{public_origin}/{}/mcp", cfg.gateway.secret);
    }

    let tunnel_detail = rt
        .pointer("/services/tunnel/detail")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            if is_vps_mode(&connection_mode) && !cfg.vps.host.trim().is_empty() {
                format!("ssh {}@{}:{}", cfg.vps.user, cfg.vps.host, cfg.vps.ssh_port)
            } else if !public_origin.is_empty() {
                public_origin.clone()
            } else {
                format!("127.0.0.1:{}", cfg.gateway.local_port)
            }
        });

    Some(ExternalProbe {
        fs_ok,
        workbench_ok,
        gateway_ok,
        chrome_ok,
        connection_mode,
        tunnel_detail,
        public_origin,
        mcp_url,
        approval_key,
    })
}

fn find_in_path(exe: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(exe))
            .find(|p| p.is_file())
    })
}

fn find_cloudflared() -> Option<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let candidates = [
        cwd.join("tools").join("cloudflared.exe"),
        PathBuf::from(r"C:\Program Files\cloudflared\cloudflared.exe"),
    ];
    candidates
        .into_iter()
        .find(|p| p.exists())
        .or_else(|| find_in_path("cloudflared.exe"))
}

fn resolve_pwsh() -> String {
    for c in [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files\PowerShell\7-preview\pwsh.exe",
    ] {
        if std::path::Path::new(c).exists() {
            return c.to_string();
        }
    }
    "pwsh.exe".to_string()
}

fn cmd_exists(exe: &str) -> bool {
    if std::path::Path::new(exe).exists() {
        return true;
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(exe).is_file()))
        .unwrap_or(false)
}

fn check_env() -> EnvCheck {
    EnvCheck {
        pwsh_ok: cmd_exists(&resolve_pwsh()) || cmd_exists("pwsh.exe"),
        cloudflared_ok: find_cloudflared().is_some() || cmd_exists("cloudflared.exe"),
        ssh_ok: std::path::Path::new(r"C:\Windows\System32\OpenSSH\ssh.exe").exists()
            || cmd_exists("ssh.exe"),
        node_ok: cmd_exists("node.exe"),
    }
}

fn read_tail_utf8(path: &Path, max_bytes: u64) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max_bytes);
    if start > 0 {
        f.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf).ok()?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        if let Some(idx) = text.find('\n') {
            text = text[idx + 1..].to_string();
        }
    }
    Some(text)
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn select_audit_path(running: bool, connection_mode: &str, gateway_ok: bool) -> PathBuf {
    let logs_dir = state_root().join("logs");
    let gw_audit = logs_dir.join("gateway-audit.jsonl");
    let local_audit = logs_dir.join("local-audit.jsonl");

    if running {
        if is_vps_mode(connection_mode) || !gateway_ok {
            return local_audit;
        }
        if gw_audit.exists() {
            return gw_audit;
        }
        return local_audit;
    }

    match (file_mtime(&local_audit), file_mtime(&gw_audit)) {
        (Some(lt), Some(gt)) => {
            if lt >= gt {
                local_audit
            } else {
                gw_audit
            }
        }
        (Some(_), None) => local_audit,
        (None, Some(_)) => gw_audit,
        (None, None) => local_audit,
    }
}

fn file_sig(path: &Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

fn read_recent_activities_cached(
    cache: &std::sync::Mutex<Option<ActivityCache>>,
    running: bool,
    connection_mode: &str,
    gateway_ok: bool,
) -> (Vec<ActivityEntry>, ActivityStats) {
    let audit_path = select_audit_path(running, connection_mode, gateway_ok);
    let dg_log = state_root()
        .join("workbench")
        .join("delete-guard")
        .join("delete-guard.log");
    let audit_sig = file_sig(&audit_path);
    let dg_sig = file_sig(&dg_log);

    if let Ok(guard) = cache.lock() {
        if let Some(ref c) = *guard {
            if c.audit_path == audit_path && c.audit_sig == audit_sig && c.dg_sig == dg_sig {
                return (c.items.clone(), c.stats.clone());
            }
        }
    }

    let (items, stats) = read_recent_activities(running, connection_mode, gateway_ok);
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(ActivityCache {
            audit_path,
            audit_sig,
            dg_sig,
            items: items.clone(),
            stats: stats.clone(),
        });
    }
    (items, stats)
}

fn stable_activity_id(
    prefix: &str,
    parts: &[&str],
    seen: &mut std::collections::HashMap<u64, u32>,
) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for b in part.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    let count = seen.entry(h).or_insert(0);
    let seq = *count;
    *count += 1;
    if seq == 0 {
        format!("{prefix}:{h:016x}")
    } else {
        format!("{prefix}:{h:016x}:{seq}")
    }
}

fn read_recent_activities(
    running: bool,
    connection_mode: &str,
    gateway_ok: bool,
) -> (Vec<ActivityEntry>, ActivityStats) {
    let mut items = Vec::new();
    let mut stats = ActivityStats::default();
    let mut seen_ids = std::collections::HashMap::new();
    let audit_path = select_audit_path(running, connection_mode, gateway_ok);

    if let Some(raw) = read_tail_utf8(&audit_path, 256 * 1024) {
        let lines: Vec<&str> = raw.lines().collect();
        let start = lines.len().saturating_sub(MAX_ACTIVITY_ITEMS);
        for line in &lines[start..] {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let event = v.get("event").and_then(Value::as_str).unwrap_or("");
            let ts_raw = v.get("ts").and_then(Value::as_str).unwrap_or("");
            let ts = DateTime::parse_from_rfc3339(ts_raw)
                .ok()
                .map(|dt| dt.with_timezone(&Local).format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "--:--:--".to_string());

            if event == "tool_call" {
                let tool = v.get("tool").and_then(Value::as_str).unwrap_or("unknown");
                let lane = v.get("lane").and_then(Value::as_str).unwrap_or("fs");
                let target = v.get("target").and_then(Value::as_str).unwrap_or("");
                let full_target = v
                    .get("fullTarget")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(target);
                let cwd = v.get("cwd").and_then(Value::as_str).unwrap_or("");
                let command_id = v.get("commandId").and_then(Value::as_str).unwrap_or("");
                let is_error = v.get("isError").and_then(Value::as_bool).unwrap_or(false);
                let source = v.get("source").and_then(Value::as_str).unwrap_or("");
                let plat_raw = v.get("platform").and_then(Value::as_str).unwrap_or("");
                let owner = v.get("owner").and_then(Value::as_str).unwrap_or("");
                let platform = if plat_raw == "google" || owner.starts_with("gemini-") {
                    "Gemini"
                } else if plat_raw == "openai" || owner.starts_with("chatgpt-") {
                    "ChatGPT"
                } else {
                    "AI Client"
                };

                let category = match lane {
                    "chrome" => {
                        stats.chrome_count += 1;
                        "chrome"
                    }
                    "cmd" | "git" => {
                        stats.cmd_count += 1;
                        "cmd"
                    }
                    _ => {
                        stats.fs_count += 1;
                        "fs"
                    }
                };
                stats.total += 1;
                let id =
                    stable_activity_id("a", &[ts_raw, tool, target, command_id], &mut seen_ids);
                items.push(ActivityEntry {
                    id,
                    time: ts,
                    category: category.into(),
                    platform: platform.into(),
                    tool: tool.into(),
                    target: target.into(),
                    full_target: full_target.into(),
                    cwd: cwd.into(),
                    command_id: command_id.into(),
                    is_error,
                    source: source.into(),
                });
            } else if event == "oauth_authorized" {
                let cid = v.get("clientId").and_then(Value::as_str).unwrap_or("");
                let platform = if cid.starts_with("gemini-") {
                    "Gemini"
                } else {
                    "ChatGPT"
                };
                stats.security_count += 1;
                stats.total += 1;
                let id = stable_activity_id("o", &[ts_raw, cid], &mut seen_ids);
                items.push(ActivityEntry {
                    id,
                    time: ts,
                    category: "security".into(),
                    platform: platform.into(),
                    tool: "OAuth 授权通过".into(),
                    target: cid.into(),
                    full_target: cid.into(),
                    cwd: String::new(),
                    command_id: String::new(),
                    is_error: false,
                    source: "oauth".into(),
                });
            }
        }
    }

    // Also include recent Delete Guard interceptions
    let dg_log = state_root()
        .join("workbench")
        .join("delete-guard")
        .join("delete-guard.log");
    if let Some(raw) = read_tail_utf8(&dg_log, 32 * 1024) {
        for line in raw.lines().rev().take(10) {
            if line.contains("BLOCK-FIRST") {
                let time = line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("--:--:--")
                    .to_string();
                let target = line
                    .split_once("[rust-workbench] ")
                    .map(|(_, rest)| rest)
                    .unwrap_or(line)
                    .to_string();
                stats.security_count += 1;
                stats.total += 1;
                let id = stable_activity_id("dg", &[&time, &target], &mut seen_ids);
                items.push(ActivityEntry {
                    id,
                    time,
                    category: "security".into(),
                    platform: "Delete Guard".into(),
                    tool: "拦截高危删除".into(),
                    full_target: target.clone(),
                    target,
                    cwd: String::new(),
                    command_id: String::new(),
                    is_error: true,
                    source: "delete-guard".into(),
                });
            }
        }
    }

    items.reverse(); // Newest first
    (items, stats)
}

#[tauri::command]
fn load_config() -> Result<AppConfig, String> {
    let path = config_path();
    let mut cfg = if path.exists() {
        AppConfig::load(&path).map_err(|e| e.to_string())?
    } else {
        AppConfig::default()
    };
    ensure_secrets(&mut cfg);
    Ok(cfg)
}

#[tauri::command]
fn save_config(mut cfg: AppConfig) -> Result<AppConfig, String> {
    ensure_secrets(&mut cfg);
    let path = config_path();
    let json = serde_json::to_string_pretty(&cfg).map_err(|e| e.to_string())?;
    write_atomic_string(&path, &json).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[tauri::command]
fn validate_root_dir(dir: String) -> Result<String, String> {
    let roots = AllowedRoots::new([dir]).map_err(|e| e.to_string())?;
    Ok(roots.roots()[0].display().to_string())
}

#[tauri::command]
async fn pick_folder() -> Result<Option<String>, String> {
    tokio::task::spawn_blocking(|| {
        let script = r#"
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = '选择要授权给 AI 访问的工作目录 / Select Allowed Workspace Folder'
$dlg.UseDescriptionForTitle = $true
if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dlg.SelectedPath)
}
"#;
        let mut cmd = std::process::Command::new("powershell.exe");
        cmd.args([
            "-NoProfile",
            "-STA",
            "-WindowStyle",
            "Hidden",
            "-Command",
            script,
        ]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.output().map_err(|e| e.to_string())?;
        let picked = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if picked.is_empty() {
            Ok(None)
        } else {
            Ok(Some(picked))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn clear_logs(state: tauri::State<'_, Arc<GuiState>>) -> Result<(), String> {
    state.logs.lock().await.clear();
    Ok(())
}

#[tauri::command]
fn get_command_detail(command_id: String) -> Result<CommandDetail, String> {
    let cid = command_id.trim();
    if cid.is_empty()
        || cid.len() > 80
        || !cid.starts_with("c_")
        || !cid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("无效的 commandId".into());
    }
    let dir = state_root().join("workbench").join("commands").join(cid);
    if !dir.is_dir() {
        return Err("命令详情目录不存在或已被自动清理".into());
    }
    let spec: Value = std::fs::read_to_string(dir.join("spec.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    let status: Value = std::fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let mut output = String::new();
    if let Some(raw) = read_tail_utf8(&dir.join("output.jsonl"), 32 * 1024) {
        for line in raw.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if let Some(txt) = v.get("text").and_then(Value::as_str) {
                    output.push_str(txt);
                }
            }
        }
    }

    Ok(CommandDetail {
        command_id: cid.to_string(),
        command: spec
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        cwd: spec
            .get("cwd")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        state: status
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        exit_code: status
            .get("exitCode")
            .and_then(Value::as_i64)
            .map(|n| n as i32),
        timed_out: status
            .get("timedOut")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        started_at: status
            .get("startedAt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        finished_at: status
            .get("finishedAt")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        output,
    })
}

#[tauri::command]
fn reveal_in_explorer(path: String) -> Result<(), String> {
    let raw = path.trim();
    if raw.is_empty() {
        return Err("路径为空".into());
    }
    // Handle multi-line fullTarget (from fs_read_multiple_files) and " (+N more)" summaries
    let first_line = raw.lines().next().unwrap_or(raw).trim();
    let cleaned = first_line.split(" (+").next().unwrap_or(first_line).trim();
    let p = PathBuf::from(cleaned);
    if !p.exists() {
        return Err(format!("路径不存在: {}", p.display()));
    }
    #[cfg(windows)]
    {
        let mut cmd = std::process::Command::new("explorer.exe");
        if p.is_file() {
            cmd.arg(format!("/select,{}", p.display()));
        } else {
            cmd.arg(p.as_os_str());
        }
        cmd.spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn get_status(state: tauri::State<'_, Arc<GuiState>>) -> Result<StatusSnapshot, String> {
    let mut guard = state.stack.lock().await;
    if let Some(ref mut s) = *guard {
        if let Some(ref mut t) = s.tunnel {
            if let Ok(Some(code)) = t.child.try_wait() {
                let msg = format!("Cloudflare 隧道已意外退出 ({code})，请重新启动服务");
                *state.last_error.lock().await = Some(msg);
                s.tunnel = None;
            }
        }
        if let Some(ref st) = s.ssh_tunnel {
            match st.status() {
                SshTunnelState::Connected { .. } => {
                    let mut le = state.last_error.lock().await;
                    if le
                        .as_deref()
                        .map(|m| m.starts_with("VPS SSH 反向隧道"))
                        .unwrap_or(false)
                    {
                        *le = None;
                    }
                }
                SshTunnelState::Reconnecting {
                    attempt,
                    backoff_secs,
                    last_error,
                } => {
                    let msg = format!(
                        "VPS SSH 反向隧道断开，正在自动重连 (第 {attempt} 次，{backoff_secs}s 后重试): {last_error}"
                    );
                    *state.last_error.lock().await = Some(msg);
                }
                SshTunnelState::Stopped => {
                    let msg = "VPS SSH 反向隧道已停止，请重新启动服务".to_string();
                    *state.last_error.lock().await = Some(msg);
                    s.ssh_tunnel = None;
                }
                SshTunnelState::Connecting { .. } => {}
            }
        }

        let err = state.last_error.lock().await.clone();
        let logs: Vec<LogEntry> = state.logs.lock().await.iter().cloned().collect();
        let env = state.env_cache.clone();
        let (activities, stats) =
            read_recent_activities_cached(&state.activity_cache, true, &s.connection_mode, s.gw_ok);
        return Ok(StatusSnapshot {
            running: true,
            managed_by: "gui".into(),
            connection_mode: s.connection_mode.clone(),
            tunnel_detail: s.tunnel_detail.clone(),
            public_origin: s.public_origin.clone(),
            mcp_url: s.mcp_url.clone(),
            approval_key: s.approval_key.clone(),
            fs_ok: s.fs_ok,
            workbench_ok: s.wb_ok,
            gateway_ok: s.gw_ok,
            chrome_ok: s.chrome_ok,
            ports: s.ports.clone(),
            fake_ip_bypassed: s.fake_ip_bypassed,
            last_error: err,
            env,
            logs,
            activities,
            stats,
        });
    }
    drop(guard);

    let cfg = load_config().unwrap_or_default();
    let external = probe_external_backend(&state.http, &cfg).await;

    if let Some(ext) = external {
        if !state.attached_logged.swap(true, Ordering::SeqCst) {
            state
                .push_log(
                    "ok",
                    "ATTACH",
                    format!(
                        "检测到已有后台服务在运行，GUI 已自动接入（模式：{} · {}）",
                        ext.connection_mode, ext.tunnel_detail
                    ),
                )
                .await;
        }
        let err = state.last_error.lock().await.clone();
        let logs: Vec<LogEntry> = state.logs.lock().await.iter().cloned().collect();
        let env = state.env_cache.clone();
        let (activities, stats) = read_recent_activities_cached(
            &state.activity_cache,
            true,
            &ext.connection_mode,
            ext.gateway_ok,
        );
        return Ok(StatusSnapshot {
            running: true,
            managed_by: "external".into(),
            connection_mode: ext.connection_mode,
            tunnel_detail: ext.tunnel_detail,
            public_origin: ext.public_origin,
            mcp_url: ext.mcp_url,
            approval_key: ext.approval_key,
            fs_ok: ext.fs_ok,
            workbench_ok: ext.workbench_ok,
            gateway_ok: ext.gateway_ok,
            chrome_ok: ext.chrome_ok,
            ports: PortInfo {
                fs_port: cfg.local_ports.fs_bearer,
                workbench_port: cfg.local_ports.workbench,
                gateway_port: cfg.gateway.local_port,
                chrome_port: cfg.local_ports.chrome_mcp,
            },
            fake_ip_bypassed: false,
            last_error: err,
            env,
            logs,
            activities,
            stats,
        });
    }

    state.attached_logged.store(false, Ordering::SeqCst);
    let err = state.last_error.lock().await.clone();
    let logs: Vec<LogEntry> = state.logs.lock().await.iter().cloned().collect();
    let env = state.env_cache.clone();
    let cfg_mode = normalize_mode(&cfg.connection_mode);
    let (activities, stats) =
        read_recent_activities_cached(&state.activity_cache, false, &cfg_mode, false);
    Ok(StatusSnapshot {
        running: false,
        managed_by: "none".into(),
        connection_mode: cfg_mode,
        tunnel_detail: String::new(),
        public_origin: String::new(),
        mcp_url: String::new(),
        approval_key: cfg.gateway.approval_key,
        fs_ok: false,
        workbench_ok: false,
        gateway_ok: false,
        chrome_ok: false,
        ports: PortInfo {
            fs_port: cfg.local_ports.fs_bearer,
            workbench_port: cfg.local_ports.workbench,
            gateway_port: cfg.gateway.local_port,
            chrome_port: cfg.local_ports.chrome_mcp,
        },
        fake_ip_bypassed: false,
        last_error: err,
        env,
        logs,
        activities,
        stats,
    })
}

async fn start_services_inner(cfg: AppConfig, state: &Arc<GuiState>) -> Result<(), String> {
    let cfg = save_config(cfg)?;
    if state.stack.lock().await.is_some() {
        return Ok(());
    }
    if probe_external_backend(&state.http, &cfg).await.is_some() {
        state
            .push_log(
                "info",
                "ATTACH",
                "检测到后台服务已在运行，保持程序唯一性并自动接入当前后台实例",
            )
            .await;
        return Ok(());
    }
    if state
        .starting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(());
    }

    struct StartingGuard<'a>(&'a AtomicBool);
    impl Drop for StartingGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _starting_guard = StartingGuard(&state.starting);

    *state.last_error.lock().await = None;
    let normalized_mode = normalize_mode(&cfg.connection_mode);
    state
        .push_log(
            "info",
            "BOOT",
            format!("正在初始化本地服务栈（模式：{normalized_mode}）..."),
        )
        .await;

    let allowed_roots = AllowedRoots::new(cfg.allowed_roots.clone())
        .map_err(|e| format!("请先在「目录与守卫」中添加至少一个有效工作目录 ({e})"))?;

    let sroot = state_root();
    let instance_lock = InstanceLock::try_acquire(&sroot.join("agent.lock"), "gui")
        .map_err(|e| format!("无法启动：检测到已有后端实例在运行 ({e})"))?;
    let local_audit = sroot.join("logs").join("local-audit.jsonl");

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    async fn abort_partial(
        handles: Vec<JoinHandle<()>>,
        chrome_backend: Option<Arc<SidecarBackend>>,
    ) {
        for h in handles {
            h.abort();
        }
        if let Some(b) = chrome_backend {
            b.shutdown().await;
        }
    }

    // 1. FS MCP
    let fs_listener = TcpListener::bind(("127.0.0.1", cfg.local_ports.fs_bearer))
        .await
        .map_err(|e| format!("FS 端口 {} 绑定失败: {e}", cfg.local_ports.fs_bearer))?;
    let fs_app = build_fs_router(FsServerConfig {
        host: "127.0.0.1".into(),
        port: cfg.local_ports.fs_bearer,
        bearer_token: cfg.tokens.fs_token.clone(),
        allowed_roots: allowed_roots.clone(),
        audit_log: Some(local_audit.clone()),
    });
    handles.push(tokio::spawn(async move {
        let _ = axum::serve(fs_listener, fs_app).await;
    }));
    state
        .push_log(
            "ok",
            "FS-MCP",
            format!(
                "已监听 http://127.0.0.1:{}/mcp（内嵌 ripgrep · {} 个白名单目录）",
                cfg.local_ports.fs_bearer,
                cfg.allowed_roots.len()
            ),
        )
        .await;

    // 2. Workbench
    let wb_listener = match TcpListener::bind(("127.0.0.1", cfg.local_ports.workbench)).await {
        Ok(l) => l,
        Err(e) => {
            abort_partial(handles, None).await;
            return Err(format!(
                "Workbench 端口 {} 绑定失败: {e}",
                cfg.local_ports.workbench
            ));
        }
    };
    let wb_engine = match WorkbenchEngine::new(
        sroot.join("workbench"),
        resolve_pwsh(),
        cfg.guards_and_hooks.enable_delete_guard,
    ) {
        Ok(eng) => Arc::new(eng),
        Err(e) => {
            abort_partial(handles, None).await;
            return Err(e.to_string());
        }
    };
    let prune_engine = Arc::clone(&wb_engine);
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let eng = Arc::clone(&prune_engine);
            let _ = tokio::task::spawn_blocking(move || eng.prune()).await;
        }
    }));
    let wb_app = build_wb_router(
        WorkbenchConfig {
            host: "127.0.0.1".into(),
            port: cfg.local_ports.workbench,
            bearer_token: cfg.tokens.workbench_token.clone(),
            state_root: sroot.join("workbench"),
            pwsh_path: resolve_pwsh(),
            enable_delete_guard: cfg.guards_and_hooks.enable_delete_guard,
            audit_log: Some(local_audit.clone()),
        },
        wb_engine,
    );
    handles.push(tokio::spawn(async move {
        let _ = axum::serve(wb_listener, wb_app).await;
    }));
    state
        .push_log(
            "ok",
            "WORKBENCH",
            format!(
                "已监听 http://127.0.0.1:{}（Win32 Job Object · DeleteGuard={}）",
                cfg.local_ports.workbench, cfg.guards_and_hooks.enable_delete_guard
            ),
        )
        .await;

    // 3. Optional Chrome Broker (uses shared chromeToken when configured; avoids ephemeral 401 in VPS mode)
    let mut chrome_ok = false;
    let mut chrome_backend = None;
    let vps_mode = is_vps_mode(&normalized_mode);
    let chrome_token = if !cfg.tokens.chrome_token.trim().is_empty() {
        cfg.tokens.chrome_token.clone()
    } else if vps_mode {
        String::new()
    } else {
        random_secret(24)
    };
    if cfg.gateway.enable_chrome {
        match TcpListener::bind(("127.0.0.1", cfg.local_ports.chrome_mcp)).await {
            Ok(ch_listener) => {
                let mut ch_cfg = ChromeBrokerConfig::default_npx(
                    cfg.local_ports.chrome_mcp,
                    cfg.local_ports.chrome_cdp,
                );
                ch_cfg.bearer_token = if chrome_token.is_empty() {
                    None
                } else {
                    Some(chrome_token.clone())
                };
                ch_cfg.audit_log = Some(local_audit.clone());
                ch_cfg.allowed_roots = Some(allowed_roots);
                let (ch_app, backend) = build_chrome_router(ch_cfg);
                handles.push(tokio::spawn(async move {
                    let _ = axum::serve(ch_listener, ch_app).await;
                }));
                chrome_backend = Some(backend);
                chrome_ok = true;
                state
                    .push_log(
                        "ok",
                        "CHROME",
                        format!(
                            "Sidecar Broker 已就绪 (:{}, Bearer 鉴权 · 按需对接 CDP :{})",
                            cfg.local_ports.chrome_mcp, cfg.local_ports.chrome_cdp
                        ),
                    )
                    .await;
            }
            Err(e) => {
                state
                    .push_log("warn", "CHROME", format!("端口占用，已跳过: {e}"))
                    .await;
            }
        }
    }

    // 4. Local Gateway (skipped in VPS mode where the gateway runs on the remote VPS)
    let gw_cfg = GatewayServerConfig {
        host: "127.0.0.1".into(),
        port: cfg.gateway.local_port,
        secret: cfg.gateway.secret.clone(),
        mode: cfg.gateway.mode.clone(),
        enable_commands: cfg.gateway.enable_commands,
        enable_chrome: chrome_ok,
        fs_url: format!("http://127.0.0.1:{}/mcp", cfg.local_ports.fs_bearer),
        fs_token: cfg.tokens.fs_token.clone(),
        workbench_url: format!("http://127.0.0.1:{}/mcp", cfg.local_ports.workbench),
        workbench_token: cfg.tokens.workbench_token.clone(),
        chrome_url: if chrome_ok {
            format!("http://127.0.0.1:{}/mcp", cfg.local_ports.chrome_mcp)
        } else {
            String::new()
        },
        chrome_token: if chrome_ok {
            chrome_token
        } else {
            String::new()
        },
        workspace_root: cfg
            .allowed_roots
            .first()
            .cloned()
            .unwrap_or_else(|| ".".into()),
        allowed_roots: cfg.allowed_roots.clone(),
        instance_label: cfg.instance_label.clone(),
        oauth: OAuthConfig {
            enabled: true,
            issuer: format!("http://127.0.0.1:{}", cfg.gateway.local_port),
            mcp_path: String::new(),
            signing_key: cfg.gateway.oauth_signing_key.clone(),
            approval_key: cfg.gateway.approval_key.clone(),
            instance_label: cfg.instance_label.clone(),
            client_store_path: Some(sroot.join("oauth-clients.json")),
            ..OAuthConfig::default()
        },
        audit_log: Some(sroot.join("logs").join("gateway-audit.jsonl")),
        task_dir: Some(sroot.join("gateway-tasks")),
        vision: VisionConfig {
            mode: cfg.guards_and_hooks.vision_backend.clone(),
            gemini_api_key: cfg.guards_and_hooks.gemini_api_key.clone(),
            openai_api_key: cfg.guards_and_hooks.openai_api_key.clone(),
            ..VisionConfig::default()
        },
    };
    let mcp_path = gw_cfg.mcp_path();
    let (gw_handle, gw_ok) = if !vps_mode {
        let gw_listener = match TcpListener::bind(("127.0.0.1", cfg.gateway.local_port)).await {
            Ok(l) => l,
            Err(e) => {
                abort_partial(handles, chrome_backend).await;
                return Err(format!(
                    "Gateway 端口 {} 绑定失败: {e}",
                    cfg.gateway.local_port
                ));
            }
        };
        let (gw_app, handle) = build_gw_router(gw_cfg);
        handles.push(tokio::spawn(async move {
            let _ = axum::serve(gw_listener, gw_app).await;
        }));
        state
            .push_log(
                "ok",
                "GATEWAY",
                format!(
                    "OAuth 2.1 聚合网关已监听 127.0.0.1:{}",
                    cfg.gateway.local_port
                ),
            )
            .await;
        (Some(handle), true)
    } else {
        state
            .push_log(
                "info",
                "GATEWAY",
                "VPS 模式：聚合网关运行在远端 VPS，跳过本地监听",
            )
            .await;
        (None, false)
    };

    // 5. Public Tunnel
    let mut public_origin = format!("http://127.0.0.1:{}", cfg.gateway.local_port);
    let mut tunnel_detail = format!("127.0.0.1:{}", cfg.gateway.local_port);
    let mut tunnel_pid: Option<u32> = None;
    let mut tunnel = None;
    let mut ssh_tunnel = None;
    let mut fake_ip_bypassed = false;

    if normalized_mode.starts_with("cloudflare") {
        let cf_mode = if normalized_mode == "cloudflare-named" {
            "named"
        } else {
            "quick"
        };
        if let Some(cf_exe) = find_cloudflared() {
            state
                .push_log(
                    "info",
                    "TUNNEL",
                    format!("正在拉起 cloudflared ({cf_mode}) 并检测 Fake-IP 环境..."),
                )
                .await;
            match start_cloudflare_tunnel(CloudflareOptions {
                mode: cf_mode.into(),
                target_url: public_origin.clone(),
                named_tunnel_token: cfg.cloudflare.named_tunnel_token.clone(),
                public_hostname: cfg.cloudflare.public_hostname.clone(),
                cloudflared_exe: cf_exe,
            })
            .await
            {
                Ok(t) => {
                    public_origin = t.public_url.clone();
                    tunnel_detail = public_origin.clone();
                    tunnel_pid = t.child.id();
                    fake_ip_bypassed = t.fake_ip_bypassed;
                    if let Some(ref handle) = gw_handle {
                        handle.set_issuer(&public_origin);
                    }
                    state
                        .push_log(
                            "ok",
                            "TUNNEL",
                            format!(
                                "Cloudflare 公网入口已打通: {}（Fake-IP 绕过={}）",
                                public_origin,
                                if fake_ip_bypassed {
                                    "QUIC+Anycast"
                                } else {
                                    "直连"
                                }
                            ),
                        )
                        .await;
                    tunnel = Some(t);
                }
                Err(e) => {
                    error!("Cloudflare tunnel failed: {e}");
                    let msg = format!("Cloudflare 隧道启动失败（本地服务已就绪）: {e}");
                    state.push_log("err", "TUNNEL", &msg).await;
                    *state.last_error.lock().await = Some(msg);
                }
            }
        } else {
            let msg = "未找到 cloudflared.exe，当前仅本地模式运行".to_string();
            state.push_log("warn", "TUNNEL", &msg).await;
            *state.last_error.lock().await = Some(msg);
        }
    } else if is_vps_mode(&normalized_mode) {
        let mut forwards = vec![
            (cfg.vps.remote_fs_port, cfg.local_ports.fs_bearer),
            (cfg.vps.remote_workbench_port, cfg.local_ports.workbench),
        ];
        if chrome_ok {
            forwards.push((cfg.vps.remote_chrome_mcp_port, cfg.local_ports.chrome_mcp));
        }
        tunnel_detail = format!("ssh {}@{}:{}", cfg.vps.user, cfg.vps.host, cfg.vps.ssh_port);
        state
            .push_log(
                "info",
                "VPS-SSH",
                format!("正在建立 SSH -R 反向隧道 -> {tunnel_detail} ..."),
            )
            .await;
        let known_hosts = config_path().parent().map(|p| p.join("vps-known-hosts"));
        match start_ssh_reverse_tunnel(&SshTunnelOptions {
            host: cfg.vps.host.clone(),
            ssh_port: cfg.vps.ssh_port,
            user: cfg.vps.user.clone(),
            ssh_key_path: cfg.vps.ssh_key_path.clone(),
            known_hosts_path: known_hosts,
            forwards,
        }) {
            Ok(t) => {
                tunnel_pid = t.current_pid();
                if !cfg.vps.domain.trim().is_empty() {
                    let dom = cfg
                        .vps
                        .domain
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    public_origin = format!("https://{dom}");
                    if let Some(ref handle) = gw_handle {
                        handle.set_issuer(&public_origin);
                    }
                }
                state
                    .push_log(
                        "ok",
                        "VPS-SSH",
                        format!("SSH -R 反向隧道守护已启动（支持断线自动重连），公网入口: {public_origin}"),
                    )
                    .await;
                ssh_tunnel = Some(t);
            }
            Err(e) => {
                error!("SSH reverse tunnel failed: {e}");
                let msg = format!("VPS SSH 反向隧道启动失败: {e}");
                state.push_log("err", "VPS-SSH", &msg).await;
                *state.last_error.lock().await = Some(msg);
            }
        }
    }

    let mcp_url = format!("{public_origin}{mcp_path}");
    info!("GUI services started: {mcp_url}");

    write_gui_runtime_status(
        &sroot.join("runtime-status.json"),
        &cfg,
        &normalized_mode,
        &public_origin,
        &mcp_url,
        &tunnel_detail,
        tunnel_pid,
        gw_ok,
        chrome_ok,
    );

    *state.stack.lock().await = Some(RunningStack {
        _instance_lock: instance_lock,
        handles,
        tunnel,
        ssh_tunnel,
        chrome_backend,
        connection_mode: normalized_mode,
        tunnel_detail,
        public_origin,
        mcp_url,
        approval_key: cfg.gateway.approval_key.clone(),
        fs_ok: true,
        wb_ok: true,
        gw_ok,
        chrome_ok,
        ports: PortInfo {
            fs_port: cfg.local_ports.fs_bearer,
            workbench_port: cfg.local_ports.workbench,
            gateway_port: cfg.gateway.local_port,
            chrome_port: cfg.local_ports.chrome_mcp,
        },
        fake_ip_bypassed,
    });

    drop(_starting_guard);
    Ok(())
}

#[tauri::command]
async fn start_services(
    cfg: AppConfig,
    state: tauri::State<'_, Arc<GuiState>>,
) -> Result<StatusSnapshot, String> {
    start_services_inner(cfg, state.inner()).await?;
    get_status(state).await
}

async fn stop_external_backend() -> Result<(), String> {
    let stop_script = repo_root().join("Stop-Agent.ps1");
    if !stop_script.exists() {
        return Err("未找到 Stop-Agent.ps1，无法停止外部后台服务".into());
    }
    tokio::task::spawn_blocking(move || {
        let mut cmd = std::process::Command::new("powershell.exe");
        cmd.args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-File",
            &stop_script.to_string_lossy(),
        ]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        let status = cmd.status().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("Stop-Agent.ps1 退出码: {status}"));
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;

    let _ = mark_runtime_status_stopped(&state_root().join("runtime-status.json"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}

#[tauri::command]
async fn stop_services(state: tauri::State<'_, Arc<GuiState>>) -> Result<StatusSnapshot, String> {
    if state.stack.lock().await.is_some() {
        state.stop_all().await;
    } else {
        let cfg = load_config().unwrap_or_default();
        if probe_external_backend(&state.http, &cfg).await.is_some() {
            stop_external_backend().await?;
            state.attached_logged.store(false, Ordering::SeqCst);
            *state.last_error.lock().await = None;
            state
                .push_log(
                    "info",
                    "ATTACH",
                    "已安全停止外部后台服务与隧道（保留独立 job-runner）",
                )
                .await;
        }
    }
    get_status(state).await
}

fn show_or_recreate_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Remote PC MCP Gateway")
        .inner_size(1100.0, 740.0)
        .min_inner_size(900.0, 620.0)
        .center()
        .build();
}

fn resolve_restart_exe() -> Option<PathBuf> {
    // Always target the canonical `rpc-mcp-gui.exe` in the same directory so that
    // even if the currently running binary was rotated to `*.old.exe`, we launch the new build.
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let sibling = dir.join("rpc-mcp-gui.exe");
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    let fallback = repo_root()
        .join("target")
        .join("release")
        .join("rpc-mcp-gui.exe");
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}

async fn restart_application(app_handle: AppHandle, state: Arc<GuiState>) {
    if state.starting.load(Ordering::SeqCst) {
        state
            .push_log("warn", "BOOT", "服务正在初始化中，请稍后再点击重启程序")
            .await;
        return;
    }
    if state
        .restarting
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let Some(target_exe) = resolve_restart_exe() else {
        state
            .push_log(
                "err",
                "BOOT",
                "未找到最新编译的 rpc-mcp-gui.exe，已取消重启（请先运行 cargo build-gui）",
            )
            .await;
        state.restarting.store(false, Ordering::SeqCst);
        let h = app_handle.clone();
        let _ = app_handle.run_on_main_thread(move || {
            show_or_recreate_main_window(&h);
        });
        return;
    };

    let was_running = state.stack.lock().await.is_some();
    state
        .push_log("info", "BOOT", "正在释放本地资源并重启加载最新版本...")
        .await;

    // Destroy existing main window first so WebView2 releases its EBWebView lock cleanly.
    let close_handle = app_handle.clone();
    let _ = app_handle.run_on_main_thread(move || {
        if let Some(win) = close_handle.get_webview_window("main") {
            let _ = win.destroy();
        }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Gracefully stop GUI-owned services, listeners, sidecars, tunnels, and agent.lock.
    state.stop_all().await;

    let mut cmd = std::process::Command::new(&target_exe);
    cmd.arg("--restarting")
        .current_dir(repo_root())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if was_running {
        cmd.arg("--auto-start");
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    // Spawn first; only release the single-instance mutex and exit if spawn succeeded.
    // The new process passes `--restarting` and retries mutex acquisition every 50ms (up to 5s).
    match cmd.spawn() {
        Ok(_) => {
            info!("Spawned updated GUI binary: {}", target_exe.display());
            #[cfg(windows)]
            {
                let si = app_handle.state::<single_instance::GuiSingleInstance>();
                si.release();
            }
            app_handle.exit(0);
        }
        Err(e) => {
            error!("Failed to spawn updated GUI binary: {e}");
            state
                .push_log(
                    "err",
                    "BOOT",
                    format!("拉起新版 {} 失败: {e}", target_exe.display()),
                )
                .await;
            state.restarting.store(false, Ordering::SeqCst);
            let h = app_handle.clone();
            let _ = app_handle.run_on_main_thread(move || {
                show_or_recreate_main_window(&h);
            });
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("job-runner") {
        if let Some(dir) = args.get(2) {
            let code = run_job_runner(std::path::Path::new(dir)).unwrap_or(1);
            std::process::exit(code);
        }
        std::process::exit(2);
    }

    let is_restarting = args.iter().any(|a| a == "--restarting");
    let auto_start = args.iter().any(|a| a == "--auto-start");

    #[cfg(windows)]
    let _single_instance =
        match single_instance::GuiSingleInstance::acquire_or_signal_existing_with_retry(
            is_restarting,
        ) {
            Some(guard) => guard,
            None => std::process::exit(0),
        };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let gui_state = Arc::new(GuiState::default());

    let app = tauri::Builder::default()
        .manage(gui_state)
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            validate_root_dir,
            pick_folder,
            clear_logs,
            get_command_detail,
            reveal_in_explorer,
            get_status,
            start_services,
            stop_services
        ])
        .setup(move |app| {
            #[cfg(windows)]
            {
                let wake_handle = app.handle().clone();
                _single_instance.start_wake_listener(move || {
                    let h = wake_handle.clone();
                    let _ = wake_handle.run_on_main_thread(move || {
                        show_or_recreate_main_window(&h);
                    });
                });
                // Keep the single-instance mutex & event handle alive for the app lifetime
                app.manage(_single_instance);
            }

            let show_i =
                MenuItem::with_id(app, "show", "打开控制台 / Show Panel", true, None::<&str>)?;
            let restart_i = MenuItem::with_id(
                app,
                "restart",
                "重启程序（加载最新版） / Restart App",
                true,
                None::<&str>,
            )?;
            let quit_i =
                MenuItem::with_id(app, "quit", "退出控制台 / Quit Panel", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &restart_i, &quit_i])?;

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Remote PC MCP Gateway (Rust)")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_or_recreate_main_window(app),
                    "restart" => {
                        let app_handle = app.clone();
                        let state = app.state::<Arc<GuiState>>().inner().clone();
                        tauri::async_runtime::spawn(async move {
                            restart_application(app_handle, state).await;
                        });
                    }
                    "quit" => {
                        let app_handle = app.clone();
                        let state = app.state::<Arc<GuiState>>().inner().clone();
                        tauri::async_runtime::spawn(async move {
                            // Only stops GUI-owned stack; externally launched background agent keeps running.
                            state.stop_all().await;
                            app_handle.exit(0);
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_or_recreate_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            if auto_start {
                let st = app.state::<Arc<GuiState>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    st.push_log(
                        "info",
                        "BOOT",
                        "已加载最新版本，正在自动恢复本地服务与隧道...",
                    )
                    .await;
                    match load_config() {
                        Ok(cfg) => {
                            if let Err(e) = start_services_inner(cfg, &st).await {
                                st.push_log("err", "BOOT", format!("重启后自动启动失败: {e}"))
                                    .await;
                                *st.last_error.lock().await = Some(e);
                            }
                        }
                        Err(e) => {
                            st.push_log("err", "BOOT", format!("重启后读取配置失败: {e}"))
                                .await;
                        }
                    }
                });
            } else if is_restarting {
                let st = app.state::<Arc<GuiState>>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    st.push_log(
                        "ok",
                        "BOOT",
                        "已重新加载最新版本 GUI（若后台有外部服务，将自动重新接管）",
                    )
                    .await;
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { .. } = event {
                info!("Main window closed to tray; WebView2 released");
                let _ = window;
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|_app_handle, event| {
        if let RunEvent::ExitRequested { api, code, .. } = event {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
