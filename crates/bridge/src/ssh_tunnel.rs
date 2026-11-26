use anyhow::{Context, Result};
use rpc_mcp_core::ChildJobGuard;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const INITIAL_BACKOFF_SECS: u64 = 1;
const MAX_BACKOFF_SECS: u64 = 30;
const HEALTHY_RESET_SECS: u64 = 60;
const STALE_CLEANUP_RELEASE_WAIT_MS: u64 = 600;
const STABLE_CONNECT_GRACE_MS: u64 = 1500;

#[derive(Debug, Clone)]
pub struct SshTunnelOptions {
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    pub ssh_key_path: String,
    pub known_hosts_path: Option<PathBuf>,
    pub forwards: Vec<(u16, u16)>, // (remote_port, local_port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshTunnelState {
    Connecting {
        attempt: u32,
    },
    Connected {
        pid: u32,
        attempt: u32,
    },
    Reconnecting {
        attempt: u32,
        backoff_secs: u64,
        last_error: String,
    },
    Stopped,
}

/// Supervised SSH reverse tunnel with Windows Job Object lifetime binding
/// and exponential-backoff auto-reconnect.
pub struct SshTunnelSupervisor {
    stop_tx: Option<oneshot::Sender<()>>,
    status_rx: watch::Receiver<SshTunnelState>,
    task: Option<JoinHandle<()>>,
}

/// Backwards-compatible alias for callers expecting `RunningSshTunnel`.
pub type RunningSshTunnel = SshTunnelSupervisor;

impl SshTunnelSupervisor {
    pub fn status(&self) -> SshTunnelState {
        self.status_rx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<SshTunnelState> {
        self.status_rx.clone()
    }

    pub fn current_pid(&self) -> Option<u32> {
        match *self.status_rx.borrow() {
            SshTunnelState::Connected { pid, .. } => Some(pid),
            _ => None,
        }
    }

    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;
        }
    }
}

impl Drop for SshTunnelSupervisor {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task.take() {
            handle.abort();
        }
    }
}

/// Builds the exact remote-forward port tokens used to identify this gateway's own
/// `ssh -R` processes without touching unrelated reverse tunnels on the same machine.
pub fn build_forward_port_tokens(forwards: &[(u16, u16)]) -> Vec<String> {
    let mut tokens: Vec<String> = forwards
        .iter()
        .map(|(remote, _)| format!("127.0.0.1:{remote}:"))
        .collect();
    tokens.sort();
    tokens.dedup();
    tokens
}

fn is_host_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
}

fn contains_host_bounded(cmdline: &str, host: &str) -> bool {
    let haystack = cmdline.to_ascii_lowercase();
    let needle = host.to_ascii_lowercase();
    if needle.is_empty() {
        return false;
    }
    let hbytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(&needle) {
        let idx = start + rel;
        let end = idx + needle.len();
        let left_ok = idx == 0 || !is_host_char(hbytes[idx - 1]);
        let right_ok = end == hbytes.len() || !is_host_char(hbytes[end]);
        if left_ok && right_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

/// Pure matching predicate (also mirrored in the PowerShell cleanup script) verifying
/// that a command line belongs to *this* gateway's reverse tunnel for `host` and at
/// least one of its configured remote forward ports.
pub fn matches_stale_tunnel_cmdline(
    cmdline: &str,
    host: &str,
    port_tokens: &[String],
) -> bool {
    let host = host.trim();
    if host.is_empty() || port_tokens.is_empty() {
        return false;
    }
    let has_reverse_flag = cmdline.contains(" -R ")
        || cmdline.contains("\t-R ")
        || cmdline.contains(" -R127.")
        || cmdline.starts_with("-R ");
    let has_host = contains_host_bounded(cmdline, host);
    let has_port = port_tokens.iter().any(|tok| cmdline.contains(tok.as_str()));
    has_reverse_flag && has_host && has_port
}

pub fn build_ssh_args(opts: &SshTunnelOptions) -> Vec<String> {
    let mut args = vec![
        "-N".to_string(),
        "-T".to_string(),
        "-p".to_string(),
        opts.ssh_port.to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        "ExitOnForwardFailure=yes".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=15".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "TCPKeepAlive=yes".to_string(),
    ];
    if !opts.ssh_key_path.trim().is_empty() {
        args.push("-i".to_string());
        args.push(opts.ssh_key_path.clone());
        args.push("-o".to_string());
        args.push("IdentitiesOnly=yes".to_string());
    }
    if let Some(ref kh) = opts.known_hosts_path {
        args.push("-o".to_string());
        args.push(format!("UserKnownHostsFile={}", kh.display()));
    }
    for (remote, local) in &opts.forwards {
        args.push("-R".to_string());
        args.push(format!("127.0.0.1:{remote}:127.0.0.1:{local}"));
    }
    args.push(format!("{}@{}", opts.user, opts.host));
    args
}

pub fn next_backoff_secs(current: u64) -> u64 {
    current.saturating_mul(2).clamp(INITIAL_BACKOFF_SECS, MAX_BACKOFF_SECS)
}

#[cfg(windows)]
const CLEANUP_STALE_SSH_PS: &str = r#"
$targetHost = $env:RPC_MCP_TARGET_HOST
$rawTokens = $env:RPC_MCP_PORT_TOKENS
if ([string]::IsNullOrWhiteSpace($targetHost) -or [string]::IsNullOrWhiteSpace($rawTokens)) { exit 0 }
$tokens = $rawTokens.Split(',') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if ($tokens.Count -eq 0) { exit 0 }
$escapedHost = "(?<![A-Za-z0-9._-])" + [regex]::Escape($targetHost) + "(?![A-Za-z0-9._-])"
$procs = Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
    $cl = [string]$p.CommandLine
    if ([string]::IsNullOrWhiteSpace($cl)) { continue }
    if ($cl -notmatch '(^|\s)-R(\s+|127\.)') { continue }
    if ($cl -notmatch $escapedHost) { continue }
    $portMatched = $false
    foreach ($tok in $tokens) {
        if ($cl.Contains($tok)) {
            $portMatched = $true
            break
        }
    }
    if ($portMatched) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            Write-Output $p.ProcessId
        } catch {}
    }
}
"#;

/// Precision, injection-free, non-blocking cleanup for legacy/orphaned `ssh.exe`
/// processes that match BOTH `host` and at least one configured remote forward port.
/// Returns the number of terminated stale processes.
async fn cleanup_stale_ssh_tunnels(host: &str, forwards: &[(u16, u16)]) -> usize {
    #[cfg(not(windows))]
    {
        let _ = (host, forwards);
        return 0;
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        let host = host.trim().to_string();
        let port_tokens = build_forward_port_tokens(forwards);
        if host.is_empty() || port_tokens.is_empty() {
            return 0;
        }
        let tokens_csv = port_tokens.join(",");

        let host_for_task = host.clone();
        let killed_pids = tokio::task::spawn_blocking(move || -> Vec<u32> {
            let mut cmd = std::process::Command::new("powershell.exe");
            cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                CLEANUP_STALE_SSH_PS,
            ])
            .env("RPC_MCP_TARGET_HOST", &host_for_task)
            .env("RPC_MCP_PORT_TOKENS", &tokens_csv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000); // CREATE_NO_WINDOW

            match cmd.output() {
                Ok(out) => String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok())
                    .collect(),
                Err(e) => {
                    warn!("stale SSH tunnel scan failed: {e}");
                    Vec::new()
                }
            }
        })
        .await
        .unwrap_or_default();

        if !killed_pids.is_empty() {
            warn!(
                "Cleaned {} stale SSH reverse tunnel process(es) matching {}: {:?}",
                killed_pids.len(),
                host,
                killed_pids
            );
            tokio::time::sleep(Duration::from_millis(STALE_CLEANUP_RELEASE_WAIT_MS)).await;
        }
        killed_pids.len()
    }
}

/// Starts a supervised SSH reverse tunnel that automatically recovers from
/// transient network drops, sleep/wake cycles, and VPS port-release races.
pub fn start_ssh_reverse_tunnel(opts: &SshTunnelOptions) -> Result<SshTunnelSupervisor> {
    if opts.host.trim().is_empty() {
        anyhow::bail!("VPS host is required for SSH reverse tunnel");
    }
    if opts.forwards.is_empty() {
        anyhow::bail!("at least one reverse port forward is required for SSH tunnel");
    }

    let opts = opts.clone();
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (status_tx, status_rx) = watch::channel(SshTunnelState::Connecting { attempt: 1 });

    let task = tokio::spawn(async move {
        let ssh_exe = if cfg!(windows) {
            r"C:\Windows\System32\OpenSSH\ssh.exe"
        } else {
            "ssh"
        };
        let args = build_ssh_args(&opts);

        // One-time precision cleanup for any pre-existing orphaned ssh.exe from legacy scripts.
        let _ = cleanup_stale_ssh_tunnels(&opts.host, &opts.forwards).await;

        let mut attempt: u32 = 1;
        let mut backoff_secs: u64 = INITIAL_BACKOFF_SECS;

        loop {
            if stop_rx.try_recv().is_ok() {
                let _ = status_tx.send(SshTunnelState::Stopped);
                break;
            }

            let _ = status_tx.send(SshTunnelState::Connecting { attempt });

            let mut cmd = Command::new(ssh_exe);
            cmd.args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            #[cfg(windows)]
            {
                cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }

            let spawn_res = cmd
                .spawn()
                .with_context(|| format!("failed to spawn SSH reverse tunnel to {}", opts.host));

            let mut child = match spawn_res {
                Ok(c) => c,
                Err(e) => {
                    let msg = e.to_string();
                    warn!("SSH tunnel spawn failed (attempt {attempt}): {msg}");
                    let _ = status_tx.send(SshTunnelState::Reconnecting {
                        attempt: attempt + 1,
                        backoff_secs,
                        last_error: msg,
                    });
                    tokio::select! {
                        _ = &mut stop_rx => {
                            let _ = status_tx.send(SshTunnelState::Stopped);
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
                    }
                    attempt = attempt.saturating_add(1);
                    backoff_secs = next_backoff_secs(backoff_secs);
                    continue;
                }
            };

            // Bind ssh.exe to a Windows Job Object (KILL_ON_JOB_CLOSE) so crashes never leak orphans.
            #[cfg(windows)]
            let _job = child
                .raw_handle()
                .and_then(ChildJobGuard::attach_raw_handle);

            let pid = child.id().unwrap_or(0);
            let started_at = tokio::time::Instant::now();
            let last_stderr: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

            let stderr_task = child.stderr.take().map(|stderr| {
                let last_stderr_clone = last_stderr.clone();
                tokio::spawn(async move {
                    let mut lines = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            warn!("ssh tunnel: {trimmed}");
                            *last_stderr_clone.lock().await = Some(trimmed.to_string());
                        }
                    }
                })
            });

            info!(
                "SSH reverse tunnel spawned (pid={}, attempt={}) -> {}@{}:{} ({} forwards)",
                pid,
                attempt,
                opts.user,
                opts.host,
                opts.ssh_port,
                opts.forwards.len()
            );

            // Wait briefly before declaring Connected so fast failures (e.g. immediate exit 255
            // on port collision or auth failure) do not falsely flash Connected in status UI.
            let mut promoted_connected = false;
            let exit_status_opt: Option<std::io::Result<std::process::ExitStatus>> = tokio::select! {
                _ = &mut stop_rx => {
                    info!("Stopping SSH reverse tunnel (pid={pid})...");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    let _ = status_tx.send(SshTunnelState::Stopped);
                    None
                }
                status_res = child.wait() => {
                    Some(status_res)
                }
                _ = tokio::time::sleep(Duration::from_millis(STABLE_CONNECT_GRACE_MS)) => {
                    promoted_connected = true;
                    let _ = status_tx.send(SshTunnelState::Connected { pid, attempt });
                    info!(
                        "SSH reverse tunnel connected (pid={}, attempt={}) -> {}@{}:{}",
                        pid, attempt, opts.user, opts.host, opts.ssh_port
                    );
                    tokio::select! {
                        _ = &mut stop_rx => {
                            info!("Stopping SSH reverse tunnel (pid={pid})...");
                            let _ = child.kill().await;
                            let _ = child.wait().await;
                            let _ = status_tx.send(SshTunnelState::Stopped);
                            None
                        }
                        status_res = child.wait() => {
                            Some(status_res)
                        }
                    }
                }
            };

            let Some(status_res) = exit_status_opt else {
                break;
            };

            if let Some(st_task) = stderr_task {
                let _ = tokio::time::timeout(Duration::from_millis(200), st_task).await;
            }
            let detail = last_stderr.lock().await.clone().unwrap_or_default();
            let exit_desc = match status_res {
                Ok(s) => format!("{s}"),
                Err(e) => format!("wait error: {e}"),
            };
            let reason = if detail.is_empty() {
                exit_desc
            } else {
                format!("{exit_desc} ({detail})")
            };

            if promoted_connected && started_at.elapsed() >= Duration::from_secs(HEALTHY_RESET_SECS) {
                backoff_secs = INITIAL_BACKOFF_SECS;
            }

            warn!(
                "SSH reverse tunnel exited ({reason}); reconnecting in {backoff_secs}s (next attempt={})",
                attempt + 1
            );

            // If exit looks like a port-forwarding collision (exit 255 / remote port forwarding failed),
            // run one precision cleanup pass before the next attempt.
            if reason.contains("255") || reason.to_ascii_lowercase().contains("forwarding failed") {
                let _ = cleanup_stale_ssh_tunnels(&opts.host, &opts.forwards).await;
            }

            let _ = status_tx.send(SshTunnelState::Reconnecting {
                attempt: attempt + 1,
                backoff_secs,
                last_error: reason,
            });

            tokio::select! {
                _ = &mut stop_rx => {
                    let _ = status_tx.send(SshTunnelState::Stopped);
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(backoff_secs)) => {}
            }

            attempt = attempt.saturating_add(1);
            backoff_secs = next_backoff_secs(backoff_secs);
        }
    });

    Ok(SshTunnelSupervisor {
        stop_tx: Some(stop_tx),
        status_rx,
        task: Some(task),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_unified_ssh_args_with_keepalive_and_forwards() {
        let opts = SshTunnelOptions {
            host: "vps.example.com".into(),
            ssh_port: 2222,
            user: "tunnel".into(),
            ssh_key_path: r"C:\keys\id_ed25519".into(),
            known_hosts_path: Some(PathBuf::from(r"C:\cfg\vps-known-hosts")),
            forwards: vec![(27618, 18849), (27623, 18623)],
        };
        let args = build_ssh_args(&opts);
        assert!(args.contains(&"-N".to_string()));
        assert!(args.contains(&"-T".to_string()));
        assert!(args.contains(&"ExitOnForwardFailure=yes".to_string()));
        assert!(args.contains(&"ServerAliveInterval=15".to_string()));
        assert!(args.contains(&"ServerAliveCountMax=3".to_string()));
        assert!(args.contains(&"ConnectTimeout=10".to_string()));
        assert!(args.contains(&"TCPKeepAlive=yes".to_string()));
        assert!(args.contains(&"127.0.0.1:27618:127.0.0.1:18849".to_string()));
        assert!(args.contains(&"127.0.0.1:27623:127.0.0.1:18623".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("tunnel@vps.example.com"));
    }

    #[test]
    fn matches_only_this_gateways_tunnel_processes() {
        let tokens = build_forward_port_tokens(&[(27618, 18849), (27623, 18623)]);
        let own_cmd = r#"C:\Windows\System32\OpenSSH\ssh.exe -N -T -p 22 -R 127.0.0.1:27618:127.0.0.1:18849 -R 127.0.0.1:27623:127.0.0.1:18623 root@203.0.113.10"#;
        let same_host_other_app = r#"ssh.exe -N -R 127.0.0.1:9999:127.0.0.1:3000 root@203.0.113.10"#;
        let other_host_same_port = r#"ssh.exe -N -R 127.0.0.1:27618:127.0.0.1:18849 root@198.51.100.20"#;
        let interactive_ssh = r#"ssh.exe root@203.0.113.10"#;

        assert!(matches_stale_tunnel_cmdline(own_cmd, "203.0.113.10", &tokens));
        assert!(!matches_stale_tunnel_cmdline(own_cmd, "203.0.113.1", &tokens));
        assert!(!matches_stale_tunnel_cmdline(same_host_other_app, "203.0.113.10", &tokens));
        assert!(!matches_stale_tunnel_cmdline(other_host_same_port, "203.0.113.10", &tokens));
        assert!(!matches_stale_tunnel_cmdline(interactive_ssh, "203.0.113.10", &tokens));
    }

    #[test]
    fn backoff_doubles_and_caps_at_30s() {
        assert_eq!(next_backoff_secs(1), 2);
        assert_eq!(next_backoff_secs(2), 4);
        assert_eq!(next_backoff_secs(4), 8);
        assert_eq!(next_backoff_secs(8), 16);
        assert_eq!(next_backoff_secs(16), 30);
        assert_eq!(next_backoff_secs(30), 30);
    }
}
