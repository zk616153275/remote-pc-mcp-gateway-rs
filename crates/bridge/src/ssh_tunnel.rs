use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct SshTunnelOptions {
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    pub ssh_key_path: String,
    pub known_hosts_path: Option<PathBuf>,
    pub forwards: Vec<(u16, u16)>, // (remote_port, local_port)
}

pub struct RunningSshTunnel {
    pub child: Child,
}

pub fn start_ssh_reverse_tunnel(opts: &SshTunnelOptions) -> Result<RunningSshTunnel> {
    if opts.host.trim().is_empty() {
        anyhow::bail!("VPS host is required for SSH reverse tunnel");
    }

    #[cfg(windows)]
    {
        let host = &opts.host;
        let _ = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &format!(
                    "Get-CimInstance Win32_Process -Filter \"Name='ssh.exe'\" -ErrorAction SilentlyContinue | Where-Object {{ $_.CommandLine -match '-R\\s+' -and $_.CommandLine -match [regex]::Escape('{host}') }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}"
                ),
            ])
            .output();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let ssh_exe = if cfg!(windows) {
        r"C:\Windows\System32\OpenSSH\ssh.exe"
    } else {
        "ssh"
    };

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
        "ServerAliveInterval=30".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=3".to_string(),
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

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn SSH reverse tunnel to {}", opts.host))?;

    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.trim().is_empty() {
                    warn!("ssh tunnel: {line}");
                }
            }
        });
    }

    info!(
        "SSH reverse tunnel started -> {}@{}:{} ({} forwards)",
        opts.user,
        opts.host,
        opts.ssh_port,
        opts.forwards.len()
    );
    Ok(RunningSshTunnel { child })
}
