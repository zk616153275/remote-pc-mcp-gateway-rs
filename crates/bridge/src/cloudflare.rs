use anyhow::{Context, Result};
use regex::Regex;
use rpc_mcp_core::ChildJobGuard;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::info;

const CLOUDFLARE_ANYCAST_EDGES: &[&str] = &["198.41.192.7:7844", "198.41.200.13:7844"];

/// Returns true if the IPv4 address falls inside 198.18.0.0/15 (Clash / Mihomo / Sing-box TUN Fake-IP).
pub fn is_fake_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

pub async fn detect_fake_ip_env() -> bool {
    let Ok(addrs) = tokio::net::lookup_host(("region1.v2.argotunnel.com", 7844)).await else {
        return false;
    };
    for addr in addrs {
        if let IpAddr::V4(v4) = addr.ip() {
            if is_fake_ip(v4) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone)]
pub struct CloudflareOptions {
    pub mode: String, // "quick" | "named"
    pub target_url: String,
    pub named_tunnel_token: String,
    pub public_hostname: String,
    pub cloudflared_exe: PathBuf,
}

pub struct RunningTunnel {
    pub child: Child,
    pub public_url: String,
    pub fake_ip_bypassed: bool,
    _job: Option<ChildJobGuard>,
}

fn trycloudflare_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)https://[a-z0-9-]+\.trycloudflare\.com").unwrap())
}

pub async fn start_cloudflare_tunnel(opts: CloudflareOptions) -> Result<RunningTunnel> {
    let fake_ip = detect_fake_ip_env().await;
    let protocol = if fake_ip { "quic" } else { "http2" };

    let mut args = vec![
        "tunnel".to_string(),
        "--protocol".to_string(),
        protocol.to_string(),
        "--no-autoupdate".to_string(),
    ];
    if fake_ip {
        for ep in CLOUDFLARE_ANYCAST_EDGES {
            args.push("--edge".to_string());
            args.push((*ep).to_string());
        }
    }

    if opts.mode == "named" {
        if opts.named_tunnel_token.is_empty() || opts.public_hostname.is_empty() {
            anyhow::bail!("named_tunnel_token and public_hostname are required for named tunnel");
        }
        args.push("run".to_string());
        args.push("--token".to_string());
        args.push(opts.named_tunnel_token.clone());
    } else {
        args.push("--url".to_string());
        args.push(opts.target_url.clone());
    }

    let mut cmd = Command::new(&opts.cloudflared_exe);
    cmd.args(&args)
        .env("NO_PROXY", "127.0.0.1,localhost")
        .env("no_proxy", "127.0.0.1,localhost")
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
        .with_context(|| format!("failed to spawn {}", opts.cloudflared_exe.display()))?;

    #[cfg(windows)]
    let job = child
        .raw_handle()
        .and_then(ChildJobGuard::attach_raw_handle);
    #[cfg(not(windows))]
    let job: Option<ChildJobGuard> = None;

    let stderr = child.stderr.take().context("missing cloudflared stderr")?;
    let mut lines = BufReader::new(stderr).lines();

    if opts.mode == "named" {
        // Continuously drain stderr in the background to prevent pipe buffer deadlock
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        let host = opts
            .public_hostname
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let public_url = format!("https://{host}");
        info!("Cloudflare Named Tunnel started ({public_url}, fake_ip_bypass={fake_ip})");
        return Ok(RunningTunnel {
            child,
            public_url,
            fake_ip_bypassed: fake_ip,
            _job: job,
        });
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(35);

    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_secs(2), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some(m) = trycloudflare_re().find(&line) {
                    let public_url = m.as_str().to_string();
                    info!("Cloudflare Quick Tunnel ready: {public_url} (fake_ip_bypass={fake_ip})");
                    // Keep draining stderr so cloudflared never hits EPIPE or blocks
                    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
                    return Ok(RunningTunnel {
                        child,
                        public_url,
                        fake_ip_bypassed: fake_ip,
                        _job: job,
                    });
                }
            }
            Ok(Ok(None)) => break,
            _ => {}
        }
    }

    let _ = child.kill().await;
    anyhow::bail!("timed out waiting for trycloudflare.com URL from cloudflared");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_clash_fake_ip_cidr() {
        assert!(is_fake_ip(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_fake_ip(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_fake_ip(Ipv4Addr::new(198, 41, 192, 7)));
        assert!(!is_fake_ip(Ipv4Addr::new(1, 1, 1, 1)));
    }
}
