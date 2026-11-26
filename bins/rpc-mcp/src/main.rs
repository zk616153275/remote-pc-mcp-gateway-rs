use anyhow::Result;
use clap::{Parser, Subcommand};
use rpc_mcp_bridge::orchestrator::ServiceHealth;
use rpc_mcp_bridge::{
    start_cloudflare_tunnel, start_ssh_reverse_tunnel, write_runtime_status, CloudflareOptions,
    RuntimeStatus, SshTunnelOptions,
};
use rpc_mcp_chrome_broker::{
    build_router as build_chrome_router, serve_chrome_broker, ChromeBrokerConfig,
};
use rpc_mcp_core::config::AppConfig;
use rpc_mcp_core::instance_lock::InstanceLock;
use rpc_mcp_core::path_guard::AllowedRoots;
use rpc_mcp_fs::{serve_fs_mcp, FsServerConfig};
use rpc_mcp_gateway::{
    build_router as build_gateway_router, serve_gateway, GatewayServerConfig, OAuthConfig,
    VisionConfig,
};
use rpc_mcp_workbench::{run_job_runner, serve_workbench, WorkbenchConfig};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Parser)]
#[command(
    name = "rpc-mcp",
    version,
    about = "Remote PC MCP Gateway — Rust Core (FS + Workbench + Gateway + Bridge)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run unified local Windows agent (FS MCP + AI Workbench in one process)
    Agent {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long)]
        fs_port: Option<u16>,
        #[arg(long)]
        workbench_port: Option<u16>,
        #[arg(long = "root")]
        roots: Vec<String>,
        #[arg(long, env = "REMOTE_LOCAL_FS_MCP_TOKEN")]
        fs_token: Option<String>,
        #[arg(long, env = "AI_WORKBENCH_TOKEN")]
        workbench_token: Option<String>,
        #[arg(long, default_value = "state/workbench")]
        workbench_state: PathBuf,
        #[arg(long)]
        audit_log: Option<PathBuf>,
        #[arg(long, default_value = "pwsh.exe")]
        pwsh: String,
        #[arg(long)]
        disable_delete_guard: bool,
    },

    /// Run standalone OAuth 2.1 + Streamable HTTP MCP Gateway (Windows or Linux VPS)
    Gateway {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1", env = "MCP_GATEWAY_HOST")]
        host: String,
        #[arg(long, env = "MCP_GATEWAY_PORT")]
        port: Option<u16>,
        #[arg(long, env = "MCP_GATEWAY_SECRET")]
        secret: Option<String>,
        #[arg(long, env = "MCP_GATEWAY_MODE")]
        mode: Option<String>,
        #[arg(long, env = "LOCAL_FS_MCP_URL")]
        fs_url: Option<String>,
        #[arg(long, env = "LOCAL_FS_MCP_TOKEN")]
        fs_token: Option<String>,
        #[arg(long, env = "AI_WORKBENCH_URL")]
        workbench_url: Option<String>,
        #[arg(long, env = "AI_WORKBENCH_TOKEN")]
        workbench_token: Option<String>,
        #[arg(long, env = "LOCAL_CHROME_MCP_URL")]
        chrome_url: Option<String>,
        #[arg(long, env = "LOCAL_CHROME_MCP_TOKEN")]
        chrome_token: Option<String>,
        #[arg(long, env = "MCP_GATEWAY_OAUTH_ISSUER")]
        oauth_issuer: Option<String>,
        #[arg(long, env = "MCP_GATEWAY_OAUTH_SIGNING_KEY")]
        oauth_signing_key: Option<String>,
        #[arg(long, env = "MCP_GATEWAY_OAUTH_APPROVAL_KEY")]
        oauth_approval_key: Option<String>,
        #[arg(long, default_value = "state/oauth-clients.json")]
        oauth_client_store: PathBuf,
        #[arg(long, default_value = "state/logs/gateway-audit.jsonl")]
        audit_log: PathBuf,
        #[arg(long = "allowed-root")]
        allowed_roots: Vec<String>,
        #[arg(long)]
        disable_oauth: bool,
    },

    /// All-in-one single-process mode: FS + Workbench + Gateway (+ optional Cloudflare tunnel)
    Up {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "state")]
        state_dir: PathBuf,
        #[arg(long)]
        cloudflared: Option<PathBuf>,
        #[arg(long, default_value = "pwsh.exe")]
        pwsh: String,
    },

    /// Run Chrome DevTools MCP sidecar broker (wraps upstream chrome-devtools-mcp 1.14+)
    ChromeBroker {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 18619)]
        port: u16,
        #[arg(long, default_value_t = 9222)]
        cdp_port: u16,
        #[arg(long, env = "LOCAL_CHROME_MCP_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },

    /// Detached per-command Windows Job Object supervisor (invoked internally by workbench)
    JobRunner {
        dir: PathBuf,
    },
}

fn resolve_pwsh(explicit: &str) -> String {
    if explicit != "pwsh.exe" && std::path::Path::new(explicit).exists() {
        return explicit.to_string();
    }
    for candidate in [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files\PowerShell\7-preview\pwsh.exe",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    explicit.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Commands::JobRunner { dir } = cli.command {
        let code = run_job_runner(&dir)?;
        std::process::exit(code);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    match cli.command {
        Commands::Agent {
            config,
            host,
            fs_port,
            workbench_port,
            roots,
            fs_token,
            workbench_token,
            workbench_state,
            audit_log,
            pwsh,
            disable_delete_guard,
        } => {
            let state_base = workbench_state
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("state"));
            let _instance_lock = InstanceLock::try_acquire(&state_base.join("agent.lock"), "agent")?;
            let local_audit = audit_log.unwrap_or_else(|| state_base.join("logs").join("local-audit.jsonl"));

            let file_cfg = match config {
                Some(ref p) => AppConfig::load(p)?,
                None => AppConfig::default(),
            };
            let effective_roots = if !roots.is_empty() {
                roots
            } else {
                file_cfg.allowed_roots
            };
            let allowed_roots = AllowedRoots::new(effective_roots)?;

            let fs_cfg = FsServerConfig {
                host: host.clone(),
                port: fs_port.unwrap_or(file_cfg.local_ports.fs_bearer),
                bearer_token: fs_token
                    .filter(|s| !s.is_empty())
                    .unwrap_or(file_cfg.tokens.fs_token),
                allowed_roots,
                audit_log: Some(local_audit.clone()),
            };

            let wb_cfg = WorkbenchConfig {
                host,
                port: workbench_port.unwrap_or(file_cfg.local_ports.workbench),
                bearer_token: workbench_token
                    .filter(|s| !s.is_empty())
                    .unwrap_or(file_cfg.tokens.workbench_token),
                state_root: workbench_state,
                pwsh_path: resolve_pwsh(&pwsh),
                enable_delete_guard: !disable_delete_guard
                    && file_cfg.guards_and_hooks.enable_delete_guard,
                audit_log: Some(local_audit),
            };

            if fs_cfg.bearer_token.is_empty() || wb_cfg.bearer_token.is_empty() {
                anyhow::bail!(
                    "both fs_token and workbench_token are required (via --config, flags, or env)"
                );
            }

            info!(
                "Starting rpc-mcp agent: fs=:{}, workbench=:{}",
                fs_cfg.port, wb_cfg.port
            );
            tokio::try_join!(serve_fs_mcp(fs_cfg), serve_workbench(wb_cfg))?;
        }

        Commands::Gateway {
            config,
            host,
            port,
            secret,
            mode,
            fs_url,
            fs_token,
            workbench_url,
            workbench_token,
            chrome_url,
            chrome_token,
            oauth_issuer,
            oauth_signing_key,
            oauth_approval_key,
            oauth_client_store,
            audit_log,
            allowed_roots,
            disable_oauth,
        } => {
            let file_cfg = match config {
                Some(ref p) => AppConfig::load(p)?,
                None => AppConfig::default(),
            };
            let listen_port = port.unwrap_or(file_cfg.gateway.local_port);
            let gw_secret = secret.unwrap_or(file_cfg.gateway.secret);
            let effective_roots = if !allowed_roots.is_empty() {
                allowed_roots
            } else {
                file_cfg.allowed_roots
            };
            let instance_label = if file_cfg.instance_label.is_empty() {
                "Windows-PC".to_string()
            } else {
                file_cfg.instance_label
            };
            let gw_cfg = GatewayServerConfig {
                host: host.clone(),
                port: listen_port,
                secret: gw_secret,
                mode: mode.unwrap_or(file_cfg.gateway.mode),
                enable_commands: file_cfg.gateway.enable_commands,
                enable_chrome: file_cfg.gateway.enable_chrome && chrome_url.is_some(),
                fs_url: fs_url.unwrap_or_else(|| {
                    format!("http://127.0.0.1:{}/mcp", file_cfg.local_ports.fs_bearer)
                }),
                fs_token: fs_token.unwrap_or(file_cfg.tokens.fs_token),
                workbench_url: workbench_url.unwrap_or_else(|| {
                    format!("http://127.0.0.1:{}/mcp", file_cfg.local_ports.workbench)
                }),
                workbench_token: workbench_token.unwrap_or(file_cfg.tokens.workbench_token),
                chrome_url: chrome_url.unwrap_or_default(),
                chrome_token: chrome_token.unwrap_or_default(),
                workspace_root: effective_roots
                    .first()
                    .cloned()
                    .unwrap_or_else(|| ".".into()),
                allowed_roots: effective_roots,
                instance_label: instance_label.clone(),
                oauth: OAuthConfig {
                    enabled: !disable_oauth,
                    issuer: oauth_issuer
                        .unwrap_or_else(|| format!("http://{host}:{listen_port}")),
                    mcp_path: String::new(),
                    signing_key: oauth_signing_key.unwrap_or(file_cfg.gateway.oauth_signing_key),
                    approval_key: oauth_approval_key.unwrap_or(file_cfg.gateway.approval_key),
                    instance_label,
                    client_store_path: Some(oauth_client_store),
                    ..OAuthConfig::default()
                },
                audit_log: Some(audit_log),
                task_dir: Some(PathBuf::from("state/gateway-tasks")),
                vision: VisionConfig {
                    mode: file_cfg.guards_and_hooks.vision_backend,
                    gemini_api_key: file_cfg.guards_and_hooks.gemini_api_key,
                    openai_api_key: file_cfg.guards_and_hooks.openai_api_key,
                    ..VisionConfig::default()
                },
            };
            serve_gateway(gw_cfg).await?;
        }

        Commands::ChromeBroker {
            host,
            port,
            cdp_port,
            token,
            audit_log,
        } => {
            let mut cfg = ChromeBrokerConfig::default_npx(port, cdp_port);
            cfg.host = host;
            cfg.bearer_token = token.filter(|s| !s.is_empty());
            cfg.audit_log = Some(
                audit_log.unwrap_or_else(|| PathBuf::from("state/logs/local-audit.jsonl")),
            );
            serve_chrome_broker(cfg).await?;
        }

        Commands::Up {
            config,
            state_dir,
            cloudflared,
            pwsh,
        } => {
            let _instance_lock = InstanceLock::try_acquire(&state_dir.join("agent.lock"), "up")?;
            let local_audit = state_dir.join("logs").join("local-audit.jsonl");

            let cfg = AppConfig::load(&config)?;
            let allowed_roots = AllowedRoots::new(cfg.allowed_roots.clone())?;
            let host = "127.0.0.1".to_string();
            let is_vps = cfg.connection_mode == "vps" || cfg.connection_mode == "vps-ssh";

            if cfg.tokens.fs_token.is_empty() || cfg.tokens.workbench_token.is_empty() {
                anyhow::bail!(
                    "both tokens.fsToken and tokens.workbenchToken must be configured"
                );
            }

            let fs_cfg = FsServerConfig {
                host: host.clone(),
                port: cfg.local_ports.fs_bearer,
                bearer_token: cfg.tokens.fs_token.clone(),
                allowed_roots: allowed_roots.clone(),
                audit_log: Some(local_audit.clone()),
            };
            let wb_cfg = WorkbenchConfig {
                host: host.clone(),
                port: cfg.local_ports.workbench,
                bearer_token: cfg.tokens.workbench_token.clone(),
                state_root: state_dir.join("workbench"),
                pwsh_path: resolve_pwsh(&pwsh),
                enable_delete_guard: cfg.guards_and_hooks.enable_delete_guard,
                audit_log: Some(local_audit.clone()),
            };
            let mut chrome_ok = false;
            let mut chrome_backend = None;
            let chrome_token = if !cfg.tokens.chrome_token.trim().is_empty() {
                cfg.tokens.chrome_token.clone()
            } else if is_vps {
                // In VPS mode without an explicit shared chromeToken, omit ephemeral token
                // so the remote VPS gateway over SSH -R is not rejected with 401.
                String::new()
            } else {
                format!(
                    "{}{}",
                    uuid::Uuid::new_v4().simple(),
                    uuid::Uuid::new_v4().simple()
                )
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
                        tokio::spawn(async move {
                            let _ = axum::serve(ch_listener, ch_app).await;
                        });
                        chrome_backend = Some(backend);
                        chrome_ok = true;
                        info!(
                            "READY rpc-mcp-chrome-broker listening on http://127.0.0.1:{}",
                            cfg.local_ports.chrome_mcp
                        );
                    }
                    Err(e) => {
                        warn!("Chrome broker skipped (port busy): {e}");
                    }
                }
            }

            let gw_cfg = GatewayServerConfig {
                host: host.clone(),
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
                chrome_token: if chrome_ok { chrome_token } else { String::new() },
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
                    client_store_path: Some(state_dir.join("oauth-clients.json")),
                    ..OAuthConfig::default()
                },
                audit_log: Some(state_dir.join("logs").join("gateway-audit.jsonl")),
                task_dir: Some(state_dir.join("gateway-tasks")),
                vision: VisionConfig {
                    mode: cfg.guards_and_hooks.vision_backend.clone(),
                    gemini_api_key: cfg.guards_and_hooks.gemini_api_key.clone(),
                    openai_api_key: cfg.guards_and_hooks.openai_api_key.clone(),
                    ..VisionConfig::default()
                },
            };

            let mcp_path = gw_cfg.mcp_path();
            let gw_addr: SocketAddr = format!("127.0.0.1:{}", gw_cfg.port).parse()?;
            // Bind local gateway BEFORE starting any public tunnel (skip local gateway in VPS mode)
            let local_gw = if !is_vps {
                let (gw_router, gw_handle) = build_gateway_router(gw_cfg);
                let gw_listener = TcpListener::bind(gw_addr).await?;
                Some((gw_listener, gw_router, gw_handle))
            } else {
                None
            };

            let mut public_origin = format!("http://127.0.0.1:{}", cfg.gateway.local_port);
            let mut _cf_tunnel = None;
            let mut ssh_tunnel = None;

            if is_vps {
                let mut forwards = vec![
                    (cfg.vps.remote_fs_port, cfg.local_ports.fs_bearer),
                    (cfg.vps.remote_workbench_port, cfg.local_ports.workbench),
                ];
                if chrome_ok {
                    forwards.push((cfg.vps.remote_chrome_mcp_port, cfg.local_ports.chrome_mcp));
                }
                let known_hosts = config.parent().map(|p| p.join("vps-known-hosts"));
                let st = start_ssh_reverse_tunnel(&SshTunnelOptions {
                    host: cfg.vps.host.clone(),
                    ssh_port: cfg.vps.ssh_port,
                    user: cfg.vps.user.clone(),
                    ssh_key_path: cfg.vps.ssh_key_path.clone(),
                    known_hosts_path: known_hosts,
                    forwards,
                })?;
                if !cfg.vps.domain.trim().is_empty() {
                    let dom = cfg
                        .vps
                        .domain
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    public_origin = format!("https://{dom}");
                }
                ssh_tunnel = Some(st);
            } else if let Some(cf_exe) = cloudflared {
                let cf_mode = if cfg.connection_mode == "cloudflare-named" {
                    "named"
                } else {
                    "quick"
                };
                let t = start_cloudflare_tunnel(CloudflareOptions {
                    mode: cf_mode.into(),
                    target_url: format!("http://127.0.0.1:{}", cfg.gateway.local_port),
                    named_tunnel_token: cfg.cloudflare.named_tunnel_token.clone(),
                    public_hostname: cfg.cloudflare.public_hostname.clone(),
                    cloudflared_exe: cf_exe,
                })
                .await?;
                public_origin = t.public_url.clone();
                if let Some((_, _, ref gw_handle)) = local_gw {
                    gw_handle.set_issuer(&public_origin);
                }
                info!("Public MCP URL: {}{}", public_origin, mcp_path);
                _cf_tunnel = Some(t);
            }

            let _ = write_runtime_status(
                &state_dir.join("runtime-status.json"),
                &RuntimeStatus {
                    updated_at: String::new(),
                    mode: cfg.connection_mode.clone(),
                    public_origin: public_origin.clone(),
                    mcp_url: format!("{public_origin}{mcp_path}"),
                    fs_mcp: ServiceHealth {
                        ok: true,
                        detail: format!("127.0.0.1:{}", cfg.local_ports.fs_bearer),
                    },
                    workbench: ServiceHealth {
                        ok: true,
                        detail: format!("127.0.0.1:{}", cfg.local_ports.workbench),
                    },
                    gateway: ServiceHealth {
                        ok: !is_vps,
                        detail: if is_vps {
                            "remote on VPS".into()
                        } else {
                            format!("127.0.0.1:{}", cfg.gateway.local_port)
                        },
                    },
                    chrome_mcp: ServiceHealth {
                        ok: chrome_ok,
                        detail: if chrome_ok {
                            format!("127.0.0.1:{}", cfg.local_ports.chrome_mcp)
                        } else {
                            "disabled".into()
                        },
                    },
                },
            );

            let gw_fut = async move {
                if let Some((gw_listener, gw_router, _)) = local_gw {
                    axum::serve(gw_listener, gw_router).await?;
                } else {
                    std::future::pending::<()>().await;
                }
                Ok::<(), anyhow::Error>(())
            };

            tokio::select! {
                res = async { tokio::try_join!(serve_fs_mcp(fs_cfg), serve_workbench(wb_cfg), gw_fut) } => {
                    res?;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C; shutting down rpc-mcp stack...");
                }
            }
            if let Some(ref mut st) = ssh_tunnel {
                st.shutdown().await;
            }
            if let Some(ref backend) = chrome_backend {
                backend.shutdown().await;
            }
        }

        Commands::JobRunner { .. } => unreachable!(),
    }

    Ok(())
}
