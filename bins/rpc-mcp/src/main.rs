use anyhow::Result;
use clap::{Parser, Subcommand};
use rpc_mcp_bridge::{start_cloudflare_tunnel, CloudflareOptions};
use rpc_mcp_chrome_broker::{serve_chrome_broker, ChromeBrokerConfig};
use rpc_mcp_core::config::AppConfig;
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
use tracing::info;

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
            pwsh,
            disable_delete_guard,
        } => {
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
            disable_oauth,
        } => {
            let file_cfg = match config {
                Some(ref p) => AppConfig::load(p)?,
                None => AppConfig::default(),
            };
            let listen_port = port.unwrap_or(file_cfg.gateway.local_port);
            let gw_secret = secret.unwrap_or(file_cfg.gateway.secret);
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
                workspace_root: file_cfg
                    .allowed_roots
                    .first()
                    .cloned()
                    .unwrap_or_else(|| ".".into()),
                allowed_roots: file_cfg.allowed_roots.clone(),
                instance_label: if file_cfg.instance_label.is_empty() {
                    "Windows-PC".into()
                } else {
                    file_cfg.instance_label
                },
                oauth: OAuthConfig {
                    enabled: !disable_oauth,
                    issuer: oauth_issuer
                        .unwrap_or_else(|| format!("http://{host}:{listen_port}")),
                    mcp_path: String::new(),
                    signing_key: oauth_signing_key.unwrap_or(file_cfg.gateway.oauth_signing_key),
                    approval_key: oauth_approval_key.unwrap_or(file_cfg.gateway.approval_key),
                    instance_label: "Windows-PC".into(),
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
        } => {
            let mut cfg = ChromeBrokerConfig::default_npx(port, cdp_port);
            cfg.host = host;
            cfg.bearer_token = token.filter(|s| !s.is_empty());
            serve_chrome_broker(cfg).await?;
        }

        Commands::Up {
            config,
            state_dir,
            cloudflared,
            pwsh,
        } => {
            let cfg = AppConfig::load(&config)?;
            let allowed_roots = AllowedRoots::new(cfg.allowed_roots.clone())?;
            let host = "127.0.0.1".to_string();

            let fs_cfg = FsServerConfig {
                host: host.clone(),
                port: cfg.local_ports.fs_bearer,
                bearer_token: cfg.tokens.fs_token.clone(),
                allowed_roots,
            };
            let wb_cfg = WorkbenchConfig {
                host: host.clone(),
                port: cfg.local_ports.workbench,
                bearer_token: cfg.tokens.workbench_token.clone(),
                state_root: state_dir.join("workbench"),
                pwsh_path: resolve_pwsh(&pwsh),
                enable_delete_guard: cfg.guards_and_hooks.enable_delete_guard,
            };
            let gw_cfg = GatewayServerConfig {
                host: host.clone(),
                port: cfg.gateway.local_port,
                secret: cfg.gateway.secret.clone(),
                mode: cfg.gateway.mode.clone(),
                enable_commands: cfg.gateway.enable_commands,
                enable_chrome: false,
                fs_url: format!("http://127.0.0.1:{}/mcp", cfg.local_ports.fs_bearer),
                fs_token: cfg.tokens.fs_token.clone(),
                workbench_url: format!("http://127.0.0.1:{}/mcp", cfg.local_ports.workbench),
                workbench_token: cfg.tokens.workbench_token.clone(),
                chrome_url: String::new(),
                chrome_token: String::new(),
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
            let (gw_router, gw_handle) = build_gateway_router(gw_cfg);

            let _tunnel = if let Some(cf_exe) = cloudflared {
                let t = start_cloudflare_tunnel(CloudflareOptions {
                    mode: "quick".into(),
                    target_url: format!("http://127.0.0.1:{}", cfg.gateway.local_port),
                    named_tunnel_token: String::new(),
                    public_hostname: String::new(),
                    cloudflared_exe: cf_exe,
                })
                .await?;
                gw_handle.set_issuer(&t.public_url);
                info!("Public MCP URL: {}{}", t.public_url, mcp_path);
                Some(t)
            } else {
                None
            };

            let gw_listener = TcpListener::bind(gw_addr).await?;
            let gw_fut = async move {
                axum::serve(gw_listener, gw_router).await?;
                Ok::<(), anyhow::Error>(())
            };

            tokio::try_join!(serve_fs_mcp(fs_cfg), serve_workbench(wb_cfg), gw_fut)?;
        }

        Commands::JobRunner { .. } => unreachable!(),
    }

    Ok(())
}
