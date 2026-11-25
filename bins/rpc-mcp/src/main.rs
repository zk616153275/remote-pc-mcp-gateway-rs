use anyhow::Result;
use clap::{Parser, Subcommand};
use rpc_mcp_core::config::AppConfig;
use rpc_mcp_core::path_guard::AllowedRoots;
use rpc_mcp_fs::{serve_fs_mcp, FsServerConfig};
use rpc_mcp_workbench::{run_job_runner, serve_workbench, WorkbenchConfig};
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "rpc-mcp",
    version,
    about = "Remote PC MCP Gateway — Rust Core (Phase 1: FS + Workbench + Job Runner)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run unified local Windows agent (FS MCP + AI Workbench in one process)
    Agent {
        /// Optional path to config.local.json
        #[arg(long)]
        config: Option<PathBuf>,

        /// Bind host (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// FS MCP listen port (overrides config)
        #[arg(long)]
        fs_port: Option<u16>,

        /// AI Workbench listen port (overrides config)
        #[arg(long)]
        workbench_port: Option<u16>,

        /// Allowed root directories (can be passed multiple times)
        #[arg(long = "root")]
        roots: Vec<String>,

        /// FS Bearer token
        #[arg(long, env = "REMOTE_LOCAL_FS_MCP_TOKEN")]
        fs_token: Option<String>,

        /// AI Workbench Bearer token
        #[arg(long, env = "AI_WORKBENCH_TOKEN")]
        workbench_token: Option<String>,

        /// State directory for workbench commands/sessions/delete-guard
        #[arg(long, default_value = "state/workbench")]
        workbench_state: PathBuf,

        /// Path to PowerShell 7 executable
        #[arg(long, default_value = "pwsh.exe")]
        pwsh: String,

        /// Disable built-in destructive delete guard
        #[arg(long)]
        disable_delete_guard: bool,
    },

    /// Detached per-command Windows Job Object supervisor (invoked internally by workbench)
    JobRunner {
        /// Command directory containing spec.json
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

    // JobRunner runs detached without logging to stdout/stderr
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
                anyhow::bail!("both fs_token and workbench_token are required (via --config, flags, or env)");
            }

            info!(
                "Starting rpc-mcp agent: fs=:{}, workbench=:{}",
                fs_cfg.port, wb_cfg.port
            );

            tokio::try_join!(serve_fs_mcp(fs_cfg), serve_workbench(wb_cfg))?;
        }
        Commands::JobRunner { .. } => unreachable!(),
    }

    Ok(())
}
