# Remote PC MCP Gateway

A high-performance, secure Remote PC Model Context Protocol (MCP) Gateway implemented in Rust. It provides a single-binary multi-subcommand core, streamable HTTP MCP gateway with OAuth 2.1 authorization, Win32 Job Object lifecycle supervision, and a native desktop GUI console.

For in-depth architectural and implementation details, see [`docs/architecture-design.md`](./docs/architecture-design.md).

---

## Architecture & Features

- **Single-Binary Core (`rpc-mcp`)**: Multi-subcommand CLI unifying filesystem operations, command execution workbench, aggregation gateway, and bridge tunnels in a single lightweight binary (<15 MB).
- **Streamable HTTP Gateway**: Aggregates downstream MCP servers behind an authenticated streamable HTTP endpoint (`/<secret>/mcp`), with OAuth 2.1 + PKCE (`S256`) + DCR, platform-specific protection (e.g., Gemini image block safety), and 5-lane concurrency isolation.
- **Sandboxed Execution Workbench**: Win32 Job Object process supervision (`rpc-mcp job-runner`) ensuring automatic cleanup of child processes without orphaned tasks, coupled with path guards (`AllowedRoots`), two-stage destructive operation confirmation (`DeleteGuard`), and read-only Git execution policies.
- **Built-in Fast Filesystem MCP**: 18 filesystem tools powered by embedded ripgrep (`ignore`, `grep-searcher`, `grep-regex`) with an 8 MiB response budget guard and structured audit logging.
- **Tunnels & Bridge**: Built-in Cloudflare Tunnel management (with automatic bypass for Clash/Mihomo `198.18.0.0/15` Fake-IP ranges) and resilient OpenSSH `-R` reverse tunnel supervision with auto-reconnect backoff.
- **Native Desktop GUI (`apps/gui`)**: Tauri v2 desktop console and system tray with zero Node frontend build dependencies. Features single-instance auto-wake, seamless background attach, live AI command activity streaming, and automatic WebView2 memory release on window close.
- **Optional Chrome DevTools Broker**: On-demand sidecar manager for `chrome-devtools-mcp` with Job Object lifecycle supervision and `select_page` isolation.

---

## Workspace Structure

```text
remote-pc-mcp-gateway-rs/
├── apps/
│   └── gui/                  # Tauri v2 native desktop console & system tray
├── bins/
│   └── rpc-mcp/              # Unified multi-subcommand CLI entry point
├── crates/
│   ├── bridge/               # Cloudflare & SSH reverse tunnel orchestration
│   ├── chrome-broker/        # On-demand Chrome DevTools MCP sidecar manager
│   ├── core/                 # Config, security path guards, instance lock & audit log
│   ├── fs-mcp/               # 18 FS tools with embedded ripgrep search & budget limits
│   ├── gateway/              # Streamable HTTP MCP gateway, OAuth 2.1 & lane isolation
│   └── workbench/            # Command execution workbench & Win32 Job Object supervisor
├── deploy/                   # Cross-platform build and deployment scripts
├── docs/                     # Architecture and technical design documentation
└── xtask/                    # Rust build assistant for hot-reloading & binary rotation
```

---

## Quick Build & Testing

### Prerequisites

- [Rust](https://rustup.rs/) (1.78+ recommended, 2021 edition)
- (Windows GUI) Microsoft Visual C++ Build Tools & WebView2 runtime (pre-installed on Windows 10/11)

### Building & Testing

```powershell
# Run all workspace unit and integration tests
cargo test --workspace

# Hot-build the desktop GUI console (rotates running rpc-mcp-gui.exe to avoid file locks)
cargo build-gui

# Build the release CLI binary (target\release\rpc-mcp.exe)
cargo build-agent

# Build all release binaries (CLI + GUI)
cargo build-all
```

> **Hot-Reload Workflow**: While developing, run `cargo build-gui`. Then right-click the system tray icon and select **"Restart App"**. The running process will cleanly hand off its single-instance lock and release ports/tunnels before the new build boots up.

---

## Operational Scripts

Preconfigured launcher scripts for Windows:

```powershell
# Start background Windows Agent and SSH reverse tunnel (VPS mode)
.\Start-Agent.bat

# Gracefully stop background agent and active tunnels
.\Stop-Agent.bat

# Launch the desktop GUI console (attaches to any running background instance automatically)
.\Start-GUI.bat
```

---

## CLI Subcommand Reference

```powershell
# 1. Windows Execution Agent (FS MCP :18849 + Workbench :18623)
.\target\release\rpc-mcp.exe agent --config .\config\config.local.json

# 2. Standalone Public OAuth 2.1 MCP Gateway (Windows or Linux VPS)
.\target\release\rpc-mcp.exe gateway --config .\config\config.local.json

# 3. All-in-One Mode (Unified FS + Workbench + Gateway + optional Cloudflare Tunnel)
.\target\release\rpc-mcp.exe up --config .\config\config.local.json --cloudflared .\tools\cloudflared.exe

# 4. Chrome DevTools MCP Sidecar Proxy
.\target\release\rpc-mcp.exe chrome-broker --port 18619 --cdp-port 9222
```

---

## Security Model

1. **Path Guards (`AllowedRoots`)**: Strictly confines file operations to authorized workspace directories.
2. **Destructive Guard (`DeleteGuard`)**: Prohibits recursive deletions or broad wildcard removals without explicit two-step confirmation.
3. **Read-Only Git Policy**: Intercepts destructive git actions (e.g., `git reset --hard`, `git push --force`) in automated sessions.
4. **OAuth 2.1 + PKCE**: Enforces standard cryptographic code exchanges for public endpoints, with rate limiting and replay defense.
5. **Job Object Isolation**: Enforces `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` on spawned process trees to guarantee zero orphaned background tasks.

---

## License

This project is licensed under the [MIT License](LICENSE).
