# Remote PC MCP Gateway — Architecture and System Design

## 1. Overview & System Goals

**Remote PC MCP Gateway** is a secure, high-performance bridge connecting cloud AI agent platforms (such as Google Gemini and OpenAI ChatGPT) to local development and execution environments via the Model Context Protocol (MCP).

Implemented in Rust, the gateway unifies filesystem operations, sandboxed command execution, upstream protocol aggregation, tunnel management, and a native desktop GUI console into a single, cohesive architecture.

### Key Architectural Metrics

| Metric | Target | Design Rationale |
| :--- | :--- | :--- |
| **Resident Processes** | 2–4 processes | On-demand detached `job-runner` workers; optional Chrome sidecar on demand |
| **Idle Memory Footprint** | < 40 MB | Pure Rust runtime, zero Node.js/PowerShell daemon overhead for core components |
| **Distribution Footprint** | ~15 MB executable | Single standalone binary; optional `cloudflared.exe` bundled for tunnel transport |
| **Linux VPS Gateway** | Pure static binary | Static `musl` build with zero external runtime dependencies (`scp` and run) |

---

## 2. Cargo Workspace Architecture

The system is organized as a Cargo workspace centered around a unified multi-subcommand binary (`rpc-mcp`):

```text
remote-pc-mcp-gateway-rs/
├── Cargo.toml                      # Workspace root configuration
├── docs/                           # Architecture and design specifications
├── crates/
│   ├── core/                       # Shared configuration, path guards, locks & audit log
│   ├── fs-mcp/                     # 18 FS tools with embedded ripgrep and size budget guard
│   ├── workbench/                  # Command execution workbench with Win32 Job Object runner
│   ├── gateway/                    # Streamable HTTP MCP gateway, OAuth 2.1/PKCE/DCR & lanes
│   ├── bridge/                     # Tunnel supervisor (Cloudflare Fake-IP bypass & SSH -R)
│   └── chrome-broker/              # Chrome DevTools MCP broker with session isolation
├── apps/
│   └── gui/                        # Tauri v2 native desktop console & system tray
├── bins/
│   └── rpc-mcp/                    # Unified multi-subcommand CLI binary
└── xtask/                          # Build assistant for binary hot-swapping and rotation
```

### CLI Subcommands (`rpc-mcp`)

- `rpc-mcp agent`: Runs the local execution agent on Windows (`fs-mcp` on port 18849, `workbench` on port 18623, plus optional Chrome broker).
- `rpc-mcp gateway`: Standalone public MCP aggregation gateway (supported on Windows and Linux VPS via static `musl` compilation).
- `rpc-mcp up` (All-in-One): Single-process execution hosting `gateway`, `fs-mcp`, `workbench`, and tunnel orchestration with dynamic OAuth issuer updates.
- `rpc-mcp job-runner <command-dir>`: Ultra-lightweight detached child process spawned by `workbench` to own and supervise the Win32 Job Object for a specific command execution tree.

---

## 3. Technology Stack

| Domain | Component / Crate | Rationale |
| :--- | :--- | :--- |
| **MCP Protocol Stack** | Native `axum 0.8` Streamable HTTP / JSON-RPC 2.0 | Lightweight Streamable HTTP server & SSE transport without heavy framework overhead |
| **Async & Networking** | `tokio 1` + `axum 0.8` + `reqwest 0.12` (`rustls-tls`) | Full `rustls` dependency chain; zero OpenSSL / MSVC linkage issues, ideal for cross-compilation |
| **Windows Process Tree** | `windows-sys 0.61` | Direct Win32 Job Object, IP Helper (`GetExtendedTcpTable`), and process snapshot APIs |
| **Embedded File Search** | `ignore 0.4` + `grep-searcher 0.1` + `grep-regex 0.1` | Native ripgrep libraries integrated in-process, avoiding child process startup latency |
| **Read-Only Git Policy** | Built-in `git_policy` token parser + system `git.exe` | Strict command token allowlist/blocklist preventing destructive operations |
| **Desktop GUI** | **Tauri v2** (native WebView2 + Rust backend) | Lightweight UI with IME support, single-instance mutex, and WebView2 destruction on minimize to tray |

---

## 4. Module Specifications

### 4.1 Filesystem MCP (`crates/fs-mcp`)

- **Protocol Endpoints**:
  - `POST/GET/DELETE /mcp`: Streamable HTTP MCP endpoint requiring `Authorization: Bearer <fsToken>`.
  - `GET /healthz`: Health inspection endpoint returning `{ ok, upstream, detail }`.
- **18 Standard Tools**:
  - *Read Operations (13)*: `list_allowed_directories`, `list_directory`, `list_directory_with_sizes`, `directory_tree`, `directory_tree_limited`, `search_files`, `grep_files`, `read_file`, `read_text_file`, `read_multiple_files`, `read_media_file`, `read_file_lines`, `get_file_info`.
  - *Write Operations (5)*: `write_file`, `edit_file` (unified diff replacement), `edit_file_at_line`, `create_directory`, `move_file`.
- **Path Security (`AllowedRoots`)**:
  - Disallows filesystem root (`C:\`) and user profiles (`C:\Users\<user>`) as unrestricted targets.
  - Resolves non-existent targets by canonicalizing the nearest existing ancestor, stripping Windows extended-length prefix (`\\?\`), lexically normalizing path segments, and verifying case-insensitive root prefixes.
- **Search & Budget Guards**:
  - Hard limit of 8 MiB per response (`FS_RESPONSE_TOO_LARGE`).
  - Search executed in `spawn_blocking` with standard ignore rules (`.git`, `node_modules`, `target`, `dist`).

### 4.2 Command Workbench (`crates/workbench`)

- **Decoupled Job Supervision**:
  - Command execution is detached via `rpc-mcp job-runner <dir>` (`CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW`).
  - The job-runner holds the Win32 Job Object handle with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
  - If the main service restarts or updates, active jobs continue uninterrupted and automatically re-attach via atomic state files (`owner.lock`, `spec.json`, `status.json`, `output.jsonl`).
- **Endpoints**:
  - `POST /mcp` & `DELETE /mcp`: Exposes `run_command`, `get_task_status`, `get_command_output`, `stop_command`, `complete_review`.
  - `POST /hook`: Binds context IDs and verifies review requirements.
  - `POST /panel`, `POST /prune`, `GET /healthz`.
- **Embedded Delete Guard**:
  - Intercepts destructive wildcard removals (`rm -rf`, `Remove-Item -Recurse`, `git reset --hard`).
  - Enforces a 10-minute SHA-256 fingerprint approval window before destructive actions are allowed.

### 4.3 Aggregation Gateway (`crates/gateway`)

- **Endpoints & Protocol**:
  - `POST/GET/DELETE /<secret>/mcp`: Streamable HTTP gateway endpoint with secret path protection.
  - `GET /.well-known/oauth-protected-resource` (RFC 9728) & `GET /.well-known/oauth-authorization-server` (RFC 8414).
  - `POST /oauth/register` (RFC 7591 Dynamic Client Registration), `/oauth/authorize` (PKCE `S256` + approval verification), `/oauth/token`.
  - Dynamic `oauth_issuer` hot-update via `Arc<RwLock<String>>` for dynamic tunnel domains.
- **Platform-Specific Adaptations**:
  - Google Gemini: Hides `fs_read_media_file` to prevent image payload stripping; exposes `inspect_image` vision tool.
  - Concurrency Lanes: 5 separate semaphores (`fs: 20`, `discovery: 8`, `git: 8`, `chrome: 8`, `cmd: 6`) preventing resource starvation.
- **Vision Proxy (`inspect_image`)**:
  - Pure Rust image downscaling (2048px / 3 MiB) and validation using the `image` crate.

### 4.4 Tunnel Bridge (`crates/bridge`)

- **Cloudflare Tunnel**:
  - Automated DNS resolution for `region1.v2.argotunnel.com`.
  - Automatic fallback to QUIC / direct IP when encountering Clash/Mihomo `198.18.0.0/15` Fake-IP pools.
- **OpenSSH Reverse Tunnel (`-R`)**:
  - Managed child process bound to Job Object to eliminate zombie connections.
  - Supervisor with auto-reconnect backoff (1s to 30s) and state broadcast.

### 4.5 Chrome Broker (`crates/chrome-broker`)

- Manages upstream `chrome-devtools-mcp` sidecar on demand.
- Governed by Win32 Job Object to guarantee process tree cleanup.
- Session-level page namespace isolation and navigation safety timeouts.

---

## 5. Security & Isolation Model

1. **Path Containment (`AllowedRoots`)**: Restricts all disk I/O to explicitly registered project directories.
2. **Destructive Command Gate (`DeleteGuard`)**: Blocks unreviewed high-risk shell commands.
3. **Read-Only Git Enforcement**: Allows query operations while blocking repository-altering commands.
4. **OAuth 2.1 & PKCE**: Cryptographically verified authorization codes with SHA-256 challenges and strict redirect URIs.
5. **Job Object Isolation**: Enforces process tree lifecycle boundaries, preventing orphaned child processes.

---

## 6. Build and Verification Strategy

- **Windows Build**:
  - Toolchain: `stable-x86_64-pc-windows-gnu` or `msvc`.
  - Compile with `cargo build --release` (or `cargo build-all` via `xtask`).
- **Linux VPS Build**:
  - Compile static binary with target `x86_64-unknown-linux-musl`:
    ```bash
    cargo build --package rpc-mcp --no-default-features --features gateway --target x86_64-unknown-linux-musl --release
    ```
- **Automated Tests**:
  - `cargo test --workspace` covers core security rules, path canonicalization, OAuth token lifecycle, and end-to-end integration flows.
