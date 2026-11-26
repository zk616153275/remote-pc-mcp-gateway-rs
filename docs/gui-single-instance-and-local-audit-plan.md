# Remote PC MCP Gateway — GUI Dashboard, Single-Instance Management, and Audit Architecture

## 1. Overview and Objectives

This document details the architectural design and implementation for the Tauri v2 desktop console (`rpc-mcp-gui`), single-instance lifecycle management, and the distributed execution audit event pipeline.

### Core Goals

1. **Dashboard Visibility**: Display the active public access topology directly on the Dashboard (e.g., `VPS · SSH -R`, `Cloudflare Quick`, `Cloudflare Named`, or `Local Debug Only`), including tunnel targets, active port assignments, and health metrics.
2. **Single-Instance Enforcement & Seamless Backend Attachment**:
   - Ensure only a single GUI instance runs on the desktop. Launching the GUI again automatically focuses the existing window or tray instance.
   - Maintain at most one local backend stack (`rpc-mcp agent` or `rpc-mcp up`).
   - When an existing backend is already running, launching the GUI automatically probes and attaches to it, displaying runtime state and AI activity without port conflict errors.
3. **Execution Audit Event Stream**:
   - Deliver real-time command execution events to the GUI even in VPS-hosted gateway mode.
   - Record local execution events (`local-audit.jsonl`) across `fs-mcp`, `workbench`, and `chrome-broker`, while passing caller metadata headers (`X-MCP-Platform`, `X-MCP-Tool`, `X-MCP-Owner`).
   - Prevent duplicate event counting across modes while ensuring zero data loss and minimal disk/CPU overhead.

---

## 2. Architecture & Design

### 2.1 Single-Instance Mutex & Event Mechanism

- On Windows, a Win32 Named Mutex (`Global\rpc-mcp-gui-instance-mutex`) and a Named Event (`Global\rpc-mcp-gui-wake-event`) regulate instance concurrency.
- If the mutex is held, the secondary process signals the wake event and exits immediately.
- A background worker in the primary instance waits on `WaitForSingleObject` for wake notifications and triggers window restoration from the system tray.

### 2.2 Background Service Attachment (Attach Mode)

When the GUI starts up:
1. It probes the health endpoints for the local agent ports (`18849` for FS MCP, `18623` for Workbench).
2. If both respond affirmatively, the GUI enters **Attached Mode**:
   - It skips spawning a new internal backend.
   - It reads `state/runtime-status.json` and begins polling `state/logs/local-audit.jsonl`.
   - The status panel indicates `Attached (External Service)` with the external process PID and endpoint details.
3. If endpoints are inactive, the GUI enters **Self-Managed Mode**, launching internal tasks and managing their lifecycles directly.

### 2.3 Distributed Audit Event Pipeline

To ensure the GUI displays accurate AI command execution logs across all deployments:
- **Local Execution Node (`local-audit.jsonl`)**: Written directly by local worker crates (`fs-mcp`, `workbench`, `chrome-broker`) for every executed tool or command. High-frequency polling requests are filtered out.
- **Gateway Node (`gateway-audit.jsonl`)**: Written by `crates/gateway` during public MCP requests and OAuth authorization events.
- **Deduplication Strategy**: When running in All-in-One or Local mode, the GUI prioritizes the unified gateway audit log. When running in VPS mode (where the gateway executes remotely), the GUI reads `local-audit.jsonl` to ensure all local operations remain visible.

---

## 3. Hot-Build & Binary Rotation via `xtask`

On Windows, active running executables are locked by the operating system, preventing overwrite during development builds.

The `xtask` tool resolves this through atomic binary rotation:
1. `cargo build-gui` or `cargo build-agent` invokes `xtask`.
2. If the target executable is currently running, `xtask` renames the active executable to a timestamped backup (`<binary>.<timestamp>.old.exe`).
3. The new binary is compiled cleanly to the standard path.
4. Old `.old.exe` files are automatically cleaned up on the next build cycle once handles are released.
5. In the desktop GUI, selecting **"Restart App"** from the system tray releases the running instance's lock and seamlessly boots the updated executable.
