use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AppConfig {
    pub instance_label: String,
    pub language: String,
    pub connection_mode: String,
    pub gateway: GatewayConfig,
    pub guards_and_hooks: GuardsAndHooksConfig,
    pub local_ports: LocalPortsConfig,
    pub tokens: TokensConfig,
    pub allowed_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GatewayConfig {
    pub mode: String,
    pub enable_commands: bool,
    pub enable_chrome: bool,
    pub enable_context_tools: bool,
    pub local_port: u16,
    pub secret: String,
    pub oauth_signing_key: String,
    pub approval_key: String,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            mode: "readwrite".to_string(),
            enable_commands: true,
            enable_chrome: true,
            enable_context_tools: false,
            local_port: 18787,
            secret: String::new(),
            oauth_signing_key: String::new(),
            approval_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GuardsAndHooksConfig {
    pub enable_delete_guard: bool,
    pub enable_tray_notifications: bool,
    pub notify_on_delete_blocked: bool,
    pub notify_on_oauth_authorized: bool,
    pub notify_on_service_error: bool,
    pub notify_on_task_idle_complete: bool,
    pub idle_complete_seconds: u64,
    pub notification_hook_command: String,
    pub vision_backend: String,
    pub gemini_api_key: String,
    pub openai_api_key: String,
}

impl Default for GuardsAndHooksConfig {
    fn default() -> Self {
        Self {
            enable_delete_guard: true,
            enable_tray_notifications: false,
            notify_on_delete_blocked: true,
            notify_on_oauth_authorized: true,
            notify_on_service_error: true,
            notify_on_task_idle_complete: false,
            idle_complete_seconds: 25,
            notification_hook_command: String::new(),
            vision_backend: "auto".to_string(),
            gemini_api_key: String::new(),
            openai_api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LocalPortsConfig {
    pub fs_internal: u16,
    pub fs_bearer: u16,
    pub workbench: u16,
    pub chrome_cdp: u16,
    pub chrome_mcp: u16,
    pub reuse_existing_chrome_mcp: bool,
}

impl Default for LocalPortsConfig {
    fn default() -> Self {
        Self {
            fs_internal: 18848,
            fs_bearer: 18849,
            workbench: 18623,
            chrome_cdp: 9222,
            chrome_mcp: 18619,
            reuse_existing_chrome_mcp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct TokensConfig {
    pub fs_token: String,
    pub workbench_token: String,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let trimmed = raw.trim_start_matches('\u{feff}');
        let cfg: Self = serde_json::from_str(trimmed)
            .with_context(|| format!("failed to parse config JSON: {}", path.display()))?;
        Ok(cfg)
    }
}
