use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
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
    pub cloudflare: CloudflareConfig,
    pub vps: VpsConfig,
    pub local_ports: LocalPortsConfig,
    pub tokens: TokensConfig,
    pub allowed_roots: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CloudflareConfig {
    pub mode: String,
    pub named_tunnel_token: String,
    pub public_hostname: String,
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            mode: "quick".to_string(),
            named_tunnel_token: String::new(),
            public_hostname: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VpsConfig {
    pub host: String,
    pub ssh_port: u16,
    pub user: String,
    pub domain: String,
    pub ssh_key_path: String,
    pub remote_fs_port: u16,
    pub remote_chrome_mcp_port: u16,
    pub remote_workbench_port: u16,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl Default for VpsConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            ssh_port: 22,
            user: "root".to_string(),
            domain: String::new(),
            ssh_key_path: String::new(),
            remote_fs_port: 27618,
            remote_chrome_mcp_port: 27619,
            remote_workbench_port: 27623,
            extra: HashMap::new(),
        }
    }
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
    pub chrome_token: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_cloudflare_vps_and_extra_fields_on_roundtrip() {
        let raw = r#"{
            "instanceLabel": "My-PC",
            "connectionMode": "vps",
            "cloudflare": { "mode": "named", "namedTunnelToken": "tok-cf", "publicHostname": "mcp.example.com" },
            "vps": { "host": "203.0.113.10", "sshPort": 2222, "user": "root", "destRoot": "/opt/isolated" },
            "customFlag": 42
        }"#;
        let cfg: AppConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.cloudflare.mode, "named");
        assert_eq!(cfg.cloudflare.named_tunnel_token, "tok-cf");
        assert_eq!(cfg.vps.host, "203.0.113.10");
        assert_eq!(cfg.vps.ssh_port, 2222);
        assert_eq!(
            cfg.vps.extra.get("destRoot").and_then(Value::as_str),
            Some("/opt/isolated")
        );
        assert_eq!(
            cfg.extra.get("customFlag").and_then(Value::as_i64),
            Some(42)
        );
    }
}
