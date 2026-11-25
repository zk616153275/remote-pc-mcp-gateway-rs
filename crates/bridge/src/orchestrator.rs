use anyhow::Result;
use chrono::Utc;
use rpc_mcp_core::write_atomic_string;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealth {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub updated_at: String,
    pub mode: String,
    pub public_origin: String,
    pub mcp_url: String,
    pub fs_mcp: ServiceHealth,
    pub workbench: ServiceHealth,
    pub gateway: ServiceHealth,
    pub chrome_mcp: ServiceHealth,
}

pub fn write_runtime_status(path: &Path, status: &RuntimeStatus) -> Result<()> {
    let mut s = status.clone();
    s.updated_at = Utc::now().to_rfc3339();
    let json = serde_json::to_string_pretty(&s)?;
    write_atomic_string(path, &json)?;
    Ok(())
}

pub async fn dispatch_notification_hook(target: &str, payload: &Value) -> bool {
    let target = target.trim();
    if target.is_empty() {
        return false;
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build();
        if let Ok(c) = client {
            return c
                .post(target)
                .json(payload)
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
        }
        return false;
    }
    false
}
