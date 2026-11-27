use chrono::Utc;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_MAX_FILES: usize = 5;

static GLOBAL_MAX_BYTES: AtomicU64 = AtomicU64::new(DEFAULT_MAX_BYTES);
static GLOBAL_MAX_FILES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_FILES);

pub fn configure_global_audit_limits(max_file_mb: u64, max_files: usize) {
    let bytes = max_file_mb.clamp(1, 100) * 1024 * 1024;
    let files = max_files.clamp(1, 20);
    GLOBAL_MAX_BYTES.store(bytes, Ordering::Relaxed);
    GLOBAL_MAX_FILES.store(files, Ordering::Relaxed);
}

pub fn audit_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub struct AuditLog {
    path: Option<PathBuf>,
    custom_limits: Option<(u64, usize)>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            custom_limits: None,
        }
    }

    pub fn with_limits(path: Option<PathBuf>, max_bytes: u64, max_files: usize) -> Self {
        Self {
            path,
            custom_limits: Some((max_bytes.max(1024 * 1024), max_files.clamp(1, 20))),
        }
    }

    pub fn record(&self, event: &str, fields: Value) {
        let Some(ref path) = self.path else { return };
        let (max_bytes, max_files) = self.custom_limits.unwrap_or_else(|| {
            (
                GLOBAL_MAX_BYTES.load(Ordering::Relaxed),
                GLOBAL_MAX_FILES.load(Ordering::Relaxed),
            )
        });
        let _g = audit_write_lock().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() >= max_bytes {
                for idx in (1..max_files).rev() {
                    let from = PathBuf::from(format!("{}.{idx}", path.display()));
                    let to = PathBuf::from(format!("{}.{}", path.display(), idx + 1));
                    let _ = fs::rename(from, to);
                }
                let _ = fs::rename(path, format!("{}.1", path.display()));
            }
        }
        let mut obj = match fields {
            Value::Object(m) => m,
            other => {
                let mut m = serde_json::Map::new();
                m.insert("detail".into(), other);
                m
            }
        };
        obj.insert("ts".into(), json!(Utc::now().to_rfc3339()));
        obj.insert("event".into(), json!(event));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", Value::Object(obj));
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditMeta {
    pub platform: String,
    pub owner: String,
    pub tool_override: Option<String>,
}

impl AuditMeta {
    pub fn from_header_values(
        platform: Option<&str>,
        owner: Option<&str>,
        tool: Option<&str>,
    ) -> Self {
        Self {
            platform: platform.unwrap_or("").trim().to_string(),
            owner: owner.unwrap_or("").trim().to_string(),
            tool_override: tool
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from),
        }
    }
}

pub fn truncate_single_line(raw: &str, max_chars: usize) -> String {
    let single = raw.replace(['\r', '\n'], " ");
    let trimmed = single.trim();
    if trimmed.chars().count() > max_chars {
        format!("{}...", trimmed.chars().take(max_chars).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

pub fn truncate_chars(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.chars().count() > max_chars {
        format!("{}...", trimmed.chars().take(max_chars).collect::<String>())
    } else {
        trimmed.to_string()
    }
}

pub fn full_target(args: &Value) -> String {
    if let Some(s) = args
        .get("commandLine")
        .or_else(|| args.get("command"))
        .or_else(|| args.get("path"))
        .or_else(|| args.get("source"))
        .or_else(|| args.get("url"))
        .or_else(|| args.get("pattern"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("cwd"))
        .or_else(|| args.get("commandId"))
        .and_then(Value::as_str)
    {
        return truncate_chars(s, 4000);
    }
    if let Some(arr) = args.get("paths").and_then(Value::as_array) {
        let joined: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
        if !joined.is_empty() {
            return truncate_chars(&joined.join("\n"), 4000);
        }
    }
    String::new()
}

pub fn summarize_target(args: &Value) -> String {
    if let Some(s) = args
        .get("path")
        .or_else(|| args.get("commandLine"))
        .or_else(|| args.get("command"))
        .or_else(|| args.get("source"))
        .or_else(|| args.get("url"))
        .or_else(|| args.get("pattern"))
        .or_else(|| args.get("filePath"))
        .or_else(|| args.get("cwd"))
        .or_else(|| args.get("commandId"))
        .and_then(Value::as_str)
    {
        return truncate_single_line(s, 120);
    }
    if let Some(arr) = args.get("paths").and_then(Value::as_array) {
        if let Some(first) = arr.first().and_then(Value::as_str) {
            let summary = if arr.len() > 1 {
                format!("{first} (+{} more)", arr.len() - 1)
            } else {
                first.to_string()
            };
            return truncate_single_line(&summary, 120);
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_common_tool_arguments() {
        assert_eq!(
            summarize_target(&json!({ "path": "D:\\trading-AI\\README.md" })),
            "D:\\trading-AI\\README.md"
        );
        assert_eq!(
            summarize_target(&json!({ "paths": ["a.rs", "b.rs", "c.rs"] })),
            "a.rs (+2 more)"
        );
        assert_eq!(
            summarize_target(&json!({ "command": "git status\n--short" })),
            "git status --short"
        );
        assert_eq!(
            full_target(&json!({ "command": "git status\n--short" })),
            "git status\n--short"
        );
        assert_eq!(
            full_target(&json!({ "paths": ["a.rs", "b.rs"] })),
            "a.rs\nb.rs"
        );
    }

    #[test]
    fn records_jsonl_entries() {
        let dir = std::env::temp_dir().join(format!("rpc-audit-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("local-audit.jsonl");
        let log = AuditLog::new(Some(path.clone()));
        log.record("tool_call", json!({ "tool": "fs_read_file", "lane": "fs" }));
        let content = fs::read_to_string(&path).unwrap();
        let line: Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["event"], "tool_call");
        assert_eq!(line["tool"], "fs_read_file");
        assert!(line["ts"].as_str().is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
