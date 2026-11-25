use chrono::Utc;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

const MAX_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FILES: usize = 5;

pub struct AuditLog {
    path: Option<PathBuf>,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn record(&self, event: &str, fields: Value) {
        let Some(ref path) = self.path else { return };
        let _g = self.lock.lock().unwrap();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() >= MAX_BYTES {
                for idx in (1..MAX_FILES).rev() {
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
