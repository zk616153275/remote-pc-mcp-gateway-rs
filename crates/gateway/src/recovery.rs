use rpc_mcp_core::write_atomic_string;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SEC: u64 = 1800;

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub status: String, // "running" | "completed" | "failed"
    pub created: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

pub struct TaskJournal {
    dir: Option<PathBuf>,
    tasks: Mutex<HashMap<String, TaskRecord>>,
}

impl TaskJournal {
    pub fn new(dir: Option<PathBuf>) -> Self {
        let mut tasks = HashMap::new();
        if let Some(ref d) = dir {
            let _ = fs::create_dir_all(d);
            let now = now_sec();
            if let Ok(rd) = fs::read_dir(d) {
                for entry in rd.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(raw) = fs::read_to_string(&path) {
                        if let Ok(rec) = serde_json::from_str::<TaskRecord>(&raw) {
                            if now.saturating_sub(rec.created) <= TTL_SEC {
                                tasks.insert(rec.id.clone(), rec);
                            } else {
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }
        Self {
            dir,
            tasks: Mutex::new(tasks),
        }
    }

    fn persist(&self, rec: &TaskRecord) {
        if let Some(ref d) = self.dir {
            if let Ok(json) = serde_json::to_string(rec) {
                let _ = write_atomic_string(&d.join(format!("{}.json", rec.id)), &json);
            }
        }
    }

    pub fn record_running(&self, id: String, owner: String, name: String) {
        let rec = TaskRecord {
            id: id.clone(),
            owner,
            name,
            status: "running".into(),
            created: now_sec(),
            finished: None,
            result: None,
        };
        self.persist(&rec);
        self.tasks.lock().unwrap().insert(id, rec);
    }

    pub fn record_finished(&self, id: &str, result: Value) {
        let mut map = self.tasks.lock().unwrap();
        if let Some(rec) = map.get_mut(id) {
            rec.status = "completed".into();
            rec.finished = Some(now_sec());
            rec.result = Some(result);
            self.persist(rec);
        }
    }

    pub fn get(&self, id: &str, owner: &str) -> Option<TaskRecord> {
        let map = self.tasks.lock().unwrap();
        map.get(id).filter(|r| r.owner == owner).cloned()
    }
}

pub fn wait_tool_definition() -> Value {
    json!({
        "name": "wait",
        "description": "Wait for an existing running/recovering tool task, then continue the original user task. Always use the returned task_id; never resubmit an active mutation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": { "type": "string", "maxLength": 80 },
                "wait_ms": { "type": "integer", "minimum": 100, "maximum": 20000 }
            },
            "additionalProperties": false
        },
        "annotations": { "readOnlyHint": true, "destructiveHint": false }
    })
}
