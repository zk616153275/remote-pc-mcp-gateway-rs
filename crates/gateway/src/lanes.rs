use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct ServiceLanes {
    lanes: HashMap<&'static str, (Arc<Semaphore>, usize)>,
}

impl ServiceLanes {
    pub fn default_lanes() -> Self {
        let mut lanes = HashMap::new();
        for (name, limit) in [
            ("fs", 20usize),
            ("discovery", 8),
            ("git", 8),
            ("chrome", 8),
            ("cmd", 6),
            ("wait", 32),
        ] {
            lanes.insert(name, (Arc::new(Semaphore::new(limit)), limit));
        }
        Self { lanes }
    }

    pub fn lane_for_tool(name: &str) -> &'static str {
        if name == "wait" {
            "wait"
        } else if name.starts_with("chrome_") {
            "chrome"
        } else if name.starts_with("git_") {
            "git"
        } else if matches!(
            name,
            "run_command"
                | "inspect_image"
                | "workbench_status"
                | "workbench_stop"
                | "workbench_review"
        ) {
            "cmd"
        } else if matches!(
            name,
            "fs_directory_tree" | "fs_directory_tree_limited" | "fs_search_files" | "fs_grep_files"
        ) {
            "discovery"
        } else {
            "fs"
        }
    }

    pub async fn acquire(&self, lane: &str) -> Result<OwnedSemaphorePermit, String> {
        let sem = self
            .lanes
            .get(lane)
            .or_else(|| self.lanes.get("fs"))
            .map(|(s, _)| Arc::clone(s))
            .unwrap();
        sem.acquire_owned()
            .await
            .map_err(|_| "gateway concurrency lane closed".to_string())
    }

    pub fn stats(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (&name, (sem, limit)) in &self.lanes {
            let active = limit.saturating_sub(sem.available_permits());
            map.insert(
                name.to_string(),
                json!({ "active": active, "limit": limit }),
            );
        }
        Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_tools_to_expected_lanes() {
        assert_eq!(ServiceLanes::lane_for_tool("wait"), "wait");
        assert_eq!(ServiceLanes::lane_for_tool("fs_grep_files"), "discovery");
        assert_eq!(
            ServiceLanes::lane_for_tool("fs_directory_tree"),
            "discovery"
        );
        assert_eq!(ServiceLanes::lane_for_tool("fs_read_file"), "fs");
        assert_eq!(ServiceLanes::lane_for_tool("workbench_status"), "cmd");
        assert_eq!(ServiceLanes::lane_for_tool("run_command"), "cmd");
        assert_eq!(ServiceLanes::lane_for_tool("git_status"), "git");
        assert_eq!(ServiceLanes::lane_for_tool("chrome_list_pages"), "chrome");
    }
}
