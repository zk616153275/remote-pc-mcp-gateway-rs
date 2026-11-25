use crate::write_atomic_string;
use chrono::{Local, Utc};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const TTL_SECONDS: i64 = 600;

fn state_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct Rule {
    regex: Regex,
    label: &'static str,
}

fn danger_rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"(?i)\brm\s+(?:-[a-z]*\s+)*-{1,2}[a-z]*r[a-z]*\b", "rm -r/-rf"),
            (r"(?i)\brm\s+-[a-z]*f[a-z]*r[a-z]*\b", "rm -fr"),
            (r"(?i)\b(?:Remove-Item|ri|del|erase)\b[^\r\n|;]*-(?:Recurse|Force|r|fo)\b", "Remove-Item -Recurse/-Force"),
            (r"(?i)\brmdir\s+/s\b", "rmdir /s"),
            (r"(?i)\brd\s+/s\b", "rd /s"),
            (r"(?i)\bdel\s+/[sq]\b", "del /s|/q"),
            (r"(?i)\[System\.IO\.Directory\]::Delete", "Directory::Delete"),
            (r"(?i)shutil\.rmtree", "shutil.rmtree"),
            (r"(?i)git\s+(?:-C\s+\S+\s+)?reset\s+--hard", "git reset --hard"),
            (r"(?i)git\s+(?:-C\s+\S+\s+)?clean\s+-[a-z]*f", "git clean -f"),
            (r"(?i)git\s+(?:-C\s+\S+\s+)?restore\b", "git restore"),
            (r"(?i)git\s+(?:-C\s+\S+\s+)?checkout\s+--\s", "git checkout -- "),
        ]
        .into_iter()
        .map(|(pat, label)| Rule {
            regex: Regex::new(pat).expect("valid delete-guard regex"),
            label,
        })
        .collect()
    })
}

fn bulk_rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        [
            (r"(?i)-SkipLast\b", "-SkipLast"),
            (r"(?i)Get-ChildItem[^\r\n]*\|[^\r\n]*Remove-Item", "Get-ChildItem | Remove-Item"),
            (r"(?i)Sort-Object[^\r\n]*\|[^\r\n]*Remove-Item", "Sort-Object | Remove-Item"),
            (r"\*", "Wildcard *"),
        ]
        .into_iter()
        .map(|(pat, label)| Rule {
            regex: Regex::new(pat).expect("valid bulk regex"),
            label,
        })
        .collect()
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    AllowConfirmedOnce { fingerprint: String, matched: Vec<String> },
    BlockFirstAttempt { fingerprint: String, matched: Vec<String>, message: String },
}

#[derive(Debug, Clone)]
pub struct DeleteGuard {
    state_dir: PathBuf,
    enabled: bool,
}

impl DeleteGuard {
    pub fn new(state_dir: PathBuf, enabled: bool) -> Self {
        Self { state_dir, enabled }
    }

    pub fn fingerprint(command: &str, cwd: &Path) -> String {
        let normalized_cmd = command.trim().replace("\r\n", "\n");
        let normalized_cwd = cwd
            .to_string_lossy()
            .trim()
            .replace('/', r"\")
            .trim_end_matches('\\')
            .to_lowercase();
        let mut hasher = Sha256::new();
        hasher.update(normalized_cwd.as_bytes());
        hasher.update(b"\0");
        hasher.update(normalized_cmd.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }

    fn log_path(&self) -> PathBuf {
        self.state_dir.join("delete-guard.log")
    }

    fn append_log(&self, line: &str) {
        let _ = fs::create_dir_all(&self.state_dir);
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_path())
        {
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
            let _ = writeln!(file, "{ts}  [rust-workbench] {line}");
        }
    }

    fn load_state(&self, now: i64) -> HashMap<String, f64> {
        let path = self.state_path();
        let Ok(raw) = fs::read_to_string(&path) else {
            return HashMap::new();
        };
        let Ok(map) = serde_json::from_str::<HashMap<String, f64>>(&raw) else {
            return HashMap::new();
        };
        map.into_iter()
            .filter(|(_, ts)| (now as f64 - *ts) < TTL_SECONDS as f64)
            .collect()
    }

    fn save_state(&self, map: &HashMap<String, f64>) {
        if let Ok(json) = serde_json::to_string_pretty(map) {
            let _ = write_atomic_string(&self.state_path(), &json);
        }
    }

    pub fn check(&self, command: &str, cwd: &Path) -> GuardDecision {
        if !self.enabled {
            return GuardDecision::Allow;
        }
        let mut matched: Vec<String> = danger_rules()
            .iter()
            .filter(|r| r.regex.is_match(command))
            .map(|r| r.label.to_string())
            .collect();
        if matched.is_empty() {
            return GuardDecision::Allow;
        }
        for br in bulk_rules() {
            if br.regex.is_match(command) {
                matched.push(br.label.to_string());
            }
        }

        let fp = Self::fingerprint(command, cwd);
        let now = Utc::now().timestamp();
        let _guard = state_lock().lock().unwrap_or_else(|e| e.into_inner());
        let mut state = self.load_state(now);

        if state.remove(&fp).is_some() {
            self.save_state(&state);
            self.append_log(&format!(
                "ALLOW-CONFIRMED fp={} matched=[{}] cwd={}",
                &fp[..12],
                matched.join(", "),
                cwd.display()
            ));
            return GuardDecision::AllowConfirmedOnce {
                fingerprint: fp,
                matched,
            };
        }

        state.insert(fp.clone(), now as f64);
        self.save_state(&state);
        self.append_log(&format!(
            "BLOCK-FIRST fp={} matched=[{}] cwd={}",
            &fp[..12],
            matched.join(", "),
            cwd.display()
        ));

        let msg = format!(
            "[DELETE_GUARD_BLOCKED] Destructive command intercepted on first attempt (matched: {}). \
             Verify the target path (cwd: {}) and resend the EXACT same command within 10 minutes to execute once.",
            matched.join(", "),
            cwd.display()
        );
        GuardDecision::BlockFirstAttempt {
            fingerprint: fp,
            matched,
            message: msg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_first_destructive_command_and_allows_exact_retry() {
        let dir = std::env::temp_dir().join(format!("rmcp-dg-{}", uuid::Uuid::new_v4()));
        let guard = DeleteGuard::new(dir.clone(), true);
        let cwd = Path::new(r"D:\workspace");

        assert_eq!(guard.check("Get-ChildItem", cwd), GuardDecision::Allow);

        let first = guard.check("rm -rf ./dist", cwd);
        assert!(matches!(first, GuardDecision::BlockFirstAttempt { .. }));

        // Different cwd must NOT reuse confirmation from the first directory
        let other_cwd = Path::new(r"D:\other-workspace");
        let diff_dir = guard.check("rm -rf ./dist", other_cwd);
        assert!(matches!(diff_dir, GuardDecision::BlockFirstAttempt { .. }));

        let second = guard.check("rm -rf ./dist", cwd);
        assert!(matches!(second, GuardDecision::AllowConfirmedOnce { .. }));

        // Consumed after one execution; a 3rd attempt blocks again
        let third = guard.check("rm -rf ./dist", cwd);
        assert!(matches!(third, GuardDecision::BlockFirstAttempt { .. }));

        // PowerShell alias ri -Recurse is also blocked
        let ps_alias = guard.check("ri -Recurse -Force ./tmp", cwd);
        assert!(matches!(ps_alias, GuardDecision::BlockFirstAttempt { .. }));

        let _ = fs::remove_dir_all(&dir);
    }
}
