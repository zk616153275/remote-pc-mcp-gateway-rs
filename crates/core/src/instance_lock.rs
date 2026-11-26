use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::json;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Exclusive process lock backed by an OS file lock.
/// On Windows, `share_mode(0)` prevents any second process from opening the file
/// and the kernel automatically releases the lock if the holder crashes or exits.
pub struct InstanceLock {
    _file: File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn try_acquire(path: &Path, role: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut opts = OpenOptions::new();
        opts.create(true).read(true).write(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.share_mode(0);
        }

        let mut file = opts.open(path).map_err(|_| {
            anyhow!(
                "Another rpc-mcp instance is already running (lock held: {})",
                path.display()
            )
        })?;

        let _ = file.set_len(0);
        let meta = json!({
            "pid": std::process::id(),
            "role": role,
            "acquiredAt": Utc::now().to_rfc3339(),
        });
        let _ = writeln!(file, "{meta}");
        let _ = file.flush();

        Ok(Self {
            _file: file,
            path: path.to_path_buf(),
        })
    }

    pub fn is_locked(path: &Path) -> bool {
        if !path.exists() {
            return false;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(path)
                .is_err()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_exclusive_lock_while_held() {
        let dir = std::env::temp_dir().join(format!("rpc-lock-test-{}", uuid::Uuid::new_v4()));
        let lock_path = dir.join("agent.lock");

        let lock = InstanceLock::try_acquire(&lock_path, "test").unwrap();
        #[cfg(windows)]
        {
            assert!(InstanceLock::is_locked(&lock_path));
            assert!(InstanceLock::try_acquire(&lock_path, "test-2").is_err());
        }
        drop(lock);

        let lock2 = InstanceLock::try_acquire(&lock_path, "test-3").unwrap();
        drop(lock2);
        let _ = fs::remove_dir_all(&dir);
    }
}
