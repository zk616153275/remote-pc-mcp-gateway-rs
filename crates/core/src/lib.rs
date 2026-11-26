pub mod audit;
pub mod config;
pub mod delete_guard;
pub mod git_policy;
pub mod instance_lock;
pub mod path_guard;

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static ATOMIC_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Atomically writes UTF-8 text to `target` using a sibling temp file + rename
/// with brief retry on Windows sharing violations.
pub fn write_atomic_string(target: &Path, content: &str) -> io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let seq = ATOMIC_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = target.with_extension(format!(
        "{}.{}.{}.tmp",
        target
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("file"),
        std::process::id(),
        seq
    ));
    fs::write(&tmp, content.as_bytes())?;
    for attempt in 0..5 {
        match fs::rename(&tmp, target) {
            Ok(()) => return Ok(()),
            Err(err) if attempt < 4 => {
                let _ = err;
                std::thread::sleep(std::time::Duration::from_millis(25 * (attempt + 1)));
            }
            Err(_) => {
                fs::copy(&tmp, target)?;
                let _ = fs::remove_file(&tmp);
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Constant-time equality check for bearer tokens and secrets.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let ba = a.as_bytes();
    let bb = b.as_bytes();
    if ba.is_empty() || ba.len() != bb.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in ba.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extracts a Bearer token from an HTTP Authorization header (RFC 9110 case-insensitive scheme).
pub fn extract_bearer_token(header_val: &str) -> Option<&str> {
    let trimmed = header_val.trim();
    if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        let token = trimmed[7..].trim();
        if !token.is_empty() {
            return Some(token);
        }
    }
    None
}
