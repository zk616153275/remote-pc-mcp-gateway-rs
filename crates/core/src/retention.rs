use crate::audit::audit_write_lock;
use crate::config::RetentionConfig;
use chrono::{DateTime, Duration as ChronoDuration, Local, NaiveDateTime, TimeZone, Utc};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const MAX_ROTATED_SCAN: usize = 20;
const MAX_AUX_ROTATED: usize = 2;

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageUsage {
    pub audit_bytes: u64,
    pub audit_files: usize,
    pub workbench_commands_bytes: u64,
    pub workbench_commands_count: usize,
    pub workbench_meta_bytes: u64,
    pub workbench_meta_files: usize,
    pub aux_logs_bytes: u64,
    pub aux_logs_files: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupReport {
    pub freed_bytes: u64,
    pub audit_files_removed: usize,
    pub audit_lines_trimmed: usize,
    pub workbench_commands_removed: usize,
    pub workbench_meta_removed: usize,
    pub aux_files_trimmed: usize,
    pub old_binaries_removed: usize,
    pub skipped_active_audit: bool,
}

fn dir_size_bytes(path: &Path) -> u64 {
    let Ok(meta) = fs::metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    let mut total = 0u64;
    if let Ok(rd) = fs::read_dir(path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total = total.saturating_add(dir_size_bytes(&p));
            } else if let Ok(m) = entry.metadata() {
                total = total.saturating_add(m.len());
            }
        }
    }
    total
}

#[cfg(windows)]
fn is_command_locked(cmd_dir: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    let lock_path = cmd_dir.join("owner.lock");
    if !lock_path.exists() {
        return false;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&lock_path)
        .is_err()
}

#[cfg(not(windows))]
fn is_command_locked(_cmd_dir: &Path) -> bool {
    false
}

fn is_audit_filename(name: &str) -> bool {
    name == "local-audit.jsonl"
        || name == "gateway-audit.jsonl"
        || name.starts_with("local-audit.jsonl.")
        || name.starts_with("gateway-audit.jsonl.")
}

pub fn inspect_storage_usage(state_root: &Path) -> StorageUsage {
    let mut u = StorageUsage::default();

    // 1. Logs directory (audit logs vs aux logs like agent.log*)
    let logs_dir = state_root.join("logs");
    if let Ok(rd) = fs::read_dir(&logs_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = entry.file_name().to_string_lossy().to_string();
            if is_audit_filename(&name) {
                u.audit_bytes = u.audit_bytes.saturating_add(len);
                u.audit_files += 1;
            } else {
                u.aux_logs_bytes = u.aux_logs_bytes.saturating_add(len);
                u.aux_logs_files += 1;
            }
        }
    }

    // 2. Workbench commands
    let wb_root = state_root.join("workbench");
    if let Ok(rd) = fs::read_dir(wb_root.join("commands")) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                u.workbench_commands_bytes = u
                    .workbench_commands_bytes
                    .saturating_add(dir_size_bytes(&p));
                u.workbench_commands_count += 1;
            }
        }
    }

    // 3. Workbench sessions, contexts, tasks
    for sub in ["sessions", "contexts", "tasks"] {
        if let Ok(rd) = fs::read_dir(wb_root.join(sub)) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    u.workbench_meta_bytes = u.workbench_meta_bytes.saturating_add(len);
                    u.workbench_meta_files += 1;
                }
            }
        }
    }

    // 4. Delete guard logs & gateway-tasks
    if let Ok(rd) = fs::read_dir(wb_root.join("delete-guard")) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("delete-guard.log") {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    u.aux_logs_bytes = u.aux_logs_bytes.saturating_add(len);
                    u.aux_logs_files += 1;
                }
            }
        }
    }
    if let Ok(rd) = fs::read_dir(state_root.join("gateway-tasks")) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_file() {
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                u.aux_logs_bytes = u.aux_logs_bytes.saturating_add(len);
                u.aux_logs_files += 1;
            }
        }
    }

    u.total_bytes = u
        .audit_bytes
        .saturating_add(u.workbench_commands_bytes)
        .saturating_add(u.workbench_meta_bytes)
        .saturating_add(u.aux_logs_bytes);
    u
}

fn replace_file_safely(tmp: &Path, target: &Path) -> std::io::Result<()> {
    for attempt in 0..4 {
        match fs::rename(tmp, target) {
            Ok(()) => return Ok(()),
            Err(_) if attempt < 3 => {
                std::thread::sleep(Duration::from_millis(25 * (attempt + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn trim_active_audit_jsonl(path: &Path, cutoff_utc: DateTime<Utc>) -> Option<(usize, u64)> {
    let _g = audit_write_lock().lock().unwrap_or_else(|e| e.into_inner());
    let orig_len = fs::metadata(path).ok()?.len();
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let tmp_path = path.with_extension(format!("jsonl.prune.{}.tmp", std::process::id()));
    let tmp_file = File::create(&tmp_path).ok()?;
    let mut writer = BufWriter::new(tmp_file);

    let mut trimmed = 0usize;
    let mut kept = 0usize;

    for line_res in reader.lines() {
        let Ok(line) = line_res else {
            continue;
        };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let expired = serde_json::from_str::<Value>(t)
            .ok()
            .and_then(|v| v.get("ts").and_then(Value::as_str).map(String::from))
            .and_then(|ts| DateTime::parse_from_rfc3339(&ts).ok())
            .map(|dt| dt.with_timezone(&Utc) < cutoff_utc)
            .unwrap_or(false);

        if expired {
            trimmed += 1;
        } else {
            let _ = writeln!(writer, "{line}");
            kept += 1;
        }
    }

    let _ = writer.flush();
    drop(writer);

    if trimmed == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Some((0, 0));
    }

    let new_len = fs::metadata(&tmp_path).map(|m| m.len()).unwrap_or(orig_len);
    if replace_file_safely(&tmp_path, path).is_ok() {
        let _ = kept;
        Some((trimmed, orig_len.saturating_sub(new_len)))
    } else {
        let _ = fs::remove_file(&tmp_path);
        None
    }
}

fn cleanup_audit_base(
    base: &Path,
    cfg: &RetentionConfig,
    now_sys: SystemTime,
    cutoff_utc: Option<DateTime<Utc>>,
    allow_active_log_trim: bool,
    report: &mut CleanupReport,
) {
    // 1. Prune rotated archives (.1 .. .20) beyond max_files or older than retention_days
    let max_age = if cfg.audit_retention_days > 0 {
        Some(Duration::from_secs(
            u64::from(cfg.audit_retention_days) * 86_400,
        ))
    } else {
        None
    };

    for idx in 1..=MAX_ROTATED_SCAN {
        let p = PathBuf::from(format!("{}.{idx}", base.display()));
        if !p.is_file() {
            continue;
        }
        let excess = idx > cfg.audit_max_files;
        let expired = max_age
            .map(|age| {
                fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .map(|t| now_sys.duration_since(t).unwrap_or_default() > age)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if excess || expired {
            let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(&p).is_ok() {
                report.audit_files_removed += 1;
                report.freed_bytes = report.freed_bytes.saturating_add(len);
            }
        }
    }

    // 2. Trim expired lines in the active JSONL file (only when safe)
    if let Some(cutoff) = cutoff_utc {
        if base.is_file() {
            if allow_active_log_trim {
                if let Some((trimmed, freed)) = trim_active_audit_jsonl(base, cutoff) {
                    report.audit_lines_trimmed += trimmed;
                    report.freed_bytes = report.freed_bytes.saturating_add(freed);
                } else {
                    report.skipped_active_audit = true;
                }
            } else {
                report.skipped_active_audit = true;
            }
        }
    }
}

fn trim_delete_guard_log(path: &Path, cutoff_local: DateTime<Local>) -> Option<(usize, u64)> {
    let orig_len = fs::metadata(path).ok()?.len();
    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);

    let tmp_path = path.with_extension(format!("log.prune.{}.tmp", std::process::id()));
    let tmp_file = File::create(&tmp_path).ok()?;
    let mut writer = BufWriter::new(tmp_file);

    let mut trimmed = 0usize;
    for line_res in reader.lines() {
        let Ok(line) = line_res else {
            continue;
        };
        let mut parts = line.split_whitespace();
        let d = parts.next().unwrap_or("");
        let t = parts.next().unwrap_or("");
        let expired = if d.len() == 10 && t.len() >= 8 {
            NaiveDateTime::parse_from_str(&format!("{d} {}", &t[..8]), "%Y-%m-%d %H:%M:%S")
                .ok()
                .and_then(|naive| Local.from_local_datetime(&naive).earliest())
                .map(|dt| dt < cutoff_local)
                .unwrap_or(false)
        } else {
            false
        };
        if expired {
            trimmed += 1;
        } else {
            let _ = writeln!(writer, "{line}");
        }
    }
    let _ = writer.flush();
    drop(writer);

    if trimmed == 0 {
        let _ = fs::remove_file(&tmp_path);
        return Some((0, 0));
    }

    let new_len = fs::metadata(&tmp_path).map(|m| m.len()).unwrap_or(orig_len);
    if replace_file_safely(&tmp_path, path).is_ok() {
        Some((trimmed, orig_len.saturating_sub(new_len)))
    } else {
        let _ = fs::remove_file(&tmp_path);
        None
    }
}

fn rotate_or_prune_aux_log(
    path: &Path,
    max_bytes: u64,
    max_age: Option<Duration>,
    now_sys: SystemTime,
    allow_active_rotate: bool,
    report: &mut CleanupReport,
) {
    // Prune excess/expired rotated backups
    for idx in 1..=MAX_ROTATED_SCAN {
        let p = PathBuf::from(format!("{}.{idx}", path.display()));
        if !p.is_file() {
            continue;
        }
        let excess = idx > MAX_AUX_ROTATED;
        let expired = max_age
            .map(|age| {
                fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .map(|t| now_sys.duration_since(t).unwrap_or_default() > age)
                    .unwrap_or(false)
            })
            .unwrap_or(false);
        if excess || expired {
            let len = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if fs::remove_file(&p).is_ok() {
                report.aux_files_trimmed += 1;
                report.freed_bytes = report.freed_bytes.saturating_add(len);
            }
        }
    }

    // Rotate active aux log if it exceeds max_bytes
    if allow_active_rotate && path.is_file() {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() >= max_bytes {
                for idx in (1..MAX_AUX_ROTATED).rev() {
                    let from = PathBuf::from(format!("{}.{idx}", path.display()));
                    let to = PathBuf::from(format!("{}.{}", path.display(), idx + 1));
                    let _ = fs::rename(from, to);
                }
                if fs::rename(path, format!("{}.1", path.display())).is_ok() {
                    report.aux_files_trimmed += 1;
                }
            }
        }
    }
}

pub fn cleanup_workbench_storage(
    wb_root: &Path,
    retention_days: u32,
    max_total_mb: u64,
) -> (usize, usize, u64) {
    let max_age = Duration::from_secs(u64::from(retention_days.max(1)) * 86_400);
    let max_bytes = max_total_mb.max(10) * 1024 * 1024;
    let now = SystemTime::now();

    let mut commands_removed = 0usize;
    let mut meta_removed = 0usize;
    let mut freed_bytes = 0u64;

    // 1. Commands: age-based cleanup, then disk-budget oldest-first eviction
    let mut survivors: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    if let Ok(rd) = fs::read_dir(wb_root.join("commands")) {
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_dir() || is_command_locked(&path) {
                continue;
            }
            let mtime = fs::metadata(&path)
                .and_then(|m| m.modified())
                .unwrap_or(now);
            let sz = dir_size_bytes(&path);
            let old = now.duration_since(mtime).unwrap_or_default() > max_age;
            if old {
                if fs::remove_dir_all(&path).is_ok() {
                    commands_removed += 1;
                    freed_bytes = freed_bytes.saturating_add(sz);
                }
            } else {
                survivors.push((path, mtime, sz));
            }
        }
    }

    let mut total_cmd_bytes: u64 = survivors.iter().map(|(_, _, sz)| *sz).sum();
    if total_cmd_bytes > max_bytes {
        // Evict oldest first until within budget
        survivors.sort_by_key(|(_, mtime, _)| *mtime);
        for (path, _, sz) in survivors {
            if total_cmd_bytes <= max_bytes {
                break;
            }
            if is_command_locked(&path) {
                continue;
            }
            if fs::remove_dir_all(&path).is_ok() {
                commands_removed += 1;
                freed_bytes = freed_bytes.saturating_add(sz);
                total_cmd_bytes = total_cmd_bytes.saturating_sub(sz);
            }
        }
    }

    // 2. Sessions, contexts, tasks
    for sub in ["sessions", "contexts", "tasks"] {
        if let Ok(rd) = fs::read_dir(wb_root.join(sub)) {
            for entry in rd.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let meta = match fs::metadata(&path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let old = meta
                    .modified()
                    .map(|t| now.duration_since(t).unwrap_or_default() > max_age)
                    .unwrap_or(false);
                if old && fs::remove_file(&path).is_ok() {
                    meta_removed += 1;
                    freed_bytes = freed_bytes.saturating_add(meta.len());
                }
            }
        }
    }

    (commands_removed, meta_removed, freed_bytes)
}

pub fn run_retention_cleanup(
    state_root: &Path,
    repo_root: Option<&Path>,
    cfg: &RetentionConfig,
    allow_active_log_trim: bool,
) -> CleanupReport {
    let cfg = cfg.sanitized();
    let mut report = CleanupReport::default();
    let now_sys = SystemTime::now();
    let cutoff_utc = if cfg.audit_retention_days > 0 {
        Some(Utc::now() - ChronoDuration::days(i64::from(cfg.audit_retention_days)))
    } else {
        None
    };
    let cutoff_local = if cfg.audit_retention_days > 0 {
        Some(Local::now() - ChronoDuration::days(i64::from(cfg.audit_retention_days)))
    } else {
        None
    };
    let aux_max_age = if cfg.audit_retention_days > 0 {
        Some(Duration::from_secs(
            u64::from(cfg.audit_retention_days) * 86_400,
        ))
    } else {
        None
    };
    let aux_max_bytes = cfg.aux_log_max_mb * 1024 * 1024;

    // 1. Audit logs
    let logs_dir = state_root.join("logs");
    cleanup_audit_base(
        &logs_dir.join("local-audit.jsonl"),
        &cfg,
        now_sys,
        cutoff_utc,
        allow_active_log_trim,
        &mut report,
    );
    cleanup_audit_base(
        &logs_dir.join("gateway-audit.jsonl"),
        &cfg,
        now_sys,
        cutoff_utc,
        allow_active_log_trim,
        &mut report,
    );

    // 2. Workbench commands & metadata
    let wb_root = state_root.join("workbench");
    let (cmd_rm, meta_rm, wb_freed) = cleanup_workbench_storage(
        &wb_root,
        cfg.workbench_retention_days,
        cfg.workbench_max_total_mb,
    );
    report.workbench_commands_removed = cmd_rm;
    report.workbench_meta_removed = meta_rm;
    report.freed_bytes = report.freed_bytes.saturating_add(wb_freed);

    // 3. Delete guard log & agent log
    let dg_log = wb_root.join("delete-guard").join("delete-guard.log");
    if allow_active_log_trim {
        if let Some(cl) = cutoff_local {
            if dg_log.is_file() {
                if let Some((trimmed, freed)) = trim_delete_guard_log(&dg_log, cl) {
                    if trimmed > 0 {
                        report.aux_files_trimmed += 1;
                        report.freed_bytes = report.freed_bytes.saturating_add(freed);
                    }
                }
            }
        }
    }
    rotate_or_prune_aux_log(
        &dg_log,
        aux_max_bytes,
        aux_max_age,
        now_sys,
        allow_active_log_trim,
        &mut report,
    );
    rotate_or_prune_aux_log(
        &logs_dir.join("agent.log"),
        aux_max_bytes,
        aux_max_age,
        now_sys,
        allow_active_log_trim,
        &mut report,
    );

    // 4. Clean unlocked hot-build *.old.exe files in target/release
    if let Some(repo) = repo_root {
        let rel = repo.join("target").join("release");
        if let Ok(rd) = fs::read_dir(&rel) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("rpc-mcp") && name.ends_with(".old.exe") {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    if fs::remove_file(&p).is_ok() {
                        report.old_binaries_removed += 1;
                        report.freed_bytes = report.freed_bytes.saturating_add(len);
                    }
                }
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_expired_audit_lines_and_excess_rotated_files() {
        let dir = std::env::temp_dir().join(format!("rpc-ret-test-{}", uuid::Uuid::new_v4()));
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();

        let active = logs.join("local-audit.jsonl");
        let old_ts = (Utc::now() - ChronoDuration::days(45)).to_rfc3339();
        let new_ts = Utc::now().to_rfc3339();
        fs::write(
            &active,
            format!(
                r#"{{"event":"tool_call","tool":"old","ts":"{old_ts}"}}
{{"event":"tool_call","tool":"fresh","ts":"{new_ts}"}}
"#
            ),
        )
        .unwrap();

        // Create excess rotated file .6 when max_files = 3
        fs::write(logs.join("local-audit.jsonl.4"), "archive4").unwrap();
        fs::write(logs.join("local-audit.jsonl.6"), "archive6").unwrap();

        let cfg = RetentionConfig {
            audit_retention_days: 30,
            audit_max_files: 3,
            ..Default::default()
        };

        let usage_before = inspect_storage_usage(&dir);
        assert_eq!(usage_before.audit_files, 3);
        assert!(usage_before.total_bytes > 0);

        let rep = run_retention_cleanup(&dir, None, &cfg, true);
        assert_eq!(rep.audit_files_removed, 2);
        assert_eq!(rep.audit_lines_trimmed, 1);
        assert!(!rep.skipped_active_audit);

        let remaining = fs::read_to_string(&active).unwrap();
        assert!(!remaining.contains("\"old\""));
        assert!(remaining.contains("\"fresh\""));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skips_active_audit_trim_when_disallowed() {
        let dir = std::env::temp_dir().join(format!("rpc-ret-skip-{}", uuid::Uuid::new_v4()));
        let logs = dir.join("logs");
        fs::create_dir_all(&logs).unwrap();
        let active = logs.join("local-audit.jsonl");
        let old_ts = (Utc::now() - ChronoDuration::days(45)).to_rfc3339();
        fs::write(
            &active,
            format!(r#"{{"event":"tool_call","ts":"{old_ts}"}}"#),
        )
        .unwrap();

        let cfg = RetentionConfig::default();
        let rep = run_retention_cleanup(&dir, None, &cfg, false);
        assert!(rep.skipped_active_audit);
        assert_eq!(rep.audit_lines_trimmed, 0);

        let _ = fs::remove_dir_all(&dir);
    }
}
