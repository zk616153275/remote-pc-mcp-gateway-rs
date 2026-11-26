use chrono::Local;
use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

struct TargetSpec {
    exe_stem: &'static str,
    cargo_args: &'static [&'static str],
    restart_hint: &'static str,
}

const GUI_SPEC: TargetSpec = TargetSpec {
    exe_stem: "rpc-mcp-gui",
    cargo_args: &["-p", "rpc-mcp-gui"],
    restart_hint: "请右键右下角托盘图标 -> 点击「重启程序（加载最新版） / Restart App」切换到新版 GUI。",
};

const AGENT_SPEC: TargetSpec = TargetSpec {
    exe_stem: "rpc-mcp",
    cargo_args: &["-p", "rpc-mcp"],
    restart_hint: "如需切换后台服务到新版 rpc-mcp，请重新运行 Start-Agent.ps1。",
};

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

fn extract_target_triple(extra_args: &[String]) -> Option<&str> {
    let mut iter = extra_args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--target" {
            return iter.next().map(String::as_str);
        }
        if let Some(val) = arg.strip_prefix("--target=") {
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn target_dir(root: &Path, release: bool, target_triple: Option<&str>) -> PathBuf {
    let mut base = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    if let Some(triple) = target_triple {
        base = base.join(triple);
    }
    base.join(if release { "release" } else { "debug" })
}

fn is_old_backup_for(file_name: &str, stem: &str) -> bool {
    let legacy = format!("{stem}.old.exe");
    if file_name.eq_ignore_ascii_case(&legacy) {
        return true;
    }
    let prefix = format!("{stem}.");
    file_name.len() > prefix.len() + ".old.exe".len()
        && file_name[..prefix.len()].eq_ignore_ascii_case(&prefix)
        && file_name[file_name.len() - ".old.exe".len()..].eq_ignore_ascii_case(".old.exe")
}

/// Best-effort cleanup of historical `*.old.exe` binaries whose processes have already exited.
fn cleanup_old_backups(dir: &Path, stem: &str) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut cleaned = 0usize;
    let mut still_locked = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !is_old_backup_for(name, stem) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => cleaned += 1,
            Err(_) => still_locked += 1,
        }
    }
    if cleaned > 0 {
        println!("[xtask] 已清理 {cleaned} 个已释放的历史 {stem}.*.old.exe 文件");
    }
    if still_locked > 0 {
        println!(
            "[xtask] 保留 {still_locked} 个仍在运行中的 {stem}.*.old.exe（旧进程或 job-runner 退出后会自动清理）"
        );
    }
}

/// Checks whether an existing `.exe` is currently locked by a running process on Windows.
fn is_exe_locked(exe_path: &Path) -> bool {
    if !exe_path.is_file() {
        return false;
    }
    OpenOptions::new().write(true).open(exe_path).is_err()
}

fn next_backup_path(dir: &Path, stem: &str) -> PathBuf {
    let stamp = Local::now().format("%Y%m%d-%H%M%S");
    let first = dir.join(format!("{stem}.{stamp}.old.exe"));
    if !first.exists() {
        return first;
    }
    for seq in 1..1000 {
        let candidate = dir.join(format!("{stem}.{stamp}-{seq}.old.exe"));
        if !candidate.exists() {
            return candidate;
        }
    }
    dir.join(format!("{stem}.{stamp}-overflow.old.exe"))
}

struct RotationRecord {
    original: PathBuf,
    backup: PathBuf,
}

fn prepare_binary_for_build(dir: &Path, stem: &str) -> Result<Option<RotationRecord>, String> {
    cleanup_old_backups(dir, stem);

    let exe_path = dir.join(format!("{stem}.exe"));
    if !exe_path.is_file() {
        return Ok(None);
    }

    if !is_exe_locked(&exe_path) {
        return Ok(None);
    }

    let backup = next_backup_path(dir, stem);
    fs::rename(&exe_path, &backup).map_err(|e| {
        format!(
            "无法重命名正在运行的 {} -> {}: {e}",
            exe_path.display(),
            backup.display()
        )
    })?;
    println!(
        "[xtask] 检测到 {} 正在运行，已重命名为 {} 以释放覆盖锁",
        exe_path.file_name().unwrap_or_default().to_string_lossy(),
        backup.file_name().unwrap_or_default().to_string_lossy()
    );
    Ok(Some(RotationRecord {
        original: exe_path,
        backup,
    }))
}

fn restore_if_build_failed(rec: &RotationRecord) {
    if !rec.original.exists() && rec.backup.exists() {
        match fs::rename(&rec.backup, &rec.original) {
            Ok(()) => {
                println!(
                    "[xtask] 编译失败，已将 {} 还原为 {}",
                    rec.backup.file_name().unwrap_or_default().to_string_lossy(),
                    rec.original
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                );
            }
            Err(e) => {
                eprintln!(
                    "[xtask] 编译失败且未能自动还原 {}: {e}",
                    rec.original.display()
                );
            }
        }
    }
}

fn run_build(specs: &[TargetSpec], release: bool, extra_args: &[String]) -> ExitCode {
    let root = workspace_root();
    let triple = extract_target_triple(extra_args);
    let out_dir = target_dir(&root, release, triple);

    let mut rotations: Vec<(&TargetSpec, RotationRecord)> = Vec::new();
    for spec in specs {
        match prepare_binary_for_build(&out_dir, spec.exe_stem) {
            Ok(Some(rec)) => rotations.push((spec, rec)),
            Ok(None) => {}
            Err(e) => {
                eprintln!("[xtask] 错误: {e}");
                for (_, prev) in &rotations {
                    restore_if_build_failed(prev);
                }
                return ExitCode::from(1);
            }
        }
    }

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(&cargo);
    cmd.current_dir(&root).arg("build");
    if release {
        cmd.arg("--release");
    }
    for spec in specs {
        cmd.args(spec.cargo_args);
    }
    cmd.args(extra_args);

    println!(
        "[xtask] 执行: {} build{}{}",
        cargo,
        if release { " --release" } else { "" },
        specs
            .iter()
            .flat_map(|s| s.cargo_args.iter())
            .fold(String::new(), |mut acc, a| {
                acc.push(' ');
                acc.push_str(a);
                acc
            })
    );

    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[xtask] 启动 cargo 失败: {e}");
            for (_, rec) in &rotations {
                restore_if_build_failed(rec);
            }
            return ExitCode::from(1);
        }
    };

    if !status.success() {
        for (_, rec) in &rotations {
            restore_if_build_failed(rec);
        }
        let code = status.code().unwrap_or(1) as u8;
        return ExitCode::from(if code == 0 { 1 } else { code });
    }

    println!("[xtask] 编译完成！");
    for (spec, _) in &rotations {
        println!("[xtask] {}", spec.restart_hint);
    }
    ExitCode::SUCCESS
}

fn print_usage() {
    eprintln!("用法:");
    eprintln!("  cargo build-gui [--debug] [-- <额外 cargo 参数>]");
    eprintln!("  cargo build-agent [--debug] [-- <额外 cargo 参数>]");
    eprintln!("  cargo build-all [--debug] [-- <额外 cargo 参数>]");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(subcmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };

    let mut release = true;
    let mut extra_args: Vec<String> = Vec::new();
    let mut passthrough = false;
    for arg in args.iter().skip(1) {
        if passthrough {
            extra_args.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "--" => passthrough = true,
            "--debug" => release = false,
            "--release" => release = true,
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => extra_args.push(other.to_string()),
        }
    }

    match subcmd {
        "build-gui" => run_build(&[GUI_SPEC], release, &extra_args),
        "build-agent" => run_build(&[AGENT_SPEC], release, &extra_args),
        "build-all" => run_build(&[AGENT_SPEC, GUI_SPEC], release, &extra_args),
        _ => {
            eprintln!("[xtask] 未知子命令: {subcmd}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_old_backup_patterns_safely() {
        assert!(is_old_backup_for("rpc-mcp-gui.old.exe", "rpc-mcp-gui"));
        assert!(is_old_backup_for(
            "rpc-mcp-gui.20261126-140530.old.exe",
            "rpc-mcp-gui"
        ));
        assert!(is_old_backup_for(
            "rpc-mcp-gui.20261126-140530-1.old.exe",
            "rpc-mcp-gui"
        ));
        assert!(!is_old_backup_for("rpc-mcp-gui.exe", "rpc-mcp-gui"));
        assert!(!is_old_backup_for("rpc-mcp.20261126-140530.old.exe", "rpc-mcp-gui"));
        assert!(!is_old_backup_for("rpc-mcp-gui.20261126-140530.old.exe", "rpc-mcp"));
    }

    #[test]
    fn extracts_optional_target_triple() {
        let a = vec!["--target".to_string(), "x86_64-pc-windows-gnu".to_string()];
        assert_eq!(extract_target_triple(&a), Some("x86_64-pc-windows-gnu"));
        let b = vec!["--target=x86_64-pc-windows-msvc".to_string()];
        assert_eq!(extract_target_triple(&b), Some("x86_64-pc-windows-msvc"));
        let c = vec!["--locked".to_string()];
        assert_eq!(extract_target_triple(&c), None);
    }
}
