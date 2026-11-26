use regex::Regex;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PathGuardError {
    #[error("path must be a non-empty string")]
    EmptyPath,
    #[error("at least one valid allowed root is required")]
    NoValidRoots,
    #[error("path not within allowed directories: {0}")]
    OutsideAllowedRoots(String),
    #[error("invalid path traversal segment in: {0}")]
    InvalidTraversal(String),
    #[error("I/O error resolving path: {0}")]
    Io(#[from] std::io::Error),
}

/// Strips Windows extended-length verbatim prefix `\\?\` when present.
pub fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

fn is_forbidden_root(raw: &str) -> bool {
    static DRIVE_ROOT_RE: OnceLock<Regex> = OnceLock::new();
    static USER_HOME_RE: OnceLock<Regex> = OnceLock::new();

    let trimmed = raw.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return true;
    }
    let drive_re = DRIVE_ROOT_RE.get_or_init(|| Regex::new(r"(?i)^[A-Z]:$").unwrap());
    let home_re =
        USER_HOME_RE.get_or_init(|| Regex::new(r"(?i)^[A-Z]:[\\/]Users[\\/][^\\/]+$").unwrap());
    drive_re.is_match(trimmed) || home_re.is_match(trimmed) || trimmed == "/"
}

fn normalize_for_compare(path: &Path) -> String {
    let clean = strip_verbatim_prefix(path);
    let mut s = clean.to_string_lossy().replace('\\', "/");
    while s.len() > 1 && !(s.len() == 3 && s.as_bytes()[1] == b':') && s.ends_with('/') {
        s.pop();
    }
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

fn is_under(child: &Path, root: &Path) -> bool {
    let c = normalize_for_compare(child);
    let r = normalize_for_compare(root);
    if c == r {
        return true;
    }
    let prefix = if r.ends_with('/') { r } else { format!("{r}/") };
    c.starts_with(&prefix)
}

/// Resolves a path safely even if the leaf file or intermediate directories do not yet exist:
/// 1. Reject dangling symlinks (checked via `symlink_metadata` so `exists()` cannot be bypassed).
/// 2. Walk up until the nearest existing ancestor is found and `canonicalize` it (blocks symlink escape).
/// 3. Lexically normalize remaining segments (rejecting any `..` escaping above the ancestor).
pub fn resolve_existing_or_new(target: &Path) -> Result<PathBuf, PathGuardError> {
    let abs = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()?.join(target)
    };

    if let Ok(meta) = fs::symlink_metadata(&abs) {
        if meta.file_type().is_symlink() && !abs.exists() {
            return Err(PathGuardError::OutsideAllowedRoots(
                target.display().to_string(),
            ));
        }
        return Ok(strip_verbatim_prefix(&fs::canonicalize(&abs)?));
    }

    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = abs.as_path();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() && !cursor.exists() {
                    return Err(PathGuardError::OutsideAllowedRoots(
                        target.display().to_string(),
                    ));
                }
                break;
            }
            Err(_) => {
                let Some(name) = cursor.file_name() else {
                    return Err(PathGuardError::OutsideAllowedRoots(
                        target.display().to_string(),
                    ));
                };
                pending.push(name.to_os_string());
                cursor = match cursor.parent() {
                    Some(p) => p,
                    None => {
                        return Err(PathGuardError::OutsideAllowedRoots(
                            target.display().to_string(),
                        ));
                    }
                };
            }
        }
    }

    let mut resolved = strip_verbatim_prefix(&fs::canonicalize(cursor)?);
    pending.reverse();
    for seg in pending {
        let seg_path = Path::new(&seg);
        for comp in seg_path.components() {
            match comp {
                Component::Normal(c) => resolved.push(c),
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(PathGuardError::InvalidTraversal(
                        target.display().to_string(),
                    ));
                }
            }
        }
    }
    Ok(resolved)
}

#[derive(Debug, Clone)]
pub struct AllowedRoots {
    roots: Vec<PathBuf>,
}

impl AllowedRoots {
    pub fn new<I, S>(raw_roots: I) -> Result<Self, PathGuardError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut valid = Vec::new();
        for item in raw_roots {
            let s = item.as_ref().trim();
            if s.is_empty() || is_forbidden_root(s) {
                continue;
            }
            let p = PathBuf::from(s);
            if let Ok(meta) = fs::metadata(&p) {
                if meta.is_dir() {
                    if let Ok(canon) = fs::canonicalize(&p) {
                        valid.push(strip_verbatim_prefix(&canon));
                    }
                }
            }
        }
        if valid.is_empty() {
            return Err(PathGuardError::NoValidRoots);
        }
        Ok(Self { roots: valid })
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Validates an existing or not-yet-created path is strictly inside one of the allowed roots.
    pub fn validate(&self, raw_target: &str) -> Result<PathBuf, PathGuardError> {
        let trimmed = raw_target.trim();
        if trimmed.is_empty() {
            return Err(PathGuardError::EmptyPath);
        }
        // Reject raw `..` components before ancestor resolution on non-existent paths
        let candidate = Path::new(trimmed);
        let resolved = resolve_existing_or_new(candidate)?;
        if self.roots.iter().any(|root| is_under(&resolved, root)) {
            Ok(resolved)
        } else {
            Err(PathGuardError::OutsideAllowedRoots(trimmed.to_string()))
        }
    }
}

/// Pure lexical Windows/cross-platform path normalization + prefix validation.
/// Safe to run on a remote Linux VPS where Windows paths do not exist locally.
pub fn validate_workspace_path_lexical(
    candidate: &str,
    allowed_roots: &[String],
) -> Result<String, PathGuardError> {
    let raw = candidate.trim();
    if raw.is_empty() {
        return Err(PathGuardError::EmptyPath);
    }
    fn lex_norm(p: &str) -> Result<String, PathGuardError> {
        let unified = p.trim().replace('/', r"\");
        let mut parts: Vec<&str> = Vec::new();
        for seg in unified.split('\\') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                if parts.len() <= 1 {
                    return Err(PathGuardError::InvalidTraversal(p.to_string()));
                }
                parts.pop();
            } else {
                parts.push(seg);
            }
        }
        Ok(parts.join(r"\").to_lowercase())
    }

    let norm_cand = lex_norm(raw)?;
    let ok = allowed_roots.iter().any(|root| {
        if let Ok(norm_root) = lex_norm(root) {
            if norm_root.is_empty() {
                return false;
            }
            norm_cand == norm_root || norm_cand.starts_with(&format!(r"{norm_root}\"))
        } else {
            false
        }
    });
    if ok {
        Ok(raw.to_string())
    } else {
        Err(PathGuardError::OutsideAllowedRoots(raw.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_drive_and_user_home_roots() {
        assert!(is_forbidden_root(r"C:\"));
        assert!(is_forbidden_root(r"D:"));
        assert!(is_forbidden_root(r"C:\Users\Alice"));
        assert!(is_forbidden_root(r"C:\Users\Alice\"));
        assert!(!is_forbidden_root(r"C:\Users\Alice\Projects"));
    }

    #[test]
    fn validates_existing_and_new_files_and_blocks_escape() {
        let base = std::env::temp_dir().join(format!("rmcp-pg-{}", uuid::Uuid::new_v4()));
        let sub = base.join("workspace");
        fs::create_dir_all(&sub).unwrap();

        let guard = AllowedRoots::new([sub.to_string_lossy().to_string()]).unwrap();

        // Existing dir
        assert!(guard.validate(&sub.to_string_lossy()).is_ok());

        // Not-yet-created nested file
        let new_file = sub.join("nested").join("new.txt");
        let checked = guard.validate(&new_file.to_string_lossy()).unwrap();
        assert!(checked.ends_with(Path::new("nested").join("new.txt")));

        // Escape via ..
        let escaped = sub.join("..").join("outside.txt");
        assert!(guard.validate(&escaped.to_string_lossy()).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn is_under_works_for_posix_and_windows_paths() {
        assert!(is_under(
            Path::new("/tmp/workspace/a/b.txt"),
            Path::new("/tmp/workspace")
        ));
        assert!(!is_under(
            Path::new("/tmp/workspace2/a.txt"),
            Path::new("/tmp/workspace")
        ));
        assert!(is_under(
            Path::new(r"D:\ws\sub\file.rs"),
            Path::new(r"D:\ws")
        ));
        assert!(!is_under(Path::new(r"D:\ws2\file.rs"), Path::new(r"D:\ws")));
    }
}
