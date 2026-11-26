use thiserror::Error;

pub const BLOCKED_GIT_TOKENS: &[&str] = &[
    "commit",
    "clean",
    "checkout",
    "merge",
    "rebase",
    "reset",
    "restore",
    "push",
    "pull",
    "fetch",
    "branch",
    "tag",
    "worktree",
    "output",
    "ext-diff",
    "textconv",
    "exec",
    "upload-pack",
    "receive-pack",
    "no-index",
    "exclude-from",
    "exclude-per-directory",
    "git-dir",
    "work-tree",
    "c",
];

pub const MAX_GIT_ARGS: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GitPolicyError {
    #[error("git args must have at most {MAX_GIT_ARGS} items")]
    TooManyArgs,
    #[error("blocked mutating git token: {0}")]
    BlockedToken(String),
    #[error("shell metacharacters are not allowed in git args: {0}")]
    ShellMetachar(String),
    #[error("absolute or traversal paths are not allowed in git args: {0}")]
    UnsafePath(String),
}

fn is_unsafe_git_path_arg(arg: &str) -> bool {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Check value portion if this is a `--flag=value` option
    let (flag_opt, candidate) = match trimmed.split_once('=') {
        Some((k, v)) if k.starts_with('-') => (
            Some(k.trim_start_matches('-').to_ascii_lowercase()),
            v.trim(),
        ),
        _ => (None, trimmed),
    };
    let is_text_flag = matches!(
        flag_opt.as_deref(),
        Some(
            "grep"
                | "format"
                | "pretty"
                | "author"
                | "committer"
                | "since"
                | "until"
                | "after"
                | "before"
                | "date"
        )
    );
    let bytes = candidate.as_bytes();
    // Windows drive path (e.g. C:\... or C:/...) or UNC path (\\server\...)
    if (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/'))
        || candidate.starts_with(r"\\")
        || (!is_text_flag && candidate.starts_with('/'))
    {
        return true;
    }
    // Path traversal segments (note: git revision ranges like HEAD~3..HEAD are allowed)
    if candidate == ".."
        || candidate.starts_with("../")
        || candidate.starts_with(r"..\")
        || candidate.contains("/../")
        || candidate.contains(r"\..\")
        || candidate.ends_with("/..")
        || candidate.ends_with(r"\..")
    {
        return true;
    }
    false
}

pub fn validate_readonly_git_args(args: &[String]) -> Result<(), GitPolicyError> {
    if args.len() > MAX_GIT_ARGS {
        return Err(GitPolicyError::TooManyArgs);
    }
    for arg in args {
        if arg.contains(['|', '&', ';', '<', '>', '`', '$']) {
            return Err(GitPolicyError::ShellMetachar(arg.clone()));
        }
        if is_unsafe_git_path_arg(arg) {
            return Err(GitPolicyError::UnsafePath(arg.clone()));
        }
        let normalized = arg
            .trim()
            .trim_start_matches('-')
            .split('=')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if BLOCKED_GIT_TOKENS.contains(&normalized.as_str()) {
            return Err(GitPolicyError::BlockedToken(normalized));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_readonly_and_blocks_mutating_or_metachar_git_args() {
        assert!(validate_readonly_git_args(&["-n".into(), "10".into(), "--oneline".into()]).is_ok());
        assert!(validate_readonly_git_args(&["--grep=/api/v1".into(), "--format=%H/%s".into()]).is_ok());
        assert!(validate_readonly_git_args(&["HEAD~3..HEAD".into(), "--".into(), "src/main.rs".into()]).is_ok());
        assert_eq!(
            validate_readonly_git_args(&["reset".into(), "--hard".into()]),
            Err(GitPolicyError::BlockedToken("reset".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--branch=main".into()]),
            Err(GitPolicyError::BlockedToken("branch".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--output=C:\\evil.txt".into()]),
            Err(GitPolicyError::UnsafePath("--output=C:\\evil.txt".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--output=evil.txt".into()]),
            Err(GitPolicyError::BlockedToken("output".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--no-index".into(), "a.txt".into(), "b.txt".into()]),
            Err(GitPolicyError::BlockedToken("no-index".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--ext-diff".into()]),
            Err(GitPolicyError::BlockedToken("ext-diff".into()))
        );
        assert!(matches!(
            validate_readonly_git_args(&["C:\\Windows\\win.ini".into()]),
            Err(GitPolicyError::UnsafePath(_))
        ));
        assert!(matches!(
            validate_readonly_git_args(&["../secret.txt".into()]),
            Err(GitPolicyError::UnsafePath(_))
        ));
        assert!(matches!(
            validate_readonly_git_args(&["HEAD; whoami".into()]),
            Err(GitPolicyError::ShellMetachar(_))
        ));
    }
}
