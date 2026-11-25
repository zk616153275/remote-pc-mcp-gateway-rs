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
}

pub fn validate_readonly_git_args(args: &[String]) -> Result<(), GitPolicyError> {
    if args.len() > MAX_GIT_ARGS {
        return Err(GitPolicyError::TooManyArgs);
    }
    for arg in args {
        if arg.contains(['|', '&', ';', '<', '>', '`', '$']) {
            return Err(GitPolicyError::ShellMetachar(arg.clone()));
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
            Err(GitPolicyError::BlockedToken("output".into()))
        );
        assert_eq!(
            validate_readonly_git_args(&["--ext-diff".into()]),
            Err(GitPolicyError::BlockedToken("ext-diff".into()))
        );
        assert!(matches!(
            validate_readonly_git_args(&["HEAD; whoami".into()]),
            Err(GitPolicyError::ShellMetachar(_))
        ));
    }
}
