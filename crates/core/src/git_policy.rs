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
];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GitPolicyError {
    #[error("blocked mutating git token: {0}")]
    BlockedToken(String),
}

pub fn validate_readonly_git_args(args: &[String]) -> Result<(), GitPolicyError> {
    for arg in args {
        let lower = arg.trim().to_ascii_lowercase();
        if BLOCKED_GIT_TOKENS.contains(&lower.as_str()) {
            return Err(GitPolicyError::BlockedToken(lower));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_readonly_and_blocks_mutating_git_args() {
        assert!(validate_readonly_git_args(&["-n".into(), "10".into(), "--oneline".into()]).is_ok());
        assert_eq!(
            validate_readonly_git_args(&["reset".into(), "--hard".into()]),
            Err(GitPolicyError::BlockedToken("reset".into()))
        );
    }
}
