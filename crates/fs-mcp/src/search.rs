use globset::{Glob, GlobSetBuilder};
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, Sink, SinkContext, SinkMatch};
use ignore::WalkBuilder;
use serde::Serialize;
use std::collections::HashSet;
use std::io;
use std::path::Path;

pub const DEFAULT_EXCLUDES: &[&str] = &[
    "node_modules",
    ".git",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    "out",
    "bin",
    "target",
    ".vite",
    ".turbo",
    ".godot",
    "__pycache__",
    ".pytest_cache",
    ".system_generated",
    "antigravity-browser-profile",
];

pub const MAX_OUTPUT_CHARS: usize = 60_000;

pub fn truncate_output(text: String, note: Option<&str>) -> String {
    if text.chars().count() <= MAX_OUTPUT_CHARS {
        return text;
    }
    let suffix = match note {
        Some(n) if !n.is_empty() => format!("\n... [truncated at {MAX_OUTPUT_CHARS} chars; {n}]"),
        _ => format!("\n... [truncated at {MAX_OUTPUT_CHARS} chars]"),
    };
    let keep = MAX_OUTPUT_CHARS.saturating_sub(suffix.chars().count());
    let mut out: String = text.chars().take(keep).collect();
    out.push_str(&suffix);
    out
}

pub fn grep_files_sync(
    root: &Path,
    pattern: &str,
    is_regex: bool,
    globs: &[String],
    context: usize,
    max_results: usize,
) -> Result<String, String> {
    let context = context.min(6);
    let max_results = max_results.clamp(1, 400);

    let matcher = RegexMatcherBuilder::new()
        .fixed_strings(!is_regex)
        .case_smart(true)
        .build(pattern)
        .map_err(|e| format!("invalid search pattern: {e}"))?;

    let glob_set = if globs.is_empty() {
        None
    } else {
        let mut builder = GlobSetBuilder::new();
        for g in globs {
            if let Ok(glob) = Glob::new(g) {
                builder.add(glob);
            }
        }
        builder.build().ok()
    };

    let excludes: HashSet<&str> = DEFAULT_EXCLUDES.iter().copied().collect();
    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if let Some(name) = entry.file_name().to_str() {
                if excludes.contains(name) {
                    return false;
                }
            }
            true
        });

    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(b'\x00'))
        .line_number(true)
        .before_context(context)
        .after_context(context)
        .build();

    let mut out_lines: Vec<String> = Vec::new();
    let mut total_matches: usize = 0;
    let mut truncated = false;

    for entry in walker.build().flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        if let Some(ref gs) = glob_set {
            let rel = path.strip_prefix(root).unwrap_or(path);
            let name_match = path.file_name().map(|n| gs.is_match(n)).unwrap_or(false);
            if !gs.is_match(rel) && !name_match {
                continue;
            }
        }

        struct ContextSink<'a> {
            file_lines: &'a mut Vec<String>,
            total_matches: &'a mut usize,
            max_results: usize,
            truncated: &'a mut bool,
        }

        impl<'a> Sink for ContextSink<'a> {
            type Error = io::Error;

            fn matched(&mut self, _searcher: &Searcher, mat: &SinkMatch<'_>) -> Result<bool, Self::Error> {
                *self.total_matches += 1;
                let lnum = mat.line_number().unwrap_or(0);
                let line = String::from_utf8_lossy(mat.bytes());
                self.file_lines
                    .push(format!("{}:{}", lnum, line.trim_end_matches(['\r', '\n'])));
                if *self.total_matches >= self.max_results {
                    *self.truncated = true;
                    return Ok(false);
                }
                Ok(true)
            }

            fn context(&mut self, _searcher: &Searcher, ctx: &SinkContext<'_>) -> Result<bool, Self::Error> {
                let lnum = ctx.line_number().unwrap_or(0);
                let line = String::from_utf8_lossy(ctx.bytes());
                self.file_lines
                    .push(format!("{}-{}", lnum, line.trim_end_matches(['\r', '\n'])));
                Ok(true)
            }

            fn context_break(&mut self, _searcher: &Searcher) -> Result<bool, Self::Error> {
                self.file_lines.push("--".to_string());
                Ok(true)
            }
        }

        let mut file_lines: Vec<String> = Vec::new();
        let _ = searcher.search_path(
            &matcher,
            path,
            ContextSink {
                file_lines: &mut file_lines,
                total_matches: &mut total_matches,
                max_results,
                truncated: &mut truncated,
            },
        );

        if !file_lines.is_empty() {
            out_lines.push(path.display().to_string());
            out_lines.extend(file_lines);
        }
        if truncated {
            break;
        }
    }

    if out_lines.is_empty() {
        return Ok("(no matches)".to_string());
    }
    let note = if truncated {
        Some("result limit reached; refine pattern or path")
    } else {
        None
    };
    Ok(truncate_output(out_lines.join("\n"), note))
}

pub fn search_files_sync(
    root: &Path,
    pattern: &str,
    exclude_patterns: &[String],
    max_results: usize,
) -> Result<String, String> {
    let max_results = max_results.clamp(1, 2000);
    let normalized_pat = if pattern.contains(['*', '?', '[']) {
        pattern.to_string()
    } else {
        format!("*{pattern}*")
    };

    let glob = Glob::new(&normalized_pat)
        .or_else(|_| Glob::new(&format!("*{pattern}*")))
        .map_err(|e| format!("invalid glob pattern: {e}"))?
        .compile_matcher();

    let mut ex_builder = GlobSetBuilder::new();
    for ex in exclude_patterns {
        if let Ok(g) = Glob::new(ex) {
            ex_builder.add(g);
        }
    }
    let extra_excludes = ex_builder.build().ok();
    let default_excludes: HashSet<&str> = DEFAULT_EXCLUDES.iter().copied().collect();

    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false)
        .git_ignore(true)
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if let Some(name) = entry.file_name().to_str() {
                if default_excludes.contains(name) {
                    return false;
                }
            }
            true
        });

    let mut matches = Vec::new();
    let mut visited = 0usize;
    let max_visited = 80_000usize;
    let pattern_lower = pattern.to_lowercase();

    for entry in walker.build().flatten() {
        if entry.depth() == 0 {
            continue;
        }
        visited += 1;
        if visited > max_visited {
            break;
        }
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(path);
        if let Some(ref ex) = extra_excludes {
            if ex.is_match(rel) {
                continue;
            }
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if glob.is_match(rel)
            || glob.is_match(name)
            || name.to_lowercase().contains(&pattern_lower)
        {
            matches.push(path.display().to_string());
            if matches.len() >= max_results {
                break;
            }
        }
    }

    if matches.is_empty() {
        Ok("No matches found".to_string())
    } else {
        Ok(truncate_output(matches.join("\n"), None))
    }
}

#[derive(Debug, Serialize)]
pub struct TreeNode {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<TreeNode>>,
}

pub fn directory_tree_json_sync(
    root: &Path,
    max_depth: usize,
    extra_excludes: &[String],
) -> Result<String, String> {
    let mut excludes: HashSet<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    for e in extra_excludes {
        excludes.insert(e.clone());
    }
    let mut budget = 2000usize;

    fn build(
        dir: &Path,
        depth: usize,
        max_depth: usize,
        excludes: &HashSet<String>,
        budget: &mut usize,
    ) -> Vec<TreeNode> {
        if depth > max_depth || *budget == 0 {
            return Vec::new();
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        let mut out = Vec::new();
        for entry in entries {
            if *budget == 0 {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if excludes.contains(&name) {
                continue;
            }
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            *budget = budget.saturating_sub(1);
            if is_dir {
                let children = if depth < max_depth {
                    Some(build(&path, depth + 1, max_depth, excludes, budget))
                } else {
                    Some(Vec::new())
                };
                out.push(TreeNode {
                    name,
                    kind: "directory",
                    children,
                });
            } else {
                out.push(TreeNode {
                    name,
                    kind: "file",
                    children: None,
                });
            }
        }
        out
    }

    let nodes = build(root, 0, max_depth.min(8), &excludes, &mut budget);
    let json = serde_json::to_string_pretty(&nodes).map_err(|e| e.to_string())?;
    Ok(truncate_output(json, None))
}

pub fn directory_tree_text_sync(
    root: &Path,
    max_depth: usize,
    dirs_only: bool,
    extra_excludes: &[String],
) -> Result<String, String> {
    let mut excludes: HashSet<String> = DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    for e in extra_excludes {
        excludes.insert(e.clone());
    }
    let mut lines = Vec::new();
    let mut budget = 2000usize;

    fn walk(
        dir: &Path,
        depth: usize,
        max_depth: usize,
        dirs_only: bool,
        excludes: &HashSet<String>,
        lines: &mut Vec<String>,
        budget: &mut usize,
    ) {
        if depth > max_depth || *budget == 0 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        let indent = "  ".repeat(depth);
        for entry in entries {
            if *budget == 0 {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if excludes.contains(&name) {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                *budget = budget.saturating_sub(1);
                lines.push(format!("{indent}{name}/"));
                if depth < max_depth {
                    walk(
                        &entry.path(),
                        depth + 1,
                        max_depth,
                        dirs_only,
                        excludes,
                        lines,
                        budget,
                    );
                }
            } else if !dirs_only {
                *budget = budget.saturating_sub(1);
                lines.push(format!("{indent}{name}"));
            }
        }
    }

    walk(
        root,
        0,
        max_depth.min(8),
        dirs_only,
        &excludes,
        &mut lines,
        &mut budget,
    );
    Ok(truncate_output(lines.join("\n"), None))
}
