use crate::search::{
    directory_tree_json_sync, directory_tree_text_sync, grep_files_sync, search_files_sync,
    truncate_output,
};
use base64::Engine;
use chrono::{DateTime, Utc};
use rpc_mcp_core::path_guard::AllowedRoots;
use rpc_mcp_core::write_atomic_string;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use similar::TextDiff;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

pub const RESPONSE_LIMIT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_EDIT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ToolResult {
    pub content: Vec<Value>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl ToolResult {
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            content: vec![json!({ "type": "text", "text": s.into() })],
            is_error: None,
        }
    }

    pub fn error(s: impl Into<String>) -> Self {
        Self {
            content: vec![json!({ "type": "text", "text": s.into() })],
            is_error: Some(true),
        }
    }

    pub fn oversized() -> Self {
        Self::error(
            "FS_RESPONSE_TOO_LARGE: response exceeds the safe 8 MiB transport budget. \
             Read text in smaller ranges, or create a smaller image copy.",
        )
    }
}

pub fn tool_definitions() -> Value {
    json!([
        {
            "name": "list_allowed_directories",
            "description": "Returns the list of directories that this server is allowed to access.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        },
        {
            "name": "list_directory",
            "description": "Get a detailed listing of all files and directories in a specified path.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "list_directory_with_sizes",
            "description": "Get a detailed listing of files and directories including sizes.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "sortBy": { "type": "string", "enum": ["name", "size"] }
                },
                "required": ["path"]
            }
        },
        {
            "name": "directory_tree",
            "description": "Get a recursive JSON tree view of files and directories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "excludePatterns": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["path"]
            }
        },
        {
            "name": "directory_tree_limited",
            "description": "Depth-limited recursive directory tree, excluding node_modules/.git/dist by default.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "max_depth": { "type": "integer", "minimum": 0, "maximum": 8 },
                    "dirs_only": { "type": "boolean" },
                    "exclude": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["path"]
            }
        },
        {
            "name": "search_files",
            "description": "Recursively search for files and directories matching a glob or substring pattern.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "pattern": { "type": "string" },
                    "excludePatterns": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["path", "pattern"]
            }
        },
        {
            "name": "grep_files",
            "description": "Search file CONTENT using embedded ripgrep.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "pattern": { "type": "string" },
                    "is_regex": { "type": "boolean" },
                    "glob": { "type": "array", "items": { "type": "string" } },
                    "context": { "type": "integer", "minimum": 0, "maximum": 6 },
                    "max_results": { "type": "integer", "minimum": 1, "maximum": 400 }
                },
                "required": ["path", "pattern"]
            }
        },
        {
            "name": "read_file",
            "description": "Read the complete contents of a UTF-8 text file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "head": { "type": "integer", "minimum": 1 },
                    "tail": { "type": "integer", "minimum": 1 }
                },
                "required": ["path"]
            }
        },
        {
            "name": "read_text_file",
            "description": "Read the complete text contents of a file (or first/last N lines via head/tail).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "head": { "type": "integer", "minimum": 1 },
                    "tail": { "type": "integer", "minimum": 1 }
                },
                "required": ["path"]
            }
        },
        {
            "name": "read_multiple_files",
            "description": "Read the contents of multiple files simultaneously.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "paths": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["paths"]
            }
        },
        {
            "name": "read_media_file",
            "description": "Read an image or audio file and return base64 data with MIME type.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "read_file_lines",
            "description": "Read a 1-based line range of a text file with line numbers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "offset": { "type": "integer", "minimum": 1 },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 4000 }
                },
                "required": ["path"]
            }
        },
        {
            "name": "get_file_info",
            "description": "Retrieve detailed metadata about a file or directory.",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "write_file",
            "description": "Create a new file or completely overwrite an existing file with UTF-8 text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        },
        {
            "name": "edit_file",
            "description": "Make line-based search/replace edits to a text file and return a unified diff.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "oldText": { "type": "string" },
                                "newText": { "type": "string" }
                            },
                            "required": ["oldText", "newText"]
                        }
                    },
                    "dryRun": { "type": "boolean" }
                },
                "required": ["path", "edits"]
            }
        },
        {
            "name": "edit_file_at_line",
            "description": "Replace a 1-based inclusive line range [start_line, end_line] with new_text.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "start_line": { "type": "integer", "minimum": 1 },
                    "end_line": { "type": "integer", "minimum": 1 },
                    "new_text": { "type": "string" }
                },
                "required": ["path", "start_line", "end_line", "new_text"]
            }
        },
        {
            "name": "create_directory",
            "description": "Create a new directory (or ensure nested directories exist).",
            "inputSchema": {
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"]
            }
        },
        {
            "name": "move_file",
            "description": "Move or rename a file or directory within allowed directories.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source": { "type": "string" },
                    "destination": { "type": "string" }
                },
                "required": ["source", "destination"]
            }
        }
    ])
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TextEdit {
    old_text: String,
    new_text: String,
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolResult> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ToolResult::error(format!("missing required string argument: {key}")))
}

fn read_text_with_bounds(
    path: &Path,
    head: Option<usize>,
    tail: Option<usize>,
) -> Result<String, ToolResult> {
    let meta = fs::metadata(path).map_err(|e| ToolResult::error(e.to_string()))?;
    if head.is_none() && tail.is_none() {
        if meta.len() > RESPONSE_LIMIT_BYTES {
            return Err(ToolResult::oversized());
        }
        return fs::read_to_string(path).map_err(|e| ToolResult::error(e.to_string()));
    }

    if let Some(n) = head {
        let file = File::open(path).map_err(|e| ToolResult::error(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for line_res in reader.lines().take(n) {
            let line = line_res.map_err(|e| ToolResult::error(e.to_string()))?;
            bytes = bytes.saturating_add(line.len() + 1);
            if bytes as u64 > RESPONSE_LIMIT_BYTES {
                return Err(ToolResult::oversized());
            }
            out.push(line);
        }
        return Ok(out.join("\n"));
    }

    if let Some(n) = tail {
        if n == 0 {
            return Ok(String::new());
        }
        // Reverse-seek from EOF in 64 KiB chunks so tail is O(tail_bytes) and
        // never false-positives on large lines earlier in the file.
        let mut file = File::open(path).map_err(|e| ToolResult::error(e.to_string()))?;
        let file_len = meta.len();
        if file_len == 0 {
            return Ok(String::new());
        }
        const CHUNK: u64 = 64 * 1024;
        let mut pos = file_len;
        let mut collected: Vec<u8> = Vec::new();
        let mut newlines = 0usize;
        // Ignore a single trailing '\n' at EOF when counting lines
        let mut skipped_eof_nl = false;

        while pos > 0 {
            let read_len = pos.min(CHUNK);
            pos -= read_len;
            file.seek(SeekFrom::Start(pos))
                .map_err(|e| ToolResult::error(e.to_string()))?;
            let mut chunk = vec![0u8; read_len as usize];
            file.read_exact(&mut chunk)
                .map_err(|e| ToolResult::error(e.to_string()))?;

            for (idx, &b) in chunk.iter().enumerate().rev() {
                if b == b'\n' {
                    if !skipped_eof_nl && collected.is_empty() && idx + 1 == chunk.len() {
                        skipped_eof_nl = true;
                        continue;
                    }
                    newlines += 1;
                    if newlines >= n {
                        let start = idx + 1;
                        let mut final_bytes =
                            Vec::with_capacity((chunk.len() - start) + collected.len());
                        final_bytes.extend_from_slice(&chunk[start..]);
                        final_bytes.extend_from_slice(&collected);
                        if final_bytes.len() as u64 > RESPONSE_LIMIT_BYTES {
                            return Err(ToolResult::oversized());
                        }
                        let text = String::from_utf8(final_bytes)
                            .map_err(|e| ToolResult::error(e.to_string()))?;
                        let trimmed = text.strip_suffix('\n').unwrap_or(&text);
                        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
                        return Ok(trimmed.replace("\r\n", "\n"));
                    }
                }
            }

            if (chunk.len() + collected.len()) as u64 > RESPONSE_LIMIT_BYTES {
                return Err(ToolResult::oversized());
            }
            chunk.extend_from_slice(&collected);
            collected = chunk;
        }

        let text = String::from_utf8(collected).map_err(|e| ToolResult::error(e.to_string()))?;
        let trimmed = text.strip_suffix('\n').unwrap_or(&text);
        let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
        return Ok(trimmed.replace("\r\n", "\n"));
    }

    Ok(String::new())
}

fn mime_for_path(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

pub async fn call_tool(roots: &AllowedRoots, name: &str, args: Value) -> ToolResult {
    let roots = roots.clone();
    let name = name.to_string();
    match tokio::task::spawn_blocking(move || call_tool_sync(&roots, &name, args)).await {
        Ok(res) => res,
        Err(e) => ToolResult::error(e.to_string()),
    }
}

fn call_tool_sync(roots: &AllowedRoots, name: &str, args: Value) -> ToolResult {
    match name {
        "list_allowed_directories" => {
            let lines: Vec<String> = roots
                .roots()
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            ToolResult::text(format!("Allowed directories:\n{}", lines.join("\n")))
        }

        "list_directory" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let rd = match fs::read_dir(&path) {
                Ok(r) => r,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let mut entries: Vec<_> = rd.flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            let lines: Vec<String> = entries
                .into_iter()
                .map(|e| {
                    let prefix = if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        "[DIR]"
                    } else {
                        "[FILE]"
                    };
                    format!("{prefix} {}", e.file_name().to_string_lossy())
                })
                .collect();
            ToolResult::text(lines.join("\n"))
        }

        "list_directory_with_sizes" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let sort_by = args.get("sortBy").and_then(Value::as_str).unwrap_or("name");
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let rd = match fs::read_dir(&path) {
                Ok(r) => r,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let mut items: Vec<(bool, String, u64)> = rd
                .flatten()
                .map(|e| {
                    let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    (is_dir, e.file_name().to_string_lossy().to_string(), size)
                })
                .collect();
            if sort_by == "size" {
                items.sort_by_key(|a| std::cmp::Reverse(a.2));
            } else {
                items.sort_by(|a, b| a.1.cmp(&b.1));
            }
            let lines: Vec<String> = items
                .into_iter()
                .map(|(is_dir, name, size)| {
                    if is_dir {
                        format!("[DIR]  {name}")
                    } else {
                        format!("[FILE] {name} ({size} bytes)")
                    }
                })
                .collect();
            ToolResult::text(lines.join("\n"))
        }

        "directory_tree" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let excludes: Vec<String> = args
                .get("excludePatterns")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            match directory_tree_json_sync(&path, 6, &excludes) {
                Ok(text) => ToolResult::text(text),
                Err(e) => ToolResult::error(e),
            }
        }

        "directory_tree_limited" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let max_depth = args
                .get("max_depth")
                .and_then(Value::as_u64)
                .unwrap_or(2)
                .min(8) as usize;
            let dirs_only = args
                .get("dirs_only")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let excludes: Vec<String> = args
                .get("exclude")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            match directory_tree_text_sync(&path, max_depth, dirs_only, &excludes) {
                Ok(text) => ToolResult::text(text),
                Err(e) => ToolResult::error(e),
            }
        }

        "search_files" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let pattern = match str_arg(&args, "pattern") {
                Ok(v) => v.to_string(),
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let excludes: Vec<String> = args
                .get("excludePatterns")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            match search_files_sync(&path, &pattern, &excludes, 500) {
                Ok(text) => ToolResult::text(text),
                Err(e) => ToolResult::error(e),
            }
        }

        "grep_files" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let pattern = match str_arg(&args, "pattern") {
                Ok(v) => v.to_string(),
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let is_regex = args
                .get("is_regex")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let context = args.get("context").and_then(Value::as_u64).unwrap_or(0) as usize;
            let max_results = args
                .get("max_results")
                .and_then(Value::as_u64)
                .unwrap_or(60) as usize;
            let globs: Vec<String> = args
                .get("glob")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            match grep_files_sync(&path, &pattern, is_regex, &globs, context, max_results) {
                Ok(text) => ToolResult::text(text),
                Err(e) => ToolResult::error(e),
            }
        }

        "read_file" | "read_text_file" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let head = args.get("head").and_then(Value::as_u64).map(|v| v as usize);
            let tail = args.get("tail").and_then(Value::as_u64).map(|v| v as usize);
            match read_text_with_bounds(&path, head, tail) {
                Ok(text) => ToolResult::text(text),
                Err(err) => err,
            }
        }

        "read_multiple_files" => {
            let Some(paths) = args.get("paths").and_then(Value::as_array) else {
                return ToolResult::error("missing required array argument: paths");
            };
            let mut total_bytes = 0u64;
            let mut parts = Vec::new();
            for p_val in paths {
                let Some(raw) = p_val.as_str() else { continue };
                match roots.validate(raw) {
                    Ok(valid) => match fs::metadata(&valid) {
                        Ok(meta) => {
                            total_bytes = total_bytes.saturating_add(meta.len());
                            if total_bytes > RESPONSE_LIMIT_BYTES {
                                return ToolResult::oversized();
                            }
                            match fs::read_to_string(&valid) {
                                Ok(content) => parts.push(format!("{raw}:\n{content}\n")),
                                Err(e) => parts.push(format!("{raw}: Error - {e}")),
                            }
                        }
                        Err(e) => parts.push(format!("{raw}: Error - {e}")),
                    },
                    Err(e) => parts.push(format!("{raw}: Error - {e}")),
                }
            }
            ToolResult::text(parts.join("\n---\n"))
        }

        "read_media_file" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            if meta.len().saturating_mul(4) / 3 > RESPONSE_LIMIT_BYTES {
                return ToolResult::oversized();
            }
            let bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let mime = mime_for_path(&path);
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let kind = if mime.starts_with("audio/") {
                "audio"
            } else {
                "image"
            };
            ToolResult {
                content: vec![json!({ "type": kind, "data": encoded, "mimeType": mime })],
                is_error: None,
            }
        }

        "read_file_lines" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let offset = args
                .get("offset")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1) as usize;
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(400)
                .clamp(1, 4000) as usize;
            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let mut reader = BufReader::new(file);
            let mut numbered = Vec::new();
            let mut total_lines = 0usize;
            let end_line = offset.saturating_add(limit).saturating_sub(1);
            let mut buf = Vec::with_capacity(256);
            loop {
                buf.clear();
                let n = match reader.read_until(b'\n', &mut buf) {
                    Ok(n) => n,
                    Err(e) => return ToolResult::error(e.to_string()),
                };
                if n == 0 {
                    break;
                }
                total_lines += 1;
                if total_lines >= offset && total_lines <= end_line {
                    if buf.ends_with(b"\n") {
                        buf.pop();
                    }
                    if buf.ends_with(b"\r") {
                        buf.pop();
                    }
                    let line = String::from_utf8_lossy(&buf);
                    numbered.push(format!("{total_lines}: {line}"));
                }
            }
            let first_shown = if numbered.is_empty() { 0 } else { offset };
            let last_shown = if numbered.is_empty() {
                0
            } else {
                offset + numbered.len() - 1
            };
            let header = format!(
                "File: {} (lines {}-{} of {})\n",
                path.display(),
                first_shown,
                last_shown,
                total_lines
            );
            ToolResult::text(truncate_output(
                format!("{header}{}", numbered.join("\n")),
                None,
            ))
        }

        "get_file_info" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let meta = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let fmt_time = |t: std::io::Result<std::time::SystemTime>| -> String {
                t.ok()
                    .map(|st| DateTime::<Utc>::from(st).to_rfc3339())
                    .unwrap_or_else(|| "unknown".into())
            };
            let info = format!(
                "size: {}\ncreated: {}\nmodified: {}\naccessed: {}\nisDirectory: {}\nisFile: {}",
                meta.len(),
                fmt_time(meta.created()),
                fmt_time(meta.modified()),
                fmt_time(meta.accessed()),
                meta.is_dir(),
                meta.is_file()
            );
            ToolResult::text(info)
        }

        "write_file" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let content = match str_arg(&args, "content") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    return ToolResult::error(format!(
                        "Parent directory does not exist: {}",
                        parent.display()
                    ));
                }
            }
            match write_atomic_string(&path, content) {
                Ok(()) => ToolResult::text(format!("Successfully wrote to {}", path.display())),
                Err(e) => ToolResult::error(e.to_string()),
            }
        }

        "edit_file" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let dry_run = args.get("dryRun").and_then(Value::as_bool).unwrap_or(false);
            let edits: Vec<TextEdit> = match args
                .get("edits")
                .cloned()
                .ok_or_else(|| "missing edits".to_string())
                .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
            {
                Ok(v) => v,
                Err(e) => return ToolResult::error(e),
            };
            match fs::metadata(&path) {
                Ok(m) if m.len() > MAX_EDIT_BYTES => return ToolResult::oversized(),
                Ok(_) => {}
                Err(e) => return ToolResult::error(e.to_string()),
            }
            let original = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let mut updated = original.replace("\r\n", "\n");
            for edit in &edits {
                if edit.old_text.is_empty() {
                    return ToolResult::error("edit oldText must not be empty");
                }
                let old_norm = edit.old_text.replace("\r\n", "\n");
                let new_norm = edit.new_text.replace("\r\n", "\n");
                if !updated.contains(&old_norm) {
                    return ToolResult::error(format!(
                        "Could not find exact match for edit target in {}",
                        path.display()
                    ));
                }
                updated = updated.replacen(&old_norm, &new_norm, 1);
            }
            let has_crlf = original.contains("\r\n");
            let diff = TextDiff::from_lines(&original.replace("\r\n", "\n"), &updated)
                .unified_diff()
                .header("original", "modified")
                .to_string();
            if !dry_run {
                let to_write = if has_crlf {
                    updated.replace('\n', "\r\n")
                } else {
                    updated
                };
                if let Err(e) = write_atomic_string(&path, &to_write) {
                    return ToolResult::error(e.to_string());
                }
            }
            ToolResult::text(diff)
        }

        "edit_file_at_line" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let new_text = match str_arg(&args, "new_text") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let start_line = args.get("start_line").and_then(Value::as_u64).unwrap_or(0) as usize;
            let end_line = args.get("end_line").and_then(Value::as_u64).unwrap_or(0) as usize;
            if start_line == 0 || end_line < start_line {
                return ToolResult::error("invalid start_line/end_line range");
            }
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            match fs::metadata(&path) {
                Ok(m) if m.len() > MAX_EDIT_BYTES => return ToolResult::oversized(),
                Ok(_) => {}
                Err(e) => return ToolResult::error(e.to_string()),
            }
            let content = match fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let eol = if content.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            };
            let mut lines: Vec<String> = content
                .replace("\r\n", "\n")
                .split('\n')
                .map(String::from)
                .collect();
            if start_line > lines.len() {
                return ToolResult::error(format!(
                    "start_line {start_line} exceeds file length {}",
                    lines.len()
                ));
            }
            let end_clamped = end_line.min(lines.len());
            let replacement: Vec<String> = new_text
                .replace("\r\n", "\n")
                .split('\n')
                .map(String::from)
                .collect();
            lines.splice((start_line - 1)..end_clamped, replacement);
            if let Err(e) = write_atomic_string(&path, &lines.join(eol)) {
                return ToolResult::error(e.to_string());
            }
            ToolResult::text(format!(
                "Replaced lines {start_line}-{end_clamped} in {}",
                path.display()
            ))
        }

        "create_directory" => {
            let raw = match str_arg(&args, "path") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let path = match roots.validate(raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            match fs::create_dir_all(&path) {
                Ok(()) => {
                    ToolResult::text(format!("Successfully created directory {}", path.display()))
                }
                Err(e) => ToolResult::error(e.to_string()),
            }
        }

        "move_file" => {
            let src_raw = match str_arg(&args, "source") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let dst_raw = match str_arg(&args, "destination") {
                Ok(v) => v,
                Err(e) => return e,
            };
            let src = match roots.validate(src_raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            let dst = match roots.validate(dst_raw) {
                Ok(p) => p,
                Err(e) => return ToolResult::error(e.to_string()),
            };
            match fs::rename(&src, &dst) {
                Ok(()) => ToolResult::text(format!(
                    "Successfully moved {} to {}",
                    src.display(),
                    dst.display()
                )),
                Err(e) => ToolResult::error(e.to_string()),
            }
        }

        other => ToolResult::error(format!("Unknown filesystem tool: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fs_tools_write_read_grep_and_escape_block() {
        let dir = std::env::temp_dir().join(format!("rmcp-fs-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let roots = AllowedRoots::new([dir.to_string_lossy().to_string()]).unwrap();

        let target = dir.join("hello.txt");
        let wr = call_tool(
            &roots,
            "write_file",
            json!({ "path": target.to_string_lossy(), "content": "alpha\nbeta-rust-mcp\ngamma\n" }),
        )
        .await;
        assert!(wr.is_error.is_none());

        let gr = call_tool(
            &roots,
            "grep_files",
            json!({ "path": dir.to_string_lossy(), "pattern": "beta-rust-mcp", "context": 1 }),
        )
        .await;
        assert!(gr.is_error.is_none());
        let gtxt = gr.content[0]["text"].as_str().unwrap();
        assert!(gtxt.contains("1-alpha"), "missing before-context: {gtxt}");
        assert!(gtxt.contains("2:beta-rust-mcp"), "missing match: {gtxt}");
        assert!(gtxt.contains("3-gamma"), "missing after-context: {gtxt}");

        let tail_res = call_tool(
            &roots,
            "read_file",
            json!({ "path": target.to_string_lossy(), "tail": 2 }),
        )
        .await;
        assert!(tail_res.is_error.is_none());
        assert_eq!(
            tail_res.content[0]["text"].as_str().unwrap(),
            "beta-rust-mcp\ngamma"
        );

        let escape = call_tool(
            &roots,
            "read_file",
            json!({ "path": dir.join("..").join("secret.txt").to_string_lossy() }),
        )
        .await;
        assert_eq!(escape.is_error, Some(true));

        let _ = fs::remove_dir_all(&dir);
    }
}
