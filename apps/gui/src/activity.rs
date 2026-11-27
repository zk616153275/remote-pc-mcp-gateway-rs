use chrono::{DateTime, Duration, Local, NaiveDate, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

const MAX_ROTATED_AUDIT_FILES: usize = 20;
const MAX_ROTATED_DG_FILES: usize = 2;
const DEFAULT_PAGE_SIZE: usize = 50;
const MIN_PAGE_SIZE: usize = 10;
const MAX_PAGE_SIZE: usize = 200;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEntry {
    pub id: String,
    pub timestamp_ms: i64,
    pub date: String,      // "YYYY-MM-DD" (local)
    pub time: String,      // "HH:MM:SS" (local)
    pub full_time: String, // "YYYY-MM-DD HH:MM:SS" (local)
    pub category: String,  // "fs" | "cmd" | "chrome" | "security"
    pub platform: String,  // "Gemini" | "ChatGPT" | "AI Client" | "Delete Guard"
    pub tool: String,
    pub target: String,
    pub full_target: String,
    pub cwd: String,
    pub command_id: String,
    pub is_error: bool,
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActivityStats {
    pub total: usize,
    pub fs_count: usize,
    pub cmd_count: usize,
    pub chrome_count: usize,
    pub security_count: usize,
    pub error_count: usize,
    pub today_count: usize,
}

impl ActivityStats {
    fn add_entry(&mut self, entry: &ActivityEntry, today_str: &str) {
        self.total += 1;
        match entry.category.as_str() {
            "fs" => self.fs_count += 1,
            "cmd" => self.cmd_count += 1,
            "chrome" => self.chrome_count += 1,
            "security" => self.security_count += 1,
            _ => self.fs_count += 1,
        }
        if entry.is_error {
            self.error_count += 1;
        }
        if entry.date == today_str {
            self.today_count += 1;
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DateCount {
    pub date: String,
    pub count: usize,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActivityQuery {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub preset: Option<String>, // "all" | "today" | "yesterday" | "3d" | "7d" | "30d" | "custom"
    pub date: Option<String>,   // "YYYY-MM-DD"
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub time_from: Option<String>, // "HH:MM" or "HH:MM:SS"
    pub time_to: Option<String>,   // "HH:MM" or "HH:MM:SS"
    pub category: Option<String>,  // "all" | "fs" | "cmd" | "chrome" | "security"
    pub errors_only: Option<bool>,
    pub search: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityPageResponse {
    pub items: Vec<ActivityEntry>,
    pub page: usize,
    pub page_size: usize,
    pub total_matched: usize,
    pub total_pages: usize,
    pub all_stats: ActivityStats,
    pub scoped_stats: ActivityStats,
    pub available_dates: Vec<DateCount>,
    pub revision: String,
}

pub struct ActivitySnapshot {
    pub recent: Vec<ActivityEntry>,
    pub stats: ActivityStats,
    pub revision: String,
}

type FileSig = (SystemTime, u64);

struct CachedIndex {
    audit_path: PathBuf,
    audit_sigs: Vec<(PathBuf, Option<FileSig>)>,
    dg_sigs: Vec<(PathBuf, Option<FileSig>)>,
    today_str: String,
    items: Vec<ActivityEntry>, // sorted newest first
    all_stats: ActivityStats,
    available_dates: Vec<DateCount>,
    revision: String,
}

#[derive(Default)]
pub struct ActivityStore {
    cache: Mutex<Option<CachedIndex>>,
}

fn file_sig(path: &Path) -> Option<FileSig> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

fn collect_rotated_files(base: &Path, max_rotated: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    // Oldest rotated file first so stable_activity_id sequence numbers remain stable as new lines append
    for idx in (1..=max_rotated).rev() {
        let rotated = PathBuf::from(format!("{}.{idx}", base.display()));
        if rotated.is_file() {
            files.push(rotated);
        }
    }
    if base.is_file() {
        files.push(base.to_path_buf());
    }
    files
}

fn stable_activity_id(prefix: &str, parts: &[&str], seen: &mut HashMap<u64, u32>) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for part in parts {
        for b in part.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    let count = seen.entry(h).or_insert(0);
    let seq = *count;
    *count += 1;
    if seq == 0 {
        format!("{prefix}:{h:016x}")
    } else {
        format!("{prefix}:{h:016x}:{seq}")
    }
}

fn parse_rfc3339_local(ts_raw: &str) -> (i64, String, String, String) {
    if let Ok(dt) = DateTime::parse_from_rfc3339(ts_raw) {
        let local = dt.with_timezone(&Local);
        return (
            local.timestamp_millis(),
            local.format("%Y-%m-%d").to_string(),
            local.format("%H:%M:%S").to_string(),
            local.format("%Y-%m-%d %H:%M:%S").to_string(),
        );
    }
    (
        0,
        String::new(),
        "--:--:--".to_string(),
        "--:--:--".to_string(),
    )
}

fn parse_dg_local_timestamp(line: &str) -> (i64, String, String, String) {
    let mut parts = line.split_whitespace();
    let date_tok = parts.next().unwrap_or("");
    let time_tok = parts.next().unwrap_or("");
    if date_tok.len() == 10 && time_tok.len() >= 8 {
        let time_short = &time_tok[..8];
        let combined = format!("{date_tok} {time_short}");
        if let Ok(naive) = NaiveDateTime::parse_from_str(&combined, "%Y-%m-%d %H:%M:%S") {
            let ts_ms = Local
                .from_local_datetime(&naive)
                .earliest()
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|| naive.and_utc().timestamp_millis());
            return (
                ts_ms,
                date_tok.to_string(),
                time_short.to_string(),
                combined,
            );
        }
    }
    (
        0,
        String::new(),
        "--:--:--".to_string(),
        "--:--:--".to_string(),
    )
}

fn load_full_index(
    audit_files: &[PathBuf],
    dg_files: &[PathBuf],
    today_str: &str,
) -> (Vec<ActivityEntry>, ActivityStats, Vec<DateCount>) {
    let mut indexed: Vec<(usize, ActivityEntry)> = Vec::new();
    let mut seq: usize = 0;
    let mut seen_ids: HashMap<u64, u32> = HashMap::new();

    for path in audit_files {
        let Ok(file) = File::open(path) else {
            continue;
        };
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                continue;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            let event = v.get("event").and_then(Value::as_str).unwrap_or("");
            let ts_raw = v.get("ts").and_then(Value::as_str).unwrap_or("");
            let (timestamp_ms, date, time, full_time) = parse_rfc3339_local(ts_raw);

            if event == "tool_call" {
                let tool = v.get("tool").and_then(Value::as_str).unwrap_or("unknown");
                let lane = v.get("lane").and_then(Value::as_str).unwrap_or("fs");
                let target = v.get("target").and_then(Value::as_str).unwrap_or("");
                let full_target = v
                    .get("fullTarget")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(target);
                let cwd = v.get("cwd").and_then(Value::as_str).unwrap_or("");
                let command_id = v.get("commandId").and_then(Value::as_str).unwrap_or("");
                let is_error = v.get("isError").and_then(Value::as_bool).unwrap_or(false);
                let source = v.get("source").and_then(Value::as_str).unwrap_or("");
                let plat_raw = v.get("platform").and_then(Value::as_str).unwrap_or("");
                let owner = v.get("owner").and_then(Value::as_str).unwrap_or("");
                let platform = if plat_raw == "google" || owner.starts_with("gemini-") {
                    "Gemini"
                } else if plat_raw == "openai" || owner.starts_with("chatgpt-") {
                    "ChatGPT"
                } else {
                    "AI Client"
                };

                let category = match lane {
                    "chrome" => "chrome",
                    "cmd" | "git" => "cmd",
                    _ => "fs",
                };
                let id =
                    stable_activity_id("a", &[ts_raw, tool, target, command_id], &mut seen_ids);
                indexed.push((
                    seq,
                    ActivityEntry {
                        id,
                        timestamp_ms,
                        date,
                        time,
                        full_time,
                        category: category.into(),
                        platform: platform.into(),
                        tool: tool.into(),
                        target: target.into(),
                        full_target: full_target.into(),
                        cwd: cwd.into(),
                        command_id: command_id.into(),
                        is_error,
                        source: source.into(),
                    },
                ));
                seq += 1;
            } else if event == "oauth_authorized" {
                let cid = v.get("clientId").and_then(Value::as_str).unwrap_or("");
                let platform = if cid.starts_with("gemini-") {
                    "Gemini"
                } else {
                    "ChatGPT"
                };
                let id = stable_activity_id("o", &[ts_raw, cid], &mut seen_ids);
                indexed.push((
                    seq,
                    ActivityEntry {
                        id,
                        timestamp_ms,
                        date,
                        time,
                        full_time,
                        category: "security".into(),
                        platform: platform.into(),
                        tool: "OAuth 授权通过".into(),
                        target: cid.into(),
                        full_target: cid.into(),
                        cwd: String::new(),
                        command_id: String::new(),
                        is_error: false,
                        source: "oauth".into(),
                    },
                ));
                seq += 1;
            }
        }
    }

    // Include all Delete Guard interceptions (including rotated archives) with true chronological timestamps
    for dg_path in dg_files {
        let Ok(file) = File::open(dg_path) else {
            continue;
        };
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                continue;
            };
            if !line.contains("BLOCK-FIRST") {
                continue;
            }
            let (timestamp_ms, date, time, full_time) = parse_dg_local_timestamp(&line);
            let target = line
                .split_once("[rust-workbench] ")
                .map(|(_, rest)| rest)
                .unwrap_or(&line)
                .to_string();
            let id = stable_activity_id("dg", &[&full_time, &target], &mut seen_ids);
            indexed.push((
                seq,
                ActivityEntry {
                    id,
                    timestamp_ms,
                    date,
                    time,
                    full_time,
                    category: "security".into(),
                    platform: "Delete Guard".into(),
                    tool: "拦截高危删除".into(),
                    full_target: target.clone(),
                    target,
                    cwd: String::new(),
                    command_id: String::new(),
                    is_error: true,
                    source: "delete-guard".into(),
                },
            ));
            seq += 1;
        }
    }

    // Sort newest first by timestamp_ms DESC, breaking ties by sequence DESC
    indexed.sort_by(|(seq_a, a), (seq_b, b)| {
        b.timestamp_ms
            .cmp(&a.timestamp_ms)
            .then_with(|| seq_b.cmp(seq_a))
    });

    let mut all_stats = ActivityStats::default();
    let mut date_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut items = Vec::with_capacity(indexed.len());

    for (_, entry) in indexed {
        all_stats.add_entry(&entry, today_str);
        if !entry.date.is_empty() {
            *date_counts.entry(entry.date.clone()).or_insert(0) += 1;
        }
        items.push(entry);
    }

    let available_dates: Vec<DateCount> = date_counts
        .into_iter()
        .rev()
        .map(|(date, count)| DateCount { date, count })
        .collect();

    (items, all_stats, available_dates)
}

fn normalize_time_bound(raw: Option<&str>, is_end: bool) -> Option<String> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    if s.len() == 5 && s.as_bytes().get(2) == Some(&b':') {
        Some(format!("{s}:{}", if is_end { "59" } else { "00" }))
    } else if s.len() >= 8 {
        Some(s[..8].to_string())
    } else {
        None
    }
}

fn resolve_date_bounds(
    preset: &str,
    date: Option<&str>,
    date_from: Option<&str>,
    date_to: Option<&str>,
    today: NaiveDate,
) -> (Option<String>, Option<String>) {
    let fmt = |d: NaiveDate| d.format("%Y-%m-%d").to_string();
    match preset {
        "today" => {
            let s = fmt(today);
            (Some(s.clone()), Some(s))
        }
        "yesterday" => {
            let y = fmt(today - Duration::days(1));
            (Some(y.clone()), Some(y))
        }
        "3d" => (Some(fmt(today - Duration::days(2))), Some(fmt(today))),
        "7d" => (Some(fmt(today - Duration::days(6))), Some(fmt(today))),
        "30d" => (Some(fmt(today - Duration::days(29))), Some(fmt(today))),
        "custom" => {
            if let Some(d) = date.map(str::trim).filter(|s| !s.is_empty()) {
                (Some(d.to_string()), Some(d.to_string()))
            } else {
                let from = date_from
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                let to = date_to
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                (from, to)
            }
        }
        _ => {
            // If preset is "all" or omitted, still honor explicit date / date_from / date_to if passed
            if let Some(d) = date.map(str::trim).filter(|s| !s.is_empty()) {
                (Some(d.to_string()), Some(d.to_string()))
            } else {
                let from = date_from
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                let to = date_to
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                (from, to)
            }
        }
    }
}

fn matches_search(entry: &ActivityEntry, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return true;
    }
    let tool = entry.tool.to_lowercase();
    let target = entry.target.to_lowercase();
    let full_target = entry.full_target.to_lowercase();
    let cwd = entry.cwd.to_lowercase();
    let platform = entry.platform.to_lowercase();
    let cmd_id = entry.command_id.to_lowercase();
    let source = entry.source.to_lowercase();
    let full_time = entry.full_time.to_lowercase();

    tokens.iter().all(|tok| {
        tool.contains(tok)
            || target.contains(tok)
            || full_target.contains(tok)
            || cwd.contains(tok)
            || platform.contains(tok)
            || cmd_id.contains(tok)
            || source.contains(tok)
            || full_time.contains(tok)
    })
}

fn query_slice(
    items: &[ActivityEntry],
    all_stats: &ActivityStats,
    available_dates: &[DateCount],
    revision: &str,
    query: &ActivityQuery,
    today: NaiveDate,
) -> ActivityPageResponse {
    let today_str = today.format("%Y-%m-%d").to_string();
    let preset = query.preset.as_deref().unwrap_or("all").trim();
    let (from_date, to_date) = resolve_date_bounds(
        preset,
        query.date.as_deref(),
        query.date_from.as_deref(),
        query.date_to.as_deref(),
        today,
    );
    let from_time = normalize_time_bound(query.time_from.as_deref(), false);
    let to_time = normalize_time_bound(query.time_to.as_deref(), true);
    let category = query.category.as_deref().unwrap_or("all").trim();
    let errors_only = query.errors_only.unwrap_or(false);
    let search_tokens: Vec<String> = query
        .search
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_lowercase())
        .collect();

    let mut scoped_stats = ActivityStats::default();
    let mut matched: Vec<&ActivityEntry> = Vec::new();

    for entry in items {
        if let Some(ref fd) = from_date {
            if entry.date.is_empty() || entry.date.as_str() < fd.as_str() {
                continue;
            }
        }
        if let Some(ref td) = to_date {
            if entry.date.is_empty() || entry.date.as_str() > td.as_str() {
                continue;
            }
        }
        if let Some(ref ft) = from_time {
            if entry.time.as_str() < ft.as_str() {
                continue;
            }
        }
        if let Some(ref tt) = to_time {
            if entry.time.as_str() > tt.as_str() {
                continue;
            }
        }
        if errors_only && !entry.is_error && entry.category != "security" {
            continue;
        }
        if !matches_search(entry, &search_tokens) {
            continue;
        }

        scoped_stats.add_entry(entry, &today_str);

        if category == "all" || category.is_empty() || entry.category == category {
            matched.push(entry);
        }
    }

    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE);
    let total_matched = matched.len();
    let total_pages = if total_matched == 0 {
        1
    } else {
        total_matched.div_ceil(page_size)
    };
    let page = query.page.unwrap_or(1).clamp(1, total_pages);
    let start = (page - 1) * page_size;
    let end = (start + page_size).min(total_matched);
    let page_items = if start < total_matched {
        matched[start..end].iter().map(|e| (*e).clone()).collect()
    } else {
        Vec::new()
    };

    ActivityPageResponse {
        items: page_items,
        page,
        page_size,
        total_matched,
        total_pages,
        all_stats: all_stats.clone(),
        scoped_stats,
        available_dates: available_dates.to_vec(),
        revision: revision.to_string(),
    }
}

impl ActivityStore {
    fn ensure_loaded<'a>(
        guard: &'a mut Option<CachedIndex>,
        audit_path: &Path,
        dg_log: &Path,
    ) -> &'a CachedIndex {
        let audit_files = collect_rotated_files(audit_path, MAX_ROTATED_AUDIT_FILES);
        let audit_sigs: Vec<(PathBuf, Option<FileSig>)> = audit_files
            .iter()
            .map(|p| (p.clone(), file_sig(p)))
            .collect();
        let dg_files = collect_rotated_files(dg_log, MAX_ROTATED_DG_FILES);
        let dg_sigs: Vec<(PathBuf, Option<FileSig>)> =
            dg_files.iter().map(|p| (p.clone(), file_sig(p))).collect();
        let today_str = Local::now().format("%Y-%m-%d").to_string();

        let needs_reload = match guard {
            Some(c) => {
                c.audit_path != audit_path
                    || c.audit_sigs != audit_sigs
                    || c.dg_sigs != dg_sigs
                    || c.today_str != today_str
            }
            None => true,
        };

        if needs_reload {
            let (items, all_stats, available_dates) =
                load_full_index(&audit_files, &dg_files, &today_str);
            let total_bytes: u64 = audit_sigs
                .iter()
                .filter_map(|(_, sig)| sig.map(|(_, len)| len))
                .sum();
            let dg_bytes: u64 = dg_sigs
                .iter()
                .filter_map(|(_, sig)| sig.map(|(_, len)| len))
                .sum();
            let newest_id = items.first().map(|e| e.id.as_str()).unwrap_or("");
            let revision = format!(
                "{}:{}:{}:{}:{}",
                all_stats.total, total_bytes, dg_bytes, today_str, newest_id
            );
            *guard = Some(CachedIndex {
                audit_path: audit_path.to_path_buf(),
                audit_sigs,
                dg_sigs,
                today_str,
                items,
                all_stats,
                available_dates,
                revision,
            });
        }

        guard.as_ref().expect("cache just populated")
    }

    pub fn snapshot(
        &self,
        audit_path: &Path,
        dg_log: &Path,
        recent_limit: usize,
    ) -> ActivitySnapshot {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let idx = Self::ensure_loaded(&mut guard, audit_path, dg_log);
        let recent = idx.items.iter().take(recent_limit).cloned().collect();
        ActivitySnapshot {
            recent,
            stats: idx.all_stats.clone(),
            revision: idx.revision.clone(),
        }
    }

    pub fn query(
        &self,
        audit_path: &Path,
        dg_log: &Path,
        query: &ActivityQuery,
    ) -> ActivityPageResponse {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let idx = Self::ensure_loaded(&mut guard, audit_path, dg_log);
        let today = Local::now().date_naive();
        query_slice(
            &idx.items,
            &idx.all_stats,
            &idx.available_dates,
            &idx.revision,
            query,
            today,
        )
    }

    pub fn last_audit_path(&self) -> Option<PathBuf> {
        let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.as_ref().map(|c| c.audit_path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[allow(clippy::too_many_arguments)]
    fn mk_entry(
        id: &str,
        ts_ms: i64,
        date: &str,
        time: &str,
        cat: &str,
        tool: &str,
        target: &str,
        is_error: bool,
    ) -> ActivityEntry {
        ActivityEntry {
            id: id.into(),
            timestamp_ms: ts_ms,
            date: date.into(),
            time: time.into(),
            full_time: format!("{date} {time}"),
            category: cat.into(),
            platform: "Gemini".into(),
            tool: tool.into(),
            target: target.into(),
            full_target: target.into(),
            cwd: String::new(),
            command_id: String::new(),
            is_error,
            source: "local-fs".into(),
        }
    }

    #[test]
    fn loads_full_audit_without_80_cap_and_sorts_chronologically() {
        let dir = std::env::temp_dir().join(format!("rpc-gui-act-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let audit = dir.join("local-audit.jsonl");
        let rotated = dir.join("local-audit.jsonl.1");
        let dg = dir.join("delete-guard.log");

        // Write 10 older lines into rotated .1 file
        {
            let mut f = File::create(&rotated).unwrap();
            for i in 0..10 {
                writeln!(
                    f,
                    r#"{{"event":"tool_call","lane":"fs","tool":"fs_read_file","target":"old_{i}.rs","ts":"2026-11-24T10:00:{i:02}Z"}}"#
                )
                .unwrap();
            }
        }

        // Write 120 lines into current audit file (exceeding old 80 cap)
        {
            let mut f = File::create(&audit).unwrap();
            for i in 0..120 {
                let min = i / 60;
                let sec = i % 60;
                let lane = match i % 3 {
                    0 => "fs",
                    1 => "cmd",
                    _ => "chrome",
                };
                writeln!(
                    f,
                    r#"{{"event":"tool_call","lane":"{lane}","tool":"tool_{i}","target":"file_{i}","ts":"2026-11-26T12:{min:02}:{sec:02}Z"}}"#
                )
                .unwrap();
            }
        }

        // Write 1 delete-guard entry with a timestamp between 2026-11-24 and 2026-11-26
        {
            let mut f = File::create(&dg).unwrap();
            writeln!(
                f,
                "2026-11-25 15:30:00  [rust-workbench] BLOCK-FIRST fp=abc matched=[Remove-Item -Recurse]"
            )
            .unwrap();
        }

        let store = ActivityStore::default();
        let snap = store.snapshot(&audit, &dg, 6);
        assert_eq!(snap.stats.total, 131);
        assert_eq!(snap.stats.fs_count, 50); // 10 rotated + 40 current
        assert_eq!(snap.stats.cmd_count, 40);
        assert_eq!(snap.stats.chrome_count, 40);
        assert_eq!(snap.stats.security_count, 1);
        assert_eq!(snap.recent.len(), 6);
        // Newest entry should be from 2026-11-26 (NOT the 2026-11-25 delete-guard entry!)
        assert_eq!(snap.recent[0].tool, "tool_119");

        // Pagination check
        let page2 = store.query(
            &audit,
            &dg,
            &ActivityQuery {
                page: Some(2),
                page_size: Some(50),
                ..Default::default()
            },
        );
        assert_eq!(page2.total_matched, 131);
        assert_eq!(page2.total_pages, 3);
        assert_eq!(page2.page, 2);
        assert_eq!(page2.items.len(), 50);
        assert_eq!(page2.all_stats.total, 131);

        let page3 = store.query(
            &audit,
            &dg,
            &ActivityQuery {
                page: Some(3),
                page_size: Some(50),
                ..Default::default()
            },
        );
        assert_eq!(page3.items.len(), 31);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filters_by_date_time_category_errors_and_multi_token_search() {
        let today = NaiveDate::from_ymd_opt(2026, 11, 27).unwrap();
        let items = vec![
            mk_entry(
                "1",
                500,
                "2026-11-27",
                "14:30:00",
                "cmd",
                "run_command",
                "cargo test",
                false,
            ),
            mk_entry(
                "2",
                400,
                "2026-11-27",
                "09:15:00",
                "fs",
                "fs_read_file",
                "D:\\repo\\main.rs",
                true,
            ),
            mk_entry(
                "3",
                300,
                "2026-11-26",
                "18:05:57",
                "security",
                "拦截高危删除",
                "Remove-Item",
                true,
            ),
            mk_entry(
                "4",
                200,
                "2026-11-26",
                "11:00:00",
                "chrome",
                "chrome_click",
                "https://example.com",
                false,
            ),
            mk_entry(
                "5",
                100,
                "2026-11-20",
                "08:00:00",
                "fs",
                "fs_grep_files",
                "pattern",
                false,
            ),
        ];
        let mut all_stats = ActivityStats::default();
        for e in &items {
            all_stats.add_entry(e, "2026-11-27");
        }
        let dates = vec![
            DateCount {
                date: "2026-11-27".into(),
                count: 2,
            },
            DateCount {
                date: "2026-11-26".into(),
                count: 2,
            },
            DateCount {
                date: "2026-11-20".into(),
                count: 1,
            },
        ];

        // Today + time window 10:00..15:00
        let res = query_slice(
            &items,
            &all_stats,
            &dates,
            "rev1",
            &ActivityQuery {
                preset: Some("today".into()),
                time_from: Some("10:00".into()),
                time_to: Some("15:00".into()),
                ..Default::default()
            },
            today,
        );
        assert_eq!(res.total_matched, 1);
        assert_eq!(res.items[0].id, "1");
        assert_eq!(res.all_stats.total, 5);
        assert_eq!(res.scoped_stats.cmd_count, 1);

        // Yesterday + category filter preserves scoped_stats across categories
        let res_y = query_slice(
            &items,
            &all_stats,
            &dates,
            "rev1",
            &ActivityQuery {
                preset: Some("yesterday".into()),
                category: Some("chrome".into()),
                ..Default::default()
            },
            today,
        );
        assert_eq!(res_y.total_matched, 1);
        assert_eq!(res_y.items[0].id, "4");
        assert_eq!(res_y.scoped_stats.total, 2);
        assert_eq!(res_y.scoped_stats.security_count, 1);
        assert_eq!(res_y.scoped_stats.chrome_count, 1);

        // Errors only
        let res_err = query_slice(
            &items,
            &all_stats,
            &dates,
            "rev1",
            &ActivityQuery {
                errors_only: Some(true),
                ..Default::default()
            },
            today,
        );
        assert_eq!(res_err.total_matched, 2);

        // Multi-token search
        let res_q = query_slice(
            &items,
            &all_stats,
            &dates,
            "rev1",
            &ActivityQuery {
                search: Some("main.rs read".into()),
                ..Default::default()
            },
            today,
        );
        assert_eq!(res_q.total_matched, 1);
        assert_eq!(res_q.items[0].id, "2");
    }
}
