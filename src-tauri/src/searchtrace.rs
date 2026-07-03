//! Lazy-discovery search traces: a bounded, local record of what the model actually
//! searched for and what the gateway handed back.
//!
//! This is the in-path answer to "how do I know lazy discovery is working, and what
//! is it costing me?" Because Toolport IS the gateway, it knows the ground truth a
//! post-hoc log reader can only estimate: the exact query, which tools matched, and
//! the tool-definition tokens the returned schemas cost THIS turn versus what loading
//! the whole catalog would have. Each `toolport_search_tools` call appends one line.
//!
//! Kept lean and non-sensitive: the model-authored query is capped, and only tool
//! NAMES (never their schemas, arguments, or results) are stored. Like the audit and
//! savings logs it is append-only (each connected client spawns its own gateway, so
//! concurrent `O_APPEND` of one small line is safe) and never leaves the machine.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Trim the log once it passes this size. A line is a few hundred bytes and a search
/// happens per model turn, so this is a long, bounded window.
const MAX_TRACE_BYTES: u64 = 512 * 1024;
/// Recent lines kept on rotation; older lines are dropped (unlike savings, there is
/// no cumulative total to preserve, so trimming just discards the oldest traces).
const KEEP_LINES: usize = 500;
/// Cap the stored query so a pathological (model-authored) query can't bloat a line.
const MAX_QUERY_CHARS: usize = 200;
/// Cap how many matched tool names we store per trace.
const MAX_NAMES: usize = 25;

fn trace_path() -> Option<PathBuf> {
    // Same anchor as the registry/audit/savings logs, so the app and every
    // client-spawned gateway (some under MSIX virtualization) share one file.
    Some(crate::registry::conduit_dir()?.join("search-trace.jsonl"))
}

fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Truncate `s` to at most `max` chars on a char boundary (never mid-codepoint).
fn cap_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// One recorded search. `flat_tokens` is what advertising the whole (scoped) catalog
/// would cost per request; `returned_tokens` is what this search's results cost. The
/// difference is the tool-definition context lazy discovery kept out on this turn.
#[allow(clippy::too_many_arguments)]
pub fn record(
    client: Option<&str>,
    query: &str,
    server_filter: Option<&str>,
    top: &str,
    names: &[String],
    returned: usize,
    total: usize,
    returned_tokens: u64,
    flat_tokens: u64,
    escalated: bool,
) {
    let stored_names: Vec<&String> = names.iter().take(MAX_NAMES).collect();
    let mut entry = json!({
        "ts": epoch_millis() as u64,
        "query": cap_chars(query, MAX_QUERY_CHARS),
        "top": top,
        "names": stored_names,
        "returned": returned as u64,
        "total": total as u64,
        "returnedTokens": returned_tokens,
        "flatTokens": flat_tokens,
        "savedTokens": flat_tokens.saturating_sub(returned_tokens),
        "escalated": escalated,
    });
    if let Some(s) = server_filter.filter(|s| !s.trim().is_empty()) {
        entry["server"] = json!(s);
    }
    if let Some(c) = client.filter(|c| !c.is_empty()) {
        entry["client"] = json!(c);
    }
    write_line(&entry);
}

/// Append one entry as a single JSON line, then rotate if the file has grown large.
/// A single `write_all` (not `writeln!`) keeps the many client-spawned gateways that
/// share this file from interleaving each other's bytes into corrupt JSON.
fn write_line(entry: &Value) {
    let Some(path) = trace_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = file.write_all(format!("{entry}\n").as_bytes());
    }
    rotate_if_large(&path);
}

/// Keep only the most recent `KEEP_LINES` once the file exceeds the cap. Best-effort:
/// a failure never affects the search that triggered it.
fn rotate_if_large(path: &Path) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size <= MAX_TRACE_BYTES {
        return;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= KEEP_LINES {
        return;
    }
    let start = lines.len() - KEEP_LINES;
    let mut trimmed = lines[start..].join("\n");
    trimmed.push('\n');
    let _ = crate::registry::atomic_write(path, &trimmed);
}

/// The most recent `limit` traces, newest first.
pub fn read_recent(limit: usize) -> Vec<Value> {
    let Some(path) = trace_path() else {
        return Vec::new();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str(line).ok())
        .take(limit)
        .collect()
}

/// Delete the trace log (called when the user clears it from Activity).
pub fn clear() {
    if let Some(path) = trace_path() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // One file per machine, so these can't run concurrently. Serialize + reset.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn record_then_read_returns_newest_first() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        record(Some("cursor"), "list products", None, "stripe__list", &["stripe__list".into()], 1, 3, 120, 5000, false);
        record(None, "send email", Some("resend"), "resend__send", &["resend__send".into()], 1, 1, 90, 5000, false);
        let recent = read_recent(10);
        assert_eq!(recent.len(), 2);
        // Newest first.
        assert_eq!(recent[0]["query"], "send email");
        assert_eq!(recent[0]["server"], "resend");
        assert_eq!(recent[0]["savedTokens"], 5000 - 90);
        assert_eq!(recent[1]["query"], "list products");
        assert_eq!(recent[1]["client"], "cursor");
        assert_eq!(recent[1]["total"], 3);
        clear();
    }

    #[test]
    fn query_is_capped_and_names_are_limited() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        let long_q = "x".repeat(500);
        let many: Vec<String> = (0..40).map(|i| format!("srv__t{i}")).collect();
        record(None, &long_q, None, "srv__t0", &many, 40, 40, 100, 200, false);
        let e = &read_recent(1)[0];
        let stored_q = e["query"].as_str().unwrap();
        // Capped to MAX_QUERY_CHARS (+ the ellipsis), never the full 500.
        assert!(stored_q.chars().count() <= MAX_QUERY_CHARS + 1, "query not capped: {}", stored_q.chars().count());
        assert_eq!(e["names"].as_array().unwrap().len(), MAX_NAMES);
        clear();
    }

    #[test]
    fn no_match_search_is_still_recorded() {
        let _g = TEST_LOCK.lock().unwrap();
        clear();
        record(None, "nonexistent capability", None, "", &[], 0, 0, 0, 5000, false);
        let e = &read_recent(1)[0];
        assert_eq!(e["returned"], 0);
        assert_eq!(e["top"], "");
        // A miss still shows what a full catalog would have cost.
        assert_eq!(e["flatTokens"], 5000);
        clear();
    }
}
