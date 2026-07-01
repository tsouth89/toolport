//! Live request/response inspection: an opt-in, off-by-default local "network tab"
//! for MCP tool calls.
//!
//! This is the ONE place Conduit captures a tool call's arguments and result. It
//! is deliberately kept apart from the governance audit log (`audit.jsonl`), which
//! stays free of args/results forever. Capture only happens while the user has
//! `live_inspect` on; when it's off, nothing here is ever called and no file is
//! written.
//!
//! The capture is EPHEMERAL and BOUNDED:
//! - a separate file `inspect.jsonl`, ring-trimmed to the last 50 entries on every
//!   write, so it can never grow;
//! - each captured `request` and `response` is size-capped to ~4 KB of serialized
//!   JSON; anything larger is dropped and replaced with a short marker string, so a
//!   large body is never stored in full.
//!
//! Local only: like the audit log, this never leaves the machine.

use std::io::Write;
use std::path::PathBuf;

use serde_json::{json, Value};

/// How many of the most recent captured calls to keep. A small window: this is a
/// live inspector, not a log, so it stays tiny and ephemeral.
const KEEP_LINES: usize = 50;

/// Cap on a single captured `request` or `response`, in bytes of serialized JSON.
/// A body larger than this is dropped and replaced with a truncation marker, so the
/// full body is never written to disk.
const MAX_BODY_BYTES: usize = 4 * 1024;

pub fn inspect_path() -> Option<PathBuf> {
    // Same anchor as the registry/audit log, so the app and a client-spawned gateway
    // (which may run under MSIX virtualization) read and write the *same* file.
    Some(crate::registry::conduit_dir()?.join("inspect.jsonl"))
}

fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Return `value` unchanged if its serialized JSON fits in `max_bytes`, otherwise a
/// short marker string like `"<truncated 12345 bytes>"`. The full oversized body is
/// never returned, so it never reaches disk.
fn cap_json(value: &Value, max_bytes: usize) -> Value {
    let serialized = value.to_string();
    if serialized.len() <= max_bytes {
        value.clone()
    } else {
        json!(format!("<truncated {} bytes>", serialized.len()))
    }
}

/// Capture one tool call's request + response into the ephemeral inspect ring.
/// Only ever called while `live_inspect` is on. `request` and `response` are each
/// size-capped before being written; oversized bodies become a truncation marker.
pub fn record(
    client: Option<&str>,
    server: &str,
    tool: &str,
    request: &Value,
    response: &Value,
    ok: bool,
    duration_ms: u64,
) {
    let mut entry = json!({
        "ts": epoch_millis() as u64,
        "server": server,
        "tool": tool,
        "request": cap_json(request, MAX_BODY_BYTES),
        "response": cap_json(response, MAX_BODY_BYTES),
        "ok": ok,
        "durationMs": duration_ms,
    });
    if let Some(c) = client {
        if !c.is_empty() {
            entry["client"] = json!(c);
        }
    }
    write_line(&entry);
}

/// Append one entry as a single JSON line, then ring-trim to the last `KEEP_LINES`.
/// A single `write_all` (not `writeln!`, which can issue several write syscalls)
/// keeps the many client-spawned gateways that share this file from interleaving
/// each other's bytes into corrupt JSON.
fn write_line(entry: &Value) {
    let Some(path) = inspect_path() else {
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
    ring_trim(&path);
}

/// Keep only the most recent `KEEP_LINES` lines. Unlike the audit log (which trims
/// only past a size threshold), this ring trims on every write so the inspector
/// stays bounded to a tiny window. Best-effort: a failure never affects the call.
fn ring_trim(path: &std::path::Path) {
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

/// The most recent `limit` captured calls, newest first.
pub fn read_recent(limit: usize) -> Vec<Value> {
    let path = match inspect_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut entries: Vec<Value> = content
        .lines()
        .rev()
        .take(limit)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    entries.truncate(limit);
    entries
}

/// Clear the inspect ring (delete the file). Called when the user turns live
/// inspection off, so no captured args/results linger.
pub fn clear() {
    if let Some(path) = inspect_path() {
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The inspect file path is process-global (one file per machine), so these
    // tests can't run concurrently against it. Serialize them, and reset the file
    // at the start of each so they don't see each other's writes.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset() {
        clear();
    }

    #[test]
    fn record_then_read_recent_returns_it() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        record(
            Some("cursor"),
            "github",
            "search",
            &json!({ "q": "conduit" }),
            &json!({ "content": [{ "type": "text", "text": "hit" }] }),
            true,
            42,
        );
        let recent = read_recent(10);
        assert_eq!(recent.len(), 1);
        let e = &recent[0];
        assert_eq!(e["server"], "github");
        assert_eq!(e["tool"], "search");
        assert_eq!(e["client"], "cursor");
        assert_eq!(e["ok"], true);
        assert_eq!(e["durationMs"], 42);
        assert_eq!(e["request"]["q"], "conduit");
        assert_eq!(e["response"]["content"][0]["text"], "hit");
        reset();
    }

    #[test]
    fn ring_caps_at_fifty() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        for i in 0..60 {
            record(
                None,
                "srv",
                "tool",
                &json!({ "i": i }),
                &json!({ "ok": true }),
                true,
                1,
            );
        }
        let recent = read_recent(1000);
        // Ring-trimmed to the last 50, so only 50 remain...
        assert_eq!(recent.len(), 50);
        // ...and they are the most recent (i = 59 newest, i = 10 oldest kept).
        assert_eq!(recent[0]["request"]["i"], 59);
        assert_eq!(recent[49]["request"]["i"], 10);
        reset();
    }

    #[test]
    fn oversized_request_is_truncated_not_stored() {
        let _g = TEST_LOCK.lock().unwrap();
        reset();
        // A request whose serialized JSON is well over the 4 KB cap.
        let big = "x".repeat(8 * 1024);
        record(
            None,
            "srv",
            "tool",
            &json!({ "blob": big }),
            &json!({ "ok": true }),
            true,
            1,
        );
        let recent = read_recent(10);
        assert_eq!(recent.len(), 1);
        let req = &recent[0]["request"];
        // The full body is NOT stored: request collapses to the marker string.
        assert!(req.is_string(), "oversized request should be a marker string");
        let marker = req.as_str().unwrap();
        assert!(marker.starts_with("<truncated "), "got: {marker}");
        assert!(marker.contains("bytes>"));
        // And the giant blob is nowhere in the stored line.
        assert!(!recent[0].to_string().contains(&big));
        // The (small) response is stored intact.
        assert_eq!(recent[0]["response"]["ok"], true);
        reset();
    }

    #[test]
    fn cap_json_keeps_small_bodies() {
        let v = json!({ "a": 1 });
        assert_eq!(cap_json(&v, MAX_BODY_BYTES), v);
    }
}
