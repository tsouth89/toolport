//! Tool-call audit log.
//!
//! Every tool call routed through the gateway is appended here as one JSON line.
//! This is the artifact the governance/MSP story is built on: a record of which
//! AI tool invoked which server's tool, and when. Local and append-only.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Trim the log once it passes this size, so it can't grow without bound.
const MAX_AUDIT_BYTES: u64 = 4 * 1024 * 1024;
/// Cap on a stored error message. Enough to show why a call failed, bounded so a
/// pathological error string can't bloat the log line.
const MAX_AUDIT_ERR_CHARS: usize = 600;
/// How many of the most recent lines to keep when trimming. Comfortably more than
/// any dashboard window, so the trim is invisible to the stats/log views.
const KEEP_LINES: usize = 5000;

pub fn audit_path() -> Option<PathBuf> {
    // Same anchor as the registry, so the app and a client-spawned gateway (which
    // may run under MSIX virtualization) write to the *same* audit log.
    Some(crate::registry::conduit_dir()?.join("audit.jsonl"))
}

fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Append a tool-call record including how long the call took. Powers the
/// in-app latency/error-rate dashboard. `error` is a short message for a failed
/// call so the Activity view can show *why* it failed; it is an error string
/// only, never tool arguments or result data, which stay out of this
/// append-only governance log.
pub fn record_timed(
    server: &str,
    tool: &str,
    ok: bool,
    duration_ms: Option<u64>,
    error: Option<&str>,
) {
    let mut entry = json!({
        "ts": epoch_millis() as u64,
        "server": server,
        "tool": tool,
        "ok": ok,
    });
    if let Some(ms) = duration_ms {
        entry["durationMs"] = json!(ms);
    }
    if !ok {
        if let Some(err) = error {
            let trimmed: String = err.trim().chars().take(MAX_AUDIT_ERR_CHARS).collect();
            if !trimmed.is_empty() {
                entry["error"] = json!(trimmed);
            }
        }
    }
    if let Some(path) = audit_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(file, "{entry}");
        }
        // File handle dropped above; safe to rewrite the path now.
        rotate_if_large(&path);
    }
}

/// Trim the audit log to its most recent `KEEP_LINES` lines once it exceeds the
/// size cap, so it stays bounded over months of use. Best-effort: a failure here
/// never affects the call being logged.
fn rotate_if_large(path: &Path) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size <= MAX_AUDIT_BYTES {
        return;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        let trimmed = trimmed_tail(&content, KEEP_LINES);
        // Atomic + unique temp: every client's gateway shares this file, so a
        // bespoke fixed temp name could let two rotations collide.
        let _ = crate::registry::atomic_write(path, &trimmed);
    }
}

/// Keep the last `keep` non-empty lines of `content`, newline-terminated.
fn trimmed_tail(content: &str, keep: usize) -> String {
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(keep);
    let mut out = lines[start..].join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// The most recent `limit` entries, newest first.
pub fn read_recent(limit: usize) -> Vec<Value> {
    let path = match audit_path() {
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
    // `rev().take()` gives newest-first already.
    entries.truncate(limit);
    entries
}

/// Average and 95th-percentile of a duration sample, in ms. `None` when the
/// sample is empty (e.g. older records logged before latency was tracked).
fn latency(durs: &mut [u64]) -> (Option<u64>, Option<u64>) {
    if durs.is_empty() {
        return (None, None);
    }
    let sum: u64 = durs.iter().sum();
    let avg = sum / durs.len() as u64;
    durs.sort_unstable();
    // Nearest-rank p95.
    let idx = (((durs.len() as f64) * 0.95).ceil() as usize)
        .saturating_sub(1)
        .min(durs.len() - 1);
    (Some(avg), Some(durs[idx]))
}

/// Aggregate the last `window` calls into per-server stats plus global totals.
/// This is the data behind the observability dashboard: call volume, error
/// rate, and latency per server, computed locally from the audit log.
pub fn stats(window: usize) -> Value {
    aggregate(&read_recent(window))
}

/// Pure aggregation of audit entries into per-server + global stats. Split from
/// `stats` so the dashboard math is testable without touching the on-disk log.
fn aggregate(entries: &[Value]) -> Value {
    use std::collections::HashMap;

    #[derive(Default)]
    struct ToolAgg {
        calls: u64,
        errors: u64,
        durs: Vec<u64>,
        last_ts: u64,
    }

    #[derive(Default)]
    struct Agg {
        calls: u64,
        errors: u64,
        durs: Vec<u64>,
        last_ts: u64,
        tools: HashMap<String, ToolAgg>,
    }

    let mut by_server: HashMap<String, Agg> = HashMap::new();
    let mut total = 0u64;
    let mut errors = 0u64;

    for e in entries {
        let server = e.get("server").and_then(|v| v.as_str()).unwrap_or("?");
        let tool = e.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
        let ok = e.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
        let ts = e.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let dur = e.get("durationMs").and_then(|v| v.as_u64());

        total += 1;
        if !ok {
            errors += 1;
        }
        let a = by_server.entry(server.to_string()).or_default();
        a.calls += 1;
        if !ok {
            a.errors += 1;
        }
        if let Some(d) = dur {
            a.durs.push(d);
        }
        a.last_ts = a.last_ts.max(ts);

        let t = a.tools.entry(tool.to_string()).or_default();
        t.calls += 1;
        if !ok {
            t.errors += 1;
        }
        if let Some(d) = dur {
            t.durs.push(d);
        }
        t.last_ts = t.last_ts.max(ts);
    }

    let mut servers: Vec<Value> = by_server
        .into_iter()
        .map(|(server, mut a)| {
            let (avg, p95) = latency(&mut a.durs);
            // Per-tool breakdown, busiest tool first.
            let mut tools: Vec<Value> = a
                .tools
                .into_iter()
                .map(|(tool, mut t)| {
                    let (tavg, tp95) = latency(&mut t.durs);
                    json!({
                        "tool": tool,
                        "calls": t.calls,
                        "errors": t.errors,
                        "errorRate": if t.calls > 0 { t.errors as f64 / t.calls as f64 } else { 0.0 },
                        "avgMs": tavg,
                        "p95Ms": tp95,
                        "lastTs": t.last_ts,
                    })
                })
                .collect();
            tools.sort_by(|x, y| {
                y.get("calls")
                    .and_then(|v| v.as_u64())
                    .cmp(&x.get("calls").and_then(|v| v.as_u64()))
            });
            json!({
                "server": server,
                "calls": a.calls,
                "errors": a.errors,
                "errorRate": if a.calls > 0 { a.errors as f64 / a.calls as f64 } else { 0.0 },
                "avgMs": avg,
                "p95Ms": p95,
                "lastTs": a.last_ts,
                "tools": tools,
            })
        })
        .collect();
    // Busiest servers first.
    servers.sort_by(|x, y| {
        y.get("calls")
            .and_then(|v| v.as_u64())
            .cmp(&x.get("calls").and_then(|v| v.as_u64()))
    });

    json!({
        "total": total,
        "errors": errors,
        "errorRate": if total > 0 { errors as f64 / total as f64 } else { 0.0 },
        "servers": servers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_avg_and_p95() {
        let mut d = vec![10u64, 20, 30, 40, 100];
        let (avg, p95) = latency(&mut d);
        assert_eq!(avg, Some(40)); // (10+20+30+40+100)/5
        assert_eq!(p95, Some(100)); // nearest-rank p95 of 5 samples = last
        let (a, p) = latency(&mut []);
        assert_eq!((a, p), (None, None));
    }

    #[test]
    fn aggregate_groups_and_sorts_by_volume() {
        let entries = vec![
            json!({"server":"github","ok":true,"ts":100,"durationMs":10}),
            json!({"server":"github","ok":false,"ts":200,"durationMs":30}),
            json!({"server":"stripe","ok":true,"ts":150,"durationMs":20}),
            json!({"server":"github","ok":true,"ts":50}), // no duration
        ];
        let s = aggregate(&entries);
        assert_eq!(s["total"], 4);
        assert_eq!(s["errors"], 1);
        assert_eq!(s["errorRate"], 0.25);

        let servers = s["servers"].as_array().unwrap();
        // Busiest first: github (3 calls) before stripe (1).
        assert_eq!(servers[0]["server"], "github");
        assert_eq!(servers[0]["calls"], 3);
        assert_eq!(servers[0]["errors"], 1);
        assert_eq!(servers[0]["lastTs"], 200);
        assert_eq!(servers[0]["avgMs"], 20); // only the two durations: (10+30)/2
        assert_eq!(servers[1]["server"], "stripe");
        assert_eq!(servers[1]["calls"], 1);
    }

    #[test]
    fn aggregate_breaks_down_by_tool() {
        let entries = vec![
            json!({"server":"github","tool":"search","ok":true,"ts":10,"durationMs":10}),
            json!({"server":"github","tool":"search","ok":false,"ts":20,"durationMs":30}),
            json!({"server":"github","tool":"create_issue","ok":true,"ts":15,"durationMs":50}),
        ];
        let s = aggregate(&entries);
        let tools = s["servers"][0]["tools"].as_array().unwrap();
        // Busiest tool first: search (2 calls) before create_issue (1).
        assert_eq!(tools[0]["tool"], "search");
        assert_eq!(tools[0]["calls"], 2);
        assert_eq!(tools[0]["errors"], 1);
        assert_eq!(tools[0]["avgMs"], 20); // (10+30)/2
        assert_eq!(tools[1]["tool"], "create_issue");
        assert_eq!(tools[1]["calls"], 1);
    }

    #[test]
    fn aggregate_handles_empty() {
        let s = aggregate(&[]);
        assert_eq!(s["total"], 0);
        assert_eq!(s["errorRate"], 0.0);
        assert_eq!(s["servers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn trimmed_tail_keeps_last_n_lines() {
        assert_eq!(trimmed_tail("a\nb\nc\nd\ne\n", 2), "d\ne\n");
        // Fewer lines than the cap -> unchanged (re-normalized with trailing \n).
        assert_eq!(trimmed_tail("x\ny\n", 5), "x\ny\n");
        // Blank lines are dropped.
        assert_eq!(trimmed_tail("a\n\n\nb\n", 5), "a\nb\n");
        assert_eq!(trimmed_tail("", 5), "");
    }
}
