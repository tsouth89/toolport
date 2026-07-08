//! Lazy-discovery savings counter.
//!
//! Every time the gateway serves a lazy `tools/list` it advertises 4 meta-tools
//! instead of the full catalog. The difference, the tool-definition tokens kept
//! out of the client's context, is appended here as one JSON line. The app sums
//! the log into the in-app "tokens saved" counter.
//!
//! Like the audit log this is append-only, because each connected client spawns
//! its own gateway process: concurrent `O_APPEND` writes of one small line are
//! safe, whereas a read-modify-write counter would race and lose updates.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Trim the log once it passes this size. A line is ~60 bytes and a serve happens
/// per client connection (not per request), so this is years of headroom.
const MAX_SAVINGS_BYTES: u64 = 1024 * 1024;
/// Recent detail lines kept on rotation; older lines collapse into one carry line
/// so the cumulative total survives trimming.
const KEEP_LINES: usize = 2000;

fn savings_path() -> Option<PathBuf> {
    // Same anchor as the registry/audit log, so the app and every client-spawned
    // gateway (some under MSIX virtualization) read and write the same file.
    Some(crate::registry::conduit_dir()?.join("savings.jsonl"))
}

fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Rough token estimate for a set of tool definitions: serialized JSON length
/// over 4. Deliberately an estimate (the in-app counter is labeled "≈"); it
/// avoids bundling a tokenizer into the gateway.
pub fn estimate_tokens(tools: &[Value]) -> u64 {
    let chars: usize = tools
        .iter()
        .filter_map(|t| serde_json::to_string(t).ok())
        .map(|s| s.len())
        .sum();
    chars.div_ceil(4) as u64
}

/// Per-server share of a catalog's tool-def tokens, resolved through `route` (the
/// router's exposed-name -> server mapping). Tools `route` can't place are skipped:
/// mis-attributing tokens to a wrongly split server id would be worse than
/// under-counting, and route_of only misses tools that just vanished from the routes.
pub fn per_server_tokens(
    tools: &[Value],
    route: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, u64> {
    let mut by_server: BTreeMap<String, u64> = BTreeMap::new();
    for t in tools {
        let Some(server) = t.get("name").and_then(Value::as_str).and_then(&route) else {
            continue;
        };
        let tokens = estimate_tokens(std::slice::from_ref(t));
        *by_server.entry(server).or_insert(0) += tokens;
    }
    by_server
}

/// Record one lazy serve: the full catalog's tool-def tokens minus the meta-tools'.
/// No-op when there's nothing to save (empty catalog / non-lazy never calls this).
/// `by_server` attributes the catalog's tokens to their servers so team usage
/// reporting can build per-server rows; empty (old callers, no routes) is fine and
/// simply leaves this serve out of the per-server rollup.
pub fn record(full_tokens: u64, meta_tokens: u64, catalog_tools: u64, by_server: BTreeMap<String, u64>) {
    let saved = full_tokens.saturating_sub(meta_tokens);
    if saved == 0 {
        return;
    }
    let mut entry = json!({ "ts": epoch_millis() as u64, "saved": saved, "tools": catalog_tools });
    if !by_server.is_empty() {
        entry["byServer"] = json!(by_server);
    }
    if let Some(path) = savings_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            // Single write_all (not writeln!) so concurrent client-spawned gateways
            // can't interleave bytes into corrupt JSON lines.
            let _ = file.write_all(format!("{entry}\n").as_bytes());
        }
        rotate_if_large(&path);
    }
}

/// Collapse old lines into a single carry line once the log exceeds the cap, so
/// the running total is preserved while the file stays bounded. Best-effort.
fn rotate_if_large(path: &Path) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size <= MAX_SAVINGS_BYTES {
        return;
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() <= KEEP_LINES {
        return;
    }
    let split = lines.len() - KEEP_LINES;
    let dropped: Vec<Value> = lines[..split]
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let carry = fold(&dropped); // one line summarizing everything being trimmed
    let mut out = carry.to_string();
    out.push('\n');
    out.push_str(&lines[split..].join("\n"));
    out.push('\n');
    // Atomic + unique temp: every client's gateway shares this file, so a
    // bespoke fixed temp name could let two rotations collide.
    let _ = crate::registry::atomic_write(path, &out);
}

/// Fold entries into a single carry record that the reader sums like any other
/// line: it preserves the saved total, the load count, the peak catalog, and the
/// earliest timestamp.
fn fold(entries: &[Value]) -> Value {
    let mut saved = 0u64;
    let mut loads = 0u64;
    let mut peak = 0u64;
    let mut since = 0u64;
    for e in entries {
        saved = saved.saturating_add(e.get("saved").and_then(Value::as_u64).unwrap_or(0));
        loads = loads.saturating_add(e.get("loads").and_then(Value::as_u64).unwrap_or(1));
        peak = peak.max(e.get("tools").and_then(Value::as_u64).unwrap_or(0));
        let ts = e.get("ts").and_then(Value::as_u64).unwrap_or(0);
        if ts > 0 && (since == 0 || ts < since) {
            since = ts;
        }
    }
    json!({ "ts": since, "saved": saved, "tools": peak, "loads": loads })
}

/// Every savings line on disk, oldest first (bounded by rotation). Shared by the
/// in-app counter and the team usage rollup.
pub fn entries() -> Vec<Value> {
    savings_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|c| {
            c.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Cumulative savings for the in-app counter.
pub fn summary() -> Value {
    aggregate(&entries())
}

/// Pure aggregation, split out so the math is testable without touching disk.
/// A normal line counts as one load; a carry line carries its own `loads`.
fn aggregate(entries: &[Value]) -> Value {
    let folded = fold(entries);
    json!({
        "tokensSaved": folded.get("saved").and_then(Value::as_u64).unwrap_or(0),
        "listLoads": folded.get("loads").and_then(Value::as_u64).unwrap_or(0),
        "peakCatalog": folded.get("tools").and_then(Value::as_u64).unwrap_or(0),
        "sinceTs": folded.get("ts").and_then(Value::as_u64).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_is_serialized_len_over_four() {
        // {"name":"x"} is 12 chars -> ceil(12/4) = 3.
        let tools = vec![json!({ "name": "x" })];
        assert_eq!(estimate_tokens(&tools), 3);
        assert_eq!(estimate_tokens(&[]), 0);
    }

    #[test]
    fn aggregate_sums_saved_and_counts_loads() {
        let entries = vec![
            json!({ "ts": 200, "saved": 100, "tools": 50 }),
            json!({ "ts": 100, "saved": 60, "tools": 80 }),
            json!({ "ts": 300, "saved": 40, "tools": 30 }),
        ];
        let s = aggregate(&entries);
        assert_eq!(s["tokensSaved"], 200); // 100 + 60 + 40
        assert_eq!(s["listLoads"], 3);
        assert_eq!(s["peakCatalog"], 80); // biggest catalog collapsed
        assert_eq!(s["sinceTs"], 100); // earliest
    }

    #[test]
    fn carry_line_preserves_totals_after_rotation() {
        // A folded carry line plus fresh detail lines aggregates the same as if
        // nothing had been trimmed.
        let detail = [
            json!({ "ts": 10, "saved": 100, "tools": 40 }),
            json!({ "ts": 20, "saved": 100, "tools": 90 }),
            json!({ "ts": 30, "saved": 100, "tools": 50 }),
        ];
        let carry = fold(&detail[..2]); // collapse the first two
        let after = vec![carry, detail[2].clone()];
        let s = aggregate(&after);
        assert_eq!(s["tokensSaved"], 300); // total survives the fold
        assert_eq!(s["listLoads"], 3); // 2 folded + 1 fresh
        assert_eq!(s["peakCatalog"], 90);
        assert_eq!(s["sinceTs"], 10);
    }

    #[test]
    fn aggregate_handles_empty() {
        let s = aggregate(&[]);
        assert_eq!(s["tokensSaved"], 0);
        assert_eq!(s["listLoads"], 0);
        assert_eq!(s["sinceTs"], 0);
    }
}
