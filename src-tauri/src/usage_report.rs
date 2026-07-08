//! Team usage rollup: per-server daily counts from the local gateway logs.
//!
//! Builds the rows a member reports to their own team's server for showback
//! (`POST /teams/{id}/usage`). Everything here is counts and estimates derived
//! from the same `audit.jsonl` / `savings.jsonl` the in-app dashboards read:
//! tool names, arguments, results, and secrets never leave the machine, and only
//! servers the team itself distributed (`source = "team:<id>"`) are ever counted.
//! This reports to the member's own team server, not to any vendor endpoint; a
//! user who never joins a team never triggers it.

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

/// Estimated $ per million tool-definition tokens kept out of context. Matches
/// the in-app savings banner's default model (Claude Sonnet list input rate);
/// the Teams dashboards label the figure "estimated, at list input rates".
pub const EST_DOLLARS_PER_MTOK: f64 = 3.0;

/// One per-server rollup row: tool calls routed + tool-def tokens kept out of
/// agent context. The dollar figure is derived, not stored (see [`est_cost`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub calls: u64,
    pub tokens_saved: u64,
}

/// The estimated dollar value of `tokens` tool-definition tokens.
pub fn est_cost(tokens: u64) -> f64 {
    (tokens as f64 / 1_000_000.0) * EST_DOLLARS_PER_MTOK
}

/// "YYYY-MM-DD" (UTC) for an epoch-milliseconds timestamp. Days are bucketed in
/// UTC so every member of a team lands in the same bucket regardless of local
/// timezone or DST, and so the key is stable across a machine's TZ changes.
pub fn utc_day(ts_millis: u64) -> String {
    let (y, m, d) = civil_from_days((ts_millis / 86_400_000) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The current UTC day, `offset_back` days ago (0 = today, 1 = yesterday).
pub fn utc_day_back(offset_back: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    utc_day(now.saturating_sub(offset_back * 86_400_000))
}

/// Days-since-epoch -> (year, month, day), proleptic Gregorian. Howard Hinnant's
/// `civil_from_days`; used instead of pulling a date crate in for one function.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m as u32, d)
}

/// Roll audit + savings lines up into per-server rows for one UTC day, counting
/// only `team_servers`. Pure so the math is testable without touching disk; the
/// caller feeds it the on-disk lines (see `teams::report_usage`).
///
/// Calls count every routed attempt, failed ones included: the dashboard figure
/// is "tool calls routed through the gateway", and a failed downstream call was
/// still routed. Savings lines carry a `byServer` token map (new format); lines
/// without one (pre-attribution builds, rotation carry lines) still count in the
/// in-app total but can't be placed per server, so they are skipped here.
pub fn rollup(
    day: &str,
    audit_lines: &[Value],
    savings_lines: &[Value],
    team_servers: &HashSet<String>,
) -> BTreeMap<String, Row> {
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    let ts_day = |e: &Value| -> bool {
        e.get("ts")
            .and_then(Value::as_u64)
            .is_some_and(|ts| utc_day(ts) == day)
    };
    for e in audit_lines.iter().filter(|e| ts_day(e)) {
        let Some(server) = e.get("server").and_then(Value::as_str) else {
            continue;
        };
        if !team_servers.contains(server) {
            continue;
        }
        rows.entry(server.to_string()).or_default().calls += 1;
    }
    for e in savings_lines.iter().filter(|e| ts_day(e)) {
        let Some(by_server) = e.get("byServer").and_then(Value::as_object) else {
            continue;
        };
        for (server, tokens) in by_server {
            if !team_servers.contains(server.as_str()) {
                continue;
            }
            let row = rows.entry(server.clone()).or_default();
            row.tokens_saved = row
                .tokens_saved
                .saturating_add(tokens.as_u64().unwrap_or(0));
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn team(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    // 2026-07-08 00:30:00 UTC and a minute later (2026-07-08T00:00Z = 20,642 days
    // since epoch = 1_783_468_800_000 ms).
    const TS_A: u64 = 1_783_470_600_000;
    const TS_B: u64 = 1_783_470_660_000;

    #[test]
    fn utc_day_formats_and_buckets() {
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(TS_A), "2026-07-08");
        // One millisecond before midnight stays on the previous day.
        assert_eq!(utc_day(1_783_468_799_999), "2026-07-07");
        assert_eq!(utc_day(1_783_468_800_000), "2026-07-08");
    }

    #[test]
    fn rollup_counts_team_calls_only_for_the_day() {
        let audit = vec![
            json!({ "ts": TS_A, "server": "github", "tool": "list", "ok": true }),
            json!({ "ts": TS_B, "server": "github", "tool": "get", "ok": false }), // failed calls count: still routed
            json!({ "ts": TS_A, "server": "personal", "tool": "x", "ok": true }), // not a team server
            json!({ "ts": TS_A - 86_400_000, "server": "github", "tool": "x", "ok": true }), // yesterday
        ];
        let rows = rollup("2026-07-08", &audit, &[], &team(&["github", "stripe"]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows["github"], Row { calls: 2, tokens_saved: 0 });
    }

    #[test]
    fn rollup_attributes_savings_by_server_and_skips_unattributed_lines() {
        let savings = vec![
            json!({ "ts": TS_A, "saved": 900, "tools": 10, "byServer": { "github": 500, "personal": 300 } }),
            json!({ "ts": TS_B, "saved": 100, "tools": 10, "byServer": { "github": 80 } }),
            json!({ "ts": TS_A, "saved": 777, "tools": 10 }), // legacy line, no attribution
        ];
        let rows = rollup("2026-07-08", &[], &savings, &team(&["github"]));
        assert_eq!(rows["github"], Row { calls: 0, tokens_saved: 580 });
        assert!(!rows.contains_key("personal"));
    }

    #[test]
    fn rollup_merges_calls_and_savings_for_one_server() {
        let audit = vec![json!({ "ts": TS_A, "server": "github", "tool": "t", "ok": true })];
        let savings =
            vec![json!({ "ts": TS_B, "saved": 50, "tools": 3, "byServer": { "github": 40 } })];
        let rows = rollup("2026-07-08", &audit, &savings, &team(&["github"]));
        assert_eq!(rows["github"], Row { calls: 1, tokens_saved: 40 });
    }

    #[test]
    fn est_cost_is_list_rate_per_million() {
        assert_eq!(est_cost(0), 0.0);
        assert_eq!(est_cost(1_000_000), EST_DOLLARS_PER_MTOK);
    }
}
