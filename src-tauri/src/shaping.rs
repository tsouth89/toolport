//! Result-shaping: keep oversized tool results from blowing the model's context
//! WITHOUT losing data. When a downstream tool returns a result larger than the
//! byte budget, the full body is cached in-process and the model gets a truncated
//! head plus a Conduit-stamped marker carrying a cursor. `conduit_fetch_result`
//! pages through the cached full result. Lossless: nothing is dropped, only
//! deferred, and the full data stays retrievable.
//!
//! This is the "other half" of the token story: lazy discovery trims tool
//! DEFINITION bloat; this trims tool RESULT bloat (a 10k-row response that would
//! otherwise sit in context). The gateway is the one place that can impose it
//! across every server, including legacy APIs with no native pagination.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Results whose serialized size exceeds this get shaped. Generous on purpose, so
/// only genuinely large results are touched. Override with `CONDUIT_RESULT_BUDGET`
/// (bytes); set it to 0 to disable shaping entirely.
pub const DEFAULT_BUDGET_BYTES: usize = 48 * 1024;

/// How long a cached full result stays fetchable.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Resolve the byte budget from the env override, falling back to the default.
/// 0 disables shaping (every result is treated as under budget).
pub fn budget() -> usize {
    std::env::var("CONDUIT_RESULT_BUDGET")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_BUDGET_BYTES)
}

struct Cached {
    body: String,
    at: Instant,
}

fn cache() -> &'static Mutex<HashMap<String, Cached>> {
    static C: OnceLock<Mutex<HashMap<String, Cached>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_cursor() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!("r{}", N.fetch_add(1, Ordering::Relaxed))
}

fn sweep(map: &mut HashMap<String, Cached>) {
    map.retain(|_, c| c.at.elapsed() < CACHE_TTL);
}

/// Concatenate the model-facing text of an MCP tool result's content blocks, then
/// fold in `structuredContent` so nothing is lost when the structured payload is
/// the bloat.
fn extract_body(result: &Value) -> String {
    let mut out = String::new();
    if let Some(blocks) = result.get("content").and_then(|c| c.as_array()) {
        for b in blocks {
            if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(t);
            }
        }
    }
    if let Some(sc) = result.get("structuredContent") {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(sc).unwrap_or_default());
    }
    out
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

/// If `result` serializes to more than `budget` bytes, cache its full body, replace
/// it with a truncated head + a stamped cursor marker, and return `true` (shaped).
/// A `budget` of 0 disables shaping. Lossless: the full body stays fetchable via
/// [`fetch_result`].
pub fn shape_result(result: &mut Value, budget: usize) -> bool {
    if budget == 0 {
        return false;
    }
    let size = serde_json::to_string(result).map(|s| s.len()).unwrap_or(0);
    if size <= budget {
        return false;
    }

    let body = extract_body(result);
    let total = body.chars().count();
    // Reserve room for the marker, then show the head of the body.
    let head_chars = budget.saturating_sub(512).max(256).min(total);
    let head: String = body.chars().take(head_chars).collect();
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let cursor = next_cursor();
    {
        let mut map = cache().lock().unwrap();
        sweep(&mut map);
        map.insert(
            cursor.clone(),
            Cached {
                body,
                at: Instant::now(),
            },
        );
    }

    let marker = format!(
        "\n\n[Conduit shaped this result: it was ~{} KB, larger than the {} KB context \
         budget. Showing the first {} of {} characters. The full result is cached, call \
         conduit_fetch_result with {{\"cursor\":\"{}\",\"offset\":{}}} to read the rest. \
         Nothing was lost.]",
        size / 1024,
        budget / 1024,
        head_chars,
        total,
        cursor,
        head_chars
    );
    *result = text_result(format!("{head}{marker}"), is_error);
    true
}

/// Return the next slice of a cached shaped result, by cursor + character offset.
/// `len` of 0 means "use the current budget".
pub fn fetch_result(cursor: &str, offset: usize, len: usize) -> Value {
    let mut map = cache().lock().unwrap();
    sweep(&mut map);
    let Some(c) = map.get(cursor) else {
        return text_result(
            format!(
                "[Conduit: cursor \"{cursor}\" is unknown or expired. Re-run the original \
                 tool call to get a fresh result.]"
            ),
            true,
        );
    };
    let chars: Vec<char> = c.body.chars().collect();
    let total = chars.len();
    if offset >= total {
        return text_result(
            format!(
                "[Conduit: offset {offset} is at or past the end of the result ({total} \
                 characters). Nothing more to read.]"
            ),
            false,
        );
    }
    let len = if len == 0 { budget() } else { len };
    let end = (offset + len).min(total);
    let slice: String = chars[offset..end].iter().collect();
    let remaining = total - end;
    let footer = if remaining > 0 {
        format!(
            "\n\n[Conduit: characters {offset}..{end} of {total}. {remaining} remain, call \
             conduit_fetch_result with offset={end} for the next slice.]"
        )
    } else {
        format!("\n\n[Conduit: end of result ({total} characters).]")
    };
    text_result(format!("{slice}{footer}"), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big_text_result(n: usize) -> Value {
        json!({ "content": [{ "type": "text", "text": "x".repeat(n) }], "isError": false })
    }

    #[test]
    fn under_budget_is_untouched() {
        let mut r = big_text_result(100);
        assert!(!shape_result(&mut r, 1024));
        assert_eq!(r["content"][0]["text"].as_str().unwrap().len(), 100);
    }

    #[test]
    fn over_budget_truncates_and_caches() {
        let mut r = big_text_result(10_000);
        assert!(shape_result(&mut r, 2048));
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("conduit_fetch_result"));
        assert!(text.len() < 10_000);
        // The marker carries a cursor that fetch_result can page.
        assert!(text.contains("\"cursor\":\"r"));
    }

    #[test]
    fn budget_zero_disables() {
        let mut r = big_text_result(10_000);
        assert!(!shape_result(&mut r, 0));
    }

    #[test]
    fn fetch_pages_the_remainder() {
        let mut r = big_text_result(10_000);
        shape_result(&mut r, 2048);
        // Pull the cursor back out of the marker.
        let text = r["content"][0]["text"].as_str().unwrap();
        let cursor = text
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        let more = fetch_result(&cursor, 1500, 500);
        let mt = more["content"][0]["text"].as_str().unwrap();
        assert!(mt.contains("of 10000"));
    }

    #[test]
    fn fetch_unknown_cursor_is_an_error() {
        let v = fetch_result("nope", 0, 100);
        assert_eq!(v["isError"].as_bool(), Some(true));
    }
}
