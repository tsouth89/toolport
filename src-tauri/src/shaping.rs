//! Result-shaping: keep oversized tool results from blowing the model's context
//! WITHOUT losing data. When a downstream tool returns a result larger than the
//! byte budget, the full body is cached in-process and the model gets a truncated
//! head plus a Toolport-stamped marker carrying a cursor. `conduit_fetch_result`
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

/// Cap on the number of cached shaped results. A burst of large tool calls would
/// otherwise grow process memory without bound between lazy TTL sweeps. Oldest
/// entries (by insertion time) are evicted first.
const MAX_CACHE_ENTRIES: usize = 64;

/// Cap on total cached body bytes. Evict oldest until a new body fits, or the
/// cache is empty (then one over-cap body is kept rather than dropping the result
/// the caller just produced).
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;

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
    structured: Option<Value>,
    /// The entry's total serialized size (`body` + structured JSON), computed once at
    /// insert. The eviction loop sums this across entries on every oversized call, so
    /// caching it avoids re-serializing every structured payload on each iteration.
    size: usize,
    at: Instant,
    /// The client the result belongs to (a registered HTTP client's label), or None
    /// for the single-tenant stdio process. Only this client may fetch it back.
    owner: Option<String>,
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

fn value_size(value: &Value) -> usize { 
    serde_json::to_string(value) .map(|s| s.len()) .unwrap_or(0) 
}

fn text_result(text: String, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn project<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;

    for segment in path.split('.') {
        if let Some(object) = current.as_object() {
            current = object.get(segment)?;
        } else if let Some(array) = current.as_array() {
            let index = segment.parse::<usize>().ok()?;
            current = array.get(index)?;
        } else {
            return None;
        }
    }

    Some(current)
}

/// The longest char-boundary prefix of `s` whose UTF-8 length is at most
/// `max_bytes`. Truncating by char COUNT alone would let a multi-byte body (CJK,
/// emoji) emit several times the byte budget; this honors the byte budget exactly
/// while never splitting a code point.
fn head_within_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = 0;
    for (i, ch) in s.char_indices() {
        let next = i + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    &s[..end]
}

/// True if every content block is text, so the text projection in [`extract_body`]
/// represents the result losslessly. A block with no `text` field is non-text
/// (image, audio, resource, resource_link); shaping would silently drop it, so such
/// results are left whole.
fn is_text_representable(result: &Value) -> bool {
    match result.get("content").and_then(|c| c.as_array()) {
        Some(blocks) => blocks
            .iter()
            .all(|b| b.get("text").and_then(|t| t.as_str()).is_some()),
        None => true,
    }
}

/// If `result` serializes to more than `budget` bytes, cache its full body, replace
/// it with a truncated head + a stamped cursor marker, and return `true` (shaped).
/// A `budget` of 0 disables shaping. Lossless: the full body stays fetchable via
/// [`fetch_result`].
pub fn shape_result(result: &mut Value, budget: usize, owner: Option<&str>) -> bool {
    if budget == 0 {
        return false;
    }
    let size = serde_json::to_string(result).map(|s| s.len()).unwrap_or(0);
    if size <= budget {
        return false;
    }

    // Only shape what we can represent losslessly as a text head. If the result has
    // non-text blocks, or its size is dominated by non-body envelope (the text
    // projection captures under half the bytes), shaping would drop data and its
    // "nothing was lost" claim would be false. Pass those through untouched.
    let body = extract_body(result);
    if !is_text_representable(result) || body.len() < size / 2 {
        return false;
    }
    let structured = result.get("structuredContent").cloned();

    let total = body.chars().count();
    // Reserve room for the marker, then show as much of the body head as fits the
    // BYTE budget (not a char count, or multi-byte text would blow past it).
    let head_byte_limit = budget.saturating_sub(512).max(256);
    let head = head_within_bytes(&body, head_byte_limit).to_string();
    let head_chars = head.chars().count();
    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let cursor = next_cursor();
    let new_entry_size = body.len() + structured.as_ref().map(value_size).unwrap_or(0);

    {
        let mut map = cache().lock().unwrap_or_else(|e| e.into_inner());
        sweep(&mut map);

        // Bound memory: evict oldest until the entry count and total bytes leave
        // room for this cached result (or the cache empties, keeping one over-cap
        // result). Each entry's `size` is precomputed, so this sum is O(n) adds, not
        // O(n) JSON re-serializations, on every iteration.
        while !map.is_empty()
            && (map.len() >= MAX_CACHE_ENTRIES
                || map.values().map(|c| c.size).sum::<usize>() + new_entry_size > MAX_CACHE_BYTES)
        {
            let Some(oldest) = map.iter().min_by_key(|(_, c)| c.at).map(|(k, _)| k.clone()) else {
                break;
            };
            map.remove(&oldest);
        }

        map.insert(
            cursor.clone(),
            Cached {
                body,
                structured,
                size: new_entry_size,
                at: Instant::now(),
                owner: owner.map(str::to_string),
            },
        );
    }
    let marker = format!(
        "\n\n[Toolport shaped this result: it was ~{} KB, larger than the {} KB context \
         budget. Showing the first {} of {} characters. The rest is held temporarily, call \
         conduit_fetch_result with {{\"cursor\":\"{}\",\"offset\":{}}} to read it. If that \
         later reports the cursor expired, just re-run this tool call for a fresh result.]",
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
pub fn fetch_result(cursor: &str, offset: usize, len: usize, requester: Option<&str>, projection: Option<&str>,) -> Value {
    let mut map = cache().lock().unwrap_or_else(|e| e.into_inner());
    sweep(&mut map);
    // Scope: a cached result is readable only by the client that stashed it. A mismatch
    // returns the SAME "unknown or expired" answer as a missing cursor, so a scoped
    // client can't probe which cursors exist. This matters because the stash is
    // process-global, and in HTTP mode one gateway serves every registered client;
    // without this check a client could read another tenant's result by guessing the
    // sequential `r{n}` cursor.
    let c = match map.get(cursor) {
        Some(c) if c.owner.as_deref() == requester => c,
        _ => {
            return text_result(
                format!(
                    "[Toolport: cursor \"{cursor}\" is unknown or expired. Re-run the original \
                     tool call to get a fresh result.]"
                ),
                true,
            );
        }
    };
    if let Some(path) = projection {
    let structured = match &c.structured {
        Some(value) => value,
        None => {
            return text_result(
                "[Toolport: this cached result has no structuredContent.]".to_string(),
                true,
            );
        }
    };

    let value = match project(structured, path) {
        Some(value) => value,
        None => {
            return text_result(
                format!("[Toolport: projection \"{path}\" not found.]"),
                true,
            );
        }
    };

    return text_result(
        serde_json::to_string(value).unwrap_or_default(),
        false,
    );
}
    let total = c.body.chars().count();
    if offset >= total {
        return text_result(
            format!(
                "[Toolport: offset {offset} is at or past the end of the result ({total} \
                 characters). Nothing more to read.]"
            ),
            false,
        );
    }
    let len = if len == 0 { budget() } else { len };
    // saturating_add: a client-supplied `len` near usize::MAX must not overflow
    // `offset + len`. On debug that panics; on release it wraps to `end < offset`,
    // and the byte-mapping below then slices `body[start_byte..end_byte]` with
    // start > end - a panic that, on the stdio transport (no catch_unwind), takes
    // down the whole gateway. Saturating clamps `end` to `total` instead.
    let end = offset.saturating_add(len).min(total);
    // Map the character window [offset, end) to byte offsets in a single pass, so a
    // page read never allocates a Vec<char> of the whole (possibly multi-MB) body.
    // `end == total` leaves end_byte at the body's byte length (the loop never yields
    // char index `total`), so the last page runs cleanly to the end.
    let mut start_byte = c.body.len();
    let mut end_byte = c.body.len();
    for (char_idx, (byte_idx, _)) in c.body.char_indices().enumerate() {
        if char_idx == offset {
            start_byte = byte_idx;
        }
        if char_idx == end {
            end_byte = byte_idx;
            break;
        }
    }
    let slice = c.body[start_byte..end_byte].to_string();
    let remaining = total - end;
    let footer = if remaining > 0 {
        format!(
            "\n\n[Toolport: characters {offset}..{end} of {total}. {remaining} remain, call \
             conduit_fetch_result with offset={end} for the next slice.]"
        )
    } else {
        format!("\n\n[Toolport: end of result ({total} characters).]")
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
        assert!(!shape_result(&mut r, 1024, None));
        assert_eq!(r["content"][0]["text"].as_str().unwrap().len(), 100);
    }

    #[test]
    fn over_budget_truncates_and_caches() {
        let mut r = big_text_result(10_000);
        assert!(shape_result(&mut r, 2048, None));
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("conduit_fetch_result"));
        assert!(text.len() < 10_000);
        // The marker carries a cursor that fetch_result can page.
        assert!(text.contains("\"cursor\":\"r"));
    }

    #[test]
    fn budget_zero_disables() {
        let mut r = big_text_result(10_000);
        assert!(!shape_result(&mut r, 0, None));
    }

    #[test]
    fn fetch_pages_the_remainder() {
        let mut r = big_text_result(10_000);
        shape_result(&mut r, 2048, None);
        // Pull the cursor back out of the marker.
        let text = r["content"][0]["text"].as_str().unwrap();
        let cursor = text
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        let more = fetch_result(&cursor, 1500, 500, None, None);
        let mt = more["content"][0]["text"].as_str().unwrap();
        assert!(mt.contains("of 10000"));
    }

    #[test]
    fn fetch_unknown_cursor_is_an_error() {
        let v = fetch_result("nope", 0, 100, None, None);
        assert_eq!(v["isError"].as_bool(), Some(true));
    }

    // Pull the cursor back out of a shaped result's marker.
    fn cursor_of(r: &Value) -> String {
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string()
    }

    #[test]
    fn fetch_is_scoped_to_the_owning_client() {
        let mut r = big_text_result(10_000);
        assert!(shape_result(&mut r, 2048, Some("alice")));
        let cursor = cursor_of(&r);
        // A different client (or an unattributed one) gets the same "unknown/expired"
        // answer as a missing cursor: no cross-tenant read, and no oracle for which
        // cursors exist. The stash is process-global, so in HTTP mode this is the only
        // thing stopping one client from reading another's result by guessing r{n}.
        assert_eq!(
            fetch_result(&cursor, 0, 100, Some("mallory"),None)["isError"].as_bool(),
            Some(true)
        );
        assert_eq!(
            fetch_result(&cursor, 0, 100, None, None)["isError"].as_bool(),
            Some(true)
        );
        // The owner still reads it.
        assert_ne!(
            fetch_result(&cursor, 0, 100, Some("alice"), None)["isError"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn fetch_with_pathological_len_does_not_panic() {
        let mut r = big_text_result(10_000);
        shape_result(&mut r, 2048, None);
        let cursor = cursor_of(&r);
        // offset + len must saturate, not overflow into a start > end byte slice
        // (which panics, and on the stdio transport takes down the whole gateway).
        let v = fetch_result(&cursor, 5, usize::MAX, None, None);
        assert_ne!(v["isError"].as_bool(), Some(true));
        assert!(v["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("end of result"));
    }

    #[test]
    fn multibyte_head_respects_byte_budget() {
        // 3-byte chars: truncating by char COUNT would emit ~3x the budget in bytes.
        let mut r = json!({
            "content": [{ "type": "text", "text": "€".repeat(5_000) }],
            "isError": false
        });
        assert!(shape_result(&mut r, 2048, None));
        let text = r["content"][0]["text"].as_str().unwrap();
        let head = text.split("\n\n[Toolport shaped").next().unwrap();
        assert!(
            head.len() <= 2048,
            "head was {} bytes, over the 2048 budget",
            head.len()
        );
    }

    #[test]
    fn fetch_pages_multibyte_by_char_offset() {
        // The body is all 3-byte chars, so char offsets != byte offsets. The
        // single-pass byte mapping must slice on char boundaries and honor the
        // requested character window exactly.
        let mut r = json!({
            "content": [{ "type": "text", "text": "€".repeat(4_000) }],
            "isError": false
        });
        assert!(shape_result(&mut r, 2048, None));
        let text = r["content"][0]["text"].as_str().unwrap();
        let cursor = text
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        // Read 100 chars starting at char 1000 (byte 3000): all euros, none split.
        let page = fetch_result(&cursor, 1000, 100, None, None);
        let pt = page["content"][0]["text"].as_str().unwrap();
        let body = pt.split("\n\n[Toolport:").next().unwrap();
        assert_eq!(body.chars().filter(|&c| c == '€').count(), 100);
        assert!(pt.contains("of 4000"));
    }

    #[test]
    fn fetch_past_end_reports_nothing_more() {
        let mut r = big_text_result(10_000);
        shape_result(&mut r, 2048, None);
        let text = r["content"][0]["text"].as_str().unwrap();
        let cursor = text
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        let past = fetch_result(&cursor, 999_999, 100, None, None);
        let pt = past["content"][0]["text"].as_str().unwrap();
        assert!(pt.contains("past the end"));
        assert_eq!(past["isError"].as_bool(), Some(false));
    }

    #[test]
    fn non_text_result_is_not_shaped() {
        // A large image block would be dropped by shaping, so it must pass through.
        let mut r = json!({
            "content": [{ "type": "image", "data": "A".repeat(10_000), "mimeType": "image/png" }],
            "isError": false
        });
        assert!(!shape_result(&mut r, 2048, None));
        assert_eq!(r["content"][0]["type"].as_str(), Some("image"));
    }

    #[test]
    fn envelope_heavy_result_is_not_shaped() {
        // Size is dominated by a non-body field the text projection can't capture,
        // so shaping would lose it; leave the result whole.
        let mut r = json!({
            "content": [{ "type": "text", "text": "small" }],
            "annotations": { "blob": "Z".repeat(10_000) },
            "isError": false
        });
        assert!(!shape_result(&mut r, 2048, None));
        assert_eq!(r["content"][0]["text"].as_str(), Some("small"));
    }

    #[test]
    fn cache_is_bounded() {
        // Insert well past the cap; the cache must never exceed MAX_CACHE_ENTRIES.
        for _ in 0..(MAX_CACHE_ENTRIES + 20) {
            let mut r = big_text_result(5_000);
            shape_result(&mut r, 1024, None);
        }
        let map = cache().lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            map.len() <= MAX_CACHE_ENTRIES,
            "cache grew to {} entries",
            map.len()
        );
    }

    #[test]
    fn fetch_result_projection_returns_nested_field() {
        let mut r = json!({
            "content": [{
                "type": "text",
                "text": "x".repeat(4096)
            }],
            "structuredContent": {
                "data": {
                    "users": [
                        {
                            "profile": {
                                "name": "Alice",
                                "age": 30
                            }
                        },
                        {
                            "profile": {
                                "name": "Bob",
                                "age": 40
                            }
                        }
                    ]
                }
            },
            "isError": false
        });

        // Force shaping so the result is cached.
        assert!(shape_result(&mut r, 2048, None));

        let text = r["content"][0]["text"].as_str().unwrap();
        let cursor = text
            .split("\"cursor\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();

        let projected = fetch_result(
            &cursor,
            0,
            0,
            None,
            Some("data.users.1.profile.age"),
        );

        assert!(!projected["isError"].as_bool().unwrap());

        let text = projected["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "40");
    }
}
