//! Conduit gateway.
//!
//! A local MCP server, spoken over stdio (newline-delimited JSON-RPC 2.0). Each
//! AI client points at this one binary; the gateway routes to all the real
//! servers the active profile enables, so there's one control point in front of
//! everything.
//!
//! What it does:
//! - Proxies stdio AND remote (http/sse) servers, namespacing each server's tools
//!   (`stripe__list_charges`) and forwarding `tools/call` to the right one.
//! - Injects secrets from the OS keychain at spawn time, so client configs never
//!   hold a plaintext key.
//! - Watches the registry file and emits `notifications/tools/list_changed` on
//!   change, so enabling/disabling a server applies live without a client restart
//!   (on clients that honor it).
//! - Lazy discovery: in lazy mode it advertises only 3 meta-tools (`conduit_status`,
//!   `conduit_search_tools`, `conduit_call_tool`) instead of the full catalog; the
//!   model searches and calls on demand, keeping context flat.
//! - Records every tool call to a local audit log.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use conduit_lib::audit;
use conduit_lib::clients;
use conduit_lib::downstream::{DownstreamServer, StdioTransport, PROTOCOL_VERSION};
use conduit_lib::integrity;
use conduit_lib::registry::{self, Registry, ServerEntry};
use conduit_lib::remote;
use conduit_lib::router::{Router, ToolPolicy};
use conduit_lib::savings;
use conduit_lib::semantic;
use conduit_lib::secrets;

fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn status_tool_def() -> Value {
    json!({
        "name": "conduit_status",
        "description": "Report Conduit's status: the MCP servers enabled in the active profile, each server's tool count, and how many tokens (and dollars) lazy discovery has saved you so far.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
    })
}

/// The two meta-tools that power lazy discovery: search then call. In lazy mode
/// these (plus conduit_status) are the ONLY tools advertised, so the client's
/// context holds 3 tool defs instead of hundreds - the model discovers the real
/// tool on demand and dispatches through `conduit_call_tool`.
fn search_tool_def() -> Value {
    json!({
        "name": "conduit_search_tools",
        "description": "Search across every tool from all MCP servers connected through Conduit. \
            Returns matching tools with their exact name, description, and input schema; call one with \
            conduit_call_tool. Once a result matches what you need, call it - do NOT keep searching for \
            a better one (the first result includes its full schema and is ready to call). \
            Pass `server` (a server name/prefix like \"stripe\") to scope results to one server, and \
            pass an EMPTY `query` together with `server` to list ALL of that server's tools. \
            If the result says more tools matched than were shown, narrow with `server` or raise \
            `limit` before concluding a capability is missing - many servers expose a generic API \
            bridge (a single write/create tool), so search by capability, not just an exact operation \
            name. conduit_status lists every server prefix and its tool count. \
            Large input schemas may be omitted from broad results (flagged schemaOmitted) to \
            keep responses small - search a tool's exact name to get its full schema.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keywords describing the tool. Empty lists tools (use with `server`)." },
                "server": { "type": "string", "description": "Optional: limit to this server, by name/prefix (e.g. \"stripe\")." },
                "limit": { "type": "integer", "description": "Max results (default 25, up to 200).", "default": 25 }
            },
            "required": ["query"],
            "additionalProperties": false
        }
    })
}

fn call_tool_def() -> Value {
    json!({
        "name": "conduit_call_tool",
        "description": "Invoke a tool discovered via conduit_search_tools. Pass the tool's exact \
            `name` (as returned by the search) and put ALL of that tool's parameters INSIDE the \
            `arguments` object (matching its input schema) - not at the top level next to `name`.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Exact tool name from conduit_search_tools." },
                // additionalProperties:true is REQUIRED: clients that constrain
                // generation to the JSON schema (e.g. local runtimes like Jan) would
                // otherwise only ever emit an empty `{}` here - an object with no
                // declared properties and no additionalProperties permits no keys - so
                // a required param like Vercel's teamId could never be passed.
                "arguments": {
                    "type": "object",
                    "additionalProperties": true,
                    "description": "Arguments for the tool, per its input schema."
                }
            },
            "required": ["name"],
            "additionalProperties": false
        }
    })
}

fn enable_server_tool_def() -> Value {
    json!({
        "name": "conduit_enable_server",
        "description": "Turn ON an MCP server in Conduit so its tools become available to you. \
            Pass the server's id or name (run conduit_status to see the list). Takes effect within \
            about a second. Only works when the user has allowed agent control in Conduit; the \
            global block on destructive tools stays under the user's control and cannot be changed here.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server": { "type": "string", "description": "The server id or name to enable, e.g. \"github\"." }
            },
            "required": ["server"],
            "additionalProperties": false
        }
    })
}

fn disable_server_tool_def() -> Value {
    json!({
        "name": "conduit_disable_server",
        "description": "Turn OFF an MCP server in Conduit so its tools are no longer loaded. Pass the \
            server's id or name (run conduit_status to see the list). Takes effect within about a \
            second. Only works when the user has allowed agent control in Conduit.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server": { "type": "string", "description": "The server id or name to disable." }
            },
            "required": ["server"],
            "additionalProperties": false
        }
    })
}

/// Apply an agent-initiated enable/disable of a server. Gated behind the user's
/// `allow_agent_control` opt-in (re-checked against a fresh on-disk copy to close
/// the toggle-off-mid-request window), resolves the target by id or name, writes
/// the registry, and lets the gateway's own watcher rebuild and connect it. The
/// `deny_destructive` safety switch is intentionally NOT reachable from here.
fn set_server_enabled_via_agent(
    reg: &Registry,
    profile: Option<&str>,
    path: &Path,
    target: &str,
    enable: bool,
) -> Result<String, String> {
    if !reg.allow_agent_control {
        return Err("Conduit: agent control is off. The user must turn on \"Allow agent control\" \
            in Conduit before an agent can enable or disable servers."
            .to_string());
    }
    let target = target.trim();
    if target.is_empty() {
        return Err("Conduit: pass the `server` id or name to change (run conduit_status for the list).".to_string());
    }
    let server = reg
        .servers
        .iter()
        .find(|s| s.id.eq_ignore_ascii_case(target) || s.name.eq_ignore_ascii_case(target))
        .ok_or_else(|| {
            let known: Vec<&str> = reg.servers.iter().map(|s| s.name.as_str()).collect();
            format!("Conduit: no server matches \"{target}\". Known servers: {}.", known.join(", "))
        })?;
    let server_id = server.id.clone();
    let server_name = server.name.clone();
    let profile_id = profile
        .map(str::to_string)
        .or_else(|| reg.active_profile_id.clone())
        .ok_or_else(|| "Conduit: no active profile to change.".to_string())?;

    // Load fresh so a concurrent edit in the app isn't clobbered, and re-check the
    // opt-in on that fresh copy (the user may have just turned it off).
    let mut fresh = registry::load_from(path)
        .map_err(|e| format!("Conduit: could not read the registry ({e})."))?;
    if !fresh.allow_agent_control {
        return Err("Conduit: agent control is off.".to_string());
    }
    if fresh.is_enabled(&profile_id, &server_id) == enable {
        return Ok(format!("{server_name} is already {}.", if enable { "on" } else { "off" }));
    }
    fresh.set_server_enabled(&profile_id, &server_id, enable)?;
    registry::save_to(path, &fresh)
        .map_err(|e| format!("Conduit: could not save the registry ({e})."))?;
    glog(&format!(
        "agent control: {} server '{server_id}' in profile '{profile_id}'",
        if enable { "ENABLED" } else { "DISABLED" }
    ));
    Ok(format!(
        "Turned {} \"{server_name}\". Its tools will be {} within about a second.",
        if enable { "on" } else { "off" },
        if enable { "available" } else { "removed" }
    ))
}

/// Unwrap a `conduit_call_tool` payload into (inner tool name, inner arguments).
/// The tool's params normally nest under `arguments`, but models frequently flatten
/// this double-nested shape and put them at the top level next to `name` instead -
/// which otherwise drops a required param (e.g. Vercel's `teamId`) so it arrives
/// downstream as undefined. Prefer a non-empty nested `arguments`; otherwise fall
/// back to the sibling keys (everything except `name`/`arguments`).
fn unwrap_call_tool(payload: &Value) -> (String, Value) {
    let inner = payload
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let nested_nonempty = payload
        .get("arguments")
        .and_then(|v| v.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);
    let args = if nested_nonempty {
        payload.get("arguments").cloned().unwrap()
    } else {
        let mut siblings = payload.as_object().cloned().unwrap_or_default();
        siblings.remove("name");
        siblings.remove("arguments");
        if siblings.is_empty() {
            json!({})
        } else {
            Value::Object(siblings)
        }
    };
    (inner, args)
}

/// The server prefix of a namespaced tool name ("stripe_2__create" -> "stripe_2").
fn tool_prefix(t: &Value) -> String {
    t.get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .split("__")
        .next()
        .unwrap_or("")
        .to_lowercase()
}

// --- Lexical search ranking (tokens + light stemming + synonyms + IDF) ---
// This is the relevance core; it's deliberately self-contained so an optional
// embedding-based scorer can blend in or replace it later without touching the
// search plumbing (server filter, diversification, projection) around it.

/// Field weights: a token hit in the tool NAME counts far more than in its description.
const NAME_W: f64 = 3.0;
const DESC_W: f64 = 1.0;

/// Split a camelCase/PascalCase word into lowercased pieces ("listProjects" -> [list, projects]).
fn split_camel(word: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for ch in word.chars() {
        if ch.is_uppercase() && prev_lower && !cur.is_empty() {
            parts.push(std::mem::take(&mut cur));
        }
        for lc in ch.to_lowercase() {
            cur.push(lc);
        }
        prev_lower = ch.is_lowercase();
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// Lightweight stem: strip a trailing plural `s` so "products"/"product",
/// "charges"/"charge", "teams"/"team" compare equal. Intentionally minimal (no
/// ing/ed handling) - over-stemming creates more mismatches than it fixes here.
fn stem_token(token: &str) -> String {
    let t = token.to_lowercase();
    if t.len() > 3 && t.ends_with('s') && !t.ends_with("ss") {
        t[..t.len() - 1].to_string()
    } else {
        t
    }
}

/// Tokenize tool text or a query into normalized search tokens (break on
/// non-alphanumeric and camelCase, lowercase, stem, drop 1-char tokens). Used for
/// tool NAMES, which are terse and meaningful, so nothing is dropped.
fn search_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .flat_map(split_camel)
        .filter(|t| t.len() > 1)
        .map(|t| stem_token(&t))
        .collect()
}

/// Noise words to drop from the search index and queries. Tool descriptions are
/// written for a human skimming a README (full of boilerplate like "Purpose:",
/// "Returns:", "When to use"), so these dilute the IDF signal without helping
/// retrieval. Deliberately conservative: NO capability words (list/get/create/send/
/// etc.), only function words and description boilerplate. Checked pre-stem.
const STOPWORDS: &[&str] = &[
    // function words
    "an", "the", "and", "or", "but", "if", "of", "to", "for", "in", "on", "at", "by",
    "with", "from", "into", "as", "is", "are", "be", "was", "were", "this", "that",
    "these", "those", "it", "its", "you", "your", "their", "them", "they", "we", "our",
    "us", "can", "will", "would", "should", "could", "may", "might", "do", "does", "did",
    "has", "have", "had", "not", "no", "all", "any", "each", "more", "most", "some",
    "such", "than", "then", "there", "here", "when", "where", "what", "which", "who",
    "whom", "how", "why", "also", "just", "only", "via", "per", "out", "off", "over",
    "under", "about", "between", "after", "before", "during", "while", "both", "either",
    // MCP-description boilerplate
    "purpose", "returns", "return", "use", "used", "uses", "using", "note", "notes",
    "example", "examples", "optional", "required", "param", "params", "parameter",
    "parameters",
];

fn is_stopword(token: &str) -> bool {
    STOPWORDS.contains(&token)
}

/// Tokens for the search INDEX and for queries: like `search_tokens` but with noise
/// words removed (checked pre-stem). Cleaning what we index buys more ranking signal
/// than a fancier retrieval method, the corpus is the lever. Names keep everything.
fn index_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .flat_map(split_camel)
        .filter(|t| t.len() > 1 && !is_stopword(t))
        .map(|t| stem_token(&t))
        .collect()
}

/// Synonym group for a (stemmed) token, bridging common MCP vocabulary so e.g.
/// "mail" finds an "email" tool and "get" finds a "list" tool. Empty if none.
fn synonym_group(token: &str) -> &'static [&'static str] {
    const GROUPS: &[&[&str]] = &[
        &["list", "get", "fetch", "show", "read", "find", "search", "view"],
        &["create", "add", "new", "make", "insert"],
        &["delete", "remove", "destroy", "drop"],
        &["update", "edit", "modify", "change", "set"],
        &["email", "mail", "message"],
        &["project", "repo", "repository"],
        &["user", "account", "member", "customer"],
        &["team", "org", "organization", "workspace"],
    ];
    GROUPS
        .iter()
        .find(|g| g.contains(&token))
        .copied()
        .unwrap_or(&[])
}

/// Rank the cached catalog against a query, optionally scoped to one server.
/// Ranking is lexical with IDF weighting: query and tools are tokenized (camelCase
/// split, light stemming, small synonym map), a name hit outweighs a description hit,
/// and a rare token (e.g. "products") outweighs a common one (e.g. "list") so the
/// specific tool wins over generic ones. An empty query lists tools (all of a
/// server's when `server` is set).
/// Returns (results, total_matched) so the caller can tell the agent when results
/// were truncated - otherwise a buried tool reads as "doesn't exist". When NOT
/// scoped to a server, results are diversified so one chatty server can't flood
/// the window (the bug where a "create product" query returned only RevenueCat).
/// Lexical-only entry point used by the unit tests (the live handler calls
/// `search_catalog_with` so it can pass the semantic config).
#[cfg(test)]
fn search_catalog(
    cached: &[Value],
    query: &str,
    server: Option<&str>,
    limit: usize,
) -> (Vec<Value>, usize) {
    search_catalog_with(cached, query, server, limit, None)
}

/// As `search_catalog`, with optional semantic re-ranking. When `sem` is None or
/// inactive, or embeddings are unavailable, ranking is pure lexical and byte-for-byte
/// identical to before, semantic only ever adds, never degrades.
fn search_catalog_with(
    cached: &[Value],
    query: &str,
    server: Option<&str>,
    limit: usize,
    sem: Option<&semantic::SemanticConfig>,
) -> (Vec<Value>, usize) {
    use std::collections::HashMap;
    let q = query.to_lowercase();
    let terms: Vec<&str> = q.split_whitespace().filter(|t| !t.is_empty()).collect();
    let server_filter = server
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());

    // Optionally restrict to one server (its prefix contains the filter text).
    let pool: Vec<&Value> = cached
        .iter()
        .filter(|t| match &server_filter {
            Some(sf) => tool_prefix(t).contains(sf.as_str()),
            None => true,
        })
        .collect();

    // Select an ordered set of tool refs (ranking happens here; projection below).
    let (selected, total): (Vec<&Value>, usize) = if terms.is_empty() {
        // Empty query: list the pool. With `server` set this enumerates that server.
        let total = pool.len();
        (pool.into_iter().take(limit).collect(), total)
    } else {
        // Tokenize each tool and compute document frequencies, so IDF can weight a
        // rare token (e.g. "products", "teams") far above a common one (e.g. "list",
        // "get"). That makes "list products" rank the products tool over the many
        // generic "list" tools - the keyword-only wandering we hit with Stripe.
        use std::collections::HashSet;
        let docs: Vec<(&Value, HashSet<String>, HashSet<String>)> = pool
            .iter()
            .map(|t| {
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
                (
                    *t,
                    search_tokens(name).into_iter().collect(),
                    index_tokens(desc).into_iter().collect(),
                )
            })
            .collect();
        let n = docs.len().max(1) as f64;
        let mut df: HashMap<&str, usize> = HashMap::new();
        for (_, name_set, desc_set) in &docs {
            for tok in name_set.union(desc_set) {
                *df.entry(tok.as_str()).or_insert(0) += 1;
            }
        }
        let idf = |tok: &str| ((n + 1.0) / (*df.get(tok).unwrap_or(&0) as f64 + 1.0)).ln() + 1.0;

        let q_tokens = index_tokens(query);
        // Lexical score for EVERY doc (0 if no hit), kept so optional semantic
        // re-ranking can also surface tools the keywords missed entirely.
        let lex: Vec<(f64, &Value)> = docs
            .iter()
            .map(|(t, name_set, desc_set)| {
                let mut score = 0.0_f64;
                for qt in &q_tokens {
                    // Best field hit across the query token and its synonyms; name
                    // beats description, and the matched token's IDF sets the weight.
                    let mut best = 0.0_f64;
                    let cands =
                        std::iter::once(qt.as_str()).chain(synonym_group(qt).iter().copied());
                    for c in cands {
                        if name_set.contains(c) {
                            best = best.max(NAME_W * idf(c));
                        } else if desc_set.contains(c) {
                            best = best.max(DESC_W * idf(c));
                        }
                    }
                    // Prefix fallback for partial words ("proj" -> "project").
                    if best == 0.0 && qt.len() >= 3 {
                        if let Some(tok) = name_set.iter().find(|t| t.starts_with(qt.as_str())) {
                            best = 0.6 * NAME_W * idf(tok);
                        }
                    }
                    score += best;
                }
                (score, *t)
            })
            .collect();

        // Blended (semantic) ranking when configured and embeddings succeed; else
        // pure lexical (positive scores only, highest first), identical to before.
        let ranked: Vec<(f64, &Value)> = semantic_rerank(sem, query, &lex).unwrap_or_else(|| {
            let mut s: Vec<(f64, &Value)> =
                lex.iter().filter(|(sc, _)| *sc > 0.0).cloned().collect();
            s.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            s
        });
        let total = ranked.len();

        // Scoped to a server: take the top `limit`. Unscoped: cap per server so one
        // server with many matching tools can't crowd the others out of the window.
        let selected: Vec<&Value> = if server_filter.is_some() {
            ranked.into_iter().take(limit).map(|(_, t)| t).collect()
        } else {
            let cap = (limit / 3).max(4);
            let mut per: HashMap<String, usize> = HashMap::new();
            let mut out = Vec::new();
            for (_, t) in ranked {
                if out.len() >= limit {
                    break;
                }
                let c = per.entry(tool_prefix(t)).or_insert(0);
                if *c >= cap {
                    continue;
                }
                *c += 1;
                out.push(t);
            }
            out
        };
        (selected, total)
    };

    (project_budgeted(&selected), total)
}

/// Blend embedding similarity into the lexical scores. Returns None when semantic
/// search is off/unconfigured or embeddings are unavailable, so the caller falls
/// back to pure lexical ranking, semantic can only add signal, never remove it.
fn semantic_rerank<'a>(
    sem: Option<&semantic::SemanticConfig>,
    query: &str,
    lex: &[(f64, &'a Value)],
) -> Option<Vec<(f64, &'a Value)>> {
    let cfg = sem?;
    if !cfg.is_active() {
        return None;
    }
    let qv = semantic::embed_query(cfg, query)?;
    let tools: Vec<&Value> = lex.iter().map(|(_, t)| *t).collect();
    let embs = semantic::embed_tools(cfg, &tools);
    if embs.is_empty() {
        return None;
    }
    let max_lex = lex.iter().map(|(s, _)| *s).fold(0.0_f64, f64::max);
    let blend = cfg.blend.clamp(0.0, 1.0) as f64;
    let mut out: Vec<(f64, &Value)> = lex
        .iter()
        .map(|(sc, t)| {
            let lex_norm = if max_lex > 0.0 { sc / max_lex } else { 0.0 };
            let name = t.get("name").and_then(Value::as_str).unwrap_or("");
            let cos = embs
                .get(name)
                .map(|tv| semantic::cosine(&qv, tv).max(0.0) as f64)
                .unwrap_or(0.0);
            ((1.0 - blend) * lex_norm + blend * cos, *t)
        })
        // Drop near-zero blended scores so a broad catalog doesn't return everything.
        .filter(|(b, _)| *b > 0.02)
        .collect();
    out.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Some(out)
}

/// Project selected tools to search results, bounding the total size of their
/// (sometimes enormous) input schemas. Lazy discovery exists to keep the agent's
/// context small, so one server's giant schemas must not blow it up: the top
/// result always carries its full schema; past a byte budget the rest return the
/// name and a short description only, flagged `schemaOmitted` so the agent can
/// fetch a tool's full schema by searching its exact name (or scoping with `server`).
fn project_budgeted(tools: &[&Value]) -> Vec<Value> {
    // Only the top result carries a full schema and a longer description - it's the
    // one we tell the model to call. Every other result is a compact menu entry:
    // name plus a one-line description, no schema. A 25-result response then stays a
    // few KB instead of tens, which matters because a (slow, local) model re-reads
    // the whole thing on every turn. Full schema/text for any other tool comes from
    // a scoped or exact-name search, as the response text explains.
    const TOP_DESC_MAX: usize = 500;
    const MENU_DESC_MAX: usize = 140;
    let truncate = |d: Option<&Value>, max: usize| match d.and_then(|v| v.as_str()) {
        Some(s) if s.chars().count() > max => {
            let head: String = s.chars().take(max).collect();
            Value::String(format!("{head}…"))
        }
        _ => d.cloned().unwrap_or(Value::Null),
    };
    tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let name = t.get("name").cloned().unwrap_or(Value::Null);
            if i == 0 {
                json!({
                    "name": name,
                    "description": truncate(t.get("description"), TOP_DESC_MAX),
                    "inputSchema": t.get("inputSchema").cloned().unwrap_or(Value::Null),
                })
            } else {
                json!({
                    "name": name,
                    "description": truncate(t.get("description"), MENU_DESC_MAX),
                    "schemaOmitted": true,
                })
            }
        })
        .collect()
}

fn enabled_summary(reg: &Registry, cached: &[Value], profile: Option<&str>) -> String {
    let active = match profile {
        Some(p) => reg.resolve_profile_id(p),
        None => reg.active_profile_id(),
    };
    let profile_name = reg
        .profiles
        .iter()
        .find(|p| p.id == active)
        .map(|p| p.name.clone())
        .unwrap_or(active.clone());

    // Exclude Conduit's own gateway entry - it's infrastructure, not a proxied
    // server, so listing it here is just confusing.
    let servers: Vec<_> = reg
        .servers
        .iter()
        .filter(|s| reg.is_enabled(&active, &s.id) && !clients::is_gateway_server(s))
        .collect();
    if servers.is_empty() {
        return format!("Profile '{profile_name}': no servers enabled.");
    }

    let mut out = format!(
        "Profile '{profile_name}' has {} enabled server(s):\n",
        servers.len()
    );
    for s in servers {
        let target = match (&s.command, &s.url) {
            (Some(cmd), _) => format!("{} {}", cmd, s.args.join(" ")),
            (None, Some(url)) => url.clone(),
            _ => "(none)".to_string(),
        };
        out.push_str(&format!("- {} [{}] {}\n", s.name, s.transport, target.trim()));
    }

    // Tool counts by server prefix, from the live catalog. These prefixes are
    // exactly what precedes "__" in tool names, so the agent can enumerate a
    // server's full tool set with conduit_search_tools(server: "<prefix>").
    if !cached.is_empty() {
        let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for t in cached {
            let prefix = tool_prefix(t);
            if !prefix.is_empty() {
                *counts.entry(prefix).or_insert(0) += 1;
            }
        }
        if !counts.is_empty() {
            out.push_str("\nTools by server (pass the prefix as `server` to list them all):\n");
            for (p, c) in counts {
                out.push_str(&format!("- {p}: {c} tool(s)\n"));
            }
        }
    }
    out.push_str(&savings_line());
    out
}

/// Compact token count for status text: "1.2M", "541k", or the raw number.
fn fmt_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// One line summarizing what lazy discovery has saved, for conduit_status, so an
/// agent can answer "what is Conduit saving me?". Empty until something is saved
/// (a fresh install, or non-lazy mode where nothing is recorded).
fn savings_line() -> String {
    let s = savings::summary();
    let saved = s.get("tokensSaved").and_then(Value::as_u64).unwrap_or(0);
    if saved == 0 {
        return String::new();
    }
    let loads = s.get("listLoads").and_then(Value::as_u64).unwrap_or(0);
    let peak = s.get("peakCatalog").and_then(Value::as_u64).unwrap_or(0);
    let dollars = (saved as f64 / 1_000_000.0) * 3.0; // Claude Sonnet input $/M
    let mut line = format!(
        "\nLazy discovery has kept ~{} tokens of tool definitions out of your agent's \
         context so far (about ${:.2} at Claude Sonnet input rates) across {loads} \
         tool-list load(s)",
        fmt_tokens(saved),
        dollars
    );
    if peak > 3 {
        line.push_str(&format!("; the biggest catalog collapsed {peak} tools to 3"));
    }
    line.push_str(".\n");
    line
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications (no reply).
/// Per-session guard against search-thrash. Weak local models (e.g. small-active
/// MoEs) will call conduit_search_tools many times in a row for the SAME need
/// instead of committing, which is slow and burns context. We escalate only on
/// that specific pattern (the same top tool surfacing across consecutive searches,
/// not on a raw search count). A capable model that searches once and calls, or
/// searches several DIFFERENT things (exploring), or narrows from broad to server
/// to exact-name (each a different, justified result), never trips this. So it fixes
/// the weak-model loop without ever penalizing Claude, Cursor, or any model doing
/// real multi-step work. Any non-search action resets it. Per client connection.
#[derive(Default)]
struct SearchGuard {
    /// The top result's name from the previous consecutive search, if any.
    last_top: Option<String>,
    /// How many consecutive searches returned that same top result.
    repeats: u32,
}

/// Escalate once the SAME top tool has come back this many times in a row: the
/// model is stuck on one need, so return only that tool and command the call.
const SEARCH_REPEAT_LIMIT: u32 = 3;

fn handle_request(
    req: &Value,
    reg: &Registry,
    router: &mut Router,
    cached: &[Value],
    lazy: bool,
    profile: Option<&str>,
    guard: &mut SearchGuard,
) -> Option<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let id = match req.get("id") {
        Some(id) if !id.is_null() => id.clone(),
        _ => return None,
    };

    match method {
        "initialize" => {
            let proto = req
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or(PROTOCOL_VERSION);
            Some(success(
                id,
                json!({
                    "protocolVersion": proto,
                    "capabilities": {
                        "tools": { "listChanged": true },
                        "resources": { "listChanged": true },
                        "prompts": { "listChanged": true }
                    },
                    "serverInfo": { "name": "conduit-gateway", "version": env!("CARGO_PKG_VERSION") }
                }),
            ))
        }
        "tools/list" => {
            // Lazy mode: advertise only the meta-tools, so the client's context
            // holds a handful of tool defs instead of the whole catalog. The model
            // finds real tools via conduit_search_tools and runs conduit_call_tool.
            if lazy {
                let mut tools = vec![status_tool_def(), search_tool_def(), call_tool_def()];
                // Opt-in: surface the agent-control tools only when the user has
                // allowed it, so an agent can't even see them otherwise.
                if reg.allow_agent_control {
                    tools.push(enable_server_tool_def());
                    tools.push(disable_server_tool_def());
                }
                // Record what lazy discovery kept out of the client's context: the
                // full catalog we'd otherwise serve (status + every downstream tool)
                // minus these 3 meta-tools. Estimating over the cached slice avoids
                // cloning the whole catalog on a serve.
                let agg;
                let catalog: &[Value] = if cached.is_empty() {
                    agg = router.aggregated_tools();
                    &agg
                } else {
                    cached
                };
                let status = status_tool_def();
                let full_tokens = savings::estimate_tokens(catalog)
                    + savings::estimate_tokens(std::slice::from_ref(&status));
                savings::record(
                    full_tokens,
                    savings::estimate_tokens(&tools),
                    catalog.len() as u64 + 1,
                );
                gtrace("tools/list -> 3 tools (lazy discovery)");
                return Some(success(id, json!({ "tools": tools })));
            }
            let mut tools = vec![status_tool_def()];
            // Prefer the cached catalog (instant); fall back to the live router.
            if cached.is_empty() {
                tools.extend(router.aggregated_tools());
            } else {
                tools.extend(cached.iter().cloned());
            }
            gtrace(&format!(
                "tools/list -> {} tools (cache={})",
                tools.len(),
                !cached.is_empty()
            ));
            Some(success(id, json!({ "tools": tools })))
        }
        "tools/call" => {
            let params = req.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));

            // Anything other than a search breaks the search-thrash streak.
            if name != "conduit_search_tools" {
                guard.last_top = None;
                guard.repeats = 0;
            }

            if name == "conduit_status" {
                return Some(success(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": enabled_summary(reg, cached, profile) }],
                        "isError": false
                    }),
                ));
            }

            if name == "conduit_search_tools" {
                let query = arguments
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let server = arguments.get("server").and_then(|v| v.as_str());
                let limit = arguments
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(25)
                    .clamp(1, 200) as usize;
                // Prefer the cached catalog (instant); on a cold cache fall back to
                // the live router so a first-time search doesn't return 0 results.
                let live;
                let source: &[Value] = if cached.is_empty() {
                    live = router.aggregated_tools();
                    &live
                } else {
                    cached
                };
                // Semantic re-ranking if the user has configured it (off by default;
                // falls back to lexical on any failure).
                let s = &reg.semantic_search;
                let sem_cfg =
                    semantic::SemanticConfig::resolve(s.enabled, s.endpoint.clone(), s.model.clone(), s.blend);
                let (mut matches, total) =
                    search_catalog_with(source, query, server, limit, Some(&sem_cfg));
                let scope = server
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| format!(" on \"{s}\""))
                    .unwrap_or_default();
                // Identify the top result, then track whether the model keeps landing
                // on the SAME one across consecutive searches - the thrash signal that a
                // raw count can't tell apart from genuine exploration/narrowing.
                let top = matches
                    .first()
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !matches.is_empty() && guard.last_top.as_deref() == Some(top.as_str()) {
                    guard.repeats += 1;
                } else {
                    guard.repeats = 1;
                    guard.last_top = (!matches.is_empty()).then(|| top.clone());
                }
                let escalate = guard.repeats >= SEARCH_REPEAT_LIMIT && !matches.is_empty();
                if escalate {
                    matches.truncate(1); // only the best match, no distractions
                }
                // Tell the agent when results were truncated, so a buried tool isn't
                // mistaken for a missing capability.
                let more = if total > matches.len() && !escalate {
                    format!(
                        " Showing {} of {}; narrow with the `server` filter (e.g. server: \
                         \"{}\") or raise `limit` (up to 200) before concluding a capability \
                         is missing.",
                        matches.len(),
                        total,
                        matches.first().map(tool_prefix).unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                let omitted = matches.iter().any(|m| {
                    m.get("schemaOmitted").and_then(|v| v.as_bool()).unwrap_or(false)
                });
                // Note only clarifies the OMITTED (non-top) results need a follow-up;
                // the first result always carries its schema, so it never does.
                let schema_note = if omitted {
                    " Results after the first may omit large input schemas (schemaOmitted); to call \
                     one of those instead, search its exact name or pass `server` to get its schema."
                } else {
                    ""
                };
                let lead = if matches.is_empty() {
                    format!(
                        "No tools matched{scope}. Try different keywords, or call conduit_status to \
                         see the connected servers and their tool counts."
                    )
                } else if escalate {
                    // Behavioral loop-breaker: the model keeps re-searching the same need
                    // and landing on the same tool. Give it that one tool and a command,
                    // not more options to graze on. (Only fires on a repeated top result,
                    // so a model exploring different needs is never cut off.)
                    format!(
                        "You have searched {} times and keep getting the same top tool, `{top}`. It \
                         is the best match and its full input schema is below - call conduit_call_tool \
                         now with name \"{top}\". Searching again will keep returning this. Only if \
                         `{top}` genuinely cannot do the task, call conduit_status to see other servers.",
                        guard.repeats
                    )
                } else {
                    // Lead with a single, named, ready-to-call directive so the model
                    // commits instead of re-searching (the v0.3.6 keep-searching nudges
                    // overcorrected and made compliant models thrash).
                    format!(
                        "Found {total} matching tool(s){scope}. Top match: `{top}` - its full input \
                         schema is included below, so call it now with conduit_call_tool (name: \
                         \"{top}\") if it fits. Only search again if none of these match.{more}{schema_note}"
                    )
                };
                let text = format!(
                    "{lead}\n\n{}",
                    serde_json::to_string_pretty(&matches).unwrap_or_default()
                );
                return Some(success(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                ));
            }

            if name == "conduit_enable_server" || name == "conduit_disable_server" {
                let enable = name == "conduit_enable_server";
                let target = arguments.get("server").and_then(|v| v.as_str()).unwrap_or("");
                let result = match registry::resolved_path() {
                    Some(p) => set_server_enabled_via_agent(reg, profile, &p, target, enable),
                    None => Err("Conduit: could not locate the registry file.".to_string()),
                };
                let (text, is_error) = match result {
                    Ok(msg) => (msg, false),
                    Err(msg) => (msg, true),
                };
                return Some(success(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error }),
                ));
            }

            // conduit_call_tool dispatches a discovered tool: unwrap to its real
            // name + arguments and fall through to the normal routing below.
            let (name, arguments) = if name == "conduit_call_tool" {
                unwrap_call_tool(&arguments)
            } else {
                (name.to_string(), arguments)
            };
            let name = name.as_str();

            let (srv, tool) = name.split_once("__").unwrap_or(("?", name));
            let started = Instant::now();
            match router.route_call(name, arguments) {
                Ok(result) => {
                    let ok = !result
                        .get("isError")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let ms = started.elapsed().as_millis() as u64;
                    audit::record_timed(srv, tool, ok, Some(ms));
                    Some(success(id, result))
                }
                Err(e) => {
                    let ms = started.elapsed().as_millis() as u64;
                    audit::record_timed(srv, tool, false, Some(ms));
                    Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": format!("Conduit: {e}") }],
                            "isError": true
                        }),
                    ))
                }
            }
        }
        "resources/list" => {
            let resources = router.aggregated_resources();
            gtrace(&format!("resources/list -> {} resources", resources.len()));
            Some(success(id, json!({ "resources": resources })))
        }
        "resources/read" => {
            let uri = req
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            match router.read_resource(uri) {
                Ok(result) => Some(success(id, result)),
                Err(e) => Some(error(id, -32602, &format!("Conduit: {e}"))),
            }
        }
        "prompts/list" => {
            let prompts = router.aggregated_prompts();
            gtrace(&format!("prompts/list -> {} prompts", prompts.len()));
            Some(success(id, json!({ "prompts": prompts })))
        }
        "prompts/get" => {
            let params = req.get("params");
            let name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            match router.get_prompt(name, arguments) {
                Ok(result) => Some(success(id, result)),
                Err(e) => Some(error(id, -32602, &format!("Conduit: {e}"))),
            }
        }
        "ping" => Some(success(id, json!({}))),
        other => Some(error(id, -32601, &format!("Method not found: {other}"))),
    }
}

/// Spawn and connect every enabled server into a router. With `profile` set, only
/// that profile's servers are connected (per-client scoping); otherwise the
/// active profile is used.
fn build_router(reg: &Registry, profile: Option<&str>, dirty: &Arc<AtomicBool>) -> Router {
    let enabled = match profile {
        Some(p) => reg.enabled_servers_for(p),
        None => reg.enabled_servers(),
    };
    let servers: Vec<ServerEntry> = enabled
        .into_iter()
        .filter(|s| !clients::is_gateway_server(s)) // never proxy ourselves
        .cloned()
        .collect();

    // Build the policy from the same server set: per-tool disables + the global
    // destructive switch. The router enforces it as servers are added.
    let mut disabled = std::collections::HashMap::new();
    for s in &servers {
        if !s.disabled_tools.is_empty() {
            disabled.insert(s.id.clone(), s.disabled_tools.iter().cloned().collect());
        }
    }
    let policy = ToolPolicy {
        disabled,
        deny_destructive: reg.deny_destructive,
    };

    // Connect concurrently so total time is the slowest server, not the sum.
    let handles: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let dirty = Arc::clone(dirty);
            std::thread::spawn(move || connect_one(&server, &dirty))
        })
        .collect();

    let mut router = Router::with_policy(policy);
    for handle in handles {
        if let Ok(Some(ds)) = handle.join() {
            router.add(ds);
        }
    }
    router
}

/// Connect a single enabled server (stdio with keychain secret injection, or
/// remote with refresh-aware auth). Returns None on failure.
fn connect_one(server: &ServerEntry, dirty: &Arc<AtomicBool>) -> Option<DownstreamServer> {
    let result = if let Some(command) = &server.command {
        let mut env: Vec<(String, String)> = Vec::new();
        for e in &server.env {
            if let Some(v) = &e.value {
                env.push((e.key.clone(), v.clone()));
            } else if e.secret {
                match secrets::get_secret_result(&server.id, &e.key) {
                    Ok(Some(v)) => env.push((e.key.clone(), v)),
                    Ok(None) => eprintln!(
                        "conduit: '{}' needs secret '{}' but none is vaulted",
                        server.id, e.key
                    ),
                    Err(err) => eprintln!(
                        "conduit: '{}' could not read secret '{}' from the keychain: {err}",
                        server.id, e.key
                    ),
                }
            }
        }
        match StdioTransport::spawn_watched(command, &server.args, &env, Arc::clone(dirty)) {
            Ok(t) => DownstreamServer::connect(server.id.clone(), Box::new(t)),
            Err(e) => Err(e),
        }
    } else if let Some(url) = &server.url {
        remote::connect_remote(&server.id, url)
    } else {
        Err("no command or url".to_string())
    };

    match result {
        Ok(mut ds) => {
            // Only the gateway needs resources/prompts (to proxy them); fetch
            // them here, off the health-probe path.
            ds.load_resources_prompts();
            let msg = format!("connected '{}' ({} tools)", server.id, ds.tools.len());
            eprintln!("conduit: {msg}");
            glog(&msg);
            Some(ds)
        }
        Err(e) => {
            let msg = format!("'{}' failed: {e}", server.id);
            eprintln!("conduit: {msg}");
            glog(&msg);
            None
        }
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn notify_tools_changed(stdout: &Arc<Mutex<std::io::Stdout>>) {
    let mut out = stdout.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = writeln!(
        out,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })
    );
    let _ = out.flush();
}

/// Persist a freshly built or refreshed catalog and tell the client it changed.
/// Never persists an empty catalog over a good one (a transient empty build or a
/// momentarily unreachable server would otherwise wipe the cache and leave the
/// client showing only conduit_status); the emit still fires so the client
/// re-fetches from cache.
/// Run tool-definition integrity detection on a freshly built catalog (gated by
/// the registry's `integrity_check`, on by default). Any drift is recorded to the
/// security log inside `integrity::check`; here we also surface it in the gateway
/// log so it's visible in "Copy diagnostics". Detection only, never blocks.
fn maybe_check_integrity(registry: &Arc<Mutex<Registry>>, tools: &[Value], profile: Option<&str>) {
    let enabled = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .integrity_check;
    if !enabled {
        return;
    }
    for d in integrity::check(profile, tools) {
        let server = d.get("server").and_then(Value::as_str).unwrap_or("?");
        let tool = d.get("tool").and_then(Value::as_str).unwrap_or("?");
        let change = d.get("change").and_then(Value::as_str).unwrap_or("?");
        glog(&format!(
            "SECURITY: tool definition {change} on already-approved server \"{server}\": {tool}"
        ));
        eprintln!("conduit: SECURITY tool drift ({change}) {tool}");
    }
}

fn persist_and_emit(
    tools: &[Value],
    cached_tools: &Arc<Mutex<Vec<Value>>>,
    stdout: &Arc<Mutex<std::io::Stdout>>,
    profile: Option<&str>,
) {
    if !tools.is_empty() {
        *cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = tools.to_vec();
        save_tool_cache(tools, profile);
    }
    notify_tools_changed(stdout);
}

/// Keep the always-on gateway log bounded; trimmed to roughly the back half once
/// it grows past this, so a long-running client can't let it grow without limit.
const GATEWAY_LOG_CAP: u64 = 256 * 1024;

/// Append a line to the always-on gateway log (connection lifecycle: starts,
/// connect successes and failures). This is what `gather_diagnostics` bundles
/// into a bug report, so it stays on regardless of `CONDUIT_DEBUG`.
fn glog(msg: &str) {
    let Some(path) = registry::gateway_log_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{msg}");
    }
    trim_log_if_large(&path);
}

/// Per-request trace, gated behind `CONDUIT_DEBUG` so the always-on log stays
/// focused on connection lifecycle and doesn't fill with one line per call.
fn gtrace(msg: &str) {
    if std::env::var_os("CONDUIT_DEBUG").is_some() {
        glog(msg);
    }
}

/// Trim the log to its back half (on a line boundary) once it exceeds the cap.
/// Best-effort: a read/rewrite race between concurrent gateways at worst drops a
/// few diagnostic lines, which is fine for a log.
fn trim_log_if_large(path: &Path) {
    let over = std::fs::metadata(path).map(|m| m.len() > GATEWAY_LOG_CAP).unwrap_or(false);
    if !over {
        return;
    }
    let Ok(data) = std::fs::read(path) else {
        return;
    };
    let keep_from = data.len().saturating_sub((GATEWAY_LOG_CAP / 2) as usize);
    let start = data[keep_from..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| keep_from + i + 1)
        .unwrap_or(keep_from);
    let _ = std::fs::write(path, &data[start..]);
}

/// Cache file for a given profile. Scoped clients get their own file
/// (`tool-cache-<profile>.json`) so a billing-scoped client never reads a
/// coding-scoped client's catalog - which would defeat the scoping.
fn tool_cache_path(profile: Option<&str>) -> Option<PathBuf> {
    let dir = registry::conduit_dir()?;
    let file = match profile {
        Some(p) if !p.is_empty() => {
            let slug: String = p
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                .collect();
            format!("tool-cache-{slug}.json")
        }
        _ => "tool-cache.json".to_string(),
    };
    Some(dir.join(file))
}

/// The namespaced tool catalog from the last successful build, so tools/list can
/// answer instantly without waiting on downstream connections.
fn load_tool_cache(profile: Option<&str>) -> Vec<Value> {
    tool_cache_path(profile)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_tool_cache(tools: &[Value], profile: Option<&str>) {
    if let Some(path) = tool_cache_path(profile) {
        if let Ok(s) = serde_json::to_string(tools) {
            // Atomic + unique temp: several gateways share this cache file, so a
            // torn or interleaved write would leave an inconsistent catalog.
            let _ = registry::atomic_write(&path, &s);
        }
    }
}

/// Poll the registry file; on change, reload, rebuild the router, and tell the
/// client its tool list changed. This is what makes a toggle apply live.
fn watch_registry(
    path: PathBuf,
    registry: Arc<Mutex<Registry>>,
    router: Arc<Mutex<Router>>,
    stdout: Arc<Mutex<std::io::Stdout>>,
    cached_tools: Arc<Mutex<Vec<Value>>>,
    profile: Option<String>,
    downstream_dirty: Arc<AtomicBool>,
) {
    eprintln!("conduit: watching registry at {}", path.display());
    let mut last = mtime(&path);
    loop {
        std::thread::sleep(Duration::from_millis(1000));
        // A live downstream server that changed its own tool set (sent
        // tools/list_changed) sets this. Swap before acting so a notification
        // arriving mid-refresh is caught on the next tick rather than lost.
        let downstream_changed = downstream_dirty.swap(false, Ordering::SeqCst);
        let current = mtime(&path);
        let file_changed = current != last;
        if !file_changed && !downstream_changed {
            continue;
        }

        if file_changed {
            // The registry changed: servers may have been added, removed, or
            // reconfigured, so reload and rebuild from scratch. This re-connects
            // everything, which also subsumes any pending downstream change.
            eprintln!("conduit: registry file changed on disk");
            // Don't advance `last` until a successful load, so a half-written file
            // (caught mid-save) is retried on the next tick instead of skipped.
            let new_reg = match registry::load_from(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("conduit: reload failed (will retry): {e}");
                    continue;
                }
            };
            last = current;
            // Build the new router (spawns processes) before taking locks.
            let new_router = build_router(&new_reg, profile.as_deref(), &downstream_dirty);
            let tools = new_router.aggregated_tools();
            *registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = new_reg;
            *router.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = new_router;
            maybe_check_integrity(&registry, &tools, profile.as_deref());
            persist_and_emit(&tools, &cached_tools, &stdout, profile.as_deref());
            eprintln!("conduit: registry changed, sent tools/list_changed");
        } else {
            // A live server announced a tool-list change. Re-query the existing
            // connections in place rather than re-spawning: a runtime or
            // session-scoped change (the usual reason a server sends this) would
            // be lost by a fresh process that never saw it.
            let tools = {
                let mut r = router.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                r.refresh_tools();
                r.aggregated_tools()
            };
            maybe_check_integrity(&registry, &tools, profile.as_deref());
            persist_and_emit(&tools, &cached_tools, &stdout, profile.as_deref());
            eprintln!("conduit: downstream tools/list_changed, refreshed + sent");
        }
    }
}

fn main() {
    // Lazy discovery resolves from an explicit env override first (per-client),
    // then the registry's global setting. Reading the registry means lazy mode
    // applies to EVERY client, including ones that don't forward env vars to the
    // gateway process (e.g. Antigravity) or servers added by hand in a client UI.
    let lazy = match std::env::var("CONDUIT_DISCOVERY") {
        Ok(v) => v.eq_ignore_ascii_case("lazy"),
        Err(_) => registry::load_resolved()
            .map(|r| r.lazy_discovery)
            .unwrap_or(true),
    };
    // Per-client scoping: this gateway exposes only the named profile's servers.
    let profile = std::env::var("CONDUIT_PROFILE")
        .ok()
        .filter(|s| !s.trim().is_empty());
    glog("=== gateway start ===");
    glog(&format!(
        "cwd={:?} CONDUIT_REGISTRY={:?} registry_path={:?} lazy={lazy} profile={profile:?}",
        std::env::current_dir().ok(),
        std::env::var("CONDUIT_REGISTRY").ok(),
        registry::resolved_path()
    ));
    let loaded = match registry::load_resolved() {
        Ok(r) => {
            glog(&format!(
                "load_resolved OK: {} servers total, {} enabled (active={})",
                r.servers.len(),
                r.enabled_servers().len(),
                r.active_profile_id()
            ));
            r
        }
        Err(e) => {
            // Always surface this (not only under CONDUIT_DEBUG). A corrupt or
            // unreadable registry would otherwise silently serve an empty catalog,
            // making every tool appear to vanish in the client with no explanation.
            // We keep running on a default so the gateway stays up, and the on-disk
            // tool cache still answers tools/list from the last good build.
            eprintln!(
                "conduit-gateway: could not load registry ({e}); serving cached tools only. \
                 Fix or recreate the registry to restore full functionality."
            );
            glog(&format!("load_resolved ERR: {e}"));
            registry::Registry::default()
        }
    };
    let registry = Arc::new(Mutex::new(loaded));
    // Empty router + cached catalog: the handshake and tools/list answer instantly
    // (from cache), while downstream servers connect in the background for the
    // actual tool calls.
    //
    // LOCK ORDER: when both are held, always lock `registry` before `router`. The
    // request loop, the watcher, and the self-heal path all follow this, so there's
    // no deadlock; keep new code consistent with it.
    let router = Arc::new(Mutex::new(Router::new()));
    let cached_tools = Arc::new(Mutex::new(load_tool_cache(profile.as_deref())));
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let ready = Arc::new(AtomicBool::new(false));
    // Flipped by any downstream transport that emits notifications/tools/list_changed.
    // The registry watcher polls it and rebuilds, so a server that changes its own
    // tool set mid-session propagates to the client instead of being dropped.
    let downstream_dirty = Arc::new(AtomicBool::new(false));
    glog(&format!(
        "loaded tool cache: {} tools",
        cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    ));

    {
        let registry = Arc::clone(&registry);
        let router = Arc::clone(&router);
        let stdout = Arc::clone(&stdout);
        let ready = Arc::clone(&ready);
        let cached_tools = Arc::clone(&cached_tools);
        let downstream_dirty = Arc::clone(&downstream_dirty);
        let profile = profile.clone();
        std::thread::spawn(move || {
            let reg = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let built = build_router(&reg, profile.as_deref(), &downstream_dirty);
            let tools = built.aggregated_tools();
            glog(&format!(
                "background build: {} tools from {} servers",
                tools.len(),
                built.server_count()
            ));
            *router.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = built;
            // Don't let a transient empty build (registry caught mid-write, or
            // every downstream momentarily unreachable) clobber a good catalog -
            // that's what leaves a client showing only conduit_status.
            if !tools.is_empty() {
                *cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = tools.clone();
                save_tool_cache(&tools, profile.as_deref());
            } else {
                glog("background build was empty; keeping previous tool cache");
            }
            ready.store(true, Ordering::SeqCst);
            notify_tools_changed(&stdout);
        });
    }

    if let Some(path) = registry::resolved_path() {
        let registry = Arc::clone(&registry);
        let router = Arc::clone(&router);
        let stdout = Arc::clone(&stdout);
        let cached_tools = Arc::clone(&cached_tools);
        let downstream_dirty = Arc::clone(&downstream_dirty);
        let profile = profile.clone();
        std::thread::spawn(move || {
            watch_registry(
                path,
                registry,
                router,
                stdout,
                cached_tools,
                profile,
                downstream_dirty,
            )
        });
    }

    let stdin = std::io::stdin();
    let mut search_guard = SearchGuard::default();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        gtrace(&format!("request: {method}"));

        // tools/list answers from cache instantly; only block on a cold cache
        // (first ever run). tools/call waits for live downstream connections.
        let wait = match method {
            "tools/list" => cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
            // These have no disk cache, so they need the live router connected.
            "tools/call" | "resources/list" | "resources/read" | "prompts/list"
            | "prompts/get" => true,
            _ => false,
        };
        if wait {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !ready.load(Ordering::SeqCst) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        // Self-heal: a tools/call with no live downstream servers means either the
        // startup read found none (transient) or a server was authed after we
        // built. Reload the registry and rebuild once so the call can route,
        // instead of failing with "no connected server".
        if method == "tools/call" && router.lock().unwrap_or_else(std::sync::PoisonError::into_inner).server_count() == 0 {
            let reg = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let built = build_router(&reg, profile.as_deref(), &downstream_dirty);
            if built.server_count() > 0 {
                let tools = built.aggregated_tools();
                *router.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = built;
                if !tools.is_empty() {
                    *cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = tools.clone();
                    save_tool_cache(&tools, profile.as_deref());
                }
                glog(&format!(
                    "self-heal: rebuilt router ({} servers, {} tools)",
                    router.lock().unwrap_or_else(std::sync::PoisonError::into_inner).server_count(),
                    tools.len()
                ));
                notify_tools_changed(&stdout);
            }
        }

        let cache_snapshot = cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let response = {
            let reg = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut r = router.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            handle_request(
                &req,
                &reg,
                &mut r,
                &cache_snapshot,
                lazy,
                profile.as_deref(),
                &mut search_guard,
            )
        };
        if let Some(resp) = response {
            let mut out = stdout.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if writeln!(out, "{resp}").is_err() {
                break;
            }
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        Router::new()
    }

    #[test]
    fn agent_control_gates_then_persists() {
        // Two servers, only Alpha enabled, agent control OFF.
        let path = std::env::temp_dir().join(format!("conduit-ac-test-{}.json", std::process::id()));
        let json = r#"{"version":1,
            "servers":[
                {"id":"a","name":"Alpha","transport":"stdio","command":"x","args":[],"env":[]},
                {"id":"b","name":"Beta","transport":"stdio","command":"x","args":[],"env":[]}],
            "profiles":[{"id":"p","name":"P","enabledServerIds":["a"]}],
            "activeProfileId":"p","allowAgentControl":false}"#;
        std::fs::write(&path, json).unwrap();
        let reg = registry::load_from(&path).unwrap();

        // Gated off: refused, and nothing on disk changes.
        assert!(set_server_enabled_via_agent(&reg, Some("p"), &path, "Beta", true).is_err());
        assert!(!registry::load_from(&path).unwrap().is_enabled("p", "b"));

        // Opt in (persisting it so the fresh-copy re-check passes), then enable
        // Beta by name, case-insensitively.
        let mut reg2 = reg.clone();
        reg2.allow_agent_control = true;
        registry::save_to(&path, &reg2).unwrap();
        let ok = set_server_enabled_via_agent(&reg2, Some("p"), &path, "beta", true);
        assert!(ok.is_ok(), "enable should succeed: {ok:?}");
        assert!(registry::load_from(&path).unwrap().is_enabled("p", "b"));
        // The destructive-tool safety switch is never reachable from agent control.
        assert!(!registry::load_from(&path).unwrap().deny_destructive);

        // Unknown server: helpful error naming the known ones.
        let bad = set_server_enabled_via_agent(&reg2, Some("p"), &path, "nope", true);
        assert!(bad.as_ref().is_err());
        assert!(bad.unwrap_err().contains("Alpha"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn initialize_echoes_protocol_and_advertises_tools() {
        let reg = Registry::default();
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None, &mut SearchGuard::default()).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(resp["result"]["capabilities"]["tools"]["listChanged"], true);
    }

    #[test]
    fn notifications_get_no_reply() {
        let reg = Registry::default();
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(&note, &reg, &mut router(), &[], false, None, &mut SearchGuard::default()).is_none());
    }

    #[test]
    fn tools_list_always_includes_status() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None, &mut SearchGuard::default()).unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"conduit_status"));
    }

    #[test]
    fn status_tool_reports_enabled_servers() {
        let mut reg = Registry::default();
        let id = reg.add_server(registry::ServerEntry {
            id: String::new(),
            name: "github".to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".to_string()),
            args: vec!["-y".to_string(), "@modelcontextprotocol/server-github".to_string()],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
        });
        reg.set_server_enabled("default", &id, true).unwrap();

        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "conduit_status", "arguments": {} }
        });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None, &mut SearchGuard::default()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn unknown_method_is_jsonrpc_error() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 9, "method": "frobnicate" });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None, &mut SearchGuard::default()).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    fn catalog() -> Vec<Value> {
        vec![
            json!({ "name": "resend__send_email", "description": "Send a transactional email", "inputSchema": {} }),
            json!({ "name": "stripe__list_charges", "description": "List recent charges", "inputSchema": {} }),
            json!({ "name": "rc__list_offerings", "description": "List offerings and email receipts", "inputSchema": {} }),
        ]
    }

    #[test]
    fn lazy_tools_list_returns_only_meta_tools() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        // Even with a full cached catalog, lazy mode advertises just the meta-tools.
        let resp = handle_request(&req, &reg, &mut router(), &catalog(), true, None, &mut SearchGuard::default()).unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"conduit_status"));
        assert!(names.contains(&"conduit_search_tools"));
        assert!(names.contains(&"conduit_call_tool"));
        assert!(!names.contains(&"resend__send_email"));
    }

    #[test]
    fn search_ranks_name_matches_first() {
        // "email" hits resend's name and rc's description; the name hit ranks higher.
        let (hits, total) = search_catalog(&catalog(), "email", None, 10);
        assert_eq!(hits[0]["name"], "resend__send_email");
        assert!(hits.iter().any(|h| h["name"] == "rc__list_offerings"));
        assert!(!hits.iter().any(|h| h["name"] == "stripe__list_charges"));
        assert_eq!(total, 2);
    }

    #[test]
    fn search_server_filter_scopes_and_enumerates() {
        // A `server` filter restricts to that server's tools...
        let (hits, _) = search_catalog(&catalog(), "list", Some("stripe"), 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["name"], "stripe__list_charges");
        // ...and an empty query with a `server` lists ALL of that server's tools.
        let (all, total) = search_catalog(&catalog(), "", Some("rc"), 10);
        assert_eq!(total, 1);
        assert_eq!(all[0]["name"], "rc__list_offerings");
    }

    #[test]
    fn menu_entries_are_compact_after_the_top() {
        // Past the top result, entries are name + a one-line description and no schema,
        // so a big result set stays small for a local model to re-read each turn.
        let cat = vec![
            json!({ "name": "a__one", "description": "x".repeat(5000), "inputSchema": { "type": "object" } }),
            json!({ "name": "a__two", "description": "y".repeat(5000), "inputSchema": { "type": "object" } }),
        ];
        let (hits, _) = search_catalog(&cat, "", Some("a"), 10);
        // Top: keeps schema and the longer description.
        assert!(hits[0].get("inputSchema").is_some());
        assert!(hits[0]["description"].as_str().unwrap().chars().count() <= 501);
        // Menu: no schema, short description.
        assert!(hits[1].get("inputSchema").is_none());
        assert_eq!(hits[1]["schemaOmitted"], json!(true));
        assert!(hits[1]["description"].as_str().unwrap().chars().count() <= 141);
    }

    #[test]
    fn search_diversifies_across_servers_when_unscoped() {
        // One server with many matching tools shouldn't crowd the others out.
        let mut cat = catalog();
        for i in 0..20 {
            cat.push(json!({
                "name": format!("rc__list_{i}"),
                "description": "list things",
                "inputSchema": {}
            }));
        }
        // "list" matches stripe (1), rc (21). With a small limit, stripe must still appear.
        let (hits, total) = search_catalog(&cat, "list", None, 6);
        assert!(total >= 22);
        assert!(hits.iter().any(|h| h["name"] == "stripe__list_charges"));
    }

    #[test]
    fn search_bounds_total_schema_size() {
        // Two tools with enormous schemas: the top result keeps its schema, the next
        // is returned without it (flagged), so the response can't blow up context.
        let big = json!({ "type": "object", "properties": { "x": { "description": "z".repeat(30_000) } } });
        let cat = vec![
            json!({ "name": "a__one", "description": "alpha", "inputSchema": big }),
            json!({ "name": "a__two", "description": "alpha", "inputSchema": big }),
        ];
        let (hits, _) = search_catalog(&cat, "alpha", Some("a"), 10);
        assert_eq!(hits.len(), 2);
        assert!(hits[0].get("inputSchema").is_some());
        assert!(hits[1].get("inputSchema").is_none());
        assert_eq!(hits[1].get("schemaOmitted").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn search_truncates_long_descriptions() {
        let cat = vec![json!({
            "name": "a__one", "description": "x".repeat(5000), "inputSchema": {}
        })];
        let (hits, _) = search_catalog(&cat, "", Some("a"), 10);
        let d = hits[0]["description"].as_str().unwrap();
        assert!(d.chars().count() <= 501); // 500 chars + ellipsis
        assert!(d.ends_with('…'));
    }

    #[test]
    fn search_tool_call_returns_matches() {
        let reg = Registry::default();
        let req = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "conduit_search_tools", "arguments": { "query": "charges" } }
        });
        let resp = handle_request(&req, &reg, &mut router(), &catalog(), true, None, &mut SearchGuard::default()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("stripe__list_charges"));
        assert_eq!(resp["result"]["isError"], false);
        // Response must lead with a named, ready-to-call directive and an explicit
        // anti-loop signal, so a compliant (esp. local) model commits to a call
        // instead of re-searching. Regression guard for the search-thrash fix.
        assert!(text.contains("Top match:"), "should name the top match");
        assert!(
            text.contains("call it now") || text.contains("call it"),
            "should tell the model to call now"
        );
        assert!(
            text.to_lowercase().contains("only search again"),
            "should signal not to keep searching"
        );
    }

    #[test]
    fn search_no_matches_guides_without_pushing_more_search() {
        let reg = Registry::default();
        let req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": "conduit_search_tools", "arguments": { "query": "zzznotarealtoolzzz" } }
        });
        let resp = handle_request(&req, &reg, &mut router(), &catalog(), true, None, &mut SearchGuard::default()).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("No tools matched"));
        // No phantom "Top match" when there's nothing to call.
        assert!(!text.contains("Top match:"));
    }

    const ESCALATION_MARK: &str = "keep getting the same top tool";

    fn search_req(query: &str) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": "conduit_search_tools", "arguments": { "query": query } }
        })
    }

    fn search_text(reg: &Registry, guard: &mut SearchGuard, query: &str) -> String {
        let resp =
            handle_request(&search_req(query), reg, &mut router(), &catalog(), true, None, guard)
                .unwrap();
        resp["result"]["content"][0]["text"].as_str().unwrap().to_string()
    }

    #[test]
    fn repeated_same_need_escalates_then_resets() {
        let reg = Registry::default();
        let mut guard = SearchGuard::default();

        // Same query keeps returning the same top tool; first two stay polite.
        for _ in 0..2 {
            let text = search_text(&reg, &mut guard, "charges");
            assert!(text.contains("Top match:"));
            assert!(!text.contains(ESCALATION_MARK));
        }
        // Third repeat of the same top tool trips the loop-breaker.
        let text = search_text(&reg, &mut guard, "charges");
        assert!(text.contains(ESCALATION_MARK), "3rd same-result search must escalate");
        assert!(text.contains("stripe__list_charges"));

        // Any non-search action resets the streak; the next search is polite again.
        let status = json!({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": { "name": "conduit_status", "arguments": {} }
        });
        handle_request(&status, &reg, &mut router(), &catalog(), true, None, &mut guard);
        let text = search_text(&reg, &mut guard, "charges");
        assert!(!text.contains(ESCALATION_MARK), "non-search action should reset the streak");
        assert!(text.contains("Top match:"));
    }

    #[test]
    fn searching_different_needs_never_escalates() {
        // The capable-model guarantee: a model that searches several DIFFERENT things
        // in a row (different top tool each time) is never cut off, no matter how many
        // searches. This is what keeps Claude/Cursor's exploration unaffected.
        let reg = Registry::default();
        let mut guard = SearchGuard::default();
        for q in ["charges", "offerings", "send", "charges", "offerings", "send"] {
            let text = search_text(&reg, &mut guard, q);
            assert!(text.contains("Top match:"), "query {q} should stay polite");
            assert!(!text.contains(ESCALATION_MARK), "query {q} must not escalate");
        }
    }

    #[test]
    fn unwrap_call_tool_tolerates_flattened_args() {
        // Correctly nested arguments.
        let (n, a) = unwrap_call_tool(&json!({
            "name": "vercel__list_projects",
            "arguments": { "teamId": "team_x" }
        }));
        assert_eq!(n, "vercel__list_projects");
        assert_eq!(a["teamId"], "team_x");

        // Flattened: a model put the param at the top level next to `name` (the
        // Jan/Vercel failure). It must still reach the tool, not arrive as undefined.
        let (n, a) = unwrap_call_tool(&json!({
            "name": "vercel__list_projects",
            "teamId": "team_x"
        }));
        assert_eq!(n, "vercel__list_projects");
        assert_eq!(a["teamId"], "team_x", "flattened args must still reach the tool");

        // No params (e.g. a list tool with no required args).
        let (n, a) = unwrap_call_tool(&json!({ "name": "x__list" }));
        assert_eq!(n, "x__list");
        assert_eq!(a, json!({}));

        // Empty nested object with no siblings stays empty.
        let (_, a) = unwrap_call_tool(&json!({ "name": "x__list", "arguments": {} }));
        assert_eq!(a, json!({}));
    }

    #[test]
    fn call_tool_arguments_allow_arbitrary_properties() {
        // Grammar-constrained clients (e.g. Jan) can only emit keys the schema permits.
        // If `arguments` declared no properties and no additionalProperties, the model
        // could only ever produce `{}`, so a required param could never be passed.
        let def = call_tool_def();
        assert_eq!(
            def["inputSchema"]["properties"]["arguments"]["additionalProperties"],
            json!(true),
            "conduit_call_tool's arguments must accept arbitrary properties"
        );
    }

    #[test]
    fn search_ranks_rare_token_over_common_one() {
        // The Stripe-wandering fix: "list products" should rank the products tool above
        // the many generic "list" tools, because "products" is rare (high IDF) and
        // "list" is common (low IDF).
        let mut cat = vec![json!({
            "name": "stripe__list_products", "description": "List products", "inputSchema": {}
        })];
        for i in 0..10 {
            cat.push(json!({
                "name": format!("svc{i}__list_items"), "description": "List items", "inputSchema": {}
            }));
        }
        let (hits, _) = search_catalog(&cat, "list products", None, 12);
        assert_eq!(hits[0]["name"], "stripe__list_products");
    }

    #[test]
    fn search_bridges_synonyms_and_stems_and_camelcase() {
        let cat = vec![
            json!({ "name": "resend__send_email", "description": "Send an email", "inputSchema": {} }),
            json!({ "name": "stripe__list_charges", "description": "List charges", "inputSchema": {} }),
            json!({ "name": "gh__listPullRequests", "description": "List PRs", "inputSchema": {} }),
        ];
        // Synonym: "mail" finds the email tool even though it never says "mail".
        let (hits, _) = search_catalog(&cat, "mail", None, 10);
        assert_eq!(hits[0]["name"], "resend__send_email");

        // Stemming: singular query matches the plural-ish tool name.
        let (hits, _) = search_catalog(&cat, "charge", None, 10);
        assert_eq!(hits[0]["name"], "stripe__list_charges");

        // camelCase: "pull requests" tokenizes listPullRequests into pull/request.
        let (hits, _) = search_catalog(&cat, "pull requests", None, 10);
        assert_eq!(hits[0]["name"], "gh__listPullRequests");
    }

    #[test]
    fn index_tokens_drops_boilerplate_and_stopwords() {
        let toks = index_tokens("**Purpose:** Returns the list of products for the user.");
        // capability words survive (stemmed); boilerplate + function words are gone.
        assert!(toks.contains(&"product".to_string()));
        assert!(toks.contains(&"list".to_string()));
        assert!(!toks.iter().any(|t| t == "purpose" || t == "return" || t == "the" || t == "of"));
    }

    #[test]
    fn search_ignores_query_noise_words() {
        // A query full of filler still lands on the right tool, the noise words don't
        // match anything and don't dilute the IDF signal of the real word ("invoices").
        let cat = vec![
            json!({ "name": "billing__list_invoices", "description": "List invoices", "inputSchema": {} }),
            json!({ "name": "misc__do_thing", "description": "Does a thing", "inputSchema": {} }),
        ];
        let (hits, _) = search_catalog(&cat, "what are the invoices for this account", None, 10);
        assert_eq!(hits[0]["name"], "billing__list_invoices");
    }

    #[test]
    fn trim_log_bounds_size_and_keeps_a_line_boundary() {
        // A file past the cap is trimmed to its back half, starting at a clean
        // line boundary, and the most recent line survives.
        let path = std::env::temp_dir().join("conduit-trim-test.log");
        let filler = "x".repeat(GATEWAY_LOG_CAP as usize + 8192);
        std::fs::write(&path, format!("OLDEST\n{filler}\nNEWEST\n")).unwrap();

        trim_log_if_large(&path);

        let after = std::fs::read_to_string(&path).unwrap();
        assert!((after.len() as u64) <= GATEWAY_LOG_CAP, "still over cap");
        assert!(after.ends_with("NEWEST\n"), "lost the newest line");
        assert!(!after.contains("OLDEST"), "kept the oldest line past the cap");
        assert!(!after.starts_with('x'), "did not cut on a line boundary");
        std::fs::remove_file(&path).ok();
    }
}
