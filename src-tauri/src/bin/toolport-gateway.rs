//! Toolport gateway.
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
//! - Lazy discovery: in lazy mode it advertises only 4 meta-tools (`toolport_status`,
//!   `toolport_search_tools`, `toolport_call_tool`, `toolport_fetch_result`) instead of the full catalog; the
//!   model searches and calls on demand, keeping context flat.
//! - Records every tool call to a local audit log.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use conduit_lib::audit;
use conduit_lib::clients;
use conduit_lib::downstream::{DownstreamServer, StdioTransport, PROTOCOL_VERSION};
use conduit_lib::inspect;
use conduit_lib::integrity;
use conduit_lib::registry::{self, Registry, ServerEntry};
use conduit_lib::remote;
use conduit_lib::router::{is_destructive, sanitize_segment, Router, ToolPolicy};
use conduit_lib::approval;
use conduit_lib::savings;
use conduit_lib::searchtrace;
use conduit_lib::secrets;
use conduit_lib::semantic;
use conduit_lib::shaping;

fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn status_tool_def() -> Value {
    json!({
        "name": "toolport_status",
        "description": "Report Toolport's status: the MCP servers enabled in the active profile, each server's tool count, and how many tokens (and dollars) lazy discovery has saved you so far.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
    })
}

/// The two meta-tools that power lazy discovery: search then call. In lazy mode
/// these (plus toolport_status) are the ONLY tools advertised, so the client's
/// context holds a handful of tool defs instead of hundreds - the model discovers
/// the real tool on demand and dispatches through `toolport_call_tool`.
///
/// The description leads with a directive plus GENERIC capability examples (email,
/// payments, deployments, ...) so the model treats Toolport as the front door for any
/// external action rather than grabbing a loosely-matched competitor tool or giving
/// up. We intentionally do NOT list the user's specific connected servers here: that
/// would scale the description with server count, go stale, and leak the user's stack
/// into a (possibly remote) model's context on every request. The generic examples
/// carry the routing without any of that; `toolport_status` names the actual servers
/// on demand if the model needs them.
fn search_tool_def() -> Value {
    json!({
        "name": "toolport_search_tools",
        "description": "Your single gateway to every connected MCP server and ALL their tools. \
            Try this FIRST for ANY external action or data the user asks for - sending or listing \
            email, deployments, payments, databases, repos, issues, files, web search, etc. Do NOT \
            reach for an unrelated tool or tell the user a capability is unavailable until you have \
            searched here; if the service is connected, its tool is here. Returns matching tools with \
            their exact name, description, and input schema; call one with toolport_call_tool. Once a \
            result matches what you need, call it - do NOT keep searching for a better one (the first \
            result includes its full schema and is ready to call). Pass `server` (a name/prefix like \
            \"resend\") to scope to one server, and pass an EMPTY `query` with `server` to list ALL of \
            that server's tools. If the result says more tools matched than were shown, narrow with \
            `server` or raise `limit` before concluding a capability is missing - many servers expose \
            a generic API bridge (a single write/create tool), so search by capability, not just an \
            exact operation name. toolport_status lists every server prefix and its tool count. Large \
            input schemas may be omitted from broad results (flagged schemaOmitted) to keep responses \
            small - search a tool's exact name to get its full schema.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keywords describing the capability you need (e.g. \"list emails\", \"create payment\", \"recent deployments\"). Empty lists tools (use with `server`)." },
                "server": { "type": "string", "description": "Optional: limit to this server, by name/prefix (e.g. \"resend\")." },
                "limit": { "type": "integer", "description": "Max results (default 25, up to 200).", "default": 25 }
            },
            "required": ["query"],
            "additionalProperties": false
        }
    })
}

fn call_tool_def() -> Value {
    json!({
        "name": "toolport_call_tool",
        "description": "Invoke a tool discovered via toolport_search_tools. Pass the tool's exact \
            `name` (as returned by the search) and put ALL of that tool's parameters INSIDE the \
            `arguments` object (matching its input schema) - not at the top level next to `name`. \
            Never invent or guess an identifier (teamId, accountId, projectId, etc.): if a required \
            value isn't known, first call a list or get tool on the SAME server to obtain it, then \
            call this with the real value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Exact tool name from toolport_search_tools." },
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

fn confirm_tool_def() -> Value {
    json!({
        "name": "toolport_confirm",
        "description": "Confirm and execute a destructive tool call that was intercepted for review. \
            When Toolport blocks a destructive call, it returns a preview with a `token`. \
            Call this with that token to proceed. The original arguments are replayed exactly \
            — you cannot change them. The token expires after 60 seconds.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": { "type": "string", "description": "The confirmation token from the intercepted call's response." }
            },
            "required": ["token"],
            "additionalProperties": false
        }
    })
}

fn fetch_result_tool_def() -> Value {
    json!({
        "name": "toolport_fetch_result",
        "description": "Read more of a large tool result that Toolport truncated. When a \
            result is too big for context, Toolport returns the head plus a cursor in a \
            `[Toolport shaped this result]` marker; call this with that `cursor` and the \
            `offset` shown in the marker to page through the rest. Nothing was lost.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cursor": { "type": "string", "description": "The cursor from the marker." },
                "offset": { "type": "integer", "minimum": 0, "description": "Character offset to read from (shown in the marker)." }
            },
            "required": ["cursor", "offset"],
            "additionalProperties": false
        }
    })
}

fn enable_server_tool_def() -> Value {
    json!({
        "name": "toolport_enable_server",
        "description": "Turn ON an MCP server in Toolport so its tools become available to you. \
            Pass the server's id or name (run toolport_status to see the list). Takes effect within \
            about a second. Only works when the user has allowed agent control in Toolport; the \
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
        "name": "toolport_disable_server",
        "description": "Turn OFF an MCP server in Toolport so its tools are no longer loaded. Pass the \
            server's id or name (run toolport_status to see the list). Takes effect within about a \
            second. Only works when the user has allowed agent control in Toolport.",
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
    // A registered HTTP client's allowed-server set (None = unscoped local/stdio). A
    // scoped client can only resolve and toggle servers in its scope, and the
    // "Known servers" list is filtered to it, so agent control can't toggle another
    // tenant's server or enumerate the full registry across tenants.
    allowed: Option<&std::collections::HashSet<String>>,
    // The calling client (a registered HTTP client's label), for the audit record.
    client: Option<&str>,
) -> Result<String, String> {
    // Every resolved outcome is stamped into the audit log so it carries proof of the
    // scope decision, not just the resulting behavior (see audit::record_agent_toggle).
    let action = if enable { "enable" } else { "disable" };
    let scoped = allowed.is_some();
    let toggle_profile = || profile.or(reg.active_profile_id.as_deref()).unwrap_or("");

    if !reg.allow_agent_control {
        audit::record_agent_toggle(
            client,
            toggle_profile(),
            action,
            target.trim(),
            None,
            "agent_control_off",
            scoped,
        );
        return Err(
            "Toolport: agent control is off. The user must turn on \"Allow agent control\" \
            in Toolport before an agent can enable or disable servers."
                .to_string(),
        );
    }
    let target = target.trim();
    if target.is_empty() {
        return Err(
            "Toolport: pass the `server` id or name to change (run toolport_status for the list)."
                .to_string(),
        );
    }
    // A scoped client sees (and can toggle) only servers in its allowed set; an
    // out-of-scope server is indistinguishable from a non-existent one.
    let in_scope =
        |s: &ServerEntry| allowed.map_or(true, |set| set.contains(&sanitize_segment(&s.id)));
    let server = match reg.servers.iter().find(|s| {
        in_scope(s) && (s.id.eq_ignore_ascii_case(target) || s.name.eq_ignore_ascii_case(target))
    }) {
        Some(s) => s,
        None => {
            // Denied/not-found: resolved_server_id stays null, so the record can't
            // reveal whether an out-of-scope server with this name exists.
            audit::record_agent_toggle(
                client,
                toggle_profile(),
                action,
                target,
                None,
                "unresolved",
                scoped,
            );
            let known: Vec<&str> = reg
                .servers
                .iter()
                .filter(|s| in_scope(s))
                .map(|s| s.name.as_str())
                .collect();
            return Err(format!(
                "Toolport: no server matches \"{target}\". Known servers: {}.",
                known.join(", ")
            ));
        }
    };
    let server_id = server.id.clone();
    let server_name = server.name.clone();
    let profile_id = profile
        .map(str::to_string)
        .or_else(|| reg.active_profile_id.clone())
        .ok_or_else(|| "Toolport: no active profile to change.".to_string())?;

    // Load fresh so a concurrent edit in the app isn't clobbered, and re-check the
    // opt-in on that fresh copy (the user may have just turned it off).
    let mut fresh = registry::load_from(path)
        .map_err(|e| format!("Toolport: could not read the registry ({e})."))?;
    if !fresh.allow_agent_control {
        audit::record_agent_toggle(
            client,
            &profile_id,
            action,
            target,
            Some(&server_id),
            "agent_control_off",
            scoped,
        );
        return Err("Toolport: agent control is off.".to_string());
    }
    if fresh.is_enabled(&profile_id, &server_id) == enable {
        audit::record_agent_toggle(
            client,
            &profile_id,
            action,
            target,
            Some(&server_id),
            "noop_already",
            scoped,
        );
        return Ok(format!(
            "{server_name} is already {}.",
            if enable { "on" } else { "off" }
        ));
    }
    fresh.set_server_enabled(&profile_id, &server_id, enable)?;
    registry::save_to(path, &fresh)
        .map_err(|e| format!("Toolport: could not save the registry ({e})."))?;
    audit::record_agent_toggle(
        client,
        &profile_id,
        action,
        target,
        Some(&server_id),
        if enable { "enabled" } else { "disabled" },
        scoped,
    );
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

/// Map a legacy `conduit_*` meta-tool name to its renamed `toolport_*` form, so the
/// old names keep working as aliases after the Conduit -> Toolport rebrand. Returns
/// `None` for anything that isn't one of the 7 legacy meta-tool names, so renamed
/// `toolport_*` names and downstream `server__tool` names pass through unchanged at
/// the call site.
fn canonical_meta(name: &str) -> Option<&'static str> {
    Some(match name {
        "conduit_status" => "toolport_status",
        "conduit_search_tools" => "toolport_search_tools",
        "conduit_call_tool" => "toolport_call_tool",
        "conduit_fetch_result" => "toolport_fetch_result",
        "conduit_confirm" => "toolport_confirm",
        "conduit_enable_server" => "toolport_enable_server",
        "conduit_disable_server" => "toolport_disable_server",
        _ => return None,
    })
}

/// Unwrap a `toolport_call_tool` payload into (inner tool name, inner arguments).
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
    "an",
    "the",
    "and",
    "or",
    "but",
    "if",
    "of",
    "to",
    "for",
    "in",
    "on",
    "at",
    "by",
    "with",
    "from",
    "into",
    "as",
    "is",
    "are",
    "be",
    "was",
    "were",
    "this",
    "that",
    "these",
    "those",
    "it",
    "its",
    "you",
    "your",
    "their",
    "them",
    "they",
    "we",
    "our",
    "us",
    "can",
    "will",
    "would",
    "should",
    "could",
    "may",
    "might",
    "do",
    "does",
    "did",
    "has",
    "have",
    "had",
    "not",
    "no",
    "all",
    "any",
    "each",
    "more",
    "most",
    "some",
    "such",
    "than",
    "then",
    "there",
    "here",
    "when",
    "where",
    "what",
    "which",
    "who",
    "whom",
    "how",
    "why",
    "also",
    "just",
    "only",
    "via",
    "per",
    "out",
    "off",
    "over",
    "under",
    "about",
    "between",
    "after",
    "before",
    "during",
    "while",
    "both",
    "either",
    // MCP-description boilerplate
    "purpose",
    "returns",
    "return",
    "use",
    "used",
    "uses",
    "using",
    "note",
    "notes",
    "example",
    "examples",
    "optional",
    "required",
    "param",
    "params",
    "parameter",
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
        &[
            "list", "get", "fetch", "show", "read", "find", "search", "view",
        ],
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

/// Human-readable "why this tool" for the search trace: which query terms hit the
/// tool's name vs its description. Reuses the same tokenizer and synonyms the ranker
/// scores with, so the explanation reflects the real match (minus IDF weighting).
/// Bounded so a long query can't bloat a trace line; an empty result means the tool
/// surfaced without a keyword hit (a semantic match, or a pinned prerequisite).
fn explain_match(query: &str, tool: &Value) -> Vec<String> {
    use std::collections::HashSet;
    let name = tool.get("name").and_then(Value::as_str).unwrap_or("");
    let desc = tool.get("description").and_then(Value::as_str).unwrap_or("");
    let name_set: HashSet<String> = search_tokens(name).into_iter().collect();
    let desc_set: HashSet<String> = index_tokens(desc).into_iter().collect();
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for qt in index_tokens(query) {
        let cands = std::iter::once(qt.as_str()).chain(synonym_group(qt.as_str()).iter().copied());
        for c in cands {
            let field = if name_set.contains(c) {
                Some("name")
            } else if desc_set.contains(c) {
                Some("desc")
            } else {
                None
            };
            if let Some(f) = field {
                let label = format!("{c} ({f})");
                if seen.insert(label.clone()) {
                    out.push(label);
                }
                break; // best (name-preferred) field for this query token
            }
        }
        if out.len() >= 6 {
            break;
        }
    }
    out
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

fn enabled_summary(
    reg: &Registry,
    cached: &[Value],
    profile: Option<&str>,
    allowed: Option<&std::collections::HashSet<String>>,
) -> String {
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

    // The set of server prefixes this caller may see. A scoped HTTP client sees
    // exactly its allowed set (its real scope, drawn from its own profile via the
    // bridge's union - never another tenant's name, command, URL, or tool count).
    // Stdio and the legacy full-access bridge token see the active profile, as
    // before. Both the server list and the tool counts are gated by this set, so
    // they always agree. Exclude Toolport's own gateway entry (infrastructure).
    let visible: std::collections::HashSet<String> = match allowed {
        Some(a) => a.clone(),
        None => reg
            .servers
            .iter()
            .filter(|s| reg.is_enabled(&active, &s.id) && !clients::is_gateway_server(s))
            .map(|s| sanitize_segment(&s.id))
            .collect(),
    };
    let servers: Vec<_> = reg
        .servers
        .iter()
        .filter(|s| {
            !clients::is_gateway_server(s) && visible.contains(sanitize_segment(&s.id).as_str())
        })
        .collect();
    let header = match allowed {
        Some(_) => "Servers available to this client".to_string(),
        None => format!("Profile '{profile_name}'"),
    };
    if servers.is_empty() {
        return format!("{header}: no servers enabled.");
    }

    let mut out = format!("{header} has {} enabled server(s):\n", servers.len());
    for s in servers {
        let target = match (&s.command, &s.url) {
            (Some(cmd), _) => format!("{} {}", cmd, s.args.join(" ")),
            (None, Some(url)) => url.clone(),
            _ => "(none)".to_string(),
        };
        out.push_str(&format!(
            "- {} [{}] {}\n",
            s.name,
            s.transport,
            target.trim()
        ));
    }

    // Tool counts by server prefix, from the live catalog, gated by the same
    // visible set so a scoped client never sees another tenant's tool counts.
    if !cached.is_empty() {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for t in cached {
            let prefix = tool_prefix(t);
            if !prefix.is_empty() && visible.contains(prefix.as_str()) {
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

/// One line summarizing what lazy discovery has saved, for toolport_status, so an
/// agent can answer "what is Toolport saving me?". Empty until something is saved
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
    if peak > 4 {
        line.push_str(&format!(
            "; the biggest catalog collapsed {peak} tools down to a handful of meta-tools"
        ));
    }
    line.push_str(".\n");
    line
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications (no reply).
/// Per-session guard against search-thrash. Weak local models (e.g. small-active
/// MoEs) will call toolport_search_tools many times in a row for the SAME need
/// instead of committing, which is slow and burns context. We escalate only on
/// that specific pattern (the same top tool surfacing across consecutive searches,
/// not on a raw search count). A capable model that searches once and calls, or
/// searches several DIFFERENT things (exploring), or narrows from broad to server
/// to exact-name (each a different, justified result), never trips this. So it fixes
/// the weak-model loop without ever penalizing Claude, Cursor, or any model doing
/// real multi-step work. Any non-search action resets it. Per client connection.
/// Interior-mutable so the HTTP workers can share ONE guard (the anti-thrash signal
/// is cross-request, so it can't be per-worker) without any of them holding a lock
/// across a downstream call: `lock()` is taken only for the brief bookkeeping below.
#[derive(Default)]
struct SearchGuard {
    inner: Mutex<SearchState>,
}

/// The mutable interior of a [`SearchGuard`], guarded by its lock.
#[derive(Default)]
struct SearchState {
    /// The top result's name from the previous consecutive search, if any.
    last_top: Option<String>,
    /// How many consecutive searches returned that same top result.
    repeats: u32,
}

impl SearchGuard {
    /// Lock the interior. Held only for the short guard update, never across dispatch.
    fn lock(&self) -> std::sync::MutexGuard<'_, SearchState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Any non-search action means the model committed, so the streak resets.
    fn reset(&self) {
        let mut s = self.lock();
        s.last_top = None;
        s.repeats = 0;
    }
}

/// Per-call confirmation state for destructive tools. When `confirm_destructive`
/// is on, the first call to a destructive tool returns a preview with a token;
/// `toolport_confirm { token }` replays the stored call. Entries expire after 60s.
struct ConfirmGuard {
    /// Pending confirmations: token → the exact call to replay. Behind a Mutex so the
    /// HTTP workers share ONE confirm set: a token stored by one request must be
    /// redeemable by a later `toolport_confirm` that may land on a different worker.
    pending: Mutex<std::collections::HashMap<String, PendingCall>>,
}

/// A stored destructive call awaiting confirmation.
struct PendingCall {
    /// The full tool name (e.g. `stripe__delete_customer`).
    name: String,
    /// The exact arguments from the preview call (serialized for replay).
    arguments: Value,
    /// When this entry was created (for expiry).
    created: Instant,
}

const CONFIRM_TTL: Duration = Duration::from_secs(60);

impl ConfirmGuard {
    fn new() -> Self {
        Self {
            pending: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Generate a cryptographically random 32-char hex token (128 bits of
    /// entropy via `getrandom`'s OS CSPRNG). Consistent with the codebase's
    /// own bearer-token convention. No silent fallback: a CSPRNG failure is a
    /// hard system error, not something to paper over on a security gate.
    fn new_token() -> String {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).expect("CSPRNG unavailable");
        buf.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Lock the pending set. Held only for the brief store/take, never across dispatch.
    fn pending(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, PendingCall>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Store a pending call and return its confirmation token.
    fn store(&self, name: String, arguments: Value) -> String {
        let mut pending = self.pending();
        // Evict expired entries to prevent unbounded growth.
        let cutoff = Instant::now() - CONFIRM_TTL;
        pending.retain(|_, v| v.created > cutoff);
        let token = Self::new_token();
        pending.insert(
            token.clone(),
            PendingCall {
                name,
                arguments,
                created: Instant::now(),
            },
        );
        token
    }

    /// Consume a confirmation token, returning the stored call if valid.
    /// Returns None if the token doesn't exist or has expired.
    fn take(&self, token: &str) -> Option<(String, Value)> {
        let entry = self.pending().remove(token)?;
        if entry.created.elapsed() > CONFIRM_TTL {
            return None; // expired
        }
        Some((entry.name, entry.arguments))
    }
}

/// Escalate once the SAME top tool has come back this many times in a row: the
/// model is stuck on one need, so return only that tool and command the call.
const SEARCH_REPEAT_LIMIT: u32 = 3;

/// True if the parameter name denotes an identifier or secret (teamId, team_id,
/// apiKey, token, ...), where a value equal to the field name or a schema type
/// word ("team_id", "string") is almost certainly an LLM placeholder rather than
/// real content. A content/query parameter is NOT an identifier, so those same
/// words are left alone there (a search for "string" is legitimate).
fn param_is_identifier(param: &str) -> bool {
    let low = param.to_ascii_lowercase();
    low == "id"
        || low.ends_with("_id")
        || param.ends_with("Id") // camelCase teamId / projectId
        || low.contains("key")
        || low.contains("token")
        || low.contains("secret")
}

/// True if a string argument value looks like an LLM-invented placeholder rather
/// than a real value (e.g. "your_team_id", "<team_id>", "REPLACE_ME"). `param` is
/// the argument's name: the collision-prone bare words ("string", "todo",
/// "team_id") only count as placeholders for an identifier-typed parameter, so a
/// legitimate search query or title of "todo" is never blocked. Deliberately
/// conservative: it must never block a real value.
fn looks_like_placeholder(param: &str, v: &str) -> bool {
    let s = v.trim();
    if s.is_empty() {
        return false;
    }
    // Unambiguous template forms: an LLM filled in a literal template. Never a
    // real value, whatever the parameter is.
    if (s.starts_with('<') && s.ends_with('>')) || (s.starts_with("{{") && s.ends_with("}}")) {
        return true;
    }
    let low = s.to_ascii_lowercase();
    if low.starts_with("your_")
        || low.starts_with("your-")
        || low.starts_with("your ")
        || low.ends_with("_here")
        || low.ends_with("-here")
        || matches!(
            low.as_str(),
            "placeholder" | "replace_me" | "replaceme" | "changeme" | "change_me" | "your_api_key"
        )
    {
        return true;
    }
    // Field-name / schema-type echoes (the model returned the parameter's own
    // name or a JSON-schema type word instead of a real value). Only a giveaway
    // for an identifier-typed parameter; for content fields these are real values.
    if param_is_identifier(param) {
        return matches!(
            low.as_str(),
            "string"
                | "example"
                | "todo"
                | "tbd"
                | "xxx"
                | "xxxx"
                | "id"
                | "key"
                | "token"
                | "team_id"
                | "teamid"
                | "account_id"
                | "accountid"
                | "project_id"
                | "projectid"
                | "api_key"
                | "apikey"
        );
    }
    false
}

/// Find the first argument whose string value looks like a placeholder.
fn find_placeholder_arg(arguments: &Value) -> Option<(String, String)> {
    arguments.as_object().and_then(|obj| {
        obj.iter().find_map(|(k, v)| {
            v.as_str()
                .filter(|s| looks_like_placeholder(k, s))
                .map(|s| (k.clone(), s.to_string()))
        })
    })
}

/// The resource a parameter identifies, derived from its name: "teamId" ->
/// "team", "account_id" -> "account". Used to prefer the right source tool.
fn resource_stem(param: &str) -> String {
    let low = param.to_ascii_lowercase();
    let stem = low
        .strip_suffix("_id")
        .or_else(|| low.strip_suffix("id"))
        .unwrap_or(&low);
    stem.trim_end_matches('_').to_string()
}

/// Sibling tools on the same server that look like they return resources or
/// identifiers (list/get/search/retrieve verbs), to point the model at a source
/// for a value it's missing. When `resource` is given (e.g. "team" for a missing
/// teamId), tools whose name mentions it rank first. General across every
/// server; only the gateway can do this because it holds the whole catalog.
fn source_tool_hints(
    catalog: &[Value],
    server: &str,
    resource: Option<&str>,
    max: usize,
) -> Vec<String> {
    let prefix = format!("{server}__");
    let mut hits: Vec<(bool, String)> = catalog
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .filter(|n| n.starts_with(&prefix))
        .filter_map(|n| {
            let bare = n[prefix.len()..].to_ascii_lowercase();
            let is_source = bare.starts_with("list")
                || bare.starts_with("get")
                || bare.starts_with("retrieve")
                || bare.contains("_list")
                || bare.contains("search");
            if !is_source {
                return None;
            }
            let on_resource = resource
                .map(|r| !r.is_empty() && bare.contains(r))
                .unwrap_or(false);
            Some((on_resource, n.to_string()))
        })
        .collect();
    // Resource-matching tools first, then alphabetical for stability.
    hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    hits.into_iter().map(|(_, n)| n).take(max).collect()
}

/// A one-line recovery hint naming sibling list/get tools, appended when a call
/// fails so the model can source a missing/invalid identifier and retry.
fn recovery_hint(catalog: &[Value], server: &str) -> String {
    let hints = source_tool_hints(catalog, server, None, 3);
    if hints.is_empty() {
        String::new()
    } else {
        format!(
            " If a required identifier was missing or wrong, get valid values from one of these on '{server}', then retry: {}.",
            hints.join(", ")
        )
    }
}

/// The server prefix of a namespaced tool name (`server__tool`). Matches the
/// router's `sanitize_segment(server_id)` prefix, so it tests against the
/// allowed-server set the same way the router names tools.
fn server_of_tool(name: &str) -> &str {
    name.split_once("__").map(|(s, _)| s).unwrap_or(name)
}

/// Whether the exposed tool `name` is destructive, for the HITL / confirm gate. Resolves
/// from the cached catalog first, then the LIVE router if the cache doesn't list it (a
/// cold or stale cache, or a tool whose `destructiveHint` was just added by drift). If
/// NEITHER can resolve the tool, it's treated as destructive - a gate that can't see a
/// tool must not wave it through (fail-closed). A truly unknown tool fails at routing
/// anyway, so the only effect is that a genuinely-destructive-but-uncached tool is never
/// silently ungated.
fn tool_is_destructive_fail_closed(name: &str, cached: &[Value], router: &Router) -> bool {
    let lookup = |tools: &[Value]| {
        tools
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
            .map(is_destructive)
    };
    if let Some(d) = lookup(cached) {
        return d;
    }
    if let Some(d) = lookup(&router.aggregated_tools()) {
        return d;
    }
    true
}

/// Keep only tools whose server prefix is in `allowed`. `None` = no scoping
/// (every tool passes). A meta-tool (no `server__` namespace, e.g.
/// `toolport_search_tools`) is always kept, since it isn't owned by any
/// downstream server. Scopes a registered HTTP client's view to its servers.
fn scope_tools(tools: &[Value], allowed: Option<&std::collections::HashSet<String>>) -> Vec<Value> {
    match allowed {
        None => tools.to_vec(),
        Some(set) => tools
            .iter()
            .filter(|t| {
                t.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| {
                        let srv = server_of_tool(n);
                        // A meta-tool has no namespace (server_of_tool returns the
                        // whole name); always keep it. Otherwise gate on the server.
                        srv == n || set.contains(srv)
                    })
                    .unwrap_or(false)
            })
            .cloned()
            .collect(),
    }
}

/// Resolve an HTTP bearer to (authorized, scope). `Some(allowed)` = authorized,
/// where `allowed` is the set of server prefixes the client may see (`None` =
/// the full connected set). The outer `None` = unauthorized. Pure given the
/// registry + tokens, so the auth/scope policy is unit-testable.
fn resolve_http_scope(
    reg: &Registry,
    env_token: Option<&str>,
    provided: Option<&str>,
) -> Option<Option<std::collections::HashSet<String>>> {
    use std::collections::HashSet;
    // Legacy single token: sees the full connected set (back-compat).
    if let (Some(t), Some(p)) = (env_token, provided) {
        if ct_eq(p.as_bytes(), t.as_bytes()) {
            return Some(None);
        }
    }
    // A registered client is scoped to its profile (empty profile = full set).
    if let Some(p) = provided {
        if let Some(client) = reg.http_client_for_token(p) {
            if client.profile.trim().is_empty() {
                return Some(None);
            }
            let set: HashSet<String> = reg
                .enabled_servers_for(&client.profile)
                .iter()
                .map(|s| sanitize_segment(&s.id))
                .collect();
            return Some(Some(set));
        }
    }
    // No auth configured at all: open, preserving the loopback default.
    if env_token.is_none() && reg.http_clients.is_empty() {
        return Some(None);
    }
    None
}

/// The audit label for a registered HTTP client's bearer: its `label`, or its `id`
/// when the label is blank. `None` when the token isn't a registered client (legacy
/// single-token, open loopback, or the local stdio app), so those calls stay
/// unattributed in the audit log rather than mislabeled. Pure, so it's unit-testable.
fn http_client_label(reg: &Registry, provided: Option<&str>) -> Option<String> {
    let client = reg.http_client_for_token(provided?)?;
    Some(if client.label.trim().is_empty() {
        client.id.clone()
    } else {
        client.label.clone()
    })
}

#[allow(clippy::too_many_arguments)]
/// A fresh 128-bit correlation id for an approval request (same CSPRNG-or-die policy
/// as the confirm token: a randomness failure on a security gate is fatal, not papered).
fn new_correlation_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("CSPRNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the approval-broker endpoint the Toolport app publishes into the data dir.
/// `None` when it is absent/unreadable (the app is not running) - a fail-closed signal.
fn read_endpoint_descriptor() -> Option<approval::EndpointDescriptor> {
    let dir = conduit_lib::registry::conduit_dir()?;
    let raw = std::fs::read_to_string(dir.join(approval::ENDPOINT_FILE)).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Ask the app broker for a human decision on `req`. FAIL-CLOSED: a missing endpoint, a
/// failed connect, any I/O error, or a read timeout all return `Timeout` (a deny). The
/// arguments travel over the socket and never touch disk. Transport is loopback TCP +
/// token for now; hardening to an OS-permissioned named-pipe / uds is a follow-up.
fn decide_via_broker(
    desc: Option<approval::EndpointDescriptor>,
    req: &mut approval::ApprovalRequest,
) -> approval::ApprovalDecision {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    let deny = approval::ApprovalDecision::Timeout;
    let Some(desc) = desc else { return deny };
    req.token = desc.token.clone();
    let Ok(mut stream) = TcpStream::connect(&desc.endpoint) else { return deny };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(approval::DEFAULT_TIMEOUT_SECS)));
    let Ok(line) = serde_json::to_string(req) else { return deny };
    if stream.write_all(line.as_bytes()).is_err() || stream.write_all(b"\n").is_err() {
        return deny;
    }
    let _ = stream.flush();
    let mut resp = String::new();
    if BufReader::new(stream).read_line(&mut resp).is_err() || resp.trim().is_empty() {
        return deny;
    }
    serde_json::from_str::<approval::ApprovalDecision>(resp.trim()).unwrap_or(deny)
}

/// Hold a gated tool call until a human decides via the Toolport app (or it fails closed).
fn request_human_decision(mut req: approval::ApprovalRequest) -> approval::ApprovalDecision {
    let desc = read_endpoint_descriptor();
    decide_via_broker(desc, &mut req)
}

#[allow(clippy::too_many_arguments)]
fn handle_request(
    req: &Value,
    reg: &Registry,
    router: &Router,
    cached: &[Value],
    lazy: bool,
    profile: Option<&str>,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    allowed: Option<&std::collections::HashSet<String>>,
    // The client this request is attributed to (a registered HTTP client's audit
    // label), threaded in rather than stored on the shared router so concurrent
    // requests can't cross-contaminate and dispatch needn't hold the router lock.
    client: Option<&str>,
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
                    "serverInfo": { "name": "toolport-gateway", "version": env!("CARGO_PKG_VERSION") }
                }),
            ))
        }
        "tools/list" => {
            // Lazy mode: advertise only the meta-tools, so the client's context
            // holds a handful of tool defs instead of the whole catalog. The model
            // finds real tools via toolport_search_tools and runs toolport_call_tool.
            if lazy {
                let mut tools = vec![
                    status_tool_def(),
                    search_tool_def(),
                    call_tool_def(),
                    fetch_result_tool_def(),
                ];
                // Opt-in: surface the agent-control tools only when the user has
                // allowed it, so an agent can't even see them otherwise.
                if reg.allow_agent_control {
                    tools.push(enable_server_tool_def());
                    tools.push(disable_server_tool_def());
                }
                // The confirm tool is advertised only while confirmation is on,
                // so an agent can't see it (and attempt to call it) otherwise.
                if reg.confirm_destructive {
                    tools.push(confirm_tool_def());
                }
                // Record what lazy discovery kept out of the client's context: the
                // full catalog we'd otherwise serve (status + every downstream tool)
                // minus these 4 meta-tools. Estimating over the cached slice avoids
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
                gtrace(&format!(
                    "tools/list -> {} meta-tools (lazy discovery)",
                    tools.len()
                ));
                return Some(success(id, json!({ "tools": tools })));
            }
            let mut tools = vec![status_tool_def(), fetch_result_tool_def()];
            // The confirm tool is advertised only while confirmation is on.
            if reg.confirm_destructive {
                tools.push(confirm_tool_def());
            }
            // Prefer the cached catalog (instant); fall back to the live router.
            // Scope to the client's allowed servers (a no-op when unscoped), so a
            // registered HTTP client only ever sees its own servers' tools.
            let catalog = if cached.is_empty() {
                router.aggregated_tools()
            } else {
                cached.to_vec()
            };
            tools.extend(scope_tools(&catalog, allowed));
            gtrace(&format!(
                "tools/list -> {} tools (cache={})",
                tools.len(),
                !cached.is_empty()
            ));
            Some(success(id, json!({ "tools": tools })))
        }
        "tools/call" => {
            let params = req.get("params");
            // `name`/`arguments` are mutable so the toolport_confirm handler
            // below can swap in the stored (confirmed) call and fall through to
            // the normal routing code instead of returning early.
            let mut name = params
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            // Accept the legacy conduit_* meta-tool names as aliases for the renamed
            // toolport_* names, so a client/model still using the old names keeps
            // working. Only the 7 known meta names are rewritten; downstream
            // `server__tool` names and the new toolport_* names pass through.
            if let Some(canon) = canonical_meta(&name) {
                name = canon.to_string();
            }
            let mut arguments = params
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            // True when this call arrived via toolport_confirm (the stored call
            // was already reviewed). Skips the destructive-interception check
            // below so the confirmed call isn't re-intercepted in a loop.
            let mut confirmed = false;

            // Anything other than a search breaks the search-thrash streak.
            if name != "toolport_search_tools" {
                guard.reset();
            }

            if name == "toolport_fetch_result" {
                let cursor = arguments
                    .get("cursor")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let offset = arguments
                    .get("offset")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                let len = arguments.get("len").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                // Pass the calling client so a client can only fetch results it stashed
                // (the stash is process-global in HTTP mode).
                return Some(success(id, shaping::fetch_result(cursor, offset, len, client)));
            }

            // toolport_confirm: replay a previously-intercepted destructive call.
            // On a valid token, overwrite `name`/`arguments` with the stored call
            // and fall through to the normal routing below (no early return).
            if name == "toolport_confirm" {
                let token = arguments
                    .get("token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if token.is_empty() {
                    return Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": "Toolport: pass the `token` from the intercepted call's preview." }],
                            "isError": true
                        }),
                    ));
                }
                match confirm.take(token) {
                    Some((confirmed_name, confirmed_args)) => {
                        name = confirmed_name;
                        arguments = confirmed_args;
                        confirmed = true;
                    }
                    None => {
                        return Some(success(
                            id,
                            json!({
                                "content": [{ "type": "text", "text": "Toolport: token expired or invalid. Call the tool again to get a new preview." }],
                                "isError": true
                            }),
                        ));
                    }
                }
            }

            if name == "toolport_status" {
                return Some(success(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": enabled_summary(reg, cached, profile, allowed) }],
                        "isError": false
                    }),
                ));
            }

            if name == "toolport_search_tools" {
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
                let base: &[Value] = if cached.is_empty() {
                    live = router.aggregated_tools();
                    &live
                } else {
                    cached
                };
                // Scope the searchable catalog to the client's allowed servers
                // (a no-op when unscoped), so search can't surface out-of-scope tools.
                let scoped = scope_tools(base, allowed);
                let source: &[Value] = &scoped;
                // Semantic re-ranking if the user has configured it (off by default;
                // falls back to lexical on any failure).
                let s = &reg.semantic_search;
                let sem_cfg = semantic::SemanticConfig::resolve(
                    s.enabled,
                    s.endpoint.clone(),
                    s.model.clone(),
                    s.blend,
                );
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
                // Lock only for the streak bookkeeping; capture `repeats` so nothing
                // holds the guard lock past this point.
                let repeats = {
                    let mut s = guard.lock();
                    if !matches.is_empty() && s.last_top.as_deref() == Some(top.as_str()) {
                        s.repeats += 1;
                    } else {
                        s.repeats = 1;
                        s.last_top = (!matches.is_empty()).then(|| top.clone());
                    }
                    s.repeats
                };
                let escalate = repeats >= SEARCH_REPEAT_LIMIT && !matches.is_empty();
                if escalate {
                    matches.truncate(1); // only the best match, no distractions
                }
                // Always surface pinned prerequisite tools (with their full schema),
                // even if the query didn't rank them, so a load-bearing tool (auth /
                // list-before-act, or one whose description doesn't match the keywords)
                // is never hidden behind lazy discovery. Scoped (source is already the
                // client's catalog) and capped so a big pin set can't itself bloat.
                let mut pins_added = 0usize;
                if !reg.pinned_tools.is_empty() {
                    let have: std::collections::HashSet<&str> = matches
                        .iter()
                        .filter_map(|m| m.get("name").and_then(Value::as_str))
                        .collect();
                    let mut pinned: Vec<Value> = source
                        .iter()
                        .filter(|t| {
                            t.get("name")
                                .and_then(Value::as_str)
                                .map(|n| !have.contains(n))
                                .unwrap_or(false)
                                && t.get("name")
                                    .and_then(Value::as_str)
                                    .and_then(|n| router.route_of(n))
                                    .map(|(srv, orig)| reg.is_tool_pinned(srv, orig))
                                    .unwrap_or(false)
                        })
                        .take(10)
                        .cloned()
                        .collect();
                    if !pinned.is_empty() {
                        // Prepend so prerequisites lead the results.
                        pins_added = pinned.len();
                        pinned.append(&mut matches);
                        matches = pinned;
                    }
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
                    m.get("schemaOmitted")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                });
                // Note only clarifies the OMITTED (non-top) results need a follow-up;
                // the first result always carries its schema, so it never does.
                let schema_note = if omitted {
                    " Results after the first may omit large input schemas (schemaOmitted); to call \
                     one of those instead, search its exact name or pass `server` to get its schema."
                } else {
                    ""
                };
                // Pinned prerequisites are prepended (not query-ranked), so name them so
                // the "top match" directive below isn't confused with the leading rows.
                let pin_note = if pins_added > 0 {
                    format!(
                        " ({pins_added} pinned prerequisite tool(s) listed first, before the ranked matches.)"
                    )
                } else {
                    String::new()
                };
                let lead = if matches.is_empty() {
                    format!(
                        "No tools matched{scope}. Try different keywords, or call toolport_status to \
                         see the connected servers and their tool counts."
                    )
                } else if escalate {
                    // Behavioral loop-breaker: the model keeps re-searching the same need
                    // and landing on the same tool. Give it that one tool and a command,
                    // not more options to graze on. (Only fires on a repeated top result,
                    // so a model exploring different needs is never cut off.)
                    format!(
                        "You have searched {} times and keep getting the same top tool, `{top}`. It \
                         is the best match and its full input schema is below - call toolport_call_tool \
                         now with name \"{top}\". Searching again will keep returning this. Only if \
                         `{top}` genuinely cannot do the task, call toolport_status to see other servers.{pin_note}",
                        repeats
                    )
                } else {
                    // Lead with a single, named, ready-to-call directive so the model
                    // commits instead of re-searching (the v0.3.6 keep-searching nudges
                    // overcorrected and made compliant models thrash).
                    format!(
                        "Found {total} matching tool(s){scope}. Top match: `{top}` - its full input \
                         schema is included below, so call it now with toolport_call_tool (name: \
                         \"{top}\") if it fits. Only search again if none of these match.{pin_note}{more}{schema_note}"
                    )
                };
                let text = format!(
                    "{lead}\n\n{}",
                    serde_json::to_string_pretty(&matches).unwrap_or_default()
                );
                // Record the trace: the ground-truth cost of what THIS search returned
                // vs. what advertising the whole (scoped) catalog would cost per turn.
                // Being in-path, we know both exactly rather than estimating from logs.
                let returned_names: Vec<String> = matches
                    .iter()
                    .filter_map(|m| m.get("name").and_then(|v| v.as_str()).map(str::to_string))
                    .collect();
                // Per-result "why it surfaced": rank, the query terms it matched (name
                // vs description), and whether it's a prepended pinned prerequisite
                // rather than a query hit. Turns "which tools" into "why this tool".
                let ranking: Vec<Value> = matches
                    .iter()
                    .enumerate()
                    .map(|(i, m)| {
                        json!({
                            "name": m.get("name").and_then(Value::as_str).unwrap_or(""),
                            "rank": i + 1,
                            "matched": explain_match(query, m),
                            "pinned": i < pins_added,
                        })
                    })
                    .collect();
                // Reflects the configured ranker (semantic re-rank falls back to lexical
                // on any embedding failure, so this is the intended mode, not a per-call
                // guarantee it succeeded).
                let mode = if sem_cfg.is_active() { "semantic" } else { "lexical" };
                searchtrace::record(
                    client,
                    query,
                    server,
                    &top,
                    &returned_names,
                    matches.len(),
                    total,
                    savings::estimate_tokens(&matches),
                    savings::estimate_tokens(source),
                    escalate,
                    &ranking,
                    mode,
                );
                return Some(success(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                ));
            }

            if name == "toolport_enable_server" || name == "toolport_disable_server" {
                let enable = name == "toolport_enable_server";
                let target = arguments
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let result = match registry::resolved_path() {
                    Some(p) => set_server_enabled_via_agent(
                        reg, profile, &p, target, enable, allowed, client,
                    ),
                    None => Err("Toolport: could not locate the registry file.".to_string()),
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

            // toolport_call_tool dispatches a discovered tool: unwrap to its real
            // name + arguments and fall through to the normal routing below.
            let (name, arguments) = if name == "toolport_call_tool" {
                unwrap_call_tool(&arguments)
            } else {
                (name, arguments)
            };
            let name = name.as_str();

            // Resolve the call's real (server, original tool) from the router's route map,
            // NOT by splitting the exposed name on `__`. A renamed tool (via a tool override)
            // or a server id containing `__` would otherwise mis-derive the server and
            // silently weaken the scope guard and the HITL untrusted-provenance check below.
            let (server_id, tool_name) = router
                .route_of(name)
                .map(|(s, t)| (s.to_string(), t.to_string()))
                .unwrap_or_else(|| (String::new(), name.to_string()));
            let srv_owned = sanitize_segment(&server_id);
            let srv = srv_owned.as_str();
            let tool = tool_name.as_str();

            // Scope guard: a registered HTTP client may only call tools on the
            // servers its token is allowed to see (a no-op when unscoped). Search
            // and list are already filtered, but a client could name any tool, so
            // enforce it on the call path too.
            if let Some(set) = allowed {
                if !set.contains(srv) {
                    return Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": format!("Toolport: '{srv}' is not available to this client.") }],
                            "isError": true
                        }),
                    ));
                }
            }

            // Pre-call guard: a model that invents an identifier (e.g.
            // teamId = "your_team_id") would otherwise waste a downstream call
            // and get a confusing failure. Catch obvious placeholders and point
            // it at where to source the real value. General across every server.
            if let Some((param, value)) = find_placeholder_arg(&arguments) {
                let resource = resource_stem(&param);
                let hints = source_tool_hints(cached, srv, Some(&resource), 3);
                let source = if hints.is_empty() {
                    format!("call a list or get tool on the '{srv}' server")
                } else {
                    format!(
                        "call one of these on the '{srv}' server first: {}",
                        hints.join(", ")
                    )
                };
                let msg = format!(
                    "Toolport: \"{value}\" for \"{param}\" looks like a placeholder, not a real \
                     value, and was not sent. Don't invent identifiers. To get a real \"{param}\", \
                     {source}, then call {name} again with the value it returns."
                );
                return Some(success(
                    id,
                    json!({ "content": [{ "type": "text", "text": msg }], "isError": true }),
                ));
            }

            // Human-in-the-loop approval: hold a gated call (destructive, or from an
            // untrusted-provenance server) until a person approves it in the Toolport app.
            // Takes precedence over the agent-facing confirm below, and is fail-closed
            // (no broker / no answer / timeout all deny). Skipped once `confirmed`.
            if reg.human_approval && !confirmed {
                // Resolve destructiveness robustly: cache, then live router, else
                // fail-closed (an unknown tool must not skip the human gate).
                let is_dest = tool_is_destructive_fail_closed(name, cached, router);
                // Untrusted provenance = the same shared/registry signal the SSRF guard
                // uses. Match the server the way its tools are prefixed (sanitized id).
                let untrusted = reg
                    .servers
                    .iter()
                    .find(|s| sanitize_segment(&s.id) == srv)
                    .map(|s| matches!(s.source.as_deref(), Some("shared") | Some("registry")))
                    .unwrap_or(false);
                if let Some(reason) = approval::gate_reason(true, is_dest, untrusted) {
                    let decision = request_human_decision(approval::ApprovalRequest {
                        token: String::new(),
                        id: new_correlation_id(),
                        client: client.map(str::to_string),
                        server: srv.to_string(),
                        tool: tool.to_string(),
                        reason,
                        arguments: arguments.clone(),
                    });
                    if !decision.is_approved() {
                        let why = if decision == approval::ApprovalDecision::Denied {
                            "was denied by a human reviewer"
                        } else {
                            "was not approved in time (the Toolport app may be closed)"
                        };
                        audit::record_held(srv, tool, client);
                        return Some(success(
                            id,
                            json!({
                                "content": [{ "type": "text", "text": format!(
                                    "Toolport: the call to {name} {why}, so it did not run. \
                                     Ask the user to approve it in the Toolport app, then retry."
                                ) }],
                                "isError": true
                            }),
                        ));
                    }
                    // A human approved: skip the agent-confirm step and route the call.
                    confirmed = true;
                }
            }

            // Per-call confirmation for destructive tools: intercept the first
            // call with these arguments, store it, and return a preview. The
            // agent calls toolport_confirm { token } to replay the stored call.
            // This runs AFTER the placeholder guard (so a placeholder never
            // gets a token) and BEFORE the actual route_call (so a destructive
            // call never reaches the downstream server unconfirmed).
            // Skip when `confirmed` is true: the call arrived via toolport_confirm
            // and was already reviewed (prevents re-interception loop).
            if reg.confirm_destructive && !confirmed {
                // Resolve destructiveness robustly (cache, then live router, else
                // fail-closed), so a cold/stale cache can't skip the confirm step for a
                // destructive tool.
                let dest = tool_is_destructive_fail_closed(name, cached, router);
                if dest {
                    let token = confirm.store(name.to_string(), arguments.clone());
                    let args_pretty = serde_json::to_string_pretty(&arguments).unwrap_or_default();
                    let msg = format!(
                        "⚠️ Destructive action intercepted.\n\nTool: {name}\nArguments:\n{args_pretty}\n\n\
                         Review the arguments above carefully. If correct, call toolport_confirm \
                         with token: {token}\n\
                         The token expires in 60 seconds. The original arguments will be replayed \
                         exactly."
                    );
                    // Held for confirmation, not a failure: record as held (ok), so the
                    // confirm-destructive feature doesn't inflate the error rate.
                    audit::record_held(srv, tool, client);
                    return Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": msg }],
                            "isError": true
                        }),
                    ));
                }
            }

            // Live inspection (opt-in, off by default): capture the raw request
            // args now, only when enabled, so the response can be paired with them
            // below. When off, nothing is cloned and nothing is ever captured.
            let inspect_args = if reg.live_inspect {
                Some(arguments.clone())
            } else {
                None
            };

            let started = Instant::now();
            match router.route_call(name, arguments) {
                Ok(mut result) => {
                    let ok = !result
                        .get("isError")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let ms = started.elapsed().as_millis() as u64;
                    // Capture the failure message (the result's text) before shaping
                    // rewrites the content, so Activity can show why the call failed.
                    let err = if ok {
                        None
                    } else {
                        Some(content_text(&result))
                    };
                    audit::record_timed(srv, tool, ok, Some(ms), err.as_deref(), client);
                    // Live inspection: capture the RAW result here, before content
                    // defense and shaping rewrite it, so the inspector shows exactly
                    // what the server returned. Only runs when live_inspect is on
                    // (inspect_args is Some only then). Attributed to the same client
                    // as the audit line.
                    if let Some(req) = &inspect_args {
                        inspect::record(client, srv, tool, req, &result, ok, ms);
                    }
                    // Content defense: scan this untrusted tool output for injection
                    // and label any flagged text as data before it reaches the agent.
                    if reg.content_defense {
                        integrity::inspect_result(srv, tool, &mut result);
                    }
                    // Result-shaping: cap an oversized result, cache the full body, and
                    // hand the model a head + a toolport_fetch_result cursor (lossless).
                    // Per-server fidelity policy: a server's `resultBudget` overrides the
                    // global default (Some(0) = never shape, for full-fidelity servers).
                    let budget = reg
                        .result_budgets
                        .get(srv)
                        .map(|&b| b as usize)
                        .unwrap_or_else(shaping::budget);
                    shaping::shape_result(&mut result, budget, client);
                    // Recover from a downstream failure: point the model at
                    // sibling list/get tools that can supply a missing/invalid
                    // identifier. Appended after shaping so it's never truncated.
                    if !ok {
                        let hint = recovery_hint(cached, srv);
                        if !hint.is_empty() {
                            if let Some(arr) =
                                result.get_mut("content").and_then(|c| c.as_array_mut())
                            {
                                arr.push(json!({ "type": "text", "text": hint.trim() }));
                            }
                        }
                    }
                    Some(success(id, result))
                }
                Err(e) => {
                    let ms = started.elapsed().as_millis() as u64;
                    audit::record_timed(srv, tool, false, Some(ms), Some(&e), client);
                    // Live inspection: capture the failed call too, with the error
                    // as the response body. Only when live_inspect is on.
                    if let Some(req) = &inspect_args {
                        inspect::record(client, srv, tool, req, &json!({ "error": e }), false, ms);
                    }
                    let recovery = recovery_hint(cached, srv);
                    Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": format!("Toolport: {e}.{recovery}") }],
                            "isError": true
                        }),
                    ))
                }
            }
        }
        "resources/list" => {
            let mut resources = router.aggregated_resources();
            // Scope to the client's allowed servers (a no-op when unscoped), so a
            // registered HTTP client can't list another server's resources.
            if let Some(set) = allowed {
                resources.retain(|r| {
                    r.get("uri")
                        .and_then(|u| u.as_str())
                        .and_then(|uri| router.resource_server(uri))
                        .map(|srv| set.contains(srv))
                        .unwrap_or(false)
                });
            }
            gtrace(&format!("resources/list -> {} resources", resources.len()));
            Some(success(id, json!({ "resources": resources })))
        }
        "resources/read" => {
            let uri = req
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            // Scope guard: a registered HTTP client may only read resources on servers
            // its token allows. Out-of-scope is reported as not-found so a scoped client
            // can't probe another server's resource names.
            if let Some(set) = allowed {
                let in_scope = router
                    .resource_server(uri)
                    .map(|srv| set.contains(srv))
                    .unwrap_or(false);
                if !in_scope {
                    return Some(error(id, -32602, &format!("Toolport: no server owns resource '{uri}'")));
                }
            }
            match router.read_resource(uri) {
                Ok(mut result) => {
                    // Content defense: a resource is as attacker-controllable as a tool
                    // result, so scan it for injection and label any flagged text as data.
                    if reg.content_defense {
                        integrity::inspect_result(uri, "resource", &mut result);
                    }
                    Some(success(id, result))
                }
                Err(e) => Some(error(id, -32602, &format!("Toolport: {e}"))),
            }
        }
        "prompts/list" => {
            let mut prompts = router.aggregated_prompts();
            // Scope to the client's allowed servers (a no-op when unscoped).
            if let Some(set) = allowed {
                prompts.retain(|p| {
                    p.get("name")
                        .and_then(|n| n.as_str())
                        .and_then(|name| router.prompt_server(name))
                        .map(|srv| set.contains(srv))
                        .unwrap_or(false)
                });
            }
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
            // Scope guard: a registered HTTP client may only fetch prompts on servers
            // its token allows. Out-of-scope is reported as no-route (no name leak).
            if let Some(set) = allowed {
                let in_scope = router
                    .prompt_server(name)
                    .map(|srv| set.contains(srv))
                    .unwrap_or(false);
                if !in_scope {
                    return Some(error(id, -32602, &format!("Toolport: no route for prompt '{name}'")));
                }
            }
            match router.get_prompt(name, arguments) {
                Ok(mut result) => {
                    // Content defense: a prompt's messages are attacker-controllable too;
                    // scan for injection and label any flagged text as data.
                    if reg.content_defense {
                        integrity::inspect_result(name, "prompt", &mut result);
                    }
                    Some(success(id, result))
                }
                Err(e) => Some(error(id, -32602, &format!("Toolport: {e}"))),
            }
        }
        "ping" => Some(success(id, json!({}))),
        other => Some(error(id, -32601, &format!("Method not found: {other}"))),
    }
}

/// Spawn and connect every enabled server into a router. With `profile` set, only
/// that profile's servers are connected (per-client scoping); otherwise the
/// active profile is used.
fn build_router(
    reg: &Registry,
    profile: Option<&str>,
    http_mode: bool,
    dirty: &Arc<AtomicBool>,
) -> Router {
    // In HTTP mode one process serves every registered client, so connect the
    // union of all their profiles (per-request filtering scopes each one down).
    // In stdio mode the process serves a single client, so connect only its
    // profile - that's what keeps stdio per-client scoping intact.
    let enabled = if http_mode {
        reg.bridge_enabled_servers(profile)
    } else {
        match profile {
            Some(p) => reg.enabled_servers_for(p),
            None => reg.enabled_servers(),
        }
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
        // Hide already-quarantined tools from the first build (the set persists across
        // restarts); newly detected drift is added during the integrity check below.
        quarantined: if reg.quarantine_on_drift {
            integrity::quarantined(profile)
        } else {
            Default::default()
        },
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
    // Per-tool exposure overrides (rename / re-describe) must be set before indexing,
    // since they're applied as each server's tools are added.
    router.set_overrides(reg.tool_overrides.clone());
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
    } else if server.url.is_some() {
        remote::connect_remote(server)
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
    let mut out = stdout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
/// client showing only toolport_status); the emit still fires so the client
/// re-fetches from cache.
/// Run tool-definition integrity detection on a freshly built catalog (gated by
/// the registry's `integrity_check`, on by default). Any drift is recorded to the
/// security log inside `integrity::check`; here we also surface it in the gateway
/// log so it's visible in "Copy diagnostics". Detection only, never blocks.
/// Returns true if a high-risk drift was just quarantined (so the caller should
/// re-filter the router this cycle).
fn maybe_check_integrity(
    registry: &Arc<Mutex<Registry>>,
    tools: &[Value],
    profile: Option<&str>,
) -> bool {
    let (enabled, quarantine_on) = {
        let r = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (r.integrity_check, r.quarantine_on_drift)
    };
    if !enabled {
        return false;
    }
    let events = integrity::check(profile, tools);
    for d in &events {
        let server = d.get("server").and_then(Value::as_str).unwrap_or("?");
        let tool = d.get("tool").and_then(Value::as_str).unwrap_or("?");
        let change = d.get("change").and_then(Value::as_str).unwrap_or("?");
        glog(&format!(
            "SECURITY: tool definition {change} on already-approved server \"{server}\": {tool}"
        ));
        eprintln!("conduit: SECURITY tool drift ({change}) {tool}");
    }
    // Block high-risk drift (poisoned / destructive) until re-approved, when enabled.
    quarantine_on && integrity::apply_quarantine(profile, tools, &events)
}

/// Run integrity detection on a freshly built catalog; if a high-risk drift was just
/// quarantined, re-filter the live router so the blocked tools are hidden this cycle
/// (not one rebuild later) and return the re-filtered catalog. Otherwise unchanged.
fn requarantine_if_needed(
    registry: &Arc<Mutex<Registry>>,
    router: &Arc<Mutex<Arc<Router>>>,
    tools: Vec<Value>,
    profile: Option<&str>,
) -> Vec<Value> {
    if maybe_check_integrity(registry, &tools, profile) {
        let mut guard = router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // make_mut clones the Router (sharing its Arc<ServerSlot> connections) only if
        // an in-flight request still holds the old Arc, then re-filters in place and
        // publishes the result; the old snapshot keeps serving until that request ends.
        let r = Arc::make_mut(&mut guard);
        r.requarantine(integrity::quarantined(profile));
        r.aggregated_tools()
    } else {
        tools
    }
}

fn persist_and_emit(
    tools: &[Value],
    cached_tools: &Arc<Mutex<Vec<Value>>>,
    stdout: &Arc<Mutex<std::io::Stdout>>,
    profile: Option<&str>,
) {
    if !tools.is_empty() {
        *cached_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tools.to_vec();
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
        let _ = f.write_all(format!("{msg}\n").as_bytes());
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
    let over = std::fs::metadata(path)
        .map(|m| m.len() > GATEWAY_LOG_CAP)
        .unwrap_or(false);
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
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
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
#[allow(clippy::too_many_arguments)]
fn watch_registry(
    path: PathBuf,
    registry: Arc<Mutex<Registry>>,
    router: Arc<Mutex<Arc<Router>>>,
    stdout: Arc<Mutex<std::io::Stdout>>,
    cached_tools: Arc<Mutex<Vec<Value>>>,
    profile: Option<String>,
    http_mode: bool,
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
            let new_router =
                build_router(&new_reg, profile.as_deref(), http_mode, &downstream_dirty);
            let tools = new_router.aggregated_tools();
            *registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = new_reg;
            *router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_router);
            let tools = requarantine_if_needed(&registry, &router, tools, profile.as_deref());
            persist_and_emit(&tools, &cached_tools, &stdout, profile.as_deref());
            eprintln!("conduit: registry changed, sent tools/list_changed");
        } else {
            // A live server announced a tool-list change. Re-query the existing
            // connections in place rather than re-spawning: a runtime or
            // session-scoped change (the usual reason a server sends this) would
            // be lost by a fresh process that never saw it.
            let tools = {
                let mut guard = router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Re-query in place on the published router (make_mut forks it only if a
                // request still holds the prior Arc), keeping live connections.
                let r = Arc::make_mut(&mut guard);
                r.refresh_tools();
                r.aggregated_tools()
            };
            let tools = requarantine_if_needed(&registry, &router, tools, profile.as_deref());
            persist_and_emit(&tools, &cached_tools, &stdout, profile.as_deref());
            eprintln!("conduit: downstream tools/list_changed, refreshed + sent");
        }
    }
}

// ---------------------------------------------------------------------------
// Shared request processing + native HTTP/OpenAPI transport.
//
// First-class HTTP consumers (Open WebUI and any OpenAPI tool client) connect
// straight to the gateway with no external bridge: set `CONDUIT_HTTP=<port>`
// and the gateway serves `/openapi.json` plus a POST endpoint per tool, routing
// each call through the exact same `handle_request` as stdio. One code path,
// two transports, so behavior can never drift between them.
// ---------------------------------------------------------------------------

/// Thread-safe gateway state shared by both transports (cheap Arc clones).
#[derive(Clone)]
struct GatewayState {
    registry: Arc<Mutex<Registry>>,
    // The live router behind a swappable Arc: dispatch clones the Arc and releases the
    // lock before the (possibly long) downstream call / approval hold, so nothing blocks
    // behind an in-flight request. Rebuilds swap in a new Arc; refresh/requarantine fork
    // via Arc::make_mut.
    router: Arc<Mutex<Arc<Router>>>,
    cached_tools: Arc<Mutex<Vec<Value>>>,
    stdout: Arc<Mutex<std::io::Stdout>>,
    ready: Arc<AtomicBool>,
    downstream_dirty: Arc<AtomicBool>,
    lazy: bool,
    profile: Option<String>,
    /// True when this process is the HTTP/OpenAPI bridge (vs a stdio client's
    /// gateway). The bridge connects the union of all registered clients' servers.
    http: bool,
}

/// One request in, one response out: wait for a cold cache / live router when
/// the method needs it, self-heal an empty router on a call, then dispatch.
/// Shared by the stdio loop and the HTTP server so they can't diverge.
fn process_request(
    state: &GatewayState,
    req: &Value,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    allowed: Option<&std::collections::HashSet<String>>,
    client: Option<&str>,
) -> Option<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");

    let wait = match method {
        "tools/list" => state
            .cached_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "tools/call" | "resources/list" | "resources/read" | "prompts/list" | "prompts/get" => true,
        _ => false,
    };
    if wait {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !state.ready.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Self-heal: a call with no live downstream servers means the startup read
    // found none (transient) or a server was authed after we built. Reload and
    // rebuild once so the call can route instead of failing.
    if method == "tools/call"
        && state
            .router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .server_count()
            == 0
    {
        let reg = state
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let built = build_router(
            &reg,
            state.profile.as_deref(),
            state.http,
            &state.downstream_dirty,
        );
        if built.server_count() > 0 {
            let tools = built.aggregated_tools();
            *state
                .router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(built);
            if !tools.is_empty() {
                *state
                    .cached_tools
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = tools.clone();
                save_tool_cache(&tools, state.profile.as_deref());
            }
            glog(&format!(
                "self-heal: rebuilt router ({} servers, {} tools)",
                state
                    .router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .server_count(),
                tools.len()
            ));
            notify_tools_changed(&state.stdout);
        }
    }

    // Snapshot everything the dispatch needs, then RELEASE all three locks before
    // calling handle_request: a tools/call can block on the downstream server or a
    // human-approval hold (up to 120s), and holding the router/registry lock across
    // that would wedge config reloads, setting toggles, and every other request. The
    // cloned Arc<Router> keeps this call on a consistent catalog even if a concurrent
    // rebuild swaps the live one; the client label is threaded in, not stored on the
    // shared router.
    let cache_snapshot = state
        .cached_tools
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let reg = state
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let router = state
        .router
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    handle_request(
        req,
        &reg,
        &router,
        &cache_snapshot,
        state.lazy,
        state.profile.as_deref(),
        guard,
        confirm,
        allowed,
        client,
    )
}

/// Resolve the HTTP port. `--http [port]` on the command line wins; otherwise
/// `CONDUIT_HTTP=<port>` is the direct env form, and a truthy `CONDUIT_HTTP`
/// falls back to `CONDUIT_HTTP_PORT` or 8765. Absent everywhere -> stdio mode.
fn http_port() -> Option<u16> {
    // CLI flag: `toolport-gateway --http` (default 8765) or `--http 9000`.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--http") {
        let port = args
            .get(i + 1)
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p > 0)
            .unwrap_or(8765);
        return Some(port);
    }
    let v = std::env::var("CONDUIT_HTTP").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if let Ok(p) = v.parse::<u16>() {
        if p > 0 {
            return Some(p);
        }
    }
    if matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes") {
        return std::env::var("CONDUIT_HTTP_PORT")
            .ok()
            .and_then(|p| p.trim().parse::<u16>().ok())
            .filter(|p| *p > 0)
            .or(Some(8765));
    }
    None
}

/// The tools the HTTP surface exposes, mirroring `tools/list`: the meta-tools
/// in lazy mode, or status + fetch + the full namespaced catalog in full mode.
/// Agent-control tools appear only when the registry opts in.
fn http_tool_defs(state: &GatewayState) -> Vec<Value> {
    let allow_agent = state
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .allow_agent_control;
    if state.lazy {
        let mut tools = vec![
            status_tool_def(),
            search_tool_def(),
            call_tool_def(),
            fetch_result_tool_def(),
        ];
        if allow_agent {
            tools.push(enable_server_tool_def());
            tools.push(disable_server_tool_def());
        }
        tools
    } else {
        let mut tools = vec![status_tool_def(), fetch_result_tool_def()];
        let cached = state
            .cached_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if cached.is_empty() {
            tools.extend(
                state
                    .router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .aggregated_tools(),
            );
        } else {
            tools.extend(cached);
        }
        tools
    }
}

/// Build an OpenAPI 3.1 document describing the exposed tools as POST
/// operations, each carrying the tool's input schema as its request body. This
/// is what an OpenAPI tool client (Open WebUI) reads to learn the tools.
fn openapi_spec(
    state: &GatewayState,
    allowed: Option<&std::collections::HashSet<String>>,
) -> Value {
    // Scope the advertised tools to the client's allowed servers (no-op when
    // unscoped), so a registered client's spec never lists out-of-scope tools.
    let defs = scope_tools(&http_tool_defs(state), allowed);
    // The gateway's error envelope is always `{ "error": "<message>" }`; point
    // every non-2xx response at the shared Error schema so a client can model it.
    let err_resp = |desc: &str| {
        json!({
            "description": desc,
            "content": {
                "application/json": { "schema": { "$ref": "#/components/schemas/Error" } }
            }
        })
    };
    let mut paths = serde_json::Map::new();
    for t in &defs {
        let name = match t.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => continue,
        };
        let desc = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let schema = t
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
        let summary: String = desc
            .lines()
            .next()
            .unwrap_or(name)
            .chars()
            .take(80)
            .collect();
        paths.insert(
            format!("/{name}"),
            json!({
                "post": {
                    "summary": summary,
                    "description": desc,
                    "operationId": name,
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": schema } }
                    },
                    "responses": {
                        "200": {
                            "description": "Tool output: the joined text content of the MCP tool result, as a JSON string.",
                            "content": { "application/json": { "schema": {
                                "type": "string",
                                "description": "The tool's text output."
                            } } }
                        },
                        "400": err_resp("Invalid JSON body, or the tool itself returned an error."),
                        "401": err_resp("Missing or invalid bearer token."),
                        "404": err_resp("Unknown tool name."),
                        "500": err_resp("Internal gateway error.")
                    }
                }
            }),
        );
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Toolport gateway",
            "description": "Toolport MCP gateway as OpenAPI for HTTP tool clients (Open WebUI and any OpenAPI consumer). Search with toolport_search_tools, then call by name with toolport_call_tool.",
            "version": env!("CARGO_PKG_VERSION")
        },
        // Relative base URL: resolves against the origin the spec was fetched
        // from, so the gateway needn't know its own externally-visible host/port.
        "servers": [
            { "url": "/", "description": "This gateway (same origin the spec was served from)." }
        ],
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "The bearer token shown in Toolport's Settings -> Integrations toggle. Paste it as the API key in your client. Required whenever the gateway was started with a token (the desktop app always sets one)."
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "properties": { "error": { "type": "string", "description": "Human-readable error message." } },
                    "required": ["error"]
                }
            }
        },
        "security": [ { "bearerAuth": [] } ]
    })
}

/// Join the text blocks of a tool result's `content` array (the inner result
/// object, not the JSON-RPC envelope). Used to capture a failed call's error
/// message for the audit log, before shaping/integrity mutate the result.
fn content_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(|c| c.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// Pull the human-facing text out of a tools/call result, joining text blocks.
/// Matches what an OpenAPI bridge returns: the tool's text as a JSON string.
fn result_text(resp: &Value) -> String {
    let result = match resp.get("result") {
        Some(r) => r,
        None => return String::new(),
    };
    if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
        let mut out = String::new();
        for item in content {
            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(t);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    serde_json::to_string(result).unwrap_or_default()
}

/// Map one HTTP request to (status, content-type, body).
#[allow(clippy::too_many_arguments)]
fn handle_http(
    state: &GatewayState,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    method: &str,
    path: &str,
    body: &str,
    allowed: Option<&std::collections::HashSet<String>>,
    client: Option<&str>,
) -> (u16, &'static str, String) {
    match (method, path) {
        // CORS preflight: browsers (Open WebUI fetches tool specs client-side)
        // send OPTIONS before a cross-origin POST. Answer it so the real request
        // is allowed through. The CORS headers themselves are added to every
        // response in serve_http_loop.
        ("OPTIONS", _) => (204, "text/plain", String::new()),
        ("GET", "/openapi.json") => (200, "application/json", openapi_spec(state, allowed).to_string()),
        ("GET", "/") | ("GET", "/docs") => (
            200,
            "text/plain; charset=utf-8",
            "Toolport gateway (HTTP/OpenAPI mode). OpenAPI at /openapi.json. POST a tool name with a JSON body, e.g. POST /toolport_search_tools {\"query\":\"...\"}."
                .to_string(),
        ),
        ("POST", p) => {
            let name = p.trim_start_matches('/');
            if name.is_empty() {
                return (
                    404,
                    "application/json",
                    json!({ "error": "missing tool name" }).to_string(),
                );
            }
            let args: Value = if body.trim().is_empty() {
                json!({})
            } else {
                match serde_json::from_str(body) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            400,
                            "application/json",
                            json!({ "error": format!("invalid JSON body: {e}") }).to_string(),
                        )
                    }
                }
            };
            let req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": args }
            });
            match process_request(state, &req, guard, confirm, allowed, client) {
                Some(resp) => {
                    if let Some(err) = resp.get("error") {
                        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("error");
                        return (400, "application/json", json!({ "error": msg }).to_string());
                    }
                    (
                        200,
                        "application/json",
                        serde_json::to_string(&result_text(&resp)).unwrap_or_else(|_| "\"\"".into()),
                    )
                }
                None => (
                    500,
                    "application/json",
                    json!({ "error": "no response" }).to_string(),
                ),
            }
        }
        _ => (
            404,
            "application/json",
            json!({ "error": "not found" }).to_string(),
        ),
    }
}

/// Run the blocking HTTP/OpenAPI server. Binds 127.0.0.1 by default (local
/// only); set `CONDUIT_HTTP_HOST=0.0.0.0` to expose it (unauthenticated, so
/// only on a trusted network).
/// Cap on an inbound HTTP request body. Tool arguments are tiny; this just stops
/// an unauthenticated caller from forcing the gateway to buffer a huge body.
const MAX_HTTP_BODY: u64 = 4 * 1024 * 1024;

/// Cap on concurrently-handled HTTP requests (across both loopback listeners). Each
/// in-flight request runs on its own worker thread; past this many, new requests are
/// handled inline (serially) rather than spawning without bound. Sized well above any
/// realistic local concurrency: the approval broker caps simultaneous holds at 64, and
/// non-held calls finish in milliseconds, so this backstop is only ever a flood guard.
const MAX_HTTP_INFLIGHT: usize = 256;

/// Parse a `Bearer <token>` Authorization value. Pure, so it's unit-testable.
fn parse_bearer(auth_value: &str) -> Option<&str> {
    let (scheme, tok) = auth_value.split_once(' ')?;
    // Reject an empty token (`Bearer ` with only whitespace): returning Some("") would
    // otherwise be looked up as a real bearer, a fail-open shape.
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| tok.trim())
        .filter(|t| !t.is_empty())
}

/// Strip control characters and bound the length of a header value we reflect
/// back (the caller-controlled Origin / requested headers), so a crafted value
/// can't inject a header or make `Header::from_bytes` reject and panic.
fn sanitize_header_value(v: &str) -> String {
    v.chars().filter(|c| !c.is_control()).take(512).collect()
}

/// Constant-time byte-slice equality for comparing the bearer token. Fails fast
/// on a length mismatch (the token length is not secret), but otherwise folds
/// over every byte without short-circuiting so a timing measurement can't
/// recover the token one byte at a time.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn serve_http(state: GatewayState, port: u16) {
    let host = std::env::var("CONDUIT_HTTP_HOST")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    // A bearer token, when set, is required on every request. The desktop app
    // always sets one (auto-generated) and shows it for the user to paste into
    // their client; manual `--http` users can set it themselves.
    let token = std::env::var("CONDUIT_HTTP_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());

    let loopback = matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost");
    // Fail closed: a non-loopback endpoint runs the user's credentials for
    // anyone who can reach the port, so refuse to bind one without a token.
    if !loopback && token.is_none() {
        eprintln!(
            "toolport-gateway: refusing to bind {host}:{port} without CONDUIT_HTTP_TOKEN. \
             A non-loopback HTTP endpoint would be unauthenticated. Set a token, or bind 127.0.0.1."
        );
        std::process::exit(1);
    }
    if token.is_none() {
        eprintln!(
            "toolport-gateway: WARNING - HTTP endpoint has no token; any local process (including a \
             web page open in your browser) can call your tools. Set CONDUIT_HTTP_TOKEN to require auth."
        );
    }

    // Two guards shared by every worker thread on BOTH loopback listeners: the
    // anti-thrash SearchGuard and the destructive-confirm ConfirmGuard each hold
    // cross-request state (a confirm token stored by one request is redeemed by a
    // later one), so they must be a single shared instance, not per-thread.
    let search = Arc::new(SearchGuard::default());
    let confirm = Arc::new(ConfirmGuard::new());

    // When binding the default IPv4 loopback, ALSO listen on the IPv6 loopback
    // (best-effort). Many systems resolve "localhost" to ::1 first, and clients
    // like Open WebUI try ::1 and don't fall back to 127.0.0.1, so an IPv4-only
    // listener makes `http://localhost:<port>` fail even though 127.0.0.1 works.
    if host == "127.0.0.1" {
        if let Ok(server6) = tiny_http::Server::http(("::1", port)) {
            let (state6, token6, search6, confirm6) =
                (state.clone(), token.clone(), search.clone(), confirm.clone());
            std::thread::spawn(move || serve_http_loop(server6, state6, token6, search6, confirm6));
            glog(&format!(
                "HTTP/OpenAPI also listening on http://[::1]:{port}"
            ));
        }
    }

    let server = match tiny_http::Server::http((host.as_str(), port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("toolport-gateway: could not bind HTTP {host}:{port}: {e}");
            std::process::exit(1);
        }
    };
    glog(&format!(
        "HTTP/OpenAPI mode on http://{host}:{port} (auth={})",
        token.is_some()
    ));
    eprintln!(
        "toolport-gateway: HTTP/OpenAPI on http://localhost:{port}  (OpenAPI spec at /openapi.json)"
    );
    serve_http_loop(server, state, token, search, confirm);
}

/// The accept loop for one listener. Each accepted request is handed to its own
/// worker thread, so a slow downstream call or a (up to two-minute) human-approval
/// hold never blocks the next request. The gateway state and the two guards are
/// shared across every worker and both loopback listeners. An in-flight cap bounds
/// the worst case; the approval broker already caps concurrent holds (MAX_PENDING),
/// so held calls can't starve request handling below that cap.
/// Decrements the in-flight counter when a worker thread finishes, panic or not.
struct InflightGuard(Arc<AtomicUsize>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn serve_http_loop(
    server: tiny_http::Server,
    state: GatewayState,
    token: Option<String>,
    search: Arc<SearchGuard>,
    confirm: Arc<ConfirmGuard>,
) {
    let inflight = Arc::new(AtomicUsize::new(0));
    for request in server.incoming_requests() {
        // Backstop against a pathological flood: never exceed the cap. At the cap we
        // handle inline (degrading to serial for the overflow) rather than spawn
        // unbounded threads or drop the request. Realistic local concurrency, bounded
        // by the broker's own hold cap plus a handful of fast calls, stays far below it.
        if inflight.load(Ordering::Relaxed) >= MAX_HTTP_INFLIGHT {
            handle_connection(request, &state, &token, &search, &confirm);
            continue;
        }
        inflight.fetch_add(1, Ordering::Relaxed);
        let (state, token, search, confirm, inflight) = (
            state.clone(),
            token.clone(),
            Arc::clone(&search),
            Arc::clone(&confirm),
            Arc::clone(&inflight),
        );
        std::thread::spawn(move || {
            // Decrement on the way out even if a handler panics before the response
            // (a panic outside handle_http's catch_unwind), so the count can't leak
            // and wedge the pool at the cap.
            let _dec = InflightGuard(inflight);
            handle_connection(request, &state, &token, &search, &confirm);
        });
    }
}

/// Handle one accepted HTTP request end to end: parse, CORS, auth/scope, dispatch,
/// and respond. A pure function of the request plus the shared state and guards, so
/// it is safe to run on many worker threads concurrently.
fn handle_connection(
    mut request: tiny_http::Request,
    state: &GatewayState,
    token: &Option<String>,
    search: &SearchGuard,
    confirm: &ConfirmGuard,
) {
        let method = request.method().to_string().to_uppercase();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("/").to_string();
        // Reflect only the caller's requested headers (sanitized) so the CORS
        // preflight passes; the Allow-Origin we return is always a wildcard, never
        // the caller's Origin (see the CORS block below). The bearer token, not
        // CORS, is what actually authorizes a call.
        let allow_headers = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Access-Control-Request-Headers"))
            .map(|h| sanitize_header_value(h.value.as_str()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Content-Type, Authorization".to_string());

        // A browser attaches Sec-Fetch-Site to every request; a server-side caller
        // (Open WebUI's backend, curl) does not. Refuse a cross-site browser
        // request outright so a malicious web page the user has open can't reach
        // the bridge or read tool output even when no token is set. The data-less
        // CORS preflight (OPTIONS) is left to the normal preflight path.
        let cross_site = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Sec-Fetch-Site"))
            .map(|h| h.value.as_str().eq_ignore_ascii_case("cross-site"))
            .unwrap_or(false);

        // Auth + scope gate: resolve the bearer to (authorized, allowed-servers).
        // OPTIONS is the data-less preflight, always allowed and unscoped. Else the
        // registry decides: the legacy env token (full connected set), a registered
        // HTTP client (its profile's servers), or open when no auth is configured.
        // A bad/missing token is rejected before we read the body or route.
        let provided = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_string());
        let provided_tok = provided.as_deref().and_then(parse_bearer);
        let mut client_label: Option<String> = None;
        let scope: Option<Option<std::collections::HashSet<String>>> = if method == "OPTIONS" {
            Some(None)
        } else {
            let reg = state
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Resolve the client's audit label from the same token, so every call it
            // makes can be attributed to it in the audit log.
            client_label = http_client_label(&reg, provided_tok);
            resolve_http_scope(&reg, token.as_deref(), provided_tok)
        };

        let (status, ctype, payload): (u16, &str, String) = if cross_site && method != "OPTIONS" {
            (
                403,
                "application/json",
                json!({ "error": "cross-site browser requests are not allowed" }).to_string(),
            )
        } else {
            match scope {
                None => (
                    401,
                    "application/json",
                    json!({ "error": "missing or invalid bearer token" }).to_string(),
                ),
                Some(allowed) => {
                    let mut body = String::new();
                    if method == "POST" {
                        let _ = request
                            .as_reader()
                            .take(MAX_HTTP_BODY)
                            .read_to_string(&mut body);
                    }
                    // A panic in a handler must return 500, not kill the listener.
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_http(
                            state,
                            search,
                            confirm,
                            &method,
                            &path,
                            &body,
                            allowed.as_ref(),
                            client_label.as_deref(),
                        )
                    }))
                    .unwrap_or((
                        500,
                        "application/json",
                        "{\"error\":\"internal error\"}".to_string(),
                    ))
                }
            }
        };

        let mut response = tiny_http::Response::from_string(payload).with_status_code(status);
        let cors: [(&[u8], &[u8]); 4] = [
            (b"Content-Type", ctype.as_bytes()),
            // Auth is a bearer header, never a cookie, so credentialed CORS is
            // unnecessary. Return a wildcard Origin (never the reflected caller
            // Origin) and omit Allow-Credentials, so a malicious page can't pair a
            // reflected origin with Allow-Credentials to read a response.
            (b"Access-Control-Allow-Origin", b"*"),
            (b"Access-Control-Allow-Methods", b"GET, POST, OPTIONS"),
            (b"Access-Control-Allow-Headers", allow_headers.as_bytes()),
        ];
        for (name, value) in cors {
            // Skip a header that won't encode rather than panicking the thread.
            if let Ok(h) = tiny_http::Header::from_bytes(name, value) {
                response = response.with_header(h);
            }
        }
        let _ = request.respond(response);
}

fn main() {
    // Diagnostic: `toolport-gateway --selftest-secrets` reads every vaulted secret
    // from THIS (gateway) process and reports. Used to validate the macOS keychain
    // shared-access ACL: this runs as a separate process from the app, exactly the
    // cross-process read path. If it reads the secrets with NO keychain prompt, the
    // gateway has silent access and the fix works.
    if std::env::args().nth(1).as_deref() == Some("--selftest-secrets") {
        let reg = match registry::load_resolved() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("selftest-secrets: could not load registry: {e}");
                std::process::exit(1);
            }
        };
        let (mut ok, mut unset, mut err) = (0u32, 0u32, 0u32);
        for s in &reg.servers {
            for e in &s.env {
                if e.value.is_some() || !e.secret {
                    continue;
                }
                match secrets::get_secret_result(&s.id, &e.key) {
                    Ok(Some(_)) => {
                        ok += 1;
                        println!("OK     {} :: {}", s.id, e.key);
                    }
                    Ok(None) => {
                        unset += 1;
                        println!("UNSET  {} :: {}", s.id, e.key);
                    }
                    Err(e2) => {
                        err += 1;
                        println!("ERR    {} :: {}  ({e2})", s.id, e.key);
                    }
                }
            }
            // Bearer / OAuth tokens live under a reserved key, not as env vars.
            match secrets::get_secret_result(&s.id, secrets::HTTP_AUTH_KEY) {
                Ok(Some(_)) => {
                    ok += 1;
                    println!("OK     {} :: (auth token)", s.id);
                }
                Ok(None) => {}
                Err(e2) => {
                    err += 1;
                    println!("ERR    {} :: (auth token)  ({e2})", s.id);
                }
            }
        }
        println!("\nselftest-secrets: {ok} read OK, {unset} unset, {err} errors");
        println!("If NO keychain prompt appeared, the gateway has silent access (the ACL works).");
        std::process::exit(0);
    }

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
    // HTTP/OpenAPI bridge mode: one process serves every registered client, so the
    // router connects the union of their profiles. Resolve the port once up front.
    let http_port_opt = http_port();
    let http_mode = http_port_opt.is_some();
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
                "toolport-gateway: could not load registry ({e}); serving cached tools only. \
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
    let router = Arc::new(Mutex::new(Arc::new(Router::new())));
    let cached_tools = Arc::new(Mutex::new(load_tool_cache(profile.as_deref())));
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let ready = Arc::new(AtomicBool::new(false));
    // Flipped by any downstream transport that emits notifications/tools/list_changed.
    // The registry watcher polls it and rebuilds, so a server that changes its own
    // tool set mid-session propagates to the client instead of being dropped.
    let downstream_dirty = Arc::new(AtomicBool::new(false));
    glog(&format!(
        "loaded tool cache: {} tools",
        cached_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
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
            let reg = registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let built = build_router(&reg, profile.as_deref(), http_mode, &downstream_dirty);
            let tools = built.aggregated_tools();
            glog(&format!(
                "background build: {} tools from {} servers",
                tools.len(),
                built.server_count()
            ));
            *router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(built);
            // Don't let a transient empty build (registry caught mid-write, or
            // every downstream momentarily unreachable) clobber a good catalog -
            // that's what leaves a client showing only toolport_status.
            if !tools.is_empty() {
                *cached_tools
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = tools.clone();
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
                http_mode,
                downstream_dirty,
            )
        });
    }

    let state = GatewayState {
        registry: Arc::clone(&registry),
        router: Arc::clone(&router),
        cached_tools: Arc::clone(&cached_tools),
        stdout: Arc::clone(&stdout),
        ready: Arc::clone(&ready),
        downstream_dirty: Arc::clone(&downstream_dirty),
        lazy,
        profile: profile.clone(),
        http: http_mode,
    };

    // Native HTTP/OpenAPI transport: a first-class path for HTTP tool clients
    // (Open WebUI and any OpenAPI consumer) with no external bridge. Standalone,
    // so it replaces the stdio loop; the background build + registry watcher
    // started above still keep the router and cache live underneath it.
    if let Some(port) = http_port_opt {
        serve_http(state, port);
        return;
    }

    let stdin = std::io::stdin();
    // stdio serves one client on one thread, so no sharing is needed, but the guards
    // are now interior-mutable (&self methods) to match the shared HTTP path.
    let search_guard = SearchGuard::default();
    let confirm_guard = ConfirmGuard::new();
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
        gtrace(&format!(
            "request: {}",
            req.get("method").and_then(|m| m.as_str()).unwrap_or("")
        ));
        // A panic in a handler must not unwind out of this loop and kill the gateway:
        // stdio has no supervisor (unlike the HTTP listener, which catches per request),
        // so one panic would drop the whole MCP connection and take every tool with it.
        // Catch it, log it, and return a JSON-RPC internal error for this request.
        let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_request(&state, &req, &search_guard, &confirm_guard, None, None)
        }))
        .unwrap_or_else(|_| {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            glog("panic while handling a request; returned an internal error, gateway still up");
            Some(error(id, -32603, "internal error"))
        });
        if let Some(resp) = response {
            let mut out = state
                .stdout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    /// The security-critical guarantee: the human-approval broker denies (never
    /// approves) when it cannot reach a live approver - no endpoint published (app
    /// closed) or a connection that refuses. Fail-closed is the whole point.
    #[test]
    fn approval_broker_fails_closed() {
        let mk = || approval::ApprovalRequest {
            token: String::new(),
            id: "id".into(),
            client: None,
            server: "db".into(),
            tool: "drop".into(),
            reason: approval::ApprovalReason::Destructive,
            arguments: serde_json::json!({}),
        };
        // No endpoint descriptor (Toolport app not running) -> deny.
        let mut r = mk();
        assert!(!decide_via_broker(None, &mut r).is_approved());
        // A published endpoint that refuses the connection -> deny.
        let mut r = mk();
        let bad = Some(approval::EndpointDescriptor {
            endpoint: "127.0.0.1:1".into(),
            token: "t".into(),
        });
        assert!(!decide_via_broker(bad, &mut r).is_approved());
    }

    fn router() -> Router {
        Router::new()
    }

    /// A minimal in-memory downstream used to build a *routed* router in tests, so
    /// paths that resolve a call's server via `route_of` (the scope guard, the HITL
    /// untrusted-provenance check) see real routes instead of an empty map.
    struct MockRoute {
        tools: Vec<Value>,
    }
    impl conduit_lib::downstream::Transport for MockRoute {
        fn request(
            &mut self,
            method: &str,
            _params: Value,
        ) -> Result<Value, conduit_lib::downstream::TransportError> {
            match method {
                "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                "tools/list" => Ok(json!({ "tools": self.tools })),
                other => Err(conduit_lib::downstream::TransportError::Fatal(format!(
                    "unexpected {other}"
                ))),
            }
        }
        fn notify(
            &mut self,
            _method: &str,
            _params: Value,
        ) -> Result<(), conduit_lib::downstream::TransportError> {
            Ok(())
        }
    }

    /// A router with one server `id` exposing one tool `tool` (so `id__tool` routes).
    fn routed_router(id: &str, tool: &str) -> Router {
        let ds = DownstreamServer::connect(
            id.to_string(),
            Box::new(MockRoute {
                tools: vec![json!({ "name": tool, "description": "" })],
            }),
        )
        .unwrap();
        let mut r = Router::new();
        r.add(ds);
        r
    }

    fn http_state(lazy: bool) -> GatewayState {
        GatewayState {
            registry: Arc::new(Mutex::new(Registry::default())),
            router: Arc::new(Mutex::new(Arc::new(Router::new()))),
            cached_tools: Arc::new(Mutex::new(Vec::new())),
            stdout: Arc::new(Mutex::new(std::io::stdout())),
            ready: Arc::new(AtomicBool::new(true)),
            downstream_dirty: Arc::new(AtomicBool::new(false)),
            lazy,
            profile: None,
            http: true,
        }
    }

    /// Minimal raw HTTP/1.1 client for the concurrency test: one request per
    /// connection, `Connection: close` so the server closes and we read to EOF.
    fn http_get(port: u16, path: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut buf = String::new();
        let _ = s.read_to_string(&mut buf);
        buf
    }

    fn http_post(port: u16, path: &str, body: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut buf = String::new();
        let _ = s.read_to_string(&mut buf);
        buf
    }

    /// The live proof of the multithreaded HTTP loop: a call blocked in dispatch (a
    /// slow downstream, or the moral equivalent of a 120s approval hold) must NOT stall
    /// an unrelated request. A single-threaded accept loop would serialize them.
    #[test]
    fn http_slow_call_does_not_block_other_requests() {
        // A downstream whose tools/call blocks ~800ms; initialize/tools/list stay fast
        // so the connect handshake and routing (`s__wait`) work normally.
        struct SlowRoute;
        impl conduit_lib::downstream::Transport for SlowRoute {
            fn request(
                &mut self,
                method: &str,
                _params: Value,
            ) -> Result<Value, conduit_lib::downstream::TransportError> {
                match method {
                    "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                    "tools/list" => Ok(json!({ "tools": [{ "name": "wait", "description": "" }] })),
                    "tools/call" => {
                        std::thread::sleep(Duration::from_millis(800));
                        Ok(json!({ "content": [{ "type": "text", "text": "done" }] }))
                    }
                    other => Err(conduit_lib::downstream::TransportError::Fatal(format!(
                        "unexpected {other}"
                    ))),
                }
            }
            fn notify(
                &mut self,
                _method: &str,
                _params: Value,
            ) -> Result<(), conduit_lib::downstream::TransportError> {
                Ok(())
            }
        }

        let ds = DownstreamServer::connect("s".into(), Box::new(SlowRoute)).unwrap();
        let mut router = Router::new();
        router.add(ds);
        let mut state = http_state(false);
        state.router = Arc::new(Mutex::new(Arc::new(router)));

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let search = Arc::new(SearchGuard::default());
        let confirm = Arc::new(ConfirmGuard::new());
        std::thread::spawn(move || serve_http_loop(server, state, None, search, confirm));
        std::thread::sleep(Duration::from_millis(50)); // let the listener come up

        // Kick off the slow (blocking) call on its own thread, then let it get parked
        // in dispatch before timing the fast request.
        let slow = std::thread::spawn(move || http_post(port, "/s__wait", "{}"));
        std::thread::sleep(Duration::from_millis(150));

        // A concurrent fast request must return well before the slow call's 800ms sleep.
        let t0 = Instant::now();
        let fast = http_get(port, "/");
        let elapsed = t0.elapsed();
        assert!(fast.contains("Toolport gateway"), "fast response was: {fast}");
        assert!(
            elapsed < Duration::from_millis(400),
            "fast request was blocked behind the slow call ({elapsed:?}); the loop serialized"
        );

        // The slow call still completes correctly.
        let slow_resp = slow.join().unwrap();
        assert!(slow_resp.contains("done"), "slow response was: {slow_resp}");
    }

    #[test]
    fn result_text_joins_text_blocks() {
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": { "content": [
                { "type": "text", "text": "hello" },
                { "type": "text", "text": "world" }
            ] }
        });
        assert_eq!(result_text(&resp), "hello\nworld");
        // No result (e.g. an error envelope) -> empty string, never a panic.
        assert_eq!(result_text(&json!({ "jsonrpc": "2.0", "id": 1 })), "");
    }

    #[test]
    fn openapi_exposes_meta_tools_as_post_paths() {
        let spec = openapi_spec(&http_state(true), None);
        let paths = spec.get("paths").unwrap().as_object().unwrap();
        // The lazy meta-tools are each a POST path.
        assert!(paths.contains_key("/toolport_search_tools"));
        assert!(paths.contains_key("/toolport_call_tool"));
        assert!(paths.contains_key("/toolport_status"));
        let op = paths
            .get("/toolport_search_tools")
            .and_then(|p| p.get("post"))
            .unwrap();
        assert_eq!(op.get("operationId").unwrap(), "toolport_search_tools");
        assert!(op.get("requestBody").is_some());
        // Error responses are declared so a client can model failures.
        let responses = op.get("responses").unwrap().as_object().unwrap();
        for code in ["200", "400", "401", "404", "500"] {
            assert!(responses.contains_key(code), "missing response {code}");
        }
        // Agent-control tools stay hidden unless the registry opts in.
        assert!(!paths.contains_key("/toolport_enable_server"));
        assert_eq!(spec.get("openapi").unwrap(), "3.1.0");
        // A relative servers entry so clients can resolve the base URL.
        assert_eq!(spec.pointer("/servers/0/url").unwrap(), "/");
        // The bearer scheme is advertised and required globally.
        assert_eq!(
            spec.pointer("/components/securitySchemes/bearerAuth/scheme")
                .unwrap(),
            "bearer"
        );
        assert!(spec.pointer("/security/0/bearerAuth").is_some());
        // The shared Error schema the non-2xx responses reference exists.
        assert!(spec
            .pointer("/components/schemas/Error/properties/error")
            .is_some());
    }

    #[test]
    fn detects_invented_placeholders_but_not_real_values() {
        // Template forms are placeholders regardless of the parameter.
        for (param, val) in [
            ("teamId", "your_team_id"),
            ("teamId", "<team_id>"),
            ("teamId", "{{teamId}}"),
            ("apiKey", "REPLACE_ME"),
            ("teamId", "team_id_here"),
        ] {
            assert!(
                looks_like_placeholder(param, val),
                "should flag {param}={val:?}"
            );
        }
        // Field-name / schema-type echoes are placeholders ONLY for an
        // identifier-typed parameter.
        assert!(looks_like_placeholder("teamId", "string"));
        assert!(looks_like_placeholder("teamId", "team_id"));
        assert!(looks_like_placeholder("apiKey", "TODO"));
        // The SAME bare words are legitimate content for a non-identifier param
        // (this is the false-positive the guard used to trip on).
        for (param, val) in [
            ("query", "string"),
            ("title", "todo"),
            ("name", "example"),
            ("message", "xxx"),
            ("branch", "tbd"),
        ] {
            assert!(
                !looks_like_placeholder(param, val),
                "should NOT flag content {param}={val:?}"
            );
        }
        // Real values are never flagged, identifier or not.
        for real in ["team_aBc123XYZ", "acme-prod", "my real project", "", "  "] {
            assert!(
                !looks_like_placeholder("teamId", real),
                "should NOT flag {real:?}"
            );
        }
    }

    #[test]
    fn find_placeholder_arg_picks_the_bad_value() {
        let args = json!({ "teamId": "your_team_id", "limit": 10 });
        let (k, v) = find_placeholder_arg(&args).unwrap();
        assert_eq!(k, "teamId");
        assert_eq!(v, "your_team_id");
        assert!(find_placeholder_arg(&json!({ "teamId": "team_real123" })).is_none());
        // A content field whose value collides with a schema word is no longer a
        // false positive.
        assert!(find_placeholder_arg(&json!({ "query": "string" })).is_none());
        assert!(find_placeholder_arg(&json!({ "title": "todo" })).is_none());
    }

    #[test]
    fn ct_eq_matches_only_equal_slices() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"token123", b"token123"));
        assert!(!ct_eq(b"token123", b"token124"));
        assert!(!ct_eq(b"token123", b"token1234")); // length mismatch
        assert!(!ct_eq(b"abc", b""));
    }

    #[test]
    fn server_of_tool_extracts_prefix() {
        assert_eq!(server_of_tool("vercel__deploy"), "vercel");
        assert_eq!(server_of_tool("resend__send_email"), "resend");
        // A meta-tool has no namespace; the whole name is returned.
        assert_eq!(server_of_tool("toolport_status"), "toolport_status");
    }

    #[test]
    fn destructive_check_resolves_then_fails_closed() {
        let cached = vec![
            json!({ "name": "s__del", "annotations": { "destructiveHint": true } }),
            json!({ "name": "s__read" }),
        ];
        let empty = router();
        // In the cache: use its destructiveHint.
        assert!(tool_is_destructive_fail_closed("s__del", &cached, &empty));
        assert!(!tool_is_destructive_fail_closed("s__read", &cached, &empty));
        // Unknown to both cache and router: FAIL-CLOSED (treated as destructive), so a
        // gate can't silently wave through a tool it can't see.
        assert!(tool_is_destructive_fail_closed("s__unknown", &cached, &empty));
        assert!(tool_is_destructive_fail_closed("anything", &[], &empty));
        // Absent from the cache but resolvable via the LIVE router: use the router's def
        // (the mock's "deploy" is non-destructive), not the fail-closed default.
        let routed = routed_router("vercel", "deploy");
        assert!(!tool_is_destructive_fail_closed("vercel__deploy", &[], &routed));
    }

    #[test]
    fn scope_tools_filters_by_server_keeps_meta() {
        let tools = vec![
            json!({ "name": "vercel__deploy" }),
            json!({ "name": "resend__send" }),
            json!({ "name": "toolport_search_tools" }),
        ];
        // Unscoped: everything passes.
        assert_eq!(scope_tools(&tools, None).len(), 3);
        // Scoped to vercel: its tool plus the meta-tool, never resend.
        let set: std::collections::HashSet<String> = ["vercel".to_string()].into_iter().collect();
        let names: Vec<String> = scope_tools(&tools, Some(&set))
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(names.contains(&"vercel__deploy".to_string()));
        assert!(names.contains(&"toolport_search_tools".to_string()));
        assert!(!names.contains(&"resend__send".to_string()));
    }

    #[test]
    fn resolve_http_scope_auth_and_scope_policy() {
        let mut reg = Registry::default();
        // No auth configured at all -> open, unscoped.
        assert_eq!(resolve_http_scope(&reg, None, None), Some(None));
        // Legacy env token: exact match -> unscoped; mismatch -> rejected.
        assert_eq!(
            resolve_http_scope(&reg, Some("envtok"), Some("envtok")),
            Some(None)
        );
        assert!(resolve_http_scope(&reg, Some("envtok"), Some("nope")).is_none());
        // A registered client with an empty profile is authorized but unscoped.
        reg.http_clients.push(registry::HttpClient {
            id: "c1".into(),
            label: "full".into(),
            token_sha256: registry::sha256_hex("fulltok"),
            profile: String::new(),
        });
        assert_eq!(resolve_http_scope(&reg, None, Some("fulltok")), Some(None));
        // Once any client is registered, an unknown/absent bearer is rejected
        // (the open default no longer applies).
        assert!(resolve_http_scope(&reg, None, Some("unknown")).is_none());
        assert!(resolve_http_scope(&reg, None, None).is_none());
        // A client scoped to a non-empty profile resolves to a (possibly empty)
        // allow-set; exact membership is covered by enabled_servers_for tests.
        reg.http_clients.push(registry::HttpClient {
            id: "c2".into(),
            label: "scoped".into(),
            token_sha256: registry::sha256_hex("scopedtok"),
            profile: "Default".into(),
        });
        assert!(matches!(
            resolve_http_scope(&reg, None, Some("scopedtok")),
            Some(Some(_))
        ));
    }

    #[test]
    fn http_client_label_attributes_registered_clients() {
        let mut reg = Registry::default();
        // Unknown / absent bearer -> unattributed (stays out of the audit log).
        assert_eq!(http_client_label(&reg, None), None);
        assert_eq!(http_client_label(&reg, Some("nope")), None);
        // A registered client resolves to its human-readable label.
        reg.http_clients.push(registry::HttpClient {
            id: "c1".into(),
            label: "Cursor".into(),
            token_sha256: registry::sha256_hex("tok1"),
            profile: String::new(),
        });
        assert_eq!(
            http_client_label(&reg, Some("tok1")).as_deref(),
            Some("Cursor")
        );
        // A blank label falls back to the id, so attribution is never an empty string.
        reg.http_clients.push(registry::HttpClient {
            id: "c2".into(),
            label: "   ".into(),
            token_sha256: registry::sha256_hex("tok2"),
            profile: String::new(),
        });
        assert_eq!(http_client_label(&reg, Some("tok2")).as_deref(), Some("c2"));
    }

    #[test]
    fn status_summary_scopes_to_allowed_servers() {
        use std::collections::HashSet;
        let mut reg = Registry::default();
        for id in ["alpha", "bravo"] {
            reg.servers.push(ServerEntry {
                id: id.into(),
                name: id.into(),
                transport: "stdio".into(),
                command: Some(format!("{id}-cmd")),
                args: vec![],
                env: vec![],
                url: None,
                source: None,
                disabled_tools: vec![],
            });
        }
        // alpha is in the active (default) profile; bravo only in a separate one.
        reg.set_server_enabled("default", "alpha", true).unwrap();
        let billing = reg.add_profile("Billing");
        reg.set_server_enabled(&billing, "bravo", true).unwrap();
        let cached = vec![json!({ "name": "alpha__x" }), json!({ "name": "bravo__y" })];
        // Unscoped (legacy/stdio): the active profile -> alpha only.
        let full = enabled_summary(&reg, &cached, None, None);
        assert!(full.contains("alpha"));
        assert!(!full.contains("bravo")); // not in the active profile
                                          // Scoped to bravo: shows bravo (its real scope) even though bravo isn't in
                                          // the active profile, and never leaks alpha's name/command/tool count.
        let allowed: HashSet<String> = ["bravo".to_string()].into_iter().collect();
        let scoped = enabled_summary(&reg, &cached, None, Some(&allowed));
        assert!(scoped.contains("bravo"));
        assert!(!scoped.contains("alpha"));
        assert!(!scoped.contains("alpha-cmd"));
    }

    #[test]
    fn scoped_call_to_out_of_scope_server_is_refused() {
        let reg = Registry::default();
        let allowed: std::collections::HashSet<String> =
            ["vercel".to_string()].into_iter().collect();
        // A call to an out-of-scope server is refused with a clear isError result.
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "resend__send", "arguments": {} }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            Some(&allowed),
            None,
        )
        .unwrap();
        let result = resp.get("result").unwrap();
        assert_eq!(result.get("isError").and_then(|v| v.as_bool()), Some(true));
        let text = result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        assert!(text.contains("not available to this client"));
        // An in-scope call passes the scope guard (it then fails at routing since
        // no server is connected, but NOT with the scope-refusal message).
        let req_ok = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "vercel__deploy", "arguments": {} }
        });
        let resp_ok = handle_request(
            &req_ok,
            &reg,
            // A routed router so `vercel__deploy` resolves to server `vercel` (in scope)
            // via route_of, rather than an empty map that would mis-refuse it.
            &routed_router("vercel", "deploy"),
            &catalog(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            Some(&allowed),
            None,
        )
        .unwrap();
        let text_ok = resp_ok
            .get("result")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
            .and_then(|b| b.get("text"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        assert!(!text_ok.contains("not available to this client"));
    }

    #[test]
    fn source_hints_find_sibling_list_get_tools_same_server() {
        let catalog = vec![
            json!({ "name": "vercel__list_teams" }),
            json!({ "name": "vercel__get_project" }),
            json!({ "name": "vercel__create_deployment" }),
            json!({ "name": "resend__list_domains" }),
        ];
        // Missing a teamId -> the team tool should rank first.
        let hits = source_tool_hints(&catalog, "vercel", Some("team"), 5);
        assert_eq!(hits.first().unwrap(), "vercel__list_teams");
        assert!(hits.contains(&"vercel__get_project".to_string()));
        // Not the write tool, and not the other server.
        assert!(!hits.contains(&"vercel__create_deployment".to_string()));
        assert!(!hits.iter().any(|h| h.starts_with("resend")));
        assert_eq!(resource_stem("teamId"), "team");
        assert_eq!(resource_stem("account_id"), "account");
    }

    #[test]
    fn parse_bearer_extracts_token_case_insensitively() {
        assert_eq!(parse_bearer("Bearer abc123"), Some("abc123"));
        assert_eq!(parse_bearer("bearer  spaced  "), Some("spaced"));
        assert_eq!(parse_bearer("Basic abc"), None);
        assert_eq!(parse_bearer("abc"), None);
        assert_eq!(parse_bearer(""), None);
        // An empty/whitespace-only token must be rejected, not returned as Some("").
        assert_eq!(parse_bearer("Bearer "), None);
        assert_eq!(parse_bearer("Bearer    "), None);
    }

    #[test]
    fn sanitize_header_value_strips_control_chars() {
        assert_eq!(
            sanitize_header_value("http://localhost:8080"),
            "http://localhost:8080"
        );
        // CR/LF injection attempt is stripped to a flat value.
        assert_eq!(
            sanitize_header_value("evil\r\nSet-Cookie: x=1"),
            "evilSet-Cookie: x=1"
        );
        assert!(sanitize_header_value(&"a".repeat(9999)).len() <= 512);
    }

    #[test]
    fn http_options_preflight_is_answered() {
        // Browsers preflight a cross-origin POST; we must answer OPTIONS so the
        // real request goes through (CORS headers themselves are added per-response).
        let state = http_state(true);
        let (status, _, body) = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "OPTIONS",
            "/toolport_search_tools",
            "",
            None,
            None,
        );
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn agent_control_gates_then_persists() {
        // Two servers, only Alpha enabled, agent control OFF.
        let path =
            std::env::temp_dir().join(format!("conduit-ac-test-{}.json", std::process::id()));
        let json = r#"{"version":1,
            "servers":[
                {"id":"a","name":"Alpha","transport":"stdio","command":"x","args":[],"env":[]},
                {"id":"b","name":"Beta","transport":"stdio","command":"x","args":[],"env":[]}],
            "profiles":[{"id":"p","name":"P","enabledServerIds":["a"]}],
            "activeProfileId":"p","allowAgentControl":false}"#;
        std::fs::write(&path, json).unwrap();
        let reg = registry::load_from(&path).unwrap();

        // Gated off: refused, and nothing on disk changes.
        assert!(set_server_enabled_via_agent(&reg, Some("p"), &path, "Beta", true, None, None).is_err());
        assert!(!registry::load_from(&path).unwrap().is_enabled("p", "b"));

        // Opt in (persisting it so the fresh-copy re-check passes), then enable
        // Beta by name, case-insensitively.
        let mut reg2 = reg.clone();
        reg2.allow_agent_control = true;
        registry::save_to(&path, &reg2).unwrap();
        let ok = set_server_enabled_via_agent(&reg2, Some("p"), &path, "beta", true, None, None);
        assert!(ok.is_ok(), "enable should succeed: {ok:?}");
        assert!(registry::load_from(&path).unwrap().is_enabled("p", "b"));
        // The destructive-tool safety switch is never reachable from agent control.
        assert!(!registry::load_from(&path).unwrap().deny_destructive);

        // Unknown server: helpful error naming the known ones.
        let bad = set_server_enabled_via_agent(&reg2, Some("p"), &path, "nope", true, None, None);
        assert!(bad.as_ref().is_err());
        assert!(bad.unwrap_err().contains("Alpha"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn agent_control_respects_the_client_scope() {
        let path =
            std::env::temp_dir().join(format!("conduit-ac-scope-{}.json", std::process::id()));
        let json = r#"{"version":1,
            "servers":[
                {"id":"a","name":"Alpha","transport":"stdio","command":"x","args":[],"env":[]},
                {"id":"b","name":"Beta","transport":"stdio","command":"x","args":[],"env":[]}],
            "profiles":[{"id":"p","name":"P","enabledServerIds":["a"]}],
            "activeProfileId":"p","allowAgentControl":true}"#;
        std::fs::write(&path, json).unwrap();
        let reg = registry::load_from(&path).unwrap();

        // A registered HTTP client scoped to only server "a" (Alpha).
        let allowed: std::collections::HashSet<String> = ["a".to_string()].into_iter().collect();

        // Toggling Beta (out of scope) by name is refused, and Beta stays untouched.
        let refused =
            set_server_enabled_via_agent(&reg, Some("p"), &path, "Beta", true, Some(&allowed), None);
        assert!(refused.is_err(), "out-of-scope toggle must be refused");
        assert!(
            !registry::load_from(&path).unwrap().is_enabled("p", "b"),
            "out-of-scope server must not be toggled"
        );

        // The "Known servers" list on a miss must not enumerate out-of-scope servers:
        // a non-matching target so Beta only appears if it leaked from the list.
        let miss = set_server_enabled_via_agent(&reg, Some("p"), &path, "zzz", true, Some(&allowed), None);
        let msg = miss.unwrap_err();
        assert!(msg.contains("Alpha"), "in-scope server should be listed: {msg}");
        assert!(!msg.contains("Beta"), "out-of-scope name leaked in Known servers: {msg}");

        // An in-scope server still resolves (Alpha is already on -> idempotent OK).
        let ok = set_server_enabled_via_agent(&reg, Some("p"), &path, "Alpha", true, Some(&allowed), None);
        assert!(ok.is_ok(), "in-scope toggle should resolve: {ok:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn initialize_echoes_protocol_and_advertises_tools() {
        let reg = Registry::default();
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &[],
            false,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(resp["result"]["capabilities"]["tools"]["listChanged"], true);
    }

    #[test]
    fn notifications_get_no_reply() {
        let reg = Registry::default();
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(
            &note,
            &reg,
            &router(),
            &[],
            false,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .is_none());
    }

    #[test]
    fn tools_list_always_includes_status() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &[],
            false,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(names.contains(&"toolport_status"));
    }

    #[test]
    fn status_tool_reports_enabled_servers() {
        let mut reg = Registry::default();
        let id = reg.add_server(registry::ServerEntry {
            id: String::new(),
            name: "github".to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".to_string()),
            args: vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-github".to_string(),
            ],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
        });
        reg.set_server_enabled("default", &id, true).unwrap();

        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "toolport_status", "arguments": {} }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &[],
            false,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn unknown_method_is_jsonrpc_error() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 9, "method": "frobnicate" });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &[],
            false,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
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
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        // Default registry has agent control off, so it's the four core
        // meta-tools: status, search, call, fetch_result (no downstream tools).
        assert_eq!(names.len(), 4);
        assert!(names.contains(&"toolport_status"));
        assert!(names.contains(&"toolport_search_tools"));
        assert!(names.contains(&"toolport_call_tool"));
        assert!(names.contains(&"toolport_fetch_result"));
        assert!(!names.contains(&"resend__send_email"));
    }

    #[test]
    fn explain_match_reports_hits_and_ignores_misses() {
        let tool = json!({
            "name": "acme__send_email",
            "description": "Send an email message to a recipient.",
        });
        // A query term present in the tool is reported as a match.
        let why = explain_match("email", &tool);
        assert!(!why.is_empty(), "expected a match, got {why:?}");
        assert!(why.iter().any(|m| m.contains("email")), "got {why:?}");
        // A term absent from both name and description contributes nothing.
        assert!(
            explain_match("quantum", &tool).is_empty(),
            "unexpected match for an absent term"
        );
        // A pinned/semantic-only surface (no lexical overlap) yields no explanation.
        assert!(explain_match("", &tool).is_empty());
    }

    #[test]
    fn canonical_meta_aliases_legacy_names() {
        // The 7 legacy conduit_* meta names map to their toolport_* forms.
        assert_eq!(canonical_meta("conduit_status"), Some("toolport_status"));
        assert_eq!(
            canonical_meta("conduit_search_tools"),
            Some("toolport_search_tools")
        );
        assert_eq!(canonical_meta("conduit_call_tool"), Some("toolport_call_tool"));
        assert_eq!(
            canonical_meta("conduit_fetch_result"),
            Some("toolport_fetch_result")
        );
        assert_eq!(canonical_meta("conduit_confirm"), Some("toolport_confirm"));
        // New names, downstream tools, and non-meta conduit_* pass through (None).
        assert_eq!(canonical_meta("toolport_search_tools"), None);
        assert_eq!(canonical_meta("resend__send_email"), None);
        assert_eq!(canonical_meta("conduit_lib"), None);
    }

    #[test]
    fn legacy_conduit_alias_dispatches_like_toolport() {
        // A tools/call under the OLD conduit_* name must route identically to the
        // renamed toolport_* name, so nothing that still uses the old names breaks.
        let reg = Registry::default();
        let call = |nm: &str| {
            handle_request(
                &json!({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": { "name": nm, "arguments": { "query": "email" } }
                }),
                &reg,
                &router(),
                &catalog(),
                true,
                None,
                &SearchGuard::default(),
                &ConfirmGuard::new(),
                None,
                None,
            )
            .unwrap()
        };
        assert_eq!(
            call("conduit_search_tools")["result"],
            call("toolport_search_tools")["result"],
            "legacy conduit_search_tools alias should dispatch identically to toolport_search_tools"
        );
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
        assert_eq!(
            hits[1].get("schemaOmitted").and_then(|v| v.as_bool()),
            Some(true)
        );
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
            "params": { "name": "toolport_search_tools", "arguments": { "query": "charges" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
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
            "params": { "name": "toolport_search_tools", "arguments": { "query": "zzznotarealtoolzzz" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("No tools matched"));
        // No phantom "Top match" when there's nothing to call.
        assert!(!text.contains("Top match:"));
    }

    const ESCALATION_MARK: &str = "keep getting the same top tool";

    fn search_req(query: &str) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": "toolport_search_tools", "arguments": { "query": query } }
        })
    }

    fn search_text(reg: &Registry, guard: &SearchGuard, query: &str) -> String {
        let resp = handle_request(
            &search_req(query),
            reg,
            &router(),
            &catalog(),
            true,
            None,
            guard,
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn repeated_same_need_escalates_then_resets() {
        let reg = Registry::default();
        let guard = SearchGuard::default();

        // Same query keeps returning the same top tool; first two stay polite.
        for _ in 0..2 {
            let text = search_text(&reg, &guard, "charges");
            assert!(text.contains("Top match:"));
            assert!(!text.contains(ESCALATION_MARK));
        }
        // Third repeat of the same top tool trips the loop-breaker.
        let text = search_text(&reg, &guard, "charges");
        assert!(
            text.contains(ESCALATION_MARK),
            "3rd same-result search must escalate"
        );
        assert!(text.contains("stripe__list_charges"));

        // Any non-search action resets the streak; the next search is polite again.
        let status = json!({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": { "name": "toolport_status", "arguments": {} }
        });
        handle_request(
            &status,
            &reg,
            &router(),
            &catalog(),
            true,
            None,
            &guard,
            &ConfirmGuard::new(),
            None,
            None,
        );
        let text = search_text(&reg, &guard, "charges");
        assert!(
            !text.contains(ESCALATION_MARK),
            "non-search action should reset the streak"
        );
        assert!(text.contains("Top match:"));
    }

    #[test]
    fn searching_different_needs_never_escalates() {
        // The capable-model guarantee: a model that searches several DIFFERENT things
        // in a row (different top tool each time) is never cut off, no matter how many
        // searches. This is what keeps Claude/Cursor's exploration unaffected.
        let reg = Registry::default();
        let guard = SearchGuard::default();
        for q in [
            "charges",
            "offerings",
            "send",
            "charges",
            "offerings",
            "send",
        ] {
            let text = search_text(&reg, &guard, q);
            assert!(text.contains("Top match:"), "query {q} should stay polite");
            assert!(
                !text.contains(ESCALATION_MARK),
                "query {q} must not escalate"
            );
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
        assert_eq!(
            a["teamId"], "team_x",
            "flattened args must still reach the tool"
        );

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
            "toolport_call_tool's arguments must accept arbitrary properties"
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
        assert!(!toks
            .iter()
            .any(|t| t == "purpose" || t == "return" || t == "the" || t == "of"));
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
        assert!(
            !after.contains("OLDEST"),
            "kept the oldest line past the cap"
        );
        assert!(!after.starts_with('x'), "did not cut on a line boundary");
        std::fs::remove_file(&path).ok();
    }

    // --- confirm_destructive tests ---

    /// A catalog with one safe tool and one destructive tool.
    fn catalog_with_destructive() -> Vec<Value> {
        vec![
            json!({ "name": "stripe__list_charges", "description": "List charges", "inputSchema": {} }),
            json!({
                "name": "stripe__delete_customer",
                "description": "Delete a customer permanently",
                "inputSchema": {},
                "annotations": { "destructiveHint": true }
            }),
        ]
    }

    /// Build a registry with confirm_destructive enabled.
    fn registry_with_confirm() -> Registry {
        let mut reg = Registry::default();
        reg.set_confirm_destructive(true);
        reg
    }

    #[test]
    fn confirm_destructive_intercepts_destructive_call() {
        let reg = registry_with_confirm();
        let req = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "stripe__delete_customer", "arguments": { "id": "cus_123" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("Destructive action intercepted"),
            "should intercept: {text}"
        );
        assert!(text.contains("stripe__delete_customer"));
        assert!(text.contains("cus_123"));
        assert!(text.contains("toolport_confirm"));
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn confirm_destructive_does_not_intercept_safe_call() {
        let reg = registry_with_confirm();
        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "stripe__list_charges", "arguments": {} }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        // list_charges is not a real server in the test router, so it'll error —
        // but it should NOT be intercepted by the confirm guard.
        assert!(
            !text.contains("Destructive action intercepted"),
            "safe call should not be intercepted"
        );
    }

    #[test]
    fn confirm_destructive_off_does_not_intercept() {
        let reg = Registry::default(); // confirm_destructive = false
        let req = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "stripe__delete_customer", "arguments": { "id": "cus_123" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            !text.contains("Destructive action intercepted"),
            "should not intercept when feature is off"
        );
    }

    #[test]
    fn confirm_destructive_cannot_be_bypassed_via_toolport_call_tool() {
        let reg = registry_with_confirm();
        // Agent tries to call the destructive tool via toolport_call_tool instead
        // of directly — the interceptor should still catch it because
        // toolport_call_tool unwraps before the interception check.
        let req = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "toolport_call_tool",
                "arguments": {
                    "name": "stripe__delete_customer",
                    "arguments": { "id": "cus_456" }
                }
            }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("Destructive action intercepted"),
            "should intercept even via toolport_call_tool"
        );
        assert!(text.contains("cus_456"));
    }

    #[test]
    fn confirm_destructive_invalid_token_fails() {
        let reg = registry_with_confirm();
        let req = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "toolport_confirm", "arguments": { "token": "deadbeef" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("expired or invalid"),
            "invalid token should error"
        );
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn confirm_destructive_empty_token_fails() {
        let reg = registry_with_confirm();
        let req = json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": { "name": "toolport_confirm", "arguments": { "token": "" } }
        });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("pass the"),
            "empty token should give guidance"
        );
    }

    #[test]
    fn confirm_destructive_tools_list_includes_toolport_confirm() {
        let reg = registry_with_confirm();
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(
            names.contains(&"toolport_confirm"),
            "tools/list should include toolport_confirm when feature is on"
        );
    }

    #[test]
    fn confirm_destructive_tools_list_excludes_toolport_confirm_when_off() {
        let reg = Registry::default(); // confirm_destructive = false
        let req = json!({ "jsonrpc": "2.0", "id": 8, "method": "tools/list" });
        let resp = handle_request(
            &req,
            &reg,
            &router(),
            &catalog_with_destructive(),
            true,
            None,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            None,
            None,
        )
        .unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        assert!(
            !names.contains(&"toolport_confirm"),
            "should not include toolport_confirm when feature is off"
        );
    }

    #[test]
    fn confirm_and_deny_destructive_are_mutually_exclusive() {
        let mut reg = Registry::default();

        // Enabling confirm turns off deny.
        reg.set_deny_destructive(true);
        reg.set_confirm_destructive(true);
        assert!(reg.confirm_destructive);
        assert!(!reg.deny_destructive, "enabling confirm must turn off deny");

        // Enabling deny turns off confirm.
        reg.set_deny_destructive(true);
        assert!(reg.deny_destructive);
        assert!(
            !reg.confirm_destructive,
            "enabling deny must turn off confirm"
        );
    }

    #[test]
    fn confirm_guard_token_is_consumed_on_use() {
        let guard = ConfirmGuard::new();
        let token = guard.store("srv__delete".into(), json!({"id": "x"}));
        // First take succeeds.
        let (name, args) = guard.take(&token).unwrap();
        assert_eq!(name, "srv__delete");
        assert_eq!(args["id"], "x");
        // Second take fails (token consumed).
        assert!(guard.take(&token).is_none(), "token should be single-use");
    }

    #[test]
    fn confirm_destructive_full_flow_does_not_loop() {
        // The critical test: a destructive call is intercepted, then confirmed
        // via toolport_confirm. The confirmed call must NOT be re-intercepted
        // (which would create an infinite loop).
        let reg = registry_with_confirm();
        let confirm = ConfirmGuard::new();
        let cat = catalog_with_destructive();

        // Step 1: destructive call is intercepted.
        let req1 = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "stripe__delete_customer", "arguments": { "id": "cus_999" } }
        });
        let resp1 = handle_request(
            &req1,
            &reg,
            &router(),
            &cat,
            true,
            None,
            &SearchGuard::default(),
            &confirm,
            None,
            None,
        )
        .unwrap();
        let text1 = resp1["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text1.contains("Destructive action intercepted"));

        // Extract the token from the preview message.
        let token_start = text1.find("token: ").unwrap() + 7;
        let token = &text1[token_start..token_start + 32];

        // Step 2: confirm with the token. This must fall through to normal
        // routing — NOT re-intercepted.
        let req2 = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "toolport_confirm", "arguments": { "token": token } }
        });
        let resp2 = handle_request(
            &req2,
            &reg,
            &router(),
            &cat,
            true,
            None,
            &SearchGuard::default(),
            &confirm,
            None,
            None,
        )
        .unwrap();
        let text2 = resp2["result"]["content"][0]["text"].as_str().unwrap();
        // The confirmed call reached the router (which doesn't have a real
        // stripe server, so it errors), but the important thing is it was NOT
        // re-intercepted.
        assert!(
            !text2.contains("Destructive action intercepted"),
            "confirmed call must not be re-intercepted (would loop). Got: {text2}"
        );
    }
}
