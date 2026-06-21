//! Conduit gateway.
//!
//! A local MCP server, spoken over stdio (newline-delimited JSON-RPC 2.0). Each
//! AI client points at this one binary; the gateway routes to all the real
//! servers the active profile enables. This is what gives us one control point,
//! and (next) hot-toggle, runtime secret injection, and an audit log.
//!
//! Implemented: the MCP handshake, a `conduit_status` meta-tool, and downstream
//! proxying - it spawns each enabled stdio server, lists its real tools
//! (namespaced by server id), and forwards `tools/call` to the right one.
//!
//! TODO(gateway): watch the registry file and emit notifications/tools/list_changed
//!                so toggles apply live without restarting the client.
//! TODO(gateway): inject secrets from the OS keychain at spawn time.
//! TODO(gateway): proxy remote (http/sse) servers, not just stdio.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use conduit_lib::audit;
use conduit_lib::clients;
use conduit_lib::downstream::{DownstreamServer, StdioTransport, PROTOCOL_VERSION};
use conduit_lib::registry::{self, Registry, ServerEntry};
use conduit_lib::remote;
use conduit_lib::router::{Router, ToolPolicy};
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
        "description": "List the MCP servers Conduit has enabled in the active profile.",
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
            `name` (as returned by the search) and its `arguments` object matching that tool's input schema.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Exact tool name from conduit_search_tools." },
                "arguments": { "type": "object", "description": "Arguments for the tool, per its input schema." }
            },
            "required": ["name"],
            "additionalProperties": false
        }
    })
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

/// Rank the cached catalog against a query, optionally scoped to one server.
/// A name hit weighs more than a description hit; tools matching more terms rank
/// higher. An empty query lists tools (all of a server's when `server` is set).
/// Returns (results, total_matched) so the caller can tell the agent when results
/// were truncated - otherwise a buried tool reads as "doesn't exist". When NOT
/// scoped to a server, results are diversified so one chatty server can't flood
/// the window (the bug where a "create product" query returned only RevenueCat).
fn search_catalog(
    cached: &[Value],
    query: &str,
    server: Option<&str>,
    limit: usize,
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
        let mut scored: Vec<(i32, &Value)> = pool
            .into_iter()
            .filter_map(|t| {
                let name = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let desc = t
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let mut score = 0;
                for term in &terms {
                    if name.contains(term) {
                        score += 3;
                    } else if desc.contains(term) {
                        score += 1;
                    }
                }
                (score > 0).then_some((score, t))
            })
            .collect();
        // Stable, highest score first.
        scored.sort_by(|a, b| b.0.cmp(&a.0));
        let total = scored.len();

        // Scoped to a server: take the top `limit`. Unscoped: cap per server so one
        // server with many matching tools can't crowd the others out of the window.
        let selected: Vec<&Value> = if server_filter.is_some() {
            scored.into_iter().take(limit).map(|(_, t)| t).collect()
        } else {
            let cap = (limit / 3).max(4);
            let mut per: HashMap<String, usize> = HashMap::new();
            let mut out = Vec::new();
            for (_, t) in scored {
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

/// Project selected tools to search results, bounding the total size of their
/// (sometimes enormous) input schemas. Lazy discovery exists to keep the agent's
/// context small, so one server's giant schemas must not blow it up: the top
/// result always carries its full schema; past a byte budget the rest return name
/// + description only, flagged `schemaOmitted` so the agent can fetch a specific
/// tool's full schema by searching its exact name (or scoping with `server`).
fn project_budgeted(tools: &[&Value]) -> Vec<Value> {
    const SCHEMA_BUDGET: usize = 24_000;
    // Cap each description too: some servers ship multi-KB descriptions, which add
    // up across results. Enough to choose a tool; full text comes from a scoped or
    // exact-name search.
    const DESC_MAX: usize = 500;
    let truncate_desc = |d: Option<&Value>| match d.and_then(|v| v.as_str()) {
        Some(s) if s.chars().count() > DESC_MAX => {
            let head: String = s.chars().take(DESC_MAX).collect();
            Value::String(format!("{head}…"))
        }
        _ => d.cloned().unwrap_or(Value::Null),
    };
    let mut used = 0usize;
    tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let name = t.get("name").cloned().unwrap_or(Value::Null);
            let description = truncate_desc(t.get("description"));
            let schema = t.get("inputSchema").cloned().unwrap_or(Value::Null);
            let slen = if schema.is_null() {
                0
            } else {
                schema.to_string().len()
            };
            if i == 0 || used + slen <= SCHEMA_BUDGET {
                used += slen;
                json!({ "name": name, "description": description, "inputSchema": schema })
            } else {
                json!({ "name": name, "description": description, "schemaOmitted": true })
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
    out
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications (no reply).
/// Per-session guard against search-thrash. Weak local models (e.g. small-active
/// MoEs) will call conduit_search_tools many times in a row for the SAME need
/// instead of committing, which is slow and burns context. We escalate only on
/// that specific pattern - the same top tool surfacing across consecutive searches
/// - not on a raw search count. A capable model that searches once and calls, or
/// searches several DIFFERENT things (exploring), or narrows broad -> server ->
/// exact-name (each a different/justified result), never trips this. So it fixes
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
                let tools = vec![status_tool_def(), search_tool_def(), call_tool_def()];
                glog("tools/list -> 3 tools (lazy discovery)");
                return Some(success(id, json!({ "tools": tools })));
            }
            let mut tools = vec![status_tool_def()];
            // Prefer the cached catalog (instant); fall back to the live router.
            if cached.is_empty() {
                tools.extend(router.aggregated_tools());
            } else {
                tools.extend(cached.iter().cloned());
            }
            glog(&format!(
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
                let (mut matches, total) = search_catalog(source, query, server, limit);
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

            // conduit_call_tool dispatches a discovered tool: unwrap to its real
            // name + arguments and fall through to the normal routing below.
            let (name, arguments) = if name == "conduit_call_tool" {
                let inner = arguments
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let inner_args = arguments
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                (inner, inner_args)
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
            glog(&format!("resources/list -> {} resources", resources.len()));
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
            glog(&format!("prompts/list -> {} prompts", prompts.len()));
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
fn build_router(reg: &Registry, profile: Option<&str>) -> Router {
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
        .map(|server| std::thread::spawn(move || connect_one(&server)))
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
fn connect_one(server: &ServerEntry) -> Option<DownstreamServer> {
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
        match StdioTransport::spawn(command, &server.args, &env) {
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

/// Append a line to the gateway debug log (for diagnosing client connections).
fn glog(msg: &str) {
    if std::env::var_os("CONDUIT_DEBUG").is_none() {
        return;
    }
    if let Some(dir) = registry::conduit_dir() {
        let path = dir.join("gateway-debug.log");
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
    }
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
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(s) = serde_json::to_string(tools) {
            let _ = std::fs::write(path, s);
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
) {
    eprintln!("conduit: watching registry at {}", path.display());
    let mut last = mtime(&path);
    loop {
        std::thread::sleep(Duration::from_millis(1000));
        let current = mtime(&path);
        if current == last {
            continue;
        }
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
        let new_router = build_router(&new_reg, profile.as_deref());
        let tools = new_router.aggregated_tools();
        *registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = new_reg;
        *router.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = new_router;
        // Same guard as the initial build: never persist an empty catalog over a
        // good one (a half-written registry would otherwise wipe the cache).
        if !tools.is_empty() {
            *cached_tools.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = tools.clone();
            save_tool_cache(&tools, profile.as_deref());
        }
        notify_tools_changed(&stdout);
        eprintln!("conduit: registry changed, sent tools/list_changed");
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
        let profile = profile.clone();
        std::thread::spawn(move || {
            let reg = registry.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            let built = build_router(&reg, profile.as_deref());
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
        let profile = profile.clone();
        std::thread::spawn(move || {
            watch_registry(path, registry, router, stdout, cached_tools, profile)
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
        glog(&format!("request: {method}"));

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
            let built = build_router(&reg, profile.as_deref());
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
}
