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
use conduit_lib::router::Router;
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
            Returns matching tools with their exact name, description, and input schema. \
            Use this to find a tool, then run it with conduit_call_tool. \
            Search by capability or vendor, e.g. \"send email\", \"list stripe charges\", \"revenuecat offerings\".",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keywords describing the tool you need." },
                "limit": { "type": "integer", "description": "Max results (default 10).", "default": 10 }
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

/// Rank the cached catalog against a query. A name hit weighs more than a
/// description hit; tools matching more terms rank higher. Empty query returns
/// the first `limit` tools so a bare call still surfaces something.
fn search_catalog(cached: &[Value], query: &str, limit: usize) -> Vec<Value> {
    let q = query.to_lowercase();
    let terms: Vec<&str> = q.split_whitespace().filter(|t| !t.is_empty()).collect();

    let project = |t: &Value| {
        json!({
            "name": t.get("name").cloned().unwrap_or(Value::Null),
            "description": t.get("description").cloned().unwrap_or(Value::Null),
            "inputSchema": t.get("inputSchema").cloned().unwrap_or(Value::Null),
        })
    };

    if terms.is_empty() {
        return cached.iter().take(limit).map(project).collect();
    }

    let mut scored: Vec<(i32, &Value)> = cached
        .iter()
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
    scored.into_iter().take(limit).map(|(_, t)| project(t)).collect()
}

fn enabled_summary(reg: &Registry, profile: Option<&str>) -> String {
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
    out
}

/// Dispatch one JSON-RPC message. Returns `None` for notifications (no reply).
fn handle_request(
    req: &Value,
    reg: &Registry,
    router: &mut Router,
    cached: &[Value],
    lazy: bool,
    profile: Option<&str>,
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
                    "capabilities": { "tools": { "listChanged": true } },
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

            if name == "conduit_status" {
                return Some(success(
                    id,
                    json!({
                        "content": [{ "type": "text", "text": enabled_summary(reg, profile) }],
                        "isError": false
                    }),
                ));
            }

            if name == "conduit_search_tools" {
                let query = arguments
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let limit = arguments
                    .get("limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10)
                    .clamp(1, 50) as usize;
                let matches = search_catalog(cached, query, limit);
                let text = format!(
                    "Found {} tool(s) for \"{}\". Call one with conduit_call_tool using its exact name.\n\n{}",
                    matches.len(),
                    query,
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
            match router.route_call(name, arguments) {
                Ok(result) => {
                    let ok = !result
                        .get("isError")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    audit::record(srv, tool, ok);
                    Some(success(id, result))
                }
                Err(e) => {
                    audit::record(srv, tool, false);
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

    // Connect concurrently so total time is the slowest server, not the sum.
    let handles: Vec<_> = servers
        .into_iter()
        .map(|server| std::thread::spawn(move || connect_one(&server)))
        .collect();

    let mut router = Router::new();
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
                if let Some(v) = secrets::get_secret(&server.id, &e.key) {
                    env.push((e.key.clone(), v));
                } else {
                    eprintln!(
                        "conduit: '{}' needs secret '{}' but none is vaulted",
                        server.id, e.key
                    );
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
        Ok(ds) => {
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
    let mut out = stdout.lock().unwrap();
    let _ = writeln!(
        out,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" })
    );
    let _ = out.flush();
}

/// Append a line to the gateway debug log (for diagnosing client connections).
fn glog(msg: &str) {
    if let Some(dir) = dirs::config_dir() {
        let path = dir.join("Conduit").join("gateway-debug.log");
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
    let dir = dirs::config_dir()?.join("Conduit");
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
        *registry.lock().unwrap() = new_reg;
        *router.lock().unwrap() = new_router;
        // Same guard as the initial build: never persist an empty catalog over a
        // good one (a half-written registry would otherwise wipe the cache).
        if !tools.is_empty() {
            *cached_tools.lock().unwrap() = tools.clone();
            save_tool_cache(&tools, profile.as_deref());
        }
        notify_tools_changed(&stdout);
        eprintln!("conduit: registry changed, sent tools/list_changed");
    }
}

fn main() {
    let lazy = std::env::var("CONDUIT_DISCOVERY")
        .map(|v| v.eq_ignore_ascii_case("lazy"))
        .unwrap_or(false);
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
    match registry::load_resolved() {
        Ok(r) => glog(&format!(
            "load_resolved OK: {} servers total, {} enabled (active={})",
            r.servers.len(),
            r.enabled_servers().len(),
            r.active_profile_id()
        )),
        Err(e) => glog(&format!("load_resolved ERR: {e}")),
    }
    let registry = Arc::new(Mutex::new(registry::load_resolved().unwrap_or_default()));
    // Empty router + cached catalog: the handshake and tools/list answer instantly
    // (from cache), while downstream servers connect in the background for the
    // actual tool calls.
    let router = Arc::new(Mutex::new(Router::new()));
    let cached_tools = Arc::new(Mutex::new(load_tool_cache(profile.as_deref())));
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let ready = Arc::new(AtomicBool::new(false));
    glog(&format!(
        "loaded tool cache: {} tools",
        cached_tools.lock().unwrap().len()
    ));

    {
        let registry = Arc::clone(&registry);
        let router = Arc::clone(&router);
        let stdout = Arc::clone(&stdout);
        let ready = Arc::clone(&ready);
        let cached_tools = Arc::clone(&cached_tools);
        let profile = profile.clone();
        std::thread::spawn(move || {
            let reg = registry.lock().unwrap().clone();
            let built = build_router(&reg, profile.as_deref());
            let tools = built.aggregated_tools();
            glog(&format!(
                "background build: {} tools from {} servers",
                tools.len(),
                built.server_count()
            ));
            *router.lock().unwrap() = built;
            // Don't let a transient empty build (registry caught mid-write, or
            // every downstream momentarily unreachable) clobber a good catalog -
            // that's what leaves a client showing only conduit_status.
            if !tools.is_empty() {
                *cached_tools.lock().unwrap() = tools.clone();
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
            "tools/list" => cached_tools.lock().unwrap().is_empty(),
            "tools/call" => true,
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
        if method == "tools/call" && router.lock().unwrap().server_count() == 0 {
            let reg = registry.lock().unwrap().clone();
            let built = build_router(&reg, profile.as_deref());
            if built.server_count() > 0 {
                let tools = built.aggregated_tools();
                *router.lock().unwrap() = built;
                if !tools.is_empty() {
                    *cached_tools.lock().unwrap() = tools.clone();
                    save_tool_cache(&tools, profile.as_deref());
                }
                glog(&format!(
                    "self-heal: rebuilt router ({} servers, {} tools)",
                    router.lock().unwrap().server_count(),
                    tools.len()
                ));
                notify_tools_changed(&stdout);
            }
        }

        let cache_snapshot = cached_tools.lock().unwrap().clone();
        let response = {
            let reg = registry.lock().unwrap();
            let mut r = router.lock().unwrap();
            handle_request(&req, &reg, &mut r, &cache_snapshot, lazy, profile.as_deref())
        };
        if let Some(resp) = response {
            let mut out = stdout.lock().unwrap();
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
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(resp["result"]["capabilities"]["tools"]["listChanged"], true);
    }

    #[test]
    fn notifications_get_no_reply() {
        let reg = Registry::default();
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(&note, &reg, &mut router(), &[], false, None).is_none());
    }

    #[test]
    fn tools_list_always_includes_status() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/list" });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None).unwrap();
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
        });
        reg.set_server_enabled("default", &id, true).unwrap();

        let req = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "conduit_status", "arguments": {} }
        });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("github"));
        assert_eq!(resp["result"]["isError"], false);
    }

    #[test]
    fn unknown_method_is_jsonrpc_error() {
        let reg = Registry::default();
        let req = json!({ "jsonrpc": "2.0", "id": 9, "method": "frobnicate" });
        let resp = handle_request(&req, &reg, &mut router(), &[], false, None).unwrap();
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
        let resp = handle_request(&req, &reg, &mut router(), &catalog(), true, None).unwrap();
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
        let hits = search_catalog(&catalog(), "email", 10);
        assert_eq!(hits[0]["name"], "resend__send_email");
        assert!(hits.iter().any(|h| h["name"] == "rc__list_offerings"));
        assert!(!hits.iter().any(|h| h["name"] == "stripe__list_charges"));
    }

    #[test]
    fn search_tool_call_returns_matches() {
        let reg = Registry::default();
        let req = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "conduit_search_tools", "arguments": { "query": "charges" } }
        });
        let resp = handle_request(&req, &reg, &mut router(), &catalog(), true, None).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("stripe__list_charges"));
        assert_eq!(resp["result"]["isError"], false);
    }
}
