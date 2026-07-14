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

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

use conduit_lib::audit;
use conduit_lib::clients;
use conduit_lib::downstream::{
    self, DownstreamServer, ServerRequestHandler, StdioTransport, Transport, PROTOCOL_VERSION,
};
use conduit_lib::inspect;
use conduit_lib::integrity;
use conduit_lib::registry::{self, Registry, ServerEntry};
use conduit_lib::remote;
use conduit_lib::router::{is_destructive, sanitize_segment, Reconnect, Router, ToolPolicy};
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

const MAX_SEARCH_QUERY_CHARS: usize = 512;
const MAX_SEARCH_QUERY_TOKENS: usize = 64;
const MAX_STDIO_LINE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum BoundedLine {
    Eof,
    Line(String),
    TooLong,
}

/// Read one newline-delimited stdio frame without allowing an upstream client to
/// grow an unbounded String. An oversized frame is fully drained so the caller can
/// safely continue with the next request instead of parsing a trailing fragment.
fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> std::io::Result<BoundedLine> {
    let mut bytes = Vec::new();
    let read = reader
        .by_ref()
        .take(max_bytes as u64 + 2)
        .read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(BoundedLine::Eof);
    }

    let terminated = bytes.last() == Some(&b'\n');
    let mut content_len = bytes.len() - usize::from(terminated);
    if terminated && content_len > 0 && bytes[content_len - 1] == b'\r' {
        content_len -= 1;
    }

    if content_len > max_bytes {
        if !terminated {
            loop {
                let buffered = reader.fill_buf()?;
                if buffered.is_empty() {
                    break;
                }
                if let Some(newline) = buffered.iter().position(|b| *b == b'\n') {
                    reader.consume(newline + 1);
                    break;
                }
                let len = buffered.len();
                reader.consume(len);
            }
        }
        return Ok(BoundedLine::TooLong);
    }

    bytes.truncate(content_len);
    String::from_utf8(bytes)
        .map(BoundedLine::Line)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

/// Validate the model-authored search query in one short-circuiting pass before
/// it reaches lexical ranking or the optional embedding endpoint. The ranker
/// splits on whitespace too, so this token bound matches the work it performs.
fn validate_search_query(query: &str) -> Result<(), &'static str> {
    let mut chars = 0;
    let mut tokens = 0;
    let mut in_token = false;

    for ch in query.chars() {
        chars += 1;
        if chars > MAX_SEARCH_QUERY_CHARS {
            return Err("Toolport: search query exceeds the 512-character limit.");
        }

        if ch.is_whitespace() {
            in_token = false;
        } else if !in_token {
            tokens += 1;
            if tokens > MAX_SEARCH_QUERY_TOKENS {
                return Err("Toolport: search query exceeds the 64-token limit.");
            }
            in_token = true;
        }
    }

    Ok(())
}

fn status_tool_def() -> Value {
    json!({
        "name": "toolport_status",
        "description": "Report Toolport's status: the MCP servers enabled in the active profile, each server's tool count, and how many tokens (and dollars) lazy discovery has saved you so far.",
        "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false }
    })
}

/// The core meta-tools that power lazy discovery. In lazy mode the gateway advertises
/// status, search, call, and fetch-result, plus only the optional controls the user has
/// enabled. The client's context holds a handful of tool defs instead of hundreds -
/// the model discovers the real tool on demand and dispatches through
/// `toolport_call_tool`.
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
                "query": { "type": "string", "maxLength": MAX_SEARCH_QUERY_CHARS, "description": "Keywords describing the capability you need (e.g. \"list emails\", \"create payment\", \"recent deployments\"). Empty lists tools (use with `server`). Maximum 512 characters / 64 whitespace-separated tokens." },
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

// --- Grouped discovery mode (CONDUIT_DISCOVERY=grouped) ---
//
// Between `lazy` (a constant handful of meta-tools; best for a capable model that
// can invent a good search query) and `full` (the entire namespaced catalog; huge),
// grouped mode advertises the lazy meta-tools PLUS a per-server `help_<server>`
// browse tool. A model too weak to invent a search query can instead pick a server
// by name - an *enumerable* choice - and list its tools. `help_<server>` is just a
// server-scoped `toolport_search_tools` (see the tools/call rewrite), and dispatch
// still goes through `toolport_call_tool`, so the audited call path is unchanged and
// there is no new execution surface. Enabled per-client via the env var; grouped
// implies not-lazy (the lazy resolver only returns true for `=lazy`).

/// The three tool-discovery modes. Resolved from env + the registry (including a
/// per-client override) and cached in `DISCOVERY_MODE`, which the registry watcher
/// refreshes on every change so a mode edit applies live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryMode {
    Lazy,
    Grouped,
    Full,
}

impl DiscoveryMode {
    fn as_u8(self) -> u8 {
        match self {
            DiscoveryMode::Lazy => 0,
            DiscoveryMode::Grouped => 1,
            DiscoveryMode::Full => 2,
        }
    }
    fn from_u8(v: u8) -> Self {
        match v {
            1 => DiscoveryMode::Grouped,
            2 => DiscoveryMode::Full,
            _ => DiscoveryMode::Lazy,
        }
    }
    /// The name used in the registry, env, and status output.
    fn as_str(self) -> &'static str {
        match self {
            DiscoveryMode::Lazy => "lazy",
            DiscoveryMode::Grouped => "grouped",
            DiscoveryMode::Full => "full",
        }
    }
}

/// The live discovery mode. Mutable (not a `OnceLock`) so the watcher can refresh it when
/// the registry's per-client override changes; `discovery_mode()` reads it lock-free.
static DISCOVERY_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

fn set_discovery_mode(mode: DiscoveryMode) {
    DISCOVERY_MODE.store(mode.as_u8(), std::sync::atomic::Ordering::Relaxed);
}

/// Parse a registry / per-client override mode string; `None` for empty, `inherit`, or an
/// unrecognized value (so it falls through to the next precedence level).
fn parse_mode(s: &str) -> Option<DiscoveryMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "grouped" => Some(DiscoveryMode::Grouped),
        "full" => Some(DiscoveryMode::Full),
        "lazy" => Some(DiscoveryMode::Lazy),
        _ => None,
    }
}

/// Resolve this client's discovery mode from a loaded registry + env. See
/// [`resolve_mode_from`] for the precedence.
fn discovery_mode_for(reg: &Registry, client_id: Option<&str>) -> DiscoveryMode {
    let env = std::env::var("CONDUIT_DISCOVERY").ok();
    let client_mode = client_id.and_then(|id| reg.client_discovery_mode(id));
    resolve_mode_from(
        env.as_deref(),
        client_mode,
        reg.discovery_mode.as_deref(),
        reg.lazy_discovery,
    )
}

/// Resolve from disk for the gateway bootstrap (before the watcher takes over the live
/// updates), keyed by this client's `CONDUIT_CLIENT_ID`.
fn resolve_discovery_mode() -> DiscoveryMode {
    let client_id = std::env::var("CONDUIT_CLIENT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    match registry::load_resolved().ok() {
        Some(reg) => discovery_mode_for(&reg, client_id.as_deref()),
        None => resolve_mode_from(
            std::env::var("CONDUIT_DISCOVERY").ok().as_deref(),
            None,
            None,
            true,
        ),
    }
}

/// Pure precedence: an explicit `CONDUIT_DISCOVERY` env var (hand-set in a client's config)
/// wins, then the per-client override (`registry.client_discovery[client_id]`), then the
/// registry's global `discovery_mode`, then its `lazy_discovery` bool. A SET env value that
/// isn't lazy/grouped resolves to Full (exactly the old `env == "lazy" ? lazy : not-lazy`);
/// an unrecognized per-client/global override is ignored (falls through).
fn resolve_mode_from(
    env: Option<&str>,
    client_mode: Option<&str>,
    registry_mode: Option<&str>,
    lazy_discovery: bool,
) -> DiscoveryMode {
    if let Some(v) = env {
        return match v.trim().to_ascii_lowercase().as_str() {
            "lazy" => DiscoveryMode::Lazy,
            "grouped" => DiscoveryMode::Grouped,
            _ => DiscoveryMode::Full,
        };
    }
    if let Some(m) = client_mode.and_then(parse_mode) {
        return m;
    }
    if let Some(m) = registry_mode.and_then(parse_mode) {
        return m;
    }
    if lazy_discovery {
        DiscoveryMode::Lazy
    } else {
        DiscoveryMode::Full
    }
}

/// The resolved mode. Defaults to `Lazy` before `main` sets it (only unit tests, which
/// don't run `main` and test the grouped helpers directly, ever observe that default).
fn discovery_mode() -> DiscoveryMode {
    DiscoveryMode::from_u8(DISCOVERY_MODE.load(std::sync::atomic::Ordering::Relaxed))
}

/// True when this gateway runs in grouped discovery mode (see [`grouped_tool_defs`]).
fn grouped_discovery() -> bool {
    discovery_mode() == DiscoveryMode::Grouped
}

/// The server prefix of a *namespaced* tool (`server__tool`). `None` for a bare name
/// (a meta-tool), so those never spawn a spurious `help_<meta>` browse tool. (Guard:
/// `tool_prefix` returns the whole name when there is no `__`.)
fn namespaced_prefix(t: &Value) -> Option<String> {
    let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.contains("__") {
        let p = tool_prefix(t);
        (!p.is_empty()).then_some(p)
    } else {
        None
    }
}

/// Distinct server prefixes in a catalog, in first-seen order, so the advertised
/// `help_<server>` tools have a stable order across lists.
fn distinct_server_prefixes(catalog: &[Value]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for t in catalog {
        if let Some(p) = namespaced_prefix(t) {
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }
    out
}

/// The `help_<server>` browse tool advertised in grouped mode.
fn help_tool_def(prefix: &str, tool_count: usize) -> Value {
    json!({
        "name": format!("help_{prefix}"),
        "description": format!(
            "Browse the {tool_count} tool(s) on the \"{prefix}\" server: returns each tool's exact \
             name, what it does, and its input schema. Pick one and run it with toolport_call_tool \
             (name = the exact name shown). Pass an optional `query` to filter to a capability \
             (recommended when a server has many tools)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Optional keywords to filter this server's tools (empty lists them)." }
            },
            "additionalProperties": false
        }
    })
}

/// The tool set advertised in grouped mode: the lazy meta-tools (so cross-server
/// search and call still work) plus one `help_<server>` browse tool per server.
/// `catalog` must already be scoped to the calling client. Takes the two registry
/// flags directly so callers needn't hold the registry lock across the router lock.
fn grouped_tool_defs(allow_agent_control: bool, confirm_destructive: bool, catalog: &[Value]) -> Vec<Value> {
    let mut tools = vec![
        status_tool_def(),
        search_tool_def(),
        call_tool_def(),
        fetch_result_tool_def(),
    ];
    if allow_agent_control {
        tools.push(enable_server_tool_def());
        tools.push(disable_server_tool_def());
    }
    if confirm_destructive {
        tools.push(confirm_tool_def());
    }
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for t in catalog {
        if let Some(p) = namespaced_prefix(t) {
            *counts.entry(p).or_insert(0) += 1;
        }
    }
    for prefix in distinct_server_prefixes(catalog) {
        let n = counts.get(&prefix).copied().unwrap_or(0);
        tools.push(help_tool_def(&prefix, n));
    }
    tools
}

/// If `name` is a grouped `help_<server>` browse tool, return the server prefix. The
/// tools/call handler rewrites it into a server-scoped `toolport_search_tools`.
fn grouped_help_target(name: &str) -> Option<&str> {
    name.strip_prefix("help_").filter(|p| !p.is_empty())
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

    // Hold the cross-process registry lock across the whole load-modify-save so a concurrent
    // app or team-sync write can't land between our read and our save and be reverted
    // (SOU-23). Held until this function returns. Also re-check the opt-in on the fresh copy
    // (the user may have just turned it off).
    let _lock = registry::lock_at(path).map_err(|e| format!("Toolport: {e}"))?;
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
/// How much a fully-on-the-nose tool name (query explains all its tokens) is boosted
/// over a longer sibling that merely contains the same words. Small: it only tips
/// near-ties toward the more specific tool, never overrides a stronger keyword signal.
const NAME_SPECIFICITY_W: f64 = 0.35;

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
        &["dispute", "chargeback"],
        &["token", "tokenize"],
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
                // Specificity boost: a tool whose NAME is "on the nose" for the query
                // (few tokens beyond what the query explains) beats a longer sibling that
                // merely contains the same words. Without this the ranker ties
                // `create_customer` with `create_customer_session` for "create customer",
                // since both name-match every query token. Multiplicative so it only
                // separates near-ties, never overrides a stronger IDF signal; skipped on
                // a zero score so non-matches stay out.
                if score > 0.0 && !name_set.is_empty() {
                    let explained = name_set
                        .iter()
                        .filter(|nt| {
                            q_tokens.iter().any(|qt| {
                                qt == *nt || synonym_group(qt).contains(&nt.as_str())
                            })
                        })
                        .count();
                    let coverage = explained as f64 / name_set.len() as f64;
                    score *= 1.0 + NAME_SPECIFICITY_W * coverage;
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
    for s in &servers {
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
        // Only surface the "0 tools" hint once the catalog has actually populated
        // (at least one server produced tools). Before that, every server reads as
        // zero simply because downstream connections are still coming up, which
        // would be pure noise rather than a signal.
        if !counts.is_empty() {
            out.push_str("\nTools by server (pass the prefix as `server` to list them all):\n");
            for (p, c) in &counts {
                out.push_str(&format!("- {p}: {c} tool(s)\n"));
            }
            // An enabled server contributing no tools to a populated catalog is the
            // classic symptom of an auth-gated server that hasn't been signed into
            // yet (e.g. Atlassian's OAuth), or one that failed to connect. Call it
            // out so the agent (and user) can self-diagnose instead of assuming the
            // server is simply missing.
            let silent: Vec<&str> = servers
                .iter()
                .filter(|s| !counts.contains_key(&sanitize_segment(&s.id)))
                .map(|s| s.name.as_str())
                .collect();
            if !silent.is_empty() {
                out.push_str(
                    "\nEnabled but exposing 0 tools (may still be connecting, or may need \
                     authentication - e.g. an OAuth sign-in in Conduit):\n",
                );
                for name in silent {
                    out.push_str(&format!("- {name}\n"));
                }
            }
        }
    }
    // The discovery mode this client is actually resolved to (env > per-client override >
    // global), so `toolport_status` answers "why am I seeing meta-tools vs the full
    // catalog?" and confirms a per-client override took effect.
    out.push_str(&format!("\nDiscovery mode: {}\n", discovery_mode().as_str()));
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
    /// The registered HTTP client that created this confirmation. `None` covers
    /// stdio and the legacy unscoped HTTP bearer, which each have one shared caller.
    owner: Option<String>,
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

    /// Store a pending call for one client and return its confirmation token.
    fn store(&self, name: String, arguments: Value, owner: Option<&str>) -> String {
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
                owner: owner.map(str::to_string),
                created: Instant::now(),
            },
        );
        token
    }

    /// Consume a confirmation token only for the client that created it. A
    /// wrong-client attempt does not consume the entry, so it cannot deny the
    /// rightful owner. Returns None when the token is missing, expired, or owned
    /// by a different client; callers intentionally expose the same error for all.
    fn take(&self, token: &str, owner: Option<&str>) -> Option<(String, Value)> {
        let mut pending = self.pending();
        let entry = pending.get(token)?;
        if entry.created.elapsed() > CONFIRM_TTL {
            pending.remove(token);
            return None;
        }
        if entry.owner.as_deref() != owner {
            return None;
        }
        let entry = pending.remove(token)?;
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

fn tool_fingerprint_for(name: &str, cached: &[Value], router: &Router) -> Option<String> {
    let lookup = |tools: &[Value]| {
        tools
            .iter()
            .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(name))
            .map(integrity::fingerprint)
    };
    // Prefer the LIVE router definition (what actually dispatches) so a drifted
    // tool re-prompts instead of matching an approval bound to its stale cached
    // form. `cached` is only a cold-start fallback before downstream servers
    // connect and the router has nothing to aggregate yet.
    lookup(&router.aggregated_tools()).or_else(|| lookup(cached))
}

/// Keep only tools a scoped client may see. `None` = no scoping (every tool passes).
/// A meta-tool (no owning downstream server, e.g. `toolport_search_tools`) is always
/// kept. A downstream tool is kept only if its REAL server is in `allowed`.
///
/// `route_of` resolves an exposed name to its owning server id via the router's route
/// map. Using it (not just the `server__` prefix) is what stops a tool renamed via a
/// `ToolOverride` to a non-namespaced name (e.g. `deploy`) from being mistaken for a
/// meta-tool and leaked to every scoped client. When the router can't resolve the name (a
/// cold cache before downstream servers are indexed), only KNOWN gateway meta-tools and
/// in-scope `help_<server>` tools are kept; an unknown bare name is dropped (fail-closed)
/// rather than assumed to be a meta-tool.
fn scope_tools(
    tools: &[Value],
    allowed: Option<&std::collections::HashSet<String>>,
    route_of: impl Fn(&str) -> Option<String>,
) -> Vec<Value> {
    match allowed {
        None => tools.to_vec(),
        Some(set) => tools
            .iter()
            .filter(|t| {
                t.get("name")
                    .and_then(|n| n.as_str())
                    .map(|n| tool_in_scope(n, set, &route_of))
                    .unwrap_or(false)
            })
            .cloned()
            .collect(),
    }
}

/// Whether a client scoped to `allowed` may see the exposed tool `name`. See
/// [`scope_tools`] for how `route_of` is resolved and why the `server__` prefix is only a
/// fallback.
fn tool_in_scope(
    name: &str,
    allowed: &std::collections::HashSet<String>,
    route_of: &impl Fn(&str) -> Option<String>,
) -> bool {
    match route_of(name) {
        // Authoritative: gate on the real server, sanitized to the same prefix form
        // `allowed` stores. Catches override-renamed names and ids containing `__`.
        Some(server_id) => allowed.contains(sanitize_segment(&server_id).as_str()),
        // The router can't resolve the name (a cold/stale cache before downstream servers
        // are indexed). Recognize gateway-generated tools by name rather than assuming any
        // bare name is a meta-tool - that assumption would leak a downstream tool renamed
        // (via an override) to a bare name during that window.
        None => {
            if is_fixed_meta_tool(name) {
                // Gateway meta-tools are owned by no server; always visible.
                true
            } else if let Some(server) = grouped_help_target(name) {
                // A grouped `help_<server>` browse tool: gate on its target server.
                allowed.contains(server)
            } else {
                // A namespaced tool the router hasn't indexed yet: gate on its `server__`
                // prefix (fail-closed). A bare name that is neither a known meta-tool nor a
                // help tool is unattributable (most likely an override-renamed downstream
                // tool) - drop it rather than leak it.
                let prefix = server_of_tool(name);
                prefix != name && allowed.contains(prefix)
            }
        }
    }
}

/// The fixed gateway meta-tools, owned by no downstream server. Grouped `help_<server>`
/// browse tools are NOT here - they're server-scoped and handled via `grouped_help_target`.
fn is_fixed_meta_tool(name: &str) -> bool {
    matches!(
        name,
        "toolport_status"
            | "toolport_search_tools"
            | "toolport_call_tool"
            | "toolport_confirm"
            | "toolport_fetch_result"
            | "toolport_enable_server"
            | "toolport_disable_server"
    )
}

/// Stable authorization context bound to an MCP Streamable-HTTP session. The
/// identity distinguishes registered and legacy/open callers; the effective
/// scope makes a live client re-scope invalidate its existing sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
struct McpSessionOwner {
    identity: String,
    /// `None` is the full connected set; `Some` is a sorted, deduplicated set of
    /// sanitized server ids, matching [`resolve_http_scope`].
    scope: Option<Vec<String>>,
}

/// Per-request HTTP attribution. The audit label stays human-readable while the
/// session owner uses a stable id and effective scope for authorization checks.
struct HttpCaller {
    audit_label: Option<String>,
    session_owner: McpSessionOwner,
}

/// Resolve authorization, routing scope, audit attribution, and MCP session
/// ownership together so those security decisions cannot drift apart.
fn resolve_http_caller(
    reg: &Registry,
    env_token: Option<&str>,
    provided: Option<&str>,
    allow_insecure_open: bool,
) -> Option<(Option<std::collections::HashSet<String>>, HttpCaller)> {
    let owner_scope = |allowed: &Option<std::collections::HashSet<String>>| {
        allowed.as_ref().map(|set| {
            let mut ids: Vec<String> = set.iter().cloned().collect();
            ids.sort();
            ids
        })
    };

    // Legacy single token: sees the full connected set (back-compat).
    if let (Some(expected), Some(actual)) = (env_token, provided) {
        if ct_eq(expected.as_bytes(), actual.as_bytes()) {
            let allowed = None;
            return Some((
                allowed,
                HttpCaller {
                    audit_label: None,
                    session_owner: McpSessionOwner {
                        identity: format!("legacy:{}", registry::sha256_hex(actual)),
                        scope: None,
                    },
                },
            ));
        }
    }

    // A registered client is scoped to its profile (empty profile = full set).
    if let Some(client) = provided.and_then(|token| reg.http_client_for_token(token)) {
        let allowed = if client.profile.trim().is_empty() {
            None
        } else {
            Some(
                reg
                .enabled_servers_for(&client.profile)
                .iter()
                .map(|server| sanitize_segment(&server.id))
                .collect(),
            )
        };
        let audit_label = Some(if client.label.trim().is_empty() {
            client.id.clone()
        } else {
            client.label.clone()
        });
        return Some((
            allowed.clone(),
            HttpCaller {
                audit_label,
                session_owner: McpSessionOwner {
                    identity: format!("client:{}", client.id),
                    scope: owner_scope(&allowed),
                },
            },
        ));
    }

    // No auth configured at all: reachable only when startup explicitly allowed
    // `--insecure-loopback`; keep the request resolver usable for that escape hatch.
    if allow_insecure_open && env_token.is_none() && reg.http_clients.is_empty() {
        return Some((
            None,
            HttpCaller {
                audit_label: None,
                session_owner: McpSessionOwner {
                    identity: "open".to_string(),
                    scope: None,
                },
            },
        ));
    }

    None
}

/// Test-facing projection of the combined resolver's authorization/scope result.
#[cfg(test)]
fn resolve_http_scope(
    reg: &Registry,
    env_token: Option<&str>,
    provided: Option<&str>,
    allow_insecure_open: bool,
) -> Option<Option<std::collections::HashSet<String>>> {
    resolve_http_caller(reg, env_token, provided, allow_insecure_open).map(|(allowed, _)| allowed)
}

/// The audit label for a registered HTTP client's bearer: its `label`, or its `id`
/// when the label is blank. `None` when the token isn't a registered client (legacy
/// single-token, explicitly insecure loopback, or the local stdio app), so those calls stay
/// unattributed in the audit log rather than mislabeled. Pure, so it's unit-testable.
#[cfg(test)]
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

/// The outcome of a single dial to the approval broker. Separating "we never reached a
/// live broker" from "a broker answered" lets the caller retry a *stale* endpoint (the app
/// just restarted and rebound to a new port) without ever re-prompting a human who was
/// already asked.
enum BrokerAttempt {
    /// A broker received the request and answered (Approved / Denied / Timeout).
    Decided(approval::ApprovalDecision),
    /// We never handed the request to a live broker: no descriptor, connect refused, or the
    /// transport failed before the request went across. No human was asked, so a retry
    /// against a freshly-read descriptor is safe.
    Unreachable,
}

/// One dial to the broker described by `desc`. FAIL-CLOSED throughout: the arguments travel
/// over the socket and never touch disk. Transport is loopback TCP + token for now;
/// hardening to an OS-permissioned named-pipe / uds is a follow-up.
///
/// The key invariant: `Unreachable` is returned ONLY when the request never reached a
/// broker (so no human saw it). Once the request is written, any later failure - including
/// the read timeout that means "the human didn't answer" - is a `Decided(Timeout)`, so we
/// never retry in a way that could double-prompt.
fn try_decide_once(
    desc: Option<approval::EndpointDescriptor>,
    req: &mut approval::ApprovalRequest,
) -> BrokerAttempt {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    let Some(desc) = desc else { return BrokerAttempt::Unreachable };
    req.token = desc.token.clone();
    let Ok(mut stream) = TcpStream::connect(&desc.endpoint) else {
        return BrokerAttempt::Unreachable;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(approval::DEFAULT_TIMEOUT_SECS)));
    let Ok(line) = serde_json::to_string(req) else {
        // We connected but can't serialize our own request: not a reachability problem, so
        // don't spin on retry. Fail closed.
        return BrokerAttempt::Decided(approval::ApprovalDecision::Timeout);
    };
    if stream.write_all(line.as_bytes()).is_err() || stream.write_all(b"\n").is_err() {
        // The request never made it across, so no human was asked: safe to re-dial.
        return BrokerAttempt::Unreachable;
    }
    let _ = stream.flush();
    let mut resp = String::new();
    match BufReader::new(stream).read_line(&mut resp) {
        // Connected and the peer closed with no answer: not a healthy broker. No human was
        // shown a prompt (the broker's pre-prompt reject paths close silently), so re-dial.
        Ok(0) => BrokerAttempt::Unreachable,
        Ok(_) => {
            let t = resp.trim();
            if t.is_empty() {
                BrokerAttempt::Unreachable
            } else {
                // A parseable decision is authoritative; an unparseable line is fail-closed
                // as a Timeout (a real broker answered, so this is not a retry case).
                BrokerAttempt::Decided(
                    serde_json::from_str::<approval::ApprovalDecision>(t)
                        .unwrap_or(approval::ApprovalDecision::Timeout),
                )
            }
        }
        // A read error AFTER we sent the request is the "human didn't answer in time" path
        // (read timeout) or a mid-wait drop. Either way the broker had our request, so this
        // is a genuine no-decision Timeout - never retry (that would re-prompt).
        Err(_) => BrokerAttempt::Decided(approval::ApprovalDecision::Timeout),
    }
}

/// Ask the app broker for a human decision on `req`, reading the endpoint descriptor once.
/// Collapses an unreachable broker to the `Unreachable` decision (still fail-closed). Kept
/// as a thin, dependency-free entry point for unit tests; `request_human_decision` is the
/// production path with the self-healing retry.
fn decide_via_broker(
    desc: Option<approval::EndpointDescriptor>,
    req: &mut approval::ApprovalRequest,
) -> approval::ApprovalDecision {
    match try_decide_once(desc, req) {
        BrokerAttempt::Decided(d) => d,
        BrokerAttempt::Unreachable => approval::ApprovalDecision::Unreachable,
    }
}

/// Hold a gated tool call until a human decides via the Toolport app (or it fails closed).
///
/// If the first dial can't reach a live broker, re-read the descriptor and retry once: the
/// app may have just restarted and rebound to a new port, leaving the descriptor we first
/// read stale. This self-heals that race without ever failing open - two unreachable dials
/// return `Unreachable`, which is still a deny.
fn request_human_decision(mut req: approval::ApprovalRequest) -> approval::ApprovalDecision {
    match try_decide_once(read_endpoint_descriptor(), &mut req) {
        BrokerAttempt::Decided(d) => d,
        BrokerAttempt::Unreachable => match try_decide_once(read_endpoint_descriptor(), &mut req) {
            BrokerAttempt::Decided(d) => d,
            BrokerAttempt::Unreachable => {
                gtrace("approval broker unreachable after retry; failing closed (Unreachable)");
                approval::ApprovalDecision::Unreachable
            }
        },
    }
}

#[cfg(test)]
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
    handle_request_with_cancel(
        req, reg, router, cached, lazy, profile, guard, confirm, allowed, None, client,
    )
}

#[allow(clippy::too_many_arguments)]
fn handle_request_with_cancel(
    req: &Value,
    reg: &Registry,
    router: &Router,
    cached: &[Value],
    lazy: bool,
    profile: Option<&str>,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    allowed: Option<&std::collections::HashSet<String>>,
    cancel: Option<downstream::CancelContext>,
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
                    savings::per_server_tokens(catalog, |name| {
                        router.route_of(name).map(|(s, _)| s.to_string())
                    }),
                );
                gtrace(&format!(
                    "tools/list -> {} meta-tools (lazy discovery)",
                    tools.len()
                ));
                return Some(success(id, json!({ "tools": tools })));
            }
            // Grouped mode: the lazy meta-tools plus a per-server help_<server> browse
            // tool, so a weak model can pick a server by name instead of inventing a
            // search query. Scoped to the client's servers, same as full mode.
            if grouped_discovery() {
                let agg;
                let catalog: &[Value] = if cached.is_empty() {
                    agg = router.aggregated_tools();
                    &agg
                } else {
                    cached
                };
                let scoped = scope_tools(catalog, allowed, |n| {
                    router.route_of(n).map(|(s, _)| s.to_string())
                });
                let tools =
                    grouped_tool_defs(reg.allow_agent_control, reg.confirm_destructive, &scoped);
                // Savings vs. advertising the whole (scoped) catalog + status.
                let status = status_tool_def();
                let full_tokens = savings::estimate_tokens(&scoped)
                    + savings::estimate_tokens(std::slice::from_ref(&status));
                savings::record(
                    full_tokens,
                    savings::estimate_tokens(&tools),
                    scoped.len() as u64 + 1,
                    savings::per_server_tokens(&scoped, |name| {
                        router.route_of(name).map(|(s, _)| s.to_string())
                    }),
                );
                gtrace(&format!(
                    "tools/list -> {} tools (grouped: {} server browse tools)",
                    tools.len(),
                    distinct_server_prefixes(&scoped).len()
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
            tools.extend(scope_tools(&catalog, allowed, |n| {
                router.route_of(n).map(|(s, _)| s.to_string())
            }));
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

            // Grouped mode: a per-server browse tool `help_<server>` is the enumerable
            // alternative to inventing a search query. Rewrite it into a server-scoped
            // toolport_search_tools so it reuses the exact ranking/listing path, and
            // dispatch of the chosen tool still goes through toolport_call_tool below.
            if grouped_discovery() {
                if let Some(prefix) = grouped_help_target(&name) {
                    let q = arguments
                        .get("query")
                        .cloned()
                        .unwrap_or_else(|| json!(""));
                    let server = prefix.to_string();
                    name = "toolport_search_tools".to_string();
                    arguments = json!({ "query": q, "server": server });
                }
            }

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
                match confirm.take(token, client) {
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
                if let Err(message) = validate_search_query(query) {
                    return Some(success(
                        id,
                        json!({
                            "content": [{ "type": "text", "text": message }],
                            "isError": true
                        }),
                    ));
                }
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
                let scoped = scope_tools(base, allowed, |n| {
                    router.route_of(n).map(|(s, _)| s.to_string())
                });
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
            if reg.human_approval_effective() && !confirmed {
                // Resolve destructiveness robustly: cache, then live router, else
                // fail-closed (an unknown tool must not skip the human gate).
                let is_dest = tool_is_destructive_fail_closed(name, cached, router);
                // Untrusted provenance = the same shared/registry signal the SSRF guard
                // uses. Match on the REAL server id from `route_of` (not the sanitized
                // prefix): two ids that sanitize alike would otherwise read the wrong
                // server's trust flag and could skip this gate.
                let untrusted = reg
                    .servers
                    .iter()
                    .find(|s| s.id == server_id)
                    .map(|s| matches!(s.source.as_deref(), Some("shared") | Some("registry")))
                    .unwrap_or(false);
                if let Some(reason) = approval::gate_reason(true, is_dest, untrusted) {
                    let t0 = std::time::Instant::now();
                    let decision = request_human_decision(approval::ApprovalRequest {
                        token: String::new(),
                        id: new_correlation_id(),
                        client: client.map(str::to_string),
                        server: srv.to_string(),
                        tool: tool.to_string(),
                        reason,
                        arguments: arguments.clone(),
                        tool_fingerprint: tool_fingerprint_for(name, cached, router),
                    });
                    let held_ms = t0.elapsed().as_millis() as u64;
                    if !decision.is_approved() {
                        let why = match decision {
                            approval::ApprovalDecision::Denied => "was denied by a human reviewer",
                            approval::ApprovalDecision::Unreachable => {
                                "could not be approved because the Toolport approval service was \
                                 unreachable (is the Toolport app running?)"
                            }
                            _ => "was not approved in time (the Toolport app may be closed)",
                        };
                        // Governance audit: the gate reason and which non-approval outcome
                        // (denied / no-response / unreachable), plus a content hash of the
                        // exact call - never the raw args. Replaces the flat record_held so
                        // the three failure modes are no longer indistinguishable in the log.
                        let reason_str = match reason {
                            approval::ApprovalReason::Destructive => "destructive",
                            approval::ApprovalReason::UntrustedSource => "untrusted_source",
                            approval::ApprovalReason::DestructiveAndUntrusted => {
                                "destructive_and_untrusted"
                            }
                        };
                        let decision_str = match decision {
                            approval::ApprovalDecision::Denied => "denied",
                            approval::ApprovalDecision::Unreachable => "unreachable",
                            _ => "no_response",
                        };
                        audit::record_decision(
                            srv, tool, client, reason_str, decision_str, &arguments, Some(held_ms),
                        );
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
                    let token = confirm.store(name.to_string(), arguments.clone(), client);
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
            match router.route_call_with_cancel(name, arguments, cancel.clone()) {
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
                    if reg.content_defense_effective() {
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
            match router.read_resource_with_cancel(uri, cancel.clone()) {
                Ok(mut result) => {
                    // Content defense: a resource is as attacker-controllable as a tool
                    // result, so scan it for injection and label any flagged text as data.
                    if reg.content_defense_effective() {
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
            match router.get_prompt_with_cancel(name, arguments, cancel.clone()) {
                Ok(mut result) => {
                    // Content defense: a prompt's messages are attacker-controllable too;
                    // scan for injection and label any flagged text as data.
                    if reg.content_defense_effective() {
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
    dirty: &Arc<AtomicU8>,
    server_handler: ServerRequestHandler,
    // The upstream client's project root for the ${ROOT} cwd token (issue #239),
    // already decoded to a filesystem path. `None` in HTTP mode and before the
    // client's roots are known; `${ROOT}` servers then fall back to the gateway cwd.
    root: Option<&str>,
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
        deny_destructive: reg.deny_destructive_effective(),
        // Hide already-quarantined tools from the first build (the set persists across
        // restarts); newly detected drift is added during the integrity check below.
        quarantined: if reg.quarantine_on_drift_effective() {
            integrity::quarantined(profile)
        } else {
            Default::default()
        },
    };

    // Connect concurrently so total time is the slowest server, not the sum. Each
    // thread hands back the server spec + dirty flag alongside the connection so we can
    // build a reconnect factory (used to re-spawn it if it dies mid-session).
    // Owned copy so each connect thread and each reconnect factory (both 'static)
    // can carry the root without borrowing.
    let root_owned = root.map(str::to_owned);
    let handles: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let dirty = Arc::clone(dirty);
            let handler = Arc::clone(&server_handler);
            let root_t = root_owned.clone();
            std::thread::spawn(move || {
                let ds = connect_one(&server, &dirty, handler, root_t.as_deref());
                (server, dirty, ds)
            })
        })
        .collect();

    let mut router = Router::with_policy(policy);
    // Per-tool exposure overrides (rename / re-describe) must be set before indexing,
    // since they're applied as each server's tools are added.
    router.set_overrides(reg.tool_overrides.clone());
    for handle in handles {
        if let Ok((server, dirty, Some(ds))) = handle.join() {
            // The same `connect_one` used for the initial spawn is the reconnect
            // factory, so a re-spawn re-injects keychain secrets and re-handshakes
            // exactly like a fresh connect.
            let handler = Arc::clone(&server_handler);
            let root_c = root_owned.clone();
            let reconnect: Reconnect =
                Box::new(move || connect_one(&server, &dirty, Arc::clone(&handler), root_c.as_deref()));
            router.add_with_reconnect(ds, Some(reconnect));
        }
    }
    router
}

/// Connect a single enabled server (stdio with keychain secret injection, or
/// remote with refresh-aware auth). Returns None on failure.
fn connect_one(
    server: &ServerEntry,
    dirty: &Arc<AtomicU8>,
    server_handler: ServerRequestHandler,
    root: Option<&str>,
) -> Option<DownstreamServer> {
    let result = if let Some(command) = &server.command {
        let mut env: Vec<(String, String)> = Vec::new();
        for e in &server.env {
            if let Some(v) = &e.value {
                env.push((e.key.clone(), v.clone()));
            } else if e.secret {
                match secrets::get_secret_result(&server.id, &e.key) {
                    Ok(Some(v)) => env.push((e.key.clone(), v)),
                    Ok(None) => eprintln!(
                        "toolport: '{}' needs secret '{}' but none is vaulted \
                         (set env {}, {}, secrets.enc, or the OS keychain)",
                        server.id,
                        e.key,
                        format_args!("CONDUIT_SECRET_{}", e.key),
                        e.key
                    ),
                    Err(err) => eprintln!(
                        "toolport: '{}' could not read secret '{}': {err}",
                        server.id, e.key
                    ),
                }
            }
        }
        // Resolve the ${ROOT} token against the client's project root (issue #239)
        // before spawning. `None` (no ${ROOT}, or ${ROOT} with no known root) means
        // inherit the gateway cwd - the pre-#239 fallback.
        let resolved_cwd = server
            .cwd
            .as_deref()
            .and_then(|c| downstream::resolve_root_token(c, root));
        match StdioTransport::spawn_watched(
            command,
            &server.args,
            &env,
            resolved_cwd.as_deref(),
            Arc::clone(dirty),
        ) {
            Ok(mut t) => {
                t.set_server_request_handler(server_handler);
                DownstreamServer::connect(server.id.clone(), Box::new(t))
            }
            Err(e) => Err(e),
        }
    } else if server.url.is_some() {
        remote::connect_remote_with_handler(server, Some(Arc::clone(&server_handler)))
    } else {
        Err("no command or url".to_string())
    };

    match result {
        Ok(mut ds) => {
            // Only the gateway needs resources/prompts (to proxy them); fetch
            // them here, off the health-probe path.
            ds.load_resources_prompts();
            let msg = format!("connected '{}' ({} tools)", server.id, ds.tools.len());
            eprintln!("toolport: {msg}");
            glog(&msg);
            Some(ds)
        }
        Err(e) => {
            let msg = format!("'{}' failed: {e}", server.id);
            eprintln!("toolport: {msg}");
            glog(&msg);
            None
        }
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn notify_tools_changed(stdout: &Arc<Mutex<std::io::Stdout>>) {
    notify_list_changed(stdout, "notifications/tools/list_changed");
}

/// Emit a bare JSON-RPC `list_changed` notification to the client so it re-fetches
/// the named list. Used for resources/prompts (which have no persisted cache) and,
/// via `notify_tools_changed`, for tools.
fn notify_list_changed(stdout: &Arc<Mutex<std::io::Stdout>>, method: &str) {
    let mut out = stdout
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = writeln!(out, "{}", json!({ "jsonrpc": "2.0", "method": method }));
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
        (r.integrity_check, r.quarantine_on_drift_effective())
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
        eprintln!("toolport: SECURITY tool drift ({change}) {tool}");
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
/// Bump when the shape/derivation of cached tools changes (new sanitizing, projection,
/// schema handling), so a stale on-disk cache from an older build is discarded and
/// rebuilt rather than served verbatim until the next server toggle.
const TOOL_CACHE_VERSION: u64 = 1;

fn load_tool_cache(profile: Option<&str>) -> Vec<Value> {
    tool_cache_path(profile)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        // Only honor a cache written by this catalog version; a bare-array (pre-version)
        // or older-version file has no matching tag and is dropped, forcing a rebuild.
        .filter(|v| v.get("version").and_then(Value::as_u64) == Some(TOOL_CACHE_VERSION))
        .and_then(|v| v.get("tools").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

fn save_tool_cache(tools: &[Value], profile: Option<&str>) {
    if let Some(path) = tool_cache_path(profile) {
        let wrapped = json!({ "version": TOOL_CACHE_VERSION, "tools": tools });
        if let Ok(s) = serde_json::to_string(&wrapped) {
            // Atomic + unique temp: several gateways share this cache file, so a
            // torn or interleaved write would leave an inconsistent catalog.
            let _ = registry::atomic_write(&path, &s);
        }
    }
}

/// Resolve this client's live profile from `registry.client_scopes[client_id]`
/// (kept current by `watch_registry` on every reload). Three cases:
/// - a non-empty entry: this client is scoped to that named profile;
/// - an empty-string entry: this client is *explicitly* unscoped (follow the
///   active profile now), so return `None` and do NOT fall back to the boot env
///   var - that's what makes a live re-scope to "all servers" take effect
///   without restarting the client (see `Registry::set_client_unscoped`);
/// - no entry at all: fall back to the `CONDUIT_PROFILE` this process started
///   with (e.g. an install from before `CONDUIT_CLIENT_ID` existed).
/// Callers with no `client_id` at all (the HTTP bridge, or a pre-CLIENT_ID
/// install) always fall through to `env_profile` unchanged. Note current
/// installs - scoped or unscoped - always write `CONDUIT_CLIENT_ID`, so an
/// unscoped one lands in the empty-string case above, not here.
fn resolve_live_profile(
    reg: &Registry,
    client_id: Option<&str>,
    env_profile: &Option<String>,
) -> Option<String> {
    match client_id.and_then(|id| reg.client_scopes.get(id)) {
        Some(p) if p.trim().is_empty() => None,
        Some(p) => Some(p.clone()),
        None => env_profile.clone(),
    }
}

/// The registry as a JSON value with the `team` block removed. The gateway builds the
/// router ONLY from servers/profiles/policy flags and never reads the `team` block (its
/// sync version/etag, role, member name, and per-day usage watermarks). The desktop team
/// sync loop rewrites those fields on a timer, so keying a rebuild off the raw file made
/// every routine sync re-spawn every stdio server — the process leak that exhausted a
/// user's RAM. Comparing this slice lets the watcher rebuild only when something the router
/// actually depends on changed. Returned as a serde_json::Value and compared with `==`
/// (order-independent) so HashMap key-order jitter across a load can't look like a change.
fn router_relevant(reg: &Registry) -> Value {
    let mut v = serde_json::to_value(reg).unwrap_or(Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.remove("team");
    }
    v
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
    profile: Arc<Mutex<Option<String>>>,
    client_id: Option<String>,
    env_profile: Option<String>,
    http_mode: bool,
    downstream_dirty: Arc<AtomicU8>,
    server_handler: ServerRequestHandler,
    // Shared ${ROOT} path (issue #239) so a registry-change rebuild keeps placing
    // ${ROOT} servers in the client's project root instead of resetting to fallback.
    client_root: Arc<Mutex<Option<String>>>,
) {
    eprintln!("toolport: watching registry at {}", path.display());
    let mut last = mtime(&path);
    // Router-relevant slice (everything except the `team` block) as of the initial build,
    // so a team-metadata-only rewrite from the desktop sync loop doesn't force a rebuild.
    let mut last_relevant = router_relevant(
        &registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    loop {
        std::thread::sleep(Duration::from_millis(1000));
        // A live downstream server that changed its own tool set (sent
        // tools/list_changed) sets this. Swap before acting so a notification
        // arriving mid-refresh is caught on the next tick rather than lost.
        let downstream_changed = downstream_dirty.swap(0, Ordering::SeqCst);
        let current = mtime(&path);
        let file_changed = current != last;
        if !file_changed && downstream_changed == 0 {
            continue;
        }

        if file_changed {
            // The registry changed: servers may have been added, removed, or
            // reconfigured, so reload and rebuild from scratch. This re-connects
            // everything, which also subsumes any pending downstream change.
            eprintln!("toolport: registry file changed on disk");
            // Don't advance `last` until a successful load, so a half-written file
            // (caught mid-save) is retried on the next tick instead of skipped.
            let new_reg = match registry::load_from(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("toolport: reload failed (will retry): {e}");
                    continue;
                }
            };
            last = current;
            // Refresh the live discovery mode from the freshly-loaded registry: a per-client
            // override edit (`client_discovery`) may be the only change, and it isn't
            // router-relevant, so resolve it here before the rebuild fast-path can `continue`.
            let new_mode = discovery_mode_for(&new_reg, client_id.as_deref());
            if new_mode != discovery_mode() {
                eprintln!("toolport: discovery mode -> {}", new_mode.as_str());
            }
            set_discovery_mode(new_mode);
            // A team-metadata-only rewrite (usage watermark, sync version/etag, role) from
            // the desktop sync loop changes nothing the router depends on. Update the stored
            // copy but skip the rebuild, so a routine sync never re-spawns every stdio server
            // (the leak that exhausted a user's RAM). Still rebuild when a downstream server
            // also signaled a change, so that path is never dropped.
            let new_relevant = router_relevant(&new_reg);
            if downstream_changed == 0 && new_relevant == last_relevant {
                *registry
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = new_reg;
                eprintln!("toolport: registry changed (team metadata only); skipped rebuild");
                continue;
            }
            last_relevant = new_relevant;
            let resolved = resolve_live_profile(&new_reg, client_id.as_deref(), &env_profile);
            // Capture the profile we were serving before this reload so the log can
            // show the transition - the single most useful line when diagnosing
            // "why can't this client see server X": it pins down which profile is
            // actually in effect and how many servers it resolved to.
            let previous = {
                let mut guard = profile
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let prev = guard.clone();
                *guard = resolved.clone();
                prev
            };
            // Build the new router (spawns processes) before taking locks.
            let root = client_root
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let new_router = build_router(
                &new_reg,
                resolved.as_deref(),
                http_mode,
                &downstream_dirty,
                Arc::clone(&server_handler),
                root.as_deref(),
            );
            let server_count = new_router.server_count();
            let tools = new_router.aggregated_tools();
            *registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = new_reg;
            *router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_router);
            let tools = requarantine_if_needed(&registry, &router, tools, resolved.as_deref());
            persist_and_emit(&tools, &cached_tools, &stdout, resolved.as_deref());
            let fmt_profile = |p: &Option<String>| match p {
                Some(name) => format!("'{name}'"),
                None => "(active profile / unscoped)".to_string(),
            };
            eprintln!(
                "toolport: registry changed{} -> profile {} (was {}); {} server(s), {} tools; sent tools/list_changed",
                client_id
                    .as_deref()
                    .map(|c| format!(" [client={c}]"))
                    .unwrap_or_default(),
                fmt_profile(&resolved),
                fmt_profile(&previous),
                server_count,
                tools.len(),
            );
        } else {
            let resolved = profile
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            // One or more live servers announced a list change. Re-query only the
            // affected list(s) in place rather than re-spawning: a runtime or
            // session-scoped change (the usual reason a server sends this) would be
            // lost by a fresh process that never saw it. Each kind forwards its own
            // notification so the client re-fetches exactly what changed. (make_mut
            // forks the router only if a request still holds the prior Arc, keeping
            // live connections.)
            // Re-query the affected list(s) WITHOUT holding the top-level router lock
            // across the blocking downstream `list` call. Each refresh_* iterates the
            // servers doing synchronous tools/list I/O bounded by the connect timeout;
            // holding the router lock across it (as the old make_mut path did) wedges
            // every concurrent request - in HTTP-bridge mode, every client - for up to
            // num_servers x connect-timeout while one slow downstream answers. Instead
            // clone the router off-lock (the Vec<Arc<ServerSlot>> shares the same live
            // connections, so only the cached metadata is copied), refresh the clone,
            // then swap it in under a brief lock. Mirrors the full-rebuild branch above.
            if downstream_changed & downstream::change::TOOLS != 0 {
                let mut next = {
                    let guard = router
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (**guard).clone()
                };
                next.refresh_tools();
                let tools = next.aggregated_tools();
                *router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
                let tools = requarantine_if_needed(&registry, &router, tools, resolved.as_deref());
                persist_and_emit(&tools, &cached_tools, &stdout, resolved.as_deref());
                eprintln!("toolport: downstream tools/list_changed, refreshed + sent");
            }
            if downstream_changed & downstream::change::RESOURCES != 0 {
                let mut next = {
                    let guard = router
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (**guard).clone()
                };
                next.refresh_resources();
                *router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
                notify_list_changed(&stdout, "notifications/resources/list_changed");
                eprintln!("toolport: downstream resources/list_changed, refreshed + sent");
            }
            if downstream_changed & downstream::change::PROMPTS != 0 {
                let mut next = {
                    let guard = router
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (**guard).clone()
                };
                next.refresh_prompts();
                *router
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
                notify_list_changed(&stdout, "notifications/prompts/list_changed");
                eprintln!("toolport: downstream prompts/list_changed, refreshed + sent");
            }
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
    downstream_dirty: Arc<AtomicU8>,
    /// Serializes the self-heal rebuild so a startup burst of concurrent tools/call
    /// workers that all observe an empty router don't each spawn the full server set
    /// (single-flight). The winner rebuilds; the others block here, then re-check
    /// server_count under the router lock and skip.
    rebuild_lock: Arc<Mutex<()>>,
    lazy: bool,
    /// Live-updated: the registry watcher keeps this in sync with
    /// `registry.client_scopes` for a scoped client, so a profile switch reaches
    /// every reader here without a gateway restart.
    profile: Arc<Mutex<Option<String>>>,
    /// True when this process is the HTTP/OpenAPI bridge (vs a stdio client's
    /// gateway). The bridge connects the union of all registered clients' servers.
    http: bool,
    /// Streamable-HTTP MCP sessions (`Mcp-Session-Id` → state). Only used when
    /// `http` is true; empty for stdio gateways.
    mcp_sessions: Arc<Mutex<HashMap<String, Arc<McpSession>>>>,
    /// Client-declared upstream capabilities (stdio gateway). Per-session copy on
    /// [`McpSession`] for HTTP MCP clients.
    client_upstream: Arc<Mutex<ClientUpstreamCaps>>,
    /// The upstream client's project root path for the `${ROOT}` cwd token
    /// (issue #239), decoded from its first declared root via `file_uri_to_path`.
    /// `None` until roots are fetched, or if the client declares none; `${ROOT}`
    /// servers fall back to the gateway cwd until it is set. stdio-only.
    client_root: Arc<Mutex<Option<String>>>,
    /// Forward server-initiated JSON-RPC to the stdio upstream client.
    stdio_upstream: Arc<StdioUpstream>,
    /// Answers downstream server-initiated RPC (roots, sampling, elicitation).
    server_handler: ServerRequestHandler,
}

/// Client capabilities the upstream MCP client declared at `initialize`.
#[derive(Clone, Default)]
struct ClientUpstreamCaps {
    roots: ClientRootsState,
    sampling: bool,
    elicitation: bool,
}

/// Roots the upstream MCP client exposed at `initialize`.
#[derive(Clone, Default)]
struct ClientRootsState {
    supported: bool,
    list_changed: bool,
    roots: Vec<Value>,
}

/// Pending upstream JSON-RPC over stdio (gateway → client request, client → response).
struct StdioUpstream {
    stdout: Arc<Mutex<std::io::Stdout>>,
    pending: Arc<Mutex<HashMap<String, std::sync::mpsc::Sender<Value>>>>,
    next_id: AtomicI64,
}

impl StdioUpstream {
    fn new(stdout: Arc<Mutex<std::io::Stdout>>) -> Self {
        Self {
            stdout,
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicI64::new(1),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.call_timeout(method, params, upstream_rpc_timeout(method))
    }

    fn call_timeout(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let id_key = id.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id_key.clone(), tx);
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let send = {
            let mut out = self
                .stdout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            writeln!(out, "{req}")
                .and_then(|_| out.flush())
                .map_err(|e| e.to_string())
        };
        if let Err(e) = send {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id_key);
            return Err(e);
        }
        let resp = match rx.recv_timeout(timeout) {
            Ok(v) => v,
            Err(_) => {
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id_key);
                return Err("upstream client did not answer".to_string());
            }
        };
        if let Some(err) = resp.get("error") {
            return Err(err.to_string());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    /// If `msg` answers a pending upstream call, deliver it and return true.
    fn try_deliver(&self, msg: &Value) -> bool {
        let Some(id) = msg.get("id").filter(|id| !id.is_null()).and_then(rpc_id_key) else {
            return false;
        };
        let tx = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(msg.clone());
            true
        } else {
            false
        }
    }
}

thread_local! {
    static ACTIVE_MCP_SESSION: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Per-session state for streamable-HTTP MCP (POST responses + GET listen stream).
struct McpSession {
    /// The authenticated HTTP identity and effective scope that initialized this
    /// session. `None` is used only by direct unit-test callers.
    owner: Option<McpSessionOwner>,
    last_seen: Mutex<Instant>,
    outbound: Mutex<VecDeque<McpOutboundMessage>>,
    closed: AtomicBool,
    listener_active: AtomicBool,
    wait: (Mutex<()>, Condvar),
    client_upstream: Mutex<ClientUpstreamCaps>,
    upstream_pending: Mutex<HashMap<String, std::sync::mpsc::Sender<Value>>>,
    next_upstream_id: AtomicI64,
}

struct McpOutboundMessage {
    json: String,
    /// Present for server-to-client JSON-RPC requests so a timed-out request can
    /// be removed before a later SSE listener accidentally receives it.
    request_id: Option<String>,
}

impl McpSession {
    fn new(owner: Option<McpSessionOwner>) -> Self {
        Self {
            owner,
            last_seen: Mutex::new(Instant::now()),
            outbound: Mutex::new(VecDeque::new()),
            closed: AtomicBool::new(false),
            listener_active: AtomicBool::new(false),
            wait: (Mutex::new(()), Condvar::new()),
            client_upstream: Mutex::new(ClientUpstreamCaps::default()),
            upstream_pending: Mutex::new(HashMap::new()),
            next_upstream_id: AtomicI64::new(1),
        }
    }

    fn upstream_call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.upstream_call_timeout(method, params, upstream_rpc_timeout(method))
    }

    fn upstream_call_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let id = self.next_upstream_id.fetch_add(1, Ordering::Relaxed);
        let id_key = id.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        self.upstream_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id_key.clone(), tx);
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let json_str = match serde_json::to_string(&req) {
            Ok(s) => s,
            Err(e) => {
                self.upstream_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id_key);
                return Err(e.to_string());
            }
        };
        if !self.push_message(json_str, Some(id_key.clone())) {
            self.upstream_pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id_key);
            return Err("upstream MCP client outbound queue is full".to_string());
        }
        let resp = match rx.recv_timeout(timeout) {
            Ok(v) => v,
            Err(_) => {
                self.upstream_pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&id_key);
                self.remove_queued_request(&id_key);
                return Err("upstream MCP client did not answer".to_string());
            }
        };
        if let Some(err) = resp.get("error") {
            return Err(err.to_string());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn try_deliver_upstream(&self, msg: &Value) -> bool {
        let Some(id) = msg.get("id").filter(|id| !id.is_null()).and_then(rpc_id_key) else {
            return false;
        };
        let tx = self
            .upstream_pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        if let Some(tx) = tx {
            let _ = tx.send(msg.clone());
            true
        } else {
            false
        }
    }

    fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = Instant::now();
        }
    }

    fn is_expired(&self) -> bool {
        self.last_seen
            .lock()
            .map(|t| t.elapsed() >= MCP_SESSION_TTL)
            .unwrap_or(true)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.wait.1.notify_all();
    }

    fn try_begin_listen(&self) -> bool {
        !self.listener_active.swap(true, Ordering::SeqCst)
    }

    fn end_listen(&self) {
        self.listener_active.store(false, Ordering::SeqCst);
        self.wait.1.notify_all();
    }

    fn push_message(&self, json: String, request_id: Option<String>) -> bool {
        let mut outbound = self
            .outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if outbound.len() >= MCP_SESSION_OUTBOUND_MAX {
            return false;
        }
        outbound.push_back(McpOutboundMessage { json, request_id });
        drop(outbound);
        self.wait.1.notify_all();
        true
    }

    fn remove_queued_request(&self, request_id: &str) {
        self.outbound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|msg| msg.request_id.as_deref() != Some(request_id));
    }

    fn next_sse_chunk(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut guard = self
            .wait
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if self.closed.load(Ordering::SeqCst) || self.is_expired() {
                return None;
            }
            if let Some(msg) = self
                .outbound
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
            {
                return Some(mcp_sse_body(&msg.json).into_bytes());
            }
            let result = self
                .wait
                .1
                .wait_timeout(guard, timeout)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard = result.0;
            if result.1.timed_out() {
                return Some(b": keepalive\n\n".to_vec());
            }
        }
    }
}

/// Blocking `Read` adapter for a long-lived `GET /mcp` SSE listen stream.
struct McpSseReader {
    session: Arc<McpSession>,
    buf: Vec<u8>,
    pos: usize,
}

impl McpSseReader {
    fn new(session: Arc<McpSession>) -> Self {
        Self {
            session,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for McpSseReader {
    fn read(&mut self, dest: &mut [u8]) -> std::io::Result<usize> {
        if dest.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.buf.len() {
                let n = dest.len().min(self.buf.len() - self.pos);
                dest[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.session.next_sse_chunk(MCP_SSE_KEEPALIVE) {
                Some(chunk) => {
                    self.buf = chunk;
                    self.pos = 0;
                }
                None => return Ok(0),
            }
        }
    }
}

impl Drop for McpSseReader {
    fn drop(&mut self) {
        self.session.end_listen();
    }
}

/// How long an idle MCP streamable-HTTP session stays valid before a request
/// with that id gets 404 (client must re-initialize).
const MCP_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound on concurrent MCP sessions to avoid unbounded memory growth.
const MCP_SESSION_MAX: usize = 4096;
/// Maximum undelivered server-to-client messages retained by one MCP session.
const MCP_SESSION_OUTBOUND_MAX: usize = 256;
/// SSE comment frames on idle `GET /mcp` listen streams.
const MCP_SSE_KEEPALIVE: Duration = Duration::from_secs(30);

/// Cryptographically random session id (visible ASCII, per MCP streamable-HTTP).
fn new_mcp_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("CSPRNG unavailable");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mint a new MCP session after TTL cleanup. Returns 503 when at capacity.
fn mint_mcp_session(
    state: &GatewayState,
    owner: Option<&McpSessionOwner>,
) -> Result<String, HttpOut> {
    let sid = new_mcp_session_id();
    let session = Arc::new(McpSession::new(owner.cloned()));
    let mut sessions = state
        .mcp_sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    sessions.retain(|_, s| !s.is_expired() && !s.closed.load(Ordering::SeqCst));
    if sessions.len() >= MCP_SESSION_MAX {
        return Err(HttpOut::json_err(503, "too many MCP sessions; retry later"));
    }
    sessions.insert(sid.clone(), Arc::clone(&session));
    Ok(sid)
}

/// Queue a server→client JSON-RPC message on an HTTP MCP session (#167 prep).
fn mcp_push_server_message(state: &GatewayState, session_id: &str, msg: &Value) -> bool {
    let Ok(json) = serde_json::to_string(msg) else {
        return false;
    };
    let sessions = state
        .mcp_sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(sess) = sessions.get(session_id) {
        let queued = sess.push_message(json, request_id_key(msg));
        if !queued {
            eprintln!("toolport: MCP session outbound queue full; server message dropped");
        }
        queued
    } else {
        false
    }
}

/// True when `id` is a non-empty visible-ASCII session id (0x21..=0x7E).
fn valid_mcp_session_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| (0x21..=0x7E).contains(&b)) && id.len() <= 128
}

fn rpc_id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn request_id_key(req: &Value) -> Option<String> {
    req.get("id").filter(|id| !id.is_null()).and_then(rpc_id_key)
}

fn cancellation_request_id(req: &Value) -> Option<String> {
    if req.get("method").and_then(|m| m.as_str()) != Some("notifications/cancelled") {
        return None;
    }
    req.get("params")
        .and_then(|p| p.get("requestId"))
        .and_then(rpc_id_key)
}

fn cancellation_reason(req: &Value) -> Option<&str> {
    req.get("params")
        .and_then(|p| p.get("reason"))
        .and_then(|r| r.as_str())
}

fn capture_client_upstream_from_init(state: &mut ClientUpstreamCaps, params: Option<&Value>) {
    *state = ClientUpstreamCaps::default();
    let Some(params) = params else {
        return;
    };
    let caps = params.get("capabilities");
    let roots_cap = caps.and_then(|c| c.get("roots"));
    state.roots.supported = roots_cap.is_some();
    state.roots.list_changed = roots_cap
        .and_then(|r| r.get("listChanged"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(roots) = params
        .get("roots")
        .and_then(|r| r.get("roots"))
        .and_then(|a| a.as_array())
    {
        state.roots.roots = roots.clone();
    }
    state.sampling = caps.and_then(|c| c.get("sampling")).is_some();
    state.elicitation = caps.and_then(|c| c.get("elicitation")).is_some();
}

const UPSTREAM_RPC_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(120);

fn upstream_rpc_timeout(method: &str) -> Duration {
    match method {
        "sampling/createMessage" | "elicitation/create" => UPSTREAM_INTERACTIVE_TIMEOUT,
        _ => UPSTREAM_RPC_TIMEOUT,
    }
}

fn client_supports_server_rpc(caps: &ClientUpstreamCaps, method: &str) -> bool {
    match method {
        "roots/list" => caps.roots.supported,
        "sampling/createMessage" => caps.sampling,
        "elicitation/create" => caps.elicitation,
        _ => false,
    }
}

fn upstream_rpc_params(method: &str, req: &Value) -> Value {
    match method {
        "roots/list" => json!({}),
        _ => req.get("params").cloned().unwrap_or_else(|| json!({})),
    }
}

fn upstream_json_rpc_response(id: Value, result: Result<Value, String>) -> Value {
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(message) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32603, "message": message }
        }),
    }
}

fn upstream_client_unsupported(id: Value, method: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32601,
            "message": format!("upstream client does not support {method}")
        }
    })
}

fn make_server_request_handler(
    client_upstream: Arc<Mutex<ClientUpstreamCaps>>,
    stdio_upstream: Arc<StdioUpstream>,
    mcp_sessions: Arc<Mutex<HashMap<String, Arc<McpSession>>>>,
    http: bool,
) -> ServerRequestHandler {
    Arc::new(move |req| {
        let method = req.get("method").and_then(|m| m.as_str())?;
        if !matches!(
            method,
            "roots/list" | "sampling/createMessage" | "elicitation/create"
        ) {
            return None;
        }
        let id = req.get("id")?.clone();
        let params = upstream_rpc_params(method, req);
        let timeout = upstream_rpc_timeout(method);
        let result = if http {
            let sid = ACTIVE_MCP_SESSION.with(|cell| cell.borrow().clone())?;
            let session = {
                let sessions = mcp_sessions.lock().ok()?;
                sessions.get(&sid).cloned()?
            };
            let supported = session
                .client_upstream
                .lock()
                .map(|caps| client_supports_server_rpc(&caps, method))
                .unwrap_or(false);
            if !supported {
                return Some(upstream_client_unsupported(id, method));
            }
            session.upstream_call_timeout(method, params, timeout)
        } else {
            let supported = client_upstream
                .lock()
                .map(|caps| client_supports_server_rpc(&caps, method))
                .unwrap_or(false);
            if !supported {
                return Some(upstream_client_unsupported(id, method));
            }
            stdio_upstream.call_timeout(method, params, timeout)
        };
        Some(upstream_json_rpc_response(id, result))
    })
}

/// Read the current resolved client project root for the `${ROOT}` cwd token.
fn current_client_root(state: &GatewayState) -> Option<String> {
    state
        .client_root
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// True when the active profile has any enabled server whose cwd uses `${ROOT}`,
/// so we only rebuild for a roots change when it can actually matter (issue #239).
fn profile_has_root_server(state: &GatewayState) -> bool {
    let profile = state
        .profile
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let reg = state
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let enabled = match profile.as_deref() {
        Some(p) => reg.enabled_servers_for(p),
        None => reg.enabled_servers(),
    };
    enabled
        .into_iter()
        .any(|s| s.cwd.as_deref().is_some_and(|c| c.contains("${ROOT}")))
}

/// Rebuild the router with the current `${ROOT}` value and swap it in, mirroring
/// the registry-watcher rebuild. Guarded by `rebuild_lock` so it single-flights
/// against the self-heal path. stdio-only (issue #239).
fn rebuild_router_for_root(state: &GatewayState) {
    let _rebuild = state
        .rebuild_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reg = state
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let profile = state
        .profile
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let root = current_client_root(state);
    let new_router = build_router(
        &reg,
        profile.as_deref(),
        state.http,
        &state.downstream_dirty,
        Arc::clone(&state.server_handler),
        root.as_deref(),
    );
    let tools = new_router.aggregated_tools();
    *state
        .router
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(new_router);
    let tools = requarantine_if_needed(&state.registry, &state.router, tools, profile.as_deref());
    persist_and_emit(&tools, &state.cached_tools, &state.stdout, profile.as_deref());
    glog(&format!("toolport: ${{ROOT}} rebuild (root={root:?}, {} tools)", tools.len()));
}

/// Fetch the upstream client's roots over stdio, update the shared `${ROOT}` path,
/// and rebuild the router when it changed and a `${ROOT}` server exists. Runs on
/// its own thread so it never blocks the initialize response or the request loop.
/// No-op in HTTP mode (issue #239 is stdio-only). Called after `initialize` and on
/// `notifications/roots/list_changed`.
fn refresh_client_root(state: &GatewayState) {
    if state.http {
        return;
    }
    let supported = state
        .client_upstream
        .lock()
        .map(|c| c.roots.supported)
        .unwrap_or(false);
    let new_root = if supported {
        match state.stdio_upstream.call("roots/list", json!({})) {
            Ok(result) => {
                let roots: Vec<Value> = result
                    .get("roots")
                    .and_then(|r| r.as_array())
                    .cloned()
                    .unwrap_or_default();
                // Keep the init-captured field in sync for any downstream consumer.
                if let Ok(mut caps) = state.client_upstream.lock() {
                    caps.roots.roots = roots.clone();
                }
                roots
                    .first()
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str())
                    .and_then(downstream::file_uri_to_path)
            }
            Err(e) => {
                glog(&format!("toolport: roots/list failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    let changed = {
        let mut cur = state
            .client_root
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *cur != new_root {
            *cur = new_root.clone();
            true
        } else {
            false
        }
    };
    // Only respawn when the resolved root actually changed and a ${ROOT} server is
    // present, so a client that has no root (or no ${ROOT} server) never churns.
    if changed && profile_has_root_server(state) {
        rebuild_router_for_root(state);
    }
}

fn handle_client_notification(state: &GatewayState, req: &Value) -> bool {
    match req.get("method").and_then(|m| m.as_str()) {
        Some("notifications/roots/list_changed") => {
            // Re-place ${ROOT} servers if the client's project root changed. Off the
            // request thread so the roots/list round-trip + rebuild don't block it.
            let st = state.clone();
            std::thread::spawn(move || refresh_client_root(&st));
            // Still tell downstream servers, for ones that consume roots themselves.
            let router = state
                .router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            router.notify_all_downstreams("notifications/roots/list_changed", json!({}));
            true
        }
        _ => false,
    }
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
    cancel: Option<downstream::CancelContext>,
    client: Option<&str>,
) -> Option<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let is_notification = !req.get("id").is_some_and(|id| !id.is_null());
    if is_notification {
        if handle_client_notification(state, req) {
            return None;
        }
    }

    if method == "initialize" && !state.http {
        if let Ok(mut caps) = state.client_upstream.lock() {
            capture_client_upstream_from_init(&mut caps, req.get("params"));
        }
        // Fetch the client's roots off-thread and place ${ROOT} servers once known,
        // so the initialize response is never blocked on the round-trip (issue #239).
        let st = state.clone();
        std::thread::spawn(move || refresh_client_root(&st));
    }

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

    // Snapshot the live-updated profile once: the watcher may swap it mid-request,
    // but a single request should see one consistent value throughout.
    let profile_snapshot = state
        .profile
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();

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
        // Single-flight: serialize the rebuild so a startup burst of concurrent
        // tools/call workers doesn't have each one spawn the full server set (and
        // then drop all but one, killing their just-spawned children). The winner
        // holds this lock while it rebuilds; the others block, then the double-check
        // below sees a non-empty router and skips.
        let _rebuild = state
            .rebuild_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let still_empty = state
            .router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .server_count()
            == 0;
        if still_empty {
            let reg = state
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let root = current_client_root(state);
            let built = build_router(
                &reg,
                profile_snapshot.as_deref(),
                state.http,
                &state.downstream_dirty,
                Arc::clone(&state.server_handler),
                root.as_deref(),
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
                    save_tool_cache(&tools, profile_snapshot.as_deref());
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
    handle_request_with_cancel(
        req,
        &reg,
        &router,
        &cache_snapshot,
        state.lazy,
        profile_snapshot.as_deref(),
        guard,
        confirm,
        allowed,
        cancel,
        client,
    )
}

fn write_stdio_response(
    stdout: &Arc<Mutex<std::io::Stdout>>,
    response: &Value,
    stdout_broken: &Arc<AtomicBool>,
) -> bool {
    let result = {
        let mut out = stdout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writeln!(out, "{response}").and_then(|_| out.flush())
    };
    if let Err(err) = result {
        stdout_broken.store(true, Ordering::SeqCst);
        glog(&format!("stdio client write failed; stopping reader loop: {err}"));
        return false;
    }
    true
}

fn handle_stdio_request(
    state: GatewayState,
    req: Value,
    request_key: String,
    search_guard: Arc<SearchGuard>,
    confirm_guard: Arc<ConfirmGuard>,
    cancel_registry: downstream::CancelRegistry,
    stdout_broken: Arc<AtomicBool>,
) {
    let cancel_context = cancel_registry.context(request_key.clone());
    // A panic in a handler must not kill the gateway: catch it, log it, and
    // return a JSON-RPC internal error for this request unless the client
    // cancelled it while it was in flight.
    let response = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        process_request(
            &state,
            &req,
            &search_guard,
            &confirm_guard,
            None,
            Some(cancel_context),
            None,
        )
    }))
    .unwrap_or_else(|_| {
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        glog("panic while handling a request; returned an internal error, gateway still up");
        Some(error(id, -32603, "internal error"))
    });

    if cancel_registry.is_cancelled(&request_key) {
        glog(&format!("suppressing response for cancelled request {request_key}"));
        cancel_registry.finish_client_request(&request_key);
        return;
    }
    cancel_registry.finish_client_request(&request_key);

    if let Some(resp) = response {
        let _ = write_stdio_response(&state.stdout, &resp, &stdout_broken);
    }
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
fn http_tool_defs(
    state: &GatewayState,
    allowed: Option<&std::collections::HashSet<String>>,
) -> Vec<Value> {
    let (allow_agent, confirm_destructive) = {
        let r = state
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (r.allow_agent_control, r.confirm_destructive)
    };
    // The namespaced catalog (cached, or live on a cold cache).
    let catalog = || {
        let cached = state
            .cached_tools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if cached.is_empty() {
            state
                .router
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .aggregated_tools()
        } else {
            cached
        }
    };
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
    } else if grouped_discovery() {
        // Grouped: the meta-tools plus a per-server help_<server> browse tool. Scope
        // the catalog to this client FIRST so the help tools (which read as meta-tools
        // to the later scope pass) can't leak an out-of-scope server's browse entry.
        // Resolve `catalog()` (which may itself lock the router) BEFORE locking the router
        // here, so the two locks never nest.
        let cat = catalog();
        let router = state
            .router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let scoped = scope_tools(&cat, allowed, |n| {
            router.route_of(n).map(|(s, _)| s.to_string())
        });
        drop(router);
        grouped_tool_defs(allow_agent, confirm_destructive, &scoped)
    } else {
        let mut tools = vec![status_tool_def(), fetch_result_tool_def()];
        tools.extend(catalog());
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
    let all_defs = http_tool_defs(state, allowed);
    let router = state
        .router
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let defs = scope_tools(&all_defs, allowed, |n| {
        router.route_of(n).map(|(s, _)| s.to_string())
    });
    drop(router);
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

/// HTTP handler result: status, content-type, body, plus optional extra headers
/// (e.g. `Mcp-Session-Id` for streamable-HTTP MCP).
struct HttpOut {
    status: u16,
    ctype: &'static str,
    body: String,
    extra: Vec<(String, String)>,
    /// Long-lived `GET /mcp` SSE listen stream (chunked response).
    mcp_listen: Option<Arc<McpSession>>,
}

impl HttpOut {
    fn new(status: u16, ctype: &'static str, body: String) -> Self {
        Self {
            status,
            ctype,
            body,
            extra: Vec::new(),
            mcp_listen: None,
        }
    }

    fn mcp_listen(session: Arc<McpSession>) -> Self {
        Self {
            status: 200,
            ctype: "text/event-stream",
            body: String::new(),
            extra: Vec::new(),
            mcp_listen: Some(session),
        }
    }

    #[cfg(test)]
    fn is_mcp_listen(&self) -> bool {
        self.mcp_listen.is_some()
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.extra.push((name.to_string(), value.to_string()));
        self
    }

    fn json_err(status: u16, msg: &str) -> Self {
        Self::new(
            status,
            "application/json",
            json!({ "error": msg }).to_string(),
        )
    }
}

/// Touch / validate an existing MCP session. Returns Ok((id, session)) or an HttpOut error.
fn mcp_require_session(
    state: &GatewayState,
    session_hdr: Option<&str>,
    owner: Option<&McpSessionOwner>,
) -> Result<(String, Arc<McpSession>), HttpOut> {
    let Some(sid) = session_hdr.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(HttpOut::json_err(
            400,
            "missing Mcp-Session-Id (send initialize first)",
        ));
    };
    if !valid_mcp_session_id(sid) {
        return Err(HttpOut::json_err(400, "invalid Mcp-Session-Id"));
    }
    let mut sessions = state
        .mcp_sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    sessions.retain(|_, s| !s.is_expired() && !s.closed.load(Ordering::SeqCst));
    match sessions.get(sid).filter(|session| session.owner.as_ref() == owner) {
        Some(sess) => {
            sess.touch();
            Ok((sid.to_string(), Arc::clone(sess)))
        }
        // Missing, expired, and wrong-owner sessions deliberately share one
        // response so callers cannot probe whether another client's id exists.
        None => Err(HttpOut::json_err(
            404,
            "unknown or expired Mcp-Session-Id; re-initialize",
        )),
    }
}

/// True when the client wants an SSE response body for a JSON-RPC request.
/// Spec clients send both `application/json` and `text/event-stream`; we keep
/// JSON as the default in that case. SSE wins only when event-stream is accepted
/// and JSON is not (or event-stream has a higher explicit `q`).
fn mcp_prefers_sse(accept: Option<&str>) -> bool {
    let Some(raw) = accept.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let lower = raw.to_ascii_lowercase();
    let q_of = |media: &str| -> Option<f32> {
        for part in lower.split(',') {
            let part = part.trim();
            if !part.starts_with(media) {
                continue;
            }
            let rest = part[media.len()..].trim_start();
            if !rest.is_empty() && !rest.starts_with(';') {
                continue;
            }
            let mut q = 1.0f32;
            for param in rest.split(';').skip(1) {
                let param = param.trim();
                if let Some(v) = param.strip_prefix("q=") {
                    q = v.parse().unwrap_or(1.0);
                }
            }
            return Some(q);
        }
        None
    };
    let sse_q = q_of("text/event-stream").filter(|q| *q > 0.0);
    let json_q = q_of("application/json").filter(|q| *q > 0.0);
    match (sse_q, json_q) {
        (Some(s), Some(j)) => s > j,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Wrap a single JSON-RPC message as one SSE `message` event (stream closes after).
fn mcp_sse_body(json: &str) -> String {
    format!("event: message\ndata: {json}\n\n")
}

fn mcp_rpc_response(status: u16, json_body: String, session_id: &str, prefer_sse: bool) -> HttpOut {
    if prefer_sse {
        HttpOut::new(status, "text/event-stream", mcp_sse_body(&json_body))
            .with_header("Mcp-Session-Id", session_id)
            .with_header("Cache-Control", "no-cache")
    } else {
        HttpOut::new(status, "application/json", json_body).with_header("Mcp-Session-Id", session_id)
    }
}

/// Handle one Streamable-HTTP MCP request at `/mcp`.
#[allow(clippy::too_many_arguments)]
fn handle_mcp_http(
    state: &GatewayState,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    method: &str,
    body: &str,
    session_hdr: Option<&str>,
    accept: Option<&str>,
    allowed: Option<&std::collections::HashSet<String>>,
    client: Option<&str>,
    session_owner: Option<&McpSessionOwner>,
) -> HttpOut {
    let prefer_sse = mcp_prefers_sse(accept);
    match method {
        "GET" => {
            if !mcp_prefers_sse(accept) {
                return HttpOut::json_err(406, "Accept must include text/event-stream");
            }
            match mcp_require_session(state, session_hdr, session_owner) {
                Ok((sid, session)) => {
                    if !session.try_begin_listen() {
                        return HttpOut::json_err(
                            409,
                            "SSE listen already active for this session",
                        );
                    }
                    HttpOut::mcp_listen(session).with_header("Mcp-Session-Id", &sid)
                }
                Err(e) => e,
            }
        }
        "DELETE" => match mcp_require_session(state, session_hdr, session_owner) {
            Ok((sid, session)) => {
                session.close();
                state
                    .mcp_sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&sid);
                HttpOut::new(204, "text/plain", String::new())
            }
            Err(e) => e,
        },
        "POST" => {
            let req: Value = if body.trim().is_empty() {
                return HttpOut::json_err(400, "empty JSON-RPC body");
            } else {
                match serde_json::from_str(body) {
                    Ok(v) => v,
                    Err(e) => {
                        return HttpOut::json_err(400, &format!("invalid JSON body: {e}"));
                    }
                }
            };

            let Some(req_obj) = req.as_object() else {
                return HttpOut::json_err(400, "JSON-RPC body must be an object");
            };
            let method_name = req_obj
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("");
            let has_id = req_obj.contains_key("id");
            let is_initialize = method_name == "initialize";

            // Session rules: initialize may omit (and gets a new id); everything
            // else that carries a method must present a live session id.
            let session_id = if is_initialize {
                if let Some(existing) = session_hdr.map(str::trim).filter(|s| !s.is_empty()) {
                    // Client re-sent a session on initialize: accept if still live,
                    // otherwise mint a fresh one (spec: start over without the old id).
                    match mcp_require_session(state, Some(existing), session_owner) {
                        Ok((sid, _)) => sid,
                        Err(_) => match mint_mcp_session(state, session_owner) {
                            Ok(sid) => sid,
                            Err(e) => return e,
                        },
                    }
                } else {
                    match mint_mcp_session(state, session_owner) {
                        Ok(sid) => sid,
                        Err(e) => return e,
                    }
                }
            } else {
                match mcp_require_session(state, session_hdr, session_owner) {
                    Ok((sid, _)) => sid,
                    Err(e) => return e,
                }
            };

            if is_initialize {
                if let Ok(sessions) = state.mcp_sessions.lock() {
                    if let Some(sess) = sessions.get(&session_id) {
                        if let Ok(mut caps) = sess.client_upstream.lock() {
                            capture_client_upstream_from_init(&mut caps, req.get("params"));
                        }
                    }
                }
            }

            if req.get("method").is_none()
                && req.get("id").is_some_and(|id| !id.is_null())
                && (req.get("result").is_some() || req.get("error").is_some())
            {
                if let Ok(sessions) = state.mcp_sessions.lock() {
                    if let Some(sess) = sessions.get(&session_id) {
                        if sess.try_deliver_upstream(&req) {
                            return HttpOut::new(202, "text/plain", String::new())
                                .with_header("Mcp-Session-Id", &session_id);
                        }
                    }
                }
            }

            // Notifications / JSON-RPC responses: 202 with empty body.
            if !has_id {
                ACTIVE_MCP_SESSION.with(|cell| *cell.borrow_mut() = Some(session_id.clone()));
                let _ = process_request(state, &req, guard, confirm, allowed, None, client);
                ACTIVE_MCP_SESSION.with(|cell| *cell.borrow_mut() = None);
                return HttpOut::new(202, "text/plain", String::new())
                    .with_header("Mcp-Session-Id", &session_id);
            }

            let resp = ACTIVE_MCP_SESSION.with(|cell| {
                *cell.borrow_mut() = Some(session_id.clone());
                let out = process_request(state, &req, guard, confirm, allowed, None, client);
                *cell.borrow_mut() = None;
                out
            });
            match resp {
                Some(resp) => {
                    let body = serde_json::to_string(&resp).unwrap_or_else(|_| {
                        json!({
                            "jsonrpc": "2.0",
                            "id": req.get("id").cloned().unwrap_or(Value::Null),
                            "error": { "code": -32603, "message": "serialize failed" }
                        })
                        .to_string()
                    });
                    mcp_rpc_response(200, body, &session_id, prefer_sse)
                }
                None => {
                    let body = json!({
                        "jsonrpc": "2.0",
                        "id": req.get("id").cloned().unwrap_or(Value::Null),
                        "error": { "code": -32603, "message": "no response" }
                    })
                    .to_string();
                    mcp_rpc_response(500, body, &session_id, prefer_sse)
                }
            }
        }
        _ => HttpOut::json_err(405, "method not allowed on /mcp"),
    }
}

/// Map one HTTP request to status / content-type / body / extra headers.
#[allow(clippy::too_many_arguments)]
fn handle_http(
    state: &GatewayState,
    guard: &SearchGuard,
    confirm: &ConfirmGuard,
    method: &str,
    path: &str,
    body: &str,
    session_hdr: Option<&str>,
    accept: Option<&str>,
    allowed: Option<&std::collections::HashSet<String>>,
    caller: Option<&HttpCaller>,
) -> HttpOut {
    let client = caller.and_then(|value| value.audit_label.as_deref());
    let session_owner = caller.map(|value| &value.session_owner);
    if method == "OPTIONS" {
        return HttpOut::new(204, "text/plain", String::new());
    }

    // Streamable-HTTP MCP endpoint (same port as OpenAPI).
    if path == "/mcp" || path.starts_with("/mcp?") {
        return handle_mcp_http(
            state,
            guard,
            confirm,
            method,
            body,
            session_hdr,
            accept,
            allowed,
            client,
            session_owner,
        );
    }

    match (method, path) {
        ("GET", "/openapi.json") => HttpOut::new(
            200,
            "application/json",
            openapi_spec(state, allowed).to_string(),
        ),
        ("GET", "/") | ("GET", "/docs") => HttpOut::new(
            200,
            "text/plain; charset=utf-8",
            "Toolport gateway (HTTP mode).\n\
             OpenAPI: GET /openapi.json, POST /{tool_name} with a JSON body.\n\
             MCP streamable-HTTP: POST /mcp with JSON-RPC; GET /mcp for server→client SSE.\n\
             Auth: Authorization: Bearer <CONDUIT_HTTP_TOKEN>."
                .to_string(),
        ),
        ("POST", p) => {
            let name = p.trim_start_matches('/');
            if name.is_empty() {
                return HttpOut::json_err(404, "missing tool name");
            }
            // Don't let OpenAPI POST swallow /mcp if path matching drifted.
            if name == "mcp" {
                return handle_mcp_http(
                    state,
                    guard,
                    confirm,
                    method,
                    body,
                    session_hdr,
                    accept,
                    allowed,
                    client,
                    session_owner,
                );
            }
            let args: Value = if body.trim().is_empty() {
                json!({})
            } else {
                match serde_json::from_str(body) {
                    Ok(v) => v,
                    Err(e) => {
                        return HttpOut::json_err(400, &format!("invalid JSON body: {e}"));
                    }
                }
            };
            let req = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": args }
            });
            match process_request(state, &req, guard, confirm, allowed, None, client) {
                Some(resp) => {
                    if let Some(err) = resp.get("error") {
                        let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("error");
                        return HttpOut::json_err(400, msg);
                    }
                    HttpOut::new(
                        200,
                        "application/json",
                        serde_json::to_string(&result_text(&resp))
                            .unwrap_or_else(|_| "\"\"".into()),
                    )
                }
                None => HttpOut::json_err(500, "no response"),
            }
        }
        _ => HttpOut::json_err(404, "not found"),
    }
}

/// Run the blocking HTTP/OpenAPI server. Binds 127.0.0.1 by default (local
/// only); set `CONDUIT_HTTP_HOST=0.0.0.0` to expose it. Every bind requires a
/// bearer token unless loopback is explicitly started with `--insecure-loopback`.
/// Cap on an inbound HTTP request body. Tool arguments are tiny; this just stops
/// an unauthenticated caller from forcing the gateway to buffer a huge body.
const MAX_HTTP_BODY: u64 = 4 * 1024 * 1024;

/// Bound the pre-routing socket work that `tiny_http` otherwise performs before
/// yielding a request. Headers and bodies each get an absolute deadline, so a
/// client cannot keep a connection alive forever by dripping one byte at a time.
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_PENDING_READS: usize = 64;
const MAX_HTTP_CHUNK_WIRE_BYTES: usize = MAX_HTTP_BODY as usize + MAX_HTTP_HEADER_BYTES;
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct HttpReadDeadlines {
    header: Duration,
    body: Duration,
}

impl Default for HttpReadDeadlines {
    fn default() -> Self {
        Self {
            header: HTTP_HEADER_READ_TIMEOUT,
            body: HTTP_BODY_READ_TIMEOUT,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HttpIngressError {
    Timeout,
    HeaderTooLarge,
    BodyTooLarge,
    BadRequest,
    ExpectationFailed,
}

impl HttpIngressError {
    fn response(&self) -> (u16, &'static str, &'static str) {
        match self {
            Self::Timeout => (408, "Request Timeout", "request read deadline exceeded"),
            Self::HeaderTooLarge => (
                431,
                "Request Header Fields Too Large",
                "request headers are too large",
            ),
            Self::BodyTooLarge => (413, "Content Too Large", "request body is too large"),
            Self::BadRequest => (400, "Bad Request", "malformed HTTP request"),
            Self::ExpectationFailed => (417, "Expectation Failed", "unsupported expectation"),
        }
    }
}

enum HttpBodyFraming {
    None,
    ContentLength(usize),
    Chunked,
}

struct ParsedHttpHead {
    forwarded: Vec<u8>,
    framing: HttpBodyFraming,
    send_continue: bool,
}

fn find_http_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}

fn parse_http_head(bytes: &[u8]) -> Result<ParsedHttpHead, HttpIngressError> {
    let text = std::str::from_utf8(bytes).map_err(|_| HttpIngressError::BadRequest)?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or(HttpIngressError::BadRequest)?;
    if request_line.split_ascii_whitespace().count() != 3 {
        return Err(HttpIngressError::BadRequest);
    }

    let mut forwarded = Vec::with_capacity(bytes.len() + 24);
    forwarded.extend_from_slice(request_line.as_bytes());
    forwarded.extend_from_slice(b"\r\n");
    let mut content_length: Option<usize> = None;
    let mut transfer_encoding: Option<String> = None;
    let mut send_continue = false;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HttpIngressError::BadRequest)?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(HttpIngressError::BadRequest);
        }

        if name.eq_ignore_ascii_case("Connection") {
            continue;
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| HttpIngressError::BadRequest)?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(HttpIngressError::BadRequest);
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if transfer_encoding.is_some() {
                return Err(HttpIngressError::BadRequest);
            }
            transfer_encoding = Some(value.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case("Expect") {
            if !value.eq_ignore_ascii_case("100-continue") {
                return Err(HttpIngressError::ExpectationFailed);
            }
            send_continue = true;
            continue;
        }

        forwarded.extend_from_slice(line.as_bytes());
        forwarded.extend_from_slice(b"\r\n");
    }

    if content_length.unwrap_or(0) > MAX_HTTP_BODY as usize {
        return Err(HttpIngressError::BodyTooLarge);
    }
    let framing = match (content_length, transfer_encoding) {
        (Some(_), Some(_)) => return Err(HttpIngressError::BadRequest),
        (Some(length), None) => HttpBodyFraming::ContentLength(length),
        (None, Some(encoding)) if encoding.trim().eq_ignore_ascii_case("chunked") => {
            HttpBodyFraming::Chunked
        }
        (None, Some(_)) => return Err(HttpIngressError::BadRequest),
        (None, None) => HttpBodyFraming::None,
    };

    // The ingress handles one request per public connection. Forcing the private
    // hop closed after its response keeps framing simple without changing any
    // public HTTP semantics; clients transparently reconnect for their next call.
    forwarded.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(ParsedHttpHead {
        forwarded,
        framing,
        send_continue,
    })
}

fn read_before_deadline(
    stream: &mut TcpStream,
    target: &mut Vec<u8>,
    deadline: Instant,
) -> Result<usize, HttpIngressError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(HttpIngressError::Timeout)?
        .max(Duration::from_millis(1));
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| HttpIngressError::BadRequest)?;
    let mut chunk = [0u8; 8192];
    match stream.read(&mut chunk) {
        Ok(0) => Err(HttpIngressError::BadRequest),
        Ok(read) => {
            target.extend_from_slice(&chunk[..read]);
            Ok(read)
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(HttpIngressError::Timeout)
        }
        Err(_) => Err(HttpIngressError::BadRequest),
    }
}

fn chunked_http_body_end(body: &[u8]) -> Result<Option<usize>, HttpIngressError> {
    let mut offset = 0usize;
    let mut decoded = 0usize;
    loop {
        let Some(line_end_rel) = body[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
        else {
            return Ok(None);
        };
        if line_end_rel > 1024 {
            return Err(HttpIngressError::BadRequest);
        }
        let line_end = offset + line_end_rel;
        let size_text = std::str::from_utf8(&body[offset..line_end])
            .map_err(|_| HttpIngressError::BadRequest)?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| HttpIngressError::BadRequest)?;
        let data_start = line_end + 2;
        decoded = decoded
            .checked_add(size)
            .ok_or(HttpIngressError::BodyTooLarge)?;
        if decoded > MAX_HTTP_BODY as usize {
            return Err(HttpIngressError::BodyTooLarge);
        }

        if size == 0 {
            if body.get(data_start..data_start + 2) == Some(b"\r\n") {
                return Ok(Some(data_start + 2));
            }
            let Some(trailer_end) = find_http_header_end(&body[data_start..]) else {
                return Ok(None);
            };
            return Ok(Some(data_start + trailer_end));
        }

        let data_end = data_start
            .checked_add(size)
            .ok_or(HttpIngressError::BodyTooLarge)?;
        let chunk_end = data_end
            .checked_add(2)
            .ok_or(HttpIngressError::BodyTooLarge)?;
        if body.len() < chunk_end {
            return Ok(None);
        }
        if body.get(data_end..chunk_end) != Some(b"\r\n") {
            return Err(HttpIngressError::BadRequest);
        }
        offset = chunk_end;
    }
}

fn read_deadline_http_request(
    stream: &mut TcpStream,
    deadlines: HttpReadDeadlines,
) -> Result<Vec<u8>, HttpIngressError> {
    let header_deadline = Instant::now() + deadlines.header;
    let mut received = Vec::new();
    let header_end = loop {
        read_before_deadline(stream, &mut received, header_deadline)?;
        if let Some(end) = find_http_header_end(&received) {
            if end > MAX_HTTP_HEADER_BYTES {
                return Err(HttpIngressError::HeaderTooLarge);
            }
            break end;
        }
        if received.len() > MAX_HTTP_HEADER_BYTES {
            return Err(HttpIngressError::HeaderTooLarge);
        }
    };

    let parsed = parse_http_head(&received[..header_end - 2])?;
    if parsed.send_continue {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| HttpIngressError::BadRequest)?;
    }
    let mut request = parsed.forwarded;
    let mut body = received.split_off(header_end);
    let body_deadline = Instant::now() + deadlines.body;

    match parsed.framing {
        HttpBodyFraming::None => {}
        HttpBodyFraming::ContentLength(length) => {
            while body.len() < length {
                read_before_deadline(stream, &mut body, body_deadline)?;
                if body.len() > MAX_HTTP_BODY as usize {
                    return Err(HttpIngressError::BodyTooLarge);
                }
            }
            request.extend_from_slice(&body[..length]);
        }
        HttpBodyFraming::Chunked => loop {
            // Permit ordinary chunk framing overhead while bounding the total wire
            // buffer as well as the decoded body size checked by the parser.
            if body.len() > MAX_HTTP_CHUNK_WIRE_BYTES {
                return Err(HttpIngressError::BodyTooLarge);
            }
            if let Some(end) = chunked_http_body_end(&body)? {
                request.extend_from_slice(&body[..end]);
                break;
            }
            read_before_deadline(stream, &mut body, body_deadline)?;
        },
    }
    let _ = stream.set_read_timeout(None);
    Ok(request)
}

fn write_ingress_response(stream: &mut TcpStream, status: u16, reason: &str, message: &str) {
    let body = serde_json::json!({ "error": message }).to_string();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn proxy_deadline_http_connection(
    mut client: TcpStream,
    backend: SocketAddr,
    deadlines: HttpReadDeadlines,
    pending_read: InflightGuard,
) {
    let request = match read_deadline_http_request(&mut client, deadlines) {
        Ok(request) => request,
        Err(err) => {
            drop(pending_read);
            let _ = client.set_read_timeout(None);
            let (status, reason, message) = err.response();
            write_ingress_response(&mut client, status, reason, message);
            return;
        }
    };
    // Only incomplete reads count against the slow-client cap. Completed requests
    // move to the existing gateway in-flight cap, so long approvals and SSE streams
    // do not consume all of the pre-routing slots.
    drop(pending_read);

    let mut upstream = match TcpStream::connect_timeout(&backend, Duration::from_secs(2)) {
        Ok(stream) => stream,
        Err(_) => {
            write_ingress_response(
                &mut client,
                503,
                "Service Unavailable",
                "gateway unavailable",
            );
            return;
        }
    };
    if upstream.write_all(&request).is_err() {
        write_ingress_response(
            &mut client,
            503,
            "Service Unavailable",
            "gateway unavailable",
        );
        return;
    }
    let _ = upstream.shutdown(Shutdown::Write);
    let _ = std::io::copy(&mut upstream, &mut client);
}

struct HttpIngressGuard {
    close: Arc<AtomicBool>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for HttpIngressGuard {
    fn drop(&mut self) {
        self.close.store(true, Ordering::Release);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
    }
}

fn bind_deadline_http_server<A: ToSocketAddrs>(
    addr: A,
    deadlines: HttpReadDeadlines,
) -> Result<
    (tiny_http::Server, HttpIngressGuard, SocketAddr),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let public_addr = listener.local_addr()?;
    let backend_listener = if public_addr.is_ipv6() {
        TcpListener::bind(("::1", 0))?
    } else {
        TcpListener::bind(("127.0.0.1", 0))?
    };
    let backend_addr = backend_listener.local_addr()?;
    let server = tiny_http::Server::from_listener(backend_listener, None)?;
    let close = Arc::new(AtomicBool::new(false));
    let accept_close = Arc::clone(&close);
    let connections = Arc::new(AtomicUsize::new(0));
    let accept_thread = std::thread::spawn(move || {
        while !accept_close.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut client, _)) => {
                    if accept_close.load(Ordering::Acquire) {
                        break;
                    }
                    // The listener is nonblocking so the guard can shut it down.
                    // Windows propagates that mode to accepted sockets; restore a
                    // blocking stream so the explicit read deadlines govern it.
                    if client.set_nonblocking(false).is_err() {
                        write_ingress_response(
                            &mut client,
                            503,
                            "Service Unavailable",
                            "gateway unavailable",
                        );
                        continue;
                    }
                    let Some(guard) = try_acquire_inflight(&connections, MAX_HTTP_PENDING_READS)
                    else {
                        write_ingress_response(
                            &mut client,
                            503,
                            "Service Unavailable",
                            "gateway busy; retry later",
                        );
                        continue;
                    };
                    std::thread::spawn(move || {
                        proxy_deadline_http_connection(client, backend_addr, deadlines, guard);
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(err) => {
                    glog(&format!("HTTP deadline ingress accept failed: {err}"));
                    break;
                }
            }
        }
    });

    Ok((
        server,
        HttpIngressGuard {
            close,
            accept_thread: Some(accept_thread),
        },
        public_addr,
    ))
}

/// Cap on concurrently-handled HTTP gateway requests. Requests above the cap are
/// rejected immediately so a slow request can never block the listener's accept
/// loop. Sized well above any realistic local concurrency: the approval broker
/// caps simultaneous holds at 64, and non-held calls finish in milliseconds, so
/// this backstop is only ever a flood guard.
const MAX_HTTP_INFLIGHT: usize = 256;

/// Stdio keeps its historical inline fallback once its worker cap is reached.
/// Unlike HTTP, this cannot stall a socket accept loop, and it keeps stdin
/// processing bounded without dropping a protocol request.
const MAX_STDIO_INFLIGHT: usize = 256;

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

const INSECURE_LOOPBACK_FLAG: &str = "--insecure-loopback";

/// Whether the operator explicitly requested the local unauthenticated escape hatch.
fn insecure_loopback_requested(args: &[String]) -> bool {
    args.iter().any(|arg| arg == INSECURE_LOOPBACK_FLAG)
}

/// Startup admission policy. The escape hatch is never valid for a non-loopback bind.
fn http_bind_is_authorized(loopback: bool, auth_configured: bool, insecure_loopback: bool) -> bool {
    auth_configured || http_allows_insecure_open(loopback, auth_configured, insecure_loopback)
}

/// Activate the open-listener fallback only when the escape hatch was required at startup.
fn http_allows_insecure_open(
    loopback: bool,
    auth_configured: bool,
    insecure_loopback: bool,
) -> bool {
    loopback && insecure_loopback && !auth_configured
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
    let registered_clients = state
        .registry
        .lock()
        .map(|reg| !reg.http_clients.is_empty())
        .unwrap_or(false);
    let auth_configured = token.is_some() || registered_clients;
    let args: Vec<String> = std::env::args().collect();
    let insecure_loopback = insecure_loopback_requested(&args);
    let allow_insecure_open =
        http_allows_insecure_open(loopback, auth_configured, insecure_loopback);

    if !http_bind_is_authorized(loopback, auth_configured, insecure_loopback) {
        if loopback {
            eprintln!(
                "toolport-gateway: refusing to bind {host}:{port} without HTTP authentication. \
                 Set CONDUIT_HTTP_TOKEN, configure a registered HTTP client, or explicitly pass \
                 {INSECURE_LOOPBACK_FLAG} to accept unauthenticated local access."
            );
        } else {
            eprintln!(
                "toolport-gateway: refusing to bind {host}:{port} without HTTP authentication. \
                 Set CONDUIT_HTTP_TOKEN or configure a registered HTTP client. \
                 {INSECURE_LOOPBACK_FLAG} is valid only for loopback binds."
            );
        }
        std::process::exit(1);
    }
    if allow_insecure_open {
        eprintln!(
            "toolport-gateway: WARNING - {INSECURE_LOOPBACK_FLAG} enabled; any local process \
             (including a web page open in your browser) can call your tools."
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
        if let Ok((server6, ingress6, _)) =
            bind_deadline_http_server(("::1", port), HttpReadDeadlines::default())
        {
            let (state6, token6, search6, confirm6) = (
                state.clone(),
                token.clone(),
                search.clone(),
                confirm.clone(),
            );
            std::thread::spawn(move || {
                let _ingress = ingress6;
                serve_http_loop(
                    server6,
                    state6,
                    token6,
                    search6,
                    confirm6,
                    allow_insecure_open,
                )
            });
            glog(&format!(
                "HTTP/OpenAPI also listening on http://[::1]:{port}"
            ));
        }
    }

    let (server, _ingress, _) =
        match bind_deadline_http_server((host.as_str(), port), HttpReadDeadlines::default()) {
            Ok(bound) => bound,
            Err(e) => {
                eprintln!("toolport-gateway: could not bind HTTP {host}:{port}: {e}");
                std::process::exit(1);
            }
        };
    glog(&format!(
        "HTTP mode on http://{host}:{port} (OpenAPI + MCP /mcp, auth={}, header_timeout={}s, body_timeout={}s)",
        auth_configured,
        HTTP_HEADER_READ_TIMEOUT.as_secs(),
        HTTP_BODY_READ_TIMEOUT.as_secs()
    ));
    eprintln!(
        "toolport-gateway: HTTP on http://localhost:{port}  (OpenAPI /openapi.json, MCP POST /mcp)"
    );
    serve_http_loop(server, state, token, search, confirm, allow_insecure_open);
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

fn try_acquire_inflight(inflight: &Arc<AtomicUsize>, limit: usize) -> Option<InflightGuard> {
    let mut current = inflight.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return None;
        }
        match inflight.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(InflightGuard(Arc::clone(inflight))),
            Err(next) => current = next,
        }
    }
}

fn spawn_or_run_stdio_inflight<F>(
    inflight: &Arc<AtomicUsize>,
    job: F,
) -> Option<std::thread::JoinHandle<()>>
where
    F: FnOnce() + Send + 'static,
{
    let Some(guard) = try_acquire_inflight(inflight, MAX_STDIO_INFLIGHT) else {
        job();
        return None;
    };
    Some(std::thread::spawn(move || {
        let _dec = guard;
        job();
    }))
}

fn reap_finished_workers(workers: &mut Vec<std::thread::JoinHandle<()>>) {
    let mut i = 0;
    while i < workers.len() {
        if workers[i].is_finished() {
            let handle = workers.swap_remove(i);
            let _ = handle.join();
        } else {
            i += 1;
        }
    }
}

fn respond_mcp_sse_listen(
    request: tiny_http::Request,
    out: HttpOut,
    allow_headers: String,
) {
    let Some(session) = out.mcp_listen else {
        let mut response =
            tiny_http::Response::from_string(out.body).with_status_code(out.status);
        if let Ok(h) = tiny_http::Header::from_bytes(b"Content-Type", out.ctype.as_bytes()) {
            response = response.with_header(h);
        }
        let _ = request.respond(response);
        return;
    };

    let mut headers = vec![
        tiny_http::Header::from_bytes(b"Content-Type", b"text/event-stream").unwrap(),
        tiny_http::Header::from_bytes(b"Cache-Control", b"no-cache").unwrap(),
        tiny_http::Header::from_bytes(b"Access-Control-Allow-Origin", b"*").unwrap(),
        tiny_http::Header::from_bytes(
            b"Access-Control-Allow-Methods",
            b"GET, POST, DELETE, OPTIONS",
        )
        .unwrap(),
        tiny_http::Header::from_bytes(b"Access-Control-Allow-Headers", allow_headers.as_bytes())
            .unwrap(),
        tiny_http::Header::from_bytes(b"Access-Control-Expose-Headers", b"Mcp-Session-Id").unwrap(),
    ];
    for (name, value) in out.extra {
        let safe = sanitize_header_value(&value);
        if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), safe.as_bytes()) {
            headers.push(h);
        }
    }

    let reader = McpSseReader::new(session);
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(200),
        headers,
        reader,
        None,
        None,
    )
    .with_chunked_threshold(0)
    .boxed();
    let _ = request.respond(response);
}

fn serve_http_loop(
    server: tiny_http::Server,
    state: GatewayState,
    token: Option<String>,
    search: Arc<SearchGuard>,
    confirm: Arc<ConfirmGuard>,
    allow_insecure_open: bool,
) {
    serve_http_loop_with_inflight(
        server,
        state,
        token,
        search,
        confirm,
        allow_insecure_open,
        Arc::new(AtomicUsize::new(0)),
    );
}

fn serve_http_loop_with_inflight(
    server: tiny_http::Server,
    state: GatewayState,
    token: Option<String>,
    search: Arc<SearchGuard>,
    confirm: Arc<ConfirmGuard>,
    allow_insecure_open: bool,
    inflight: Arc<AtomicUsize>,
) {
    for request in server.incoming_requests() {
        let Some(guard) = try_acquire_inflight(&inflight, MAX_HTTP_INFLIGHT) else {
            respond_http_overloaded(request);
            continue;
        };
        let (state, token, search, confirm) = (
            state.clone(),
            token.clone(),
            Arc::clone(&search),
            Arc::clone(&confirm),
        );
        std::thread::spawn(move || {
            let _permit = guard;
            handle_connection(
                request,
                &state,
                &token,
                &search,
                &confirm,
                allow_insecure_open,
            );
        });
    }
}

fn respond_http_overloaded(request: tiny_http::Request) {
    let body = serde_json::json!({ "error": "gateway busy; retry later" }).to_string();
    let mut response = tiny_http::Response::from_string(body).with_status_code(503);
    for (name, value) in [
        (b"Content-Type".as_slice(), b"application/json".as_slice()),
        (b"Retry-After".as_slice(), b"1".as_slice()),
        (b"Access-Control-Allow-Origin".as_slice(), b"*".as_slice()),
    ] {
        if let Ok(header) = tiny_http::Header::from_bytes(name, value) {
            response = response.with_header(header);
        }
    }
    let _ = request.respond(response);
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
    allow_insecure_open: bool,
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
            .unwrap_or_else(|| {
                "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version".to_string()
            });

        let session_hdr = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Mcp-Session-Id"))
            .map(|h| sanitize_header_value(h.value.as_str()))
            .filter(|s| !s.is_empty());

        let accept_hdr = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Accept"))
            .map(|h| sanitize_header_value(h.value.as_str()))
            .filter(|s| !s.is_empty());

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
        // HTTP client (its profile's servers), or open only when startup explicitly
        // accepted `--insecure-loopback`.
        // A bad/missing token is rejected before we read the body or route.
        let provided = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str().to_string());
        let provided_tok = provided.as_deref().and_then(parse_bearer);
        let mut caller: Option<HttpCaller> = None;
        let scope: Option<Option<std::collections::HashSet<String>>> = if method == "OPTIONS" {
            Some(None)
        } else {
            let reg = state
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Resolve authorization, routing scope, audit attribution, and MCP
            // session ownership from one token lookup and one effective allow-set.
            match resolve_http_caller(
                &reg,
                token.as_deref(),
                provided_tok,
                allow_insecure_open,
            ) {
                Some((allowed, resolved_caller)) => {
                    caller = Some(resolved_caller);
                    Some(allowed)
                }
                None => None,
            }
        };

        let out: HttpOut = if cross_site && method != "OPTIONS" {
            HttpOut::json_err(403, "cross-site browser requests are not allowed")
        } else {
            match scope {
                None => HttpOut::json_err(401, "missing or invalid bearer token"),
                Some(allowed) => {
                    let mut body = String::new();
                    if method == "POST" || method == "DELETE" {
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
                            session_hdr.as_deref(),
                            accept_hdr.as_deref(),
                            allowed.as_ref(),
                            caller.as_ref(),
                        )
                    }))
                    .unwrap_or_else(|_| HttpOut::json_err(500, "internal error"))
                }
            }
        };

        if out.mcp_listen.is_some() {
            respond_mcp_sse_listen(request, out, allow_headers);
            return;
        }

        let mut response = tiny_http::Response::from_string(out.body).with_status_code(out.status);
        let cors: [(&[u8], &[u8]); 5] = [
            (b"Content-Type", out.ctype.as_bytes()),
            // Auth is a bearer header, never a cookie, so credentialed CORS is
            // unnecessary. Return a wildcard Origin (never the reflected caller
            // Origin) and omit Allow-Credentials, so a malicious page can't pair a
            // reflected origin with Allow-Credentials to read a response.
            (b"Access-Control-Allow-Origin", b"*"),
            (b"Access-Control-Allow-Methods", b"GET, POST, DELETE, OPTIONS"),
            (b"Access-Control-Allow-Headers", allow_headers.as_bytes()),
            // Browser MCP clients need to read the session id off the response.
            (b"Access-Control-Expose-Headers", b"Mcp-Session-Id"),
        ];
        for (name, value) in cors {
            // Skip a header that won't encode rather than panicking the thread.
            if let Ok(h) = tiny_http::Header::from_bytes(name, value) {
                response = response.with_header(h);
            }
        }
        for (name, value) in &out.extra {
            let safe = sanitize_header_value(value);
            if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), safe.as_bytes()) {
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

    // Discovery mode resolves from an explicit env override first (per-client), then
    // the registry (its `discovery_mode` override, else the `lazy_discovery` bool), so
    // it applies to EVERY client, including ones that don't forward env vars to the
    // gateway (e.g. Antigravity). Resolved once and cached; `lazy` is derived so its
    // behavior is unchanged, and grouped mode reads the same cached value.
    let mode = resolve_discovery_mode();
    set_discovery_mode(mode);
    let lazy = matches!(mode, DiscoveryMode::Lazy);
    // Per-client scoping: this gateway exposes only the named profile's servers.
    // This is only the bootstrap value - once the registry loads below, the live
    // value (kept in sync with registry.client_scopes on every watcher tick) wins.
    let env_profile = std::env::var("CONDUIT_PROFILE")
        .ok()
        .filter(|s| !s.trim().is_empty());
    // Identifies this client for a live profile lookup in registry.client_scopes,
    // so any re-scope (scoped->scoped, scoped->unscoped, unscoped->scoped)
    // propagates without restarting the client. Every install now writes this,
    // scoped or not; only a client installed before this env var existed lacks it
    // (until its next reinstall) and falls back to CONDUIT_PROFILE - see
    // docs/drafts/profile-switch-live-reload-plan.md.
    let client_id = std::env::var("CONDUIT_CLIENT_ID")
        .ok()
        .filter(|s| !s.trim().is_empty());
    // HTTP/OpenAPI bridge mode: one process serves every registered client, so the
    // router connects the union of their profiles. Resolve the port once up front.
    let http_port_opt = http_port();
    let http_mode = http_port_opt.is_some();
    glog("=== gateway start ===");
    glog(&format!(
        "cwd={:?} CONDUIT_REGISTRY={:?} registry_path={:?} dir_resolution={:?} lazy={lazy} profile={env_profile:?} client_id={client_id:?}",
        std::env::current_dir().ok(),
        std::env::var("CONDUIT_REGISTRY").ok(),
        registry::resolved_path(),
        registry::conduit_dir_resolution(),
    ));
    if registry::conduit_dir_resolution() == registry::DirResolution::VirtualizedFallback {
        // Loud, not fatal: inside an MSIX container with no UNC escape, the data
        // dir may be the package's stale shadow copy - registry edits made in the
        // app won't propagate here, and HITL approvals can fail closed against a
        // dead broker endpoint. Say so instead of desyncing silently.
        eprintln!(
            "toolport-gateway: running inside an MSIX app container and the \\\\localhost \
             UNC view of the data dir is unreachable; registry/approval files may be a \
             stale virtualized shadow copy (server changes and approvals may not work)."
        );
        glog("WARNING: MSIX container detected but devirtualization failed (UNC view unreachable)");
    }
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
    inspect::clear();
    // Resolve the live profile immediately from what's already on disk, rather than
    // waiting for the watcher's first tick: a scoped client re-launched after being
    // re-scoped should see the new profile from its very first request.
    let resolved_profile = resolve_live_profile(&loaded, client_id.as_deref(), &env_profile);
    let registry = Arc::new(Mutex::new(loaded));
    // Empty router + cached catalog: the handshake and tools/list answer instantly
    // (from cache), while downstream servers connect in the background for the
    // actual tool calls.
    //
    // LOCK ORDER: when both are held, always lock `registry` before `router`. The
    // request loop, the watcher, and the self-heal path all follow this, so there's
    // no deadlock; keep new code consistent with it.
    let router = Arc::new(Mutex::new(Arc::new(Router::new())));
    let cached_tools = Arc::new(Mutex::new(load_tool_cache(resolved_profile.as_deref())));
    // Shared, live-updated: the watcher re-resolves this from registry.client_scopes
    // on every reload (falling back to `env_profile` if this client has no scope
    // entry), so a profile switch reaches every reader below without a restart.
    let profile = Arc::new(Mutex::new(resolved_profile));
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let ready = Arc::new(AtomicBool::new(false));
    // Flipped by any downstream transport that emits notifications/tools/list_changed.
    // The registry watcher polls it and rebuilds, so a server that changes its own
    // tool set mid-session propagates to the client instead of being dropped.
    let downstream_dirty = Arc::new(AtomicU8::new(0));
    let mcp_sessions = Arc::new(Mutex::new(HashMap::new()));
    let client_upstream = Arc::new(Mutex::new(ClientUpstreamCaps::default()));
    let client_root = Arc::new(Mutex::new(None::<String>));
    // Single-flight for every router build/swap (startup, watcher self-heal, and
    // ${ROOT} rebuilds). Created up front so the startup build can share it.
    let rebuild_lock = Arc::new(Mutex::new(()));
    let stdio_upstream = Arc::new(StdioUpstream::new(Arc::clone(&stdout)));
    let server_handler = make_server_request_handler(
        Arc::clone(&client_upstream),
        Arc::clone(&stdio_upstream),
        Arc::clone(&mcp_sessions),
        http_mode,
    );
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
        let server_handler = Arc::clone(&server_handler);
        let profile = Arc::clone(&profile);
        let client_root = Arc::clone(&client_root);
        let rebuild_lock = Arc::clone(&rebuild_lock);
        std::thread::spawn(move || {
            let reg = registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let p = profile
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            // Single-flight with the ${ROOT} / self-heal rebuilds, and read the
            // shared root inside the lock so a late startup swap can't overwrite an
            // already-resolved ${ROOT} rebuild back to the fallback cwd (issue #239).
            let _rebuild = rebuild_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let root = client_root
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let built = build_router(
                &reg,
                p.as_deref(),
                http_mode,
                &downstream_dirty,
                server_handler,
                root.as_deref(),
            );
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
                save_tool_cache(&tools, p.as_deref());
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
        let server_handler = Arc::clone(&server_handler);
        let profile = Arc::clone(&profile);
        let client_id = client_id.clone();
        let env_profile = env_profile.clone();
        let client_root = Arc::clone(&client_root);
        std::thread::spawn(move || {
            watch_registry(
                path,
                registry,
                router,
                stdout,
                cached_tools,
                profile,
                client_id,
                env_profile,
                http_mode,
                downstream_dirty,
                server_handler,
                client_root,
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
        rebuild_lock,
        lazy,
        profile: Arc::clone(&profile),
        http: http_mode,
        mcp_sessions,
        client_upstream,
        client_root,
        stdio_upstream,
        server_handler,
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
    let search_guard = Arc::new(SearchGuard::default());
    let confirm_guard = Arc::new(ConfirmGuard::new());
    let cancel_registry = downstream::CancelRegistry::new();
    let stdio_inflight = Arc::new(AtomicUsize::new(0));
    let stdout_broken = Arc::new(AtomicBool::new(false));
    let mut stdio_workers = Vec::new();
    let mut stdin = stdin.lock();
    loop {
        reap_finished_workers(&mut stdio_workers);
        if stdout_broken.load(Ordering::SeqCst) {
            break;
        }
        let line = match read_bounded_line(&mut stdin, MAX_STDIO_LINE_BYTES) {
            Ok(BoundedLine::Line(line)) => line,
            Ok(BoundedLine::TooLong) => {
                glog("ignored oversized stdio request (>16 MiB)");
                continue;
            }
            Ok(BoundedLine::Eof) | Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if state.stdio_upstream.try_deliver(&req) {
            continue;
        }
        gtrace(&format!(
            "request: {}",
            req.get("method").and_then(|m| m.as_str()).unwrap_or("")
        ));
        if let Some(cancel_id) = cancellation_request_id(&req) {
            if cancel_registry.cancel(&cancel_id, cancellation_reason(&req)) {
                glog(&format!("client cancelled in-flight request {cancel_id}"));
            } else {
                gtrace(&format!("ignored cancellation for unknown request {cancel_id}"));
            }
            continue;
        }

        let Some(request_key) = request_id_key(&req) else {
            let _ = process_request(&state, &req, &search_guard, &confirm_guard, None, None, None);
            continue;
        };
        if !cancel_registry.begin_client_request(request_key.clone()) {
            gtrace(&format!("rejected duplicate in-flight request id {request_key}"));
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let resp = error(id, -32600, "duplicate in-flight request id");
            if !write_stdio_response(&state.stdout, &resp, &stdout_broken) {
                break;
            }
            continue;
        }

        let state = state.clone();
        let search_guard = Arc::clone(&search_guard);
        let confirm_guard = Arc::clone(&confirm_guard);
        let cancel_registry = cancel_registry.clone();
        let stdout_broken_for_worker = Arc::clone(&stdout_broken);
        let job = move || {
            handle_stdio_request(
                state,
                req,
                request_key,
                search_guard,
                confirm_guard,
                cancel_registry,
                stdout_broken_for_worker,
            );
        };
        if let Some(handle) = spawn_or_run_stdio_inflight(&stdio_inflight, job) {
            stdio_workers.push(handle);
        }
    }
    for worker in stdio_workers {
        let _ = worker.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_relevant_ignores_team_metadata_but_tracks_real_changes() {
        // A team-metadata-only rewrite (what the desktop sync loop does every ~25s, even on
        // a no-op 304 or a usage-watermark bump) must NOT register as a change, or the
        // gateway respawns every stdio server on every sync - the process leak that
        // exhausted a user's RAM. A change OUTSIDE the team block must still be detected.
        let mut reg = Registry::default();
        let base = router_relevant(&reg);

        // Connecting to a team + bumping usage/version/etag/role lives entirely in the
        // `team` block, which the gateway never reads.
        let mut usage = std::collections::HashMap::new();
        usage.insert("2026-07-10".to_string(), std::collections::HashMap::new());
        reg.team = Some(registry::TeamConnection {
            server_url: "https://teams.toolport.app".into(),
            team_id: "t1".into(),
            role: "admin".into(),
            member_name: Some("Tyler".into()),
            last_version: 42,
            last_etag: Some("\"v42\"".into()),
            usage_reported: usage,
        });
        assert_eq!(
            router_relevant(&reg),
            base,
            "team-block churn (usage/version/etag/role) must not count as a router change"
        );

        // A policy flag lives OUTSIDE the team block: a real change the router must rebuild for.
        reg.deny_destructive = !reg.deny_destructive;
        assert_ne!(
            router_relevant(&reg),
            base,
            "a non-team change must still be detected so a real toggle rebuilds"
        );
    }

    #[test]
    fn resolve_live_profile_prefers_client_scope_over_frozen_env_var() {
        // The bug: a scoped client's profile used to be frozen at CONDUIT_PROFILE
        // for the process lifetime. Once client_scopes has an entry for this
        // client, it must win - that's what makes a profile switch apply without
        // restarting the client.
        let mut reg = Registry::default();
        reg.set_client_scope("cursor", Some("Billing"));
        let env_profile = Some("Default".to_string());
        assert_eq!(
            resolve_live_profile(&reg, Some("cursor"), &env_profile),
            Some("Billing".to_string())
        );
    }

    #[test]
    fn resolve_live_profile_falls_back_to_env_var_when_scope_unset() {
        // A client_id with no client_scopes entry yet (e.g. installed before
        // CONDUIT_CLIENT_ID existed, or never re-scoped) keeps the bootstrap value.
        let reg = Registry::default();
        let env_profile = Some("Default".to_string());
        assert_eq!(
            resolve_live_profile(&reg, Some("cursor"), &env_profile),
            Some("Default".to_string())
        );
    }

    #[test]
    fn resolve_live_profile_explicit_unscope_overrides_frozen_env_var() {
        // Re-scoping a client to "all servers" records an explicit-unscoped marker
        // (empty string), which must resolve to None (follow the active profile)
        // rather than falling back to the CONDUIT_PROFILE this process booted with.
        // Without this, switching from a named profile to unscoped wouldn't apply
        // until the client restarted.
        let mut reg = Registry::default();
        reg.set_client_unscoped("cursor");
        let env_profile = Some("Billing".to_string());
        assert_eq!(resolve_live_profile(&reg, Some("cursor"), &env_profile), None);
    }

    #[test]
    fn resolve_live_profile_ignores_other_clients_scopes() {
        let mut reg = Registry::default();
        reg.set_client_scope("windsurf", Some("Billing"));
        let env_profile = Some("Default".to_string());
        assert_eq!(
            resolve_live_profile(&reg, Some("cursor"), &env_profile),
            Some("Default".to_string())
        );
    }

    #[test]
    fn resolve_live_profile_unscoped_client_always_uses_env_profile() {
        // No client_id at all (unscoped install): never consult client_scopes.
        // This path already resolves the active profile live elsewhere, via
        // Registry::enabled_servers().
        let mut reg = Registry::default();
        reg.set_client_scope("cursor", Some("Billing"));
        assert_eq!(resolve_live_profile(&reg, None, &None), None);
    }

    #[test]
    fn resolve_live_profile_switch_takes_effect_on_next_resolution() {
        // Simulates a profile switch mid-session: same client_id, registry
        // mutated in place (as the watcher would see across two poll ticks).
        let mut reg = Registry::default();
        reg.set_client_scope("cursor", Some("Billing"));
        assert_eq!(
            resolve_live_profile(&reg, Some("cursor"), &None),
            Some("Billing".to_string())
        );
        reg.set_client_scope("cursor", Some("Engineering"));
        assert_eq!(
            resolve_live_profile(&reg, Some("cursor"), &None),
            Some("Engineering".to_string())
        );
    }

    #[test]
    fn capture_client_upstream_records_roots_sampling_and_elicitation() {
        let mut state = ClientUpstreamCaps::default();
        let params = json!({
            "capabilities": {
                "roots": { "listChanged": true },
                "sampling": {},
                "elicitation": {}
            },
            "roots": { "roots": [{ "uri": "file:///tmp", "name": "tmp" }] }
        });
        capture_client_upstream_from_init(&mut state, Some(&params));
        assert!(state.roots.supported);
        assert!(state.roots.list_changed);
        assert!(state.sampling);
        assert!(state.elicitation);
        assert_eq!(state.roots.roots.len(), 1);
        assert_eq!(state.roots.roots[0]["uri"], "file:///tmp");
    }

    #[test]
    fn capture_client_upstream_resets_stale_capabilities_on_reinitialize() {
        let mut state = ClientUpstreamCaps {
            sampling: true,
            elicitation: true,
            ..Default::default()
        };
        capture_client_upstream_from_init(&mut state, Some(&json!({"capabilities": {}})));
        assert!(!state.sampling);
        assert!(!state.elicitation);
    }

    #[test]
    fn client_supports_server_rpc_matches_declared_capabilities() {
        let caps = ClientUpstreamCaps {
            roots: ClientRootsState {
                supported: true,
                ..Default::default()
            },
            sampling: true,
            elicitation: false,
        };
        assert!(client_supports_server_rpc(&caps, "roots/list"));
        assert!(client_supports_server_rpc(&caps, "sampling/createMessage"));
        assert!(!client_supports_server_rpc(&caps, "elicitation/create"));
    }

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
            tool_fingerprint: Some("v2:abc".into()),
        };
        // No endpoint descriptor (Toolport app not running) -> Unreachable (fail-closed),
        // distinct from a human Timeout so the caller can explain *why* it was blocked.
        let mut r = mk();
        let d = decide_via_broker(None, &mut r);
        assert!(!d.is_approved());
        assert_eq!(d, approval::ApprovalDecision::Unreachable);
        // A published endpoint that refuses the connection -> also Unreachable (we never
        // handed the request to a broker), so request_human_decision may retry a re-read.
        let mut r = mk();
        let bad = Some(approval::EndpointDescriptor {
            endpoint: "127.0.0.1:1".into(),
            token: "t".into(),
        });
        let d = decide_via_broker(bad, &mut r);
        assert!(!d.is_approved());
        assert_eq!(d, approval::ApprovalDecision::Unreachable);
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
        let stdout = Arc::new(Mutex::new(std::io::stdout()));
        let mcp_sessions = Arc::new(Mutex::new(HashMap::new()));
        let client_upstream = Arc::new(Mutex::new(ClientUpstreamCaps::default()));
        let stdio_upstream = Arc::new(StdioUpstream::new(Arc::clone(&stdout)));
        let server_handler = make_server_request_handler(
            Arc::clone(&client_upstream),
            Arc::clone(&stdio_upstream),
            Arc::clone(&mcp_sessions),
            true,
        );
        GatewayState {
            registry: Arc::new(Mutex::new(Registry::default())),
            router: Arc::new(Mutex::new(Arc::new(Router::new()))),
            cached_tools: Arc::new(Mutex::new(Vec::new())),
            stdout,
            ready: Arc::new(AtomicBool::new(true)),
            downstream_dirty: Arc::new(AtomicU8::new(0)),
            rebuild_lock: Arc::new(Mutex::new(())),
            lazy,
            profile: Arc::new(Mutex::new(None)),
            http: true,
            mcp_sessions,
            client_upstream,
            client_root: Arc::new(Mutex::new(None)),
            stdio_upstream,
            server_handler,
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

    #[test]
    fn deadline_http_ingress_times_out_slow_headers_and_bodies() {
        let deadlines = HttpReadDeadlines {
            header: Duration::from_millis(180),
            body: Duration::from_millis(120),
        };
        let (_server, _ingress, public_addr) =
            bind_deadline_http_server("127.0.0.1:0", deadlines).unwrap();

        let mut slow_header = TcpStream::connect(public_addr).unwrap();
        slow_header
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut drip_stream = slow_header.try_clone().unwrap();
        let drip = std::thread::spawn(move || {
            for byte in b"GET / HTTP/1.1" {
                if drip_stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let started = Instant::now();
        let mut response = String::new();
        let read_result = slow_header.read_to_string(&mut response);
        let elapsed = started.elapsed();
        drip.join().unwrap();
        assert!(
            read_result.is_ok()
                || read_result
                    .as_ref()
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::ConnectionReset),
            "unexpected slow-header read error: {read_result:?}"
        );
        assert!(
            response.starts_with("HTTP/1.1 408 Request Timeout"),
            "slow header response was: {response}"
        );
        assert!(
            elapsed < Duration::from_millis(350),
            "header timeout reset after each drip ({elapsed:?}) instead of enforcing an absolute deadline"
        );

        let mut slow_body = TcpStream::connect(public_addr).unwrap();
        slow_body
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        slow_body
            .write_all(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\na")
            .unwrap();
        let mut response = String::new();
        slow_body.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 408 Request Timeout"),
            "slow body response was: {response}"
        );
    }

    #[test]
    fn deadline_http_ingress_forwards_complete_requests_and_closes_private_hop() {
        let (server, _ingress, public_addr) =
            bind_deadline_http_server("127.0.0.1:0", HttpReadDeadlines::default()).unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(public_addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .write_all(
                    b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
                )
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });

        let request = server
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .expect("ingress did not forward a complete request");
        assert_eq!(request.url(), "/ready");
        assert!(request.headers().iter().any(|header| {
            header.field.equiv("Connection") && header.value.as_str().eq_ignore_ascii_case("close")
        }));
        request
            .respond(tiny_http::Response::from_string("ready"))
            .unwrap();
        assert!(client.join().unwrap().contains("ready"));
    }

    #[test]
    fn chunked_http_body_parser_bounds_and_finds_the_terminal_chunk() {
        assert_eq!(
            chunked_http_body_end(b"4\r\ntest\r\n0\r\n\r\n").unwrap(),
            Some(14)
        );
        assert_eq!(
            chunked_http_body_end(b"4\r\ntest\r\n0\r\nX-Test: yes\r\n\r\n").unwrap(),
            Some(27)
        );
        assert_eq!(chunked_http_body_end(b"4\r\nte").unwrap(), None);
        assert_eq!(
            chunked_http_body_end(b"nope\r\n").unwrap_err(),
            HttpIngressError::BadRequest
        );
    }

    #[test]
    fn deadline_http_ingress_rejects_ambiguous_request_framing() {
        assert!(matches!(
            parse_http_head(
                b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n"
            ),
            Err(HttpIngressError::BadRequest)
        ));
        assert!(matches!(
            parse_http_head(
                b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"
            ),
            Err(HttpIngressError::BadRequest)
        ));
        assert!(matches!(
            parse_http_head(b"POST / HTTP/1.1\r\nExpect: something-else\r\n"),
            Err(HttpIngressError::ExpectationFailed)
        ));
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
        std::thread::spawn(move || serve_http_loop(server, state, None, search, confirm, true));
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
    fn bounded_stdio_line_recovers_after_oversized_frame() {
        let input = b"1234\r\nabcdefgh\nok\nlast";
        let mut reader = std::io::BufReader::with_capacity(3, input.as_slice());

        assert_eq!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::Line("1234".to_string()),
            "CRLF is excluded from the byte limit"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::TooLong
        );
        assert_eq!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::Line("ok".to_string()),
            "oversized input is drained through its newline"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::Line("last".to_string()),
            "a final frame without a newline is still accepted"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 4).unwrap(),
            BoundedLine::Eof
        );
    }

    #[test]
    fn http_over_cap_rejects_promptly_and_recovers() {
        let state = http_state(false);
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let search = Arc::new(SearchGuard::default());
        let confirm = Arc::new(ConfirmGuard::new());
        let inflight = Arc::new(AtomicUsize::new(0));

        // Hold every permit without creating 256 slow OS threads. The listener
        // sees exactly the same saturated counter it would see under real load.
        let mut guards: Vec<_> = (0..MAX_HTTP_INFLIGHT)
            .map(|_| {
                try_acquire_inflight(&inflight, MAX_HTTP_INFLIGHT)
                    .expect("permit under cap")
            })
            .collect();

        let listener_inflight = Arc::clone(&inflight);
        std::thread::spawn(move || {
            serve_http_loop_with_inflight(
                server,
                state,
                None,
                search,
                confirm,
                true,
                listener_inflight,
            )
        });
        std::thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        let rejected = http_get(port, "/");
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "over-cap response blocked the accept loop"
        );
        assert!(
            rejected.contains("503 Service Unavailable"),
            "unexpected over-cap response: {rejected}"
        );
        assert!(
            rejected.contains("Retry-After: 1"),
            "missing retry guidance: {rejected}"
        );

        // Once one request releases its permit, the next connection is handled
        // normally and the worker returns that permit when it finishes.
        drop(guards.pop());
        let recovered = http_get(port, "/");
        assert!(
            recovered.contains("200 OK") && recovered.contains("Toolport gateway"),
            "listener did not recover after a permit released: {recovered}"
        );
        drop(guards);
    }

    #[test]
    fn inflight_guard_caps_and_releases_workers() {
        let inflight = Arc::new(AtomicUsize::new(0));
        let guards: Vec<_> = (0..MAX_HTTP_INFLIGHT)
            .map(|_| {
                try_acquire_inflight(&inflight, MAX_HTTP_INFLIGHT)
                    .expect("permit under cap")
            })
            .collect();

        assert!(try_acquire_inflight(&inflight, MAX_HTTP_INFLIGHT).is_none());
        drop(guards);
        assert_eq!(inflight.load(Ordering::SeqCst), 0);
        assert!(try_acquire_inflight(&inflight, MAX_HTTP_INFLIGHT).is_some());
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
    fn insecure_loopback_requires_the_exact_cli_flag() {
        let args = vec![
            "toolport-gateway".to_string(),
            "--http".to_string(),
            "8765".to_string(),
            INSECURE_LOOPBACK_FLAG.to_string(),
        ];
        assert!(insecure_loopback_requested(&args));
        assert!(!insecure_loopback_requested(&[
            "toolport-gateway".to_string(),
            "--insecure".to_string(),
        ]));
    }

    #[test]
    fn http_bind_requires_auth_except_for_explicit_loopback_escape_hatch() {
        assert!(http_bind_is_authorized(true, true, false));
        assert!(http_bind_is_authorized(false, true, false));
        assert!(http_bind_is_authorized(true, false, true));
        assert!(!http_bind_is_authorized(true, false, false));
        assert!(!http_bind_is_authorized(false, false, false));
        assert!(!http_bind_is_authorized(false, false, true));
        assert!(http_allows_insecure_open(true, false, true));
        assert!(!http_allows_insecure_open(true, true, true));
        assert!(!http_allows_insecure_open(false, false, true));
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
        // Unscoped: everything passes. (`|_| None` = the router knows nothing, so scoping
        // falls back to the `server__` prefix heuristic.)
        assert_eq!(scope_tools(&tools, None, |_| None).len(), 3);
        // Scoped to vercel: its tool plus the meta-tool, never resend.
        let set: std::collections::HashSet<String> = ["vercel".to_string()].into_iter().collect();
        let names: Vec<String> = scope_tools(&tools, Some(&set), |_| None)
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(names.contains(&"vercel__deploy".to_string()));
        assert!(names.contains(&"toolport_search_tools".to_string()));
        assert!(!names.contains(&"resend__send".to_string()));
    }

    #[test]
    fn scope_tools_scopes_override_renamed_tool_via_router() {
        // A tool renamed via a ToolOverride to a non-namespaced name ("deploy") has no
        // `__`, so the prefix heuristic alone treats it as a meta-tool and leaks it to
        // every scoped client. The router's route_of gives its real server, so a client
        // that can't see that server never sees the tool's name or schema. (SOU-21)
        let tools = vec![
            json!({ "name": "deploy" }), // vercel tool renamed, no namespace
            json!({ "name": "resend__send" }),
            json!({ "name": "toolport_search_tools" }), // genuine meta-tool
        ];
        let route_of = |n: &str| match n {
            "deploy" => Some("vercel".to_string()),
            "resend__send" => Some("resend".to_string()),
            _ => None,
        };
        let set: std::collections::HashSet<String> = ["resend".to_string()].into_iter().collect();
        let names: Vec<String> = scope_tools(&tools, Some(&set), route_of)
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(names.contains(&"resend__send".to_string()), "in-scope server kept");
        assert!(names.contains(&"toolport_search_tools".to_string()), "meta-tool kept");
        assert!(
            !names.contains(&"deploy".to_string()),
            "renamed vercel tool must not leak to a resend-only client"
        );
    }

    #[test]
    fn scope_tools_drops_unknown_bare_name_when_router_misses() {
        // Cold/stale cache: route_of can't resolve a downstream tool renamed to a bare name
        // yet. It must NOT be treated as a meta-tool (that would leak it to every scoped
        // client) - only known gateway meta-tools survive a route_of miss. (SOU-21)
        let tools = vec![
            json!({ "name": "deploy" }), // renamed downstream tool, router hasn't indexed it
            json!({ "name": "toolport_status" }), // genuine gateway meta-tool
            json!({ "name": "vercel__ship" }), // namespaced, in scope
        ];
        let set: std::collections::HashSet<String> = ["vercel".to_string()].into_iter().collect();
        let names: Vec<String> = scope_tools(&tools, Some(&set), |_| None)
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(names.contains(&"toolport_status".to_string()), "known meta-tool kept");
        assert!(names.contains(&"vercel__ship".to_string()), "namespaced in-scope tool kept");
        assert!(
            !names.contains(&"deploy".to_string()),
            "unknown bare name must not leak during a cold cache"
        );
    }

    #[test]
    fn resolve_http_scope_auth_and_scope_policy() {
        let mut reg = Registry::default();
        // No auth configured at all -> open only under the explicit escape hatch.
        assert_eq!(resolve_http_scope(&reg, None, None, true), Some(None));
        assert_eq!(resolve_http_scope(&reg, None, None, false), None);
        // Legacy env token: exact match -> unscoped; mismatch -> rejected.
        assert_eq!(
            resolve_http_scope(&reg, Some("envtok"), Some("envtok"), false),
            Some(None)
        );
        assert!(resolve_http_scope(&reg, Some("envtok"), Some("nope"), false).is_none());
        // A registered client with an empty profile is authorized but unscoped.
        reg.http_clients.push(registry::HttpClient {
            id: "c1".into(),
            label: "full".into(),
            token_sha256: registry::sha256_hex("fulltok"),
            profile: String::new(),
        });
        assert_eq!(
            resolve_http_scope(&reg, None, Some("fulltok"), false),
            Some(None)
        );
        // Once any client is registered, an unknown/absent bearer is rejected
        // (the open default no longer applies).
        assert!(resolve_http_scope(&reg, None, Some("unknown"), false).is_none());
        assert!(resolve_http_scope(&reg, None, None, false).is_none());
        // A client scoped to a non-empty profile resolves to a (possibly empty)
        // allow-set; exact membership is covered by enabled_servers_for tests.
        reg.http_clients.push(registry::HttpClient {
            id: "c2".into(),
            label: "scoped".into(),
            token_sha256: registry::sha256_hex("scopedtok"),
            profile: "Default".into(),
        });
        assert!(matches!(
            resolve_http_scope(&reg, None, Some("scopedtok"), false),
            Some(Some(_))
        ));

        // Removing the last registered client while the gateway is live must not
        // turn an authenticated listener into an open one. Only immutable startup
        // policy from `--insecure-loopback` enables the fallback.
        let authenticated_startup_allows_open = http_allows_insecure_open(true, true, true);
        reg.http_clients.clear();
        assert!(resolve_http_scope(&reg, None, None, authenticated_startup_allows_open).is_none());
        let explicit_open_startup = http_allows_insecure_open(true, false, true);
        assert_eq!(
            resolve_http_scope(&reg, None, None, explicit_open_startup),
            Some(None)
        );
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
    fn http_session_owner_uses_stable_client_id_and_effective_scope() {
        let mut reg = Registry::default();
        let billing = reg.add_profile("Billing");
        reg.http_clients.push(registry::HttpClient {
            id: "c1".into(),
            label: "Open WebUI".into(),
            token_sha256: registry::sha256_hex("tok1"),
            profile: billing,
        });
        reg.http_clients.push(registry::HttpClient {
            id: "c2".into(),
            label: "Open WebUI".into(),
            token_sha256: registry::sha256_hex("tok2"),
            profile: String::new(),
        });

        let (_, first) = resolve_http_caller(&reg, None, Some("tok1"), false).unwrap();
        let (_, second) = resolve_http_caller(&reg, None, Some("tok2"), false).unwrap();
        assert_eq!(first.audit_label.as_deref(), Some("Open WebUI"));
        assert_eq!(second.audit_label.as_deref(), Some("Open WebUI"));
        assert_ne!(
            first.session_owner.identity, second.session_owner.identity,
            "duplicate display labels must not collapse distinct clients"
        );
        assert_eq!(first.session_owner.scope, Some(Vec::new()));
        assert_eq!(second.session_owner.scope, None);
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
                cwd: None,
                unknown_fields: serde_json::Map::new(),
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
    fn status_flags_enabled_servers_that_expose_no_tools() {
        let mut reg = Registry::default();
        for id in ["github", "atlassian"] {
            reg.servers.push(ServerEntry {
                id: id.into(),
                name: id.into(),
                transport: "http".into(),
                command: None,
                args: vec![],
                env: vec![],
                url: Some(format!("https://mcp.{id}.example/mcp")),
                source: None,
                disabled_tools: vec![],
                cwd: None,
                unknown_fields: serde_json::Map::new(),
            });
            reg.set_server_enabled("default", id, true).unwrap();
        }
        // Catalog has loaded (github contributed tools) but atlassian is silent -
        // the classic "connected but unauthed" case (e.g. OAuth not completed).
        let cached = vec![
            json!({ "name": "github__list_repos" }),
            json!({ "name": "github__create_issue" }),
        ];
        let out = enabled_summary(&reg, &cached, None, None);
        assert!(out.contains("github: 2 tool(s)"));
        assert!(out.contains("Enabled but exposing 0 tools"));
        // The silent server is named under the hint; the one with tools is not.
        let hint = out.split("Enabled but exposing 0 tools").nth(1).unwrap();
        assert!(hint.contains("atlassian"));
        assert!(!hint.contains("github"));
    }

    #[test]
    fn status_omits_zero_tool_hint_before_catalog_populates() {
        // Before any server has produced tools (empty catalog = still connecting),
        // the hint must stay silent - otherwise every server reads as "0 tools".
        let mut reg = Registry::default();
        reg.servers.push(ServerEntry {
            id: "github".into(),
            name: "github".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some("https://mcp.github.example/mcp".into()),
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        reg.set_server_enabled("default", "github", true).unwrap();
        let out = enabled_summary(&reg, &[], None, None);
        assert!(!out.contains("Enabled but exposing 0 tools"));
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
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "OPTIONS",
            "/toolport_search_tools",
            "",
            None,
            None,
            None,
            None,
        );
        assert_eq!(out.status, 204);
        assert!(out.body.is_empty());
    }

    fn mcp_session_of(out: &HttpOut) -> String {
        out.extra
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Mcp-Session-Id"))
            .map(|(_, v)| v.clone())
            .expect("Mcp-Session-Id header")
    }

    #[test]
    fn mcp_http_initialize_list_call_round_trip() {
        // Streamable-HTTP MCP: initialize → session id → tools/list → tools/call.
        let state = http_state(true);
        let search = SearchGuard::default();
        let confirm = ConfirmGuard::new();

        let init = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" }
                }
            })
            .to_string(),
            None,
            None,
            None,
            None,
        );
        assert_eq!(init.status, 200, "body={}", init.body);
        assert_eq!(init.ctype, "application/json");
        let sid = mcp_session_of(&init);
        assert!(valid_mcp_session_id(&sid));
        let init_body: Value = serde_json::from_str(&init.body).unwrap();
        assert_eq!(init_body["result"]["serverInfo"]["name"], "toolport-gateway");

        // Notification: 202, no JSON-RPC body.
        let note = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string(),
            Some(&sid),
            None,
            None,
            None,
        );
        assert_eq!(note.status, 202);

        let list = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
            Some(&sid),
            None,
            None,
            None,
        );
        assert_eq!(list.status, 200, "body={}", list.body);
        let list_body: Value = serde_json::from_str(&list.body).unwrap();
        let tools = list_body["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"toolport_status"));
        assert!(names.contains(&"toolport_search_tools"));

        let call = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": { "name": "toolport_status", "arguments": {} }
            })
            .to_string(),
            Some(&sid),
            None,
            None,
            None,
        );
        assert_eq!(call.status, 200, "body={}", call.body);
        let call_body: Value = serde_json::from_str(&call.body).unwrap();
        assert!(call_body.get("result").is_some());
        assert!(call_body.get("error").is_none());

        // Missing session on a non-initialize request → 400.
        let missing = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list" }).to_string(),
            None,
            None,
            None,
            None,
        );
        assert_eq!(missing.status, 400);

        // Unknown session → 404.
        let dead = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/list" }).to_string(),
            Some("deadbeefdeadbeefdeadbeefdeadbeef"),
            None,
            None,
            None,
        );
        assert_eq!(dead.status, 404);

        // DELETE tears the session down.
        let del = handle_http(
            &state,
            &search,
            &confirm,
            "DELETE",
            "/mcp",
            "",
            Some(&sid),
            None,
            None,
            None,
        );
        assert_eq!(del.status, 204);
        let after = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 6, "method": "tools/list" }).to_string(),
            Some(&sid),
            None,
            None,
            None,
        );
        assert_eq!(after.status, 404);
    }

    #[test]
    fn mcp_http_session_is_bound_to_client_identity_and_scope() {
        let state = http_state(true);
        let search = SearchGuard::default();
        let confirm = ConfirmGuard::new();
        let caller = |identity: &str, scope: &[&str]| HttpCaller {
            audit_label: Some(identity.to_string()),
            session_owner: McpSessionOwner {
                identity: identity.to_string(),
                scope: Some(scope.iter().map(|value| value.to_string()).collect()),
            },
        };
        let owner = caller("client:cursor", &["github"]);
        let intruder = caller("client:webui", &["github"]);
        let rescoped_owner = caller("client:cursor", &["github", "stripe"]);

        let init = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-06-18", "capabilities": {} }
            })
            .to_string(),
            None,
            None,
            None,
            Some(&owner),
        );
        assert_eq!(init.status, 200, "body={}", init.body);
        let sid = mcp_session_of(&init);
        let list_body = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
            .to_string();

        // A different authenticated identity cannot POST, listen, or delete.
        let wrong_post = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &list_body,
            Some(&sid),
            None,
            None,
            Some(&intruder),
        );
        assert_eq!(wrong_post.status, 404);
        let wrong_get = handle_http(
            &state,
            &search,
            &confirm,
            "GET",
            "/mcp",
            "",
            Some(&sid),
            Some("text/event-stream"),
            None,
            Some(&intruder),
        );
        assert_eq!(wrong_get.status, 404);
        let wrong_delete = handle_http(
            &state,
            &search,
            &confirm,
            "DELETE",
            "/mcp",
            "",
            Some(&sid),
            None,
            None,
            Some(&intruder),
        );
        assert_eq!(wrong_delete.status, 404);

        // The same client after a live scope change must also re-initialize.
        let wrong_scope = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &list_body,
            Some(&sid),
            None,
            None,
            Some(&rescoped_owner),
        );
        assert_eq!(wrong_scope.status, 404);

        // Refused attempts do not destroy the session; the original owner can
        // still use and then explicitly terminate it.
        let owner_post = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &list_body,
            Some(&sid),
            None,
            None,
            Some(&owner),
        );
        assert_eq!(owner_post.status, 200, "body={}", owner_post.body);
        let owner_delete = handle_http(
            &state,
            &search,
            &confirm,
            "DELETE",
            "/mcp",
            "",
            Some(&sid),
            None,
            None,
            Some(&owner),
        );
        assert_eq!(owner_delete.status, 204);
    }

    #[test]
    fn mcp_http_get_opens_listen_stream() {
        let state = http_state(true);
        let search = SearchGuard::default();
        let confirm = ConfirmGuard::new();
        let init = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" }
                }
            })
            .to_string(),
            None,
            None,
            None,
            None,
        );
        let sid = mcp_session_of(&init);
        let out = handle_http(
            &state,
            &search,
            &confirm,
            "GET",
            "/mcp",
            "",
            Some(&sid),
            Some("text/event-stream"),
            None,
            None,
        );
        assert_eq!(out.status, 200);
        assert_eq!(out.ctype, "text/event-stream");
        assert!(out.is_mcp_listen());
    }

    #[test]
    fn mcp_http_get_without_sse_accept_returns_406() {
        let state = http_state(true);
        let search = SearchGuard::default();
        let confirm = ConfirmGuard::new();
        let init = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" }
                }
            })
            .to_string(),
            None,
            None,
            None,
            None,
        );
        let sid = mcp_session_of(&init);
        let out = handle_http(
            &state,
            &search,
            &confirm,
            "GET",
            "/mcp",
            "",
            Some(&sid),
            Some("application/json"),
            None,
            None,
        );
        assert_eq!(out.status, 406);
    }

    #[test]
    fn mcp_push_server_message_queues_sse_payload() {
        let state = http_state(true);
        let sid = mint_mcp_session(&state, None).ok().unwrap();
        let msg = json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"});
        assert!(mcp_push_server_message(&state, &sid, &msg));
        let sessions = state.mcp_sessions.lock().unwrap();
        let session = sessions.get(&sid).unwrap();
        let mut reader = McpSseReader::new(Arc::clone(session));
        let mut buf = [0u8; 512];
        let n = reader.read(&mut buf).unwrap();
        assert!(n > 0);
        let chunk = String::from_utf8_lossy(&buf[..n]);
        assert!(chunk.contains("event: message"));
        assert!(chunk.contains("tools/list_changed"));
    }

    #[test]
    fn mcp_session_outbound_queue_is_bounded() {
        let session = McpSession::new(None);
        for i in 0..MCP_SESSION_OUTBOUND_MAX {
            assert!(session.push_message(
                json!({"jsonrpc":"2.0","method":"notifications/test","params":{"i":i}})
                    .to_string(),
                None,
            ));
        }
        assert!(!session.push_message(
            json!({"jsonrpc":"2.0","method":"notifications/overflow"}).to_string(),
            None,
        ));
        assert_eq!(session.outbound.lock().unwrap().len(), MCP_SESSION_OUTBOUND_MAX);
    }

    #[test]
    fn mcp_upstream_timeout_drops_undelivered_request() {
        let session = McpSession::new(None);
        let err = session
            .upstream_call_timeout("roots/list", json!({}), Duration::ZERO)
            .unwrap_err();
        assert_eq!(err, "upstream MCP client did not answer");
        assert!(session.outbound.lock().unwrap().is_empty());
        assert!(session.upstream_pending.lock().unwrap().is_empty());
    }

    #[test]
    fn mcp_upstream_call_fails_immediately_when_queue_is_full() {
        let session = McpSession::new(None);
        for _ in 0..MCP_SESSION_OUTBOUND_MAX {
            assert!(session.push_message("queued".to_string(), None));
        }
        let err = session
            .upstream_call_timeout("roots/list", json!({}), Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(err, "upstream MCP client outbound queue is full");
        assert!(session.upstream_pending.lock().unwrap().is_empty());
        assert_eq!(session.outbound.lock().unwrap().len(), MCP_SESSION_OUTBOUND_MAX);
    }

    #[test]
    fn mcp_http_get_without_session_returns_400() {
        let state = http_state(true);
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "GET",
            "/mcp",
            "",
            None,
            Some("text/event-stream"),
            None,
            None,
        );
        assert_eq!(out.status, 400);
    }

    #[test]
    fn mcp_http_bad_session_format_returns_400() {
        let state = http_state(true);
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 10, "method": "tools/list" }).to_string(),
            Some("bad\nvalue"),
            None,
            None,
            None,
        );
        assert_eq!(out.status, 400);
    }

    #[test]
    fn mcp_http_delete_without_session_returns_400() {
        let state = http_state(true);
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "DELETE",
            "/mcp",
            "",
            None,
            None,
            None,
            None,
        );
        assert_eq!(out.status, 400);
    }

    #[test]
    fn mcp_prefers_sse_only_when_event_stream_wins() {
        // Spec clients list both; keep JSON as the default in that case.
        assert!(!mcp_prefers_sse(None));
        assert!(!mcp_prefers_sse(Some(
            "application/json, text/event-stream"
        )));
        assert!(!mcp_prefers_sse(Some("application/json")));
        assert!(mcp_prefers_sse(Some("text/event-stream")));
        assert!(mcp_prefers_sse(Some(
            "text/event-stream;q=1, application/json;q=0.5"
        )));
        assert!(!mcp_prefers_sse(Some(
            "application/json;q=1, text/event-stream;q=0.8"
        )));
        assert!(!mcp_prefers_sse(Some("text/event-stream;q=0")));
    }

    #[test]
    fn mcp_http_options_preflight_returns_204() {
        let state = http_state(true);
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "OPTIONS",
            "/mcp",
            "",
            None,
            None,
            None,
            None,
        );
        assert_eq!(out.status, 204);
    }

    #[test]
    fn mcp_http_sse_when_accept_prefers_event_stream() {
        let state = http_state(true);
        let search = SearchGuard::default();
        let confirm = ConfirmGuard::new();
        let init = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" }
                }
            })
            .to_string(),
            None,
            Some("text/event-stream"),
            None,
            None,
        );
        assert_eq!(init.status, 200, "body={}", init.body);
        assert_eq!(init.ctype, "text/event-stream");
        assert!(
            init.body.starts_with("event: message\ndata: "),
            "{}",
            init.body
        );
        assert!(init.body.contains("\"serverInfo\""));
        let sid = mcp_session_of(&init);
        // Dual Accept (spec default) stays JSON.
        let list = handle_http(
            &state,
            &search,
            &confirm,
            "POST",
            "/mcp",
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }).to_string(),
            Some(&sid),
            Some("application/json, text/event-stream"),
            None,
            None,
        );
        assert_eq!(list.ctype, "application/json");
        assert!(list.body.starts_with('{'));
    }

    #[test]
    fn docs_mention_mcp_endpoint() {
        let state = http_state(true);
        let out = handle_http(
            &state,
            &SearchGuard::default(),
            &ConfirmGuard::new(),
            "GET",
            "/",
            "",
            None,
            None,
            None,
            None,
        );
        assert_eq!(out.status, 200);
        assert!(out.body.contains("POST /mcp"), "body={}", out.body);
        assert!(out.body.contains("/openapi.json"));
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
            cwd: None,
            unknown_fields: serde_json::Map::new(),
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

    /// Data-driven recall measurement (not a pass/fail unit test): set
    /// STRIPE_TOOLS_JSON + STRIPE_INTENTS_JSON to fixture paths and run with
    /// `--nocapture` to print recall@k of the REAL lexical ranker over a generated
    /// tool set. No-ops (passes) when the env vars are unset, so CI is unaffected.
    #[test]
    fn recall_report() {
        let (Ok(tp), Ok(ip)) = (
            std::env::var("STRIPE_TOOLS_JSON"),
            std::env::var("STRIPE_INTENTS_JSON"),
        ) else {
            return;
        };
        let server = std::env::var("RECALL_SERVER").unwrap_or_else(|_| "stripe".into());
        let limit: usize = std::env::var("RECALL_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(25);
        let tools: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(&tp).unwrap()).unwrap();
        let intents: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(&ip).unwrap()).unwrap();
        let (mut r5, mut r10, mut r25) = (0usize, 0usize, 0usize);
        let mut misses: Vec<String> = Vec::new();
        println!(
            "\n=== recall @ limit {limit} over {} tools, {} intents (server={server}) ===",
            tools.len(),
            intents.len()
        );
        for it in &intents {
            let q = it["q"].as_str().unwrap_or("");
            let oks: Vec<&str> = it["ok"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let (hits, total) = search_catalog(&tools, q, Some(server.as_str()), limit);
            let names: Vec<&str> = hits
                .iter()
                .filter_map(|h| h.get("name").and_then(|v| v.as_str()))
                .collect();
            let rank = oks
                .iter()
                .filter_map(|o| names.iter().position(|n| n == o))
                .min();
            match rank {
                Some(r) => {
                    if r < 5 {
                        r5 += 1;
                    }
                    if r < 10 {
                        r10 += 1;
                    }
                    r25 += 1;
                    println!("  #{:<2} {:<34} -> {}", r + 1, q, names[r]);
                }
                None => {
                    misses.push(q.to_string());
                    println!(
                        "  MISS   {:<34} (matched {total} tools; target not in top {limit})",
                        q
                    );
                }
            }
        }
        let n = intents.len().max(1) as f64;
        println!(
            "\n  recall@5:  {r5}/{}  ({:.0}%)\n  recall@10: {r10}/{}  ({:.0}%)\n  recall@{limit}: {r25}/{}  ({:.0}%)",
            intents.len(),
            100.0 * r5 as f64 / n,
            intents.len(),
            100.0 * r10 as f64 / n,
            intents.len(),
            100.0 * r25 as f64 / n
        );
        if !misses.is_empty() {
            println!("  misses: {misses:?}");
        }
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
    fn search_query_bounds_are_enforced_before_ranking() {
        assert!(validate_search_query(&"x".repeat(MAX_SEARCH_QUERY_CHARS)).is_ok());
        assert!(validate_search_query(&"x".repeat(MAX_SEARCH_QUERY_CHARS + 1)).is_err());

        let sixty_four_tokens = std::iter::repeat("x")
            .take(MAX_SEARCH_QUERY_TOKENS)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(validate_search_query(&sixty_four_tokens).is_ok());
        let sixty_five_tokens = format!("{sixty_four_tokens} x");
        assert!(validate_search_query(&sixty_five_tokens).is_err());

        let call = |query: &str| {
            handle_request(
                &search_req(query),
                &Registry::default(),
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

        let char_limit_resp = call(&"x".repeat(MAX_SEARCH_QUERY_CHARS + 1));
        assert_eq!(char_limit_resp["result"]["isError"], true);
        assert!(char_limit_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("512-character limit"));

        let token_limit_resp = call(&sixty_five_tokens);
        assert_eq!(token_limit_resp["result"]["isError"], true);
        assert!(token_limit_resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("64-token limit"));
        assert_eq!(
            search_tool_def()["inputSchema"]["properties"]["query"]["maxLength"],
            MAX_SEARCH_QUERY_CHARS
        );
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
    fn grouped_mode_advertises_meta_plus_per_server_help() {
        // The catalog: two servers, github with 2 tools, stripe with 1.
        let catalog = vec![
            json!({ "name": "github__create_issue", "description": "Create an issue", "inputSchema": {} }),
            json!({ "name": "github__list_repos", "description": "List repos", "inputSchema": {} }),
            json!({ "name": "stripe__create_charge", "description": "Create a charge", "inputSchema": {} }),
        ];
        let defs = grouped_tool_defs(false, false, &catalog);
        let names: Vec<&str> = defs
            .iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
            .collect();
        // The lazy meta-tools are present (so search/call still work)...
        for m in [
            "toolport_status",
            "toolport_search_tools",
            "toolport_call_tool",
            "toolport_fetch_result",
        ] {
            assert!(names.contains(&m), "missing meta-tool {m}");
        }
        // ...plus one enumerable browse tool per server, in first-seen order...
        assert!(names.contains(&"help_github"));
        assert!(names.contains(&"help_stripe"));
        assert!(
            names.iter().position(|n| *n == "help_github")
                < names.iter().position(|n| *n == "help_stripe"),
            "help tools keep first-seen order"
        );
        // ...and NOT the raw namespaced tools (that's what full mode would dump).
        assert!(!names.iter().any(|n| n.contains("__")));
        // The github help tool states its tool count so the model knows the scope.
        let gh = defs.iter().find(|t| t["name"] == "help_github").unwrap();
        assert!(gh["description"].as_str().unwrap().contains("2 tool"));
        // Agent-control and confirm tools stay gated off when their flags are off.
        assert!(!names.contains(&"toolport_enable_server"));
        assert!(!names.contains(&"toolport_confirm"));
    }

    #[test]
    fn grouped_mode_gates_agent_and_confirm_tools() {
        let catalog = vec![
            json!({ "name": "s__t", "description": "x", "inputSchema": {} }),
        ];
        let defs = grouped_tool_defs(true, true, &catalog);
        let names: Vec<&str> = defs
            .iter()
            .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
            .collect();
        assert!(names.contains(&"toolport_enable_server"));
        assert!(names.contains(&"toolport_disable_server"));
        assert!(names.contains(&"toolport_confirm"));
        assert!(names.contains(&"help_s"));
    }

    #[test]
    fn distinct_server_prefixes_dedups_in_first_seen_order() {
        let catalog = vec![
            json!({ "name": "b__one", "inputSchema": {} }),
            json!({ "name": "a__one", "inputSchema": {} }),
            json!({ "name": "b__two", "inputSchema": {} }),
            json!({ "name": "toolport_status", "inputSchema": {} }), // bare name -> no prefix
        ];
        assert_eq!(
            distinct_server_prefixes(&catalog),
            vec!["b".to_string(), "a".to_string()]
        );
    }

    #[test]
    fn grouped_help_target_extracts_server_prefix() {
        assert_eq!(grouped_help_target("help_github"), Some("github"));
        assert_eq!(grouped_help_target("help_a__b"), Some("a__b"));
        assert_eq!(grouped_help_target("toolport_status"), None);
        assert_eq!(grouped_help_target("help_"), None);
        assert_eq!(grouped_help_target("github__create"), None);
    }

    #[test]
    fn discovery_mode_precedence_and_no_regression() {
        use DiscoveryMode::*;
        // Args: (env, client_mode, registry_mode, lazy_discovery).
        // A hand-set env override wins over everything, including the per-client override.
        assert_eq!(resolve_mode_from(Some("grouped"), Some("lazy"), Some("lazy"), true), Grouped);
        assert_eq!(resolve_mode_from(Some("lazy"), None, None, false), Lazy);
        assert_eq!(resolve_mode_from(Some("full"), Some("lazy"), Some("grouped"), true), Full);
        assert_eq!(resolve_mode_from(Some(" GROUPED "), None, None, true), Grouped);
        // Old behavior preserved: a SET-but-unrecognized/empty env is Full (was the
        // `env == "lazy" ? lazy : not-lazy` branch), NOT a fall-through.
        assert_eq!(resolve_mode_from(Some("typo"), None, Some("grouped"), true), Full);
        assert_eq!(resolve_mode_from(Some(""), None, Some("grouped"), true), Full);

        // No env: the PER-CLIENT override wins over the global mode and the bool.
        assert_eq!(resolve_mode_from(None, Some("grouped"), Some("full"), true), Grouped);
        assert_eq!(resolve_mode_from(None, Some("full"), None, true), Full);
        assert_eq!(resolve_mode_from(None, Some("lazy"), Some("grouped"), false), Lazy);
        // An `inherit`/empty/unrecognized per-client value falls through to the global mode.
        assert_eq!(resolve_mode_from(None, Some("inherit"), Some("grouped"), true), Grouped);
        assert_eq!(resolve_mode_from(None, Some("weird"), None, true), Lazy);

        // No env, no per-client: the global registry override wins over the bool.
        assert_eq!(resolve_mode_from(None, None, Some("grouped"), true), Grouped);
        assert_eq!(resolve_mode_from(None, None, Some("full"), true), Full);
        assert_eq!(resolve_mode_from(None, None, Some("lazy"), false), Lazy);
        // An unrecognized global override is ignored, falling through to the bool.
        assert_eq!(resolve_mode_from(None, None, Some("weird"), true), Lazy);

        // BACK-COMPAT: no env, no override anywhere resolves to exactly the old bool.
        assert_eq!(resolve_mode_from(None, None, None, true), Lazy);
        assert_eq!(resolve_mode_from(None, None, None, false), Full);
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
            json!({ "name": "stripe__list_disputes", "description": "List disputes", "inputSchema": {} }),
            json!({ "name": "stripe__create_token", "description": "Create a token", "inputSchema": {} }),
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

        // Domain synonyms surfaced by the recall benchmark: "chargeback" == dispute,
        // and "tokenize" bridges to a "token" tool.
        let (hits, _) = search_catalog(&cat, "chargeback", None, 10);
        assert_eq!(hits[0]["name"], "stripe__list_disputes");
        let (hits, _) = search_catalog(&cat, "tokenize", None, 10);
        assert_eq!(hits[0]["name"], "stripe__create_token");
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
        let token = guard.store(
            "srv__delete".into(),
            json!({"id": "x"}),
            Some("cursor"),
        );
        // First take succeeds.
        let (name, args) = guard.take(&token, Some("cursor")).unwrap();
        assert_eq!(name, "srv__delete");
        assert_eq!(args["id"], "x");
        // Second take fails (token consumed).
        assert!(
            guard.take(&token, Some("cursor")).is_none(),
            "token should be single-use"
        );
    }

    #[test]
    fn confirm_destructive_token_is_client_scoped_and_does_not_loop() {
        // The critical test: a destructive call is intercepted, then confirmed
        // via toolport_confirm. A different client cannot redeem or consume it,
        // and the rightful owner's confirmed call must NOT be re-intercepted.
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
            Some("cursor"),
        )
        .unwrap();
        let text1 = resp1["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text1.contains("Destructive action intercepted"));

        // Extract the token from the preview message.
        let token_start = text1.find("token: ").unwrap() + 7;
        let token = &text1[token_start..token_start + 32];

        // Step 2: a different client cannot redeem the token.
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
            Some("claude"),
        )
        .unwrap();
        let text2 = resp2["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text2.contains("expired or invalid"),
            "another client must not redeem the token: {text2}"
        );

        // Step 3: the wrong-client attempt did not consume the token, so its
        // owner can still confirm. This falls through to normal routing and is
        // NOT re-intercepted.
        let resp3 = handle_request(
            &req2,
            &reg,
            &router(),
            &cat,
            true,
            None,
            &SearchGuard::default(),
            &confirm,
            None,
            Some("cursor"),
        )
        .unwrap();
        let text3 = resp3["result"]["content"][0]["text"].as_str().unwrap();
        // The confirmed call reached the router (which doesn't have a real
        // stripe server, so it errors), but the important thing is it was NOT
        // re-intercepted.
        assert!(
            !text3.contains("Destructive action intercepted"),
            "confirmed call must not be re-intercepted (would loop). Got: {text3}"
        );
    }
}
