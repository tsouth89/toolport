//! Tool router.
//!
//! Aggregates the tools of every connected downstream server into one list the
//! gateway exposes upward, namespacing each tool by its server id so names can't
//! collide. Routing a call maps the exposed name back to its owning server and
//! that server's original tool name.
//!
//! Exposed names are sanitized to `[A-Za-z0-9_]`. MCP allows hyphens in tool
//! names, but clients like Cursor enforce the OpenAI function-name charset and
//! silently drop any tool whose name (server id included) contains a hyphen - so
//! `revenuecat-rigcast__list-offerings` would never appear. We rewrite hyphens
//! (and anything else out of charset) to `_` on the way out, and keep a reverse
//! map so `tools/call` still forwards the server's real, hyphenated tool name.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::downstream::{
    backoff_delay, CancelContext, DownstreamServer, TransportError, HTTP_MAX_RETRIES,
    HTTP_RETRY_CAP,
};
use crate::registry::ToolOverride;

/// The delay before a retry attempt. Prefers a server-advertised `Retry-After`,
/// else our exponential backoff, but never longer than `HTTP_RETRY_CAP` so a
/// downstream advertising `Retry-After: 3600` can't pin the calling agent's
/// thread. Retries are bounded, so if the server is still limiting past the cap
/// the loop exhausts and surfaces the error to the caller.
fn retry_wait(retry_after: Option<std::time::Duration>, attempt: u32) -> std::time::Duration {
    retry_after
        .unwrap_or_else(|| backoff_delay(attempt))
        .min(HTTP_RETRY_CAP)
}

/// Rewrite a name segment to the function-name charset clients accept
/// (`[A-Za-z0-9_]`); every other character becomes `_`.
pub fn sanitize_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Inline local `$ref` pointers into a self-contained JSON Schema, so a downstream
/// consumer that can't resolve refs gets a complete schema. Handles `#/$defs/X`,
/// `#/definitions/X`, AND any in-document JSON Pointer (`#/properties/a/b`, which
/// real servers like revenuecat use to share subschemas). mcpo (the MCP-to-OpenAPI
/// proxy OpenWebUI uses) aborts with "Custom field not found" on an unresolved
/// `$ref`, so one such server would otherwise break the whole full-discovery bridge.
/// Refs resolve against a snapshot of the original schema; a recursive or otherwise
/// unresolvable ref collapses to a permissive `{}`, so the output is always ref-free.
pub fn inline_refs(schema: &mut Value) {
    if !has_ref(schema) {
        return;
    }
    let root = schema.clone();
    let mut active = HashSet::new();
    inline_node(schema, &root, &mut active);
    if let Some(obj) = schema.as_object_mut() {
        obj.remove("$defs");
        obj.remove("definitions");
    }
}

/// True if `node` contains a `$ref` anywhere, so we can skip the clone otherwise.
fn has_ref(node: &Value) -> bool {
    match node {
        Value::Object(map) => map.contains_key("$ref") || map.values().any(has_ref),
        Value::Array(arr) => arr.iter().any(has_ref),
        _ => false,
    }
}

/// Replace a `{"$ref": "#/..."}` node with a copy of what that JSON Pointer resolves
/// to in `root` (itself inlined). `active` holds the ref strings currently expanding;
/// a ref into one (a cycle), an external ref (no `#` prefix), or an unresolvable
/// pointer collapses to a permissive `{}` so NO `$ref` ever leaks to a consumer that
/// can't resolve it. Cycles thus terminate with a wildcard rather than recursing.
fn inline_node(node: &mut Value, root: &Value, active: &mut HashSet<String>) {
    let ref_str = node.get("$ref").and_then(|v| v.as_str()).map(str::to_string);
    if let Some(r) = ref_str {
        let mut resolved = None;
        if let Some(ptr) = r.strip_prefix('#') {
            if !active.contains(&r) {
                if let Some(target) = root.pointer(ptr).cloned() {
                    let mut sub = target;
                    active.insert(r.clone());
                    inline_node(&mut sub, root, active);
                    active.remove(&r);
                    resolved = Some(sub);
                }
            }
        }
        *node = resolved.unwrap_or_else(|| json!({}));
        return;
    }
    match node {
        Value::Object(map) => {
            for v in map.values_mut() {
                inline_node(v, root, active);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                inline_node(v, root, active);
            }
        }
        _ => {}
    }
}

/// True if a tool advertises `destructiveHint: true` (MCP tool annotations), or
/// has an obvious write/delete verb when no explicit hint is present. Accepts the
/// spec's nested `annotations.destructiveHint` and a top-level fallback some
/// servers emit. An explicit `false` hint wins over the name fallback.
pub fn is_destructive(tool: &Value) -> bool {
    if let Some(hint) = tool
        .get("annotations")
        .and_then(|a| a.get("destructiveHint"))
        .and_then(|v| v.as_bool())
        .or_else(|| tool.get("destructiveHint").and_then(|v| v.as_bool()))
    {
        return hint;
    }

    tool.get("name")
        .and_then(Value::as_str)
        .map(name_looks_destructive)
        .unwrap_or(false)
}

fn name_looks_destructive(name: &str) -> bool {
    let mut tokens = name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .flat_map(split_camel_lower);
    tokens.any(|t| {
        matches!(
            t.as_str(),
            "create"
                | "delete"
                | "destroy"
                | "drop"
                | "execute"
                | "insert"
                | "move"
                | "patch"
                | "post"
                | "publish"
                | "remove"
                | "rename"
                | "replace"
                | "run"
                | "send"
                | "truncate"
                | "update"
                | "upload"
                | "write"
        )
        // `edit`/`modify` are deliberately omitted: they overlap with the benign
        // description-churn class that integrity drift tiering keeps quiet (see
        // `drift_severity_tiers_loud_vs_benign`), and widening them there would
        // trade the alert-fatigue win for louder, lower-signal drift alerts.
    })
}

fn split_camel_lower(word: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = word.char_indices().collect();
    for window in chars.windows(2) {
        let (idx, ch) = window[0];
        let (_, next) = window[1];
        if idx > start && ch.is_ascii_lowercase() && next.is_ascii_uppercase() {
            out.push(word[start..idx + ch.len_utf8()].to_ascii_lowercase());
            start = idx + ch.len_utf8();
        }
    }
    if start < word.len() {
        out.push(word[start..].to_ascii_lowercase());
    }
    out
}

/// Which downstream tools the gateway is allowed to expose. Default-allow: an
/// empty policy passes everything. This is the enforcement point behind the
/// per-tool toggle and the global destructive-tool deny switch.
#[derive(Default, Clone)]
pub struct ToolPolicy {
    /// server id -> original tool names the user switched off.
    pub disabled: HashMap<String, HashSet<String>>,
    /// server id -> the ONLY original tool names the active profile exposes (tool-granular
    /// scoping / "FeatureSet"). A server present here allow-lists: every other tool on it is
    /// hidden and blocked. A server ABSENT exposes all of its tools. Empty = no tool-granular
    /// scoping, so this is fully backward compatible.
    pub allow: HashMap<String, HashSet<String>>,
    /// Hide and block any tool annotated `destructiveHint: true`.
    pub deny_destructive: bool,
    /// Exposed (namespaced) tool names quarantined after a high-risk drift; hidden
    /// until the user re-approves them. Empty unless quarantine-on-drift is enabled.
    pub quarantined: BTreeSet<String>,
}

impl ToolPolicy {
    /// Reason this tool is blocked, or `None` if it may be exposed. `exposed` is the
    /// namespaced client-facing name (what quarantine is keyed by).
    fn blocked_reason(
        &self,
        exposed: &str,
        server_id: &str,
        orig: &str,
        tool: &Value,
    ) -> Option<&'static str> {
        if self
            .disabled
            .get(server_id)
            .is_some_and(|set| set.contains(orig))
        {
            return Some("disabled");
        }
        // Tool-granular profile scope: if this server is narrowed to an allow-list, a tool
        // not on it is outside the active profile's scope (hidden + blocked, same as disabled).
        if self
            .allow
            .get(server_id)
            .is_some_and(|set| !set.contains(orig))
        {
            return Some("outside the active profile's tool scope");
        }
        if self.deny_destructive && is_destructive(tool) {
            return Some("blocked by the destructive-tool policy");
        }
        if self.quarantined.contains(exposed) {
            return Some("quarantined after a high-risk change; re-approve to restore");
        }
        None
    }
}

/// One connected downstream server behind its own lock. A call to it only blocks
/// other calls to the SAME server (a single stdio pipe is one-in-flight by
/// design), never calls to other servers. Held as an `Arc` so an in-flight call
/// can keep the slot (and its live child process) alive across the downstream I/O
/// without holding the router lock, and survive a concurrent router replacement.
struct ServerSlot {
    id: String,
    inner: Mutex<DownstreamServer>,
    /// Fast-fail state for a server that keeps failing (dead/hung), so we don't pay
    /// its full read timeout on every call once it's clearly down.
    breaker: Mutex<Breaker>,
    /// Rebuild this server's connection from scratch (re-spawn a crashed stdio child
    /// / re-dial a dropped remote). Invoked only on the breaker's half-open probe,
    /// i.e. after the server has failed for a full cooldown, so a live server is never
    /// needlessly re-spawned on a transient blip. `None` = not reconnectable (e.g. a
    /// test fixture), in which case a dead server just stays fast-failed as before.
    reconnect: Option<Reconnect>,
}

/// Factory that rebuilds a downstream connection on demand. Supplied by the gateway
/// (which owns the registry + secret injection) so `router` stays free of spawn logic;
/// returns `None` if the server still can't be reached.
pub type Reconnect = Box<dyn Fn() -> Option<DownstreamServer> + Send + Sync>;

/// After this many consecutive health failures, a server's circuit opens.
const BREAKER_FAILURE_THRESHOLD: u32 = 3;
/// How long a tripped circuit stays open before one probe call is let through.
const BREAKER_COOLDOWN: Duration = Duration::from_secs(20);

/// Per-server circuit breaker. Once a server racks up consecutive health failures
/// (timeouts / dead connections), the circuit opens and calls fast-fail for a
/// cooldown instead of each one waiting out the read timeout and piling up worker
/// threads. `now` is passed in so the transitions are unit-testable without sleeping.
#[derive(Default)]
struct Breaker {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

impl Breaker {
    /// Remaining open time if the circuit is tripped at `now`. A circuit whose
    /// cooldown has elapsed transitions to half-open here (clears `open_until` and
    /// returns `None`) so the next call probes the server.
    fn open_remaining(&mut self, now: Instant) -> Option<Duration> {
        match self.open_until {
            Some(t) if now < t => Some(t - now),
            Some(_) => {
                self.open_until = None;
                None
            }
            None => None,
        }
    }

    /// A successful call closes the circuit and clears the failure streak.
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    /// A health failure; opens the circuit once the streak hits the threshold.
    fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= BREAKER_FAILURE_THRESHOLD {
            self.open_until = Some(now + BREAKER_COOLDOWN);
        }
    }
}

/// Cloneable so the dispatcher can hold the live router as a `Mutex<Arc<Router>>`,
/// clone the `Arc` for a request, and release the lock BEFORE the (possibly
/// long-blocking) downstream call or human-approval hold. Cloning shares the
/// `Arc<ServerSlot>` connections, so it never re-spawns a server.
#[derive(Default, Clone)]
pub struct Router {
    servers: Vec<Arc<ServerSlot>>,
    /// Server id -> index into `servers`, so a call resolves its server without a
    /// linear scan and without locking any server to read its id.
    by_id: HashMap<String, usize>,
    /// Exposed (client-facing) tools, names already sanitized, in add order.
    tools: Vec<Value>,
    /// Exposed tool name -> (server id, original downstream tool name).
    routes: HashMap<String, (String, String)>,
    /// Exposed names already handed out, for collision disambiguation.
    seen: HashSet<String>,
    /// What may be exposed; applied as each server is added.
    policy: ToolPolicy,
    /// Per-tool exposure overrides (rename / re-describe), keyed by server id then ORIGINAL
    /// tool name (NOT the exposed name, so a rename or a `_2` collision suffix can't
    /// misalign the key). Applied while indexing; the route still points at the real
    /// downstream tool, so a rename never changes where a call goes.
    overrides: HashMap<String, HashMap<String, ToolOverride>>,
    /// Exposed name -> why it's hidden, for a clear message if a hidden tool is
    /// still called by name (e.g. via conduit_call_tool).
    blocked: HashMap<String, String>,
    /// Aggregated resources, passed through as-is (uris are server-scoped).
    resources: Vec<Value>,
    /// Resource uri -> owning server id (for resources/read).
    resource_routes: HashMap<String, String>,
    /// Aggregated prompts, names namespaced like tools.
    prompts: Vec<Value>,
    /// Exposed prompt name -> (server id, original prompt name).
    prompt_routes: HashMap<String, (String, String)>,
}

impl Router {
    pub fn new() -> Self {
        Router::default()
    }

    /// A router that enforces `policy` as servers are added.
    pub fn with_policy(policy: ToolPolicy) -> Self {
        Router {
            policy,
            ..Router::default()
        }
    }

    /// Set the per-tool exposure overrides. Must be called BEFORE `add`/`refresh`, since
    /// they're applied while indexing each server's tools.
    pub fn set_overrides(&mut self, overrides: HashMap<String, HashMap<String, ToolOverride>>) {
        self.overrides = overrides;
    }

    /// The real `(server id, original tool name)` an exposed name routes to, or `None` if
    /// unknown. Callers that need a call's provenance or server-scoping MUST use this rather
    /// than string-splitting the exposed name on `__` — that split silently mis-derives the
    /// server for a renamed tool (overrides) or any server id containing `__`.
    pub fn route_of(&self, exposed: &str) -> Option<(&str, &str)> {
        self.routes.get(exposed).map(|(s, t)| (s.as_str(), t.as_str()))
    }

    /// Index one server's advertised tools/resources/prompts into the exposed
    /// aggregation (names, routes, policy). Shared by `add` (a new server) and
    /// `rebuild_aggregation` (after a refresh). Within a server, `_2` collision
    /// suffixes are allocated by raw name rather than list position, so neither
    /// the call order nor a downstream reordering its own catalog can move them
    /// (see [`allocate_exposed_names`](Self::allocate_exposed_names)).
    fn index_server(
        &mut self,
        server_id: &str,
        tools: &[Value],
        resources: &[Value],
        prompts: &[Value],
    ) {
        // Allocate the exposed name regardless of policy so toggling one tool
        // never renames its siblings (their `_2` suffixes stay put), and in an
        // order that doesn't depend on how the server happened to list them.
        let tool_names = self.allocate_exposed_names(server_id, tools);
        for (idx, tool) in tools.iter().enumerate() {
            let Some(orig) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let base = tool_names[idx]
                .clone()
                .expect("a tool with a name always gets an allocated exposed name");
            // Apply the user's exposure override (keyed by the ORIGINAL name) BEFORE
            // evaluating policy, so the quarantine check (keyed by the client-facing
            // name) sees the SAME name the client will call. Evaluating it on the
            // pre-rename base name meant a renamed tool could never be quarantined, and
            // the app would show it quarantined while the gateway kept routing it (#423).
            // Cloned to owned so we don't hold a borrow of `self.overrides` across the
            // `self.seen` mutation below. A rename that is empty or would collide with an
            // existing exposed name is ignored (keep the base) so routing stays
            // unambiguous. Both the base name (reserved by allocate_exposed_names) and the
            // rename's own slot stay reserved in `seen`, even when the tool ends up
            // blocked, so neither can be reused by a sibling's `_2` suffix.
            let ov = self.overrides.get(server_id).and_then(|m| m.get(orig));
            let ov_name = ov.and_then(|o| o.name.clone());
            let ov_desc = ov.and_then(|o| o.description.clone());
            let exposed = match ov_name {
                Some(new) => {
                    let cand = sanitize_segment(&new);
                    if !cand.is_empty() && self.seen.insert(cand.clone()) {
                        cand
                    } else {
                        base
                    }
                }
                None => base,
            };
            // Policy: disabled / scope / destructive gate on the ORIGINAL downstream
            // name (server_id + orig); quarantine gates on the final exposed name.
            if let Some(reason) = self.policy.blocked_reason(&exposed, server_id, orig, tool) {
                self.blocked.insert(exposed, reason.to_string());
                continue;
            }
            let mut t = tool.clone();
            if let Some(desc) = ov_desc {
                t["description"] = json!(desc);
            }
            t["name"] = json!(exposed);
            if let Some(schema) = t.get_mut("inputSchema") {
                inline_refs(schema);
            }
            self.tools.push(t);
            self.routes
                .insert(exposed, (server_id.to_string(), orig.to_string()));
        }

        // Resources: pass uris through unchanged (they're already server-scoped)
        // and remember which server owns each, so resources/read can reach it.
        for resource in resources {
            if let Some(uri) = resource.get("uri").and_then(|u| u.as_str()) {
                self.resources.push(resource.clone());
                self.resource_routes
                    .insert(uri.to_string(), server_id.to_string());
            }
        }

        // Prompts: namespace names like tools so two servers can't collide, and
        // allocate them in the same order-independent way.
        let prompt_names = self.allocate_exposed_names(server_id, prompts);
        for (idx, prompt) in prompts.iter().enumerate() {
            let Some(orig) = prompt.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let exposed = prompt_names[idx]
                .clone()
                .expect("a prompt with a name always gets an allocated exposed name");
            let mut p = prompt.clone();
            p["name"] = json!(exposed);
            self.prompts.push(p);
            self.prompt_routes
                .insert(exposed, (server_id.to_string(), orig.to_string()));
        }
    }

    pub fn add(&mut self, server: DownstreamServer) {
        self.add_with_reconnect(server, None);
    }

    /// Add a server whose connection can be rebuilt on demand (see [`Reconnect`]). The
    /// router re-spawns it automatically if it dies mid-session; `add` is the
    /// non-reconnectable variant kept for tests and callers with no factory.
    pub fn add_with_reconnect(&mut self, server: DownstreamServer, reconnect: Option<Reconnect>) {
        let id = server.id.clone();
        self.index_server(&id, &server.tools, &server.resources, &server.prompts);
        let idx = self.servers.len();
        self.servers.push(Arc::new(ServerSlot {
            id: id.clone(),
            inner: Mutex::new(server),
            breaker: Mutex::new(Breaker::default()),
            reconnect,
        }));
        self.by_id.insert(id, idx);
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Allocate exposed names for one server's `items` (tools or prompts),
    /// returned positionally so the caller keeps the server's own catalog order.
    ///
    /// Names are handed out in order of the item's RAW name rather than the order
    /// the server listed them in. Two names that sanitize to the same string
    /// (`get-user` and `get_user`) collide, and the loser takes a `_2` suffix;
    /// allocating in list order meant a downstream that reordered its
    /// `tools/list` across a refresh swapped that suffix between two real tools.
    /// The client's cached name then pointed at the *other* tool, so calls kept
    /// working and silently went somewhere new. Sorting on the raw name makes the
    /// assignment a property of the tools themselves, so list order can't move it.
    ///
    /// Cross-server collisions can't arise here: server ids are slugified to
    /// `[a-z0-9-]` and `sanitize_segment` only maps `-` to `_`, which is injective
    /// over that alphabet. So the contested namespace is always within one server.
    fn allocate_exposed_names(&mut self, server_id: &str, items: &[Value]) -> Vec<Option<String>> {
        fn raw_name(item: &Value) -> Option<&str> {
            item.get("name").and_then(|n| n.as_str())
        }
        let mut order: Vec<usize> = (0..items.len()).collect();
        // Ties (a server listing the same raw name twice) fall back to list
        // position, which keeps the sort total and the result reproducible.
        order.sort_by(|&a, &b| raw_name(&items[a]).cmp(&raw_name(&items[b])).then(a.cmp(&b)));
        let mut out = vec![None; items.len()];
        for i in order {
            if let Some(orig) = raw_name(&items[i]) {
                out[i] = Some(self.exposed_name(server_id, orig));
            }
        }
        out
    }

    /// Allocate a unique exposed name for `server_id`'s `tool`, sanitizing both
    /// halves and suffixing `_2`, `_3`, ... if two distinct tools would collide.
    fn exposed_name(&mut self, server_id: &str, tool: &str) -> String {
        let base = format!(
            "{}__{}",
            sanitize_segment(server_id),
            sanitize_segment(tool)
        );
        let mut name = base.clone();
        let mut i = 2;
        while !self.seen.insert(name.clone()) {
            name = format!("{base}_{i}");
            i += 1;
        }
        name
    }

    /// Every downstream tool, with its exposed (sanitized) name.
    pub fn aggregated_tools(&self) -> Vec<Value> {
        self.tools.clone()
    }

    /// Re-query every live server's tool list (a downstream announced a
    /// `tools/list_changed`) and rebuild the exposed aggregation in place. Unlike
    /// a full rebuild this keeps the existing connections, so a runtime or
    /// session-scoped tool change isn't lost to a freshly spawned process that
    /// never saw it.
    pub fn refresh_tools(&mut self) {
        // `&mut self` is exclusive, so locking each slot here can't contend.
        for slot in &self.servers {
            slot.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .refresh_tools();
        }
        self.rebuild_aggregation();
    }

    /// Re-query every live server's resource list (a downstream announced a
    /// `resources/list_changed`) and rebuild the exposed aggregation in place.
    /// Mirrors [`refresh_tools`].
    pub fn refresh_resources(&mut self) {
        for slot in &self.servers {
            slot.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .refresh_resources();
        }
        self.rebuild_aggregation();
    }

    /// Re-query every live server's prompt list (a downstream announced a
    /// `prompts/list_changed`) and rebuild the exposed aggregation in place.
    /// Mirrors [`refresh_tools`].
    pub fn refresh_prompts(&mut self) {
        for slot in &self.servers {
            slot.inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .refresh_prompts();
        }
        self.rebuild_aggregation();
    }

    /// Forward one JSON-RPC notification to every connected downstream server.
    pub fn notify_all_downstreams(&self, method: &str, params: Value) {
        for slot in &self.servers {
            if let Ok(mut ds) = slot.inner.lock() {
                let _ = ds.notify_downstream(method, params.clone());
            }
        }
    }

    /// Replace the quarantine set and re-derive the exposed aggregation so newly
    /// quarantined tools are hidden (or re-approved ones restored) without re-querying
    /// downstream. Cheap: it only re-applies the policy to the cached tool lists.
    pub fn requarantine(&mut self, quarantined: BTreeSet<String>) {
        self.policy.quarantined = quarantined;
        self.rebuild_aggregation();
    }

    /// The quarantine set this router is currently enforcing. Lets a caller diff the
    /// live set against the persisted one and skip `requarantine` (and the client
    /// `list_changed` that follows it) when nothing actually changed.
    pub fn quarantined(&self) -> &BTreeSet<String> {
        &self.policy.quarantined
    }

    /// Re-derive the exposed tool/resource/prompt aggregation from the current
    /// servers' (possibly refreshed) lists, in the original add order so exposed
    /// names and their `_2` collision suffixes stay stable. The server set itself
    /// is unchanged, so `servers` and `by_id` are kept.
    fn rebuild_aggregation(&mut self) {
        self.tools.clear();
        self.routes.clear();
        self.seen.clear();
        self.blocked.clear();
        self.resources.clear();
        self.resource_routes.clear();
        self.prompts.clear();
        self.prompt_routes.clear();
        // Clone the Arcs (cheap) and snapshot each slot's lists under its lock, so
        // we hold neither a slot lock nor a borrow of `self.servers` across the
        // `&mut self` re-index.
        let slots: Vec<Arc<ServerSlot>> = self.servers.clone();
        for slot in &slots {
            let (tools, resources, prompts) = {
                let s = slot
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (s.tools.clone(), s.resources.clone(), s.prompts.clone())
            };
            self.index_server(&slot.id, &tools, &resources, &prompts);
        }
    }

    /// The slot owning `server_id`, as a cloned `Arc` so the caller can lock and
    /// use it after dropping any borrow of the router (this is what lets the
    /// downstream call run without holding the router lock).
    fn slot_for(&self, server_id: &str) -> Result<Arc<ServerSlot>, String> {
        self.by_id
            .get(server_id)
            .and_then(|&i| self.servers.get(i))
            .cloned()
            .ok_or_else(|| format!("no connected server '{server_id}'"))
    }

    /// Retry wrapper that releases the per-server Mutex during the backoff sleep
    /// so concurrent calls to the same server aren't blocked while one call waits
    /// for a rate-limit or connection-retry delay.
    fn call_with_retry<T, F>(&self, slot: &Arc<ServerSlot>, mut f: F) -> Result<T, String>
    where
        F: FnMut(&mut DownstreamServer) -> Result<T, TransportError>,
    {
        // Circuit breaker: a server that just failed repeatedly is fast-failed here,
        // BEFORE taking its `inner` lock, so a dead/hung server neither pays its full
        // read timeout again nor queues callers behind an in-flight timing-out call.
        // A call that gets past this after the cooldown is the half-open PROBE: if it
        // still fails, the server has been down for a full cooldown and we try to
        // re-spawn it (below) rather than fast-failing forever.
        let is_probe = {
            let mut breaker = slot
                .breaker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(remaining) = breaker.open_remaining(Instant::now()) {
                return Err(format!(
                    "server '{}' is temporarily unavailable (too many recent failures; retrying in {}s)",
                    slot.id,
                    remaining.as_secs() + 1
                ));
            }
            // Cooldown elapsed but the failure streak is still at/over threshold: this
            // call is the half-open probe of a tripped breaker.
            breaker.consecutive_failures >= BREAKER_FAILURE_THRESHOLD
        };
        let mut attempt = 0u32;
        loop {
            let result = {
                let mut server = slot.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                f(&mut server)
            };
            match result {
                Ok(v) => {
                    slot.breaker
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .record_success();
                    return Ok(v);
                }
                Err(TransportError::Retry { retry_after, message }) if attempt < HTTP_MAX_RETRIES => {
                    let wait = retry_wait(retry_after, attempt);
                    eprintln!("conduit: retrying downstream call after {wait:?}: {message}");
                    std::thread::sleep(wait);
                    attempt += 1;
                }
                Err(e) => {
                    // Only a health failure (timeout / dead connection / exhausted
                    // retries) counts toward the breaker; a normal error response does
                    // not disable the server.
                    if e.is_health_failure() {
                        // The server has now failed for a full cooldown and the probe
                        // confirms it's still down. Re-spawn the connection once and
                        // retry: this recovers a crashed stdio child or a dropped remote
                        // that the plain breaker would otherwise fast-fail forever (its
                        // self-heal only fires when EVERY server is dead). Gated on the
                        // probe so a live server is never re-spawned on a transient blip.
                        if is_probe {
                            if let Some(v) = self.reconnect_and_retry(slot, &mut f) {
                                return v;
                            }
                        }
                        slot.breaker
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .record_failure(Instant::now());
                    }
                    return Err(e.to_string());
                }
            }
        }
    }

    /// Re-spawn a slot's downstream connection and retry the call once on the fresh
    /// transport. Returns `Some(result)` when a reconnect was attempted (so the caller
    /// stops), or `None` when the slot has no reconnect factory (fall through to the
    /// normal breaker-failure path). The spawn runs without holding the `inner` lock so
    /// a slow re-spawn doesn't wedge other callers to the same server.
    fn reconnect_and_retry<T, F>(&self, slot: &Arc<ServerSlot>, f: &mut F) -> Option<Result<T, String>>
    where
        F: FnMut(&mut DownstreamServer) -> Result<T, TransportError>,
    {
        let factory = slot.reconnect.as_ref()?;
        eprintln!("conduit: server '{}' is down; re-spawning it", slot.id);
        let Some(fresh) = factory() else {
            eprintln!("conduit: re-spawn of '{}' failed; leaving it fast-failed", slot.id);
            return None; // still unreachable: fall through to record_failure
        };
        let retry = {
            let mut server = slot.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *server = fresh; // swap the live child/connection for the fresh one
            f(&mut server)
        };
        let mut breaker = slot
            .breaker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(match retry {
            Ok(v) => {
                eprintln!("conduit: server '{}' recovered after re-spawn", slot.id);
                breaker.record_success();
                Ok(v)
            }
            Err(e) => {
                breaker.record_failure(Instant::now());
                Err(e.to_string())
            }
        })
    }

    /// Forward an exposed tool call to its owning downstream server, using that
    /// server's original tool name. Takes `&self`: it locks only the target
    /// server, so concurrent calls to different servers run in parallel while
    /// calls to the same server (one stdio pipe) serialize.
    pub fn route_call(&self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        self.route_call_with_cancel(exposed_name, arguments, None)
    }

    pub fn route_call_with_cancel(
        &self,
        exposed_name: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, String> {
        if let Some(reason) = self.blocked.get(exposed_name) {
            return Err(format!("tool '{exposed_name}' is {reason}"));
        }
        let (server_id, tool) = self
            .routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for tool '{exposed_name}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| {
            server.call_with_cancel(&tool, arguments.clone(), cancel.clone())
        })
    }

    /// Every downstream resource, uris unchanged.
    pub fn aggregated_resources(&self) -> Vec<Value> {
        self.resources.clone()
    }

    /// Every downstream prompt, with its exposed (namespaced) name.
    pub fn aggregated_prompts(&self) -> Vec<Value> {
        self.prompts.clone()
    }

    /// The server that advertised resource `uri`, if any. Used to scope a registered
    /// HTTP client's resource access to its allowed server set (see the gateway).
    pub fn resource_server(&self, uri: &str) -> Option<&str> {
        self.resource_routes.get(uri).map(String::as_str)
    }

    /// The server that owns the exposed prompt `name`, if any. Used to scope a
    /// registered HTTP client's prompt access to its allowed server set.
    pub fn prompt_server(&self, exposed_name: &str) -> Option<&str> {
        self.prompt_routes.get(exposed_name).map(|(s, _)| s.as_str())
    }

    /// Read a resource by uri from whichever server advertised it. `&self`: locks
    /// only the owning server (see `route_call`).
    pub fn read_resource(&self, uri: &str) -> Result<Value, String> {
        self.read_resource_with_cancel(uri, None)
    }

    pub fn read_resource_with_cancel(
        &self,
        uri: &str,
        cancel: Option<CancelContext>,
    ) -> Result<Value, String> {
        let server_id = self
            .resource_routes
            .get(uri)
            .cloned()
            .ok_or_else(|| format!("no server owns resource '{uri}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| {
            server.read_resource_with_cancel(uri, cancel.clone())
        })
    }

    /// Get a prompt by its exposed name, forwarding the server's real name.
    /// `&self`: locks only the owning server (see `route_call`).
    pub fn get_prompt(&self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        self.get_prompt_with_cancel(exposed_name, arguments, None)
    }

    pub fn get_prompt_with_cancel(
        &self,
        exposed_name: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, String> {
        let (server_id, name) = self
            .prompt_routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for prompt '{exposed_name}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| {
            server.get_prompt_with_cancel(&name, arguments.clone(), cancel.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn breaker_opens_after_threshold_then_half_opens_after_cooldown() {
        let t0 = Instant::now();
        let mut b = Breaker::default();
        // Below the threshold the circuit stays closed.
        for _ in 0..BREAKER_FAILURE_THRESHOLD - 1 {
            b.record_failure(t0);
            assert!(b.open_remaining(t0).is_none(), "closed below threshold");
        }
        // The threshold-th consecutive failure opens it.
        b.record_failure(t0);
        let rem = b.open_remaining(t0).expect("circuit should be open");
        assert!(rem > Duration::ZERO && rem <= BREAKER_COOLDOWN);
        // Still open partway through the cooldown.
        assert!(b.open_remaining(t0 + BREAKER_COOLDOWN / 2).is_some());
        // Once the cooldown elapses it half-opens: a probe is let through (None) and
        // the tripped state is cleared.
        assert!(b.open_remaining(t0 + BREAKER_COOLDOWN).is_none());
        assert!(b.open_remaining(t0 + BREAKER_COOLDOWN).is_none());
    }

    #[test]
    fn breaker_success_resets_the_streak() {
        let t0 = Instant::now();
        let mut b = Breaker::default();
        b.record_failure(t0);
        b.record_failure(t0);
        b.record_success(); // a good call clears the streak
        // Two failures alone no longer open it (needs THRESHOLD consecutive).
        b.record_failure(t0);
        b.record_failure(t0);
        assert!(b.open_remaining(t0).is_none(), "success reset the streak");
        // The threshold-th consecutive failure opens it.
        b.record_failure(t0);
        assert!(b.open_remaining(t0).is_some());
    }

    #[test]
    fn retry_wait_clamps_large_retry_after() {
        // A downstream advertising a huge Retry-After is clamped to our cap so it
        // can't pin the calling thread.
        assert_eq!(retry_wait(Some(Duration::from_secs(3600)), 0), HTTP_RETRY_CAP);
        // A reasonable Retry-After under the cap is honored as-is.
        assert_eq!(
            retry_wait(Some(Duration::from_secs(2)), 0),
            Duration::from_secs(2)
        );
        // With no Retry-After, it falls back to the exponential backoff schedule.
        assert_eq!(retry_wait(None, 0), backoff_delay(0));
        assert_eq!(retry_wait(None, 1), backoff_delay(1));
    }

    #[test]
    fn inline_refs_resolves_defs() {
        let mut schema = json!({
            "type": "object",
            "properties": { "a": { "$ref": "#/$defs/Foo" } },
            "$defs": { "Foo": { "type": "string", "enum": ["x", "y"] } }
        });
        inline_refs(&mut schema);
        assert!(schema.get("$defs").is_none(), "defs should be dropped");
        assert_eq!(schema["properties"]["a"]["type"], "string");
        assert_eq!(schema["properties"]["a"]["enum"][0], "x");
        assert!(!serde_json::to_string(&schema).unwrap().contains("$ref"));
    }

    #[test]
    fn inline_refs_handles_definitions_keyword() {
        let mut schema = json!({
            "properties": { "b": { "$ref": "#/definitions/Bar" } },
            "definitions": { "Bar": { "type": "number" } }
        });
        inline_refs(&mut schema);
        assert_eq!(schema["properties"]["b"]["type"], "number");
        assert!(schema.get("definitions").is_none());
    }

    #[test]
    fn inline_refs_breaks_cycles() {
        let mut schema = json!({
            "$ref": "#/$defs/Node",
            "$defs": { "Node": { "type": "object", "properties": { "next": { "$ref": "#/$defs/Node" } } } }
        });
        inline_refs(&mut schema); // must terminate, not recurse forever
        assert_eq!(schema["type"], "object");
        // the cyclic inner ref collapses to {}, so nothing references out
        assert!(!serde_json::to_string(&schema).unwrap().contains("$ref"));
    }

    #[test]
    fn inline_refs_noop_without_defs() {
        let mut schema = json!({ "type": "object", "properties": { "x": { "type": "string" } } });
        let before = schema.clone();
        inline_refs(&mut schema);
        assert_eq!(schema, before);
    }

    #[test]
    fn inline_refs_resolves_json_pointer_into_properties() {
        // revenuecat-style: a property $refs another property by JSON Pointer.
        let mut schema = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "alias": { "$ref": "#/properties/name" }
            }
        });
        inline_refs(&mut schema);
        assert_eq!(schema["properties"]["alias"]["type"], "string");
        assert_eq!(schema["properties"]["alias"]["minLength"], 1);
        assert!(!serde_json::to_string(&schema).unwrap().contains("$ref"));
    }
    use crate::downstream::{CancelRegistry, DownstreamServer, Transport};

    /// A fake downstream server: advertises `echo` + `add`, echoes calls back.
    struct MockTransport {
        label: String,
    }

    impl Transport for MockTransport {
        fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
            match method {
                "initialize" => Ok(json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "resources": {}, "prompts": {} }
                })),
                "tools/list" => Ok(json!({
                    "tools": [
                        { "name": "echo", "description": "echo back" },
                        { "name": "add", "description": "add numbers" }
                    ]
                })),
                "tools/call" => {
                    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    Ok(json!({
                        "content": [{ "type": "text", "text": format!("{}:{}", self.label, name) }],
                        "isError": false
                    }))
                }
                "resources/list" => Ok(json!({
                    "resources": [
                        { "uri": format!("{}://readme", self.label), "name": "readme" }
                    ]
                })),
                "resources/read" => {
                    let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");
                    Ok(json!({ "contents": [{ "uri": uri, "text": format!("{}-body", self.label) }] }))
                }
                "prompts/list" => Ok(json!({
                    "prompts": [{ "name": "greet", "description": "greeting" }]
                })),
                "prompts/get" => {
                    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    Ok(json!({ "messages": [{ "role": "user", "content": format!("{}:{}", self.label, name) }] }))
                }
                other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn mock_server(id: &str) -> DownstreamServer {
        let mut ds = DownstreamServer::connect(
            id.to_string(),
            Box::new(MockTransport {
                label: id.to_string(),
            }),
        )
        .unwrap();
        // Mirror the gateway: load resources/prompts after connect.
        ds.load_resources_prompts();
        ds
    }

    /// Handshakes fine (so it can be constructed) but every `tools/call` reports the
    /// connection is dead - i.e. a crashed/hung stdio child mid-session.
    struct DeadOnCallTransport;
    impl Transport for DeadOnCallTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
            match method {
                "initialize" => Ok(json!({ "protocolVersion": "2025-06-18", "capabilities": {} })),
                "tools/list" => Ok(json!({ "tools": [{ "name": "echo" }] })),
                "tools/call" => Err(TransportError::Unavailable("broken pipe".into())),
                _ => Ok(json!({})),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn dead_slot(reconnect: Option<Reconnect>) -> Arc<ServerSlot> {
        Arc::new(ServerSlot {
            id: "s".into(),
            inner: Mutex::new(
                DownstreamServer::connect("s".into(), Box::new(DeadOnCallTransport)).unwrap(),
            ),
            breaker: Mutex::new(Breaker::default()),
            reconnect,
        })
    }

    #[test]
    fn reconnect_and_retry_recovers_a_dead_server() {
        let router = Router::new();
        // Factory hands back a healthy connection, mirroring a re-spawn that succeeds.
        let slot = dead_slot(Some(Box::new(|| Some(mock_server("s")))));
        let out = router.reconnect_and_retry(&slot, &mut |ds| ds.call("echo", json!({})));
        // The probe re-spawned the server and the retried call went through.
        let value = out.expect("reconnect attempted").expect("call recovered");
        assert!(serde_json::to_string(&value).unwrap().contains("s:echo"));
        // The live connection was swapped in, so subsequent calls hit the healthy one.
        assert!(slot.inner.lock().unwrap().call("echo", json!({})).is_ok());
        // A successful recovery closes the breaker.
        assert!(slot.breaker.lock().unwrap().open_remaining(Instant::now()).is_none());
    }

    #[test]
    fn reconnect_and_retry_gives_up_when_respawn_fails() {
        let router = Router::new();
        // Factory still can't reach the server (returns None): no recovery, and the
        // caller must fall through to record the failure.
        let slot = dead_slot(Some(Box::new(|| None)));
        let out: Option<Result<Value, String>> =
            router.reconnect_and_retry(&slot, &mut |ds| ds.call("echo", json!({})));
        assert!(out.is_none(), "a failed re-spawn falls through to the breaker");
    }

    #[test]
    fn reconnect_and_retry_noops_without_a_factory() {
        let router = Router::new();
        // A slot with no reconnect factory (e.g. a test fixture) behaves as before:
        // reconnect is skipped and the breaker path handles the failure.
        let slot = dead_slot(None);
        let out: Option<Result<Value, String>> =
            router.reconnect_and_retry(&slot, &mut |ds| ds.call("echo", json!({})));
        assert!(out.is_none());
    }

    #[test]
    fn sanitizes_hyphens_in_both_halves() {
        // Server ids and tool names with hyphens are rewritten to `_` so clients
        // like Cursor don't drop them.
        assert_eq!(sanitize_segment("file-system"), "file_system");
        assert_eq!(sanitize_segment("list-offerings"), "list_offerings");
        assert_eq!(sanitize_segment("already_ok"), "already_ok");
    }

    #[test]
    fn resource_and_prompt_server_resolve_owner() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        router.add(mock_server("postgres"));
        // Resources keep their server-scoped uris; the map resolves the owner.
        assert_eq!(router.resource_server("github://readme"), Some("github"));
        assert_eq!(router.resource_server("postgres://readme"), Some("postgres"));
        assert_eq!(router.resource_server("unknown://x"), None);
        // Prompts resolve by their exposed (namespaced) name.
        let prompts = router.aggregated_prompts();
        let gh_prompt = prompts
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
            .find(|n| router.prompt_server(n) == Some("github"))
            .expect("a github prompt is exposed")
            .to_string();
        assert_eq!(router.prompt_server(&gh_prompt), Some("github"));
        assert_eq!(router.prompt_server("no__such_prompt"), None);
    }

    #[test]
    fn aggregates_and_namespaces_tools() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        router.add(mock_server("postgres"));

        let tools = router.aggregated_tools();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                "github__echo",
                "github__add",
                "postgres__echo",
                "postgres__add"
            ]
        );
    }

    #[test]
    fn routes_call_to_the_right_server() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        router.add(mock_server("postgres"));

        let result = router.route_call("postgres__add", json!({ "a": 1 })).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "postgres:add");
    }

    #[test]
    fn tool_overrides_rename_and_redescribe() {
        let mut router = Router::new();
        // Keyed by (server id, ORIGINAL tool name), not the exposed name.
        let mut srv = HashMap::new();
        srv.insert(
            "echo".to_string(),
            ToolOverride { name: Some("say".into()), description: Some("say it back".into()) },
        );
        srv.insert(
            "add".to_string(),
            ToolOverride { name: None, description: Some("cleaned".into()) },
        );
        router.set_overrides(HashMap::from([("srv".to_string(), srv)]));
        router.add(mock_server("srv"));

        let tools = router.aggregated_tools();
        let by_name: HashMap<&str, &Value> =
            tools.iter().map(|t| (t["name"].as_str().unwrap(), t)).collect();

        // echo is renamed to "say" (its original exposed name is gone) and re-described.
        assert!(by_name.contains_key("say"));
        assert!(!by_name.contains_key("srv__echo"));
        assert_eq!(by_name["say"]["description"], "say it back");
        // add keeps its name, description replaced (the poisoned-desc neutralize case).
        assert_eq!(by_name["srv__add"]["description"], "cleaned");

        // The renamed tool STILL routes to the original downstream tool (echo).
        let out = router.route_call("say", json!({})).unwrap();
        assert_eq!(out["content"][0]["text"], "srv:echo");
        let out = router.route_call("srv__add", json!({})).unwrap();
        assert_eq!(out["content"][0]["text"], "srv:add");
    }

    #[test]
    fn quarantine_follows_a_renamed_tool_by_its_exposed_name() {
        // #423: quarantine is keyed by the client-facing (exposed) name. A tool renamed
        // via an override must be quarantined under its RENAMED name, and blocking must
        // key on that same name. The old code evaluated the policy on the pre-rename base
        // name, so a renamed tool could never be quarantined: the app showed it blocked
        // while the gateway kept exposing and routing it.
        let mut srv = HashMap::new();
        srv.insert(
            "echo".to_string(),
            ToolOverride { name: Some("say".into()), description: None },
        );
        let policy = ToolPolicy {
            quarantined: BTreeSet::from(["say".to_string()]),
            ..Default::default()
        };
        let mut router = Router::with_policy(policy);
        router.set_overrides(HashMap::from([("srv".to_string(), srv)]));
        router.add(mock_server("srv"));

        // The renamed tool is hidden from the catalog...
        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(!names.contains(&"say".to_string()), "quarantined rename must be hidden");
        // ...and blocked on a direct call, with the quarantine reason.
        let err = router.route_call("say", json!({})).unwrap_err();
        assert!(err.contains("quarantine"), "unexpected: {err}");
    }

    #[test]
    fn a_stale_pre_rename_quarantine_entry_does_not_block_the_renamed_tool() {
        // The mirror of the above: quarantining the OLD exposed name (srv__echo) must NOT
        // block the tool now exposed as "say", so the fix doesn't just swap which name is
        // wrong. A stale entry from before a rename is inert, not a silent block.
        let mut srv = HashMap::new();
        srv.insert(
            "echo".to_string(),
            ToolOverride { name: Some("say".into()), description: None },
        );
        let policy = ToolPolicy {
            quarantined: BTreeSet::from(["srv__echo".to_string()]),
            ..Default::default()
        };
        let mut router = Router::with_policy(policy);
        router.set_overrides(HashMap::from([("srv".to_string(), srv)]));
        router.add(mock_server("srv"));

        assert_eq!(router.route_of("say"), Some(("srv", "echo")));
        assert!(router.route_call("say", json!({})).is_ok(), "stale entry must not block");
    }

    #[test]
    fn rename_to_an_already_taken_name_is_ignored() {
        // add is indexed after echo, so renaming add -> "srv__echo" (already taken) must
        // fall back to add's original name, keeping routing unambiguous.
        let mut router = Router::new();
        let srv = HashMap::from([(
            "add".to_string(),
            ToolOverride { name: Some("srv__echo".into()), description: None },
        )]);
        router.set_overrides(HashMap::from([("srv".to_string(), srv)]));
        router.add(mock_server("srv"));

        let tools = router.aggregated_tools();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"srv__echo"), "the real echo keeps the name");
        assert!(names.contains(&"srv__add"), "add fell back to its own name");
        assert_eq!(router.route_call("srv__echo", json!({})).unwrap()["content"][0]["text"], "srv:echo");
        assert_eq!(router.route_call("srv__add", json!({})).unwrap()["content"][0]["text"], "srv:add");
    }

    #[test]
    fn route_of_resolves_renamed_tool_to_real_server_and_original_tool() {
        // The gate derives provenance/scoping from route_of, NOT by splitting the exposed
        // name. A renamed tool must still resolve to its real (server, original tool) so the
        // untrusted-source HITL check and per-client scoping aren't silently bypassed.
        let mut router = Router::new();
        let srv = HashMap::from([(
            "echo".to_string(),
            ToolOverride { name: Some("say".into()), description: None },
        )]);
        router.set_overrides(HashMap::from([("srv".to_string(), srv)]));
        router.add(mock_server("srv"));

        assert_eq!(router.route_of("say"), Some(("srv", "echo")), "renamed tool resolves to origin");
        assert_eq!(router.route_of("srv__add"), Some(("srv", "add")), "normal tool resolves");
        assert_eq!(router.route_of("nope"), None, "unknown name resolves to nothing");
    }

    #[test]
    fn routes_call_with_a_sanitized_name() {
        // A hyphenated server id is exposed with `_`, but the call still reaches
        // the server under its real id.
        let mut router = Router::new();
        router.add(mock_server("file-system"));

        let tools = router.aggregated_tools();
        let name = tools[0]["name"].as_str().unwrap();
        assert_eq!(name, "file_system__echo");

        let result = router.route_call(name, json!({})).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "file-system:echo");
    }

    #[test]
    fn unknown_namespace_errors() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        assert!(router.route_call("nope__x", json!({})).is_err());
        assert!(router.route_call("notnamespaced", json!({})).is_err());
    }

    /// A server whose single tool is annotated destructive.
    struct DestructiveMock;
    impl Transport for DestructiveMock {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
            match method {
                "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                "tools/list" => Ok(json!({
                    "tools": [
                        { "name": "drop_table",
                          "description": "drops a table",
                          "annotations": { "destructiveHint": true } },
                        { "name": "list_tables", "description": "lists tables" }
                    ]
                })),
                "tools/call" => Ok(json!({
                    "content": [{ "type": "text", "text": "ok" }], "isError": false
                })),
                other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn is_destructive_reads_annotations() {
        assert!(is_destructive(&json!({ "annotations": { "destructiveHint": true } })));
        assert!(is_destructive(&json!({ "destructiveHint": true }))); // top-level fallback
        assert!(!is_destructive(&json!({ "annotations": { "destructiveHint": false } })));
        assert!(!is_destructive(&json!({ "name": "x" })));
    }

    #[test]
    fn is_destructive_falls_back_to_obvious_write_verbs() {
        assert!(is_destructive(&json!({ "name": "delete_file" })));
        assert!(is_destructive(&json!({ "name": "sendEmail" })));
        assert!(is_destructive(&json!({ "name": "run_query" })));
        assert!(is_destructive(&json!({ "name": "rename_branch" })));
        assert!(is_destructive(&json!({ "name": "uploadObject" })));
        assert!(is_destructive(&json!({ "name": "patch_record" })));
        assert!(!is_destructive(&json!({ "name": "list_files" })));
        assert!(!is_destructive(&json!({
            "name": "delete_file",
            "annotations": { "destructiveHint": false }
        })));
    }

    #[test]
    fn disabled_tool_is_hidden_and_blocked() {
        let mut policy = ToolPolicy::default();
        policy
            .disabled
            .insert("github".to_string(), ["echo".to_string()].into_iter().collect());
        let mut router = Router::with_policy(policy);
        router.add(mock_server("github"));

        // echo is hidden; add survives.
        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert_eq!(names, vec!["github__add"]);

        // Calling the hidden tool by name gives a clear policy error.
        let err = router.route_call("github__echo", json!({})).unwrap_err();
        assert!(err.contains("disabled"), "unexpected: {err}");
        // The allowed tool still routes.
        assert!(router.route_call("github__add", json!({})).is_ok());
    }

    #[test]
    fn requarantine_restores_a_re_approved_tool_without_a_rebuild() {
        // Regression for SOU-292: re-approving a quarantined tool left it blocked in the
        // running gateway. The refresh path could ADD to the quarantine set but never
        // REMOVE from it, and because `route_call` reads the materialized `blocked` map,
        // a client that already held its catalog stayed broken even though the app showed
        // nothing quarantined. Shrinking the set must restore the tool in place, with no
        // rebuild and no downstream re-query.
        let mut policy = ToolPolicy::default();
        policy.quarantined = ["github__echo".to_string()].into_iter().collect();
        let mut router = Router::with_policy(policy);
        router.add(mock_server("github"));

        // Quarantined: hidden from the catalog AND blocked on a direct call.
        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert_eq!(names, vec!["github__add"]);
        let err = router.route_call("github__echo", json!({})).unwrap_err();
        assert!(err.contains("quarantined"), "unexpected: {err}");

        // Re-approval: the persisted set no longer holds the tool.
        router.requarantine(BTreeSet::new());

        // It must be routable again immediately, not "on the next rebuild".
        assert!(
            router.route_call("github__echo", json!({})).is_ok(),
            "a re-approved tool must route again without a rebuild"
        );
        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert!(
            names.contains(&"github__echo".to_string()),
            "and be re-exposed"
        );
    }

    #[test]
    fn quarantined_accessor_reflects_the_live_set() {
        // The watcher diffs this against the persisted set to decide whether to re-filter,
        // so it has to track `requarantine` exactly. If it went stale the reconciler would
        // either spin (re-filtering every tick) or never fire at all.
        let mut router = Router::new();
        router.add(mock_server("github"));
        assert!(router.quarantined().is_empty());

        let set: BTreeSet<String> = ["github__echo".to_string()].into_iter().collect();
        router.requarantine(set.clone());
        assert_eq!(router.quarantined(), &set);

        router.requarantine(BTreeSet::new());
        assert!(router.quarantined().is_empty());
    }

    #[test]
    fn aggregates_and_routes_resources() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        router.add(mock_server("postgres"));

        // Resources pass through with their original uris.
        let uris: Vec<String> = router
            .aggregated_resources()
            .iter()
            .filter_map(|r| r.get("uri").and_then(|u| u.as_str()).map(String::from))
            .collect();
        assert_eq!(uris, vec!["github://readme", "postgres://readme"]);

        // resources/read reaches the owning server.
        let result = router.read_resource("postgres://readme").unwrap();
        assert_eq!(result["contents"][0]["text"], "postgres-body");
        assert!(router.read_resource("nope://x").is_err());
    }

    #[test]
    fn route_call_passes_cancel_context_to_transport() {
        struct CancelAware {
            saw_cancel: Arc<AtomicBool>,
        }

        impl Transport for CancelAware {
            fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
                match method {
                    "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                    "tools/list" => Ok(json!({ "tools": [{ "name": "echo", "description": "" }] })),
                    other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
                }
            }

            fn request_with_cancel(
                &mut self,
                method: &str,
                params: Value,
                cancel: Option<CancelContext>,
            ) -> Result<Value, TransportError> {
                match method {
                    "tools/call" => {
                        self.saw_cancel.store(cancel.is_some(), Ordering::SeqCst);
                        Ok(json!({
                            "content": [{ "type": "text", "text": "ok" }],
                            "isError": false
                        }))
                    }
                    _ => self.request(method, params),
                }
            }

            fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let saw_cancel = Arc::new(AtomicBool::new(false));
        let ds = DownstreamServer::connect(
            "s".into(),
            Box::new(CancelAware {
                saw_cancel: Arc::clone(&saw_cancel),
            }),
        )
        .unwrap();
        let mut router = Router::new();
        router.add(ds);
        let registry = CancelRegistry::new();
        assert!(registry.begin_client_request("99".to_string()));

        let result = router
            .route_call_with_cancel(
                "s__echo",
                json!({}),
                Some(registry.context("99".to_string())),
            )
            .unwrap();

        assert_eq!(result["content"][0]["text"], "ok");
        assert!(saw_cancel.load(Ordering::SeqCst));
        registry.finish_client_request("99");
    }

    #[test]
    fn aggregates_and_routes_prompts() {
        let mut router = Router::new();
        router.add(mock_server("github"));
        router.add(mock_server("postgres"));

        // Prompt names are namespaced like tools.
        let names: Vec<String> = router
            .aggregated_prompts()
            .iter()
            .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert_eq!(names, vec!["github__greet", "postgres__greet"]);

        // prompts/get forwards the server's real prompt name.
        let result = router.get_prompt("github__greet", json!({})).unwrap();
        assert_eq!(result["messages"][0]["content"], "github:greet");
        assert!(router.get_prompt("nope__greet", json!({})).is_err());
    }

    #[test]
    fn deny_destructive_hides_flagged_tools() {
        let policy = ToolPolicy {
            deny_destructive: true,
            ..Default::default()
        };
        let mut router = Router::with_policy(policy);
        router.add(DownstreamServer::connect("db".to_string(), Box::new(DestructiveMock)).unwrap());

        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        // drop_table is blocked; list_tables remains.
        assert_eq!(names, vec!["db__list_tables"]);
        let err = router.route_call("db__drop_table", json!({})).unwrap_err();
        assert!(err.contains("destructive"), "unexpected: {err}");
    }

    #[test]
    fn tool_scope_allow_list_hides_and_blocks_non_listed_tools() {
        // A profile's per-server allow-list ("FeatureSet"): the server exposes ONLY the
        // listed tool; the rest are both hidden from the catalog and blocked on a direct call.
        let mut allow = HashMap::new();
        allow.insert("db".to_string(), HashSet::from(["echo".to_string()]));
        let policy = ToolPolicy {
            allow,
            ..Default::default()
        };
        let mut router = Router::with_policy(policy);
        router.add(mock_server("db"));

        let names: Vec<String> = router
            .aggregated_tools()
            .iter()
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
            .collect();
        assert_eq!(names, vec!["db__echo"], "only the allow-listed tool is exposed");

        // Hidden, and also blocked on a direct call (not merely invisible).
        let err = router.route_call("db__add", json!({})).unwrap_err();
        assert!(err.contains("tool scope"), "unexpected: {err}");
        assert!(router.route_call("db__echo", json!({})).is_ok());
    }

    #[test]
    fn refresh_keeps_collision_suffixes_stable() {
        // Two tools that sanitize to the same exposed name collide; the second
        // gets a `_2` suffix. After a refresh (re-query + reindex) the order and
        // suffixes must not shuffle, or a client's tool names would change
        // mid-session and break in-flight calls.
        struct DupMock;
        impl Transport for DupMock {
            fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
                match method {
                    "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                    "tools/list" => Ok(json!({ "tools": [
                        { "name": "a-b", "description": "one" },
                        { "name": "a_b", "description": "two" }
                    ] })),
                    other => Err(TransportError::Fatal(format!("unexpected {other}"))),
                }
            }
            fn notify(&mut self, _m: &str, _p: Value) -> Result<(), TransportError> {
                Ok(())
            }
        }
        let names = |r: &Router| -> Vec<String> {
            r.aggregated_tools()
                .iter()
                .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        };
        let mut router = Router::new();
        router.add(DownstreamServer::connect("s".to_string(), Box::new(DupMock)).unwrap());
        let before = names(&router);
        assert_eq!(before, vec!["s__a_b", "s__a_b_2"]);
        router.refresh_tools();
        assert_eq!(names(&router), before, "refresh shuffled the collision suffixes");
    }

    #[test]
    fn reordered_tool_list_keeps_each_tool_its_own_exposed_name() {
        // The dangerous variant of the test above: the server doesn't just get
        // re-queried, it comes back listing the SAME two colliding tools in the
        // opposite order. Allocating suffixes by list position swapped `_2`
        // between them, so the client's cached `s__a_b` silently started routing
        // to `a_b` instead of `a-b` — calls kept succeeding and went to the wrong
        // tool. The exposed name must be a property of the tool, not its position.
        struct ReorderMock {
            calls: AtomicU32,
        }
        impl Transport for ReorderMock {
            fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
                match method {
                    "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                    "tools/list" => {
                        let first = self.calls.fetch_add(1, Ordering::SeqCst) == 0;
                        // Same two tools, flipped on the second listing.
                        Ok(if first {
                            json!({ "tools": [
                                { "name": "a-b", "description": "one" },
                                { "name": "a_b", "description": "two" }
                            ] })
                        } else {
                            json!({ "tools": [
                                { "name": "a_b", "description": "two" },
                                { "name": "a-b", "description": "one" }
                            ] })
                        })
                    }
                    other => Err(TransportError::Fatal(format!("unexpected {other}"))),
                }
            }
            fn notify(&mut self, _m: &str, _p: Value) -> Result<(), TransportError> {
                Ok(())
            }
        }

        let mut router = Router::new();
        router.add(
            DownstreamServer::connect(
                "s".to_string(),
                Box::new(ReorderMock {
                    calls: AtomicU32::new(0),
                }),
            )
            .unwrap(),
        );
        // Assert the ROUTE, not just the name set: both names exist either way,
        // so only the mapping reveals the swap.
        assert_eq!(router.route_of("s__a_b"), Some(("s", "a-b")));
        assert_eq!(router.route_of("s__a_b_2"), Some(("s", "a_b")));

        router.refresh_tools();

        assert_eq!(
            router.route_of("s__a_b"),
            Some(("s", "a-b")),
            "a reordered tools/list re-pointed a cached exposed name at a different tool"
        );
        assert_eq!(router.route_of("s__a_b_2"), Some(("s", "a_b")));
    }

    /// Shared retry-capable mock used to exercise the Router helper.
    struct RetryMock {
        tool_failures: Arc<AtomicU32>,
        resource_failures: Arc<AtomicU32>,
        prompt_failures: Arc<AtomicU32>,
        tool_call_entries: Arc<AtomicU32>,
    }

    impl Transport for RetryMock {
        fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
            match method {
                "initialize" => Ok(json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "resources": {}, "prompts": {} }
                })),
                "tools/list" => Ok(json!({
                    "tools": [
                        { "name": "flaky", "description": "flaky tool" },
                        { "name": "stable", "description": "always succeeds" }
                    ]
                })),
                "resources/list" => Ok(json!({
                    "resources": [{ "uri": "retry://res", "name": "res" }]
                })),
                "prompts/list" => Ok(json!({
                    "prompts": [{ "name": "greet", "description": "greeting" }]
                })),
                "tools/call" => {
                    self.tool_call_entries.fetch_add(1, Ordering::SeqCst);
                    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if name == "stable" {
                        return Ok(json!({
                            "content": [{ "type": "text", "text": "stable-ok" }],
                            "isError": false
                        }));
                    }
                    let prev = self.tool_failures.load(Ordering::SeqCst);
                    if prev > 0 {
                        self.tool_failures.store(prev - 1, Ordering::SeqCst);
                        Err(TransportError::Retry {
                            retry_after: Some(Duration::from_millis(50)),
                            message: "simulated 429".to_string(),
                        })
                    } else {
                        Ok(json!({
                            "content": [{ "type": "text", "text": "ok-after-retry" }],
                            "isError": false
                        }))
                    }
                }
                "resources/read" => {
                    let prev = self.resource_failures.load(Ordering::SeqCst);
                    if prev > 0 {
                        self.resource_failures.store(prev - 1, Ordering::SeqCst);
                        Err(TransportError::Retry {
                            retry_after: Some(Duration::from_millis(1)),
                            message: "retry resource".to_string(),
                        })
                    } else {
                        let uri = params.get("uri").and_then(|v| v.as_str()).unwrap_or("");
                        Ok(json!({ "contents": [{ "uri": uri, "text": "resource-ok" }] }))
                    }
                }
                "prompts/get" => {
                    let prev = self.prompt_failures.load(Ordering::SeqCst);
                    if prev > 0 {
                        self.prompt_failures.store(prev - 1, Ordering::SeqCst);
                        Err(TransportError::Retry {
                            retry_after: Some(Duration::from_millis(1)),
                            message: "retry prompt".to_string(),
                        })
                    } else {
                        let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        Ok(json!({ "messages": [{ "role": "user", "content": format!("gp:{name}") }] }))
                    }
                }
                other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    struct FatalMock;
    impl Transport for FatalMock {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, TransportError> {
            match method {
                "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
                "tools/list" => Ok(json!({ "tools": [{ "name": "boom", "description": "always fails" }] })),
                "tools/call" => Err(TransportError::Fatal("HTTP 500: server error".to_string())),
                other => Err(TransportError::Fatal(format!("unexpected method {other}"))),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn retry_server(id: &str, tool_failures: u32, resource_failures: u32, prompt_failures: u32) -> DownstreamServer {
        let mut ds = DownstreamServer::connect(
            id.to_string(),
            Box::new(RetryMock {
                tool_failures: Arc::new(AtomicU32::new(tool_failures)),
                resource_failures: Arc::new(AtomicU32::new(resource_failures)),
                prompt_failures: Arc::new(AtomicU32::new(prompt_failures)),
                tool_call_entries: Arc::new(AtomicU32::new(0)),
            }),
        )
        .unwrap();
        ds.load_resources_prompts();
        ds
    }

    fn retry_server_inspectable(
        id: &str,
        tool_failures: u32,
    ) -> (DownstreamServer, Arc<AtomicU32>) {
        let entries = Arc::new(AtomicU32::new(0));
        let mut ds = DownstreamServer::connect(
            id.to_string(),
            Box::new(RetryMock {
                tool_failures: Arc::new(AtomicU32::new(tool_failures)),
                resource_failures: Arc::new(AtomicU32::new(0)),
                prompt_failures: Arc::new(AtomicU32::new(0)),
                tool_call_entries: Arc::clone(&entries),
            }),
        )
        .unwrap();
        ds.load_resources_prompts();
        (ds, entries)
    }

    #[test]
    fn retry_succeeds_after_transient_failure() {
        let mut router = Router::new();
        router.add(retry_server("flaky", 1, 0, 0));
        let result = router.route_call("flaky__flaky", json!({})).unwrap();
        assert_eq!(result["content"][0]["text"], "ok-after-retry");
    }

    #[test]
    fn fatal_error_does_not_retry() {
        let mut router = Router::new();
        router.add(DownstreamServer::connect("fatal".to_string(), Box::new(FatalMock)).unwrap());
        let err = router.route_call("fatal__boom", json!({})).unwrap_err();
        assert!(err.contains("500"), "unexpected error: {err}");
    }

    #[test]
    fn get_prompt_also_retries() {
        let mut router = Router::new();
        router.add(retry_server("gp", 0, 0, 1));
        let result = router.get_prompt("gp__greet", json!({})).unwrap();
        assert_eq!(result["messages"][0]["content"], "gp:greet");
    }

    #[test]
    fn read_resource_also_retries() {
        let mut router = Router::new();
        router.add(retry_server("rr", 0, 1, 0));
        let result = router.read_resource("retry://res").unwrap();
        assert_eq!(result["contents"][0]["text"], "resource-ok");
    }

    #[test]
    fn retry_does_not_block_unrelated_server() {
        let slow = retry_server("slow", 1, 0, 0);
        let fast = mock_server("fast");
        let mut router = Router::new();
        router.add(slow);
        router.add(fast);

        let router = Arc::new(router);
        let router_a = Arc::clone(&router);
        let handle = std::thread::spawn(move || router_a.route_call("slow__flaky", json!({})));

        std::thread::sleep(Duration::from_millis(10));
        let fast_result = router.route_call("fast__echo", json!({}));
        assert!(fast_result.is_ok(), "fast server should not block behind slow retry");

        let slow_result = handle.join().unwrap();
        assert!(slow_result.is_ok(), "slow server should eventually succeed");
    }

    /// THE critical test: proves the per-server Mutex is RELEASED during the
    /// backoff sleep. Without the fix, call A would hold the lock while sleeping,
    /// and call B to the SAME server would block until A's retry completed.
    #[test]
    fn same_server_lock_released_during_backoff_sleep() {
        let (server, entries) = retry_server_inspectable("srv", 1);
        let mut router = Router::new();
        router.add(server);
        let router = Arc::new(router);

        let router1 = Arc::clone(&router);
        let handle = std::thread::spawn(move || router1.route_call("srv__flaky", json!({})));

        // Wait long enough for thread 1 to acquire the lock, get the 429, and
        // enter the backoff sleep — but NOT long enough for the 50ms retry.
        std::thread::sleep(Duration::from_millis(15));

        // Call the stable tool on the SAME server. If the fix is correct, the
        // lock was released during the backoff sleep, so this succeeds immediately.
        let result_b = router.route_call("srv__stable", json!({}));
        assert!(result_b.is_ok(), "same-server call should succeed during backoff sleep");
        let result = result_b.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "stable-ok");

        let result_a = handle.join().unwrap();
        assert!(result_a.is_ok(), "flaky call should succeed after retry");

        // At least 3 lock acquisitions: flaky 429, stable ok, flaky retry ok.
        assert!(
            entries.load(Ordering::SeqCst) >= 3,
            "expected >=3 tool/call lock acquisitions"
        );
    }
}
