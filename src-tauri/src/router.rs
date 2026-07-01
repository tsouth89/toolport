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

use serde_json::{json, Value};

use crate::downstream::{
    backoff_delay, DownstreamServer, TransportError, HTTP_MAX_RETRIES, HTTP_RETRY_CAP,
};

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

/// True if a tool advertises `destructiveHint: true` (MCP tool annotations).
/// Accepts the spec's nested `annotations.destructiveHint` and a top-level
/// fallback some servers emit.
pub fn is_destructive(tool: &Value) -> bool {
    tool.get("annotations")
        .and_then(|a| a.get("destructiveHint"))
        .and_then(|v| v.as_bool())
        .or_else(|| tool.get("destructiveHint").and_then(|v| v.as_bool()))
        .unwrap_or(false)
}

/// Which downstream tools the gateway is allowed to expose. Default-allow: an
/// empty policy passes everything. This is the enforcement point behind the
/// per-tool toggle and the global destructive-tool deny switch.
#[derive(Default, Clone)]
pub struct ToolPolicy {
    /// server id -> original tool names the user switched off.
    pub disabled: HashMap<String, HashSet<String>>,
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
}

#[derive(Default)]
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

    /// Index one server's advertised tools/resources/prompts into the exposed
    /// aggregation (names, routes, policy). Shared by `add` (a new server) and
    /// `rebuild_aggregation` (after a refresh); the call order is the exposed-name
    /// order, so `_2` collision suffixes stay stable.
    fn index_server(
        &mut self,
        server_id: &str,
        tools: &[Value],
        resources: &[Value],
        prompts: &[Value],
    ) {
        for tool in tools {
            let Some(orig) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            // Allocate the exposed name regardless of policy so toggling one tool
            // never renames its siblings (their `_2` suffixes stay put).
            let exposed = self.exposed_name(server_id, orig);
            if let Some(reason) = self.policy.blocked_reason(&exposed, server_id, orig, tool) {
                self.blocked.insert(exposed, reason.to_string());
                continue;
            }
            let mut t = tool.clone();
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

        // Prompts: namespace names like tools so two servers can't collide.
        for prompt in prompts {
            let Some(orig) = prompt.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let exposed = self.exposed_name(server_id, orig);
            let mut p = prompt.clone();
            p["name"] = json!(exposed);
            self.prompts.push(p);
            self.prompt_routes
                .insert(exposed, (server_id.to_string(), orig.to_string()));
        }
    }

    pub fn add(&mut self, server: DownstreamServer) {
        let id = server.id.clone();
        self.index_server(&id, &server.tools, &server.resources, &server.prompts);
        let idx = self.servers.len();
        self.servers.push(Arc::new(ServerSlot {
            id: id.clone(),
            inner: Mutex::new(server),
        }));
        self.by_id.insert(id, idx);
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
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

    /// Replace the quarantine set and re-derive the exposed aggregation so newly
    /// quarantined tools are hidden (or re-approved ones restored) without re-querying
    /// downstream. Cheap: it only re-applies the policy to the cached tool lists.
    pub fn requarantine(&mut self, quarantined: BTreeSet<String>) {
        self.policy.quarantined = quarantined;
        self.rebuild_aggregation();
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
        let mut attempt = 0u32;
        loop {
            let result = {
                let mut server = slot.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                f(&mut server)
            };
            match result {
                Ok(v) => return Ok(v),
                Err(TransportError::Retry { retry_after, message }) if attempt < HTTP_MAX_RETRIES => {
                    let wait = retry_wait(retry_after, attempt);
                    eprintln!("conduit: retrying downstream call after {wait:?}: {message}");
                    std::thread::sleep(wait);
                    attempt += 1;
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    /// Forward an exposed tool call to its owning downstream server, using that
    /// server's original tool name. Takes `&self`: it locks only the target
    /// server, so concurrent calls to different servers run in parallel while
    /// calls to the same server (one stdio pipe) serialize.
    pub fn route_call(&self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        if let Some(reason) = self.blocked.get(exposed_name) {
            return Err(format!("tool '{exposed_name}' is {reason}"));
        }
        let (server_id, tool) = self
            .routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for tool '{exposed_name}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| server.call(&tool, arguments.clone()))
    }

    /// Every downstream resource, uris unchanged.
    pub fn aggregated_resources(&self) -> Vec<Value> {
        self.resources.clone()
    }

    /// Every downstream prompt, with its exposed (namespaced) name.
    pub fn aggregated_prompts(&self) -> Vec<Value> {
        self.prompts.clone()
    }

    /// Read a resource by uri from whichever server advertised it. `&self`: locks
    /// only the owning server (see `route_call`).
    pub fn read_resource(&self, uri: &str) -> Result<Value, String> {
        let server_id = self
            .resource_routes
            .get(uri)
            .cloned()
            .ok_or_else(|| format!("no server owns resource '{uri}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| server.read_resource(uri))
    }

    /// Get a prompt by its exposed name, forwarding the server's real name.
    /// `&self`: locks only the owning server (see `route_call`).
    pub fn get_prompt(&self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        let (server_id, name) = self
            .prompt_routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for prompt '{exposed_name}'"))?;
        let slot = self.slot_for(&server_id)?;
        self.call_with_retry(&slot, |server| server.get_prompt(&name, arguments.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

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
    use crate::downstream::{DownstreamServer, Transport};

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

    #[test]
    fn sanitizes_hyphens_in_both_halves() {
        // Server ids and tool names with hyphens are rewritten to `_` so clients
        // like Cursor don't drop them.
        assert_eq!(sanitize_segment("file-system"), "file_system");
        assert_eq!(sanitize_segment("list-offerings"), "list_offerings");
        assert_eq!(sanitize_segment("already_ok"), "already_ok");
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
