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

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};

use crate::downstream::DownstreamServer;

/// Rewrite a name segment to the function-name charset clients accept
/// (`[A-Za-z0-9_]`); every other character becomes `_`.
pub fn sanitize_segment(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
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
}

impl ToolPolicy {
    /// Reason this tool is blocked, or `None` if it may be exposed.
    fn blocked_reason(&self, server_id: &str, orig: &str, tool: &Value) -> Option<&'static str> {
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
        None
    }
}

#[derive(Default)]
pub struct Router {
    servers: Vec<DownstreamServer>,
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

    pub fn add(&mut self, server: DownstreamServer) {
        for tool in &server.tools {
            let Some(orig) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            // Allocate the exposed name regardless of policy so toggling one tool
            // never renames its siblings (their `_2` suffixes stay put).
            let exposed = self.exposed_name(&server.id, orig);
            if let Some(reason) = self.policy.blocked_reason(&server.id, orig, tool) {
                self.blocked.insert(exposed, reason.to_string());
                continue;
            }
            let mut t = tool.clone();
            t["name"] = json!(exposed);
            self.tools.push(t);
            self.routes
                .insert(exposed, (server.id.clone(), orig.to_string()));
        }

        // Resources: pass uris through unchanged (they're already server-scoped)
        // and remember which server owns each, so resources/read can reach it.
        for resource in &server.resources {
            if let Some(uri) = resource.get("uri").and_then(|u| u.as_str()) {
                self.resources.push(resource.clone());
                self.resource_routes
                    .insert(uri.to_string(), server.id.clone());
            }
        }

        // Prompts: namespace names like tools so two servers can't collide.
        for prompt in &server.prompts {
            let Some(orig) = prompt.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let exposed = self.exposed_name(&server.id, orig);
            let mut p = prompt.clone();
            p["name"] = json!(exposed);
            self.prompts.push(p);
            self.prompt_routes
                .insert(exposed, (server.id.clone(), orig.to_string()));
        }

        self.servers.push(server);
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
        for server in &mut self.servers {
            server.refresh_tools();
        }
        self.reindex();
    }

    /// Re-derive the exposed tool/resource/prompt aggregation from the current
    /// servers' (possibly refreshed) lists. Order is preserved, so exposed names
    /// and their `_2` collision suffixes stay stable across a refresh.
    fn reindex(&mut self) {
        let servers = std::mem::take(&mut self.servers);
        self.tools.clear();
        self.routes.clear();
        self.seen.clear();
        self.blocked.clear();
        self.resources.clear();
        self.resource_routes.clear();
        self.prompts.clear();
        self.prompt_routes.clear();
        for server in servers {
            self.add(server);
        }
    }

    /// Forward an exposed tool call to its owning downstream server, using that
    /// server's original tool name.
    pub fn route_call(&mut self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        if let Some(reason) = self.blocked.get(exposed_name) {
            return Err(format!("tool '{exposed_name}' is {reason}"));
        }
        let (server_id, tool) = self
            .routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for tool '{exposed_name}'"))?;
        let server = self
            .servers
            .iter_mut()
            .find(|s| s.id == server_id)
            .ok_or_else(|| format!("no connected server '{server_id}'"))?;
        server.call(&tool, arguments)
    }

    /// Every downstream resource, uris unchanged.
    pub fn aggregated_resources(&self) -> Vec<Value> {
        self.resources.clone()
    }

    /// Every downstream prompt, with its exposed (namespaced) name.
    pub fn aggregated_prompts(&self) -> Vec<Value> {
        self.prompts.clone()
    }

    /// Read a resource by uri from whichever server advertised it.
    pub fn read_resource(&mut self, uri: &str) -> Result<Value, String> {
        let server_id = self
            .resource_routes
            .get(uri)
            .cloned()
            .ok_or_else(|| format!("no server owns resource '{uri}'"))?;
        let server = self
            .servers
            .iter_mut()
            .find(|s| s.id == server_id)
            .ok_or_else(|| format!("no connected server '{server_id}'"))?;
        server.read_resource(uri)
    }

    /// Get a prompt by its exposed name, forwarding the server's real name.
    pub fn get_prompt(&mut self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
        let (server_id, name) = self
            .prompt_routes
            .get(exposed_name)
            .cloned()
            .ok_or_else(|| format!("no route for prompt '{exposed_name}'"))?;
        let server = self
            .servers
            .iter_mut()
            .find(|s| s.id == server_id)
            .ok_or_else(|| format!("no connected server '{server_id}'"))?;
        server.get_prompt(&name, arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::downstream::{DownstreamServer, Transport};

    /// A fake downstream server: advertises `echo` + `add`, echoes calls back.
    struct MockTransport {
        label: String,
    }

    impl Transport for MockTransport {
        fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
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
                other => Err(format!("unexpected method {other}")),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), String> {
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
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
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
                other => Err(format!("unexpected method {other}")),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), String> {
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
}
