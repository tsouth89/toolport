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

#[derive(Default)]
pub struct Router {
    servers: Vec<DownstreamServer>,
    /// Exposed (client-facing) tools, names already sanitized, in add order.
    tools: Vec<Value>,
    /// Exposed tool name -> (server id, original downstream tool name).
    routes: HashMap<String, (String, String)>,
    /// Exposed names already handed out, for collision disambiguation.
    seen: HashSet<String>,
}

impl Router {
    pub fn new() -> Self {
        Router::default()
    }

    pub fn add(&mut self, server: DownstreamServer) {
        for tool in &server.tools {
            let Some(orig) = tool.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let exposed = self.exposed_name(&server.id, orig);
            let mut t = tool.clone();
            t["name"] = json!(exposed);
            self.tools.push(t);
            self.routes
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

    /// Forward an exposed tool call to its owning downstream server, using that
    /// server's original tool name.
    pub fn route_call(&mut self, exposed_name: &str, arguments: Value) -> Result<Value, String> {
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
                "initialize" => Ok(json!({ "protocolVersion": "2025-06-18" })),
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
                other => Err(format!("unexpected method {other}")),
            }
        }
        fn notify(&mut self, _method: &str, _params: Value) -> Result<(), String> {
            Ok(())
        }
    }

    fn mock_server(id: &str) -> DownstreamServer {
        DownstreamServer::connect(
            id.to_string(),
            Box::new(MockTransport {
                label: id.to_string(),
            }),
        )
        .unwrap()
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
}
