//! A minimal MCP server used as a test fixture for the gateway's downstream
//! proxying. Exposes `echo` (returns its `text` arg), `add` (returns `a + b`),
//! and `grow`. Calling `grow` adds a `greet` tool to the list and emits a
//! `notifications/tools/list_changed`, simulating a server that changes its own
//! tool set mid-session, so the gateway's live tool-refresh can be exercised.
//! Self-contained: no dependency on conduit_lib.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// The advertised tool list. `greet` only appears once the server has "grown"
/// (after a `grow` call), modeling a runtime tool-set change.
fn tool_list(grown: bool) -> Value {
    let mut tools = vec![
        json!({ "name": "echo", "description": "Echo back the text argument.",
                "inputSchema": { "type": "object", "properties": { "text": { "type": "string" } } } }),
        json!({ "name": "add", "description": "Add two numbers a and b.",
                "inputSchema": { "type": "object", "properties": { "a": { "type": "number" }, "b": { "type": "number" } } } }),
        json!({ "name": "grow", "description": "Add a new tool and announce tools/list_changed.",
                "inputSchema": { "type": "object", "properties": {} } }),
    ];
    if grown {
        tools.push(json!({ "name": "greet", "description": "Greet someone by name.",
                "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } } } }));
    }
    json!({ "tools": tools })
}

/// Handle one request, returning its response. `grown` is flipped on by a `grow`
/// call so the next `tools/list` reflects the larger set.
fn handle(req: &Value, grown: &mut bool) -> Option<Value> {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = match req.get("id") {
        Some(id) if !id.is_null() => id.clone(),
        _ => return None,
    };

    match method {
        "initialize" => Some(success(
            id,
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": { "listChanged": true } },
                "serverInfo": { "name": "mock-mcp-server", "version": "0.1.0" }
            }),
        )),
        "tools/list" => Some(success(id, tool_list(*grown))),
        "tools/call" => {
            let params = req.get("params");
            let name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
            let args = params.and_then(|p| p.get("arguments")).cloned().unwrap_or_else(|| json!({}));
            let text = match name {
                "echo" => args.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                "add" => {
                    let a = args.get("a").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let b = args.get("b").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    format!("{}", a + b)
                }
                "grow" => {
                    *grown = true;
                    "grew: greet is now available".to_string()
                }
                "greet" => {
                    let who = args.get("name").and_then(|t| t.as_str()).unwrap_or("there");
                    format!("hello {who}")
                }
                other => format!("unknown tool {other}"),
            };
            Some(success(
                id,
                json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
            ))
        }
        "ping" => Some(success(id, json!({}))),
        _ => None,
    }
}

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut grown = false;
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
        let was_grown = grown;
        if let Some(resp) = handle(&req, &mut grown) {
            if writeln!(out, "{resp}").is_err() {
                break;
            }
            let _ = out.flush();
        }
        // A `grow` call just changed the tool set: announce it (after the call
        // response) so a watching gateway re-fetches and surfaces the new tool.
        if grown && !was_grown {
            let notif = json!({ "jsonrpc": "2.0", "method": "notifications/tools/list_changed" });
            if writeln!(out, "{notif}").is_err() {
                break;
            }
            let _ = out.flush();
        }
    }
}
