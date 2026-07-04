//! A minimal MCP server used as a test fixture for the gateway's downstream
//! proxying. Exposes `echo` (returns its `text` arg), `add` (returns `a + b`),
//! and `grow`, plus a baseline resource and prompt. Calling `grow` adds a `greet`
//! tool, a `mock://grown` resource, and a `grown_prompt`, then emits the tools,
//! resources, and prompts `list_changed` notifications, simulating a server that
//! changes its own catalog mid-session so the gateway's live refresh can be
//! exercised for all three kinds. Self-contained: no dependency on conduit_lib.

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
        json!({ "name": "die", "description": "Exit the process to simulate a mid-session crash.",
                "inputSchema": { "type": "object", "properties": {} } }),
    ];
    if grown {
        tools.push(json!({ "name": "greet", "description": "Greet someone by name.",
                "inputSchema": { "type": "object", "properties": { "name": { "type": "string" } } } }));
    }
    json!({ "tools": tools })
}

/// The advertised resource list. `grown` adds a second resource, modeling a
/// runtime `resources/list_changed`.
fn resource_list(grown: bool) -> Value {
    let mut resources = vec![json!({ "uri": "mock://base", "name": "base" })];
    if grown {
        resources.push(json!({ "uri": "mock://grown", "name": "grown" }));
    }
    json!({ "resources": resources })
}

/// The advertised prompt list. `grown` adds a second prompt, modeling a runtime
/// `prompts/list_changed`.
fn prompt_list(grown: bool) -> Value {
    let mut prompts = vec![json!({ "name": "hi", "description": "Say hi." })];
    if grown {
        prompts.push(json!({ "name": "grown_prompt", "description": "A newly grown prompt." }));
    }
    json!({ "prompts": prompts })
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
                "capabilities": {
                    "tools": { "listChanged": true },
                    "resources": { "listChanged": true },
                    "prompts": { "listChanged": true }
                },
                "serverInfo": { "name": "mock-mcp-server", "version": "0.1.0" }
            }),
        )),
        "tools/list" => Some(success(id, tool_list(*grown))),
        "resources/list" => Some(success(id, resource_list(*grown))),
        "prompts/list" => Some(success(id, prompt_list(*grown))),
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
                "die" => {
                    // Crash without responding, so the gateway sees the connection die
                    // (used to exercise the circuit breaker).
                    std::process::exit(0);
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
        // A `grow` call just changed all three lists: announce each (after the call
        // response) so a watching gateway re-fetches and surfaces the new entries.
        if grown && !was_grown {
            for method in [
                "notifications/tools/list_changed",
                "notifications/resources/list_changed",
                "notifications/prompts/list_changed",
            ] {
                let notif = json!({ "jsonrpc": "2.0", "method": method });
                if writeln!(out, "{notif}").is_err() {
                    return;
                }
            }
            let _ = out.flush();
        }
    }
}
