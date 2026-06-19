//! A minimal MCP server used as a test fixture for the gateway's downstream
//! proxying. Exposes two tools: `echo` (returns its `text` arg) and `add`
//! (returns `a + b`). Self-contained: no dependency on conduit_lib.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

fn success(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn handle(req: &Value) -> Option<Value> {
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
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock-mcp-server", "version": "0.1.0" }
            }),
        )),
        "tools/list" => Some(success(
            id,
            json!({
                "tools": [
                    { "name": "echo", "description": "Echo back the text argument.",
                      "inputSchema": { "type": "object", "properties": { "text": { "type": "string" } } } },
                    { "name": "add", "description": "Add two numbers a and b.",
                      "inputSchema": { "type": "object", "properties": { "a": { "type": "number" }, "b": { "type": "number" } } } }
                ]
            }),
        )),
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
        if let Some(resp) = handle(&req) {
            if writeln!(out, "{resp}").is_err() {
                break;
            }
            let _ = out.flush();
        }
    }
}
