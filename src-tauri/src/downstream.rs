//! Downstream MCP client.
//!
//! The gateway is an MCP *server* to the AI client, and an MCP *client* to each
//! real server behind it. This module is that client half: it speaks JSON-RPC to
//! one downstream server over a transport, does the handshake, and lists/calls
//! its tools. The transport is abstracted so the router can be tested with a mock
//! instead of spawning real processes.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Build an `Authorization` header value from a raw token, adding the `Bearer`
/// scheme unless the caller already included one.
pub fn bearer_header(token: &str) -> String {
    if token.to_lowercase().starts_with("bearer ") {
        token.to_string()
    } else {
        format!("Bearer {token}")
    }
}

/// Resolve a bare command to a concrete executable.
///
/// On Windows, Node tooling lives in `.cmd` shims (`npx` is really `npx.cmd`),
/// and `Command::new("npx")` won't find it. Search PATH with PATHEXT so bare
/// commands resolve. (Rust 1.77.2+ then runs the resolved `.cmd` via cmd.exe.)
#[cfg(windows)]
pub fn resolve_command(command: &str) -> String {
    let p = Path::new(command);
    if p.extension().is_some() || command.contains('\\') || command.contains('/') {
        return command.to_string();
    }
    let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(';').filter(|d| !d.is_empty()) {
            for ext in exts.split(';').filter(|e| !e.is_empty()) {
                let candidate = Path::new(dir).join(format!("{command}{ext}"));
                if candidate.is_file() {
                    return candidate.to_string_lossy().into_owned();
                }
            }
        }
    }
    command.to_string()
}

#[cfg(not(windows))]
pub fn resolve_command(command: &str) -> String {
    command.to_string()
}

/// A bidirectional JSON-RPC channel to one downstream server.
pub trait Transport: Send {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
    fn notify(&mut self, method: &str, params: Value) -> Result<(), String>;
}

/// Talks to a downstream MCP server over its stdio (a spawned child process).
pub struct StdioTransport {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: i64,
}

impl StdioTransport {
    pub fn spawn(command: &str, args: &[String], env: &[(String, String)]) -> Result<Self, String> {
        let resolved = resolve_command(command);
        let mut cmd = Command::new(&resolved);
        cmd.args(args)
            .envs(env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn '{command}': {e}"))?;
        let stdin = child.stdin.take().ok_or("no child stdin")?;
        let stdout = child.stdout.take().ok_or("no child stdout")?;
        Ok(StdioTransport {
            child,
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
        })
    }
}

impl Transport for StdioTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{msg}").map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;

        // Read until the response with our id arrives, skipping notifications.
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("downstream server closed the connection".to_string());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if value.get("id").and_then(|i| i.as_i64()) == Some(id) {
                if let Some(err) = value.get("error") {
                    return Err(err.to_string());
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        writeln!(self.stdin, "{msg}").map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Talks to a remote MCP server over the Streamable HTTP transport: each request
/// is a POST, and the response is either a JSON body or an SSE stream carrying
/// the JSON-RPC message. A session id from `initialize` is echoed on later calls.
pub struct HttpTransport {
    url: String,
    agent: ureq::Agent,
    session_id: Option<String>,
    next_id: i64,
    /// Raw bearer token (without the "Bearer " prefix), if the server needs auth.
    auth: Option<String>,
}

impl HttpTransport {
    pub fn new(url: &str) -> Self {
        Self::with_auth(url, None)
    }

    pub fn with_auth(url: &str, auth: Option<String>) -> Self {
        HttpTransport {
            url: url.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
            session_id: None,
            next_id: 1,
            auth,
        }
    }

    fn post(&mut self, body: &Value, expect_response: bool) -> Result<Option<Value>, String> {
        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json, text/event-stream")
            .set("MCP-Protocol-Version", PROTOCOL_VERSION);
        if let Some(sid) = &self.session_id {
            req = req.set("Mcp-Session-Id", sid);
        }
        if let Some(token) = &self.auth {
            req = req.set("Authorization", &bearer_header(token));
        }

        let resp = match req.send_string(&body.to_string()) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let detail: String = r
                    .into_string()
                    .unwrap_or_default()
                    .chars()
                    .take(200)
                    .collect();
                let hint = if code == 401 || code == 403 {
                    " (needs authentication)"
                } else {
                    ""
                };
                return Err(format!("HTTP {code}{hint}: {detail}"));
            }
            Err(e) => return Err(e.to_string()),
        };

        if let Some(sid) = resp.header("Mcp-Session-Id") {
            self.session_id = Some(sid.to_string());
        }
        if !expect_response {
            return Ok(None);
        }

        let is_sse = resp
            .header("content-type")
            .map(|c| c.to_lowercase().contains("text/event-stream"))
            .unwrap_or(false);
        let wanted = body.get("id").cloned();
        let text = resp.into_string().map_err(|e| e.to_string())?;

        if is_sse {
            for line in text.lines() {
                let line = line.trim_start();
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();
                    if data.is_empty() {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(data) {
                        if wanted.is_none() || v.get("id") == wanted.as_ref() {
                            return Ok(Some(v));
                        }
                    }
                }
            }
            Err("no matching message in SSE stream".to_string())
        } else {
            serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| format!("bad JSON response: {e}"))
        }
    }
}

impl Transport for HttpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = self.post(&body, true)?.ok_or("empty response")?;
        if let Some(err) = resp.get("error") {
            return Err(err.to_string());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.post(&body, false)?;
        Ok(())
    }
}

/// One connected downstream server: its id, its transport, and its cached tools.
pub struct DownstreamServer {
    pub id: String,
    transport: Box<dyn Transport>,
    pub tools: Vec<Value>,
}

impl DownstreamServer {
    /// Handshake with the server and fetch its tool list.
    pub fn connect(id: String, mut transport: Box<dyn Transport>) -> Result<Self, String> {
        transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "conduit-gateway", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        transport.notify("notifications/initialized", json!({}))?;
        let result = transport.request("tools/list", json!({}))?;
        let tools = result
            .get("tools")
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(DownstreamServer {
            id,
            transport,
            tools,
        })
    }

    pub fn call(&mut self, tool: &str, arguments: Value) -> Result<Value, String> {
        self.transport
            .request("tools/call", json!({ "name": tool, "arguments": arguments }))
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_command;

    #[test]
    fn paths_with_extension_pass_through() {
        assert_eq!(resolve_command("C:\\tools\\foo.exe"), "C:\\tools\\foo.exe");
    }

    #[test]
    #[cfg(windows)]
    fn resolves_bare_command_via_pathext() {
        // `cmd` is always on PATH on Windows; it should resolve to a real file.
        let resolved = resolve_command("cmd");
        assert!(
            resolved.to_lowercase().ends_with("cmd.exe"),
            "expected cmd.exe, got {resolved}"
        );
    }

    #[test]
    fn bearer_header_adds_scheme_once() {
        assert_eq!(super::bearer_header("sk-123"), "Bearer sk-123");
        assert_eq!(super::bearer_header("Bearer sk-123"), "Bearer sk-123");
        assert_eq!(super::bearer_header("bearer sk-123"), "bearer sk-123");
    }
}
