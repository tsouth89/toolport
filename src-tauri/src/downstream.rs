//! Downstream MCP client.
//!
//! The gateway is an MCP *server* to the AI client, and an MCP *client* to each
//! real server behind it. This module is that client half: it speaks JSON-RPC to
//! one downstream server over a transport, does the handshake, and lists/calls
//! its tools. The transport is abstracted so the router can be tested with a mock
//! instead of spawning real processes.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Max time to wait for a single stdio response before giving up. Without this a
/// server that never replies would block its thread (and the batch health probe)
/// forever.
const STDIO_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Tighter bound for the connect handshake (initialize + tools/list). The batch
/// probe and every router rebuild connect to all servers and wait on the slowest,
/// so one hung server should fail in seconds, not stall everything for the full
/// live-call timeout. Restored to STDIO_READ_TIMEOUT once connected.
const STDIO_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Keep at most this many bytes of a child's stderr tail for error reporting.
const STDERR_TAIL_CAP: usize = 4096;

/// Cap on how much of a downstream HTTP/SSE response body we buffer, so a malicious
/// or broken server can't stream gigabytes to exhaust gateway memory. Generous: real
/// MCP responses are tiny.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Read up to `max` bytes of a ureq response body, lossily as text, never more than
/// the cap even if the server keeps streaming.
fn read_capped(resp: ureq::Response, max: u64) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(max).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

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

/// A PATH that includes the user's real shell PATH plus common install dirs.
/// macOS GUI apps (and apps they launch, like the client-spawned gateway) inherit
/// only a minimal PATH, so `npx`/`uvx`/`node` aren't found without this. Computed
/// once and cached.
#[cfg(not(windows))]
pub fn augmented_path() -> &'static str {
    use std::sync::OnceLock;
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED.get_or_init(|| {
        let mut dirs_list: Vec<String> = std::env::var("PATH")
            .ok()
            .map(|p| p.split(':').map(String::from).collect())
            .unwrap_or_default();
        let mut push = |d: String, list: &mut Vec<String>| {
            if !d.is_empty() && !list.iter().any(|x| *x == d) {
                list.push(d);
            }
        };
        // Best effort: the login shell's PATH (covers nvm/asdf/homebrew/volta).
        if let Ok(shell) = std::env::var("SHELL") {
            if let Ok(out) = std::process::Command::new(&shell)
                .args(["-ilc", "printf %s \"$PATH\""])
                .output()
            {
                if out.status.success() {
                    for d in String::from_utf8_lossy(&out.stdout).split(':') {
                        push(d.to_string(), &mut dirs_list);
                    }
                }
            }
        }
        if let Some(home) = dirs::home_dir() {
            for sub in [".local/bin", ".cargo/bin", ".bun/bin"] {
                push(home.join(sub).to_string_lossy().into_owned(), &mut dirs_list);
            }
        }
        for d in ["/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin"] {
            push(d.to_string(), &mut dirs_list);
        }
        dirs_list.join(":")
    })
}

#[cfg(not(windows))]
pub fn resolve_command(command: &str) -> String {
    if command.contains('/') {
        return command.to_string();
    }
    for dir in augmented_path().split(':').filter(|d| !d.is_empty()) {
        let candidate = Path::new(dir).join(command);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    command.to_string()
}

/// A bidirectional JSON-RPC channel to one downstream server.
pub trait Transport: Send {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
    fn notify(&mut self, method: &str, params: Value) -> Result<(), String>;
    /// Bound how long a single `request` waits for its response. Used to fail the
    /// connect handshake fast. Default no-op: transports with their own fixed
    /// request timeout (e.g. HTTP) ignore it.
    fn set_read_timeout(&mut self, _timeout: Duration) {}
    /// Start reacting to the server's own `notifications/tools/list_changed`.
    /// Called once the connect handshake is done, so a server that announces its
    /// tools during startup doesn't trigger a needless rebuild. Default no-op:
    /// transports without a live notification stream ignore it.
    fn arm_tools_watch(&mut self) {}
}

/// True if `line` is a downstream `notifications/tools/list_changed` message: a
/// JSON-RPC notification (a `method` of that name, no `id`). Lets the stdout drain
/// spot when a server changes its own tool set mid-session.
fn is_list_changed(line: &str) -> bool {
    // Cheap gate: skip the JSON parse for the overwhelming majority of lines
    // (ordinary responses to our requests) that can't be this notification.
    if !line.contains("tools/list_changed") {
        return false;
    }
    serde_json::from_str::<Value>(line.trim())
        .ok()
        .and_then(|v| {
            v.get("method")
                .and_then(|m| m.as_str())
                .map(|m| m == "notifications/tools/list_changed")
        })
        .unwrap_or(false)
}

/// Forward one drained stdout line to the request loop, first flagging `dirty` if
/// the server (once `armed`) announced a tool-list change. Returns false when the
/// receiver is gone (transport closed) so the drain loop can stop.
fn forward_line(
    line: String,
    tx: &Sender<String>,
    dirty: &Option<Arc<AtomicBool>>,
    armed: &Arc<AtomicBool>,
) -> bool {
    if let Some(flag) = dirty {
        if armed.load(Ordering::SeqCst) && is_list_changed(&line) {
            flag.store(true, Ordering::SeqCst);
        }
    }
    tx.send(line).is_ok()
}

/// Talks to a downstream MCP server over its stdio (a spawned child process).
/// Stdout is drained on a background thread into a channel so reads can time out
/// (a blocking `read_line` on an unresponsive child would otherwise hang forever).
pub struct StdioTransport {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<String>,
    /// Tail of the child's stderr, drained on a background thread. A server that
    /// dies on startup (bad package name, missing API key) explains itself here,
    /// so we can report that instead of a bare "closed the connection".
    stderr: Arc<Mutex<String>>,
    next_id: i64,
    /// How long a single request waits for its response. Lowered during the
    /// connect handshake, then restored for (potentially slow) live tool calls.
    read_timeout: Duration,
    /// Gate shared with the stdout drain: the drain only flags a `dirty` signal
    /// once this is set, so tool-list changes announced during startup are
    /// ignored. Flipped on by `arm_tools_watch` after the handshake.
    armed: Arc<AtomicBool>,
}

impl StdioTransport {
    /// Spawn a downstream server without watching for its tool-list changes.
    /// Used by one-shot callers (the app's health probe and playground) that
    /// don't keep the connection around to react to live notifications.
    pub fn spawn(command: &str, args: &[String], env: &[(String, String)]) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, None)
    }

    /// Like [`spawn`], but flips `dirty` to true whenever the downstream server
    /// emits `notifications/tools/list_changed` (after `arm_tools_watch`). The
    /// gateway watches that flag and rebuilds, so a server changing its own tool
    /// set mid-session reaches the client instead of being silently dropped.
    pub fn spawn_watched(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        dirty: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, Some(dirty))
    }

    fn spawn_inner(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        dirty: Option<Arc<AtomicBool>>,
    ) -> Result<Self, String> {
        let resolved = resolve_command(command);
        let mut cmd = Command::new(&resolved);
        cmd.args(args)
            .envs(env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Give the child the augmented PATH too, so e.g. `npx` can find `node`.
        #[cfg(not(windows))]
        cmd.env("PATH", augmented_path());
        // CREATE_NO_WINDOW: without it, every stdio server we spawn flashes a
        // console window on Windows (very visible during a probe/refresh, which
        // spawns one per server). The app and the gateway both spawn through here.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn '{command}': {e}"))?;
        let stdin = child.stdin.take().ok_or("no child stdin")?;
        let stdout = child.stdout.take().ok_or("no child stdout")?;
        let stderr = child.stderr.take().ok_or("no child stderr")?;

        // Drain stdout line-by-line on a dedicated thread; the request loop pulls
        // from the channel with a timeout. The thread ends on EOF/read error or
        // when the receiver is dropped (transport closed). `forward_line` also
        // flags `dirty` when an armed server announces a tool-list change.
        let (tx, rx) = std::sync::mpsc::channel();
        let armed = Arc::new(AtomicBool::new(false));
        let drain_armed = Arc::clone(&armed);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if !forward_line(line, &tx, &dirty, &drain_armed) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Drain stderr into a shared buffer, capped so a chatty server can't grow
        // it without bound. We keep the most recent output (where the fatal error
        // usually is).
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let stderr_writer = Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if let Ok(mut buf) = stderr_writer.lock() {
                    buf.push_str(&line);
                    if buf.len() > STDERR_TAIL_CAP {
                        let cut = buf.len() - STDERR_TAIL_CAP;
                        buf.drain(..cut);
                    }
                }
                line.clear();
            }
        });

        Ok(StdioTransport {
            child,
            stdin,
            rx,
            stderr: stderr_buf,
            next_id: 1,
            read_timeout: STDIO_READ_TIMEOUT,
            armed,
        })
    }

    /// Build a useful error for when the child's stdout closed (it exited or
    /// crashed). Includes the exit status and the tail of stderr when available -
    /// that is where "package not found" or "missing API key" actually shows up.
    fn closed_error(&mut self) -> String {
        // The child just exited; give its stderr drain a brief moment to flush.
        std::thread::sleep(Duration::from_millis(150));
        let status = self.child.try_wait().ok().flatten();
        let tail = self
            .stderr
            .lock()
            .map(|b| b.trim().to_string())
            .unwrap_or_default();
        let mut msg = String::from("downstream server exited");
        if let Some(code) = status.and_then(|s| s.code()) {
            msg.push_str(&format!(" (status {code})"));
        }
        if tail.is_empty() {
            msg.push_str(" without output. Check the command, args, and any required API keys.");
        } else {
            msg.push_str(":\n");
            msg.push_str(&tail);
        }
        msg
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
        // The deadline bounds the whole wait so an unresponsive server fails fast
        // instead of hanging the thread (and the batch probe) indefinitely.
        let deadline = Instant::now() + self.read_timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or_default();
            let line = match self.rx.recv_timeout(remaining) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("timed out waiting for '{method}' response"))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(self.closed_error())
                }
            };
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

    fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    fn arm_tools_watch(&mut self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Normalize a JSON-RPC id (number or string) to a string for comparison.
fn id_key(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Whether an SSE message's id matches the request id. Tolerant of number-vs-string
/// encoding (some servers echo a numeric id as a string). A `None` wanted id means
/// take the first message (used when we didn't send an id).
fn ids_match(got: Option<&Value>, wanted: Option<&Value>) -> bool {
    match wanted {
        None => true,
        Some(w) => match (id_key(w), got.and_then(id_key)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
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
                // Never follow redirects. MCP Streamable HTTP doesn't need cross-host
                // redirects, and following one would let a malicious server bounce us to
                // an internal address (SSRF, e.g. cloud metadata) or replay our
                // Authorization bearer to a host of its choosing (token theft).
                .redirects(0)
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
                let detail: String = read_capped(r, 64 * 1024).chars().take(200).collect();
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
        let text = read_capped(resp, MAX_RESPONSE_BYTES);

        if is_sse {
            for line in text.lines() {
                let line = line.trim_start();
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();
                    if data.is_empty() {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<Value>(data) {
                        if ids_match(v.get("id"), wanted.as_ref()) {
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

/// One connected downstream server: its id, its transport, and its cached
/// tools, resources, and prompts.
pub struct DownstreamServer {
    pub id: String,
    transport: Box<dyn Transport>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    /// Whether the server's `initialize` advertised resources / prompts. The
    /// actual lists are fetched lazily via `load_resources_prompts`.
    caps_resources: bool,
    caps_prompts: bool,
}

impl DownstreamServer {
    /// Handshake with the server and fetch its tool list. Resources and prompts
    /// are NOT fetched here - only whether the server advertises them is noted,
    /// so the health probe (which connects to every server in one batch) stays
    /// tools-only and fast and can't stall on a slow or hanging resources/prompts
    /// endpoint. The gateway calls `load_resources_prompts` to populate them.
    pub fn connect(id: String, mut transport: Box<dyn Transport>) -> Result<Self, String> {
        // Fail the handshake fast so one unresponsive server can't stall the whole
        // batch probe / router rebuild for the full live-call timeout.
        transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        let init = transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "conduit-gateway", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        let caps = init.get("capabilities");
        let caps_resources = caps.and_then(|c| c.get("resources")).is_some();
        let caps_prompts = caps.and_then(|c| c.get("prompts")).is_some();
        transport.notify("notifications/initialized", json!({}))?;

        let result = transport.request("tools/list", json!({}))?;
        let tools = extract_array(&result, "tools");

        // Restore the longer timeout: actual tool calls can legitimately be slow.
        transport.set_read_timeout(STDIO_READ_TIMEOUT);
        // Handshake done: from here on, react to the server's own tool-list
        // changes (ignored until now so a startup announcement is a no-op).
        transport.arm_tools_watch();

        Ok(DownstreamServer {
            id,
            transport,
            tools,
            resources: Vec::new(),
            prompts: Vec::new(),
            caps_resources,
            caps_prompts,
        })
    }

    /// Re-fetch the server's tool list on the existing connection, after it
    /// announced a `tools/list_changed`. Bounds the wait like the handshake so a
    /// hung server can't stall the refresh; on error the previous list is kept.
    pub fn refresh_tools(&mut self) {
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        if let Ok(result) = self.transport.request("tools/list", json!({})) {
            self.tools = extract_array(&result, "tools");
        }
        self.transport.set_read_timeout(STDIO_READ_TIMEOUT);
    }

    /// Fetch the resources and prompts the server advertised. Best-effort: an
    /// error or empty response just leaves the list empty. Kept out of `connect`
    /// so only the gateway (which actually proxies these) pays the cost.
    pub fn load_resources_prompts(&mut self) {
        if self.caps_resources {
            if let Ok(r) = self.transport.request("resources/list", json!({})) {
                self.resources = extract_array(&r, "resources");
            }
        }
        if self.caps_prompts {
            if let Ok(r) = self.transport.request("prompts/list", json!({})) {
                self.prompts = extract_array(&r, "prompts");
            }
        }
    }

    pub fn call(&mut self, tool: &str, arguments: Value) -> Result<Value, String> {
        self.transport
            .request("tools/call", json!({ "name": tool, "arguments": arguments }))
    }

    /// Read one resource by its (original, downstream) uri.
    pub fn read_resource(&mut self, uri: &str) -> Result<Value, String> {
        self.transport
            .request("resources/read", json!({ "uri": uri }))
    }

    /// Get one prompt by its (original, downstream) name.
    pub fn get_prompt(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        self.transport
            .request("prompts/get", json!({ "name": name, "arguments": arguments }))
    }
}

/// Pull a named array field out of a JSON-RPC result, or an empty vec.
fn extract_array(result: &Value, key: &str) -> Vec<Value> {
    result
        .get(key)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
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

    #[test]
    fn ids_match_tolerates_number_vs_string() {
        use super::ids_match;
        use serde_json::json;
        assert!(ids_match(Some(&json!(1)), Some(&json!(1))));
        // A server that echoes the numeric id as a string still matches.
        assert!(ids_match(Some(&json!("1")), Some(&json!(1))));
        assert!(ids_match(Some(&json!(1)), Some(&json!("1"))));
        assert!(!ids_match(Some(&json!(2)), Some(&json!(1))));
        // No id requested -> take the first message.
        assert!(ids_match(Some(&json!(1)), None));
        // Wanted an id but the message has none -> no match.
        assert!(!ids_match(None, Some(&json!(1))));
    }

    #[test]
    fn recognizes_a_tools_list_changed_notification() {
        use super::is_list_changed;
        assert!(is_list_changed(
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#
        ));
        assert!(is_list_changed(
            "  {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n"
        ));
        // A response to our own tools/list call is not the notification.
        assert!(!is_list_changed(r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#));
        // Other notifications and unrelated lines are ignored (and skip the parse).
        assert!(!is_list_changed(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#
        ));
        assert!(!is_list_changed("not json at all"));
        assert!(!is_list_changed(""));
    }

    #[test]
    fn forward_line_flags_dirty_only_when_armed() {
        use super::forward_line;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let notif = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let dirty = Some(Arc::new(AtomicBool::new(false)));
        let armed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();

        // Unarmed (still in the handshake window): the line is forwarded but the
        // change is not acted on.
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed));
        assert!(!dirty.as_ref().unwrap().load(Ordering::SeqCst));
        assert_eq!(rx.recv().unwrap(), notif);

        // Armed: the same notification now flips the dirty flag.
        armed.store(true, Ordering::SeqCst);
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed));
        assert!(dirty.as_ref().unwrap().load(Ordering::SeqCst));
        assert_eq!(rx.recv().unwrap(), notif);

        // An ordinary line is always forwarded and never flags a change.
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let dirty2 = Some(Arc::new(AtomicBool::new(false)));
        assert!(forward_line(resp.to_string(), &tx, &dirty2, &armed));
        assert!(!dirty2.as_ref().unwrap().load(Ordering::SeqCst));
        assert_eq!(rx.recv().unwrap(), resp);

        // A closed receiver makes forward_line report "stop".
        drop(rx);
        assert!(!forward_line(notif.to_string(), &tx, &dirty, &armed));
    }
}
