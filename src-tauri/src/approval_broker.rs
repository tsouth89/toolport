//! App-side HITL approval broker.
//!
//! The Toolport app hosts this broker; every `toolport-gateway` process (one per stdio
//! client, plus the app's `--http` bridge) dials OUT to it when it holds a gated tool
//! call, and blocks reading for the decision. This is the counterpart to the gateway's
//! `request_human_decision` (see `bin/toolport-gateway.rs`).
//!
//! Protocol: the gateway connects over loopback TCP, sends one JSON line
//! ([`ApprovalRequest`]) carrying the shared token, and reads one JSON line back
//! ([`ApprovalDecision`]). Arguments travel over the socket and are never written to
//! disk. The only thing on disk is the endpoint descriptor (address + token). The
//! human decides in the app UI; a fail-closed timeout denies. Transport is loopback
//! TCP + token for now; hardening to a named-pipe / uds is a follow-up.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::approval::{
    ApprovalDecision, ApprovalReason, ApprovalRequest, EndpointDescriptor, DEFAULT_TIMEOUT_SECS,
    ENDPOINT_FILE,
};

/// A pending approval as the UI sees it. The auth token is deliberately NOT included.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingView {
    pub id: String,
    pub client: Option<String>,
    pub server: String,
    pub tool: String,
    pub tool_fingerprint: Option<String>,
    pub reason: ApprovalReason,
    pub arguments: serde_json::Value,
    /// Wall-clock epoch-millis when this call auto-denies (park time + the fail-closed
    /// timeout). The UI counts down to this exactly, instead of approximating from when
    /// it first saw the request. App and broker share one clock, so it's accurate.
    pub deadline_ms: u64,
}

/// A gateway connection parked waiting for a human decision.
struct Waiter {
    view: PendingView,
    decide: Sender<ApprovalDecision>,
}

struct Inner {
    /// The token a gateway must present (matches the published descriptor).
    token: String,
    /// id -> parked connection. Bounded by `MAX_PENDING`.
    pending: Mutex<HashMap<String, Waiter>>,
    /// Ephemeral per-session "always allow" set of fingerprint-bound `server/tool/fingerprint`
    /// keys. A matching call auto-approves without prompting; cleared on app restart (the
    /// persistent list lives in the registry). "Approve for this session" adds here; "Always
    /// allow" adds here AND to the registry.
    session_allow: Mutex<HashSet<String>>,
}

/// Cap on simultaneously-pending approvals, so a misbehaving client can't grow the
/// queue without bound. Beyond this, new requests are denied immediately.
const MAX_PENDING: usize = 64;
/// Bound unauthenticated request memory before a gateway proves it has the token.
const MAX_APPROVAL_REQUEST_BYTES: usize = 1024 * 1024;
/// Pending approvals occupy workers while awaiting a decision. Keep bounded
/// headroom for authentication, allowlisted calls, and prompt fail-closed denials.
const MAX_CONNECTION_WORKERS: usize = MAX_PENDING + 32;

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection(active: &Arc<AtomicUsize>) -> Option<ConnectionPermit> {
    let mut current = active.load(Ordering::Acquire);
    loop {
        if current >= MAX_CONNECTION_WORKERS {
            return None;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(ConnectionPermit {
                    active: Arc::clone(active),
                })
            }
            Err(observed) => current = observed,
        }
    }
}

/// Read exactly one newline-terminated request without allowing an unauthenticated
/// peer to grow the allocation indefinitely.
fn read_approval_request<R: BufRead>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut limited = Read::take(reader, (MAX_APPROVAL_REQUEST_BYTES + 1) as u64);
    let read = limited.read_until(b'\n', &mut line)?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty approval request",
        ));
    }
    if line.len() > MAX_APPROVAL_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "approval request exceeds size limit",
        ));
    }
    if !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "approval request is not newline terminated",
        ));
    }
    Ok(line)
}

/// Constant-time equality for the fixed-length broker token. Token length is public.
fn token_eq(actual: &str, expected: &str) -> bool {
    let (actual, expected) = (actual.as_bytes(), expected.as_bytes());
    if actual.len() != expected.len() {
        return false;
    }
    actual.ct_eq(expected).into()
}

/// The wall-clock epoch-millis deadline for a newly parked approval: now plus the
/// fail-closed timeout. Matches the broker's own `recv_timeout` below, so the UI's
/// countdown to it lands on the same moment the call actually auto-denies.
fn deadline_ms_from_now() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    now + DEFAULT_TIMEOUT_SECS * 1000
}

/// Handle to the broker, managed as Tauri state so the approve/deny commands can reach it.
#[derive(Clone)]
pub struct ApprovalBroker {
    inner: Arc<Inner>,
}

impl ApprovalBroker {
    /// Snapshot the pending queue for the UI.
    pub fn list(&self) -> Vec<PendingView> {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|w| w.view.clone())
            .collect()
    }

    /// Deliver a human decision for `id`, returning the resolved call's view (so the caller
    /// can apply an "allow this tool" scope from its server/tool). `Err` if the id is unknown
    /// (already resolved or timed out). Sending is best-effort: a parked connection that
    /// already timed out has dropped its receiver, which is harmless.
    pub fn decide(&self, id: &str, approved: bool) -> Result<PendingView, String> {
        let waiter = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
        match waiter {
            Some(w) => {
                let d = if approved {
                    ApprovalDecision::Approved
                } else {
                    ApprovalDecision::Denied
                };
                let _ = w.decide.send(d);
                Ok(w.view)
            }
            None => Err("no pending approval with that id (it may have expired)".into()),
        }
    }

    /// Add a `server/tool` key to the ephemeral session allowlist (auto-approve until the
    /// app restarts). Both "approve for session" and "always allow" add here so the
    /// decision takes effect immediately for later matching calls.
    pub fn add_session_allow(&self, key: String) {
        self.inner
            .session_allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key);
    }

    /// Remove a key from the session allowlist (used when the user revokes it).
    pub fn remove_session_allow(&self, key: &str) {
        self.inner
            .session_allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
    }

    /// Snapshot the session allowlist for the UI.
    pub fn session_allowed(&self) -> Vec<String> {
        self.inner
            .session_allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Whether a key is in the ephemeral session allowlist.
    fn session_contains(&self, key: &str) -> bool {
        self.inner
            .session_allow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }
}

/// Start the broker: generate a token, bind a loopback port, publish the endpoint
/// descriptor into the data dir, and spawn the accept loop. ALWAYS returns a broker so
/// the Tauri commands have state to bind to; if binding/publishing fails, the broker is
/// inert (no listener) and HITL simply never receives approvals - gateways then fail
/// closed on their own (a connect to nothing denies). Never panics.
pub fn start(app: AppHandle) -> ApprovalBroker {
    let mut tok = [0u8; 24];
    let token: String = match getrandom::getrandom(&mut tok) {
        Ok(()) => tok.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => String::new(),
    };
    let broker = ApprovalBroker {
        inner: Arc::new(Inner {
            token: token.clone(),
            pending: Mutex::new(HashMap::new()),
            session_allow: Mutex::new(HashSet::new()),
        }),
    };

    match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(listener) => {
            if let Some(port) = listener.local_addr().ok().map(|a| a.port()) {
                if let Some(dir) = crate::registry::conduit_dir() {
                    let desc = EndpointDescriptor {
                        endpoint: format!("127.0.0.1:{port}"),
                        token,
                    };
                    let path = dir.join(ENDPOINT_FILE);
                    // A stale descriptor (app crashed) points at a dead port, so a gateway
                    // connect fails and denies - fail-closed either way. The gateway also
                    // re-reads the descriptor and retries once, which self-heals the case
                    // where the app restarted and rebound to a new port.
                    // Written via atomic_write so the HITL endpoint + auth token land
                    // owner-only (0600) on Unix rather than world-readable: a same-user
                    // process reading the token could otherwise spoof approval decisions.
                    let _ = crate::registry::atomic_write(
                        &path,
                        &serde_json::to_string(&desc).unwrap_or_default(),
                    );
                    // Record WHERE we published, into the same always-on log the gateway
                    // writes its `dir_resolution=` line to. If a client-spawned gateway
                    // resolves the data dir differently from the app (MSIX virtualization,
                    // a differently-spelled HOME), that mismatch is now a one-line read
                    // instead of a multi-hour hunt - it was the root cause of a live
                    // "HITL blocks every call but no prompt appears" incident.
                    log_broker_event(&format!(
                        "bound 127.0.0.1:{port}; endpoint published at {}",
                        path.display()
                    ));
                } else {
                    log_broker_event(
                        "conduit_dir() unavailable; endpoint NOT published (HITL fails closed)",
                    );
                }
                let accept_broker = broker.clone();
                std::thread::spawn(move || {
                    let active_workers = Arc::new(AtomicUsize::new(0));
                    for conn in listener.incoming().flatten() {
                        let Some(permit) = try_acquire_connection(&active_workers) else {
                            // Closing immediately is fail-closed and keeps a slow or
                            // stalled peer from consuming an unbounded thread count.
                            drop(conn);
                            continue;
                        };
                        let b = accept_broker.clone();
                        let a = app.clone();
                        let _ = std::thread::Builder::new()
                            .name("toolport-approval".into())
                            .spawn(move || {
                                let _permit = permit;
                                handle_conn(conn, b, a);
                            });
                    }
                });
            }
        }
        Err(_) => { /* inert broker; HITL never fires, gateways fail-closed */ }
    }
    broker
}

/// Append a line to the shared, always-on gateway log, so the broker's bind/publish
/// location sits right next to the gateway's `dir_resolution=` line. Best-effort: a logging
/// failure never touches an approval decision.
fn log_broker_event(msg: &str) {
    if let Some(path) = crate::registry::gateway_log_path() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "[broker] {msg}");
        }
    }
}

/// Best-effort removal of the endpoint descriptor on app shutdown, so a gateway that dials
/// after the app is gone reads no descriptor (a clean `Unreachable`) instead of connecting
/// to a dead port left behind. Safe to call when none exists. Call ONLY on final exit, not
/// on a cancelable exit-request: while the broker is still bound the descriptor must stand.
pub fn clear_endpoint() {
    if let Some(dir) = crate::registry::conduit_dir() {
        if std::fs::remove_file(dir.join(ENDPOINT_FILE)).is_ok() {
            log_broker_event("endpoint descriptor cleared on shutdown");
        }
    }
}

/// Serve one gateway connection: read the request, authenticate it, park it for a human
/// decision (or a fail-closed timeout), and write the decision back.
fn handle_conn(stream: TcpStream, broker: ApprovalBroker, app: AppHandle) {
    // Read the request promptly; a slow/stalled sender must not tie up a thread.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let line = match read_approval_request(&mut BufReader::new(reader_stream)) {
        Ok(line) => line,
        Err(_) => return,
    };
    let req: ApprovalRequest = match serde_json::from_slice(&line) {
        Ok(r) => r,
        Err(_) => return,
    };

    let mut out = stream;
    let deny = |out: &mut TcpStream| {
        let _ = out.set_write_timeout(Some(Duration::from_secs(10)));
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(&ApprovalDecision::Denied).unwrap_or_default()
        );
    };

    // Authenticate: only a process holding our token may register an approval.
    if req.token.is_empty() || !token_eq(&req.token, &broker.inner.token) {
        deny(&mut out);
        return;
    }

    // Auto-approve only if the current tool definition matches a fingerprint-bound allow.
    // Legacy broad `server/tool` entries are intentionally ignored: a tool definition that
    // changed since approval should re-prompt instead of inheriting a stale bypass.
    if let Some(fp) = req.tool_fingerprint.as_deref() {
        let key = crate::approval::fingerprint_allow_key(&req.server, &req.tool, fp);
        if broker.session_contains(&key) || registry_allows(&app, &key) {
            let _ = out.set_write_timeout(Some(Duration::from_secs(10)));
            let _ = writeln!(
                out,
                "{}",
                serde_json::to_string(&ApprovalDecision::Approved).unwrap_or_default()
            );
            return;
        }
    }

    let view = PendingView {
        id: req.id.clone(),
        client: req.client.clone(),
        server: req.server.clone(),
        tool: req.tool.clone(),
        tool_fingerprint: req.tool_fingerprint.clone(),
        reason: req.reason,
        arguments: req.arguments.clone(),
        // Stamp the deadline now, right before we park on `recv_timeout` below.
        deadline_ms: deadline_ms_from_now(),
    };
    let (tx, rx) = channel::<ApprovalDecision>();
    {
        let mut pending = broker
            .inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pending.len() >= MAX_PENDING {
            drop(pending);
            deny(&mut out);
            return;
        }
        pending.insert(
            req.id.clone(),
            Waiter {
                view: view.clone(),
                decide: tx,
            },
        );
    }

    // Surface it to the UI (best-effort; the poll-based list() is the source of truth).
    let _ = app.emit("approval-pending", &view);
    // The call BLOCKS and auto-denies on timeout, so a person who isn't looking at the
    // (often backgrounded) app would silently miss it. Raise an OS notification and flash
    // the taskbar so the pending decision is noticed while there's still time to make it.
    notify_pending(&app, &view);

    // Block for the human decision or the fail-closed timeout.
    let decision = rx
        .recv_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .unwrap_or(ApprovalDecision::Timeout);
    // Ensure it's gone (timeout path leaves it; decide() already removed it).
    broker
        .inner
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&req.id);
    let _ = app.emit("approval-resolved", &req.id);

    let _ = out.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(&decision).unwrap_or_else(|_| "\"timeout\"".into())
    );
}

/// Whether the tool `key` is on the registry's persistent always-allow list. Reads the
/// app-managed registry state; false if unavailable.
fn registry_allows(app: &AppHandle, key: &str) -> bool {
    app.try_state::<Mutex<crate::registry::Registry>>()
        .map(|s| {
            s.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_tool_allowed(key)
        })
        .unwrap_or(false)
}

/// Notify the human that a call is held: an OS notification plus a taskbar-attention
/// flash on the main window. Best-effort and non-blocking - if either fails (permission
/// off, no window) the in-app overlay is still the source of truth. We flash rather than
/// force-focus so we don't yank the user out of what they're doing.
fn notify_pending(app: &AppHandle, view: &PendingView) {
    let who = view.client.as_deref().map(|c| format!("{c} wants to run ")).unwrap_or_default();
    let _ = app
        .notification()
        .builder()
        .title("Toolport: approval required")
        .body(format!("{who}{}/{} - approve or deny it in Toolport.", view.server, view.tool))
        .show();
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.request_user_attention(Some(tauri::UserAttentionType::Critical));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> ApprovalBroker {
        ApprovalBroker {
            inner: Arc::new(Inner {
                token: "tok".into(),
                pending: Mutex::new(HashMap::new()),
                session_allow: Mutex::new(HashSet::new()),
            }),
        }
    }

    fn park(b: &ApprovalBroker, id: &str) -> std::sync::mpsc::Receiver<ApprovalDecision> {
        let (tx, rx) = channel();
        let view = PendingView {
            id: id.into(),
            client: None,
            server: "s".into(),
            tool: "drop".into(),
            tool_fingerprint: Some("v2:abc".into()),
            reason: ApprovalReason::Destructive,
            arguments: serde_json::json!({}),
            deadline_ms: deadline_ms_from_now(),
        };
        b.inner
            .pending
            .lock()
            .unwrap()
            .insert(id.into(), Waiter { view, decide: tx });
        rx
    }

    #[test]
    fn approve_delivers_then_removes() {
        let b = broker();
        let rx = park(&b, "x");
        assert_eq!(b.list().len(), 1);
        b.decide("x", true).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ApprovalDecision::Approved
        );
        assert!(b.list().is_empty(), "resolved entry should be gone");
    }

    #[test]
    fn deny_delivers_denied() {
        let b = broker();
        let rx = park(&b, "y");
        b.decide("y", false).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ApprovalDecision::Denied
        );
    }

    #[test]
    fn unknown_id_errs() {
        assert!(broker().decide("nope", true).is_err());
    }

    #[test]
    fn deadline_is_about_the_timeout_out() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let d = deadline_ms_from_now();
        let target = DEFAULT_TIMEOUT_SECS * 1000;
        // ~timeout out; allow a few seconds of slack for a slow CI scheduler.
        assert!(
            d >= now + target - 3_000 && d <= now + target + 3_000,
            "deadline {d} not ~{target}ms past {now}"
        );
    }

    #[test]
    fn broker_token_comparison_matches_only_equal_values() {
        assert!(token_eq("token123", "token123"));
        assert!(!token_eq("token123", "token124"));
        assert!(!token_eq("token123", "token1234"));
        assert!(!token_eq("", "token123"));
    }

    #[test]
    fn approval_request_reader_requires_a_bounded_line() {
        let valid = b"{\"token\":\"tok\"}\n";
        assert_eq!(
            read_approval_request(&mut std::io::Cursor::new(valid)).unwrap(),
            valid
        );

        let unterminated = br#"{"token":"tok"}"#;
        assert_eq!(
            read_approval_request(&mut std::io::Cursor::new(unterminated))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let oversized = vec![b'x'; MAX_APPROVAL_REQUEST_BYTES + 1];
        assert_eq!(
            read_approval_request(&mut std::io::Cursor::new(oversized))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn approval_connection_worker_count_is_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut permits = Vec::new();
        for _ in 0..MAX_CONNECTION_WORKERS {
            permits.push(try_acquire_connection(&active).expect("worker permit"));
        }
        assert_eq!(active.load(Ordering::Acquire), MAX_CONNECTION_WORKERS);
        assert!(try_acquire_connection(&active).is_none());

        permits.pop();
        assert_eq!(active.load(Ordering::Acquire), MAX_CONNECTION_WORKERS - 1);
        permits.push(try_acquire_connection(&active).expect("released permit is reusable"));
        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn session_allow_round_trips_and_decide_returns_view() {
        let b = broker();
        let key = crate::approval::fingerprint_allow_key("db", "db__read", "v2:abc");
        assert!(!b.session_contains(&key));
        b.add_session_allow(key.clone());
        assert!(b.session_contains(&key));
        assert_eq!(b.session_allowed(), vec![key.clone()]);
        b.remove_session_allow(&key);
        assert!(!b.session_contains(&key));

        // decide now hands back the resolved view (so the command can apply an allow scope).
        let rx = park(&b, "z");
        let view = b.decide("z", true).unwrap();
        assert_eq!(view.tool, "drop");
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), ApprovalDecision::Approved);
    }
}
