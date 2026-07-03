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
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
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
    /// Ephemeral per-session "always allow" set of `server/tool` keys. A matching call
    /// auto-approves without prompting; cleared on app restart (the persistent list lives
    /// in the registry). "Approve for this session" adds here; "Always allow" adds here
    /// AND to the registry.
    session_allow: Mutex<HashSet<String>>,
}

/// Cap on simultaneously-pending approvals, so a misbehaving client can't grow the
/// queue without bound. Beyond this, new requests are denied immediately.
const MAX_PENDING: usize = 64;

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
                    // A stale descriptor (app crashed) points at a dead port, so a gateway
                    // connect fails and denies - fail-closed either way.
                    let _ = std::fs::write(
                        dir.join(ENDPOINT_FILE),
                        serde_json::to_string(&desc).unwrap_or_default(),
                    );
                }
                let accept_broker = broker.clone();
                std::thread::spawn(move || {
                    for conn in listener.incoming().flatten() {
                        let b = accept_broker.clone();
                        let a = app.clone();
                        std::thread::spawn(move || handle_conn(conn, b, a));
                    }
                });
            }
        }
        Err(_) => { /* inert broker; HITL never fires, gateways fail-closed */ }
    }
    broker
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
    let mut line = String::new();
    if BufReader::new(reader_stream).read_line(&mut line).is_err() {
        return;
    }
    let req: ApprovalRequest = match serde_json::from_str(line.trim()) {
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
    if req.token.is_empty() || req.token != broker.inner.token {
        deny(&mut out);
        return;
    }

    // Auto-approve if the user already allowed this tool - per session (broker) or
    // persistently (registry). Skips the prompt entirely so "approve for this session"
    // and "always allow this tool" actually stick for later matching calls.
    let key = crate::approval::allow_key(&req.server, &req.tool);
    if broker.session_contains(&key) || registry_allows(&app, &key) {
        let _ = out.set_write_timeout(Some(Duration::from_secs(10)));
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(&ApprovalDecision::Approved).unwrap_or_default()
        );
        return;
    }

    let view = PendingView {
        id: req.id.clone(),
        client: req.client.clone(),
        server: req.server.clone(),
        tool: req.tool.clone(),
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
    fn session_allow_round_trips_and_decide_returns_view() {
        let b = broker();
        let key = crate::approval::allow_key("db", "db__read");
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
