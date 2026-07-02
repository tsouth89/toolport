//! App-side HITL approval broker.
//!
//! The Toolport app hosts this broker; every `conduit-gateway` process (one per stdio
//! client, plus the app's `--http` bridge) dials OUT to it when it holds a gated tool
//! call, and blocks reading for the decision. This is the counterpart to the gateway's
//! `request_human_decision` (see `bin/conduit-gateway.rs`).
//!
//! Protocol: the gateway connects over loopback TCP, sends one JSON line
//! ([`ApprovalRequest`]) carrying the shared token, and reads one JSON line back
//! ([`ApprovalDecision`]). Arguments travel over the socket and are never written to
//! disk. The only thing on disk is the endpoint descriptor (address + token). The
//! human decides in the app UI; a fail-closed timeout denies. Transport is loopback
//! TCP + token for now; hardening to a named-pipe / uds is a follow-up.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

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
}

/// Cap on simultaneously-pending approvals, so a misbehaving client can't grow the
/// queue without bound. Beyond this, new requests are denied immediately.
const MAX_PENDING: usize = 64;

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

    /// Deliver a human decision for `id`. `Err` if the id is unknown (already resolved
    /// or timed out). Sending is best-effort: a parked connection that already timed out
    /// has dropped its receiver, which is harmless.
    pub fn decide(&self, id: &str, approved: bool) -> Result<(), String> {
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
                Ok(())
            }
            None => Err("no pending approval with that id (it may have expired)".into()),
        }
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

    let view = PendingView {
        id: req.id.clone(),
        client: req.client.clone(),
        server: req.server.clone(),
        tool: req.tool.clone(),
        reason: req.reason,
        arguments: req.arguments.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn broker() -> ApprovalBroker {
        ApprovalBroker {
            inner: Arc::new(Inner {
                token: "tok".into(),
                pending: Mutex::new(HashMap::new()),
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
}
