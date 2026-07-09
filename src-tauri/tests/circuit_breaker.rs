//! End-to-end check for the per-server circuit breaker.
//!
//! Drives the real `mock-mcp-server` binary and calls its `die` tool, which exits
//! the process mid-session. Every subsequent call then hits a dead connection; once
//! the failure streak crosses the threshold the breaker opens and the next call is
//! fast-failed WITHOUT waiting on the (dead) connection. This pins down that a
//! crashed/hung server stops costing every caller its full read timeout.

use std::sync::atomic::AtomicU8;
use std::sync::Arc;

use conduit_lib::downstream::{DownstreamServer, StdioTransport};
use conduit_lib::router::Router;
use serde_json::json;

#[test]
fn circuit_opens_after_a_server_dies_and_fast_fails() {
    let mock = env!("CARGO_BIN_EXE_mock-mcp-server");
    let dirty = Arc::new(AtomicU8::new(0));
    let transport = StdioTransport::spawn_watched(mock, &[], &[], None, dirty).expect("spawn mock");
    let server =
        DownstreamServer::connect("mock".to_string(), Box::new(transport)).expect("connect mock");
    let mut router = Router::new();
    router.add(server);

    // Kill the server mid-session: this call gets no response (connection dies) and is
    // health failure #1.
    let _ = router.route_call("mock__die", json!({}));

    // The next calls hit the now-dead connection. Failures #2 and #3 open the circuit
    // (threshold is 3). Each returns an error, but from the dead transport, not the breaker.
    for _ in 0..2 {
        assert!(
            router.route_call("mock__echo", json!({ "text": "x" })).is_err(),
            "a call to a dead server should error"
        );
    }

    // Now the breaker is open: the next call is fast-failed by the breaker itself,
    // identifiable by its message, rather than being sent to the dead connection.
    let err = router
        .route_call("mock__echo", json!({ "text": "x" }))
        .expect_err("call should fail");
    assert!(
        err.contains("temporarily unavailable"),
        "expected a circuit-open fast-fail, got: {err}"
    );
}
