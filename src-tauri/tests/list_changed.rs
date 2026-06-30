//! End-to-end check for live tool-list refresh.
//!
//! Drives the real `mock-mcp-server` binary: it advertises `echo`/`add`/`grow`,
//! and a `grow` call makes it add a `greet` tool and emit
//! `notifications/tools/list_changed`. We assert the watched transport flags the
//! change and that re-querying the *existing* connection surfaces the new tool.
//! A re-spawn approach would lose the in-memory change, so this also pins down
//! that the gateway refreshes in place rather than reconnecting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use conduit_lib::downstream::{DownstreamServer, StdioTransport};
use conduit_lib::router::Router;
use serde_json::json;

fn tool_names(router: &Router) -> Vec<String> {
    router
        .aggregated_tools()
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

#[test]
fn live_tool_change_surfaces_via_refresh_without_respawn() {
    let mock = env!("CARGO_BIN_EXE_mock-mcp-server");
    let dirty = Arc::new(AtomicBool::new(false));
    let transport =
        StdioTransport::spawn_watched(mock, &[], &[], Arc::clone(&dirty)).expect("spawn mock");
    let server =
        DownstreamServer::connect("mock".to_string(), Box::new(transport)).expect("connect mock");

    let mut router = Router::new();
    router.add(server);

    // Baseline: the change hasn't happened, and a startup connection must not
    // have falsely flagged dirty (the watch is only armed post-handshake).
    let before = tool_names(&router);
    assert!(before.contains(&"mock__grow".to_string()), "got {before:?}");
    assert!(
        !before.contains(&"mock__greet".to_string()),
        "got {before:?}"
    );
    assert!(!dirty.load(Ordering::SeqCst), "nothing changed yet");

    // Drive the live server to add a tool and announce the change.
    router
        .route_call("mock__grow", json!({}))
        .expect("grow call should succeed");

    // The stdout drain flags dirty asynchronously once it reads the notification.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !dirty.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        dirty.load(Ordering::SeqCst),
        "tools/list_changed should have flipped the dirty flag"
    );

    // Re-query the SAME live connection: the new tool now appears. (A re-spawned
    // process would report the original list, so this proves the in-place path.)
    router.refresh_tools();
    let after = tool_names(&router);
    assert!(after.contains(&"mock__greet".to_string()), "got {after:?}");

    // The new tool is actually callable end-to-end through the router.
    let result = router
        .route_call("mock__greet", json!({ "name": "Conduit" }))
        .expect("greet call should route");
    assert_eq!(result["content"][0]["text"], "hello Conduit");
}
