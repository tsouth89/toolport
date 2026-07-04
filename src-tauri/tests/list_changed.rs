//! End-to-end check for live tools / resources / prompts refresh.
//!
//! Drives the real `mock-mcp-server` binary: it advertises `echo`/`add`/`grow`
//! plus a baseline resource and prompt, and a `grow` call makes it add a `greet`
//! tool, a `mock://grown` resource, and a `grown_prompt`, then emit all three
//! `list_changed` notifications. We assert the watched transport flags each kind
//! and that re-querying the *existing* connection surfaces the new entries. A
//! re-spawn approach would lose the in-memory change, so this also pins down that
//! the gateway refreshes in place rather than reconnecting.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use conduit_lib::downstream::{change, DownstreamServer, StdioTransport};
use conduit_lib::router::Router;
use serde_json::json;

fn tool_names(router: &Router) -> Vec<String> {
    router
        .aggregated_tools()
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

fn resource_uris(router: &Router) -> Vec<String> {
    router
        .aggregated_resources()
        .iter()
        .filter_map(|r| r.get("uri").and_then(|u| u.as_str()).map(String::from))
        .collect()
}

fn prompt_names(router: &Router) -> Vec<String> {
    router
        .aggregated_prompts()
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

#[test]
fn live_tool_change_surfaces_via_refresh_without_respawn() {
    let mock = env!("CARGO_BIN_EXE_mock-mcp-server");
    let dirty = Arc::new(AtomicU8::new(0));
    let transport =
        StdioTransport::spawn_watched(mock, &[], &[], Arc::clone(&dirty)).expect("spawn mock");
    let mut server =
        DownstreamServer::connect("mock".to_string(), Box::new(transport)).expect("connect mock");
    // connect() only loads tools; pull the baseline resources/prompts so the
    // router aggregates them (the gateway does this via load_resources_prompts).
    server.load_resources_prompts();

    let mut router = Router::new();
    router.add(server);

    // Baseline: the change hasn't happened, and a startup connection must not
    // have falsely flagged dirty (the watch is only armed post-handshake).
    let before = tool_names(&router);
    assert!(before.contains(&"mock__grow".to_string()), "got {before:?}");
    assert!(!before.contains(&"mock__greet".to_string()), "got {before:?}");
    assert!(resource_uris(&router).contains(&"mock://base".to_string()));
    assert!(prompt_names(&router).contains(&"mock__hi".to_string()));
    assert_eq!(dirty.load(Ordering::SeqCst), 0, "nothing changed yet");

    // Drive the live server to grow all three lists and announce each change.
    router
        .route_call("mock__grow", json!({}))
        .expect("grow call should succeed");

    // The stdout drain flags dirty asynchronously once it reads the notifications.
    // Wait until all three kinds have registered (they arrive as separate lines).
    let want = change::TOOLS | change::RESOURCES | change::PROMPTS;
    let deadline = Instant::now() + Duration::from_secs(5);
    while dirty.load(Ordering::SeqCst) & want != want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        dirty.load(Ordering::SeqCst) & want,
        want,
        "all three list_changed kinds should have set their bit"
    );

    // Re-query the SAME live connection per kind: the new entries now appear. (A
    // re-spawned process would report the original lists, proving the in-place path.)
    router.refresh_tools();
    router.refresh_resources();
    router.refresh_prompts();
    assert!(tool_names(&router).contains(&"mock__greet".to_string()));
    assert!(resource_uris(&router).contains(&"mock://grown".to_string()));
    assert!(prompt_names(&router).contains(&"mock__grown_prompt".to_string()));

    // The new tool is actually callable end-to-end through the router.
    let result = router
        .route_call("mock__greet", json!({ "name": "Conduit" }))
        .expect("greet call should route");
    assert_eq!(result["content"][0]["text"], "hello Conduit");
}
