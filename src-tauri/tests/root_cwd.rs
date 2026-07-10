//! End-to-end check that a stdio server spawns in the resolved `${ROOT}` cwd.
//!
//! The `${ROOT}` chain the gateway runs is: a `file://` root URI is decoded to a
//! path (`file_uri_to_path`), substituted into the server's configured cwd
//! (`resolve_root_token`), and the child is spawned with the result. The two
//! parsing halves are unit-tested in `downstream.rs`; this drives the real
//! `mock-mcp-server` through the actual spawn path and asserts the child process
//! reports the resolved directory as its cwd, closing the loop for issue #239.

use conduit_lib::downstream::{resolve_root_token, DownstreamServer, StdioTransport};
use conduit_lib::router::Router;
use serde_json::json;

/// Spawn the mock server with the given cwd and return what its `pwd` tool reports.
fn reported_cwd(cwd: Option<&str>) -> String {
    let mock = env!("CARGO_BIN_EXE_mock-mcp-server");
    let transport = StdioTransport::spawn(mock, &[], &[], cwd).expect("spawn mock");
    let server =
        DownstreamServer::connect("mock".to_string(), Box::new(transport)).expect("connect mock");
    let mut router = Router::new();
    router.add(server);
    let result = router
        .route_call("mock__pwd", json!({}))
        .expect("pwd call should route");
    result["content"][0]["text"]
        .as_str()
        .expect("pwd returns text")
        .to_string()
}

#[test]
fn resolved_root_places_the_spawned_server_and_none_falls_back() {
    // A real directory standing in for the client's project root. Canonicalize so
    // the comparison is immune to symlinks (macOS /tmp) and path casing.
    let root_dir = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
    let root = root_dir.to_string_lossy().to_string();

    // ${ROOT} with a known root resolves to that path, and the server actually
    // spawns there.
    let resolved = resolve_root_token("${ROOT}", Some(&root)).expect("resolve to a path");
    let reported = reported_cwd(Some(&resolved));
    assert_eq!(
        std::fs::canonicalize(&reported).expect("canonicalize reported cwd"),
        root_dir,
        "the server should run in the resolved ${{ROOT}} directory"
    );

    // ${ROOT} with no known root resolves to None, so the server inherits the
    // default (this test process's) cwd, not the root dir - the fallback path that
    // keeps a rootless client working.
    assert!(resolve_root_token("${ROOT}", None).is_none());
    let reported_default = reported_cwd(None);
    assert_ne!(
        std::fs::canonicalize(&reported_default).ok(),
        Some(root_dir),
        "with no known root the server must not run in the root directory"
    );
}
