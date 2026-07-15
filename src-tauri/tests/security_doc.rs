//! Regression guard for SECURITY.md accuracy (SOU-41).
//!
//! SECURITY.md used to carry two materially false absolute claims: that the gateway
//! "opens no listening network port" (false in HTTP / Docker mode, which binds a
//! persistent listener, `0.0.0.0:8765` by default in the image) and that "There is no
//! telemetry" (Teams reports per-server aggregate usage to the team server). If you
//! reword the doc, keep every such statement mode-aware, not absolute, so the two
//! claims can never silently return.

#[test]
fn security_md_has_no_stale_absolute_claims() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../SECURITY.md");
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    for banned in ["opens no listening network port", "There is no telemetry"] {
        assert!(
            !text.contains(banned),
            "SECURITY.md re-introduced a false absolute claim: {banned:?}. Keep the \
             wording mode-aware (see SOU-41): the gateway binds a listener in HTTP/Docker \
             mode, and Teams reports aggregate usage."
        );
    }
}
