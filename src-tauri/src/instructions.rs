//! Team Instructions — write org-managed agent rules to each AI client's rules file.
//!
//! An admin authors the team's agent instructions once in the Teams dashboard; the server
//! carries them in the team config under the top-level `instructions` key (see the
//! `team-instructions` spec). This module is the client half (spec "W2"): it turns that
//! content into files on disk next to — never over — the member's own instructions, and
//! removes them cleanly when the member leaves the team.
//!
//! Two write strategies, both non-destructive:
//!
//!   * [`Strategy::OwnedFile`] — Toolport owns a whole file in a client's rules *directory*
//!     (e.g. `~/.claude/rules/toolport-team-rules.md`). We create/replace/delete the entire
//!     file; there are no user bytes in it to protect.
//!   * [`Strategy::SentinelBlock`] — the client reads a single shared global rules file that
//!     the user may also edit, so we own only the span between two HTML-comment markers and
//!     leave every byte outside them untouched.
//!
//! The invariant the tests pin: an upsert changes only the managed span (or appends one), and
//! a remove takes the managed span back out, so a full join→edit→leave cycle returns the
//! user's own content unchanged.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// How a client's rules file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Toolport owns the whole file (a dedicated file in a rules directory).
    OwnedFile,
    /// Toolport owns only the span between the sentinel markers in a shared file.
    SentinelBlock,
}

/// A resolved place to write one client's copy of the org instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Absolute path of the file to write.
    pub path: std::path::PathBuf,
    pub strategy: Strategy,
    /// Hard character cap for clients that truncate/ignore an over-long global file
    /// (e.g. Windsurf's 6,000-char global rules). `None` = no client-imposed cap.
    pub char_cap: Option<usize>,
    /// A user opt-out file whose mere existence makes the client ignore `path` (Codex's
    /// `AGENTS.override.md` shadows `AGENTS.md`). When it exists, applying reports
    /// [`ApplyState::BlockedOverride`] and writes nothing.
    pub blocked_if_present: Option<std::path::PathBuf>,
}

/// The per-client outcome of applying (or checking) the org instructions. Reported to the
/// dashboard (spec W5) so an admin can prove which client actually loaded the current rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyState {
    /// The current org content is present on disk for this client.
    Applied,
    /// This client has no supported global-rules location; nothing written.
    Unsupported,
    /// A user opt-out file shadows the target (e.g. Codex `AGENTS.override.md`); not written.
    BlockedOverride,
    /// Content exceeds the client's hard cap and can't be trimmed safely; not written.
    TooLong,
    /// A filesystem/parse error prevented a safe read/write; the file was left untouched.
    Error,
    /// The client is installed but the current org content is NOT (yet) on disk — never
    /// written, drifted, or hand-edited. Distinct from `Applied` so the coverage panel shows a
    /// truthful "not covered" for a client added after the last write (see [`current_state`]).
    Stale,
}

/// One client's reported state, for the apply-status receipt (spec W5).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientReceipt {
    pub id: String,
    pub state: ApplyState,
}

/// The "effective rules receipt" a member reports so the dashboard can prove per-client
/// coverage: which version+content the member is on, and each installed client's state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub version: i64,
    /// Hash of the org content this receipt is about — proves on-disk == pushed content.
    pub content_hash: String,
    pub clients: Vec<ClientReceipt>,
}

/// Sentinel markers. FROZEN compatibility contract — an older build must still recognize and
/// replace/remove a block a newer build wrote, so these strings never change. The team id and
/// version live in the START marker for provenance and cheap change display; only the START
/// *prefix* is matched, so the id/version can vary without breaking recognition.
pub const SENTINEL_START_PREFIX: &str = "<!-- toolport:team-instructions:start";
pub const SENTINEL_END: &str = "<!-- toolport:team-instructions:end -->";

/// FROZEN prefix of the header stamped on an [`Strategy::OwnedFile`] file. Cleanup on
/// team-leave identifies our owned files by this prefix (so it only ever deletes files we
/// wrote), which must stay recognizable across versions.
pub const OWNED_HEADER_PREFIX: &str = "<!-- Managed by Toolport";

/// The one-line header stamped at the top of an [`Strategy::OwnedFile`] file so a member who
/// opens it understands it is managed and will be overwritten.
fn owned_header(team_id: &str, version: i64) -> String {
    format!("{OWNED_HEADER_PREFIX} — team {team_id}, v{version}. Edits are overwritten on sync; leave the team to remove. -->")
}

fn start_marker(team_id: &str, version: i64) -> String {
    format!("{SENTINEL_START_PREFIX} team={team_id} v={version} -->")
}

/// Stable content hash reported to the server as the "effective rules receipt": it identifies
/// exactly the org content a client wrote to disk. Not cryptographic — only needs to detect
/// change and let the dashboard prove on-disk == the pushed version.
pub fn content_hash(content: &str) -> String {
    let mut h = DefaultHasher::new();
    content.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Render the full body of an [`Strategy::OwnedFile`] file (header + a blank line + content).
/// Always newline-terminated.
pub fn render_owned_file(team_id: &str, version: i64, content: &str) -> String {
    let body = content.trim_end_matches('\n');
    format!("{}\n\n{}\n", owned_header(team_id, version), body)
}

/// The managed block text for the sentinel strategy: START marker, content, END marker.
fn render_block(team_id: &str, version: i64, content: &str) -> String {
    let body = content.trim_end_matches('\n');
    format!("{}\n{}\n{}", start_marker(team_id, version), body, SENTINEL_END)
}

/// Byte range `[start, end)` of an existing managed block in `existing`, or `None`. `start` is
/// the offset of the START marker; `end` is just past the END marker (not its trailing
/// newline). Matches on the frozen START prefix + END, so a block from any version is found.
fn find_block(existing: &str) -> Option<(usize, usize)> {
    let start = existing.find(SENTINEL_START_PREFIX)?;
    // The END marker that closes THIS block is the first one at or after START.
    let end_rel = existing[start..].find(SENTINEL_END)?;
    let end = start + end_rel + SENTINEL_END.len();
    Some((start, end))
}

/// Insert or replace the managed block in a shared file, leaving every byte outside the block
/// untouched.
///
///   * If a block already exists, its span (START..END) is replaced in place — the surrounding
///     user text, including whatever separated it, is byte-identical afterwards.
///   * Otherwise the block is appended after the user's content with a single blank-line
///     separator, so a later [`remove_block`] can take exactly those bytes back out.
///
/// Idempotent: re-running with the same team/version/content yields byte-identical output.
pub fn upsert_block(existing: &str, team_id: &str, version: i64, content: &str) -> String {
    let block = render_block(team_id, version, content);
    if let Some((start, end)) = find_block(existing) {
        let mut out = String::with_capacity(existing.len() + block.len());
        out.push_str(&existing[..start]);
        out.push_str(&block);
        out.push_str(&existing[end..]);
        return out;
    }
    if existing.is_empty() {
        return format!("{block}\n");
    }
    // Append after the user's content. Guarantee the block starts at column 0 with exactly one
    // blank line of separation, without rewriting any existing byte: only newlines are added.
    let sep = if existing.ends_with('\n') { "\n" } else { "\n\n" };
    format!("{existing}{sep}{block}\n")
}

/// Remove the managed block (and the single blank-line separator [`upsert_block`] adds when it
/// appends) from a shared file. Returns `None` if there is no block. The result restores the
/// user's own content, normalized to end with a newline: a file that had no trailing newline
/// before we appended gets one back, because the newline we must insert to put the block on its
/// own line is indistinguishable on the way out from a newline the user typed — an unavoidable
/// ambiguity, and a cosmetically irrelevant one for a rules file. A block the user relocated
/// mid-file is removed in place, leaving at most one blank line where it sat.
pub fn remove_block(existing: &str) -> Option<String> {
    let (start, end) = find_block(existing)?;
    // Consume the block's own trailing newline if present.
    let mut cut_end = end;
    if existing[cut_end..].starts_with('\n') {
        cut_end += 1;
    }
    // Consume exactly one blank-line separator immediately before the block — the one we add on
    // append. Only a lone leading "\n" (the separator) is eaten; the newline that terminates the
    // user's real previous line is preserved.
    let mut cut_start = start;
    if existing[..cut_start].ends_with('\n') {
        let without_last = &existing[..cut_start - 1];
        if without_last.is_empty() || without_last.ends_with('\n') {
            cut_start -= 1;
        }
    }
    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..cut_start]);
    out.push_str(&existing[cut_end..]);
    Some(out)
}

/// True when `existing` already carries a managed block for the exact `team_id`+`version`+
/// `content` (so a re-sync with no change can skip the write entirely).
pub fn block_is_current(existing: &str, team_id: &str, version: i64, content: &str) -> bool {
    match find_block(existing) {
        Some((start, end)) => existing[start..end] == render_block(team_id, version, content),
        None => false,
    }
}

/// Read a target file, treating "not found" as empty (a first write). An existing-but-unreadable
/// file is an error so the caller reports it rather than clobbering.
fn read_existing(path: &std::path::Path) -> Result<String, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

/// Create parent dirs then write atomically (temp + rename, 0600), reusing the registry's
/// hardened primitive so a crash mid-write can't leave a torn rules file.
fn write_atomic(path: &std::path::Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    crate::registry::atomic_write(path, contents)
}

/// Apply the org instructions to ONE client target. Atomic and non-destructive: it never
/// partially writes, never overwrites a shared file it couldn't read, and skips (reporting why)
/// when a client shadow-file or hard cap makes the write pointless.
pub fn write_target(t: &Target, team_id: &str, version: i64, content: &str) -> ApplyState {
    // Codex-style shadow file: the client ignores our target entirely, so writing it would be
    // invisible and confusing. Report it instead.
    if let Some(shadow) = &t.blocked_if_present {
        if shadow.exists() {
            return ApplyState::BlockedOverride;
        }
    }
    // Org content that contains our own frozen markers would corrupt everything downstream: an
    // embedded END would fool `find_block` into terminating the managed span early, and an
    // embedded START would make `remove_recorded` misclassify an owned file as a sentinel one.
    // Refuse rather than write something we can't later find and cleanly remove.
    if content.contains(SENTINEL_START_PREFIX) || content.contains(SENTINEL_END) {
        return ApplyState::Error;
    }
    let desired = match t.strategy {
        Strategy::OwnedFile => render_owned_file(team_id, version, content),
        Strategy::SentinelBlock => {
            let existing = match read_existing(&t.path) {
                Ok(s) => s,
                Err(_) => return ApplyState::Error,
            };
            if block_is_current(&existing, team_id, version, content) {
                return ApplyState::Applied; // already up to date; skip the write
            }
            upsert_block(&existing, team_id, version, content)
        }
    };
    // Hard client cap (Windsurf) applies to the WHOLE global-rules file we're about to write —
    // the member's existing rules plus our block and markers — not just the org content. Check
    // the fully rendered result so we never write a file the client will silently truncate.
    if let Some(cap) = t.char_cap {
        if desired.chars().count() > cap {
            return ApplyState::TooLong;
        }
    }
    match write_atomic(&t.path, &desired) {
        Ok(()) => ApplyState::Applied,
        Err(_) => ApplyState::Error,
    }
}

/// Read-only: what state IS this client's rules file in right now, relative to the current org
/// `content`+`version`? Used to build the coverage receipt (spec W5) every report cycle, so the
/// dashboard reflects reality — a client installed after the last write reports `Stale`, a
/// deleted/hand-edited block reports `Stale`, a shadowed Codex reports `BlockedOverride`, etc.
/// Never writes.
pub fn current_state(t: &Target, team_id: &str, version: i64, content: &str) -> ApplyState {
    if let Some(shadow) = &t.blocked_if_present {
        if shadow.exists() {
            return ApplyState::BlockedOverride;
        }
    }
    if content.contains(SENTINEL_START_PREFIX) || content.contains(SENTINEL_END) {
        return ApplyState::Error;
    }
    let existing = match read_existing(&t.path) {
        Ok(s) => s,
        Err(_) => return ApplyState::Error,
    };
    let (is_current, rendered_len) = match t.strategy {
        Strategy::OwnedFile => {
            let desired = render_owned_file(team_id, version, content);
            (existing == desired, desired.chars().count())
        }
        Strategy::SentinelBlock => (
            block_is_current(&existing, team_id, version, content),
            upsert_block(&existing, team_id, version, content).chars().count(),
        ),
    };
    if let Some(cap) = t.char_cap {
        if rendered_len > cap {
            return ApplyState::TooLong;
        }
    }
    if is_current {
        ApplyState::Applied
    } else {
        ApplyState::Stale
    }
}

/// Remove a previously-written managed artifact, identifying its kind by content so cleanup
/// survives a client that was uninstalled or whose detection changed. An owned file (our header)
/// is deleted whole; a shared file has only our sentinel block stripped, and is deleted if
/// nothing but whitespace remains. A file that is neither (already cleaned, or user-replaced) is
/// left untouched. Best-effort: unreadable/missing paths are a no-op.
pub fn remove_recorded(path: &std::path::Path) {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    if existing.contains(SENTINEL_START_PREFIX) {
        if let Some(stripped) = remove_block(&existing) {
            if stripped.trim().is_empty() {
                let _ = std::fs::remove_file(path);
            } else {
                let _ = write_atomic(path, &stripped);
            }
        }
    } else if existing.starts_with(OWNED_HEADER_PREFIX) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "team_abc";

    #[test]
    fn owned_file_has_header_and_content_and_trailing_newline() {
        let f = render_owned_file(TEAM, 3, "Never commit secrets.");
        assert!(f.starts_with("<!-- Managed by Toolport"));
        assert!(f.contains("team team_abc, v3"));
        assert!(f.contains("Never commit secrets."));
        assert!(f.ends_with('\n'));
        // Idempotent render.
        assert_eq!(f, render_owned_file(TEAM, 3, "Never commit secrets.\n"));
    }

    #[test]
    fn upsert_into_empty_file() {
        let out = upsert_block("", TEAM, 1, "Rule one");
        assert!(out.contains(SENTINEL_START_PREFIX));
        assert!(out.contains("Rule one"));
        assert!(out.trim_end().ends_with(SENTINEL_END));
    }

    #[test]
    fn upsert_appends_and_preserves_user_bytes() {
        let user = "# My personal rules\nAlways run tests.\n";
        let out = upsert_block(user, TEAM, 1, "Org rule");
        // Every user byte is preserved as a prefix.
        assert!(out.starts_with(user), "user content must be byte-preserved");
        assert!(out.contains("Org rule"));
    }

    #[test]
    fn upsert_appends_when_user_file_lacks_trailing_newline() {
        let user = "no trailing newline";
        let out = upsert_block(user, TEAM, 1, "Org rule");
        assert!(out.starts_with(user));
        // Block sits on its own line after a blank separator.
        assert!(out.contains("\n\n<!-- toolport:team-instructions:start"));
    }

    #[test]
    fn upsert_replaces_in_place_leaving_outside_bytes_identical() {
        let user_pre = "# Top\n\n";
        let user_post = "\n# Bottom\n";
        let v1 = format!("{user_pre}{}{user_post}", render_block(TEAM, 1, "old"));
        let v2 = upsert_block(&v1, TEAM, 2, "new");
        // Text outside the managed block is byte-for-byte unchanged.
        assert!(v2.starts_with(user_pre), "prefix must be untouched");
        assert!(v2.ends_with(user_post), "suffix must be untouched");
        assert!(v2.contains("new") && !v2.contains(">old<"));
        assert!(v2.contains("v=2"));
    }

    #[test]
    fn upsert_is_idempotent() {
        let user = "# Rules\nkeep me\n";
        let once = upsert_block(user, TEAM, 5, "org content");
        let twice = upsert_block(&once, TEAM, 5, "org content");
        assert_eq!(once, twice, "re-applying the same version is a no-op");
    }

    #[test]
    fn remove_after_append_restores_user_content() {
        // Full join -> apply -> leave cycle: the user's content comes back, normalized only by
        // a guaranteed trailing newline (see `remove_block` docs). Files that already end in a
        // newline round-trip byte-for-byte.
        for user in [
            "# My personal rules\nAlways run tests.\n",
            "single line, no newline",
            "trailing spaces   \nand more\n",
            "",
        ] {
            let with = upsert_block(user, TEAM, 1, "Org rule");
            let back = remove_block(&with).expect("a block was inserted");
            let normalized = if user.is_empty() || user.ends_with('\n') {
                user.to_string()
            } else {
                format!("{user}\n")
            };
            assert_eq!(back, normalized, "full cycle must restore user content for {user:?}");
        }
    }

    #[test]
    fn remove_returns_none_without_a_block() {
        assert_eq!(remove_block("# just user rules\n"), None);
    }

    #[test]
    fn remove_in_place_block_leaves_surrounding_text() {
        let user_pre = "# Top\ntext\n\n";
        let user_post = "\n# Bottom\nmore\n";
        let full = format!("{user_pre}{}{user_post}", render_block(TEAM, 1, "org"));
        let back = remove_block(&full).expect("block present");
        assert!(!back.contains(SENTINEL_START_PREFIX));
        assert!(!back.contains(SENTINEL_END));
        assert!(back.contains("# Top"));
        assert!(back.contains("# Bottom"));
    }

    #[test]
    fn block_is_current_detects_matching_and_stale() {
        let f = upsert_block("user\n", TEAM, 7, "content");
        assert!(block_is_current(&f, TEAM, 7, "content"));
        assert!(!block_is_current(&f, TEAM, 8, "content"), "version change");
        assert!(!block_is_current(&f, TEAM, 7, "different"), "content change");
        assert!(!block_is_current("user\n", TEAM, 7, "content"), "no block");
    }

    #[test]
    fn content_hash_is_stable_and_distinguishes() {
        assert_eq!(content_hash("abc"), content_hash("abc"));
        assert_ne!(content_hash("abc"), content_hash("abd"));
    }

    #[test]
    fn upsert_survives_content_with_marker_lookalikes() {
        // User text that mentions the marker words must not confuse find/replace.
        let user = "I documented the toolport:team-instructions format once.\n";
        let out = upsert_block(user, TEAM, 1, "real org rule");
        assert!(out.starts_with(user));
        let back = remove_block(&out).expect("block present");
        assert_eq!(back, user);
    }

    // ---- filesystem-level apply/remove ----

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A unique scratch dir per test (no `tempfile` dep needed); best-effort cleanup on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "toolport-instr-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn owned_target(path: PathBuf) -> Target {
        Target { path, strategy: Strategy::OwnedFile, char_cap: None, blocked_if_present: None }
    }
    fn block_target(path: PathBuf) -> Target {
        Target { path, strategy: Strategy::SentinelBlock, char_cap: None, blocked_if_present: None }
    }

    #[test]
    fn owned_file_apply_creates_then_remove_deletes() {
        let s = Scratch::new();
        // Parent dirs are created on demand.
        let t = owned_target(s.path("rules").join("toolport-team-rules.md"));
        assert_eq!(write_target(&t, TEAM, 2, "Org rule"), ApplyState::Applied);
        let on_disk = std::fs::read_to_string(&t.path).unwrap();
        assert!(on_disk.starts_with(OWNED_HEADER_PREFIX));
        assert!(on_disk.contains("Org rule"));
        remove_recorded(&t.path);
        assert!(!t.path.exists(), "owned file should be deleted on leave");
    }

    #[test]
    fn sentinel_apply_preserves_user_file_and_remove_restores_it() {
        let s = Scratch::new();
        let path = s.path("AGENTS.md");
        let user = "# My rules\nAlways run tests.\n";
        std::fs::write(&path, user).unwrap();
        let t = block_target(path.clone());
        assert_eq!(write_target(&t, TEAM, 1, "Org rule"), ApplyState::Applied);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.starts_with(user), "user bytes preserved");
        assert!(after.contains("Org rule"));
        // Idempotent re-apply doesn't churn the file.
        assert_eq!(write_target(&t, TEAM, 1, "Org rule"), ApplyState::Applied);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), after);
        // Leaving strips only our block; the user's file survives with their content.
        remove_recorded(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), user);
    }

    #[test]
    fn sentinel_into_absent_file_then_remove_deletes_empty_file() {
        let s = Scratch::new();
        let path = s.path("GEMINI.md"); // does not exist yet
        let t = block_target(path.clone());
        assert_eq!(write_target(&t, TEAM, 1, "Only org content"), ApplyState::Applied);
        assert!(path.exists());
        // The whole file was ours -> stripping the block leaves nothing -> delete.
        remove_recorded(&path);
        assert!(!path.exists(), "a file that held only our block should be removed");
    }

    #[test]
    fn blocked_override_skips_write() {
        let s = Scratch::new();
        let shadow = s.path("AGENTS.override.md");
        std::fs::write(&shadow, "user opt-out").unwrap();
        let target_path = s.path("AGENTS.md");
        let t = Target {
            path: target_path.clone(),
            strategy: Strategy::SentinelBlock,
            char_cap: None,
            blocked_if_present: Some(shadow),
        };
        assert_eq!(write_target(&t, TEAM, 1, "Org rule"), ApplyState::BlockedOverride);
        assert!(!target_path.exists(), "must not write when shadowed");
    }

    #[test]
    fn too_long_content_skips_write() {
        let s = Scratch::new();
        let path = s.path("global_rules.md");
        let t = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            char_cap: Some(10),
            blocked_if_present: None,
        };
        assert_eq!(write_target(&t, TEAM, 1, "way over the tiny cap"), ApplyState::TooLong);
        assert!(!path.exists());
    }

    #[test]
    fn content_carrying_our_markers_is_refused() {
        let s = Scratch::new();
        // A START marker in owned content would make cleanup misclassify the file; an END marker
        // in sentinel content would truncate the block. Both must be refused, nothing written.
        let owned = owned_target(s.path("owned.md"));
        assert_eq!(
            write_target(&owned, TEAM, 1, &format!("evil {SENTINEL_START_PREFIX} x -->")),
            ApplyState::Error
        );
        assert!(!owned.path.exists());
        let block = block_target(s.path("block.md"));
        assert_eq!(
            write_target(&block, TEAM, 1, &format!("evil {SENTINEL_END} tail")),
            ApplyState::Error
        );
        assert!(!block.path.exists());
    }

    #[test]
    fn cap_counts_the_whole_rendered_file_not_just_content() {
        let s = Scratch::new();
        let path = s.path("global_rules.md");
        // Pre-existing user rules already near the cap; a small org block tips the FILE over even
        // though the org content alone is tiny.
        std::fs::write(&path, "x".repeat(40)).unwrap();
        let t = Target {
            path: path.clone(),
            strategy: Strategy::SentinelBlock,
            char_cap: Some(50),
            blocked_if_present: None,
        };
        assert_eq!(write_target(&t, TEAM, 1, "tiny"), ApplyState::TooLong);
        // The user's file must be left exactly as it was.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x".repeat(40));
    }

    #[test]
    fn current_state_reports_applied_stale_and_blocked() {
        let s = Scratch::new();
        // Owned file: absent -> Stale; after write -> Applied; hand-edited -> Stale.
        let owned = owned_target(s.path("rules.md"));
        assert_eq!(current_state(&owned, TEAM, 1, "c"), ApplyState::Stale);
        write_target(&owned, TEAM, 1, "c");
        assert_eq!(current_state(&owned, TEAM, 1, "c"), ApplyState::Applied);
        // A newer version the writer hasn't applied yet reads as Stale.
        assert_eq!(current_state(&owned, TEAM, 2, "c"), ApplyState::Stale);
        std::fs::write(&owned.path, "user clobbered it").unwrap();
        assert_eq!(current_state(&owned, TEAM, 1, "c"), ApplyState::Stale);

        // Sentinel block in a shared file.
        let path = s.path("AGENTS.md");
        std::fs::write(&path, "# user\n").unwrap();
        let block = block_target(path.clone());
        assert_eq!(current_state(&block, TEAM, 1, "c"), ApplyState::Stale);
        write_target(&block, TEAM, 1, "c");
        assert_eq!(current_state(&block, TEAM, 1, "c"), ApplyState::Applied);

        // Codex-style shadow file -> BlockedOverride regardless of the target's contents.
        let shadow = s.path("AGENTS.override.md");
        std::fs::write(&shadow, "opt out").unwrap();
        let shadowed = Target {
            path: s.path("codex-AGENTS.md"),
            strategy: Strategy::SentinelBlock,
            char_cap: None,
            blocked_if_present: Some(shadow),
        };
        assert_eq!(current_state(&shadowed, TEAM, 1, "c"), ApplyState::BlockedOverride);
    }

    #[test]
    fn current_state_reports_too_long() {
        let s = Scratch::new();
        let path = s.path("global_rules.md");
        std::fs::write(&path, "x".repeat(40)).unwrap();
        let t = Target {
            path,
            strategy: Strategy::SentinelBlock,
            char_cap: Some(50),
            blocked_if_present: None,
        };
        assert_eq!(current_state(&t, TEAM, 1, "tiny"), ApplyState::TooLong);
    }

    #[test]
    fn remove_recorded_leaves_a_foreign_file_untouched() {
        let s = Scratch::new();
        let path = s.path("someones.md");
        let foreign = "# not ours\njust user content\n";
        std::fs::write(&path, foreign).unwrap();
        remove_recorded(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), foreign);
    }
}
