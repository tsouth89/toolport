//! Conduit's own source-of-truth registry.
//!
//! This is independent of any client. It holds the full set of MCP servers the
//! user has in Conduit, plus profiles. A profile is a named set of *enabled*
//! servers (e.g. "Personal", "Work"); toggling a server on/off is just editing
//! the active profile. The gateway exposes whatever the active profile enables.
//!
//! Secrets are never stored here. Env vars marked `secret` keep their value in
//! the OS keychain; this file only records that a secret exists.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

const REGISTRY_VERSION: u32 = 1;

/// Per-process counter for unique atomic-write temp names.
static ATOMIC_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Write `contents` to `path` atomically: a uniquely-named sibling temp file,
/// then rename over the target. The unique name (pid + per-process sequence)
/// means two writers to the same path can't overwrite each other's half-written
/// temp. The temp sits in the same directory so the rename stays on one
/// filesystem (and is therefore atomic). The temp is cleaned up if the rename
/// fails, so a failed write never leaves a stray file behind.
pub fn atomic_write(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let seq = ATOMIC_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = PathBuf::from(format!(
        "{}.{}.{}.conduit-tmp",
        path.display(),
        std::process::id(),
        seq
    ));
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
        // Restrict to owner-only (0600) BEFORE writing, so secrets.enc, the registry,
        // pins, and the audit log are never world-readable, not even for the brief
        // window before the content lands, under a permissive umask on a shared or
        // headless host. No-op on Windows (NTFS ACLs inherit from the parent dir).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        f.write_all(contents.as_bytes()).map_err(|e| e.to_string())?;
        // Flush the data to stable storage BEFORE the rename, so a crash/power loss
        // can't make the rename durable while the file's blocks aren't — which would
        // leave a truncated registry.json. `fs::write` + `rename` alone did not.
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })?;
    // Best-effort: fsync the containing directory so the rename entry itself is durable
    // (Unix). Opening a directory as a File fails on Windows, where NTFS journals the
    // rename anyway, so the error is ignored.
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
const DEFAULT_PROFILE_ID: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnvVar {
    pub key: String,
    /// Non-secret value, stored inline. For secrets this is `None` and the value
    /// lives in the OS keychain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default)]
    pub secret: bool,
}

// No `Eq`: the `unknown_fields` flatten map (a serde_json::Map) is only `PartialEq`.
// Dropping `Eq` is what lets an older binary preserve per-server fields it doesn't
// recognize on re-save, mirroring the same forward-compat protection already on
// `Registry`. Nothing keys a set/map by `ServerEntry`, so `Eq` was unused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServerEntry {
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// "stdio" | "http" | "sse"
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Working directory for a stdio server. Unset means inherit the gateway's
    /// cwd (the previous behavior). A leading `~` expands to the home dir and
    /// `${VAR}` expands from the environment, so a server that operates on the
    /// project (e.g. a grep/filesystem tool) can be pinned to it. The reserved
    /// token `${ROOT}` expands to the upstream MCP client's current project
    /// directory (its first declared root); it is resolved only in stdio-gateway
    /// mode, and falls back to the gateway cwd when no client root is known.
    /// Only applies to stdio servers. See issue #239.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Where this entry came from, e.g. "imported:cursor" or "manual".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Original (downstream) tool names the user has switched off. The gateway
    /// hides these from `tools/list` and rejects calls to them. Default-allow:
    /// an empty list means every tool the server advertises is exposed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_tools: Vec<String>,
    /// Per-server fields written by a newer build that this binary doesn't know
    /// about. Captured on load and re-emitted on save so a mixed-version binary
    /// never strips them (same contract as `Registry::unknown_fields`).
    #[serde(flatten)]
    pub unknown_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled_server_ids: Vec<String>,
    /// Optional tool-granular scoping (the "FeatureSet" layer): a per-server allow-list of
    /// the ORIGINAL tool names this profile exposes. A server present here exposes ONLY the
    /// listed tools; a server ABSENT exposes all of its tools, exactly as before. An empty
    /// map means the profile is server-granular only, so this is fully backward compatible.
    /// Keyed by server id -> original tool names (like `pinned_tools`), so a `tool_override`
    /// rename can't slip a tool past the scope. Enforced everywhere the server scope is:
    /// tools/list, search, and the call guard.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tool_scope: HashMap<String, Vec<String>>,
}

/// Maps a project folder to a profile, so the gateway can auto-scope a client to the right
/// server set based on the working directory (MCP `root`) it reports, instead of a manual
/// profile switch. A client whose reported root is `path` or a descendant of it resolves to
/// `profile`; the longest matching `path` wins. `profile` is a profile id OR name (resolved
/// the same way as `client_scopes`, via `resolve_profile_id`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FolderProfile {
    pub path: String,
    pub profile: String,
}

/// A consumer registered to reach the gateway over the HTTP/OpenAPI bridge with
/// its own bearer token and scope. Lets one bridge process serve several clients
/// (e.g. Open WebUI) with different server sets, resolved per request from the
/// token. The plaintext token is shown once at creation and never stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HttpClient {
    pub id: String,
    pub label: String,
    /// SHA-256 (hex) of the bearer token. We store only the hash, like any token.
    pub token_sha256: String,
    /// Profile name this client is scoped to. Empty = the full connected set
    /// (no extra filtering), so it behaves like the legacy single-token bridge.
    #[serde(default)]
    pub profile: String,
}

/// SHA-256 (hex) of a string. Used to hash bearer tokens so plaintext never hits
/// disk; the same hash is recomputed on an incoming token to look up its client.
pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Constant-time byte equality, so a token-hash comparison can't leak the stored
/// hash prefix through early-exit timing (consistent with the gateway's other token
/// checks). A length mismatch short-circuits; length isn't secret for a fixed-width hash.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Normalize a filesystem path for prefix comparison WITHOUT touching disk: unify separators
/// to `/`, trim a trailing separator, and lowercase on Windows (its paths are
/// case-insensitive). String-only so it works for a path that doesn't exist on this machine
/// (the client reported it). Not canonicalization, just enough to compare two reported paths.
fn normalize_path(p: &str) -> String {
    let mut s = p.trim().replace('\\', "/");
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    if cfg!(windows) {
        s = s.to_ascii_lowercase();
    }
    s
}

/// True when `root` is `base` itself or a descendant of it, matched on a path BOUNDARY so
/// base `/a/proj` matches `/a/proj` and `/a/proj/src` but never `/a/project`. Both must
/// already be [`normalize_path`]-ed. An empty `base` matches nothing (an unset mapping path
/// must not swallow every root).
fn path_is_within(base: &str, root: &str) -> bool {
    if base.is_empty() {
        return false;
    }
    if root == base {
        return true;
    }
    root.starts_with(base) && root.as_bytes().get(base.len()) == Some(&b'/')
}

/// A user override for how one tool is exposed to clients, keyed in the registry by the
/// tool's exposed (namespaced `server__tool`) name. Lets the user rename a tool or replace
/// its description - the latter is the security lever: locally neutralize a poisoned or
/// injection-laden description without waiting on the upstream server. Overrides only touch
/// the EXPOSED definition; the call still routes to the original downstream tool. (Pinning
/// input params is a planned follow-up and not in this struct yet.)
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolOverride {
    /// A replacement client-facing name (sanitized to a valid tool name; ignored if it
    /// would collide with another exposed tool).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// A replacement description shown to the client instead of the server's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub version: u32,
    pub servers: Vec<ServerEntry>,
    pub profiles: Vec<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile_id: Option<String>,
    /// Global safety switch: when true, the gateway hides and blocks any tool a
    /// server annotates with `destructiveHint: true` (deletes, drops, writes).
    /// One toggle to keep agents read-only across every connected server.
    #[serde(default)]
    pub deny_destructive: bool,
    /// Per-call confirmation for destructive tools: when true, the gateway
    /// intercepts each call to a destructive-hinted tool, returns a preview
    /// with a confirmation token, and requires `conduit_confirm { token }` to
    /// proceed. The original arguments are replayed exactly — the agent cannot
    /// change them. Unlike `deny_destructive` (which hides tools entirely),
    /// this lets agents use destructive tools — but forces a conscious review
    /// of every call first.
    #[serde(default)]
    pub confirm_destructive: bool,
    /// Human-in-the-loop approval: when true, a *gated* tool call (destructive-hinted, or
    /// from an untrusted-provenance server) is held and surfaced to the Toolport app for a
    /// person to approve or deny before it runs. Unlike `confirm_destructive` (which the
    /// AGENT re-confirms with a token), this puts a HUMAN in the loop: the call blocks until
    /// a decision or a fail-closed timeout. Off by default. Takes precedence over
    /// `confirm_destructive` for the tools it gates (a human decision supersedes the agent's).
    #[serde(default)]
    pub human_approval: bool,
    /// Tools the user chose to "always allow" past human approval, so the HITL gate skips
    /// them. Each entry is a `server/tool` key (see `approval::allow_key`). Persisted so an
    /// always-allowed tool stays allowed across restarts; the broker also keeps a separate
    /// ephemeral per-session allowlist that is NOT saved here.
    #[serde(default)]
    pub human_approval_allow: Vec<String>,
    /// Set true only while an ACTIVE team's screening policy forces human approval
    /// (`forceHumanApproval`). Kept SEPARATE from `human_approval` (the member's own choice)
    /// so the org lock is RELEASABLE: recomputed on every team sync and cleared when the
    /// member leaves or is removed from a team, instead of being baked permanently into the
    /// member's own setting (which had no release path, so an org lock outlived the team).
    /// The gate holds a call when either is true (see [`Registry::human_approval_effective`]).
    #[serde(default)]
    pub team_forced_human_approval: bool,
    /// The same releasable org-lock treatment as [`team_forced_human_approval`] for the other
    /// tighten-only screening flags (`denyDestructive`, `forceContentDefense`,
    /// `forceQuarantineOnDrift`). Set from the active team's policy, recomputed each sync and
    /// cleared on leave, so an org lock never permanently overwrites the member's own setting.
    /// Enforcement reads `*_effective()` (member's own OR team-forced).
    #[serde(default)]
    pub team_forced_deny_destructive: bool,
    #[serde(default)]
    pub team_forced_content_defense: bool,
    #[serde(default)]
    pub team_forced_quarantine_on_drift: bool,
    /// Per-tool exposure overrides, keyed by server id then ORIGINAL tool name (not the
    /// exposed name, so a rename or `_2` collision suffix can't misalign the key): rename or
    /// re-describe a tool as clients see it (e.g. neutralize a poisoned description). The
    /// call still routes to the original downstream tool.
    #[serde(default)]
    pub tool_overrides: HashMap<String, HashMap<String, ToolOverride>>,
    /// Tools pinned as lazy-discovery prerequisites, keyed by server id -> original tool
    /// names. Search always surfaces a pinned tool (with its schema) regardless of the
    /// query's match score, so a load-bearing tool (auth, list-before-act, one whose
    /// description doesn't match the user's keywords) is never hidden behind lazy
    /// discovery. Empty = nothing pinned.
    #[serde(default)]
    pub pinned_tools: HashMap<String, Vec<String>>,
    /// Quarantine-on-drift: when true, a high-risk tool (poisoned definition, or a
    /// destructive tool whose definition changed/appeared) that drifts from its pinned
    /// baseline is hidden and blocked from every client until the user re-approves it.
    /// Opt-in, since blocking a tool is more disruptive than just flagging the drift.
    #[serde(default)]
    pub quarantine_on_drift: bool,
    /// Lazy discovery: the gateway exposes 4 meta-tools (status/search/call/fetch)
    /// instead of every downstream tool, so clients with tool-count limits don't
    /// drop tools. The gateway reads this from the registry file it already
    /// loads, so it applies to EVERY client regardless of whether the client
    /// passes the `CONDUIT_DISCOVERY` env var (an explicit env still overrides).
    /// Defaults on, since clients commonly cap the tool list.
    #[serde(default = "default_true")]
    pub lazy_discovery: bool,
    /// Discovery-mode override: `"lazy"` | `"grouped"` | `"full"`. When set, it takes
    /// precedence over `lazy_discovery`; `None` (the default, and every pre-existing
    /// registry) falls back to that bool. An explicit `CONDUIT_DISCOVERY` env var still
    /// overrides this. Lets a user pick grouped mode once - for weak/local models that
    /// browse per-server instead of searching - instead of setting a per-client env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_mode: Option<String>,
    /// Opt-in agent control: when true, an agent may turn servers on or off via
    /// the gateway's `conduit_enable_server` / `conduit_disable_server` tools.
    /// Off by default. The `deny_destructive` safety switch is never agent-
    /// writable regardless, so granting this cannot let an agent escalate past
    /// the user's governance, only flip which servers are connected.
    #[serde(default)]
    pub allow_agent_control: bool,
    /// Tool-definition integrity: fingerprint each connected tool and flag when a
    /// previously-approved tool's definition changes (a rug-pull signal) or a known
    /// server quietly adds a tool. Detection only, it records a security event and
    /// never blocks. On by default.
    #[serde(default = "default_true")]
    pub integrity_check: bool,
    /// Content defense (anti-agentjacking): scan untrusted tool RESULTS for injection
    /// and label flagged content as data, not instructions, before the agent sees it.
    /// Detection + labeling, never blocks. On by default.
    #[serde(default = "default_true")]
    pub content_defense: bool,
    /// Live request/response inspection: when true, the gateway captures each tool
    /// call's arguments and result into a small, separate, ephemeral local ring
    /// (`inspect.jsonl`, last 50 calls, each body size-capped) so the Activity view
    /// can show them. OFF by default and never touches the governance audit log,
    /// which stays free of args/results. This is the ONE place args/results are
    /// captured, and only on the user's machine.
    #[serde(default)]
    pub live_inspect: bool,
    /// Optional semantic re-ranking for tool search (blends embedding similarity
    /// into the lexical ranking). Off by default; when off or unconfigured, search
    /// is pure lexical exactly as before.
    #[serde(default)]
    pub semantic_search: SemanticSettings,
    /// Connection to a Conduit Teams server (the paid config-sync layer), if the user
    /// has joined a team. The member token is NOT stored here, it lives in the OS
    /// keychain like any other secret. Servers pulled from the team are merged into
    /// `servers` tagged `source = "team:<id>"`, non-destructively.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<TeamConnection>,
    /// Per-server result-shaping budgets in bytes, keyed by server id (tier-2
    /// fidelity policy). A server absent from the map uses the global default; a
    /// value of `0` means NEVER shape that server's results (full fidelity, for
    /// financial/compliance APIs); `n` caps that server's results at n bytes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub result_budgets: HashMap<String, u64>,
    /// Which profile each client was connected with, keyed by client id (e.g.
    /// "cursor" -> "Billing"). This is the binding Conduit wrote into that client's
    /// config as `CONDUIT_PROFILE`; recording it here lets the UI show a connected
    /// client's effective scope and re-scope it in place. Absent / empty value =
    /// the client follows the active profile (all its enabled servers).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_scopes: HashMap<String, String>,
    /// Folder -> profile mappings for project-scoped auto-routing: when a client reports a
    /// working directory (MCP `root`), the gateway picks the profile whose mapped path is the
    /// longest prefix of that root, instead of the client's manually-set profile. Empty = no
    /// folder routing (every client follows its configured/active profile as before).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folder_profiles: Vec<FolderProfile>,
    /// Per-client discovery-mode override, keyed by stable client id (e.g. "cursor" ->
    /// "grouped"). Value is `"full" | "lazy" | "grouped"`; an absent entry means the client
    /// inherits the global mode (`discovery_mode`, else `lazy_discovery`). The gateway
    /// resolves it live via `CONDUIT_CLIENT_ID`, so changing it re-applies without
    /// reinstalling the client (same mechanism as `client_scopes`).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub client_discovery: HashMap<String, String>,
    /// Consumers registered to reach the gateway over the HTTP/OpenAPI bridge,
    /// each with its own hashed bearer token and scope. Empty = the bridge uses
    /// only the legacy single `CONDUIT_HTTP_TOKEN` (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<HttpClient>,
    /// Bumped when vaulted secrets change so running gateways reload even when
    /// the rest of the registry JSON is unchanged.
    #[serde(default)]
    pub secrets_generation: u64,
    /// Top-level fields THIS build doesn't know, preserved verbatim across
    /// load -> save. The registry is shared by mixed versions of the app and
    /// long-running gateways (a dev build, the installed release, and gateways
    /// spawned days ago can all touch one file); serde's default is to silently
    /// IGNORE unknown fields, which meant an older binary's next save stripped
    /// every newer-schema field. Capturing them instead makes old binaries
    /// pass-through-safe.
    #[serde(flatten)]
    pub unknown_fields: serde_json::Map<String, serde_json::Value>,
}

/// A joined Conduit Teams server. Holds only non-secret connection metadata; the
/// member bearer token is vaulted in the OS keychain (see `secrets`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TeamConnection {
    /// Base URL of the conduit-teams server, e.g. `https://teams.example.com`.
    pub server_url: String,
    pub team_id: String,
    /// "admin" | "member".
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_name: Option<String>,
    /// Last config version pulled, for change display and ETag polling.
    #[serde(default)]
    pub last_version: i64,
    /// The exact ETag the server returned on the last pull. Echoed back as If-None-Match
    /// so the 304 fast-path works even for access-restricted members, whose server ETag
    /// carries a per-member suffix that a reconstructed "v{n}" would never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_etag: Option<String>,
    /// Usage rows already reported to the team server, "YYYY-MM-DD" (UTC) -> server id ->
    /// [calls, tokens_saved]. The next report sends max(local rollup, this), so a local
    /// log rotation mid-day can never shrink a count the server already has. Pruned to
    /// the report window (today + yesterday) on every successful report.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub usage_reported: HashMap<String, HashMap<String, [u64; 2]>>,
}

/// Settings for embedding-based search re-ranking. The embedding API key, if the
/// endpoint needs one, is read from the `CONDUIT_EMBED_KEY` env var, never stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticSettings {
    #[serde(default)]
    pub enabled: bool,
    /// OpenAI-compatible embeddings endpoint, e.g. http://localhost:1234/v1/embeddings.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub model: String,
    /// Weight of semantic vs lexical, 0.0 (pure lexical) .. 1.0 (pure semantic).
    #[serde(default = "default_blend")]
    pub blend: f32,
}

fn default_blend() -> f32 {
    0.5
}

impl Default for SemanticSettings {
    fn default() -> Self {
        SemanticSettings { enabled: false, endpoint: String::new(), model: String::new(), blend: 0.5 }
    }
}

fn default_true() -> bool {
    true
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            version: REGISTRY_VERSION,
            servers: Vec::new(),
            profiles: vec![Profile {
                id: DEFAULT_PROFILE_ID.to_string(),
                name: "Default".to_string(),
                enabled_server_ids: Vec::new(),
                tool_scope: HashMap::new(),
            }],
            active_profile_id: Some(DEFAULT_PROFILE_ID.to_string()),
            deny_destructive: false,
            confirm_destructive: false,
            human_approval: false,
            human_approval_allow: Vec::new(),
            team_forced_human_approval: false,
            team_forced_deny_destructive: false,
            team_forced_content_defense: false,
            team_forced_quarantine_on_drift: false,
            tool_overrides: HashMap::new(),
            pinned_tools: HashMap::new(),
            quarantine_on_drift: false,
            lazy_discovery: true,
            discovery_mode: None,
            allow_agent_control: false,
            integrity_check: true,
            content_defense: true,
            live_inspect: false,
            semantic_search: SemanticSettings::default(),
            team: None,
            result_budgets: HashMap::new(),
            client_scopes: HashMap::new(),
            folder_profiles: Vec::new(),
            client_discovery: HashMap::new(),
            http_clients: Vec::new(),
            secrets_generation: 0,
            unknown_fields: serde_json::Map::new(),
        }
    }
}

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !out.is_empty() && !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

pub(crate) fn unique_id(base: &str, existing: &[String]) -> String {
    let base = if base.is_empty() { "item" } else { base };
    if !existing.iter().any(|e| e == base) {
        return base.to_string();
    }
    let mut n = 2;
    loop {
        let candidate = format!("{base}-{n}");
        if !existing.iter().any(|e| e == &candidate) {
            return candidate;
        }
        n += 1;
    }
}

impl Registry {
    fn server_ids(&self) -> Vec<String> {
        self.servers.iter().map(|s| s.id.clone()).collect()
    }

    fn profile_ids(&self) -> Vec<String> {
        self.profiles.iter().map(|p| p.id.clone()).collect()
    }

    /// Add a new server, assigning a unique id derived from its name. Returns the id.
    pub fn add_server(&mut self, mut entry: ServerEntry) -> String {
        let id = unique_id(&slugify(&entry.name), &self.server_ids());
        entry.id = id.clone();
        self.servers.push(entry);
        id
    }

    pub fn update_server(&mut self, entry: ServerEntry) -> Result<(), String> {
        let slot = self
            .servers
            .iter_mut()
            .find(|s| s.id == entry.id)
            .ok_or_else(|| format!("No server with id '{}'", entry.id))?;
        *slot = entry;
        Ok(())
    }

    pub fn remove_server(&mut self, id: &str) -> Result<(), String> {
        let before = self.servers.len();
        self.servers.retain(|s| s.id != id);
        if self.servers.len() == before {
            return Err(format!("No server with id '{id}'"));
        }
        for profile in &mut self.profiles {
            profile.enabled_server_ids.retain(|sid| sid != id);
            // Drop any tool-scope allow-list for the removed server so it can't orphan.
            profile.tool_scope.remove(id);
        }
        Ok(())
    }

    pub fn active_profile_id(&self) -> String {
        self.active_profile_id
            .clone()
            .or_else(|| self.profiles.first().map(|p| p.id.clone()))
            .unwrap_or_else(|| DEFAULT_PROFILE_ID.to_string())
    }

    pub fn is_enabled(&self, profile_id: &str, server_id: &str) -> bool {
        self.profiles
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.enabled_server_ids.iter().any(|s| s == server_id))
            .unwrap_or(false)
    }

    /// Toggle a server's enabled state within a profile.
    pub fn set_server_enabled(
        &mut self,
        profile_id: &str,
        server_id: &str,
        enabled: bool,
    ) -> Result<(), String> {
        if !self.servers.iter().any(|s| s.id == server_id) {
            return Err(format!("No server with id '{server_id}'"));
        }
        let profile = self
            .profiles
            .iter_mut()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| format!("No profile with id '{profile_id}'"))?;
        let present = profile.enabled_server_ids.iter().any(|s| s == server_id);
        if enabled && !present {
            profile.enabled_server_ids.push(server_id.to_string());
        } else if !enabled && present {
            profile.enabled_server_ids.retain(|s| s != server_id);
        }
        Ok(())
    }

    /// Enable or disable every server in a profile at once.
    pub fn set_all_enabled(&mut self, profile_id: &str, enabled: bool) -> Result<(), String> {
        let ids: Vec<String> = self.servers.iter().map(|s| s.id.clone()).collect();
        let profile = self
            .profiles
            .iter_mut()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| format!("No profile with id '{profile_id}'"))?;
        profile.enabled_server_ids = if enabled { ids } else { Vec::new() };
        Ok(())
    }

    /// Enable or disable a single tool on a server. Disabling adds it to the
    /// server's `disabled_tools`; enabling removes it. Idempotent.
    pub fn set_tool_enabled(
        &mut self,
        server_id: &str,
        tool: &str,
        enabled: bool,
    ) -> Result<(), String> {
        let server = self
            .servers
            .iter_mut()
            .find(|s| s.id == server_id)
            .ok_or_else(|| format!("No server with id '{server_id}'"))?;
        let present = server.disabled_tools.iter().any(|t| t == tool);
        if enabled && present {
            server.disabled_tools.retain(|t| t != tool);
        } else if !enabled && !present {
            server.disabled_tools.push(tool.to_string());
        }
        Ok(())
    }

    /// Whether a specific tool is enabled (default-allow: unknown tools are on).
    pub fn is_tool_enabled(&self, server_id: &str, tool: &str) -> bool {
        self.servers
            .iter()
            .find(|s| s.id == server_id)
            .map(|s| !s.disabled_tools.iter().any(|t| t == tool))
            .unwrap_or(true)
    }

    /// Whether a profile exposes a given tool (tool-granular scoping / "FeatureSet"). Default-
    /// allow: if the profile has no `tool_scope` allow-list for `server_id`, every tool on
    /// that server is exposed (server-granular behavior, unchanged). If it does, ONLY the
    /// listed tools are. Layered UNDER the server scope, so it only narrows within a profile's
    /// enabled servers. `tool` is the ORIGINAL tool name (as `route_of` yields it). An unknown
    /// profile ref imposes no extra tool restriction here (the server scope already blocks it).
    pub fn profile_allows_tool(&self, profile_ref: &str, server_id: &str, tool: &str) -> bool {
        let id = self.resolve_profile_id(profile_ref);
        match self.profiles.iter().find(|p| p.id == id) {
            Some(p) => match p.tool_scope.get(server_id) {
                Some(allowed) => allowed.iter().any(|t| t == tool),
                None => true,
            },
            None => true,
        }
    }

    /// Set or clear a profile's tool allow-list for one server. `Some(list)` narrows that
    /// server to exactly those ORIGINAL tool names (an EMPTY list is a real state: expose NO
    /// tools on that server, enforced as block-all). `None` removes the entry, restoring "all
    /// tools on that server". Idempotent. The UI sends `None` only when every tool is selected,
    /// so an unnarrowed profile keeps an empty `tool_scope` (backward compatible), and sends
    /// `Some(subset)` otherwise, distinguishing "all" (None) from "none" (empty list).
    pub fn set_profile_server_tools(
        &mut self,
        profile_id: &str,
        server_id: &str,
        tools: Option<Vec<String>>,
    ) -> Result<(), String> {
        let profile = self
            .profiles
            .iter_mut()
            .find(|p| p.id == profile_id)
            .ok_or_else(|| format!("No profile with id '{profile_id}'"))?;
        match tools {
            Some(list) => {
                profile.tool_scope.insert(server_id.to_string(), list);
            }
            None => {
                profile.tool_scope.remove(server_id);
            }
        }
        Ok(())
    }

    /// Pin or unpin a tool as a lazy-discovery prerequisite (by ORIGINAL tool name).
    /// Idempotent; drops the server's entry when its last pin is removed.
    pub fn set_tool_pinned(&mut self, server_id: &str, tool: &str, pinned: bool) {
        let list = self.pinned_tools.entry(server_id.to_string()).or_default();
        let present = list.iter().any(|t| t == tool);
        if pinned && !present {
            list.push(tool.to_string());
        } else if !pinned && present {
            list.retain(|t| t != tool);
        }
        if list.is_empty() {
            self.pinned_tools.remove(server_id);
        }
    }

    /// Whether a tool is pinned as a prerequisite (default: not pinned).
    pub fn is_tool_pinned(&self, server_id: &str, tool: &str) -> bool {
        self.pinned_tools
            .get(server_id)
            .map(|l| l.iter().any(|t| t == tool))
            .unwrap_or(false)
    }

    /// Set the global destructive-tool deny switch. Mutually exclusive with
    /// `confirm_destructive`: enabling deny clears confirm.
    pub fn set_deny_destructive(&mut self, deny: bool) {
        self.deny_destructive = deny;
        if deny {
            self.confirm_destructive = false;
        }
    }

    /// Set per-call confirmation mode for destructive tools. When enabled,
    /// `deny_destructive` is forced off (they're mutually exclusive: deny hides
    /// tools entirely, confirm intercepts them with a preview).
    pub fn set_confirm_destructive(&mut self, confirm: bool) {
        self.confirm_destructive = confirm;
        if confirm {
            self.deny_destructive = false;
        }
    }

    /// Turn human-in-the-loop approval on or off. Independent of deny/confirm: `deny`
    /// hides tools, `confirm` has the agent re-confirm, `human_approval` holds the call
    /// for a person. When it gates a tool it takes precedence over `confirm_destructive`.
    pub fn set_human_approval(&mut self, on: bool) {
        self.human_approval = on;
    }

    /// Whether the HITL gate is active: the member's OWN toggle, OR an active team's forced
    /// policy. The gate reads this instead of `human_approval` directly so an org lock stays
    /// releasable (it lives in `team_forced_human_approval`, cleared on leave) rather than
    /// permanently overwriting the member's own choice.
    pub fn human_approval_effective(&self) -> bool {
        self.human_approval || self.team_forced_human_approval
    }

    /// Effective (member's own OR team-forced) values for the other tighten-only safety flags,
    /// so an org lock is releasable on leave instead of permanently overwriting the member's own.
    pub fn deny_destructive_effective(&self) -> bool {
        self.deny_destructive || self.team_forced_deny_destructive
    }
    pub fn content_defense_effective(&self) -> bool {
        self.content_defense || self.team_forced_content_defense
    }
    pub fn quarantine_on_drift_effective(&self) -> bool {
        self.quarantine_on_drift || self.team_forced_quarantine_on_drift
    }

    /// Add a `server/tool` key to the persistent "always allow" list, so the HITL gate
    /// skips it. Idempotent.
    pub fn allow_tool(&mut self, key: String) {
        if !self.human_approval_allow.contains(&key) {
            self.human_approval_allow.push(key);
        }
    }

    /// Remove a key from the persistent allow list (re-require approval for that tool).
    pub fn revoke_tool(&mut self, key: &str) {
        self.human_approval_allow.retain(|k| k != key);
    }

    /// Whether a `server/tool` key is on the persistent always-allow list.
    pub fn is_tool_allowed(&self, key: &str) -> bool {
        self.human_approval_allow.iter().any(|k| k == key)
    }

    /// Set (or replace) the exposure override for a `(server, original tool)`. An override
    /// with both fields cleared is removed rather than stored empty (and the server's map is
    /// dropped when it becomes empty).
    pub fn set_tool_override(&mut self, server: String, tool: String, ov: ToolOverride) {
        if ov.name.is_none() && ov.description.is_none() {
            self.clear_tool_override(&server, &tool);
        } else {
            self.tool_overrides.entry(server).or_default().insert(tool, ov);
        }
    }

    /// Remove any override for a `(server, original tool)` (restore the server's own
    /// definition), dropping the server's map when it becomes empty.
    pub fn clear_tool_override(&mut self, server: &str, tool: &str) {
        if let Some(m) = self.tool_overrides.get_mut(server) {
            m.remove(tool);
            if m.is_empty() {
                self.tool_overrides.remove(server);
            }
        }
    }

    /// Set lazy discovery mode (gateway exposes meta-tools vs the full catalog).
    pub fn set_lazy_discovery(&mut self, lazy: bool) {
        self.lazy_discovery = lazy;
    }

    /// Set the discovery-mode override. `"lazy"`/`"grouped"`/`"full"` are honored;
    /// any other value (including clearing to the empty string) resets to `None`, so
    /// resolution falls back to `lazy_discovery`. Keeps `lazy_discovery` in sync for
    /// the "lazy"/"full" cases so an older gateway reading only that bool still agrees.
    pub fn set_discovery_mode(&mut self, mode: &str) {
        match mode.trim().to_ascii_lowercase().as_str() {
            "lazy" => {
                self.discovery_mode = Some("lazy".into());
                self.lazy_discovery = true;
            }
            "full" => {
                self.discovery_mode = Some("full".into());
                self.lazy_discovery = false;
            }
            "grouped" => self.discovery_mode = Some("grouped".into()),
            _ => self.discovery_mode = None,
        }
    }

    /// Turn live request/response inspection on or off. When on, the gateway
    /// captures each tool call's args + result into the ephemeral `inspect.jsonl`
    /// ring; when off, nothing is captured and no inspect file is written.
    pub fn set_live_inspect(&mut self, on: bool) {
        self.live_inspect = on;
    }

    pub fn add_profile(&mut self, name: &str) -> String {
        let id = unique_id(&slugify(name), &self.profile_ids());
        self.profiles.push(Profile {
            id: id.clone(),
            name: name.to_string(),
            enabled_server_ids: Vec::new(),
            tool_scope: HashMap::new(),
        });
        id
    }

    pub fn remove_profile(&mut self, id: &str) -> Result<(), String> {
        if self.profiles.len() <= 1 {
            return Err("Cannot remove the last profile".to_string());
        }
        let before = self.profiles.len();
        self.profiles.retain(|p| p.id != id);
        if self.profiles.len() == before {
            return Err(format!("No profile with id '{id}'"));
        }
        if self.active_profile_id.as_deref() == Some(id) {
            self.active_profile_id = self.profiles.first().map(|p| p.id.clone());
        }
        Ok(())
    }

    pub fn set_active_profile(&mut self, id: &str) -> Result<(), String> {
        if !self.profiles.iter().any(|p| p.id == id) {
            return Err(format!("No profile with id '{id}'"));
        }
        self.active_profile_id = Some(id.to_string());
        Ok(())
    }

    /// Servers enabled in the active profile - what the gateway should expose.
    pub fn enabled_servers(&self) -> Vec<&ServerEntry> {
        let active = self.active_profile_id();
        self.servers
            .iter()
            .filter(|s| self.is_enabled(&active, &s.id))
            .collect()
    }

    /// Resolve a profile by id or (case-insensitive) name, returning its id.
    ///
    /// An **empty/whitespace** reference means "unscoped": it follows the active
    /// profile. A **named** reference that matches no existing profile (e.g. one
    /// that was deleted or renamed out from under a scoped client) fails CLOSED:
    /// it resolves to itself, which `is_enabled` matches to no servers, so the
    /// client sees an empty set rather than silently widening to the active
    /// profile's servers. Only ever widen scope on an explicit unscoped request,
    /// never on a dangling reference.
    pub fn resolve_profile_id(&self, profile_ref: &str) -> String {
        if profile_ref.trim().is_empty() {
            return self.active_profile_id();
        }
        self.profiles
            .iter()
            .find(|p| p.id == profile_ref || p.name.eq_ignore_ascii_case(profile_ref))
            .map(|p| p.id.clone())
            .unwrap_or_else(|| profile_ref.to_string())
    }

    /// Servers enabled in a specific profile (id or name). Powers per-client
    /// scoping: each gateway can expose only the slice its client needs, so
    /// overlapping verbs from unrelated servers never share one tool surface.
    pub fn enabled_servers_for(&self, profile_ref: &str) -> Vec<&ServerEntry> {
        let id = self.resolve_profile_id(profile_ref);
        self.servers
            .iter()
            .filter(|s| self.is_enabled(&id, &s.id))
            .collect()
    }

    /// Resolve the folder-scoped profile for a client's reported root path, if any
    /// [`folder_profiles`](Self::folder_profiles) mapping matches. The longest matching
    /// mapped path wins (so a nested mapping overrides its parent). Returns the mapped
    /// profile string (id or name, resolved like `client_scopes`), or `None` to fall back to
    /// the client's configured/active profile. Path-only string matching, never touches disk:
    /// canonicalizing would fail for a root that doesn't exist on THIS machine, and the point
    /// is to match what the client reported.
    pub fn profile_for_root(&self, root: &str) -> Option<String> {
        let root = normalize_path(root);
        if root.is_empty() {
            return None;
        }
        self.folder_profiles
            .iter()
            .filter_map(|fp| {
                let base = normalize_path(&fp.path);
                path_is_within(&base, &root).then_some((base.len(), fp.profile.clone()))
            })
            .max_by_key(|(len, _)| *len)
            .map(|(_, profile)| profile)
    }

    /// Replace the folder -> profile routing mappings (the UI edits the list wholesale). Drops
    /// entries with a blank path or profile; stores paths verbatim (normalized only at match
    /// time in [`profile_for_root`]).
    pub fn set_folder_profiles(&mut self, mappings: Vec<FolderProfile>) {
        self.folder_profiles = mappings
            .into_iter()
            .filter(|m| !m.path.trim().is_empty() && !m.profile.trim().is_empty())
            .collect();
    }

    /// Servers the multi-tenant HTTP bridge must connect: the union of the base
    /// profile's enabled servers and every registered HTTP client's profile, so a
    /// scoped client's servers are always actually connected (per-request
    /// filtering then narrows each client's view). An empty-profile client is
    /// unscoped and contributes nothing beyond the base. Deduplicated by id;
    /// registry order is preserved.
    pub fn bridge_enabled_servers(&self, base: Option<&str>) -> Vec<&ServerEntry> {
        use std::collections::HashSet;
        let base_id = match base {
            Some(p) => self.resolve_profile_id(p),
            None => self.active_profile_id(),
        };
        let mut profile_ids: Vec<String> = vec![base_id];
        for c in &self.http_clients {
            if c.profile.trim().is_empty() {
                continue; // unscoped client: sees the union, adds nothing to it
            }
            let pid = self.resolve_profile_id(&c.profile);
            if !profile_ids.contains(&pid) {
                profile_ids.push(pid);
            }
        }
        let mut ids: HashSet<&str> = HashSet::new();
        for pid in &profile_ids {
            for s in &self.servers {
                if self.is_enabled(pid, &s.id) {
                    ids.insert(s.id.as_str());
                }
            }
        }
        self.servers
            .iter()
            .filter(|s| ids.contains(s.id.as_str()))
            .collect()
    }

    /// Record (or clear) which profile a client was connected with, mirroring the
    /// `CONDUIT_PROFILE` env Conduit wrote into that client's config. `None` or an
    /// empty/whitespace profile clears the binding (the client follows the active
    /// profile). Lets the UI show and re-apply a connected client's scope.
    pub fn set_client_scope(&mut self, client_id: &str, profile: Option<&str>) {
        match profile.map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => {
                self.client_scopes.insert(client_id.to_string(), p.to_string());
            }
            None => {
                self.client_scopes.remove(client_id);
            }
        }
    }

    /// Set (or clear) a client's discovery-mode override. `Some("full"|"lazy"|"grouped")`
    /// pins that mode for the client; `None`, an empty/whitespace value, `"inherit"`, or any
    /// unrecognized value clears the entry so the client inherits the global mode.
    pub fn set_client_discovery(&mut self, client_id: &str, mode: Option<&str>) {
        let valid = mode
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| matches!(m.as_str(), "full" | "lazy" | "grouped"));
        match valid {
            Some(m) => {
                self.client_discovery.insert(client_id.to_string(), m);
            }
            None => {
                self.client_discovery.remove(client_id);
            }
        }
    }

    /// This client's discovery-mode override, if any (`None` = inherit the global mode).
    pub fn client_discovery_mode(&self, client_id: &str) -> Option<&str> {
        self.client_discovery.get(client_id).map(String::as_str)
    }

    /// Record that a client is *explicitly* unscoped: it follows the active
    /// profile (the full connected set), and we want that to apply live. This is
    /// deliberately distinct from having no entry at all: an empty-string marker
    /// means "follow the active profile now", so a running gateway can drop its
    /// previous scope on the next reload; a missing entry means "no recorded
    /// scope, fall back to the CONDUIT_PROFILE this process booted with" (e.g. an
    /// install from before CONDUIT_CLIENT_ID existed). Without this distinction,
    /// re-scoping a client from a named profile to "all servers" wouldn't take
    /// effect until the client restarted. The frontend already reads a missing
    /// or empty scope identically (`clientScopes?.[id] ?? ""`), so this needs no
    /// UI change.
    pub fn set_client_unscoped(&mut self, client_id: &str) {
        self.client_scopes
            .insert(client_id.to_string(), String::new());
    }

    /// Find the registered HTTP client whose stored hash matches `token`'s
    /// SHA-256, if any. The bridge uses this to resolve a bearer to its scope.
    pub fn http_client_for_token(&self, token: &str) -> Option<&HttpClient> {
        let h = sha256_hex(token);
        self.http_clients.iter().find(|c| ct_eq(&c.token_sha256, &h))
    }
}

/// Leaf directory name under the OS config root (`Conduit` release, `Conduit-dev`
/// for debug/`tauri dev` builds). Override the full path with `CONDUIT_DATA_DIR`.
pub(crate) fn data_dir_leaf_name() -> &'static str {
    if cfg!(debug_assertions) {
        "Conduit-dev"
    } else {
        "Conduit"
    }
}

/// How [`conduit_dir`] was resolved, for startup diagnostics. Only Windows has
/// interesting cases (MSIX app containers); everywhere else it is `Direct`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirResolution {
    /// Normal process: the natural path IS the real directory.
    Direct,
    /// Running inside an MSIX app container: using the loopback-UNC view of the
    /// real directory, bypassing the package's virtualized shadow copy.
    Devirtualized,
    /// Running inside an MSIX app container but the UNC view is unreachable
    /// (admin share disabled/inaccessible), so we are stuck with the natural
    /// path, which the container may redirect to a STALE shadow copy. The
    /// gateway warns loudly when it sees this - see its startup path.
    VirtualizedFallback,
}

/// Conduit's data dir, anchored so every process agrees regardless of launch
/// context.
///
/// On Windows this is `%USERPROFILE%\AppData\Roaming\Conduit`. Spelling the path
/// out (instead of the APPDATA known folder) is NOT enough to agree across
/// processes: a gateway spawned by an MSIX-packaged client (e.g. Claude Desktop)
/// runs inside that app's container, whose filesystem filter redirects opens
/// under `AppData\Roaming` - by ANY path spelling, home-derived or not - into
/// the package's `LocalCache` shadow copy, which can be days stale. (Verified
/// empirically 2026-07-05: a probe file written to `%APPDATA%` from inside the
/// Claude container landed in the package `LocalCache`. An earlier version of
/// this comment claimed home-derived paths escape the redirect; that is false.)
/// A shadowed gateway reads a frozen `registry.json` (server/profile edits never
/// arrive) and a stale `approval-endpoint.json` (HITL approvals fail closed
/// against a dead broker port).
///
/// The fix: when this process has MSIX package identity - meaning it was spawned
/// inside a packaged app's container, since Conduit's own binaries never ship as
/// MSIX - address the SAME directory through its loopback-UNC twin
/// (`\\localhost\C$\Users\...`). SMB serves those opens from the real filesystem,
/// outside the virtualization filter's reach (verified on the same machine). If
/// the UNC view is unreachable we fall back to the natural path, no worse than
/// before; see [`DirResolution`] and [`conduit_dir_resolution`].
///
/// Public so every Conduit file (registry, tool cache, audit log, approval
/// endpoint, debug logs) derives from the same anchor - otherwise the app and a
/// client-spawned gateway would read/write different dirs.
pub fn conduit_dir() -> Option<PathBuf> {
    resolve_conduit_dir().0
}

/// How [`conduit_dir`] was resolved. Cached with it; the answer cannot change
/// mid-process (package identity and the home dir are fixed at spawn).
pub fn conduit_dir_resolution() -> DirResolution {
    resolve_conduit_dir().1
}

/// Resolve the data dir once and cache it: the container check and the UNC
/// reachability probe should not run on every path lookup, and a stable answer
/// keeps every consumer (registry, watcher, tool cache, approval endpoint) on
/// one directory for the process lifetime.
fn resolve_conduit_dir() -> (Option<PathBuf>, DirResolution) {
    static RESOLVED: std::sync::OnceLock<(Option<PathBuf>, DirResolution)> =
        std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            if let Ok(dir) = std::env::var("CONDUIT_DATA_DIR") {
                if !dir.trim().is_empty() {
                    return (Some(PathBuf::from(dir)), DirResolution::Direct);
                }
            }
            let leaf = data_dir_leaf_name();
            #[cfg(windows)]
            {
                let Some(home) = dirs::home_dir() else {
                    return (None, DirResolution::Direct);
                };
                let conduit = |base: &Path| {
                    base.join("AppData").join("Roaming").join(leaf)
                };
                if !msix::has_package_identity() {
                    return (Some(conduit(&home)), DirResolution::Direct);
                }
                match msix::unc_twin(&home) {
                    // The profile dir always exists, so a metadata success proves the
                    // UNC view actually works before we commit every file to it.
                    Some(unc_home) if std::fs::metadata(&unc_home).is_ok() => {
                        (Some(conduit(&unc_home)), DirResolution::Devirtualized)
                    }
                    _ => (Some(conduit(&home)), DirResolution::VirtualizedFallback),
                }
            }
            #[cfg(not(windows))]
            {
                (
                    dirs::config_dir().map(|d| d.join(leaf)),
                    DirResolution::Direct,
                )
            }
        })
        .clone()
}

/// MSIX app-container detection and escape hatch (see [`conduit_dir`]).
#[cfg(windows)]
mod msix {
    use std::path::{Path, PathBuf};

    /// True when this process runs with MSIX package identity, i.e. it was
    /// spawned inside a packaged app's container (child processes inherit the
    /// container). Conduit's own binaries are never packaged, so identity here
    /// always means "inside ANOTHER app's container" - exactly the situation
    /// where `AppData\Roaming` opens get redirected to that package's shadow.
    pub fn has_package_identity() -> bool {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentPackageFamilyName(length: *mut u32, family_name: *mut u16) -> i32;
        }
        // Per appmodel.h: "The process has no package identity."
        const APPMODEL_ERROR_NO_PACKAGE: i32 = 15700;
        let mut len: u32 = 0;
        let rc = unsafe { GetCurrentPackageFamilyName(&mut len, std::ptr::null_mut()) };
        rc != APPMODEL_ERROR_NO_PACKAGE
    }

    /// The loopback-UNC twin of a local drive path: `C:\Users\x` becomes
    /// `\\localhost\C$\Users\x`. SMB requests are served from the real
    /// filesystem, outside the MSIX virtualization filter, so from inside a
    /// container this reaches the REAL directory. `None` for paths without a
    /// drive root (already UNC, relative); callers then stay on the natural path.
    pub fn unc_twin(p: &Path) -> Option<PathBuf> {
        let s = p.to_str()?;
        let b = s.as_bytes();
        if b.len() < 3
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || (b[2] != b'\\' && b[2] != b'/')
        {
            return None;
        }
        Some(PathBuf::from(format!(
            r"\\localhost\{}$\{}",
            b[0].to_ascii_uppercase() as char,
            &s[3..]
        )))
    }
}

/// Default path: `<conduit dir>/registry.json`.
pub fn registry_path() -> Option<PathBuf> {
    Some(conduit_dir()?.join("registry.json"))
}

const RECOVERY_NOTICE_FILE: &str = "registry-recovery.json";

/// Written when `load_from` recovers from `registry.json.bak` so the app can
/// surface a one-time notice. Consumed by [`take_recovery_notice`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RegistryRecoveryNotice {
    pub recovered_at_ms: u128,
    /// `"missing"` when the primary was absent; `"corrupt"` when it was unreadable.
    pub reason: String,
    pub quarantine_path: Option<String>,
}

fn recovery_notice_path() -> Option<PathBuf> {
    Some(conduit_dir()?.join(RECOVERY_NOTICE_FILE))
}

fn record_registry_recovery(reason: &str, quarantine: Option<PathBuf>) {
    let Some(path) = recovery_notice_path() else {
        return;
    };
    let recovered_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let notice = RegistryRecoveryNotice {
        recovered_at_ms,
        reason: reason.to_string(),
        quarantine_path: quarantine.as_ref().map(|p| p.to_string_lossy().into_owned()),
    };
    if let Ok(json) = serde_json::to_string_pretty(&notice) {
        let _ = atomic_write(&path, &json);
    }
    eprintln!(
        "toolport: recovered registry from backup ({reason}){}",
        quarantine
            .as_ref()
            .map(|p| format!("; quarantined copy at {}", p.display()))
            .unwrap_or_default()
    );
}

/// Read and delete the pending recovery notice (at most once per recovery).
pub fn take_recovery_notice() -> Option<RegistryRecoveryNotice> {
    let path = recovery_notice_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    serde_json::from_str(&raw).ok()
}

/// The always-on gateway log (connection lifecycle: starts, connect successes
/// and failures). Shared by the gateway (writer) and the diagnostics command
/// (reader) so the path can't drift between them.
pub fn gateway_log_path() -> Option<PathBuf> {
    Some(conduit_dir()?.join("gateway.log"))
}

/// Sibling `<registry>.bak` path holding the last-known-good registry.
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".bak");
    PathBuf::from(name)
}

/// How many rolling backup generations `save_to` keeps beyond the single `.bak`.
/// The registry is a few KB, so 5 generations is negligible on disk but means
/// recovery has several recent snapshots to fall back to, not one file that (as
/// in the 2026-07-07 incident) may itself be stale.
const BACKUP_GENERATIONS: usize = 5;

/// The rolling journal generations written by `save_to`, named
/// `<registry>.bak.<ts-millis>`. Timestamps are fixed-width for any realistic
/// epoch, so name order is age order; returned oldest-first. Excludes the single
/// `<registry>.bak` (no trailing timestamp) and the `.unreadable-*` quarantine
/// files, which use a different prefix.
fn backup_generations(path: &Path) -> Vec<PathBuf> {
    let (Some(dir), Some(base)) = (path.parent(), path.file_name().and_then(|f| f.to_str()))
    else {
        return Vec::new();
    };
    let prefix = format!("{base}.bak.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut gens: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.starts_with(&prefix))
        })
        .collect();
    gens.sort();
    gens
}

/// Append the current good registry to the rolling journal and prune to the
/// newest `BACKUP_GENERATIONS`. Best-effort: a failure here never fails a save -
/// the primary write and the single `.bak` remain the durability guarantees, and
/// this only adds recovery depth on top of them.
fn write_backup_generation(path: &Path, content: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".bak.{ts}"));
    if atomic_write(&PathBuf::from(name), content).is_err() {
        return;
    }
    let mut gens = backup_generations(path);
    while gens.len() > BACKUP_GENERATIONS {
        let _ = std::fs::remove_file(gens.remove(0));
    }
}

/// Recover the registry from the backups `save_to` maintains, newest-first: the
/// single `.bak` (the last-known-good fast path), then the rolling journal
/// generations from newest to oldest. Returns the first that parses (and
/// best-effort rewrites the primary from it so a later read self-heals), or None
/// when nothing usable remains. Walking the journal means one stale or corrupt
/// `.bak` no longer strands recovery when fresher snapshots exist.
fn restore_from_backup(path: &Path) -> Option<Registry> {
    let mut candidates = vec![backup_path(path)];
    let mut gens = backup_generations(path);
    gens.reverse(); // newest generation first
    candidates.extend(gens);

    for candidate in candidates {
        let Ok(content) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        if let Ok(registry) = serde_json::from_str::<Registry>(&content) {
            // Best-effort: restore the primary so we don't keep reading a backup.
            // Recovery still succeeds if this write fails.
            let _ = atomic_write(path, &content);
            return Some(registry);
        }
    }
    None
}

/// What a (retried) read of the registry file actually found.
enum ReadOutcome {
    Content(String),
    /// Still missing or empty after retries: genuinely absent, not a race.
    Absent,
}

/// Read the registry tolerating the transient states a concurrent `atomic_write`
/// (or an SMB view of one - packaged gateways reach this file over the
/// `\\localhost\C$` twin, where rename windows are wider) can expose: a brief
/// not-found, empty, or sharing-violation moment during the rename. A reader
/// that mistakes that moment for "the registry is gone" used to fall into
/// `restore_from_backup`, which REWRITES the primary from a possibly-days-old
/// .bak - the exact mechanism that destroyed a real user registry (manual
/// servers added over three days lost to a self-heal from a stale backup).
/// Retrying a few times before concluding anything makes that race unloseable.
fn read_registry_file(path: &Path) -> ReadOutcome {
    const ATTEMPTS: u32 = 4;
    const BACKOFF_MS: u64 = 75;
    for attempt in 0..ATTEMPTS {
        match std::fs::read_to_string(path) {
            Ok(content) if !content.trim().is_empty() => return ReadOutcome::Content(content),
            // Empty, missing, locked (sharing violation), or any other error:
            // all indistinguishable from a rename in flight. Wait and re-look.
            _ => {}
        }
        if attempt + 1 < ATTEMPTS {
            std::thread::sleep(std::time::Duration::from_millis(BACKOFF_MS));
        }
    }
    ReadOutcome::Absent
}

/// Preserve an unreadable registry file next to the original before anything
/// overwrites it. "Unreadable" does NOT always mean corrupt: on a machine
/// running mixed builds it can be a NEWER schema this binary can't parse, and
/// destroying it silently loses whatever the newer build stored. Best-effort;
/// keeps the most recent few so a repeating failure can't fill the disk.
/// Returns the quarantine file path when a copy was written.
fn quarantine_unreadable(path: &Path, content: &str) -> Option<PathBuf> {
    const KEEP: usize = 3;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".unreadable-{ts}"));
    let dest = PathBuf::from(name);
    atomic_write(&dest, content).ok()?;
    // Prune older quarantine files beyond the newest KEEP.
    let (Some(dir), Some(base)) = (path.parent(), path.file_name().and_then(|f| f.to_str()))
    else {
        return None;
    };
    let prefix = format!("{base}.unreadable-");
    let Ok(entries) = std::fs::read_dir(dir) else { return None };
    let mut quarantined: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.starts_with(&prefix))
        })
        .collect();
    // Timestamps are fixed-width for any realistic epoch, so name order = age order.
    quarantined.sort();
    while quarantined.len() > KEEP {
        let _ = std::fs::remove_file(quarantined.remove(0));
    }
    Some(dest)
}

pub fn load_from(path: &Path) -> Result<Registry, String> {
    match read_registry_file(path) {
        // Genuinely missing or empty (not a rename race - read_registry_file
        // already waited that out): recover the last-known-good from the .bak
        // sibling if one survived, else this is a first run.
        ReadOutcome::Absent => {
            if let Some(reg) = restore_from_backup(path) {
                record_registry_recovery("missing", None);
                Ok(reg)
            } else {
                Ok(Registry::default())
            }
        }
        ReadOutcome::Content(content) => match serde_json::from_str(&content) {
            Ok(reg) => Ok(reg),
            // Present but unparseable by THIS build: corrupt, or a newer schema.
            // Quarantine the evidence BEFORE restore_from_backup self-heals the
            // primary from .bak, so nothing is ever silently destroyed.
            Err(e) => {
                let quarantine = quarantine_unreadable(path, &content);
                match restore_from_backup(path) {
                    Some(reg) => {
                        record_registry_recovery("corrupt", quarantine);
                        Ok(reg)
                    }
                    None => Err(format!("Corrupt registry: {e}")),
                }
            }
        },
    }
}

pub fn save_to(path: &Path, registry: &Registry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
    let existing = std::fs::read_to_string(path).ok();
    // No-op guard: if the on-disk registry is already semantically identical to what we
    // would write, skip the whole save so we never bump the file's mtime. This is NOT just
    // an IO optimization. The gateway watches this file's mtime and, on ANY change, does a
    // full rebuild that re-spawns every stdio MCP server. The team sync loop calls save()
    // every ~25s even on a no-op (304) pull, so without this guard each cycle bumped the
    // mtime and made every gateway respawn every server; the orphaned npx/node children
    // piled up until the machine ran out of RAM. Compare as PARSED JSON, not raw bytes, so
    // HashMap key-order jitter across a load->save round-trip can't masquerade as a change.
    if let Some(cur) = existing.as_deref() {
        if let Ok(cur_val) = serde_json::from_str::<serde_json::Value>(cur) {
            if serde_json::to_value(registry).map(|v| v == cur_val).unwrap_or(false) {
                return Ok(());
            }
        }
    }
    // Snapshot the current on-disk registry to a `.bak` sibling before overwriting,
    // but only if it still parses, so a bad write or an accidental deletion of
    // registry.json has a last-known-good to recover from (see load_from). An
    // existing file that does NOT parse is quarantined instead of silently
    // overwritten: on a mixed-version machine it may be a newer build's registry,
    // and this save (from an older binary) must not be the thing that destroys it.
    if let Some(existing) = existing {
        if !existing.trim().is_empty() {
            if serde_json::from_str::<Registry>(&existing).is_ok() {
                // Single last-known-good (compat + the load_from fast path)...
                let _ = atomic_write(&backup_path(path), &existing);
                // ...plus a rolling journal generation, so recovery can fall back
                // to the immediately-previous state and a few before it, not just
                // whatever the one .bak happens to hold.
                write_backup_generation(path, &existing);
            } else {
                quarantine_unreadable(path, &existing);
            }
        }
    }
    // The registry is the single source of truth for every server, so a crash,
    // power loss, or full disk mid-write must not be able to truncate it.
    atomic_write(path, &json)
}

pub fn load() -> Result<Registry, String> {
    load_resolved()
}

pub fn save(registry: &Registry) -> Result<(), String> {
    let path = resolved_path().ok_or("Could not resolve registry path")?;
    save_to(&path, registry)
}

/// A held cross-process exclusive lock over the registry, released on drop (and by the OS
/// if the holding process exits). Serializes the registry read-modify-write section across
/// the desktop app, the gateway binary, and the team-sync worker, so no writer's save can
/// revert another process's concurrent change (SOU-23). Advisory: it only excludes other
/// holders of THIS lock, which every registry writer takes via `update` / `update_at`.
pub struct RegistryLock(std::fs::File);

impl Drop for RegistryLock {
    fn drop(&mut self) {
        // Also released when the File closes / the process exits; explicit for clarity.
        let _ = self.0.unlock();
    }
}

/// The sibling lock file for the registry at `path` (`<registry>.lock`). A dedicated file,
/// not registry.json itself, so locking never races the atomic temp+rename that swaps the
/// registry inode on every save.
fn lock_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".lock");
    PathBuf::from(s)
}

/// Acquire the exclusive registry lock, retrying briefly under contention. Registry writes
/// are sub-millisecond, so a real conflict clears at once; a holder stuck past the deadline
/// surfaces as an error rather than hanging the caller indefinitely.
fn lock_for(path: &Path) -> Result<RegistryLock, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path(path))
        .map_err(|e| format!("Could not open the registry lock: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(RegistryLock(file)),
            // Contended. The error KIND for "already locked" differs by platform (`WouldBlock`
            // on Unix, a lock-violation OS error on Windows), so do NOT gate the retry on it:
            // the lock file already opened above, so any try-lock failure here is contention.
            // Retry briefly, then surface it rather than hang the caller indefinitely.
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "The registry is locked by another Toolport process ({e}); try again."
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Load-modify-save the resolved registry while holding the cross-process lock, so the
/// write reflects (and can't clobber) any change another process made since this one last
/// read. `f` mutates a FRESH on-disk copy; the persisted registry and `f`'s value are
/// returned. Every registry writer (app commands, the gateway toggle, team sync) goes
/// through this or [`update_at`] — that is what makes the lock effective.
pub fn update<T>(f: impl FnOnce(&mut Registry) -> Result<T, String>) -> Result<(Registry, T), String> {
    let path = resolved_path().ok_or("Could not resolve registry path")?;
    let _lock = lock_for(&path)?;
    let mut reg = load()?;
    let out = f(&mut reg)?;
    save(&reg)?;
    Ok((reg, out))
}

/// Acquire the cross-process registry lock for an explicit path, for a caller that runs its
/// own load-modify-save (the gateway's agent toggle, which interleaves audit + early
/// returns) rather than using [`update_at`]. Hold the returned guard across the entire
/// read-decide-write.
pub fn lock_at(path: &Path) -> Result<RegistryLock, String> {
    lock_for(path)
}

/// Like [`update`] but for a caller that already resolved an explicit path (the gateway
/// binary), locking the same sibling lock file so it serializes with the app's `update`.
pub fn update_at<T>(
    path: &Path,
    f: impl FnOnce(&mut Registry) -> Result<T, String>,
) -> Result<(Registry, T), String> {
    let _lock = lock_for(path)?;
    let mut reg = load_from(path)?;
    let out = f(&mut reg)?;
    save_to(path, &reg)?;
    Ok((reg, out))
}

/// The path the registry actually resolves to, honoring `CONDUIT_REGISTRY`.
pub fn resolved_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CONDUIT_REGISTRY") {
        return Some(PathBuf::from(path));
    }
    registry_path()
}

/// Load honoring the `CONDUIT_REGISTRY` env override (used by the gateway and
/// tests), falling back to the default path.
pub fn load_resolved() -> Result<Registry, String> {
    match resolved_path() {
        Some(path) => load_from(&path),
        None => Ok(Registry::default()),
    }
}

/// True when a command argument looks like it carries a secret: an inline
/// credential param (password=, token=, ...) or a connection URI with embedded
/// userinfo (scheme://user:pass@host). Used to redact args before sharing, since
/// some servers (e.g. Postgres) take a connection string with a password in args.
/// Biased toward over-redacting: for a share, a false positive is harmless.
pub(crate) fn arg_looks_secret(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    const NEEDLES: [&str; 8] = [
        "password=", "pwd=", "token=", "apikey=", "api_key=", "secret=", "accountkey=",
        "access_key",
    ];
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        return true;
    }
    // A connection URI with embedded userinfo: scheme://user:pass@host/...
    if let Some((_, rest)) = arg.split_once("://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.contains('@') {
            return true;
        }
    }
    false
}

/// Redact credentials embedded in a URL's authority: `scheme://user:pass@host/x`
/// (or `scheme://token@host/x`) becomes `scheme://<redacted>@host/x`. A URL is a
/// legitimate place for a secret (HTTP basic, token-as-username), so it must be
/// stripped anywhere a setup leaves the machine - env/arg redaction alone misses the
/// `url` field. Returns the input unchanged when there is no userinfo. Best-effort
/// string surgery (no URL-crate dependency): only the span between `://` and the
/// first `/?#` is touched, and ANY `@` there is treated as a userinfo separator.
pub(crate) fn redact_url_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    match authority.rsplit_once('@') {
        Some((_userinfo, host)) => format!("{scheme}://<redacted>@{host}{tail}"),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server(name: &str) -> ServerEntry {
        ServerEntry {
            id: String::new(),
            name: name.to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".to_string()),
            args: vec!["-y".to_string(), format!("@scope/{name}")],
            env: vec![],
            url: None,
            source: Some("manual".to_string()),
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    #[test]
    fn default_has_one_active_profile() {
        let r = Registry::default();
        assert_eq!(r.profiles.len(), 1);
        assert_eq!(r.active_profile_id(), DEFAULT_PROFILE_ID);
        assert!(r.enabled_servers().is_empty());
    }

    #[test]
    fn update_at_loads_fresh_and_preserves_a_concurrent_write() {
        // The core SOU-23 property: because `update_at` load-modify-saves a FRESH on-disk
        // copy (under the cross-process lock), a write another process made to a DIFFERENT
        // field between this process's reads is preserved, not reverted. Uses an explicit
        // path (no CONDUIT_REGISTRY env), so it's independent of other tests.
        let dir = std::env::temp_dir().join(format!("conduit-sou23-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        save_to(&path, &Registry::default()).unwrap();

        // Simulate a concurrent external writer flipping `allow_agent_control` on disk.
        let mut disk = load_from(&path).unwrap();
        disk.allow_agent_control = true;
        save_to(&path, &disk).unwrap();

        // Our update touches a different field. Loading fresh must keep the concurrent change.
        let (out, ()) = update_at(&path, |r| {
            r.deny_destructive = true;
            Ok(())
        })
        .unwrap();
        assert!(out.deny_destructive, "our change applied");
        assert!(out.allow_agent_control, "the concurrent write was NOT reverted");

        let reloaded = load_from(&path).unwrap();
        assert!(reloaded.deny_destructive && reloaded.allow_agent_control);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn update_at_serializes_concurrent_writers_with_no_lost_updates() {
        // The definitive lock check: many threads each read-increment-write via update_at.
        // Because each increment is a load-modify-save under the exclusive lock, none are
        // lost, so the final count equals the total number of writes. Without the lock, the
        // interleaved read-modify-write would drop increments. This exercises the same file
        // lock used cross-process: each update_at opens its own handle and contends on it.
        let dir = std::env::temp_dir().join(format!("conduit-sou23-conc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.json");
        save_to(&path, &Registry::default()).unwrap(); // secrets_generation starts at 0

        const THREADS: u64 = 4;
        const PER: u64 = 30;
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..PER {
                        update_at(&p, |r| {
                            r.secrets_generation += 1;
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let final_reg = load_from(&path).unwrap();
        assert_eq!(
            final_reg.secrets_generation,
            THREADS * PER,
            "every increment persisted; the lock prevented lost updates"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn add_server_assigns_unique_slug_ids() {
        let mut r = Registry::default();
        let a = r.add_server(sample_server("File System"));
        let b = r.add_server(sample_server("File System"));
        assert_eq!(a, "file-system");
        assert_eq!(b, "file-system-2");
        assert_eq!(r.servers.len(), 2);
    }

    #[test]
    fn toggle_drives_active_profile_membership() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("github"));
        let profile = r.active_profile_id();
        assert!(!r.is_enabled(&profile, &id));
        r.set_server_enabled(&profile, &id, true).unwrap();
        assert!(r.is_enabled(&profile, &id));
        assert_eq!(r.enabled_servers().len(), 1);
        r.set_server_enabled(&profile, &id, false).unwrap();
        assert!(r.enabled_servers().is_empty());
    }

    #[test]
    fn profiles_isolate_enabled_sets() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("postgres"));
        let work = r.add_profile("Work");
        r.set_server_enabled("default", &id, true).unwrap();
        assert!(r.is_enabled("default", &id));
        assert!(!r.is_enabled(&work, &id));
        r.set_active_profile(&work).unwrap();
        assert!(r.enabled_servers().is_empty());
    }

    #[test]
    fn enabled_servers_for_scopes_by_profile_id_or_name() {
        let mut r = Registry::default();
        let db = r.add_server(sample_server("postgres"));
        let pay = r.add_server(sample_server("stripe"));
        let billing = r.add_profile("Billing");
        // default enables only postgres; Billing enables only stripe.
        r.set_server_enabled("default", &db, true).unwrap();
        r.set_server_enabled(&billing, &pay, true).unwrap();

        // Resolve by name (case-insensitive) and by id, independent of active.
        let by_name: Vec<_> = r.enabled_servers_for("billing").iter().map(|s| s.id.clone()).collect();
        assert_eq!(by_name, vec![pay.clone()]);
        let by_id: Vec<_> = r.enabled_servers_for("default").iter().map(|s| s.id.clone()).collect();
        assert_eq!(by_id, vec![db]);
        // A NAMED reference that matches no profile (deleted/renamed) fails CLOSED:
        // an empty set, NOT a silent widening to the active profile's servers.
        assert!(
            r.enabled_servers_for("nope").is_empty(),
            "unknown profile must fail closed, not fall back to active"
        );
    }

    #[test]
    fn profile_for_root_longest_prefix_wins_on_a_path_boundary() {
        let mut r = Registry::default();
        r.folder_profiles = vec![
            FolderProfile { path: "/home/me/work".into(), profile: "Work".into() },
            FolderProfile { path: "/home/me/work/client-a".into(), profile: "ClientA".into() },
            FolderProfile { path: "/home/me/personal".into(), profile: "Personal".into() },
        ];
        // Exact match, and a descendant picks the parent mapping.
        assert_eq!(r.profile_for_root("/home/me/work"), Some("Work".into()));
        assert_eq!(r.profile_for_root("/home/me/work/src"), Some("Work".into()));
        // A more specific nested mapping wins over its parent.
        assert_eq!(
            r.profile_for_root("/home/me/work/client-a/repo"),
            Some("ClientA".into())
        );
        assert_eq!(r.profile_for_root("/home/me/personal/notes"), Some("Personal".into()));
        // No mapping -> None (caller falls back to the configured profile).
        assert_eq!(r.profile_for_root("/tmp/other"), None);
        // Boundary: a sibling sharing a NAME prefix must not match ("work" vs "workspace").
        assert_eq!(r.profile_for_root("/home/me/workspace"), None);
        // Empty root never matches.
        assert_eq!(r.profile_for_root(""), None);
    }

    #[test]
    fn tool_scope_narrows_a_profile_to_specific_tools() {
        let mut r = Registry::default();
        let gh = r.add_server(sample_server("github"));
        let db = r.add_server(sample_server("postgres"));
        // Default-allow: no scope -> every tool exposed on every server.
        assert!(r.profile_allows_tool("default", &gh, "search"));
        assert!(r.profile_allows_tool("default", &db, "query"));

        // Narrow github to only `search`; postgres untouched.
        r.set_profile_server_tools("default", &gh, Some(vec!["search".into()]))
            .unwrap();
        assert!(r.profile_allows_tool("default", &gh, "search"));
        assert!(!r.profile_allows_tool("default", &gh, "create_issue")); // not allow-listed
        assert!(r.profile_allows_tool("default", &db, "query")); // no scope on db -> all allowed
        // Resolves by profile NAME too, like the other scope lookups.
        assert!(!r.profile_allows_tool("Default", &gh, "create_issue"));

        // Clearing restores all-allowed and leaves the map empty (backward compatible).
        r.set_profile_server_tools("default", &gh, None).unwrap();
        assert!(r.profile_allows_tool("default", &gh, "create_issue"));
        assert!(r.profiles[0].tool_scope.is_empty());
    }

    #[test]
    fn empty_allow_list_exposes_no_tools_distinct_from_clear() {
        let mut r = Registry::default();
        let gh = r.add_server(sample_server("github"));
        // Some(empty) = expose NO tools on this server (not the same as "all tools").
        r.set_profile_server_tools("default", &gh, Some(vec![])).unwrap();
        assert!(!r.profile_allows_tool("default", &gh, "search"));
        assert!(!r.profile_allows_tool("default", &gh, "anything"));
        assert!(r.profiles[0].tool_scope.contains_key(&gh));
        // None = clear the narrowing, back to all tools.
        r.set_profile_server_tools("default", &gh, None).unwrap();
        assert!(r.profile_allows_tool("default", &gh, "search"));
        assert!(r.profiles[0].tool_scope.is_empty());
    }

    #[test]
    fn removing_a_server_drops_its_tool_scope() {
        let mut r = Registry::default();
        let gh = r.add_server(sample_server("github"));
        r.set_profile_server_tools("default", &gh, Some(vec!["search".into()]))
            .unwrap();
        assert!(!r.profiles[0].tool_scope.is_empty());
        r.remove_server(&gh).unwrap();
        assert!(
            r.profiles[0].tool_scope.is_empty(),
            "tool_scope must not orphan a removed server"
        );
    }

    #[test]
    fn tool_scope_omitted_from_json_when_empty() {
        // Back-compat: a profile with no tool scope serializes without the field.
        let r = Registry::default();
        assert!(!serde_json::to_string(&r).unwrap().contains("toolScope"));
    }

    #[test]
    fn unknown_profile_ref_imposes_no_extra_tool_restriction() {
        // The server scope already fails an unknown profile closed; this must not add a
        // second, confusing block, so it is default-allow for an unresolved profile.
        let r = Registry::default();
        assert!(r.profile_allows_tool("nope", "github", "anything"));
    }

    #[test]
    fn set_folder_profiles_drops_blank_entries() {
        let mut r = Registry::default();
        r.set_folder_profiles(vec![
            FolderProfile { path: "/a".into(), profile: "P".into() },
            FolderProfile { path: "  ".into(), profile: "P".into() }, // blank path
            FolderProfile { path: "/b".into(), profile: " ".into() },  // blank profile
        ]);
        assert_eq!(r.folder_profiles.len(), 1);
        assert_eq!(r.folder_profiles[0].path, "/a");
    }

    #[test]
    fn profile_for_root_normalizes_separators_and_trailing_slash() {
        let mut r = Registry::default();
        r.folder_profiles =
            vec![FolderProfile { path: "/home/me/work/".into(), profile: "Work".into() }];
        // A trailing slash on the mapping and backslash separators in the root both normalize.
        assert_eq!(r.profile_for_root("/home/me/work"), Some("Work".into()));
        assert_eq!(r.profile_for_root(r"\home\me\work\sub"), Some("Work".into()));
    }

    #[test]
    fn folder_profiles_omitted_from_json_when_empty() {
        // Back-compat: a registry with no folder routing serializes without the field, so
        // existing registry.json files round-trip unchanged.
        let r = Registry::default();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("folderProfiles"));
    }

    #[test]
    fn unknown_profile_fails_closed_but_empty_ref_follows_active() {
        let mut r = Registry::default();
        let db = r.add_server(sample_server("postgres"));
        r.set_server_enabled("default", &db, true).unwrap();

        // A deleted/renamed profile a scoped client still references resolves to
        // nothing (fail closed), so the client can't inherit the active profile.
        assert!(r.enabled_servers_for("deleted-profile").is_empty());
        assert_eq!(r.resolve_profile_id("deleted-profile"), "deleted-profile");

        // An empty/whitespace ref is the *unscoped* case and still follows active.
        assert_eq!(r.resolve_profile_id(""), r.active_profile_id());
        assert_eq!(r.resolve_profile_id("   "), r.active_profile_id());
        assert_eq!(r.enabled_servers_for("").len(), 1);
    }

    #[test]
    fn client_scope_records_and_clears() {
        let mut r = Registry::default();
        r.set_client_scope("cursor", Some("Billing"));
        assert_eq!(r.client_scopes.get("cursor").map(String::as_str), Some("Billing"));
        // Whitespace-only / empty / None all clear the binding.
        r.set_client_scope("cursor", Some("  "));
        assert!(!r.client_scopes.contains_key("cursor"));
        r.set_client_scope("claude", Some("Work"));
        r.set_client_scope("claude", None);
        assert!(!r.client_scopes.contains_key("claude"));
    }

    #[test]
    fn client_discovery_records_normalizes_and_clears() {
        let mut r = Registry::default();
        assert_eq!(r.client_discovery_mode("cursor"), None);
        // Recorded case-insensitively / trimmed to a canonical lowercase mode.
        r.set_client_discovery("cursor", Some("  LAZY "));
        assert_eq!(r.client_discovery_mode("cursor"), Some("lazy"));
        r.set_client_discovery("cursor", Some("Grouped"));
        assert_eq!(r.client_discovery_mode("cursor"), Some("grouped"));
        // Unknown / empty / None all clear the override (client inherits the global mode).
        r.set_client_discovery("cursor", Some("nonsense"));
        assert_eq!(r.client_discovery_mode("cursor"), None);
        r.set_client_discovery("claude", Some("full"));
        r.set_client_discovery("claude", None);
        assert_eq!(r.client_discovery_mode("claude"), None);
        // Empty map is omitted from serialization (skip_serializing_if).
        assert!(r.client_discovery.is_empty());
    }

    #[test]
    fn explicit_unscoped_is_distinct_from_no_entry() {
        let mut r = Registry::default();
        // Explicit-unscoped is recorded as an empty-string entry, NOT a removal, so
        // the gateway can tell "follow the active profile now" (present, empty)
        // apart from "no recorded scope, fall back to boot env" (absent).
        r.set_client_unscoped("cursor");
        assert_eq!(r.client_scopes.get("cursor").map(String::as_str), Some(""));
        assert!(r.client_scopes.contains_key("cursor"));
        // Re-scoping to a named profile replaces the marker; uninstall clears it.
        r.set_client_scope("cursor", Some("Billing"));
        assert_eq!(r.client_scopes.get("cursor").map(String::as_str), Some("Billing"));
        r.set_client_scope("cursor", None);
        assert!(!r.client_scopes.contains_key("cursor"));
    }

    #[test]
    fn http_client_lookup_by_token_hash() {
        let mut r = Registry::default();
        let token = "tok_abc123";
        r.http_clients.push(HttpClient {
            id: "c1".into(),
            label: "Open WebUI".into(),
            token_sha256: sha256_hex(token),
            profile: "Billing".into(),
        });
        // The plaintext token resolves to its client; a wrong token doesn't.
        assert_eq!(r.http_client_for_token(token).map(|c| c.profile.as_str()), Some("Billing"));
        assert!(r.http_client_for_token("tok_wrong").is_none());
        // The hash is deterministic and not the plaintext.
        assert_eq!(sha256_hex(token), sha256_hex(token));
        assert_ne!(sha256_hex(token), token);
    }

    #[test]
    fn bridge_union_connects_every_clients_servers() {
        let mut r = Registry::default();
        let a = r.add_server(sample_server("alpha"));
        let b = r.add_server(sample_server("bravo"));
        let c = r.add_server(sample_server("charlie"));
        let billing = r.add_profile("Billing");
        let support = r.add_profile("Support");
        // default (active) enables alpha; Billing -> bravo; Support -> charlie.
        r.set_server_enabled("default", &a, true).unwrap();
        r.set_server_enabled(&billing, &b, true).unwrap();
        r.set_server_enabled(&support, &c, true).unwrap();
        // Base alone (no clients) connects only the active profile's server.
        assert_eq!(
            r.bridge_enabled_servers(None).iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            vec![a.clone()]
        );
        // Two clients scoped to Billing and Support -> the bridge connects the union.
        r.http_clients.push(HttpClient {
            id: "1".into(), label: "x".into(), token_sha256: "h1".into(), profile: "Billing".into(),
        });
        r.http_clients.push(HttpClient {
            id: "2".into(), label: "y".into(), token_sha256: "h2".into(), profile: "Support".into(),
        });
        let ids: Vec<_> = r.bridge_enabled_servers(None).iter().map(|s| s.id.clone()).collect();
        assert!(ids.contains(&a) && ids.contains(&b) && ids.contains(&c));
        assert_eq!(ids.len(), 3);
        // An unscoped (empty-profile) client adds nothing beyond the union.
        r.http_clients.push(HttpClient {
            id: "3".into(), label: "z".into(), token_sha256: "h3".into(), profile: String::new(),
        });
        assert_eq!(r.bridge_enabled_servers(None).len(), 3);
    }

    #[test]
    fn tool_disable_is_default_allow_and_idempotent() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("github"));
        // Unknown tools are enabled by default.
        assert!(r.is_tool_enabled(&id, "create_issue"));
        // Disable, then confirm; double-disable doesn't duplicate.
        r.set_tool_enabled(&id, "create_issue", false).unwrap();
        r.set_tool_enabled(&id, "create_issue", false).unwrap();
        assert!(!r.is_tool_enabled(&id, "create_issue"));
        let server = r.servers.iter().find(|s| s.id == id).unwrap();
        assert_eq!(server.disabled_tools, vec!["create_issue".to_string()]);
        // Re-enable removes it.
        r.set_tool_enabled(&id, "create_issue", true).unwrap();
        assert!(r.is_tool_enabled(&id, "create_issue"));
        assert!(r.servers.iter().find(|s| s.id == id).unwrap().disabled_tools.is_empty());
    }

    #[test]
    fn tool_pin_is_idempotent_and_prunes_empty() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("github"));
        // Default: nothing pinned.
        assert!(!r.is_tool_pinned(&id, "create_issue"));
        // Pin, then double-pin doesn't duplicate.
        r.set_tool_pinned(&id, "create_issue", true);
        r.set_tool_pinned(&id, "create_issue", true);
        assert!(r.is_tool_pinned(&id, "create_issue"));
        assert_eq!(r.pinned_tools.get(&id).map(Vec::len), Some(1));
        // A second pin adds to the same server's list.
        r.set_tool_pinned(&id, "list_issues", true);
        assert_eq!(r.pinned_tools.get(&id).map(Vec::len), Some(2));
        // Unpinning the last one prunes the server entry entirely.
        r.set_tool_pinned(&id, "create_issue", false);
        r.set_tool_pinned(&id, "list_issues", false);
        assert!(!r.is_tool_pinned(&id, "create_issue"));
        assert!(r.pinned_tools.get(&id).is_none());
    }

    #[test]
    fn deny_destructive_round_trips_through_disk() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("postgres"));
        r.set_tool_enabled(&id, "drop_table", false).unwrap();
        r.set_deny_destructive(true);

        let mut path = std::env::temp_dir();
        path.push(format!("conduit-policy-test-{}.json", std::process::id()));
        save_to(&path, &r).unwrap();
        let loaded = load_from(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(loaded.deny_destructive);
        assert!(!loaded.is_tool_enabled(&id, "drop_table"));
    }

    #[test]
    fn removing_server_cleans_profiles() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("linear"));
        r.set_server_enabled("default", &id, true).unwrap();
        r.remove_server(&id).unwrap();
        assert!(r.servers.is_empty());
        assert!(r.profiles[0].enabled_server_ids.is_empty());
    }

    #[test]
    fn cannot_remove_last_profile() {
        let mut r = Registry::default();
        assert!(r.remove_profile("default").is_err());
    }

    #[test]
    fn discovery_mode_setter_and_backcompat() {
        let mut r = Registry::default();
        // Absent by default (and every pre-existing registry).
        assert_eq!(r.discovery_mode, None);
        assert!(r.lazy_discovery);

        r.set_discovery_mode("grouped");
        assert_eq!(r.discovery_mode.as_deref(), Some("grouped"));
        // grouped doesn't touch the bool; lazy/full keep it in sync for old gateways.
        r.set_discovery_mode("full");
        assert_eq!(r.discovery_mode.as_deref(), Some("full"));
        assert!(!r.lazy_discovery);
        r.set_discovery_mode("lazy");
        assert_eq!(r.discovery_mode.as_deref(), Some("lazy"));
        assert!(r.lazy_discovery);
        // An unknown value clears the override (falls back to lazy_discovery).
        r.set_discovery_mode("nonsense");
        assert_eq!(r.discovery_mode, None);

        // Serde: None is skipped, so a default registry serializes exactly as before
        // (no new key), and that JSON - which lacks the field, like every old registry -
        // round-trips back to None.
        let json = serde_json::to_string(&Registry::default()).unwrap();
        assert!(!json.contains("discovery_mode"), "None must not be serialized");
        let back: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.discovery_mode, None);
    }

    #[test]
    fn round_trips_through_disk() {
        let mut r = Registry::default();
        let id = r.add_server(sample_server("vercel"));
        r.set_server_enabled("default", &id, true).unwrap();
        r.add_profile("Work");

        let mut path = std::env::temp_dir();
        path.push(format!("conduit-test-{}.json", std::process::id()));
        save_to(&path, &r).unwrap();
        let loaded = load_from(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.servers, r.servers);
        assert_eq!(loaded.profiles, r.profiles);
        assert_eq!(loaded.active_profile_id, r.active_profile_id);
    }

    #[test]
    fn load_and_save_resolved_honor_registry_override() {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();

        let mut path = std::env::temp_dir();
        path.push(format!("conduit-registry-override-{}.json", std::process::id()));
        let previous = std::env::var_os("CONDUIT_REGISTRY");
        struct RestoreEnv(Option<std::ffi::OsString>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("CONDUIT_REGISTRY", value),
                    None => std::env::remove_var("CONDUIT_REGISTRY"),
                }
            }
        }
        let _restore = RestoreEnv(previous);
        std::env::set_var("CONDUIT_REGISTRY", &path);

        let mut r = Registry::default();
        let id = r.add_server(sample_server("oauth"));
        r.set_server_enabled("default", &id, true).unwrap();
        save(&r).unwrap();

        let loaded = load().unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(loaded.servers, r.servers);
        assert_eq!(loaded.profiles, r.profiles);
        assert_eq!(loaded.active_profile_id, r.active_profile_id);
    }

    #[test]
    fn missing_file_yields_default() {
        let path = std::env::temp_dir().join("conduit-does-not-exist-xyz.json");
        let r = load_from(&path).unwrap();
        assert_eq!(r.profiles.len(), 1);
    }

    /// The MSIX escape hatch: a drive-rooted path maps to its `\\localhost\<D>$`
    /// admin-share twin; anything without a drive root is refused so callers
    /// stay on the natural path.
    #[cfg(windows)]
    #[test]
    fn unc_twin_maps_drive_paths_and_rejects_others() {
        assert_eq!(
            super::msix::unc_twin(Path::new(r"C:\Users\alice")).unwrap(),
            Path::new(r"\\localhost\C$\Users\alice")
        );
        // Lowercase drive letters normalize; forward slashes count as a root.
        assert_eq!(
            super::msix::unc_twin(Path::new("d:/stuff")).unwrap(),
            Path::new(r"\\localhost\D$\stuff")
        );
        assert!(super::msix::unc_twin(Path::new(r"\\server\share\home")).is_none());
        assert!(super::msix::unc_twin(Path::new(r"relative\path")).is_none());
        assert!(super::msix::unc_twin(Path::new("C:")).is_none());
    }

    /// `cargo test` never runs with package identity, so resolution must be
    /// Direct and the dir the natural home-derived path (not a UNC one).
    #[cfg(windows)]
    #[test]
    fn conduit_dir_is_direct_outside_a_container() {
        assert_eq!(conduit_dir_resolution(), DirResolution::Direct);
        let dir = conduit_dir().expect("home dir resolves");
        assert!(dir.ends_with(format!("AppData\\Roaming\\{}", data_dir_leaf_name())));
        assert!(!dir.to_string_lossy().starts_with(r"\\"));
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-aw-{}.json", std::process::id()));
        atomic_write(&path, "first").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first");
        // Overwrite replaces the contents in place.
        atomic_write(&path, "second").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
        // A successful write leaves no .conduit-tmp sibling behind.
        let prefix = format!("conduit-aw-{}.json.", std::process::id());
        let leftover = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().starts_with(&prefix));
        assert!(!leftover, "temp file left behind after a successful write");
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-perm-{}.json", std::process::id()));
        atomic_write(&path, "secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "atomic_write must produce an owner-only file");
        // Re-writing an existing file keeps it owner-only.
        atomic_write(&path, "secret2").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "overwrite must stay owner-only");
        std::fs::remove_file(&path).ok();
    }

    fn quarantine_files(path: &Path) -> Vec<PathBuf> {
        let dir = path.parent().unwrap();
        let prefix = format!("{}.unreadable-", path.file_name().unwrap().to_str().unwrap());
        let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|f| f.to_str())
                    .is_some_and(|f| f.starts_with(&prefix))
            })
            .collect();
        out.sort();
        out
    }

    fn cleanup_quarantine(path: &Path) {
        for q in quarantine_files(path) {
            std::fs::remove_file(q).ok();
        }
    }

    #[test]
    fn corrupt_primary_is_quarantined_before_selfheal() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-quar-{}.json", std::process::id()));
        let bak = backup_path(&path);
        cleanup_quarantine(&path);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();

        let mut reg = Registry::default();
        reg.add_server(sample_server("alpha"));
        save_to(&path, &reg).unwrap();
        // A second, DIFFERENT save snapshots the prior {alpha} state into .bak before
        // overwriting. (An identical re-save is now a no-op and writes no backup.)
        reg.add_server(sample_server("beta"));
        save_to(&path, &reg).unwrap();

        // A newer build (or corruption) leaves bytes this build can't parse. The
        // self-heal from .bak must PRESERVE those bytes, not destroy them - they
        // may be three days of a newer build's data (this happened for real).
        std::fs::write(&path, r#"{"servers": "future-shape"}"#).unwrap();
        let recovered = load_from(&path).unwrap();
        assert_eq!(recovered.servers.len(), 1, "self-healed from .bak");
        let q = quarantine_files(&path);
        assert_eq!(q.len(), 1, "unreadable primary must be quarantined");
        let kept = std::fs::read_to_string(&q[0]).unwrap();
        assert!(kept.contains("future-shape"), "quarantine holds the exact bytes");

        cleanup_quarantine(&path);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();
    }

    #[test]
    fn identical_save_is_a_noop_leaving_the_file_untouched() {
        // The gateway rebuilds (re-spawning every stdio MCP server) on any registry
        // mtime change, and the team sync loop save()s every cycle even when the pull was
        // a 304. A save whose content already matches disk must therefore be a complete
        // no-op: no rewrite, no mtime bump, no backup. Without this, each idle sync cycle
        // triggered every gateway to respawn every server, orphaning npx/node children
        // until the machine ran out of RAM.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-noop-{}.json", std::process::id()));
        let bak = backup_path(&path);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }

        let mut reg = Registry::default();
        reg.add_server(sample_server("alpha"));
        save_to(&path, &reg).unwrap();
        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Re-save the SAME registry (freshly re-serialized, exactly as the sync loop does
        // after a load): a complete no-op.
        std::thread::sleep(std::time::Duration::from_millis(15));
        save_to(&path, &reg).unwrap();
        let mtime2 = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime1, mtime2, "an identical save must not rewrite the file");
        assert!(!bak.exists(), "an identical save must not create a backup");
        assert!(
            backup_generations(&path).is_empty(),
            "an identical save must not add a journal generation"
        );

        // A genuine change still writes (and snapshots the prior state).
        reg.add_server(sample_server("beta"));
        save_to(&path, &reg).unwrap();
        assert!(bak.exists(), "a real change snapshots the prior state to .bak");
        assert_eq!(
            load_from(&path).unwrap().servers.len(),
            2,
            "a real change is persisted"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }
    }

    #[test]
    fn save_over_unparseable_existing_quarantines_instead_of_clobbering() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-savequar-{}.json", std::process::id()));
        let bak = backup_path(&path);
        cleanup_quarantine(&path);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();

        std::fs::write(&path, r#"{"servers": 42}"#).unwrap();
        save_to(&path, &Registry::default()).unwrap();
        assert!(!bak.exists(), "unparseable existing must never become the .bak");
        let q = quarantine_files(&path);
        assert_eq!(q.len(), 1, "the bytes we overwrote must survive in quarantine");
        assert!(std::fs::read_to_string(&q[0]).unwrap().contains("42"));

        cleanup_quarantine(&path);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unknown_top_level_fields_survive_a_round_trip() {
        // An OLDER binary loading and re-saving a NEWER build's registry must not
        // strip fields it doesn't understand (mixed versions share this file).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-fwd-{}.json", std::process::id()));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();

        let mut json = serde_json::to_value(Registry::default()).unwrap();
        json["someFutureFeature"] = serde_json::json!({ "enabled": true, "level": 3 });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let reg = load_from(&path).unwrap();
        save_to(&path, &reg).unwrap();
        let round: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            round["someFutureFeature"]["level"], 3,
            "unknown fields must round-trip, not be stripped"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
    }

    #[test]
    fn unknown_server_fields_survive_a_round_trip() {
        // Same forward-compat contract as the top-level test, at the per-SERVER
        // level: an older binary loading and re-saving a newer build's registry
        // must not strip a `ServerEntry` field it doesn't understand.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-srv-fwd-{}.json", std::process::id()));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();

        let mut reg = Registry::default();
        reg.servers.push(ServerEntry {
            id: "s1".into(),
            name: "s1".into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        // Inject a per-server field this binary's ServerEntry doesn't define.
        let mut json = serde_json::to_value(&reg).unwrap();
        json["servers"][0]["futureServerFlag"] = serde_json::json!({ "enabled": true });
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

        let loaded = load_from(&path).unwrap();
        save_to(&path, &loaded).unwrap();
        let round: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            round["servers"][0]["futureServerFlag"]["enabled"],
            true,
            "unknown per-server fields must round-trip, not be stripped"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
    }

    #[test]
    fn quarantine_prunes_to_the_newest_three() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-prune-{}.json", std::process::id()));
        cleanup_quarantine(&path);
        for i in 0..5 {
            quarantine_unreadable(&path, &format!("junk-{i}"));
            // Distinct millisecond timestamps so each call gets its own file.
            std::thread::sleep(std::time::Duration::from_millis(3));
        }
        let q = quarantine_files(&path);
        assert_eq!(q.len(), 3, "quarantine must stay bounded");
        let newest = std::fs::read_to_string(q.last().unwrap()).unwrap();
        assert_eq!(newest, "junk-4", "pruning removes the oldest, keeps the newest");
        cleanup_quarantine(&path);
    }

    #[test]
    fn save_keeps_backup_and_load_recovers_from_it() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-bak-{}.json", std::process::id()));
        let bak = backup_path(&path);
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();

        // First save: one server. No prior file, so nothing to snapshot yet.
        let mut reg = Registry::default();
        reg.add_server(sample_server("alpha"));
        save_to(&path, &reg).unwrap();
        assert!(!bak.exists(), "no backup on the first save");

        // Second save snapshots the one-server registry into .bak before overwriting
        // it with an empty one.
        save_to(&path, &Registry::default()).unwrap();
        assert_eq!(
            load_from(&bak).unwrap().servers.len(),
            1,
            ".bak holds the pre-overwrite registry"
        );

        // A corrupt primary recovers its server list from the backup.
        std::fs::write(&path, "{ not valid json").unwrap();
        assert_eq!(
            load_from(&path).unwrap().servers.len(),
            1,
            "recovered from .bak when the primary is corrupt"
        );

        // A missing primary also recovers from the backup.
        std::fs::remove_file(&path).ok();
        assert_eq!(
            load_from(&path).unwrap().servers.len(),
            1,
            "recovered from .bak when the primary is missing"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&bak).ok();
    }

    #[test]
    fn save_journal_prunes_to_the_generation_cap() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-journal-{}.json", std::process::id()));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }

        // The first save has no prior file to snapshot; every save after that
        // writes one generation. Well past the cap, the journal must stay bounded
        // to the newest BACKUP_GENERATIONS.
        let mut reg = Registry::default();
        for i in 0..(BACKUP_GENERATIONS + 3) {
            reg.add_server(sample_server(&format!("s{i}")));
            save_to(&path, &reg).unwrap();
            // Distinct millisecond timestamps so each generation gets its own file.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let gens = backup_generations(&path);
        assert_eq!(
            gens.len(),
            BACKUP_GENERATIONS,
            "journal must be pruned to the newest {BACKUP_GENERATIONS} generations"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }
    }

    #[test]
    fn recovery_uses_the_journal_when_bak_is_gone() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("conduit-reg-recover-journal-{}.json", std::process::id()));
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }

        // Six saves: the last on-disk state has 6 servers; the immediately-previous
        // state (in .bak and the newest journal generation) has 5.
        let mut reg = Registry::default();
        for i in 0..6 {
            reg.add_server(sample_server(&format!("s{i}")));
            save_to(&path, &reg).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        // Corrupt the primary AND remove the single .bak, so recovery has only the
        // rolling journal to fall back to. This is the acceptance case: recover the
        // immediately-previous state, not a stale one.
        std::fs::write(&path, "{ not json").unwrap();
        std::fs::remove_file(backup_path(&path)).ok();

        let recovered = load_from(&path).unwrap();
        assert_eq!(
            recovered.servers.len(),
            5,
            "recovered the immediately-previous state from the journal"
        );

        std::fs::remove_file(&path).ok();
        std::fs::remove_file(backup_path(&path)).ok();
        for g in backup_generations(&path) {
            std::fs::remove_file(g).ok();
        }
    }

    #[test]
    fn data_dir_leaf_is_dev_in_debug_builds() {
        assert_eq!(
            data_dir_leaf_name(),
            if cfg!(debug_assertions) {
                "Conduit-dev"
            } else {
                "Conduit"
            }
        );
    }
}
