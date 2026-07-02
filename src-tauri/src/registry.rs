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
    std::fs::write(&tmp, contents).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Where this entry came from, e.g. "imported:cursor" or "manual".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Original (downstream) tool names the user has switched off. The gateway
    /// hides these from `tools/list` and rejects calls to them. Default-allow:
    /// an empty list means every tool the server advertises is exposed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_tools: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled_server_ids: Vec<String>,
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
    /// Quarantine-on-drift: when true, a high-risk tool (poisoned definition, or a
    /// destructive tool whose definition changed/appeared) that drifts from its pinned
    /// baseline is hidden and blocked from every client until the user re-approves it.
    /// Opt-in, since blocking a tool is more disruptive than just flagging the drift.
    #[serde(default)]
    pub quarantine_on_drift: bool,
    /// Lazy discovery: the gateway exposes a few meta-tools (status/search/call/fetch)
    /// instead of every downstream tool, so clients with tool-count limits don't
    /// drop tools. The gateway reads this from the registry file it already
    /// loads, so it applies to EVERY client regardless of whether the client
    /// passes the `CONDUIT_DISCOVERY` env var (an explicit env still overrides).
    /// Defaults on, since clients commonly cap the tool list.
    #[serde(default = "default_true")]
    pub lazy_discovery: bool,
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
    /// Consumers registered to reach the gateway over the HTTP/OpenAPI bridge,
    /// each with its own hashed bearer token and scope. Empty = the bridge uses
    /// only the legacy single `CONDUIT_HTTP_TOKEN` (back-compat).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<HttpClient>,
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
            }],
            active_profile_id: Some(DEFAULT_PROFILE_ID.to_string()),
            deny_destructive: false,
            confirm_destructive: false,
            human_approval: false,
            quarantine_on_drift: false,
            lazy_discovery: true,
            allow_agent_control: false,
            integrity_check: true,
            content_defense: true,
            live_inspect: false,
            semantic_search: SemanticSettings::default(),
            team: None,
            result_budgets: HashMap::new(),
            client_scopes: HashMap::new(),
            http_clients: Vec::new(),
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

fn unique_id(base: &str, existing: &[String]) -> String {
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

    /// Set lazy discovery mode (gateway exposes meta-tools vs the full catalog).
    pub fn set_lazy_discovery(&mut self, lazy: bool) {
        self.lazy_discovery = lazy;
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
    /// Falls back to the active profile when the reference doesn't match.
    pub fn resolve_profile_id(&self, profile_ref: &str) -> String {
        self.profiles
            .iter()
            .find(|p| p.id == profile_ref || p.name.eq_ignore_ascii_case(profile_ref))
            .map(|p| p.id.clone())
            .unwrap_or_else(|| self.active_profile_id())
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

    /// Find the registered HTTP client whose stored hash matches `token`'s
    /// SHA-256, if any. The bridge uses this to resolve a bearer to its scope.
    pub fn http_client_for_token(&self, token: &str) -> Option<&HttpClient> {
        let h = sha256_hex(token);
        self.http_clients.iter().find(|c| c.token_sha256 == h)
    }
}

/// Conduit's data dir, anchored so every process agrees regardless of launch
/// context.
///
/// On Windows, MSIX-packaged apps (e.g. Claude Desktop) have their Roaming
/// AppData known-folder redirected into the package's `LocalCache`, while normal
/// apps (Cursor) see the real `%APPDATA%`. A gateway spawned by each would then
/// read a *different* `registry.json` and silently desync. The user-profile dir
/// is NOT redirected by MSIX, so deriving the path from it keeps packaged and
/// unpackaged processes on the same file. Elsewhere the platform config dir is
/// correct and not virtualized.
///
/// Public so every Conduit file (registry, tool cache, audit log, debug logs)
/// derives from the same anchor - otherwise the app and a client-spawned gateway
/// would write to different dirs under MSIX virtualization.
pub fn conduit_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        Some(
            dirs::home_dir()?
                .join("AppData")
                .join("Roaming")
                .join("Conduit"),
        )
    }
    #[cfg(not(windows))]
    {
        Some(dirs::config_dir()?.join("Conduit"))
    }
}

/// Default path: `<conduit dir>/registry.json`.
pub fn registry_path() -> Option<PathBuf> {
    Some(conduit_dir()?.join("registry.json"))
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

/// Recover the registry from the `.bak` sibling that `save_to` maintains. Returns
/// the parsed backup (and best-effort rewrites the primary from it so a later read
/// self-heals), or None when there's no usable backup.
fn restore_from_backup(path: &Path) -> Option<Registry> {
    let content = std::fs::read_to_string(backup_path(path)).ok()?;
    if content.trim().is_empty() {
        return None;
    }
    let registry: Registry = serde_json::from_str(&content).ok()?;
    // Best-effort: restore the primary so we don't keep reading the .bak. Recovery
    // still succeeds if this write fails.
    let _ = atomic_write(path, &content);
    Some(registry)
}

pub fn load_from(path: &Path) -> Result<Registry, String> {
    if !path.exists() {
        // registry.json is gone; recover the last-known-good from the .bak sibling
        // if one survived (e.g. the primary was deleted but the backup intact).
        return Ok(restore_from_backup(path).unwrap_or_default());
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    if content.trim().is_empty() {
        return Ok(restore_from_backup(path).unwrap_or_default());
    }
    match serde_json::from_str(&content) {
        Ok(reg) => Ok(reg),
        // Corrupt registry.json: recover from the backup before surfacing the
        // error, so a bad file doesn't wipe the user's server list.
        Err(e) => restore_from_backup(path).ok_or_else(|| format!("Corrupt registry: {e}")),
    }
}

pub fn save_to(path: &Path, registry: &Registry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // Snapshot the current on-disk registry to a `.bak` sibling before overwriting,
    // but only if it still parses, so a bad write or an accidental deletion of
    // registry.json has a last-known-good to recover from (see load_from).
    if let Ok(existing) = std::fs::read_to_string(path) {
        if !existing.trim().is_empty() && serde_json::from_str::<Registry>(&existing).is_ok() {
            let _ = atomic_write(&backup_path(path), &existing);
        }
    }
    let json = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
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
        // Unknown reference falls back to the active profile (default).
        assert_eq!(r.enabled_servers_for("nope").len(), 1);
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
}
