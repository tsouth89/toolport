//! Conduit's own source-of-truth registry.
//!
//! This is independent of any client. It holds the full set of MCP servers the
//! user has in Conduit, plus profiles. A profile is a named set of *enabled*
//! servers (e.g. "Personal", "Work"); toggling a server on/off is just editing
//! the active profile. The gateway exposes whatever the active profile enables.
//!
//! Secrets are never stored here. Env vars marked `secret` keep their value in
//! the OS keychain; this file only records that a secret exists.

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
    /// Lazy discovery: the gateway exposes 3 meta-tools (status/search/call)
    /// instead of every downstream tool, so clients with tool-count limits don't
    /// drop tools. The gateway reads this from the registry file it already
    /// loads, so it applies to EVERY client regardless of whether the client
    /// passes the `CONDUIT_DISCOVERY` env var (an explicit env still overrides).
    /// Defaults on, since clients commonly cap the tool list.
    #[serde(default = "default_true")]
    pub lazy_discovery: bool,
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
            lazy_discovery: true,
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

    /// Set the global destructive-tool deny switch.
    pub fn set_deny_destructive(&mut self, deny: bool) {
        self.deny_destructive = deny;
    }

    /// Set lazy discovery mode (gateway exposes meta-tools vs the full catalog).
    pub fn set_lazy_discovery(&mut self, lazy: bool) {
        self.lazy_discovery = lazy;
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

pub fn load_from(path: &Path) -> Result<Registry, String> {
    if !path.exists() {
        return Ok(Registry::default());
    }
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    if content.trim().is_empty() {
        return Ok(Registry::default());
    }
    serde_json::from_str(&content).map_err(|e| format!("Corrupt registry: {e}"))
}

pub fn save_to(path: &Path, registry: &Registry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
    // The registry is the single source of truth for every server, so a crash,
    // power loss, or full disk mid-write must not be able to truncate it.
    atomic_write(path, &json)
}

pub fn load() -> Result<Registry, String> {
    let path = registry_path().ok_or("Could not resolve registry path")?;
    load_from(&path)
}

pub fn save(registry: &Registry) -> Result<(), String> {
    let path = registry_path().ok_or("Could not resolve registry path")?;
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
}
