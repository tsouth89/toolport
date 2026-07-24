//! Tauri desktop shell: tray, webview IPC commands, approval broker, HTTP bridge.

use std::io::ErrorKind;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Listener, Manager, State};
use tauri_plugin_notification::NotificationExt;
use sha2::{Digest, Sha256};

use crate::approval_broker;
use crate::approval;
use crate::audit;
use crate::catalog;
use crate::clients;
use crate::downstream::{resolve_root_token, DownstreamServer, StdioTransport};
use crate::inspect;
use crate::integrity;
use crate::oauth;
use crate::registry::{
    self, arg_looks_secret, redact_url_userinfo, FolderProfile, Profile, Registry, ServerEntry,
};
use crate::remote;
use crate::router;
use crate::savings;
use crate::searchtrace;
use crate::secrets;
use crate::stacks;
use crate::teams;
use crate::usage_report;
use crate::vendors;

type RegistryState = Mutex<Registry>;

const OAUTH_LOCK_LEASE_SECS: u64 = 180;
const OAUTH_LOCK_WAIT_SECS: u64 = 30;
const OAUTH_LOCK_POLL_MS: u64 = 250;

struct OAuthFlowLock {
    path: std::path::PathBuf,
    attempt_id: String,
}

impl Drop for OAuthFlowLock {
    fn drop(&mut self) {
        let completion = oauth_completion_path(&self.path, &self.attempt_id);
        let _ = std::fs::write(
            completion,
            format!("done={} pid={}
", now_unix_secs(), std::process::id()),
        );
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Clone)]
struct OAuthLockSnapshot {
    modified: SystemTime,
    content: String,
    attempt_id: Option<String>,
}

impl OAuthLockSnapshot {
    fn instance_key(&self) -> String {
        let modified = self
            .modified
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{modified}:{}", self.content)
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn oauth_attempt_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

fn oauth_completion_path(path: &std::path::Path, attempt_id: &str) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("oauth.lock");
    path.with_file_name(format!("{name}.{attempt_id}.done"))
}

fn oauth_lock_contents(attempt_id: &str) -> String {
    format!(
        "attempt_id={attempt_id}
pid={}
started={}
lease_secs={}
",
        std::process::id(),
        now_unix_secs(),
        OAUTH_LOCK_LEASE_SECS
    )
}

fn parse_lock_attempt_id(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("attempt_id=").or_else(|| line.strip_prefix("nonce=")).map(ToOwned::to_owned))
}

fn read_oauth_lock_snapshot(path: &std::path::Path) -> Result<Option<OAuthLockSnapshot>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not stat oauth lock file: {e}")),
    };
    let modified = meta
        .modified()
        .map_err(|e| format!("could not read oauth lock timestamp: {e}"))?;
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read oauth lock file: {e}"))?;
    let attempt_id = parse_lock_attempt_id(&content);
    Ok(Some(OAuthLockSnapshot {
        modified,
        content,
        attempt_id,
    }))
}

fn lock_snapshot_is_expired(snapshot: &OAuthLockSnapshot) -> bool {
    let Ok(elapsed) = snapshot.modified.elapsed() else {
        return false;
    };
    elapsed.as_secs() >= OAUTH_LOCK_LEASE_SECS
}

fn completion_exists(path: &std::path::Path, attempt_id: &str) -> bool {
    oauth_completion_path(path, attempt_id).exists()
}

fn try_replace_stale_lock(
    path: &std::path::Path,
    observed: &OAuthLockSnapshot,
    contender_contents: &str,
    contender_attempt_id: &str,
) -> Result<bool, String> {
    let Some(current) = read_oauth_lock_snapshot(path)? else {
        return Ok(false);
    };
    if current.instance_key() != observed.instance_key() {
        return Ok(false);
    }
    let _ = std::fs::remove_file(oauth_completion_path(path, contender_attempt_id));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("could not rewrite stale oauth lock file: {e}"))?;
    use std::io::Write;
    file.write_all(contender_contents.as_bytes())
        .map_err(|e| format!("could not write oauth lock file: {e}"))?;
    file.flush()
        .map_err(|e| format!("could not flush oauth lock file: {e}"))?;
    Ok(true)
}

fn oauth_lock_key(server_id: &str, url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(server_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(url.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn oauth_lock_path(server_id: &str, url: &str) -> Result<std::path::PathBuf, String> {
    let dir = registry::conduit_dir().ok_or("could not resolve the data directory")?;
    let locks = dir.join("oauth-locks");
    std::fs::create_dir_all(&locks)
        .map_err(|e| format!("could not create oauth lock directory: {e}"))?;
    Ok(locks.join(format!("{}.lock", oauth_lock_key(server_id, url))))
}

fn try_acquire_oauth_lock(path: &std::path::Path) -> Result<Option<OAuthFlowLock>, String> {
    let attempt_id = oauth_attempt_id();
    let contents = oauth_lock_contents(&attempt_id);
    let _ = std::fs::remove_file(oauth_completion_path(path, &attempt_id));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(contents.as_bytes())
                .map_err(|e| format!("could not write oauth lock file: {e}"))?;
            Ok(Some(OAuthFlowLock {
                path: path.to_path_buf(),
                attempt_id,
            }))
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let Some(observed) = read_oauth_lock_snapshot(path)? else {
                return Ok(None);
            };
            if lock_snapshot_is_expired(&observed)
                && try_replace_stale_lock(path, &observed, &contents, &attempt_id)?
            {
                return Ok(Some(OAuthFlowLock {
                    path: path.to_path_buf(),
                    attempt_id,
                }));
            }
            Ok(None)
        }
        Err(e) => Err(format!("could not create oauth lock file: {e}")),
    }
}

fn acquire_or_wait_oauth_lock(_server_id: &str, url: &str) -> Result<Option<OAuthFlowLock>, String> {
    let path = oauth_lock_path(_server_id, url)?;
    let mut observed_attempt_id: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(OAUTH_LOCK_WAIT_SECS);
    loop {
        if let Some(lock) = try_acquire_oauth_lock(&path)? {
            if let Some(attempt_id) = &observed_attempt_id {
                if completion_exists(&path, attempt_id) {
                    drop(lock);
                    return Ok(None);
                }
            }
            return Ok(Some(lock));
        }
        if let Some(snapshot) = read_oauth_lock_snapshot(&path)? {
            if let Some(attempt_id) = snapshot.attempt_id {
                observed_attempt_id = Some(attempt_id);
            }
        }
        if let Some(attempt_id) = &observed_attempt_id {
            if completion_exists(&path, attempt_id) {
                return Ok(None);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                "another Toolport process is already running OAuth for this server; timed out waiting for it to finish"
                    .to_string(),
            );
        }
        std::thread::sleep(Duration::from_millis(OAUTH_LOCK_POLL_MS));
    }
}

/// Tracks the optional `toolport-gateway --http` child the app supervises so
/// HTTP/OpenAPI clients (Open WebUI and the like) can connect with one click,
/// no terminal. Only one runs at a time; the app kills it on exit.
#[derive(Default)]
struct HttpBridge {
    child: Option<std::process::Child>,
    port: Option<u16>,
    token: Option<String>,
}
type HttpBridgeState = Mutex<HttpBridge>;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct HttpBridgeStatus {
    running: bool,
    port: Option<u16>,
    url: Option<String>,
    /// The bearer token the client must send (Authorization: Bearer ...). Shown
    /// in the UI to copy; required on every request to the endpoint.
    token: Option<String>,
}

impl HttpBridgeStatus {
    fn new(port: Option<u16>, token: Option<String>) -> Self {
        HttpBridgeStatus {
            running: port.is_some(),
            url: port.map(|p| format!("http://localhost:{p}")),
            port,
            token,
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeResult {
    server_id: String,
    ok: bool,
    tool_count: usize,
    error: Option<String>,
    /// The failure looks like missing credentials (a remote 401/403, or a stdio
    /// server with secret env vars that aren't vaulted) - so the fix is to
    /// authenticate, not to debug. Drives the "Needs sign-in" UI.
    auth_required: bool,
}

/// True if this server declares secret env vars that don't yet have a vaulted value.
fn missing_secret(server: &ServerEntry) -> bool {
    server
        .env
        .iter()
        .any(|e| e.secret && e.value.is_none() && secrets::get_secret(&server.id, &e.key).is_none())
}

/// Connect to one server (stdio or remote), injecting any vaulted secrets, and
/// return the live connection (its tools are already listed). Shared by the
/// health probe and the tool playground - the running gateway is a separate
/// process, so the app connects on demand for these one-off operations.
fn connect_server(server: &ServerEntry) -> Result<DownstreamServer, String> {
    if let Some(command) = &server.command {
        let mut env: Vec<(String, String)> = Vec::new();
        for e in &server.env {
            if let Some(v) = &e.value {
                env.push((e.key.clone(), v.clone()));
            } else if e.secret {
                // Distinguish "never saved" from "couldn't read it" so we don't
                // silently launch a server without its key (which then fails with
                // its own cryptic message). Surface the real reason instead.
                match secrets::get_secret_result(&server.id, &e.key) {
                    Ok(Some(v)) => env.push((e.key.clone(), v)),
                    Ok(None) => {
                        return Err(format!(
                            "missing secret '{}': add its value under this server's secrets",
                            e.key
                        ))
                    }
                    Err(err) => {
                        return Err(format!(
                            "could not read secret '{}' from the keychain: {err}",
                            e.key
                        ))
                    }
                }
            }
        }
        // The probe/playground has no upstream client, so ${ROOT} has no root to
        // resolve against and falls back to the default cwd (issue #239).
        let cwd = server.cwd.as_deref().and_then(|c| resolve_root_token(c, None));
        let t = StdioTransport::spawn(command, &server.args, &env, cwd.as_deref())?;
        DownstreamServer::connect(server.id.clone(), Box::new(t))
    } else if server.url.is_some() {
        remote::connect_remote(server)
    } else {
        Err("no command or url".to_string())
    }
}

/// Connect to one server and report whether it came up and how many tools it has.
fn probe_one(server: &ServerEntry) -> ProbeResult {
    match connect_server(server) {
        Ok(ds) => ProbeResult {
            server_id: server.id.clone(),
            ok: true,
            tool_count: ds.tools.len(),
            error: None,
            auth_required: false,
        },
        // A stdio server that spawned but didn't list tools is very likely missing
        // its key; a remote 401/403 is an auth error outright.
        Err(e) => ProbeResult {
            server_id: server.id.clone(),
            ok: false,
            tool_count: 0,
            auth_required: remote::is_auth_error(&e) || missing_secret(server),
            error: Some(e),
        },
    }
}

/// Connect to a possibly-unsaved server entry and report whether it came up and
/// how many tools it exposes. Backs the "Test connection" button in the add/edit
/// dialog, so the user learns a server is broken before saving it. Never
/// persists anything; secret values the user typed ride in on `entry.env`, and
/// for an edit the entry keeps its id so already-vaulted secrets resolve.
#[tauri::command]
async fn test_server(entry: ServerEntry) -> Result<ProbeResult, String> {
    tauri::async_runtime::spawn_blocking(move || probe_one(&entry))
        .await
        .map_err(|e| e.to_string())
}

/// Probe every supported MCP client and return its current server configuration.
#[tauri::command]
async fn detect_clients() -> Result<Vec<clients::DetectedClient>, String> {
    // Reads several config files and scans plugin dirs - off the UI thread.
    tauri::async_runtime::spawn_blocking(clients::detect_clients)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_registry(state: State<RegistryState>) -> Registry {
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
}

fn server_from_detected(server: &clients::McpServer, client_id: &str) -> ServerEntry {
    ServerEntry {
        id: String::new(),
        name: server.name.clone(),
        transport: server.transport.clone(),
        command: server.command.clone(),
        args: server.args.clone(),
        // We only know env var names (values are never read into the UI layer).
        // Imported env vars are treated as secrets to be vaulted later.
        env: server
            .env_keys
            .iter()
            .map(|key| registry::EnvVar {
                key: key.clone(),
                value: None,
                secret: true,
            })
            .collect(),
        url: server.url.clone(),
        source: Some(format!("imported:{client_id}")),
        disabled_tools: vec![],
        cwd: None,
        unknown_fields: serde_json::Map::new(),
    }
}

/// Servers to add to the registry from a set of detected clients: both a
/// client's main config servers and its plugin-detected ones (e.g. Cursor/Roo
/// project-level scans), skipping the gateway's own entry and anything with the
/// same import key (checked against `existing` plus whatever this same call has
/// already picked). Package runners use their full package spec as that key, so
/// distinct scoped packages that share a friendly display name are retained and
/// given unique registry ids by `Registry::add_server`.
/// The onboarding banner promises a count across both server sources (see
/// `importableServers` in `src/lib/types.ts`), so this must actually cover
/// both or it silently under-imports relative to what was promised.
fn servers_to_import(detected: &[clients::DetectedClient], existing: &Registry) -> Vec<ServerEntry> {
    let mut picked: Vec<ServerEntry> = Vec::new();
    let mut import_keys: std::collections::HashSet<String> = existing
        .servers
        .iter()
        .map(|server| clients::import_dedupe_key(&server.name, server.command.as_deref(), &server.args))
        .collect();
    for client in detected {
        for server in client.servers.iter().chain(client.plugin_servers.iter()) {
            let entry = server_from_detected(server, &client.id);
            // Recognize the gateway by command path too, not just the "conduit"
            // name: an entry registered under any other name (a leftover from
            // before the rename, a manual add, whatever) still points straight
            // at our own binary, and importing it risks the gateway proxying
            // itself. See is_gateway_server's doc comment - this is the exact
            // contract it promises but this call site wasn't honoring.
            if clients::is_gateway_server(&entry) {
                continue;
            }
            let key = clients::import_dedupe_key(&entry.name, entry.command.as_deref(), &entry.args);
            if import_keys.insert(key) {
                picked.push(entry);
            }
        }
    }
    picked
}

fn selected_servers_to_import(
    detected: &[clients::DetectedClient],
    existing: &Registry,
    selected: Option<&std::collections::HashSet<String>>,
) -> Vec<ServerEntry> {
    servers_to_import(detected, existing)
        .into_iter()
        .filter(|server| {
            selected.map_or(true, |keys| {
                keys.contains(&clients::import_dedupe_key(
                    &server.name,
                    server.command.as_deref(),
                    &server.args,
                ))
            })
        })
        .collect()
}

/// Pull selected servers from every detected client into the registry. Omitting
/// `selected` preserves the legacy import-all behavior; callers that preview
/// first pass the opaque import keys they explicitly confirmed.
#[tauri::command]
async fn import_servers(
    state: State<'_, RegistryState>,
    selected: Option<Vec<String>>,
) -> Result<Registry, String> {
    let detected = tauri::async_runtime::spawn_blocking(clients::detect_clients)
        .await
        .map_err(|e| e.to_string())?;
    let selected: Option<std::collections::HashSet<String>> =
        selected.map(|keys| keys.into_iter().collect());
    let (reg, _) = write_registry(state.inner(), |reg| {
        for server in selected_servers_to_import(&detected, reg, selected.as_ref()) {
            reg.add_server(server);
        }
        Ok(())
    })?;
    Ok(reg)
}

/// Parse a pasted config snippet and return the detected server(s) with
/// env-var values included. Used by the Add Server dialog's "paste config" feature.
#[tauri::command]
fn parse_server_snippet(text: String) -> Result<Vec<clients::ParsedSnippetServer>, String> {
    const MAX_SNIPPET_BYTES: usize = 256 * 1024;
    if text.len() > MAX_SNIPPET_BYTES {
        return Err(format!(
            "Snippet is {} KB; limit is {} KB. Paste a single server config, not an entire file.",
            text.len() / 1024,
            MAX_SNIPPET_BYTES / 1024,
        ));
    }
    clients::parse_snippet(&text)
}

#[tauri::command]
fn add_server(state: State<RegistryState>, entry: ServerEntry) -> Result<Registry, String> {
    let (reg, id) = write_registry(state.inner(), |reg| Ok(reg.add_server(entry)))?;
    // Warm the launcher for the entry we just added, found by its assigned id (a concurrent
    // add under the lock could otherwise make `last` a different server).
    if let Some(saved) = reg.servers.iter().find(|s| s.id == id) {
        prewarm_launcher(saved);
    }
    Ok(reg)
}

/// Fire-and-forget spawn of a just-added download-then-run server (npx, uvx, ...)
/// so the launcher fetches its package now, in the background, instead of on the
/// first health probe or gateway connect. Lenient about env: missing secrets are
/// skipped rather than fatal - the child may exit complaining about them, but by
/// then the package is already in the launcher's cache, which is the whole point.
/// The connect result is deliberately ignored; the real probe reports health.
fn prewarm_launcher(server: &ServerEntry) {
    let Some(command) = server.command.clone() else {
        return;
    };
    if !crate::downstream::is_download_launcher(&command, &server.args) {
        return;
    }
    let server = server.clone();
    std::thread::spawn(move || {
        let env: Vec<(String, String)> = server
            .env
            .iter()
            .filter_map(|e| {
                e.value
                    .clone()
                    .or_else(|| secrets::get_secret(&server.id, &e.key))
                    .map(|v| (e.key.clone(), v))
            })
            .collect();
        let cwd = server.cwd.as_deref().and_then(|c| resolve_root_token(c, None));
        if let Ok(t) = StdioTransport::spawn(&command, &server.args, &env, cwd.as_deref()) {
            // Attempting the handshake keeps the child alive until the download
            // finishes (dropping the transport kills it), and warms it end-to-end
            // when the server actually comes up.
            let _ = DownstreamServer::connect(server.id.clone(), Box::new(t));
        }
    });
}

#[tauri::command]
fn update_server(state: State<RegistryState>, entry: ServerEntry) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| reg.update_server(entry))?;
    Ok(reg)
}

#[tauri::command]
fn remove_server(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| reg.remove_server(&id))?;
    Ok(reg)
}

#[tauri::command]
fn set_server_enabled(
    state: State<RegistryState>,
    profile_id: String,
    server_id: String,
    enabled: bool,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_server_enabled(&profile_id, &server_id, enabled)
    })?;
    Ok(reg)
}

#[tauri::command]
fn set_all_enabled(
    state: State<RegistryState>,
    profile_id: String,
    enabled: bool,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| reg.set_all_enabled(&profile_id, enabled))?;
    Ok(reg)
}

#[tauri::command]
fn create_profile(state: State<RegistryState>, name: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.add_profile(&name);
        Ok(())
    })?;
    Ok(reg)
}

#[tauri::command]
fn delete_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| reg.remove_profile(&id))?;
    Ok(reg)
}

#[tauri::command]
fn set_active_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| reg.set_active_profile(&id))?;
    Ok(reg)
}

/// Replace the folder -> profile auto-routing mappings (SOU-188). A gateway serving a client
/// whose reported project root is under a mapped path auto-scopes to that profile. Returns
/// the saved registry so the UI reflects the persisted list.
#[tauri::command]
fn set_folder_profiles(
    state: State<RegistryState>,
    mappings: Vec<FolderProfile>,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_folder_profiles(mappings);
        Ok(())
    })?;
    Ok(reg)
}

/// Set (or clear) a profile's tool-granular scope for one server (SOU-189). `tools = Some(list)`
/// narrows that server to exactly those original tool names within the profile; `None` (or an
/// empty list) clears it, restoring all tools on that server. Returns the saved registry.
#[tauri::command]
fn set_profile_server_tools(
    state: State<RegistryState>,
    profile_id: String,
    server_id: String,
    tools: Option<Vec<String>>,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_profile_server_tools(&profile_id, &server_id, tools)
    })?;
    Ok(reg)
}

/// Write a server set into a client's config (backs up first). Not yet called by
/// the UI; reserved for bulk operations.
#[tauri::command]
fn write_to_client(
    client_id: String,
    servers: Vec<ServerEntry>,
) -> Result<clients::WriteOutcome, String> {
    clients::write_servers(&client_id, &servers)
}

/// Install the Toolport gateway into a client (one click "connect to Toolport").
/// `profile` scopes that client to one profile (None = all enabled servers).
#[tauri::command]
fn install_gateway(
    state: State<RegistryState>,
    client_id: String,
    profile: Option<String>,
) -> Result<clients::WriteOutcome, String> {
    let outcome = clients::install_gateway(&client_id, profile.as_deref())?;
    // Record the scope we just wrote into the client's config, so the UI can show
    // and re-apply this client's effective scope without re-reading the config.
    // A concrete profile is stored by name; "no profile" is recorded as an
    // explicit-unscoped marker (not a removal) so a running gateway drops its old
    // scope live instead of falling back to its boot-time CONDUIT_PROFILE. The client
    // config was already written above (outside the lock); only the registry record
    // goes through the locked load-modify-save.
    let scope: Option<String> = profile
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    write_registry(state.inner(), |reg| {
        match scope.as_deref() {
            Some(p) => reg.set_client_scope(&client_id, Some(p)),
            None => reg.set_client_unscoped(&client_id),
        }
        Ok(())
    })?;
    Ok(outcome)
}

/// Remove the Toolport gateway from a client.
#[tauri::command]
fn uninstall_gateway(
    state: State<RegistryState>,
    client_id: String,
) -> Result<clients::WriteOutcome, String> {
    let outcome = clients::uninstall_gateway(&client_id)?;
    write_registry(state.inner(), |reg| {
        reg.set_client_scope(&client_id, None);
        Ok(())
    })?;
    Ok(outcome)
}

/// 24 random bytes (192 bits) as hex, for a bearer token or a unique id.
fn random_hex() -> Result<String, String> {
    let mut buf = [0u8; 24];
    getrandom::getrandom(&mut buf).map_err(|e| format!("could not generate randomness: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AddedHttpClient {
    registry: Registry,
    /// The plaintext bearer token. Shown once; only its SHA-256 is stored.
    token: String,
}

/// Register an HTTP-bridge client: generate a bearer token, store its hash plus
/// the chosen scope, and return the plaintext token once. The client pastes the
/// token as its API key; the multi-tenant bridge resolves it to this profile per
/// request, so several HTTP clients on one bridge get different server sets.
#[tauri::command]
fn add_http_client(
    state: State<RegistryState>,
    label: String,
    profile: Option<String>,
) -> Result<AddedHttpClient, String> {
    let token = random_hex()?;
    let id = random_hex()?;
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.http_clients.push(registry::HttpClient {
            id,
            label: label.trim().to_string(),
            token_sha256: registry::sha256_hex(&token),
            profile: profile.unwrap_or_default().trim().to_string(),
        });
        Ok(())
    })?;
    Ok(AddedHttpClient {
        registry: reg,
        token,
    })
}

/// Remove a registered HTTP-bridge client (revokes its token).
#[tauri::command]
fn remove_http_client(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.http_clients.retain(|c| c.id != id);
        Ok(())
    })?;
    Ok(reg)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrateResult {
    registry: Registry,
    /// How many of the client's servers were newly imported into Toolport.
    imported: usize,
    /// Names of the servers moved out of the client's config.
    moved: Vec<String>,
}

/// Migrate a client to Toolport: import its directly-configured servers into the
/// registry, then rewrite the client's config to contain only the Toolport
/// gateway (optionally scoped to `profile`). The client is left managing nothing
/// directly - everything routes through Toolport. Backs the config up first.
///
/// Plugin servers (read-only, outside the config file) are left untouched.
#[tauri::command]
async fn migrate_client(
    state: State<'_, RegistryState>,
    client_id: String,
    profile: Option<String>,
) -> Result<MigrateResult, String> {
    let detected = tauri::async_runtime::spawn_blocking(clients::detect_clients)
        .await
        .map_err(|e| e.to_string())?;
    let client = detected
        .into_iter()
        .find(|c| c.id == client_id)
        .ok_or_else(|| format!("Unknown client '{client_id}'"))?;

    // Import the client's servers under the lock (a fresh load-modify-save).
    let (_, (imported, moved)) = write_registry(state.inner(), |reg| {
        let mut imported = 0;
        let mut moved = Vec::new();
        for server in &client.servers {
            if clients::detected_is_gateway(server) {
                continue;
            }
            moved.push(server.name.clone());
            let exists = reg
                .servers
                .iter()
                .any(|e| e.name.eq_ignore_ascii_case(&server.name));
            if !exists {
                reg.add_server(server_from_detected(server, &client_id));
                imported += 1;
            }
        }
        Ok((imported, moved))
    })?;

    // Rewrite the client to only the gateway (backs up first). External to the registry, so
    // it stays outside the lock; the scope record below is a separate locked write.
    clients::migrate_to_gateway(&client_id, profile.as_deref())?;

    // Record the scope now that the client config was rewritten to the gateway.
    // "No profile" becomes an explicit-unscoped marker (not a removal) so a live
    // re-scope to "all servers" applies without restarting the client.
    let scope: Option<String> = profile
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string);
    let (registry, _) = write_registry(state.inner(), |reg| {
        match scope.as_deref() {
            Some(p) => reg.set_client_scope(&client_id, Some(p)),
            None => reg.set_client_unscoped(&client_id),
        }
        Ok(())
    })?;

    Ok(MigrateResult {
        registry,
        imported,
        moved,
    })
}

/// Store a secret env value in the OS keychain and mark it on the server entry
/// (the value itself never enters the registry file).
#[tauri::command]
fn set_secret(
    state: State<RegistryState>,
    server_id: String,
    key: String,
    value: String,
) -> Result<Registry, String> {
    // Keychain write first (external to the registry, so outside the lock), then record
    // that the secret exists + bump the generation on the FRESH value under the lock.
    secrets::set_secret(&server_id, &key, &value)?;
    let (reg, _) = write_registry(state.inner(), |reg| {
        if let Some(server) = reg.servers.iter_mut().find(|s| s.id == server_id) {
            match server.env.iter_mut().find(|e| e.key == key) {
                Some(ev) => {
                    ev.secret = true;
                    ev.value = None;
                }
                None => server.env.push(registry::EnvVar {
                    key,
                    value: None,
                    secret: true,
                }),
            }
        }
        reg.secrets_generation = reg.secrets_generation.wrapping_add(1);
        Ok(())
    })?;
    Ok(reg)
}

/// Remove a secret from the keychain and drop the env var from the server entry.
#[tauri::command]
fn delete_secret(
    state: State<RegistryState>,
    server_id: String,
    key: String,
) -> Result<Registry, String> {
    secrets::delete_secret(&server_id, &key)?;
    let (reg, _) = write_registry(state.inner(), |reg| {
        if let Some(server) = reg.servers.iter_mut().find(|s| s.id == server_id) {
            server.env.retain(|e| e.key != key);
        }
        reg.secrets_generation = reg.secrets_generation.wrapping_add(1);
        Ok(())
    })?;
    Ok(reg)
}

/// The most recent tool-call audit entries (newest first).
#[tauri::command]
fn get_audit_log(limit: usize) -> Vec<serde_json::Value> {
    audit::read_recent(limit)
}

/// Aggregate the full retained audit log into per-server call/error/latency stats for
/// the observability dashboard. Bounded by the log's byte cap, so totals are real.
#[tauri::command]
fn audit_stats() -> serde_json::Value {
    audit::stats()
}

/// Recent tool-definition integrity events (newest first): a previously-approved
/// tool whose definition changed (rug-pull signal) or a known server that added a
/// tool. Powers the in-app security notices.
#[tauri::command]
fn get_security_events(limit: usize) -> Vec<serde_json::Value> {
    integrity::read_recent(limit)
}

/// Cumulative tool-definition tokens that lazy discovery has kept out of clients'
/// context, summed from the local savings log for the in-app counter.
#[tauri::command]
fn savings_summary() -> serde_json::Value {
    savings::summary()
}

/// How many trailing gateway-log lines the diagnostics bundle includes.
const DIAG_LOG_LINES: usize = 200;

/// A shareable diagnostics blob for bug reports: Toolport version + OS, a
/// secrets-stripped registry summary, and the tail of the always-on gateway log.
/// Safe to paste into a public issue, secret values live in the OS keychain and
/// are never included; env vars are listed by key name only.
#[tauri::command]
fn gather_diagnostics() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Toolport diagnostics");
    let _ = writeln!(out, "version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "os: {} {}", std::env::consts::OS, std::env::consts::ARCH);

    // A load failure is exactly what a bug report needs to surface, not a
    // silently-empty registry from unwrap_or_default.
    match registry::load() {
        Ok(reg) => out.push_str(&registry_summary(&reg)),
        Err(e) => {
            let _ = writeln!(out, "\nregistry: failed to load: {e}");
        }
    }

    let _ = writeln!(out, "\ngateway log (last {DIAG_LOG_LINES} lines):");
    out.push_str(&gateway_log_tail(DIAG_LOG_LINES));
    out
}

/// Format the registry for a diagnostics bundle: settings, servers (on/off plus
/// launch target), and profiles. Secret-safe: env vars are listed by key name
/// only (with a `(secret)` marker), never their values.
fn registry_summary(reg: &Registry) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let active = reg.active_profile_id();
    let _ = writeln!(out, "\nsettings:");
    let _ = writeln!(out, "  lazy discovery: {}", reg.lazy_discovery);
    let global_mode = reg
        .discovery_mode
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| if reg.lazy_discovery { "lazy".into() } else { "full".into() });
    let _ = writeln!(out, "  discovery mode: {global_mode} (global)");
    if !reg.client_discovery.is_empty() {
        let mut overrides: Vec<String> = reg
            .client_discovery
            .iter()
            .map(|(id, mode)| format!("{id}={mode}"))
            .collect();
        overrides.sort();
        let _ = writeln!(out, "  per-client discovery: {}", overrides.join(", "));
    }
    let _ = writeln!(out, "  deny destructive: {}", reg.deny_destructive);
    let _ = writeln!(out, "  active profile: {active}");

    let _ = writeln!(out, "\nservers ({}):", reg.servers.len());
    for s in &reg.servers {
        let on = if reg.is_enabled(&active, &s.id) { "on" } else { "off" };
        let target = match (&s.command, &s.url) {
            (Some(cmd), _) => safe_command_target(cmd, &s.args),
            (None, Some(url)) => redact_url_userinfo(url),
            _ => String::new(),
        };
        let _ = writeln!(out, "  [{on}] {} ({}) {}", s.id, s.transport, target);
        if !s.env.is_empty() {
            let keys: Vec<String> = s
                .env
                .iter()
                .map(|e| if e.secret { format!("{} (secret)", e.key) } else { e.key.clone() })
                .collect();
            let _ = writeln!(out, "        env: {}", keys.join(", "));
        }
    }

    let _ = writeln!(out, "\nprofiles ({}):", reg.profiles.len());
    for p in &reg.profiles {
        let _ = writeln!(out, "  {}: [{}]", p.name, p.enabled_server_ids.join(", "));
    }
    out
}

fn safe_command_target(cmd: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(redact_arg_for_sharing(cmd));
    parts.extend(args.iter().map(|arg| redact_arg_for_sharing(arg)));
    parts.join(" ").trim().to_string()
}

fn redact_arg_for_sharing(arg: &str) -> String {
    if arg_looks_secret(arg) {
        "<redacted>".to_string()
    } else {
        redact_url_userinfo(arg)
    }
}

/// The last `n` lines of the always-on gateway log, or a friendly note when it
/// hasn't been written yet (no client has connected through the gateway).
fn gateway_log_tail(n: usize) -> String {
    let Some(path) = registry::gateway_log_path() else {
        return "(log path unavailable)\n".to_string();
    };
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => last_lines(&text, n),
        _ => "(no gateway log yet, connect a client to populate it)\n".to_string(),
    }
}

/// The last `n` lines of `text`, newline-terminated. Returns everything when the
/// text has fewer than `n` lines.
fn last_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    let mut tail = lines[start..].join("\n");
    if !tail.is_empty() {
        tail.push('\n');
    }
    tail
}

/// How long to wait for one server's probe before giving up on it. Generous
/// enough for an `npx` first-run package install, but bounded so a single hung
/// server can't leave its row "checking" forever. Issue #252.
const PROBE_TIMEOUT: Duration = Duration::from_secs(90);

/// Probe one server, never blocking longer than `PROBE_TIMEOUT`. On timeout the
/// underlying probe thread is left to finish or die on its own; we return a
/// timed-out result so the row resolves instead of spinning indefinitely.
fn probe_one_bounded(server: &ServerEntry) -> ProbeResult {
    let (tx, rx) = std::sync::mpsc::channel();
    let s = server.clone();
    std::thread::spawn(move || {
        let _ = tx.send(probe_one(&s));
    });
    rx.recv_timeout(PROBE_TIMEOUT).unwrap_or_else(|_| ProbeResult {
        server_id: server.id.clone(),
        ok: false,
        tool_count: 0,
        error: Some(format!("timed out after {}s", PROBE_TIMEOUT.as_secs())),
        auth_required: false,
    })
}

/// Connect to each enabled server in the active profile and report health + tool
/// count. Emits a `server-probed` event per server the moment it finishes, so the
/// UI resolves each row independently instead of waiting for the slowest - a cold
/// `npx` install used to leave the whole grid "checking" for 30-60s. Still returns
/// the full batch for callers that want it. Issue #252.
#[tauri::command]
async fn probe_servers(
    app: tauri::AppHandle,
    state: State<'_, RegistryState>,
) -> Result<Vec<ProbeResult>, String> {
    // Snapshot which servers to probe, then drop the lock before any I/O.
    let servers: Vec<ServerEntry> = {
        let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.enabled_servers()
            .into_iter()
            .filter(|s| !clients::is_gateway_server(s))
            .cloned()
            .collect()
    };
    // One worker thread per server. Each emits its result as soon as it's ready
    // (the UI listens for `server-probed`), then contributes to the returned batch.
    tauri::async_runtime::spawn_blocking(move || {
        let handles: Vec<_> = servers
            .into_iter()
            .map(|s| {
                let app = app.clone();
                std::thread::spawn(move || {
                    let result = probe_one_bounded(&s);
                    let _ = app.emit("server-probed", &result);
                    result
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
    .await
    .map_err(|e| e.to_string())
}

/// Snapshot one server out of the registry by id (dropping the lock before I/O).
fn server_by_id(state: &RegistryState, server_id: &str) -> Result<ServerEntry, String> {
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.servers
        .iter()
        .find(|s| s.id == server_id)
        .cloned()
        .ok_or_else(|| format!("server '{server_id}' not found"))
}

/// List the tools one server exposes (raw MCP tool objects: name, description,
/// inputSchema). Connects on demand and disconnects when the connection drops.
/// Powers the tool playground's tool picker.
#[tauri::command]
async fn list_server_tools(
    state: State<'_, RegistryState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || connect_server(&server).map(|ds| ds.tools))
        .await
        .map_err(|e| e.to_string())?
}

/// Invoke one tool on a server with the given arguments and return its raw MCP
/// result (`{ content, isError }`). Connects on demand and records the call in
/// the audit log, just like a call routed through the gateway.
#[tauri::command]
async fn call_tool(
    state: State<'_, RegistryState>,
    server_id: String,
    tool: String,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ds = connect_server(&server)?;
        let started = std::time::Instant::now();
        let result = ds.call(&tool, arguments).map_err(|e| e.to_string());
        let ms = started.elapsed().as_millis() as u64;
        // Mirror the gateway's success accounting: a result with isError=true is
        // a failed call even though the transport round-tripped fine.
        let ok = result
            .as_ref()
            .map(|r| !r.get("isError").and_then(|v| v.as_bool()).unwrap_or(false))
            .unwrap_or(false);
        // A transport error carries its own message; capture it so Activity can
        // show why a playground call failed, not just that it did.
        let err = result.as_ref().err().map(|e| e.to_string());
        // The in-app tool playground: a local action by the desktop user, so it's
        // unattributed (client identity is only meaningful for registered HTTP clients).
        audit::record_timed(&server.id, &tool, ok, Some(ms), err.as_deref(), None);
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

/// List the resources a server advertises (uri, name, mimeType). Connects on
/// demand; empty if the server declares no resources capability. Powers the
/// playground's Resources tab.
#[tauri::command]
async fn list_server_resources(
    state: State<'_, RegistryState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        connect_server(&server).map(|mut ds| {
            ds.load_resources_prompts();
            ds.resources
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// List the prompts a server advertises (name, description, arguments). Connects
/// on demand; empty if the server declares no prompts capability. Powers the
/// playground's Prompts tab.
#[tauri::command]
async fn list_server_prompts(
    state: State<'_, RegistryState>,
    server_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        connect_server(&server).map(|mut ds| {
            ds.load_resources_prompts();
            ds.prompts
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Read one resource by its uri and return the raw MCP result (`{ contents }`).
/// Connects on demand. Playground.
#[tauri::command]
async fn read_resource(
    state: State<'_, RegistryState>,
    server_id: String,
    uri: String,
) -> Result<serde_json::Value, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ds = connect_server(&server)?;
        ds.read_resource(&uri).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Get one prompt by name with arguments, returning the raw MCP result
/// (`{ messages }`). Connects on demand. Playground.
#[tauri::command]
async fn get_prompt(
    state: State<'_, RegistryState>,
    server_id: String,
    name: String,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let server = server_by_id(state.inner(), &server_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut ds = connect_server(&server)?;
        ds.get_prompt(&name, arguments).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Enable or disable a single tool on a server. The gateway hides disabled
/// tools from `tools/list` and rejects calls to them; the change propagates live
/// via the registry watcher. Returns the updated registry.
#[tauri::command]
fn set_tool_enabled(
    state: State<RegistryState>,
    server_id: String,
    tool: String,
    enabled: bool,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_tool_enabled(&server_id, &tool, enabled)
    })?;
    Ok(reg)
}

/// Pin (or unpin) a tool as a lazy-discovery prerequisite: search always surfaces a
/// pinned tool with its full schema, regardless of the query's match score, so a
/// load-bearing tool is never hidden. Propagates live via the registry watcher.
#[tauri::command]
fn set_tool_pinned(
    state: State<RegistryState>,
    server_id: String,
    tool: String,
    pinned: bool,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_tool_pinned(&server_id, &tool, pinned);
        Ok(())
    })?;
    Ok(reg)
}

/// Flip the global destructive-tool deny switch. When on, the gateway hides and
/// blocks every tool annotated `destructiveHint: true` across all servers.
#[tauri::command]
fn set_deny_destructive(state: State<RegistryState>, deny: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_deny_destructive(deny);
        Ok(())
    })?;
    Ok(reg)
}

/// Toggle per-call confirmation for destructive tools. When enabled, the gateway
/// intercepts each destructive tool call, returns a preview with a token, and
/// requires `conduit_confirm { token }` to proceed. Mutually exclusive with
/// `deny_destructive` (confirm turns deny off).
#[tauri::command]
fn set_confirm_destructive(state: State<RegistryState>, confirm: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_confirm_destructive(confirm);
        Ok(())
    })?;
    Ok(reg)
}

/// Toggle human-in-the-loop approval. When on, a gated tool call (destructive, or from an
/// untrusted-provenance server) is HELD until a person approves or denies it in the app,
/// via the approval broker. Distinct from confirm-destructive (which the agent re-confirms).
#[tauri::command]
fn set_human_approval(state: State<RegistryState>, on: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_human_approval(on);
        Ok(())
    })?;
    Ok(reg)
}

/// The tool calls currently held awaiting a human decision (for the Pending Approvals UI).
/// Polled by the frontend; the `approval-pending` / `approval-resolved` events prompt a refresh.
#[tauri::command]
fn list_pending_approvals(
    broker: State<approval_broker::ApprovalBroker>,
) -> Vec<approval_broker::PendingView> {
    broker.list()
}

/// Approve or deny a held tool call by id. The parked gateway call then runs (approve) or is
/// refused (deny). `scope` (on approve) controls whether future calls to the same tool skip
/// the prompt: `once` (default, remember nothing), `session` (until the app restarts), or
/// `always` (persisted). `Err` if the id is unknown (already resolved or timed out).
#[tauri::command]
fn decide_approval(
    broker: State<approval_broker::ApprovalBroker>,
    state: State<RegistryState>,
    id: String,
    approved: bool,
    scope: String,
) -> Result<(), String> {
    let view = broker.decide(&id, approved)?;
    if approved && scope != "once" {
        // Persist only when we can bind the allow to the current definition
        // fingerprint. If it's unavailable (the tool is no longer resolvable),
        // the call itself already went through via `decide` above; we simply
        // can't remember it, so degrade to a one-time approval rather than
        // returning an error for a decision that already succeeded.
        if let Some(fp) = view.tool_fingerprint.as_deref() {
            let key = approval::fingerprint_allow_key(&view.server, &view.tool, fp);
            broker.add_session_allow(key.clone());
            if scope == "always" {
                write_registry(state.inner(), |reg| {
                    reg.allow_tool(key);
                    Ok(())
                })?;
            }
        }
    }
    Ok(())
}

/// A tool allowed to skip human approval, for the Settings "Allowed tools" list.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AllowedTool {
    key: String,
    server: String,
    tool: String,
    /// true = persisted ("always"); false = only for this app session.
    persistent: bool,
}

/// Tools currently allowed to skip human approval: persistent ("always allow") from the
/// registry, plus this session's temporary allows from the broker.
#[tauri::command]
fn list_allowed_tools(
    state: State<RegistryState>,
    broker: State<approval_broker::ApprovalBroker>,
) -> Vec<AllowedTool> {
    let persistent = {
        let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.human_approval_allow.clone()
    };
    // Only fingerprint-bound `server/tool/<fingerprint>` keys still auto-approve;
    // the broker ignores legacy broad `server/tool` entries, so they must not be
    // surfaced here as active allows (that would misreport an inert entry as live).
    let parse = |key: &str| -> Option<(String, String)> {
        let mut parts = key.splitn(3, '/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(s), Some(t), Some(_fp)) => Some((s.to_string(), t.to_string())),
            _ => None,
        }
    };
    let mut out: Vec<AllowedTool> = persistent
        .iter()
        .filter_map(|k| {
            let (server, tool) = parse(k)?;
            Some(AllowedTool { key: k.clone(), server, tool, persistent: true })
        })
        .collect();
    for k in broker.session_allowed() {
        if !persistent.contains(&k) {
            if let Some((server, tool)) = parse(&k) {
                out.push(AllowedTool { key: k, server, tool, persistent: false });
            }
        }
    }
    out
}

/// Revoke an allowed tool (re-require approval): drop it from both the persistent registry
/// list and this session's allowlist.
#[tauri::command]
fn revoke_allowed_tool(
    state: State<RegistryState>,
    broker: State<approval_broker::ApprovalBroker>,
    key: String,
) -> Result<(), String> {
    write_registry(state.inner(), |reg| {
        reg.revoke_tool(&key);
        Ok(())
    })?;
    broker.remove_session_allow(&key);
    Ok(())
}

/// Set (or clear) a per-tool exposure override, keyed by `(server, original tool)`: rename
/// the tool and/or replace its description as clients see it (the latter locally neutralizes
/// a poisoned description). Empty/blank name and description clears the override. The call
/// still routes to the original downstream tool; gateways pick up the change via the registry
/// watcher.
#[tauri::command]
fn set_tool_override(
    state: State<RegistryState>,
    server: String,
    tool: String,
    name: Option<String>,
    description: Option<String>,
) -> Result<Registry, String> {
    let norm = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_tool_override(
            server,
            tool,
            registry::ToolOverride { name: norm(name), description: norm(description) },
        );
        Ok(())
    })?;
    Ok(reg)
}

/// Remove a tool's exposure override, restoring the server's own name and description.
#[tauri::command]
fn clear_tool_override(
    state: State<RegistryState>,
    server: String,
    tool: String,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.clear_tool_override(&server, &tool);
        Ok(())
    })?;
    Ok(reg)
}

/// Toggle live request/response inspection. When enabled, the gateway captures each
/// tool call's args + result into a small, separate, ephemeral local ring
/// (`inspect.jsonl`, last 50 calls, each body size-capped) that the Activity view can
/// show. Off by default; the governance audit log is never touched by this. Turning
/// it off in the UI should also clear the ring (see `clear_inspect_log`).
#[tauri::command]
fn set_live_inspect(state: State<RegistryState>, enabled: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_live_inspect(enabled);
        Ok(())
    })?;
    Ok(reg)
}

/// The most recent live-inspection captures (newest first): each tool call's args and
/// result, only present while live inspection has been on. Empty when off/unused.
#[tauri::command]
fn get_inspect_log(limit: usize) -> Vec<serde_json::Value> {
    inspect::read_recent(limit)
}

/// Clear the live-inspection ring (delete `inspect.jsonl`), so no captured args/results
/// linger. Called when the user turns live inspection off. Surfaces a real removal
/// failure so the UI never confirms a delete that did not happen.
#[tauri::command]
fn clear_inspect_log() -> Result<(), String> {
    inspect::try_clear().map_err(|e| format!("Couldn't clear the inspector log: {e}"))
}

/// Recent lazy-discovery search traces (newest first): what the model searched for,
/// which tools matched, and the tool-definition tokens the results cost vs. loading
/// the whole catalog. The in-path proof that lazy discovery is working. Empty when
/// nothing has searched yet.
#[tauri::command]
fn get_search_traces(limit: usize) -> Vec<serde_json::Value> {
    searchtrace::read_recent(limit)
}

/// Clear the search-trace log (delete `search-trace.jsonl`).
#[tauri::command]
fn clear_search_traces() -> Result<(), String> {
    searchtrace::try_clear().map_err(|e| format!("Couldn't clear the search traces: {e}"))
}

/// Clear all retained local activity in one confirmed action: the audit log, discovery
/// search traces, live-inspection captures, and the savings tally (including its
/// carry-forward total). Each is a local, irreversible delete; the logs re-create
/// themselves on the next event. Backs the Activity view's "Clear retained activity".
///
/// Attempts every log even if one fails (so a single locked file doesn't leave the
/// rest un-cleared), then reports exactly which could not be removed. Never confirms a
/// delete that did not happen: a leftover sensitive log must not read as "cleared".
#[tauri::command]
fn clear_activity_logs() -> Result<(), String> {
    let mut failed = Vec::new();
    if audit::try_clear().is_err() {
        failed.push("audit log");
    }
    if searchtrace::try_clear().is_err() {
        failed.push("search traces");
    }
    if inspect::try_clear().is_err() {
        failed.push("inspector captures");
    }
    if savings::try_clear().is_err() {
        failed.push("savings");
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("Couldn't clear: {}", failed.join(", ")))
    }
}

/// One exposed tool's verifiable identity: the model-visible alias joined back to its
/// source server + the profiles that enable it, plus the integrity fingerprint and
/// when the definition was first seen / last changed. This is the "capability
/// provenance" view: prefixing helps the model pick a tool, this helps a human verify
/// what actually crossed the boundary.
#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ToolIdentity {
    /// Model-visible exposed name (the integrity pin key).
    alias: String,
    /// Resolved source server id, or empty if the alias couldn't be attributed (a
    /// renamed tool whose alias no longer carries its `server__` prefix; its exact
    /// provenance needs the deeper gateway integration, tracked separately).
    server_id: String,
    server_name: String,
    /// Names of the profiles whose enabled set includes this server.
    profiles: Vec<String>,
    /// Upstream tool name, taken as the alias suffix after `server__`.
    upstream: String,
    /// Version-prefixed fingerprint of the pinned definition (drift detection compares
    /// against this exact value).
    fingerprint: String,
    first_seen: u64,
    last_changed: u64,
    quarantined: bool,
}

/// Assemble the identity rows. Pure (no state/IO) so the alias->server attribution is
/// unit-testable.
fn build_tool_identities(
    baselines: &std::collections::BTreeMap<String, integrity::ToolBaseline>,
    quarantined: &std::collections::BTreeSet<String>,
    servers: &[ServerEntry],
    profiles: &[Profile],
) -> Vec<ToolIdentity> {
    // Exposed prefix (sanitize_segment(id)) -> server. Matching by the KNOWN prefixes
    // (longest wins) is robust against a server id that itself contains `__`, unlike a
    // naive split on the first separator.
    let prefixed: Vec<(String, &ServerEntry)> = servers
        .iter()
        .map(|s| (router::sanitize_segment(&s.id), s))
        .collect();
    baselines
        .iter()
        .map(|(alias, base)| {
            let mut server: Option<&ServerEntry> = None;
            let mut upstream = String::new();
            let mut best_len = 0usize;
            for (prefix, srv) in &prefixed {
                if let Some(rest) = alias
                    .strip_prefix(prefix.as_str())
                    .and_then(|r| r.strip_prefix("__"))
                {
                    if prefix.len() > best_len || server.is_none() {
                        best_len = prefix.len();
                        server = Some(srv);
                        upstream = rest.to_string();
                    }
                }
            }
            let (server_id, server_name) =
                server.map(|s| (s.id.clone(), s.name.clone())).unwrap_or_default();
            let profile_names = if server_id.is_empty() {
                Vec::new()
            } else {
                profiles
                    .iter()
                    .filter(|p| p.enabled_server_ids.contains(&server_id))
                    .map(|p| p.name.clone())
                    .collect()
            };
            ToolIdentity {
                alias: alias.clone(),
                server_id,
                server_name,
                profiles: profile_names,
                upstream,
                fingerprint: base.fingerprint.clone(),
                first_seen: base.first_seen,
                last_changed: base.last_changed,
                quarantined: quarantined.contains(alias),
            }
        })
        .collect()
}

/// The capability-provenance table: every pinned tool's identity for the active
/// newest-changed first. Aggregates pins across all profiles, because the gateway keys
/// pins by the CONDUIT_PROFILE it ran under (often None -> tool-pins.json), which need
/// not equal the app's active profile. Empty until the gateway has pinned a baseline.
#[tauri::command]
fn list_tool_identities(state: State<RegistryState>) -> Vec<ToolIdentity> {
    let reg = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ids = build_tool_identities(
        &integrity::all_baselines(),
        &integrity::all_quarantined_names(),
        &reg.servers,
        &reg.profiles,
    );
    ids.sort_by(|a, b| b.last_changed.cmp(&a.last_changed).then(a.alias.cmp(&b.alias)));
    ids
}

/// Toggle quarantine-on-drift. When enabled, the gateway hides and blocks a high-risk
/// tool (poisoned definition, or a destructive tool whose definition changed/appeared)
/// that drifts from its pinned baseline, until the user re-approves it.
#[tauri::command]
fn set_quarantine_on_drift(state: State<RegistryState>, on: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.quarantine_on_drift = on;
        Ok(())
    })?;
    Ok(reg)
}

/// Tools currently quarantined (blocked after a high-risk drift), across all profiles.
///
/// Also fires an OS notification when a **new** entry appears after the first baseline
/// poll (SOU-305 option 1). Quarantine is decided in the gateway process; the app only
/// learns by polling, so this is the cheapest "notify when it happens while the app is
/// running" path. First call only seeds the seen-set so restarting the app with an
/// already-quarantined tool does not re-notify.
#[tauri::command]
fn list_quarantined(app: AppHandle) -> Vec<serde_json::Value> {
    let list = integrity::all_quarantined();
    notify_new_quarantines(&app, &list);
    list
}

/// Keys of quarantine entries we have already observed this process. `None` = not
/// baselined yet (first poll seeds without notifying).
static QUARANTINE_SEEN: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

fn quarantine_entry_key(rec: &serde_json::Value) -> String {
    let profile = rec.get("profile").and_then(|v| v.as_str()).unwrap_or("");
    let tool = rec.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
    let ts = rec.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
    format!("{profile}\0{tool}@{ts}")
}

fn notify_new_quarantines(app: &AppHandle, list: &[serde_json::Value]) {
    let keys: std::collections::HashSet<String> =
        list.iter().map(quarantine_entry_key).collect();
    let mut guard = QUARANTINE_SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_mut() {
        None => {
            // First poll: baseline only.
            *guard = Some(keys);
        }
        Some(seen) => {
            let mut newcomers: Vec<&serde_json::Value> = list
                .iter()
                .filter(|rec| !seen.contains(&quarantine_entry_key(rec)))
                .collect();
            if !newcomers.is_empty() {
                // Newest first for the body when several land in one poll.
                newcomers.sort_by_key(|r| std::cmp::Reverse(r.get("ts").and_then(|v| v.as_u64()).unwrap_or(0)));
                let title = if newcomers.len() == 1 {
                    "Toolport: tool quarantined".to_string()
                } else {
                    format!("Toolport: {} tools quarantined", newcomers.len())
                };
                let body = newcomers
                    .iter()
                    .take(3)
                    .map(|r| {
                        let tool = r.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
                        let detail = r
                            .get("detail")
                            .and_then(|v| v.as_str())
                            .or_else(|| r.get("reason").and_then(|v| v.as_str()))
                            .unwrap_or("high-risk change");
                        format!("{tool}: {detail}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let _ = app
                    .notification()
                    .builder()
                    .title(title)
                    .body(body)
                    .show();
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.request_user_attention(Some(tauri::UserAttentionType::Informational));
                }
            }
            *seen = keys;
        }
    }
}

/// Re-approve a quarantined tool so the gateway re-exposes it. Re-saving the registry
/// nudges the gateway (which watches it) to rebuild and re-read the smaller set.
#[tauri::command]
fn release_quarantine(
    state: State<RegistryState>,
    profile: String,
    tool: String,
) -> Result<(), String> {
    let prof = if profile.is_empty() {
        None
    } else {
        Some(profile.as_str())
    };
    integrity::release(prof, &tool);
    // The quarantine release lives in the separate tool-pins file; the former blind re-save
    // here was only a gateway mtime-nudge (which the no-op guard usually swallowed anyway)
    // and it could revert a concurrent gateway/team write (SOU-23). Refresh the cache
    // instead of blind-writing the possibly-stale snapshot.
    reload_into_state(state.inner())?;
    Ok(())
}

/// Set lazy discovery globally. The gateway reads this from the registry, so it
/// takes effect for every client (including ones that don't forward env vars).
/// Clients pick it up the next time they (re)spawn the gateway.
#[tauri::command]
fn set_lazy_discovery(state: State<RegistryState>, lazy: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_lazy_discovery(lazy);
        Ok(())
    })?;
    Ok(reg)
}

/// Enable or disable server-side "code mode" (the `toolport_run_script` meta-tool). The
/// gateway reads this from the registry and refreshes it live on the next watcher tick, so
/// it applies to every client without forwarding an env var. Off by default.
#[tauri::command]
fn set_code_mode(state: State<RegistryState>, enabled: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.code_mode = enabled;
        Ok(())
    })?;
    Ok(reg)
}

/// Opt into agent control: lets an agent enable or disable servers through the
/// gateway's `conduit_enable_server` / `conduit_disable_server` tools. Off by
/// default; the destructive-tool safety switch stays user-only regardless of this.
#[tauri::command]
fn set_allow_agent_control(state: State<RegistryState>, allow: bool) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.allow_agent_control = allow;
        Ok(())
    })?;
    Ok(reg)
}

/// Set (or clear) a client's discovery-mode override. `mode` is `"full" | "lazy" |
/// "grouped"`; `None` (or "inherit"/unknown) clears it so the client inherits the global
/// mode. The gateway resolves this live via `CONDUIT_CLIENT_ID`, so the change applies
/// without reinstalling the client.
#[tauri::command]
fn set_client_discovery(
    state: State<RegistryState>,
    client_id: String,
    mode: Option<String>,
) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| {
        reg.set_client_discovery(&client_id, mode.as_deref());
        Ok(())
    })?;
    Ok(reg)
}

/// Flush the in-memory registry to disk so the teams module (which reads the registry
/// file) operates on the current state, then refresh the in-memory state from disk
/// after the team operation merged into it.
/// Load-modify-save the registry under the cross-process lock (mutating a FRESH on-disk
/// copy), then sync the in-memory cache to the persisted result. The in-process mutex is
/// held across the whole op so app threads serialize on it before the file lock; together
/// with `registry::update` this stops any app command from reverting a concurrent gateway
/// or team-sync write (SOU-23). Returns the new registry and `f`'s value.
fn write_registry<T>(
    state: &RegistryState,
    f: impl FnOnce(&mut Registry) -> Result<T, String>,
) -> Result<(Registry, T), String> {
    let mut guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (reg, out) = registry::update(f)?;
    *guard = reg.clone();
    Ok((reg, out))
}

/// Refresh the in-memory cache from disk. Formerly `flush_to_disk`, which PUSHED the
/// in-memory snapshot to disk; that blind write could revert a concurrent gateway/team
/// change (SOU-23), and it is now unnecessary because every mutation persists immediately
/// via `write_registry`, so the in-memory copy never holds unsaved changes. Pulling instead
/// keeps the cache current for the team flows without ever clobbering the file.
fn refresh_from_disk(state: &RegistryState) -> Result<(), String> {
    reload_into_state(state).map(|_| ())
}

fn reload_into_state(state: &RegistryState) -> Result<Registry, String> {
    let fresh = registry::load()?;
    *state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = fresh.clone();
    Ok(fresh)
}

/// Result of a connect (or a pending-join poll). `status` is "connected" (joined; `registry`
/// is the fresh merged state), "pending" (an approval-gated link — poll `request_token` via
/// `team_join_poll`), "denied", or "unknown". The frontend switches on `status`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamConnectResult {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry: Option<Registry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_token: Option<String>,
}

/// Join a Toolport Teams server with an invite or join-link code. A normal code vaults the
/// member token in the OS keychain, pulls the team's server set, and merges it into the local
/// registry non-destructively. An approval-gated link instead returns `status: "pending"` with
/// a `request_token` the frontend polls (nothing is stored locally until an admin approves).
#[tauri::command]
async fn team_connect(
    app: tauri::AppHandle,
    state: State<'_, RegistryState>,
    server_url: String,
    invite_code: String,
    member_name: Option<String>,
) -> Result<TeamConnectResult, String> {
    refresh_from_disk(state.inner())?;
    // Same reason as team_sync: a synchronous command runs on Tauri's main (UI) thread, and
    // teams::connect does a blocking network join + first config pull. Run it off-thread so
    // clicking "Connect" to join a team doesn't freeze the whole app until the join returns.
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        teams::connect(&server_url, &invite_code, member_name.as_deref())
    })
    .await
    .map_err(|e| format!("connect task join failed: {e}"))??;
    match outcome {
        teams::ConnectOutcome::Connected(review) => {
            let fresh = reload_into_state(state.inner())?;
            nudge_gateway(state.inner());
            // Team config adds local/stdio + LAN servers OFF (the member reviews + enables them)
            // and refuses link-local/metadata URLs. Surface both so the state is never a mystery.
            emit_team_review(&app, review);
            Ok(TeamConnectResult { status: "connected", registry: Some(fresh), request_token: None })
        }
        teams::ConnectOutcome::Pending { request_token } => Ok(TeamConnectResult {
            status: "pending",
            registry: None,
            request_token: Some(request_token),
        }),
    }
}

/// Poll a pending, approval-gated join. The frontend calls this on an interval after
/// `team_connect` returned `status: "pending"`, handing back the `request_token` (and the same
/// `member_name`). On approval it finalizes exactly like a direct connect and returns the fresh
/// registry; otherwise it reports still-pending, denied, or unknown (expired/invalid).
#[tauri::command]
async fn team_join_poll(
    app: tauri::AppHandle,
    state: State<'_, RegistryState>,
    server_url: String,
    request_token: String,
    member_name: Option<String>,
) -> Result<TeamConnectResult, String> {
    let poll = tauri::async_runtime::spawn_blocking(move || {
        teams::poll_join(&server_url, &request_token, member_name.as_deref())
    })
    .await
    .map_err(|e| format!("poll task join failed: {e}"))??;
    match poll {
        teams::JoinPoll::Connected(review) => {
            let fresh = reload_into_state(state.inner())?;
            nudge_gateway(state.inner());
            emit_team_review(&app, review);
            Ok(TeamConnectResult { status: "connected", registry: Some(fresh), request_token: None })
        }
        teams::JoinPoll::Pending => {
            Ok(TeamConnectResult { status: "pending", registry: None, request_token: None })
        }
        teams::JoinPoll::Denied => {
            Ok(TeamConnectResult { status: "denied", registry: None, request_token: None })
        }
        teams::JoinPoll::Unknown => {
            Ok(TeamConnectResult { status: "unknown", registry: None, request_token: None })
        }
    }
}

/// Pull the latest team config and re-merge it. A no-op when nothing changed.
///
/// `async` + `spawn_blocking` is load-bearing, not stylistic: a synchronous Tauri command
/// runs on the main (UI) thread, and the config pull is a blocking network call. The
/// long-poll variant below blocks for up to 30s per cycle, and the member's background loop
/// re-invokes it continuously, so as a sync command it froze the whole app ("Not Responding")
/// for anyone connected to a team and starved every other command (probe_servers, etc.).
/// Running the blocking pull on a worker thread keeps the event loop free.
#[tauri::command]
async fn team_sync(app: tauri::AppHandle, state: State<'_, RegistryState>) -> Result<Registry, String> {
    refresh_from_disk(state.inner())?;
    let result = tauri::async_runtime::spawn_blocking(teams::sync_now)
        .await
        .map_err(|e| format!("sync task join failed: {e}"))??;
    finish_sync(&app, state.inner(), result)
}

/// Long-polling sync for the member's background loop: the config pull parks on the server
/// for up to `wait_secs` (clamped) and returns the instant the team config view changes, so
/// a dashboard policy edit enforces in ~1s instead of at the next interval. Otherwise
/// identical to [`team_sync`]; the frontend re-invokes it in a loop. See [`team_sync`] for
/// why the blocking pull must run off the main thread.
#[tauri::command]
async fn team_sync_wait(
    app: tauri::AppHandle,
    state: State<'_, RegistryState>,
    wait_secs: u64,
) -> Result<Registry, String> {
    refresh_from_disk(state.inner())?;
    let wait = wait_secs.min(30);
    let result = tauri::async_runtime::spawn_blocking(move || teams::sync_wait(wait))
        .await
        .map_err(|e| format!("sync task join failed: {e}"))??;
    finish_sync(&app, state.inner(), result)
}

/// Apply a sync result to the shared registry state and tell the UI what happened. Shared by
/// the immediate ([`team_sync`]) and long-polling ([`team_sync_wait`]) commands.
fn finish_sync(
    app: &tauri::AppHandle,
    state: &RegistryState,
    result: teams::SyncResult,
) -> Result<Registry, String> {
    match result {
        teams::SyncResult::Removed => {
            // The member was removed; sync already cleared the local team. Reload so the UI
            // drops the team, and tell it why so it can surface a notice rather than the raw
            // error the config pull used to throw.
            let fresh = reload_into_state(state)?;
            nudge_gateway(state);
            let _ = app.emit("team-removed", serde_json::json!({}));
            Ok(fresh)
        }
        teams::SyncResult::Ok { applied, .. } => {
            let outcome = applied.map(|(_, o)| o).unwrap_or_default();
            let fresh = reload_into_state(state)?;
            nudge_gateway(state);
            emit_team_review(app, outcome);
            Ok(fresh)
        }
    }
}

/// Tell the UI how a team config landed: how many servers need the member's review (they
/// run a local command or hit a LAN URL, so they're added OFF) and how many were blocked
/// outright (link-local / cloud-metadata URLs). Only fires when there's something to say.
fn emit_team_review(app: &tauri::AppHandle, outcome: teams::MergeOutcome) {
    if outcome.review > 0 || outcome.blocked > 0 {
        let _ = app.emit(
            "team-servers-review",
            serde_json::json!({ "review": outcome.review, "blocked": outcome.blocked }),
        );
    }
}

/// Member-facing Team Instructions status (spec W4): the org content on this machine, its
/// version, and each installed client's on-disk state. `None` when the team has no active
/// instructions. Read-only. Async + `spawn_blocking` because it scans every installed client's
/// rules file, which must not run on the UI thread.
#[tauri::command]
async fn team_instructions_status() -> Option<teams::InstructionsStatusView> {
    tauri::async_runtime::spawn_blocking(teams::instructions_status)
        .await
        .ok()
        .flatten()
}

/// Leave the team: remove its merged servers, clear the connection and the token.
#[tauri::command]
fn team_disconnect(state: State<RegistryState>) -> Result<Registry, String> {
    refresh_from_disk(state.inner())?;
    teams::disconnect()?;
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    Ok(fresh)
}

/// Admin: replace only the team's shared server list with the current local set (own servers
/// only, secret values never sent). Remote instructions and policy fields are preserved, and
/// an optimistic-concurrency conflict is returned rather than overwriting another admin.
#[tauri::command]
async fn team_push_preview(state: State<'_, RegistryState>) -> Result<teams::PushPreview, String> {
    refresh_from_disk(state.inner())?;
    tauri::async_runtime::spawn_blocking(teams::preview_push_current)
        .await
        .map_err(|e| format!("push preview task join failed: {e}"))?
}

#[tauri::command]
async fn team_push(
    state: State<'_, RegistryState>,
    base_version: i64,
    local_fingerprint: String,
) -> Result<i64, String> {
    refresh_from_disk(state.inner())?;
    // push_current does a blocking GET + PUT to the team server; keep it off the main thread.
    tauri::async_runtime::spawn_blocking(move || {
        teams::push_current(base_version, &local_fingerprint)
    })
        .await
        .map_err(|e| format!("push task join failed: {e}"))?
}

/// Re-save the registry to bump its mtime. The running gateway watches that file
/// and rebuilds on change, so freshly-vaulted credentials take effect (and the
/// server's tools flow to connected clients) without a manual restart.
/// Refresh the in-memory cache from disk. Formerly a blind re-save meant to bump the
/// registry mtime so the gateway would reload; that reverted concurrent gateway/team writes
/// (SOU-23) and, because the no-op guard skips a same-content save, rarely bumped the mtime
/// anyway. A real change (e.g. `bump_secrets_generation`) advances the file under the lock
/// and triggers the gateway reload on its own.
fn nudge_gateway(state: &RegistryState) {
    let _ = reload_into_state(state);
}

/// Bump [`Registry::secrets_generation`] and save under the lock so gateways reload even
/// when only the keychain changed. Increments the FRESH on-disk value (not a stale `+1`) so
/// a concurrent bump from another writer isn't lost.
fn bump_secrets_generation(state: &RegistryState) {
    let _ = write_registry(state, |reg| {
        reg.secrets_generation = reg.secrets_generation.wrapping_add(1);
        Ok(())
    });
}

#[tauri::command]
fn take_registry_recovery_notice() -> Option<registry::RegistryRecoveryNotice> {
    registry::take_recovery_notice()
}

/// Store a bearer token for an http server (used as `Authorization: Bearer ...`).
#[tauri::command]
fn set_auth_token(
    state: State<RegistryState>,
    server_id: String,
    token: String,
) -> Result<(), String> {
    // A manually pasted bearer replaces any prior OAuth session. Keeping stale
    // refresh metadata could otherwise overwrite the user's token later.
    remote::clear_oauth_state(&server_id)?;
    secrets::set_secret(&server_id, secrets::HTTP_AUTH_KEY, &token)?;
    bump_secrets_generation(state.inner());
    Ok(())
}

#[tauri::command]
fn clear_auth_token(state: State<RegistryState>, server_id: String) -> Result<(), String> {
    // Remove refresh metadata first so a second-write failure cannot leave state
    // that silently recreates the bearer token the user asked to delete.
    remote::clear_oauth_state(&server_id)?;
    secrets::delete_secret(&server_id, secrets::HTTP_AUTH_KEY)?;
    bump_secrets_generation(state.inner());
    Ok(())
}

#[tauri::command]
fn has_auth_token(server_id: String) -> bool {
    secrets::get_secret(&server_id, secrets::HTTP_AUTH_KEY).is_some()
}

/// Figure out what a remote server needs to connect (none / oauth / token) and
/// how to get it. Runs off the UI thread (it makes a network call).
#[tauri::command]
async fn probe_auth(url: String) -> vendors::AuthInfo {
    tauri::async_runtime::spawn_blocking(move || vendors::probe_auth(&url))
        .await
        .unwrap_or_else(|_| vendors::AuthInfo::fallback())
}

/// Run the OAuth 2.1 browser flow for a remote server and vault the resulting
/// access token (and refresh token). Runs on a blocking worker so the UI thread
/// stays responsive while the user completes sign-in in their browser.
#[tauri::command]
async fn authenticate_oauth(
    state: State<'_, RegistryState>,
    server_id: String,
    url: String,
) -> Result<(), String> {
    let Some(_lock) = acquire_or_wait_oauth_lock(&server_id, &url)? else {
        // Another process completed the OAuth flow for this same server while we waited.
        return Ok(());
    };
    let resource = url.clone();
    let res = tauri::async_runtime::spawn_blocking(move || oauth::authenticate(&url))
        .await
        .map_err(|e| e.to_string())??;
    secrets::set_secret(&server_id, secrets::HTTP_AUTH_KEY, &res.access_token)?;
    remote::store_oauth_state(
        &server_id,
        &res.token_endpoint,
        &res.client_id,
        res.refresh_token,
        Some(resource),
        res.issued_at,
        res.expires_at,
    )?;
    bump_secrets_generation(state.inner());
    Ok(())
}

/// The popular catalog (the curated set).
#[tauri::command]
fn popular_catalog() -> Vec<catalog::CatalogEntry> {
    catalog::popular()
}

/// Curated stacks: role-based bundles of catalog servers (each resolved to full
/// entries with credential hints) for the guided one-flow setup.
#[tauri::command]
fn list_stacks() -> Vec<stacks::Stack> {
    stacks::stacks()
}

/// Search the official MCP Registry for servers to add. Network call, so it runs
/// on a blocking worker. Empty query returns popular/recent servers.
#[tauri::command]
async fn search_catalog(query: String) -> Result<Vec<catalog::CatalogEntry>, String> {
    tauri::async_runtime::spawn_blocking(move || catalog::search(&query))
        .await
        .map_err(|e| e.to_string())?
}

/// Which of a server's env keys currently have a value stored in the keychain.
#[tauri::command]
fn secret_status(server_id: String, keys: Vec<String>) -> Vec<(String, bool)> {
    keys.into_iter()
        .map(|k| {
            let present = secrets::get_secret(&server_id, &k).is_some();
            (k, present)
        })
        .collect()
}

/// Open Toolport's data directory (registry, logs, audit) in the OS file manager,
/// so users can back it up or inspect it.
#[tauri::command]
fn open_data_dir() -> Result<(), String> {
    let dir = registry::conduit_dir().ok_or("could not resolve the data directory")?;
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "linux")]
    let program = "xdg-open";
    std::process::Command::new(program)
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("could not open the data directory: {e}"))?;
    Ok(())
}

/// Serialize the user's servers into a shareable setup (server definitions only,
/// never secret values). A teammate imports this and adds their own keys, so a
/// curated server set can be shared without leaking any credentials. An optional
/// name/description lets the sharer label the set.
#[tauri::command]
fn export_config(
    state: State<RegistryState>,
    name: Option<String>,
    description: Option<String>,
    server_names: Option<Vec<String>>,
) -> Result<String, String> {
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    serde_json::to_string_pretty(&build_export(
        &reg,
        name.as_deref(),
        description.as_deref(),
        server_names.as_deref(),
    ))
    .map_err(|e| e.to_string())
}

/// Write a shareable setup to a file on disk (the path comes from a save dialog).
/// Same content as export_config; just easier to hand to a teammate than a paste.
#[tauri::command]
fn export_config_to_path(
    state: State<RegistryState>,
    path: String,
    name: Option<String>,
    description: Option<String>,
    server_names: Option<Vec<String>>,
) -> Result<(), String> {
    let json = {
        let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        serde_json::to_string_pretty(&build_export(
            &reg,
            name.as_deref(),
            description.as_deref(),
            server_names.as_deref(),
        ))
        .map_err(|e| e.to_string())?
    };
    std::fs::write(&path, json).map_err(|e| format!("Couldn't write the file: {e}"))
}

/// Export the audit log to a file (path from a save dialog). `format` is "csv" or
/// "json". CSV is formula-injection-safe (see `audit::to_csv`) since tool names and
/// error text come from untrusted downstream servers. Exports the full retained
/// log, which the audit module already caps.
#[tauri::command]
fn export_audit_to_path(path: String, format: String) -> Result<(), String> {
    let entries = audit::read_recent(usize::MAX);
    let body = if format == "csv" {
        audit::to_csv(&entries)
    } else {
        serde_json::to_string_pretty(&entries).map_err(|e| e.to_string())?
    };
    std::fs::write(&path, body).map_err(|e| format!("Couldn't write the file: {e}"))
}

/// Public endpoint that turns a shared setup into a `toolport.app/s/<id>` link.
const SHARE_ENDPOINT: &str = "https://toolport.app/api/share";

/// POST a shareable setup (the secret-stripped JSON from `export_config`) to the
/// share service and return the short link to copy. The service stores it with a
/// 90-day TTL and renders a preview page; secrets are never in the payload.
#[tauri::command]
async fn share_stack(setup_json: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let resp = ureq::post(SHARE_ENDPOINT)
            .timeout(std::time::Duration::from_secs(20))
            .set("content-type", "application/json")
            .send_string(&setup_json)
            .map_err(|e| format!("couldn't reach the share service: {e}"))?;
        let mut buf = Vec::new();
        resp.into_reader()
            .take(64 * 1024)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        let body: serde_json::Value = serde_json::from_slice(&buf).map_err(|e| e.to_string())?;
        body.get("url")
            .and_then(|u| u.as_str())
            .map(str::to_string)
            .ok_or_else(|| "the share service did not return a link".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Holds a share id captured from a conduit:// deep link that arrived before the
/// UI was ready (cold start). The frontend claims it on mount.
type PendingShare = Mutex<Option<String>>;

/// Parse a conduit://import?s=<id> deep link into its share id. Tolerates an
/// optional trailing slash after the host; the id must look like a share id.
fn parse_share_url(url: &str) -> Option<String> {
    let after = url.strip_prefix("conduit://")?;
    let after = after.strip_prefix("import")?;
    let query = after.trim_start_matches('/').strip_prefix('?')?;
    query.split('&').find_map(|pair| {
        let v = pair.strip_prefix("s=")?;
        let id: String = v.chars().take(64).collect();
        if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()) {
            Some(id)
        } else {
            None
        }
    })
}

/// Resolve a shared-stack id (from a deep link) by fetching its setup JSON from
/// the share service; the frontend then previews it like any other import.
#[tauri::command]
async fn fetch_shared_setup(id: String) -> Result<String, String> {
    if id.is_empty() || id.len() > 32 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("invalid share id".to_string());
    }
    let url = format!("{SHARE_ENDPOINT}?id={id}");
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let resp = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .map_err(|e| format!("couldn't reach the share service: {e}"))?;
        let mut buf = Vec::new();
        resp.into_reader()
            .take(128 * 1024)
            .read_to_end(&mut buf)
            .map_err(|e| e.to_string())?;
        String::from_utf8(buf).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Claim a share id captured from a deep link before the UI was listening.
#[tauri::command]
fn take_pending_shared(state: State<PendingShare>) -> Option<String> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// Deliver a shared-stack id from a deep link to the UI: stash it so a cold start
/// can claim it on mount, focus the window, and emit the live event for a running
/// app. Idempotent enough that delivering the same id twice just re-opens it.
fn deliver_shared_import(handle: &tauri::AppHandle, id: String) {
    if let Some(st) = handle.try_state::<PendingShare>() {
        *st.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(id.clone());
    }
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.set_focus();
    }
    let _ = handle.emit("import-shared", id);
}

/// Import a shared setup. Adds servers not already present (by name); secret
/// values are never included, so each new server is left for the user to vault.
#[tauri::command]
fn import_config(state: State<RegistryState>, json: String) -> Result<Registry, String> {
    let (reg, _) = write_registry(state.inner(), |reg| apply_import(reg, &json))?;
    Ok(reg)
}

/// Read a shared-setup file from disk (path from an open dialog), capped so a
/// malicious or accidental huge file can't OOM the app. The contents go to the UI
/// for a preview/confirm step; nothing is imported here.
#[tauri::command]
fn read_setup_file(path: String) -> Result<String, String> {
    const MAX_SETUP_BYTES: u64 = 4 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_SETUP_BYTES {
            return Err("That file is too large to be a Toolport setup.".to_string());
        }
    }
    std::fs::read_to_string(&path).map_err(|e| format!("Couldn't read the file: {e}"))
}

/// One server a shared setup would add. The UI shows the exact command/args/url so
/// the user reviews what an (attacker-controllable) shared config will run before
/// accepting it - enabling a server later spawns its command.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportItem {
    /// Stable only for the current detected-import preview. Shared setup previews
    /// have no key because they are confirmed as one complete document.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    name: String,
    transport: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    /// False if a server with this name already exists (the import would skip it).
    is_new: bool,
}

/// Show exactly what the bulk client import would add without changing the
/// registry. The same import key is accepted by `import_servers` after review.
#[tauri::command]
async fn preview_import_servers(state: State<'_, RegistryState>) -> Result<Vec<ImportItem>, String> {
    let detected = tauri::async_runtime::spawn_blocking(clients::detect_clients)
        .await
        .map_err(|e| e.to_string())?;
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(servers_to_import(&detected, &reg)
        .into_iter()
        .map(|server| ImportItem {
            key: Some(clients::import_dedupe_key(
                &server.name,
                server.command.as_deref(),
                &server.args,
            )),
            name: server.name,
            transport: server.transport,
            command: server.command,
            args: server.args,
            url: server.url,
            is_new: true,
        })
        .collect())
}

/// Parse a shared setup and report what it WOULD add, without importing anything.
#[tauri::command]
fn preview_import(state: State<RegistryState>, json: String) -> Result<Vec<ImportItem>, String> {
    #[derive(serde::Deserialize)]
    struct Doc {
        servers: Vec<ServerEntry>,
    }
    let doc: Doc = serde_json::from_str(&json)
        .map_err(|e| format!("That doesn't look like a Toolport setup: {e}"))?;
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(doc
        .servers
        .into_iter()
        .map(|s| {
            let is_new = !reg
                .servers
                .iter()
                .any(|e| e.name.eq_ignore_ascii_case(&s.name));
            ImportItem {
                key: None,
                name: s.name,
                transport: s.transport,
                command: s.command,
                args: s.args,
                url: s.url,
                is_new,
            }
        })
        .collect())
}

/// Build a shareable setup document: server definitions only, with the gateway
/// entry excluded and every secret value stripped. Pure, so the never-leak-a-key
/// invariant is testable without Tauri state.
fn build_export(
    reg: &Registry,
    name: Option<&str>,
    description: Option<&str>,
    server_names: Option<&[String]>,
) -> serde_json::Value {
    // When a selection is given, share only those servers (by name); otherwise
    // share them all. Lets a user share a focused "stack" instead of everything.
    let include: Option<std::collections::HashSet<&str>> =
        server_names.map(|names| names.iter().map(String::as_str).collect());
    let servers: Vec<ServerEntry> = reg
        .servers
        .iter()
        .filter(|s| !clients::is_gateway_server(s))
        .filter(|s| {
            include
                .as_ref()
                .map(|set| set.contains(s.name.as_str()))
                .unwrap_or(true)
        })
        .map(|s| {
            let mut s = s.clone();
            s.id = String::new();
            for e in &mut s.env {
                e.value = None; // never share env values
            }
            // Some servers take credentials inline in args (e.g. a Postgres
            // connection string with a password). Redact those too, so a shared
            // setup never leaks a secret the env-stripping above wouldn't catch.
            for a in &mut s.args {
                if arg_looks_secret(a) {
                    *a = "<redacted>".to_string();
                }
            }
            // A remote server's URL can carry inline credentials
            // (`https://user:pass@host`); strip them too - the env/arg passes miss
            // the `url` field, which would otherwise leak through the share link.
            if let Some(u) = &s.url {
                s.url = Some(redact_url_userinfo(u));
            }
            s
        })
        .collect();
    let mut doc = serde_json::json!({ "kind": "conduit-setup", "version": 1, "servers": servers });
    if let Some(n) = name.map(str::trim).filter(|s| !s.is_empty()) {
        doc["name"] = serde_json::json!(n);
    }
    if let Some(d) = description.map(str::trim).filter(|s| !s.is_empty()) {
        doc["description"] = serde_json::json!(d);
    }
    doc
}

/// Merge a shared setup into the registry: add servers not already present (by
/// name, case-insensitive), stripping any secret values. Pure (no Tauri state).
fn apply_import(reg: &mut Registry, json: &str) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Doc {
        servers: Vec<ServerEntry>,
    }
    let doc: Doc = serde_json::from_str(json)
        .map_err(|e| format!("That doesn't look like a Toolport setup: {e}"))?;
    for mut s in doc.servers {
        if reg.servers.iter().any(|e| e.name.eq_ignore_ascii_case(&s.name)) {
            continue;
        }
        s.id = String::new();
        for e in &mut s.env {
            e.value = None;
        }
        s.source = Some("shared".to_string());
        reg.add_server(s);
    }
    Ok(())
}

/// Watch the registry file and mirror external changes (e.g. an agent enabling a
/// server through the gateway) back into the app's in-memory state, then nudge the
/// UI to refetch. Without this, a gateway-written change would be invisible to the
/// app and clobbered by its next save. Polls mtime (the gateway uses the same
/// approach) and skips identical touches so an mtime-only bump doesn't churn the UI.
fn watch_registry_for_app(handle: tauri::AppHandle) {
    let Some(path) = registry::resolved_path() else {
        return;
    };
    let mtime = |p: &std::path::Path| std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
    let mut last = mtime(&path);
    let mut last_json = registry::load_from(&path)
        .ok()
        .and_then(|r| serde_json::to_string(&r).ok())
        .unwrap_or_default();
    loop {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let cur = mtime(&path);
        if cur == last {
            continue;
        }
        last = cur;
        let Ok(fresh) = registry::load_from(&path) else {
            continue; // half-written file; retry next tick
        };
        let fresh_json = serde_json::to_string(&fresh).unwrap_or_default();
        if fresh_json == last_json {
            continue; // identical content (e.g. an mtime bump to nudge the gateway)
        }
        last_json = fresh_json;
        {
            let state = handle.state::<RegistryState>();
            *state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = fresh.clone();
        }
        let _ = handle.emit("registry-changed", &fresh);
    }
}

/// Reap the child if it has already exited; returns true if it is still alive.
fn http_bridge_alive(bridge: &mut HttpBridge) -> bool {
    let alive = match bridge.child.as_mut() {
        Some(child) => !matches!(child.try_wait(), Ok(Some(_))),
        None => false,
    };
    if !alive {
        bridge.child = None;
        bridge.port = None;
        bridge.token = None;
    }
    alive
}

/// Stop client-spawned gateway processes before an in-app update (Windows).
/// MCP clients stay open; only `toolport-gateway` children exit.
#[tauri::command]
fn stop_spawned_gateways() -> u32 {
    crate::gateway_publish::stop_spawned_gateways()
}

/// Start `toolport-gateway --http <port>` as a supervised child so HTTP/OpenAPI
/// clients can connect. Idempotent: if it's already running, returns the current
/// status; otherwise spawns the bundled gateway binary and tracks it.
#[tauri::command]
fn start_http_bridge(
    state: State<HttpBridgeState>,
    port: Option<u16>,
) -> Result<HttpBridgeStatus, String> {
    let port = port.unwrap_or(8765);
    let mut bridge = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if http_bridge_alive(&mut bridge) {
        return Ok(HttpBridgeStatus::new(bridge.port, bridge.token.clone()));
    }
    // Fail fast if the port is already taken (another instance, or a stray
    // gateway). Otherwise the child would just exit on the bind error and we'd
    // wrongly report success while the user is actually talking to whatever
    // already owns the port.
    if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
        return Err(format!(
            "Port {port} is already in use. Stop whatever is using it, then try again."
        ));
    }
    let bin = clients::resolve_gateway_path()
        .ok_or_else(|| "toolport-gateway binary not found next to the app".to_string())?;
    // Auto-generate a bearer token the client must send on every request.
    // Without it, any local process (including a web page open in the user's
    // browser) could POST to the port and run their tools.
    let mut tok = [0u8; 24];
    getrandom::getrandom(&mut tok).map_err(|e| format!("could not generate a token: {e}"))?;
    let token: String = tok.iter().map(|b| format!("{b:02x}")).collect();
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("--http")
        .arg(port.to_string())
        .env("CONDUIT_HTTP_TOKEN", &token)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Don't flash a console window on Windows.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("could not start the HTTP bridge: {e}"))?;
    // Confirm it actually came up rather than dying on startup (bind race,
    // bad binary, etc.). Poll the port; if the child exits or never answers,
    // surface a real error instead of a false success.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!(
                "The HTTP endpoint exited on startup ({status}). Is port {port} already in use?"
            ));
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break; // it's listening
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            return Err(format!(
                "The HTTP endpoint did not come up on port {port} within 5s."
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bridge.child = Some(child);
    bridge.port = Some(port);
    bridge.token = Some(token.clone());
    Ok(HttpBridgeStatus::new(Some(port), Some(token)))
}

/// Stop the supervised HTTP bridge child, if any.
#[tauri::command]
fn stop_http_bridge(state: State<HttpBridgeState>) -> Result<HttpBridgeStatus, String> {
    let mut bridge = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(mut child) = bridge.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    bridge.port = None;
    bridge.token = None;
    Ok(HttpBridgeStatus::new(None, None))
}

/// Report whether the HTTP bridge is running, reaping it if it has exited.
#[tauri::command]
fn http_bridge_status(state: State<HttpBridgeState>) -> Result<HttpBridgeStatus, String> {
    let mut bridge = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    http_bridge_alive(&mut bridge);
    Ok(HttpBridgeStatus::new(bridge.port, bridge.token.clone()))
}

/// macOS only: show the Dock icon when a window is visible, and drop it (Accessory
/// activation policy) when the app is only in the menu bar, so Toolport is never in
/// both the Dock and the menu bar at once. No-op on Windows/Linux, which have no
/// such concept and keep their normal taskbar/tray behavior.
#[cfg(target_os = "macos")]
fn set_dock_icon_visible(app: &AppHandle, visible: bool) {
    let policy = if visible {
        tauri::ActivationPolicy::Regular
    } else {
        tauri::ActivationPolicy::Accessory
    };
    let _ = app.set_activation_policy(policy);
}

#[cfg(not(target_os = "macos"))]
fn set_dock_icon_visible(_app: &AppHandle, _visible: bool) {}

/// Bring the main window back to the foreground (from the tray, a re-launch, or an
/// approval). Un-hides, un-minimizes, and focuses so it works from every hidden state.
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        // A visible window means the app should own a Dock icon again (macOS).
        set_dock_icon_visible(app, true);
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
        // Tell the frontend the window is visible again so the team-sync loop resumes and does
        // an immediate catch-up poll. The webview's Page Visibility API doesn't report Tauri
        // tray show/hide on Windows, so this event is the authoritative signal (see the
        // team-sync effect in App.tsx and `main_window_visible`).
        let _ = app.emit("team-window-visible", true);
    }
}

/// Whether the main window is currently shown (vs hidden to the tray). Seeds the frontend
/// team-sync loop's visibility gate on mount - live changes come via the `team-window-visible`
/// event emitted from show/hide. Defaults to visible if the window is missing or the platform
/// query fails, so sync never wedges off on an unexpected error.
#[tauri::command]
fn main_window_visible(app: AppHandle) -> bool {
    app.get_webview_window("main")
        .and_then(|w| w.is_visible().ok())
        .unwrap_or(true)
}

/// Reflect the pending-approval count on the tray tooltip, so a glance at the tray
/// tells you something is waiting even with the window hidden (complements the OS
/// notification the broker already fires). Best-effort.
fn update_tray_tooltip(app: &AppHandle) {
    let pending = app
        .try_state::<approval_broker::ApprovalBroker>()
        .map(|b| b.list().len())
        .unwrap_or(0);
    if let Some(tray) = app.tray_by_id("main") {
        let tip = if pending > 0 {
            format!(
                "Toolport - {pending} tool call{} awaiting approval",
                if pending == 1 { "" } else { "s" }
            )
        } else {
            "Toolport".to_string()
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}

/// The first time the window is closed to the tray, tell the user it's still running
/// (so a background HITL gate isn't a surprise) and how to fully quit. Once ever: a
/// marker file in the data dir gates it.
fn maybe_show_tray_hint(app: &AppHandle) {
    let Some(dir) = registry::conduit_dir() else {
        return;
    };
    let marker = dir.join(".tray-hint-shown");
    if marker.exists() {
        return;
    }
    let _ = std::fs::write(&marker, b"1");
    let _ = app
        .notification()
        .builder()
        .title("Toolport is still running")
        .body(
            "It stays in your tray so it can hold tool calls for your approval. \
             Quit it any time from the tray icon.",
        )
        .show();
}

/// Build the system-tray (Windows) / menu-bar (macOS) icon: left-click opens the app,
/// right-click shows an Open/Quit menu. Quit fully exits (the run-loop's Exit handler
/// tears down the HTTP bridge); closing the window only hides it (see the window-event
/// handler), so the gateway/broker keep running and HITL stays live.
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "tray_open", "Open Toolport", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "tray_quit", "Quit Toolport", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &sep, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .tooltip("Toolport")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "tray_open" => show_main_window(app),
            "tray_quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    // macOS: use a monochrome glyph rendered as a template image, so the menu bar
    // tints it to match every other status item (white on the dark bar) instead of
    // showing the full-color app icon. Every other platform keeps the colored icon.
    #[cfg(target_os = "macos")]
    {
        let glyph = tauri::image::Image::from_bytes(include_bytes!(
            "../icons/tray-mac-template.png"
        ))?;
        builder = builder.icon(glyph).icon_as_template(true);
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let registry = registry::load().unwrap_or_default();

    // Migrate legacy keychain secrets into the data-protection keychain (the
    // team-scoped shared access group) in the background. On macOS, older versions
    // of Toolport stored secrets as per-app-ACL keychain items that trigger a
    // password prompt every time a freshly-signed app/gateway reads them. This
    // moves each value into the data-protection keychain, which the separately
    // signed gateway reads with NO prompt across updates — read each value, write +
    // verify the data-protection copy, then delete the legacy item (no secret is
    // lost; an item that can't move is left in place). Guarded by a marker file so
    // it runs once. Only the app runs this (the gateway is read-only). Best-effort:
    // failures are logged but never block startup.
    {
        let reg = registry.clone();
        std::thread::spawn(move || {
            // Collect every secret key the registry knows about: env vars marked
            // secret, plus the reserved keys for remote servers and team tokens.
            let mut keys: Vec<(String, String)> = Vec::new();
            for server in &reg.servers {
                for e in &server.env {
                    if e.secret {
                        keys.push((server.id.clone(), e.key.clone()));
                    }
                }
                if server.url.is_some() {
                    // Remote servers store both the auth token and OAuth state.
                    keys.push((server.id.clone(), secrets::HTTP_AUTH_KEY.to_string()));
                    keys.push((server.id.clone(), remote::OAUTH_STATE_KEY.to_string()));
                }
            }
            // Team member token (one global slot, not per-server).
            keys.push((
                teams::TEAM_TOKEN_SERVER.to_string(),
                teams::TEAM_TOKEN_KEY.to_string(),
            ));
            let report = secrets::migrate_secrets_to_dpk(&keys);
            if report.migrated > 0 || report.failed > 0 {
                eprintln!(
                    "conduit: keychain migration complete ({} entries moved to data-protection keychain, {} failed, {} not found)",
                    report.migrated, report.failed, report.not_found
                );
            }
        });
    }

    if !registry.live_inspect {
        inspect::clear();
    }

    tauri::Builder::default()
        // Single-instance must be registered first. With its `deep-link` feature
        // a second launch carrying a conduit:// URL is forwarded to the deep-link
        // plugin's on_open_url (set up below); here we just focus the window.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // A second launch (or clicking the app while it's hidden in the tray) should
            // bring the window back, not just focus a hidden window.
            show_main_window(app);
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        // Launch at login (opt-in via Settings). `--hidden` is passed on auto-launch so
        // the app starts to the tray without flashing a window (see setup()).
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .manage(Mutex::new(registry))
        .manage(Mutex::new(HttpBridge::default()))
        .manage(PendingShare::default())
        .invoke_handler(tauri::generate_handler![
            detect_clients,
            get_registry,
            take_registry_recovery_notice,
            import_servers,
            preview_import_servers,
            parse_server_snippet,
            add_server,
            update_server,
            remove_server,
            set_server_enabled,
            create_profile,
            delete_profile,
            set_active_profile,
            set_folder_profiles,
            set_profile_server_tools,
            write_to_client,
            install_gateway,
            uninstall_gateway,
            migrate_client,
            set_secret,
            delete_secret,
            secret_status,
            get_audit_log,
            audit_stats,
            get_security_events,
            savings_summary,
            gather_diagnostics,
            probe_servers,
            test_server,
            list_server_tools,
            list_server_resources,
            list_server_prompts,
            read_resource,
            get_prompt,
            add_http_client,
            remove_http_client,
            call_tool,
            set_tool_enabled,
            set_tool_pinned,
            set_deny_destructive,
            set_confirm_destructive,
            set_human_approval,
            list_pending_approvals,
            decide_approval,
            list_allowed_tools,
            revoke_allowed_tool,
            set_tool_override,
            clear_tool_override,
            set_live_inspect,
            get_inspect_log,
            clear_inspect_log,
            get_search_traces,
            clear_search_traces,
            clear_activity_logs,
            list_tool_identities,
            set_quarantine_on_drift,
            list_quarantined,
            release_quarantine,
            set_lazy_discovery,
            set_code_mode,
            set_allow_agent_control,
            set_client_discovery,
            team_connect,
            team_join_poll,
            team_sync,
            team_sync_wait,
            main_window_visible,
            team_instructions_status,
            team_disconnect,
            team_push_preview,
            team_push,
            set_auth_token,
            clear_auth_token,
            has_auth_token,
            authenticate_oauth,
            probe_auth,
            popular_catalog,
            list_stacks,
            search_catalog,
            open_data_dir,
            set_all_enabled,
            export_config,
            export_config_to_path,
            export_audit_to_path,
            share_stack,
            fetch_shared_setup,
            take_pending_shared,
            import_config,
            read_setup_file,
            preview_import,
            start_http_bridge,
            stop_http_bridge,
            http_bridge_status,
            stop_spawned_gateways,
        ])
        // Close-to-tray: the window's X hides it instead of quitting, so the gateway and
        // approval broker keep running (HITL only works while the app is alive). Quit is
        // explicit, from the tray menu. A one-time notification explains it the first time.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                    // Hidden to the tray => menu-bar only, so drop the Dock icon (macOS).
                    set_dock_icon_visible(window.app_handle(), false);
                    // Tell the frontend the window is hidden so the team-sync loop parks and
                    // stops polling the team server (each poll would otherwise keep a
                    // scale-to-zero Postgres awake). Resumes via show_main_window's emit.
                    let _ = window.app_handle().emit("team-window-visible", false);
                    maybe_show_tray_hint(window.app_handle());
                }
            }
        })
        .setup(|app| {
            let handle = app.handle();

            // Build the tray icon, then show the window - unless launched with `--hidden`
            // (auto-start at login), in which case we start straight to the tray. The
            // window is created hidden (visible:false) so a normal launch never flashes.
            build_tray(handle)?;
            let start_hidden = std::env::args().any(|a| a == "--hidden");
            if start_hidden {
                // Auto-start at login goes straight to the tray: menu-bar only, no
                // Dock icon until the user opens the window.
                set_dock_icon_visible(handle, false);
            } else {
                show_main_window(handle);
            }

            // Keep the tray tooltip's pending-approval count fresh as calls are held and
            // resolved (the broker emits these; the window may be hidden in the tray).
            let h = handle.clone();
            app.listen("approval-pending", move |_| update_tray_tooltip(&h));
            let h = handle.clone();
            app.listen("approval-resolved", move |_| update_tray_tooltip(&h));

            // Mirror external registry changes (an agent toggling a server through
            // the gateway) back into the app and the UI, in a background thread.
            let handle = app.handle().clone();
            std::thread::spawn(move || watch_registry_for_app(handle));

            // One-time, idempotent migration: after the conduit-gateway ->
            // toolport-gateway rename, re-point any existing client whose config
            // still names the old binary (Windows/Linux have no compat symlink, so
            // that path no longer exists). Surgical + backed up; a no-op once every
            // client is on the current path.
            std::thread::spawn(|| {
                if let Some(published) = crate::gateway_publish::publish_bundled_gateway() {
                    eprintln!(
                        "toolport: published client gateway at {}",
                        published.display()
                    );
                }
                let repointed = clients::repoint_stale_gateways();
                if !repointed.is_empty() {
                    eprintln!(
                        "toolport: re-pointed {} client config(s) to the renamed gateway: {}",
                        repointed.len(),
                        repointed.join(", ")
                    );
                }
                // Stop any gateway running a version other than this one, so each client
                // respawns the freshly-installed gateway on its next request rather than the
                // user having to relaunch the client. Covers MANUAL updates (running the
                // installer), which never go through the in-app updater that already calls
                // stop_spawned_gateways.
                //
                // Deliberately NOT gated on `repointed` (SOU-306). That call is idempotent, so
                // once configs point at the new binary it returns empty forever and the cleanup
                // became one-shot: it was a proxy for "is a running gateway on an old version?"
                // and the two come apart precisely after a manual install, or on any launch
                // after the first. Checking versions directly makes this self-correcting, so a
                // later launch still cleans up what an earlier one missed. Current-version
                // gateways are left alone, so a normal launch kills nothing.
                let stale = crate::gateway_publish::stop_stale_gateways();
                if !stale.is_empty() {
                    eprintln!(
                        "toolport: stopped {} stale gateway process image(s): {}",
                        stale.len(),
                        stale.join(", ")
                    );
                }
            });

            // Start the human-approval broker: it publishes a loopback endpoint that every
            // gateway process dials into, and holds gated tool calls until the user approves
            // or denies them here. Always managed so the approve/deny commands have state.
            let broker = approval_broker::start(app.handle().clone());
            app.manage(broker);

            // conduit://import?s=<id> deep links open the shared-stack import.
            // The installer registers the scheme; we also register at runtime so
            // it works unpackaged (dev). Three delivery paths are covered:
            //   - cold start (app launched by the link): the URL is in this
            //     process's launch args, read via get_current();
            //   - already running (second launch): the single-instance plugin
            //     forwards the URL to on_open_url;
            //   - macOS: the OS delivers via on_open_url at launch and runtime.
            // Cold starts can arrive before the UI is listening, so the id is also
            // stashed for the frontend to claim on mount (take_pending_shared).
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let _ = app.deep_link().register("conduit");

                // Cold start: the URL(s) the app was launched with.
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    for url in urls {
                        if let Some(id) = parse_share_url(url.as_str()) {
                            deliver_shared_import(app.handle(), id);
                        }
                    }
                }

                // While running (and macOS launch): delivered as an event.
                let handle = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        if let Some(id) = parse_share_url(url.as_str()) {
                            deliver_shared_import(&handle, id);
                        }
                    }
                });
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // Never orphan the HTTP bridge: kill the supervised child on exit.
            if matches!(
                event,
                tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
            ) {
                if let Some(state) = app_handle.try_state::<HttpBridgeState>() {
                    let mut bridge =
                        state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(mut child) = bridge.child.take() {
                        let _ = child.kill();
                    }
                }
            }
            // On FINAL exit only (not a cancelable ExitRequested), remove the approval
            // endpoint descriptor so a gateway dialing after we're gone reads no broker
            // (a clean Unreachable) rather than connecting to the dead port we left behind.
            if matches!(event, tauri::RunEvent::Exit) {
                approval_broker::clear_endpoint();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{arg_looks_secret, redact_url_userinfo};
    use registry::EnvVar;

    fn github_with_secret() -> ServerEntry {
        ServerEntry {
            id: "gh".into(),
            name: "GitHub".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![],
            env: vec![EnvVar {
                key: "TOKEN".into(),
                value: Some("sk-live-xyz".into()),
                secret: true,
            }],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    #[test]
    fn probe_one_bounded_passes_through_a_fast_failure_well_under_the_timeout() {
        // A bogus command fails to spawn immediately, so the bounded wrapper must
        // return that result promptly (nowhere near PROBE_TIMEOUT) and carry the
        // server id - it only times out for a genuinely hung probe.
        let mut server = plain_server("bogus", "Bogus");
        server.command = Some("toolport-no-such-binary-xyz".into());
        let start = std::time::Instant::now();
        let r = probe_one_bounded(&server);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "a fast failure must not wait on the timeout"
        );
        assert!(!r.ok);
        assert_eq!(r.server_id, "bogus");
    }

    fn plain_server(id: &str, name: &str) -> ServerEntry {
        ServerEntry {
            id: id.into(),
            name: name.into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    fn detected_mcp_server(name: &str) -> clients::McpServer {
        clients::McpServer {
            name: name.into(),
            transport: "stdio".into(),
            command: Some("x".into()),
            args: vec![],
            env_keys: vec![],
            url: None,
        }
    }

    fn detected_mcp_server_with_command(name: &str, command: &str) -> clients::McpServer {
        clients::McpServer {
            command: Some(command.into()),
            ..detected_mcp_server(name)
        }
    }

    fn detected_mcp_server_with_args(
        name: &str,
        command: &str,
        args: &[&str],
    ) -> clients::McpServer {
        clients::McpServer {
            command: Some(command.into()),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            ..detected_mcp_server(name)
        }
    }

    fn detected_client(id: &str, servers: Vec<&str>, plugin_servers: Vec<&str>) -> clients::DetectedClient {
        clients::DetectedClient {
            id: id.into(),
            name: id.into(),
            uses_connectors: false,
            config_path: String::new(),
            config_exists: true,
            app_present: true,
            servers: servers.into_iter().map(detected_mcp_server).collect(),
            plugin_servers: plugin_servers.into_iter().map(detected_mcp_server).collect(),
            gateway_installed: false,
            error: None,
        }
    }

    #[test]
    fn servers_to_import_includes_plugin_detected_servers() {
        // The onboarding banner promises a count across BOTH client.servers and
        // client.plugin_servers (see importableServers in src/lib/types.ts); the
        // import used to only walk client.servers, silently dropping every
        // plugin-detected one (e.g. Cursor/Roo project-level scans) and leaving
        // the actual import far short of the promised count.
        let detected = vec![detected_client(
            "cursor",
            vec!["node_repl"],
            vec!["linear", "github", "figma"],
        )];
        let reg = Registry::default();
        let picked = servers_to_import(&detected, &reg);
        let names: std::collections::HashSet<_> =
            picked.iter().map(|s| s.name.to_lowercase()).collect();
        assert_eq!(names.len(), 4);
        assert!(names.contains("node_repl"));
        assert!(names.contains("linear"));
        assert!(names.contains("github"));
        assert!(names.contains("figma"));
    }

    #[test]
    fn servers_to_import_dedupes_by_name_across_clients_and_sources() {
        let detected = vec![
            detected_client("cursor", vec!["Linear"], vec!["linear"]),
            detected_client("claude-code", vec!["linear"], vec![]),
        ];
        let reg = Registry::default();
        let picked = servers_to_import(&detected, &reg);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name.to_lowercase(), "linear");
    }

    #[test]
    fn selected_servers_to_import_respects_the_reviewed_keys() {
        let detected = vec![detected_client(
            "cursor",
            vec!["linear", "github"],
            vec![],
        )];
        let selected = std::collections::HashSet::from(["name:github".to_string()]);
        let picked = selected_servers_to_import(&detected, &Registry::default(), Some(&selected));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "github");
    }

    #[test]
    fn servers_to_import_keeps_distinct_packages_with_the_same_friendly_name() {
        // Bare package-runner entries use the package-derived friendly name. The
        // scopes below both become "weather", but the runner invocations target
        // different packages and must survive bulk import as separate entries.
        let mut client = detected_client("cursor", vec![], vec![]);
        client.servers = vec![
            detected_mcp_server_with_args("weather", "npx", &["-y", "@acme/mcp-weather"]),
            detected_mcp_server_with_args("weather", "npx", &["-y", "@other/mcp-weather"]),
        ];
        let mut reg = Registry::default();
        let picked = servers_to_import(&[client], &reg);
        assert_eq!(picked.len(), 2);
        assert!(picked.iter().all(|server| server.name == "weather"));

        for server in picked {
            reg.add_server(server);
        }
        let ids: std::collections::HashSet<_> =
            reg.servers.iter().map(|server| server.id.as_str()).collect();
        assert_eq!(ids, std::collections::HashSet::from(["weather", "weather-2"]));
    }

    #[test]
    fn servers_to_import_keeps_same_package_under_distinct_names() {
        // A multi-account setup runs the SAME package twice under different
        // names (e.g. a personal and a work token). Keying on the package alone
        // would collapse them and silently drop one; the name tiebreaker keeps
        // both while still distinguishing different packages (see the test above).
        let mut client = detected_client("claude", vec![], vec![]);
        client.servers = vec![
            detected_mcp_server_with_args("github-personal", "npx", &["-y", "@mcp/server-github"]),
            detected_mcp_server_with_args("github-work", "npx", &["-y", "@mcp/server-github"]),
        ];
        let picked = servers_to_import(&[client], &Registry::default());
        assert_eq!(picked.len(), 2);
        let names: std::collections::HashSet<_> =
            picked.iter().map(|server| server.name.as_str()).collect();
        assert_eq!(
            names,
            std::collections::HashSet::from(["github-personal", "github-work"])
        );
    }

    #[test]
    fn servers_to_import_skips_existing_and_own_gateway_entry() {
        let detected = vec![detected_client(
            "cursor",
            vec!["already-here", clients::GATEWAY_ENTRY_NAME],
            vec!["new-one"],
        )];
        let mut reg = Registry::default();
        reg.add_server(plain_server("x", "already-here"));
        let picked = servers_to_import(&detected, &reg);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name, "new-one");
    }

    #[test]
    fn servers_to_import_skips_gateway_registered_under_a_different_name() {
        // Regression: a real config had the gateway entry named "toolport"
        // (not "conduit"), pointing at toolport-gateway.exe - a leftover from
        // before the rename or a manual add. The name-only check let it through
        // and imported the gateway as if it were a normal downstream server,
        // which risks the gateway proxying itself if ever enabled.
        let mut client = detected_client("claude-code", vec!["linear"], vec![]);
        client.servers.push(detected_mcp_server_with_command(
            "toolport",
            r"C:\Users\x\AppData\Local\Toolport\toolport-gateway.exe",
        ));
        let reg = Registry::default();
        let picked = servers_to_import(&[client], &reg);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].name.to_lowercase(), "linear");
    }

    #[test]
    fn oauth_lock_serializes_concurrent_attempts() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("conduit-oauth-lock-{unique}.lock"));
        let lock1 = try_acquire_oauth_lock(&path)
            .expect("first lock should not fail")
            .expect("first lock should be acquired");
        assert!(
            try_acquire_oauth_lock(&path)
                .expect("second lock should not fail")
                .is_none(),
            "second concurrent lock must wait"
        );
        drop(lock1);
        let lock2 = try_acquire_oauth_lock(&path)
            .expect("third lock should not fail")
            .expect("lock should be available after release");
        drop(lock2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn oauth_lock_key_is_stable_and_scoped() {
        let a = oauth_lock_key("srv-1", "https://mcp.example.com");
        let b = oauth_lock_key("srv-1", "https://mcp.example.com");
        let c = oauth_lock_key("srv-2", "https://mcp.example.com");
        assert_eq!(a, b, "same server identity must map to same lock key");
        assert_ne!(a, c, "different server identity must map to different lock keys");
    }


    #[test]
    fn oauth_waiter_uses_attempt_completion_id() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("conduit-oauth-lock-{unique}.lock"));

        let lock = try_acquire_oauth_lock(&path)
            .expect("lock acquisition should not fail")
            .expect("lock should be acquired");
        let attempt_id = lock.attempt_id.clone();

        let stale_attempt = format!("old-attempt-{unique}");
        let stale_done = oauth_completion_path(&path, &stale_attempt);
        std::fs::write(&stale_done, "done=1").expect("stale completion should be writable");
        assert!(
            !completion_exists(&path, &attempt_id),
            "completion from a prior attempt must not satisfy current waiter"
        );

        drop(lock);
        assert!(
            completion_exists(&path, &attempt_id),
            "lock drop should mark the specific attempt complete"
        );

        let _ = std::fs::remove_file(stale_done);
        let _ = std::fs::remove_file(oauth_completion_path(&path, &attempt_id));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_lock_replace_requires_same_observed_instance() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("conduit-oauth-lock-{unique}.lock"));

        let observed_id = format!("observed-{unique}");
        let fresh_id = format!("fresh-owner-{unique}");
        let contender_id = format!("contender-{unique}");
        std::fs::write(&path, oauth_lock_contents(&observed_id))
            .expect("initial lock write should work");
        let observed = read_oauth_lock_snapshot(&path)
            .expect("snapshot read should work")
            .expect("snapshot should exist");

        std::thread::sleep(Duration::from_millis(5));
        std::fs::write(&path, oauth_lock_contents(&fresh_id))
            .expect("fresh lock write should work");

        let replaced = try_replace_stale_lock(
            &path,
            &observed,
            &oauth_lock_contents(&contender_id),
            &contender_id,
        )
        .expect("replace check should not error");
        assert!(
            !replaced,
            "stale cleanup must not clobber a newly replaced lock"
        );

        let current = std::fs::read_to_string(&path).expect("current lock should be readable");
        assert!(
            current.contains(&format!("attempt_id={fresh_id}")),
            "fresh lock instance must remain intact"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tool_identities_attribute_alias_to_server_and_profiles() {
        use std::collections::{BTreeMap, BTreeSet};
        let servers = vec![plain_server("gh", "GitHub"), plain_server("my-server", "My Server")];
        let profiles = vec![Profile {
            id: "default".into(),
            name: "Default".into(),
            enabled_server_ids: vec!["gh".into()],
            tool_scope: Default::default(),
        }];
        let mut baselines = BTreeMap::new();
        let bl = |fp: &str, fs: u64, lc: u64| integrity::ToolBaseline {
            fingerprint: fp.into(),
            first_seen: fs,
            last_changed: lc,
        };
        baselines.insert("gh__create_issue".to_string(), bl("v2:abc", 100, 200));
        baselines.insert("my_server__do_thing".to_string(), bl("v2:def", 50, 60));
        baselines.insert("orphan_alias".to_string(), bl("v2:ghi", 1, 2));
        let quarantined: BTreeSet<String> =
            ["gh__create_issue".to_string()].into_iter().collect();

        let ids = build_tool_identities(&baselines, &quarantined, &servers, &profiles);
        let get = |a: &str| ids.iter().find(|i| i.alias == a).cloned().unwrap();

        let gh = get("gh__create_issue");
        assert_eq!(gh.server_id, "gh");
        assert_eq!(gh.server_name, "GitHub");
        assert_eq!(gh.upstream, "create_issue");
        assert_eq!(gh.profiles, vec!["Default".to_string()]);
        assert_eq!(gh.fingerprint, "v2:abc");
        assert!(gh.quarantined);

        // The REAL server id ("my-server") is recovered even though its exposed prefix
        // is the sanitized "my_server". Not enabled in any profile -> empty profiles.
        let my = get("my_server__do_thing");
        assert_eq!(my.server_id, "my-server");
        assert_eq!(my.upstream, "do_thing");
        assert!(my.profiles.is_empty());
        assert!(!my.quarantined);

        // An alias matching no server prefix is honestly left unattributed, not guessed.
        let orphan = get("orphan_alias");
        assert_eq!(orphan.server_id, "");
        assert_eq!(orphan.server_name, "");
        assert!(orphan.profiles.is_empty());
    }

    #[test]
    fn export_strips_secrets_and_excludes_gateway() {
        let mut reg = Registry::default();
        reg.add_server(github_with_secret());
        reg.add_server(ServerEntry {
            id: String::new(),
            name: "conduit".into(),
            transport: "stdio".into(),
            command: Some("conduit-gateway".into()),
            args: vec![],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });

        let doc = build_export(&reg, Some("Team setup"), Some("Our shared servers"), None);
        let serialized = serde_json::to_string(&doc).unwrap();
        // The secret value must never appear in a shared setup.
        assert!(!serialized.contains("sk-live-xyz"));
        let servers = doc["servers"].as_array().unwrap();
        // Gateway entry excluded.
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["env"][0]["value"], serde_json::Value::Null);
        // Optional label is carried through.
        assert_eq!(doc["name"], "Team setup");
        assert_eq!(doc["description"], "Our shared servers");

        // Selective share: a name filter includes only the matching servers, so a
        // user can share a focused stack instead of their whole setup.
        let shared_name = servers[0]["name"].as_str().unwrap().to_string();
        let subset = build_export(&reg, None, None, Some(&[shared_name]));
        assert_eq!(subset["servers"].as_array().unwrap().len(), 1);
        let empty = build_export(&reg, None, None, Some(&["does-not-exist".to_string()]));
        assert_eq!(empty["servers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn redact_url_userinfo_strips_credentials_only() {
        // Password AND token-as-username are both stripped; the host/path survive.
        assert_eq!(
            redact_url_userinfo("https://user:s3cr3t@mcp.example.com/mcp"),
            "https://<redacted>@mcp.example.com/mcp"
        );
        assert_eq!(
            redact_url_userinfo("https://gh_tok3n@api.example.com/v1?x=1"),
            "https://<redacted>@api.example.com/v1?x=1"
        );
        // No userinfo -> unchanged (host with '@' only after a '/' is not authority).
        assert_eq!(
            redact_url_userinfo("https://api.githubcopilot.com/mcp/"),
            "https://api.githubcopilot.com/mcp/"
        );
        assert_eq!(
            redact_url_userinfo("https://host.example.com/path/u@v"),
            "https://host.example.com/path/u@v"
        );
        // Non-URL input is returned verbatim.
        assert_eq!(redact_url_userinfo("not a url"), "not a url");
    }

    #[test]
    fn export_redacts_url_embedded_credentials() {
        // A remote server whose URL carries inline creds must not leak them in a share.
        let mut reg = Registry::default();
        reg.add_server(ServerEntry {
            id: "remote".into(),
            name: "Remote".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some("https://user:hunter2@mcp.example.com/mcp".into()),
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        let doc = build_export(&reg, None, None, None);
        let serialized = serde_json::to_string(&doc).unwrap();
        assert!(!serialized.contains("hunter2"), "url password leaked: {serialized}");
        assert_eq!(
            doc["servers"][0]["url"].as_str().unwrap(),
            "https://<redacted>@mcp.example.com/mcp"
        );
    }

    #[test]
    fn export_redacts_inline_secret_args() {
        // The connection-URI and inline-credential heuristics.
        assert!(arg_looks_secret("postgresql://admin:hunter2@db.example.com:5432/app"));
        assert!(arg_looks_secret("--dsn=postgres://u:p@h/db"));
        assert!(arg_looks_secret("PASSWORD=hunter2"));
        assert!(arg_looks_secret("Authorization: token=abc123"));
        // Legitimate args must NOT be redacted.
        assert!(!arg_looks_secret("-y"));
        assert!(!arg_looks_secret("@modelcontextprotocol/server-postgres"));
        assert!(!arg_looks_secret("--stdio"));
        assert!(!arg_looks_secret("https://api.githubcopilot.com/mcp/")); // no userinfo

        let mut reg = Registry::default();
        reg.add_server(ServerEntry {
            id: "pg".into(),
            name: "PostgreSQL".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![
                "-y".into(),
                "@modelcontextprotocol/server-postgres".into(),
                "postgresql://admin:hunter2@db.example.com:5432/app".into(),
            ],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        let doc = build_export(&reg, None, None, None);
        let serialized = serde_json::to_string(&doc).unwrap();
        // The password must never appear in a shared setup.
        assert!(!serialized.contains("hunter2"));
        let args = doc["servers"][0]["args"].as_array().unwrap();
        // Benign args are kept; only the credential-bearing one is redacted.
        assert_eq!(args[0], "-y");
        assert_eq!(args[1], "@modelcontextprotocol/server-postgres");
        assert_eq!(args[2], "<redacted>");
    }

    #[test]
    fn secret_arg_never_survives_export_then_import() {
        // End-to-end invariant: a credential pasted into args must not leak
        // through the full share path (export -> serialize -> import elsewhere).
        let mut reg = Registry::default();
        reg.add_server(ServerEntry {
            id: "pg".into(),
            name: "PostgreSQL".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![
                "-y".into(),
                "postgresql://admin:hunter2@db.example.com/app".into(),
            ],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        let json = serde_json::to_string(&build_export(&reg, None, None, None)).unwrap();
        let mut recipient = Registry::default();
        apply_import(&mut recipient, &json).unwrap();
        let imported = recipient
            .servers
            .iter()
            .find(|s| s.name == "PostgreSQL")
            .expect("server imported");
        assert!(
            imported.args.iter().all(|a| !a.contains("hunter2")),
            "secret leaked through export+import"
        );
        assert!(imported.args.iter().any(|a| a == "<redacted>"));
    }

    #[test]
    fn import_dedups_by_name_and_nulls_secrets() {
        let mut reg = Registry::default();
        reg.add_server(github_with_secret());
        let doc = r#"{"kind":"conduit-setup","version":1,"servers":[
            {"name":"github","transport":"stdio","command":"npx"},
            {"name":"Stripe","transport":"http","url":"https://x",
             "env":[{"key":"K","value":"shh","secret":true}]}
        ]}"#;
        apply_import(&mut reg, doc).unwrap();

        // "github" is deduped case-insensitively; only Stripe is added.
        assert_eq!(
            reg.servers
                .iter()
                .filter(|s| s.name.eq_ignore_ascii_case("github"))
                .count(),
            1
        );
        let stripe = reg.servers.iter().find(|s| s.name == "Stripe").unwrap();
        assert_eq!(stripe.env[0].value, None);
        assert_eq!(stripe.source.as_deref(), Some("shared"));
    }

    #[test]
    fn import_rejects_garbage() {
        let mut reg = Registry::default();
        assert!(apply_import(&mut reg, "{not json").is_err());
    }

    #[test]
    fn parse_share_url_extracts_id() {
        assert_eq!(
            parse_share_url("conduit://import?s=071g6i3h5f5g6h2i"),
            Some("071g6i3h5f5g6h2i".to_string())
        );
        // Tolerate a trailing slash after the host, and pick s out of many params.
        assert_eq!(
            parse_share_url("conduit://import/?ref=x&s=abc123"),
            Some("abc123".to_string())
        );
        // Reject the wrong action, missing id, and non-alphanumeric ids.
        assert_eq!(parse_share_url("conduit://other?s=abc"), None);
        assert_eq!(parse_share_url("conduit://import?x=1"), None);
        assert_eq!(parse_share_url("conduit://import?s=../etc"), None);
        assert_eq!(parse_share_url("https://example.com?s=abc"), None);
    }

    #[test]
    fn last_lines_returns_the_tail() {
        let text = "a\nb\nc\nd\ne";
        // Fewer requested than available: just the tail, newline-terminated.
        assert_eq!(last_lines(text, 2), "d\ne\n");
        // More requested than available: everything.
        assert_eq!(last_lines(text, 99), "a\nb\nc\nd\ne\n");
        // Empty input stays empty (no stray newline).
        assert_eq!(last_lines("", 10), "");
    }

    #[test]
    fn diagnostics_lists_env_keys_but_never_values() {
        let mut reg = Registry::default();
        reg.add_server(github_with_secret());
        let s = registry_summary(&reg);
        // The key is shown (with a secret marker) so a report says what's set...
        assert!(s.contains("TOKEN (secret)"), "got: {s}");
        // ...but the secret value itself must never appear in a pasted report.
        assert!(!s.contains("sk-live-xyz"), "secret value leaked: {s}");
        // The launch command is present for debugging.
        assert!(s.contains("(stdio) npx"), "missing launch line: {s}");
    }

    #[test]
    fn diagnostics_redacts_inline_arg_and_url_secrets() {
        let mut reg = Registry::default();
        reg.add_server(ServerEntry {
            id: "pg".into(),
            name: "Postgres".into(),
            transport: "stdio".into(),
            command: Some("npx".into()),
            args: vec![
                "@modelcontextprotocol/server-postgres".into(),
                "postgresql://admin:hunter2@db.example.com/app".into(),
                "--token=sk-live-xyz".into(),
                "https://api.example.com/path".into(),
            ],
            env: vec![],
            url: None,
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });
        reg.add_server(ServerEntry {
            id: "remote".into(),
            name: "Remote".into(),
            transport: "http".into(),
            command: None,
            args: vec![],
            env: vec![],
            url: Some("https://user:hunter2@mcp.example.com/mcp".into()),
            source: None,
            disabled_tools: vec![],
            cwd: None,
            unknown_fields: serde_json::Map::new(),
        });

        let s = registry_summary(&reg);
        assert!(!s.contains("hunter2"), "secret value leaked: {s}");
        assert!(!s.contains("sk-live-xyz"), "secret token leaked: {s}");
        assert!(s.contains("<redacted>"), "missing redaction marker: {s}");
        assert!(s.contains("https://api.example.com/path"), "safe URL was over-redacted: {s}");
    }
}
