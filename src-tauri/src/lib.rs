use std::sync::Mutex;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Listener, Manager, State};
use tauri_plugin_notification::NotificationExt;

pub mod approval;
mod approval_broker;
pub mod audit;
pub mod catalog;
pub mod clients;
pub mod downstream;
pub mod inspect;
pub mod integrity;
pub mod oauth;
pub mod registry;
pub mod remote;
pub mod router;
pub mod savings;
pub mod searchtrace;
pub mod semantic;
pub mod shaping;
pub mod secrets;
pub mod stacks;
pub mod teams;
pub mod vendors;

use downstream::{DownstreamServer, StdioTransport};
use registry::{Profile, Registry, ServerEntry};

type RegistryState = Mutex<Registry>;

/// Tracks the optional `conduit-gateway --http` child the app supervises so
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
        let t = StdioTransport::spawn(command, &server.args, &env)?;
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
    }
}

/// Pull servers from every detected client into the registry, skipping any whose
/// name already exists.
#[tauri::command]
async fn import_servers(state: State<'_, RegistryState>) -> Result<Registry, String> {
    let detected = tauri::async_runtime::spawn_blocking(clients::detect_clients)
        .await
        .map_err(|e| e.to_string())?;
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for client in &detected {
        for server in &client.servers {
            // Never import our own gateway entry (it would recurse).
            if server.name.eq_ignore_ascii_case(clients::GATEWAY_ENTRY_NAME) {
                continue;
            }
            let exists = reg
                .servers
                .iter()
                .any(|e| e.name.eq_ignore_ascii_case(&server.name));
            if !exists {
                reg.add_server(server_from_detected(server, &client.id));
            }
        }
    }
    registry::save(&reg)?;
    Ok(reg.clone())
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.add_server(entry);
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn update_server(state: State<RegistryState>, entry: ServerEntry) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.update_server(entry)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn remove_server(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.remove_server(&id)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn set_server_enabled(
    state: State<RegistryState>,
    profile_id: String,
    server_id: String,
    enabled: bool,
) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_server_enabled(&profile_id, &server_id, enabled)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn set_all_enabled(
    state: State<RegistryState>,
    profile_id: String,
    enabled: bool,
) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_all_enabled(&profile_id, enabled)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn create_profile(state: State<RegistryState>, name: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.add_profile(&name);
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn delete_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.remove_profile(&id)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn set_active_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_active_profile(&id)?;
    registry::save(&reg)?;
    Ok(reg.clone())
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_client_scope(&client_id, profile.as_deref());
    registry::save(&reg)?;
    Ok(outcome)
}

/// Remove the Toolport gateway from a client.
#[tauri::command]
fn uninstall_gateway(
    state: State<RegistryState>,
    client_id: String,
) -> Result<clients::WriteOutcome, String> {
    let outcome = clients::uninstall_gateway(&client_id)?;
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_client_scope(&client_id, None);
    registry::save(&reg)?;
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.http_clients.push(registry::HttpClient {
        id,
        label: label.trim().to_string(),
        token_sha256: registry::sha256_hex(&token),
        profile: profile.unwrap_or_default().trim().to_string(),
    });
    registry::save(&reg)?;
    Ok(AddedHttpClient {
        registry: reg.clone(),
        token,
    })
}

/// Remove a registered HTTP-bridge client (revokes its token).
#[tauri::command]
fn remove_http_client(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.http_clients.retain(|c| c.id != id);
    registry::save(&reg)?;
    Ok(reg.clone())
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

    let (imported, moved) = {
        let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut imported = 0;
        let mut moved = Vec::new();
        for server in &client.servers {
            if server.name.eq_ignore_ascii_case(clients::GATEWAY_ENTRY_NAME) {
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
        registry::save(&reg)?;
        (imported, moved)
    };

    // Rewrite the client to only the gateway (backs up first).
    clients::migrate_to_gateway(&client_id, profile.as_deref())?;

    // Record the scope now that the client config was rewritten to the gateway.
    let registry = {
        let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.set_client_scope(&client_id, profile.as_deref());
        registry::save(&reg)?;
        reg.clone()
    };

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
    secrets::set_secret(&server_id, &key, &value)?;
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Remove a secret from the keychain and drop the env var from the server entry.
#[tauri::command]
fn delete_secret(
    state: State<RegistryState>,
    server_id: String,
    key: String,
) -> Result<Registry, String> {
    secrets::delete_secret(&server_id, &key)?;
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(server) = reg.servers.iter_mut().find(|s| s.id == server_id) {
        server.env.retain(|e| e.key != key);
    }
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// The most recent tool-call audit entries (newest first).
#[tauri::command]
fn get_audit_log(limit: usize) -> Vec<serde_json::Value> {
    audit::read_recent(limit)
}

/// Aggregate the recent audit log into per-server call/error/latency stats for
/// the observability dashboard.
#[tauri::command]
fn audit_stats(window: usize) -> serde_json::Value {
    audit::stats(window)
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
    let _ = writeln!(out, "  deny destructive: {}", reg.deny_destructive);
    let _ = writeln!(out, "  active profile: {active}");

    let _ = writeln!(out, "\nservers ({}):", reg.servers.len());
    for s in &reg.servers {
        let on = if reg.is_enabled(&active, &s.id) { "on" } else { "off" };
        let target = match (&s.command, &s.url) {
            (Some(cmd), _) => format!("{cmd} {}", s.args.join(" ")).trim().to_string(),
            (None, Some(url)) => url.clone(),
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

/// Connect to each enabled server in the active profile and report health + tool count.
#[tauri::command]
async fn probe_servers(state: State<'_, RegistryState>) -> Result<Vec<ProbeResult>, String> {
    // Snapshot which servers to probe, then drop the lock before any I/O.
    let servers: Vec<ServerEntry> = {
        let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.enabled_servers()
            .into_iter()
            .filter(|s| !clients::is_gateway_server(s))
            .cloned()
            .collect()
    };
    // Probe concurrently on worker threads so the UI thread never blocks.
    tauri::async_runtime::spawn_blocking(move || {
        let handles: Vec<_> = servers
            .into_iter()
            .map(|s| std::thread::spawn(move || probe_one(&s)))
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_tool_enabled(&server_id, &tool, enabled)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Flip the global destructive-tool deny switch. When on, the gateway hides and
/// blocks every tool annotated `destructiveHint: true` across all servers.
#[tauri::command]
fn set_deny_destructive(state: State<RegistryState>, deny: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_deny_destructive(deny);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Toggle per-call confirmation for destructive tools. When enabled, the gateway
/// intercepts each destructive tool call, returns a preview with a token, and
/// requires `conduit_confirm { token }` to proceed. Mutually exclusive with
/// `deny_destructive` (confirm turns deny off).
#[tauri::command]
fn set_confirm_destructive(state: State<RegistryState>, confirm: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_confirm_destructive(confirm);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Toggle human-in-the-loop approval. When on, a gated tool call (destructive, or from an
/// untrusted-provenance server) is HELD until a person approves or denies it in the app,
/// via the approval broker. Distinct from confirm-destructive (which the agent re-confirms).
#[tauri::command]
fn set_human_approval(state: State<RegistryState>, on: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_human_approval(on);
    registry::save(&reg)?;
    Ok(reg.clone())
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
        let key = approval::allow_key(&view.server, &view.tool);
        broker.add_session_allow(key.clone());
        if scope == "always" {
            let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.allow_tool(key);
            registry::save(&reg)?;
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
    let split = |key: &str| match key.split_once('/') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => (String::new(), key.to_string()),
    };
    let mut out: Vec<AllowedTool> = persistent
        .iter()
        .map(|k| {
            let (server, tool) = split(k);
            AllowedTool { key: k.clone(), server, tool, persistent: true }
        })
        .collect();
    for k in broker.session_allowed() {
        if !persistent.contains(&k) {
            let (server, tool) = split(&k);
            out.push(AllowedTool { key: k, server, tool, persistent: false });
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
    {
        let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.revoke_tool(&key);
        registry::save(&reg)?;
    }
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_tool_override(
        server,
        tool,
        registry::ToolOverride { name: norm(name), description: norm(description) },
    );
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Remove a tool's exposure override, restoring the server's own name and description.
#[tauri::command]
fn clear_tool_override(
    state: State<RegistryState>,
    server: String,
    tool: String,
) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.clear_tool_override(&server, &tool);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Toggle live request/response inspection. When enabled, the gateway captures each
/// tool call's args + result into a small, separate, ephemeral local ring
/// (`inspect.jsonl`, last 50 calls, each body size-capped) that the Activity view can
/// show. Off by default; the governance audit log is never touched by this. Turning
/// it off in the UI should also clear the ring (see `clear_inspect_log`).
#[tauri::command]
fn set_live_inspect(state: State<RegistryState>, enabled: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_live_inspect(enabled);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// The most recent live-inspection captures (newest first): each tool call's args and
/// result, only present while live inspection has been on. Empty when off/unused.
#[tauri::command]
fn get_inspect_log(limit: usize) -> Vec<serde_json::Value> {
    inspect::read_recent(limit)
}

/// Clear the live-inspection ring (delete `inspect.jsonl`), so no captured args/results
/// linger. Called when the user turns live inspection off.
#[tauri::command]
fn clear_inspect_log() -> Result<(), String> {
    inspect::clear();
    Ok(())
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
    searchtrace::clear();
    Ok(())
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
/// profile, newest-changed first. Empty until the gateway has pinned a baseline.
#[tauri::command]
fn list_tool_identities(state: State<RegistryState>) -> Vec<ToolIdentity> {
    let reg = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let profile = reg.active_profile_id.as_deref();
    let mut ids = build_tool_identities(
        &integrity::baselines(profile),
        &integrity::quarantined(profile),
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.quarantine_on_drift = on;
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Tools currently quarantined (blocked after a high-risk drift), across all profiles.
#[tauri::command]
fn list_quarantined() -> Vec<serde_json::Value> {
    integrity::all_quarantined()
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
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    registry::save(&reg)?;
    Ok(())
}

/// Set lazy discovery globally. The gateway reads this from the registry, so it
/// takes effect for every client (including ones that don't forward env vars).
/// Clients pick it up the next time they (re)spawn the gateway.
#[tauri::command]
fn set_lazy_discovery(state: State<RegistryState>, lazy: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.set_lazy_discovery(lazy);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Opt into agent control: lets an agent enable or disable servers through the
/// gateway's `conduit_enable_server` / `conduit_disable_server` tools. Off by
/// default; the destructive-tool safety switch stays user-only regardless of this.
#[tauri::command]
fn set_allow_agent_control(state: State<RegistryState>, allow: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    reg.allow_agent_control = allow;
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Flush the in-memory registry to disk so the teams module (which reads the registry
/// file) operates on the current state, then refresh the in-memory state from disk
/// after the team operation merged into it.
fn flush_to_disk(state: &RegistryState) -> Result<(), String> {
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    registry::save(&reg)
}

fn reload_into_state(state: &RegistryState) -> Result<Registry, String> {
    let fresh = registry::load()?;
    *state.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = fresh.clone();
    Ok(fresh)
}

/// Join a Toolport Teams server with an invite code. Vaults the member token in the OS
/// keychain, pulls the team's server set, and merges it into the local registry
/// non-destructively (team servers are tagged and enabled in the active profile).
#[tauri::command]
fn team_connect(
    app: tauri::AppHandle,
    state: State<RegistryState>,
    server_url: String,
    invite_code: String,
    member_name: Option<String>,
) -> Result<Registry, String> {
    flush_to_disk(state.inner())?;
    let outcome = teams::connect(&server_url, &invite_code, member_name.as_deref())?;
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    // Team config adds local/stdio + LAN servers OFF (the member reviews + enables them)
    // and refuses link-local/metadata URLs. Surface both so the state is never a mystery.
    emit_team_review(&app, outcome);
    Ok(fresh)
}

/// Pull the latest team config and re-merge it. A no-op when nothing changed.
#[tauri::command]
fn team_sync(app: tauri::AppHandle, state: State<RegistryState>) -> Result<Registry, String> {
    flush_to_disk(state.inner())?;
    let outcome = teams::sync_now()?.map(|(_, o)| o).unwrap_or_default();
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    emit_team_review(&app, outcome);
    Ok(fresh)
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

/// Leave the team: remove its merged servers, clear the connection and the token.
#[tauri::command]
fn team_disconnect(state: State<RegistryState>) -> Result<Registry, String> {
    flush_to_disk(state.inner())?;
    teams::disconnect()?;
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    Ok(fresh)
}

/// Admin: push the current local server set as the team's shared config (own servers
/// only, secret values never sent). Returns the new config version.
#[tauri::command]
fn team_push(state: State<RegistryState>) -> Result<i64, String> {
    flush_to_disk(state.inner())?;
    teams::push_current()
}

/// Re-save the registry to bump its mtime. The running gateway watches that file
/// and rebuilds on change, so freshly-vaulted credentials take effect (and the
/// server's tools flow to connected clients) without a manual restart.
fn nudge_gateway(state: &RegistryState) {
    // Recover from a poisoned lock like every other command does; otherwise a
    // poisoned mutex would skip this re-save and freshly-vaulted credentials would
    // silently never propagate to the running gateway.
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = registry::save(&reg);
}

/// Store a bearer token for an http server (used as `Authorization: Bearer ...`).
#[tauri::command]
fn set_auth_token(
    state: State<RegistryState>,
    server_id: String,
    token: String,
) -> Result<(), String> {
    secrets::set_secret(&server_id, secrets::HTTP_AUTH_KEY, &token)?;
    nudge_gateway(state.inner());
    Ok(())
}

#[tauri::command]
fn clear_auth_token(state: State<RegistryState>, server_id: String) -> Result<(), String> {
    secrets::delete_secret(&server_id, secrets::HTTP_AUTH_KEY)?;
    nudge_gateway(state.inner());
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
    )?;
    nudge_gateway(state.inner());
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
    tauri::async_runtime::spawn_blocking(move || Ok(catalog::search(&query)))
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
    let mut reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    apply_import(&mut reg, &json)?;
    registry::save(&reg)?;
    Ok(reg.clone())
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
    name: String,
    transport: String,
    command: Option<String>,
    args: Vec<String>,
    url: Option<String>,
    /// False if a server with this name already exists (the import would skip it).
    is_new: bool,
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

/// True when a command argument looks like it carries a secret: an inline
/// credential param (password=, token=, ...) or a connection URI with embedded
/// userinfo (scheme://user:pass@host). Used to redact args before sharing, since
/// some servers (e.g. Postgres) take a connection string with a password in args.
/// Biased toward over-redacting: for a share, a false positive is harmless.
fn arg_looks_secret(arg: &str) -> bool {
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
        if let Some((userinfo, _host)) = authority.rsplit_once('@') {
            if userinfo.contains(':') {
                return true;
            }
        }
    }
    false
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

/// Start `conduit-gateway --http <port>` as a supervised child so HTTP/OpenAPI
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
        .ok_or_else(|| "conduit-gateway binary not found next to the app".to_string())?;
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

/// Bring the main window back to the foreground (from the tray, a re-launch, or an
/// approval). Un-hides, un-minimizes, and focuses so it works from every hidden state.
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
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
            import_servers,
            parse_server_snippet,
            add_server,
            update_server,
            remove_server,
            set_server_enabled,
            create_profile,
            delete_profile,
            set_active_profile,
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
            list_tool_identities,
            set_quarantine_on_drift,
            list_quarantined,
            release_quarantine,
            set_lazy_discovery,
            set_allow_agent_control,
            team_connect,
            team_sync,
            team_disconnect,
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
            share_stack,
            fetch_shared_setup,
            take_pending_shared,
            import_config,
            read_setup_file,
            preview_import,
            start_http_bridge,
            stop_http_bridge,
            http_bridge_status,
        ])
        // Close-to-tray: the window's X hides it instead of quitting, so the gateway and
        // approval broker keep running (HITL only works while the app is alive). Quit is
        // explicit, from the tray menu. A one-time notification explains it the first time.
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
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
            if !start_hidden {
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
        });
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
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
        }
    }

    #[test]
    fn tool_identities_attribute_alias_to_server_and_profiles() {
        use std::collections::{BTreeMap, BTreeSet};
        let servers = vec![plain_server("gh", "GitHub"), plain_server("my-server", "My Server")];
        let profiles = vec![Profile {
            id: "default".into(),
            name: "Default".into(),
            enabled_server_ids: vec!["gh".into()],
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
}
