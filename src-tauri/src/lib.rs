use std::sync::Mutex;

use tauri::{Emitter, Manager, State};

pub mod audit;
pub mod catalog;
pub mod clients;
pub mod downstream;
pub mod integrity;
pub mod oauth;
pub mod registry;
pub mod remote;
pub mod router;
pub mod savings;
pub mod semantic;
pub mod shaping;
pub mod secrets;
pub mod teams;
pub mod vendors;

use downstream::{DownstreamServer, StdioTransport};
use registry::{Registry, ServerEntry};

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

/// Install the Conduit gateway into a client (one click "connect to Conduit").
/// `profile` scopes that client to one profile (None = all enabled servers).
#[tauri::command]
fn install_gateway(
    client_id: String,
    profile: Option<String>,
) -> Result<clients::WriteOutcome, String> {
    clients::install_gateway(&client_id, profile.as_deref())
}

/// Remove the Conduit gateway from a client.
#[tauri::command]
fn uninstall_gateway(client_id: String) -> Result<clients::WriteOutcome, String> {
    clients::uninstall_gateway(&client_id)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrateResult {
    registry: Registry,
    /// How many of the client's servers were newly imported into Conduit.
    imported: usize,
    /// Names of the servers moved out of the client's config.
    moved: Vec<String>,
}

/// Migrate a client to Conduit: import its directly-configured servers into the
/// registry, then rewrite the client's config to contain only the Conduit
/// gateway (optionally scoped to `profile`). The client is left managing nothing
/// directly - everything routes through Conduit. Backs the config up first.
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

    let (registry, imported, moved) = {
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
        (reg.clone(), imported, moved)
    };

    // Rewrite the client to only the gateway (backs up first).
    clients::migrate_to_gateway(&client_id, profile.as_deref())?;

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

/// A shareable diagnostics blob for bug reports: Conduit version + OS, a
/// secrets-stripped registry summary, and the tail of the always-on gateway log.
/// Safe to paste into a public issue, secret values live in the OS keychain and
/// are never included; env vars are listed by key name only.
#[tauri::command]
fn gather_diagnostics() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Conduit diagnostics");
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
        let result = ds.call(&tool, arguments);
        let ms = started.elapsed().as_millis() as u64;
        // Mirror the gateway's success accounting: a result with isError=true is
        // a failed call even though the transport round-tripped fine.
        let ok = result
            .as_ref()
            .map(|r| !r.get("isError").and_then(|v| v.as_bool()).unwrap_or(false))
            .unwrap_or(false);
        audit::record_timed(&server.id, &tool, ok, Some(ms));
        result
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

/// Join a Conduit Teams server with an invite code. Vaults the member token in the OS
/// keychain, pulls the team's server set, and merges it into the local registry
/// non-destructively (team servers are tagged and enabled in the active profile).
#[tauri::command]
fn team_connect(
    state: State<RegistryState>,
    server_url: String,
    invite_code: String,
    member_name: Option<String>,
) -> Result<Registry, String> {
    flush_to_disk(state.inner())?;
    teams::connect(&server_url, &invite_code, member_name.as_deref())?;
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    Ok(fresh)
}

/// Pull the latest team config and re-merge it. A no-op when nothing changed.
#[tauri::command]
fn team_sync(state: State<RegistryState>) -> Result<Registry, String> {
    flush_to_disk(state.inner())?;
    teams::sync_now()?;
    let fresh = reload_into_state(state.inner())?;
    nudge_gateway(state.inner());
    Ok(fresh)
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

/// Open Conduit's data directory (registry, logs, audit) in the OS file manager,
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
) -> Result<String, String> {
    let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    serde_json::to_string_pretty(&build_export(&reg, name.as_deref(), description.as_deref()))
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
) -> Result<(), String> {
    let json = {
        let reg = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        serde_json::to_string_pretty(&build_export(&reg, name.as_deref(), description.as_deref()))
            .map_err(|e| e.to_string())?
    };
    std::fs::write(&path, json).map_err(|e| format!("Couldn't write the file: {e}"))
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
            return Err("That file is too large to be a Conduit setup.".to_string());
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
        .map_err(|e| format!("That doesn't look like a Conduit setup: {e}"))?;
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

/// Build a shareable setup document: server definitions only, with the gateway
/// entry excluded and every secret value stripped. Pure, so the never-leak-a-key
/// invariant is testable without Tauri state.
fn build_export(
    reg: &Registry,
    name: Option<&str>,
    description: Option<&str>,
) -> serde_json::Value {
    let servers: Vec<ServerEntry> = reg
        .servers
        .iter()
        .filter(|s| !clients::is_gateway_server(s))
        .map(|s| {
            let mut s = s.clone();
            s.id = String::new();
            for e in &mut s.env {
                e.value = None; // never share env values
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
        .map_err(|e| format!("That doesn't look like a Conduit setup: {e}"))?;
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
    let Some(path) = registry::registry_path() else {
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let registry = registry::load().unwrap_or_default();

    // Migrate legacy (ACL-bearing) keychain entries in the background. On macOS,
    // older versions of Conduit created keychain items via the `keyring` crate,
    // which attaches per-app ACLs that trigger repeated password prompts. This
    // reads each entry's value, deletes it, and re-creates it via the ACL-free
    // SecItemAdd path — no secret values are lost. Guarded by a marker file so it
    // runs exactly once. Only the app runs this (the gateway can't read legacy
    // entries without triggering prompts). Best-effort: failures are logged but
    // never block startup.
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
            let report = secrets::migrate_legacy_entries(&keys);
            if report.migrated > 0 || report.failed > 0 {
                eprintln!(
                    "conduit: keychain migration complete ({} entries rewritten, {} failed, {} not found)",
                    report.migrated, report.failed, report.not_found
                );
            }
        });
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(registry))
        .manage(Mutex::new(HttpBridge::default()))
        .invoke_handler(tauri::generate_handler![
            detect_clients,
            get_registry,
            import_servers,
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
            list_server_tools,
            call_tool,
            set_tool_enabled,
            set_deny_destructive,
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
            search_catalog,
            open_data_dir,
            set_all_enabled,
            export_config,
            export_config_to_path,
            import_config,
            read_setup_file,
            preview_import,
            start_http_bridge,
            stop_http_bridge,
            http_bridge_status,
        ])
        .setup(|app| {
            // Mirror external registry changes (an agent toggling a server through
            // the gateway) back into the app and the UI, in a background thread.
            let handle = app.handle().clone();
            std::thread::spawn(move || watch_registry_for_app(handle));
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

        let doc = build_export(&reg, Some("Team setup"), Some("Our shared servers"));
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
