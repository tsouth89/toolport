use std::sync::Mutex;

use tauri::State;

pub mod audit;
pub mod catalog;
pub mod clients;
pub mod downstream;
pub mod oauth;
pub mod registry;
pub mod remote;
pub mod router;
pub mod secrets;
pub mod vendors;

use downstream::{DownstreamServer, StdioTransport};
use registry::{Registry, ServerEntry};

type RegistryState = Mutex<Registry>;

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
    } else if let Some(url) = &server.url {
        remote::connect_remote(&server.id, url)
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
    state.lock().unwrap().clone()
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
    let mut reg = state.lock().unwrap();
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
    let mut reg = state.lock().unwrap();
    reg.add_server(entry);
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn update_server(state: State<RegistryState>, entry: ServerEntry) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
    reg.update_server(entry)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn remove_server(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
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
    let mut reg = state.lock().unwrap();
    reg.set_server_enabled(&profile_id, &server_id, enabled)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn create_profile(state: State<RegistryState>, name: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
    reg.add_profile(&name);
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn delete_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
    reg.remove_profile(&id)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

#[tauri::command]
fn set_active_profile(state: State<RegistryState>, id: String) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
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
        let mut reg = state.lock().unwrap();
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
    let mut reg = state.lock().unwrap();
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
    let mut reg = state.lock().unwrap();
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

/// Connect to each enabled server in the active profile and report health + tool count.
#[tauri::command]
async fn probe_servers(state: State<'_, RegistryState>) -> Result<Vec<ProbeResult>, String> {
    // Snapshot which servers to probe, then drop the lock before any I/O.
    let servers: Vec<ServerEntry> = {
        let reg = state.lock().unwrap();
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
    let reg = state.lock().unwrap();
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
    let mut reg = state.lock().unwrap();
    reg.set_tool_enabled(&server_id, &tool, enabled)?;
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Flip the global destructive-tool deny switch. When on, the gateway hides and
/// blocks every tool annotated `destructiveHint: true` across all servers.
#[tauri::command]
fn set_deny_destructive(state: State<RegistryState>, deny: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
    reg.set_deny_destructive(deny);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Set lazy discovery globally. The gateway reads this from the registry, so it
/// takes effect for every client (including ones that don't forward env vars).
/// Clients pick it up the next time they (re)spawn the gateway.
#[tauri::command]
fn set_lazy_discovery(state: State<RegistryState>, lazy: bool) -> Result<Registry, String> {
    let mut reg = state.lock().unwrap();
    reg.set_lazy_discovery(lazy);
    registry::save(&reg)?;
    Ok(reg.clone())
}

/// Re-save the registry to bump its mtime. The running gateway watches that file
/// and rebuilds on change, so freshly-vaulted credentials take effect (and the
/// server's tools flow to connected clients) without a manual restart.
fn nudge_gateway(state: &RegistryState) {
    if let Ok(reg) = state.lock() {
        let _ = registry::save(&reg);
    }
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

/// The popular catalog (the user's promoted picks + the curated set).
#[tauri::command]
fn popular_catalog() -> Vec<catalog::CatalogEntry> {
    catalog::popular()
}

/// Promote one of the user's registry servers into their personal catalog, so it
/// shows up (and is searchable) under popular picks.
#[tauri::command]
fn promote_to_catalog(state: State<RegistryState>, server_id: String) -> Result<(), String> {
    let reg = state.lock().unwrap();
    let server = reg
        .servers
        .iter()
        .find(|s| s.id == server_id)
        .ok_or_else(|| format!("No server with id '{server_id}'"))?;
    let entry = catalog::CatalogEntry {
        name: server.name.clone(),
        description: "Added from your servers.".to_string(),
        transport: server.transport.clone(),
        command: server.command.clone(),
        args: server.args.clone(),
        url: server.url.clone(),
        env_keys: server.env.iter().map(|e| e.key.clone()).collect(),
        source: "user".to_string(),
        homepage: None,
        publisher: None,
    };
    catalog::promote(entry)
}

/// Remove an entry from the user's personal catalog by name.
#[tauri::command]
fn unpromote_from_catalog(name: String) -> Result<(), String> {
    catalog::unpromote(&name)
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

/// The latest published release tag on GitHub (e.g. "v0.3.1"), for an
/// update-available hint. Network/parse failures are returned as Err and the UI
/// simply shows no update info.
#[tauri::command]
async fn latest_release() -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let body: serde_json::Value =
            ureq::get("https://api.github.com/repos/tsouth89/conduit/releases/latest")
                .set("User-Agent", "conduit-app")
                .timeout(std::time::Duration::from_secs(10))
                .call()
                .map_err(|e| e.to_string())?
                .into_json()
                .map_err(|e| e.to_string())?;
        body.get("tag_name")
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| "no tag_name in response".to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let registry = registry::load().unwrap_or_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(registry))
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
            probe_servers,
            list_server_tools,
            call_tool,
            set_tool_enabled,
            set_deny_destructive,
            set_lazy_discovery,
            set_auth_token,
            clear_auth_token,
            has_auth_token,
            authenticate_oauth,
            probe_auth,
            popular_catalog,
            search_catalog,
            promote_to_catalog,
            unpromote_from_catalog,
            latest_release,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
