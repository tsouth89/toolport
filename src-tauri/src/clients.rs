//! Client adapter layer.
//!
//! Each supported MCP client stores its servers in its own file, in its own
//! location, in its own format. This module knows how to find each client's
//! config and read its servers into one canonical shape, so the rest of the
//! app never has to care about per-client differences.
//!
//! Security note: we surface env-variable *names* but never their *values*.
//! Those values are secrets (API keys, tokens) and must not leak to the UI.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::registry::ServerEntry;

/// One MCP server, normalized across every client format.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServer {
    pub name: String,
    /// "stdio" | "http" | "sse" | "unknown"
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    /// Names of env vars only. Values are deliberately omitted (secrets).
    pub env_keys: Vec<String>,
    pub url: Option<String>,
}

/// The result of probing a single client on this machine.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedClient {
    pub id: String,
    pub name: String,
    /// True for clients that manage servers through a UI/account connector system
    /// (Claude Desktop) rather than the local config file. Their file-based count
    /// is misleading, so the UI shows a connector indicator instead.
    pub uses_connectors: bool,
    pub config_path: String,
    pub config_exists: bool,
    pub servers: Vec<McpServer>,
    /// Servers that live outside the main config file but are still readable
    /// (e.g. Cursor plugin servers). Read-only inventory - managed by the client.
    pub plugin_servers: Vec<McpServer>,
    /// Whether the Conduit gateway is currently installed in this client's config.
    pub gateway_installed: bool,
    /// Set when the config exists but could not be read or parsed.
    pub error: Option<String>,
}

/// How a given client stores its server list.
#[derive(Clone, Copy)]
enum Format {
    /// JSON with a top-level `mcpServers` object (Claude Desktop, Cursor, Windsurf).
    JsonMcpServers,
    /// JSON with a top-level `servers` object (VS Code).
    JsonServers,
    /// TOML with `[mcp_servers.<name>]` tables (Codex CLI).
    TomlMcpServers,
}

struct ClientDef {
    id: &'static str,
    name: &'static str,
    format: Format,
    uses_connectors: bool,
    /// Resolves the absolute config path for the current OS, if determinable.
    path: fn() -> Option<PathBuf>,
    /// Optional scan for servers stored outside the main config file but still
    /// readable (e.g. Cursor plugin manifests).
    plugin_scan: Option<fn() -> Vec<McpServer>>,
}

/// The name Conduit uses for its own entry when installed into a client config.
pub const GATEWAY_ENTRY_NAME: &str = "conduit";

/// Whether a registry entry refers to Conduit's own gateway. The gateway must
/// never proxy itself (that recurses), and import must never pull it in.
pub fn is_gateway_server(server: &ServerEntry) -> bool {
    server.id == GATEWAY_ENTRY_NAME
        || server.name.eq_ignore_ascii_case(GATEWAY_ENTRY_NAME)
        || server
            .command
            .as_deref()
            .map(|c| c.to_lowercase().contains("conduit-gateway"))
            .unwrap_or(false)
}

fn home() -> Option<PathBuf> {
    dirs::home_dir()
}

/// Roaming app config dir: `%APPDATA%` on Windows,
/// `~/Library/Application Support` on macOS, `~/.config` on Linux.
fn config() -> Option<PathBuf> {
    dirs::config_dir()
}

fn claude_desktop_path() -> Option<PathBuf> {
    Some(config()?.join("Claude").join("claude_desktop_config.json"))
}

fn cursor_path() -> Option<PathBuf> {
    Some(home()?.join(".cursor").join("mcp.json"))
}

fn vscode_path() -> Option<PathBuf> {
    Some(config()?.join("Code").join("User").join("mcp.json"))
}

fn windsurf_path() -> Option<PathBuf> {
    Some(
        home()?
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
    )
}

fn codex_path() -> Option<PathBuf> {
    Some(home()?.join(".codex").join("config.toml"))
}

fn claude_code_path() -> Option<PathBuf> {
    Some(home()?.join(".claude.json"))
}

fn gemini_cli_path() -> Option<PathBuf> {
    Some(home()?.join(".gemini").join("settings.json"))
}

/// Google Antigravity reads MCP servers from `mcp_config.json` under `~/.gemini`.
/// The subdir has shifted across versions (`config`, `antigravity-ide`,
/// `antigravity`) and installers leave empty decoy files in the unused ones, so
/// prefer whichever actually has content; otherwise default to `config` (what
/// current Antigravity writes).
fn antigravity_path() -> Option<PathBuf> {
    let base = home()?.join(".gemini");
    let candidates = ["config", "antigravity-ide", "antigravity"];
    for dir in candidates {
        let p = base.join(dir).join("mcp_config.json");
        if std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false) {
            return Some(p);
        }
    }
    Some(base.join("config").join("mcp_config.json"))
}

/// A file under a VS Code extension's globalStorage settings dir.
fn vscode_globalstorage(ext: &str, file: &str) -> Option<PathBuf> {
    Some(
        config()?
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join(ext)
            .join("settings")
            .join(file),
    )
}

fn cline_path() -> Option<PathBuf> {
    vscode_globalstorage("saoudrizwan.claude-dev", "cline_mcp_settings.json")
}

fn roo_code_path() -> Option<PathBuf> {
    vscode_globalstorage("rooveterinaryinc.roo-cline", "mcp_settings.json")
}

fn cursor_plugins_dir() -> Option<PathBuf> {
    Some(home()?.join(".cursor").join("plugins").join("cache"))
}

fn collect_mcp_files(dir: &Path, out: &mut Vec<PathBuf>, depth: u32) {
    if depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "node_modules" || name == ".git" {
                continue;
            }
            collect_mcp_files(&path, out, depth - 1);
        } else {
            let fname = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
            if fname == "mcp.json" || fname == ".mcp.json" {
                out.push(path);
            }
        }
    }
}

/// Read Cursor's plugin MCP servers from `~/.cursor/plugins/cache/**/mcp.json`.
/// Two shapes appear: `{ "<name>": {...} }` and `{ "mcpServers": { ... } }`.
fn scan_cursor_plugins() -> Vec<McpServer> {
    let dir = match cursor_plugins_dir() {
        Some(d) => d,
        None => return Vec::new(),
    };
    if !dir.exists() {
        return Vec::new();
    }
    let mut files = Vec::new();
    collect_mcp_files(&dir, &mut files, 8);

    let mut servers: Vec<McpServer> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for path in files {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let value: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let map = value
            .get("mcpServers")
            .and_then(|v| v.as_object())
            .or_else(|| value.as_object());
        if let Some(obj) = map {
            for (name, def) in obj {
                if def.is_object() && seen.insert(name.clone()) {
                    servers.push(json_server(name, def));
                }
            }
        }
    }
    servers.sort_by_key(|s| s.name.to_lowercase());
    servers
}

fn defs() -> Vec<ClientDef> {
    vec![
        ClientDef {
            id: "claude-desktop",
            name: "Claude Desktop",
            format: Format::JsonMcpServers,
            uses_connectors: true,
            path: claude_desktop_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "cursor",
            name: "Cursor",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: cursor_path,
            plugin_scan: Some(scan_cursor_plugins),
        },
        ClientDef {
            id: "vscode",
            name: "VS Code",
            format: Format::JsonServers,
            uses_connectors: false,
            path: vscode_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "windsurf",
            name: "Windsurf",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: windsurf_path,
            plugin_scan: None,
        },
        ClientDef {
            // The Codex CLI and the Codex desktop app share ~/.codex/config.toml.
            id: "codex",
            name: "Codex",
            format: Format::TomlMcpServers,
            uses_connectors: false,
            path: codex_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "antigravity",
            name: "Antigravity",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: antigravity_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "claude-code",
            name: "Claude Code",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: claude_code_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "gemini-cli",
            name: "Gemini CLI",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: gemini_cli_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "cline",
            name: "Cline",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: cline_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "roo-code",
            name: "Roo Code",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: roo_code_path,
            plugin_scan: None,
        },
    ]
}

/// Classify transport from the presence of `command` vs `url` and an optional
/// explicit `type`/transport hint.
fn classify(command: &Option<String>, url: &Option<String>, type_hint: Option<&str>) -> String {
    if command.is_some() {
        "stdio".to_string()
    } else if url.is_some() {
        match type_hint {
            Some("sse") => "sse".to_string(),
            Some("http") | Some("streamable-http") => "http".to_string(),
            _ => "http".to_string(),
        }
    } else {
        "unknown".to_string()
    }
}

fn json_server(name: &str, def: &serde_json::Value) -> McpServer {
    let command = def.get("command").and_then(|c| c.as_str()).map(String::from);
    // Standard MCP uses `url`; Windsurf/Antigravity use `serverUrl` for remotes.
    let url = def
        .get("url")
        .or_else(|| def.get("serverUrl"))
        .and_then(|u| u.as_str())
        .map(String::from);
    let args = def
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let env_keys = def
        .get("env")
        .and_then(|e| e.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    let type_hint = def.get("type").and_then(|t| t.as_str());
    let transport = classify(&command, &url, type_hint);
    McpServer {
        name: name.to_string(),
        transport,
        command,
        args,
        env_keys,
        url,
    }
}

fn parse_json(content: &str, key: &str) -> Result<Vec<McpServer>, String> {
    let value: serde_json::Value = serde_json::from_str(content).map_err(|e| e.to_string())?;
    let obj = match value.get(key).and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };

    let mut servers: Vec<McpServer> = obj.iter().map(|(name, def)| json_server(name, def)).collect();
    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

fn parse_toml(content: &str) -> Result<Vec<McpServer>, String> {
    let value: toml::Value = toml::from_str(content).map_err(|e| e.to_string())?;
    let table = match value.get("mcp_servers").and_then(|v| v.as_table()) {
        Some(t) => t,
        None => return Ok(Vec::new()),
    };

    let mut servers: Vec<McpServer> = table
        .iter()
        .map(|(name, def)| {
            let command = def.get("command").and_then(|c| c.as_str()).map(String::from);
            let url = def.get("url").and_then(|u| u.as_str()).map(String::from);
            let args = def
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let env_keys = def
                .get("env")
                .and_then(|e| e.as_table())
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default();
            let transport = classify(&command, &url, None);
            McpServer {
                name: name.clone(),
                transport,
                command,
                args,
                env_keys,
                url,
            }
        })
        .collect();

    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

fn read_client(def: &ClientDef) -> DetectedClient {
    let plugin_servers = def.plugin_scan.map(|scan| scan()).unwrap_or_default();

    let build = |config_path: String,
                 config_exists: bool,
                 servers: Vec<McpServer>,
                 error: Option<String>| {
        let gateway_installed = servers.iter().any(|s| s.name == GATEWAY_ENTRY_NAME);
        DetectedClient {
            id: def.id.to_string(),
            name: def.name.to_string(),
            uses_connectors: def.uses_connectors,
            config_path,
            config_exists,
            servers,
            plugin_servers: plugin_servers.clone(),
            gateway_installed,
            error,
        }
    };

    let path = match (def.path)() {
        Some(p) => p,
        None => {
            return build(
                String::new(),
                false,
                Vec::new(),
                Some("Could not resolve a config path on this OS".to_string()),
            )
        }
    };
    let config_path = path.display().to_string();

    if !path.exists() {
        return build(config_path, false, Vec::new(), None);
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => return build(config_path, true, Vec::new(), Some(format!("Could not read config: {e}"))),
    };

    if content.trim().is_empty() {
        return build(config_path, true, Vec::new(), None);
    }

    let parsed = match def.format {
        Format::JsonMcpServers => parse_json(&content, "mcpServers"),
        Format::JsonServers => parse_json(&content, "servers"),
        Format::TomlMcpServers => parse_toml(&content),
    };

    match parsed {
        Ok(servers) => build(config_path, true, servers, None),
        Err(e) => build(config_path, true, Vec::new(), Some(format!("Could not parse config: {e}"))),
    }
}

/// Probe every supported client and return what each currently has configured.
pub fn detect_clients() -> Vec<DetectedClient> {
    defs().iter().map(read_client).collect()
}

// ---------------------------------------------------------------------------
// Write path
//
// Writing a server set back into a client's own format. Every write is preceded
// by a timestamped backup of the existing file (stored centrally under Conduit's
// config dir, not next to the client's config), so any change is reversible.
// Only env values that are present (non-secret) are written inline; secret
// values are vaulted separately and injected by the gateway at runtime.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteOutcome {
    pub path: String,
    pub backup: Option<String>,
}

fn find_def(client_id: &str) -> Option<ClientDef> {
    defs().into_iter().find(|d| d.id == client_id)
}

fn backup_dir(client_id: &str) -> Option<PathBuf> {
    Some(
        dirs::config_dir()?
            .join("Conduit")
            .join("backups")
            .join(client_id),
    )
}

fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Copy a client's config to a timestamped backup. No-op (Ok(None)) if it doesn't exist yet.
fn backup_file(client_id: &str, path: &Path) -> Result<Option<PathBuf>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let dir = backup_dir(client_id).ok_or("Could not resolve backup dir")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("config");
    let dest = dir.join(format!("{}-{}", epoch_millis(), name));
    std::fs::copy(path, &dest).map_err(|e| e.to_string())?;
    Ok(Some(dest))
}

fn entry_to_json(entry: &ServerEntry) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    if let Some(cmd) = &entry.command {
        map.insert("command".into(), serde_json::Value::String(cmd.clone()));
    }
    if !entry.args.is_empty() {
        map.insert(
            "args".into(),
            serde_json::Value::Array(
                entry
                    .args
                    .iter()
                    .map(|a| serde_json::Value::String(a.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(url) = &entry.url {
        map.insert("url".into(), serde_json::Value::String(url.clone()));
    }
    let env: serde_json::Map<String, serde_json::Value> = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value
                .as_ref()
                .map(|v| (e.key.clone(), serde_json::Value::String(v.clone())))
        })
        .collect();
    if !env.is_empty() {
        map.insert("env".into(), serde_json::Value::Object(env));
    }
    serde_json::Value::Object(map)
}

fn entry_to_toml(entry: &ServerEntry) -> toml::Value {
    let mut t = toml::map::Map::new();
    if let Some(cmd) = &entry.command {
        t.insert("command".into(), toml::Value::String(cmd.clone()));
    }
    if !entry.args.is_empty() {
        t.insert(
            "args".into(),
            toml::Value::Array(
                entry
                    .args
                    .iter()
                    .map(|a| toml::Value::String(a.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(url) = &entry.url {
        t.insert("url".into(), toml::Value::String(url.clone()));
    }
    let env: toml::map::Map<String, toml::Value> = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value
                .as_ref()
                .map(|v| (e.key.clone(), toml::Value::String(v.clone())))
        })
        .collect();
    if !env.is_empty() {
        t.insert("env".into(), toml::Value::Table(env));
    }
    toml::Value::Table(t)
}

fn write_json(path: &Path, key: &str, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if content.trim().is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(&content)
                .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
        }
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    if !root.is_object() {
        root = serde_json::Value::Object(serde_json::Map::new());
    }
    let obj = root.as_object_mut().unwrap();
    let servers_map: serde_json::Map<String, serde_json::Value> = servers
        .iter()
        .map(|s| (s.name.clone(), entry_to_json(s)))
        .collect();
    obj.insert(key.to_string(), serde_json::Value::Object(servers_map));

    let json = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, json).map_err(|e| e.to_string())
}

fn write_toml(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str::<toml::Value>(&content)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    if !root.is_table() {
        root = toml::Value::Table(toml::map::Map::new());
    }
    let table = root.as_table_mut().unwrap();
    let servers_table: toml::map::Map<String, toml::Value> = servers
        .iter()
        .map(|s| (s.name.clone(), entry_to_toml(s)))
        .collect();
    table.insert("mcp_servers".into(), toml::Value::Table(servers_table));

    let out = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// Write a server set into a client's config, backing up the existing file first
/// and preserving any unrelated top-level keys.
pub fn write_servers(client_id: &str, servers: &[ServerEntry]) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    let backup = backup_file(client_id, &path)?;
    match def.format {
        Format::JsonMcpServers => write_json(&path, "mcpServers", servers)?,
        Format::JsonServers => write_json(&path, "servers", servers)?,
        Format::TomlMcpServers => write_toml(&path, servers)?,
    }
    Ok(WriteOutcome {
        path: path.display().to_string(),
        backup: backup.map(|b| b.display().to_string()),
    })
}

// ---------------------------------------------------------------------------
// Gateway install
//
// "Installing Conduit into a client" means adding a single entry to that
// client's config that runs the conduit-gateway binary. The client then talks
// only to Conduit, which routes to everything behind it. This is a surgical
// edit: existing servers (and their secret env values) are left untouched.
// ---------------------------------------------------------------------------

fn resolve_gateway_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join(format!("conduit-gateway{}", std::env::consts::EXE_SUFFIX)))
}

fn gateway_entry(profile: Option<&str>) -> Result<ServerEntry, String> {
    let path = resolve_gateway_path().ok_or("Could not locate the conduit-gateway binary")?;
    let env_var = |k: &str, v: &str| crate::registry::EnvVar {
        key: k.to_string(),
        value: Some(v.to_string()),
        secret: false,
    };
    // Connect clients in lazy-discovery mode by default: the gateway advertises a
    // few meta-tools instead of the full catalog, keeping each client's context
    // small. Plain (non-secret) env values, written into the client's own config.
    let mut env = vec![env_var("CONDUIT_DISCOVERY", "lazy")];
    // Optionally scope this client to one profile, so it only ever sees that
    // slice of servers (no cross-domain tool ambiguity).
    if let Some(p) = profile.map(str::trim).filter(|p| !p.is_empty()) {
        env.push(env_var("CONDUIT_PROFILE", p));
    }
    Ok(ServerEntry {
        id: GATEWAY_ENTRY_NAME.to_string(),
        name: GATEWAY_ENTRY_NAME.to_string(),
        transport: "stdio".to_string(),
        command: Some(path.to_string_lossy().into_owned()),
        args: Vec::new(),
        env,
        url: None,
        source: Some("conduit".to_string()),
    })
}

fn edit_json_gateway(
    path: &Path,
    key: &str,
    install: bool,
    profile: Option<&str>,
) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if content.trim().is_empty() {
            serde_json::Value::Object(serde_json::Map::new())
        } else {
            serde_json::from_str(&content)
                .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()))
        }
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    if !root.is_object() {
        root = serde_json::Value::Object(serde_json::Map::new());
    }
    let obj = root.as_object_mut().unwrap();
    if !obj.get(key).map(|v| v.is_object()).unwrap_or(false) {
        obj.insert(key.to_string(), serde_json::Value::Object(serde_json::Map::new()));
    }
    let servers = obj.get_mut(key).unwrap().as_object_mut().unwrap();
    if install {
        servers.insert(
            GATEWAY_ENTRY_NAME.to_string(),
            entry_to_json(&gateway_entry(profile)?),
        );
    } else {
        servers.remove(GATEWAY_ENTRY_NAME);
    }

    let out = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

fn edit_toml_gateway(path: &Path, install: bool, profile: Option<&str>) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str::<toml::Value>(&content)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    if !root.is_table() {
        root = toml::Value::Table(toml::map::Map::new());
    }
    let table = root.as_table_mut().unwrap();
    if !table.get("mcp_servers").map(|v| v.is_table()).unwrap_or(false) {
        table.insert("mcp_servers".to_string(), toml::Value::Table(toml::map::Map::new()));
    }
    let servers = table.get_mut("mcp_servers").unwrap().as_table_mut().unwrap();
    if install {
        servers.insert(
            GATEWAY_ENTRY_NAME.to_string(),
            entry_to_toml(&gateway_entry(profile)?),
        );
    } else {
        servers.remove(GATEWAY_ENTRY_NAME);
    }

    let out = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

fn install_or_remove(
    client_id: &str,
    install: bool,
    profile: Option<&str>,
) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    let backup = backup_file(client_id, &path)?;
    match def.format {
        Format::JsonMcpServers => edit_json_gateway(&path, "mcpServers", install, profile)?,
        Format::JsonServers => edit_json_gateway(&path, "servers", install, profile)?,
        Format::TomlMcpServers => edit_toml_gateway(&path, install, profile)?,
    }
    Ok(WriteOutcome {
        path: path.display().to_string(),
        backup: backup.map(|b| b.display().to_string()),
    })
}

/// Add Conduit's gateway entry to a client's config (preserves existing servers).
/// `profile` scopes the client to one profile via `CONDUIT_PROFILE` (None = all).
pub fn install_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    install_or_remove(client_id, true, profile)
}

/// Remove Conduit's gateway entry from a client's config.
pub fn uninstall_gateway(client_id: &str) -> Result<WriteOutcome, String> {
    install_or_remove(client_id, false, None)
}

/// Replace a client's entire server list with just the Conduit gateway. Used by
/// "migrate": after the client's servers are imported into Conduit, this leaves
/// the client talking only to the gateway. Backs up first; unrelated config keys
/// are preserved. Caller is responsible for importing first so nothing is lost.
pub fn migrate_to_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    write_servers(client_id, &[gateway_entry(profile)?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EnvVar;

    fn stdio(name: &str) -> ServerEntry {
        ServerEntry {
            id: name.to_string(),
            name: name.to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".to_string()),
            args: vec!["-y".to_string(), format!("@modelcontextprotocol/server-{name}")],
            env: vec![EnvVar {
                key: "TOKEN".to_string(),
                value: Some("plain-value".to_string()),
                secret: false,
            }],
            url: None,
            source: None,
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("conduit-w-{}-{}.cfg", std::process::id(), label))
    }

    #[test]
    fn json_mcpservers_round_trips() {
        let path = temp_path("json-mcp");
        std::fs::remove_file(&path).ok();
        let servers = vec![stdio("filesystem"), stdio("github")];
        write_json(&path, "mcpServers", &servers).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed = parse_json(&content, "mcpServers").unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "filesystem");
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(parsed[0].env_keys, vec!["TOKEN".to_string()]);
    }

    #[test]
    fn reads_windsurf_antigravity_server_url() {
        // Antigravity/Windsurf use `serverUrl` for remotes instead of `url`.
        let content = r#"{"mcpServers":{"supabase":{"serverUrl":"https://mcp.supabase.com/mcp"}}}"#;
        let parsed = parse_json(content, "mcpServers").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "supabase");
        assert_eq!(parsed[0].url.as_deref(), Some("https://mcp.supabase.com/mcp"));
        assert_eq!(parsed[0].transport, "http");
    }

    #[test]
    fn json_write_preserves_unrelated_keys() {
        let path = temp_path("json-preserve");
        std::fs::write(&path, r#"{"theme":"dark","mcpServers":{"old":{"command":"x"}}}"#).unwrap();
        write_json(&path, "mcpServers", &[stdio("fresh")]).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(root.get("theme").and_then(|v| v.as_str()), Some("dark"));
        let servers = root.get("mcpServers").unwrap().as_object().unwrap();
        assert!(servers.contains_key("fresh"));
        assert!(!servers.contains_key("old"));
    }

    #[test]
    fn toml_mcp_servers_round_trips() {
        let path = temp_path("toml-mcp");
        std::fs::remove_file(&path).ok();
        write_toml(&path, &[stdio("postgres")]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed = parse_toml(&content).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "postgres");
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn toml_write_preserves_unrelated_keys() {
        let path = temp_path("toml-preserve");
        std::fs::write(&path, "model = \"opus\"\n").unwrap();
        write_toml(&path, &[stdio("linear")]).unwrap();
        let root: toml::Value =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(root.get("model").and_then(|v| v.as_str()), Some("opus"));
        assert!(root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .map(|t| t.contains_key("linear"))
            .unwrap_or(false));
    }

    #[test]
    fn install_gateway_is_surgical() {
        let path = temp_path("install-json");
        std::fs::write(
            &path,
            r#"{"theme":"dark","mcpServers":{"existing":{"command":"node","env":{"SECRET":"keepme"}}}}"#,
        )
        .unwrap();

        edit_json_gateway(&path, "mcpServers", true, Some("Billing")).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key("conduit"));
        assert!(servers.contains_key("existing"));
        // The gateway is installed in lazy-discovery mode, scoped to the profile.
        assert_eq!(servers["conduit"]["env"]["CONDUIT_DISCOVERY"], "lazy");
        assert_eq!(servers["conduit"]["env"]["CONDUIT_PROFILE"], "Billing");
        // Unrelated key and the existing server's secret value are untouched.
        assert_eq!(root["theme"], "dark");
        assert_eq!(servers["existing"]["env"]["SECRET"], "keepme");

        edit_json_gateway(&path, "mcpServers", false, None).unwrap();
        let root2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = root2["mcpServers"].as_object().unwrap();
        assert!(!servers2.contains_key("conduit"));
        assert!(servers2.contains_key("existing"));
        std::fs::remove_file(&path).ok();
    }

    // Informational (no assert): prints what the Cursor plugin scanner finds on
    // this machine. Run with `cargo test cursor_plugin_scan -- --nocapture`.
    #[test]
    fn cursor_plugin_scan_runs() {
        let servers = scan_cursor_plugins();
        println!("cursor plugin servers found: {}", servers.len());
        for s in &servers {
            let target = s.command.clone().or_else(|| s.url.clone()).unwrap_or_default();
            println!("  {} [{}] {}", s.name, s.transport, target);
        }
    }
}
