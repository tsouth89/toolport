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
    /// Whether the client app appears installed on this machine, independent of
    /// whether it has an MCP config yet. Inferred from the existence of the
    /// client's own data directory (the config file's parent). Lets us tell
    /// "installed but no servers" apart from "not installed at all", so we don't
    /// label a present client "not found" or write a config into a client that
    /// isn't here.
    pub app_present: bool,
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
    /// JSONC with a top-level `context_servers` object (Zed). Same per-server shape
    /// as mcpServers; the file is read leniently (comments + trailing commas) and
    /// never wiped on a parse failure (it holds the user's whole editor config).
    JsonContextServers,
    /// TOML with `[mcp_servers.<name>]` tables (Codex CLI).
    TomlMcpServers,
    /// YAML with a top-level `extensions` map (Goose). Each entry is an
    /// `{enabled, type, name, cmd, args, envs, ...}` record; `cmd`/`envs` (not
    /// `command`/`env`) and a `type` tag distinguish it from mcpServers. The file
    /// also holds the user's model config, so it's read leniently and never wiped.
    YamlExtensions,
    /// YAML with a top-level `mcp_servers` map (Hermes). Each entry has
    /// `command`/`args` (stdio) or `url` (http/sse), with optional `headers`,
    /// `timeout`, `connect_timeout`, etc. The file also holds user model/config.
    YamlMcpServers,
    /// YAML with a top-level `mcpServers` list (Continue).
    /// Each entry is a server object with fields like `name`, `command`,
    /// `args`, `env`, `type`, `url`, etc.
    YamlMcpServersList,
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

/// OS family for cross-platform path expectations. Production code uses
/// `Platform::current()`; unit tests iterate all three to lock in paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Windows,
    MacOs,
    Linux,
}

impl Platform {
    fn current() -> Self {
        #[cfg(windows)]
        {
            Platform::Windows
        }
        #[cfg(target_os = "macos")]
        {
            Platform::MacOs
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Platform::Linux
        }
    }

    // Names every variant, so a single-platform build doesn't see MacOs/Linux as
    // "never constructed"; the cross-platform path tests iterate it.
    #[allow(dead_code)]
    const ALL: [Platform; 3] = [Platform::Windows, Platform::MacOs, Platform::Linux];
}

/// Roaming app config dir: `%APPDATA%` on Windows, `~/Library/Application
/// Support` on macOS, `~/.config` on Linux.
///
/// On Windows it's anchored to the user profile (`~/AppData/Roaming`) rather than
/// `dirs::config_dir()`. MSIX-packaged apps (Claude Desktop) virtualize the
/// Roaming known-folder into their package's LocalCache, and if the Conduit
/// process is ever launched inside such a context, `config_dir()` would resolve
/// to that sandbox - so reads of Claude Desktop's `claude_desktop_config.json`
/// would miss the real file and report "not configured". The user-profile path
/// is not virtualized, matching how the registry path is anchored.
fn roaming_config_dir(home: &std::path::Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::Windows => home.join("AppData").join("Roaming"),
        Platform::MacOs => home.join("Library").join("Application Support"),
        Platform::Linux => home.join(".config"),
    }
}

/// App data dir (`dirs::data_dir()`), parameterized for cross-platform tests.
fn app_data_dir(home: &std::path::Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::Windows | Platform::MacOs => roaming_config_dir(home, platform),
        Platform::Linux => home.join(".local").join("share"),
    }
}

/// Resolve a client's config file path for a given home dir and platform.
fn resolve_client_config_path(
    client_id: &str,
    home: &std::path::Path,
    platform: Platform,
) -> Option<PathBuf> {
    let config = roaming_config_dir(home, platform);
    let data = app_data_dir(home, platform);
    let path = match client_id {
        "claude-desktop" => config.join("Claude").join("claude_desktop_config.json"),
        "cursor" => home.join(".cursor").join("mcp.json"),
        "boltai" => home.join(".boltai").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        "codex" => home.join(".codex").join("config.toml"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "antigravity" => home
            .join(".gemini")
            .join("config")
            .join("mcp_config.json"),
        "cline" => config
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings")
            .join("cline_mcp_settings.json"),
        "roo-code" => config
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("rooveterinaryinc.roo-cline")
            .join("settings")
            .join("mcp_settings.json"),
        "warp" => home.join(".warp").join(".mcp.json"),
        "amazon-q" => home.join(".aws").join("amazonq").join("mcp.json"),
        "kiro" => home.join(".kiro").join("settings").join("mcp.json"),
        "lm-studio" => home.join(".lmstudio").join("mcp.json"),
        "jan" => data.join("Jan").join("data").join("mcp_config.json"),
        "zed" => match platform {
            Platform::Windows => config.join("Zed").join("settings.json"),
            Platform::MacOs | Platform::Linux => {
                home.join(".config").join("zed").join("settings.json")
            }
        },
        "continue" => home.join(".continue").join("config.yaml"),
        "goose" => match platform {
            Platform::Windows => config
                .join("Block")
                .join("goose")
                .join("config")
                .join("config.yaml"),
            Platform::MacOs => home
                .join("Library")
                .join("Application Support")
                .join("Block")
                .join("goose")
                .join("config.yaml"),
            Platform::Linux => home.join(".config").join("goose").join("config.yaml"),
        },
        "hermes" => home.join(".hermes").join("config.yaml"),
        _ => return None,
    };
    Some(path)
}

fn client_config_path(client_id: &str) -> Option<PathBuf> {
    let home = home()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return resolve_client_config_path_linux(client_id, &home);
    }
    resolve_client_config_path(client_id, &home, Platform::current())
}

/// Linux production paths honor `XDG_CONFIG_HOME` / `XDG_DATA_HOME` via `dirs`.
#[cfg(all(unix, not(target_os = "macos")))]
fn resolve_client_config_path_linux(client_id: &str, home: &std::path::Path) -> Option<PathBuf> {
    let config = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
    let data = dirs::data_dir().unwrap_or_else(|| home.join(".local").join("share"));
    let path = match client_id {
        "claude-desktop" => config.join("Claude").join("claude_desktop_config.json"),
        "cursor" => home.join(".cursor").join("mcp.json"),
        "boltai" => home.join(".boltai").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        "codex" => home.join(".codex").join("config.toml"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "antigravity" => home
            .join(".gemini")
            .join("config")
            .join("mcp_config.json"),
        "cline" => config
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("settings")
            .join("cline_mcp_settings.json"),
        "roo-code" => config
            .join("Code")
            .join("User")
            .join("globalStorage")
            .join("rooveterinaryinc.roo-cline")
            .join("settings")
            .join("mcp_settings.json"),
        "warp" => home.join(".warp").join(".mcp.json"),
        "amazon-q" => home.join(".aws").join("amazonq").join("mcp.json"),
        "kiro" => home.join(".kiro").join("settings").join("mcp.json"),
        "lm-studio" => home.join(".lmstudio").join("mcp.json"),
        "jan" => data.join("Jan").join("data").join("mcp_config.json"),
        "zed" => home.join(".config").join("zed").join("settings.json"),
        "goose" => home.join(".config").join("goose").join("config.yaml"),
        "continue" => home.join(".continue").join("config.yaml"),
        "hermes" => home.join(".hermes").join("config.yaml"),
        _ => return None,
    };
    Some(path)
}

fn claude_desktop_path() -> Option<PathBuf> {
    // Claude Desktop is MSIX-packaged, so its Roaming config can live at the real
    // %APPDATA% and/or inside the package's virtualized LocalCache. Prefer the
    // real path (home-anchored via `client_config_path`); if only the package copy exists,
    // find it by scanning for the `Claude*` package so we don't depend on a
    // process running under the same virtualization.
    let real = client_config_path("claude-desktop")?;
    if real.exists() {
        return Some(real);
    }
    if let Some(home) = dirs::home_dir() {
        let packages = home.join("AppData").join("Local").join("Packages");
        if let Ok(entries) = std::fs::read_dir(&packages) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("Claude") {
                    let p = entry
                        .path()
                        .join("LocalCache")
                        .join("Roaming")
                        .join("Claude")
                        .join("claude_desktop_config.json");
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
    }
    // Default to the real path even if absent, so the status reads "not found"
    // rather than erroring.
    Some(real)
}

fn cursor_path() -> Option<PathBuf> {
    client_config_path("cursor")
}

fn boltai_path() -> Option<PathBuf> {
    client_config_path("boltai")
}

fn vscode_path() -> Option<PathBuf> {
    client_config_path("vscode")
}

fn windsurf_path() -> Option<PathBuf> {
    client_config_path("windsurf")
}

fn codex_path() -> Option<PathBuf> {
    client_config_path("codex")
}

fn claude_code_path() -> Option<PathBuf> {
    client_config_path("claude-code")
}

fn gemini_cli_path() -> Option<PathBuf> {
    client_config_path("gemini-cli")
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
    client_config_path("antigravity")
}

fn cline_path() -> Option<PathBuf> {
    client_config_path("cline")
}

fn roo_code_path() -> Option<PathBuf> {
    client_config_path("roo-code")
}

/// Warp reads file-based MCP servers from `~/.warp/.mcp.json` (keyed under
/// `mcpServers`), alongside its in-app UI. The file is home-anchored on every OS.
fn warp_path() -> Option<PathBuf> {
    client_config_path("warp")
}

/// Amazon Q Developer CLI global MCP config: `~/.aws/amazonq/mcp.json`
/// (`mcpServers`). A per-workspace `.amazonq/mcp.json` also exists; we manage the
/// global one so the gateway is available everywhere.
fn amazon_q_path() -> Option<PathBuf> {
    client_config_path("amazon-q")
}

/// Kiro user-level MCP config: `~/.kiro/settings/mcp.json` (`mcpServers`). A
/// per-workspace `.kiro/settings/mcp.json` also exists and takes precedence.
fn kiro_path() -> Option<PathBuf> {
    client_config_path("kiro")
}

/// LM Studio reads MCP servers from `~/.lmstudio/mcp.json` (`mcpServers`, plain
/// JSON). The file is created by LM Studio, so the parent-dir presence check works.
fn lmstudio_path() -> Option<PathBuf> {
    client_config_path("lm-studio")
}

/// Jan keeps MCP servers in mcp_config.json (standard `mcpServers` shape) inside
/// its data folder, `<data_dir>/Jan/data` on every OS (e.g. %APPDATA%\Jan\data on
/// Windows, ~/Library/Application Support/Jan/data on macOS). Jan creates the
/// folder and a default config on first launch, so the parent-dir check detects it.
fn jan_path() -> Option<PathBuf> {
    client_config_path("jan")
}

/// Goose keeps extensions (its MCP servers) in config.yaml. It resolves the dir
/// via the `etcetera` "Block/goose" app strategy: ~/.config/goose on Linux, an
/// app-support path on macOS, and %APPDATA%\Block\goose\config on Windows. (The
/// Windows path is the etcetera default and is confirmed against a real install.)
fn goose_path() -> Option<PathBuf> {
    client_config_path("goose")
}

/// Zed keeps MCP ("context") servers in its main settings.json (JSONC). Windows
/// uses %APPDATA%\Zed; macOS and Linux use ~/.config/zed (not App Support). The
/// parent dir is created on install, so the default presence heuristic works.
fn zed_path() -> Option<PathBuf> {
    client_config_path("zed")
}

/// Hermes keeps MCP servers in ~/.hermes/config.yaml under the `mcp_servers:` key.
/// The file is YAML and also holds the user's model and platform toolsets config,
/// so it's read leniently and never wiped on a parse failure.
fn hermes_path() -> Option<PathBuf> {
    client_config_path("hermes")
}

fn continue_path() -> Option<PathBuf> {
    Some(home()?.join(".continue").join("config.yaml"))
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
        let content = match read_config_file(&path) {
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
        ClientDef {
            id: "warp",
            name: "Warp",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: warp_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "amazon-q",
            name: "Amazon Q",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: amazon_q_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "kiro",
            name: "Kiro",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: kiro_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "zed",
            name: "Zed",
            format: Format::JsonContextServers,
            uses_connectors: false,
            path: zed_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "lm-studio",
            name: "LM Studio",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: lmstudio_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "jan",
            name: "Jan",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: jan_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "boltai",
            name: "BoltAI",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: boltai_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "goose",
            name: "Goose",
            format: Format::YamlExtensions,
            uses_connectors: false,
            path: goose_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "hermes",
            name: "Hermes",
            format: Format::YamlMcpServers,
            uses_connectors: false,
            path: hermes_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "continue",
            name: "Continue",
            format: Format::YamlMcpServersList,
            uses_connectors: false,
            path: continue_path,
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
    // Treat an empty command string as no command: some clients (e.g. Jan's `exa`
    // default) ship a remote/url server with `"command": ""`, which must not read
    // as a broken stdio server.
    let command = def
        .get("command")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
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

/// Parse JSON or JSON5, returning a syntax error with line/column when possible.
fn parse_json_value(content: &str) -> Result<serde_json::Value, String> {
    if content.trim().is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    if let Ok(v) = serde_json::from_str(content) {
        return Ok(v);
    }
    if let Ok(v) = json5::from_str(content) {
        return Ok(v);
    }
    let err = serde_json::from_str::<serde_json::Value>(content).unwrap_err();
    Err(format!(
        "JSON syntax error at line {} column {}: {}",
        err.line(),
        err.column(),
        err
    ))
}

/// Parse YAML, preserving serde_yaml's line/column in the error text.
fn parse_yaml_value(content: &str) -> Result<serde_yaml::Value, String> {
    serde_yaml::from_str(content).map_err(|e| format!("YAML syntax error: {e}"))
}

/// Read an existing JSON config we're about to modify. Tolerant of JSONC. When
/// `lenient` (e.g. Zed's settings.json, which holds the user's whole editor config),
/// an unparseable file is an ERROR, never silently replaced with an empty object,
/// so Conduit can't wipe it. For the well-behaved JSON configs, an unparseable file
/// falls back to empty (start fresh), preserving prior behavior.
fn read_existing_json(content: &str, lenient: bool) -> Result<serde_json::Value, String> {
    match parse_json_value(content) {
        Ok(v) => Ok(v),
        Err(e) if lenient => Err(format!(
            "Could not parse the existing config ({e}); leaving it untouched."
        )),
        Err(_) => Ok(serde_json::Value::Object(serde_json::Map::new())),
    }
}

fn parse_json(content: &str, key: &str) -> Result<Vec<McpServer>, String> {
    let value = parse_json_value(content)?;
    let obj = match value.get(key) {
        None => return Ok(Vec::new()),
        Some(v) if v.is_object() => v.as_object().unwrap(),
        Some(_) => {
            return Err(format!(
                "'{key}' must be an object mapping server names to definitions"
            ));
        }
    };

    let mut malformed = Vec::new();
    let mut servers: Vec<McpServer> = Vec::new();
    for (name, def) in obj {
        if def.is_object() {
            servers.push(json_server(name, def));
        } else {
            malformed.push(name.clone());
        }
    }
    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!(
            "malformed '{key}' entry (expected an object): {}",
            malformed.join(", ")
        ));
    }
    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

fn parse_toml(content: &str) -> Result<Vec<McpServer>, String> {
    let value: toml::Value =
        toml::from_str(content).map_err(|e| format!("TOML syntax error: {e}"))?;
    let table = match value.get("mcp_servers") {
        None => return Ok(Vec::new()),
        Some(v) if v.is_table() => v.as_table().unwrap(),
        Some(_) => {
            return Err(
                "'mcp_servers' must be a table mapping server names to definitions".into(),
            );
        }
    };

    let mut malformed = Vec::new();
    let mut servers: Vec<McpServer> = Vec::new();
    for (name, def) in table {
        let Some(def) = def.as_table() else {
            malformed.push(name.clone());
            continue;
        };
        servers.push(McpServer {
            name: name.clone(),
            transport: classify(
                &def
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(String::from),
                &def.get("url").and_then(|u| u.as_str()).map(String::from),
                None,
            ),
            command: def
                .get("command")
                .and_then(|c| c.as_str())
                .map(String::from),
            args: def
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            env_keys: def
                .get("env")
                .and_then(|e| e.as_table())
                .map(|t| t.keys().cloned().collect())
                .unwrap_or_default(),
            url: def.get("url").and_then(|u| u.as_str()).map(String::from),
        });
    }

    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!(
            "malformed mcp_servers entry (expected a table): {}",
            malformed.join(", ")
        ));
    }

    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

/// Whether the client app appears installed, given its config path and whether
/// the config file exists. The config's parent is the app's own data dir, so its
/// presence means the app has run here even if it has no MCP config yet. An empty
/// path means we couldn't resolve a location, so the app isn't detectable.
fn app_present_for(config_path: &str, config_exists: bool) -> bool {
    config_exists
        || (!config_path.is_empty()
            && std::path::Path::new(config_path)
                .parent()
                .map(|p| p.exists())
                .unwrap_or(false))
}

/// Warp keeps its state under the OS data dir, not next to its MCP config: it reads
/// file-based servers from `~/.warp/.mcp.json` but only creates `~/.warp` on first
/// file-based use, while the app itself lives under the data dir. So the
/// config-parent heuristic misses it. This finds Warp's install dir instead.
/// Per-user location, so the all-users-vs-just-me install choice doesn't matter.
fn warp_data_dir() -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(d) = dirs::data_local_dir() {
        roots.push(d); // Windows %LOCALAPPDATA%, macOS App Support, Linux ~/.local/share
    }
    if let Some(d) = dirs::data_dir() {
        roots.push(d);
    }
    if let Some(h) = home() {
        roots.push(h.join(".local").join("state")); // Linux state dir
    }
    for root in roots {
        for name in ["warp", "Warp", "dev.warp.Warp-Stable", "warp-terminal"] {
            let p = root.join(name);
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// An explicit install/data dir for clients where the default "config file's
/// parent = app data dir" heuristic gives a wrong answer (too broad, like a config
/// that sits directly in the home dir, or too narrow, like a config dir that only
/// appears after first use). Returning `Some` here OVERRIDES the parent heuristic
/// for that client, so detection reflects whether the app is actually installed,
/// not merely whether an MCP config file happens to exist.
fn install_override(id: &str) -> Option<PathBuf> {
    match id {
        // ~/.warp only appears on first file-based MCP use; the app itself lives
        // under the OS data dir.
        "warp" => warp_data_dir(),
        // Config is ~/.claude.json, whose parent is the home dir (always present),
        // which would mark Claude Code installed everywhere. Its real data dir is
        // ~/.claude.
        "claude-code" => Some(home()?.join(".claude")),
        // ~/.kiro/settings may not exist until something is configured; ~/.kiro is
        // created on install.
        "kiro" => Some(home()?.join(".kiro")),
        _ => None,
    }
}

fn read_client(def: &ClientDef) -> DetectedClient {
    let plugin_servers = def.plugin_scan.map(|scan| scan()).unwrap_or_default();

    let build = |config_path: String,
                 config_exists: bool,
                 servers: Vec<McpServer>,
                 error: Option<String>| {
        let gateway_installed = servers
            .iter()
            .any(|s| s.name.eq_ignore_ascii_case(GATEWAY_ENTRY_NAME));
        // The config file's parent is the client's own data dir (e.g. `.../Code/User`,
        // `.../Claude`, `~/.codex`); its presence means the app has run here. If the
        // config itself exists the app is obviously present. An empty path means we
        // couldn't even resolve a location, so the app is not detectable.
        // Clients with an explicit install dir use it (and ignore the config-parent
        // heuristic, which for them is wrong); everyone else uses the parent of
        // their resolved config path (which is their data dir, e.g. ~/.codex).
        let app_present = match install_override(def.id) {
            Some(marker) => config_exists || marker.exists(),
            None => app_present_for(&config_path, config_exists),
        };
        DetectedClient {
            id: def.id.to_string(),
            name: def.name.to_string(),
            uses_connectors: def.uses_connectors,
            config_path,
            config_exists,
            app_present,
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

    let content = match read_config_file(&path) {
        Ok(c) => c,
        Err(e) => {
            return build(
                config_path,
                true,
                Vec::new(),
                Some(format!("Could not read config: {e}")),
            )
        }
    };

    if content.trim().is_empty() {
        return build(config_path, true, Vec::new(), None);
    }

    let parsed = match def.format {
        Format::JsonMcpServers => parse_json(&content, "mcpServers"),
        Format::JsonServers => parse_json(&content, "servers"),
        Format::JsonContextServers => parse_json(&content, "context_servers"),
        Format::TomlMcpServers => parse_toml(&content),
        Format::YamlExtensions => parse_yaml_extensions(&content),
        Format::YamlMcpServers => parse_hermes_yaml_servers(&content),
        Format::YamlMcpServersList => parse_continue_yaml_servers(&content),
    };

    match parsed {
        Ok(servers) => build(config_path, true, servers, None),
        Err(e) => build(
            config_path,
            true,
            Vec::new(),
            Some(format!("Could not parse config: {e}")),
        ),
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
    // Anchor to the same home-based dir as the registry (see registry::conduit_dir)
    // so config backups land in one place regardless of whether a packaged or
    // unpackaged process wrote them.
    Some(
        crate::registry::conduit_dir()?
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

/// Largest client config we'll read into memory or back up. Real MCP client
/// configs are a few KB; this cap stops a maliciously large file, or a config
/// symlinked to a huge or special file (a device, a FIFO), from exhausting
/// memory or filling the disk via the backup dir.
const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;

/// Read a client config to a string, refusing anything that isn't a regular file
/// (after following symlinks, so a benign symlinked dotfile still works but a
/// link to a device/FIFO/directory does not) and capping the size. Returns the
/// same `Result<String, String>` shape as a plain read, so callers are otherwise
/// unchanged. A missing file is an error here; callers that tolerate that already
/// guard with `path.exists()` or treat the `Err` arm as "no config".
fn read_config_file(path: &Path) -> Result<String, String> {
    // `metadata` follows symlinks, so this reflects the real target's type/size.
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file (refusing to read a device, FIFO, or directory)",
            path.display()
        ));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "{} is {} bytes, larger than the {}-byte config limit",
            path.display(),
            meta.len(),
            MAX_CONFIG_BYTES
        ));
    }
    std::fs::read_to_string(path).map_err(|e| e.to_string())
}

/// Copy a client's config to a timestamped backup. No-op (Ok(None)) if it doesn't
/// exist yet, or if it isn't a regular file / is over the size cap (we won't copy
/// a device or a huge file into the backup dir).
fn backup_file(client_id: &str, path: &Path) -> Result<Option<PathBuf>, String> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_CONFIG_BYTES => {}
        // Missing, special file, or oversized: nothing safe to back up.
        _ => return Ok(None),
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
        // A stdio server always carries `args`, even empty: some clients (e.g. Jan)
        // reject an entry whose `args` key is missing ("failed to extract command args").
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

/// Write a client's config atomically (temp file + rename) so a crash or full
/// disk mid-write can't leave it truncated or empty. Delegates to the shared
/// [`registry::atomic_write`], which uses a unique temp name so two writers to
/// the same config can't clobber each other.
fn atomic_write(path: &Path, contents: &str) -> Result<(), String> {
    crate::registry::atomic_write(path, contents)
}

fn write_json(
    path: &Path,
    key: &str,
    servers: &[ServerEntry],
    lenient: bool,
) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = read_config_file(path)?;
        read_existing_json(&content, lenient)?
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
    atomic_write(path, &json)
}

fn write_toml(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = read_config_file(path)?;
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
    atomic_write(path, &out)
}

// --- Goose: YAML config.yaml with a top-level `extensions` map ---

/// Parse Goose's `extensions` map into servers. Each entry carries a `type` tag
/// plus `cmd`/`args`/`envs` (stdio) or `url` (http/sse), not the mcpServers shape.
fn parse_yaml_extensions(content: &str) -> Result<Vec<McpServer>, String> {
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value = parse_yaml_value(content)?;
    let exts = match value.get("extensions") {
        None => return Ok(Vec::new()),
        Some(v) if v.is_mapping() => v.as_mapping().unwrap(),
        Some(_) => {
            return Err(
                "'extensions' must be a mapping of extension names to definitions".into(),
            );
        }
    };
    let mut malformed = Vec::new();
    let mut servers: Vec<McpServer> = Vec::new();
    for (k, def) in exts {
        let Some(name) = k.as_str().map(str::to_string) else {
            continue;
        };
        let Some(def) = def.as_mapping() else {
            malformed.push(name);
            continue;
        };
        let str_of = |key: &str| def.get(key).and_then(|v| v.as_str()).map(String::from);
        let command = str_of("cmd").filter(|s| !s.is_empty());
        let url = str_of("url").filter(|s| !s.is_empty());
        // Goose's `builtin`/`platform` extensions are internal to Goose, not
        // proxiable external MCP servers, so skip them (they have no cmd/url).
        if command.is_none() && url.is_none() {
            continue;
        }
        let args = def
            .get("args")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let env_keys = def
            .get("envs")
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        servers.push(McpServer {
            name,
            transport: str_of("type").unwrap_or_else(|| "unknown".into()),
            command,
            args,
            env_keys,
            url,
        });
    }
    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!(
            "malformed 'extensions' entry (expected a mapping): {}",
            malformed.join(", ")
        ));
    }
    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

/// Build a Goose stdio extension record for a server entry.
fn entry_to_goose_yaml(entry: &ServerEntry) -> serde_yaml::Value {
    let envs: serde_json::Map<String, serde_json::Value> = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value
                .as_ref()
                .map(|v| (e.key.clone(), serde_json::Value::String(v.clone())))
        })
        .collect();
    let v = serde_json::json!({
        "enabled": true,
        "type": "stdio",
        "name": entry.name,
        "cmd": entry.command.clone().unwrap_or_default(),
        "args": entry.args,
        "envs": envs,
        "timeout": 300,
    });
    serde_yaml::to_value(&v).unwrap_or(serde_yaml::Value::Null)
}

/// Read an existing config.yaml we're about to modify. Like the JSON lenient path,
/// an unparseable non-empty file is an ERROR, never replaced - config.yaml also
/// holds the user's model settings and other extensions, so we must not wipe it.
fn read_existing_yaml(path: &Path) -> Result<serde_yaml::Value, String> {
    if !path.exists() {
        return Ok(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    let content = read_config_file(path)?;
    if content.trim().is_empty() {
        return Ok(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    serde_yaml::from_str(&content).map_err(|e| {
        format!("Could not parse the existing config.yaml ({e}); leaving it untouched.")
    })
}

fn yaml_extensions_mut(root: &mut serde_yaml::Value) -> &mut serde_yaml::Mapping {
    if !root.is_mapping() {
        *root = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let map = root.as_mapping_mut().unwrap();
    let key = serde_yaml::Value::String("extensions".into());
    if !map.get(&key).map(|v| v.is_mapping()).unwrap_or(false) {
        map.insert(
            key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    map.get_mut(&key).unwrap().as_mapping_mut().unwrap()
}

fn write_yaml_extensions(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;
    let exts = yaml_extensions_mut(&mut root);
    exts.clear();
    for s in servers {
        exts.insert(
            serde_yaml::Value::String(s.name.clone()),
            entry_to_goose_yaml(s),
        );
    }
    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

fn edit_yaml_gateway(path: &Path, install: bool, profile: Option<&str>) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;
    let exts = yaml_extensions_mut(&mut root);
    let key = serde_yaml::Value::String(GATEWAY_ENTRY_NAME.into());
    if install {
        exts.insert(key, entry_to_goose_yaml(&gateway_entry(profile)?));
    } else {
        exts.remove(&key);
    }
    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

/// Parse Continue's `mcpServers` list into servers. Each entry carries
/// `command`/`args`/`env` in YAML list form.
fn parse_continue_yaml_servers(content: &str) -> Result<Vec<McpServer>, String> {
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| e.to_string())?;

    let entries = match value.get("mcpServers") {
        None => return Ok(Vec::new()),
        Some(v) if v.is_sequence() => v.as_sequence().unwrap(),
        Some(_) => {
            return Err(
                "'mcpServers' must be a sequence of server definitions".into(),
            );
        }
    };

    let mut malformed = Vec::new();
    let mut servers = Vec::new();

    for (idx, server) in entries.iter().enumerate() {
        let Some(def) = server.as_mapping() else {
            malformed.push(format!("mcpServers[{idx}]"));
            continue;
        };

        let str_of = |key: &str| {
            def.get(serde_yaml::Value::String(key.into()))
                .and_then(|v| v.as_str())
                .map(String::from)
        };

        // Try to identify the entry by name.
        let name = match str_of("name") {
            Some(name) => name,
            None => {
                malformed.push(format!("mcpServers[{idx}]"));
                continue;
            }
        };

        let command = str_of("command").filter(|s| !s.is_empty());

        let args = def
            .get(serde_yaml::Value::String("args".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let env_keys = def
            .get(serde_yaml::Value::String("env".into()))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        servers.push(McpServer {
            name,
            transport: "stdio".into(),
            command,
            args,
            env_keys,
            url: None,
        });
    }

    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!(
            "malformed 'mcpServers' entry (expected a mapping): {}",
            malformed.join(", ")
        ));
    }

    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

/// Build a Continue stdio MCP server record for a server entry.
fn entry_to_continue_yaml(entry: &ServerEntry) -> serde_yaml::Value {
    let env: serde_json::Map<String, serde_json::Value> = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value
                .as_ref()
                .map(|v| (e.key.clone(), serde_json::Value::String(v.clone())))
        })
        .collect();

    let v = serde_json::json!({
        "name": entry.name,
        "command": entry.command.clone().unwrap_or_default(),
        "args": entry.args,
        "env": env,
    });

    serde_yaml::to_value(&v).unwrap_or(serde_yaml::Value::Null)
}

fn continue_servers_mut(root: &mut serde_yaml::Value) -> &mut Vec<serde_yaml::Value> {
    if !root.is_mapping() {
        *root = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }

    let map = root.as_mapping_mut().unwrap();

    let key = serde_yaml::Value::String("mcpServers".into());

    if !map.get(&key).map(|v| v.is_sequence()).unwrap_or(false) {
        map.insert(key.clone(), serde_yaml::Value::Sequence(Vec::new()));
    }

    map.get_mut(&key).unwrap().as_sequence_mut().unwrap()
}

fn write_continue_yaml_servers(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;

    let list = continue_servers_mut(&mut root);

    list.clear();

    for server in servers {
        list.push(entry_to_continue_yaml(server));
    }

    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;

    atomic_write(path, &out)
}

fn edit_continue_yaml_gateway(
    path: &Path,
    install: bool,
    profile: Option<&str>,
) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;

    let servers = continue_servers_mut(&mut root);

    servers.retain(|server| {
        server
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("name".into())))
            .and_then(|v| v.as_str())
            != Some(GATEWAY_ENTRY_NAME)
    });

    if install {
        servers.push(entry_to_continue_yaml(&gateway_entry(profile)?));
    }

    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;

    atomic_write(path, &out)
}

// ---------------------------------------------------------------------------
// Hermes (YAML `mcp_servers:` map).
//
// Hermes stores MCP servers in ~/.hermes/config.yaml under a top-level
// `mcp_servers:` key — the same conceptual location as Claude Desktop's JSON
// `mcpServers`, but in YAML. Each entry uses `command`/`args` (stdio) or `url`
// (http/sse), with optional `headers`, `env`, `timeout`, `connect_timeout`, etc.
// The file also holds the user's model and platform toolsets config, so it is
// read leniently and never wiped on a parse failure.
// ---------------------------------------------------------------------------

/// Parse a Hermes `config.yaml` with a top-level `mcp_servers:` map. Each entry has
/// `command`/`args` (stdio) or `url` (http/sse), with optional `headers`,
/// `timeout`, `connect_timeout`, etc.
fn parse_hermes_yaml_servers(content: &str) -> Result<Vec<McpServer>, String> {
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value = parse_yaml_value(content)?;
    let servers_map = match value.get("mcp_servers") {
        None => return Ok(Vec::new()),
        Some(v) if v.is_mapping() => v.as_mapping().unwrap(),
        Some(_) => {
            return Err(
                "'mcp_servers' must be a mapping of server names to definitions".into(),
            );
        }
    };
    let mut malformed = Vec::new();
    let mut servers: Vec<McpServer> = Vec::new();
    for (k, def) in servers_map {
        let Some(name) = k.as_str().map(str::to_string) else {
            continue;
        };
        let Some(def) = def.as_mapping() else {
            malformed.push(name);
            continue;
        };
        let str_of = |key: &str| def.get(key).and_then(|v| v.as_str()).map(String::from);
        let command = str_of("command").filter(|s| !s.is_empty());
        let url = str_of("url").filter(|s| !s.is_empty());
        if command.is_none() && url.is_none() {
            continue;
        }
        let args = def
            .get("args")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // Extract env/header keys from `headers` and `env` sub-maps.
        let mut env_keys: Vec<String> = Vec::new();
        for key in &["headers", "env"] {
            if let Some(m) = def.get(*key).and_then(|v| v.as_mapping()) {
                env_keys.extend(m.keys().filter_map(|k| k.as_str().map(String::from)));
            }
        }
        env_keys.sort_unstable();
        env_keys.dedup();
        servers.push(McpServer {
            name,
            transport: if url.is_some() { "http" } else { "stdio" }.into(),
            command,
            args,
            env_keys,
            url,
        });
    }
    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!(
            "malformed 'mcp_servers' entry (expected a mapping): {}",
            malformed.join(", ")
        ));
    }
    servers.sort_by_key(|s| s.name.to_lowercase());
    Ok(servers)
}

/// Build a Hermes stdio/HTTP server entry for a server entry.
fn entry_to_hermes_yaml(entry: &ServerEntry) -> serde_yaml::Value {
    let mut cfg: serde_yaml::Mapping = serde_yaml::Mapping::new();
    if let Some(cmd) = &entry.command {
        cfg.insert(
            serde_yaml::Value::String("command".into()),
            serde_yaml::Value::String(cmd.clone()),
        );
    }
    if !entry.args.is_empty() {
        cfg.insert(
            serde_yaml::Value::String("args".into()),
            serde_yaml::Value::Sequence(
                entry
                    .args
                    .iter()
                    .map(|a| serde_yaml::Value::String(a.clone()))
                    .collect(),
            ),
        );
    }
    if let Some(url) = &entry.url {
        cfg.insert(
            serde_yaml::Value::String("url".into()),
            serde_yaml::Value::String(url.clone()),
        );
    }
    // Hermes stores subprocess env vars under `env` (same purpose as Goose's `envs`).
    // Auth headers for HTTP servers are handled at import time, not reconstructed here.
    let env: serde_yaml::Mapping = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value.as_ref().map(|v| {
                (
                    serde_yaml::Value::String(e.key.clone()),
                    serde_yaml::Value::String(v.clone()),
                )
            })
        })
        .collect();
    if !env.is_empty() {
        cfg.insert(
            serde_yaml::Value::String("env".into()),
            serde_yaml::Value::Mapping(env),
        );
    }
    serde_yaml::Value::Mapping(cfg)
}

/// Read a Hermes config.yaml we're about to modify. Same contract as
/// `read_existing_yaml`: an unparseable non-empty file is an ERROR, never
/// replaced — config.yaml also holds the user's model and toolsets.
fn read_existing_hermes_yaml(path: &Path) -> Result<serde_yaml::Value, String> {
    read_existing_yaml(path)
}

fn hermes_mcp_servers_mut(root: &mut serde_yaml::Value) -> &mut serde_yaml::Mapping {
    if !root.is_mapping() {
        *root = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let map = root.as_mapping_mut().unwrap();
    let key = serde_yaml::Value::String("mcp_servers".into());
    if !map.get(&key).map(|v| v.is_mapping()).unwrap_or(false) {
        map.insert(
            key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    map.get_mut(&key).unwrap().as_mapping_mut().unwrap()
}

fn write_hermes_yaml_servers(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let mut root = read_existing_hermes_yaml(path)?;
    let mcp_servers = hermes_mcp_servers_mut(&mut root);
    mcp_servers.clear();
    for entry in servers {
        let name_val = serde_yaml::Value::String(entry.name.clone());
        mcp_servers.insert(name_val, entry_to_hermes_yaml(entry));
    }
    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

fn edit_hermes_yaml_gateway(
    path: &Path,
    install: bool,
    profile: Option<&str>,
) -> Result<(), String> {
    let mut root = read_existing_hermes_yaml(path)?;
    let mcp_servers = hermes_mcp_servers_mut(&mut root);
    let key = serde_yaml::Value::String(GATEWAY_ENTRY_NAME.into());
    if install {
        mcp_servers.insert(key, entry_to_hermes_yaml(&gateway_entry(profile)?));
    } else {
        mcp_servers.remove(&key);
    }
    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

/// Write a server set into a client's config, backing up the existing file first
/// and preserving any unrelated top-level keys.
pub fn write_servers(client_id: &str, servers: &[ServerEntry]) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    let backup = backup_file(client_id, &path)?;
    match def.format {
        Format::JsonMcpServers => write_json(&path, "mcpServers", servers, false)?,
        Format::JsonServers => write_json(&path, "servers", servers, false)?,
        Format::JsonContextServers => write_json(&path, "context_servers", servers, true)?,
        Format::TomlMcpServers => write_toml(&path, servers)?,
        Format::YamlExtensions => write_yaml_extensions(&path, servers)?,
        Format::YamlMcpServers => write_hermes_yaml_servers(&path, servers)?,
        Format::YamlMcpServersList => write_continue_yaml_servers(&path, servers)?,
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

pub(crate) fn resolve_gateway_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let ext = std::env::consts::EXE_SUFFIX;
    // Dev / `cargo run`, and most packaged builds: the gateway sits next to the app
    // binary as `conduit-gateway` (Tauri strips the sidecar's target-triple suffix
    // when installing). True for Windows (install dir), macOS (.app/Contents/MacOS),
    // and the Linux .deb (/usr/bin).
    let plain = dir.join(format!("conduit-gateway{ext}"));

    // AppImage is the exception: it runs from an ephemeral mount (e.g.
    // /tmp/.mount_XXXX) that disappears when the app exits, so a gateway path inside
    // it would be dead by the time a client tries to spawn it. Copy the gateway to a
    // stable per-user location and hand clients that path. ($APPIMAGE is only set
    // when running inside an AppImage.)
    if std::env::var_os("APPIMAGE").is_some() && plain.exists() {
        if let Some(stable) = stable_gateway_copy(&plain) {
            return Some(stable);
        }
    }

    if plain.exists() {
        return Some(plain);
    }
    // Packaged fallback: a sidecar that kept its `-<target-triple>` suffix.
    if let Some(triple) = option_env!("CONDUIT_TARGET_TRIPLE").filter(|t| !t.is_empty()) {
        let suffixed = dir.join(format!("conduit-gateway-{triple}{ext}"));
        if suffixed.exists() {
            return Some(suffixed);
        }
    }
    // Fall back to the plain path so callers surface a clear "not found" error
    // rather than silently resolving to nothing.
    Some(plain)
}

/// Copy the gateway binary to a stable per-user location, so a client config can
/// point at a path that outlives an ephemeral AppImage mount. Re-copies when the
/// source size differs (e.g. after an app update). Returns the stable path.
fn stable_gateway_copy(src: &std::path::Path) -> Option<PathBuf> {
    let dest_dir = crate::registry::conduit_dir()?.join("bin");
    std::fs::create_dir_all(&dest_dir).ok()?;
    let dest = dest_dir.join("conduit-gateway");
    let stale = match (std::fs::metadata(&dest), std::fs::metadata(src)) {
        (Ok(d), Ok(s)) => d.len() != s.len(),
        _ => true,
    };
    if stale {
        std::fs::copy(src, &dest).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&dest) {
                let mut perms = meta.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(&dest, perms);
            }
        }
    }
    Some(dest)
}

fn gateway_entry(profile: Option<&str>) -> Result<ServerEntry, String> {
    let path = resolve_gateway_path().ok_or("Could not locate the conduit-gateway binary")?;
    let env_var = |k: &str, v: &str| crate::registry::EnvVar {
        key: k.to_string(),
        value: Some(v.to_string()),
        secret: false,
    };
    // Discovery mode (lazy vs full) is NOT written here: the gateway reads it
    // from the registry, so the app's global setting governs every client
    // uniformly - including clients that don't forward env vars to the spawned
    // gateway (e.g. Antigravity), where a config env would never take effect.
    // Only per-client profile scoping needs an env var.
    let mut env: Vec<crate::registry::EnvVar> = Vec::new();
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
        disabled_tools: Vec::new(),
    })
}

fn edit_json_gateway(
    path: &Path,
    key: &str,
    install: bool,
    profile: Option<&str>,
    lenient: bool,
) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = read_config_file(path)?;
        read_existing_json(&content, lenient)?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };
    if !root.is_object() {
        root = serde_json::Value::Object(serde_json::Map::new());
    }
    let obj = root.as_object_mut().unwrap();
    if !obj.get(key).map(|v| v.is_object()).unwrap_or(false) {
        obj.insert(
            key.to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
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
    atomic_write(path, &out)
}

fn edit_toml_gateway(path: &Path, install: bool, profile: Option<&str>) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = read_config_file(path)?;
        toml::from_str::<toml::Value>(&content)
            .unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    if !root.is_table() {
        root = toml::Value::Table(toml::map::Map::new());
    }
    let table = root.as_table_mut().unwrap();
    if !table
        .get("mcp_servers")
        .map(|v| v.is_table())
        .unwrap_or(false)
    {
        table.insert(
            "mcp_servers".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
    }
    let servers = table
        .get_mut("mcp_servers")
        .unwrap()
        .as_table_mut()
        .unwrap();
    if install {
        servers.insert(
            GATEWAY_ENTRY_NAME.to_string(),
            entry_to_toml(&gateway_entry(profile)?),
        );
    } else {
        servers.remove(GATEWAY_ENTRY_NAME);
    }

    let out = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
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
        Format::JsonMcpServers => edit_json_gateway(&path, "mcpServers", install, profile, false)?,
        Format::JsonServers => edit_json_gateway(&path, "servers", install, profile, false)?,
        Format::JsonContextServers => {
            edit_json_gateway(&path, "context_servers", install, profile, true)?
        }
        Format::TomlMcpServers => edit_toml_gateway(&path, install, profile)?,
        Format::YamlExtensions => edit_yaml_gateway(&path, install, profile)?,
        Format::YamlMcpServers => edit_hermes_yaml_gateway(&path, install, profile)?,
        Format::YamlMcpServersList => edit_continue_yaml_gateway(&path, install, profile)?,
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

    #[test]
    fn app_present_distinguishes_installed_from_absent() {
        // Config file present => app is obviously present.
        assert!(app_present_for("/anywhere/config.json", true));
        // No resolvable path => not detectable.
        assert!(!app_present_for("", false));
        // Data dir exists but no MCP config yet (the "installed, no servers" case
        // that used to read as "not found") => present.
        let cfg = std::env::temp_dir().join("conduit-app-present-probe.json");
        assert!(app_present_for(&cfg.to_string_lossy(), false));
        // Parent dir absent => app not installed here.
        assert!(!app_present_for(
            "/no/such/dir/deep/conduit-absent/config.json",
            false
        ));
    }

    fn stdio(name: &str) -> ServerEntry {
        ServerEntry {
            id: name.to_string(),
            name: name.to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".to_string()),
            args: vec![
                "-y".to_string(),
                format!("@modelcontextprotocol/server-{name}"),
            ],
            env: vec![EnvVar {
                key: "TOKEN".to_string(),
                value: Some("plain-value".to_string()),
                secret: false,
            }],
            url: None,
            source: None,
            disabled_tools: vec![],
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("conduit-w-{}-{}.cfg", std::process::id(), label))
    }

    #[test]
    fn read_config_file_reads_regular_rejects_others() {
        let path = temp_path("read-cfg");
        std::fs::remove_file(&path).ok();
        // A normal small config reads back verbatim.
        std::fs::write(&path, "{\"ok\":true}").unwrap();
        assert_eq!(read_config_file(&path).unwrap(), "{\"ok\":true}");
        // A directory is not a regular file -> refused (portable stand-in for a
        // device/FIFO, which we can't create on every platform).
        assert!(read_config_file(&std::env::temp_dir()).is_err());
        // A missing file is an error.
        std::fs::remove_file(&path).ok();
        assert!(read_config_file(&path).is_err());
    }

    #[test]
    fn json_mcpservers_round_trips() {
        let path = temp_path("json-mcp");
        std::fs::remove_file(&path).ok();
        let servers = vec![stdio("filesystem"), stdio("github")];
        write_json(&path, "mcpServers", &servers, false).unwrap();
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
        assert_eq!(
            parsed[0].url.as_deref(),
            Some("https://mcp.supabase.com/mcp")
        );
        assert_eq!(parsed[0].transport, "http");
    }

    #[test]
    fn json_write_preserves_unrelated_keys() {
        let path = temp_path("json-preserve");
        std::fs::write(
            &path,
            r#"{"theme":"dark","mcpServers":{"old":{"command":"x"}}}"#,
        )
        .unwrap();
        write_json(&path, "mcpServers", &[stdio("fresh")], false).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(root.get("theme").and_then(|v| v.as_str()), Some("dark"));
        let servers = root.get("mcpServers").unwrap().as_object().unwrap();
        assert!(servers.contains_key("fresh"));
        assert!(!servers.contains_key("old"));
    }

    #[test]
    fn json_parse_error_includes_line_and_column() {
        let content = r#"{"mcpServers": {broken"#;
        let err = parse_json(content, "mcpServers").unwrap_err();
        assert!(err.contains("JSON syntax error"), "got: {err}");
        assert!(err.contains("line"), "got: {err}");
    }

    #[test]
    fn json_malformed_server_entry_names_key() {
        let content = r#"{"mcpServers":{"good":{"command":"npx"},"bad":"not-an-object"}}"#;
        let err = parse_json(content, "mcpServers").unwrap_err();
        assert!(err.contains("bad"), "error should name the bad entry: {err}");
        assert!(err.contains("malformed 'mcpServers' entry"));
    }

    #[test]
    fn json_wrong_key_type_is_reported() {
        let content = r#"{"mcpServers":"not-an-object"}"#;
        let err = parse_json(content, "mcpServers").unwrap_err();
        assert!(err.contains("mcpServers"), "got: {err}");
        assert!(err.contains("must be an object"), "got: {err}");
    }

    #[test]
    fn toml_malformed_mcp_server_entry_returns_error() {
        let content = r#"
[mcp_servers]
good = { command = "npx", args = ["-y", "server"] }
bad = "not-a-table"
"#;
        let err = parse_toml(content).unwrap_err();
        assert!(err.contains("bad"), "error should name the bad entry: {err}");
        assert!(err.contains("malformed mcp_servers entry"));
    }

    #[test]
    fn toml_syntax_error_includes_location() {
        let content = "[mcp_servers]\nbad = { command = \"unclosed\n";
        let err = parse_toml(content).unwrap_err();
        assert!(err.contains("TOML syntax error"), "got: {err}");
        assert!(err.contains("line"), "got: {err}");
    }

    #[test]
    fn yaml_extensions_syntax_error_includes_location() {
        let content = "extensions:\n  fetch:\n    cmd: uvx\n bad-indent: true\n";
        let err = parse_yaml_extensions(content).unwrap_err();
        assert!(err.contains("YAML syntax error"), "got: {err}");
        assert!(err.contains("line"), "got: {err}");
    }

    #[test]
    fn yaml_extensions_malformed_entry_names_key() {
        let content = "extensions:\n  good:\n    type: stdio\n    cmd: uvx\n  bad: not-a-mapping\n";
        let err = parse_yaml_extensions(content).unwrap_err();
        assert!(err.contains("bad"), "error should name the bad entry: {err}");
        assert!(err.contains("malformed 'extensions' entry"));
    }

    #[test]
    fn hermes_yaml_syntax_error_includes_location() {
        let content = "mcp_servers:\n  srv:\n    url: https://example.com\n  bad:\n  - [unbalanced\n";
        let err = parse_hermes_yaml_servers(content).unwrap_err();
        assert!(err.contains("YAML syntax error"), "got: {err}");
        assert!(err.contains("line"), "got: {err}");
    }

    #[test]
    fn hermes_yaml_malformed_entry_names_key() {
        let content = "mcp_servers:\n  good:\n    url: https://example.com\n  bad: not-a-mapping\n";
        let err = parse_hermes_yaml_servers(content).unwrap_err();
        assert!(err.contains("bad"), "error should name the bad entry: {err}");
        assert!(err.contains("malformed 'mcp_servers' entry"));
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
        let root: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
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

        edit_json_gateway(&path, "mcpServers", true, Some("Billing"), false).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key("conduit"));
        assert!(servers.contains_key("existing"));
        // Discovery mode comes from the registry, not the client config; only the
        // profile scope is written as an env var.
        assert_eq!(servers["conduit"]["env"]["CONDUIT_PROFILE"], "Billing");
        assert!(servers["conduit"]["env"].get("CONDUIT_DISCOVERY").is_none());
        // Unrelated key and the existing server's secret value are untouched.
        assert_eq!(root["theme"], "dark");
        assert_eq!(servers["existing"]["env"]["SECRET"], "keepme");

        edit_json_gateway(&path, "mcpServers", false, None, false).unwrap();
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
            let target = s
                .command
                .clone()
                .or_else(|| s.url.clone())
                .unwrap_or_default();
            println!("  {} [{}] {}", s.name, s.transport, target);
        }
    }

    #[test]
    fn install_override_targets_the_unreliable_clients() {
        // Clients whose config-parent heuristic is wrong get an explicit install dir.
        assert!(
            install_override("claude-code")
                .unwrap()
                .ends_with(".claude"),
            "Claude Code must check ~/.claude, not the home dir its config sits in"
        );
        assert!(install_override("kiro").unwrap().ends_with(".kiro"));
        let _ = install_override("warp"); // env-dependent; just ensure no panic.
                                          // Well-behaved clients have no override (they use the config-parent heuristic).
        assert!(install_override("cursor").is_none());
        assert!(install_override("codex").is_none());
        assert!(install_override("vscode").is_none());
    }

    #[test]
    fn zed_context_servers_jsonc_round_trip() {
        let path = std::env::temp_dir().join(format!("conduit-zed-{}.json", std::process::id()));
        // JSONC: line comment, trailing comma, an unrelated user setting.
        std::fs::write(
            &path,
            "// my zed settings\n{\n  \"ui_font_size\": 16,\n  \"context_servers\": {\n    \"existing\": { \"command\": \"x\", \"args\": [] },\n  },\n}\n",
        )
        .unwrap();

        // Parsing tolerates the comments/trailing commas.
        let parsed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "context_servers").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "existing");

        // Installing preserves the unrelated key and the existing server.
        edit_json_gateway(&path, "context_servers", true, None, true).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["ui_font_size"], 16);
        let cs = root["context_servers"].as_object().unwrap();
        assert!(cs.contains_key("conduit"));
        assert!(cs.contains_key("existing"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lenient_edit_never_wipes_unparseable_config() {
        let path = std::env::temp_dir().join(format!("conduit-bad-{}.json", std::process::id()));
        let garbage = "this is not json or json5 at all {{{";
        std::fs::write(&path, garbage).unwrap();
        // A lenient edit must ERROR, never replace the file with an empty object.
        assert!(edit_json_gateway(&path, "context_servers", true, None, true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn zed_is_registered_as_context_servers() {
        let d = defs().into_iter().find(|d| d.id == "zed").unwrap();
        assert!(matches!(d.format, Format::JsonContextServers));
        assert!((d.path)().is_some());
    }

    #[test]
    fn new_json_clients_are_registered() {
        // Warp, Amazon Q, Kiro, and LM Studio all use the standard mcpServers JSON
        // shape, so a ClientDef + path is all they need. Lock in their registration,
        // format, and that their config paths resolve on this OS.
        for id in ["warp", "amazon-q", "kiro", "lm-studio", "jan"] {
            let d = defs()
                .into_iter()
                .find(|d| d.id == id)
                .unwrap_or_else(|| panic!("missing client def: {id}"));
            assert!(
                matches!(d.format, Format::JsonMcpServers),
                "{id} should use mcpServers JSON"
            );
            assert!((d.path)().is_some(), "{id} path should resolve");
        }
    }

    #[test]
    fn goose_yaml_round_trip_preserves_config() {
        let path = temp_path("goose.yaml");
        // A real config.yaml has model settings AND extensions; touch neither but ours.
        std::fs::write(
            &path,
            "GOOSE_MODEL: gpt-4o\nextensions:\n  fetch:\n    enabled: true\n    type: stdio\n    name: fetch\n    cmd: uvx\n    args:\n      - mcp-server-fetch\n    envs: {}\n    timeout: 300\n",
        )
        .unwrap();

        // Parse reads the existing extension as a stdio server.
        let parsed = parse_yaml_extensions(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "fetch");
        assert_eq!(parsed[0].command.as_deref(), Some("uvx"));
        assert_eq!(parsed[0].transport, "stdio");

        // Installing the gateway preserves the model key and the existing extension.
        edit_yaml_gateway(&path, true, None).unwrap();
        let v: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v.get("GOOSE_MODEL").and_then(|x| x.as_str()),
            Some("gpt-4o")
        );
        let exts = v.get("extensions").and_then(|x| x.as_mapping()).unwrap();
        assert!(exts.get("fetch").is_some());
        let conduit = exts.get("conduit").and_then(|x| x.as_mapping()).unwrap();
        assert_eq!(conduit.get("type").and_then(|x| x.as_str()), Some("stdio"));
        assert_eq!(conduit.get("enabled").and_then(|x| x.as_bool()), Some(true));
        assert!(conduit.get("cmd").and_then(|x| x.as_str()).is_some());

        // Uninstall removes only conduit.
        edit_yaml_gateway(&path, false, None).unwrap();
        let after: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let exts2 = after
            .get("extensions")
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert!(exts2.get("conduit").is_none());
        assert!(exts2.get("fetch").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn goose_yaml_edit_never_wipes_unparseable() {
        let path = temp_path("goose-bad.yaml");
        let garbage = "key: value\n  - [unbalanced flow sequence\n:::not valid";
        std::fs::write(&path, garbage).unwrap();
        // A parse failure must error, never replace config.yaml (it holds model config).
        assert!(edit_yaml_gateway(&path, true, None).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn goose_is_registered_as_yaml_extensions() {
        let d = defs().into_iter().find(|d| d.id == "goose").unwrap();
        assert!(matches!(d.format, Format::YamlExtensions));
        assert!((d.path)().is_some());
    }

  
   
   #[test]
    fn continue_yaml_parses_stdio_server() {
        let content = "mcpServers:\n  - name: fetch\n    command: uvx\n    args:\n      - mcp-server-fetch\n    env:\n      TOKEN: abc123\n";

        let parsed = parse_continue_yaml_servers(content).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "fetch");
        assert_eq!(parsed[0].command.as_deref(), Some("uvx"));
        assert_eq!(parsed[0].transport, "stdio");
        assert_eq!(parsed[0].args, vec!["mcp-server-fetch"]);
        assert_eq!(parsed[0].env_keys, vec!["TOKEN".to_string()]);
    }

    #[test]
    fn continue_yaml_malformed_entry_returns_error() {
        let content = "mcpServers:\n  - name: fetch\n    command: uvx\n  - not-a-mapping\n";

        let err = parse_continue_yaml_servers(content).unwrap_err();

        assert!(
            err.contains("mcpServers[1]"),
            "error should identify the malformed entry: {err}"
        );
        assert!(err.contains("malformed 'mcpServers' entry"));
}

    #[test]
    fn hermes_yaml_round_trip_preserves_config() {
        let path = temp_path("hermes.yaml");
        // A real config.yaml has model settings AND mcp_servers; touch neither but ours.
        std::fs::write(
            &path,
            "model:\n  default: gpt-4o\nmcp_servers:\n  zread:\n    connect_timeout: 30\n    headers:\n      Authorization: Bearer token\n    timeout: 120\n    url: https://mcp.example.com/mcp\n",
        )
        .unwrap();

        // Parse reads the existing server as an HTTP server.
        let parsed = parse_hermes_yaml_servers(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "zread");
        assert_eq!(
            parsed[0].url.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(parsed[0].transport, "http");
        assert_eq!(parsed[0].env_keys, vec!["Authorization".to_string()]);

        // Installing the gateway preserves the model key and the existing server.
        edit_hermes_yaml_gateway(&path, true, None).unwrap();
        let v: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v.get("model")
                .and_then(|m| m.get("default"))
                .and_then(|x| x.as_str()),
            Some("gpt-4o")
        );
        let servers = v.get("mcp_servers").and_then(|x| x.as_mapping()).unwrap();
        assert!(servers.get("zread").is_some());
        let conduit = servers.get("conduit").and_then(|x| x.as_mapping()).unwrap();
        assert!(conduit.get("command").and_then(|x| x.as_str()).is_some());

        // Uninstall removes only conduit.
        edit_hermes_yaml_gateway(&path, false, None).unwrap();
        let after: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = after
            .get("mcp_servers")
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert!(servers2.get("conduit").is_none());
        assert!(servers2.get("zread").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hermes_yaml_edit_never_wipes_unparseable() {
        let path = temp_path("hermes-bad.yaml");
        let garbage = "key: value\n  - [unbalanced flow sequence\n:::not valid";
        std::fs::write(&path, garbage).unwrap();
        // A parse failure must error, never replace config.yaml (it holds model config).
        assert!(edit_hermes_yaml_gateway(&path, true, None).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hermes_mcp_servers_mut_recovers_from_non_mapping() {
        // If mcp_servers is a scalar (corrupt but parseable YAML), the helper
        // must replace it with an empty map instead of panicking.
        let mut root: serde_yaml::Value = serde_yaml::from_str("mcp_servers: oops").unwrap();
        let m = hermes_mcp_servers_mut(&mut root);
        assert!(m.is_empty());
        // After inserting a gateway, the key is a proper mapping.
        m.insert(
            serde_yaml::Value::String("conduit".into()),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
        let back: serde_yaml::Value =
            serde_yaml::from_str(&serde_yaml::to_string(&root).unwrap()).unwrap();
        assert!(back.get("mcp_servers").unwrap().is_mapping());
    }

    #[test]
    fn hermes_is_registered_as_yaml_mcp_servers() {
        let d = defs().into_iter().find(|d| d.id == "hermes").unwrap();
        assert!(matches!(d.format, Format::YamlMcpServers));
        assert!((d.path)().is_some());
    }

    fn mock_home(platform: Platform) -> PathBuf {
        match platform {
            Platform::Windows => PathBuf::from(r"C:\Users\alice"),
            Platform::MacOs => PathBuf::from("/Users/alice"),
            Platform::Linux => PathBuf::from("/home/alice"),
        }
    }

    /// Serializes tests that read or mutate the process-global XDG env vars. Rust
    /// runs tests in parallel, so without this the test that sets `XDG_CONFIG_HOME`
    /// could change `dirs::config_dir()` mid-flight under a test that reads it,
    /// which is exactly what made `client_config_paths_match_current_platform`
    /// flake on CI. Poison is recovered: a panic elsewhere shouldn't wedge these.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn client_config_paths_match_current_platform() {
        // Hold the env lock: the path resolution reads `dirs::config_dir()`, which
        // another test mutates via `XDG_CONFIG_HOME`. Serialize so we never read it
        // mid-change.
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home = home().expect("home dir should be available in tests");
        let platform = Platform::current();
        for client in defs() {
            if matches!(client.id, "antigravity" | "claude-desktop") {
                // These probe alternate on-disk locations (Antigravity subdirs,
                // Claude Desktop MSIX virtualized config).
                continue;
            }
            #[cfg(not(all(unix, not(target_os = "macos"))))]
            let expected = resolve_client_config_path(client.id, &home, platform)
                .unwrap_or_else(|| panic!("missing path expectation for {}", client.id));
            #[cfg(all(unix, not(target_os = "macos")))]
            let expected = resolve_client_config_path_linux(client.id, &home)
                .unwrap_or_else(|| panic!("missing linux path expectation for {}", client.id));
            let actual = (client.path)()
                .unwrap_or_else(|| panic!("{} path should resolve on this host", client.id));
            assert_eq!(actual, expected, "{}", client.id);
        }
    }

    #[test]
    fn client_config_paths_are_stable_across_platforms() {
        let cases: &[(&str, fn(&Path, Platform) -> PathBuf)] = &[
            ("cursor", |home, _| home.join(".cursor").join("mcp.json")),
            (
                "vscode",
                |home, platform| {
                    roaming_config_dir(home, platform)
                        .join("Code")
                        .join("User")
                        .join("mcp.json")
                },
            ),
            (
                "claude-desktop",
                |home, platform| {
                    roaming_config_dir(home, platform)
                        .join("Claude")
                        .join("claude_desktop_config.json")
                },
            ),
            (
                "cline",
                |home, platform| {
                    roaming_config_dir(home, platform)
                        .join("Code")
                        .join("User")
                        .join("globalStorage")
                        .join("saoudrizwan.claude-dev")
                        .join("settings")
                        .join("cline_mcp_settings.json")
                },
            ),
            (
                "goose",
                |home, platform| match platform {
                    Platform::Windows => home
                        .join("AppData")
                        .join("Roaming")
                        .join("Block")
                        .join("goose")
                        .join("config")
                        .join("config.yaml"),
                    Platform::MacOs => home
                        .join("Library")
                        .join("Application Support")
                        .join("Block")
                        .join("goose")
                        .join("config.yaml"),
                    Platform::Linux => home.join(".config").join("goose").join("config.yaml"),
                },
            ),
            (
                "zed",
                |home, platform| match platform {
                    Platform::Windows => home
                        .join("AppData")
                        .join("Roaming")
                        .join("Zed")
                        .join("settings.json"),
                    Platform::MacOs | Platform::Linux => {
                        home.join(".config").join("zed").join("settings.json")
                    }
                },
            ),
            (
                "jan",
                |home, platform| match platform {
                    Platform::Windows | Platform::MacOs => app_data_dir(home, platform)
                        .join("Jan")
                        .join("data")
                        .join("mcp_config.json"),
                    Platform::Linux => home
                        .join(".local")
                        .join("share")
                        .join("Jan")
                        .join("data")
                        .join("mcp_config.json"),
                },
            ),
        ];

        for (client_id, build_expected) in cases {
            for platform in Platform::ALL {
                let home = mock_home(platform);
                let path = resolve_client_config_path(client_id, &home, platform)
                    .unwrap_or_else(|| panic!("missing path for {client_id} on {platform:?}"));
                let expected = build_expected(&home, platform);
                assert_eq!(path, expected, "{client_id} on {platform:?}");
            }
        }
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn client_config_paths_honor_xdg_dirs_on_linux() {
        // Hold the env lock across the set/read/remove so no concurrent test reads
        // `dirs::config_dir()` while XDG is temporarily overridden here.
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("conduit-xdg-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let xdg_config = base.join("xdg-config");
        let xdg_data = base.join("xdg-data");
        std::fs::create_dir_all(&xdg_config).unwrap();
        std::fs::create_dir_all(&xdg_data).unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &xdg_config);
        std::env::set_var("XDG_DATA_HOME", &xdg_data);

        let home = home().expect("home dir");
        let vscode = client_config_path("vscode").unwrap();
        let jan = client_config_path("jan").unwrap();

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_DATA_HOME");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            vscode,
            xdg_config.join("Code").join("User").join("mcp.json")
        );
        assert_eq!(
            jan,
            xdg_data.join("Jan").join("data").join("mcp_config.json")
        );
        let _ = home;
    }
}
