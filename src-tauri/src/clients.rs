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
    /// Whether the Toolport gateway is currently installed in this client's config.
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

/// The name Toolport uses for its own entry when installed into a client config.
pub const GATEWAY_ENTRY_NAME: &str = "conduit";

/// Match the frozen canonical name, the short-lived `toolport` name used by
/// manual installs, and both current and pre-rename gateway binary names.
fn gateway_identity_matches(id: &str, name: &str, command: Option<&str>) -> bool {
    let has_gateway_name = |value: &str| {
        value.eq_ignore_ascii_case(GATEWAY_ENTRY_NAME) || value.eq_ignore_ascii_case("toolport")
    };

    has_gateway_name(id)
        || has_gateway_name(name)
        || command
            .map(|command| {
                let command = command.to_lowercase();
                command.contains("toolport-gateway") || command.contains("conduit-gateway")
            })
            .unwrap_or(false)
}

/// Whether a registry entry refers to Toolport's own gateway. The gateway must
/// never proxy itself (that recurses), and import must never pull it in.
pub fn is_gateway_server(server: &ServerEntry) -> bool {
    gateway_identity_matches(&server.id, &server.name, server.command.as_deref())
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
/// `dirs::config_dir()`, matching how the registry path is anchored. Note the
/// path *spelling* alone does not escape MSIX virtualization: inside a packaged
/// app's container the filesystem filter redirects `AppData\Roaming` opens to the
/// package's LocalCache shadow regardless of how the path was derived (see
/// `registry::conduit_dir`, which detects the container and de-virtualizes).
/// This helper runs in the Toolport app, which is never containerized, so the
/// natural path is correct here.
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
        "pi" => home.join(".pi").join("agent").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        "codex" => home.join(".codex").join("config.toml"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "antigravity" => home.join(".gemini").join("config").join("mcp_config.json"),
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
        "anythingllm" => match platform {
            Platform::Windows => config
                .join("anythingllm-desktop")
                .join("storage")
                .join("plugins")
                .join("anythingllm_mcp_servers.json"),
            Platform::MacOs => home
                .join("Library")
                .join("Application Support")
                .join("anythingllm-desktop")
                .join("storage")
                .join("plugins")
                .join("anythingllm_mcp_servers.json"),
            Platform::Linux => home
                .join(".config")
                .join("anythingllm-desktop")
                .join("storage")
                .join("plugins")
                .join("anythingllm_mcp_servers.json"),
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
        "pi" => home.join(".pi").join("agent").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        "codex" => home.join(".codex").join("config.toml"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "antigravity" => home.join(".gemini").join("config").join("mcp_config.json"),
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
        "anythingllm" => home
            .join(".config")
            .join("anythingllm-desktop")
            .join("storage")
            .join("plugins")
            .join("anythingllm_mcp_servers.json"),
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

fn anythingllm_path() -> Option<PathBuf> {
    client_config_path("anythingllm")
}

fn boltai_path() -> Option<PathBuf> {
    client_config_path("boltai")
}

/// Pi coding agent reads its Pi-owned global MCP config from ~/.pi/agent/mcp.json
/// (standard `mcpServers` shape; pi's optional `lifecycle`/`idleTimeout` keys are
/// left unset so it uses its defaults). Home-anchored, identical on every OS.
fn pi_path() -> Option<PathBuf> {
    client_config_path("pi")
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

fn plugin_cache_dir_from_settings_path(settings_path: &Path) -> Option<PathBuf> {
    Some(
        settings_path
            .parent()?
            .parent()?
            .join("plugins")
            .join("cache"),
    )
}

fn roo_code_plugins_dir() -> Option<PathBuf> {
    plugin_cache_dir_from_settings_path(&roo_code_path()?)
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

/// Read plugin MCP servers from `**/mcp.json` or `**/.mcp.json` files.
/// Two shapes appear: `{ "<name>": {...} }` and `{ "mcpServers": { ... } }`.
fn scan_plugin_mcp_servers(dir: &Path) -> Vec<McpServer> {
    if !dir.exists() {
        return Vec::new();
    }
    let mut files = Vec::new();
    collect_mcp_files(dir, &mut files, 8);

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

/// Read Cursor's plugin MCP servers from `~/.cursor/plugins/cache/**/mcp.json`.
fn scan_cursor_plugins() -> Vec<McpServer> {
    cursor_plugins_dir()
        .map(|dir| scan_plugin_mcp_servers(&dir))
        .unwrap_or_default()
}

/// Read Roo Code's plugin MCP servers from its global storage plugin cache.
fn scan_roo_code_plugins() -> Vec<McpServer> {
    roo_code_plugins_dir()
        .map(|dir| scan_plugin_mcp_servers(&dir))
        .unwrap_or_default()
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
            id: "anythingllm",
            name: "AnythingLLM",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: anythingllm_path,
            plugin_scan: None,
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
            plugin_scan: Some(scan_roo_code_plugins),
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
            id: "pi",
            name: "Pi",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: pi_path,
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
    // Delegate to the with-values parser, then strip values for the security
    // boundary: detection reads other apps' files, so env values must not leak.
    let parsed = json_server_with_values(name, def);
    McpServer {
        name: parsed.name,
        transport: parsed.transport,
        command: parsed.command,
        args: parsed.args,
        env_keys: parsed.env.into_iter().map(|e| e.key).collect(),
        url: parsed.url,
    }
}

/// A server parsed from a user-pasted config snippet. Unlike `McpServer` (which
/// only carries env-var keys for security), this includes env-var VALUES because
/// the user explicitly pasted them — many are non-secret paths/flags
/// (OD_DATA_DIR, ELECTRON_RUN_AS_NODE), and discarding them would force
/// pointless re-entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedSnippetServer {
    pub name: String,
    /// "stdio" | "http" | "sse" | "unknown"
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    /// Full env entries (key + optional value), since the user pasted them.
    pub env: Vec<SnippetEnvVar>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetEnvVar {
    pub key: String,
    pub value: Option<String>,
}

/// Like `json_server`, but also captures env-var values from the JSON def.
/// Used for pasted snippets where the user is voluntarily providing values.
/// Non-string values (numbers, booleans) are stringified so e.g.
/// `{"PORT": 3000}` doesn't silently lose its value.
fn json_server_with_values(name: &str, def: &serde_json::Value) -> ParsedSnippetServer {
    let command = def
        .get("command")
        .and_then(|c| c.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
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
    let env = def
        .get("env")
        .and_then(|e| e.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, v)| SnippetEnvVar {
                    key: k.clone(),
                    value: json_value_to_string(v),
                })
                .collect()
        })
        .unwrap_or_default();
    let type_hint = def.get("type").and_then(|t| t.as_str());
    let transport = classify(&command, &url, type_hint);
    ParsedSnippetServer {
        name: name.to_string(),
        transport,
        command,
        args,
        url,
        env,
    }
}

/// Coerce a JSON value to its env-var string representation. Strings pass
/// through; numbers/booleans are stringified; null/objects/arrays yield None
/// (they're not valid env values).
fn json_value_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
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

/// Extract a server definition from a `claude mcp add-json` CLI invocation.
/// Pattern: `claude mcp add-json [--scope <scope>] <name> '<json>'`
/// Returns (name, json_string) if the input matches, else None.
fn extract_claude_cli(input: &str) -> Option<(String, String)> {
    let trimmed = input.trim();
    if !trimmed.starts_with("claude mcp add-json") {
        return None;
    }
    // Find the JSON payload: first `{` to its matching `}`, skipping braces
    // that appear inside JSON string literals (e.g. `"desc": "use { for blocks"`).
    let start = trimmed.find('{')?;
    let bytes = trimmed.as_bytes();
    let mut depth = 0i32;
    let mut end = start;
    let mut in_string = false;
    let mut escape = false;
    let mut i = start;
    while i < trimmed.len() {
        let ch = bytes[i];
        if in_string {
            if escape {
                escape = false;
            } else if ch == b'\\' {
                escape = true;
            } else if ch == b'"' {
                in_string = false;
            }
        } else if ch == b'"' {
            in_string = true;
        } else if ch == b'{' {
            depth += 1;
        } else if ch == b'}' {
            depth -= 1;
            if depth == 0 {
                end = i;
                break;
            }
        }
        i += 1;
    }
    if depth != 0 {
        return None;
    }
    let json_str = &trimmed[start..=end];

    // Extract the server name: the last non-flag token before the JSON.
    // Tokens are trimmed of shell quotes first, then filtered.
    let before = trimmed[..start].trim();
    let name = before
        .split_whitespace()
        .map(|tok| tok.trim_matches(|c| c == '\'' || c == '"'))
        .rfind(|tok| {
            !tok.eq_ignore_ascii_case("claude")
                && !tok.eq_ignore_ascii_case("mcp")
                && !tok.eq_ignore_ascii_case("add-json")
                && !tok.starts_with("--")
                && !tok.is_empty()
        })
        .map(String::from);

    Some((name.unwrap_or_default(), json_str.to_string()))
}

/// Parse a pasted config snippet, auto-detecting the format.
///
/// Tries each format in order: Claude Code CLI → TOML → JSON (mcpServers,
/// servers, context_servers, or bare server object) → YAML. Returns all servers
/// found (the first is pre-filled in the UI; extras get a toast).
///
/// Unlike `detect_clients`, this includes env-var values because the user
/// explicitly pasted them.
pub fn parse_snippet(content: &str) -> Result<Vec<ParsedSnippetServer>, String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("Empty input".to_string());
    }

    // 1. Claude Code CLI: `claude mcp add-json ... <name> '{...}'`
    if let Some((name, json_str)) = extract_claude_cli(trimmed) {
        let value: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| format!("Invalid JSON in CLI command: {e}"))?;
        // Bare server object (the common case from the CLI).
        if value.is_object() && (value.get("command").is_some() || value.get("url").is_some()) {
            return Ok(vec![json_server_with_values(&name, &value)]);
        }
        // Wrapped in a key (unusual for CLI, but handle it).
        return parse_json_snippet(&json_str, &name);
    }

    // 2. TOML: `[mcp_servers.<name>]` tables. Check before JSON because TOML
    //    table headers start with `[`, which would otherwise match the JSON
    //    array heuristic below.
    if trimmed.contains("[mcp_servers.") || trimmed.contains("[mcp_servers]") {
        return parse_toml_snippet(trimmed);
    }

    // 3. JSON (including JSON5 for Zed-style comments).
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return parse_json_snippet(trimmed, "");
    }

    // 4. YAML fallback (Hermes `mcp_servers:` or Goose `extensions:`).
    if let Ok(servers) = parse_yaml_snippet(trimmed) {
        if !servers.is_empty() {
            return Ok(servers);
        }
    }

    Err(
        "Could not detect format. Expected JSON, TOML, YAML, or a 'claude mcp add-json' command."
            .to_string(),
    )
}

/// The base program name of a command: the file name, lowercased, without a
/// `.exe`/`.cmd`/`.ps1` extension (so `C:\...\npx.cmd` -> `npx`).
fn launcher_base(command: &str) -> String {
    let file = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let lower = file.to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".ps1"] {
        if let Some(stripped) = lower.strip_suffix(ext) {
            return stripped.to_string();
        }
    }
    lower
}

/// If the command is a package runner (npx, uvx, bunx, pnpm/yarn dlx, npm exec/x,
/// pipx run), return the package it runs - the meaningful identity - rather than
/// the runner. Mirrors `isDownloadLauncher` in the frontend. `None` when the
/// command is a normal program (then the command name itself is the identity).
fn launcher_package_arg(command: &str, args: &[String]) -> Option<String> {
    // Tolerate a packed `"npx -y @scope/pkg"` command with empty args.
    let (base, argv): (String, Vec<String>) = if args.is_empty() {
        let mut parts = command.split_whitespace();
        let first = parts.next().unwrap_or("");
        (launcher_base(first), parts.map(str::to_string).collect())
    } else {
        (launcher_base(command), args.to_vec())
    };
    let sub = argv.first().map(String::as_str);
    let pkg_start = match base.as_str() {
        "npx" | "uvx" | "bunx" => 0,
        "pnpm" | "yarn" if sub == Some("dlx") => 1,
        "npm" if matches!(sub, Some("exec") | Some("x")) => 1,
        "pipx" if sub == Some("run") => 1,
        _ => return None,
    };
    // Find the package among the runner's args. An explicit `--package=<pkg>` /
    // `--package <pkg>` / `-p <pkg>` wins; otherwise it's the first positional
    // (non-flag) token. Stop at `--`: everything after it is the command to run
    // inside the package, not the package itself.
    let mut it = argv.iter().skip(pkg_start);
    while let Some(tok) = it.next() {
        if tok == "--" {
            break;
        }
        if let Some(pkg) = tok.strip_prefix("--package=") {
            return Some(pkg.to_string());
        }
        if tok == "--package" || tok == "-p" {
            return it.next().cloned();
        }
        if !tok.starts_with('-') {
            return Some(tok.clone());
        }
    }
    None
}

/// Turn a package spec into a friendly server name: drop the `@scope/`, drop a
/// `@version` suffix, and strip the ubiquitous MCP name affixes, so
/// `@verygoodplugins/mcp-automem` -> `automem` and
/// `@modelcontextprotocol/server-github` -> `github`.
fn package_friendly_name(pkg: &str) -> String {
    let no_scope = pkg
        .strip_prefix('@')
        .and_then(|s| s.split_once('/'))
        .map(|(_, n)| n)
        .unwrap_or(pkg);
    let no_version = no_scope.split('@').next().unwrap_or(no_scope);
    let mut core = no_version;
    for p in ["mcp-server-", "mcp-", "server-"] {
        if let Some(rest) = core.strip_prefix(p) {
            core = rest;
            break;
        }
    }
    for s in ["-mcp-server", "-server-mcp", "-mcp", "-server"] {
        if let Some(rest) = core.strip_suffix(s) {
            core = rest;
            break;
        }
    }
    if core.is_empty() { no_version } else { core }.to_string()
}

/// The file stem of a command path, splitting on both `/` and `\` so a
/// Windows-style path resolves on a Unix host too (std's `Path` only treats `/`
/// as a separator there, so `C:\...\foo.exe` would otherwise stay intact). Keeps
/// original case; drops a single trailing extension, preserving dotfiles.
fn command_stem(command: &str) -> String {
    let file = command.rsplit(['/', '\\']).next().unwrap_or(command);
    match file.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem.to_string(),
        _ => file.to_string(),
    }
}

/// Derive a display name for a bare (unnamed) pasted server from its invocation:
/// the package a runner launches (so every `npx ...` server doesn't collapse to
/// the name "npx"), else the command's own file stem.
fn name_from_invocation(command: &str, args: &[String]) -> String {
    if let Some(pkg) = launcher_package_arg(command, args) {
        return package_friendly_name(&pkg);
    }
    command_stem(command)
}

/// Key an imported server for bulk-import dedupe. The friendly display name
/// intentionally drops a package scope, so keying on it alone collapses
/// `@acme/mcp-weather` and `@other/mcp-weather` (both name "weather") during
/// import (#257). Fold the launched package spec into the key so those stay
/// distinct, but keep the name as a tiebreaker so two entries for the SAME
/// package under different names (e.g. `github-personal` and `github-work`,
/// one token each) both survive instead of silently collapsing to one. Servers
/// without a recognizable runner package key on name alone, as before.
pub fn import_dedupe_key(name: &str, command: Option<&str>, args: &[String]) -> String {
    let name = name.to_ascii_lowercase();
    match command.and_then(|command| launcher_package_arg(command, args)) {
        Some(package) => format!("package:{}|name:{}", package.to_ascii_lowercase(), name),
        None => format!("name:{}", name),
    }
}

/// Parse a JSON snippet, trying each known wrapper key, then a bare server object.
fn parse_json_snippet(
    content: &str,
    forced_name: &str,
) -> Result<Vec<ParsedSnippetServer>, String> {
    let value = parse_json_value(content)?;

    // Try each wrapper key.
    for key in ["mcpServers", "servers", "context_servers"] {
        if let Some(obj) = value.get(key).and_then(|v| v.as_object()) {
            let servers: Vec<ParsedSnippetServer> = obj
                .iter()
                .filter(|(_, def)| def.is_object())
                .map(|(name, def)| json_server_with_values(name, def))
                .collect();
            if !servers.is_empty() {
                return Ok(servers);
            }
        }
    }

    // Bare server object: has `command` or `url` at the top level.
    if value.get("command").is_some() || value.get("url").is_some() {
        let name = if forced_name.is_empty() {
            // Derive a name from the invocation. A package runner (npx, uvx, ...)
            // is named after the package it runs, not the runner - otherwise every
            // `npx -y <pkg>` server collapses to the name (and id, and tool prefix)
            // "npx" and they all collide. See issue #251.
            let command = value.get("command").and_then(|c| c.as_str()).unwrap_or_default();
            let args: Vec<String> = value
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            name_from_invocation(command, &args)
        } else {
            forced_name.to_string()
        };
        return Ok(vec![json_server_with_values(&name, &value)]);
    }

    Err("JSON parsed but no server definition found (expected mcpServers, servers, context_servers, or a bare server object)".to_string())
}

/// Parse a TOML snippet with `[mcp_servers.<name>]` tables.
fn parse_toml_snippet(content: &str) -> Result<Vec<ParsedSnippetServer>, String> {
    let value: toml::Value = toml::from_str(content).map_err(|e| e.to_string())?;
    let table = value
        .get("mcp_servers")
        .and_then(|v| v.as_table())
        .ok_or("No [mcp_servers] table found in TOML")?;

    let servers: Vec<ParsedSnippetServer> = table
        .iter()
        .filter(|(_, def)| def.is_table())
        .map(|(name, def)| {
            let command = def
                .get("command")
                .and_then(|c| c.as_str())
                .map(String::from);
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
            let env = def
                .get("env")
                .and_then(|e| e.as_table())
                .map(|t| {
                    t.iter()
                        .map(|(k, v)| SnippetEnvVar {
                            key: k.clone(),
                            value: toml_value_to_string(v),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let type_hint = def.get("type").and_then(|t| t.as_str());
            let transport = classify(&command, &url, type_hint);
            ParsedSnippetServer {
                name: name.clone(),
                transport,
                command,
                args,
                url,
                env,
            }
        })
        .collect();

    if servers.is_empty() {
        Err("No servers found in TOML mcp_servers table".to_string())
    } else {
        Ok(servers)
    }
}

/// Coerce a TOML value to its env-var string representation.
fn toml_value_to_string(v: &toml::Value) -> Option<String> {
    match v {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Integer(i) => Some(i.to_string()),
        toml::Value::Float(f) => Some(f.to_string()),
        toml::Value::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Coerce a YAML value to its env-var string representation.
fn yaml_value_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Parse a YAML snippet (Hermes `mcp_servers:` or Goose `extensions:`).
fn parse_yaml_snippet(content: &str) -> Result<Vec<ParsedSnippetServer>, String> {
    let value: serde_yaml::Value = serde_yaml::from_str(content).map_err(|e| e.to_string())?;

    // Try Hermes format: `mcp_servers:` map.
    if let Some(servers_map) = value.get("mcp_servers").and_then(|v| v.as_mapping()) {
        let servers: Vec<ParsedSnippetServer> = servers_map
            .iter()
            .filter_map(|(k, def)| {
                let name = k.as_str()?.to_string();
                let def = def.as_mapping()?;
                let str_of = |key: &str| def.get(key).and_then(|v| v.as_str()).map(String::from);
                let command = str_of("command").filter(|s| !s.is_empty());
                let url = str_of("url").filter(|s| !s.is_empty());
                if command.is_none() && url.is_none() {
                    return None;
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
                let env = def
                    .get("env")
                    .and_then(|v| v.as_mapping())
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| SnippetEnvVar {
                                key: k.as_str().unwrap_or("").to_string(),
                                value: yaml_value_to_string(v),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let transport = classify(&command, &url, str_of("type").as_deref());
                Some(ParsedSnippetServer {
                    name,
                    transport,
                    command,
                    args,
                    url,
                    env,
                })
            })
            .collect();
        if !servers.is_empty() {
            return Ok(servers);
        }
    }

    // Try Goose format: `extensions:` map.
    if let Some(exts) = value.get("extensions").and_then(|v| v.as_mapping()) {
        let servers: Vec<ParsedSnippetServer> = exts
            .iter()
            .filter_map(|(k, def)| {
                let name = k.as_str()?.to_string();
                let def = def.as_mapping()?;
                let str_of = |key: &str| def.get(key).and_then(|v| v.as_str()).map(String::from);
                let command = str_of("cmd").filter(|s| !s.is_empty());
                let url = str_of("url").filter(|s| !s.is_empty());
                if command.is_none() && url.is_none() {
                    return None;
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
                let env = def
                    .get("envs")
                    .and_then(|v| v.as_mapping())
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| SnippetEnvVar {
                                key: k.as_str().unwrap_or("").to_string(),
                                value: yaml_value_to_string(v),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let transport = classify(&command, &url, str_of("type").as_deref());
                Some(ParsedSnippetServer {
                    name,
                    transport,
                    command,
                    args,
                    url,
                    env,
                })
            })
            .collect();
        if !servers.is_empty() {
            return Ok(servers);
        }
    }

    Ok(Vec::new())
}

/// Parse YAML, preserving serde_yaml's line/column in the error text.
fn parse_yaml_value(content: &str) -> Result<serde_yaml::Value, String> {
    serde_yaml::from_str(content).map_err(|e| format!("YAML syntax error: {e}"))
}

/// Read an existing JSON config we're about to modify. Tolerant of JSONC/JSON5. A
/// NON-empty file that won't parse is ALWAYS an error, never silently replaced with an
/// empty object, so writing our gateway entry back can't drop the user's other servers.
/// This protection used to apply only to whole-app-state configs; single-purpose
/// `mcpServers` files (Cursor/VS Code/Windsurf/LM Studio/Jan/Warp/etc.) fell back to an
/// empty object on a parse failure, which silently wiped every other server the file held
/// while still reporting success. An empty/whitespace file still starts fresh, since
/// `parse_json_value` returns `{}` for it. `_lenient` is retained so callers can keep
/// threading their whole-app-state flag, but it no longer changes this path.
fn read_existing_json(content: &str, _lenient: bool) -> Result<serde_json::Value, String> {
    match parse_json_value(content) {
        Ok(v) => Ok(v),
        Err(e) => Err(format!(
            "Could not parse the existing config ({e}); leaving it untouched."
        )),
    }
}

/// Read an existing TOML config we're about to modify. Codex's `config.toml` holds
/// the user's ENTIRE Codex configuration (model, provider, approval policy, profiles),
/// so an unparseable file is an ERROR, never silently replaced with an empty table —
/// otherwise writing our one `[mcp_servers.Toolport]` entry back would wipe every
/// other setting. An empty/whitespace file starts fresh, matching read_existing_json.
fn read_existing_toml(content: &str) -> Result<toml::Value, String> {
    if content.trim().is_empty() {
        return Ok(toml::Value::Table(toml::map::Map::new()));
    }
    toml::from_str::<toml::Value>(content).map_err(|e| {
        format!("Could not parse the existing config ({e}); leaving it untouched.")
    })
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
            return Err("'mcp_servers' must be a table mapping server names to definitions".into());
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
                &def.get("command")
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
        let gateway_installed = servers.iter().any(|server| {
            gateway_identity_matches(
                &server.name,
                &server.name,
                server.command.as_deref(),
            )
        });
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
// by a timestamped backup of the existing file (stored centrally under Toolport's
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

/// Largest client config we'll read into memory or back up. Most MCP client configs
/// are a few KB, but whole-app-state files legitimately grow large - notably Claude
/// Code's `~/.claude.json`, which stores project/session history and routinely reaches
/// tens of MB for active users. An 8 MB cap hard-blocked those users from ever
/// connecting Claude Code through the gateway (install errored on the read), so the
/// bound is 64 MB: generous enough for real whole-app-state files while still capping
/// memory. The device/FIFO/directory case is handled separately by the `is_file`
/// check, so this only guards against an abnormally huge regular file.
const MAX_CONFIG_BYTES: u64 = 64 * 1024 * 1024;

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
        read_existing_toml(&content)?
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
            return Err("'extensions' must be a mapping of extension names to definitions".into());
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

fn edit_yaml_gateway(
    path: &Path,
    install: bool,
    profile: Option<&str>,
    client_id: &str,
) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;
    let exts = yaml_extensions_mut(&mut root);
    let key = serde_yaml::Value::String(GATEWAY_ENTRY_NAME.into());
    exts.retain(|name, definition| {
        let name = name.as_str().unwrap_or_default();
        let command = definition
            .as_mapping()
            .and_then(|mapping| mapping.get("cmd"))
            .and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });
    if install {
        exts.insert(
            key,
            entry_to_goose_yaml(&gateway_entry(profile, client_id)?),
        );
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

    let value: serde_yaml::Value = serde_yaml::from_str(content).map_err(|e| e.to_string())?;

    let entries = match value.get("mcpServers") {
        None => return Ok(Vec::new()),
        Some(v) if v.is_sequence() => v.as_sequence().unwrap(),
        Some(_) => {
            return Err("'mcpServers' must be a sequence of server definitions".into());
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
    client_id: &str,
) -> Result<(), String> {
    let mut root = read_existing_yaml(path)?;

    let servers = continue_servers_mut(&mut root);

    servers.retain(|server| {
        let Some(mapping) = server.as_mapping() else {
            return true;
        };
        let name = mapping
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let command = mapping.get("command").and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });

    if install {
        servers.push(entry_to_continue_yaml(&gateway_entry(profile, client_id)?));
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
            return Err("'mcp_servers' must be a mapping of server names to definitions".into());
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
    client_id: &str,
) -> Result<(), String> {
    let mut root = read_existing_hermes_yaml(path)?;
    let mcp_servers = hermes_mcp_servers_mut(&mut root);
    let key = serde_yaml::Value::String(GATEWAY_ENTRY_NAME.into());
    mcp_servers.retain(|name, definition| {
        let name = name.as_str().unwrap_or_default();
        let command = definition
            .as_mapping()
            .and_then(|mapping| mapping.get("command"))
            .and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });
    if install {
        mcp_servers.insert(
            key,
            entry_to_hermes_yaml(&gateway_entry(profile, client_id)?),
        );
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
    let lenient = config_is_whole_app_state(client_id);
    match def.format {
        Format::JsonMcpServers => write_json(&path, "mcpServers", servers, lenient)?,
        Format::JsonServers => write_json(&path, "servers", servers, lenient)?,
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
// "Installing Toolport into a client" means adding a single entry to that
// client's config that runs the toolport-gateway binary. The client then talks
// only to Toolport, which routes to everything behind it. This is a surgical
// edit: existing servers (and their secret env values) are left untouched.
// ---------------------------------------------------------------------------

pub(crate) fn resolve_gateway_path() -> Option<PathBuf> {
    if let Some(p) = crate::gateway_publish::client_gateway_path() {
        return Some(p);
    }

    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let ext = std::env::consts::EXE_SUFFIX;
    // Dev / `cargo run`, and most packaged builds: the gateway sits next to the app
    // binary as `toolport-gateway` (Tauri strips the sidecar's target-triple suffix
    // when installing). True for Windows (install dir), macOS (.app/Contents/MacOS),
    // and the Linux .deb (/usr/bin). `conduit-gateway` is the pre-rename name, kept
    // as a fallback so an install updated in place still resolves.
    let plain = dir.join(format!("toolport-gateway{ext}"));
    let plain_legacy = dir.join(format!("conduit-gateway{ext}"));

    // macOS signed bundle: the keychain-access-group wrapper (scripts/macos-sign-local.sh)
    // re-homes the gateway into a nested helper bundle so it can carry its own
    // embedded provisioning profile:
    //     Toolport.app/Contents/Helpers/ToolportGateway.app/Contents/MacOS/toolport-gateway
    // The app binary runs from Toolport.app/Contents/MacOS, so `dir` is that
    // directory. Prefer the nested binary when it exists. Both bare paths
    // (Contents/MacOS/{toolport,conduit}-gateway) are kept as SYMLINKs to this same
    // binary by the signing script, so spawning either reaches the same signed,
    // profile-bearing gateway and older client configs still work. The pre-rename
    // helper (ConduitGateway.app) is checked as a fallback for an in-place update.
    #[cfg(target_os = "macos")]
    {
        for (app, exe) in [
            ("ToolportGateway.app", "toolport-gateway"),
            ("ConduitGateway.app", "conduit-gateway"),
        ] {
            let nested = dir
                .join("..")
                .join("Helpers")
                .join(app)
                .join("Contents")
                .join("MacOS")
                .join(exe);
            if nested.exists() {
                return Some(nested);
            }
        }
    }

    // AppImage is the exception: it runs from an ephemeral mount (e.g.
    // /tmp/.mount_XXXX) that disappears when the app exits, so a gateway path inside
    // it would be dead by the time a client tries to spawn it. Copy the gateway to a
    // stable per-user location and hand clients that path. ($APPIMAGE is only set
    // when running inside an AppImage.)
    if std::env::var_os("APPIMAGE").is_some() {
        for src in [&plain, &plain_legacy] {
            if src.exists() {
                if let Some(stable) = stable_gateway_copy(src) {
                    return Some(stable);
                }
            }
        }
    }

    if plain.exists() {
        return Some(plain);
    }
    if plain_legacy.exists() {
        return Some(plain_legacy);
    }
    // Packaged fallback: a sidecar that kept its `-<target-triple>` suffix.
    if let Some(triple) = option_env!("CONDUIT_TARGET_TRIPLE").filter(|t| !t.is_empty()) {
        for name in ["toolport-gateway", "conduit-gateway"] {
            let suffixed = dir.join(format!("{name}-{triple}{ext}"));
            if suffixed.exists() {
                return Some(suffixed);
            }
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
    // Keep the source's filename so the stable copy matches whichever binary name
    // (toolport-gateway, or the legacy conduit-gateway) was found next to the app.
    let dest = dest_dir.join(src.file_name()?);
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

fn gateway_entry(profile: Option<&str>, client_id: &str) -> Result<ServerEntry, String> {
    let path = resolve_gateway_path().ok_or("Could not locate the toolport-gateway binary")?;
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
    // Always identify the client. The gateway re-resolves this client's live
    // profile from registry.client_scopes[CONDUIT_CLIENT_ID] on every reload, so
    // every re-scope applies without restarting the client - scoped->scoped,
    // scoped->unscoped, AND unscoped->scoped (an unscoped install still carries
    // its id, and its empty-string scope marker just resolves to "follow the
    // active profile" until it's given a named one). A client installed before
    // this env var existed simply has no CONDUIT_CLIENT_ID until its next
    // reinstall and falls back to CONDUIT_PROFILE meanwhile. See
    // docs/drafts/profile-switch-live-reload-plan.md.
    env.push(env_var("CONDUIT_CLIENT_ID", client_id));
    // CONDUIT_PROFILE is only the *initial* value for a scoped install; once the
    // registry loads, the live client_scopes entry wins. Unscoped installs omit
    // it (and record an empty-string scope marker via set_client_unscoped).
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
        cwd: None,
        unknown_fields: serde_json::Map::new(),
    })
}

fn edit_json_gateway(
    path: &Path,
    key: &str,
    install: bool,
    profile: Option<&str>,
    lenient: bool,
    client_id: &str,
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
    servers.retain(|name, definition| {
        let command = definition.get("command").and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });
    if install {
        servers.insert(
            GATEWAY_ENTRY_NAME.to_string(),
            entry_to_json(&gateway_entry(profile, client_id)?),
        );
    }

    let out = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

fn edit_toml_gateway(
    path: &Path,
    install: bool,
    profile: Option<&str>,
    client_id: &str,
) -> Result<(), String> {
    let mut root = if path.exists() {
        let content = read_config_file(path)?;
        read_existing_toml(&content)?
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
    servers.retain(|name, definition| {
        let command = definition.get("command").and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });
    if install {
        servers.insert(
            GATEWAY_ENTRY_NAME.to_string(),
            entry_to_toml(&gateway_entry(profile, client_id)?),
        );
    }

    let out = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

/// Clients whose JSON config file holds their ENTIRE application state (project
/// history, signed-in account, all servers), not just an MCP-servers block. For
/// these an unparseable file must ERROR rather than be silently replaced with a
/// fresh object, so a transient parse failure can't wipe the user's whole config
/// down to just our gateway entry. `~/.claude.json` (Claude Code) and
/// `~/.gemini/settings.json` (Gemini CLI) share the plain `mcpServers` JSON shape
/// with single-purpose files (Claude Desktop, VS Code's dedicated mcp.json, LM
/// Studio, ...), which keep the harmless start-fresh behavior. (Zed's whole-editor
/// settings.json is already lenient via its JsonContextServers format.)
fn config_is_whole_app_state(client_id: &str) -> bool {
    matches!(client_id, "claude-code" | "gemini-cli")
}

fn install_or_remove(
    client_id: &str,
    install: bool,
    profile: Option<&str>,
) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    let backup = backup_file(client_id, &path)?;
    let lenient = config_is_whole_app_state(client_id);
    match def.format {
        Format::JsonMcpServers => {
            edit_json_gateway(&path, "mcpServers", install, profile, lenient, client_id)?
        }
        Format::JsonServers => {
            edit_json_gateway(&path, "servers", install, profile, lenient, client_id)?
        }
        Format::JsonContextServers => {
            edit_json_gateway(&path, "context_servers", install, profile, true, client_id)?
        }
        Format::TomlMcpServers => edit_toml_gateway(&path, install, profile, client_id)?,
        Format::YamlExtensions => edit_yaml_gateway(&path, install, profile, client_id)?,
        Format::YamlMcpServers => edit_hermes_yaml_gateway(&path, install, profile, client_id)?,
        Format::YamlMcpServersList => {
            edit_continue_yaml_gateway(&path, install, profile, client_id)?
        }
    }
    Ok(WriteOutcome {
        path: path.display().to_string(),
        backup: backup.map(|b| b.display().to_string()),
    })
}

/// Add Toolport's gateway entry to a client's config (preserves existing servers).
/// `profile` scopes the client to one profile via `CONDUIT_PROFILE` (None = all).
pub fn install_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    install_or_remove(client_id, true, profile)
}

/// Remove Toolport's gateway entry from a client's config.
pub fn uninstall_gateway(client_id: &str) -> Result<WriteOutcome, String> {
    install_or_remove(client_id, false, None)
}

/// Replace a client's entire server list with just the Toolport gateway. Used by
/// "migrate": after the client's servers are imported into Toolport, this leaves
/// the client talking only to the gateway. Backs up first; unrelated config keys
/// are preserved. Caller is responsible for importing first so nothing is lost.
pub fn migrate_to_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    write_servers(client_id, &[gateway_entry(profile, client_id)?])
}

/// Whether a client's stored gateway command should be re-pointed: it names the
/// pre-rename binary (`conduit-gateway`), or its path no longer exists on disk, and
/// it isn't already the current path.
fn gateway_command_is_stale(stored: &str, current: &str) -> bool {
    if stored.is_empty() || stored == current {
        return false;
    }
    if crate::gateway_publish::is_unversioned_install_gateway_path(stored) {
        return true;
    }
    if stored.to_lowercase().contains("conduit-gateway") || !Path::new(stored).exists() {
        return true;
    }
    // Published bin dir: repoint when the app version bumped the gateway path.
    let current_norm = current.replace('/', "\\").to_ascii_lowercase();
    if current_norm.contains("\\conduit\\bin\\toolport-gateway-") {
        return true;
    }
    false
}

/// Best-effort read of the gateway entry's `CONDUIT_PROFILE` from raw client-config
/// text, format-tolerantly (JSON `"CONDUIT_PROFILE": "x"`, TOML `= "x"`, YAML `: x`).
/// The parsed `McpServer` drops env VALUES (they can be secret), so a re-point reads
/// the profile here to preserve per-client scoping. None if absent/unparseable, in
/// which case the re-point falls back to the unscoped default, which widens access
/// rather than breaking it.
fn profile_from_config_text(content: &str) -> Option<String> {
    let idx = content.find("CONDUIT_PROFILE")?;
    let mut rest = content[idx + "CONDUIT_PROFILE".len()..].trim_start();
    rest = rest.strip_prefix('"').unwrap_or(rest).trim_start(); // JSON key's closing quote
    rest = rest.trim_start_matches([':', '=']).trim_start(); // the key/value separator
    if let Some(after) = rest.strip_prefix('"') {
        let val = after.split('"').next().unwrap_or("").trim();
        return (!val.is_empty()).then(|| val.to_string());
    }
    // Unquoted YAML bareword: up to whitespace / structural punctuation.
    let val: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ',' | '}' | ']'))
        .collect();
    let val = val.trim();
    (!val.is_empty()).then(|| val.to_string())
}

fn read_gateway_profile(client_id: &str) -> Option<String> {
    let def = find_def(client_id)?;
    let path = (def.path)()?;
    let content = read_config_file(&path).ok()?;
    profile_from_config_text(&content)
}

/// Re-point client configs whose gateway entry still names the pre-rename binary
/// (or a path that no longer exists) to the current gateway. This closes the
/// backward-compat gap the `conduit-gateway` -> `toolport-gateway` rename opened on
/// platforms without the macOS compat symlink (Windows/Linux), where an existing
/// client would otherwise spawn a binary that no longer exists.
///
/// Idempotent (an entry already on the current path is skipped, so it's a no-op
/// after the first launch), surgical (`install_gateway` rewrites only the gateway
/// entry and backs the config up first), and profile-preserving. Guarded so it never
/// writes a path that doesn't exist. Returns the ids of clients it re-pointed.
pub fn repoint_stale_gateways() -> Vec<String> {
    let Some(current) = resolve_gateway_path().map(|p| p.to_string_lossy().into_owned()) else {
        return Vec::new();
    };
    // Never re-point onto a binary that isn't there (resolve_gateway_path returns a
    // best-guess path even when nothing is found, for clearer error messages).
    if !Path::new(&current).exists() {
        return Vec::new();
    }
    let mut repointed = Vec::new();
    for client in detect_clients() {
        if !client.gateway_installed || !client.config_exists || client.error.is_some() {
            continue;
        }
        let stored = client
            .servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(GATEWAY_ENTRY_NAME))
            .and_then(|s| s.command.as_deref())
            .unwrap_or("");
        if !gateway_command_is_stale(stored, &current) {
            continue;
        }
        let profile = read_gateway_profile(&client.id);
        if install_gateway(&client.id, profile.as_deref()).is_ok() {
            repointed.push(client.id.clone());
        }
    }
    repointed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EnvVar;

    #[test]
    fn gateway_command_stale_detection() {
        let current = "/opt/toolport/toolport-gateway";
        // Names the pre-rename binary -> stale (even though this test path is fake).
        assert!(gateway_command_is_stale(
            "/Applications/Toolport.app/Contents/MacOS/conduit-gateway",
            current
        ));
        // Points at a path that doesn't exist -> stale.
        assert!(gateway_command_is_stale(
            "/nonexistent/toolport-gateway-xyz-does-not-exist",
            current
        ));
        // Already the current path -> not stale (short-circuits before the fs check).
        assert!(!gateway_command_is_stale(current, current));
        // Empty -> not stale.
        assert!(!gateway_command_is_stale("", current));
    }

    #[test]
    fn profile_extracted_across_config_formats() {
        // JSON
        assert_eq!(
            profile_from_config_text(r#"{"env":{"CONDUIT_PROFILE":"work"}}"#).as_deref(),
            Some("work")
        );
        // TOML
        assert_eq!(
            profile_from_config_text("CONDUIT_PROFILE = \"billing\"").as_deref(),
            Some("billing")
        );
        // YAML, quoted and bareword
        assert_eq!(
            profile_from_config_text("  CONDUIT_PROFILE: \"dev\"\n").as_deref(),
            Some("dev")
        );
        assert_eq!(
            profile_from_config_text("env:\n  CONDUIT_PROFILE: staging\n").as_deref(),
            Some("staging")
        );
        // Absent
        assert_eq!(profile_from_config_text(r#"{"env":{"OTHER":"x"}}"#), None);
    }

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
            cwd: None,
            unknown_fields: serde_json::Map::new(),
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
        assert!(
            err.contains("bad"),
            "error should name the bad entry: {err}"
        );
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
        assert!(
            err.contains("bad"),
            "error should name the bad entry: {err}"
        );
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
        assert!(
            err.contains("bad"),
            "error should name the bad entry: {err}"
        );
        assert!(err.contains("malformed 'extensions' entry"));
    }

    #[test]
    fn hermes_yaml_syntax_error_includes_location() {
        let content =
            "mcp_servers:\n  srv:\n    url: https://example.com\n  bad:\n  - [unbalanced\n";
        let err = parse_hermes_yaml_servers(content).unwrap_err();
        assert!(err.contains("YAML syntax error"), "got: {err}");
        assert!(err.contains("line"), "got: {err}");
    }

    #[test]
    fn hermes_yaml_malformed_entry_names_key() {
        let content = "mcp_servers:\n  good:\n    url: https://example.com\n  bad: not-a-mapping\n";
        let err = parse_hermes_yaml_servers(content).unwrap_err();
        assert!(
            err.contains("bad"),
            "error should name the bad entry: {err}"
        );
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

        edit_json_gateway(&path, "mcpServers", true, Some("Billing"), false, "claude-code").unwrap();
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

        edit_json_gateway(&path, "mcpServers", false, None, false, "claude-code").unwrap();
        let root2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = root2["mcpServers"].as_object().unwrap();
        assert!(!servers2.contains_key("conduit"));
        assert!(servers2.contains_key("existing"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn gateway_edits_replace_all_legacy_entries_across_formats() {
        assert!(is_gateway_server(&stdio("toolport")));

        let json_path = temp_path("dedupe-json");
        std::fs::write(
            &json_path,
            r#"{
                "theme": "dark",
                "mcpServers": {
                    "toolport": { "command": "manual-wrapper" },
                    "stale": { "command": "C:\\Local\\Toolport\\toolport-gateway.exe" },
                    "existing": { "command": "node" }
                }
            }"#,
        )
        .unwrap();
        edit_json_gateway(&json_path, "mcpServers", true, None, false, "claude-code").unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let json_servers = json["mcpServers"].as_object().unwrap();
        assert_eq!(json_servers.len(), 2);
        assert!(json_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(json_servers.contains_key("existing"));
        assert_eq!(
            json_servers[GATEWAY_ENTRY_NAME]["env"]["CONDUIT_CLIENT_ID"],
            "claude-code"
        );
        edit_json_gateway(&json_path, "mcpServers", false, None, false, "claude-code").unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let json_servers = json["mcpServers"].as_object().unwrap();
        assert_eq!(json_servers.keys().collect::<Vec<_>>(), vec!["existing"]);

        let toml_path = temp_path("dedupe-toml");
        std::fs::write(
            &toml_path,
            r#"model = "gpt-5"

[mcp_servers.toolport]
command = "manual-wrapper"

[mcp_servers.stale]
command = 'C:\Local\Toolport\conduit-gateway.exe'

[mcp_servers.existing]
command = "npx"
"#,
        )
        .unwrap();
        edit_toml_gateway(&toml_path, true, None, "codex").unwrap();
        let toml: toml::Value =
            toml::from_str(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        let toml_servers = toml["mcp_servers"].as_table().unwrap();
        assert_eq!(toml_servers.len(), 2);
        assert!(toml_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(toml_servers.contains_key("existing"));
        edit_toml_gateway(&toml_path, false, None, "codex").unwrap();
        let toml: toml::Value =
            toml::from_str(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        let toml_servers = toml["mcp_servers"].as_table().unwrap();
        assert_eq!(toml_servers.keys().collect::<Vec<_>>(), vec!["existing"]);

        let goose_path = temp_path("dedupe-goose-yaml");
        std::fs::write(
            &goose_path,
            "extensions:\n  toolport:\n    cmd: manual-wrapper\n  stale:\n    cmd: C:\\Local\\Toolport\\toolport-gateway.exe\n  fetch:\n    cmd: uvx\n",
        )
        .unwrap();
        edit_yaml_gateway(&goose_path, true, None, "goose").unwrap();
        let goose: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&goose_path).unwrap()).unwrap();
        let goose_servers = goose["extensions"].as_mapping().unwrap();
        assert_eq!(goose_servers.len(), 2);
        assert!(goose_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(goose_servers.contains_key("fetch"));
        edit_yaml_gateway(&goose_path, false, None, "goose").unwrap();
        let goose: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&goose_path).unwrap()).unwrap();
        let goose_servers = goose["extensions"].as_mapping().unwrap();
        assert_eq!(goose_servers.len(), 1);
        assert!(goose_servers.contains_key("fetch"));

        let hermes_path = temp_path("dedupe-hermes-yaml");
        std::fs::write(
            &hermes_path,
            "mcp_servers:\n  toolport:\n    command: manual-wrapper\n  stale:\n    command: C:\\Local\\Toolport\\conduit-gateway.exe\n  fetch:\n    command: uvx\n",
        )
        .unwrap();
        edit_hermes_yaml_gateway(&hermes_path, true, None, "hermes").unwrap();
        let hermes: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&hermes_path).unwrap()).unwrap();
        let hermes_servers = hermes["mcp_servers"].as_mapping().unwrap();
        assert_eq!(hermes_servers.len(), 2);
        assert!(hermes_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(hermes_servers.contains_key("fetch"));
        edit_hermes_yaml_gateway(&hermes_path, false, None, "hermes").unwrap();
        let hermes: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&hermes_path).unwrap()).unwrap();
        let hermes_servers = hermes["mcp_servers"].as_mapping().unwrap();
        assert_eq!(hermes_servers.len(), 1);
        assert!(hermes_servers.contains_key("fetch"));

        let continue_path = temp_path("dedupe-continue-yaml");
        std::fs::write(
            &continue_path,
            "mcpServers:\n  - name: toolport\n    command: manual-wrapper\n  - name: stale\n    command: C:\\Local\\Toolport\\toolport-gateway.exe\n  - name: fetch\n    command: uvx\n",
        )
        .unwrap();
        edit_continue_yaml_gateway(&continue_path, true, None, "continue").unwrap();
        let continue_yaml: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&continue_path).unwrap()).unwrap();
        let continue_servers = continue_yaml["mcpServers"].as_sequence().unwrap();
        assert_eq!(continue_servers.len(), 2);
        assert!(continue_servers
            .iter()
            .any(|server| server["name"].as_str() == Some(GATEWAY_ENTRY_NAME)));
        assert!(continue_servers
            .iter()
            .any(|server| server["name"].as_str() == Some("fetch")));
        edit_continue_yaml_gateway(&continue_path, false, None, "continue").unwrap();
        let continue_yaml: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&continue_path).unwrap()).unwrap();
        let continue_servers = continue_yaml["mcpServers"].as_sequence().unwrap();
        assert_eq!(continue_servers.len(), 1);
        assert_eq!(continue_servers[0]["name"].as_str(), Some("fetch"));

        for path in [json_path, toml_path, goose_path, hermes_path, continue_path] {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn scoped_install_writes_client_id_for_live_profile_resolution() {
        // A scoped install must carry CONDUIT_CLIENT_ID alongside CONDUIT_PROFILE,
        // so the running gateway can re-resolve this client's profile live from
        // registry.client_scopes instead of trusting a frozen env var forever.
        let entry = gateway_entry(Some("Billing"), "cursor").unwrap();
        let env: std::collections::HashMap<_, _> = entry
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        assert_eq!(env.get("CONDUIT_PROFILE").unwrap().as_deref(), Some("Billing"));
        assert_eq!(env.get("CONDUIT_CLIENT_ID").unwrap().as_deref(), Some("cursor"));

        // Unscoped installs still carry CONDUIT_CLIENT_ID (so the client can be
        // re-scoped to a named profile live later, without a restart) but omit
        // CONDUIT_PROFILE - the gateway resolves the active profile live for them.
        let unscoped = gateway_entry(None, "cursor").unwrap();
        let uenv: std::collections::HashMap<_, _> = unscoped
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        assert_eq!(uenv.get("CONDUIT_CLIENT_ID").unwrap().as_deref(), Some("cursor"));
        assert!(uenv.get("CONDUIT_PROFILE").is_none());
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
    fn plugin_mcp_scan_reads_nested_mcp_files() {
        let root = std::env::temp_dir().join(format!("conduit-plugin-scan-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(root.join("alpha")).unwrap();
        std::fs::create_dir_all(root.join("beta").join("nested")).unwrap();
        std::fs::create_dir_all(root.join("ignored")).unwrap();

        std::fs::write(
            root.join("alpha").join("mcp.json"),
            r#"{
  "mcpServers": {
    "remote": {
      "type": "sse",
      "url": "https://example.com/sse",
      "env": { "REMOTE_TOKEN": "secret" }
    }
  }
}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("beta").join("nested").join(".mcp.json"),
            r#"{
  "local": {
    "command": "npx",
    "args": ["-y", "@example/mcp"],
    "env": { "LOCAL_TOKEN": "secret" }
  }
}"#,
        )
        .unwrap();
        std::fs::write(root.join("ignored").join("mcp.json"), "not json").unwrap();

        let servers = scan_plugin_mcp_servers(&root);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "local");
        assert_eq!(servers[0].transport, "stdio");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[0].args, vec!["-y", "@example/mcp"]);
        assert_eq!(servers[0].env_keys, vec!["LOCAL_TOKEN"]);
        assert_eq!(servers[1].name, "remote");
        assert_eq!(servers[1].transport, "sse");
        assert_eq!(servers[1].url.as_deref(), Some("https://example.com/sse"));
        assert_eq!(servers[1].env_keys, vec!["REMOTE_TOKEN"]);
    }

    #[test]
    fn roo_code_plugin_cache_is_under_extension_storage() {
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let settings_path = resolve_client_config_path("roo-code", &home, platform)
                .unwrap_or_else(|| panic!("missing Roo Code path on {platform:?}"));
            let expected = settings_path
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("plugins")
                .join("cache");
            assert_eq!(
                plugin_cache_dir_from_settings_path(&settings_path).unwrap(),
                expected,
                "Roo Code plugin cache path on {platform:?}"
            );
        }
    }

    #[test]
    fn roo_code_is_registered_with_plugin_scan() {
        let d = defs().into_iter().find(|d| d.id == "roo-code").unwrap();
        assert!(matches!(d.format, Format::JsonMcpServers));
        assert!(d.plugin_scan.is_some());
        assert!((d.path)().is_some());
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
        edit_json_gateway(&path, "context_servers", true, None, true, "zed").unwrap();
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
        assert!(edit_json_gateway(&path, "context_servers", true, None, true, "zed").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn whole_app_state_clients_are_lenient() {
        // claude-code (~/.claude.json) and gemini-cli (~/.gemini/settings.json) hold
        // the client's entire state, so an unparseable file must never be wiped.
        assert!(config_is_whole_app_state("claude-code"));
        assert!(config_is_whole_app_state("gemini-cli"));
        // Single-purpose mcpServers files keep the start-fresh behavior.
        assert!(!config_is_whole_app_state("claude-desktop"));
        assert!(!config_is_whole_app_state("vscode"));
        assert!(!config_is_whole_app_state("lm-studio"));

        // A whole-app-state client with a genuinely-broken config errors (leaving the
        // file intact) instead of replacing it with just the gateway entry.
        let path = std::env::temp_dir().join(format!("conduit-claude-{}.json", std::process::id()));
        let garbage = "{ \"projects\": {}, \"oauthAccount\": broken not json";
        std::fs::write(&path, garbage).unwrap();
        assert!(edit_json_gateway(&path, "mcpServers", true, None, true, "claude-code").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn single_purpose_edit_never_wipes_unparseable_config() {
        // A single-purpose mcpServers file (Cursor/VS Code/claude-desktop/etc.) that won't
        // parse must ERROR and be left intact — NOT silently replaced with a file holding
        // only the gateway entry, which would drop every other MCP server the user had. This
        // path used to fall back to an empty object (lenient=false); SOU-20 closed that.
        assert!(!config_is_whole_app_state("claude-desktop"));
        let path = std::env::temp_dir().join(format!("conduit-single-{}.json", std::process::id()));
        let garbage = "{ \"mcpServers\": { \"other\": broken not json";
        std::fs::write(&path, garbage).unwrap();
        assert!(edit_json_gateway(&path, "mcpServers", true, None, false, "claude-desktop").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage, "unparseable file left untouched");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn toml_edit_never_wipes_unparseable_config() {
        // Codex's config.toml holds the user's whole config; a parse failure must
        // ERROR and leave the file byte-for-byte intact, never rewrite it down to
        // just our [mcp_servers.Toolport] entry.
        let path = std::env::temp_dir().join(format!("conduit-bad-{}.toml", std::process::id()));
        let garbage = "model = \"o3\"\n[[[ this is not valid toml";
        std::fs::write(&path, garbage).unwrap();
        assert!(edit_toml_gateway(&path, true, None, "codex").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn toml_edit_preserves_other_settings() {
        // A parseable config.toml keeps every unrelated key when we add our entry.
        let path = std::env::temp_dir().join(format!("conduit-ok-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "model = \"o3\"\napproval_policy = \"on-request\"\n\n[profiles.work]\nmodel = \"gpt-5\"\n",
        )
        .unwrap();
        edit_toml_gateway(&path, true, None, "codex").unwrap();
        let v: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v.get("model").and_then(|x| x.as_str()), Some("o3"));
        assert_eq!(
            v.get("approval_policy").and_then(|x| x.as_str()),
            Some("on-request")
        );
        assert!(v.get("profiles").is_some());
        assert!(v
            .get("mcp_servers")
            .and_then(|m| m.get(GATEWAY_ENTRY_NAME))
            .is_some());
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
        // Warp, Amazon Q, Kiro, LM Studio, Jan, and AnythingLLM all use the standard mcpServers JSON
        // shape, so a ClientDef + path is all they need. Lock in their registration,
        // format, and that their config paths resolve on this OS.
        for id in [
            "warp",
            "amazon-q",
            "kiro",
            "lm-studio",
            "jan",
            "anythingllm",
        ] {
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
        edit_yaml_gateway(&path, true, None, "goose").unwrap();
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
        edit_yaml_gateway(&path, false, None, "goose").unwrap();
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
        assert!(edit_yaml_gateway(&path, true, None, "goose").is_err());
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
        edit_hermes_yaml_gateway(&path, true, None, "hermes").unwrap();
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
        edit_hermes_yaml_gateway(&path, false, None, "hermes").unwrap();
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
        assert!(edit_hermes_yaml_gateway(&path, true, None, "hermes").is_err());
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
            ("pi", |home, _| {
                home.join(".pi").join("agent").join("mcp.json")
            }),
            ("vscode", |home, platform| {
                roaming_config_dir(home, platform)
                    .join("Code")
                    .join("User")
                    .join("mcp.json")
            }),
            ("claude-desktop", |home, platform| {
                roaming_config_dir(home, platform)
                    .join("Claude")
                    .join("claude_desktop_config.json")
            }),
            ("cline", |home, platform| {
                roaming_config_dir(home, platform)
                    .join("Code")
                    .join("User")
                    .join("globalStorage")
                    .join("saoudrizwan.claude-dev")
                    .join("settings")
                    .join("cline_mcp_settings.json")
            }),
            ("goose", |home, platform| match platform {
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
            }),
            ("zed", |home, platform| match platform {
                Platform::Windows => home
                    .join("AppData")
                    .join("Roaming")
                    .join("Zed")
                    .join("settings.json"),
                Platform::MacOs | Platform::Linux => {
                    home.join(".config").join("zed").join("settings.json")
                }
            }),
            ("jan", |home, platform| match platform {
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
            }),
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

    // --- parse_snippet tests ---

    #[test]
    fn parse_cursor_json_snippet() {
        let json = r#"{"mcpServers":{"open-design":{"command":"/usr/bin/node","args":["server.mjs"],"env":{"KEY":"val"}}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "open-design");
        assert_eq!(servers[0].command.as_deref(), Some("/usr/bin/node"));
        assert_eq!(servers[0].args, vec!["server.mjs"]);
        assert_eq!(servers[0].env.len(), 1);
        assert_eq!(servers[0].env[0].key, "KEY");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("val"));
    }

    #[test]
    fn parse_vscode_json_snippet() {
        let json =
            r#"{"servers":{"my-server":{"type":"stdio","command":"npx","args":["-y","foo"]}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].transport, "stdio");
    }

    #[test]
    fn parse_codex_toml_snippet() {
        let toml = r#"
[mcp_servers.open-design]
command = "/usr/bin/node"
args = ["server.mjs"]

[mcp_servers.open-design.env]
OD_DATA_DIR = "/tmp/data"
"#;
        let servers = parse_snippet(toml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "open-design");
        assert_eq!(servers[0].env[0].key, "OD_DATA_DIR");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("/tmp/data"));
    }

    #[test]
    fn parse_claude_cli_snippet() {
        let cli = r#"claude mcp add-json --scope user open-design '{"command":"/usr/bin/node","args":["server.mjs"],"env":{"KEY":"val"}}'"#;
        let servers = parse_snippet(cli).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "open-design");
        assert_eq!(servers[0].command.as_deref(), Some("/usr/bin/node"));
    }

    #[test]
    fn parse_bare_json_server() {
        let json = r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        // A package runner is named after the package it runs, not the runner
        // "npx" - otherwise every bare npx server collides on the id "npx" and its
        // tools are prefixed npx__ (issue #251).
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn launcher_named_after_package_not_runner() {
        let vs = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // The reporter's case and friends: name comes from the package, with the
        // scope, version, and MCP name affixes stripped (issue #251).
        assert_eq!(name_from_invocation("npx", &vs(&["-y", "@verygoodplugins/mcp-automem"])), "automem");
        assert_eq!(name_from_invocation("npx", &vs(&["-y", "@modelcontextprotocol/server-github"])), "github");
        assert_eq!(name_from_invocation("uvx", &vs(&["mcp-server-fetch"])), "fetch");
        assert_eq!(name_from_invocation("npx", &vs(&["@upstash/context7-mcp"])), "context7");
        assert_eq!(name_from_invocation("npx", &vs(&["-y", "mcp-remote@latest"])), "remote");
        assert_eq!(name_from_invocation("bunx", &vs(&["some-tool"])), "some-tool");
        // A Windows npx.cmd path is still recognized as the npx launcher.
        assert_eq!(
            name_from_invocation("C:\\Program Files\\nodejs\\npx.cmd", &vs(&["-y", "@scope/mcp-thing"])),
            "thing"
        );
        // A packed "npx -y <pkg>" command with empty args is handled.
        assert_eq!(name_from_invocation("npx -y @verygoodplugins/mcp-automem", &[]), "automem");
        // A non-runner keeps its own command file stem (unchanged behavior).
        assert_eq!(name_from_invocation("/usr/local/bin/my-server", &[]), "my-server");
    }

    #[test]
    fn launcher_handles_package_flag_and_separator() {
        let vs = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // An explicit --package=/--package/-p names the package, not the command
        // after `--` (which is what to run inside the package env), issue #251 f/u.
        assert_eq!(
            name_from_invocation("npm", &vs(&["exec", "--package=@scope/mcp-weather", "--", "server"])),
            "weather"
        );
        assert_eq!(
            name_from_invocation("npx", &vs(&["--package=@acme/mcp-thing", "--", "cmd"])),
            "thing"
        );
        assert_eq!(
            name_from_invocation("npx", &vs(&["--package", "@scope/mcp-foo", "--", "cmd"])),
            "foo"
        );
        assert_eq!(name_from_invocation("npx", &vs(&["-p", "@scope/mcp-foo", "cmd"])), "foo");
        // A positional package before `--` still wins, and `--` stops the search.
        assert_eq!(
            name_from_invocation("npx", &vs(&["-y", "@scope/mcp-a", "--", "not-a-package"])),
            "a"
        );
        // Cross-platform: a Windows path resolves to its stem even on a Unix host.
        assert_eq!(name_from_invocation("C:\\tools\\my-server.exe", &[]), "my-server");
    }

    #[test]
    fn parse_zed_jsonc_snippet() {
        let json = r#"{
            "context_servers": {
                "my-server": {
                    "source": "custom",
                    "command": "npx",
                    "args": ["-y", "foo"]
                }
            }
        }"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn parse_hermes_yaml_snippet() {
        let yaml = r#"
mcp_servers:
  my-server:
    command: npx
    args:
      - "-y"
      - "foo"
    env:
      API_KEY: secret123
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[0].env[0].key, "API_KEY");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("secret123"));
    }

    #[test]
    fn parse_goose_yaml_snippet() {
        let yaml = r#"
extensions:
  my-server:
    enabled: true
    type: stdio
    cmd: npx
    args:
      - "-y"
      - "foo"
    envs:
      KEY: val
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[0].env[0].key, "KEY");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("val"));
    }

    #[test]
    fn parse_empty_snippet_errors() {
        assert!(parse_snippet("").is_err());
        assert!(parse_snippet("   ").is_err());
    }

    #[test]
    fn parse_garbage_errors() {
        assert!(parse_snippet("this is not a config").is_err());
    }

    #[test]
    fn parse_multi_server_json_snippet() {
        let json = r#"{"mcpServers":{"one":{"command":"npx","args":["a"]},"two":{"command":"node","args":["b"]}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn parse_http_server_snippet() {
        // Windsurf/Antigravity use `serverUrl` for remote servers.
        let json = r#"{"mcpServers":{"supabase":{"serverUrl":"https://mcp.supabase.com/mcp"}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "supabase");
        assert_eq!(servers[0].transport, "http");
        assert_eq!(
            servers[0].url.as_deref(),
            Some("https://mcp.supabase.com/mcp")
        );
        assert!(servers[0].command.is_none());
    }

    #[test]
    fn parse_sse_server_snippet() {
        // VS Code `type: "sse"` classification.
        let json =
            r#"{"servers":{"remote":{"type":"sse","url":"https://events.example.com/sse"}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].transport, "sse");
    }

    #[test]
    fn parse_toml_sse_type_hint() {
        // TOML `type = "sse"` should classify as sse, not http.
        let toml = r#"
[mcp_servers.remote]
url = "https://events.example.com/sse"
type = "sse"
"#;
        let servers = parse_snippet(toml).unwrap();
        assert_eq!(servers[0].transport, "sse");
    }

    #[test]
    fn parse_json_malformed_entry_skipped() {
        // Non-object entries should be silently skipped, not produce "unknown" servers.
        let json =
            r#"{"mcpServers":{"good":{"command":"npx","args":["x"]},"bad":"not-an-object"}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "good");
    }

    #[test]
    fn parse_claude_cli_without_scope() {
        // Minimal form: `claude mcp add-json name '{...}'`
        let cli = r#"claude mcp add-json my-server '{"command":"npx","args":["-y","foo"]}'"#;
        let servers = parse_snippet(cli).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn parse_multiple_env_values() {
        let json = r#"{"mcpServers":{"srv":{"command":"npx","args":["x"],"env":{"KEY1":"val1","KEY2":"val2","KEY3":"val3"}}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers[0].env.len(), 3);
        let vals: std::collections::HashMap<&str, &str> = servers[0]
            .env
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(vals.get("KEY1"), Some(&"val1"));
        assert_eq!(vals.get("KEY2"), Some(&"val2"));
        assert_eq!(vals.get("KEY3"), Some(&"val3"));
    }

    #[test]
    fn parse_non_string_env_values() {
        let json = r#"{"mcpServers":{"srv":{"command":"npx","args":["x"],"env":{"PORT":3000,"DEBUG":true,"NAME":"string-val"}}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers[0].env.len(), 3);
        let vals: std::collections::HashMap<&str, &str> = servers[0]
            .env
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(vals.get("PORT"), Some(&"3000"));
        assert_eq!(vals.get("DEBUG"), Some(&"true"));
        assert_eq!(vals.get("NAME"), Some(&"string-val"));
    }

    #[test]
    fn parse_toml_non_string_env_values() {
        let toml = r#"
[mcp_servers.srv]
command = "npx"
args = ["x"]

[mcp_servers.srv.env]
PORT = 3000
DEBUG = true
"#;
        let servers = parse_snippet(toml).unwrap();
        assert_eq!(servers[0].env.len(), 2);
        let vals: std::collections::HashMap<&str, &str> = servers[0]
            .env
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(vals.get("PORT"), Some(&"3000"));
        assert_eq!(vals.get("DEBUG"), Some(&"true"));
    }

    #[test]
    fn parse_claude_cli_with_braces_in_string() {
        let cli = r#"claude mcp add-json srv '{"command":"npx","args":["x"],"description":"use { for blocks"}'"#;
        let servers = parse_snippet(cli).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "srv");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn parse_json_server_with_extraneous_keys() {
        let json = r#"{"context_servers":{"srv":{"source":"custom","type":"stdio","command":"npx","args":["x"]}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers[0].name, "srv");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
    }

    #[test]
    fn parse_json_server_url_only() {
        let json = r#"{"mcpServers":{"remote":{"url":"https://api.example.com/mcp"}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers[0].transport, "http");
        assert!(servers[0].command.is_none());
        assert!(servers[0].url.is_some());
    }

    #[test]
    fn parse_yaml_non_string_env_values() {
        let yaml = r#"
mcp_servers:
  srv:
    command: npx
    args:
      - "x"
    env:
      PORT: 3000
      DEBUG: true
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers[0].env.len(), 2);
        let vals: std::collections::HashMap<&str, &str> = servers[0]
            .env
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(vals.get("PORT"), Some(&"3000"));
        assert_eq!(vals.get("DEBUG"), Some(&"true"));
    }

    #[test]
    fn parse_goose_non_string_env_values() {
        let yaml = r#"
extensions:
  srv:
    enabled: true
    type: stdio
    cmd: npx
    args:
      - "x"
    envs:
      PORT: 3000
      DEBUG: true
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers[0].env.len(), 2);
        let vals: std::collections::HashMap<&str, &str> = servers[0]
            .env
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_deref().unwrap_or("")))
            .collect();
        assert_eq!(vals.get("PORT"), Some(&"3000"));
        assert_eq!(vals.get("DEBUG"), Some(&"true"));
    }
}
