//! Client adapter layer.
//!
//! Each supported MCP client stores its servers in its own file, in its own
//! location, in its own format. This module knows how to find each client's
//! config and read its servers into one canonical shape, so the rest of the
//! app never has to care about per-client differences.
//!
//! Security note: we surface env-variable *names* but never their *values*.
//! Those values are secrets (API keys, tokens) and must not leak to the UI.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::registry::{ManagedEntry, ServerEntry};

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

/// Ownership of the gateway entry under our name in a client config (SOU-406).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GatewayEntryState {
    /// We wrote it (or pre-record install that still looks like our binary).
    Managed,
    /// An identity-matching entry exists but is not what we last wrote (or, with
    /// no ownership record, its command is not a Toolport gateway binary).
    Customized,
    /// No identity-matching gateway entry.
    Absent,
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
    /// First-class ownership of that entry: managed by us, hand-customized, or
    /// absent (SOU-406). Computed with the registry ownership record when present.
    pub entry_state: GatewayEntryState,
    /// Set when the config exists but could not be read or parsed.
    pub error: Option<String>,
}

/// How a given client stores its server list.
#[derive(Clone, Copy)]
enum Format {
    /// JSON with a top-level `mcpServers` object (Claude Desktop, Cursor, Windsurf).
    JsonMcpServers,
    /// GitHub Copilot CLI's `mcpServers` object. Entries use the standard JSON
    /// shape but require a `tools` allowlist; Toolport enables every gateway tool.
    JsonCopilotMcpServers,
    /// Factory Droid's `mcpServers` object. Standard JSON shape, but every
    /// entry requires a `"type"` field ("stdio" for local servers).
    JsonDroidMcpServers,
    /// Amp's shared settings file stores servers under the literal dotted
    /// top-level key `amp.mcpServers` (not a nested `amp` object).
    JsonAmpMcpServers,
    /// Qwen Code's top-level `mcpServers` object. Stdio entries use the standard
    /// command/args/env shape, while remote entries distinguish SSE (`url`) from
    /// streamable HTTP (`httpUrl`) and store credentials under `headers`.
    JsonQwenMcpServers,
    /// JSON with a top-level `servers` object (VS Code).
    JsonServers,
    /// JSON with a top-level `mcp` object (Crush).
    JsonMcp,
    /// JSON/JSONC with a top-level `mcp` object (OpenCode, Kilo Code). Local
    /// entries store the full argv in `command` and env vars in `environment`;
    /// remote entries use `type: "remote"` plus `url` and optional `headers`.
    JsonOpenCodeMcp,
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
/// This is the user-visible label the entry shows up as inside every client (e.g.
/// Claude Desktop lists it as this). Wire identifiers now prefer `TOOLPORT_*`
/// (with `CONDUIT_*` still accepted). Bundle id and keychain access-group stay
/// on the pre-rename identity so OS installs/updates keep working. See
/// [`LEGACY_GATEWAY_ENTRY_NAME`] for the entry-name migration path.
pub const GATEWAY_ENTRY_NAME: &str = "toolport";

/// The name Toolport wrote before the SOU-318 rename. Existing installs still have
/// their entry named this; [`gateway_identity_matches`] keeps recognizing it so we
/// detect, de-duplicate, and (via [`repoint_stale_gateways`]) migrate those entries
/// to [`GATEWAY_ENTRY_NAME`] on launch. Do not remove — dropping it would make old
/// entries invisible and leak a second, orphaned gateway into client configs.
const LEGACY_GATEWAY_ENTRY_NAME: &str = "conduit";

/// Match the current entry name, the pre-rename `conduit` name still present in
/// existing installs, and both current and pre-rename gateway binary names.
fn gateway_identity_matches(id: &str, name: &str, command: Option<&str>) -> bool {
    let has_gateway_name = |value: &str| {
        value.eq_ignore_ascii_case(GATEWAY_ENTRY_NAME)
            || value.eq_ignore_ascii_case(LEGACY_GATEWAY_ENTRY_NAME)
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

/// Whether a server read out of a client's own config (a detected [`McpServer`]) is
/// Toolport's own gateway entry. Recognizes the pre-rename `conduit` name too, so a
/// "migrate" run doesn't import a legacy gateway entry back into the registry as if
/// it were a real server.
pub fn detected_is_gateway(server: &McpServer) -> bool {
    gateway_identity_matches(&server.name, &server.name, server.command.as_deref())
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
        "droid" => home.join(".factory").join("mcp.json"),
        "crush" => home.join(".config").join("crush").join("crush.json"),
        "boltai" => home.join(".boltai").join("mcp.json"),
        "pi" => home.join(".pi").join("agent").join("mcp.json"),
        "omp" => home.join(".omp").join("agent").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        "amp" => home.join(".config").join("amp").join("settings.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        "opencode" => home.join(".config").join("opencode").join("opencode.json"),
        "kilo-code" => home.join(".config").join("kilo").join("kilo.jsonc"),
        "grok" => home.join(".grok").join("config.toml"),
        "codex" => home.join(".codex").join("config.toml"),
        "github-copilot-cli" => home.join(".copilot").join("mcp-config.json"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "qwen-code" => home.join(".qwen").join("settings.json"),
        "junie" => home.join(".junie").join("mcp").join("mcp.json"),
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
        "witsy" => config.join("Witsy").join("settings.json"),
        // Toolport Studio injects the gateway per provider session with
        // TOOLPORT_CLIENT_ID=toolport-studio (legacy CONDUIT_CLIENT_ID dual-write
        // in Studio for older gateways). This file is the Toolport-managed connect
        // marker + scope target (same identity Studio already uses).
        "toolport-studio" => home.join(".toolport-studio").join("mcp.json"),
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
        "droid" => home.join(".factory").join("mcp.json"),
        "crush" => config.join("crush").join("crush.json"),
        "boltai" => home.join(".boltai").join("mcp.json"),
        "pi" => home.join(".pi").join("agent").join("mcp.json"),
        "omp" => home.join(".omp").join("agent").join("mcp.json"),
        "vscode" => config.join("Code").join("User").join("mcp.json"),
        // Amp documents this literal home-relative location on Linux.
        "amp" => home.join(".config").join("amp").join("settings.json"),
        "windsurf" => home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        // OpenCode and Kilo Code document literal home-relative paths on every
        // platform; unlike most Linux clients they do not follow XDG_CONFIG_HOME.
        "opencode" => home.join(".config").join("opencode").join("opencode.json"),
        "kilo-code" => home.join(".config").join("kilo").join("kilo.jsonc"),
        "grok" => home.join(".grok").join("config.toml"),
        "codex" => home.join(".codex").join("config.toml"),
        "github-copilot-cli" => home.join(".copilot").join("mcp-config.json"),
        "claude-code" => home.join(".claude.json"),
        "gemini-cli" => home.join(".gemini").join("settings.json"),
        "qwen-code" => home.join(".qwen").join("settings.json"),
        "junie" => home.join(".junie").join("mcp").join("mcp.json"),
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
        "witsy" => config.join("Witsy").join("settings.json"),
        "toolport-studio" => home.join(".toolport-studio").join("mcp.json"),
        _ => return None,
    };
    Some(path)
}

/// Resolve where a client reads its GLOBAL agent-rules file (Team Instructions, spec "W2").
/// This is DISTINCT from the client's MCP-config path — e.g. Claude Code's config is
/// `~/.claude.json` but its rules live under `~/.claude/rules/`. `None` means the client has
/// no global-rules location we write: either its globals are UI/cloud-stored (Cursor, Warp),
/// or it's covered transitively by another client's file (Antigravity reads Gemini's
/// `GEMINI.md`; VS Code Copilot reads Claude Code's `~/.claude` rules). Unlike the config
/// resolver these paths are all home-anchored (or literal `~/.config`), so one cross-platform
/// resolver covers Linux too — no XDG/data-dir or MSIX handling needed. See the spec's adapter
/// table for citations.
fn resolve_rules_target(
    client_id: &str,
    home: &std::path::Path,
    platform: Platform,
) -> Option<crate::instructions::Target> {
    use crate::instructions::{Strategy, Target};
    let config = roaming_config_dir(home, platform);
    let owned = |path: PathBuf| Target {
        path,
        strategy: Strategy::OwnedFile,
        char_cap: None,
        blocked_if_present: None,
    };
    let block = |path: PathBuf| Target {
        path,
        strategy: Strategy::SentinelBlock,
        char_cap: None,
        blocked_if_present: None,
    };
    let target = match client_id {
        // Strategy A — Toolport owns a whole file in the client's rules DIRECTORY.
        // Claude Code's `~/.claude/rules/` is also read by VS Code Copilot (Claude-compat
        // paths), so both map here; path-dedup writes it once when both are installed and a
        // standalone VS Code install is still covered.
        "claude-code" | "vscode" => owned(
            home.join(".claude")
                .join("rules")
                .join("toolport-team-rules.md"),
        ),
        "kiro" => owned(
            home.join(".kiro")
                .join("steering")
                .join("toolport-team-rules.md"),
        ),
        "roo-code" => owned(
            home.join(".roo")
                .join("rules")
                .join("toolport-team-rules.md"),
        ),
        "cline" => owned(
            home.join("Documents")
                .join("Cline")
                .join("Rules")
                .join("toolport-team-rules.md"),
        ),
        // Strategy B — Toolport owns only the sentinel span in a shared global file.
        "codex" => Target {
            path: home.join(".codex").join("AGENTS.md"),
            strategy: Strategy::SentinelBlock,
            char_cap: None,
            // AGENTS.override.md, if present, makes Codex ignore AGENTS.md entirely.
            blocked_if_present: Some(home.join(".codex").join("AGENTS.override.md")),
        },
        // Gemini CLI and Antigravity share `~/.gemini/GEMINI.md`; both resolve to it so a
        // standalone install of EITHER is covered, and `apply_instructions`' path-dedup writes
        // it once when both are present.
        "gemini-cli" | "antigravity" => block(home.join(".gemini").join("GEMINI.md")),
        "windsurf" => Target {
            path: home
                .join(".codeium")
                .join("windsurf")
                .join("memories")
                .join("global_rules.md"),
            strategy: Strategy::SentinelBlock,
            char_cap: Some(6000), // Windsurf hard-caps the global rules file.
            blocked_if_present: None,
        },
        "goose" => block(home.join(".config").join("goose").join(".goosehints")),
        "pi" => block(home.join(".pi").join("agent").join("AGENTS.md")),
        "omp" => block(home.join(".omp").join("agent").join("AGENTS.md")),
        "zed" => match platform {
            Platform::Windows => block(config.join("Zed").join("AGENTS.md")),
            Platform::MacOs | Platform::Linux => {
                block(home.join(".config").join("zed").join("AGENTS.md"))
            }
        },
        _ => return None,
    };
    Some(target)
}

/// The rules-file target for a client on the current machine, or `None` if unsupported /
/// transitively covered. Mirrors [`client_config_path`].
pub fn client_rules_target(client_id: &str) -> Option<crate::instructions::Target> {
    let home = home()?;
    resolve_rules_target(client_id, &home, Platform::current())
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

fn droid_path() -> Option<PathBuf> {
    client_config_path("droid")
}

fn crush_override_path(config_dir: Option<std::ffi::OsString>) -> Option<PathBuf> {
    config_dir
        .filter(|p| !p.is_empty())
        .map(|dir| PathBuf::from(dir).join("crush.json"))
}

fn resolve_crush_path(
    home: &Path,
    config_override: Option<std::ffi::OsString>,
    xdg_config_home: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(path) = crush_override_path(config_override) {
        return path;
    }
    xdg_config_home
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("crush")
        .join("crush.json")
}

/// Crush v0.88.0 resolves its global config through CRUSH_GLOBAL_CONFIG, then
/// XDG_CONFIG_HOME, and finally ~/.config on every OS. Older Windows releases
/// used LocalAppData, so retain that path only when it already contains a file.
fn crush_path() -> Option<PathBuf> {
    let home = home()?;
    if let Some(path) = crush_override_path(std::env::var_os("CRUSH_GLOBAL_CONFIG")) {
        return Some(path);
    }
    let current = resolve_crush_path(&home, None, std::env::var_os("XDG_CONFIG_HOME"));
    #[cfg(windows)]
    if !current.exists() {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA").filter(|p| !p.is_empty()) {
            let legacy = PathBuf::from(local_app_data)
                .join("crush")
                .join("crush.json");
            if legacy.exists() {
                return Some(legacy);
            }
        }
    }
    Some(current)
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

/// Oh My Pi (omp) is a fork of Pi with its own config directory (~/.omp).
/// Same `mcpServers` JSON format as Pi; home-anchored, identical on every OS.
fn omp_path() -> Option<PathBuf> {
    client_config_path("omp")
}

fn vscode_path() -> Option<PathBuf> {
    client_config_path("vscode")
}

fn amp_path() -> Option<PathBuf> {
    std::env::var_os("AMP_SETTINGS_FILE")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| client_config_path("amp"))
}

fn windsurf_path() -> Option<PathBuf> {
    client_config_path("windsurf")
}

fn codex_path() -> Option<PathBuf> {
    client_config_path("codex")
}

/// GitHub Copilot CLI stores user-level MCP servers under `COPILOT_HOME`,
/// defaulting to `~/.copilot/mcp-config.json` on every supported platform.
fn github_copilot_cli_path() -> Option<PathBuf> {
    std::env::var_os("COPILOT_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join("mcp-config.json"))
        .or_else(|| client_config_path("github-copilot-cli"))
}

/// Grok Build (xAI's terminal coding agent) stores MCP servers in
/// `~/.grok/config.toml` under `[mcp_servers.<name>]` - the same TOML shape as
/// Codex, so it shares the `TomlMcpServers` format. It also reads Claude Code's
/// config as a fallback, but writing our own explicit entry is what makes the
/// gateway reliably visible (`grok mcp list` doesn't surface the Claude-config
/// pickup).
fn grok_path() -> Option<PathBuf> {
    client_config_path("grok")
}

/// Toolport Studio (sibling product): per-session MCP injection uses
/// `TOOLPORT_CLIENT_ID=toolport-studio`. Connect writes `~/.toolport-studio/mcp.json`
/// so scopes, discovery overrides, and gatewayInstalled state stay consistent
/// with every other client. Tools still work without Connect (Studio auto-discovers
/// the gateway); Connect pins profile scope and shows the client as connected.
fn toolport_studio_path() -> Option<PathBuf> {
    client_config_path("toolport-studio")
}

/// Install / state markers for Toolport Studio. The MCP connect file lives under
/// `~/.toolport-studio`, but a fresh install may only have the app dir or
/// Electron userData until the first Studio launch creates the home state tree.
fn toolport_studio_install_marker() -> Option<PathBuf> {
    let home = home()?;
    let fallback = home.join(".toolport-studio");
    let mut candidates: Vec<PathBuf> = vec![fallback.clone()];

    if let Some(roaming) = dirs::config_dir() {
        candidates.push(roaming.join("toolport-studio"));
        candidates.push(roaming.join("toolport-studio-dev"));
    }
    if let Some(local) = dirs::data_local_dir() {
        // NSIS default under electron-builder; include the transitional t3code
        // install folder from the Studio fork until installers fully rename.
        candidates.push(local.join("Programs").join("toolport-studio"));
        candidates.push(local.join("Programs").join("t3code"));
        candidates.push(local.join("toolport-studio"));
        candidates.push(local.join("toolport-studio-updater"));
    }
    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from("/Applications/Toolport Studio.app"));
        candidates.push(PathBuf::from("/Applications/Toolport Studio (Alpha).app"));
        candidates.push(PathBuf::from("/Applications/Toolport Studio (Nightly).app"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(data) = dirs::data_dir() {
            candidates.push(data.join("applications").join("toolport-studio.desktop"));
            candidates.push(data.join("toolport-studio"));
        }
        candidates.push(
            home.join(".local")
                .join("share")
                .join("applications")
                .join("toolport-studio.desktop"),
        );
    }

    // Returning `None` would make `read_client` fall back to the config-parent
    // heuristic. Studio's config parent is the home directory itself when the
    // state tree is absent, which exists on every machine and would make Studio
    // appear installed everywhere. Keep the override active with a deterministic
    // non-existing fallback when no install marker is present.
    Some(
        candidates
            .into_iter()
            .find(|path| path.exists())
            .unwrap_or(fallback),
    )
}

fn claude_code_path() -> Option<PathBuf> {
    client_config_path("claude-code")
}

fn gemini_cli_path() -> Option<PathBuf> {
    client_config_path("gemini-cli")
}

/// Qwen Code stores user-scoped settings at `~/.qwen/settings.json` on every
/// supported platform.
fn qwen_code_path() -> Option<PathBuf> {
    client_config_path("qwen-code")
}

/// Junie stores user-scoped MCP servers at ~/.junie/mcp/mcp.json on every
/// supported platform. Project-scoped configs are intentionally left untouched.
fn junie_path() -> Option<PathBuf> {
    client_config_path("junie")
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

/// OpenCode stores its global config at the literal
/// `~/.config/opencode/opencode.json` on every supported OS.
fn opencode_path() -> Option<PathBuf> {
    client_config_path("opencode")
}

/// Kilo Code stores its global JSONC config at the literal
/// `~/.config/kilo/kilo.jsonc` on every supported OS.
fn kilo_code_path() -> Option<PathBuf> {
    client_config_path("kilo-code")
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
    client_config_path("continue")
}

/// Witsy keeps MCP servers in a top-level `mcpServers` object inside its main
/// settings.json (alongside all other app settings), in the Claude-compatible
/// `{command, args, env}` shape. Electron's userData dir is "Witsy" on every OS:
/// ~/Library/Application Support/Witsy on macOS, %APPDATA%\Witsy on Windows,
/// ~/.config/Witsy on Linux. Confirmed against the app's own source
/// (src/main/mcp.ts reads/writes config.mcpServers directly) and the project's
/// file-location wiki page.
fn witsy_path() -> Option<PathBuf> {
    client_config_path("witsy")
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
            id: "droid",
            name: "Factory Droid",
            format: Format::JsonDroidMcpServers,
            uses_connectors: false,
            path: droid_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "crush",
            name: "Crush",
            format: Format::JsonMcp,
            uses_connectors: false,
            path: crush_path,
            plugin_scan: None,
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
            id: "amp",
            name: "Amp",
            format: Format::JsonAmpMcpServers,
            uses_connectors: false,
            path: amp_path,
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
            id: "opencode",
            name: "OpenCode",
            format: Format::JsonOpenCodeMcp,
            uses_connectors: false,
            path: opencode_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "kilo-code",
            name: "Kilo Code",
            format: Format::JsonOpenCodeMcp,
            uses_connectors: false,
            path: kilo_code_path,
            plugin_scan: None,
        },
        ClientDef {
            // Grok Build (xAI's terminal coding agent): ~/.grok/config.toml,
            // [mcp_servers.<name>] - same TOML shape as Codex.
            id: "grok",
            name: "Grok Build",
            format: Format::TomlMcpServers,
            uses_connectors: false,
            path: grok_path,
            plugin_scan: None,
        },
        ClientDef {
            // Sibling product: injects this gateway into provider sessions as
            // TOOLPORT_CLIENT_ID=toolport-studio. Connect target is
            // ~/.toolport-studio/mcp.json (Json mcpServers). Distinct from Grok
            // Build (the CLI under Studio's Grok provider), which uses ~/.grok.
            id: "toolport-studio",
            name: "Toolport Studio",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: toolport_studio_path,
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
            id: "github-copilot-cli",
            name: "GitHub Copilot CLI",
            format: Format::JsonCopilotMcpServers,
            uses_connectors: false,
            path: github_copilot_cli_path,
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
            id: "qwen-code",
            name: "Qwen Code",
            format: Format::JsonQwenMcpServers,
            uses_connectors: false,
            path: qwen_code_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "junie",
            name: "JetBrains Junie",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: junie_path,
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
            id: "omp",
            name: "Oh My Pi",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: omp_path,
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
        ClientDef {
            id: "witsy",
            name: "Witsy",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: witsy_path,
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
        .map(|arr| arr.iter().filter_map(json_value_to_string).collect())
        .unwrap_or_default();
    // Merge `env` and `headers` keys (remote MCP stores credentials under headers;
    // ownership matching and import need both visible as env_keys).
    let mut env: Vec<SnippetEnvVar> = Vec::new();
    for field in ["env", "headers"] {
        if let Some(o) = def.get(field).and_then(|e| e.as_object()) {
            for (k, v) in o {
                if env.iter().any(|e| e.key == *k) {
                    continue;
                }
                env.push(SnippetEnvVar {
                    key: k.clone(),
                    value: json_value_to_string(v),
                });
            }
        }
    }
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
    let mut unusable_mcp = Vec::new();

    if let Some(mcp) = value.get("mcp") {
        let obj = mcp
            .as_object()
            .ok_or_else(|| "'mcp' must be an object".to_string())?;
        let mut malformed = Vec::new();
        let mut servers = Vec::new();
        for (name, definition) in obj {
            let command = definition.get("command");
            let type_hint = definition.get("type").and_then(|t| t.as_str());
            // Both clients use a top-level `mcp` key, so the entry shape decides which
            // one wrote it. OpenCode types entries `local`/`remote`; Crush uses
            // `http`/`sse`. Those vocabularies do not overlap, which is what makes the
            // branches below decidable.
            let is_explicit_opencode_type = matches!(type_hint, Some("local") | Some("remote"));

            if command.map(|c| c.is_string()).unwrap_or(false) {
                if is_explicit_opencode_type {
                    // Typed as OpenCode, but `command` is a string where OpenCode
                    // requires an array. A malformed OpenCode entry, not a Crush one,
                    // so say so rather than silently importing it as Crush.
                    malformed.push(format!("{name} ('command' must be an array of strings)"));
                    continue;
                }
                // Crush stdio: `command` is a string, args live separately.
                servers.push(json_server_with_values(name, definition));
                continue;
            }

            let is_array = command.map(|c| c.is_array()).unwrap_or(false);
            let is_absent = command.is_none();

            if is_absent && matches!(type_hint, Some("http") | Some("sse")) {
                // Crush remote: no `command`, transport comes from `type`, and env
                // lives under `env`. Checked before the OpenCode branch below, which
                // would otherwise claim it and hardcode http while reading
                // `environment`. (Crush requires `type` on every entry, so a typeless
                // remote is not a valid Crush config.)
                servers.push(json_server_with_values(name, definition));
                continue;
            }

            if is_array || is_absent {
                // OpenCode: `command` is an argv array, or absent for remote and
                // override-only entries, which carry env under `environment`.
                match opencode_server_with_values(name, definition) {
                    Ok(Some(server)) => servers.push(server),
                    Ok(None) => {}
                    Err(error) => malformed.push(format!("{name} ({error})")),
                }
                continue;
            }

            // `command` is null, a number, or an object: not a shape either client
            // writes. Skipped rather than reported, so the wrapper-key fallthrough
            // below still runs. If no supported wrapper parses either, report the
            // skipped entry instead of falling through to the generic error.
            unusable_mcp.push(format!(
                "{name} ('command' must be a string or array of strings)"
            ));
        }
        if !malformed.is_empty() {
            malformed.sort();
            return Err(format!("malformed 'mcp' entry: {}", malformed.join(", ")));
        }
        if !servers.is_empty() {
            return Ok(servers);
        }
    }

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
            let command = value
                .get("command")
                .and_then(|c| c.as_str())
                .unwrap_or_default();
            let args: Vec<String> = value
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            name_from_invocation(command, &args)
        } else {
            forced_name.to_string()
        };
        return Ok(vec![json_server_with_values(&name, &value)]);
    }

    if !unusable_mcp.is_empty() {
        unusable_mcp.sort();
        return Err(format!("unusable 'mcp' entry: {}", unusable_mcp.join(", ")));
    }

    Err("JSON parsed but no server definition found (expected mcp, mcpServers, servers, context_servers, or a bare server object)".to_string())
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
                .map(|arr| arr.iter().filter_map(toml_value_to_string).collect())
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

/// Parse a YAML snippet (Hermes `mcp_servers:`, Goose `extensions:`, or Continue `mcpServers:`).
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
                    .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
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
                    .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
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

    // Try Continue format: `mcpServers:` sequence.
    if let Some(entries) = value.get("mcpServers").and_then(|v| v.as_sequence()) {
        let servers: Vec<ParsedSnippetServer> = entries
            .iter()
            .filter_map(|server| {
                let def = server.as_mapping()?;

                let str_of = |key: &str| def.get(key).and_then(|v| v.as_str()).map(String::from);

                let name = str_of("name")?;
                let command = str_of("command").filter(|s| !s.is_empty());
                let url = str_of("url").filter(|s| !s.is_empty());

                if command.is_none() && url.is_none() {
                    return None;
                }

                let args = def
                    .get("args")
                    .and_then(|v| v.as_sequence())
                    .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
                    .unwrap_or_default();

                let env = def
                    .get("env")
                    .and_then(|v| v.as_mapping())
                    .map(|mapping| {
                        mapping
                            .iter()
                            .filter_map(|(key, value)| {
                                Some(SnippetEnvVar {
                                    key: key.as_str()?.to_string(),
                                    value: yaml_value_to_string(value),
                                })
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
    toml::from_str::<toml::Value>(content)
        .map_err(|e| format!("Could not parse the existing config ({e}); leaving it untouched."))
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

fn parse_qwen_json(content: &str) -> Result<Vec<McpServer>, String> {
    let value = parse_json_value(content)?;
    let definitions = match value.get("mcpServers") {
        None => return Ok(Vec::new()),
        Some(value) if value.is_object() => value.as_object().unwrap(),
        Some(_) => {
            return Err(
                "'mcpServers' must be an object mapping server names to definitions".into(),
            );
        }
    };

    let mut servers = parse_json(content, "mcpServers")?;
    for server in &mut servers {
        // `parse_json` names each server after its map key, so a lookup here always
        // hits. Indexing would still be a panic in a Tauri command if that ever
        // stopped holding, and this is parsing a user-supplied file, so fail soft.
        let Some(definition) = definitions.get(&server.name) else {
            continue;
        };
        let http_url = definition
            .get("httpUrl")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty());
        let sse_url = definition
            .get("url")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty());
        let (transport, url) = if let Some(url) = http_url {
            ("http", Some(url))
        } else if let Some(url) = sse_url {
            ("sse", Some(url))
        } else {
            continue;
        };

        server.transport = transport.into();
        server.url = url.map(String::from);
        server.command = None;
        server.args.clear();
        server.env_keys = definition
            .get("headers")
            .and_then(|value| value.as_object())
            .map(|headers| headers.keys().cloned().collect())
            .unwrap_or_default();
        server.env_keys.sort();
    }
    Ok(servers)
}

/// Parse one OpenCode-compatible `mcp` entry while retaining env/header values.
/// These clients store local commands as one argv array and use `environment`
/// instead of `env`; remote entries use `url` plus optional `headers`.
fn opencode_server_with_values(
    name: &str,
    def: &serde_json::Value,
) -> Result<Option<ParsedSnippetServer>, String> {
    let obj = def
        .as_object()
        .ok_or_else(|| "expected an object".to_string())?;

    let type_hint = obj.get("type").and_then(|value| value.as_str());
    let (command, args) = match obj.get("command") {
        None => (None, Vec::new()),
        Some(value) => {
            let argv = value
                .as_array()
                .ok_or_else(|| "'command' must be an array of strings".to_string())?;
            let mut parts = Vec::with_capacity(argv.len());
            for part in argv {
                let Some(part) = part.as_str() else {
                    return Err("'command' must contain only strings".to_string());
                };
                parts.push(part.to_string());
            }
            let command = parts.first().filter(|part| !part.is_empty()).cloned();
            let args = parts.into_iter().skip(1).collect();
            (command, args)
        }
    };

    let url = obj
        .get("url")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(String::from);

    if type_hint == Some("local") && command.is_none() {
        return Err("a local server requires a non-empty 'command' array".into());
    }
    if type_hint == Some("remote") && url.is_none() {
        return Err("a remote server requires a non-empty 'url'".into());
    }
    // OpenCode also allows a config entry that only overrides `enabled` for a
    // server inherited from elsewhere. It is not a complete server definition,
    // so leave it in the config but omit it from Toolport's import inventory.
    if command.is_none() && url.is_none() {
        return Ok(None);
    }

    let mut env = Vec::new();
    for key in ["environment", "headers"] {
        let Some(value) = obj.get(key) else {
            continue;
        };
        let values = value
            .as_object()
            .ok_or_else(|| format!("'{key}' must be an object"))?;
        env.extend(values.iter().map(|(key, value)| SnippetEnvVar {
            key: key.clone(),
            value: json_value_to_string(value),
        }));
    }
    env.sort_by(|left, right| left.key.cmp(&right.key));
    env.dedup_by(|left, right| left.key == right.key);

    Ok(Some(ParsedSnippetServer {
        name: name.to_string(),
        transport: if command.is_some() {
            "stdio".into()
        } else {
            "http".into()
        },
        command,
        args,
        url,
        env,
    }))
}

fn parse_opencode_json(content: &str) -> Result<Vec<McpServer>, String> {
    let value = parse_json_value(content)?;
    let obj = match value.get("mcp") {
        None => return Ok(Vec::new()),
        Some(value) if value.is_object() => value.as_object().unwrap(),
        Some(_) => {
            return Err("'mcp' must be an object mapping server names to definitions".into())
        }
    };

    let mut malformed = Vec::new();
    let mut servers = Vec::new();
    for (name, definition) in obj {
        match opencode_server_with_values(name, definition) {
            Ok(Some(server)) => servers.push(McpServer {
                name: server.name,
                transport: server.transport,
                command: server.command,
                args: server.args,
                env_keys: server.env.into_iter().map(|entry| entry.key).collect(),
                url: server.url,
            }),
            Ok(None) => {}
            Err(error) => malformed.push(format!("{name} ({error})")),
        }
    }
    if !malformed.is_empty() {
        malformed.sort();
        return Err(format!("malformed 'mcp' entry: {}", malformed.join(", ")));
    }
    servers.sort_by_key(|server| server.name.to_lowercase());
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
                .map(|arr| arr.iter().filter_map(toml_value_to_string).collect())
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

fn app_present_with_override(
    config_path: &str,
    config_exists: bool,
    install_marker: Option<&Path>,
) -> bool {
    match install_marker {
        Some(marker) => config_exists || marker.exists(),
        None => app_present_for(config_path, config_exists),
    }
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
        // ~/.junie/mcp may not exist until MCP is configured; ~/.junie is the
        // stable user-scope data root created by Junie.
        "junie" => Some(home()?.join(".junie")),
        // MCP file lives under ~/.toolport-studio, but presence also includes
        // Electron userData and installer dirs (and the transitional t3code path).
        "toolport-studio" => toolport_studio_install_marker(),
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
            gateway_identity_matches(&server.name, &server.name, server.command.as_deref())
        });
        // Ownership is filled in later via [`apply_entry_states`] once the registry
        // record is available. Until then: identity match → Managed (legacy), none → Absent.
        let entry_state = if gateway_installed {
            GatewayEntryState::Managed
        } else {
            GatewayEntryState::Absent
        };
        // The config file's parent is the client's own data dir (e.g. `.../Code/User`,
        // `.../Claude`, `~/.codex`); its presence means the app has run here. If the
        // config itself exists the app is obviously present. An empty path means we
        // couldn't even resolve a location, so the app is not detectable.
        // Clients with an explicit install dir use it (and ignore the config-parent
        // heuristic, which for them is wrong); everyone else uses the parent of
        // their resolved config path (which is their data dir, e.g. ~/.codex).
        let install_marker = install_override(def.id);
        let app_present =
            app_present_with_override(&config_path, config_exists, install_marker.as_deref());
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
            entry_state,
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
        Format::JsonCopilotMcpServers => parse_json(&content, "mcpServers"),
        Format::JsonDroidMcpServers => parse_json(&content, "mcpServers"),
        Format::JsonAmpMcpServers => parse_json(&content, "amp.mcpServers"),
        Format::JsonQwenMcpServers => parse_qwen_json(&content),
        Format::JsonServers => parse_json(&content, "servers"),
        Format::JsonMcp => parse_json(&content, "mcp"),
        Format::JsonOpenCodeMcp => parse_opencode_json(&content),
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

/// Whether a detected gateway slot matches the ownership record we last wrote.
/// Auth headers / bearer args are stripped before compare so shared-HTTP entries
/// still match without storing tokens on the registry (SOU-406/407).
fn managed_matches_detected(server: &McpServer, rec: &ManagedEntry) -> bool {
    let cmd = server.command.as_deref().unwrap_or("");
    if cmd != rec.command {
        return false;
    }
    let server_args = crate::registry::strip_auth_header_args(&server.args);
    if server_args != rec.args {
        return false;
    }
    // Env keys: ignore Authorization (secret, not in the record).
    let mut keys: Vec<String> = server
        .env_keys
        .iter()
        .filter(|k| !k.eq_ignore_ascii_case("authorization"))
        .cloned()
        .collect();
    keys.sort();
    let rec_keys: Vec<String> = rec.env.keys().cloned().collect();
    if keys != rec_keys {
        return false;
    }
    // Shared-HTTP: URL must agree when both sides have one.
    if let Some(rec_url) = rec.url.as_deref() {
        let live_url = server.url.as_deref().or_else(|| {
            server
                .args
                .iter()
                .find(|a| a.starts_with("http://") || a.starts_with("https://"))
                .map(String::as_str)
        });
        if live_url != Some(rec_url) {
            return false;
        }
    }
    true
}

/// Resolve Managed / Customized / Absent for one client (SOU-406).
pub fn resolve_entry_state(
    servers: &[McpServer],
    record: Option<&ManagedEntry>,
) -> GatewayEntryState {
    let entry = servers
        .iter()
        .find(|s| gateway_identity_matches(&s.name, &s.name, s.command.as_deref()));
    let Some(entry) = entry else {
        return GatewayEntryState::Absent;
    };
    match record {
        Some(rec) if managed_matches_detected(entry, rec) => GatewayEntryState::Managed,
        Some(_) => GatewayEntryState::Customized,
        // No ownership record (install predates SOU-406): fall back to the
        // SOU-405 command-basename heuristic so genuine installs stay Managed
        // and hand-edited npx/docker/etc. entries surface as Customized.
        None if command_is_gateway_binary(entry.command.as_deref().unwrap_or("")) => {
            GatewayEntryState::Managed
        }
        None => GatewayEntryState::Customized,
    }
}

/// Fill [`DetectedClient::entry_state`] from the registry ownership map.
pub fn apply_entry_states(clients: &mut [DetectedClient], managed: &HashMap<String, ManagedEntry>) {
    for client in clients.iter_mut() {
        client.entry_state = resolve_entry_state(&client.servers, managed.get(&client.id));
        // Keep gateway_installed aligned with identity presence (not ownership).
        client.gateway_installed = client.entry_state != GatewayEntryState::Absent;
    }
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
    /// Snapshot of the gateway entry just installed (for the ownership record).
    /// Absent on uninstall or when the write did not install a gateway entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedEntry>,
}

/// Result of launch-time re-point (SOU-405/406).
#[derive(Debug, Default)]
pub struct RepointOutcome {
    /// Client ids whose gateway entry was rewritten to the current binary, with
    /// the ownership snapshot that was written.
    pub repointed: Vec<(String, ManagedEntry)>,
    /// Client ids left alone because their entry is user-customized.
    pub customized: Vec<String>,
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
    prune_backups(&dir, name);
    Ok(Some(dest))
}

/// How many backup generations to keep per client config file. Matches the
/// registry's `BACKUP_GENERATIONS` so both stores bound recovery depth the same way.
const CONFIG_BACKUP_GENERATIONS: usize = 5;

/// Drop all but the newest [`CONFIG_BACKUP_GENERATIONS`] backups of one config file
/// (SOU-433).
///
/// These copies are not inert: a Shared HTTP client's config carries a live
/// `Authorization: Bearer <token>`, and since #503 that bearer is the one the client
/// actually sends. Repoint runs on every launch, so an unpruned directory accumulated
/// working credentials indefinitely, and `revoke_client_http_token` (which exists
/// precisely so "a leftover backup" cannot keep authenticating) only covers Disconnect.
/// Bounding the count bounds how long a rotated-away token survives on disk.
///
/// Best-effort: a failure here must never fail the write the backup was protecting.
/// Names are `<millis>-<file name>`. Age order comes from parsing that prefix as a
/// number, not from sorting the names: lexical order only equals age order while every
/// stamp is the same width, so a short prefix (a clock that read near the epoch, or any
/// future change to the stamp format) would sort as "oldest" and get deleted first
/// regardless of when it was written.
fn prune_backups(dir: &Path, name: &str) {
    let suffix = format!("-{name}");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut mine: Vec<(u128, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter_map(|p| {
            let stamp = p
                .file_name()
                .and_then(|f| f.to_str())
                .and_then(|f| f.strip_suffix(&suffix))
                // Timestamp prefix only, so backups of `config.yaml` never prune
                // backups of some other `<x>-config.yaml` in the same directory.
                .filter(|stamp| !stamp.is_empty() && stamp.bytes().all(|b| b.is_ascii_digit()))
                // An unparseable stamp means a name we do not own the format of; skip
                // it rather than guess its age.
                .and_then(|stamp| stamp.parse::<u128>().ok())?;
            Some((stamp, p))
        })
        .collect();
    if mine.len() <= CONFIG_BACKUP_GENERATIONS {
        return;
    }
    mine.sort_by_key(|(stamp, _)| *stamp);
    let excess = mine.len() - CONFIG_BACKUP_GENERATIONS;
    for (_, stale) in mine.into_iter().take(excess) {
        let _ = std::fs::remove_file(stale);
    }
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
        // Native remote (VS Code `servers`, etc.): clients send HTTP headers, not
        // process env. Writing Authorization under `env` leaves the token on disk
        // but never on the wire (WS3-3). Prefer `headers` + a type hint.
        if entry.command.is_none() {
            let type_hint = if entry.transport.eq_ignore_ascii_case("sse") {
                "sse"
            } else {
                "http"
            };
            map.insert("type".into(), serde_json::Value::String(type_hint.into()));
        }
    }
    let kv: serde_json::Map<String, serde_json::Value> = entry
        .env
        .iter()
        .filter_map(|e| {
            e.value
                .as_ref()
                .map(|v| (e.key.clone(), serde_json::Value::String(v.clone())))
        })
        .collect();
    if !kv.is_empty() {
        // Remote → headers (sent). Stdio → env (subprocess). Qwen remaps headers
        // further (httpUrl) in entry_to_qwen_json.
        let key = if entry.command.is_none() && entry.url.is_some() {
            "headers"
        } else {
            "env"
        };
        map.insert(key.into(), serde_json::Value::Object(kv));
    }
    serde_json::Value::Object(map)
}

/// Crush uses the standard command/args/env fields but requires an explicit
/// transport type on every entry.
fn entry_to_crush_json(entry: &ServerEntry) -> serde_json::Value {
    let mut value = entry_to_json(entry);
    value.as_object_mut().unwrap().insert(
        "type".into(),
        serde_json::Value::String(entry.transport.clone()),
    );
    value
}

fn entry_to_droid_json(entry: &ServerEntry) -> serde_json::Value {
    let mut value = entry_to_json(entry);
    value.as_object_mut().unwrap().insert(
        "type".into(),
        serde_json::Value::String(entry.transport.clone()),
    );
    value
}

fn entry_to_qwen_json(entry: &ServerEntry) -> serde_json::Value {
    let mut value = entry_to_json(entry);
    if entry.command.is_none() {
        let object = value.as_object_mut().unwrap();
        if entry.transport != "sse" {
            if let Some(url) = object.remove("url") {
                object.insert("httpUrl".into(), url);
            }
        }
        // entry_to_json already emits `headers` for remote; keep a remap of legacy
        // `env` so older call sites that stuffed auth into env still work.
        if let Some(env) = object.remove("env") {
            object.insert("headers".into(), env);
        }
        // Qwen does not use a `type` field on remote entries.
        object.remove("type");
    }
    value
}

fn entry_to_opencode_json(entry: &ServerEntry) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("enabled".into(), serde_json::Value::Bool(true));

    if let Some(command) = &entry.command {
        map.insert("type".into(), serde_json::Value::String("local".into()));
        map.insert(
            "command".into(),
            serde_json::Value::Array(
                std::iter::once(command)
                    .chain(entry.args.iter())
                    .map(|part| serde_json::Value::String(part.clone()))
                    .collect(),
            ),
        );
    } else if let Some(url) = &entry.url {
        map.insert("type".into(), serde_json::Value::String("remote".into()));
        map.insert("url".into(), serde_json::Value::String(url.clone()));
    }

    let values: serde_json::Map<String, serde_json::Value> = entry
        .env
        .iter()
        .filter_map(|env| {
            env.value
                .as_ref()
                .map(|value| (env.key.clone(), serde_json::Value::String(value.clone())))
        })
        .collect();
    if !values.is_empty() {
        let key = if entry.command.is_some() {
            "environment"
        } else {
            "headers"
        };
        map.insert(key.into(), serde_json::Value::Object(values));
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

/// Convert a `serde_json::Value` into a `jsonc-parser` CST input so we can splice
/// a rewritten value into an existing JSONC document without losing comments.
fn serde_to_cst_input(value: &serde_json::Value) -> jsonc_parser::cst::CstInputValue {
    use jsonc_parser::cst::CstInputValue;
    match value {
        serde_json::Value::Null => CstInputValue::Null,
        serde_json::Value::Bool(b) => CstInputValue::Bool(*b),
        serde_json::Value::Number(n) => CstInputValue::Number(n.to_string()),
        serde_json::Value::String(s) => CstInputValue::String(s.clone()),
        serde_json::Value::Array(items) => {
            CstInputValue::Array(items.iter().map(serde_to_cst_input).collect())
        }
        serde_json::Value::Object(map) => CstInputValue::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), serde_to_cst_input(v)))
                .collect(),
        ),
    }
}

/// Count how many times `key` appears as a top-level property name in a JSONC object.
fn count_top_level_key(obj: &jsonc_parser::cst::CstObject, key: &str) -> usize {
    obj.properties()
        .into_iter()
        .filter(|prop| {
            prop.name()
                .and_then(|n| n.decoded_value().ok())
                .map(|name| name == key)
                .unwrap_or(false)
        })
        .count()
}

/// Reject duplicate top-level occurrences of `key` in JSONC text.
///
/// Duplicate keys are ambiguous: `obj.get(key)` only rewrites the first, so a later
/// effective entry can stay stale. Callers must not fall back to pretty JSON when this
/// fails — the file must remain unchanged (#555 review).
fn reject_duplicate_top_level_key(original: &str, key: &str) -> Result<(), String> {
    use jsonc_parser::cst::CstRootNode;
    use jsonc_parser::ParseOptions;

    let root = CstRootNode::parse(original, &ParseOptions::default())
        .map_err(|e| e.to_string())?;
    let Some(obj) = root.object_value() else {
        return Ok(());
    };
    let n = count_top_level_key(&obj, key);
    if n > 1 {
        return Err(format!(
            "malformed config: top-level key '{key}' appears {n} times; refusing to write"
        ));
    }
    Ok(())
}

/// Rewrite a single top-level object property in `original` JSON/JSONC text,
/// preserving comments, trailing commas, and formatting of everything else.
/// Used so gateway install/write no longer strips user annotations (#555).
///
/// Fails if `key` appears more than once at the top level (ambiguous rewrite).
fn rewrite_json_key_preserving(
    original: &str,
    key: &str,
    new_value: &serde_json::Value,
) -> Result<String, String> {
    use jsonc_parser::cst::CstRootNode;
    use jsonc_parser::ParseOptions;

    let root = CstRootNode::parse(original, &ParseOptions::default())
        .map_err(|e| e.to_string())?;
    // Client configs we edit are always root objects. Non-objects fall through
    // to the pretty-print path via the caller.
    let Some(obj) = root.object_value() else {
        return Err("JSONC root is not an object".into());
    };
    let n = count_top_level_key(&obj, key);
    if n > 1 {
        return Err(format!(
            "malformed config: top-level key '{key}' appears {n} times; refusing to write"
        ));
    }
    let input = serde_to_cst_input(new_value);
    if let Some(prop) = obj.get(key) {
        prop.set_value(input);
    } else {
        obj.append(key, input);
    }
    Ok(root.to_string())
}

/// Serialize `root` for disk. When `original` is present, surgically rewrite
/// only `changed_key` via a JSONC CST so comments outside that key survive.
/// Falls back to `serde_json::to_string_pretty` for new/empty files or when the
/// CST rewrite cannot apply (keeps prior behavior for pure JSON / edge cases).
///
/// Duplicate top-level keys for `changed_key` are a hard error (no pretty fallback)
/// so the existing file is left untouched.
fn atomic_write_json_config(
    path: &Path,
    original: Option<&str>,
    root: &serde_json::Value,
    changed_key: &str,
) -> Result<(), String> {
    let pretty = || {
        serde_json::to_string_pretty(root).map_err(|e| e.to_string())
    };

    let out = match (original, root.get(changed_key)) {
        (Some(src), Some(val)) if !src.trim().is_empty() => {
            // Hard-fail on duplicate target keys before any rewrite/fallback so the
            // file is never replaced with pretty JSON that drops one of the entries.
            // Pre-check (not error-string matching) so jsonc-parser message rewords
            // cannot silently re-enable the pretty fallback (#592 review).
            reject_duplicate_top_level_key(src, changed_key)?;
            match rewrite_json_key_preserving(src, changed_key, val) {
                Ok(text) => text,
                // rewrite may still fail for non-object roots / CST issues → pretty
                Err(_) => pretty()?,
            }
        }
        _ => pretty()?,
    };
    atomic_write(path, &out)
}

fn validate_amp_settings_shape(root: &serde_json::Value) -> Result<(), String> {
    let object = root
        .as_object()
        .ok_or("Amp settings root must be an object; leaving it untouched.")?;
    if object
        .get("amp.mcpServers")
        .is_some_and(|servers| !servers.is_object())
    {
        return Err("'amp.mcpServers' must be an object; leaving Amp settings untouched.".into());
    }
    Ok(())
}

fn validate_crush_settings_shape(root: &serde_json::Value) -> Result<(), String> {
    let object = root
        .as_object()
        .ok_or("Crush config root must be an object; leaving it untouched.")?;
    if object.get("mcp").is_some_and(|servers| !servers.is_object()) {
        return Err("'mcp' must be an object; leaving the Crush config untouched.".into());
    }
    Ok(())
}

fn write_json(
    path: &Path,
    key: &str,
    servers: &[ServerEntry],
    lenient: bool,
) -> Result<(), String> {
    write_json_with(path, key, servers, lenient, entry_to_json, false, false)
}

fn write_crush_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    write_json_with(path, "mcp", servers, true, entry_to_crush_json, true, false)
}

fn write_copilot_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    write_json_with(path, "mcpServers", servers, false, entry_to_json, false, true)
}

fn write_droid_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    write_json_with(path, "mcpServers", servers, false, entry_to_droid_json, false, false)
}

fn write_json_with(
    path: &Path,
    key: &str,
    servers: &[ServerEntry],
    lenient: bool,
    entry_to_value: fn(&ServerEntry) -> serde_json::Value,
    validate_crush_shape: bool,
    include_tools: bool,
) -> Result<(), String> {
    let (mut root, original) = if path.exists() {
        let content = read_config_file(path)?;
        let root = read_existing_json(&content, lenient)?;
        (root, Some(content))
    } else {
        (serde_json::Value::Object(serde_json::Map::new()), None)
    };
    if validate_crush_shape {
        validate_crush_settings_shape(&root)?;
    } else if key == "amp.mcpServers" {
        validate_amp_settings_shape(&root)?;
    } else if !root.is_object() {
        // Non-object roots are replaced wholesale; skip comment-preserving rewrite.
        root = serde_json::Value::Object(serde_json::Map::new());
        return write_json_with_body(
            path,
            None,
            key,
            &mut root,
            servers,
            entry_to_value,
            include_tools,
        );
    }
    write_json_with_body(
        path,
        original.as_deref(),
        key,
        &mut root,
        servers,
        entry_to_value,
        include_tools,
    )
}

fn write_json_with_body(
    path: &Path,
    original: Option<&str>,
    key: &str,
    root: &mut serde_json::Value,
    servers: &[ServerEntry],
    entry_to_value: fn(&ServerEntry) -> serde_json::Value,
    include_tools: bool,
) -> Result<(), String> {
    let obj = root.as_object_mut().unwrap();
    let servers_map: serde_json::Map<String, serde_json::Value> = servers
        .iter()
        .map(|server| {
            let mut value = entry_to_value(server);
            if include_tools {
                value.as_object_mut().unwrap().insert(
                    "tools".into(),
                    serde_json::json!(["*"]),
                );
            }
            (server.name.clone(), value)
        })
        .collect();
    obj.insert(key.to_string(), serde_json::Value::Object(servers_map));
    atomic_write_json_config(path, original, root, key)
}

fn write_qwen_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let (mut root, original) = if path.exists() {
        let content = read_config_file(path)?;
        let root = read_existing_json(&content, true)?;
        (root, Some(content))
    } else {
        (serde_json::Value::Object(serde_json::Map::new()), None)
    };
    if !root.is_object() {
        return Err("Qwen Code config root must be an object; leaving it untouched.".into());
    }

    let object = root.as_object_mut().unwrap();
    let servers_map = servers
        .iter()
        .map(|server| (server.name.clone(), entry_to_qwen_json(server)))
        .collect();
    object.insert("mcpServers".into(), serde_json::Value::Object(servers_map));

    atomic_write_json_config(path, original.as_deref(), &root, "mcpServers")
}

fn opencode_mcp_mut(
    root: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, String> {
    if !root.is_object() {
        return Err("Client config root must be an object; leaving it untouched.".into());
    }
    let object = root.as_object_mut().unwrap();
    if object
        .get("mcp")
        .map(|value| !value.is_object())
        .unwrap_or(false)
    {
        return Err("'mcp' must be an object; leaving the client config untouched.".into());
    }
    if !object.contains_key("mcp") {
        object.insert(
            "mcp".into(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
    }
    Ok(object.get_mut("mcp").unwrap().as_object_mut().unwrap())
}

fn opencode_entry_is_override_only(definition: &serde_json::Value) -> bool {
    let Some(object) = definition.as_object() else {
        return false;
    };
    object.get("type").is_none()
        && object.get("command").is_none()
        && object.get("url").is_none()
        && object
            .get("enabled")
            .is_some_and(|value| value.is_boolean())
}

fn write_opencode_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    let original = if path.exists() {
        Some(read_config_file(path)?)
    } else {
        None
    };
    let mut root = match &original {
        Some(content) => read_existing_json(content, true)?,
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    let mcp = opencode_mcp_mut(&mut root)?;
    // Complete server definitions are replaced by Toolport's inventory, but an
    // `enabled`-only entry may override a server inherited from another OpenCode
    // config layer and has no inventory representation of its own.
    mcp.retain(|_, definition| opencode_entry_is_override_only(definition));
    mcp.extend(
        servers
            .iter()
            .map(|server| (server.name.clone(), entry_to_opencode_json(server))),
    );
    atomic_write_json_config(path, original.as_deref(), &root, "mcp")
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
            .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
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

fn edit_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
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
    if let Some(entry) = entry {
        exts.insert(key, entry_to_goose_yaml(entry));
    }
    let out = serde_yaml::to_string(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

/// Parse Continue's `mcpServers` list into servers. Entries may be local stdio
/// servers (`command`/`args`/`env`) or remote servers (`type`/`url`).
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
        let url = str_of("url").filter(|s| !s.is_empty());
        if command.is_none() && url.is_none() {
            continue;
        }
        let transport = classify(&command, &url, str_of("type").as_deref());

        let args = def
            .get(serde_yaml::Value::String("args".into()))
            .and_then(|v| v.as_sequence())
            .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
            .unwrap_or_default();

        // Stdio: Continue reads `env`. Remote: Continue sends
        // `requestOptions.headers` (not process env) — collect both so ownership
        // re-detect and Shared HTTP stay in sync (WS3-1).
        let env_keys = continue_yaml_env_keys(def);

        servers.push(McpServer {
            name,
            transport,
            command,
            args,
            env_keys,
            url,
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

/// Keys Continue may use for credentials / client identity on one mcpServers entry.
fn continue_yaml_env_keys(def: &serde_yaml::Mapping) -> Vec<String> {
    let mut env_keys = Vec::new();
    let str_key = |k: &str| serde_yaml::Value::String(k.into());
    if let Some(m) = def.get(str_key("env")).and_then(|v| v.as_mapping()) {
        env_keys.extend(m.keys().filter_map(|k| k.as_str().map(String::from)));
    }
    if let Some(m) = def
        .get(str_key("requestOptions"))
        .and_then(|v| v.as_mapping())
        .and_then(|ro| ro.get(str_key("headers")))
        .and_then(|v| v.as_mapping())
    {
        env_keys.extend(m.keys().filter_map(|k| k.as_str().map(String::from)));
    }
    env_keys.sort_unstable();
    env_keys.dedup();
    env_keys
}

/// Build a Continue MCP server record for a server entry.
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

    let v = if let Some(command) = &entry.command {
        serde_json::json!({
            "name": entry.name,
            "command": command,
            "args": entry.args,
            "env": env,
        })
    } else if let Some(url) = &entry.url {
        let transport = if entry.transport.eq_ignore_ascii_case("sse") {
            "sse"
        } else {
            "streamable-http"
        };
        // Remote: Continue only forwards `requestOptions.headers` on the wire.
        // Writing Authorization under `env` leaves a plaintext bearer on disk
        // that never authenticates (WS3-1) — same trap entry_to_json documents.
        let mut remote = serde_json::json!({
            "name": entry.name,
            "type": transport,
            "url": url,
        });
        if !env.is_empty() {
            remote.as_object_mut().unwrap().insert(
                "requestOptions".into(),
                serde_json::json!({ "headers": env }),
            );
        }
        remote
    } else {
        // Preserve invalid entries visibly instead of silently dropping them.
        serde_json::json!({
            "name": entry.name,
            "command": "",
            "args": entry.args,
            "env": env,
        })
    };

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

fn edit_continue_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
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

    if let Some(entry) = entry {
        servers.push(entry_to_continue_yaml(entry));
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
            .map(|seq| seq.iter().filter_map(yaml_value_to_string).collect())
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
    // Stdio: env vars go under `env`. Remote: credentials must be under `headers`
    // or Hermes never sends them (WS3-3). Same split as OpenCode / VS Code.
    let kv: serde_yaml::Mapping = entry
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
    if !kv.is_empty() {
        let key = if entry.command.is_none() && entry.url.is_some() {
            "headers"
        } else {
            "env"
        };
        cfg.insert(
            serde_yaml::Value::String(key.into()),
            serde_yaml::Value::Mapping(kv),
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

fn edit_hermes_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
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
    if let Some(entry) = entry {
        mcp_servers.insert(key, entry_to_hermes_yaml(entry));
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
        Format::JsonCopilotMcpServers => write_copilot_json(&path, servers)?,
        Format::JsonDroidMcpServers => write_droid_json(&path, servers)?,
        Format::JsonAmpMcpServers => write_json(&path, "amp.mcpServers", servers, true)?,
        Format::JsonQwenMcpServers => write_qwen_json(&path, servers)?,
        Format::JsonServers => write_json(&path, "servers", servers, lenient)?,
        Format::JsonMcp => write_crush_json(&path, servers)?,
        Format::JsonOpenCodeMcp => write_opencode_json(&path, servers)?,
        Format::JsonContextServers => write_json(&path, "context_servers", servers, true)?,
        Format::TomlMcpServers => write_toml(&path, servers)?,
        Format::YamlExtensions => write_yaml_extensions(&path, servers)?,
        Format::YamlMcpServers => write_hermes_yaml_servers(&path, servers)?,
        Format::YamlMcpServersList => write_continue_yaml_servers(&path, servers)?,
    }
    // migrate_to_gateway writes a single gateway entry; capture ownership when so.
    let managed = servers
        .iter()
        .find(|s| is_gateway_server(s))
        .filter(|_| servers.len() == 1)
        .map(ManagedEntry::from_gateway_entry);

    Ok(WriteOutcome {
        path: path.display().to_string(),
        backup: backup.map(|b| b.display().to_string()),
        managed,
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
    // profile from registry.client_scopes[TOOLPORT_CLIENT_ID] on every reload, so
    // every re-scope applies without restarting the client - scoped->scoped,
    // scoped->unscoped, AND unscoped->scoped (an unscoped install still carries
    // its id, and its empty-string scope marker just resolves to "follow the
    // active profile" until it's given a named one). A client installed before
    // this env var existed simply has no client-id env until its next
    // reinstall and falls back to TOOLPORT_PROFILE / CONDUIT_PROFILE meanwhile.
    // See docs/drafts/profile-switch-live-reload-plan.md.
    env.push(env_var(crate::brand::CLIENT_ID, client_id));
    // PROFILE is only the *initial* value for a scoped install; once the
    // registry loads, the live client_scopes entry wins. Unscoped installs omit
    // it (and record an empty-string scope marker via set_client_unscoped).
    if let Some(p) = profile.map(str::trim).filter(|p| !p.is_empty()) {
        env.push(env_var(crate::brand::PROFILE, p));
    }
    Ok(ServerEntry {
        id: GATEWAY_ENTRY_NAME.to_string(),
        name: GATEWAY_ENTRY_NAME.to_string(),
        transport: "stdio".to_string(),
        command: Some(path.to_string_lossy().into_owned()),
        args: Vec::new(),
        env,
        url: None,
        source: Some("toolport".to_string()),
        disabled_tools: Vec::new(),
        cwd: None,
        client_credentials: None,
        unknown_fields: serde_json::Map::new(),
    })
}

/// Parameters for installing a shared-HTTP gateway entry (SOU-407).
#[derive(Debug, Clone)]
pub struct SharedHttpSpec {
    pub url: String,
    pub token: String,
}

/// Whether this client needs the `npx mcp-remote` bridge instead of a native
/// remote MCP entry. Native: formats with first-class url+headers. Bridge: most
/// JsonMcpServers clients (Claude Desktop, etc.) that only spawn stdio.
pub fn client_uses_mcp_remote_bridge(client_id: &str) -> bool {
    let Some(def) = find_def(client_id) else {
        return true;
    };
    match def.format {
        // Native remote shapes already exist in our writers.
        Format::JsonQwenMcpServers
        | Format::JsonMcp
        | Format::JsonCopilotMcpServers
        | Format::JsonDroidMcpServers
        | Format::JsonOpenCodeMcp
        | Format::JsonServers
        | Format::YamlMcpServers
        | Format::YamlMcpServersList => false,
        // JsonMcpServers / TOML / Goose: bridge unless we know better later.
        Format::JsonMcpServers
        | Format::JsonAmpMcpServers
        | Format::JsonContextServers
        | Format::TomlMcpServers
        | Format::YamlExtensions => true,
    }
}

/// Build a shared-HTTP gateway entry: native url+headers, or `npx mcp-remote` bridge.
pub fn gateway_entry_shared_http(
    client_id: &str,
    profile: Option<&str>,
    spec: &SharedHttpSpec,
) -> ServerEntry {
    let auth = format!("Bearer {}", spec.token);
    if client_uses_mcp_remote_bridge(client_id) {
        // Bridge form (Claude Desktop, etc.): third-party mcp-remote is opt-in
        // only when the user chooses Shared HTTP in Integrations (SOU-407).
        ServerEntry {
            id: GATEWAY_ENTRY_NAME.to_string(),
            name: GATEWAY_ENTRY_NAME.to_string(),
            transport: "stdio".to_string(),
            command: Some("npx".into()),
            args: vec![
                "-y".into(),
                "mcp-remote".into(),
                spec.url.clone(),
                "--header".into(),
                format!("Authorization: {auth}"),
            ],
            env: Vec::new(),
            url: None,
            source: Some("toolport".into()),
            disabled_tools: Vec::new(),
            cwd: None,
            client_credentials: None,
            unknown_fields: serde_json::Map::new(),
        }
    } else {
        let mut env = vec![crate::registry::EnvVar {
            key: "Authorization".into(),
            value: Some(auth),
            secret: true,
        }];
        // Keep client id for live scope resolution when the client forwards headers/env.
        env.push(crate::registry::EnvVar {
            key: crate::brand::CLIENT_ID.to_string(),
            value: Some(client_id.to_string()),
            secret: false,
        });
        if let Some(p) = profile.map(str::trim).filter(|p| !p.is_empty()) {
            env.push(crate::registry::EnvVar {
                key: crate::brand::PROFILE.to_string(),
                value: Some(p.to_string()),
                secret: false,
            });
        }
        ServerEntry {
            id: GATEWAY_ENTRY_NAME.to_string(),
            name: GATEWAY_ENTRY_NAME.to_string(),
            transport: "http".to_string(),
            command: None,
            args: Vec::new(),
            env,
            url: Some(spec.url.clone()),
            source: Some("toolport".into()),
            disabled_tools: Vec::new(),
            cwd: None,
            client_credentials: None,
            unknown_fields: serde_json::Map::new(),
        }
    }
}

fn edit_json_gateway(
    path: &Path,
    key: &str,
    entry: Option<&ServerEntry>,
    lenient: bool,
) -> Result<(), String> {
    edit_json_gateway_with(path, key, entry, lenient, None, false, false)
}

fn edit_crush_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    edit_json_gateway_with(
        path,
        "mcp",
        entry,
        true,
        Some(entry_to_crush_json),
        true,
        false,
    )
}

fn edit_copilot_json_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    edit_json_gateway_with(path, "mcpServers", entry, false, None, false, true)
}

fn edit_droid_json_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    edit_json_gateway_with(path, "mcpServers", entry, false, Some(entry_to_droid_json), false, false)
}

fn edit_json_gateway_with(
    path: &Path,
    key: &str,
    entry: Option<&ServerEntry>,
    lenient: bool,
    entry_formatter: Option<fn(&ServerEntry) -> serde_json::Value>,
    validate_crush_shape: bool,
    include_tools: bool,
) -> Result<(), String> {
    let (mut root, original) = if path.exists() {
        let content = read_config_file(path)?;
        let root = read_existing_json(&content, lenient)?;
        (root, Some(content))
    } else {
        (serde_json::Value::Object(serde_json::Map::new()), None)
    };
    if validate_crush_shape {
        validate_crush_settings_shape(&root)?;
    } else if key == "amp.mcpServers" {
        validate_amp_settings_shape(&root)?;
    } else if !root.is_object() {
        // Non-object roots are replaced wholesale; skip comment-preserving rewrite.
        root = serde_json::Value::Object(serde_json::Map::new());
        return edit_json_gateway_body(
            path,
            None,
            key,
            &mut root,
            entry,
            entry_formatter,
            include_tools,
        );
    }
    edit_json_gateway_body(
        path,
        original.as_deref(),
        key,
        &mut root,
        entry,
        entry_formatter,
        include_tools,
    )
}

fn edit_json_gateway_body(
    path: &Path,
    original: Option<&str>,
    key: &str,
    root: &mut serde_json::Value,
    entry: Option<&ServerEntry>,
    entry_formatter: Option<fn(&ServerEntry) -> serde_json::Value>,
    include_tools: bool,
) -> Result<(), String> {
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
    if let Some(entry) = entry {
        let mut value = if let Some(formatter) = entry_formatter {
            formatter(entry)
        } else if include_tools {
            entry_to_json(entry)
        } else if entry.command.is_none() && entry.url.is_some() {
            // Remote-only entries: Qwen wants httpUrl+headers; VS Code "servers" keeps url.
            // entry_to_qwen_json leaves url as-is for SSE and renames for streamable HTTP.
            if key == "servers" {
                entry_to_json(entry)
            } else {
                entry_to_qwen_json(entry)
            }
        } else {
            entry_to_json(entry)
        };
        if include_tools {
            value.as_object_mut().unwrap().insert(
                "tools".into(),
                serde_json::json!(["*"]),
            );
        }
        servers.insert(GATEWAY_ENTRY_NAME.to_string(), value);
    }

    atomic_write_json_config(path, original, root, key)
}

fn edit_opencode_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    let original = if path.exists() {
        Some(read_config_file(path)?)
    } else {
        None
    };
    let mut root = match &original {
        Some(content) => read_existing_json(content, true)?,
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    let mcp = opencode_mcp_mut(&mut root)?;
    mcp.retain(|name, definition| {
        let command = definition
            .get("command")
            .and_then(|value| value.as_array())
            .and_then(|parts| parts.first())
            .and_then(|value| value.as_str());
        !gateway_identity_matches(name, name, command)
    });
    if let Some(entry) = entry {
        mcp.insert(GATEWAY_ENTRY_NAME.into(), entry_to_opencode_json(entry));
    }
    atomic_write_json_config(path, original.as_deref(), &root, "mcp")
}

fn edit_toml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
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
    if let Some(entry) = entry {
        servers.insert(GATEWAY_ENTRY_NAME.to_string(), entry_to_toml(entry));
    }

    let out = toml::to_string_pretty(&root).map_err(|e| e.to_string())?;
    atomic_write(path, &out)
}

/// Clients whose JSON config file holds their ENTIRE application state (project
/// history, signed-in account, all servers), not just an MCP-servers block. For
/// these an unparseable file must ERROR rather than be silently replaced with a
/// fresh object, so a transient parse failure can't wipe the user's whole config
/// down to just our gateway entry. `~/.claude.json` (Claude Code),
/// `~/.gemini/settings.json` (Gemini CLI), `~/.qwen/settings.json` (Qwen Code),
/// `~/.config/kilo/kilo.jsonc` (Kilo Code), and Amp's shared `settings.json`
/// contain server maps alongside unrelated app state. Single-purpose files
/// (Claude Desktop, VS Code's dedicated `mcp.json`, LM Studio, ...) keep the
/// harmless start-fresh behavior. (Zed's whole-editor `settings.json` is already
/// lenient via its JsonContextServers format.)
fn config_is_whole_app_state(client_id: &str) -> bool {
    matches!(
        client_id,
        "claude-code" | "crush" | "gemini-cli" | "qwen-code" | "opencode" | "kilo-code" | "amp"
    )
}

fn install_or_remove(client_id: &str, entry: Option<&ServerEntry>) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    let backup = backup_file(client_id, &path)?;
    let lenient = config_is_whole_app_state(client_id);
    // Build the snapshot before writing so the ownership record matches the bytes
    // we put on disk (SOU-406). Strip secrets for the registry record.
    let managed = entry.map(ManagedEntry::from_gateway_entry);
    match def.format {
        Format::JsonMcpServers => {
            edit_json_gateway(&path, "mcpServers", entry, lenient)?
        }
        Format::JsonCopilotMcpServers => edit_copilot_json_gateway(&path, entry)?,
        Format::JsonDroidMcpServers => edit_droid_json_gateway(&path, entry)?,
        Format::JsonAmpMcpServers => {
            edit_json_gateway(&path, "amp.mcpServers", entry, true)?
        }
        Format::JsonQwenMcpServers => edit_json_gateway(&path, "mcpServers", entry, true)?,
        Format::JsonServers => edit_json_gateway(&path, "servers", entry, lenient)?,
        Format::JsonMcp => edit_crush_gateway(&path, entry)?,
        Format::JsonOpenCodeMcp => edit_opencode_gateway(&path, entry)?,
        Format::JsonContextServers => edit_json_gateway(&path, "context_servers", entry, true)?,
        Format::TomlMcpServers => edit_toml_gateway(&path, entry)?,
        Format::YamlExtensions => edit_yaml_gateway(&path, entry)?,
        Format::YamlMcpServers => edit_hermes_yaml_gateway(&path, entry)?,
        Format::YamlMcpServersList => edit_continue_yaml_gateway(&path, entry)?,
    }
    Ok(WriteOutcome {
        path: path.display().to_string(),
        backup: backup.map(|b| b.display().to_string()),
        managed,
    })
}

/// Add Toolport's stdio gateway entry to a client's config (preserves existing servers).
/// `profile` scopes the client to one profile via `TOOLPORT_PROFILE` (None = all).
pub fn install_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    let entry = gateway_entry(profile, client_id)?;
    install_or_remove(client_id, Some(&entry))
}

/// Add a shared-HTTP gateway entry (native remote or `npx mcp-remote` bridge). SOU-407.
pub fn install_gateway_shared_http(
    client_id: &str,
    profile: Option<&str>,
    spec: &SharedHttpSpec,
) -> Result<WriteOutcome, String> {
    let entry = gateway_entry_shared_http(client_id, profile, spec);
    install_or_remove(client_id, Some(&entry))
}

/// Remove Toolport's gateway entry from a client's config.
pub fn uninstall_gateway(client_id: &str) -> Result<WriteOutcome, String> {
    install_or_remove(client_id, None)
}

/// Replace a client's entire server list with just the Toolport gateway. Used by
/// "migrate": after the client's servers are imported into Toolport, this leaves
/// the client talking only to the gateway. Backs up first; unrelated config keys
/// are preserved. Caller is responsible for importing first so nothing is lost.
///
/// When `shared` is set, write a Shared HTTP entry instead of stdio so migrate
/// does not silently downgrade an existing Shared HTTP install (WS3-2).
pub fn migrate_to_gateway(client_id: &str, profile: Option<&str>) -> Result<WriteOutcome, String> {
    migrate_to_gateway_with_transport(client_id, profile, None)
}

/// Like [`migrate_to_gateway`], with an optional Shared HTTP spec (WS3-2).
pub fn migrate_to_gateway_with_transport(
    client_id: &str,
    profile: Option<&str>,
    shared: Option<&SharedHttpSpec>,
) -> Result<WriteOutcome, String> {
    let entry = match shared {
        Some(spec) => gateway_entry_shared_http(client_id, profile, spec),
        None => gateway_entry(profile, client_id)?,
    };
    write_servers(client_id, &[entry])
}

/// Whether a stored client-config command is recognizably one of *our* gateway
/// binaries. This is the provenance test that separates an entry Toolport wrote
/// from one the user has taken over.
///
/// [`gateway_identity_matches`] deliberately matches on the entry NAME alone, so a
/// hand-edited entry still called `toolport` is found (we must not leave a duplicate
/// behind, and the UI must still show it as our slot). But "we recognize this slot"
/// is not "we own this command". A user who repoints the entry at an HTTP bridge
/// (`npx -y mcp-remote http://localhost:8765/mcp ...`), a container, or their own
/// wrapper script has taken it over, and rewriting it destroys a deliberate
/// customization on every launch (issue #487).
///
/// Matched on the command's BASENAME rather than a substring of the whole path, so a
/// wrapper that merely *lives* in a directory containing `toolport-gateway` is not
/// mistaken for the binary itself. Version suffixes (`toolport-gateway-1.9.5.exe`)
/// and the pre-rename name (`conduit-gateway`) both count as ours.
fn command_is_gateway_binary(stored: &str) -> bool {
    let basename = stored
        .trim()
        .trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let stem = basename.strip_suffix(".exe").unwrap_or(&basename);
    stem.starts_with("toolport-gateway") || stem.starts_with("conduit-gateway")
}

/// Whether a client's stored gateway command should be re-pointed: it names the
/// pre-rename binary (`conduit-gateway`), or its path no longer exists on disk, and
/// it isn't already the current path.
///
/// Presumes the command is already known to be ours; the caller
/// ([`gateway_entry_needs_rewrite`]) establishes that with
/// [`command_is_gateway_binary`] first. These heuristics cannot make that call
/// themselves - they read "not our current path" as "our binary moved", which is only
/// true once provenance is settled.
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
    // Published bin dir: repoint when the app version bumped the gateway path,
    // or when the data-dir leaf moved Conduit → Toolport.
    let current_norm = current.replace('/', "\\").to_ascii_lowercase();
    let stored_norm = stored.replace('/', "\\").to_ascii_lowercase();
    if current_norm.contains("\\toolport\\bin\\toolport-gateway-")
        || current_norm.contains("\\conduit\\bin\\toolport-gateway-")
    {
        return true;
    }
    // Legacy data-dir path still in the client config after leaf migration.
    if stored_norm.contains("\\conduit\\bin\\") && current_norm.contains("\\toolport\\bin\\") {
        return true;
    }
    false
}

/// Whether [`repoint_stale_gateways`] should rewrite a client's existing gateway
/// entry: either its command is stale (see [`gateway_command_is_stale`]), it still
/// carries the pre-rename `conduit` name, or its env block still uses only the
/// pre-rename `CONDUIT_*` keys (no `TOOLPORT_*` yet).
fn gateway_entry_needs_rewrite(
    entry_name: &str,
    stored_command: &str,
    current: &str,
    config_text: Option<&str>,
) -> bool {
    // Provenance gate (issue #487), deliberately FIRST. Every rewrite below is a
    // migration of an entry we wrote - a moved binary, the pre-rename entry name, the
    // pre-rename env keys. None of them apply to an entry whose command isn't one of
    // our gateway binaries: that entry belongs to the user, and rewriting it silently
    // reverts a deliberate customization on every app launch.
    //
    // The heuristics below cannot make this call on their own. A bare `npx` fails
    // `gateway_command_is_stale`'s `Path::exists` test, and on a normal install its
    // published-bin branch treats anything not byte-identical to the current path as
    // stale - so without this gate every custom command is "stale" by construction.
    //
    // An entry with no command at all (a user-written http/sse entry under our name)
    // is likewise not ours, and falls out here on the empty basename.
    if !command_is_gateway_binary(stored_command) {
        return false;
    }
    if gateway_command_is_stale(stored_command, current)
        || entry_name.eq_ignore_ascii_case(LEGACY_GATEWAY_ENTRY_NAME)
    {
        return true;
    }
    // Migrate CONDUIT_CLIENT_ID / CONDUIT_PROFILE → TOOLPORT_* on launch when the
    // entry name and path are already current (SOU-318 only renamed the key).
    if let Some(text) = config_text {
        let has_legacy = text.contains(crate::brand::CLIENT_ID_LEGACY)
            || text.contains(crate::brand::PROFILE_LEGACY);
        let has_new =
            text.contains(crate::brand::CLIENT_ID) || text.contains(crate::brand::PROFILE);
        if has_legacy && !has_new {
            return true;
        }
    }
    false
}

/// Best-effort read of the gateway entry's profile env from raw client-config
/// text, format-tolerantly (JSON `"TOOLPORT_PROFILE": "x"`, TOML `= "x"`, YAML
/// `: x`). Prefers `TOOLPORT_PROFILE`, then legacy `CONDUIT_PROFILE`.
/// The parsed `McpServer` drops env VALUES (they can be secret), so a re-point reads
/// the profile here to preserve per-client scoping. None if absent/unparseable, in
/// which case the re-point falls back to the unscoped default, which widens access
/// rather than breaking it.
fn profile_from_config_text(content: &str) -> Option<String> {
    profile_key_from_config_text(content, crate::brand::PROFILE)
        .or_else(|| profile_key_from_config_text(content, crate::brand::PROFILE_LEGACY))
}

fn profile_key_from_config_text(content: &str, key: &str) -> Option<String> {
    let idx = content.find(key)?;
    let mut rest = content[idx + key.len()..].trim_start();
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

/// Re-point / migrate client gateway entries to the current install on launch.
/// Rewrites an entry when either:
///   - its command still names the pre-rename binary (or a path that no longer
///     exists), closing the `conduit-gateway` -> `toolport-gateway` gap on
///     platforms without the macOS compat symlink (Windows/Linux); or
///   - it still carries the pre-rename `conduit` entry name (SOU-318), migrating
///     it to [`GATEWAY_ENTRY_NAME`] so a brand-new install no longer shows up as
///     "conduit" inside clients. `install_gateway` retains-out every
///     identity-matching entry (legacy name included) before writing the current
///     one, so this renames in place rather than leaving a duplicate.
///
/// The stored entry is located by identity, not by the current name, so a legacy
/// `conduit` entry is found rather than skipped. Idempotent (an entry already on
/// the current name and path is left untouched, so it's a no-op after the first
/// launch), surgical (only the gateway entry is rewritten, and the config is backed
/// up first), and profile-preserving (the profile is read from raw config text,
/// independent of the entry name). Guarded so it never writes a path that doesn't
/// exist. Returns the ids of clients it rewrote.
///
/// Only entries we still own are ever rewritten. Ownership is the registry record
/// when present, else the SOU-405 command-basename heuristic (issue #487 / SOU-406).
/// A Customized entry is left byte-identical and reported in [`RepointOutcome::customized`].
/// Every gateway binary path a detected client would spawn.
///
/// Used to decide which published gateway binaries are safe to delete (SOU-484).
/// Deleting one a client still names turns "runs old code" into "cannot start the
/// gateway at all", so this is the authoritative do-not-delete set.
///
/// Returns `None` when any client's config could not be read. That client's
/// reference set is then unknown, and an unknown reference must not be treated as
/// an absent one: pruning is never urgent, so the caller skips the pass entirely
/// and retries on the next launch.
///
/// Unlike [`repoint_stale_gateways`], customized entries are **included**. Repoint
/// leaves them alone, but they still name a binary the user's client will spawn,
/// which is exactly what must survive.
///
/// `plugin_servers` are included for the same reason, and more strongly: they live
/// outside the main config, are managed by the client rather than by us, and so can
/// never be re-pointed onto a current binary. Deleting one out from under a plugin
/// entry leaves a reference nothing will ever repair.
pub fn referenced_gateway_paths() -> Option<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for client in detect_clients() {
        if client.error.is_some() {
            return None;
        }
        if !client.config_exists {
            continue;
        }
        for server in client.servers.iter().chain(client.plugin_servers.iter()) {
            if !gateway_identity_matches(&server.name, &server.name, server.command.as_deref()) {
                continue;
            }
            let Some(command) = server.command.as_deref() else {
                continue;
            };
            let command = command.trim();
            if command.is_empty() {
                continue;
            }
            let path = PathBuf::from(command);
            if !out.iter().any(|p| p == &path) {
                out.push(path);
            }
        }
    }
    Some(out)
}

pub fn repoint_stale_gateways(managed: &HashMap<String, ManagedEntry>) -> RepointOutcome {
    let mut outcome = RepointOutcome::default();
    let Some(current) = resolve_gateway_path().map(|p| p.to_string_lossy().into_owned()) else {
        return outcome;
    };
    // Never re-point onto a binary that isn't there (resolve_gateway_path returns a
    // best-guess path even when nothing is found, for clearer error messages).
    if !Path::new(&current).exists() {
        return outcome;
    }
    for client in detect_clients() {
        if !client.config_exists || client.error.is_some() {
            continue;
        }
        // Find our entry by identity (recognizes the legacy `conduit` name too), so
        // a pre-rename entry is migrated rather than missed.
        let entry = client
            .servers
            .iter()
            .find(|s| gateway_identity_matches(&s.name, &s.name, s.command.as_deref()));
        let Some(entry) = entry else {
            continue;
        };
        let stored = entry.command.as_deref().unwrap_or("");
        let entry_name = entry.name.as_str();
        let state = resolve_entry_state(&client.servers, managed.get(&client.id));
        if state == GatewayEntryState::Customized {
            eprintln!(
                "toolport: leaving {}'s '{}' entry alone - custom configuration (not managed \
                 by Toolport); command={}",
                client.id,
                entry_name,
                if stored.is_empty() { "none" } else { stored },
            );
            outcome.customized.push(client.id.clone());
            continue;
        }
        // Raw config text for profile preservation + legacy CONDUIT_* env detection.
        let config_text = find_def(&client.id)
            .and_then(|def| (def.path)())
            .and_then(|path| read_config_file(&path).ok());
        if !gateway_entry_needs_rewrite(entry_name, stored, &current, config_text.as_deref()) {
            continue;
        }
        let profile = config_text
            .as_deref()
            .and_then(profile_from_config_text)
            .or_else(|| read_gateway_profile(&client.id));
        if let Ok(write) = install_gateway(&client.id, profile.as_deref()) {
            if let Some(m) = write.managed {
                outcome.repointed.push((client.id.clone(), m));
            }
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EnvVar;

    fn sample_gateway(profile: Option<&str>, client_id: &str) -> ServerEntry {
        let mut env = vec![EnvVar {
            key: crate::brand::CLIENT_ID.to_string(),
            value: Some(client_id.to_string()),
            secret: false,
        }];
        if let Some(p) = profile.map(str::trim).filter(|p| !p.is_empty()) {
            env.push(EnvVar {
                key: crate::brand::PROFILE.to_string(),
                value: Some(p.to_string()),
                secret: false,
            });
        }
        ServerEntry {
            id: GATEWAY_ENTRY_NAME.to_string(),
            name: GATEWAY_ENTRY_NAME.to_string(),
            transport: "stdio".to_string(),
            command: Some("toolport-gateway".into()),
            args: Vec::new(),
            env,
            url: None,
            source: Some("toolport".into()),
            disabled_tools: Vec::new(),
            cwd: None,
            client_credentials: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

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
        // New keys
        assert_eq!(
            profile_from_config_text(r#"{"env":{"TOOLPORT_PROFILE":"work"}}"#).as_deref(),
            Some("work")
        );
        // Legacy keys still parse (existing installs until re-point).
        assert_eq!(
            profile_from_config_text(r#"{"env":{"CONDUIT_PROFILE":"work"}}"#).as_deref(),
            Some("work")
        );
        // TOML
        assert_eq!(
            profile_from_config_text("TOOLPORT_PROFILE = \"billing\"").as_deref(),
            Some("billing")
        );
        // YAML, quoted and bareword
        assert_eq!(
            profile_from_config_text("  CONDUIT_PROFILE: \"dev\"\n").as_deref(),
            Some("dev")
        );
        assert_eq!(
            profile_from_config_text("env:\n  TOOLPORT_PROFILE: staging\n").as_deref(),
            Some("staging")
        );
        // Prefer new over legacy when both appear.
        assert_eq!(
            profile_from_config_text(
                r#"{"env":{"TOOLPORT_PROFILE":"new","CONDUIT_PROFILE":"old"}}"#
            )
            .as_deref(),
            Some("new")
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
            client_credentials: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    fn remote(name: &str, transport: &str) -> ServerEntry {
        ServerEntry {
            id: name.to_string(),
            name: name.to_string(),
            transport: transport.to_string(),
            command: None,
            args: vec![],
            env: vec![EnvVar {
                key: "Authorization".to_string(),
                value: Some("Bearer fixture".to_string()),
                secret: false,
            }],
            url: Some(format!("https://{name}.example.com/mcp")),
            source: None,
            disabled_tools: vec![],
            cwd: None,
            client_credentials: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("conduit-w-{}-{}.cfg", std::process::id(), label))
    }

    /// SOU-433: config backups carry a live Shared HTTP bearer, so the directory
    /// must not grow forever. Prune keeps the newest generations of the file it was
    /// called for, and never touches a differently-named config's backups.
    #[test]
    fn prune_backups_bounds_generations_per_config_file() {
        let dir = std::env::temp_dir().join(format!("toolport-bk-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();

        // 8 generations of config.yaml, oldest first by timestamp prefix.
        for stamp in 1000000000001u64..=1000000000008 {
            std::fs::write(
                dir.join(format!("{stamp}-config.yaml")),
                "Authorization: Bearer x",
            )
            .unwrap();
        }
        // A different config whose name ENDS with the same suffix, plus unrelated files.
        std::fs::write(dir.join("1000000000001-other-config.yaml"), "x").unwrap();
        std::fs::write(dir.join("notes.txt"), "x").unwrap();

        prune_backups(&dir, "config.yaml");

        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "1000000000001-other-config.yaml".to_string(),
                "1000000000004-config.yaml".to_string(),
                "1000000000005-config.yaml".to_string(),
                "1000000000006-config.yaml".to_string(),
                "1000000000007-config.yaml".to_string(),
                "1000000000008-config.yaml".to_string(),
                "notes.txt".to_string(),
            ],
            "keep the newest {CONFIG_BACKUP_GENERATIONS}, drop older, touch nothing else"
        );

        // Idempotent once at the cap.
        prune_backups(&dir, "config.yaml");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 7);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Age order must come from the parsed stamp, not the name. When the millisecond
    /// count gains a digit, lexical order inverts and a plain sort would delete one of
    /// the NEWEST backups while keeping older ones.
    #[test]
    fn prune_backups_orders_by_parsed_timestamp_not_lexically() {
        let dir = std::env::temp_dir().join(format!("toolport-bk-width-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();

        // Straddle a digit-width boundary: 13-digit stamps are numerically OLDER than
        // the 14-digit ones, but sort AFTER them as strings.
        let oldest = "9999999999997";
        for stamp in [
            oldest,
            "9999999999998",
            "9999999999999",
            "10000000000000",
            "10000000000001",
            "10000000000002",
        ] {
            std::fs::write(dir.join(format!("{stamp}-config.yaml")), "x").unwrap();
        }

        prune_backups(&dir, "config.yaml");

        let left: std::collections::BTreeSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .collect();
        assert_eq!(left.len(), CONFIG_BACKUP_GENERATIONS);
        assert!(
            !left.contains(&format!("{oldest}-config.yaml")),
            "the numerically oldest backup must be the one dropped: {left:?}"
        );
        assert!(
            left.contains("10000000000000-config.yaml"),
            "a lexical sort would have deleted this newer backup instead: {left:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
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
    fn amp_literal_dotted_key_round_trips_and_preserves_shared_settings() {
        let path = temp_path("amp-roundtrip");
        std::fs::write(
            &path,
            r#"{"amp.theme":"dark","telemetry":false,"amp.mcpServers":{"old":{"command":"x"}}}"#,
        )
        .unwrap();

        write_json(&path, "amp.mcpServers", &[stdio("filesystem")], true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&content).unwrap();
        let parsed = parse_json(&content, "amp.mcpServers").unwrap();

        assert_eq!(root["amp.theme"], "dark");
        assert_eq!(root["telemetry"], false);
        assert!(
            root.get("amp").is_none(),
            "the dotted key must stay literal"
        );
        assert!(root["amp.mcpServers"].get("old").is_none());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "filesystem");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn amp_gateway_edit_and_uninstall_are_surgical() {
        let path = temp_path("amp-surgical");
        std::fs::write(
            &path,
            r#"{"amp.notifications":true,"amp.mcpServers":{"existing":{"command":"node","env":{"SECRET":"keepme"}},"conduit":{"command":"conduit-gateway"}}}"#,
        ).unwrap();

        let entry = sample_gateway(Some("Work"), "amp");
        edit_json_gateway(&path, "amp.mcpServers", Some(&entry), true).unwrap();
        let installed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(installed["amp.notifications"], true);
        assert_eq!(
            installed["amp.mcpServers"]["existing"]["env"]["SECRET"],
            "keepme"
        );
        assert!(installed["amp.mcpServers"].get("conduit").is_none());
        assert!(installed["amp.mcpServers"]
            .get(GATEWAY_ENTRY_NAME)
            .is_some());

        edit_json_gateway(&path, "amp.mcpServers", None, true).unwrap();
        let removed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(removed["amp.notifications"], true);
        assert!(removed["amp.mcpServers"].get("existing").is_some());
        assert!(removed["amp.mcpServers"].get(GATEWAY_ENTRY_NAME).is_none());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn amp_malformed_nonempty_shared_settings_are_never_overwritten() {
        let path = temp_path("amp-malformed");
        let malformed = r#"{"amp.theme":"dark","amp.mcpServers": {broken"#;
        std::fs::write(&path, malformed).unwrap();
        let error = edit_json_gateway(
            &path,
            "amp.mcpServers",
            Some(&sample_gateway(None, "amp")),
            true,
        )
        .unwrap_err();
        assert!(error.contains("leaving it untouched"), "got: {error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), malformed);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn amp_valid_non_object_root_is_never_overwritten() {
        let path = temp_path("amp-non-object-root");
        let original = r#"["shared", "settings"]"#;
        std::fs::write(&path, original).unwrap();

        assert!(write_json(&path, "amp.mcpServers", &[stdio("filesystem")], true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(edit_json_gateway(
            &path,
            "amp.mcpServers",
            Some(&sample_gateway(None, "amp")),
            true,
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn amp_valid_non_object_server_key_is_never_overwritten() {
        let path = temp_path("amp-non-object-key");
        let original = r#"{"amp.theme":"dark","amp.mcpServers":["unexpected"]}"#;
        std::fs::write(&path, original).unwrap();

        assert!(write_json(&path, "amp.mcpServers", &[stdio("filesystem")], true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(edit_json_gateway(
            &path,
            "amp.mcpServers",
            Some(&sample_gateway(None, "amp")),
            true,
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn qwen_json_parses_cli_generated_transports() {
        // Generated with Qwen Code 0.20.1 using `qwen mcp add --scope user`.
        let content = r#"{
            "mcpServers": {
                "local-fixture": {
                    "command": "/usr/bin/printf",
                    "args": ["ready\n"],
                    "env": {"TEST_TOKEN": "fixture"}
                },
                "remote-http": {
                    "httpUrl": "https://http.example.com/mcp",
                    "headers": {"X-Test": "fixture"}
                },
                "remote-sse": {
                    "url": "https://sse.example.com/events",
                    "headers": {"Authorization": "Bearer fixture"}
                }
            },
            "$version": 4
        }"#;

        let parsed = parse_qwen_json(content).unwrap();
        assert_eq!(parsed.len(), 3);

        assert_eq!(parsed[0].name, "local-fixture");
        assert_eq!(parsed[0].transport, "stdio");
        assert_eq!(parsed[0].command.as_deref(), Some("/usr/bin/printf"));
        assert_eq!(parsed[0].args, vec!["ready\n"]);
        assert_eq!(parsed[0].env_keys, vec!["TEST_TOKEN".to_string()]);

        assert_eq!(parsed[1].name, "remote-http");
        assert_eq!(parsed[1].transport, "http");
        assert_eq!(
            parsed[1].url.as_deref(),
            Some("https://http.example.com/mcp")
        );
        assert_eq!(parsed[1].env_keys, vec!["X-Test".to_string()]);

        assert_eq!(parsed[2].name, "remote-sse");
        assert_eq!(parsed[2].transport, "sse");
        assert_eq!(
            parsed[2].url.as_deref(),
            Some("https://sse.example.com/events")
        );
        assert_eq!(parsed[2].env_keys, vec!["Authorization".to_string()]);
    }

    #[test]
    fn qwen_transport_precedence_matches_current_cli() {
        let content = r#"{
            "mcpServers": {
                "mixed": {
                    "httpUrl": "https://http.example.com/mcp",
                    "url": "https://sse.example.com/events",
                    "command": "node",
                    "args": ["server.js"]
                }
            }
        }"#;

        let parsed = parse_qwen_json(content).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].transport, "http");
        assert_eq!(
            parsed[0].url.as_deref(),
            Some("https://http.example.com/mcp")
        );
        assert!(parsed[0].command.is_none());
        assert!(parsed[0].args.is_empty());
    }

    #[test]
    fn opencode_json_parses_local_remote_and_override_entries() {
        let content = r#"{
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "local-tools": {
                    "type": "local",
                    "command": ["npx", "-y", "@example/mcp"],
                    "environment": {"TOKEN": "secret"},
                    "enabled": true
                },
                "remote-tools": {
                    "type": "remote",
                    "url": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": "Bearer secret"},
                    "enabled": true
                },
                "inherited-toggle": {
                    "enabled": false
                }
            }
        }"#;

        let parsed = parse_opencode_json(content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "local-tools");
        assert_eq!(parsed[0].transport, "stdio");
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(parsed[0].args, vec!["-y", "@example/mcp"]);
        assert_eq!(parsed[0].env_keys, vec!["TOKEN"]);
        assert_eq!(parsed[1].name, "remote-tools");
        assert_eq!(parsed[1].transport, "http");
        assert_eq!(
            parsed[1].url.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(parsed[1].env_keys, vec!["Authorization"]);
    }

    #[test]
    fn opencode_json_rejects_malformed_command_arrays() {
        let content = r#"{"mcp":{"broken":{"type":"local","command":"npx"}}}"#;
        let error = parse_opencode_json(content).unwrap_err();
        assert!(error.contains("broken"), "got: {error}");
        assert!(error.contains("array of strings"), "got: {error}");
    }

    #[test]
    fn parse_json_snippet_disambiguates_opencode_and_crush_mcp_shapes() {
        // OpenCode shape: command is an argv array.
        let opencode = r#"{"mcp":{"fs":{"type":"local","command":["npx","-y","pkg"]}}}"#;
        let parsed = parse_json_snippet(opencode, "").unwrap();
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(parsed[0].args, vec!["-y", "pkg"]);

        // Crush shape: command is a string, args separate.
        let crush = r#"{"mcp":{"fs":{"type":"stdio","command":"npx","args":["-y","pkg"]}}}"#;
        let parsed = parse_json_snippet(crush, "").unwrap();
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(parsed[0].args, vec!["-y", "pkg"]);
    }

    #[test]
    fn parse_json_snippet_disambiguates_crush_sse_remote() {
        let crush_remote = r#"{"mcp":{"remote":{"type":"sse","url":"https://example.com/mcp","env":{"TOKEN":"secret"}}}}"#;
        let parsed = parse_json_snippet(crush_remote, "").unwrap();
        assert_eq!(parsed[0].transport, "sse");
        assert_eq!(parsed[0].url.as_deref(), Some("https://example.com/mcp"));
        assert_eq!(parsed[0].env[0].key, "TOKEN");
    }

    #[test]
    fn parse_json_snippet_unmatched_command_falls_through_to_wrapper_key() {
        let mixed =
            r#"{"mcp":{"unmatched":{"command":null}},"mcpServers":{"fallback":{"command":"npx"}}}"#;
        let parsed = parse_json_snippet(mixed, "").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "fallback");
    }

    #[test]
    fn parse_json_snippet_names_unusable_mcp_command() {
        let content = r#"{"mcp":{"foo":{"command":null}}}"#;
        let error = parse_json_snippet(content, "").unwrap_err();
        assert!(error.contains("foo"), "got: {error}");
        assert!(error.contains("string or array"), "got: {error}");
        assert!(!error.contains("no server definition"), "got: {error}");
    }

    #[test]
    fn parse_json_snippet_ignores_unusable_command_when_servers_parse() {
        let content = r#"{"mcp":{"bad":{"command":null},"crush":{"command":"npx"},"opencode":{"command":["uvx","server"]}}}"#;
        let parsed = parse_json_snippet(content, "").unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "crush");
        assert_eq!(parsed[1].name, "opencode");
    }

    #[test]
    fn parse_json_snippet_rejects_explicit_opencode_with_string_command() {
        let malformed = r#"{"mcp":{"fs":{"type":"local","command":"npx"}}}"#;
        let error = parse_json_snippet(malformed, "").unwrap_err();
        assert!(error.contains("fs"), "got: {error}");
        assert!(error.contains("array of strings"), "got: {error}");
    }

    #[test]
    fn crush_json_round_trips_without_wiping_app_settings() {
        let path = temp_path("crush-json");
        std::fs::write(&path, r#"{"theme":"dark","mcp":{"old":{"command":"x"}}}"#).unwrap();
        write_crush_json(&path, &[stdio("fresh")]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&content).unwrap();
        let parsed = parse_json(&content, "mcp").unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(root.get("theme").and_then(|v| v.as_str()), Some("dark"));
        assert_eq!(
            root.pointer("/mcp/fresh/type").and_then(|v| v.as_str()),
            Some("stdio")
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "fresh");
    }

    #[test]
    fn crush_gateway_install_includes_required_type() {
        let path = temp_path("crush-gateway");
        std::fs::write(&path, r#"{"theme":"dark","mcp":{}}"#).unwrap();
        let entry = sample_gateway(None, "crush");

        edit_crush_gateway(&path, Some(&entry)).unwrap();

        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(
            root.get("theme").and_then(|value| value.as_str()),
            Some("dark")
        );
        assert_eq!(
            root["mcp"][GATEWAY_ENTRY_NAME]["type"].as_str(),
            Some("stdio")
        );
    }

    #[test]
    fn crush_mutations_reject_unexpected_shapes_without_changing_the_file() {
        let path = temp_path("crush-invalid-shape");
        let gateway = sample_gateway(None, "crush");

        for original in [r#"["valid","state"]"#, r#"{"theme":"dark","mcp":[]}"#] {
            std::fs::write(&path, original).unwrap();
            assert!(write_crush_json(&path, &[stdio("fresh")]).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

            std::fs::write(&path, original).unwrap();
            assert!(edit_crush_gateway(&path, Some(&gateway)).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

            std::fs::write(&path, original).unwrap();
            assert!(edit_crush_gateway(&path, None).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }

        std::fs::remove_file(&path).ok();
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

        {
            let _e = sample_gateway(Some("Billing"), "claude-code");
            edit_json_gateway(&path, "mcpServers", Some(&_e), false)
        }
        .unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(servers.contains_key("existing"));
        // Discovery mode comes from the registry, not the client config; only the
        // profile scope is written as an env var.
        assert_eq!(
            servers[GATEWAY_ENTRY_NAME]["env"][crate::brand::PROFILE],
            "Billing"
        );
        assert!(servers[GATEWAY_ENTRY_NAME]["env"]
            .get("CONDUIT_DISCOVERY")
            .is_none());
        // Unrelated key and the existing server's secret value are untouched.
        assert_eq!(root["theme"], "dark");
        assert_eq!(servers["existing"]["env"]["SECRET"], "keepme");

        edit_json_gateway(&path, "mcpServers", None, false).unwrap();
        let root2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = root2["mcpServers"].as_object().unwrap();
        assert!(!servers2.contains_key(GATEWAY_ENTRY_NAME));
        assert!(servers2.contains_key("existing"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn droid_install_preserves_existing_factory_server() {
        let path = temp_path("droid-install-json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"],"env":{"HOME":"/home/user"}}}}"#,
        )
        .unwrap();

        // Install: gateway entry added, existing Factory server untouched.
        {
            let entry = sample_gateway(Some("Work"), "droid");
            edit_droid_json_gateway(&path, Some(&entry))
        }
        .unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(servers.contains_key("filesystem"));
        assert_eq!(
            servers["filesystem"]["env"]["HOME"],
            "/home/user"
        );
        assert_eq!(
            servers[GATEWAY_ENTRY_NAME]["env"][crate::brand::PROFILE],
            "Work"
        );

        // Uninstall: gateway entry removed, existing Factory server still untouched.
        edit_droid_json_gateway(&path, None).unwrap();
        let root2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = root2["mcpServers"].as_object().unwrap();
        assert!(!servers2.contains_key(GATEWAY_ENTRY_NAME));
        assert!(servers2.contains_key("filesystem"));
        assert_eq!(
            servers2["filesystem"]["args"],
            serde_json::json!(["-y", "@modelcontextprotocol/server-filesystem"])
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn droid_gateway_install_includes_required_type() {
        let path = temp_path("droid-gateway");
        std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();
        let entry = sample_gateway(None, "droid");
        edit_droid_json_gateway(&path, Some(&entry)).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            root["mcpServers"][GATEWAY_ENTRY_NAME]["type"].as_str(),
            Some("stdio")
        );
        edit_droid_json_gateway(&path, None).unwrap();
        let root2: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(!root2["mcpServers"]
            .as_object()
            .unwrap()
            .contains_key(GATEWAY_ENTRY_NAME));
    }

    #[test]
    fn shared_http_bridge_entry_for_claude_desktop() {
        // Claude Desktop has no native remote MCP shape; Shared HTTP writes mcp-remote.
        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "secrettok".into(),
        };
        let entry = gateway_entry_shared_http("claude-desktop", None, &spec);
        assert_eq!(entry.command.as_deref(), Some("npx"));
        assert!(entry.args.iter().any(|a| a == "mcp-remote"));
        assert!(entry.args.iter().any(|a| a.contains("8765/mcp")));
        assert!(entry
            .args
            .iter()
            .any(|a| a.contains("Authorization: Bearer secrettok")));
        // Ownership record must not retain the bearer.
        let rec = ManagedEntry::from_gateway_entry(&entry);
        assert_eq!(rec.transport, "sharedHttp");
        assert_eq!(rec.url.as_deref(), Some("http://127.0.0.1:8765/mcp"));
        assert!(!rec.args.iter().any(|a| a.contains("Bearer")));
        assert!(client_uses_mcp_remote_bridge("claude-desktop"));
        assert!(client_uses_mcp_remote_bridge("amp"));
        assert!(!client_uses_mcp_remote_bridge("opencode"));
        assert!(!client_uses_mcp_remote_bridge("vscode"));
        assert!(!client_uses_mcp_remote_bridge("github-copilot-cli"));
    }

    #[test]
    fn github_copilot_cli_shared_http_entry_uses_native_schema() {
        let path = temp_path("github-copilot-cli-http.json");
        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "tok".into(),
        };
        let entry = gateway_entry_shared_http("github-copilot-cli", None, &spec);

        edit_copilot_json_gateway(&path, Some(&entry)).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let gateway = &root["mcpServers"][GATEWAY_ENTRY_NAME];
        assert_eq!(gateway["type"], "http");
        assert_eq!(gateway["url"], "http://127.0.0.1:8765/mcp");
        assert_eq!(gateway["tools"], serde_json::json!(["*"]));
        assert_eq!(gateway["headers"]["Authorization"], "Bearer tok");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn shared_http_native_entry_for_opencode() {
        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "tok".into(),
        };
        let entry = gateway_entry_shared_http("opencode", Some("Work"), &spec);
        assert!(entry.command.is_none());
        assert_eq!(entry.url.as_deref(), Some("http://127.0.0.1:8765/mcp"));
        assert_eq!(entry.transport, "http");
        assert!(entry
            .env
            .iter()
            .any(|e| e.key == "Authorization" && e.value.as_deref() == Some("Bearer tok")));
        let rec = ManagedEntry::from_gateway_entry(&entry);
        assert!(!rec.env.contains_key("Authorization"));
        assert_eq!(rec.transport, "sharedHttp");
    }

    /// WS3-1 / WS3-3: write Shared HTTP to a real config file, re-detect, assert
    /// the bearer reaches a field that is sent (env/headers), across native formats.
    #[test]
    fn shared_http_write_redetect_preserves_token_keys_across_formats() {
        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "roundtrip-secret".into(),
        };
        let auth = "Bearer roundtrip-secret";

        // Continue (YamlMcpServersList): remote bearer under requestOptions.headers
        // (Continue's wire contract), not env (WS3-1).
        {
            let path = temp_path("ws3-continue.yaml");
            std::fs::write(&path, "name: Test\nmcpServers: []\n").unwrap();
            let entry = gateway_entry_shared_http("continue", Some("Work"), &spec);
            edit_continue_yaml_gateway(&path, Some(&entry)).unwrap();
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(
                content.contains(auth),
                "Continue config must contain the bearer: {content}"
            );
            let root: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
            let slot = root
                .get("mcpServers")
                .and_then(|v| v.as_sequence())
                .and_then(|seq| {
                    seq.iter().find(|s| {
                        s.get("name").and_then(|n| n.as_str()) == Some(GATEWAY_ENTRY_NAME)
                    })
                })
                .expect("gateway entry in yaml");
            assert_eq!(
                slot.get("requestOptions")
                    .and_then(|ro| ro.get("headers"))
                    .and_then(|h| h.get("Authorization"))
                    .and_then(|v| v.as_str()),
                Some(auth),
                "Continue remote must put Authorization under requestOptions.headers: {content}"
            );
            assert!(
                slot.get("env").is_none(),
                "Continue remote must not put the bearer under env: {content}"
            );
            let parsed = parse_continue_yaml_servers(&content).unwrap();
            let gw = parsed
                .iter()
                .find(|s| s.name == GATEWAY_ENTRY_NAME)
                .expect("gateway entry");
            assert_eq!(gw.url.as_deref(), Some(spec.url.as_str()));
            assert!(
                gw.env_keys.iter().any(|k| k == "Authorization"),
                "re-detect must see Authorization key: {:?}",
                gw.env_keys
            );
            let rec = ManagedEntry::from_gateway_entry(&entry);
            assert_eq!(
                resolve_entry_state(&[gw.clone()], Some(&rec)),
                GatewayEntryState::Managed
            );
            std::fs::remove_file(&path).ok();
        }

        // VS Code (JsonServers): headers, not env (WS3-3).
        {
            let path = temp_path("ws3-vscode.json");
            std::fs::write(&path, r#"{"servers":{}}"#).unwrap();
            let entry = gateway_entry_shared_http("vscode", None, &spec);
            edit_json_gateway(&path, "servers", Some(&entry), false).unwrap();
            let root: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let slot = &root["servers"][GATEWAY_ENTRY_NAME];
            assert_eq!(slot["url"], spec.url);
            assert_eq!(slot["headers"]["Authorization"], auth);
            assert!(
                slot.get("env").is_none(),
                "VS Code must not put the bearer under env: {slot}"
            );
            let parsed = parse_json(&std::fs::read_to_string(&path).unwrap(), "servers").unwrap();
            let gw = parsed
                .iter()
                .find(|s| s.name == GATEWAY_ENTRY_NAME)
                .expect("gateway");
            assert!(gw.env_keys.iter().any(|k| k == "Authorization"));
            std::fs::remove_file(&path).ok();
        }

        // Hermes (YamlMcpServers): headers for remote (WS3-3).
        {
            let path = temp_path("ws3-hermes.yaml");
            std::fs::write(&path, "mcp_servers: {}\n").unwrap();
            let entry = gateway_entry_shared_http("hermes", None, &spec);
            edit_hermes_yaml_gateway(&path, Some(&entry)).unwrap();
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(
                content.contains(auth),
                "Hermes must contain bearer: {content}"
            );
            assert!(
                content.contains("headers:"),
                "Hermes remote auth under headers: {content}"
            );
            let parsed = parse_hermes_yaml_servers(&content).unwrap();
            let gw = parsed
                .iter()
                .find(|s| s.name == GATEWAY_ENTRY_NAME)
                .expect("gateway");
            assert!(gw.env_keys.iter().any(|k| k == "Authorization"));
            std::fs::remove_file(&path).ok();
        }

        // OpenCode: headers on remote type.
        {
            let path = temp_path("ws3-opencode.json");
            std::fs::write(&path, r#"{"mcp":{}}"#).unwrap();
            let entry = gateway_entry_shared_http("opencode", Some("Work"), &spec);
            edit_opencode_gateway(&path, Some(&entry)).unwrap();
            let root: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let slot = &root["mcp"][GATEWAY_ENTRY_NAME];
            assert_eq!(slot["type"], "remote");
            assert_eq!(slot["headers"]["Authorization"], auth);
            std::fs::remove_file(&path).ok();
        }

        // Qwen: httpUrl + headers.
        {
            let path = temp_path("ws3-qwen.json");
            std::fs::write(&path, r#"{"mcpServers":{}}"#).unwrap();
            let entry = gateway_entry_shared_http("qwen-code", None, &spec);
            edit_json_gateway(&path, "mcpServers", Some(&entry), true).unwrap();
            let root: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let slot = &root["mcpServers"][GATEWAY_ENTRY_NAME];
            assert_eq!(slot["httpUrl"], spec.url);
            assert_eq!(slot["headers"]["Authorization"], auth);
            assert!(slot.get("env").is_none());
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn entry_state_from_record_and_heuristic() {
        // SOU-406: ownership record when present; SOU-405 basename heuristic when not.
        let managed_cmd = r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.9.5.exe";
        let rec = ManagedEntry {
            command: managed_cmd.to_string(),
            args: vec![],
            env: [(crate::brand::CLIENT_ID.to_string(), "claude-desktop".into())]
                .into_iter()
                .collect(),
            transport: "stdio".into(),
            url: None,
            updated_at: 1,
        };
        let matching = McpServer {
            name: GATEWAY_ENTRY_NAME.into(),
            transport: "stdio".into(),
            command: Some(managed_cmd.into()),
            args: vec![],
            env_keys: vec![crate::brand::CLIENT_ID.to_string()],
            url: None,
        };
        assert_eq!(
            resolve_entry_state(&[matching.clone()], Some(&rec)),
            GatewayEntryState::Managed
        );

        let mut args_changed = matching.clone();
        args_changed.args = vec!["--extra".into()];
        assert_eq!(
            resolve_entry_state(&[args_changed], Some(&rec)),
            GatewayEntryState::Customized
        );

        let mut cmd_changed = matching.clone();
        cmd_changed.command = Some("npx".into());
        assert_eq!(
            resolve_entry_state(&[cmd_changed.clone()], Some(&rec)),
            GatewayEntryState::Customized
        );
        // No record + npx → Customized (heuristic).
        assert_eq!(
            resolve_entry_state(&[cmd_changed], None),
            GatewayEntryState::Customized
        );
        // No record + our binary → Managed (back-compat).
        assert_eq!(
            resolve_entry_state(&[matching], None),
            GatewayEntryState::Managed
        );
        // No identity entry → Absent.
        assert_eq!(resolve_entry_state(&[], None), GatewayEntryState::Absent);
        assert_eq!(
            resolve_entry_state(
                &[McpServer {
                    name: "other".into(),
                    transport: "stdio".into(),
                    command: Some("node".into()),
                    args: vec![],
                    env_keys: vec![],
                    url: None,
                }],
                Some(&rec)
            ),
            GatewayEntryState::Absent
        );
    }

    #[test]
    fn customized_gateway_entry_is_never_repointed() {
        // Regression for issue #487. A user repointed Claude Desktop's `toolport` entry
        // at the documented HTTP endpoint via an mcp-remote bridge; every launch of the
        // app reverted it to the default stdio command and left another backup behind.
        //
        // The entry is still ours by NAME (that's what keeps it visible and dedup'd),
        // but not by command, so the launch re-point must stand down.
        let current = r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.9.5.exe";

        // The reported command, as Claude Desktop stores it. Note it would fail every
        // staleness heuristic: `npx` is not a path that exists, and the published-bin
        // branch calls anything that isn't byte-identical to `current` stale.
        assert!(!gateway_entry_needs_rewrite(
            GATEWAY_ENTRY_NAME,
            "npx",
            current,
            Some(
                r#"{"mcpServers":{"toolport":{"command":"npx","args":["-y","mcp-remote","http://localhost:8765/mcp"]}}}"#
            )
        ));

        // Other shapes a user reasonably reaches for, all left alone.
        for command in [
            "npx",
            "cmd",
            "docker",
            "node",
            "uvx",
            r"C:\Users\me\bin\my-toolport-wrapper.cmd",
            // Lives in a dir named for the gateway, but is not the gateway. Basename
            // matching is what keeps this from being mistaken for ours.
            r"C:\tools\toolport-gateway\wrapper.exe",
            // A user-written http/sse entry has no command at all.
            "",
        ] {
            assert!(
                !gateway_entry_needs_rewrite(GATEWAY_ENTRY_NAME, command, current, None),
                "custom command {command:?} must be treated as user-managed"
            );
        }

        // The legacy-name and legacy-env branches must not sneak past the gate either:
        // a customized entry the user happened to leave named `conduit`, in a config
        // that still mentions CONDUIT_* elsewhere, is still theirs.
        assert!(!gateway_entry_needs_rewrite(
            LEGACY_GATEWAY_ENTRY_NAME,
            "npx",
            current,
            Some(r#"{"env":{"CONDUIT_CLIENT_ID":"claude-desktop"}}"#)
        ));

        // ...while real migrations still happen. These are the cases the re-point
        // exists for, and each names one of our binaries.
        for stale in [
            r"C:\Users\me\AppData\Local\Toolport\toolport-gateway.exe", // unversioned install dir
            r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.9.4.exe", // older version
            r"C:\Users\me\AppData\Roaming\Conduit\bin\toolport-gateway-1.9.5.exe", // pre-rename data dir
            "/Applications/Toolport.app/Contents/MacOS/conduit-gateway", // pre-rename binary
        ] {
            assert!(
                gateway_entry_needs_rewrite(GATEWAY_ENTRY_NAME, stale, current, None),
                "{stale:?} is one of ours and must still be re-pointed"
            );
        }
    }

    #[test]
    fn gateway_binary_provenance_matches_basename_only() {
        assert!(command_is_gateway_binary("toolport-gateway"));
        assert!(command_is_gateway_binary("conduit-gateway"));
        assert!(command_is_gateway_binary(
            r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.9.5.exe"
        ));
        // Case and quoting as they turn up in real client configs.
        assert!(command_is_gateway_binary(r#""C:\X\Toolport-Gateway.EXE""#));
        assert!(command_is_gateway_binary("/opt/toolport/toolport-gateway"));

        assert!(!command_is_gateway_binary(""));
        assert!(!command_is_gateway_binary("npx"));
        assert!(!command_is_gateway_binary("cmd"));
        // A substring match on the full path would wrongly claim these.
        assert!(!command_is_gateway_binary(
            r"C:\tools\toolport-gateway\wrapper.exe"
        ));
        assert!(!command_is_gateway_binary(
            "/usr/local/bin/my-toolport-gateway-shim"
        ));
    }

    #[test]
    fn legacy_conduit_entry_is_recognized_and_migrated() {
        // The pre-SOU-318 name must stay recognized as our own gateway, so detection,
        // dedup, and the launch migration all still see a pre-rename entry.
        assert!(gateway_identity_matches(
            LEGACY_GATEWAY_ENTRY_NAME,
            LEGACY_GATEWAY_ENTRY_NAME,
            None
        ));
        assert!(is_gateway_server(&stdio(LEGACY_GATEWAY_ENTRY_NAME)));

        // repoint rewrites a legacy-named entry even when its command is already
        // current (that's the rename), but leaves a current-named, current-path entry
        // untouched (idempotent no-op after the first launch).
        let current = "/opt/toolport/toolport-gateway";
        assert!(gateway_entry_needs_rewrite(
            LEGACY_GATEWAY_ENTRY_NAME,
            current,
            current,
            None
        ));
        assert!(!gateway_entry_needs_rewrite(
            GATEWAY_ENTRY_NAME,
            current,
            current,
            None
        ));
        // Current name + path, but still only CONDUIT_* env keys → rewrite.
        assert!(gateway_entry_needs_rewrite(
            GATEWAY_ENTRY_NAME,
            current,
            current,
            Some(r#"{"env":{"CONDUIT_CLIENT_ID":"claude-code"}}"#)
        ));
        // Already on TOOLPORT_* → leave alone.
        assert!(!gateway_entry_needs_rewrite(
            GATEWAY_ENTRY_NAME,
            current,
            current,
            Some(r#"{"env":{"TOOLPORT_CLIENT_ID":"claude-code"}}"#)
        ));

        // Installing over a config whose only gateway entry is the legacy name renames
        // it in place: the entry is retained-out by identity and re-inserted under the
        // current name, so there's exactly one gateway entry and both the unrelated
        // server and the profile scope survive.
        let path = temp_path("migrate-legacy-json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"conduit":{"command":"toolport-gateway","env":{"CONDUIT_CLIENT_ID":"claude-code","CONDUIT_PROFILE":"Billing"}},"existing":{"command":"node"}}}"#,
        )
        .unwrap();
        {
            let _e = sample_gateway(Some("Billing"), "claude-code");
            edit_json_gateway(&path, "mcpServers", Some(&_e), false)
        }
        .unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(!servers.contains_key(LEGACY_GATEWAY_ENTRY_NAME));
        assert!(servers.contains_key("existing"));
        assert_eq!(
            servers[GATEWAY_ENTRY_NAME]["env"][crate::brand::PROFILE],
            "Billing"
        );
        // Legacy env keys are not re-written on migrate; new installs use TOOLPORT_*.
        assert!(servers[GATEWAY_ENTRY_NAME]["env"]
            .get(crate::brand::PROFILE_LEGACY)
            .is_none());
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
        {
            let _e = sample_gateway(None, "claude-code");
            edit_json_gateway(&json_path, "mcpServers", Some(&_e), false)
        }
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let json_servers = json["mcpServers"].as_object().unwrap();
        assert_eq!(json_servers.len(), 2);
        assert!(json_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(json_servers.contains_key("existing"));
        assert_eq!(
            json_servers[GATEWAY_ENTRY_NAME]["env"][crate::brand::CLIENT_ID],
            "claude-code"
        );
        edit_json_gateway(&json_path, "mcpServers", None, false).unwrap();
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
        {
            let _e = sample_gateway(None, "codex");
            edit_toml_gateway(&toml_path, Some(&_e))
        }
        .unwrap();
        let toml: toml::Value =
            toml::from_str(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
        let toml_servers = toml["mcp_servers"].as_table().unwrap();
        assert_eq!(toml_servers.len(), 2);
        assert!(toml_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(toml_servers.contains_key("existing"));
        edit_toml_gateway(&toml_path, None).unwrap();
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
        {
            let _e = sample_gateway(None, "goose");
            edit_yaml_gateway(&goose_path, Some(&_e))
        }
        .unwrap();
        let goose: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&goose_path).unwrap()).unwrap();
        let goose_servers = goose["extensions"].as_mapping().unwrap();
        assert_eq!(goose_servers.len(), 2);
        assert!(goose_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(goose_servers.contains_key("fetch"));
        edit_yaml_gateway(&goose_path, None).unwrap();
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
        {
            let _e = sample_gateway(None, "hermes");
            edit_hermes_yaml_gateway(&hermes_path, Some(&_e))
        }
        .unwrap();
        let hermes: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&hermes_path).unwrap()).unwrap();
        let hermes_servers = hermes["mcp_servers"].as_mapping().unwrap();
        assert_eq!(hermes_servers.len(), 2);
        assert!(hermes_servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(hermes_servers.contains_key("fetch"));
        edit_hermes_yaml_gateway(&hermes_path, None).unwrap();
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
        {
            let _e = sample_gateway(None, "continue");
            edit_continue_yaml_gateway(&continue_path, Some(&_e))
        }
        .unwrap();
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
        edit_continue_yaml_gateway(&continue_path, None).unwrap();
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
        // A scoped install must carry TOOLPORT_CLIENT_ID alongside TOOLPORT_PROFILE,
        // so the running gateway can re-resolve this client's profile live from
        // registry.client_scopes instead of trusting a frozen env var forever.
        let entry = gateway_entry(Some("Billing"), "cursor").unwrap();
        let env: std::collections::HashMap<_, _> = entry
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        assert_eq!(
            env.get(crate::brand::PROFILE).unwrap().as_deref(),
            Some("Billing")
        );
        assert_eq!(
            env.get(crate::brand::CLIENT_ID).unwrap().as_deref(),
            Some("cursor")
        );

        // Unscoped installs still carry TOOLPORT_CLIENT_ID (so the client can be
        // re-scoped to a named profile live later, without a restart) but omit
        // TOOLPORT_PROFILE - the gateway resolves the active profile live for them.
        let unscoped = gateway_entry(None, "cursor").unwrap();
        let uenv: std::collections::HashMap<_, _> = unscoped
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        assert_eq!(
            uenv.get(crate::brand::CLIENT_ID).unwrap().as_deref(),
            Some("cursor")
        );
        assert!(uenv.get(crate::brand::PROFILE).is_none());
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
        assert!(install_override("junie").unwrap().ends_with(".junie"));
        let _ = install_override("warp"); // env-dependent; just ensure no panic.
        assert!(
            install_override("toolport-studio").is_some(),
            "Toolport Studio must always override the home-parent heuristic"
        );
        // Well-behaved clients have no override (they use the config-parent heuristic).
        assert!(install_override("cursor").is_none());
        assert!(install_override("codex").is_none());
        assert!(install_override("vscode").is_none());
    }

    #[test]
    fn junie_install_marker_controls_detection_without_config() {
        let marker = std::env::temp_dir().join(format!(
            "toolport-junie-marker-{}",
            std::process::id()
        ));
        std::fs::remove_dir_all(&marker).ok();
        let config = marker.join("mcp").join("mcp.json");

        assert!(!app_present_with_override(
            &config.to_string_lossy(),
            false,
            Some(&marker)
        ));

        std::fs::create_dir_all(&marker).unwrap();
        assert!(app_present_with_override(
            &config.to_string_lossy(),
            false,
            Some(&marker)
        ));

        std::fs::remove_dir_all(&marker).ok();
    }

    #[test]
    fn toolport_studio_is_registered_with_session_client_id() {
        let d = defs()
            .into_iter()
            .find(|d| d.id == "toolport-studio")
            .expect("toolport-studio client");
        assert_eq!(d.name, "Toolport Studio");
        assert!(matches!(d.format, Format::JsonMcpServers));
        assert!(!d.uses_connectors);
        assert!((d.path)().is_some());
        // Identity must match Studio's McpProviderSession TOOLPORT_CLIENT_ID.
        assert_eq!(d.id, "toolport-studio");
    }

    #[test]
    fn toolport_studio_config_path_is_under_home_state_dir() {
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let path = resolve_client_config_path("toolport-studio", &home, platform)
                .expect("toolport-studio path");
            assert_eq!(
                path,
                home.join(".toolport-studio").join("mcp.json"),
                "toolport-studio on {platform:?}"
            );
        }
    }

    #[test]
    fn toolport_studio_gateway_round_trip() {
        let dir =
            std::env::temp_dir().join(format!("toolport-studio-client-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mcp.json");

        // Install writes mcpServers.toolport with TOOLPORT_CLIENT_ID=toolport-studio.
        {
            let _e = sample_gateway(Some("Work"), "toolport-studio");
            edit_json_gateway(&path, "mcpServers", Some(&_e), false)
        }
        .unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let entry = &root["mcpServers"][GATEWAY_ENTRY_NAME];
        assert!(entry["command"].as_str().is_some());
        let env = entry["env"].as_object().expect("env object");
        assert_eq!(
            env.get(crate::brand::CLIENT_ID).and_then(|v| v.as_str()),
            Some("toolport-studio")
        );
        assert_eq!(
            env.get(crate::brand::PROFILE).and_then(|v| v.as_str()),
            Some("Work")
        );

        // Uninstall removes the gateway entry and leaves an empty mcpServers map.
        edit_json_gateway(&path, "mcpServers", None, false).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(!servers.contains_key(GATEWAY_ENTRY_NAME));
        assert!(!servers.contains_key(LEGACY_GATEWAY_ENTRY_NAME));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zed_context_servers_jsonc_round_trip() {
        let path = std::env::temp_dir().join(format!("conduit-zed-{}.json", std::process::id()));
        // JSONC: line comment, trailing comma, an unrelated user setting.
        std::fs::write(
            &path,
            "// my zed settings\n{\n  \"ui_font_size\": 16, // keep font note\n  \"context_servers\": {\n    \"existing\": { \"command\": \"x\", \"args\": [] },\n  },\n}\n",
        )
        .unwrap();

        // Parsing tolerates the comments/trailing commas.
        let parsed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "context_servers").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "existing");

        // Installing preserves the unrelated key, the existing server, and comments.
        {
            let _e = sample_gateway(None, "zed");
            edit_json_gateway(&path, "context_servers", Some(&_e), true)
        }
        .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("// my zed settings"),
            "file-level comment must survive install: {content}"
        );
        assert!(
            content.contains("// keep font note"),
            "inline comment on an unrelated key must survive: {content}"
        );
        let root = parse_json_value(&content).unwrap();
        assert_eq!(root["ui_font_size"], 16);
        let cs = root["context_servers"].as_object().unwrap();
        assert!(cs.contains_key(GATEWAY_ENTRY_NAME));
        assert!(cs.contains_key("existing"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn vscode_mcp_json_jsonc_preserves_comments_on_write() {
        // VS Code's mcp.json is JSONC; writing servers must not strip user comments (#555).
        let path = temp_path("vscode-mcp-jsonc");
        std::fs::write(
            &path,
            r#"// VS Code MCP servers
{
  // prefer the local catalog
  "servers": {
    "existing": { "command": "npx", "args": ["-y", "x"] },
  },
}
"#,
        )
        .unwrap();

        write_json(
            &path,
            "servers",
            &[stdio("filesystem"), stdio("github")],
            false,
        )
        .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("// VS Code MCP servers"),
            "top comment must survive write_json: {content}"
        );
        assert!(
            content.contains("// prefer the local catalog"),
            "comment above servers must survive: {content}"
        );
        let parsed = parse_json(&content, "servers").unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "filesystem");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn lenient_edit_never_wipes_unparseable_config() {
        let path = std::env::temp_dir().join(format!("conduit-bad-{}.json", std::process::id()));
        let garbage = "this is not json or json5 at all {{{";
        std::fs::write(&path, garbage).unwrap();
        // A lenient edit must ERROR, never replace the file with an empty object.
        assert!({
            let _e = sample_gateway(None, "zed");
            edit_json_gateway(&path, "context_servers", Some(&_e), true)
        }
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn whole_app_state_clients_are_lenient() {
        // These files hold the client's entire state, so an unparseable file must
        // never be wiped.
        assert!(config_is_whole_app_state("claude-code"));
        assert!(config_is_whole_app_state("gemini-cli"));
        assert!(config_is_whole_app_state("qwen-code"));
        assert!(config_is_whole_app_state("opencode"));
        assert!(config_is_whole_app_state("kilo-code"));
        // Single-purpose mcpServers files keep the start-fresh behavior.
        assert!(!config_is_whole_app_state("claude-desktop"));
        assert!(!config_is_whole_app_state("vscode"));
        assert!(!config_is_whole_app_state("lm-studio"));

        // A whole-app-state client with a genuinely-broken config errors (leaving the
        // file intact) instead of replacing it with just the gateway entry.
        let path = std::env::temp_dir().join(format!("conduit-claude-{}.json", std::process::id()));
        let garbage = "{ \"projects\": {}, \"oauthAccount\": broken not json";
        std::fs::write(&path, garbage).unwrap();
        assert!({
            let _e = sample_gateway(None, "claude-code");
            edit_json_gateway(&path, "mcpServers", Some(&_e), true)
        }
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn qwen_round_trip_preserves_settings_and_remote_transports() {
        let path = temp_path("qwen.json");
        std::fs::write(
            &path,
            r#"{
                "$version": 4,
                "model": {"name": "qwen3-coder-plus"},
                "ui": {"theme": "GitHub"},
                "mcpServers": {
                    "old": {"command": "old-command"}
                }
            }"#,
        )
        .unwrap();

        let servers = vec![
            stdio("filesystem"),
            remote("remote-http", "http"),
            remote("remote-sse", "sse"),
        ];
        write_qwen_json(&path, &servers).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(root["$version"], 4);
        assert_eq!(root["model"]["name"], "qwen3-coder-plus");
        assert_eq!(root["ui"]["theme"], "GitHub");
        assert!(root["mcpServers"].get("old").is_none());

        let http = &root["mcpServers"]["remote-http"];
        assert_eq!(http["httpUrl"], "https://remote-http.example.com/mcp");
        assert!(http.get("url").is_none());
        assert_eq!(http["headers"]["Authorization"], "Bearer fixture");
        assert!(http.get("env").is_none());

        let sse = &root["mcpServers"]["remote-sse"];
        assert_eq!(sse["url"], "https://remote-sse.example.com/mcp");
        assert!(sse.get("httpUrl").is_none());
        assert_eq!(sse["headers"]["Authorization"], "Bearer fixture");

        let parsed = parse_qwen_json(&content).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].transport, "stdio");
        assert_eq!(parsed[1].transport, "http");
        assert_eq!(parsed[2].transport, "sse");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn qwen_write_never_wipes_unparseable_settings() {
        let path = temp_path("qwen-bad.json");
        let garbage = r#"{"model":{"name":"qwen3"},"mcpServers":{broken"#;
        std::fs::write(&path, garbage).unwrap();

        assert!(write_qwen_json(&path, &[stdio("filesystem")]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn qwen_code_is_registered_with_its_native_transport_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "qwen-code")
            .unwrap();
        assert!(matches!(definition.format, Format::JsonQwenMcpServers));
        assert!((definition.path)().is_some());
    }

    #[test]
    fn grok_build_is_registered_as_toml_mcp_servers() {
        // Grok Build shares Codex's TOML `[mcp_servers.<name>]` shape, so it reuses the
        // TomlMcpServers format and just points at ~/.grok/config.toml.
        let definition = defs().into_iter().find(|d| d.id == "grok").unwrap();
        assert!(matches!(definition.format, Format::TomlMcpServers));
        assert!((definition.path)().is_some());
    }

    #[test]
    fn opencode_round_trip_preserves_other_settings() {
        let path = temp_path("opencode.json");
        std::fs::write(
            &path,
            r#"{
                "$schema": "https://opencode.ai/config.json",
                "model": "anthropic/claude-sonnet-4-5",
                "mcp": {
                    "existing": {
                        "type": "local",
                        "command": ["node", "server.mjs"],
                        "environment": {"SECRET": "keep-me"},
                        "enabled": false
                    }
                }
            }"#,
        )
        .unwrap();

        {
            let _e = sample_gateway(Some("Work"), "opencode");
            edit_opencode_gateway(&path, Some(&_e))
        }
        .unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            root.get("$schema").and_then(|value| value.as_str()),
            Some("https://opencode.ai/config.json")
        );
        assert_eq!(
            root.get("model").and_then(|value| value.as_str()),
            Some("anthropic/claude-sonnet-4-5")
        );
        let mcp = root.get("mcp").and_then(|value| value.as_object()).unwrap();
        assert_eq!(
            mcp["existing"]["environment"]["SECRET"],
            serde_json::Value::String("keep-me".into())
        );
        assert_eq!(mcp["existing"]["enabled"], false);
        assert_eq!(mcp[GATEWAY_ENTRY_NAME]["type"], "local");
        assert_eq!(mcp[GATEWAY_ENTRY_NAME]["enabled"], true);
        let command = mcp[GATEWAY_ENTRY_NAME]["command"].as_array().unwrap();
        assert_eq!(command.len(), 1);
        assert!(command[0].as_str().unwrap().contains("toolport-gateway"));
        assert_eq!(
            mcp[GATEWAY_ENTRY_NAME]["environment"][crate::brand::CLIENT_ID],
            "opencode"
        );
        assert_eq!(
            mcp[GATEWAY_ENTRY_NAME]["environment"][crate::brand::PROFILE],
            "Work"
        );

        edit_opencode_gateway(&path, None).unwrap();
        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(after["mcp"].get(GATEWAY_ENTRY_NAME).is_none());
        assert!(after["mcp"].get("existing").is_some());
        assert_eq!(after["model"], "anthropic/claude-sonnet-4-5");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn opencode_write_servers_round_trips_local_and_remote() {
        let path = temp_path("opencode-write.json");
        std::fs::write(
            &path,
            r#"{
                "model": "anthropic/claude-sonnet-4-5",
                "mcp": {
                    "inherited-toggle": {
                        "enabled": false
                    },
                    "stale-server": {
                        "type": "local",
                        "command": ["node", "stale.mjs"],
                        "enabled": true
                    }
                }
            }"#,
        )
        .unwrap();
        let mut remote = stdio("remote");
        remote.transport = "http".into();
        remote.command = None;
        remote.args.clear();
        remote.url = Some("https://mcp.example.com/mcp".into());

        write_opencode_json(&path, &[stdio("filesystem"), remote]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let root: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(root["model"], "anthropic/claude-sonnet-4-5");
        assert_eq!(root["mcp"]["inherited-toggle"]["enabled"], false);
        assert!(root["mcp"].get("stale-server").is_none());
        let parsed = parse_opencode_json(&content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(parsed[1].transport, "http");
        assert_eq!(
            parsed[1].url.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn opencode_edit_never_wipes_unparseable_config() {
        let path = temp_path("opencode-bad.json");
        let garbage = r#"{"model":"keep-me","mcp":{"broken": not-json"#;
        std::fs::write(&path, garbage).unwrap();
        assert!({
            let _e = sample_gateway(None, "opencode");
            edit_opencode_gateway(&path, Some(&_e))
        }
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);

        let wrong_shape = r#"{"model":"keep-me","mcp":"not-an-object"}"#;
        std::fs::write(&path, wrong_shape).unwrap();
        assert!({
            let _e = sample_gateway(None, "opencode");
            edit_opencode_gateway(&path, Some(&_e))
        }
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), wrong_shape);
        assert!(write_opencode_json(&path, &[stdio("filesystem")]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), wrong_shape);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn opencode_is_registered_with_its_native_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "opencode")
            .unwrap();
        assert!(matches!(definition.format, Format::JsonOpenCodeMcp));
        assert!((definition.path)().is_some());
    }

    #[test]
    fn kilo_code_jsonc_round_trip_preserves_other_settings() {
        let path = temp_path("kilo.jsonc");
        std::fs::write(
            &path,
            r#"// Kilo settings
            {
                "$schema": "https://app.kilo.ai/config.json",
                // preferred model for day-to-day work
                "model": "anthropic/claude-sonnet-4-5",
                "mcp": {
                    "existing": {
                        "type": "local",
                        "command": ["node", "server.mjs"],
                        "environment": {"SECRET": "keep-me"},
                        "enabled": false,
                    },
                },
            }"#,
        )
        .unwrap();

        let parsed = parse_opencode_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "existing");
        assert_eq!(parsed[0].command.as_deref(), Some("node"));

        {
            let entry = sample_gateway(Some("Work"), "kilo-code");
            edit_opencode_gateway(&path, Some(&entry))
        }
        .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("// Kilo settings"),
            "file-level comment must survive gateway install: {content}"
        );
        assert!(
            content.contains("// preferred model for day-to-day work"),
            "comment on unrelated key must survive: {content}"
        );
        // Still JSONC after write — parse with the lenient path, not strict serde_json.
        let root = parse_json_value(&content).unwrap();
        assert_eq!(
            root.get("$schema").and_then(|value| value.as_str()),
            Some("https://app.kilo.ai/config.json")
        );
        assert_eq!(root["model"], "anthropic/claude-sonnet-4-5");
        assert_eq!(root["mcp"]["existing"]["environment"]["SECRET"], "keep-me");
        assert_eq!(
            root["mcp"][GATEWAY_ENTRY_NAME]["environment"][crate::brand::CLIENT_ID],
            "kilo-code"
        );
        assert_eq!(
            root["mcp"][GATEWAY_ENTRY_NAME]["environment"][crate::brand::PROFILE],
            "Work"
        );

        edit_opencode_gateway(&path, None).unwrap();
        let after_content = std::fs::read_to_string(&path).unwrap();
        assert!(
            after_content.contains("// Kilo settings"),
            "comments must also survive uninstall: {after_content}"
        );
        let after = parse_json_value(&after_content).unwrap();
        assert!(after["mcp"].get(GATEWAY_ENTRY_NAME).is_none());
        assert!(after["mcp"].get("existing").is_some());
        assert_eq!(after["model"], "anthropic/claude-sonnet-4-5");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rewrite_json_key_preserving_keeps_unrelated_text() {
        let original = r#"// header
{
  "ui_font_size": 16, // note
  "context_servers": {
    "old": { "command": "x" },
  },
}
"#;
        let new_servers = serde_json::json!({
            "old": { "command": "x" },
            "Toolport": { "command": "toolport-gateway", "args": [] }
        });
        let rewritten =
            rewrite_json_key_preserving(original, "context_servers", &new_servers).unwrap();
        assert!(rewritten.contains("// header"));
        assert!(rewritten.contains("// note"));
        assert!(rewritten.contains("\"Toolport\""));
        assert!(rewritten.contains("\"ui_font_size\""));
        let root = parse_json_value(&rewritten).unwrap();
        assert_eq!(root["ui_font_size"], 16);
        assert!(root["context_servers"].get("Toolport").is_some());
    }

    #[test]
    fn atomic_write_json_config_rejects_duplicate_top_level_keys() {
        // Duplicate top-level mcpServers: rewriting only the first would leave a stale second.
        let path = temp_path("dup-mcpServers.json");
        let original = r#"{
  // keep me
  "mcpServers": { "a": { "command": "old-a" } },
  "other": 1,
  "mcpServers": { "b": { "command": "old-b" } }
}
"#;
        std::fs::write(&path, original).unwrap();
        let root = serde_json::json!({
            "mcpServers": { "Toolport": { "command": "toolport-gateway" } },
            "other": 1
        });
        let err = atomic_write_json_config(&path, Some(original), &root, "mcpServers").unwrap_err();
        assert!(
            err.contains("malformed") && err.contains("mcpServers"),
            "expected malformed duplicate-key error, got: {err}"
        );
        // File must stay unchanged (no pretty-JSON fallback).
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rewrite_json_key_preserving_rejects_duplicate_top_level_keys() {
        let original = r#"{
  "context_servers": { "a": {} },
  "context_servers": { "b": {} }
}"#;
        let err = rewrite_json_key_preserving(
            original,
            "context_servers",
            &serde_json::json!({ "Toolport": {} }),
        )
        .unwrap_err();
        assert!(err.contains("appears") && err.contains("2"), "got: {err}");
    }

    #[test]
    fn kilo_code_edit_never_wipes_unparseable_config() {
        let path = temp_path("kilo-bad.jsonc");
        let garbage = r#"{"model":"keep-me","mcp":{"broken": not-json"#;
        std::fs::write(&path, garbage).unwrap();

        assert!({
            let entry = sample_gateway(None, "kilo-code");
            edit_opencode_gateway(&path, Some(&entry))
        }
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn kilo_code_is_registered_with_the_shared_opencode_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "kilo-code")
            .unwrap();
        assert_eq!(definition.name, "Kilo Code");
        assert!(matches!(definition.format, Format::JsonOpenCodeMcp));
        assert!((definition.path)().is_some());
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
        assert!({
            let _e = sample_gateway(None, "claude-desktop");
            edit_json_gateway(&path, "mcpServers", Some(&_e), false)
        }
        .is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            garbage,
            "unparseable file left untouched"
        );
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
        assert!({
            let _e = sample_gateway(None, "codex");
            edit_toml_gateway(&path, Some(&_e))
        }
        .is_err());
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
        {
            let _e = sample_gateway(None, "codex");
            edit_toml_gateway(&path, Some(&_e))
        }
        .unwrap();
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
    fn crush_is_registered_as_mcp_json() {
        let d = defs().into_iter().find(|d| d.id == "crush").unwrap();
        assert!(matches!(d.format, Format::JsonMcp));
        assert!((d.path)().is_some());
        assert!(config_is_whole_app_state("crush"));
        assert_eq!(
            crush_override_path(Some(std::ffi::OsString::from("custom-config"))),
            Some(PathBuf::from("custom-config").join("crush.json"))
        );
        let home = Path::new("mock-home");
        assert_eq!(
            resolve_crush_path(home, None, None),
            home.join(".config").join("crush").join("crush.json")
        );
        assert_eq!(
            resolve_crush_path(
                home,
                None,
                Some(std::ffi::OsString::from("xdg-config")),
            ),
            PathBuf::from("xdg-config").join("crush").join("crush.json")
        );
        assert_eq!(
            resolve_crush_path(
                home,
                Some(std::ffi::OsString::from("custom-config")),
                Some(std::ffi::OsString::from("xdg-config")),
            ),
            PathBuf::from("custom-config").join("crush.json")
        );
    }

    #[test]
    fn new_json_clients_are_registered() {
        // These clients all use the standard mcpServers JSON shape, so a ClientDef
        // plus a path is all they need. Lock in their registration, format, and
        // that their config paths resolve on this OS.
        for id in [
            "warp",
            "amazon-q",
            "kiro",
            "lm-studio",
            "jan",
            "anythingllm",
            "witsy",
            "junie",
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
    fn github_copilot_cli_is_registered_with_required_tools_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "github-copilot-cli")
            .unwrap();
        assert_eq!(definition.name, "GitHub Copilot CLI");
        assert!(matches!(
            definition.format,
            Format::JsonCopilotMcpServers
        ));
        assert!((definition.path)().is_some());
    }

    #[test]
    fn github_copilot_cli_mcp_config_round_trips() {
        let path = temp_path("github-copilot-cli-mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"existing":{"command":"node","args":["server.js"],"env":{"TOKEN":"keep"}}}}"#,
        )
        .unwrap();

        let original: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let original_existing = original["mcpServers"]["existing"].clone();

        let before = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].name, "existing");

        {
            let gateway = sample_gateway(None, "github-copilot-cli");
            edit_copilot_json_gateway(&path, Some(&gateway))
        }
        .unwrap();
        let installed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(installed.len(), 2);
        assert!(installed.iter().any(|server| server.name == "existing"));
        assert!(installed
            .iter()
            .any(|server| server.name == GATEWAY_ENTRY_NAME));
        let installed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            installed_json["mcpServers"]["existing"],
            original_existing
        );
        assert_eq!(
            installed_json["mcpServers"][GATEWAY_ENTRY_NAME]["tools"],
            serde_json::json!(["*"])
        );

        edit_copilot_json_gateway(&path, None).unwrap();
        let removed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "existing");
        let removed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(removed_json["mcpServers"]["existing"], original_existing);

        write_copilot_json(&path, &[stdio("replacement")]).unwrap();
        let replaced_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            replaced_json["mcpServers"]["replacement"]["tools"],
            serde_json::json!(["*"])
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn junie_mcp_config_round_trips() {
        let path = temp_path("junie-mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"existing":{"command":"node","args":["server.js"],"env":{"TOKEN":"keep"}}}}"#,
        )
        .unwrap();

        let original: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let original_existing = original["mcpServers"]["existing"].clone();

        let before = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].name, "existing");

        { let _e = sample_gateway(None, "junie"); edit_json_gateway(&path, "mcpServers", Some(&_e), false) }
            .unwrap();
        let installed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(installed.len(), 2);
        assert!(installed.iter().any(|server| server.name == "existing"));
        assert!(installed
            .iter()
            .any(|server| server.name == GATEWAY_ENTRY_NAME));
        let installed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            installed_json["mcpServers"]["existing"],
            original_existing
        );

        edit_json_gateway(&path, "mcpServers", None, false).unwrap();
        let removed =
            parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "existing");
        let removed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(removed_json["mcpServers"]["existing"], original_existing);
        std::fs::remove_file(&path).ok();
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
        {
            let _e = sample_gateway(None, "goose");
            edit_yaml_gateway(&path, Some(&_e))
        }
        .unwrap();
        let v: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            v.get("GOOSE_MODEL").and_then(|x| x.as_str()),
            Some("gpt-4o")
        );
        let exts = v.get("extensions").and_then(|x| x.as_mapping()).unwrap();
        assert!(exts.get("fetch").is_some());
        let gateway = exts
            .get(GATEWAY_ENTRY_NAME)
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert_eq!(gateway.get("type").and_then(|x| x.as_str()), Some("stdio"));
        assert_eq!(gateway.get("enabled").and_then(|x| x.as_bool()), Some(true));
        assert!(gateway.get("cmd").and_then(|x| x.as_str()).is_some());

        // Uninstall removes only the gateway entry.
        edit_yaml_gateway(&path, None).unwrap();
        let after: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let exts2 = after
            .get("extensions")
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert!(exts2.get(GATEWAY_ENTRY_NAME).is_none());
        assert!(exts2.get("fetch").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn goose_yaml_edit_never_wipes_unparseable() {
        let path = temp_path("goose-bad.yaml");
        let garbage = "key: value\n  - [unbalanced flow sequence\n:::not valid";
        std::fs::write(&path, garbage).unwrap();
        // A parse failure must error, never replace config.yaml (it holds model config).
        assert!({
            let _e = sample_gateway(None, "goose");
            edit_yaml_gateway(&path, Some(&_e))
        }
        .is_err());
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
    fn omp_is_registered_as_json_mcp_servers() {
        let d = defs().into_iter().find(|d| d.id == "omp").unwrap();
        assert!(matches!(d.format, Format::JsonMcpServers));
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
    fn continue_yaml_parses_remote_server() {
        let content = "mcpServers:\n  - name: remote-http\n    type: streamable-http\n    url: https://example.com/mcp\n  - name: remote-sse\n    type: sse\n    url: https://example.com/events\n";

        let parsed = parse_continue_yaml_servers(content).unwrap();

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, "remote-http");
        assert_eq!(parsed[0].transport, "http");
        assert_eq!(parsed[0].url.as_deref(), Some("https://example.com/mcp"));
        assert!(parsed[0].command.is_none());
        assert_eq!(parsed[1].name, "remote-sse");
        assert_eq!(parsed[1].transport, "sse");
        assert_eq!(parsed[1].url.as_deref(), Some("https://example.com/events"));
        assert!(parsed[1].command.is_none());
    }

    #[test]
    fn continue_yaml_parses_request_options_headers() {
        // Continue's remote auth contract (not top-level env / headers).
        let content = "mcpServers:\n  - name: secured\n    type: streamable-http\n    url: https://example.com/mcp\n    requestOptions:\n      headers:\n        Authorization: Bearer remote-tok\n        TOOLPORT_CLIENT_ID: continue\n";

        let parsed = parse_continue_yaml_servers(content).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "secured");
        assert_eq!(
            parsed[0].env_keys,
            vec![
                "Authorization".to_string(),
                "TOOLPORT_CLIENT_ID".to_string()
            ]
        );
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
    fn continue_yaml_round_trip_preserves_config() {
        let path = temp_path("continue.yaml");
        std::fs::write(
            &path,
            "models:\n  - title: GPT-4o\n    provider: openai\n    model: gpt-4o\nrules:\n  - Keep responses concise\nmcpServers:\n  - name: old-server\n    command: old-command\n",
        )
        .unwrap();

        let servers = vec![
            stdio("filesystem"),
            stdio("github"),
            remote("remote", "http"),
            remote("remote-sse", "sse"),
        ];
        write_continue_yaml_servers(&path, &servers).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed = parse_continue_yaml_servers(&content).unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].name, "filesystem");
        assert_eq!(parsed[0].command.as_deref(), Some("npx"));
        assert_eq!(
            parsed[0].args,
            vec!["-y", "@modelcontextprotocol/server-filesystem"]
        );
        assert_eq!(parsed[0].env_keys, vec!["TOKEN".to_string()]);
        assert_eq!(parsed[1].name, "github");
        assert_eq!(parsed[2].name, "remote");
        assert_eq!(parsed[2].transport, "http");
        assert_eq!(
            parsed[2].url.as_deref(),
            Some("https://remote.example.com/mcp")
        );
        assert!(parsed[2].command.is_none());
        assert_eq!(parsed[2].env_keys, vec!["Authorization".to_string()]);
        assert_eq!(parsed[3].name, "remote-sse");
        assert_eq!(parsed[3].transport, "sse");
        assert_eq!(
            parsed[3].url.as_deref(),
            Some("https://remote-sse.example.com/mcp")
        );
        assert!(parsed[3].command.is_none());

        let root: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
        assert_eq!(
            root.get("models")
                .and_then(|models| models.as_sequence())
                .and_then(|models| models.first())
                .and_then(|model| model.get("title"))
                .and_then(|title| title.as_str()),
            Some("GPT-4o")
        );
        assert_eq!(
            root.get("rules")
                .and_then(|rules| rules.as_sequence())
                .and_then(|rules| rules.first())
                .and_then(|rule| rule.as_str()),
            Some("Keep responses concise")
        );
        assert!(content.contains("plain-value"));
        // Remote credentials must be under requestOptions.headers (Continue wire contract).
        let remotes: Vec<_> = root
            .get("mcpServers")
            .and_then(|v| v.as_sequence())
            .into_iter()
            .flatten()
            .filter(|s| s.get("url").is_some())
            .collect();
        assert_eq!(remotes.len(), 2);
        for remote in remotes {
            assert_eq!(
                remote
                    .get("requestOptions")
                    .and_then(|ro| ro.get("headers"))
                    .and_then(|h| h.get("Authorization"))
                    .and_then(|v| v.as_str()),
                Some("Bearer fixture"),
                "remote Continue entry must use requestOptions.headers: {content}"
            );
            assert!(
                remote.get("env").is_none(),
                "remote Continue entry must not use env: {content}"
            );
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn continue_yaml_write_never_wipes_unparseable() {
        let path = temp_path("continue-bad.yaml");
        let garbage = "models:\n  - title: GPT-4o\nmcpServers: [unbalanced\n";
        std::fs::write(&path, garbage).unwrap();

        assert!(write_continue_yaml_servers(&path, &[stdio("github")]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), garbage);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn continue_is_registered_as_yaml_mcp_servers_list() {
        let d = defs().into_iter().find(|d| d.id == "continue").unwrap();
        assert!(matches!(d.format, Format::YamlMcpServersList));
        assert!((d.path)().is_some());
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
        {
            let _e = sample_gateway(None, "hermes");
            edit_hermes_yaml_gateway(&path, Some(&_e))
        }
        .unwrap();
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
        let gateway = servers
            .get(GATEWAY_ENTRY_NAME)
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert!(gateway.get("command").and_then(|x| x.as_str()).is_some());

        // Uninstall removes only the gateway entry.
        edit_hermes_yaml_gateway(&path, None).unwrap();
        let after: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let servers2 = after
            .get("mcp_servers")
            .and_then(|x| x.as_mapping())
            .unwrap();
        assert!(servers2.get(GATEWAY_ENTRY_NAME).is_none());
        assert!(servers2.get("zread").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn hermes_yaml_edit_never_wipes_unparseable() {
        let path = temp_path("hermes-bad.yaml");
        let garbage = "key: value\n  - [unbalanced flow sequence\n:::not valid";
        std::fs::write(&path, garbage).unwrap();
        // A parse failure must error, never replace config.yaml (it holds model config).
        assert!({
            let _e = sample_gateway(None, "hermes");
            edit_hermes_yaml_gateway(&path, Some(&_e))
        }
        .is_err());
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

    #[test]
    fn rules_target_claude_code_is_owned_file_all_platforms() {
        use crate::instructions::Strategy;
        for p in [Platform::Windows, Platform::MacOs, Platform::Linux] {
            let t = resolve_rules_target("claude-code", &mock_home(p), p).expect("supported");
            assert_eq!(t.strategy, Strategy::OwnedFile);
            assert!(
                t.path
                    .ends_with(PathBuf::from("rules").join("toolport-team-rules.md")),
                "unexpected claude-code rules path on {p:?}: {:?}",
                t.path
            );
            assert!(t.path.to_string_lossy().contains(".claude"));
        }
    }

    #[test]
    fn rules_target_codex_is_sentinel_and_flags_override() {
        use crate::instructions::Strategy;
        let home = mock_home(Platform::MacOs);
        let t = resolve_rules_target("codex", &home, Platform::MacOs).expect("supported");
        assert_eq!(t.strategy, Strategy::SentinelBlock);
        assert!(t.path.ends_with(PathBuf::from(".codex").join("AGENTS.md")));
        assert_eq!(
            t.blocked_if_present,
            Some(home.join(".codex").join("AGENTS.override.md")),
            "Codex AGENTS.override.md must shadow AGENTS.md"
        );
    }

    #[test]
    fn rules_target_windsurf_carries_hard_cap() {
        let t = resolve_rules_target("windsurf", &mock_home(Platform::Linux), Platform::Linux)
            .expect("supported");
        assert_eq!(t.char_cap, Some(6000));
    }

    #[test]
    fn rules_target_zed_is_platform_specific() {
        let win = resolve_rules_target("zed", &mock_home(Platform::Windows), Platform::Windows)
            .expect("supported");
        assert!(win.path.to_string_lossy().contains("Zed"));
        let mac = resolve_rules_target("zed", &mock_home(Platform::MacOs), Platform::MacOs)
            .expect("supported");
        assert!(mac
            .path
            .ends_with(PathBuf::from(".config").join("zed").join("AGENTS.md")));
    }

    #[test]
    fn rules_target_unsupported_clients_return_none() {
        // Cursor/Warp store globals in UI/cloud; Continue is deferred; chat/identity apps have
        // no global rules file we manage.
        for id in [
            "cursor",
            "warp",
            "continue",
            "claude-desktop",
            "lm-studio",
            "jan",
            "hermes",
        ] {
            assert!(
                resolve_rules_target(id, &mock_home(Platform::MacOs), Platform::MacOs).is_none(),
                "{id} should have no managed rules target"
            );
        }
    }

    #[test]
    fn rules_target_transitive_clients_share_the_covering_file() {
        // A standalone Antigravity / VS Code install must still be covered: each resolves to the
        // same file as the client whose format it reads, and `apply_instructions` de-dupes the
        // shared path so it's written once when both are installed.
        let home = mock_home(Platform::MacOs);
        let p = Platform::MacOs;
        assert_eq!(
            resolve_rules_target("antigravity", &home, p),
            resolve_rules_target("gemini-cli", &home, p),
            "Antigravity shares Gemini's GEMINI.md"
        );
        assert_eq!(
            resolve_rules_target("vscode", &home, p),
            resolve_rules_target("claude-code", &home, p),
            "VS Code Copilot shares Claude Code's rules file"
        );
    }

    /// Serializes tests that read or mutate the process-global XDG env vars. Rust
    /// runs tests in parallel, so without this the test that sets `XDG_CONFIG_HOME`
    /// could change `dirs::config_dir()` mid-flight under a test that reads it,
    /// which is exactly what made `client_config_paths_match_current_platform`
    /// flake on CI. Poison is recovered: a panic elsewhere shouldn't wedge these.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvRestore {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvRestore {
        fn set(key: &'static str, value: &Path) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn amp_is_registered() {
        let definition = defs().into_iter().find(|def| def.id == "amp").unwrap();
        assert_eq!(definition.name, "Amp");
        assert!(matches!(definition.format, Format::JsonAmpMcpServers));
        assert!(!definition.uses_connectors);
        assert!(definition.plugin_scan.is_none());
        assert!((definition.path)().is_some());
        assert!(config_is_whole_app_state("amp"));
    }

    #[test]
    fn amp_default_config_paths_match_each_platform() {
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let expected = home.join(".config").join("amp").join("settings.json");
            assert_eq!(
                resolve_client_config_path("amp", &home, platform),
                Some(expected),
                "Amp on {platform:?}"
            );
        }
    }

    #[test]
    fn amp_settings_file_overrides_production_path() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let override_path = std::env::temp_dir().join("amp-custom-settings.json");
        let _restore = EnvRestore::set("AMP_SETTINGS_FILE", &override_path);
        assert_eq!(amp_path(), Some(override_path));
    }

    #[test]
    fn github_copilot_cli_home_overrides_default_path() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let override_path = std::env::temp_dir().join("copilot-custom-home");
        let _restore = EnvRestore::set("COPILOT_HOME", &override_path);
        assert_eq!(
            github_copilot_cli_path(),
            Some(override_path.join("mcp-config.json"))
        );
    }

    #[test]
    fn client_config_paths_match_current_platform() {
        // Hold the env lock: the path resolution reads `dirs::config_dir()`, which
        // another test mutates via `XDG_CONFIG_HOME`. Serialize so we never read it
        // mid-change.
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _copilot_home = EnvRestore::set("COPILOT_HOME", Path::new(""));
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
            ("droid", |home, _| home.join(".factory").join("mcp.json")),
            ("crush", |home, _| home.join(".config").join("crush").join("crush.json")),
            ("grok", |home, _| home.join(".grok").join("config.toml")),
            ("github-copilot-cli", |home, _| {
                home.join(".copilot").join("mcp-config.json")
            }),
            ("toolport-studio", |home, _| {
                home.join(".toolport-studio").join("mcp.json")
            }),
            ("opencode", |home, _| {
                home.join(".config").join("opencode").join("opencode.json")
            }),
            ("kilo-code", |home, _| {
                home.join(".config").join("kilo").join("kilo.jsonc")
            }),
            ("qwen-code", |home, _| {
                home.join(".qwen").join("settings.json")
            }),
            ("junie", |home, _| {
                home.join(".junie").join("mcp").join("mcp.json")
            }),
            ("continue", |home, _| {
                home.join(".continue").join("config.yaml")
            }),
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
            // Confirmed against Witsy's own file-location wiki: same "Witsy" folder
            // name under the OS-standard roaming config root on every platform.
            ("witsy", |home, platform| {
                roaming_config_dir(home, platform)
                    .join("Witsy")
                    .join("settings.json")
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
        let crush = client_config_path("crush").unwrap();
        let opencode = client_config_path("opencode").unwrap();
        let kilo_code = client_config_path("kilo-code").unwrap();

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
        assert_eq!(
            crush,
            xdg_config.join("crush").join("crush.json")
        );
        assert_eq!(
            opencode,
            home.join(".config").join("opencode").join("opencode.json")
        );
        assert_eq!(
            kilo_code,
            home.join(".config").join("kilo").join("kilo.jsonc")
        );
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
    fn parse_opencode_json_snippet() {
        let json = r#"{
            "mcp": {
                "my-server": {
                    "type": "local",
                    "command": ["npx", "-y", "foo"],
                    "environment": {"TOKEN": "value"},
                    "enabled": true
                }
            }
        }"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "my-server");
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[0].args, vec!["-y", "foo"]);
        assert_eq!(servers[0].env[0].key, "TOKEN");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("value"));
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
        assert_eq!(
            name_from_invocation("npx", &vs(&["-y", "@verygoodplugins/mcp-automem"])),
            "automem"
        );
        assert_eq!(
            name_from_invocation("npx", &vs(&["-y", "@modelcontextprotocol/server-github"])),
            "github"
        );
        assert_eq!(
            name_from_invocation("uvx", &vs(&["mcp-server-fetch"])),
            "fetch"
        );
        assert_eq!(
            name_from_invocation("npx", &vs(&["@upstash/context7-mcp"])),
            "context7"
        );
        assert_eq!(
            name_from_invocation("npx", &vs(&["-y", "mcp-remote@latest"])),
            "remote"
        );
        assert_eq!(
            name_from_invocation("bunx", &vs(&["some-tool"])),
            "some-tool"
        );
        // A Windows npx.cmd path is still recognized as the npx launcher.
        assert_eq!(
            name_from_invocation(
                "C:\\Program Files\\nodejs\\npx.cmd",
                &vs(&["-y", "@scope/mcp-thing"])
            ),
            "thing"
        );
        // A packed "npx -y <pkg>" command with empty args is handled.
        assert_eq!(
            name_from_invocation("npx -y @verygoodplugins/mcp-automem", &[]),
            "automem"
        );
        // A non-runner keeps its own command file stem (unchanged behavior).
        assert_eq!(
            name_from_invocation("/usr/local/bin/my-server", &[]),
            "my-server"
        );
    }

    #[test]
    fn launcher_handles_package_flag_and_separator() {
        let vs = |args: &[&str]| args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // An explicit --package=/--package/-p names the package, not the command
        // after `--` (which is what to run inside the package env), issue #251 f/u.
        assert_eq!(
            name_from_invocation(
                "npm",
                &vs(&["exec", "--package=@scope/mcp-weather", "--", "server"])
            ),
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
        assert_eq!(
            name_from_invocation("npx", &vs(&["-p", "@scope/mcp-foo", "cmd"])),
            "foo"
        );
        // A positional package before `--` still wins, and `--` stops the search.
        assert_eq!(
            name_from_invocation("npx", &vs(&["-y", "@scope/mcp-a", "--", "not-a-package"])),
            "a"
        );
        // Cross-platform: a Windows path resolves to its stem even on a Unix host.
        assert_eq!(
            name_from_invocation("C:\\tools\\my-server.exe", &[]),
            "my-server"
        );
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
    fn parse_continue_yaml_snippet() {
        let yaml = r#"
mcpServers:
- name: fetch
  command: uvx
  args:
    - mcp-server-fetch
  env:
    TOKEN: abc123
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "fetch");
        assert_eq!(servers[0].command.as_deref(), Some("uvx"));
        assert_eq!(servers[0].args, vec!["mcp-server-fetch"]);
        assert_eq!(servers[0].env.len(), 1);
        assert_eq!(servers[0].env[0].key, "TOKEN");
        assert_eq!(servers[0].env[0].value.as_deref(), Some("abc123"));
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
    fn parse_non_string_json_arg_values() {
        let json = r#"{"mcpServers":{"srv":{"command":"npx","args":["server.js",8080,true]}}}"#;
        let servers = parse_snippet(json).unwrap();
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].args, vec!["server.js", "8080", "true"]);
    }

    #[test]
    fn parse_non_string_toml_arg_values() {
        let toml = r#"
        [mcp_servers.srv]
        command = "npx"
        args = ["server.js",8080,true]
        "#;
        let servers = parse_snippet(toml).unwrap();
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].args, vec!["server.js", "8080", "true"]);
    }

    #[test]
    fn parse_non_string_goose_yaml_arg_values() {
        let yaml = r#"
        extensions:
        srv:
            enabled: true
            type: stdio
            cmd: npx
            args:
            - "server.js"
            - 8080
            - true
        "#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].args, vec!["server.js", "8080", "true"]);
    }

    #[test]
    fn parse_non_string_continue_yaml_arg_values() {
        // Continue's list form is indentation-sensitive, so this fixture stays
        // flush against the left margin rather than matching the block above.
        let yaml = r#"
mcpServers:
  - name: fetch
    command: uvx
    args:
      - mcp-server-fetch
      - 8080
      - true
"#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].args, vec!["mcp-server-fetch", "8080", "true"]);
    }

    #[test]
    fn parse_non_string_hermes_yaml_arg_values() {
        let yaml = r#"
        mcp_servers:
         my-server:
            command: npx
            args:
              - "-y"
              - 8080
              - true
        "#;
        let servers = parse_snippet(yaml).unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].args.len(), 3);
        assert_eq!(servers[0].args, vec!["-y", "8080", "true"]);
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
