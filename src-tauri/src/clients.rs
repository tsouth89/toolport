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
    /// Kimi Code's top-level `mcpServers` object (`~/.kimi-code/mcp.json`).
    /// Stdio entries use the standard command/args/env shape; remote entries are
    /// streamable HTTP unless they carry `transport: "sse"` (Kimi ignores the
    /// `type` hint other clients use), and bearer auth is declared via
    /// `bearerTokenEnvVar` naming a shell env var that holds the token.
    JsonKimiMcpServers,
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
        "devin-cli" => match platform {
            Platform::Windows => config.join("devin").join("mcp_config.json"),
            Platform::MacOs | Platform::Linux => {
                home.join(".config").join("devin").join("mcp_config.json")
            }
        },
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
        "kimi-code" => home.join(".kimi-code").join("mcp.json"),
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
        _ => return None,
    };
    Some(path)
}

/// Claude Code relocates its whole config tree - `.claude.json` included - when
/// `CLAUDE_CONFIG_DIR` is set, so the default `~/.claude.json` is not always the
/// file it reads.
///
/// Resolving only the default is not a cosmetic miss: Toolport rewrites the
/// gateway path in this file on every upgrade, so a relocated config keeps
/// pinning whichever versioned binary was current when it was written. The
/// client then respawns that obsolete gateway forever, and the "app is still
/// launching an old gateway" reaper cannot win - it stops the process, and the
/// config Toolport never updated starts it again.
///
/// Taken from Toolport's own environment, which covers a user who exports the
/// variable. It does NOT cover a launcher that sets the variable only for the
/// child process it spawns - Toolport cannot see that, and such a config stays
/// stale. Kept split from the pure path table so tests stay env-free.
fn claude_config_dir_override() -> Option<PathBuf> {
    claude_config_dir_from(std::env::var_os("CLAUDE_CONFIG_DIR"))
}

/// An env-supplied directory is only used when it is an absolute path.
/// Empty or relative values are a misconfiguration, not an instruction to
/// write relative to Toolport's cwd. Shared by `CLAUDE_CONFIG_DIR`,
/// `CODEX_HOME`, `GEMINI_CLI_HOME`, `GROK_HOME`, and `QWEN_HOME` (SBS-885).
///
/// A literal `~` is NOT a home reference here. Every one of those clients except
/// Qwen Code uses its env value verbatim (Codex `find_codex_home_from_env`, Grok
/// `resolve_grok_home_from`, Gemini CLI `homedir()`), so a value the shell left
/// unexpanded is already broken for the client itself and the default path is the
/// closer guess. Qwen Code expands it, so `qwen_home_from` runs the value through
/// [`expand_leading_tilde`] first.
fn absolute_env_dir(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let dir = PathBuf::from(raw?);
    dir.is_absolute().then_some(dir)
}

/// Expand a leading `~`, `~/`, or `~\` against the home directory.
///
/// Only for env vars whose owning client performs the same expansion; see
/// [`absolute_env_dir`] for why the rest keep the value verbatim. A bare `~work`
/// has no separator and is not a home reference, which matches the client. A
/// non-UTF-8 value, or one read with no home directory available, passes through
/// untouched so the caller's absolute check still sees the original.
fn expand_leading_tilde(raw: Option<std::ffi::OsString>) -> Option<std::ffi::OsString> {
    let raw = raw?;
    let Some(text) = raw.to_str() else {
        return Some(raw);
    };
    let rest = if text == "~" {
        ""
    } else if let Some(rest) = text.strip_prefix("~/").or_else(|| text.strip_prefix(r"~\")) {
        // Every further separator has to go too. `~//work/qwen` leaves `/work/qwen`,
        // which `PathBuf::join` reads as rooted and substitutes for the home dir
        // instead of appending to it, so the value escapes home entirely.
        rest.trim_start_matches(['/', '\\'])
    } else {
        return Some(raw);
    };
    let Some(home) = home() else {
        return Some(raw);
    };
    let expanded = if rest.is_empty() {
        home
    } else {
        home.join(rest)
    };
    Some(expanded.into_os_string())
}

/// The env-free half of [`claude_config_dir_override`], so the validation rules
/// are testable without mutating process environment from a parallel test.
fn claude_config_dir_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    absolute_env_dir(raw)
}

/// The `.claude.json` a Claude Code process reads, given its config dir.
fn claude_code_config_path(config_dir: &std::path::Path) -> PathBuf {
    config_dir.join(".claude.json")
}

/// Goose relocates its whole tree — `config/config.yaml` and
/// `config/.goosehints` included — when `GOOSE_PATH_ROOT` is an absolute path
/// (SBS-899). Relative or empty values are a misconfiguration, not an
/// instruction to write relative to Toolport's cwd. Matches Goose's own
/// `Paths::validated_path_root`.
fn goose_path_root_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let dir = PathBuf::from(raw.filter(|p| !p.is_empty())?);
    dir.is_absolute().then_some(dir)
}

fn goose_config_under_root(root: &Path) -> PathBuf {
    root.join("config").join("config.yaml")
}

fn goose_hints_under_root(root: &Path) -> PathBuf {
    root.join("config").join(".goosehints")
}

fn rules_sentinel_block(
    path: PathBuf,
    scope: crate::instructions::Scope,
) -> crate::instructions::Target {
    crate::instructions::Target {
        path,
        strategy: crate::instructions::Strategy::SentinelBlock,
        scope,
        char_cap: None,
        blocked_if_present: None,
    }
}

/// Every `.claude.json` on this machine that some Claude Code process may read.
///
/// [`claude_config_dir_override`] resolves the ONE config Toolport reads and writes,
/// which is correct for connecting a client but wrong for maintaining one. A machine
/// routinely has several: `CLAUDE_CONFIG_DIR` is usually exported per-shell or set by
/// a launcher for one profile (a personal `~/.claude` beside a work `~/.claude-work`),
/// so whichever one Toolport did not resolve today keeps pinning whatever gateway
/// binary was current the day it was written. Pruning deliberately keeps recent
/// binaries, so that client goes on respawning superseded gateway code indefinitely,
/// and the reaper cannot win: it stops the process and the config Toolport never
/// updated starts it again. That is the failure this list exists to close.
///
/// Discovery is deliberately narrow: the documented default, the override, and
/// `.claude*` siblings directly under home. No recursion, nothing outside home.
fn claude_code_config_paths() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let dirs = match claude_profile_dirs(&home) {
        Ok(dirs) => dirs,
        Err(error) => {
            let msg = format!(
                "toolport: could not scan {} for secondary Claude Code configs: {error}",
                home.display()
            );
            eprintln!("{msg}");
            crate::gatewaylog::append(&msg);
            Vec::new()
        }
    };
    claude_code_config_paths_from(&home, claude_config_dir_override().as_deref(), &dirs)
        .into_iter()
        .filter(|p| p.is_file())
        .collect()
}

/// Directory names directly under home that may hold Claude Code profiles. `Path::is_dir`
/// deliberately follows symlinks: keeping a work profile on another volume via
/// `~/.claude-work -> /volume/work-claude` is a supported filesystem shape.
fn claude_profile_dirs(home: &Path) -> Result<Vec<String>, String> {
    let entries = std::fs::read_dir(home).map_err(|e| e.to_string())?;
    Ok(entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect())
}

/// The env- and filesystem-free half of [`claude_code_config_paths`], so ordering and
/// de-duplication are testable without a home directory full of fixtures.
///
/// `home_dirs` is the set of directory names directly under `home`. Order matters: the
/// resolved config comes first so a caller that only wants "the one we manage" can take
/// the head, and the rest follow in a stable order.
fn claude_code_config_paths_from(
    home: &std::path::Path,
    override_dir: Option<&std::path::Path>,
    home_dirs: &[String],
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let push = |path: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    if let Some(dir) = override_dir {
        push(claude_code_config_path(dir), &mut out);
    }
    // The documented default is a FILE at the home root, not `.claude/.claude.json`.
    push(home.join(".claude.json"), &mut out);
    let mut siblings: Vec<&String> = home_dirs
        .iter()
        .filter(|name| *name == ".claude" || name.starts_with(".claude-"))
        .collect();
    // read_dir order is unspecified; sort so the log and any diagnostics are stable.
    siblings.sort();
    for name in siblings {
        push(claude_code_config_path(&home.join(name)), &mut out);
    }
    out
}

/// The `settings.json` a Claude Code process reads, given its config dir. This is the
/// file that carries `hooks`, which `.claude.json` does not.
fn claude_settings_path(config_dir: &Path) -> PathBuf {
    config_dir.join("settings.json")
}

/// Every Claude Code profile's `settings.json` on this machine.
///
/// Same discovery, and the same reason, as [`claude_code_config_paths`]: a machine
/// routinely has `~/.claude` beside `~/.claude-work`, chosen per shell by
/// `CLAUDE_CONFIG_DIR`. A hook sensor installed into only the profile Toolport
/// resolved today is blind to every session run under any other one, and would
/// under-report silently rather than visibly (SBS-822).
///
/// Two deliberate differences from the config list:
///
///   * The default lives at `~/.claude/settings.json`, a file inside the profile
///     directory, not `~/.claude.json` at the home root.
///   * Paths are kept when the file does not exist yet, because a profile that has
///     never had settings written still needs the sensor; the caller creates it.
///     What IS required is that the profile directory exists, so a stale
///     `CLAUDE_CONFIG_DIR` cannot make Toolport conjure a profile that Claude Code
///     has never used.
pub(crate) fn claude_settings_paths() -> Vec<PathBuf> {
    let Some(home) = home() else {
        return Vec::new();
    };
    let dirs = match claude_profile_dirs(&home) {
        Ok(dirs) => dirs,
        Err(error) => {
            let msg = format!(
                "toolport: could not scan {} for Claude Code profiles: {error}",
                home.display()
            );
            eprintln!("{msg}");
            crate::gatewaylog::append(&msg);
            Vec::new()
        }
    };
    claude_settings_paths_from(&home, claude_config_dir_override().as_deref(), &dirs)
        .into_iter()
        .filter(|p| p.parent().map(Path::is_dir).unwrap_or(false))
        .collect()
}

/// The env- and filesystem-free half of [`claude_settings_paths`], so ordering and
/// de-duplication are testable without a home directory full of fixtures.
fn claude_settings_paths_from(
    home: &Path,
    override_dir: Option<&Path>,
    home_dirs: &[String],
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let push = |path: PathBuf, out: &mut Vec<PathBuf>| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    if let Some(dir) = override_dir {
        push(claude_settings_path(dir), &mut out);
    }
    push(claude_settings_path(&home.join(".claude")), &mut out);
    let mut siblings: Vec<&String> = home_dirs
        .iter()
        .filter(|name| *name == ".claude" || name.starts_with(".claude-"))
        .collect();
    // read_dir order is unspecified; sort so the log and any diagnostics are stable.
    siblings.sort();
    for name in siblings {
        push(claude_settings_path(&home.join(name)), &mut out);
    }
    out
}

/// Read one agent settings file as a value, plus its original text.
///
/// A missing file is an empty object: the caller is about to create it. Any other
/// read failure, and any syntax error, is an `Err` so a caller cannot silently
/// replace a file it could not understand (the failure mode behind SBS-873 and
/// friends). The original text is returned so the write can go back through the
/// JSONC CST and keep the user's comments.
pub(crate) fn read_settings_json(
    path: &Path,
) -> Result<(serde_json::Value, Option<String>), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((serde_json::Value::Object(serde_json::Map::new()), None));
        }
        Err(e) => return Err(format!("could not stat {}: {e}", path.display())),
        Ok(_) => {}
    }
    let text = read_config_file(path)?;
    let value = parse_json_value(&text)?;
    Ok((value, Some(text)))
}

/// Write an agent settings file after backing up whatever was there.
///
/// Rewrites only the `hooks` key through the JSONC CST ([`atomic_write_json_config`]),
/// so comments, trailing commas, and the formatting of every other setting survive.
/// A duplicate top-level `hooks` key is a hard refusal that leaves the file untouched.
pub(crate) fn write_settings_json(
    path: &Path,
    original: Option<&str>,
    root: &serde_json::Value,
) -> Result<(), String> {
    write_settings_key(path, original, root, "hooks")
}

/// [`write_settings_json`] for a caller that owns a different top-level key (the
/// permission policy owns `permissions`). Same backup, same CST rewrite of only that key.
pub(crate) fn write_settings_key(
    path: &Path,
    original: Option<&str>,
    root: &serde_json::Value,
    key: &str,
) -> Result<(), String> {
    write_settings_key_for("claude-code", path, original, root, key)
}

/// [`write_settings_key`] for another client's JSON settings file (the Cursor guard writes
/// `~/.cursor/hooks.json`); the backup is filed under that client.
pub(crate) fn write_settings_key_for(
    client_id: &str,
    path: &Path,
    original: Option<&str>,
    root: &serde_json::Value,
    key: &str,
) -> Result<(), String> {
    if original.is_some() {
        backup_file_named(client_id, path, &claude_settings_backup_name(path))?;
    }
    atomic_write(path, &render_settings_key(original, root, key)?)
}

/// The exact bytes [`write_settings_json`] would put on disk.
///
/// Split out so a dry run can show the real result. Pretty-printing the value instead
/// would report that every comment in the file is about to vanish, which is the
/// opposite of what the CST write does (SBS-822 review).
pub(crate) fn render_settings_json(
    original: Option<&str>,
    root: &serde_json::Value,
) -> Result<String, String> {
    render_settings_key(original, root, "hooks")
}

/// [`render_settings_json`] for one top-level `key`: rewrite that key through the CST,
/// or delete it through the CST when `root` no longer has it.
pub(crate) fn render_settings_key(
    original: Option<&str>,
    root: &serde_json::Value,
    key: &str,
) -> Result<String, String> {
    match (original, root.get(key)) {
        // The key is gone, which is what uninstall produces. `render_json_config`
        // only rewrites a key it can still find, so this case would fall through to a
        // pretty-print of the whole file and strip every comment in it. Delete the key
        // through the CST instead.
        (Some(src), None) if !src.trim().is_empty() => remove_json_key_preserving(src, key),
        _ => render_json_config(original, root, key),
    }
}

/// Give each profile's `settings.json` its own backup identity, so one profile's
/// backups can never overwrite or prune another's.
///
/// Hashes the FULL path, exactly like [`secondary_claude_backup_name`] and for the same
/// reason: the parent directory's leaf name is not unique. `~/.claude` and a
/// `CLAUDE_CONFIG_DIR` of `D:\work\.claude` share the leaf `.claude`, so a leaf-based
/// identity makes both profiles share one backup series and `prune_backups` then deletes
/// one profile's only recovery copies to stay inside `CONFIG_BACKUP_GENERATIONS`
/// (SBS-822 review).
fn claude_settings_backup_name(path: &Path) -> String {
    let digest = crate::registry::sha256_hex(&path.to_string_lossy());
    format!("claude-settings-{}.json", &digest[..16])
}

fn client_config_path(client_id: &str) -> Option<PathBuf> {
    client_config_path_with_home(client_id, home())
}

/// [`client_config_path`] with the home directory passed in, so a test can drive the
/// `$HOME`-unavailable case on any platform (`dirs::home_dir` reads a known folder on
/// Windows, so it cannot be unset from a test).
fn client_config_path_with_home(client_id: &str, home: Option<PathBuf>) -> Option<PathBuf> {
    // An absolute `GOOSE_PATH_ROOT` names the live config outright, so it resolves even
    // when there is no home directory to fall back to. This mirrors `codex_path`, which
    // checks `CODEX_HOME` before it ever calls this (SBS-885), and it keeps the config
    // path in step with `client_rules_target`: without it Connect could write Goose Team
    // Instructions under the root but fail to find the config beside them (SBS-899).
    if client_id == "goose" {
        if let Some(root) = goose_path_root_from(std::env::var_os("GOOSE_PATH_ROOT")) {
            return Some(goose_config_under_root(&root));
        }
    }
    let home = home?;
    if client_id == "claude-code" {
        if let Some(dir) = claude_config_dir_override() {
            return Some(claude_code_config_path(&dir));
        }
    }
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
        "devin-cli" => config.join("devin").join("mcp_config.json"),
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
        "kimi-code" => home.join(".kimi-code").join("mcp.json"),
        "lm-studio" => home.join(".lmstudio").join("mcp.json"),
        "jan" => data.join("Jan").join("data").join("mcp_config.json"),
        "zed" => config.join("zed").join("settings.json"),
        "goose" => config.join("goose").join("config.yaml"),
        "anythingllm" => config
            .join("anythingllm-desktop")
            .join("storage")
            .join("plugins")
            .join("anythingllm_mcp_servers.json"),
        "continue" => home.join(".continue").join("config.yaml"),
        "hermes" => home.join(".hermes").join("config.yaml"),
        "witsy" => config.join("Witsy").join("settings.json"),
        _ => return None,
    };
    Some(path)
}

/// Resolve where a client reads its GLOBAL agent-rules file, for one [`crate::instructions::Scope`]
/// (Team Instructions spec "W2"; personal rules in the `agent-rules` spec). The scope only changes
/// the file NAME under [`crate::instructions::Strategy::OwnedFile`] — sentinel clients share one
/// file and are separated by their markers instead, so both scopes resolve to the same path there
/// by design.
/// This is DISTINCT from the client's MCP-config path — e.g. Claude Code's config is
/// `~/.claude.json` but its rules live under `~/.claude/rules/`. `None` means the client has
/// no global-rules location we write: either its globals are UI/cloud-stored (Cursor, Warp),
/// or it's covered transitively by another client's file (Antigravity reads Gemini's
/// `GEMINI.md`; VS Code Copilot reads Claude Code's `~/.claude` rules). Most of these
/// paths are home-anchored. Goose and Zed on Linux follow `XDG_CONFIG_HOME` via
/// [`client_rules_target`] / `dirs::config_dir()`, matching [`client_config_path`]
/// (SBS-899 / #757). Goose also honours absolute `GOOSE_PATH_ROOT`, which relocates
/// both `config/config.yaml` and `config/.goosehints`. See the spec's adapter table
/// for citations.
fn resolve_rules_target(
    client_id: &str,
    home: &std::path::Path,
    platform: Platform,
    scope: crate::instructions::Scope,
) -> Option<crate::instructions::Target> {
    use crate::instructions::{Strategy, Target};
    let config = roaming_config_dir(home, platform);
    // `dir` is the client's rules DIRECTORY; the file name inside it is the scope's, so a team
    // file and a personal file sit side by side and the client loads both.
    let owned = |dir: PathBuf| Target {
        path: dir.join(scope.owned_file_name()),
        strategy: Strategy::OwnedFile,
        scope,
        char_cap: None,
        blocked_if_present: None,
    };
    let block = |path: PathBuf| Target {
        path,
        strategy: Strategy::SentinelBlock,
        scope,
        char_cap: None,
        blocked_if_present: None,
    };
    let target = match client_id {
        // Strategy A — Toolport owns a whole file in the client's rules DIRECTORY.
        // Claude Code's `~/.claude/rules/` is also read by VS Code: its custom-instructions
        // docs list "User profile: ~/.copilot/instructions or ~/.claude/rules" as a user-level
        // location (verified 2026-08-22, SBS-916), so both map here; path-dedup writes it once
        // when both are installed and a standalone VS Code install is still covered.
        "claude-code" | "vscode" => owned(home.join(".claude").join("rules")),
        "kiro" => owned(home.join(".kiro").join("steering")),
        "roo-code" => owned(home.join(".roo").join("rules")),
        "cline" => owned(home.join("Documents").join("Cline").join("Rules")),
        // Strategy B — Toolport owns only the sentinel span in a shared global file.
        // Default home only. `client_rules_target` relocates Codex / Gemini CLI
        // when `CODEX_HOME` / `GEMINI_CLI_HOME` is an absolute path (SBS-885).
        "codex" => codex_rules_target(&home.join(".codex"), scope),
        // Gemini CLI and Antigravity share `~/.gemini/GEMINI.md` at the default
        // home so a standalone install of EITHER is covered, and
        // `apply_instructions`' path-dedup writes it once when both are present.
        // A relocated Gemini CLI home is handled in `client_rules_target` and
        // does not move Antigravity (`GEMINI_CLI_HOME` is CLI-only).
        "gemini-cli" | "antigravity" => block(home.join(".gemini").join("GEMINI.md")),
        "windsurf" => Target {
            path: home
                .join(".codeium")
                .join("windsurf")
                .join("memories")
                .join("global_rules.md"),
            strategy: Strategy::SentinelBlock,
            scope,
            char_cap: Some(6000), // Devin Desktop's Cascade agent hard-caps the global rules file.
            blocked_if_present: None,
        },
        "devin-cli" => match platform {
            Platform::Windows => block(config.join("devin").join("AGENTS.md")),
            Platform::MacOs | Platform::Linux => {
                block(home.join(".config").join("devin").join("AGENTS.md"))
            }
        },
        // Sibling of config.yaml. Windows uses the etcetera config dir
        // (%APPDATA%\\Block\\goose\\config); macOS/Linux default to ~/.config/goose
        // (Goose's documented XDG location). Production Linux overlays XDG via
        // client_rules_target; GOOSE_PATH_ROOT is handled there too.
        "goose" => match platform {
            Platform::Windows => block(
                config
                    .join("Block")
                    .join("goose")
                    .join("config")
                    .join(".goosehints"),
            ),
            Platform::MacOs | Platform::Linux => {
                block(home.join(".config").join("goose").join(".goosehints"))
            }
        },
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

/// Codex rules live next to `config.toml` under `CODEX_HOME` (default `~/.codex`).
/// `AGENTS.override.md` in that same directory, if present, makes Codex ignore
/// `AGENTS.md` entirely — for either scope, since both share the one file.
fn codex_rules_target(
    codex_home: &Path,
    scope: crate::instructions::Scope,
) -> crate::instructions::Target {
    crate::instructions::Target {
        path: codex_home.join("AGENTS.md"),
        strategy: crate::instructions::Strategy::SentinelBlock,
        scope,
        char_cap: None,
        blocked_if_present: Some(codex_home.join("AGENTS.override.md")),
    }
}

/// Gemini CLI rules follow `GEMINI_CLI_HOME` the same way settings
/// do: the env replaces the process home, then `.gemini/` is still appended.
fn gemini_cli_rules_target(
    cli_home: &Path,
    scope: crate::instructions::Scope,
) -> crate::instructions::Target {
    crate::instructions::Target {
        path: cli_home.join(".gemini").join("GEMINI.md"),
        strategy: crate::instructions::Strategy::SentinelBlock,
        scope,
        char_cap: None,
        blocked_if_present: None,
    }
}

/// The rules-file target for a client on the current machine for one
/// [`crate::instructions::Scope`], or `None` if unsupported / transitively covered. Mirrors
/// [`client_config_path`]: Goose/Zed on Linux honor `XDG_CONFIG_HOME`, and Goose honors absolute
/// `GOOSE_PATH_ROOT` (SBS-899).
pub fn client_rules_target(
    client_id: &str,
    scope: crate::instructions::Scope,
) -> Option<crate::instructions::Target> {
    // Honor relocate envs even when `$HOME` is unset: the live file is under
    // the override, not the default home table (SBS-885, SBS-899).
    if client_id == "goose" {
        if let Some(root) = goose_path_root_from(std::env::var_os("GOOSE_PATH_ROOT")) {
            return Some(rules_sentinel_block(goose_hints_under_root(&root), scope));
        }
    }
    if client_id == "codex" {
        if let Some(dir) = codex_home_from(std::env::var_os("CODEX_HOME")) {
            return Some(codex_rules_target(&dir, scope));
        }
    }
    if client_id == "gemini-cli" {
        if let Some(dir) = gemini_cli_home_from(std::env::var_os("GEMINI_CLI_HOME")) {
            return Some(gemini_cli_rules_target(&dir, scope));
        }
    }
    let home = home()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    if matches!(client_id, "goose" | "zed" | "devin-cli") {
        let config = dirs::config_dir().unwrap_or_else(|| home.join(".config"));
        let path = match client_id {
            "goose" => config.join("goose").join(".goosehints"),
            "zed" => config.join("zed").join("AGENTS.md"),
            "devin-cli" => config.join("devin").join("AGENTS.md"),
            _ => unreachable!("guarded by matches! above"),
        };
        return Some(rules_sentinel_block(path, scope));
    }
    resolve_rules_target(client_id, &home, Platform::current(), scope)
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

fn amp_path() -> Option<PathBuf> {
    std::env::var_os("AMP_SETTINGS_FILE")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| client_config_path("amp"))
}

/// Codex reads `$CODEX_HOME/config.toml` when `CODEX_HOME` is set, otherwise
/// `~/.codex/config.toml`. The env *is* the Codex home directory, not its
/// parent. Empty or relative values fall back: resolving them would depend
/// on Toolport's cwd, which is not where Codex looks (SBS-885).
fn codex_home_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    absolute_env_dir(raw)
}

fn codex_config_path(codex_home: &Path) -> PathBuf {
    codex_home.join("config.toml")
}

fn codex_path() -> Option<PathBuf> {
    if let Some(dir) = codex_home_from(std::env::var_os("CODEX_HOME")) {
        return Some(codex_config_path(&dir));
    }
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

/// Grok Build stores MCP servers in `$GROK_HOME/config.toml` (default
/// `~/.grok/config.toml`) under `[mcp_servers.<name>]` - the same TOML
/// shape as Codex. `GROK_HOME` is the same relocate class as `CODEX_HOME`
/// (SBS-885). It also reads Claude Code's config as a fallback, but writing
/// our own explicit entry is what makes the gateway reliably visible
/// (`grok mcp list` doesn't surface the Claude-config pickup).
fn grok_home_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    absolute_env_dir(raw)
}

fn grok_config_path(grok_home: &Path) -> PathBuf {
    grok_home.join("config.toml")
}

fn grok_path() -> Option<PathBuf> {
    if let Some(dir) = grok_home_from(std::env::var_os("GROK_HOME")) {
        return Some(grok_config_path(&dir));
    }
    client_config_path("grok")
}

/// Gemini CLI treats `GEMINI_CLI_HOME` as a replacement *home directory*,
/// then still appends `.gemini/`. Settings live at
/// `$GEMINI_CLI_HOME/.gemini/settings.json`. Empty or relative values fall
/// back the same way `CLAUDE_CONFIG_DIR` does (SBS-885).
fn gemini_cli_home_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    absolute_env_dir(raw)
}

fn gemini_cli_settings_path(cli_home: &Path) -> PathBuf {
    cli_home.join(".gemini").join("settings.json")
}

fn gemini_cli_path() -> Option<PathBuf> {
    if let Some(dir) = gemini_cli_home_from(std::env::var_os("GEMINI_CLI_HOME")) {
        return Some(gemini_cli_settings_path(&dir));
    }
    client_config_path("gemini-cli")
}

/// Qwen Code stores user-scoped settings at `~/.qwen/settings.json`.
/// `QWEN_HOME` relocates that directory (`$QWEN_HOME/settings.json`), the
/// same class as `CODEX_HOME` (SBS-885). Qwen itself also accepts a
/// relative `QWEN_HOME` resolved against cwd; we do not, because Toolport's
/// cwd is not Qwen's.
///
/// A leading `~` IS honored, unlike the sibling relocate envs: Qwen's
/// `Storage.resolvePath` expands `~`, `~/`, and `~\` against `os.homedir()`
/// before any cwd resolve, so `$expanded/settings.json` is the live file. An
/// unquoted `export QWEN_HOME=~/work` is expanded by the shell before Toolport
/// sees it, but a quoted export, a PowerShell `$env:QWEN_HOME`, and a Windows
/// user-env value all stay literal. Dropping those left Connect, migrate, and
/// the launch re-point writing `~/.qwen/settings.json` while Qwen read the
/// expanded home.
fn qwen_home_from(raw: Option<std::ffi::OsString>) -> Option<PathBuf> {
    absolute_env_dir(expand_leading_tilde(raw))
}

fn qwen_settings_path(qwen_home: &Path) -> PathBuf {
    qwen_home.join("settings.json")
}

fn qwen_code_path() -> Option<PathBuf> {
    if let Some(dir) = qwen_home_from(std::env::var_os("QWEN_HOME")) {
        return Some(qwen_settings_path(&dir));
    }
    client_config_path("qwen-code")
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

fn roo_code_path() -> Option<PathBuf> {
    client_config_path("roo-code")
}

fn resolve_opencode_config_path(json_path: PathBuf) -> Result<PathBuf, String> {
    let jsonc_path = json_path.with_extension("jsonc");
    match (json_path.exists(), jsonc_path.exists()) {
        (true, true) => Err(format!(
            "Both {} and {} exist. OpenCode config is ambiguous; remove or rename one before Toolport changes it.",
            json_path.display(),
            jsonc_path.display()
        )),
        (false, true) => Ok(jsonc_path),
        _ => Ok(json_path),
    }
}

fn resolved_definition_path(def: &ClientDef) -> Result<PathBuf, String> {
    let path = (def.path)().ok_or("Could not resolve a config path on this OS")?;
    if def.id == "opencode" {
        resolve_opencode_config_path(path)
    } else {
        Ok(path)
    }
}

/// Kimi Code (Moonshot AI) user-level MCP config: `~/.kimi-code/mcp.json`
/// (`mcpServers`). Kimi merges a per-project `.kimi-code/mcp.json` over it on
/// startup; we manage the user-level file so the gateway is available
/// everywhere. `KIMI_CODE_HOME` relocates the whole data root, mcp.json
/// included. The data root is created by the CLI itself, so the default
/// parent-dir presence check detects the install.
fn kimi_code_path() -> Option<PathBuf> {
    std::env::var_os("KIMI_CODE_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|root| root.join("mcp.json"))
        .or_else(|| client_config_path("kimi-code"))
}

/// Goose keeps extensions (its MCP servers) in config.yaml. It resolves the dir
/// via the `etcetera` "Block/goose" app strategy: ~/.config/goose on Linux, an
/// app-support path on macOS, and %APPDATA%\Block\goose\config on Windows. (The
/// Windows path is the etcetera default and is confirmed against a real install.)
fn goose_path() -> Option<PathBuf> {
    client_config_path("goose")
}

/// Hermes keeps MCP servers in ~/.hermes/config.yaml under the `mcp_servers:` key.
/// The file is YAML and also holds the user's model and platform toolsets config,
/// so it's read leniently and never wiped on a parse failure.
///
/// The Windows desktop build does NOT use the home-anchored path: it writes
/// `%LOCALAPPDATA%\hermes\config.yaml` (lowercase dir), so resolving only
/// `~/.hermes` made an installed Hermes undetectable there and there was no way
/// to connect it. Related to [`crush_path`], but the preference is the other way
/// round: Crush's platform path is the LEGACY one, so it only wins when it holds a
/// file, whereas Hermes' platform path is the CURRENT one on Windows and so also
/// wins when neither exists. Writing a fresh config into `~/.hermes` on Windows
/// would put it somewhere Hermes never reads.
fn hermes_path() -> Option<PathBuf> {
    let canonical = client_config_path("hermes")?;
    // Only the Windows build uses the platform data dir. Passing None elsewhere
    // keeps macOS and Linux on the home-anchored path with no probing at all.
    let local = if cfg!(windows) {
        dirs::data_local_dir()
    } else {
        None
    };
    Some(resolve_hermes_path(canonical, local))
}

/// Body of [`hermes_path`], taking the two roots directly so the fallback can be
/// tested on any platform. An existing canonical file always wins, so a user who
/// already has `~/.hermes/config.yaml` is never silently repointed.
fn resolve_hermes_path(canonical: PathBuf, local_data: Option<PathBuf>) -> PathBuf {
    if canonical.exists() {
        return canonical;
    }
    // Nothing at the canonical path. Where a platform dir applies at all (Windows
    // only), that is the file the installed build reads, whether it exists yet or
    // not, so a first write has to land there. Returning the canonical path here
    // would write a config into `~/.hermes` that Hermes never looks at, which reads
    // to the user as "Toolport said it connected and nothing happened".
    match local_data {
        Some(local) => local.join("hermes").join("config.yaml"),
        None => canonical,
    }
}

fn continue_path() -> Option<PathBuf> {
    client_config_path("continue")
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
            path: || client_config_path("cursor"),
            plugin_scan: Some(scan_cursor_plugins),
        },
        ClientDef {
            id: "droid",
            name: "Factory Droid",
            format: Format::JsonDroidMcpServers,
            uses_connectors: false,
            path: || client_config_path("droid"),
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
            path: || client_config_path("anythingllm"),
            plugin_scan: None,
        },
        ClientDef {
            id: "vscode",
            name: "VS Code",
            format: Format::JsonServers,
            uses_connectors: false,
            path: || client_config_path("vscode"),
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
            name: "Devin Desktop (Cascade)",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: || client_config_path("windsurf"),
            plugin_scan: None,
        },
        ClientDef {
            id: "devin-cli",
            name: "Devin Local / CLI",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: || client_config_path("devin-cli"),
            plugin_scan: None,
        },
        ClientDef {
            id: "opencode",
            name: "OpenCode",
            format: Format::JsonOpenCodeMcp,
            uses_connectors: false,
            // OpenCode stores its global config at the literal
            // `~/.config/opencode/opencode.json` or `opencode.jsonc` on every supported OS.
            path: || client_config_path("opencode"),
            plugin_scan: None,
        },
        ClientDef {
            id: "kilo-code",
            name: "Kilo Code",
            format: Format::JsonOpenCodeMcp,
            uses_connectors: false,
            // Kilo Code stores its global JSONC config at the literal
            // `~/.config/kilo/kilo.jsonc` on every supported OS.
            path: || client_config_path("kilo-code"),
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
            // The Codex CLI and the Codex desktop app share config.toml under
            // `CODEX_HOME` (default ~/.codex).
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
            path: || client_config_path("claude-code"),
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
            // Junie stores user-scoped MCP servers at ~/.junie/mcp/mcp.json on every
            // supported platform. Project-scoped configs are intentionally left untouched.
            path: || client_config_path("junie"),
            plugin_scan: None,
        },
        ClientDef {
            id: "cline",
            name: "Cline",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: || client_config_path("cline"),
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
            // Warp reads file-based MCP servers from `~/.warp/.mcp.json` (keyed under
            // `mcpServers`), alongside its in-app UI. The file is home-anchored on every OS.
            path: || client_config_path("warp"),
            plugin_scan: None,
        },
        ClientDef {
            id: "amazon-q",
            name: "Amazon Q",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // Amazon Q Developer CLI global MCP config: `~/.aws/amazonq/mcp.json`
            // (`mcpServers`). A per-workspace `.amazonq/mcp.json` also exists; we manage the
            // global one so the gateway is available everywhere.
            path: || client_config_path("amazon-q"),
            plugin_scan: None,
        },
        ClientDef {
            id: "kiro",
            name: "Kiro",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // Kiro user-level MCP config: `~/.kiro/settings/mcp.json` (`mcpServers`). A
            // per-workspace `.kiro/settings/mcp.json` also exists and takes precedence.
            path: || client_config_path("kiro"),
            plugin_scan: None,
        },
        ClientDef {
            id: "kimi-code",
            name: "Kimi Code",
            format: Format::JsonKimiMcpServers,
            uses_connectors: false,
            path: kimi_code_path,
            plugin_scan: None,
        },
        ClientDef {
            id: "zed",
            name: "Zed",
            format: Format::JsonContextServers,
            uses_connectors: false,
            // Zed keeps MCP ("context") servers in its main settings.json (JSONC). Windows
            // uses %APPDATA%\Zed; macOS and Linux use ~/.config/zed (not App Support). The
            // parent dir is created on install, so the default presence heuristic works.
            path: || client_config_path("zed"),
            plugin_scan: None,
        },
        ClientDef {
            id: "lm-studio",
            name: "LM Studio",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // LM Studio reads MCP servers from `~/.lmstudio/mcp.json` (`mcpServers`, plain
            // JSON). The file is created by LM Studio, so the parent-dir presence check works.
            path: || client_config_path("lm-studio"),
            plugin_scan: None,
        },
        ClientDef {
            id: "jan",
            name: "Jan",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // Jan keeps MCP servers in mcp_config.json (standard `mcpServers` shape) inside
            // its data folder, `<data_dir>/Jan/data` on every OS (e.g. %APPDATA%\Jan\data on
            // Windows, ~/Library/Application Support/Jan/data on macOS). Jan creates the
            // folder and a default config on first launch, so the parent-dir check detects it.
            path: || client_config_path("jan"),
            plugin_scan: None,
        },
        ClientDef {
            id: "boltai",
            name: "BoltAI",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            path: || client_config_path("boltai"),
            plugin_scan: None,
        },
        ClientDef {
            id: "pi",
            name: "Pi",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // Pi coding agent reads its Pi-owned global MCP config from ~/.pi/agent/mcp.json
            // (standard `mcpServers` shape; pi's optional `lifecycle`/`idleTimeout` keys are
            // left unset so it uses its defaults). Home-anchored, identical on every OS.
            path: || client_config_path("pi"),
            plugin_scan: None,
        },
        ClientDef {
            id: "omp",
            name: "Oh My Pi",
            format: Format::JsonMcpServers,
            uses_connectors: false,
            // Oh My Pi (omp) is a fork of Pi with its own config directory (~/.omp).
            // Same `mcpServers` JSON format as Pi; home-anchored, identical on every OS.
            path: || client_config_path("omp"),
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
            // Witsy keeps MCP servers in a top-level `mcpServers` object inside its main
            // settings.json (alongside all other app settings), in the Claude-compatible
            // `{command, args, env}` shape. Electron's userData dir is "Witsy" on every OS:
            // ~/Library/Application Support/Witsy on macOS, %APPDATA%\Witsy on Windows,
            // ~/.config/Witsy on Linux. Confirmed against the app's own source
            // (src/main/mcp.ts reads/writes config.mcpServers directly) and the project's
            // file-location wiki page.
            path: || client_config_path("witsy"),
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
    // `type` is the common hint key (VS Code, Droid); Kimi Code marks legacy
    // SSE endpoints with `transport: "sse"` instead. Both mean the same thing
    // anywhere they appear, so either keys the hint.
    // Kimi Code's `bearerTokenEnvVar` names a shell env var holding the token
    // (the value never sits in the file). Surface the var NAME as a value-less
    // env key so import vaults the token and remote connects send it as
    // `Authorization: Bearer` (see `remote::first_vaulted_secret`).
    if let Some(var) = def.get("bearerTokenEnvVar").and_then(|v| v.as_str()) {
        if !var.is_empty() && !env.iter().any(|e| e.key == var) {
            env.push(SnippetEnvVar {
                key: var.to_string(),
                value: None,
            });
        }
    }
    let type_hint = def
        .get("type")
        .or_else(|| def.get("transport"))
        .and_then(|t| t.as_str());
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
    // `.bat` belongs here too: a Node install can put `npx.bat` on PATH, and omitting it
    // made launcher_package_arg return None, so two servers running different packages
    // under one display name collapsed to a single import (and a bare paste got named
    // "npx"). `launcher::command_base` already strips all four for the same role.
    for ext in [".exe", ".cmd", ".bat", ".ps1"] {
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

    let path = match resolved_definition_path(def) {
        Ok(path) => path,
        Err(error) => {
            let fallback = (def.path)();
            let config_path = fallback
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let config_exists = fallback.as_ref().is_some_and(|path| path.exists());
            return build(config_path, config_exists, Vec::new(), Some(error));
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
        Format::JsonKimiMcpServers => parse_json(&content, "mcpServers"),
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
    // A command that differs only by *which of our gateway binaries* it names is
    // path drift, not a user taking the entry over.
    //
    // Requiring byte equality here made the ownership record a trap: anything that
    // rewrote the path out from under it - a republish under a content-addressed
    // filename, a data-dir move, a support fix applied by hand - silently
    // reclassified the entry as Customized, and `repoint_stale_gateways` skips
    // Customized entries. The client was then abandoned on whatever binary it
    // happened to hold, permanently, and the only evidence was an eprintln the
    // desktop app writes to a stderr nobody reads.
    //
    // Issue #487 is preserved exactly: an entry repointed at npx / docker / a
    // wrapper script fails `command_is_gateway_binary` and is still Customized.
    // Only the "still ours, different path" case is forgiven, and args/env/url
    // below stay byte-strict so a genuine customization anywhere else still counts.
    if cmd != rec.command
        && !(command_is_gateway_binary(cmd) && command_is_gateway_binary(&rec.command))
    {
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
    /// Clients that needed a re-point and could not be written, with the reason.
    ///
    /// Previously an `install_gateway` error here was dropped on the floor by an
    /// `if let Ok(..)`, which made a client that failed to migrate look exactly
    /// like one that never needed to - no log line, no retry, no surface in the
    /// UI. Six clients on this developer's machine sat on a superseded gateway
    /// for days with nothing anywhere recording why.
    pub failed: Vec<(String, String)>,
    /// Claude Code configs other than the one Toolport resolves, repaired by
    /// [`repoint_other_claude_configs`]. Paths rather than client ids, because they
    /// all belong to the same `claude-code` client and carry no ownership record of
    /// their own - the registry keys ownership by client id, and a sibling must not
    /// overwrite the resolved config's snapshot.
    pub extra_claude_repointed: Vec<PathBuf>,
    /// Sibling Claude configs that needed a repair and could not be written.
    pub extra_claude_failed: Vec<(PathBuf, String)>,
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
    let name = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("config");
    backup_file_named(client_id, path, name)
}

fn backup_file_named(
    client_id: &str,
    path: &Path,
    backup_name: &str,
) -> Result<Option<PathBuf>, String> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_CONFIG_BYTES => {}
        // Genuinely missing: nothing to back up yet, and the caller may create
        // the file from scratch. Special file or oversized: deliberately nothing
        // safe to back up (kept from the original behaviour).
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // A stat that failed for any other reason (permission, network share,
        // transient I/O) must NOT read as "no file here": the caller would then
        // treat the config as absent, start from an empty document, and overwrite
        // the user's real file with no backup to recover it.
        Err(e) => {
            return Err(format!(
                "could not stat {} before backing it up: {e}",
                path.display()
            ))
        }
    }
    let dir = backup_dir(client_id).ok_or("Could not resolve backup dir")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut stamp = epoch_millis();
    let dest = loop {
        let candidate = dir.join(format!("{stamp}-{backup_name}"));
        if !candidate.exists() {
            break candidate;
        }
        stamp += 1;
    };
    std::fs::copy(path, &dest).map_err(|e| e.to_string())?;
    prune_backups(&dir, backup_name);
    Ok(Some(dest))
}

/// Secondary Claude configs all share the `.claude.json` basename and client id.
/// Give each full path a stable backup identity so profiles cannot overwrite or prune
/// one another's recovery copies.
fn backup_secondary_claude_file(path: &Path) -> Result<Option<PathBuf>, String> {
    backup_file_named("claude-code", path, &secondary_claude_backup_name(path))
}

fn secondary_claude_backup_name(path: &Path) -> String {
    let digest = crate::registry::sha256_hex(&path.to_string_lossy());
    format!("claude-{}.json", &digest[..16])
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

/// Kimi Code treats a bare `url` entry as streamable HTTP and needs an explicit
/// `transport: "sse"` on legacy SSE endpoints; it ignores the `type` hint
/// `entry_to_json` emits, which would silently downgrade an SSE server to HTTP.
fn entry_to_kimi_json(entry: &ServerEntry) -> serde_json::Value {
    let mut value = entry_to_json(entry);
    if entry.command.is_none() {
        let object = value.as_object_mut().unwrap();
        object.remove("type");
        if entry.transport.eq_ignore_ascii_case("sse") {
            object.insert("transport".into(), serde_json::Value::String("sse".into()));
        }
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

    let root = CstRootNode::parse(original, &ParseOptions::default()).map_err(|e| e.to_string())?;
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

    let root = CstRootNode::parse(original, &ParseOptions::default()).map_err(|e| e.to_string())?;
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

/// Delete a single top-level property from `original` JSON/JSONC text, preserving
/// comments, trailing commas, and the formatting of everything else.
///
/// The counterpart to [`rewrite_json_key_preserving`], and needed for the same reason:
/// that function can only set or append, so a caller removing a managed key would
/// otherwise fall through to a pretty-print that silently strips the user's comments
/// from the whole file. Uninstalling a feature must not cost someone their annotations.
///
/// Removing a key that is not there is success, not an error: the outcome is what the
/// caller asked for.
fn remove_json_key_preserving(original: &str, key: &str) -> Result<String, String> {
    use jsonc_parser::cst::CstRootNode;
    use jsonc_parser::ParseOptions;

    let root = CstRootNode::parse(original, &ParseOptions::default()).map_err(|e| e.to_string())?;
    let Some(obj) = root.object_value() else {
        return Err("JSONC root is not an object".into());
    };
    let n = count_top_level_key(&obj, key);
    if n > 1 {
        return Err(format!(
            "malformed config: top-level key '{key}' appears {n} times; refusing to write"
        ));
    }
    if let Some(prop) = obj.get(key) {
        prop.remove();
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
    atomic_write(path, &render_json_config(original, root, changed_key)?)
}

/// The rendering half of [`atomic_write_json_config`], so a dry run can show the exact
/// bytes without writing them.
fn render_json_config(
    original: Option<&str>,
    root: &serde_json::Value,
    changed_key: &str,
) -> Result<String, String> {
    let pretty = || serde_json::to_string_pretty(root).map_err(|e| e.to_string());

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
    Ok(out)
}

/// Convert a `toml::Value` into a `toml_edit::Item` so we can splice a rewritten
/// `mcp_servers` table into an existing DocumentMut without losing comments on
/// every other key (SBS-884).
fn toml_value_to_item(value: &toml::Value) -> toml_edit::Item {
    use toml_edit::{Item, Table};
    match value {
        toml::Value::Table(map) => {
            let mut table = Table::new();
            for (k, v) in map {
                table.insert(k, toml_value_to_item(v));
            }
            Item::Table(table)
        }
        other => Item::Value(toml_value_to_edit_value(other)),
    }
}

/// Value-level counterpart of [`toml_value_to_item`]. A nested table inside an
/// array has to become an inline table: a standard `Item::Table` is not an
/// `Item::Value`, so an array-of-tables would otherwise be dropped silently.
fn toml_value_to_edit_value(value: &toml::Value) -> toml_edit::Value {
    use toml_edit::{Array, InlineTable, Value};
    match value {
        toml::Value::String(s) => Value::from(s.as_str()),
        toml::Value::Integer(i) => Value::from(*i),
        toml::Value::Float(f) => Value::from(*f),
        toml::Value::Boolean(b) => Value::from(*b),
        toml::Value::Datetime(dt) => match dt.to_string().parse::<toml_edit::Datetime>() {
            Ok(parsed) => Value::from(parsed),
            Err(_) => Value::from(dt.to_string()),
        },
        toml::Value::Array(items) => {
            let mut array = Array::new();
            for item in items {
                array.push(toml_value_to_edit_value(item));
            }
            Value::Array(array)
        }
        toml::Value::Table(map) => {
            let mut inline = InlineTable::new();
            for (k, v) in map {
                inline.insert(k, toml_value_to_edit_value(v));
            }
            Value::InlineTable(inline)
        }
    }
}

/// Load a TOML config as a comment-preserving DocumentMut. An unparseable
/// non-empty file is an error (same fail-closed contract as `read_existing_toml`)
/// so we never replace Codex/Grok `config.toml` with a pretty-printed stub.
fn load_toml_document(path: &Path) -> Result<toml_edit::DocumentMut, String> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let content = read_config_file(path)?;
    // Keep the toml 0.8 parse as the public error gate so existing tests and
    // callers still see "Could not parse the existing config".
    read_existing_toml(&content)?;
    if content.trim().is_empty() {
        return Ok(toml_edit::DocumentMut::new());
    }
    content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("Could not parse the existing config ({e}); leaving it untouched."))
}

/// Guarantee `item` is a standard table. Inline tables and non-table values
/// (a corrupt-but-parseable `mcp_servers = "..."`) become an empty table, matching
/// the previous `toml::Value` path that replaced a non-table with `Table::new()`.
fn ensure_toml_table(item: &mut toml_edit::Item) -> &mut toml_edit::Table {
    use toml_edit::{Item, Table};
    if item.as_table().is_some() {
        return item.as_table_mut().unwrap();
    }
    let converted = item.as_inline_table().map(|inline| {
        let mut table = Table::new();
        for (k, val) in inline.iter() {
            table.insert(k, Item::Value(val.clone()));
        }
        table
    });
    *item = Item::Table(converted.unwrap_or_default());
    item.as_table_mut().unwrap()
}

fn toml_mcp_servers_mut(doc: &mut toml_edit::DocumentMut) -> &mut toml_edit::Table {
    ensure_toml_table(&mut doc["mcp_servers"])
}

/// Does the document already carry an explicit `[mcp_servers]` header with a
/// `#` comment on it? An implicit table emits no header line, so making the
/// table implicit would throw that comment away, the exact loss this path exists
/// to prevent (SBS-884). Files with a bare header keep the old collapsed
/// `[mcp_servers.name]` shape.
fn toml_keeps_servers_header(doc: &toml_edit::DocumentMut) -> bool {
    let Some(table) = doc.get("mcp_servers").and_then(|item| item.as_table()) else {
        return false;
    };
    if table.is_implicit() {
        return false;
    }
    let decor = table.decor();
    [decor.prefix(), decor.suffix()]
        .into_iter()
        .flatten()
        .filter_map(|raw| raw.as_str())
        .any(|text| text.contains('#'))
}

/// Line-scan state for locating top-level YAML mapping keys without expanding
/// anchors or dropping comments outside the rewritten node (SBS-884).
#[derive(Default)]
struct YamlLineState {
    in_double: bool,
    in_single: bool,
    escape: bool,
    flow_depth: i32,
    /// Indent of the key that opened a `|` / `>` block scalar. Lines indented
    /// further belong to the scalar, so a nested `extensions:` must not look
    /// like a top-level key.
    block_scalar_indent: Option<usize>,
}

/// Byte length of a line's YAML indentation.
///
/// Bytes, not characters, because callers use the result as a slice index.
/// `char::is_whitespace` also matches multi-byte whitespace such as U+00A0 and
/// U+3000, so a character count is smaller than the byte offset of the first
/// content byte and the slice lands mid-character (panic). Only space and tab
/// count: YAML indents with spaces, and everything else is content.
fn yaml_leading_indent(line: &str) -> usize {
    line.bytes()
        .take_while(|b| *b == b' ' || *b == b'\t')
        .count()
}

fn yaml_is_doc_marker(line: &str) -> bool {
    let t = line.trim_end();
    t == "---"
        || t == "..."
        || t.starts_with("--- ")
        || t.starts_with("---\t")
        || t.starts_with("---#")
        || t.starts_with("... ")
        || t.starts_with("...\t")
        || t.starts_with("...#")
}

fn yaml_is_seq_item(line: &str) -> bool {
    let t = line.trim_start();
    t == "-"
        || t.starts_with("- ")
        || t.starts_with("-\t")
        || t.starts_with("-[")
        || t.starts_with("-{")
}

fn yaml_is_block_scalar_header(s: &str) -> bool {
    let b = s.as_bytes();
    if !matches!(b.first(), Some(b'|' | b'>')) {
        return false;
    }
    let mut i = 1;
    while i < b.len() && matches!(b[i], b'+' | b'-' | b'0'..=b'9') {
        i += 1;
    }
    i == b.len() || b[i].is_ascii_whitespace() || b[i] == b'#'
}

/// Skip YAML `&anchor`, `*alias`, and `!tag` prefixes that can sit between `:`
/// and the real value (`key: &foo |`, `key: !!str bar`).
fn yaml_skip_value_prefixes(s: &str) -> &str {
    let mut rest = s.trim_start();
    loop {
        if rest.starts_with('&') || rest.starts_with('*') || rest.starts_with('!') {
            let token_end = rest
                .find(|c: char| {
                    c.is_whitespace()
                        || c == '#'
                        || c == ','
                        || c == '{'
                        || c == '['
                        || c == '}'
                        || c == ']'
                })
                .unwrap_or(rest.len());
            if token_end == 0 {
                return rest;
            }
            rest = rest[token_end..].trim_start();
            continue;
        }
        return rest;
    }
}

/// The `&anchor` token defined on a value, if any (`key: &exts`, `key: !!map &exts`).
/// Returned with its `&` so a rewrite can re-emit it verbatim.
fn yaml_value_anchor(s: &str) -> Option<&str> {
    let mut rest = s.trim_start();
    loop {
        if !rest.starts_with('&') && !rest.starts_with('!') {
            return None;
        }
        let token_end = rest
            .find(|c: char| {
                c.is_whitespace()
                    || c == '#'
                    || c == ','
                    || c == '{'
                    || c == '['
                    || c == '}'
                    || c == ']'
            })
            .unwrap_or(rest.len());
        if token_end <= 1 {
            return None;
        }
        let token = &rest[..token_end];
        if token.starts_with('&') {
            return Some(token);
        }
        rest = rest[token_end..].trim_start();
    }
}

fn yaml_scan_chars(state: &mut YamlLineState, text: &str) {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if state.in_double {
            if state.escape {
                state.escape = false;
            } else if c == '\\' {
                state.escape = true;
            } else if c == '"' {
                state.in_double = false;
            }
            i += 1;
            continue;
        }
        if state.in_single {
            if c == '\'' {
                if i + 1 < chars.len() && chars[i + 1] == '\'' {
                    i += 2;
                    continue;
                }
                state.in_single = false;
            }
            i += 1;
            continue;
        }
        if c == '#' {
            break;
        }
        if c == '"' {
            state.in_double = true;
            i += 1;
            continue;
        }
        if c == '\'' {
            state.in_single = true;
            i += 1;
            continue;
        }
        if c == '{' || c == '[' {
            state.flow_depth += 1;
            i += 1;
            continue;
        }
        if (c == '}' || c == ']') && state.flow_depth > 0 {
            state.flow_depth -= 1;
            i += 1;
            continue;
        }
        i += 1;
    }
}

fn yaml_scan_after_colon(state: &mut YamlLineState, rest: &str, key_indent: usize) {
    let rest = yaml_skip_value_prefixes(rest);
    if yaml_is_block_scalar_header(rest) {
        state.block_scalar_indent = Some(key_indent);
        return;
    }
    yaml_scan_chars(state, rest);
}

fn yaml_unquote_double(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Split a YAML mapping line into (unquoted key, text after `:`). Returns
/// `None` for comments, document markers, and sequence items.
fn split_yaml_mapping_key(line: &str) -> Option<(String, &str)> {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty()
        || line.starts_with('#')
        || yaml_is_doc_marker(line)
        || yaml_is_seq_item(line)
    {
        return None;
    }
    let bytes = line.as_bytes();
    if bytes.first() == Some(&b'"') {
        let mut i = 1;
        let mut escape = false;
        while i < bytes.len() {
            if escape {
                escape = false;
                i += 1;
                continue;
            }
            if bytes[i] == b'\\' {
                escape = true;
                i += 1;
                continue;
            }
            if bytes[i] == b'"' {
                let key = yaml_unquote_double(&line[1..i]);
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    return Some((key, &line[j + 1..]));
                }
                return None;
            }
            i += 1;
        }
        return None;
    }
    if bytes.first() == Some(&b'\'') {
        let mut i = 1;
        while i < bytes.len() {
            if bytes[i] == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                let key = line[1..i].replace("''", "'");
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b':' {
                    return Some((key, &line[j + 1..]));
                }
                return None;
            }
            i += 1;
        }
        return None;
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            let after = i + 1;
            if after == bytes.len() || bytes[after].is_ascii_whitespace() || bytes[after] == b'#' {
                let key = line[..i].trim();
                if key.is_empty() {
                    return None;
                }
                return Some((key.to_string(), &line[after..]));
            }
        }
        i += 1;
    }
    None
}

/// Locate each top-level block-mapping key and the byte span of its value.
/// Column-0 comments, `---` markers, and keys inside `|`/`>` scalars are not keys.
fn top_level_yaml_key_spans(src: &str) -> Vec<(String, usize, usize)> {
    let (bom_len, src) = match src.strip_prefix('\u{feff}') {
        Some(rest) => ('\u{feff}'.len_utf8(), rest),
        None => (0, src),
    };
    let mut spans = Vec::new();
    let mut state = YamlLineState::default();
    let mut current: Option<(String, usize)> = None;
    let mut last_value_end = 0usize;
    let mut offset = 0usize;
    for line in src.split_inclusive('\n') {
        let line_start = offset;
        offset += line.len();
        let line_end = offset;
        let stripped = line.trim_end_matches(['\n', '\r']);
        let indent = yaml_leading_indent(stripped);
        let content = &stripped[indent.min(stripped.len())..];
        let at_col0 = indent == 0 && !content.is_empty();

        if let Some(parent_indent) = state.block_scalar_indent {
            if !content.is_empty() && indent <= parent_indent {
                state.block_scalar_indent = None;
            } else {
                last_value_end = line_end;
                continue;
            }
        }

        if state.in_double || state.in_single || state.flow_depth > 0 {
            yaml_scan_chars(&mut state, stripped);
            last_value_end = line_end;
            continue;
        }

        if content.is_empty() {
            continue;
        }

        if at_col0 && content.starts_with('#') {
            if let Some((k, start)) = current.take() {
                spans.push((k, start, last_value_end.max(start)));
            }
            continue;
        }
        if at_col0 && yaml_is_doc_marker(content) {
            if let Some((k, start)) = current.take() {
                spans.push((k, start, last_value_end.max(start)));
            }
            continue;
        }
        if at_col0 {
            if let Some((key, rest)) = split_yaml_mapping_key(content) {
                if let Some((k, start)) = current.take() {
                    spans.push((k, start, last_value_end.max(start)));
                }
                current = Some((key, line_start));
                last_value_end = line_end;
                yaml_scan_after_colon(&mut state, rest, 0);
                continue;
            }
            if yaml_is_seq_item(content) {
                last_value_end = line_end;
                yaml_scan_chars(&mut state, stripped);
                continue;
            }
        }

        last_value_end = line_end;
        if let Some((_, rest)) = split_yaml_mapping_key(content) {
            yaml_scan_after_colon(&mut state, rest, indent);
        } else {
            yaml_scan_chars(&mut state, stripped);
        }
    }
    if let Some((k, start)) = current {
        spans.push((k, start, last_value_end.max(start)));
    }
    spans
        .into_iter()
        .map(|(k, start, end)| (k, start + bom_len, end + bom_len))
        .collect()
}

fn count_top_level_yaml_key(src: &str, key: &str) -> usize {
    top_level_yaml_key_spans(src)
        .into_iter()
        .filter(|(k, _, _)| k == key)
        .count()
}

/// Reject duplicate top-level occurrences of `key` in YAML text.
///
/// Duplicate keys are ambiguous: a span rewrite only replaces the first, so a
/// later effective entry can stay stale. Callers must not fall back to
/// `serde_yaml::to_string` when this fails — the file must remain unchanged
/// (SBS-884, matching #555).
fn reject_duplicate_top_level_yaml_key(original: &str, key: &str) -> Result<(), String> {
    let n = count_top_level_yaml_key(original, key);
    if n > 1 {
        return Err(format!(
            "malformed config: top-level key '{key}' appears {n} times; refusing to write"
        ));
    }
    Ok(())
}

/// Indentation the replacement block should give the key's children, taken from
/// the node already in the file so a 4-space config does not get one node
/// reformatted to serde_yaml's 2 spaces (SBS-884 review). `span` is the existing
/// text of the key, first line included. Levels below the first keep
/// serde_yaml's own step: re-indenting emitted text per level would break
/// sequence-item alignment and block-scalar content.
fn yaml_child_indent(span: &str) -> String {
    const DEFAULT: &str = "  ";
    for line in span.split_inclusive('\n').skip(1) {
        let stripped = line.trim_end_matches(['\n', '\r']);
        let indent = yaml_leading_indent(stripped);
        let content = &stripped[indent..];
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let ws = &stripped[..indent];
        // A tab never indents valid YAML, and a 0-indent child is a sequence
        // written at the parent's column, which a mapping cannot reuse.
        if (1..=8).contains(&ws.len()) && ws.bytes().all(|b| b == b' ') {
            return ws.to_string();
        }
        break;
    }
    DEFAULT.to_string()
}

/// Render `key: <value>` as a YAML block (mapping/sequence nested under the key).
/// `anchor` is re-emitted on the key line when the key being replaced defined one.
fn format_yaml_key_block(
    key: &str,
    value: &serde_yaml::Value,
    anchor: Option<&str>,
    indent: &str,
) -> Result<String, String> {
    let head = match anchor {
        Some(anchor) => format!("{key}: {anchor}"),
        None => format!("{key}:"),
    };
    match value {
        serde_yaml::Value::Mapping(_) | serde_yaml::Value::Sequence(_) => {
            let body = serde_yaml::to_string(value).map_err(|e| e.to_string())?;
            let body = body.trim_end_matches('\n');
            if body.is_empty() || body == "{}" || body == "[]" {
                return Ok(format!("{head} {body}\n"));
            }
            let mut out = format!("{head}\n");
            for line in body.lines() {
                if line.is_empty() {
                    out.push('\n');
                } else {
                    out.push_str(indent);
                    out.push_str(line);
                    out.push('\n');
                }
            }
            Ok(out)
        }
        serde_yaml::Value::Null => Ok(format!("{head} null\n")),
        other => {
            let body = serde_yaml::to_string(other).map_err(|e| e.to_string())?;
            Ok(format!("{head} {}\n", body.trim()))
        }
    }
}

/// Rewrite a single top-level mapping key in `original` YAML text, preserving
/// comments, anchors, aliases, and formatting of everything else. Used so
/// Goose/Hermes/Continue Connect no longer strips user annotations (SBS-884).
///
/// Fails if `key` appears more than once at the top level (ambiguous rewrite).
fn rewrite_yaml_key_preserving(
    original: &str,
    key: &str,
    new_value: &serde_yaml::Value,
) -> Result<String, String> {
    let spans = top_level_yaml_key_spans(original);
    let hits: Vec<&(String, usize, usize)> = spans.iter().filter(|(k, _, _)| k == key).collect();
    if hits.len() > 1 {
        return Err(format!(
            "malformed config: top-level key '{key}' appears {} times; refusing to write",
            hits.len()
        ));
    }
    if let Some((_, start, end)) = hits.first() {
        let span = &original[*start..*end];
        // An anchor defined on this key is referenced by `*alias` elsewhere in the
        // file. Replacing the key line without it leaves every alias undefined and
        // the config no longer parses, so carry it onto the replacement (SBS-884).
        // A tag on the key line is dropped on purpose: it described the value we
        // are replacing, not the new one.
        let anchor = split_yaml_mapping_key(span.lines().next().unwrap_or_default())
            .and_then(|(_, rest)| yaml_value_anchor(rest));
        let block = format_yaml_key_block(key, new_value, anchor, &yaml_child_indent(span))?;
        let mut out = String::with_capacity(original.len() + block.len());
        out.push_str(&original[..*start]);
        out.push_str(&block);
        out.push_str(&original[*end..]);
        Ok(out)
    } else {
        let block = format_yaml_key_block(key, new_value, None, "  ")?;
        let mut out = original.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&block);
        Ok(out)
    }
}

/// Serialize `root` for disk. When `original` is present, surgically rewrite
/// only `changed_key` so comments and YAML anchors outside that key survive.
/// Pretty-print is used only for new/empty files — an existing parseable file
/// is never replaced with a full `serde_yaml::to_string` dump (that is SBS-884).
///
/// Duplicate top-level keys for `changed_key` are a hard error (no pretty fallback)
/// so the existing file is left untouched.
fn atomic_write_yaml_config(
    path: &Path,
    original: Option<&str>,
    root: &serde_yaml::Value,
    changed_key: &str,
) -> Result<(), String> {
    let pretty = || serde_yaml::to_string(root).map_err(|e| e.to_string());

    let out = match (original, root.get(changed_key)) {
        (Some(src), Some(val)) if !src.trim().is_empty() => {
            reject_duplicate_top_level_yaml_key(src, changed_key)?;
            rewrite_yaml_key_preserving(src, changed_key, val)?
        }
        _ => pretty()?,
    };
    atomic_write(path, &out)
}

fn parse_existing_yaml_content(content: &str) -> Result<serde_yaml::Value, String> {
    if content.trim().is_empty() {
        return Ok(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    }
    serde_yaml::from_str(content).map_err(|e| {
        format!("Could not parse the existing config.yaml ({e}); leaving it untouched.")
    })
}

/// Read an existing YAML config and keep the original text so the write can
/// surgically replace one key instead of pretty-printing the whole file.
fn read_existing_yaml_with_source(
    path: &Path,
) -> Result<(Option<String>, serde_yaml::Value), String> {
    if !path.exists() {
        return Ok((None, serde_yaml::Value::Mapping(serde_yaml::Mapping::new())));
    }
    let content = read_config_file(path)?;
    let value = parse_existing_yaml_content(&content)?;
    Ok((Some(content), value))
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
    if object
        .get("mcp")
        .is_some_and(|servers| !servers.is_object())
    {
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
    write_json_with(
        path,
        "mcpServers",
        servers,
        false,
        entry_to_json,
        false,
        true,
    )
}

fn write_droid_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    write_json_with(
        path,
        "mcpServers",
        servers,
        false,
        entry_to_droid_json,
        false,
        false,
    )
}

/// Kimi Code's `mcp.json` is MCP-only (app settings live in config.toml).
/// `read_existing_json` ignores the lenient flag and always errors on a parse
/// failure; pass `true` anyway to match Qwen, the closest analogue.
fn write_kimi_json(path: &Path, servers: &[ServerEntry]) -> Result<(), String> {
    write_json_with(
        path,
        "mcpServers",
        servers,
        true,
        entry_to_kimi_json,
        false,
        false,
    )
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
                value
                    .as_object_mut()
                    .unwrap()
                    .insert("tools".into(), serde_json::json!(["*"]));
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
    let mut doc = load_toml_document(path)?;
    let keep_header = toml_keeps_servers_header(&doc);
    // Carry the old header's comments and blank lines onto the rebuilt table.
    let decor = doc
        .get("mcp_servers")
        .and_then(|item| item.as_table())
        .map(|table| table.decor().clone());
    let mut servers_table = toml_edit::Table::new();
    if let Some(decor) = decor {
        *servers_table.decor_mut() = decor;
    }
    if !servers.is_empty() && !keep_header {
        // Implicit so we emit `[mcp_servers.name]` rather than a `[mcp_servers]`
        // wrapper, the same shape Codex already ships.
        servers_table.set_implicit(true);
    }
    for s in servers {
        servers_table.insert(&s.name, toml_value_to_item(&entry_to_toml(s)));
    }
    doc["mcp_servers"] = toml_edit::Item::Table(servers_table);
    atomic_write(path, &doc.to_string())
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
    let (original, mut root) = read_existing_yaml_with_source(path)?;
    let exts = yaml_extensions_mut(&mut root);
    // Replace only definitions Toolport can actually import as MCP servers.
    // Goose builtins/platform extensions and unknown shapes share this map but
    // have no inventory representation, so clearing the map silently deletes
    // functionality during migration.
    exts.retain(|_, definition| {
        let Some(mapping) = definition.as_mapping() else {
            return true;
        };
        let extension_type = mapping.get("type").and_then(|value| value.as_str());
        if matches!(extension_type, Some("builtin" | "platform")) {
            return true;
        }
        let has_command = mapping
            .get("cmd")
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.is_empty());
        let has_url = mapping
            .get("url")
            .and_then(|value| value.as_str())
            .is_some_and(|value| !value.is_empty());
        !has_command && !has_url
    });
    for s in servers {
        exts.insert(
            serde_yaml::Value::String(s.name.clone()),
            entry_to_goose_yaml(s),
        );
    }
    atomic_write_yaml_config(path, original.as_deref(), &root, "extensions")
}

fn edit_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    let (original, mut root) = read_existing_yaml_with_source(path)?;
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
    atomic_write_yaml_config(path, original.as_deref(), &root, "extensions")
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
    let (original, mut root) = read_existing_yaml_with_source(path)?;

    let list = continue_servers_mut(&mut root);

    list.clear();

    for server in servers {
        list.push(entry_to_continue_yaml(server));
    }

    atomic_write_yaml_config(path, original.as_deref(), &root, "mcpServers")
}

fn edit_continue_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    let (original, mut root) = read_existing_yaml_with_source(path)?;

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

    atomic_write_yaml_config(path, original.as_deref(), &root, "mcpServers")
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
    let (original, mut root) = read_existing_yaml_with_source(path)?;
    let mcp_servers = hermes_mcp_servers_mut(&mut root);
    mcp_servers.clear();
    for entry in servers {
        let name_val = serde_yaml::Value::String(entry.name.clone());
        mcp_servers.insert(name_val, entry_to_hermes_yaml(entry));
    }
    atomic_write_yaml_config(path, original.as_deref(), &root, "mcp_servers")
}

fn edit_hermes_yaml_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    let (original, mut root) = read_existing_yaml_with_source(path)?;
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
    atomic_write_yaml_config(path, original.as_deref(), &root, "mcp_servers")
}

/// Write a server set into a client's config, backing up the existing file first
/// and preserving any unrelated top-level keys.
pub fn write_servers(client_id: &str, servers: &[ServerEntry]) -> Result<WriteOutcome, String> {
    let def = find_def(client_id).ok_or_else(|| format!("Unknown client '{client_id}'"))?;
    let path = resolved_definition_path(&def)?;
    let backup = backup_file(client_id, &path)?;
    let lenient = config_is_whole_app_state(client_id);
    match def.format {
        Format::JsonMcpServers => write_json(&path, "mcpServers", servers, lenient)?,
        Format::JsonCopilotMcpServers => write_copilot_json(&path, servers)?,
        Format::JsonDroidMcpServers => write_droid_json(&path, servers)?,
        Format::JsonAmpMcpServers => write_json(&path, "amp.mcpServers", servers, true)?,
        Format::JsonQwenMcpServers => write_qwen_json(&path, servers)?,
        Format::JsonKimiMcpServers => write_kimi_json(&path, servers)?,
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
    resolve_gateway_sidecar()
}

/// [`resolve_gateway_path`] with every side effect removed: no publish of the bundled
/// gateway, no AppImage stable copy, and no optimistic "here is where it would be"
/// fallback. Returns a path only when that exact file exists right now.
///
/// For callers that must not write, which is narrower than it sounds: publishing copies
/// a versioned binary into the data dir and writes a manifest, and the AppImage path
/// copies a binary, so a read-only view or a dry run that used the normal resolver
/// would create files as a side effect of rendering (SBS-822 review).
pub(crate) fn resolve_gateway_path_readonly() -> Option<PathBuf> {
    if let Some(p) = crate::gateway_publish::published_gateway_path() {
        return Some(p);
    }
    // A missing/corrupt manifest does not mean the matching published image is gone.
    // Select it by the same source digest as publication before falling back to a
    // sidecar, so preview and apply agree without writing a manifest during preview.
    if let Some(p) = crate::gateway_publish::existing_publish_destination() {
        return Some(p);
    }
    // An AppImage's in-mount binary is the wrong answer: it dies with the mount. Only
    // an existing stable copy counts, and making one is a write.
    if std::env::var_os("APPIMAGE").is_some() {
        let dest_dir = crate::registry::conduit_dir()?.join("bin");
        let ext = std::env::consts::EXE_SUFFIX;
        return ["toolport-gateway", "conduit-gateway"]
            .into_iter()
            .map(|name| dest_dir.join(format!("{name}{ext}")))
            .find(|p| p.is_file());
    }
    resolve_gateway_sidecar().filter(|p| p.is_file())
}

/// The gateway that ships beside the app binary, for when nothing has been published.
fn resolve_gateway_sidecar() -> Option<PathBuf> {
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
/// source size or content differs (e.g. after an app update that rebuilt the
/// gateway at the same byte length). Returns the stable path.
fn stable_gateway_copy(src: &std::path::Path) -> Option<PathBuf> {
    let dest_dir = crate::registry::conduit_dir()?.join("bin");
    std::fs::create_dir_all(&dest_dir).ok()?;
    // Keep the source's filename so the stable copy matches whichever binary name
    // (toolport-gateway, or the legacy conduit-gateway) was found next to the app.
    let dest = dest_dir.join(src.file_name()?);
    stable_gateway_copy_with(src, dest, replace_gateway_copy)
}

/// Refresh logic for [`stable_gateway_copy`], with the write step injected so
/// tests can exercise the failure path without needing a genuinely busy binary.
fn stable_gateway_copy_with(
    src: &std::path::Path,
    dest: PathBuf,
    replace: impl Fn(&std::path::Path, &std::path::Path) -> std::io::Result<()>,
) -> Option<PathBuf> {
    if !gateway_copy_is_stale(src, &dest) {
        return Some(dest);
    }
    if replace(src, &dest).is_ok() {
        return Some(dest);
    }
    // The refresh failed, but an earlier stable copy is still sitting there.
    // Hand that back: a slightly stale gateway on a path that survives is far
    // better than the caller falling through to the AppImage-internal
    // /tmp/.mount_XXXX path, which is written into a client config and then
    // dies with the mount when Toolport exits. Only give up when there is no
    // stable copy at all.
    match std::fs::metadata(&dest) {
        Ok(meta) if meta.is_file() && meta.len() > 0 => Some(dest),
        _ => None,
    }
}

/// Replace `dest` with the bytes of `src`.
///
/// Deliberately not a plain `std::fs::copy`: that opens the destination
/// `O_WRONLY|O_TRUNC`, which on Linux fails with `ETXTBSY` whenever the
/// destination is a binary that is currently executing. Any connected client
/// keeps a gateway alive out of `~/.toolport/bin`, so that is the normal case,
/// not a rare one. Writing a sibling temp file and `rename(2)`-ing it over the
/// destination succeeds against a busy target (the running process keeps the
/// old inode) and swaps atomically, so a reader never sees a half-written
/// binary. The exec bit is set on the temp file *before* the rename for the
/// same reason: the path is never briefly non-executable.
fn replace_gateway_copy(src: &std::path::Path, dest: &std::path::Path) -> std::io::Result<()> {
    let dir = dest.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "gateway copy destination has no parent directory",
        )
    })?;
    let stem = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "toolport-gateway".to_string());
    let tmp = dir.join(format!(
        ".{stem}.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let written = (|| -> std::io::Result<()> {
        std::fs::copy(src, &tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp, dest)
    })();
    if written.is_err() {
        // Never leave the half-written temp file behind in ~/.toolport/bin.
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// True when dest is missing, unreadable, a different length, or the same length
/// with different bytes. Size alone is not enough: AppImage rebuilds commonly
/// keep the previous length.
fn gateway_copy_is_stale(src: &std::path::Path, dest: &std::path::Path) -> bool {
    match (std::fs::metadata(dest), std::fs::metadata(src)) {
        (Ok(d), Ok(s)) if d.is_file() && d.len() == s.len() => !files_have_same_bytes(src, dest),
        _ => true,
    }
}

/// Byte-compare two files without slurping either into memory. The gateway is a
/// multi-MB binary and this runs on every Connect plus twice at startup, so a
/// streaming compare that short-circuits on the first differing chunk beats two
/// full `std::fs::read`s. Returns false if either file cannot be read, which
/// makes the caller treat the copy as stale.
fn files_have_same_bytes(a: &std::path::Path, b: &std::path::Path) -> bool {
    use std::io::BufRead;
    let (Ok(fa), Ok(fb)) = (std::fs::File::open(a), std::fs::File::open(b)) else {
        return false;
    };
    const CHUNK: usize = 64 * 1024;
    let mut ra = std::io::BufReader::with_capacity(CHUNK, fa);
    let mut rb = std::io::BufReader::with_capacity(CHUNK, fb);
    loop {
        let consumed = {
            let (Ok(buf_a), Ok(buf_b)) = (ra.fill_buf(), rb.fill_buf()) else {
                return false;
            };
            if buf_a.is_empty() || buf_b.is_empty() {
                // Equal only if both hit EOF at the same offset.
                return buf_a.is_empty() && buf_b.is_empty();
            }
            let n = buf_a.len().min(buf_b.len());
            if buf_a[..n] != buf_b[..n] {
                return false;
            }
            n
        };
        ra.consume(consumed);
        rb.consume(consumed);
    }
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
        request_timeout_ms: None,
        unknown_fields: serde_json::Map::new(),
    })
}

/// A secondary Claude config has no distinct registry client id. Preserve its frozen
/// profile and omit `TOOLPORT_CLIENT_ID`; otherwise every secondary resolves through
/// the primary `claude-code` client scope and silently changes tool sets on repair.
fn secondary_claude_gateway_entry(profile: Option<&str>) -> Result<ServerEntry, String> {
    let mut entry = gateway_entry(profile, "claude-code")?;
    entry.env.retain(|var| var.key != crate::brand::CLIENT_ID);
    Ok(entry)
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
    // The one client whose format does not decide this. Devin Local / CLI reads
    // the plain `mcpServers` shape, but unlike the rest of that format it takes a
    // remote entry directly: its user config documents `url` plus an optional
    // `headers` object, with `transport` defaulting to http, which is exactly
    // what entry_to_json already emits for a native remote. Bridging it through
    // `npx mcp-remote` would work but would make users install a third-party
    // shim for a transport the client speaks natively.
    //
    // Devin Desktop (the `windsurf` id) is deliberately not covered: it is a
    // separate config that has not been checked for the same support, so it
    // keeps the format default.
    if client_id == "devin-cli" {
        return false;
    }
    match def.format {
        // Native remote shapes already exist in our writers.
        Format::JsonQwenMcpServers
        | Format::JsonKimiMcpServers
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
            request_timeout_ms: None,
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
            request_timeout_ms: None,
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
    edit_json_gateway_with(
        path,
        "mcpServers",
        entry,
        false,
        Some(entry_to_droid_json),
        false,
        false,
    )
}

fn edit_qwen_json_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    edit_json_gateway_with(
        path,
        "mcpServers",
        entry,
        true,
        Some(entry_to_qwen_json),
        false,
        false,
    )
}

/// Kimi requires `url` (and `transport: "sse"` on legacy SSE). The generic
/// editor used to remap remotes through `entry_to_qwen_json` (`url` → `httpUrl`)
/// whenever the map key was not VS Code `"servers"`, which Kimi rejects (SBS-921).
fn edit_kimi_json_gateway(path: &Path, entry: Option<&ServerEntry>) -> Result<(), String> {
    edit_json_gateway_with(
        path,
        "mcpServers",
        entry,
        true,
        Some(entry_to_kimi_json),
        false,
        false,
    )
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
        // Default is the standard `url`/`command` shape. Qwen's `httpUrl` remap
        // used to fire for every remote whose map key was not VS Code `"servers"`,
        // so Kimi Shared HTTP Connect wrote a field Kimi rejects (SBS-921).
        // Clients with a distinct remote schema pass their own formatter.
        let mut value = if let Some(formatter) = entry_formatter {
            formatter(entry)
        } else {
            entry_to_json(entry)
        };
        if include_tools {
            value
                .as_object_mut()
                .unwrap()
                .insert("tools".into(), serde_json::json!(["*"]));
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
    let mut doc = load_toml_document(path)?;
    let keep_header = toml_keeps_servers_header(&doc);
    let servers = toml_mcp_servers_mut(&mut doc);
    let doomed: Vec<String> = servers
        .iter()
        .filter(|(name, definition)| {
            let command = definition.get("command").and_then(|value| value.as_str());
            gateway_identity_matches(name, name, command)
        })
        .map(|(name, _)| name.to_string())
        .collect();
    for name in doomed {
        servers.remove(&name);
    }
    if let Some(entry) = entry {
        servers.insert(
            GATEWAY_ENTRY_NAME,
            toml_value_to_item(&entry_to_toml(entry)),
        );
    }
    if servers.is_empty() || keep_header {
        // Keep an explicit empty table so uninstall still leaves `mcp_servers`
        // present, matching the previous toml::Value insert-if-missing path.
        // An existing commented header stays explicit too, otherwise the comment
        // has no header line left to hang on.
        servers.set_implicit(false);
    } else {
        servers.set_implicit(true);
    }

    atomic_write(path, &doc.to_string())
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
    let path = resolved_definition_path(&def)?;
    let backup = backup_file(client_id, &path)?;
    let lenient = config_is_whole_app_state(client_id);
    // Build the snapshot before writing so the ownership record matches the bytes
    // we put on disk (SOU-406). Strip secrets for the registry record.
    let managed = entry.map(ManagedEntry::from_gateway_entry);
    match def.format {
        Format::JsonMcpServers => edit_json_gateway(&path, "mcpServers", entry, lenient)?,
        Format::JsonCopilotMcpServers => edit_copilot_json_gateway(&path, entry)?,
        Format::JsonDroidMcpServers => edit_droid_json_gateway(&path, entry)?,
        Format::JsonAmpMcpServers => edit_json_gateway(&path, "amp.mcpServers", entry, true)?,
        Format::JsonQwenMcpServers => edit_qwen_json_gateway(&path, entry)?,
        Format::JsonKimiMcpServers => edit_kimi_json_gateway(&path, entry)?,
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
    let path = resolved_definition_path(&def).ok()?;
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
    let mut out = referenced_gateway_paths_in(&detect_clients())?;
    // Secondary Claude Code configs are invisible to detect_clients(), which probes
    // one path per client. Their gateway commands are still live references: pruning
    // a binary one of them names is what strands that profile on a missing gateway.
    // Keep-paths must be a superset of what any config can spawn, not of what we
    // happen to resolve today.
    for path in extra_claude_gateway_references() {
        if !out.contains(&path) {
            out.push(path);
        }
    }
    Some(out)
}

/// Gateway binaries named by Claude Code configs other than the resolved one.
///
/// Unreadable or unparseable files yield nothing rather than failing the whole scan:
/// [`referenced_gateway_paths`] already fails closed on a client it could not probe,
/// and these are best-effort extras discovered by directory scan, so one unreadable
/// sibling must not suppress pruning across the machine forever.
fn extra_claude_gateway_references() -> Vec<PathBuf> {
    let primary = client_config_path("claude-code");
    let mut out = Vec::new();
    for path in claude_code_config_paths() {
        if primary.as_deref() == Some(path.as_path()) {
            continue;
        }
        let Ok(text) = read_config_file(&path) else {
            continue;
        };
        let Some((_, command)) = claude_gateway_entry_in(&text) else {
            continue;
        };
        let command = command.trim();
        if !command.is_empty() {
            out.push(PathBuf::from(command));
        }
    }
    out
}

/// The pure half of [`referenced_gateway_paths`], over an already-probed client list so
/// the fail-closed and plugin-reference rules are testable without touching real configs.
fn referenced_gateway_paths_in(clients: &[DetectedClient]) -> Option<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for client in clients {
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
            .and_then(|def| resolved_definition_path(&def).ok())
            .and_then(|path| read_config_file(&path).ok());
        if !gateway_entry_needs_rewrite(entry_name, stored, &current, config_text.as_deref()) {
            continue;
        }
        let profile = config_text
            .as_deref()
            .and_then(profile_from_config_text)
            .or_else(|| read_gateway_profile(&client.id));
        match install_gateway(&client.id, profile.as_deref()) {
            Ok(write) => match write.managed {
                Some(m) => outcome.repointed.push((client.id.clone(), m)),
                // Written, but no ownership snapshot came back, so the registry
                // would keep the superseded command and read this entry as
                // Customized on the next pass - i.e. we would stop maintaining a
                // client we just rewrote. Worth recording rather than assuming.
                None => outcome.failed.push((
                    client.id.clone(),
                    "config was written but returned no ownership record".to_string(),
                )),
            },
            Err(error) => {
                let msg = format!(
                    "toolport: could not re-point {}'s gateway entry from {} to {}: {error}",
                    client.id,
                    if stored.is_empty() { "none" } else { stored },
                    current,
                );
                eprintln!("{msg}");
                crate::gatewaylog::append(&msg);
                outcome.failed.push((client.id.clone(), error.to_string()));
            }
        }
    }
    repoint_other_claude_configs(&current, &mut outcome);
    log_repoint_outcome(&current, &outcome);
    outcome
}

/// Repair Toolport's entry in every Claude Code config EXCEPT the one
/// [`client_config_path`] resolves, which the pass above already handled.
///
/// Strictly a repair, never an install. A file is touched only when it already holds
/// an entry of ours whose command is one of our gateway binaries
/// ([`gateway_entry_needs_rewrite`] gates on [`command_is_gateway_binary`]). A Claude
/// profile that deliberately has no Toolport keeps not having one, and a hand-written
/// entry under our name stays the user's. That distinction is why this is separate
/// from the connect path rather than folded into it: connecting is a decision the user
/// makes per profile, but a config we already wrote going stale is our bug to fix.
///
/// The registry ownership record is deliberately not written here. It is keyed by
/// client id, and all of these files are `claude-code`, so recording a sibling would
/// overwrite the resolved config's snapshot and make the next pass read that one as
/// Customized - i.e. we would stop maintaining the config we actually manage.
fn repoint_other_claude_configs(current: &str, outcome: &mut RepointOutcome) {
    let primary = client_config_path("claude-code");
    let others: Vec<PathBuf> = claude_code_config_paths()
        .into_iter()
        .filter(|path| primary.as_deref() != Some(path.as_path()))
        .collect();
    for repair in claude_configs_needing_repair(&others, current) {
        let ClaudeRepair {
            path,
            profile,
            stored,
        } = repair;
        let write = secondary_claude_gateway_entry(profile.as_deref()).and_then(|entry| {
            backup_secondary_claude_file(&path)?;
            edit_json_gateway(&path, "mcpServers", Some(&entry), true)
        });
        match write {
            Ok(()) => {
                let msg = format!(
                    "toolport: re-pointed a secondary Claude Code config at {} from {stored} to {current}",
                    path.display(),
                );
                eprintln!("{msg}");
                crate::gatewaylog::append(&msg);
                outcome.extra_claude_repointed.push(path);
            }
            Err(error) => {
                let msg = format!(
                    "toolport: could not re-point the secondary Claude Code config at {}: {error}",
                    path.display(),
                );
                eprintln!("{msg}");
                crate::gatewaylog::append(&msg);
                outcome.extra_claude_failed.push((path, error));
            }
        }
    }
}

/// One secondary Claude config that needs its gateway entry repaired.
#[derive(Debug, PartialEq, Eq)]
struct ClaudeRepair {
    path: PathBuf,
    /// This file's own `TOOLPORT_PROFILE`. These configs are scoped independently, so
    /// the resolved config's profile is not necessarily this one's, and a repair that
    /// dropped it would silently unscope a client.
    profile: Option<String>,
    /// What the entry pointed at before, for the log.
    stored: String,
}

/// Decide which of `paths` need repair, reading but never writing.
///
/// Split out from [`repoint_other_claude_configs`] so the rules are testable against
/// real files without a home directory, a `CLAUDE_CONFIG_DIR`, or an installed gateway
/// binary to resolve. The caller does the writing.
fn claude_configs_needing_repair(paths: &[PathBuf], current: &str) -> Vec<ClaudeRepair> {
    let mut out = Vec::new();
    for path in paths {
        let Ok(text) = read_config_file(path) else {
            continue;
        };
        let Some((entry_name, stored)) = claude_gateway_entry_in(&text) else {
            continue;
        };
        if !gateway_entry_needs_rewrite(&entry_name, &stored, current, Some(&text)) {
            continue;
        }
        out.push(ClaudeRepair {
            path: path.clone(),
            profile: profile_from_config_text(&text),
            stored,
        });
    }
    out
}

/// Our gateway entry's `(name, command)` in a `.claude.json`, by identity rather than
/// by exact name, so a pre-rename `conduit` entry is found too.
///
/// Returns None on unparseable text rather than treating it as "no entry": these files
/// hold Claude Code's entire application state, and a transient parse failure must not
/// be read as an invitation to write.
fn claude_gateway_entry_in(text: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let servers = value.get("mcpServers")?.as_object()?;
    servers.iter().find_map(|(name, entry)| {
        let command = entry.get("command").and_then(|c| c.as_str());
        gateway_identity_matches(name, name, command)
            .then(|| (name.clone(), command.unwrap_or_default().to_string()))
    })
}

/// Record a re-point pass in the gateway log.
///
/// This runs in the desktop app, whose stderr no one ever sees, so until now a
/// re-point left no durable trace at all: a pass that migrated every client and a
/// pass that silently skipped six of them produced identical evidence. The log is
/// what `gather_diagnostics` bundles, so a stale-gateway report can be answered
/// from it instead of reconstructed from file mtimes.
fn log_repoint_outcome(current: &str, outcome: &RepointOutcome) {
    if outcome.repointed.is_empty()
        && outcome.customized.is_empty()
        && outcome.failed.is_empty()
        && outcome.extra_claude_repointed.is_empty()
        && outcome.extra_claude_failed.is_empty()
    {
        return;
    }
    let ids = |pairs: &[(String, ManagedEntry)]| {
        pairs
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let paths = |items: &[PathBuf]| {
        items
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    crate::gatewaylog::append(&format!(
        "toolport: re-point pass against {current}: {} re-pointed [{}], {} customized [{}], {} failed [{}], {} secondary Claude configs re-pointed [{}], {} secondary failed [{}]",
        outcome.repointed.len(),
        ids(&outcome.repointed),
        outcome.customized.len(),
        outcome.customized.join(", "),
        outcome.failed.len(),
        outcome
            .failed
            .iter()
            .map(|(id, why)| format!("{id}: {why}"))
            .collect::<Vec<_>>()
            .join("; "),
        outcome.extra_claude_repointed.len(),
        paths(&outcome.extra_claude_repointed),
        outcome.extra_claude_failed.len(),
        outcome
            .extra_claude_failed
            .iter()
            .map(|(p, why)| format!("{}: {why}", p.display()))
            .collect::<Vec<_>>()
            .join("; "),
    ));
}

/// Serializes tests that read or mutate the process-global env vars these resolvers depend on
/// (`XDG_*`, `GOOSE_PATH_ROOT`, `CLAUDE_CONFIG_DIR`). The env is process-global and Rust runs
/// tests in parallel, so a test in ANY module that sets one of those keys must hold this lock,
/// not a lock of its own. Poison is recovered: a panic elsewhere shouldn't wedge these.
#[cfg(test)]
pub(crate) fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Sets a process env var and puts the old value back when the guard drops. Only valid while
/// [`env_test_lock`] is held. Lives beside the lock so other modules' tests use both.
#[cfg(test)]
pub(crate) struct EnvRestore {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl EnvRestore {
    pub(crate) fn set(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

#[cfg(test)]
impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::EnvVar;

    #[test]
    fn claude_code_config_follows_a_relocated_config_dir() {
        // Claude Code moves `.claude.json` when CLAUDE_CONFIG_DIR is set. Resolving
        // only `~/.claude.json` leaves the relocated copy pinned to whichever
        // versioned gateway binary was current when it was last written, and the
        // client then respawns that obsolete gateway indefinitely.
        let relocated = if cfg!(windows) {
            PathBuf::from(r"C:\Users\someone\.claude-work")
        } else {
            PathBuf::from("/home/someone/.claude-work")
        };
        assert_eq!(
            claude_config_dir_from(Some(relocated.clone().into_os_string())),
            Some(relocated.clone())
        );
        assert_eq!(
            claude_code_config_path(&relocated),
            relocated.join(".claude.json")
        );
    }

    #[test]
    fn every_claude_profile_on_the_machine_is_discovered() {
        // The resolved config is one of several. A personal `.claude` beside a work
        // `.claude-work` is the ordinary shape, and the one Toolport did not resolve
        // is exactly the one that rots.
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        let dirs = [
            ".claude-work".to_string(),
            ".claude".to_string(),
            // These share the `.claude` prefix but are not profiles. A plain
            // starts_with(".claude") would sweep them in and write a gateway entry
            // into a backup directory or another tool's state.
            ".claude.bak".to_string(),
            ".claudesync".to_string(),
            "Documents".to_string(),
        ];
        let paths = claude_code_config_paths_from(&home, Some(&home.join(".claude-work")), &dirs);
        assert_eq!(
            paths,
            vec![
                // The resolved config leads, so callers can take the head.
                home.join(".claude-work").join(".claude.json"),
                // The documented default is a file at the home root.
                home.join(".claude.json"),
                home.join(".claude").join(".claude.json"),
            ],
            "expected the override first, then the default, then sorted siblings"
        );
        for impostor in [".claude.bak", ".claudesync"] {
            assert!(
                !paths.iter().any(|p| p.starts_with(home.join(impostor))),
                "{impostor} is not a Claude Code profile and must not be written"
            );
        }
    }

    #[test]
    fn every_claude_profile_gets_a_settings_path_for_the_hook_sensor() {
        // Same discovery as the config list, and the same reason: a sensor installed
        // into only the resolved profile is blind to every session run under another
        // one, and under-reports silently (SBS-822).
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        let dirs = [
            ".claude-work".to_string(),
            ".claude".to_string(),
            ".claude.bak".to_string(),
            ".claudesync".to_string(),
        ];
        let paths = claude_settings_paths_from(&home, Some(&home.join(".claude-work")), &dirs);
        assert_eq!(
            paths,
            vec![
                home.join(".claude-work").join("settings.json"),
                // Unlike `.claude.json`, the default settings file lives INSIDE the
                // profile directory, not at the home root.
                home.join(".claude").join("settings.json"),
            ],
            "expected the override first, then the default, de-duplicated"
        );
        for impostor in [".claude.bak", ".claudesync"] {
            assert!(
                !paths.iter().any(|p| p.starts_with(home.join(impostor))),
                "{impostor} is not a Claude Code profile and must not be written"
            );
        }
    }

    #[test]
    fn a_settings_path_is_never_listed_twice() {
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        // The override commonly IS the default profile; writing it twice would take
        // two backups of one file and rewrite it needlessly.
        let paths = claude_settings_paths_from(
            &home,
            Some(&home.join(".claude")),
            &[".claude".to_string()],
        );
        assert_eq!(paths, vec![home.join(".claude").join("settings.json")]);
    }

    #[test]
    fn each_claude_profile_backs_its_settings_up_under_its_own_name() {
        // A work profile's backups must never overwrite or prune a personal profile's,
        // which is why the FULL path is the backup identity.
        let home = PathBuf::from("/home/someone");
        let personal = claude_settings_backup_name(&home.join(".claude").join("settings.json"));
        let work = claude_settings_backup_name(&home.join(".claude-work").join("settings.json"));
        assert_ne!(personal, work);

        // The case a leaf-name identity got wrong: two profiles whose directories share
        // a leaf. `prune_backups` keys on this name, so a collision here deletes one
        // profile's recovery copies (SBS-822 review).
        let other_volume =
            claude_settings_backup_name(Path::new("/mnt/work/.claude/settings.json"));
        assert_ne!(
            personal, other_volume,
            "two profiles both ending in `.claude` must not share a backup series"
        );
        assert!(personal.ends_with(".json"));
    }

    #[test]
    fn the_resolved_claude_config_is_never_listed_twice() {
        // The override commonly IS one of the siblings. Listing it twice would make
        // the repair pass rewrite the same file, and the resolved config is handled
        // by the main loop, so a duplicate is a double write, not a harmless extra.
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        let dirs = [".claude".to_string()];
        let paths = claude_code_config_paths_from(&home, Some(&home.join(".claude")), &dirs);
        assert_eq!(
            paths,
            vec![
                home.join(".claude").join(".claude.json"),
                home.join(".claude.json"),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_claude_profile_directories_are_discovered() {
        use std::os::unix::fs::symlink;

        let root = temp_path("claude-symlink-profile");
        let home = root.join("home");
        let target = root.join("work-profile");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join(".claude.json"), "{}").unwrap();
        symlink(&target, home.join(".claude-work")).unwrap();

        let dirs = claude_profile_dirs(&home).unwrap();
        assert!(dirs.iter().any(|name| name == ".claude-work"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn claude_profile_scan_surfaces_read_errors() {
        let missing = temp_path("missing-claude-profile-home");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(claude_profile_dirs(&missing).is_err());
    }

    #[test]
    fn secondary_claude_backups_have_per_path_identities() {
        let home = PathBuf::from(if cfg!(windows) {
            r"C:\Users\someone"
        } else {
            "/home/someone"
        });
        let personal = secondary_claude_backup_name(&home.join(".claude.json"));
        let work = secondary_claude_backup_name(&home.join(".claude-work").join(".claude.json"));
        assert_ne!(personal, work);
        assert_eq!(
            secondary_claude_backup_name(&home.join(".claude-work").join(".claude.json")),
            work,
            "the identity must stay stable across launches"
        );
    }

    #[test]
    fn a_secondary_claude_config_yields_its_gateway_entry() {
        // Found by identity, so the pre-rename `conduit` entry is repaired too.
        let text = r#"{
            "mcpServers": {
                "conduit": {
                    "type": "stdio",
                    "command": "/opt/Toolport/bin/conduit-gateway-1.11.0",
                    "env": { "CONDUIT_PROFILE": "work" }
                }
            },
            "projects": {}
        }"#;
        assert_eq!(
            claude_gateway_entry_in(text),
            Some((
                "conduit".to_string(),
                "/opt/Toolport/bin/conduit-gateway-1.11.0".to_string()
            ))
        );
        // Per-file profile: a sibling is scoped independently of the resolved config.
        assert_eq!(profile_from_config_text(text).as_deref(), Some("work"));
    }

    #[test]
    fn an_unreadable_secondary_config_is_not_read_as_having_no_entry() {
        // `.claude.json` holds Claude Code's entire application state. Treating a
        // parse failure as "no gateway entry here" is how a transient failure turns
        // into a write that flattens the user's whole config.
        assert_eq!(claude_gateway_entry_in("{ not json"), None);
        assert_eq!(claude_gateway_entry_in("{}"), None);
        assert_eq!(claude_gateway_entry_in(r#"{"mcpServers":{}}"#), None);
        // A server that isn't ours is not ours, whatever it is called.
        assert_eq!(
            claude_gateway_entry_in(r#"{"mcpServers":{"sentry":{"command":"npx"}}}"#),
            None
        );
    }

    #[test]
    fn a_secondary_config_is_repaired_only_when_the_entry_is_one_of_ours() {
        // The repair pass gates on gateway_entry_needs_rewrite, whose provenance
        // check is what keeps this a repair rather than a takeover: a hand-written
        // entry under our name belongs to the user even in a config we also write.
        let current = if cfg!(windows) {
            r"C:\Users\someone\AppData\Roaming\Toolport\bin\toolport-gateway-1.13.0.exe"
        } else {
            "/home/someone/.config/Toolport/bin/toolport-gateway-1.13.0"
        };
        let stale = if cfg!(windows) {
            r"C:\Users\someone\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0.exe"
        } else {
            "/home/someone/.config/Toolport/bin/toolport-gateway-1.12.0"
        };
        assert!(
            gateway_entry_needs_rewrite("toolport", stale, current, None),
            "a superseded gateway binary is exactly what this pass exists to fix"
        );
        assert!(
            !gateway_entry_needs_rewrite("toolport", "npx", current, None),
            "a custom command must survive a pass over a secondary config"
        );
        assert!(
            !gateway_entry_needs_rewrite("toolport", "", current, None),
            "an entry with no command is not ours to rewrite"
        );
        assert!(
            !gateway_entry_needs_rewrite("toolport", current, current, None),
            "an already-current entry must not be rewritten on every launch"
        );
    }

    #[test]
    fn only_the_stale_secondary_claude_configs_are_selected_for_repair() {
        // The wiring, against real files: which of several Claude profiles actually
        // get rewritten, and with which profile preserved. This is the step that was
        // missing before - the resolved config was maintained and every other one
        // silently kept respawning whatever gateway was current the day it was
        // written.
        let dir = temp_path("claude-secondary-repair");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let current = dir
            .join("toolport-gateway-1.13.0")
            .to_string_lossy()
            .into_owned();
        std::fs::write(&current, b"binary").unwrap();

        let write = |name: &str, body: &str| {
            let path = dir.join(name);
            std::fs::write(&path, body).unwrap();
            path
        };
        let stale_command = dir.join("toolport-gateway-1.12.0");
        let stale = write(
            "stale.json",
            &format!(
                r#"{{"mcpServers":{{"toolport":{{"command":{},"env":{{"TOOLPORT_PROFILE":"work"}}}}}},"projects":{{}}}}"#,
                serde_json::to_string(&stale_command.to_string_lossy().into_owned()).unwrap()
            ),
        );
        let already_current = write(
            "current.json",
            &format!(
                r#"{{"mcpServers":{{"toolport":{{"command":{}}}}}}}"#,
                serde_json::to_string(&current).unwrap()
            ),
        );
        let customized = write(
            "custom.json",
            r#"{"mcpServers":{"toolport":{"command":"npx","args":["-y","something"]}}}"#,
        );
        let no_gateway = write(
            "none.json",
            r#"{"mcpServers":{"sentry":{"command":"npx"}}}"#,
        );
        let unparseable = write("broken.json", "{ this is not json");
        let missing = dir.join("does-not-exist.json");

        let repairs = claude_configs_needing_repair(
            &[
                stale.clone(),
                already_current,
                customized,
                no_gateway,
                unparseable,
                missing,
            ],
            &current,
        );

        assert_eq!(
            repairs,
            vec![ClaudeRepair {
                path: stale,
                // Preserved per file: dropping it would silently unscope this client.
                profile: Some("work".to_string()),
                stored: stale_command.to_string_lossy().into_owned(),
            }],
            "only the config pinned to a superseded gateway of ours should be repaired"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_or_unusable_claude_config_dir_falls_back_to_the_default() {
        assert_eq!(claude_config_dir_from(None), None);
        assert_eq!(claude_config_dir_from(Some("".into())), None);
        // Relative: resolving it would depend on Toolport's cwd, which has nothing
        // to do with where the client reads its config.
        assert_eq!(claude_config_dir_from(Some("relative/dir".into())), None);
    }

    fn relocated_abs(unix: &str, windows: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(windows)
        } else {
            PathBuf::from(unix)
        }
    }

    /// Pins the failure mode in SBS-885: an absolute `CODEX_HOME` is the
    /// directory Codex reads, so Connect must write `$CODEX_HOME/config.toml`
    /// rather than a leftover `~/.codex/config.toml`.
    #[test]
    fn an_absolute_codex_home_is_the_config_and_rules_root() {
        let relocated = relocated_abs("/work/codex", r"D:\work\codex");
        assert_eq!(
            codex_home_from(Some(relocated.clone().into_os_string())),
            Some(relocated.clone())
        );
        assert_eq!(codex_config_path(&relocated), relocated.join("config.toml"));
        let rules = codex_rules_target(&relocated, crate::instructions::Scope::Team);
        assert_eq!(rules.path, relocated.join("AGENTS.md"));
        assert_eq!(
            rules.blocked_if_present,
            Some(relocated.join("AGENTS.override.md"))
        );
    }

    #[test]
    fn an_unset_or_unusable_codex_home_falls_back_to_the_default() {
        assert_eq!(codex_home_from(None), None);
        assert_eq!(codex_home_from(Some("".into())), None);
        assert_eq!(codex_home_from(Some("relative/dir".into())), None);
    }

    /// Gemini CLI replaces the process home, then still appends `.gemini/`.
    /// Writing `$GEMINI_CLI_HOME/settings.json` would miss the live file.
    #[test]
    fn an_absolute_gemini_cli_home_nests_settings_and_rules_under_dot_gemini() {
        let relocated = relocated_abs("/work/gemini", r"D:\work\gemini");
        assert_eq!(
            gemini_cli_home_from(Some(relocated.clone().into_os_string())),
            Some(relocated.clone())
        );
        assert_eq!(
            gemini_cli_settings_path(&relocated),
            relocated.join(".gemini").join("settings.json")
        );
        assert_eq!(
            gemini_cli_rules_target(&relocated, crate::instructions::Scope::Team).path,
            relocated.join(".gemini").join("GEMINI.md")
        );
    }

    #[test]
    fn an_unset_or_unusable_gemini_cli_home_falls_back_to_the_default() {
        assert_eq!(gemini_cli_home_from(None), None);
        assert_eq!(gemini_cli_home_from(Some("".into())), None);
        assert_eq!(gemini_cli_home_from(Some("relative/dir".into())), None);
    }

    #[test]
    fn an_absolute_grok_home_is_the_config_root() {
        let relocated = relocated_abs("/work/grok", r"D:\work\grok");
        assert_eq!(
            grok_home_from(Some(relocated.clone().into_os_string())),
            Some(relocated.clone())
        );
        assert_eq!(grok_config_path(&relocated), relocated.join("config.toml"));
    }

    #[test]
    fn an_unset_or_unusable_grok_home_falls_back_to_the_default() {
        assert_eq!(grok_home_from(None), None);
        assert_eq!(grok_home_from(Some("".into())), None);
        assert_eq!(grok_home_from(Some("relative/dir".into())), None);
    }

    #[test]
    fn an_absolute_qwen_home_is_the_settings_root() {
        let relocated = relocated_abs("/work/qwen", r"D:\work\qwen");
        assert_eq!(
            qwen_home_from(Some(relocated.clone().into_os_string())),
            Some(relocated.clone())
        );
        assert_eq!(
            qwen_settings_path(&relocated),
            relocated.join("settings.json")
        );
    }

    #[test]
    fn an_unset_or_unusable_qwen_home_falls_back_to_the_default() {
        assert_eq!(qwen_home_from(None), None);
        assert_eq!(qwen_home_from(Some("".into())), None);
        assert_eq!(qwen_home_from(Some("relative/dir".into())), None);
    }

    /// Qwen's own `Storage.resolvePath` expands a leading `~` before it reads
    /// `$QWEN_HOME/settings.json`, and a quoted export or a PowerShell
    /// `$env:QWEN_HOME` never gets shell expansion. Dropping the value as "not
    /// absolute" left Connect writing `~/.qwen/settings.json` while Qwen read
    /// the expanded home.
    #[test]
    fn a_tilde_qwen_home_expands_against_the_home_dir() {
        let home = home().expect("home dir should be available in tests");

        assert_eq!(qwen_home_from(Some("~".into())), Some(home.clone()));
        assert_eq!(
            qwen_home_from(Some("~/work/qwen".into())),
            Some(home.join("work/qwen"))
        );
        assert_eq!(
            qwen_home_from(Some(r"~\work\qwen".into())),
            Some(home.join(r"work\qwen"))
        );
        assert_eq!(
            qwen_settings_path(&qwen_home_from(Some("~/work/qwen".into())).expect("expanded")),
            home.join("work/qwen").join("settings.json")
        );
        // No separator, so it is a literal directory name and not a home
        // reference, the same call Qwen's `resolvePath` makes.
        assert_eq!(qwen_home_from(Some("~work".into())), None);
    }

    /// A doubled separator after the `~` used to leave a rooted remainder, and
    /// `PathBuf::join` substitutes a rooted path for the base rather than
    /// appending to it. `~//work/qwen` resolved to `/work/qwen`, outside the home
    /// dir the tilde asked for. Every leading separator is stripped now, so an
    /// expanded value always stays under home.
    #[test]
    fn extra_separators_after_the_tilde_cannot_escape_the_home_dir() {
        let home = home().expect("home dir should be available in tests");

        for raw in ["~", "~/", r"~\", "~//work/qwen", r"~\\work\qwen", "~///"] {
            let expanded = qwen_home_from(Some(raw.into()))
                .unwrap_or_else(|| panic!("{raw} should expand to an absolute path"));
            assert!(
                expanded.starts_with(&home),
                "{raw} expanded to {expanded:?}, which escapes {home:?}"
            );
        }

        assert_eq!(
            qwen_home_from(Some("~//work/qwen".into())),
            Some(home.join("work/qwen"))
        );
        assert_eq!(
            qwen_home_from(Some(r"~\\work\qwen".into())),
            Some(home.join(r"work\qwen"))
        );
        assert_eq!(qwen_home_from(Some("~".into())), Some(home.clone()));
        assert_eq!(qwen_home_from(Some("~///".into())), Some(home));
    }

    /// The tilde rule is Qwen-only on purpose. Codex (`find_codex_home_from_env`),
    /// Grok (`resolve_grok_home_from`), Gemini CLI (`homedir()`), and Claude Code
    /// all use the env value verbatim, so a literal `~` is already broken for the
    /// client and the default path is the closer guess. Expanding it here would
    /// have Toolport write a config the client never reads.
    #[test]
    fn a_tilde_is_not_expanded_for_the_verbatim_relocate_envs() {
        assert_eq!(codex_home_from(Some("~/work/codex".into())), None);
        assert_eq!(gemini_cli_home_from(Some("~/work/gemini".into())), None);
        assert_eq!(grok_home_from(Some("~/work/grok".into())), None);
        assert_eq!(claude_config_dir_from(Some("~/work/claude".into())), None);
    }

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
            request_timeout_ms: None,
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
            request_timeout_ms: None,
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
            request_timeout_ms: None,
            unknown_fields: serde_json::Map::new(),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("conduit-w-{}-{}.cfg", std::process::id(), label))
    }

    /// The Windows Hermes desktop build writes `%LOCALAPPDATA%\hermes\config.yaml`,
    /// not `~/.hermes/config.yaml`, so resolving only the home path left an
    /// installed Hermes undetectable with no way to connect it. The canonical path
    /// still wins when it exists, so nobody with an existing config is repointed.
    #[test]
    fn hermes_path_falls_back_to_the_platform_dir_only_when_home_has_no_config() {
        let root = std::env::temp_dir().join(format!("toolport-hermes-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let home_cfg = root.join("home").join(".hermes").join("config.yaml");
        let local = root.join("local");
        let local_cfg = local.join("hermes").join("config.yaml");

        // Neither exists: a first write must still land where the installed build
        // reads. Returning the home path here would write a config into `~/.hermes`
        // that Hermes never opens, so connecting would silently do nothing.
        assert_eq!(
            resolve_hermes_path(home_cfg.clone(), Some(local.clone())),
            local_cfg,
            "a fresh Windows config must be written where Hermes reads it"
        );

        // Only the platform dir has a config: that is the file Hermes actually reads.
        std::fs::create_dir_all(local_cfg.parent().unwrap()).unwrap();
        std::fs::write(&local_cfg, "mcp_servers: {}\n").unwrap();
        assert_eq!(
            resolve_hermes_path(home_cfg.clone(), Some(local.clone())),
            local_cfg,
            "an installed Hermes must be found in the platform data dir"
        );

        // Both exist: the canonical path wins, so an existing setup is untouched.
        std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
        std::fs::write(&home_cfg, "mcp_servers: {}\n").unwrap();
        assert_eq!(
            resolve_hermes_path(home_cfg.clone(), Some(local.clone())),
            home_cfg,
            "an existing home config must never be silently repointed"
        );

        // No platform dir at all (macOS / Linux pass None): canonical, no probing.
        std::fs::remove_file(&home_cfg).unwrap();
        assert_eq!(
            resolve_hermes_path(home_cfg.clone(), None),
            home_cfg,
            "platforms without the fallback resolve the home path unchanged"
        );

        std::fs::remove_dir_all(&root).ok();
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

    /// SBS-735: a stat that fails for a reason other than "missing" must abort
    /// the write, not read as "no file to back up". A metadata error on a config
    /// whose path sits on an unreadable network share was folded into the same
    /// `Ok(None)` as a genuinely absent file, so the caller started from an
    /// empty document and overwrote the user's config with no recovery copy.
    #[test]
    fn backup_propagates_stat_failures_instead_of_noop() {
        // A directory path makes metadata() succeed but is_file() fail -> still
        // the deliberate Ok(None) "nothing safe to back up" case. Use a path
        // that fails to stat for a reason other than "missing".
        let dir = std::env::temp_dir().join(format!("toolport-bk-stat-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        // A NUL byte makes the path invalid on BOTH platforms: the stat fails
        // with InvalidInput (unix) / InvalidFilename (Windows), never NotFound.
        // (The file/child ENOTDIR trick only errors non-NotFound on unix — on
        // Windows a path under a regular file reports ERROR_PATH_NOT_FOUND,
        // which maps to NotFound and would be swallowed by the missing-file arm.)
        let broken = dir.join("child\u{0}.json");

        let err = backup_file_named("claude-desktop", &broken, "child.json").unwrap_err();
        assert!(
            err.contains("could not stat"),
            "a stat failure must be reported, not treated as no backup: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// SBS-735 acceptance: a write must not proceed when the app could not tell
    /// whether an existing file was there. Drive the full caller (`write_servers`)
    /// with CLAUDE_CONFIG_DIR pointed at a path that fails to stat for a reason
    /// other than "missing", so the pre-write backup stat fails and the write
    /// must abort. Each platform gets its own non-NotFound stat failure: a NUL
    /// byte cannot go into an env var, and a path under a regular file is
    /// ENOTDIR on unix but ERROR_PATH_NOT_FOUND (NotFound) on Windows.
    #[test]
    fn write_servers_aborts_when_backup_stat_fails() {
        // Serialize against other tests that mutate the process-global
        // CLAUDE_CONFIG_DIR (e.g. client_config_paths_match_current_platform):
        // without the lock, that test could resolve the default home config
        // path mid-flight and make this one flaky.
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!("toolport-bk-write-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();

        #[cfg(unix)]
        {
            // Parent-of-config is a regular file: metadata(config) fails ENOTDIR.
            let not_a_dir = dir.join("claude-home");
            std::fs::write(&not_a_dir, "not a directory").unwrap();
            let _restore = EnvRestore::set("CLAUDE_CONFIG_DIR", &not_a_dir);

            let err = write_servers("claude-code", &[stdio("filesystem")]).unwrap_err();
            assert!(
                err.contains("could not stat"),
                "the caller must surface the stat failure instead of writing: {err}"
            );
            // No destructive write happened: the "config" file was never created.
            assert!(!not_a_dir.join(".claude.json").exists());
        }

        #[cfg(windows)]
        {
            // A '<' is an invalid filename character on Windows: metadata fails
            // with ERROR_INVALID_NAME (InvalidFilename), not ERROR_PATH_NOT_FOUND.
            let not_a_dir = dir.join("claude-home<>");
            let _restore = EnvRestore::set("CLAUDE_CONFIG_DIR", &not_a_dir);

            let err = write_servers("claude-code", &[stdio("filesystem")]).unwrap_err();
            assert!(
                err.contains("could not stat"),
                "the caller must surface the stat failure instead of writing: {err}"
            );
            // No destructive write happened: the "config" file was never created.
            assert!(!not_a_dir.join(".claude.json").exists());
        }

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
    fn settings_reader_keeps_the_missing_case_but_rejects_non_files() {
        let path = temp_path("read-settings");
        std::fs::remove_file(&path).ok();
        let (missing, original) = read_settings_json(&path).unwrap();
        assert_eq!(missing, serde_json::json!({}));
        assert!(original.is_none());

        std::fs::write(&path, "{ \"model\": \"opus\" }").unwrap();
        let (value, original) = read_settings_json(&path).unwrap();
        assert_eq!(value["model"], serde_json::json!("opus"));
        assert!(original.is_some());

        assert!(read_settings_json(&std::env::temp_dir())
            .unwrap_err()
            .contains("not a regular file"));
        std::fs::remove_file(path).ok();
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

    /// SBS-886: Connect (`edit_json_gateway` / `install_or_remove`) must write
    /// through a stow/chezmoi symlink. Failure mode: POSIX rename replaced
    /// `~/.claude.json -> ~/dotfiles/claude.json` with a regular file, the repo
    /// copy never got the gateway entry, and the next chezmoi apply restored
    /// the old link and the entry disappeared.
    #[cfg(unix)]
    #[test]
    fn connect_write_through_symlinked_config_keeps_link_and_updates_target() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "toolport-sbs886-connect-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("dotfiles").join("claude.json");
        let link = dir.join("home").join(".claude.json");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::write(
            &target,
            r#"{"theme":"dark","mcpServers":{"existing":{"command":"node","env":{"SECRET":"keepme"}}}}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        {
            let entry = sample_gateway(Some("Billing"), "claude-code");
            edit_json_gateway(&link, "mcpServers", Some(&entry), true)
        }
        .unwrap();

        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "Connect must leave the config path a symlink, became {:?}",
            meta.file_type()
        );
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        let servers = root["mcpServers"].as_object().unwrap();
        assert!(
            servers.contains_key(GATEWAY_ENTRY_NAME),
            "gateway entry must land in the symlink target"
        );
        assert!(servers.contains_key("existing"));
        assert_eq!(root["theme"], "dark");
        assert_eq!(servers["existing"]["env"]["SECRET"], "keepme");
        std::fs::remove_dir_all(dir).ok();
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
        assert_eq!(servers["filesystem"]["env"]["HOME"], "/home/user");
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
        assert!(!client_uses_mcp_remote_bridge("devin-cli"));
    }

    #[test]
    fn devin_cli_shared_http_entry_uses_native_remote_schema() {
        let path = temp_path("devin-cli-http.json");
        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "tok".into(),
        };
        let entry = gateway_entry_shared_http("devin-cli", None, &spec);
        // No mcp-remote shim: Devin Local / CLI takes the remote entry directly.
        assert!(entry.command.is_none());
        assert_eq!(entry.url.as_deref(), Some("http://127.0.0.1:8765/mcp"));

        edit_json_gateway(&path, "mcpServers", Some(&entry), false).unwrap();
        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let gateway = &root["mcpServers"][GATEWAY_ENTRY_NAME];
        assert_eq!(gateway["url"], "http://127.0.0.1:8765/mcp");
        // Devin defaults `transport` to http, so the `type` hint is advisory; the
        // credential must ride in `headers` rather than `env` to reach the wire.
        assert_eq!(gateway["type"], "http");
        assert_eq!(gateway["headers"]["Authorization"], "Bearer tok");
        assert!(gateway.get("command").is_none());
        assert!(gateway.get("env").is_none());
        std::fs::remove_file(&path).ok();
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
            edit_qwen_json_gateway(&path, Some(&entry)).unwrap();
            let root: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let slot = &root["mcpServers"][GATEWAY_ENTRY_NAME];
            assert_eq!(slot["httpUrl"], spec.url);
            assert_eq!(slot["headers"]["Authorization"], auth);
            assert!(slot.get("env").is_none());
            std::fs::remove_file(&path).ok();
        }
    }

    /// A detected client with no servers, no error, and a config file present.
    fn detected(id: &str) -> DetectedClient {
        DetectedClient {
            id: id.into(),
            name: id.into(),
            uses_connectors: false,
            config_path: format!("/tmp/{id}.json"),
            config_exists: true,
            app_present: true,
            servers: Vec::new(),
            plugin_servers: Vec::new(),
            gateway_installed: true,
            entry_state: GatewayEntryState::Managed,
            error: None,
        }
    }

    fn gateway_server(name: &str, command: &str) -> McpServer {
        McpServer {
            name: name.into(),
            transport: "stdio".into(),
            command: Some(command.into()),
            args: vec![],
            env_keys: vec![],
            url: None,
        }
    }

    #[test]
    fn referenced_gateway_paths_fails_closed_on_an_unreadable_client() {
        // An unreadable config means that client's references are UNKNOWN, and an unknown
        // reference must never be read as an absent one - the caller skips the whole prune.
        let mut broken = detected("claude-desktop");
        broken.error = Some("permission denied".into());
        assert_eq!(referenced_gateway_paths_in(&[broken.clone()]), None);

        // ...and it still fails closed alongside a client we CAN read, rather than
        // handing back a partial list that would make the other binary look unreferenced.
        let mut healthy = detected("cursor");
        healthy.servers = vec![gateway_server(
            GATEWAY_ENTRY_NAME,
            r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.9.5.exe",
        )];
        assert_eq!(
            referenced_gateway_paths_in(&[healthy.clone(), broken.clone()]),
            None,
            "one unreadable client must veto the whole set, not yield a partial list"
        );
        assert_eq!(referenced_gateway_paths_in(&[broken, healthy]), None);
    }

    #[test]
    fn referenced_gateway_paths_includes_plugin_and_customized_entries() {
        let plugin_path = r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.8.0.exe";
        // Plugin servers live outside the main config and can never be re-pointed, so a
        // binary only they name must still survive the prune.
        let mut plugin_only = detected("cursor");
        plugin_only.plugin_servers = vec![gateway_server(GATEWAY_ENTRY_NAME, plugin_path)];
        assert_eq!(
            referenced_gateway_paths_in(&[plugin_only.clone()]),
            Some(vec![PathBuf::from(plugin_path)])
        );

        // A customized entry (repoint leaves it alone) still names a binary the client
        // will spawn, so it is included too.
        let customized_path = r"C:\Users\me\custom\toolport-gateway-1.7.0.exe";
        let mut customized = detected("windsurf");
        customized.entry_state = GatewayEntryState::Customized;
        customized.servers = vec![gateway_server(GATEWAY_ENTRY_NAME, customized_path)];
        assert_eq!(
            referenced_gateway_paths_in(&[customized.clone()]),
            Some(vec![PathBuf::from(customized_path)])
        );

        // Both together, de-duplicated, and unrelated servers ignored.
        let mut noise = detected("cline");
        noise.servers = vec![gateway_server("github", "npx")];
        let mut dupe = detected("claude-code");
        dupe.servers = vec![gateway_server(GATEWAY_ENTRY_NAME, plugin_path)];
        assert_eq!(
            referenced_gateway_paths_in(&[plugin_only, customized, noise, dupe]),
            Some(vec![
                PathBuf::from(plugin_path),
                PathBuf::from(customized_path),
            ])
        );
    }

    #[test]
    fn referenced_gateway_paths_skips_clients_without_a_config() {
        // No config file is a KNOWN-empty reference set, unlike an error: keep going.
        let mut absent = detected("zed");
        absent.config_exists = false;
        absent.servers = vec![gateway_server(GATEWAY_ENTRY_NAME, "toolport-gateway-9.9.9")];
        assert_eq!(referenced_gateway_paths_in(&[absent]), Some(vec![]));
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

    fn managed_record(command: &str) -> ManagedEntry {
        ManagedEntry {
            command: command.to_string(),
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            transport: "stdio".to_string(),
            url: None,
            updated_at: 0,
        }
    }

    fn detected_server(command: &str) -> McpServer {
        McpServer {
            name: GATEWAY_ENTRY_NAME.to_string(),
            transport: "stdio".to_string(),
            command: Some(command.to_string()),
            args: Vec::new(),
            env_keys: Vec::new(),
            url: None,
        }
    }

    #[test]
    fn a_drifted_gateway_path_stays_managed() {
        // The ownership record must not become a trap. When a republish moves our
        // binary to a content-addressed filename, the config and the record
        // disagree on the path while both still name OUR gateway. Reading that as
        // Customized makes repoint_stale_gateways skip the client forever, which
        // is how six clients on a real machine sat on a superseded gateway.
        let record =
            managed_record(r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0.exe");
        let drifted = detected_server(
            r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0-140f0e8d8cfa.exe",
        );
        assert_eq!(
            resolve_entry_state(&[drifted], Some(&record)),
            GatewayEntryState::Managed,
            "a path-only drift between two of our own binaries is not customization"
        );
    }

    #[test]
    fn a_user_owned_command_is_still_customized() {
        // The other side of the same rule: #487 must keep working. A record exists,
        // but the command now names something that is not our binary, so the user
        // has taken the entry over and we stand down.
        let record =
            managed_record(r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0.exe");
        for taken_over in ["npx", "docker", r"C:\Users\me\bin\my-wrapper.cmd"] {
            assert_eq!(
                resolve_entry_state(&[detected_server(taken_over)], Some(&record)),
                GatewayEntryState::Customized,
                "{taken_over} is not ours and must stay customized"
            );
        }
    }

    #[test]
    fn a_drifted_path_with_changed_args_is_still_customized() {
        // Only the command path is forgiven. Anything else the user touched still
        // counts as customization.
        let record =
            managed_record(r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0.exe");
        let mut server = detected_server(
            r"C:\Users\me\AppData\Roaming\Toolport\bin\toolport-gateway-1.12.0-140f0e8d8cfa.exe",
        );
        server.args = vec!["--their-flag".to_string()];
        assert_eq!(
            resolve_entry_state(&[server], Some(&record)),
            GatewayEntryState::Customized
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

    #[test]
    fn secondary_claude_repair_keeps_profile_without_primary_client_id() {
        let entry = secondary_claude_gateway_entry(Some("work")).unwrap();
        let env: std::collections::HashMap<_, _> = entry
            .env
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();
        assert_eq!(
            env.get(crate::brand::PROFILE).unwrap().as_deref(),
            Some("work")
        );
        assert!(
            !env.contains_key(crate::brand::CLIENT_ID),
            "a secondary config must fall through to its own frozen profile"
        );
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
                                          // Well-behaved clients have no override (they use the config-parent heuristic).
        assert!(install_override("cursor").is_none());
        assert!(install_override("codex").is_none());
        assert!(install_override("vscode").is_none());
    }

    #[test]
    fn junie_install_marker_controls_detection_without_config() {
        let marker =
            std::env::temp_dir().join(format!("toolport-junie-marker-{}", std::process::id()));
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
    fn opencode_prefers_the_existing_jsonc_config() {
        let mut json_path = temp_path("opencode-path");
        json_path.set_extension("json");
        let jsonc_path = json_path.with_extension("jsonc");
        std::fs::write(&jsonc_path, "{}\n").unwrap();

        assert_eq!(
            resolve_opencode_config_path(json_path.clone()).unwrap(),
            jsonc_path
        );

        std::fs::remove_file(json_path.with_extension("jsonc")).ok();
    }

    #[test]
    fn opencode_refuses_to_choose_when_json_and_jsonc_both_exist() {
        let mut json_path = temp_path("opencode-conflict");
        json_path.set_extension("json");
        let jsonc_path = json_path.with_extension("jsonc");
        std::fs::write(&json_path, "{}\n").unwrap();
        std::fs::write(&jsonc_path, "{}\n").unwrap();

        let error = resolve_opencode_config_path(json_path.clone()).unwrap_err();
        assert!(error.contains("Both"));
        assert!(error.contains("opencode-conflict.json"));
        assert!(error.contains("opencode-conflict.jsonc"));

        std::fs::remove_file(&json_path).ok();
        std::fs::remove_file(&jsonc_path).ok();
    }

    #[test]
    fn opencode_jsonc_round_trip_preserves_comments_and_trailing_commas() {
        let path = temp_path("opencode-round-trip.jsonc");
        std::fs::write(
            &path,
            r#"{
                // Keep the user's model choice.
                "model": "anthropic/claude-sonnet-4-5",
                "mcp": {
                    "existing": {
                        "type": "local",
                        "command": ["node", "server.mjs"],
                        "enabled": true,
                    },
                },
            }"#,
        )
        .unwrap();

        let entry = sample_gateway(None, "opencode");
        edit_opencode_gateway(&path, Some(&entry)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("// Keep the user's model choice."));
        assert!(content.contains("anthropic/claude-sonnet-4-5"));
        let parsed = parse_opencode_json(&content).unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|server| server.name == "existing"));
        assert!(parsed
            .iter()
            .any(|server| server.name == GATEWAY_ENTRY_NAME));

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

    /// SBS-884: a `#` comment and an `&anchor` sitting outside `extensions`
    /// must survive a surgical YAML rewrite. Pretty-printing the whole file
    /// expands the alias and drops both.
    #[test]
    fn rewrite_yaml_key_preserving_keeps_unrelated_text() {
        let original = r#"# Goose config
GOOSE_MODEL: gpt-4o
defaults: &anchor
  timeout: 300
  enabled: true
extensions:
  fetch:
    cmd: uvx
"#;
        let new_exts = serde_yaml::from_str::<serde_yaml::Value>(
            "fetch:\n  cmd: uvx\ntoolport:\n  cmd: toolport-gateway\n",
        )
        .unwrap();
        let rewritten = rewrite_yaml_key_preserving(original, "extensions", &new_exts).unwrap();
        assert!(
            rewritten.contains("# Goose config"),
            "file-level comment must survive: {rewritten}"
        );
        assert!(
            rewritten.contains("&anchor"),
            "anchor outside extensions must survive: {rewritten}"
        );
        assert!(rewritten.contains("GOOSE_MODEL: gpt-4o"));
        assert!(rewritten.contains("toolport"));
        let root: serde_yaml::Value = serde_yaml::from_str(&rewritten).unwrap();
        assert!(root["extensions"].get("toolport").is_some());
        assert!(root.get("defaults").is_some());
    }

    /// SBS-884: a `|` block scalar can contain a line that looks like
    /// `extensions:`; that line is not a top-level key and must not be rewritten.
    #[test]
    fn rewrite_yaml_key_preserving_ignores_keys_inside_block_scalars() {
        let original = r#"prompt: |
  extensions:
    fake: true
extensions:
  real:
    cmd: uvx
"#;
        let new_exts =
            serde_yaml::from_str::<serde_yaml::Value>("real:\n  cmd: uvx\nextra: 1\n").unwrap();
        let rewritten = rewrite_yaml_key_preserving(original, "extensions", &new_exts).unwrap();
        assert!(
            rewritten.contains("  extensions:\n    fake: true"),
            "text inside a block scalar must stay: {rewritten}"
        );
        assert!(rewritten.contains("extra: 1") || rewritten.contains("extra:1"));
        let root: serde_yaml::Value = serde_yaml::from_str(&rewritten).unwrap();
        assert_eq!(
            root["prompt"].as_str().map(str::trim),
            Some("extensions:\n  fake: true")
        );
        assert!(root["extensions"].get("extra").is_some());
    }

    /// SBS-884 review: `yaml_leading_indent` counted characters while the caller
    /// used the count as a byte index. A U+00A0 in a block scalar's indentation
    /// made the slice land mid-character and panicked before this fix.
    #[test]
    fn rewrite_yaml_key_preserving_survives_multi_byte_whitespace() {
        let original = concat!(
            "# Goose config\n",
            "instructions: |\n",
            "  \u{a0}review the plan\n",
            "  then run it\n",
            "extensions:\n",
            "  fetch:\n",
            "    cmd: uvx\n",
        );
        // The fixture is valid YAML, so it really can reach the line scanner.
        serde_yaml::from_str::<serde_yaml::Value>(original).unwrap();
        let new_exts = serde_yaml::from_str::<serde_yaml::Value>(
            "fetch:\n  cmd: uvx\ntoolport:\n  cmd: toolport-gateway\n",
        )
        .unwrap();
        let rewritten = rewrite_yaml_key_preserving(original, "extensions", &new_exts).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&rewritten).unwrap();
        assert!(root["extensions"].get("toolport").is_some());
        assert!(
            root["instructions"]
                .as_str()
                .is_some_and(|s| s.contains('\u{a0}')),
            "block scalar content must be untouched: {rewritten}"
        );
        assert!(rewritten.contains("# Goose config"));
    }

    /// SBS-884 review: an anchor on the rewritten key is referenced by aliases
    /// elsewhere. Dropping it leaves `*exts` undefined and the config unloadable.
    #[test]
    fn rewrite_yaml_key_preserving_keeps_anchor_on_the_rewritten_key() {
        let original = concat!(
            "extensions: &exts\n",
            "  fetch:\n",
            "    cmd: uvx\n",
            "shared:\n",
            "  copy: *exts\n",
        );
        let new_exts = serde_yaml::from_str::<serde_yaml::Value>(
            "fetch:\n  cmd: uvx\ntoolport:\n  cmd: toolport-gateway\n",
        )
        .unwrap();
        let rewritten = rewrite_yaml_key_preserving(original, "extensions", &new_exts).unwrap();
        assert!(
            rewritten.contains("extensions: &exts"),
            "anchor on the rewritten key must survive: {rewritten}"
        );
        // The real failure was an unparseable file, so parsing is the assertion
        // that matters: an undefined alias is a hard error in serde_yaml.
        let root: serde_yaml::Value = serde_yaml::from_str(&rewritten).unwrap();
        assert!(root["extensions"].get("toolport").is_some());
        assert!(root["shared"]["copy"].get("toolport").is_some());
    }

    /// SBS-884 review: a 4-space config must not get one node reformatted to
    /// serde_yaml's 2 spaces.
    #[test]
    fn rewrite_yaml_key_preserving_matches_existing_indent_width() {
        let original = concat!(
            "extensions:\n",
            "    fetch:\n",
            "        cmd: uvx\n",
            "other: 1\n",
        );
        let new_exts = serde_yaml::from_str::<serde_yaml::Value>(
            "fetch:\n  cmd: uvx\ntoolport:\n  cmd: toolport-gateway\n",
        )
        .unwrap();
        let rewritten = rewrite_yaml_key_preserving(original, "extensions", &new_exts).unwrap();
        assert!(
            rewritten.contains("\n    toolport:"),
            "children must keep the file's 4-space indent: {rewritten}"
        );
        let root: serde_yaml::Value = serde_yaml::from_str(&rewritten).unwrap();
        assert!(root["extensions"].get("toolport").is_some());
        assert_eq!(root["other"].as_i64(), Some(1));
    }

    #[test]
    fn rewrite_yaml_key_preserving_rejects_duplicate_top_level_keys() {
        let original = r#"# keep me
extensions:
  a:
    cmd: old-a
other: 1
extensions:
  b:
    cmd: old-b
"#;
        let err = rewrite_yaml_key_preserving(
            original,
            "extensions",
            &serde_yaml::from_str::<serde_yaml::Value>("toolport:\n  cmd: x\n").unwrap(),
        )
        .unwrap_err();
        assert!(err.contains("appears") && err.contains("2"), "got: {err}");
    }

    #[test]
    fn atomic_write_yaml_config_rejects_duplicate_top_level_keys() {
        let path = temp_path("dup-extensions.yaml");
        let original = r#"# keep me
extensions:
  a:
    cmd: old-a
other: 1
extensions:
  b:
    cmd: old-b
"#;
        std::fs::write(&path, original).unwrap();
        let root: serde_yaml::Value =
            serde_yaml::from_str("other: 1\nextensions:\n  toolport:\n    cmd: toolport-gateway\n")
                .unwrap();
        let err = atomic_write_yaml_config(&path, Some(original), &root, "extensions").unwrap_err();
        assert!(
            err.contains("malformed") && err.contains("extensions"),
            "expected malformed duplicate-key error, got: {err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        std::fs::remove_file(&path).ok();
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

    /// SBS-884: `toml::to_string_pretty` dropped every `#` comment in Codex/Grok
    /// `config.toml` on Connect and again on uninstall. Hash comments outside
    /// `mcp_servers` must survive both writes.
    #[test]
    fn toml_connect_and_uninstall_preserve_hash_comments() {
        let path = temp_path("toml-comments-connect");
        std::fs::write(
            &path,
            r#"# Codex configuration
model = "o3"  # default model
approval_policy = "on-request"

[profiles.work]
model = "gpt-5"

[mcp_servers.existing]
command = "npx"
"#,
        )
        .unwrap();

        {
            let entry = sample_gateway(None, "codex");
            edit_toml_gateway(&path, Some(&entry))
        }
        .unwrap();
        let connected = std::fs::read_to_string(&path).unwrap();
        assert!(
            connected.contains("# Codex configuration"),
            "file-level comment must survive Connect: {connected}"
        );
        assert!(
            connected.contains("# default model"),
            "inline comment on an unrelated key must survive Connect: {connected}"
        );
        let parsed: toml::Value = toml::from_str(&connected).unwrap();
        assert_eq!(parsed.get("model").and_then(|v| v.as_str()), Some("o3"));
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get(GATEWAY_ENTRY_NAME))
            .is_some());
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get("existing"))
            .is_some());

        edit_toml_gateway(&path, None).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("# Codex configuration"),
            "file-level comment must survive uninstall: {after}"
        );
        assert!(
            after.contains("# default model"),
            "inline comment must survive uninstall: {after}"
        );
        let parsed: toml::Value = toml::from_str(&after).unwrap();
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get(GATEWAY_ENTRY_NAME))
            .is_none());
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get("existing"))
            .is_some());
        std::fs::remove_file(&path).ok();
    }

    /// SBS-884 review: a comment on the `[mcp_servers]` header itself only
    /// survives while the table stays explicit. An implicit table emits no
    /// header line, so both write paths dropped it.
    #[test]
    fn toml_preserves_mcp_servers_header_comment() {
        let path = temp_path("toml-servers-header");
        let original = r#"# Codex configuration
model = "o3"

# gateway servers live below
[mcp_servers]

[mcp_servers.existing]
command = "npx"
"#;
        std::fs::write(&path, original).unwrap();

        {
            let entry = sample_gateway(None, "codex");
            edit_toml_gateway(&path, Some(&entry))
        }
        .unwrap();
        let connected = std::fs::read_to_string(&path).unwrap();
        assert!(
            connected.contains("# gateway servers live below"),
            "comment on the [mcp_servers] header must survive Connect: {connected}"
        );
        let parsed: toml::Value = toml::from_str(&connected).unwrap();
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get(GATEWAY_ENTRY_NAME))
            .is_some());
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get("existing"))
            .is_some());

        // The inventory write path rebuilds the table from scratch, so it has to
        // carry the header decor over too.
        std::fs::write(&path, original).unwrap();
        write_toml(&path, &[stdio("linear")]).unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# gateway servers live below"),
            "comment on the [mcp_servers] header must survive write_toml: {written}"
        );
        let parsed: toml::Value = toml::from_str(&written).unwrap();
        assert!(parsed
            .get("mcp_servers")
            .and_then(|m| m.get("linear"))
            .is_some());
        std::fs::remove_file(&path).ok();
    }

    /// SBS-884: inventory write (`write_toml`) used the same pretty-print path
    /// and stripped comments even when it kept unrelated keys as data.
    #[test]
    fn toml_write_preserves_hash_comments() {
        let path = temp_path("toml-comments-write");
        std::fs::write(&path, "# keep this comment\nmodel = \"opus\"\n").unwrap();
        write_toml(&path, &[stdio("linear")]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# keep this comment"),
            "comment must survive write_toml: {content}"
        );
        let root: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(root.get("model").and_then(|v| v.as_str()), Some("opus"));
        assert!(root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .map(|t| t.contains_key("linear"))
            .unwrap_or(false));
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
            resolve_crush_path(home, None, Some(std::ffi::OsString::from("xdg-config")),),
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
            "devin-cli",
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
    fn devin_clients_keep_legacy_and_current_configs_distinct() {
        let legacy = defs().into_iter().find(|d| d.id == "windsurf").unwrap();
        let current = defs().into_iter().find(|d| d.id == "devin-cli").unwrap();
        assert_eq!(legacy.name, "Devin Desktop (Cascade)");
        assert_eq!(current.name, "Devin Local / CLI");
        assert!(matches!(legacy.format, Format::JsonMcpServers));
        assert!(matches!(current.format, Format::JsonMcpServers));
        assert_ne!((legacy.path)(), (current.path)());
        assert!(!client_uses_mcp_remote_bridge("devin-cli"));
    }

    #[test]
    fn github_copilot_cli_is_registered_with_required_tools_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "github-copilot-cli")
            .unwrap();
        assert_eq!(definition.name, "GitHub Copilot CLI");
        assert!(matches!(definition.format, Format::JsonCopilotMcpServers));
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
        let installed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(installed.len(), 2);
        assert!(installed.iter().any(|server| server.name == "existing"));
        assert!(installed
            .iter()
            .any(|server| server.name == GATEWAY_ENTRY_NAME));
        let installed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(installed_json["mcpServers"]["existing"], original_existing);
        assert_eq!(
            installed_json["mcpServers"][GATEWAY_ENTRY_NAME]["tools"],
            serde_json::json!(["*"])
        );

        edit_copilot_json_gateway(&path, None).unwrap();
        let removed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
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

        {
            let _e = sample_gateway(None, "junie");
            edit_json_gateway(&path, "mcpServers", Some(&_e), false)
        }
        .unwrap();
        let installed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(installed.len(), 2);
        assert!(installed.iter().any(|server| server.name == "existing"));
        assert!(installed
            .iter()
            .any(|server| server.name == GATEWAY_ENTRY_NAME));
        let installed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(installed_json["mcpServers"]["existing"], original_existing);

        edit_json_gateway(&path, "mcpServers", None, false).unwrap();
        let removed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "existing");
        let removed_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(removed_json["mcpServers"]["existing"], original_existing);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn kimi_code_is_registered_with_its_native_transport_format() {
        let definition = defs()
            .into_iter()
            .find(|definition| definition.id == "kimi-code")
            .unwrap();
        assert_eq!(definition.name, "Kimi Code");
        assert!(matches!(definition.format, Format::JsonKimiMcpServers));
        assert!(!definition.uses_connectors);
        assert!((definition.path)().is_some());
        assert!(!client_uses_mcp_remote_bridge("kimi-code"));
    }

    #[test]
    fn kimi_code_config_path_is_under_home_data_root() {
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let path =
                resolve_client_config_path("kimi-code", &home, platform).expect("kimi-code path");
            assert_eq!(
                path,
                home.join(".kimi-code").join("mcp.json"),
                "kimi-code path on {platform:?}"
            );
        }
    }

    #[test]
    fn kimi_code_path_honors_kimi_code_home_override() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("toolport-kimi-home-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let _restore = EnvRestore::set("KIMI_CODE_HOME", &root);
        let resolved = kimi_code_path().expect("kimi-code path with override");
        assert_eq!(resolved, root.join("mcp.json"));
        drop(_restore);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn codex_path_and_rules_honor_an_absolute_codex_home() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("toolport-codex-home-{}", std::process::id()));
        let _restore = EnvRestore::set("CODEX_HOME", &root);
        assert_eq!(codex_path(), Some(root.join("config.toml")));
        let rules =
            client_rules_target("codex", crate::instructions::Scope::Team).expect("codex rules");
        assert_eq!(rules.path, root.join("AGENTS.md"));
        assert_eq!(
            rules.blocked_if_present,
            Some(root.join("AGENTS.override.md"))
        );
    }

    #[test]
    fn gemini_cli_path_and_rules_honor_an_absolute_gemini_cli_home() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root =
            std::env::temp_dir().join(format!("toolport-gemini-cli-home-{}", std::process::id()));
        let _restore = EnvRestore::set("GEMINI_CLI_HOME", &root);
        assert_eq!(
            gemini_cli_path(),
            Some(root.join(".gemini").join("settings.json"))
        );
        let rules = client_rules_target("gemini-cli", crate::instructions::Scope::Team)
            .expect("gemini rules");
        assert_eq!(rules.path, root.join(".gemini").join("GEMINI.md"));
        // Antigravity is a different product; GEMINI_CLI_HOME must not move it.
        let home = home().expect("home");
        let antigravity = resolve_rules_target(
            "antigravity",
            &home,
            Platform::current(),
            crate::instructions::Scope::Team,
        )
        .expect("antigravity rules");
        assert_eq!(antigravity.path, home.join(".gemini").join("GEMINI.md"));
    }

    #[test]
    fn grok_path_honors_an_absolute_grok_home() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("toolport-grok-home-{}", std::process::id()));
        let _restore = EnvRestore::set("GROK_HOME", &root);
        assert_eq!(grok_path(), Some(root.join("config.toml")));
    }

    #[test]
    fn qwen_code_path_honors_an_absolute_qwen_home() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("toolport-qwen-home-{}", std::process::id()));
        let _restore = EnvRestore::set("QWEN_HOME", &root);
        assert_eq!(qwen_code_path(), Some(root.join("settings.json")));
    }

    #[test]
    fn kimi_json_parses_sse_transport_hint_and_bearer_env_var() {
        let content = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "context7": {
                    "url": "https://mcp.context7.com/mcp",
                    "headers": { "CONTEXT7_API_KEY": "your-key" }
                },
                "legacy-events": {
                    "transport": "sse",
                    "url": "https://mcp.example.com/sse"
                },
                "authed": {
                    "url": "https://mcp.example.com/mcp",
                    "bearerTokenEnvVar": "MY_MCP_TOKEN"
                }
            }
        }"#;
        let servers = parse_json(content, "mcpServers").unwrap();
        assert_eq!(servers.len(), 4);

        let filesystem = servers.iter().find(|s| s.name == "filesystem").unwrap();
        assert_eq!(filesystem.transport, "stdio");
        assert_eq!(filesystem.command.as_deref(), Some("npx"));

        let http = servers.iter().find(|s| s.name == "context7").unwrap();
        assert_eq!(http.transport, "http");
        assert_eq!(http.env_keys, vec!["CONTEXT7_API_KEY".to_string()]);

        let sse = servers.iter().find(|s| s.name == "legacy-events").unwrap();
        assert_eq!(sse.transport, "sse");
        assert_eq!(sse.url.as_deref(), Some("https://mcp.example.com/sse"));

        let authed = servers.iter().find(|s| s.name == "authed").unwrap();
        assert_eq!(authed.transport, "http");
        assert_eq!(authed.env_keys, vec!["MY_MCP_TOKEN".to_string()]);
    }

    #[test]
    fn kimi_write_round_trips_stdio_http_and_sse() {
        let path = temp_path("kimi-mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"existing":{"command":"node","args":["server.js"],"env":{"TOKEN":"keep"}}}}"#,
        )
        .unwrap();

        // Value-less env keys model Kimi's bearerTokenEnvVar import path; they are
        // vaulted for remote::first_vaulted_secret, but entry_to_json drops them and
        // entry_to_kimi_json never rewrites bearerTokenEnvVar — pin that asymmetry.
        let mut bearer_remote = remote("bearer-remote", "http");
        bearer_remote.env = vec![EnvVar {
            key: "MY_MCP_TOKEN".to_string(),
            value: None,
            secret: true,
        }];

        let servers = vec![
            stdio("filesystem"),
            remote("remote-http", "http"),
            remote("remote-sse", "sse"),
            bearer_remote,
        ];
        write_kimi_json(&path, &servers).unwrap();

        let root: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(root["mcpServers"].get("existing").is_none());

        let http = &root["mcpServers"]["remote-http"];
        assert_eq!(http["url"], "https://remote-http.example.com/mcp");
        assert!(http.get("type").is_none());
        assert!(http.get("transport").is_none());
        assert_eq!(http["headers"]["Authorization"], "Bearer fixture");

        let sse = &root["mcpServers"]["remote-sse"];
        assert_eq!(sse["url"], "https://remote-sse.example.com/mcp");
        assert_eq!(sse["transport"], "sse");
        assert!(sse.get("type").is_none());
        assert_eq!(sse["headers"]["Authorization"], "Bearer fixture");

        let bearer = &root["mcpServers"]["bearer-remote"];
        assert_eq!(bearer["url"], "https://bearer-remote.example.com/mcp");
        assert!(bearer.get("bearerTokenEnvVar").is_none());
        assert!(bearer.get("headers").is_none());
        assert!(bearer.get("env").is_none());

        let parsed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(
            parsed
                .iter()
                .find(|s| s.name == "filesystem")
                .unwrap()
                .transport,
            "stdio"
        );
        assert_eq!(
            parsed
                .iter()
                .find(|s| s.name == "remote-http")
                .unwrap()
                .transport,
            "http"
        );
        assert_eq!(
            parsed
                .iter()
                .find(|s| s.name == "remote-sse")
                .unwrap()
                .transport,
            "sse"
        );
        assert!(parsed
            .iter()
            .find(|s| s.name == "bearer-remote")
            .unwrap()
            .env_keys
            .is_empty());

        // Gateway install preserves existing servers and uses the standard stdio shape.
        {
            let _e = sample_gateway(None, "kimi-code");
            edit_json_gateway(&path, "mcpServers", Some(&_e), true)
        }
        .unwrap();
        let installed = parse_json(&std::fs::read_to_string(&path).unwrap(), "mcpServers").unwrap();
        assert!(installed.iter().any(|s| s.name == "filesystem"));
        assert!(installed.iter().any(|s| s.name == GATEWAY_ENTRY_NAME));

        std::fs::remove_file(&path).ok();
    }

    /// SBS-921: Shared HTTP Connect/rescope/reset for Kimi goes through
    /// `install_gateway_shared_http` → `install_or_remove`. That used to remap
    /// remotes via `entry_to_qwen_json` (`url` → `httpUrl`) whenever the key was
    /// not VS Code `"servers"`. Kimi requires `url` and rejects `httpUrl`.
    /// `type` must also stay off: Kimi ignores it, and `entry_to_kimi_json`
    /// strips the hint `entry_to_json` would emit.
    #[test]
    fn kimi_shared_http_connect_writes_url_not_qwen_http_url() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _data_lock = crate::registry::data_dir_test_lock();
        let root =
            std::env::temp_dir().join(format!("toolport-kimi-sbs921-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let data_dir = root.join("toolport-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let _data_dir = crate::registry::DataDirOverride::set(&data_dir);
        let path = root.join("mcp.json");
        std::fs::write(
            &path,
            r#"{"mcpServers":{"keep":{"command":"node","args":["server.js"]}}}"#,
        )
        .unwrap();
        let _restore = EnvRestore::set("KIMI_CODE_HOME", &root);

        let spec = SharedHttpSpec {
            url: "http://127.0.0.1:8765/mcp".into(),
            token: "kimi-tok".into(),
        };
        install_gateway_shared_http("kimi-code", Some("Work"), &spec).unwrap();

        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let slot = &written["mcpServers"][GATEWAY_ENTRY_NAME];
        assert_eq!(
            slot["url"], spec.url,
            "Kimi Shared HTTP must write url: {slot}"
        );
        assert!(
            slot.get("httpUrl").is_none(),
            "Kimi rejects Qwen's httpUrl: {slot}"
        );
        assert!(
            slot.get("type").is_none(),
            "Kimi ignores type; entry_to_kimi_json must strip it: {slot}"
        );
        assert!(
            slot.get("transport").is_none(),
            "streamable HTTP is Kimi's default; do not emit transport: {slot}"
        );
        assert_eq!(slot["headers"]["Authorization"], "Bearer kimi-tok");
        assert!(
            written["mcpServers"].get("keep").is_some(),
            "Connect must preserve existing servers: {written}"
        );
        let backups = data_dir.join("backups").join("kimi-code");
        assert_eq!(
            std::fs::read_dir(&backups).unwrap().count(),
            1,
            "the fixture backup must stay under the overridden test data dir"
        );

        drop(_data_dir);
        drop(_restore);
        std::fs::remove_dir_all(&root).ok();
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
    fn goose_inventory_write_preserves_non_mcp_extensions() {
        let path = temp_path("goose-preserve-builtins.yaml");
        std::fs::write(
            &path,
            "GOOSE_MODEL: gpt-4o\nextensions:\n  developer:\n    type: builtin\n    enabled: true\n  platform-tools:\n    type: platform\n    cmd: internal\n  future-shape:\n    enabled: true\n  fetch:\n    type: stdio\n    cmd: uvx\n    args: [mcp-server-fetch]\n",
        )
        .unwrap();

        let gateway = sample_gateway(None, "goose");
        write_yaml_extensions(&path, &[gateway]).unwrap();

        let root: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["GOOSE_MODEL"].as_str(), Some("gpt-4o"));
        let extensions = root["extensions"].as_mapping().unwrap();
        assert!(extensions.get("developer").is_some());
        assert!(extensions.get("platform-tools").is_some());
        assert!(extensions.get("future-shape").is_some());
        assert!(extensions.get("fetch").is_none());
        assert!(extensions.get(GATEWAY_ENTRY_NAME).is_some());

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

    /// SBS-884: Goose Connect/uninstall pretty-printed `config.yaml` and dropped
    /// `#` comments plus `&anchor` definitions sitting outside `extensions`.
    #[test]
    fn goose_yaml_connect_and_uninstall_preserve_comments_and_anchors() {
        let path = temp_path("goose-comments-anchors.yaml");
        std::fs::write(
            &path,
            r#"# Goose config
GOOSE_MODEL: gpt-4o
defaults: &anchor
  timeout: 300
  enabled: true
extensions:
  developer:
    type: builtin
    enabled: true
  fetch:
    type: stdio
    cmd: uvx
    args: [mcp-server-fetch]
"#,
        )
        .unwrap();

        {
            let entry = sample_gateway(None, "goose");
            edit_yaml_gateway(&path, Some(&entry))
        }
        .unwrap();
        let connected = std::fs::read_to_string(&path).unwrap();
        assert!(
            connected.contains("# Goose config"),
            "hash comment must survive Connect: {connected}"
        );
        assert!(
            connected.contains("&anchor"),
            "anchor outside extensions must survive Connect: {connected}"
        );
        let v: serde_yaml::Value = serde_yaml::from_str(&connected).unwrap();
        assert_eq!(v["GOOSE_MODEL"].as_str(), Some("gpt-4o"));
        assert!(v["extensions"].get(GATEWAY_ENTRY_NAME).is_some());
        assert!(v["extensions"].get("fetch").is_some());
        assert!(v["extensions"].get("developer").is_some());

        edit_yaml_gateway(&path, None).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("# Goose config"),
            "hash comment must survive uninstall: {after}"
        );
        assert!(
            after.contains("&anchor"),
            "anchor must survive uninstall: {after}"
        );
        let after_v: serde_yaml::Value = serde_yaml::from_str(&after).unwrap();
        assert!(after_v["extensions"].get(GATEWAY_ENTRY_NAME).is_none());
        assert!(after_v["extensions"].get("fetch").is_some());
        std::fs::remove_file(&path).ok();
    }

    /// SBS-884: inventory write must not pretty-print the whole Goose file.
    #[test]
    fn goose_yaml_write_preserves_comments_and_anchors() {
        let path = temp_path("goose-write-comments.yaml");
        std::fs::write(
            &path,
            "# keep this comment\ndefaults: &anchor\n  timeout: 300\nGOOSE_MODEL: gpt-4o\nextensions:\n  developer:\n    type: builtin\n    enabled: true\n",
        )
        .unwrap();
        write_yaml_extensions(&path, &[sample_gateway(None, "goose")]).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# keep this comment"),
            "comment must survive write_yaml_extensions: {content}"
        );
        assert!(
            content.contains("&anchor"),
            "anchor must survive write_yaml_extensions: {content}"
        );
        let root: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
        assert!(root["extensions"].get("developer").is_some());
        assert!(root["extensions"].get(GATEWAY_ENTRY_NAME).is_some());
        std::fs::remove_file(&path).ok();
    }

    /// SBS-884: Hermes Connect/uninstall must keep `#` comments and `&anchor`
    /// outside `mcp_servers`.
    #[test]
    fn hermes_yaml_connect_and_uninstall_preserve_comments_and_anchors() {
        let path = temp_path("hermes-comments-anchors.yaml");
        std::fs::write(
            &path,
            r#"# Hermes config
model:
  default: gpt-4o
shared_headers: &anchor
  Authorization: Bearer token
mcp_servers:
  zread:
    url: https://mcp.example.com/mcp
    timeout: 120
"#,
        )
        .unwrap();

        {
            let entry = sample_gateway(None, "hermes");
            edit_hermes_yaml_gateway(&path, Some(&entry))
        }
        .unwrap();
        let connected = std::fs::read_to_string(&path).unwrap();
        assert!(
            connected.contains("# Hermes config"),
            "hash comment must survive Connect: {connected}"
        );
        assert!(
            connected.contains("&anchor"),
            "anchor outside mcp_servers must survive Connect: {connected}"
        );
        let v: serde_yaml::Value = serde_yaml::from_str(&connected).unwrap();
        assert_eq!(v["model"]["default"].as_str(), Some("gpt-4o"));
        assert!(v["mcp_servers"].get(GATEWAY_ENTRY_NAME).is_some());
        assert!(v["mcp_servers"].get("zread").is_some());

        edit_hermes_yaml_gateway(&path, None).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("# Hermes config"),
            "hash comment must survive uninstall: {after}"
        );
        assert!(
            after.contains("&anchor"),
            "anchor must survive uninstall: {after}"
        );
        let after_v: serde_yaml::Value = serde_yaml::from_str(&after).unwrap();
        assert!(after_v["mcp_servers"].get(GATEWAY_ENTRY_NAME).is_none());
        assert!(after_v["mcp_servers"].get("zread").is_some());
        std::fs::remove_file(&path).ok();
    }

    /// SBS-884: Continue Connect/uninstall must keep `#` comments and `&anchor`
    /// outside the `mcpServers` list (column-0 sequence items stay in that node).
    #[test]
    fn continue_yaml_connect_and_uninstall_preserve_comments_and_anchors() {
        let path = temp_path("continue-comments-anchors.yaml");
        std::fs::write(
            &path,
            r#"# Continue config
models:
  - title: GPT-4o
shared: &anchor
  env:
    TOKEN: abc
mcpServers:
- name: fetch
  command: uvx
rules:
  - Keep responses concise
"#,
        )
        .unwrap();

        {
            let entry = sample_gateway(None, "continue");
            edit_continue_yaml_gateway(&path, Some(&entry))
        }
        .unwrap();
        let connected = std::fs::read_to_string(&path).unwrap();
        assert!(
            connected.contains("# Continue config"),
            "hash comment must survive Connect: {connected}"
        );
        assert!(
            connected.contains("&anchor"),
            "anchor outside mcpServers must survive Connect: {connected}"
        );
        let v: serde_yaml::Value = serde_yaml::from_str(&connected).unwrap();
        let servers = v["mcpServers"].as_sequence().unwrap();
        assert!(servers
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some(GATEWAY_ENTRY_NAME)));
        assert!(servers
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("fetch")));
        assert_eq!(v["models"][0]["title"].as_str(), Some("GPT-4o"));

        edit_continue_yaml_gateway(&path, None).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("# Continue config"),
            "hash comment must survive uninstall: {after}"
        );
        assert!(
            after.contains("&anchor"),
            "anchor must survive uninstall: {after}"
        );
        let after_v: serde_yaml::Value = serde_yaml::from_str(&after).unwrap();
        let servers = after_v["mcpServers"].as_sequence().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["name"].as_str(), Some("fetch"));
        std::fs::remove_file(&path).ok();
    }

    fn mock_home(platform: Platform) -> PathBuf {
        match platform {
            Platform::Windows => PathBuf::from(r"C:\Users\alice"),
            Platform::MacOs => PathBuf::from("/Users/alice"),
            Platform::Linux => PathBuf::from("/home/alice"),
        }
    }

    /// Team-scope resolution, the default for these path tests. Scope changes only the owned-file
    /// NAME; `rules_target_owned_file_name_follows_the_scope` covers the personal variant, and
    /// sentinel clients share one file across scopes by design.
    fn team_rules_target(
        client_id: &str,
        home: &Path,
        platform: Platform,
    ) -> Option<crate::instructions::Target> {
        resolve_rules_target(client_id, home, platform, crate::instructions::Scope::Team)
    }

    #[test]
    fn rules_target_claude_code_is_owned_file_all_platforms() {
        use crate::instructions::Strategy;
        for p in [Platform::Windows, Platform::MacOs, Platform::Linux] {
            let t = team_rules_target("claude-code", &mock_home(p), p).expect("supported");
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

    /// Team and personal owned files are siblings in the client's rules DIRECTORY, never the same
    /// file: the client reads the whole directory, so both apply and neither clobbers the other.
    #[test]
    fn rules_target_owned_file_name_follows_the_scope() {
        use crate::instructions::Scope;
        let home = mock_home(Platform::MacOs);
        let p = Platform::MacOs;
        for client in ["claude-code", "vscode", "kiro", "roo-code", "cline"] {
            let team = resolve_rules_target(client, &home, p, Scope::Team).expect("supported");
            let personal =
                resolve_rules_target(client, &home, p, Scope::Personal).expect("supported");
            assert_eq!(
                team.path.parent(),
                personal.path.parent(),
                "{client}: both scopes live in the same rules directory"
            );
            assert_ne!(
                team.path, personal.path,
                "{client}: scopes must not share a file"
            );
            assert!(team.path.ends_with(Scope::Team.owned_file_name()));
            assert!(personal.path.ends_with(Scope::Personal.owned_file_name()));
            assert_eq!(personal.scope, Scope::Personal);
        }
    }

    /// Sentinel clients deliberately resolve to ONE file for both scopes. The two managed spans
    /// coexist there, separated by their disjoint markers.
    #[test]
    fn rules_target_sentinel_clients_share_one_file_across_scopes() {
        use crate::instructions::Scope;
        let home = mock_home(Platform::MacOs);
        let p = Platform::MacOs;
        for client in [
            "codex",
            "gemini-cli",
            "windsurf",
            "devin-cli",
            "goose",
            "zed",
            "pi",
            "omp",
        ] {
            let team = resolve_rules_target(client, &home, p, Scope::Team).expect("supported");
            let personal =
                resolve_rules_target(client, &home, p, Scope::Personal).expect("supported");
            assert_eq!(team.path, personal.path, "{client}: one shared rules file");
            assert_eq!(team.char_cap, personal.char_cap, "{client}: same cap");
            assert_eq!(
                team.blocked_if_present, personal.blocked_if_present,
                "{client}: a shadow file blocks both scopes"
            );
        }
    }

    #[test]
    fn rules_target_codex_is_sentinel_and_flags_override() {
        use crate::instructions::Strategy;
        let home = mock_home(Platform::MacOs);
        let t = team_rules_target("codex", &home, Platform::MacOs).expect("supported");
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
        let t = team_rules_target("windsurf", &mock_home(Platform::Linux), Platform::Linux)
            .expect("supported");
        assert_eq!(t.char_cap, Some(6000));
    }

    #[test]
    fn rules_target_devin_cli_matches_user_config_directory() {
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let rules = team_rules_target("devin-cli", &home, platform).expect("supported");
            let config = resolve_client_config_path("devin-cli", &home, platform).unwrap();
            assert_eq!(rules.path.parent(), config.parent(), "{platform:?}");
            assert!(rules.path.ends_with("AGENTS.md"));
        }
    }

    #[test]
    fn rules_target_zed_is_platform_specific() {
        let win = team_rules_target("zed", &mock_home(Platform::Windows), Platform::Windows)
            .expect("supported");
        assert!(win.path.to_string_lossy().contains("Zed"));
        let mac = team_rules_target("zed", &mock_home(Platform::MacOs), Platform::MacOs)
            .expect("supported");
        assert!(mac
            .path
            .ends_with(PathBuf::from(".config").join("zed").join("AGENTS.md")));
    }

    #[test]
    fn rules_target_goose_matches_config_directory() {
        // Rules sit beside config.yaml so the two path families cannot drift
        // (SBS-899). Windows uses the etcetera config dir; macOS/Linux stay on
        // Goose's documented ~/.config/goose (macOS config in Toolport is
        // Application Support — a pre-existing split, listed in the PR).
        for platform in Platform::ALL {
            let home = mock_home(platform);
            let rules = team_rules_target("goose", &home, platform).expect("supported");
            let config =
                resolve_client_config_path("goose", &home, platform).expect("goose config");
            match platform {
                Platform::Windows => {
                    assert_eq!(
                        rules.path,
                        home.join("AppData")
                            .join("Roaming")
                            .join("Block")
                            .join("goose")
                            .join("config")
                            .join(".goosehints")
                    );
                    assert_eq!(rules.path.parent(), config.parent());
                }
                Platform::MacOs | Platform::Linux => {
                    assert_eq!(
                        rules.path,
                        home.join(".config").join("goose").join(".goosehints")
                    );
                }
            }
        }
    }

    #[test]
    fn rules_target_unsupported_clients_return_none() {
        // Cursor/Warp store globals in UI/cloud; chat/identity apps have no global rules file
        // we manage. Continue has no global rules FILE either: `.continue/rules/` is
        // workspace-local, and its user-level rules are a `rules:` array inside
        // `~/.continue/config.yaml` whose entries are hub refs or `file://` paths. That fits
        // neither strategy here - it is a YAML list in the same file we already write MCP config
        // into, not a markdown file we can own or bracket with sentinels. With
        // `continuedev/continue` archived read-only in June 2026, a third strategy for one dead
        // client is not worth building. It stays a detected MCP client for pinned builds and forks.
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
                team_rules_target(id, &mock_home(Platform::MacOs), Platform::MacOs).is_none(),
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
            team_rules_target("antigravity", &home, p),
            team_rules_target("gemini-cli", &home, p),
            "Antigravity shares Gemini's GEMINI.md"
        );
        assert_eq!(
            team_rules_target("vscode", &home, p),
            team_rules_target("claude-code", &home, p),
            "VS Code Copilot shares Claude Code's rules file"
        );
    }

    /// Serializes tests that read or mutate the process-global XDG env vars. Rust
    /// runs tests in parallel, so without this the test that sets `XDG_CONFIG_HOME`
    /// could change `dirs::config_dir()` mid-flight under a test that reads it,
    /// which is exactly what made `client_config_paths_match_current_platform`
    /// flake on CI. Lives on the module (see [`super::env_test_lock`]) so tests in
    /// other modules that set the same keys take the SAME lock.
    use super::ENV_TEST_LOCK as ENV_LOCK;

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
        // kimi_code_path() honors KIMI_CODE_HOME; clear it so the wrapper matches
        // the static resolver used for the expected path.
        let _kimi_home = EnvRestore::set("KIMI_CODE_HOME", Path::new(""));
        // This asserts the documented default table, so neutralize the Claude Code
        // config-dir override the host may have exported (a Claude Code session
        // running these tests has it set, which legitimately relocates
        // `.claude.json`). The override itself is covered by
        // `claude_code_config_follows_a_relocated_config_dir`.
        let _claude_config_dir = EnvRestore::set("CLAUDE_CONFIG_DIR", Path::new(""));
        // Same class as CLAUDE_CONFIG_DIR: neutralize relocate envs the host
        // (or a parallel test) may have exported so this asserts the default table.
        let _codex_home = EnvRestore::set("CODEX_HOME", Path::new(""));
        let _gemini_cli_home = EnvRestore::set("GEMINI_CLI_HOME", Path::new(""));
        let _grok_home = EnvRestore::set("GROK_HOME", Path::new(""));
        let _qwen_home = EnvRestore::set("QWEN_HOME", Path::new(""));
        // goose_path / client_config_path honor GOOSE_PATH_ROOT; clear it so this
        // table assertion stays on the documented default (SBS-899).
        let _goose_root = EnvRestore::set("GOOSE_PATH_ROOT", Path::new(""));
        let home = home().expect("home dir should be available in tests");
        // Only the non-Linux expectation takes a Platform; the Linux branch below
        // resolves without one, so gate the binding the same way to keep the
        // Linux build warning-free.
        #[cfg(not(all(unix, not(target_os = "macos"))))]
        let platform = Platform::current();
        for client in defs() {
            // These probe alternate on-disk locations (Antigravity subdirs, Claude
            // Desktop MSIX virtualized config), so the resolved path legitimately
            // depends on what is installed on the host rather than on the static
            // table.
            if matches!(client.id, "antigravity" | "claude-desktop") {
                continue;
            }
            // Hermes only probes on Windows, where `%LOCALAPPDATA%\hermes` makes the
            // answer host-dependent. Everywhere else `hermes_path` passes no platform
            // root at all and is a pure function of home, so it stays covered here.
            // The Windows behaviour is covered by
            // `hermes_path_falls_back_to_the_platform_dir_only_when_home_has_no_config`.
            if cfg!(windows) && client.id == "hermes" {
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
            ("crush", |home, _| {
                home.join(".config").join("crush").join("crush.json")
            }),
            ("grok", |home, _| home.join(".grok").join("config.toml")),
            ("github-copilot-cli", |home, _| {
                home.join(".copilot").join("mcp-config.json")
            }),
            ("devin-cli", |home, platform| match platform {
                Platform::Windows => roaming_config_dir(home, platform)
                    .join("devin")
                    .join("mcp_config.json"),
                Platform::MacOs | Platform::Linux => {
                    home.join(".config").join("devin").join("mcp_config.json")
                }
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
            ("kimi-code", |home, _| {
                home.join(".kimi-code").join("mcp.json")
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
        // Absolute GOOSE_PATH_ROOT wins over XDG; neutralize it so this test
        // pins the XDG branch (SBS-899).
        let _goose_root = EnvRestore::set("GOOSE_PATH_ROOT", Path::new(""));

        let home = home().expect("home dir");
        let vscode = client_config_path("vscode").unwrap();
        let jan = client_config_path("jan").unwrap();
        let crush = client_config_path("crush").unwrap();
        let zed = client_config_path("zed").unwrap();
        let goose = client_config_path("goose").unwrap();
        let anythingllm = client_config_path("anythingllm").unwrap();
        let devin_cli = client_config_path("devin-cli").unwrap();
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
        assert_eq!(crush, xdg_config.join("crush").join("crush.json"));
        assert_eq!(zed, xdg_config.join("zed").join("settings.json"));
        assert_eq!(goose, xdg_config.join("goose").join("config.yaml"));
        assert_eq!(devin_cli, xdg_config.join("devin").join("mcp_config.json"));
        assert_eq!(
            anythingllm,
            xdg_config
                .join("anythingllm-desktop")
                .join("storage")
                .join("plugins")
                .join("anythingllm_mcp_servers.json")
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

    /// SBS-899: Team Instructions for Goose/Zed must land in the same XDG
    /// config dir as Connect already writes (`client_config_path`). Without
    /// this, a user with `XDG_CONFIG_HOME=/data/cfg` gets a successful write
    /// to `~/.config/...` that Goose/Zed never read.
    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn client_rules_paths_honor_xdg_dirs_on_linux() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("conduit-xdg-rules-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let xdg_config = base.join("xdg-config");
        std::fs::create_dir_all(&xdg_config).unwrap();

        let _xdg = EnvRestore::set("XDG_CONFIG_HOME", &xdg_config);
        let _goose_root = EnvRestore::set("GOOSE_PATH_ROOT", Path::new(""));

        let goose = client_rules_target("goose", crate::instructions::Scope::Team)
            .expect("goose has a rules target");
        let zed = client_rules_target("zed", crate::instructions::Scope::Team)
            .expect("zed has a rules target");
        let devin_cli = client_rules_target("devin-cli", crate::instructions::Scope::Team)
            .expect("Devin CLI has a rules target");
        let goose_config = client_config_path("goose").expect("goose config");
        let zed_config = client_config_path("zed").expect("zed config");
        let devin_cli_config = client_config_path("devin-cli").expect("Devin CLI config");

        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            goose.path,
            xdg_config.join("goose").join(".goosehints"),
            "Goose Team Instructions must follow XDG_CONFIG_HOME"
        );
        assert_eq!(
            zed.path,
            xdg_config.join("zed").join("AGENTS.md"),
            "Zed Team Instructions must follow XDG_CONFIG_HOME"
        );
        assert_eq!(
            goose.path.parent(),
            goose_config.parent(),
            "Goose rules and config must share a directory so the two families cannot drift"
        );
        assert_eq!(
            zed.path.parent(),
            zed_config.parent(),
            "Zed rules and config must share a directory so the two families cannot drift"
        );
        assert_eq!(
            devin_cli.path,
            xdg_config.join("devin").join("AGENTS.md"),
            "Devin CLI rules must follow XDG_CONFIG_HOME"
        );
        assert_eq!(devin_cli.path.parent(), devin_cli_config.parent());
    }

    /// SBS-899: absolute GOOSE_PATH_ROOT relocates both config.yaml and
    /// .goosehints to `<root>/config/`, matching Goose `Paths::get_dir`.
    #[test]
    fn goose_path_root_relocates_config_and_rules() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("goose-root-{}", std::process::id()));
        let _restore = EnvRestore::set("GOOSE_PATH_ROOT", &root);

        assert_eq!(
            client_config_path("goose"),
            Some(root.join("config").join("config.yaml"))
        );
        assert_eq!(
            client_rules_target("goose", crate::instructions::Scope::Team)
                .expect("goose has a rules target")
                .path,
            root.join("config").join(".goosehints")
        );
    }

    /// SBS-899: an absolute GOOSE_PATH_ROOT names the live config outright, so it must
    /// resolve with no home directory at all. `client_rules_target` already did, so
    /// without this the rules file relocates but the config beside it comes back `None`
    /// and Connect cannot write the gateway entry. Same rule `codex_path` applies to
    /// `CODEX_HOME` (SBS-885).
    #[test]
    fn goose_path_root_resolves_without_a_home_dir() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("goose-nohome-{}", std::process::id()));
        let _restore = EnvRestore::set("GOOSE_PATH_ROOT", &root);

        assert_eq!(
            client_config_path_with_home("goose", None),
            Some(root.join("config").join("config.yaml")),
            "an absolute GOOSE_PATH_ROOT must not depend on a resolvable home dir"
        );
        // The override is Goose-only: every other client still needs a home.
        assert_eq!(client_config_path_with_home("zed", None), None);
    }

    /// Relative / empty GOOSE_PATH_ROOT is ignored — same rule as
    /// `CLAUDE_CONFIG_DIR` and Goose's own `validated_path_root`.
    #[test]
    fn goose_path_root_relative_or_empty_is_ignored() {
        assert_eq!(goose_path_root_from(None), None);
        assert_eq!(
            goose_path_root_from(Some(std::ffi::OsString::from(""))),
            None
        );
        assert_eq!(
            goose_path_root_from(Some(std::ffi::OsString::from("relative/goose"))),
            None
        );
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\\abs\\goose")
        } else {
            PathBuf::from("/abs/goose")
        };
        assert_eq!(
            goose_path_root_from(Some(absolute.clone().into_os_string())),
            Some(absolute)
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

    #[test]
    fn stable_gateway_copy_replaces_same_size_different_bytes() {
        // AppImage updates often rebuild the gateway at the same length. Size-only
        // stale detection would leave clients on the previous copy.
        let _lock = crate::registry::data_dir_test_lock();
        let scratch = std::env::temp_dir().join(format!(
            "toolport-stable-gw-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let _data_dir = crate::registry::DataDirOverride::set(&scratch);

        let fixture_a = b"gateway-binary-AAAA";
        let fixture_b = b"gateway-binary-BBBB";
        assert_eq!(
            fixture_a.len(),
            fixture_b.len(),
            "fixtures must be equal length so size-only detection would skip the copy"
        );

        let dest_dir = scratch.join("bin");
        std::fs::create_dir_all(&dest_dir).unwrap();
        let dest = dest_dir.join("toolport-gateway");
        std::fs::write(&dest, fixture_a).unwrap();

        let src_dir = scratch.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        let src = src_dir.join("toolport-gateway");
        std::fs::write(&src, fixture_b).unwrap();

        let copied = stable_gateway_copy(&src).expect("same-size newer src must recopy");
        assert_eq!(copied, dest);
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            fixture_b,
            "dest must match the newer src, not the equal-length previous copy"
        );

        // Same-content same-size is not a failure; dest still matches src.
        let again = stable_gateway_copy(&src).expect("identical src must still succeed");
        assert_eq!(again, dest);
        assert_eq!(std::fs::read(&dest).unwrap(), fixture_b);

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// Scratch dir + src/dest fixture pair for the stable-copy tests.
    fn stable_gw_fixture(
        tag: &str,
        dest_bytes: &[u8],
        src_bytes: &[u8],
    ) -> (PathBuf, PathBuf, PathBuf) {
        let scratch = std::env::temp_dir().join(format!(
            "toolport-stable-gw-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        let dest_dir = scratch.join("bin");
        let src_dir = scratch.join("src");
        std::fs::create_dir_all(&dest_dir).unwrap();
        std::fs::create_dir_all(&src_dir).unwrap();
        let dest = dest_dir.join("toolport-gateway");
        let src = src_dir.join("toolport-gateway");
        std::fs::write(&dest, dest_bytes).unwrap();
        std::fs::write(&src, src_bytes).unwrap();
        (scratch, src, dest)
    }

    #[test]
    fn stable_gateway_copy_keeps_existing_copy_when_refresh_fails() {
        // The refresh can legitimately fail: on Linux, overwriting the stable
        // gateway while a client keeps one running returns ETXTBSY. Giving up
        // here would make resolve_gateway_path fall through to the
        // AppImage-internal /tmp/.mount_XXXX path, and that path is written into
        // the client's config and dies with the mount. A stale-but-reachable
        // stable copy is the right answer instead.
        let (scratch, src, dest) =
            stable_gw_fixture("busy", b"gateway-binary-AAAA", b"gateway-binary-BBBB");

        let attempted = std::cell::Cell::new(false);
        let out = stable_gateway_copy_with(&src, dest.clone(), |_, _| {
            attempted.set(true);
            Err(std::io::Error::other("ETXTBSY"))
        });

        assert!(attempted.get(), "a stale copy must attempt a refresh");
        assert_eq!(
            out,
            Some(dest.clone()),
            "a failed refresh must still return the existing stable path, \
             never fall through to the ephemeral mount"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"gateway-binary-AAAA",
            "the previous copy must be left intact"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn stable_gateway_copy_gives_up_when_no_stable_copy_exists() {
        // With nothing usable at dest there is no stable path to hand back, so
        // the caller should be told to look elsewhere.
        let (scratch, src, dest) = stable_gw_fixture("nodest", b"", b"gateway-binary-BBBB");
        std::fs::remove_file(&dest).unwrap();

        let out = stable_gateway_copy_with(&src, dest.clone(), |_, _| {
            Err(std::io::Error::other("ETXTBSY"))
        });
        assert_eq!(out, None, "no stable copy at all must return None");

        // A zero-length leftover is not a usable gateway either.
        std::fs::write(&dest, b"").unwrap();
        let out = stable_gateway_copy_with(&src, dest.clone(), |_, _| {
            Err(std::io::Error::other("ETXTBSY"))
        });
        assert_eq!(
            out, None,
            "an empty leftover must not be handed to a client"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn stable_gateway_copy_skips_the_write_when_content_matches() {
        let (scratch, src, dest) =
            stable_gw_fixture("fresh", b"gateway-binary-AAAA", b"gateway-binary-AAAA");
        let attempted = std::cell::Cell::new(false);
        let out = stable_gateway_copy_with(&src, dest.clone(), |_, _| {
            attempted.set(true);
            Ok(())
        });
        assert_eq!(out, Some(dest));
        assert!(
            !attempted.get(),
            "an up-to-date copy must not be rewritten on every Connect"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn replace_gateway_copy_swaps_the_inode_and_sets_the_exec_bit() {
        // rename(2) over the destination is what makes the refresh survive a
        // running gateway (ETXTBSY). Prove we replaced the directory entry
        // rather than truncating the existing inode: a hard link taken before
        // the refresh must still read the OLD bytes afterwards, exactly as a
        // process executing the old binary would.
        use std::os::unix::fs::PermissionsExt;
        let (scratch, src, dest) =
            stable_gw_fixture("inode", b"gateway-binary-AAAA", b"gateway-binary-BBBB");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
        let witness = scratch.join("bin").join("old-inode");
        std::fs::hard_link(&dest, &witness).unwrap();

        replace_gateway_copy(&src, &dest).expect("refresh must succeed");

        assert_eq!(std::fs::read(&dest).unwrap(), b"gateway-binary-BBBB");
        assert_eq!(
            std::fs::read(&witness).unwrap(),
            b"gateway-binary-AAAA",
            "the old inode must be left alone, not truncated in place"
        );
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o755,
            "the swapped-in binary must already be executable"
        );

        // No temp files left behind in ~/.toolport/bin.
        let leftovers: Vec<_> = std::fs::read_dir(scratch.join("bin"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[cfg(unix)]
    #[test]
    fn replace_gateway_copy_cleans_up_after_a_failed_write() {
        let (scratch, src, dest) =
            stable_gw_fixture("cleanup", b"gateway-binary-AAAA", b"gateway-binary-BBBB");
        std::fs::remove_file(&src).unwrap();

        assert!(
            replace_gateway_copy(&src, &dest).is_err(),
            "a missing source must fail loudly"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"gateway-binary-AAAA",
            "a failed refresh must not damage the existing copy"
        );
        let leftovers: Vec<_> = std::fs::read_dir(scratch.join("bin"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn gateway_copy_is_stale_streams_large_files() {
        // The compare must stay correct on files bigger than one read chunk,
        // and must short-circuit on the first differing chunk.
        let big = vec![7u8; 300 * 1024];
        let mut differs_late = big.clone();
        *differs_late.last_mut().unwrap() = 9;
        let mut differs_early = big.clone();
        differs_early[0] = 9;

        let (scratch, src, dest) = stable_gw_fixture("big", &big, &big);
        assert!(!gateway_copy_is_stale(&src, &dest), "identical big files");

        std::fs::write(&src, &differs_late).unwrap();
        assert!(
            gateway_copy_is_stale(&src, &dest),
            "a difference in the final chunk must be caught"
        );

        std::fs::write(&src, &differs_early).unwrap();
        assert!(gateway_copy_is_stale(&src, &dest), "first-chunk difference");

        // Different lengths never reach the byte compare.
        std::fs::write(&src, b"short").unwrap();
        assert!(gateway_copy_is_stale(&src, &dest));

        // A missing source is treated as stale rather than "up to date".
        std::fs::remove_file(&src).unwrap();
        assert!(gateway_copy_is_stale(&src, &dest));

        let _ = std::fs::remove_dir_all(&scratch);
    }
}
