<div align="center">

<img src="docs/logo.svg" alt="Conduit" width="84" />

# Conduit

**One local gateway for all your MCP servers, shared by every AI client, with far fewer tokens.**

[![CI](https://github.com/tsouth89/conduit/actions/workflows/ci.yml/badge.svg)](https://github.com/tsouth89/conduit/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/tsouth89/conduit?label=release)](https://github.com/tsouth89/conduit/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-join%20the%20community-5865F2?logo=discord&logoColor=white)](https://discord.gg/Xsn27MxdBA)

</div>

![Conduit: every tool from all your servers, collapsed to the 3 your agent loads](docs/feature.png)

![Conduit demo: add a server, connect it to every AI tool, and the agent uses it](docs/demo.gif)

Conduit is a local MCP (Model Context Protocol) gateway. You set up and
authenticate each server once, and every AI client (Claude, Cursor, Codex, and
the rest) points at Conduit and shares them, so you stop configuring the same
servers separately in each app.

It also fixes what those servers cost your agent. Every MCP server you connect
dumps all of its tools into context on every single request, and it adds up fast:
just 3 servers (62 tools) cost ~24,000 tokens of definitions before you've asked
anything. Conduit advertises 3 meta-tools the agent searches on demand instead,
so it pays ~660 tokens.

**Measured on a frontier model: up to 91% fewer total tokens at the same task
success** (graded for correct answers, not just completion), plus 97% less
tool-definition overhead on every request, rising to 99.6% on a real 415-tool
catalog (see [BENCHMARK.md](BENCHMARK.md)). That holds whether you run one AI tool
or five, on cloud models (where tokens are your bill) or local ones (where tool defs
eat your context window).

## Screenshots

| Servers | Catalog | Activity |
|---|---|---|
| ![Every server in one dense list with health, secrets, and per-tool toggles](docs/screenshots/servers.png) | ![A curated catalog of MCP servers grouped by category](docs/screenshots/catalog.png) | ![Per-server latency, error rates, token savings, and tool-security notices](docs/screenshots/activity.png) |

## Why

Every MCP server you connect dumps its full tool list into your agent's context on
every request, and most AI clients also want their own separate configuration. So you
pay a token tax on every call and reconfigure the same servers in every app. Conduit
fixes both.

### Fewer tokens

- **~90% fewer tokens.** In lazy-discovery mode the gateway advertises three meta-tools
  (`conduit_status`, `conduit_search_tools`, `conduit_call_tool`) instead of the full
  catalog, and the agent searches and calls on demand, so context stays flat no matter
  how many servers you connect. Benchmarked, graded for correct answers: up to 91% fewer
  total tokens at the same task success, 97% less tool-definition overhead per request,
  99.6% at a real 415-tool catalog ([BENCHMARK.md](BENCHMARK.md)). Ask `conduit_status`
  for what it has saved you so far.
- **Search by intent, not just keywords.** `conduit_search_tools` ranks by relevance
  across every server, and no tool is ever hidden, any server's full set is one call
  away. Optional semantic re-ranking (a local or hosted embeddings endpoint) surfaces
  paraphrased needs like "charge a card"; off by default, pure lexical otherwise.

### One setup, every client

- **Set up once, use everywhere.** Each client points at one gateway. Add and
  authenticate a server a single time and it appears in every client.
- **Per-agent scoping.** Give each client only the servers it should see. A coding
  agent literally cannot call a billing tool that isn't in its profile.
- **Obvious auth.** OAuth or API key, stored once in the OS keychain, a single click per
  server. Newly-authed servers propagate to connected clients without a restart.
- **No secrets in client configs.** Clients only ever say "talk to Conduit." Keys live
  in the OS keychain and are injected at runtime.
- **A catalog to grow.** Add popular servers from a curated list of 40+, or search the
  official MCP Registry, then authenticate through the same flow.

### Security, because the gateway is on the path

- **Tool integrity (rug-pull + poisoning detection).** Conduit fingerprints each tool
  when you connect a server and flags it if the definition later changes or a server
  quietly adds one (a "rug pull"), or if a description or schema carries injection-like
  content ("tool poisoning"). Detection only, on by default, entirely local
  ([details](docs/specs/mcp-integrity.md)).
- **Content defense (anti-agentjacking).** When a tool *returns* untrusted content (a
  Sentry error, a web page, an issue body) with injection-like instructions, Conduit
  flags it and marks it as external data, not instructions, the separation that blunts
  indirect prompt injection. Never blocks, on by default
  ([details](docs/specs/content-defense.md)).
- **Governance and audit.** Toggle any tool on or off, or hide every destructive tool
  from every client with one switch. Every call is recorded with per-server latency and
  error rates.

### Control and extras

- **Agent control, on your terms.** Optionally let an agent enable or disable servers
  through the gateway (`conduit_enable_server` / `conduit_disable_server`), reflected in
  the app live. Off by default, and the destructive-tool switch always stays yours.
- **Full MCP, not just tools.** Tools, resources, and prompts are all proxied.
- **Test before you wire it up.** A built-in playground invokes any tool with a form
  generated from its schema, so you can confirm a server works without configuring a
  client first.
- **Diagnostics in one click.** Bundles your version, OS, a secrets-stripped server
  summary, and the recent gateway log, ready to paste into a bug report.

## How it works

Conduit has two pieces:

1. **The desktop app** (Tauri + React) where you manage servers, profiles,
   credentials, and which clients are connected.
2. **The gateway binary** (`conduit-gateway`) that each AI client launches over
   stdio. It reads Conduit's registry, connects to the enabled downstream servers
   (stdio or remote HTTP/SSE), and routes tool calls to the right one. Tool names
   are namespaced per server (`stripe__list_charges`) so they never collide.

```
AI client (Cursor / Claude / Codex / Antigravity / ...)
        │  stdio MCP
        ▼
  conduit-gateway  ──reads──►  registry.json + OS keychain
        │  routes tools/calls
        ▼
  downstream MCP servers (Stripe, Supabase, GitHub, ...)
```

The registry is the shared source of truth; the gateway watches it and rebuilds
live, so toggles and new credentials take effect without restarting the client.
If a connected server changes its own tool set mid-session, Conduit picks that up
and refreshes too.

## Supported clients

Conduit auto-detects these **19 AI clients**, installs the gateway into each with one
click, and can import a client's existing servers. It writes the config file shown
below for you, so you never have to edit these by hand.

| Client | Config file | Format |
| --- | --- | --- |
| Claude Desktop | `<config>/Claude/claude_desktop_config.json` | JSON (`mcpServers`) |
| Claude Code | `~/.claude.json` | JSON (`mcpServers`) |
| Cursor | `~/.cursor/mcp.json` | JSON (`mcpServers`) |
| VS Code | `<config>/Code/User/mcp.json` | JSON (`servers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | JSON (`mcpServers`) |
| Codex | `~/.codex/config.toml` | TOML (`mcp_servers`) |
| Antigravity | `~/.gemini/config/mcp_config.json` | JSON (`mcpServers`) |
| Gemini CLI | `~/.gemini/settings.json` | JSON (`mcpServers`) |
| Cline | `<config>/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | JSON (`mcpServers`) |
| Roo Code | `<config>/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json` | JSON (`mcpServers`) |
| Warp | `~/.warp/.mcp.json` | JSON (`mcpServers`) |
| Amazon Q | `~/.aws/amazonq/mcp.json` | JSON (`mcpServers`) |
| Kiro | `~/.kiro/settings/mcp.json` | JSON (`mcpServers`) |
| Zed | `~/.config/zed/settings.json` | JSON (`context_servers`) |
| LM Studio | `~/.lmstudio/mcp.json` | JSON (`mcpServers`) |
| Jan | `<data>/Jan/data/mcp_config.json` | JSON (`mcpServers`) |
| BoltAI | `~/.boltai/mcp.json` | JSON (`mcpServers`) |
| Goose | `~/.config/goose/config.yaml` | YAML (`extensions`) |
| Hermes | `~/.hermes/config.yaml` | YAML (`mcp_servers`) |

`<config>` is your OS application-config dir (`%APPDATA%` on Windows, `~/Library/Application Support` on macOS, `~/.config` on Linux); `<data>` is the data dir (`~/.local/share` on Linux, the same as `<config>` elsewhere). Zed and Goose paths vary slightly by OS; Conduit resolves the right one automatically.

### Open WebUI and other HTTP/OpenAPI consumers

The gateway speaks HTTP/OpenAPI natively, so Open WebUI (and any OpenAPI tool
client) connects straight to Conduit, no bridge or proxy. Flip on **Settings ->
Integrations -> Open WebUI / HTTP endpoint** in the app (or run
`conduit-gateway --http 8765`), then add `http://localhost:8765` as an OpenAPI
tool server. See [docs/openwebui.md](docs/openwebui.md). The same endpoint serves
any HTTP/OpenAPI MCP consumer (n8n, LibreChat, custom agents).

## Configuration

Lazy discovery, the destructive-tool block, and agent control are global settings,
stored in the registry and toggled in the app's Settings view, so they apply to every
client (lazy discovery is on by default). Per-client behavior is set via env vars on the
gateway entry, written for you when you connect a client:

- `CONDUIT_PROFILE=<name>` - scope this client to one profile's servers. Unset =
  the active profile.
- `CONDUIT_DISCOVERY=lazy|full` - optional per-client override of the global lazy
  setting. Rarely needed; the gateway reads the registry default otherwise.
- `CONDUIT_REGISTRY=<path>` - override the registry file location. Defaults to a
  stable per-user path so packaged and unpackaged clients agree.
- `CONDUIT_RESULT_BUDGET=<bytes>` - cap oversized tool results at this many bytes
  (0 disables it). Optional; off by default.
- `CONDUIT_HTTP=<port>` (with optional `CONDUIT_HTTP_HOST`, default `127.0.0.1`,
  and `CONDUIT_HTTP_TOKEN` for the required bearer token) - run the gateway in
  HTTP/OpenAPI mode instead of stdio, for Open WebUI and other OpenAPI clients (see
  above). The in-app Settings -> Integrations toggle sets these for you, and the
  gateway refuses a non-loopback bind without a token.

**Semantic search (optional).** Lazy discovery ranks tools lexically by default. Point it
at any `/v1/embeddings` endpoint (LM Studio, Ollama, or a cloud provider) to blend in
embedding similarity for paraphrased queries: `CONDUIT_SEMANTIC=on`,
`CONDUIT_EMBED_ENDPOINT`, `CONDUIT_EMBED_MODEL`, plus optional `CONDUIT_EMBED_KEY`
(endpoint auth) and `CONDUIT_EMBED_BLEND`. See
[docs/specs/semantic-search.md](docs/specs/semantic-search.md).

**Multiple accounts for the same service.** Credentials belong to a server, not a
profile. To use, say, a work and a personal GitHub, add GitHub twice as two
servers ("GitHub (work)", "GitHub (personal)"), authenticate each with its own
account, and enable one in each profile. A client scoped to the work profile
(`CONDUIT_PROFILE`) then only ever sees the work account. Tool names are
namespaced per server, so the two never collide even in the same profile.

## Install

Prebuilt installers are published on the
[Releases](https://github.com/tsouth89/conduit/releases) page. Conduit runs on
**Windows and macOS** (both builds are code-signed; macOS is also notarized), with
**Linux** in beta. On Linux, prefer the **`.deb`** (it links your system's WebKitGTK and is
the most reliable package); the **AppImage** is a portable, no-root fallback but
can clash with very new or virtualized graphics stacks (see Troubleshooting). To
run from source, see Development below.

Both the **Windows** and **macOS** installers are code-signed (macOS is also
notarized). macOS installs cleanly through Gatekeeper. On Windows the installer is
signed with your validated publisher name (no "unknown publisher"), but because it
uses a standard certificate rather than EV, SmartScreen reputation still builds with
downloads, so an early install may still show "Windows protected your PC", click
**More info -> Run anyway** to continue. The **Linux** packages are unsigned, as is
typical. See [docs/SIGNING.md](docs/SIGNING.md) for details.

**Updating and uninstalling on Linux.** There is no graphical uninstaller, use the
terminal. The package name is `conduit`.

```bash
# Update to a newer version: just install the new .deb, it upgrades in place.
sudo apt install ./Conduit_0.6.0_amd64.deb

# Uninstall (keeps your config + saved secrets).
sudo apt remove conduit

# Uninstall and wipe app config too (secrets in the keyring stay).
sudo apt purge conduit
```

If you used the **AppImage**, there's nothing to uninstall, just delete the
`.AppImage` file. (On Windows use Add or Remove Programs; on macOS drag
**Conduit.app** to the Trash.)

## Development

Requires Node and the Rust toolchain.

```bash
npm install
npm run tauri dev      # run the desktop app
```

Other useful commands:

```bash
cargo test --manifest-path src-tauri/Cargo.toml   # Rust unit tests (lib + gateway)

# Build the gateway binary. Required when running from source: AI clients spawn
# this binary directly, so without it a connected client reports "not found".
# (Packaged releases bundle it, so installed users never need this.)
npm run build:gateway

# Build a Windows installer (NSIS) with the gateway bundled.
npm run tauri:bundle
```

The frontend is typechecked with `npx tsc --noEmit`.

## Troubleshooting

- **OAuth opens a blank page (macOS).** The OAuth flow redirects back to a local
  `http://127.0.0.1` callback. Safari can silently block that redirect, so the
  sign-in page renders blank. Set **Chrome or Brave** as your default browser (or
  paste an access token instead). Complete one attempt at a time, an abandoned
  attempt keeps the callback port reserved for a few minutes and can cause a
  "state mismatch" on the next try.
- **A client reports the gateway "was not found" (running from source).** Build
  the gateway binary once: `cd src-tauri && cargo build --bin conduit-gateway`.
  `npm run tauri dev` builds the app but not this separate binary; packaged
  releases bundle it, so installed users never hit this.
- **Repeated macOS keychain prompts / "could not read secret from the keychain"
  in dev.** An unsigned dev build gets an unstable code-signing identity, so the
  keychain re-prompts or denies reads. A signed release fixes this; it is a
  dev-only artifact.
- **"could not read/store secret" on Linux.** Secret storage uses the freedesktop
  Secret Service (libsecret), provided by GNOME Keyring, KWallet, or similar. A
  headless box or a session without a running keyring daemon has nowhere to store
  secrets. Run Conduit in a desktop session, or install and unlock a keyring
  (e.g. `gnome-keyring`).
- **macOS keychain prompt the first time the gateway runs.** When a client spawns
  the gateway and it reads a saved key, macOS asks for keychain access ("Conduit
  wants to use ..."). Click **Always Allow** once and it won't ask again. (The app
  and the gateway are separate signed binaries today; a future release will share
  keychain access so this prompt goes away.)
- **VS Code: the conduit server doesn't start automatically.** VS Code may require
  you to click **Start Server** on the conduit MCP entry the first time, that's VS
  Code's own MCP handling, not Conduit. After that it reconnects on its own.
- **Linux: the AppImage won't launch / no window (`EGL_BAD_PARAMETER`).** The
  AppImage bundles its own libraries, which can clash with a very new or
  virtualized graphics stack (e.g. VMware's `vmwgfx` driver, where the default EGL
  display fails). **Use the `.deb` instead**, it links your system's WebKitGTK and
  is the more reliable Linux package. If you must use the AppImage, try
  `EGL_PLATFORM=surfaceless ./Conduit_*.AppImage`, or in a VM enable 3D
  acceleration. (This is a packaging/GPU issue, not a Conduit bug; the `.deb` works
  where the AppImage doesn't.)

## Status

Conduit is in active development. Working end to end: the
gateway, lazy discovery, per-agent scoping, OAuth/key auth with live propagation,
the catalog, client import/migrate, per-tool and destructive-tool governance, a global
Settings view, tool-integrity and content-defense detection, an audit log with
latency/error stats, resources + prompts proxying, and a tool playground. See
[docs/ROADMAP.md](docs/ROADMAP.md) for what is done and planned.

## Known issues

- **Linux only, glib `VariantStrIter` soundness ([RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429)).**
  Tauri's Linux webview stack pulls in `glib` 0.18 transitively (`wry → webkit2gtk →
  gtk 0.18 → glib 0.18`). The fix only exists in `glib` 0.20+, and the gtk-0.18
  binding line, which is what Tauri 2 uses on Linux, hard-pins `glib = "^0.18"`, so
  the patched release cannot be selected without moving the whole webview stack. The
  bug is a soundness/null-deref crash (not remote code execution), is confined to the
  webview binding layer (Conduit never calls `VariantStrIter`), and does not affect
  the Windows or macOS builds. We are tracking the upstream move to a glib-0.20 stack
  and will apply a `[patch.crates-io]` backport if Linux crashes surface before then.

## License

[MIT](LICENSE), and the local app and gateway always will be. Conduit follows an
open-core model: the desktop app and `conduit-gateway` are free and open source,
and a separate commercial product, Conduit Teams (shared/hosted gateway, RBAC/SSO,
policy, audit export, secret-vault integrations), funds the free app. Anything you
contribute here is MIT and benefits everyone, see [CONTRIBUTING.md](CONTRIBUTING.md).
