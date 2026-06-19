# Conduit

**One gateway for all your MCP servers, across every AI agent.**

Conduit is a local MCP (Model Context Protocol) gateway and manager. You set up
and authenticate each MCP server once in Conduit, point your AI agents at the
single Conduit gateway, and every server is instantly available in all of them.
No more configuring the same servers separately in Cursor, Claude, Codex, and
the rest.

Built for people who use more than one AI coding tool and are tired of managing
MCP servers per app.

## Why

Every AI client wants its own MCP configuration. Run a handful of agents and you
end up configuring the same servers several times, re-authenticating in each, and
drowning every agent in hundreds of tool definitions. Conduit fixes that:

- **Set up once, use everywhere.** Each client points at one Conduit gateway.
  Add a server and authenticate it a single time; it appears in every client.
- **Small context, not hundreds of tools.** In lazy-discovery mode the gateway
  advertises three meta-tools (`conduit_status`, `conduit_search_tools`,
  `conduit_call_tool`) instead of the full catalog. The agent searches and calls
  on demand, so context stays flat no matter how many servers you connect.
- **Per-agent scoping.** Give each client only the servers it should see. A
  coding agent literally cannot call a billing tool that is not in its profile.
- **Obvious auth.** OAuth or API key, stored once in the OS keychain. Status is
  shown per server; a single click authenticates. Newly-authed servers propagate
  to connected clients without a restart.
- **A catalog to grow.** Add popular servers from a curated list or search the
  official MCP Registry, then authenticate through the same flow.
- **No secrets in client configs.** Clients only ever say "talk to Conduit." Keys
  live in the OS keychain and are injected at runtime.

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

## Supported clients

Cursor, Claude Desktop, Claude Code, Codex, Google Antigravity, VS Code,
Windsurf, Gemini CLI, Cline, Roo Code. Conduit detects each one, installs the
gateway with one click, and can import a client's existing servers.

## Configuration (gateway env vars)

The gateway is configured per client via env vars on its entry, set for you when
you connect a client:

- `CONDUIT_DISCOVERY=lazy` - expose the three meta-tools instead of the full
  catalog (recommended; keeps context small). Unset = full direct catalog.
- `CONDUIT_PROFILE=<name>` - scope this client to one profile's servers. Unset =
  the active profile.
- `CONDUIT_REGISTRY=<path>` - override the registry file location. Defaults to a
  stable per-user path so packaged and unpackaged clients agree.

## Development

Requires Node and the Rust toolchain.

```bash
npm install
npm run tauri dev      # run the desktop app
```

Other useful commands:

```bash
cd src-tauri
cargo test             # Rust unit tests (lib + gateway)
cargo build --bin conduit-gateway   # build just the gateway binary
```

The frontend is typechecked with `npx tsc --noEmit`.

## Status

Conduit is in active development. The core is working end to end: gateway,
lazy discovery, per-agent scoping, auth with live propagation, the catalog, and
client import/migrate. See [docs/ROADMAP.md](docs/ROADMAP.md) for what is done
and what is planned.

## License

Open core. The gateway and local manager are intended to be free and open
source; team/enterprise features (shared/hosted gateway, RBAC/SSO, policy, audit
export, secret-vault integrations) are the planned paid layer.
