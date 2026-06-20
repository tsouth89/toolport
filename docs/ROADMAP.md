# Conduit roadmap

Conduit is a cross-platform manager for MCP servers across AI coding tools
(Claude Desktop, Cursor, VS Code, Windsurf, Codex CLI). This document is the
working spec. It captures the architecture decision and the build order.

**Status (2026-06-20):** shipping. Signed/notarized macOS (Apple Silicon + Intel),
Windows, and Linux (deb/AppImage) builds via a tag-triggered release pipeline. v0.3.x
released. Next: macOS keychain access-group entitlement, auto-updater, and the
launch (Product Hunt, MCP registry).

## The core decision: Conduit is a gateway, not a file editor

A tool that only edits each client's MCP JSON config is a dead end:

1. Clients are migrating servers out of the JSON file into UI-managed,
   account-synced connectors (Claude already has). The JSON file is emptying.
2. Editing a config file requires restarting the client for changes to take
   effect, so "toggle a server on/off without reloading the app" is impossible
   with the file-editor approach.

Conduit instead runs a **local MCP gateway**. Each client points at Conduit
once (as a local stdio server and/or a custom connector URL). Conduit holds the
real registry of servers and routes to them. This flips every weakness:

- **Hot toggle, no restart.** Enable/disable a server, the gateway re-emits its
  tool list via the MCP `notifications/tools/list_changed`; supporting clients
  update live. The client's own config never changed, so nothing reloads.
- **No plaintext secrets in client configs.** The gateway holds keys in the OS
  keychain and injects them at runtime. Client config only says "talk to Conduit."
- **Audit log for free.** Every tool call flows through the gateway. That log is
  the governance/MSP product.
- **Routes around the connector migration.** Conduit registers as one custom
  connector in Claude; all managed servers appear through it.

## Spike findings (2026-06-18)

### Spike 42: can we read Claude's connectors from disk? (Partially, but fragile)

- Claude Desktop's `claude_desktop_config.json` `mcpServers` is **empty** on this
  machine. All servers moved to connectors.
- Connectors + OAuth tokens live in `%APPDATA%\Claude\config.json` as
  **DPAPI-encrypted** blobs (Chromium safeStorage, `v10` prefix). Not readable.
- Connector *names* (Clerk, GitHub, Pax8, revenuecat, Supabase, Vercel, Stripe,
  expo) DO appear in plaintext in the Chromium LevelDB/IndexedDB stores for the
  `claude.ai` origin.
- BUT those stores are **locked while Claude is running**, the schema is
  undocumented Chromium IndexedDB, and the real source of truth is the user's
  Anthropic account (server-side sync), not a local file.

**Verdict:** local read-only *inventory* of connector names is possible but
fragile and operationally awkward (locked DBs, undocumented schema, account-side
truth). It is NOT a foundation to build *management* on. This confirms the
gateway architecture: Conduit cannot manage Claude's connectors directly, so it
becomes one connector that fans out to everything it manages. A best-effort,
read-only "connectors detected (view-only)" panel is worth showing for the
governance inventory story, clearly labeled as not-managed.

### Spikes 40 and 41 (need morning verification on running clients)

- Spike 40 (live toggle): confirm `tools/list_changed` actually refreshes the
  tool list without restart in each client. Determines how universal hot-toggle is.
- Spike 41 (Claude as connector): confirm Conduit can register as a custom
  connector / local server in current Claude Desktop and expose downstream tools.

These require driving real client UIs and were deferred (user asleep; not safe to
mutate their live client setup unattended).

## Build order

Phase 0 - Foundation
- [x] Tauri + React + Rust scaffold, 0 vulns
- [x] Client adapter readers (import/discovery): detect clients, parse JSON/TOML
- [x] Conduit registry: own source-of-truth store (servers, profiles, enabled)
- [x] Profiles: named server sets, switchable
- [x] Write-back adapters with auto-backup (fixture-tested)
- [x] Frontend: profiles, toggles, import, add-server
- [x] OS keychain module for secrets

Phase 1 - The gateway
- [x] MCP stdio server (initialize, tools/list, tools/call)
- [x] Downstream MCP client: spawn/connect real servers, multiplex tools (namespaced)
- [x] Live reconfig + `tools/list_changed` on toggle (registry file watcher)
- [x] Secret injection at runtime (OS keychain via keyring; injected at spawn)
- [x] Audit log of tool calls (Activity view)
- [x] Proxy remote (http/sse) downstream servers, not just stdio
- [x] Self-heal: rebuild router on a call when no servers are connected
- [x] Tool-name sanitizing (clients drop hyphenated names) + cache-poisoning guard

Phase 1.5 - Remote auth
- [x] Token auth: vault a bearer token per http server, injected by gateway
- [x] OAuth 2.1 flow: discovery + DCR + PKCE + loopback + exchange
- [x] OAuth token refresh on 401/expiry
- [x] Auth UX: auto-probed status badges, one-click authenticate (OAuth + key),
      vendor hints, live propagation to connected clients

Phase 2 - Client integration
- [x] "Install Conduit into client X" (surgical, backs up, preserves others)
- [x] Uninstall (surgical remove)
- [x] Client detail reframed as connect + import sources
- [x] Migrate-on-connect: import a client's servers, leave it gateway-only
- [x] Live propagation (registry mtime bump -> gateway rebuild -> tools/list_changed)
- [x] Registry path anchored to a non-virtualized home path (MSIX desync fix)
- [x] Bundle conduit-gateway as a sidecar so the installed path survives in
      production (externalBin via merge config `tauri.bundle.conf.json`, staged by
      `scripts/prepare-sidecar.mjs`; `resolve_gateway_path` finds the dev name or
      the packaged `-<triple>` name). Shipping in signed releases.

Phase 3 - Scaling & UX
- [x] Lazy discovery: `CONDUIT_DISCOVERY=lazy` exposes 3 meta-tools (search/call)
- [x] Per-agent scoping: `CONDUIT_PROFILE` + per-client profile picker, per-profile cache
- [x] Catalog: curated popular set + live official MCP Registry search, type-ahead
- [x] Promote-to-catalog (a user's own picks seed the catalog)
- [x] Catalog as a left-nav destination; status grouping; non-blocking UI commands

## Next (tiered)

Tier 2 - feature completeness (in progress)
- [x] Per-tool enable/disable + destructive-tool deny-list (UI toggles; gateway
      hides+blocks; global destructiveHint switch)
- [x] Tool playground: invoke any tool from the app and see the result
- [x] Proxy resources + prompts (capability-gated discovery, namespaced prompts,
      uri-routed resources); sampling / elicitation passthrough still TODO
- [x] Observability: per-server latency (avg/p95), success/error rates (Activity
      dashboard); per-tool breakdown + filters still TODO

Tier 3 - launch prep
- [x] Bundle the gateway sidecar; signed/notarized macOS installers (Win/Linux
      unsigned with documented bypass); cargo-audit in CI. Auto-updater still TODO.
- [x] Verify macOS / Linux (signed mac dmgs arm64 + Intel, Linux deb/AppImage;
      tested across Windows/macOS/Ubuntu VMs)
- [x] Marketing site (conduit.southforgeai.com) with demo video. First-run
      onboarding still minimal.
- [ ] macOS keychain access-group entitlement (app + gateway share secrets with
      no "Always Allow" prompt); auto-updater; Product Hunt + MCP registry launch

Tier 4 - teams / enterprise (paid)
- [ ] Hosted/remote gateway, shared/synced config, RBAC/SSO
- [ ] Policy engine (allow/deny tools, approval gates), audit export
- [ ] Secret-vault integrations (1Password, Vault, cloud secret managers)

## Security invariants (do not regress)

- Backend never sends secret *values* to the UI; env var names only.
- Secrets live in the OS keychain, never in Conduit's registry file or any
  client config.
- Snapshot every client config before modifying it; modifications are reversible.
- Never read or decrypt another app's OAuth tokens.
