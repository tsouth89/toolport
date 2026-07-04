# Toolport roadmap

Toolport is a local MCP gateway for AI coding tools (Claude Desktop, Cursor,
VS Code, Windsurf, Codex CLI). Every server you connect dumps its whole tool list
into the agent's context on every request; Toolport routes them through one gateway
that exposes 3 meta-tools the agent searches on demand, so context stays flat:
measured ~90% fewer tokens at the same task success. This document is the working
spec, capturing the architecture decision and the build order.

**Status (2026-07-03):** v1.1.0 published (renamed Conduit -> Toolport at v1.0.0).
Signed/notarized macOS (Apple Silicon + Intel, data-protection keychain + nested
gateway, no keychain prompts on update), Windows (Azure Trusted Signing), Linux
(deb/AppImage) via a tag-triggered pipeline + in-app auto-updater. 20 clients.
Recently shipped: human-in-the-loop tool approval (with approve-for-session and
per-tool overrides), tray/menu-bar background running + launch-at-login, desktop
notifications on held calls, and severity-tiered security notices. Shipping: lazy
discovery, OAuth/key auth
with live propagation, catalog, import/migrate, per-tool + destructive-tool
governance, audit log, resources/prompts proxying, tool playground, semantic search,
rug-pull + injection + agentjacking detection, result-shaping Tier 1. **v0.7.0 made
Open WebUI first-class:** the gateway speaks HTTP/OpenAPI natively (`--http` /
`CONDUIT_HTTP`, mcpo retired), with a one-click in-app toggle, a required bearer
token (closing a browser drive-by CSRF), and self-resolving multi-step tool calls
(an invented-ID guard that points the model at the right list/get tool). Live
priorities are below.

## Near-term priorities (2026-07-01)

A competitive review reset the near-term order toward widening the two structural
moats (zero-infra local-first + tool-supply-chain security) and reaching parity on
a few governance/observability items other gateways have. (Detailed competitive
notes live in the internal `docs/COMPETITIVE.md`.)

**Shipped since (2026-07-03 update)** — several items below have landed and should be
read as done: the **human-in-the-loop approval queue** (+ tray/menu-bar background
run, OS notification, exact fail-closed countdown, and an org-mandated
`forceHumanApproval` policy), the **multithreaded HTTP loop + released router lock**
(supersedes "single-threaded accept loop" and "router lock held across the downstream
call" below), **tool overrides** (rename / re-describe), the **DNS-rebind TOCTOU** and
**IPv6 cloud-metadata** SSRF guards, and **audit-line client attribution** (the stamp;
a per-caller Activity filter is still open). A 2026-07-03 code audit (Teams server +
desktop app) also drove a **security hardening pass**: HTTP clients are now scoped on
`resources`/`prompts` too, three tool-poisoning detection gaps closed (outputSchema
scan, structuredContent co-occurrence, quarantine fail-closed), and gateway
durability/auth hardening (fsync, empty-bearer, constant-time token). Follow-ups since
then also landed: the **content-defense DoS byte-cap** (512KB scan bound, #110), the
**HITL/confirm fail-closed** resolution on a cache miss (#109), a **canonical
`fmtTokens`** (#111), and, on the Teams server, the full robustness batch — logout
session revoke, CSV-injection guard, secret-strip precision, Google/GitHub email
verification, `billing_success` owner-gate + webhook refetch, magic-link rate limit,
and hourly auth-row reaping (Teams #15-21, all deployed). Still open: the **seat-count
race** (atomic fix in Teams PR #22, awaiting review) and one deferred desktop item —
the **registry cross-process cache-coherence** problem (the app persists its in-memory
`Mutex<Registry>` while the gateway does its own disk load→mutate→save on agent-control
toggles, so the two can clobber each other; a file lock alone won't fix it, the correct
fix is reload-under-lock at every app mutation or a gateway→app cache-refresh signal;
low real exposure since the gateway only writes when `allow_agent_control` is on).

**In flight**

- ~~Teams **org screening policy** (Phase 1): tighten-only `forceContentDefense` /
  `forceQuarantineOnDrift`.~~ **Shipped**, and extended with `forceHumanApproval`
  (org-mandated HITL). Plan in `docs/drafts/parry-teams-plan.md`.

**Tier 1 - security + cheap parity (do first)**

- [x] **Stdio spawn hardening.** Refuse code-smuggling / container-escape args
      (interpreter inline-eval + module-preload, docker `--privileged` / host-mount /
      `--cap-add` / host-namespace) before spawning a stdio server, so a
      booby-trapped (team- or registry-sourced) config can't turn a benign-looking
      launcher into arbitrary code execution. `screen_spawn_command` in
      `downstream.rs`, on every spawn path. (S)
- [~] **Identity attribution in the audit line.** The client label is now threaded
  through dispatch and stamped into `audit.rs`/`inspect.rs` records (#95). Remaining:
  a per-caller filter in the Activity view. (S)
- [x] **Tool overrides (rename / re-describe) SHIPPED (#88, #89):** a user can rename or
      replace a tool's description as clients see it (neutralizing a poisoned description
      in place). Param-pin/override defaults is the remaining piece.

**Tier 2 - parity on real gaps**

- [ ] Tool Groups (cross-server reusable collections) + allow/block ACL with an
      explicit `default-allow`/`default-block` posture per client, generalizing
      profiles. (M)
- [ ] **Opt-in** OTel/Prometheus exporter (`/metrics` or OTLP push), OFF by default
      so zero-infra stays the default experience; keep the in-app dashboard primary. (M)
- [ ] Finish native **streamable-HTTP** upstream transport (OpenAPI HTTP mode already
      ships) so remote/network clients connect natively. (M)

**Strategic**

- [x] **Human-in-the-loop approval queue. SHIPPED** (v1.1.0 + follow-ups): the gateway
      holds a gated call and the app prompts to approve/deny, fail-closed on timeout;
      plus tray/menu-bar run, OS notification, approve-for-session/always-allow, exact
      countdown, and an org-mandated `forceHumanApproval` Teams policy.
- [ ] **Named retention / data-handling statement** (docs + in-app one-liner):
      payloads never leave the machine; we log metadata, not bodies. Structurally
      true today, just never stated. (S)
- Teams enterprise (SSO/IdP, central catalog, approval workflows) stays
  **Teams-only** and selective; not in the local app.

## What's next (backlog, from the 2026-06-28 audit)

Prioritized after v0.7.0 and a fresh-eyes audit (code/tech-debt, first-run UX,
HTTP/security surface). Ordered by impact within each track. (S/M/L = effort.)
The 2026-07-01 block above supersedes the ordering; these remain the detailed backlog.

### Security (most shipped in v0.7.0; residuals)

- [x] HTTP bridge **bearer token** (required, OPTIONS preflight exempt), fail-closed
      on non-loopback bind, 4 MB body cap, sanitized reflected headers, `catch_unwind`
      per request. Closed the credential-CSRF (a browser tab can reach `localhost`).
- [x] IPv6 cloud-metadata is covered by the resolver-level `ip_is_private` screen.
- [x] **DNS-rebind TOCTOU SHIPPED (#81):** SSRF screening moved into the resolver so the
      validated address set is enforced at connect time (whole-set refusal), closing the
      resolve-once/connect-later window.
- [x] Worker-per-request HTTP loop **SHIPPED (#99)** — a slow downstream / held call no
      longer blocks other callers. (A per-request read timeout for slowloris is still open.)

### New-user UX (first 10 minutes; scaffolding is strong, these are the sharp edges)

- [ ] **Backend failures render as innocent empty states.** Gateway down ->
      Activity shows "No tool calls yet", not "can't reach backend, retry".
      Distinguish error from empty (CatalogView already does). Top UX fix. (M)
- [ ] **Add-server form saves broken servers silently** (empty command/URL);
      require + inline-validate before enabling Add. (S)
- [ ] ClientDetail throws Connect / Import / Move at a first-timer before teaching
      that Toolport is the gateway; lead with the mental model. (M)
- [ ] Jargon + dead ends: rename "Move config in", tooltip "Add to catalog", helper
      text on transports, make the Settings "See docs/openwebui.md" a real link,
      default Activity "Recent calls" filter off, Playground "0 tools" state,
      `vendorFromKey` fallback for unknown keys. (S each)

### Robustness / tech debt

- [ ] **Tool-cache versioning.** The gateway serves the on-disk cache verbatim with
      no version tag, so catalog-logic changes don't take effect until a server
      toggles or the cache is deleted. Wrap in `{version, tools}`, discard on
      mismatch. (S)
- [x] **Router lock held across the downstream call SHIPPED (#95, #99):** the live
      router is a `Mutex<Arc<Router>>`; dispatch clones the Arc and releases the lock
      before the (possibly 120s-held) downstream call, and the HTTP loop is multithreaded.
- [ ] Tests for the new HTTP transport (status mapping, error paths) and
      `semantic.rs` (blend math, embed cache). (M)

### Strategic / differentiators (what makes it amazing)

- [ ] **OAuth client registration + per-client server scoping.** A client
      authenticates to Toolport, shows up in the app, you assign which servers it
      sees. Profiles already do half. This is Sigiz's explicit ask AND the proper
      long-term auth model for the HTTP bridge. The real moat. (L)
- [x] **Block-on-drift / quarantine + re-approval for high-risk tools.** SHIPPED
      2026-06-30 (on main, unreleased): opt-in `quarantine_on_drift` blocks a
      high-risk drift (a poisoned definition, or a destructive tool whose definition
      changed/appeared) until the user re-approves it; detection-only stays the
      default. Settings toggle + re-approve list in the app. Auth-bearing dimension
      (drift on a credential-bearing server) deferred to a later pass.
- [ ] **Local-small-model UX.** 7B models still struggle with the lazy
      search-then-call chain (the multi-step guard helped, didn't solve). This is
      Open WebUI's core audience. (L)
- [ ] **Live call-inspection in Activity** (real request/response bytes) folds MCP
      Peek's value into Toolport, since we're already on the path. (M)
- [ ] Result-shaping Tier 2: per-server fidelity policy, projection, code-execution
      handoff; end-to-end "does the model actually page" validation. (M-L)
- [ ] Showcase server (`conduit-openapi-mcp`: any OpenAPI spec -> an MCP server; npm
      publish pending) as the funnel + a demo of lazy discovery + result-shaping.

**Community-requested (2026-07-03, r/LocalLLaMA launch thread):**

- [x] **Lazy-discovery search trace / observability.** Shipped (#114) as the Activity
      **Discovery** panel: every `toolport_search_tools` call records the query, the
      matched tool names, which won (top), and the ground-truth per-turn token overhead
      (returned schemas vs. the full scoped catalog, via `savings::estimate_tokens`).
      Local, bounded, tool-names-only (no args/results). The in-path angle is the
      differentiator vs. post-hoc telemetry (e.g. tokentelemetry.com), which reads
      session logs and doesn't break out MCP tool-schema overhead. Follow-ups still open:
      per-candidate scores (lexical + semantic blend) and the exact returned input
      schema, not just names. (M, core done)
- [ ] **Pinned / prerequisite tools in search (`tool_prereq`).** Let a tool be marked so
      it's always returned (with its schema) regardless of match score - for tools that
      are a hard prerequisite (auth/list-before-act) or whose description doesn't match
      the user's query keywords, so lazy discovery never hides a load-bearing tool.
      Fits alongside tool overrides (same per-tool config surface). Suggested by kevrex5,
      who built the same pattern. (S-M) **SHIPPED (#126)** as the PlaygroundView pin toggle.
- [x] **Client support: pi coding agent. SHIPPED (#128):** requested on the launch thread
      ("a lot of users here use pi for local agent coding"). Registered pi as a
      `JsonMcpServers` client writing its Pi-owned global config at `~/.pi/agent/mcp.json`
      (home-anchored), mirroring the Cursor/BoltAI writers. Bound for the next release.
- [ ] **Two-layer / hybrid tool search (the "Zillow isn't near 'house'" miss).** Suggested
      by MajMin5 (r/LocalLLaMA), who independently built the same lazy loader and validated
      the pattern. Pure semantic (embedding) search misses tools whose name/description
      doesn't embed near the query even though the association is common knowledge (search
      "home information" → embeddings skip a `zillow` tool). His fix was a slow LLM fallback
      (ask a small model "which of these tools fit <task>?"). Our cheaper version: (a) a
      genuine **hybrid ranker** (lexical/BM25 blended with the existing semantic score, not
      semantic-alone), and (b) **broaden the candidate set when top scores are low-confidence**
      so the (already capable) calling model can reason over descriptions instead of us
      hiding them. Optionally a `search_tools_deep` meta-tool that returns more candidates +
      full descriptions. No mandatory local model — the client model IS the reasoning layer.
      Ties into the open "per-candidate lexical+semantic scores" search-trace follow-up. (M)
- [ ] **Per-client discovery mode + raw/direct passthrough.** Also from MajMin5: clients that
      already do their own tool-gating/deferral (Claude Desktop, LibreChat, and Claude Code's
      tool-search) pay a wasteful double hop when forced through our meta-tools (load meta-tools
      → search → load tool → call) versus just seeing the tools directly and using their native
      logic. Today `lazy_discovery` is a single **global** bool in the registry (registry.rs);
      make it **per-client** (and consider auto-defaulting self-managing clients to the direct
      catalog, weak/local models to lazy). This is the client-agnostic story finished: one
      place to configure servers, right discovery surface per client. (His stdio→HTTP + mobile
      asks we already cover — the gateway speaks HTTP/OpenAPI natively.) (M)

## The core decision: Toolport is a gateway, not a file editor

A tool that only edits each client's MCP JSON config is a dead end:

1. Clients are migrating servers out of the JSON file into UI-managed,
   account-synced connectors (Claude already has). The JSON file is emptying.
2. Editing a config file requires restarting the client for changes to take
   effect, so "toggle a server on/off without reloading the app" is impossible
   with the file-editor approach.

Toolport instead runs a **local MCP gateway**. Each client points at Toolport
once (as a local stdio server and/or a custom connector URL). Toolport holds the
real registry of servers and routes to them. This unlocks the headline win and
flips every weakness:

- **~90% fewer tokens.** In lazy-discovery mode the gateway advertises 3 meta-tools
  instead of every server's full tool list, so the agent's context stays flat no
  matter how many servers you connect. Measured: 97% less tool overhead per request
  (see [BENCHMARK.md](../BENCHMARK.md)).
- **Hot toggle, no restart.** Enable/disable a server, the gateway re-emits its
  tool list via the MCP `notifications/tools/list_changed`; supporting clients
  update live. The client's own config never changed, so nothing reloads.
- **No plaintext secrets in client configs.** The gateway holds keys in the OS
  keychain and injects them at runtime. Client config only says "talk to Toolport."
- **Audit log for free.** Every tool call flows through the gateway. That log is
  the governance/MSP product.
- **Routes around the connector migration.** Toolport registers as one custom
  connector in Claude; all managed servers appear through it.

## Spike findings (2026-06-18)

### Spike 42: can we read Claude's connectors from disk? (Partially, but fragile)

- Claude Desktop's `claude_desktop_config.json` `mcpServers` is **empty** on this
  machine. All servers moved to connectors.
- Connectors + OAuth tokens live in `%APPDATA%\Claude\config.json` as
  **DPAPI-encrypted** blobs (Chromium safeStorage, `v10` prefix). Not readable.
- Connector _names_ (Clerk, GitHub, Pax8, revenuecat, Supabase, Vercel, Stripe,
  expo) DO appear in plaintext in the Chromium LevelDB/IndexedDB stores for the
  `claude.ai` origin.
- BUT those stores are **locked while Claude is running**, the schema is
  undocumented Chromium IndexedDB, and the real source of truth is the user's
  Anthropic account (server-side sync), not a local file.

**Verdict:** local read-only _inventory_ of connector names is possible but
fragile and operationally awkward (locked DBs, undocumented schema, account-side
truth). It is NOT a foundation to build _management_ on. This confirms the
gateway architecture: Toolport cannot manage Claude's connectors directly, so it
becomes one connector that fans out to everything it manages. A best-effort,
read-only "connectors detected (view-only)" panel is worth showing for the
governance inventory story, clearly labeled as not-managed.

### Spikes 40 and 41 (need morning verification on running clients)

- Spike 40 (live toggle): confirm `tools/list_changed` actually refreshes the
  tool list without restart in each client. Determines how universal hot-toggle is.
- Spike 41 (Claude as connector): confirm Toolport can register as a custom
  connector / local server in current Claude Desktop and expose downstream tools.

These require driving real client UIs and were deferred (user asleep; not safe to
mutate their live client setup unattended).

## Build order

Phase 0 - Foundation

- [x] Tauri + React + Rust scaffold, 0 vulns
- [x] Client adapter readers (import/discovery): detect clients, parse JSON/TOML
- [x] Toolport registry: own source-of-truth store (servers, profiles, enabled)
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

- [x] "Install Toolport into client X" (surgical, backs up, preserves others)
- [x] Uninstall (surgical remove)
- [x] Client detail reframed as connect + import sources
- [x] Migrate-on-connect: import a client's servers, leave it gateway-only
- [x] Live propagation (registry mtime bump -> gateway rebuild -> tools/list_changed)
- [x] Registry path anchored to a non-virtualized home path (MSIX desync fix)
- [x] Bundle toolport-gateway as a sidecar so the installed path survives in
      production (externalBin via merge config `tauri.bundle.conf.json`, staged by
      `scripts/prepare-sidecar.mjs`; `resolve_gateway_path` finds the dev name or
      the packaged `-<triple>` name). Shipping in signed releases.

Phase 3 - Scaling & UX

- [x] Lazy discovery: `CONDUIT_DISCOVERY=lazy` exposes 3 meta-tools (search/call)
- [x] Per-agent scoping: `CONDUIT_PROFILE` + per-client profile picker, per-profile cache
- [x] Catalog: curated popular set + live official MCP Registry search, type-ahead
- [x] Catalog as a left-nav destination; status grouping; non-blocking UI commands

## Next (tiered)

Tier 2 - feature completeness (in progress)

- [x] Per-tool enable/disable + destructive-tool deny-list (UI toggles; gateway
      hides+blocks; global destructiveHint switch)
- [x] Tool playground: invoke any tool from the app and see the result
- [x] Proxy resources + prompts (capability-gated discovery, namespaced prompts,
      uri-routed resources); sampling / elicitation passthrough still TODO
- [x] Observability: per-server latency (avg/p95), success/error rates, per-tool
      breakdown, and server/errors-only filters (Activity dashboard)
- [x] Tool-definition integrity / rug-pull detection: fingerprint tools on connect,
      diff on every refresh, flag changed/added definitions on already-approved
      servers as a security notice (detection only, on by default). Reuses the
      existing tools/list_changed refresh hook. See `docs/specs/mcp-integrity.md`.
- [x] Security: tool-description injection scanning (poisoning / line jumping),
      folded into the integrity pass.
- [x] Semantic tool search (optional, off by default): blend embedding similarity
      into the lexical ranker so paraphrased needs surface the right tool. Pluggable
      `/v1/embeddings` endpoint, disk-cached, lexical fallback. Recall measured by
      `benchmark/retrieval.mjs`. See `docs/specs/semantic-search.md`.
- [x] Content defense (agentjacking): scan untrusted tool _results_ for injection and
      wrap flagged content with a "data, not instructions" provenance marker before the
      agent sees it. Detection + labeling, never blocks, on by default. See
      `docs/specs/content-defense.md`.
- [ ] Security, next: a Security page mapping Toolport's controls to the MCP attack
      taxonomy; opt-in lossy result shaping / dangerous-call gating (content-defense Tier 2).

Tier 3 - launch prep

- [x] Bundle the gateway sidecar; signed/notarized macOS installers (Win/Linux
      unsigned with documented bypass); cargo-audit in CI.
- [x] Verify macOS / Linux (signed mac dmgs arm64 + Intel, Linux deb/AppImage;
      tested across Windows/macOS/Ubuntu VMs)
- [x] Marketing site (toolport.app) with demo video.
- [x] In-app auto-updater (Tauri v2 updater plugin + signed `latest.json` from the
      release pipeline). Live from v0.3.3 onward.
- [x] First-run onboarding wizard (detect clients, add servers, connect a client).
- [ ] macOS keychain access-group entitlement (app + gateway share secrets with
      no "Always Allow" prompt)
- [x] Launch: Product Hunt, MCP registries (Glama/mcp.so/awesome-mcp listed)

Tier 4 - teams / enterprise (paid)

- [ ] Hosted/remote gateway, shared/synced config, RBAC/SSO
- [ ] Policy engine (allow/deny tools, approval gates), audit export
- [ ] Secret-vault integrations (1Password, Vault, cloud secret managers)

## Security invariants (do not regress)

- Backend never sends secret _values_ to the UI; env var names only.
- Secrets live in the OS keychain, never in Toolport's registry file or any
  client config.
- Snapshot every client config before modifying it; modifications are reversible.
- Never read or decrypt another app's OAuth tokens.
