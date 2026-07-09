# Changelog

All notable changes to Toolport are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions match the GitHub releases.
Entries before the rename below shipped under the project's former name, Conduit.

## [Unreleased]

### Added

- **Dev data directory** — debug/`tauri dev` builds use `Conduit-dev` instead of the
  production `Conduit` folder (`CONDUIT_DATA_DIR` overrides). (#232)
- **Registry recovery notice** — when `registry.json` is restored from `.bak`, the app
  shows a one-time toast with the recovery time (and quarantine path when applicable).
  (#231)

### Fixed

- **OAuth callback port collision across clients** — concurrent gateway processes now
  serialize browser OAuth for the same remote server with a short-lived filesystem
  lock, so only one callback listener/browser flow runs and waiters reuse the
  vaulted auth state when it completes. (#228)

- **Gateway stale secrets** — `secrets_generation` in the registry bumps on vault
  changes so running gateways reload credentials without a manual restart. (#226)

## [1.6.2] - 2026-07-09

**Windows install fix (completes 1.6.1).** Manual installer downloads and the
1.6.0 → 1.6.1 hop now kill locked gateway processes before NSIS copies files.

### Fixed

- **Windows NSIS install with locked gateway** — `NSIS_HOOK_PREINSTALL` runs
  `taskkill` on `toolport-gateway.exe` / `conduit-gateway.exe` before file copy.
  1.6.1 only stopped gateways during in-app update from an already-updated app, so
  manual installs and upgrades from 1.6.0 still failed when Cursor held the gateway.

## [1.6.1] - 2026-07-09

**Windows auto-update fix.** If Cursor or another MCP client held `toolport-gateway.exe`
open, the in-app updater could fail to replace the install-dir binary. This patch
publishes a versioned gateway under `%APPDATA%\\Roaming\\Conduit\\bin` and stops only
spawned gateway processes before install.

### Fixed

- **Windows auto-update with locked gateway** — MCP configs point at a versioned
  `toolport-gateway-{version}.exe` under `%APPDATA%\\Roaming\\Conduit\\bin` instead of
  the install-dir copy; before updating, Toolport stops only spawned gateway processes so
  NSIS can replace locked binaries without closing Cursor or other agents. (#244)

## [1.6.0] - 2026-07-09

**Headless gateway.** Deploy `toolport-gateway` in Docker, speak MCP over HTTP/SSE, pull
a prebuilt image from GHCR. Desktop users get smoother npx/uvx first connects, AnythingLLM
support, Teams usage rollups, and registry safety fixes.

### Added

- **Headless / container gateway** — run without the desktop app: `POST /mcp`
  streamable-HTTP, env-file secrets (`CONDUIT_SECRET_KEY`), Docker +
  `docker-compose.example.yml`. See `docs/headless.md`. (#214)
- **MCP listen stream** — `GET /mcp` SSE for server→client JSON-RPC (30s keepalive when
  idle). (#216)
- **MCP server-initiated RPC passthrough (#167)** — when the upstream client declares
  `roots`, `sampling`, or `elicitation` at `initialize`, downstream servers can call
  `roots/list`, `sampling/createMessage`, and `elicitation/create`; the gateway forwards
  over stdio or HTTP MCP (inline during SSE `POST` responses). (#217, #218, #219)
- **Prebuilt gateway image on GHCR** — `ghcr.io/tsouth89/toolport-gateway:latest`
  (CI-built binary + slim runtime; ~3 min builds vs ~8 min). (#222, #223, #225)
- **AnythingLLM client** — connect from the Clients view. (#213)
- **Teams per-server usage rollups** — members report tool-call counts to the team
  dashboard (counts/estimates only; tool names stay local). (#221)

### Fixed

- **npx/uvx cold-start false errors** — download launchers (`npx -y`, `uvx`, `pnpm dlx`,
  …) get a 120s first-`initialize` budget (10s for everything else), **"Installing…"**
  UI while downloading, and background pre-warm on add. (#237)
- **SSE streaming for inline server-initiated RPC** — HTTP downstream no longer buffers
  the full body before forwarding JSON-RPC to the upstream client. (#220)
- **Registry preserved on read failure** — a corrupt or unreadable `registry.json` is
  quarantined and restored from `.bak` instead of silently reset. (#224)

### Changed

- **Gateway-only compile** — `cargo build --no-default-features --bin toolport-gateway`
  skips Tauri/WebKit for headless/CI builds; desktop default unchanged. (#225)

### Documentation

- **Headless production checklist and security guidance** — deploy checklist, inherited
  vs new security surface, and audit recommendations in `docs/headless.md`. (#242)
- **Release notes draft** — `docs/release-notes/v1.6.0.md`; updated `docs/RELEASING.md`.
- **Headless smoke tests** — `scripts/smoke-headless.ps1` (auth, MCP handshake, HITL
  fail-closed).

## [1.5.3] - 2026-07-08

Teams reliability and activation batch, ahead of the Teams launch.

### Fixed

- **Org-forced safety locks are released when you leave a team.** A team that enforced
  human-in-the-loop approval, destructive-tool blocking, content defense, or
  quarantine-on-drift used to bake that setting permanently into the member's own settings,
  so leaving the team left the lock stuck on with no way to turn it back off. These org
  forces are now tracked separately from your own settings and cleared the moment you leave;
  your own toggles are never touched. (#209)

### Added

- **"Joining a team?" onboarding path.** The first-run wizard now offers first-class
  invite-code entry, so a team member who was told to install Toolport can join their team
  immediately instead of clicking through solo setup to look for it. (#210)
- **Near-instant team policy sync.** Members now long-poll the team config, so an admin's
  policy or access change in the dashboard enforces on member machines in about a second
  instead of at the next poll interval. Falls back cleanly against an older team server. (#211)

## [1.5.2] - 2026-07-07

Post-1.5.1 security and robustness batch from a multi-dimension gateway audit
(#203 HIGH, #204 MEDIUM, #205 LOW/robustness), plus a follow-on hardening pass
(#207). All batches ship with regression tests; full suite green.

### Security

- **Approvals are now bound to the tool definition.** A "for this session" or "always" allow
  is keyed to a fingerprint of the exact tool definition it was granted for, resolved from
  the live server. If a server later changes that tool (a rug-pull), the call re-prompts
  instead of inheriting the old approval; legacy broad allows are ignored, so existing users
  re-approve once. (#207)
- **Broader destructive-tool detection.** When a server omits the MCP `destructiveHint`, the
  approval gate now also treats obvious write/delete verbs in the tool name (delete, drop,
  send, publish, truncate, upload, ...) as destructive, failing toward caution. An explicit
  `destructiveHint: false` still wins. (#207)
- **Secret redaction in shareable diagnostics.** The diagnostics summary now redacts inline
  secret arguments and credentials embedded in server URLs, and clears the live-inspection
  buffer on startup when inspection is off. (#207)
- **Spawn-guard bypass via attached inline-eval flags.** The dangerous-flag guard only
  matched interpreter flags as standalone argv tokens, so the attached form
  (`python -c<code>`, `ruby -e<code>`) from a booby-trapped server config slipped past and
  executed arbitrary code. Generalized the matcher to the attached short form. (#203)
- **OAuth DNS-rebind SSRF into the private network.** The OAuth metadata resolver refused
  only link-local / metadata IPs; RFC1918 and loopback were blocked by a separate
  pre-connect check, a resolve-then-connect TOCTOU a rebinding host could exploit. A
  stable, provenance-derived `block_private` flag now refuses private answers at connect
  time too, so a rebind can't flip it. Self-hosted LAN auth servers still work. (#204)
- **OAuth cleartext-exchange bypass.** `require_https`'s loopback exception used a string
  prefix that also matched `http://127.0.0.1.evil.com`; it now decides on the parsed host
  (`is_loopback()` / `localhost`). (#204)
- **HTTP-bridge token masked in the UI.** The bearer token that grants any local process
  access to every tool was shown in plaintext on each visit; it is now masked by default
  with a reveal toggle. (#205)

### Fixed

- **Config-wipe data loss on parse failure.** A genuinely-unparseable `codex/config.toml`,
  `~/.claude.json`, or Gemini `settings.json` was replaced with a fresh file holding only
  the gateway entry, destroying the user's model/provider/profile/MCP state. Both paths now
  fail closed and preserve the file (a timestamped backup was always taken first, so prior
  damage was recoverable). (#203)
- **Router lock held across downstream refresh I/O.** A `list_changed` from one slow
  downstream stalled every concurrent request for up to num_servers x connect-timeout; the
  refresh now runs on an off-lock router clone swapped in under a brief lock. (#204)
- **Self-heal thundering herd.** A startup burst of workers could each rebuild the router,
  spawning the full server set N times; the rebuild is now single-flighted behind a
  double-checked lock. (#205)
- **Robustness batch:** cancel-forward threads capped at 64 to stop a wedged downstream
  leaking threads; config install cap raised 8MB to 64MB for heavy Claude Code users;
  saturating arithmetic on the savings/audit hot paths; frontend polish (approval-bar
  countdown scales against the real window, stale share-export guard, capped
  dismissed-activity set). (#205)

### CI

- Pinned the release workflow's actions to commit SHAs (it holds the signing secrets);
  removed stray 0-byte local signing-key artifacts. (#205)

## [1.5.1] - 2026-07-06

A focused safety and gateway-control patch release. The headline fix is the
human-in-the-loop approval path: approval failures are now diagnosable, audited,
and resilient to stale broker descriptors instead of collapsing into a vague
timeout.

### Added

- **Grouped discovery mode.** `CONDUIT_DISCOVERY=grouped` now advertises the lazy
  meta-tools plus one `help_<server>` browse tool per connected server, giving
  weaker/local models an enumerable middle ground between the tiny lazy surface and
  the full catalog.
- **Per-registry discovery mode.** Discovery mode can now be stored in the registry
  (`lazy`, `grouped`, or `full`) instead of only being controlled by a process env
  var.
- **MCP request cancellation forwarding.** The gateway now proxies cancellation
  signals down to the active downstream request path, so canceled client work can
  stop instead of continuing pointlessly in the background.
- **HIL decision audit records.** Approval decisions now record the gate reason,
  decision kind, held duration, and a canonical `argsHash` without storing raw
  arguments.

### Changed

- **HIL approval failures are legible.** A dead or stale approval broker is reported
  as `unreachable`, distinct from a human timeout, and the gateway re-reads the broker
  descriptor once to self-heal the common app-restart/rebound-port race.
- **Lazy search recall improved.** Added dispute/chargeback and token/tokenize
  synonym coverage, improving the local recall fixture from 87% to 96% at 10.

### Fixed

- **Packaged Windows gateways escape MSIX filesystem virtualization.** The app and
  gateway now agree on the same real data directory, avoiding stale registry and
  approval files from Windows app-container redirection.
- **Several high-severity audit findings were closed.** The pass tightened external
  URL opening, catalog/import handling, and content-defense scanning, including a
  result-side evasion found during the app audit.
- **Release hygiene.** Version metadata now targets `1.5.1`, and local `.claude/`
  session artifacts are ignored so they cannot drift into release commits.

## [1.5.0] - 2026-07-05

A robustness release (the gateway, app, and Teams client now recover cleanly from
failure modes that used to fail silently), plus the Teams polish batch for the
Toolport for Teams launch.

### Added

- **Playground: cancel a stuck call.** A tool call that hangs now shows a live elapsed
  timer and a Cancel button, with a clear timeout message, instead of spinning on
  "Calling…" indefinitely.
- **Teams: automatic background sync.** A member's shared server set and security policy
  now stay current on their own (on launch and on a modest interval), so an admin's
  change reaches every member, not just those who click "Sync now".
- **Teams: synced servers grouped by state.** Servers your team shares now split into
  "Needs review" (on top, awaiting your enable) and "Active", so a fresh sync can't
  hide below the fold. (#190)

### Changed

- **Confirm before deleting saved credentials.** Clearing an OAuth token or removing an
  API key now asks first, matching every other destructive action in the app.
- **Catalog search failures are distinguishable from empty.** A registry or network
  error during a catalog search now shows an error with a retry, not a misleading
  "no results".
- **Search ranks the on-the-nose tool first.** In lazy discovery, a tool whose name
  matches your query exactly now wins near-ties instead of losing to a chattier
  description. (#189)
- **Teams and Playground polish.** The shared-server list is sorted, the Playground's
  invoke panel is hoisted above the fold, filters gained clear affordances, and the
  Playground shows proper empty/auth states. (#184, #196)
- **Catalog: removed the dead Railway entry** (its MCP endpoint 404s). (#195)

### Fixed

- **Crashed downstream servers recover automatically.** A stdio server that crashes or
  exits mid-session is now re-spawned on the circuit breaker's probe instead of staying
  dead until the client restarts (self-heal previously only fired when every server was
  down).
- **Teams: removed members are actually cut off.** A removed or demoted member's app now
  disconnects the team locally and refreshes their role on sync, instead of quietly
  keeping the team's servers and stale security policy.
- **Gateway tolerates an unsplit command.** A server config whose `command` is one
  string ("npx -y some-server" with no args array) now just works instead of failing
  with "cannot find the path specified (os error 3)". (#191)
- **Teams: restricted members get 304s again.** The app echoes the server's exact
  team-config ETag, restoring the not-modified fast path for members behind per-server
  access rules. (#192)
- **"Push my setup" no longer pushes the gateway itself** as if it were one of your
  team's servers. (#194)
- **The invite-code field no longer implies a `ci_` prefix** codes don't have. (#193)
- **Onboarding surfaces a failed health probe** on the final step instead of a
  green-looking finish over a server that never started. (#186)
- **Settings: security panels distinguish a failed poll from genuinely empty.** (#185)
- Under-the-hood hardening: the embeddings endpoint is time-boxed so a hung model falls
  back to lexical search, stdio reads are size-bounded, the tool cache is versioned so a
  stale cache from an older build is rebuilt, and shaped-result messaging no longer
  over-promises that a paged result is permanently retained.

## [1.4.0] - 2026-07-04

### Added

- **A full visual redesign.** Toolport moves to its brand palette, a deep navy
  ground with a single orange accent, applied consistently across every tab. Server
  health now reads as a colored word (not just an 8px dot), the Servers header is a
  scannable status bar, and the transport label is demoted to neutral so color means
  health, not metadata.
- **The connect flow shows the product.** Pointing a client that isn't connected yet
  now leads with a `client -> Toolport -> your servers` diagram and a clear call to
  action, instead of a wall of prose.
- **Tool identities are searchable and grouped by server.** Activity → Tool identities
  collapses hundreds of tools into per-server sections with a filter box: type a server
  name to see its whole block, or a tool name to jump to it.
- **A security posture summary in Settings.** The Security section opens with a
  one-line read of whether you're protected (guarded / partly / unprotected) and what's
  active, so you don't have to decode every toggle.
- **Pinned lazy-discovery tools now have a home.** When lazy discovery is on, Settings
  shows a Pinned prerequisites list of every tool you've pinned (with its server) and a
  one-click unpin, so the pin set is visible and manageable instead of being buried
  per-tool in Playground.
- **Tool-poison flags now show the matched text.** A flagged tool definition surfaces a
  short, de-obfuscated excerpt of exactly what tripped the scan, so the alert is
  verifiable instead of an opaque label.

### Changed

- **The Activity tab is calmer.** New/first-seen tools no longer flood the security
  lane; recurring notices collapse into a single counted row; the per-server stats table
  and discovery panel are collapsed by default; the recent-calls log shows all calls
  rather than defaulting to an errors-only view that read as "everything is failing."

### Fixed

- **First-seen destructive tools are no longer quarantined.** A destructive tool simply
  appearing for the first time is inventory, not a rug-pull, and no longer gets blocked
  behind a wall of re-approvals (the call is still gated by the block/confirm/approval
  policies). Legacy quarantine entries from the old behavior auto-clear.
- **No more spurious "integrity baseline lost" alarms** from an empty or mid-swap read
  of the shared pin file, while a genuinely truncated baseline is still treated as
  tampering (loud), not silently rebuilt.
- **A benign tool description no longer trips the poison scanner.** The stealth-directive
  check now requires a real concealment target, so a formatting note like "do not mention
  if a column is boolean" on a legitimate server is not flagged.
- **The connect view no longer describes buttons that aren't there,** and no longer lists
  Toolport's own gateway entry as one of the servers a client can reach (the managed count
  now matches the Servers list).
- **Corrected a Settings pointer** in the tool-identity history note that referenced an
  integrity-checking toggle which does not exist (integrity checking is always on).

## [1.3.0] - 2026-07-04

### Added

- **Discovery now shows why each tool ranked.** The lazy-discovery search trace
  (Activity → Discovery) records, per result, its rank, the query terms it matched
  (name vs description), whether it was a pinned prerequisite, and the ranker used
  (lexical vs semantic). You can now see not just which tools a search returned, but
  why, and what the model was handed.

### Changed

- **The gateway binary is now `toolport-gateway`** (was `conduit-gateway`; the macOS
  helper bundle is `ToolportGateway.app`). Existing client integrations keep working:
  detection and path resolution accept both names, macOS ships a compatibility symlink,
  and on launch Toolport re-points any client config still naming the old binary to the
  new one (each config is backed up first). Keychain and stored data are untouched: the
  keychain service, access group, master key, bundle id, and data directory are all
  unchanged, so no secrets or servers are lost across the update.

## [1.2.0] - 2026-07-03

### Security

- **Closed several bypasses in the stdio spawn guard** (the supply-chain check that
  refuses code-smuggling launch args on a spawned server). Two rounds of adversarial
  review found a booby-trapped (team- or registry-sourced) config could still reach code
  execution through: wrapper programs (`sudo`/`time`/`flock`/`busybox`/... run the real
  program from their args); Deno/Bun remote execution (`deno eval`, `deno run`/`serve`
  and `bun run` of an `http(s)://` / `npm:` / `jsr:` target); several unlisted
  interpreters (`osascript`, `elixir`, `lua`, `Rscript`, `julia`, `awk`, ...) and
  `cmd /c` on Windows; an attached `node -r./x` preload; and code-injecting env vars in
  the config (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, and preload/eval options
  inside `NODE_OPTIONS` / `RUBYOPT` / `JAVA_TOOL_OPTIONS`). The guard now catches all of
  these. `env VAR=val <cmd>` still works (the assignments are screened and the real
  command is checked), and normal launchers (npx/node/python/docker, benign env/tuning
  vars) are unaffected.
- **Agent-control enable/disable now respects the client's scope.** In HTTP mode a
  registered client could call `toolport_enable_server` / `toolport_disable_server` on
  a server outside its allowed set (toggling another tenant's server), and a "no server
  matches" error listed every server in the registry across tenants. Both the lookup and
  that "Known servers" list are now filtered to the client's scope, so an out-of-scope
  server is indistinguishable from a non-existent one. (Only reachable when the global
  "Allow agent control" opt-in is on.)
- **Agent-control toggles are audited with proof of the scope decision.** Each
  `enable_server` / `disable_server` attempt writes an `agent_control.server_toggle`
  audit record (client, profile, requested target, decision, and whether the lookup was
  scoped). A denied out-of-scope attempt records `resolvedServerId: null`, so the audit
  itself carries the guarantee that the denial never resolved or named an out-of-scope
  server.
- **`fetch_result` is now scoped to the client that produced the result.** In HTTP mode
  one gateway serves every registered client from a shared result cache with sequential
  `r{n}` cursors, so a scoped client could read another client's large-result body by
  guessing a cursor (`fetch_result` was the one data path that skipped the client scope
  check). It now only returns a result to the client that stashed it, with the same
  "unknown or expired" answer for anything else so cursors can't be probed.
- **A malformed `fetch_result` can no longer crash the gateway.** A pathological `len`
  overflowed the paging math into an invalid byte slice that panicked; on the stdio
  transport (no panic guard) that took down the whole gateway process. The offset math
  now saturates.
- **The stdio transport now catches handler panics like the HTTP one already did.** A
  panic while handling a request returns a JSON-RPC internal error for that request and
  keeps the gateway running, instead of unwinding out and dropping the whole MCP
  connection (defense-in-depth for the primary local transport).
- **HTTP clients are scoped on resources and prompts too.** A registered HTTP/OpenAPI
  client scoped to a subset of servers could still read _any_ connected server's
  resources and prompts (`resources/read` / `prompts/get` ignored the scope); they now
  enforce the same allowed-server set as tool calls.
- **Closed three tool-supply-chain detection gaps** from an internal audit: a tool's
  `outputSchema` is now poison-scanned (not just drift-hashed); injection in a result's
  `structuredContent` is flagged even when a text block already flagged; and a corrupt
  quarantine file no longer silently re-exposes quarantined tools (it's preserved and
  logged instead of failing open).
- **Gateway durability + auth hardening:** the registry is fsync'd before its atomic
  rename (no truncated file on a crash), an empty `Bearer` token is rejected instead of
  looked up, and the per-client token check is constant-time.
- **The approval / confirm gate now fails closed on an unresolved tool.** If the gateway
  can't tell from its cached catalog whether a tool is destructive, it re-checks the
  live tool list and, if the tool is still unknown, treats it as destructive (held for
  approval or confirmation) instead of letting it through unheld.
- **The injection scan is bounded.** Content-defense now caps the bytes it inspects per
  tool result (512 KB), so a hostile server returning a huge payload can't pin CPU.
  Realistic results are far under the cap, so detection is unaffected in practice.

### Added

- **Pi coding agent is now a supported client.** Toolport detects Pi, imports its
  configured MCP servers, and installs/removes the gateway entry in Pi's global config
  (`~/.pi/agent/mcp.json`), the same one-click flow as Cursor and the other clients.
  (Requested on the r/LocalLLaMA launch thread.)
- **Pin a tool as a lazy-discovery prerequisite.** Mark a load-bearing tool (auth,
  list-before-act, or one whose description doesn't match the model's keywords) with the
  pin toggle in the tool list, and lazy-discovery search will always surface it with its
  full schema, regardless of the query's match score, so it's never hidden behind
  discovery. Pinned tools stay scoped to the client and are capped so a large pin set
  can't itself bloat a result. (Requested on the r/LocalLLaMA launch thread.)
- **Tool identities (capability provenance).** A new Activity panel shows what each
  model-visible tool name actually maps to: its source server and the profiles that
  enable it, the pinned definition fingerprint drift detection checks against, and when
  the tool was first seen / last changed. Prefixing helps the model pick a tool; this
  lets a human verify what crossed the boundary. (The integrity baseline now tracks
  first-seen / last-changed per tool to power it.)
- **Teams can require human approval org-wide.** A team admin can turn on "Require
  human approval" in the Teams policy, and every member's gateway then holds gated
  tool calls for a person to approve. Like the other org policies, it's tighten-only:
  it can force approval on for the team but can never turn a member's own setting off.
- **Discovery panel: see what lazy discovery searched, and what it saved.** Activity now
  records each tool search the model ran: the query, which tools matched, and the
  tool-definition tokens the results cost that turn versus loading the whole catalog.
  Because Toolport is in the request path, those figures are measured, not estimated.
  Local and bounded, and it stores tool names only (never arguments or results).

### Changed

- **The HTTP gateway now handles requests concurrently.** Each request runs on its
  own worker, so a slow downstream server or a tool call held for human approval (up
  to two minutes) no longer blocks other requests, live setting toggles, or
  server-config reloads. The dispatcher already released its locks before the
  downstream call and the approval wait; the accept loop now hands each request to a
  worker instead of serving them one at a time.
- **Clearer client list and import view.** The client sidebar now surfaces connection
  state as the signal instead of the import backlog: connected clients read as a plain
  status (the count of importable servers moved to a small badge), and only
  not-connected / not-found / error clients carry a status word, so the one client that
  isn't wired up stands out instead of being buried under a wall of "connected". In a
  client's detail, "Move config in" is now the emphasized action (it's the real cutover
  that saves context), "Import" is clearly framed as a copy, and a note warns when
  importing into an already-connected client would load its tools twice. The profile
  scope dropdown was also widened so "All enabled servers" is no longer clipped.

### Fixed

- **macOS: monochrome menu-bar glyph, and no more Dock-and-menu-bar at once.** The
  tray now uses a template image (the Toolport porthole mark), so macOS tints it to
  match every other menu-bar item instead of showing the full-color app icon. And the
  Dock icon appears only while a window is open: closing to the tray (or auto-starting
  hidden at login) drops to the menu bar alone, and reopening restores the Dock icon.
- **Approval prompt is keyboard- and screen-reader-accessible.** When a held call
  appears, focus moves into the prompt, Escape denies the oldest pending call, and
  the count is announced. Also removed a brief flicker where a just-decided row
  could momentarily reappear.
- **The approval countdown is now exact.** It counts down to the broker's real
  fail-closed deadline instead of approximating from when the overlay first appeared,
  so the timer matches the moment the call actually auto-denies.
- Large tool results paged via `fetch_result` no longer re-scan the whole cached
  body on each page.
- A failed confirmation (e.g. removing a server) keeps its dialog open cleanly
  instead of surfacing an unhandled error.
- **Enable-all / Disable-all respects the current filter.** With a search filter active,
  the bulk toggle now acts only on the servers you can see instead of every server, and
  it's gated on its own busy state so it can't be double-fired. The profile delete dialog
  also names the profile it's about to remove.
- **Activity and the sidebar now report the same tokens-saved figure.** They each had a
  separate formatter that rounded differently, so the same number could read as, say,
  "1.2M" in one place and "1.23M" in another; both now use one shared formatter.
- **A failed health probe no longer shows a green "Refreshed".** If the manual refresh
  reloads your servers but the health check itself throws, it now says so instead of
  reporting success.

## [1.1.0] - 2026-07-02

### Added

- **Human-in-the-loop tool approval (opt-in).** With "Require human approval" on, Toolport
  holds any destructive or untrusted-server tool call and raises a desktop notification until
  you approve or deny it in the app. Fail-closed: if no decision is made in time, the call is
  denied. Off by default.
- **Runs in the tray / menu bar.** Closing the window now keeps Toolport running in the
  background (system tray on Windows, menu bar on macOS) so it can hold tool calls for approval
  while you work; the tray tooltip shows how many are waiting. Quit explicitly from the tray menu.
- **Launch at login (opt-in).** Start Toolport hidden in the tray when you sign in
  (Settings > General).

### Changed

- **Security notices are tiered by severity, so real threats aren't buried.** Risky
  tool-definition drift (a destructive tool changing, a tool dropping a readOnly/destructive
  safety annotation, or poisoned content) stays a loud, actionable notice; benign vendor
  revisions move to a quiet, collapsible "Recent tool changes" history. Dismissals now stick
  across restarts, and duplicate notices from multiple clients are collapsed.

### Fixed

- Cleaned up leftover "Conduit" references in a few spots (the Teams connect URL placeholder,
  the "download from releases" link, and the exported setup filename).

## [1.0.1] - 2026-07-02

### Fixed

- **Windows: upgraders now show "Toolport" in the Start menu.** After the rename, an
  in-place update from Conduit left the old "Conduit" shortcut and green icon behind
  (the bundle identifier is intentionally unchanged so your data and secrets carry
  over). The installer now removes that stale shortcut so the Start-menu entry and
  icon match the app.
- **Settings: clearer "Allow agent control" note.** It now states your destructive-tool
  block always stays yours, instead of referencing a toggle by position (which had
  since moved).

## [1.0.0] - 2026-07-02

- **Renamed Conduit to Toolport.** Visible names, the app title, and the meta-tools
  (`toolport_status`, `toolport_search_tools`, `toolport_call_tool`, ...) are now
  Toolport; the old `conduit_*` meta-tool names keep working as aliases. Internal
  identifiers (the `conduit-gateway` binary, the data directory, keychain entries, and
  `CONDUIT_*` environment variables) are unchanged, so existing installs upgrade with no
  loss of servers or saved secrets.
- **Security: confidence scoring + new injection categories.** The tool-poisoning /
  content-defense scanner now combines signals into a weighted confidence score
  (surfaced on security events) and adds three detection categories (role-jailbreak,
  system-prompt exfiltration, chat-template delimiter injection). Existing signatures
  and behavior are unchanged.

## [0.9.4] - 2026-07-01

### Added

- **Registry backup and recovery.** A `registry.json.bak` sibling keeps the
  last-known-good server list; Conduit recovers from it if `registry.json` is deleted
  or corrupted, so a bad write or an accidental wipe no longer loses your servers.

### Fixed

- **Per-server head-of-line blocking.** The gateway releases the per-server lock during
  a downstream backoff, so one server's 429 rate-limit no longer stalls other concurrent
  calls to that same server.
- **Retry-After clamp.** A downstream's `Retry-After` header is capped to the backoff
  cap (10s), so a misconfigured or hostile server can't park a call for minutes.

### Docs

- Codex setup walkthrough in the README.

## [0.9.3] - 2026-07-01

### Security

- **macOS: no more keychain prompts on update.** Secrets now live in the macOS
  data-protection keychain under a team-scoped shared access group, and the gateway
  ships as a nested notarized helper that shares that group. The gateway reads the
  secrets the app saved with no password prompt, even across app updates (the repeated
  "Conduit wants to use your confidential information" dialog is gone). Secrets still
  never touch disk.

### Added

- **Quarantine-on-drift.** High-risk tool-definition changes (a poisoned definition, or
  a destructive tool that changed or newly appeared) are blocked until you re-approve.
- **Headless encrypted-file secret backend** (`CONDUIT_SECRET_KEY`) for server/self-host
  use where no OS keychain is available.

### Changed

- Teams pricing is $12/seat (was $20). Smaller initial bundle via code-splitting.

## [0.9.2] - 2026-06-30

### Added

- **Catalog: configure-on-add** (enter keys while adding a server), **self-hosted
  servers** (n8n, Langfuse), and more entries (DataForSEO, Chrome DevTools, Railway,
  Twilio, Postiz).
- **Per-call confirmation for destructive tools.**
- **Paste a config snippet** to auto-fill the Add Server dialog.

### Fixed

- Remote servers refresh an expired OAuth token on a mid-session 401 and retry, no manual
  reconnect.
- Teams only soft-syncs servers the member opts into (no silent RCE from team config).

## [0.9.1] - 2026-06-29

### Added

- **New stack: Web scraping & automation.** An eighth role bundle (Firecrawl,
  Tavily, Playwright, Browserbase, Apify) for agents that search, scrape, and
  drive real browsers.
- **Share a stack as a link.** The Share dialog turns your selected servers into
  a `conduitmcp.app/s/...` link. The page unfolds the stack with a rich preview
  card, and its "Open in Conduit" button deep-links straight into the import
  review (with a copy-the-code fallback). Secrets are never included, and copy /
  save-to-file still work for offline sharing.

## [0.9.0] - 2026-06-29

### Added

- **Stacks: role-based server bundles.** Pick what you work on (full-stack web,
  backend & data, infra & DevOps, AI & ML, product & design, founder, research)
  and Conduit sets up a matching set of MCP servers in one click. Stacks appear at
  the top of the Catalog, and the first-run wizard now leads with a "What do you
  work on?" picker. Each server that needs a credential shows a direct "get key"
  link to the right token page.
- **Selective sharing.** Share a chosen subset of your servers as a stack instead
  of your whole setup (secrets still stripped; the recipient previews before
  importing).
- **Roo Code plugin-hosted server detection.** Conduit now surfaces Roo Code's
  plugin-provided MCP servers (read-only), matching the existing Cursor behavior.
  Thanks @leemeo3 (#50).
- **New catalog servers:** Linode (Akamai) cloud, and Qdrant (vector store for RAG).

### Fixed

- The scoped-client scope picker in Settings rendered an unthemed white dropdown
  in dark mode; it now uses the app's themed select.

### Internal

- Groundwork for concurrent tool routing (per-server interior mutability in the
  router; no behavior change yet), and a fix for an XDG env race that could flake
  a path test on CI.

## [0.8.0] - 2026-06-28

### Added

- **Multi-tenant HTTP bridge (per-client scoping).** Register HTTP clients in
  Settings → Integrations, each with its own bearer token and profile. One bridge
  process serves them all and resolves every request's token to its own set of
  servers, so (for example) two Open WebUI instances can see entirely different
  tools. The bridge connects the union of every registered client's profile, then
  filters each request (tools/list, search, call, status, and the OpenAPI spec)
  down to exactly what that token is allowed to see.
- **Resources & Prompts in the Playground.** New Tools / Resources / Prompts tabs:
  list a server's resources and read one, or fill a prompt's arguments and render
  it, exercising the full MCP surface Conduit proxies, not just tools.
- **Per-client scope, persisted and editable.** A connected client now shows its
  effective scope ("sees the 'Billing' profile, 3 servers"), and you can re-scope
  it in place without disconnecting.
- **Test connection in the add/edit server dialog.** Verify a server (and its
  secrets) actually connects before saving, alongside per-transport validation
  and a duplicate-name warning.
- **Activity error detail.** Failed tool calls now record and show the failure
  message and per-call latency; click a failed row to see why it failed.
- **Continue** client support (`~/.continue/config.yaml`). Thanks @BharadwajKanneveti (#49).
- The OpenAPI spec is now complete: a `servers` block, a `bearerAuth` security
  scheme, and real error responses, so OpenAPI clients can model auth and failures.

### Changed

- **HTTP bridge auth tightened.** Once any scoped client is registered, the bridge
  rejects unauthenticated requests even when no global token is set. CORS no longer
  reflects the caller's Origin or sends credentials, and cross-site browser
  requests are refused outright.
- **Downstream HTTP calls now retry** safely on a connection failure or a 429
  (honoring `Retry-After`) with capped backoff, never on a 5xx, since an MCP tool
  call may already have executed.

### Security

- Constant-time comparison for the bridge bearer token.
- The SSRF connect-guard now also blocks IPv6 link-local and cloud-metadata
  addresses (including the AWS IPv6 metadata address), not just IPv4 169.254.x.
- Client-config reads and backups reject non-regular files (devices, FIFOs) and
  cap size, so a crafted or symlinked config can't exhaust memory or disk.
- A scoped HTTP client's `conduit_status` no longer reveals other tenants'
  server names, commands, URLs, or tool counts.
- The placeholder-ID guard no longer blocks legitimate values like "todo" or
  "string" on content fields (only identifier-typed params).

### Removed

- **"Add to catalog" (promote-to-catalog).** It only pinned a server you already had into
  a local discovery view, with no sync or sharing, so it added clutter without real value.
  Browse Catalog still does what matters: discover and add new servers (curated set + live
  MCP-registry search).

## [0.7.0] - 2026-06-28

### Added

- **Native HTTP/OpenAPI transport.** Run the gateway with `conduit-gateway --http <port>`
  (or `CONDUIT_HTTP=<port>`) and it serves an OpenAPI spec plus a POST endpoint per tool,
  so Open WebUI and any OpenAPI tool client connect straight to Conduit with no mcpo,
  proxy, or Python bridge. It uses the same request path as stdio (one code path, two
  transports), binds both IPv4 and IPv6 loopback, and sends CORS headers so browser
  clients work. See [docs/openwebui.md](docs/openwebui.md).
- **One-click Open WebUI / HTTP endpoint toggle** in Settings -> Integrations. The app
  supervises the gateway, shows the URL to paste, verifies it actually started, and shuts
  it down when you quit.
- **Self-resolving multi-step tool calls.** When a model invents a placeholder identifier
  (e.g. `teamId: "your_team_id"`), the gateway refuses it before the downstream call and
  points the model at the right list/get tool on the same server to source the real value
  (resource-aware: a missing `teamId` suggests the team-listing tool first). The same
  recovery hint is appended whenever a call fails.

### Security

- **The HTTP endpoint now requires a bearer token.** The app auto-generates one, shows it
  in Settings -> Integrations, and you paste it into the client (Open WebUI: the tool
  server's API key / Bearer auth). This closes a credential-CSRF: the `localhost` bind does
  not stop a web page open in your browser from POSTing to the port and running your tools,
  but the token does. The gateway also refuses to bind a non-loopback host
  (`CONDUIT_HTTP_HOST=0.0.0.0`) without a token, caps request bodies, and sanitizes
  reflected headers so a crafted request can't inject or crash a listener.

### Changed

- **Windows installers are now code-signed** via Azure Trusted Signing (publisher name
  shows; SmartScreen reputation still builds with downloads).

## [0.6.0] - 2026-06-27

### Changed

- **The server list is a dense, scannable list now.** The bulky three-column cards are
  replaced by compact grouped rows: toggle, status, name, source, tool count, and
  transport on one line, with the command and per-server actions (secrets, duplicate,
  edit, remove) one click away in an expandable drawer. Needs-attention and disabled
  servers get their own collapsible groups (disabled starts collapsed). Roughly 2-3x
  denser at 20+ servers, and the row actions are real keyboard-reachable buttons now.
- **The catalog browse view is grouped by category.** The default view organizes the
  curated set into sections (Code & infrastructure, Databases, Search & knowledge, Web &
  automation, Apps & productivity, Local tools) instead of a flat grid; search stays flat.
- **Consistent accent colors.** Success, warning, info, and "yours" now come from four
  semantic tokens (one shade each) instead of emerald/amber/violet/sky drifting across
  300/400/500, so the same meaning renders identically in every view.
- **A calmer Activity page.** The tool-security panel is collapsible and each notice can
  be dismissed once reviewed; the raw call log is collapsed by default and filtered to
  errors first, so the per-server stats table stays the headline. The "has secrets" key
  icon on server rows is gone (it was a non-interactive indicator that looked clickable).
- **Global policy moved to a Settings view.** Lazy discovery, Block destructive tools,
  and Allow agent control now live in a dedicated Settings tab (grouped Discovery /
  Security) instead of being buried atop the Playground, which is now a clean
  tool-testing surface.

### Added

- **Three more catalog servers:** Perplexity, Kubernetes, and Todoist.
- **A confirmation step before destructive actions.** Removing a server, deleting a
  profile, disconnecting a client, or leaving a team now asks first and says what
  survives (your secrets stay in the keychain, your own servers are untouched).

### Fixed

- The manual Refresh always confirms now ("Refreshed"), even when a health probe is
  already running, so the click is never silent.
- Hardened the first-run wizard's resume-after-catalog flow against future regressions.
- A refresh failure no longer wipes a working server list; it keeps what's on screen and
  toasts instead. The full-screen error is reserved for the initial-load failure.
- The catalog browse view shows a loading skeleton and a retryable error state instead
  of silently collapsing to "Catalog unavailable."
- Dialogs cap their height and scroll, so a server with many env vars or secrets can't
  push the Save and Cancel buttons off-screen.
- Accessibility: screen readers now get the selected view (aria-current) and toggle
  state (aria-pressed), the active sidebar item reads clearly, and long names truncate
  instead of overflowing their rows.
- Consistent transport pills across every server list, plural-correct labels ("1 tool"),
  and several user-facing strings tidied up.
- The server row no longer nests its toggle and Authenticate buttons inside a clickable
  button. Mouse users still click anywhere on the row to expand; keyboard and screen
  reader users get a dedicated chevron button with proper `aria-expanded`.

## [0.5.2] - 2026-06-27

### Added

- **More one-click catalog servers.** Added MongoDB, Elasticsearch, Airtable, Exa,
  Tavily, Apify, Browserbase, and the Sequential Thinking, Memory, and Time reference
  servers, every package name verified.

### Changed

- **A calmer Servers header.** The duplicate Browse catalog button is gone (it's
  already in the sidebar), Search and Add server stay up front, and the occasional
  actions (Import, Enable/Disable all) move into a `...` overflow menu so the header no
  longer crowds on narrow windows. Thanks @BharadwajKanneveti.
- **One Refresh, not two.** The header's Refresh button now reloads servers, clients,
  and health in a single action and reports an "N of M servers healthy" summary, so the
  separate Check health action has been folded into it.

### Fixed

- **Onboarding no longer drops you mid-setup.** Browsing the catalog from the first-run
  wizard used to end onboarding before the Connect-a-client step; it now resumes there
  when you return, so new users don't silently skip connecting a client.
- **Onboarding tells the truth about broken servers.** The final step now probes the
  servers you just added and flags any that can't start (usually a missing runtime like
  Node or Python), instead of always declaring "you're set up."

## [0.5.1] - 2026-06-27

### Fixed

- **macOS: the keychain prompts are gone.** The `conduit-gateway` helper that your
  AI clients launch now reads your vaulted secrets (API keys, OAuth/bearer tokens)
  with no keychain password prompt. Newly saved secrets get this automatically;
  existing ones are upgraded on first launch. (Done with a trusted-application ACL
  granting both the app and the gateway access, since the modern entitlement
  approach can't work for a standalone helper binary.) Thanks @bradhallett for
  tracing the root cause.

## [0.5.0] - 2026-06-27

A security-hardening release. Conduit tightens the whole tool-trust boundary,
caps and filters what the gateway will fetch and sync, and adds accessibility and
UI polish.

### Fixed

- **The sidebar action bar stays put.** It's pinned to the bottom of the server
  list and always visible instead of appearing only when you scroll to the end,
  and undetected clients collapse under a disclosure so the list stays short.

### Security

- **Hardened the anti-agentjacking scan.** Tool results are normalized before
  scanning (lowercase, invisible/zero-width/bidi stripping, homoglyph and
  full-width folding) and base64-decoded payloads are scanned too, so injection
  text can't slip past with Unicode tricks or encoding. Nested `structuredContent`
  is scanned as well.
- **Rug-pull detection covers more of the tool definition.** Fingerprints now
  include `outputSchema` and `annotations` (version-tagged), so a server can't
  quietly change those behind an already-approved tool.
- **Integrity pins fail closed.** A corrupt or tampered pin baseline now raises a
  security event instead of silently resetting to trust-everything.
- **Blocked RCE/SSRF from synced team config.** Team sync drops stdio/command
  servers (remote code execution) and private-host URLs (SSRF); only public remote
  servers sync. The gateway also stops following HTTP redirects.
- **Capped downstream responses.** The gateway limits how much it reads from a
  downstream MCP server (16 MiB), so a hostile or runaway server can't exhaust
  memory.
- **Validated catalog install specs.** Registry-supplied package IDs with shell
  metacharacters or leading dashes are rejected, remote URLs must be http(s), and
  the registry fetch is size-capped.
- **Teams/OAuth hardening.** HTTP timeouts, a malformed-config guard, and token
  cleanup after a failed connect.

### Accessibility

- **Respects "reduce motion."** When the OS prefers reduced motion, Conduit zeroes
  out spinners, pulses, dialog and tooltip zooms, and transitions.

### Internal

- **CI on every PR**: frontend build, Rust library tests, and a gateway build
  check now run on pull requests across the project.
- **macOS:** newer secrets use the ACL-free SecItem keychain path, with a one-time
  migration of older entries (#26). The fuller DataProtection-keychain change is
  still in progress (it needs a code-signing approach that works for the gateway
  sidecar), so prompts behave as before for now.
- Removed leftover Vite/Tauri scaffold files and shipped a real favicon.

### Thanks

- @bradhallett (#26) for the macOS keychain migration work.

## [0.4.2] - 2026-06-26

### Added

- **Conduit Teams (beta), desktop side.** A new Teams tab connects your local Conduit
  to a self-hosted Conduit Teams server and syncs a shared MCP server set into your
  registry. Keys never leave your machine: only the server set syncs, and you
  authenticate each server locally. Inert until you connect to a team.
- **Composio** in the curated catalog (connect agents to 1,000+ apps via MCP). (#23)

### Fixed

- **Custom API keys now reach HTTP servers.** A remote/HTTP server that uses a manually
  vaulted secret (e.g. a `BEARER` key) gets it injected as the bearer token, not just
  OAuth tokens, so "Manage secrets" works for HTTP servers. (#22)
- **Cleaner multi-account duplicates.** Duplicating a server produces collision-free
  names (`Server (2)`, `(3)`) instead of `Server 2`, with an "add another account"
  hint. (#24)
- **Hermes config keys.** Hermes `mcp_servers` entries are keyed by server name, so the
  config round-trips correctly. (#25)

### Internal

- **macOS secret storage moved to the SecItem keychain API** for new entries, which
  avoids the per-application ACLs behind repeated keychain prompts (#21). If you're on
  macOS and still see prompts, they're from entries created by older versions: clear
  Conduit's old entries in Keychain Access and re-authenticate to use the new path. A
  confirmed prompt-elimination claim is pending validation on signed release builds.

### Thanks

- @bradhallett (#21, #22, #23, #25) and @BharadwajKanneveti (#24).

## [0.4.1] - 2026-06-26

### Changed

- **Windows installers are now code-signed** via Azure Trusted Signing, so the
  SmartScreen "unknown publisher" warning is gone (reputation still accrues with
  downloads). macOS was already signed and notarized; Linux remains unsigned as
  usual. No functional changes from 0.4.0.

## [0.4.0] - 2026-06-26

A security + intent-search release: Conduit now covers the whole tool-trust
boundary (both tool definitions and tool results), searches by meaning, can be
driven by the agent on your terms, and supports two more clients.

### Added

- **Tool-definition integrity (rug-pull + poisoning detection).** The gateway
  fingerprints every tool when a server is first connected and diffs it on each
  refresh. If a previously-approved tool's definition changes, or a known server adds
  a tool (the signature of a "rug pull"), it records a security event. It also scans
  each tool's description/schema for injection-like content (tool poisoning / line
  jumping) when first seen or when it changes. Both surface as notices in the Activity
  view. Detection only, never blocks; on by default (`integrityCheck`), fully local.
  New `get_security_events` command + `security.jsonl`.
- **Content defense (anti-agentjacking).** The gateway scans untrusted tool _results_
  for injection-like content and, on a hit, wraps the offending text with a provenance
  marker ("external data, not instructions") before the agent sees it, plus records a
  security notice. Information-preserving (the original text stays inside the marker),
  only flagged results are touched, never blocks. On by default (`contentDefense`). The
  result-side companion to the definition-side integrity checks.
- **Semantic tool search (optional).** `conduit_search_tools` can blend embedding
  similarity into its lexical ranking so paraphrased needs surface the right tool, not
  just keyword matches. Off by default (`semanticSearch`); point it at any
  OpenAI-compatible `/v1/embeddings` endpoint. Tool embeddings are cached on disk; on
  any failure it falls back to pure lexical, so it can only add signal, never degrade.
  New `benchmark/retrieval.mjs` measures retrieval recall (lexical vs semantic).
- **Controllable MCP (opt-in agent control).** A new _Allow agent control_ switch
  (off by default) lets an agent enable or disable servers through the gateway
  (`conduit_enable_server` / `conduit_disable_server`). The destructive-tool block
  stays user-only, so granting it can't let an agent escalate past your governance;
  the app watches the registry and reflects an agent's change live.
- **Two more clients / catalog entries.** **Hermes** (NousResearch Hermes Agent, YAML
  `mcp_servers` in `~/.hermes/config.yaml`) is now supported, bringing the total to
  **20 clients** (#20). **Firecrawl** (#19) and **OpenRouter** (live model
  intelligence) were added to the curated catalog.

### Changed

- Benchmark suite: added a graded server-sweep harness (`bench-sweep.mjs`) that grades
  answers for correctness, not just completion, and expanded `token-cost.mjs`
  (context-window share, scaling curve, per-tool distribution, multi-volume dollar
  tables). Headline numbers re-measured on a frontier model: up to ~91% fewer total
  tokens at the same graded task success.

### Fixed

- The Playground policy toggles lay out as an even responsive grid instead of
  orphaning the third switch onto its own row.

### Internal

- Release pipeline wired for Windows Authenticode signing via Azure Trusted Signing,
  gated and inert until the signing secrets are configured (changes nothing until the
  certificate is ready).

## [0.3.18] - 2026-06-25

### Added

- **Ask your agent what Conduit is saving you.** `conduit_status` now reports the
  tokens lazy discovery has kept out of context, a dollar estimate at Claude Sonnet
  input rates, the number of tool-list loads, and your biggest catalog collapse.

### Changed

- The in-app savings model picker and the public calculator group models by provider
  (Anthropic, OpenAI, Google), with a custom-price option on the calculator.

### Fixed

- Native select dropdowns render readable in the dark theme (no more light text on a
  light popup).

## [0.3.17] - 2026-06-25

### Added

- **Token economics card.** The Activity tab shows the dollar value of what lazy
  discovery has saved you, with a model-price selector and a one-click Share that
  copies a "Conduit saved me ~~X tokens (~~$Y)" snippet.

### Security

- Hardened three findings from an internal audit: OAuth PKCE/state generation now
  fails loudly instead of silently returning zeros if the OS RNG is unavailable;
  file writes use a unique atomic-write temp name (no torn writes under concurrent
  writers); and a saved bearer token is refused over non-HTTPS to a public host.

## [0.3.16] - 2026-06-25

### Added

- **Live tool refresh.** When a connected server changes its own tool set
  mid-session (via `tools/list_changed`), Conduit re-queries it in place, so new
  or removed tools reach your agent without a restart.
- **Always-on diagnostics.** A size-capped gateway log of connection events, plus
  a one-click **Copy diagnostics** button that bundles your version, OS, a
  secrets-stripped server summary, and the recent log, ready to paste into a bug
  report.
- **BoltAI** is now a supported client (18 total), thanks to a first-time
  contributor (#18).

## [0.3.15] - 2026-06-23

### Fixed

- Clean, all-platforms build of the tokens-saved counter. v0.3.14's Linux job was
  OOM-killed mid-compile, leaving no Linux build or updater manifest; the pipeline
  now gives the Linux runner enough disk and swap, so auto-update works on all four
  platforms again.

## [0.3.14] - 2026-06-23

### Fixed

- The v0.3.12 "tokens saved" counter was missing from the release binaries (a CI
  build cache compiled a stale library from before the command existed). The
  pipeline now builds the workspace from scratch, so the counter ships.

## [0.3.12] - 2026-06-23

### Added

- **"Tokens saved" counter in Activity.** A running estimate of the
  tool-definition tokens lazy discovery has kept out of your agent's context, with
  tool-list loads, your biggest catalog collapse, and since-when. No setup.

## [0.3.11] - 2026-06-22

### Improved

- **Cleaner search index.** The gateway strips boilerplate and stopwords from tool
  descriptions and queries before indexing, so `conduit_search_tools` ranks on the
  words that actually distinguish one tool from another.

### Added

- **BENCHMARK.md** with a reproducible harness: ~97% less tool-definition overhead
  per request and ~90% fewer total tokens at the same task success rate (3 servers,
  62 tools, local model, repeated runs).

## [0.3.10] - 2026-06-22

### Improved

- **Tool search ranks the right tool more often.** When a query mixed a common word
  with a specific one (e.g. "list products"), keyword matching could surface a generic
  "list" tool instead of the products one. Search now tokenizes queries and tools
  (splitting camelCase, light stemming), weights matches by how rare the token is so a
  specific word like "products" outweighs a common one like "list", and bridges a small
  synonym map (mail/email, get/list, team/org). The agent finds the intended tool with
  fewer searches.

## [0.3.9] - 2026-06-22

### Added

- **Two more clients: Jan and Goose** (17 supported in total). Jan uses the standard
  `mcpServers` JSON; Goose is the first YAML client, its MCP servers live under a
  top-level `extensions:` map in `config.yaml`. Both detect, connect with one click,
  and import existing servers, with the same no-wipe safeguard as Zed (config.yaml
  also holds Goose's model settings and built-in extensions).

### Fixed

- **Required tool parameters now work from grammar-constrained local clients.** Some
  local runtimes (e.g. Jan) force the model's output to match the tool schema, and
  `conduit_call_tool`'s `arguments` declared no properties, so the model could only
  ever emit an empty `{}`, making a required param (e.g. Vercel's `teamId`) impossible
  to pass. `arguments` now accepts arbitrary properties, and the gateway also tolerates
  models that put params at the top level instead of nesting them under `arguments`.
- A stdio server entry now always writes `args` (even empty); some clients reject an
  entry whose `args` key is missing. An empty `command` string is treated as no command,
  so a remote/url server shipped with `"command": ""` isn't mis-read as stdio.
- The sidebar now fills the full window height instead of stopping at its content.
- Clearer messages when the onboarding starter list can't load (offline) and when a
  Linux box has no system keyring.

## [0.3.8] - 2026-06-21

### Improved

- **Faster, more decisive tool search, especially with local models.** Search now
  leads with the single best match and tells the model to call it; the remaining
  results come back as a compact menu (name + a one-line description, no schema)
  instead of every tool's full schema. A large result set drops from tens of KB to a
  few KB, so a model that re-reads its context each turn (local models especially)
  runs noticeably faster. Full schema for any other tool still comes from a scoped or
  exact-name search.
- **A loop-breaker for weaker models.** When a model re-searches and keeps landing on
  the same top tool, the gateway returns just that tool and tells it to call it,
  rather than letting the model spin on repeated searches. It only triggers on a
  repeated top result, so a capable model, or one legitimately exploring different
  tools, is never affected.

## [0.3.7] - 2026-06-21

### Added

- **Five more clients: Zed, LM Studio, Warp, Amazon Q, and Kiro.** Conduit detects
  each, installs the gateway with one click, and imports its existing servers.
  - Zed keeps MCP servers under `context_servers` in its `settings.json`, which is
    JSONC (comments and trailing commas) holding the user's whole editor config. That
    file is now read leniently so a commented config isn't mistaken for corrupt, and
    is **never replaced with an empty document on a parse failure**, so Conduit cannot
    wipe your settings.
  - LM Studio, Warp, Amazon Q, and Kiro use the standard `mcpServers` JSON shape at
    their respective config paths (`~/.lmstudio/mcp.json`, `~/.warp/.mcp.json`,
    `~/.aws/amazonq/mcp.json`, `~/.kiro/settings/mcp.json`).

### Fixed

- Client detection now reflects whether an app is actually installed, not merely
  whether an MCP config file happens to exist. The old "config file's parent dir"
  heuristic was wrong for some clients: Claude Code's config lives at `~/.claude.json`
  (parent is the home dir, which always exists, so it falsely showed as installed
  everywhere), and Warp's `~/.warp` only appears after its first file-based MCP use.
  Those clients now check an explicit install/data directory.

## [0.3.6] - 2026-06-21

### Fixed

- Lazy-discovery tool search is far more reliable on multi-server setups. A tool
  that exists could read as missing (so an agent would wrongly conclude a server
  was "read only"): the default result limit was too low with no signal that
  results were truncated, and one server with many matching tools could crowd out
  the rest. Search now returns more results, reports when it truncated and how to
  narrow, diversifies across servers, and accepts a `server` filter to scope or
  fully enumerate one server's tools. `conduit_status` now lists each server and
  its tool count.
- Tool search no longer blows up the agent's context: a few servers ship enormous
  input schemas (tens of KB each), and search returned the full schema for every
  result. It now bounds the total schema size (keeping the top result's full schema
  and returning the rest compact) and truncates long descriptions. Full schema/text
  for a specific tool is available by searching its exact name.

## [0.3.5] - 2026-06-21

### Security

- Importing a shared setup now previews exactly what it will run (each server's
  command, args, and url) and imports only on confirmation, and flags entries that
  spawn a shell. A shared config can no longer slip an unseen command past you.
- OAuth endpoints discovered from a server's metadata are rejected if they point at
  a private or loopback address while the server itself is public (SSRF guard);
  legitimate local servers are unaffected.
- Set an explicit Content-Security-Policy for the app window.

### Fixed

- Registry writes are atomic, so a crash mid-write can't corrupt your server set.
- A corrupt registry no longer silently makes every tool vanish: the gateway keeps
  serving the last good tool list and logs the problem.
- The user catalog and config backups are stored in one consistent location across
  packaged and unpackaged installs.

### Changed

- Onboarding's final step reflects what you actually set up and explains lazy
  discovery; the empty state offers a "Browse catalog" action; the New Profile
  dialog explains that profiles scope servers, not credentials.
- Clearer macOS OAuth guidance (shown before sign-in, not only after a failure).

## [0.3.4] - 2026-06-21

### Fixed

- Client config writes are now atomic (temp file + rename), so a crash or full
  disk mid-write can't truncate a client's MCP config.
- One unresponsive stdio server no longer stalls the whole gateway: the connect
  handshake fails fast (10s) instead of waiting the full 30s read timeout.
- Playground policy toggles report failures instead of silently reverting.
- The share-import file size is capped before reading.
- Updater "Check for updates" tells "up to date" apart from "couldn't check".
- macOS builds now publish auto-update artifacts; macOS auto-update was inert in
  v0.3.3 (the update manifest had empty macOS entries).

## [0.3.3] - 2026-06-21

### Added

- First-run onboarding wizard: detect clients, add your first servers (import,
  one-click popular starters, or the catalog), and connect a client. Re-run it
  anytime from the sidebar footer.
- In-app auto-updater: Conduit checks for new releases and can download, install,
  and relaunch itself, with release notes shown before installing.
- Share a setup as a `.json` file (in addition to the clipboard), with an optional
  name and description. Secrets are never included.
- Per-tool breakdown in the Activity dashboard, plus server and errors-only filters.

### Changed

- Reliability: gateway recovers from a poisoned lock, the audit log rotates so it
  can't grow unbounded, more tolerant SSE id matching, and a guard against
  overlapping health probes (which curbed macOS keychain prompt storms).

## [0.3.2] - 2026-06-20

### Added

- Signed and notarized macOS builds (Apple Silicon + Intel), alongside Windows
  and Linux, via a tag-triggered release pipeline.

## [0.3.0] - 2026-06-20

- First public release: local MCP gateway and manager with lazy discovery,
  per-agent profiles, the catalog, the tool playground, and the activity log.

[Unreleased]: https://github.com/tsouth89/toolport/compare/v1.6.2...HEAD
[1.6.2]: https://github.com/tsouth89/toolport/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/tsouth89/toolport/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/tsouth89/toolport/releases/tag/v1.6.0
[1.5.3]: https://github.com/tsouth89/toolport/releases/tag/v1.5.3
[0.3.16]: https://github.com/tsouth89/conduit/releases/tag/v0.3.16
[0.3.15]: https://github.com/tsouth89/conduit/releases/tag/v0.3.15
[0.3.14]: https://github.com/tsouth89/conduit/releases/tag/v0.3.14
[0.3.12]: https://github.com/tsouth89/conduit/releases/tag/v0.3.12
[0.3.11]: https://github.com/tsouth89/conduit/releases/tag/v0.3.11
[0.3.10]: https://github.com/tsouth89/conduit/releases/tag/v0.3.10
[0.3.9]: https://github.com/tsouth89/conduit/releases/tag/v0.3.9
[0.3.8]: https://github.com/tsouth89/conduit/releases/tag/v0.3.8
[0.3.7]: https://github.com/tsouth89/conduit/releases/tag/v0.3.7
[0.3.6]: https://github.com/tsouth89/conduit/releases/tag/v0.3.6
[0.3.5]: https://github.com/tsouth89/conduit/releases/tag/v0.3.5
[0.3.4]: https://github.com/tsouth89/conduit/releases/tag/v0.3.4
[0.3.3]: https://github.com/tsouth89/conduit/releases/tag/v0.3.3
[0.3.2]: https://github.com/tsouth89/conduit/releases/tag/v0.3.2
[0.3.0]: https://github.com/tsouth89/conduit/releases/tag/v0.3.0
