# Changelog

All notable changes to Toolport are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions match the GitHub releases.
Entries before the rename below shipped under the project's former name, Conduit.

## [Unreleased]

### Security
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
  client scoped to a subset of servers could still read *any* connected server's
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

### Fixed
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
- **Content defense (anti-agentjacking).** The gateway scans untrusted tool *results*
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
- **Controllable MCP (opt-in agent control).** A new *Allow agent control* switch
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
  copies a "Conduit saved me ~X tokens (~$Y)" snippet.

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

[Unreleased]: https://github.com/tsouth89/conduit/compare/v0.3.16...HEAD
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
