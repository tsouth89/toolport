# Changelog

All notable changes to Conduit are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions match the GitHub releases.

## [Unreleased]

### Added
- **Tool-definition integrity (rug-pull + poisoning detection).** The gateway now
  fingerprints every tool when a server is first connected and diffs it on each
  refresh. If a previously-approved tool's definition changes, or a known server adds
  a tool (the signature of a "rug pull"), it records a security event. It also scans
  each tool's description/schema for injection-like content (tool poisoning / line
  jumping) when first seen or when it changes. Both surface as notices in the Activity
  view. Detection only, never blocks; on by default (`integrityCheck`), fully local.
  New `get_security_events` command + `security.jsonl`.
- **OpenRouter** added to the curated catalog (live model intelligence; OAuth).
- **Semantic tool search (optional).** `conduit_search_tools` can blend embedding
  similarity into its lexical ranking so paraphrased needs surface the right tool, not
  just keyword matches. Off by default (`semanticSearch`); point it at any
  OpenAI-compatible `/v1/embeddings` endpoint. Tool embeddings are cached on disk; on
  any failure it falls back to pure lexical, so it can only add signal, never degrade.
  New `benchmark/retrieval.mjs` measures retrieval recall (lexical vs semantic).

### Changed
- Benchmark suite: added a graded server-sweep harness (`bench-sweep.mjs`) that
  grades answers for correctness, not just completion, and expanded `token-cost.mjs`
  (context-window share, scaling curve, per-tool distribution, multi-volume dollar
  tables).

## [0.3.19] - 2026-06-25

### Added
- **Controllable MCP (opt-in agent control).** A new *Allow agent control* switch
  (off by default) lets an agent enable or disable servers through the gateway
  (`conduit_enable_server` / `conduit_disable_server`). The destructive-tool block
  stays user-only, so granting it can't let an agent escalate past your governance;
  the app watches the registry and reflects an agent's change live.

### Fixed
- The Playground policy toggles lay out as an even responsive grid instead of
  orphaning the third switch onto its own row.

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
