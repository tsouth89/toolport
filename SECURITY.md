# Security

Toolport is a local-first MCP gateway and manager. This document describes how it
handles secrets, network boundaries, and trust across each way it runs, what it
records locally, and how to report a vulnerability.

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue:

- Preferred: GitHub's [private vulnerability reporting](https://github.com/tsouth89/toolport/security/advisories/new)
  (repo **Security** tab to **Report a vulnerability**).
- Or email the maintainer at **tyler@southforgeai.com**.

Please include reproduction steps and the affected version/commit. We aim to
acknowledge within a few days. Coordinated disclosure is appreciated; we will
credit reporters who want it.

## Supported versions

Toolport ships fixes on the latest release only. Always run the newest version
from the [Releases](https://github.com/tsouth89/toolport/releases) page.

## How Toolport runs, and where the boundaries are

Toolport's core is a local gateway that AI clients reach; the desktop app is a
manager around it. What network surface exists depends on the mode you run:

- **Desktop app + stdio gateway (the default).** Each AI client spawns the
  gateway as a local child process and talks to it over stdio (standard
  input/output). In this mode the gateway binds **no listening network port** at
  all. The only socket it ever opens is a transient `127.0.0.1` loopback listener
  during an OAuth callback, which closes as soon as that flow completes.
- **Local HTTP / OpenAPI bridge (`CONDUIT_HTTP`).** For clients that speak HTTP
  or OpenAPI instead of stdio, the gateway can bind a listener. It defaults to
  `127.0.0.1:8765` (loopback only), configurable with `CONDUIT_HTTP_HOST` and the
  port. When the desktop app starts this bridge it auto-generates a bearer token
  (`CONDUIT_HTTP_TOKEN`); a request without a valid token gets `401`, and any
  cross-site browser request is rejected with `403` regardless of token. A gateway
  you launch by hand on loopback **without** a token binds anyway and is reachable
  by any local process, so set a token if other local users or processes are not
  trusted.
- **Headless / Docker.** The published image runs the HTTP bridge and sets
  `CONDUIT_HTTP_HOST=0.0.0.0` so it is reachable off-host. Binding to a
  non-loopback address **requires** `CONDUIT_HTTP_TOKEN`: without one the gateway
  refuses to start. Put it behind your own TLS/ingress; the gateway serves plain
  HTTP and expects the operator to terminate TLS.
- **Sharing and Teams (opt-in, hosted).** These make explicit, user-initiated
  requests to hosted services and are covered under
  [Telemetry and hosted services](#telemetry-and-hosted-services) below.

## Secrets

API keys and OAuth tokens are never written to plaintext config files and never
written to logs. Where they live depends on the backend, selected by environment:

- **OS keychain (desktop default).** With no secret-related env var set, secrets
  go to the platform keychain: the macOS data-protection keychain (under a
  team-scoped access group shared with the signed gateway), Windows Credential
  Manager, or the Linux Secret Service.
- **Encrypted file backend (`CONDUIT_SECRET_KEY`).** Setting this env var switches
  storage to an encrypted `secrets.enc` file (XChaCha20-Poly1305) in Toolport's
  data directory, keyed from the passphrase. This is the backend for headless and
  containerized deployments where no OS keychain is available. The passphrase is
  the whole key: choose a high-entropy value and keep it out of shell history and
  image layers. If `secrets.enc` leaks together with a weak passphrase, the
  secrets are recoverable, so treat the file as sensitive.
- **Environment injection (headless).** A secret can also be supplied directly as
  `CONDUIT_SECRET_<KEY>`, or as a bare `<KEY>` only when
  `CONDUIT_ALLOW_BARE_SECRET_ENV` is set. These are read from the process
  environment in cleartext, so they are only as protected as the environment that
  holds them.

## Authentication and OAuth 2.1

Downstream OAuth is done conservatively: dynamic client registration, PKCE
(S256), a CSRF `state` check, a loopback (`127.0.0.1`) redirect, RFC 8707 resource
binding, and `offline_access` refresh tokens. Discovered authorization, token, and
registration endpoints must be `https://` (loopback `http` is allowed only for
local development).

## Tool governance and enforcement

Toolport is detection-first by default, but it is not detection-only: several
controls actively gate or block a call before it reaches an upstream server.

- **Destructive-tool policy.** With the destructive-tool deny policy on, tools
  judged destructive (by their `destructiveHint`, or a write-verb name heuristic)
  are hidden from the catalog and blocked before a client can call them.
- **Confirm-before-destructive.** A softer mode intercepts the first call to a
  destructive tool, returns a preview, and only routes it after an explicit
  `toolport_confirm`.
- **Quarantine on drift.** When an already-approved tool changes in a high-risk
  way (poisoned description, or a destructive/annotation downgrade), it is
  quarantined and blocked until you re-approve it.
- **Human-in-the-loop approval.** When enabled, destructive tools and tools from
  untrusted-provenance servers (shared/registry sources) require an explicit human
  approval. This gate is fail-closed: a denied, timed-out, or unreachable decision
  blocks the call, which returns an error and never routes.
- **Content provenance labeling.** Flagged tool results and resource reads are
  wrapped with a provenance marker telling the model the block is external data,
  not instructions. This labels and fences the content; by design it does not drop
  or block it, so the model still receives it, clearly marked.

Which of these are active depends on your settings and, for Teams, your org
policy. Debug logging is off by default, gated behind `CONDUIT_DEBUG`, and never
records tokens or full authorization URLs.

## Telemetry and hosted services

In local use, Toolport sends **no telemetry**. Routine tool traffic is only
between the gateway and the upstream MCP servers _you_ configure. Data leaves your
machine only through features you explicitly turn on:

- **Teams usage reporting (opt-in, only when joined to a team).** When connected
  to a Toolport Teams organization, a periodic sync reports **aggregate** usage
  for team-provided servers to the team server URL you joined: per-server row of
  call count, tokens saved, and estimated cost. It never sends tool names,
  arguments, results, or anything about your personal (non-team) servers.
- **Shared setup links.** Creating a share link POSTs a secret-stripped server
  setup to `https://toolport.app/api/share`, and only when you take that action.
  Importing a shared link fetches it from the same endpoint.
- **Team server URL.** You provide the Teams server address when you join; there
  is no hardcoded default, and non-loopback team URLs must be `https://`.

## What Toolport records locally, and how to clear it

Everything below stays in Toolport's local data directory (`%APPDATA%\Conduit` on
Windows, the platform config dir elsewhere; override with `CONDUIT_DATA_DIR`) and
never leaves your device on its own. Each log is capped and trims oldest-first:

| Local record           | File                 | Retained                                | Contains                                                      |
| ---------------------- | -------------------- | --------------------------------------- | ------------------------------------------------------------- |
| Audit log              | `audit.jsonl`        | last ~5,000 entries (or 4 MB)           | tool calls and approval/policy decisions                      |
| Discovery search trace | `search-trace.jsonl` | last ~500                               | lazy-discovery searches the agent ran                         |
| Live inspector         | `inspect.jsonl`      | last ~50 (opt-in, off by default)       | captured call arguments and results                           |
| Savings log            | `savings.jsonl`      | last ~2,000, plus a carry-forward total | token-savings tallies (a running aggregate survives trimming) |

Registry config, secrets, tool catalogs, and these logs never leave the device
except through the opt-in hosted features above.

Clear controls: the Activity view has a confirmed **Clear retained activity**
action that deletes all four logs; the live inspector also clears itself when you
turn live inspection off. Both are local, irreversible deletes.

## Trust model and your responsibilities

Toolport proxies to whatever MCP servers **you** add. It does not vet the behavior
of third-party servers: an upstream server you configure runs as a local process
(for stdio servers) and/or receives the credentials you give it. **Only add
servers you trust.** Lazy discovery reduces how much surface is exposed to the
agent, and the governance controls above can gate a call, but a tool you approve
still executes upstream.

When you run Toolport outside the desktop app, some safety defaults become your
responsibility: set `CONDUIT_HTTP_TOKEN` (required for any non-loopback bind),
choose a high-entropy `CONDUIT_SECRET_KEY` for the encrypted file backend, and put
the HTTP bridge behind your own TLS.

## Known issues

See the [Known issues](README.md#known-issues) section of the README for current
advisories, including the Linux-only `glib` `RUSTSEC-2024-0429` soundness issue
inherited transitively from Tauri's Linux webview stack.
