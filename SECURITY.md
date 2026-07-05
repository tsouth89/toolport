# Security

Toolport is a local-first MCP gateway and manager. This document describes how it
handles secrets and trust, and how to report a vulnerability.

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

## Security design

- **Local-first.** Toolport's core gateway runs on your machine. The desktop app
  is a manager; the gateway is a local process each AI client spawns over stdio.
  There is no telemetry. Routine tool traffic is between the gateway and the
  upstream MCP servers _you_ configure. Optional hosted features make explicit
  user-initiated requests: shared setup links use `toolport.app`, and Teams uses
  the team server URL you choose.
- **Secrets in the OS keychain.** API keys and OAuth tokens are stored in the
  platform keychain (macOS Keychain, Windows Credential Manager, Linux Secret
  Service), never in plaintext config files and never written to logs.
- **OAuth 2.1, done conservatively.** Dynamic client registration, PKCE (S256),
  a CSRF `state` check, a loopback (`127.0.0.1`) redirect, RFC 8707 resource
  binding, and `offline_access` refresh tokens. Discovered authorization, token,
  and registration endpoints must be `https://` (loopback `http` is allowed only
  for local development).
- **Minimal attack surface.** The gateway communicates over stdio and opens no
  listening network port. The only socket it ever binds is a transient
  `127.0.0.1` loopback listener during an OAuth callback, which closes as soon as
  the flow completes.
- **Diagnostics off by default.** Debug logging is gated behind the
  `CONDUIT_DEBUG` environment variable and never records tokens or full
  authorization URLs.
- **Tool governance.** Per-tool enable/disable and a destructive-tool deny-list
  let you block dangerous tools before a client can ever call them.

## Trust model and your responsibilities

Toolport proxies to whatever MCP servers **you** add. It does not vet the behavior
of third-party servers: an upstream server you configure runs as a local process
(for stdio servers) and/or receives the credentials you give it. **Only add
servers you trust.** Lazy discovery reduces how much surface is exposed to the
agent, but a tool you approve still executes upstream.

## Known issues

See the [Known issues](README.md#known-issues) section of the README for current
advisories, including the Linux-only `glib` `RUSTSEC-2024-0429` soundness issue
inherited transitively from Tauri's Linux webview stack.
