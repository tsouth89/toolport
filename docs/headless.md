# Headless / container gateway

**Gateway-only compile:** CI and headless builds use
`cargo build --no-default-features --bin toolport-gateway` to skip the Tauri
desktop shell and WebKit dependencies. The default feature set (`desktop`) is
for the full app.

Run `toolport-gateway` without the desktop app — for Docker hosts, sandboxed
coding agents, and Open WebUI. The desktop app stays the local-first product
(client config writers, HITL approvals, OAuth UX). This path is the same binary
with HTTP enabled.

## What you get

| Endpoint                             | Use                                                                  |
| ------------------------------------ | -------------------------------------------------------------------- |
| `GET /openapi.json` + `POST /{tool}` | Open WebUI, n8n, LibreChat (OpenAPI)                                 |
| `POST /mcp`                          | MCP clients over streamable-HTTP (Claude Code, Cursor remote, Pi, …) |
| `GET /`                              | Short help text                                                      |

Current streamable-HTTP scope:

- `POST /mcp` returns JSON-RPC responses as JSON by default.
- If `Accept` prefers `text/event-stream`, `POST /mcp` returns a single SSE `message` event and closes.
- `GET /mcp` opens a long-lived SSE listen stream for server→client JSON-RPC (keepalive comments every 30s when idle).
- **Server-initiated RPC passthrough** (#167): when the MCP client declares `roots`, `sampling`, or `elicitation` at `initialize`, downstream servers (stdio or HTTP/SSE) can call `roots/list`, `sampling/createMessage`, and `elicitation/create`; the gateway forwards those to the upstream MCP client over stdio or HTTP MCP (`GET /mcp` listen). Interactive calls use a 120s upstream timeout. `notifications/roots/list_changed` from the client is forwarded to all downstream servers. HTTP downstream answers inline during SSE `POST` responses (no separate downstream `GET /mcp` listener yet).

Auth is the same bearer token as today (`CONDUIT_HTTP_TOKEN` or a registered
`httpClients[]` entry). Non-loopback binds **require** a token.

## Quick start (binary)

```bash
export CONDUIT_HTTP_HOST=0.0.0.0
export CONDUIT_HTTP_TOKEN="$(openssl rand -hex 24)"
export CONDUIT_REGISTRY=/path/to/registry.json
# optional: encrypted vault
# export CONDUIT_SECRET_KEY=...

toolport-gateway --http 8765
```

Point Open WebUI at `http://host:8765` with the bearer token as the API key.
Point an MCP client at `http://host:8765/mcp` (streamable-HTTP).

### MCP handshake (curl)

```bash
# 1) initialize — capture Mcp-Session-Id from the response headers
curl -sD - -o /tmp/init.json -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $CONDUIT_HTTP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

# 2) tools/list (reuse the session id)
curl -s -X POST http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $CONDUIT_HTTP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Mcp-Session-Id: <session-from-step-1>" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

## Docker

### Pull from GHCR (recommended)

After the first CI publish, make the package public (GitHub → Packages →
`toolport-gateway` → Package settings → Change visibility). Then:

```bash
docker pull ghcr.io/tsouth89/toolport-gateway:latest
mkdir -p data
cp data/registry.json.example data/registry.json
cp docker-compose.example.yml docker-compose.yml
# create .env with at least CONDUIT_HTTP_TOKEN=...
docker compose up -d
```

### Build locally

From source (slow — compiles inside Docker):

```bash
docker build -f Dockerfile.source -t toolport-gateway .
```

Or use the runtime Dockerfile after building the binary on the host:

```bash
cargo build --release --bin toolport-gateway --manifest-path src-tauri/Cargo.toml --no-default-features
cp src-tauri/target/release/toolport-gateway toolport-gateway-bin
docker build -t toolport-gateway .
```

Image defaults:

- `CONDUIT_HTTP_HOST=0.0.0.0`
- `CONDUIT_REGISTRY=/data/registry.json`
- port `8765`
- volume `/data`

## Secrets without the OS keychain

Resolution order when a server marks `env[].secret: true`:

1. Process env `CONDUIT_SECRET_<KEY>` (preferred in compose)
2. Process env `<KEY>` when `CONDUIT_ALLOW_BARE_SECRET_ENV=1` (opt-in; enabled in the compose example)
3. Encrypted `secrets.enc` when `CONDUIT_SECRET_KEY` is set
4. OS keychain (desktop)

Example `.env`:

```env
CONDUIT_HTTP_TOKEN=replace-me
CONDUIT_SECRET_STRIPE_SECRET_KEY=sk_live_...
# or bare name with explicit opt-in (set in compose example):
# CONDUIT_ALLOW_BARE_SECRET_ENV=1
# STRIPE_SECRET_KEY=sk_live_...
```

## Minimal `registry.json`

Start from [`data/registry.json.example`](../data/registry.json.example) (remote
MCP server — works in a minimal container with no extra runtime). Or copy a full
`registry.json` from a machine that already runs the desktop app.

A valid headless registry needs `profiles` and `activeProfileId`, not just
`servers`:

```json
{
  "version": 1,
  "servers": [
    {
      "id": "stripe",
      "name": "Stripe",
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@stripe/mcp"],
      "env": [{ "key": "STRIPE_SECRET_KEY", "secret": true }],
      "source": "manual"
    }
  ],
  "profiles": [
    {
      "id": "default",
      "name": "Default",
      "enabledServerIds": ["stripe"]
    }
  ],
  "activeProfileId": "default"
}
```

Stdio servers inside the container need their runtimes (`node`/`npx`, `uv`,
etc.) installed in the image or reached via another container on the same
network. Remote MCP servers (`url` + streamable-HTTP downstream) need no extra
runtime in the gateway image.

## Production checklist

Use this before exposing a headless gateway beyond a trusted host or LAN.

### Network and auth

- [ ] **Bearer token set** — `CONDUIT_HTTP_TOKEN` with at least 24 bytes of
      entropy (`openssl rand -hex 24`). Required when binding anything other than
      loopback; the process refuses `0.0.0.0` without it.
- [ ] **Firewall** — only trusted clients can reach the port. Do not publish
      `:8765` to the public internet without a reverse proxy.
- [ ] **TLS in front** — the gateway speaks plain HTTP. Terminate TLS at nginx,
      Caddy, Traefik, or a cloud load balancer. Never send the bearer token over
      untrusted HTTP.
- [ ] **Scoped HTTP clients** — if the registry lists `httpClients[]`, give each
      caller its own token and profile scope instead of sharing one global token.

### Secrets and registry

- [ ] **Vault passphrase** — set `CONDUIT_SECRET_KEY` and use `secrets.enc`, or
      inject via `CONDUIT_SECRET_<KEY>` env vars. Prefer prefixed names over bare
      `STRIPE_SECRET_KEY` unless you understand `CONDUIT_ALLOW_BARE_SECRET_ENV`.
- [ ] **`.env` permissions** — mode `600`, never commit, rotate if leaked.
- [ ] **Registry on a volume** — persist `/data/registry.json`; back up before
      upgrades. A corrupt file is quarantined, not silently wiped (#224).
- [ ] **Disable HITL** — set `humanApproval: false` in the registry (and leave
      team-forced approval off). Without the desktop app's approval broker,
      gated tools **fail closed** with "approval service unreachable".

### Container hygiene

- [ ] **Non-root** — the published image runs as user `toolport` (uid 10001).
- [ ] **GHCR visibility** — make the package public only if you want anonymous
      pulls; otherwise configure registry auth.
- [ ] **Pin the image** — use a digest or version tag in production, not only
      `:latest`, once you have a known-good deploy.
- [ ] **Healthcheck token** — compose passes `CONDUIT_HTTP_TOKEN` into the
      healthcheck; ensure logs don't echo env vars.

### Runtime expectations

- [ ] **OAuth** — browser OAuth still needs the desktop app. Use API keys /
      pre-vaulted secrets for headless servers.
- [ ] **npx/uvx cold start** — first connect can take up to ~2 minutes while a
      package downloads; this is normal (v1.6.0+).
- [ ] **HTTP downstream MCP** — some remote servers need server-initiated RPC
      outside an SSE `POST` response; those may not work until downstream
      `GET /mcp` listen ships. Prefer stdio or remote servers that answer inline.

## Security

### What already existed (desktop HTTP bridge)

The headless path reuses the same HTTP/OpenAPI server that shipped earlier:
bearer auth, per-client profile scoping, 4 MB request body cap, spawn-command
screening, downstream SSRF guards on OAuth, destructive-tool governance, and
fail-closed approval when the broker is missing. Those paths were hardened in
the v1.5.1–1.5.2 audit batch (#203–#207).

### What is new in 1.6.0 (less field time)

| Area                     | Risk                                                                 | Mitigations in code                                                         |
| ------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **Network exposure**     | Anyone with token + network path can invoke all scoped tools         | Non-loopback requires token; scope via `httpClients[]` / profiles           |
| **MCP streamable-HTTP**  | New `POST /mcp`, `GET /mcp` SSE, session ids                         | Random 128-bit session ids, 24h TTL, 4096 session cap, id format validation |
| **Server-initiated RPC** | Downstream can prompt upstream client (sampling, elicitation, roots) | Gated on client capabilities declared at `initialize`; 120s timeout         |
| **Container secrets**    | Env vars in process memory / compose files                           | `CONDUIT_SECRET_*` prefix; encrypted `secrets.enc` option                   |
| **Long-lived SSE**       | Idle connections, queue growth                                       | Keepalive comments; session cleanup on TTL                                  |

**Known limitations (not bugs, but deploy constraints):**

- No built-in TLS or rate limiting — use a reverse proxy.
- Loopback without a token warns but still starts: any **local** process (including
  a malicious web page via browser) can call tools. Set a token even on localhost if
  browsers run on the same machine.
- Headless + human approval on = destructive calls blocked, not prompted.
- MCP HTTP test coverage is thinner than the stdio gateway path (see ROADMAP).

### Do you need a separate security audit?

**For a typical solo/small-team LAN or VPN deploy:** a disciplined walk through
the [production checklist](#production-checklist) above is the minimum. You do
not need a third-party audit before shipping 1.6.0 to users who already trust
the desktop app with the same credentials.

**Before internet-facing or multi-tenant production**, do a **focused review**
(not necessarily a full pentest) of:

1. Token handling and TLS termination at the proxy
2. Registry + secrets file permissions on the volume
3. Which servers/tools are enabled (principle of least privilege)
4. Whether HITL and team policies match headless mode

A full external audit makes sense if you are selling headless gateway as a
managed service or putting customer API keys on a shared host. The highest-risk
delta is **operational** (exposing the existing HTTP surface on `0.0.0.0`), not
a wholly new trust model.

Optional internal pass: re-run the gateway HTTP + MCP integration tests, smoke
`POST /mcp` initialize → `tools/list` with and without auth, and confirm
unauthenticated requests to a non-loopback bind are rejected at startup.

## Notes

- **HITL approvals** need the desktop app’s approval broker. Leave human
  approval off (or expect fail-closed) in pure headless mode.
- **Client config writers** (Cursor/Claude local JSON) still need the desktop
  app or a one-time manual URL in the client config — which is what sandboxed
  setups usually want anyway.
- Open WebUI details: [openwebui.md](./openwebui.md).
