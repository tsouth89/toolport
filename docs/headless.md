# Headless / container gateway

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
- Long-lived server-initiated `GET /mcp` SSE listening is not implemented yet (`405`).

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

```bash
# from repo root
docker build -t toolport-gateway .
mkdir -p data
cp data/registry.json.example data/registry.json
# edit data/registry.json for your servers, then:
cp docker-compose.example.yml docker-compose.yml
# create .env with at least CONDUIT_HTTP_TOKEN=...
docker compose up --build
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

## Notes

- **HITL approvals** need the desktop app’s approval broker. Leave human
  approval off (or expect fail-closed) in pure headless mode.
- **Client config writers** (Cursor/Claude local JSON) still need the desktop
  app or a one-time manual URL in the client config — which is what sandboxed
  setups usually want anyway.
- Open WebUI details: [openwebui.md](./openwebui.md).
