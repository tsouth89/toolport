# Using Toolport with Open WebUI

Toolport speaks **HTTP/OpenAPI natively**, so [Open WebUI](https://github.com/open-webui/open-webui)
(and any OpenAPI tool client) connects straight to the gateway. No bridge, no
proxy, no Python. Validated end to end: a model in Open WebUI reaches every
server you've connected through Toolport, including chained multi-step tool flows.

## The recipe

**1. Turn on the HTTP endpoint.** In the Toolport app: **Settings ->
Integrations -> "Open WebUI / HTTP endpoint"**, flip it on, and copy the **URL**
(`http://localhost:8765`) and the **token** it shows. The app supervises the
gateway for you and shuts it down when you quit.

> Prefer the command line? `toolport-gateway --http 8765` (or `CONDUIT_HTTP=8765`)
> does the same thing when `CONDUIT_HTTP_TOKEN=<your-token>` is set (the app does
> this automatically). It serves an OpenAPI spec at
> `http://localhost:8765/openapi.json` and a POST endpoint per tool.

**2. Add it to Open WebUI.** Settings -> Tools -> add an OpenAPI tool server
pointing at `http://localhost:8765`, and paste the **token** as its API key
(Bearer auth). The `toolport_*` tools appear. The token matters: without it, any
web page open in your browser could call your tools, so the endpoint requires it.

**3. Set Function Calling to Native (per chat).** This is the setting that
silently breaks things. In the chat's **Controls** panel -> **Advanced Params**,
set **Function Calling** to **Native**, not Default. Default uses prompt-injection
and often never fires (the model just replies "I don't have access to that");
Native passes the tools through the model's real function-calling API. Note: this
can reset to Default on each new chat, and setting it at the model level
(Workspace -> Models) does not reliably carry over, so set it in the chat itself
if tools stop firing.

**4. Use a capable model.** Lazy discovery (the default) gives the model the
meta-tools and it searches then calls on demand. A capable model (a frontier API
like gpt-4o-mini, or a strong local model in the 14B+ range) handles this well,
including chained multi-step flows. Small local models (a 7B, say) tend to
struggle with the search-then-call chain.

That's it. Ask for something one of your servers does ("list my recent emails",
"show my Vercel projects") and it routes through Toolport.

## Notes

- **Local-only by default.** The gateway binds `127.0.0.1`, so only this machine
  can reach it. If you run Open WebUI in Docker, set `CONDUIT_HTTP_HOST=0.0.0.0`
  and point the tool server at `http://host.docker.internal:8765`. Every bind requires
  `CONDUIT_HTTP_TOKEN` or a registered HTTP client. For isolated local development,
  `--insecure-loopback` explicitly permits an open loopback listener; it never bypasses
  authentication for `0.0.0.0`. Only expose non-loopback HTTP on a trusted network.
- **Lazy vs full discovery.** Lazy (default) keeps the model's context tiny and
  is best for capable models. For a weaker local model, `CONDUIT_DISCOVERY=full`
  scoped to a small profile exposes the tools directly (no search step) so the
  tool count stays manageable.
- **Multi-step calls resolve themselves.** If a tool needs an identifier the model
  doesn't have yet (e.g. a Vercel `teamId`), the gateway refuses an invented
  placeholder and points the model at the right list/get tool to fetch the real
  value first, so chained calls work even with smaller models.
- **Plays well with other tools.** `toolport_search_tools` is written to be the
  model's first stop for any external action, so it competes well against other
  tools you may have installed, no need to disable them.
- **Any HTTP/OpenAPI consumer.** The same endpoint works for n8n, LibreChat,
  custom agents, anything that speaks OpenAPI, not just Open WebUI.

> Earlier versions of this guide used `mcpo` (Open WebUI's MCP-to-OpenAPI proxy)
> in front of the gateway. The gateway now serves OpenAPI itself, so mcpo is no
> longer needed.
