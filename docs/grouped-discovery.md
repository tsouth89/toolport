# Grouped discovery mode

Toolport has three tool-discovery modes, selected per client by the
`CONDUIT_DISCOVERY` environment variable (falling back to the registry's
`lazy_discovery` setting when unset):

| Mode             | `tools/list` advertises                                                                                      | Best for                                                                                 |
| ---------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| `lazy` (default) | The 4 meta-tools (`toolport_status`, `toolport_search_tools`, `toolport_call_tool`, `toolport_fetch_result`) | Capable models: minimal, constant context regardless of server count                     |
| `grouped`        | The 4 meta-tools **plus** a per-server `help_<server>` browse tool                                           | Weaker / local models: an _enumerable_ server choice instead of inventing a search query |
| `full`           | The entire namespaced catalog (`server__tool`, every tool)                                                   | Debugging, or small setups where full schemas are affordable                             |

## Why grouped exists

`lazy` mode is ideal for a strong model: it exposes a single
`toolport_search_tools` and the model invents a query to find what it needs. A
weaker or local model (e.g. a 7B) often struggles to invent a good query from a
blank slate.

Grouped mode keeps context small but replaces the blank-slate search with an
**enumerable** choice: the model sees one `help_<server>` tool per connected
server (`help_github`, `help_stripe`, ...). It picks a server by name, calls
`help_<server>` to list that server's tools (optionally filtered by a `query`),
then runs the chosen tool with `toolport_call_tool` using the exact name the
listing returned.

Context cost is roughly `4 + (number of servers)` tool definitions, so grouped
mode is the sweet spot for a **handful of tool-heavy servers** (e.g. Stripe's
587 tools collapse to one `help_stripe`). It is not worth it for many tiny
servers, where the per-server tools approach the full catalog.

## How it works (and why it's safe)

- `help_<server>` is a thin rewrite: internally it runs `toolport_search_tools`
  scoped to that server, reusing the exact ranking, truncation, and schema
  handling. `help_<server>(query: "refund")` on Stripe returns
  `stripe__create_refund`, ready to call.
- Tool execution still goes through `toolport_call_tool`, so the audited call
  path is unchanged: content-defense screening, human-in-the-loop approval, the
  destructive-tool confirm gate, per-client scope enforcement, and result
  shaping all apply exactly as they do in lazy and full mode. Grouped mode adds
  **no new execution surface.**
- The `help_<server>` tools are scoped to the client's allowed servers, so a
  registered HTTP client never sees a browse tool for a server outside its
  scope.

## Enabling it

Per client, set the env in that client's MCP server config:

```
CONDUIT_DISCOVERY=grouped
```

## Roadmap

Grouped is the stateless, universally-compatible foundation. A future opt-in
enhancement ("dynamic drill-in") could, for clients that reliably honor
`notifications/tools/list_changed`, swap in a server's real flat tools on
activation so weak models call them with top-level arguments. That is gated on
verified client support because a client that caches `tools/list` for the
session would break it; grouped mode works everywhere today.
