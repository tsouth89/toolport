# Toolport token benchmark

**Routing MCP servers through Toolport's lazy discovery cut total tokens 74-91% at the
SAME task success rate**, measured on a frontier model and graded for *correct answers*,
not just completion. Every task completed correctly in both modes, and the savings grow
as you add servers. The reduction comes from not loading every tool's schema into the
model's context on every request.

Reproduce it yourself: [`benchmark/`](benchmark/).

## Method

- **Two modes**, same tasks, same model:
  - **flat**, every downstream tool exposed directly (`CONDUIT_DISCOVERY=full`), the normal MCP setup.
  - **lazy**, Toolport advertises 3 meta-tools (`toolport_status`, `toolport_search_tools`,
    `toolport_call_tool`) and the agent searches/calls on demand (`CONDUIT_DISCOVERY=lazy`).
    (The current default adds a fourth, `toolport_fetch_result`, ~330 tokens more of
    always-on overhead. It doesn't change the reduction story below.)
- **Model:** GPT-5.5 (frontier, via the Vercel AI Gateway), so model capability is not the
  variable, both modes can actually complete every task.
- **Tasks (5 runs each):** list Stripe products; list Neon projects; list Vercel projects
  (a two-step that needs a team id first).
- **Graded for correctness:** a run counts only if the agent's final answer contains the
  real items from the account, so "completed" can't hide a wrong or "I couldn't" answer.
- **Swept across catalog size** (3 and 6 connected servers) to show how the gap scales.

## Results

End-to-end tokens to complete the three tasks (median of 5 runs), both modes graded:

| Servers | Tools | Flat tokens | Lazy tokens | Reduction | Correct (flat / lazy) |
|---|---|---|---|---|---|
| 3 | 63 | 179,181 | 47,095 | **74%** | 15/15 · 15/15 |
| 6 | 183 | 471,775 | 40,354 | **91%** | 15/15 · 15/15 |

Two things stand out:

- **Identical task success.** Every task completed *correctly* in both modes, 30/30.
  Lazy discovery did not trade accuracy for tokens.
- **The savings grow with your catalog.** Flat's cost more than doubled as servers went
  3 → 6 (it re-sends every tool schema on every call), while lazy's actually *dropped*
  (47K → 40K), it pays a flat ~450-token meta-tool overhead no matter how many servers
  you connect. Per-request tool-definition overhead: flat **19,002 → 51,533**, lazy a
  constant **451**.

## Why flat is so expensive

Flat mode re-sends every tool schema on **every** LLM call, so a multi-step task pays that
overhead several times before counting any real work, and it climbs with each server you
add. Lazy mode pays ~450 tokens of meta-tool overhead and searches for what it needs. The
more tools you connect and the more calls a task takes, the wider the gap.

## Measured on a real 14-server catalog

The 62-tool test above is deliberately small. Point [`benchmark/token-cost.mjs`](benchmark/token-cost.mjs)
at a real Toolport catalog (no model needed, it just measures the tool definitions)
and the gap widens fast. On a live 14-server setup of **415 tools**, the definitions
an agent loads on **every request** measure:

| | Per request |
|---|---|
| Without Toolport (all 415 tools) | **164,880 tokens** |
| With Toolport (3 meta-tools, flat) | **660 tokens** |
| Reduction | **99.6%** |

The cost is dominated by a few large servers:

| Server | Tools | Definition tokens |
|---|---|---|
| RevenueCat | 93 | 42,370 |
| GitHub | 44 | 27,913 |
| Resend | 83 | 26,045 |
| Cloudflare (observability) | 8 | 5,948 |
| Stripe | 11 | 5,214 |
| Vercel | 20 | 5,029 |
| Supabase | 29 | 4,897 |
| (5 more) | ... | ... |

At ~165k tokens of definitions *per request*, that catalog barely fits in most
models' context alongside real work. On a subscription with usage caps (Claude
Pro/Max, Cursor, and the like) you feel that directly as runway: cutting ~99% of
always-on tool tokens is roughly that much more headroom for real work before you
hit a limit, and prompt caching doesn't stretch a usage cap the way it discounts a
bill. Toolport's meta-tools stay flat no matter how many servers you add, which is
why the reduction *grows* with your setup (90% at 62 tools, 99.6% at 415).

The measured average here is ~397 tokens per tool, consistent with the ~387 the
public [calculator](https://toolport.app/calculator) uses.

## Latency: the gateway is not the bottleneck

Tokens are the headline, but a gateway adds a hop, so does it cost you time? Measure
it with [`benchmark/latency.mjs`](benchmark/latency.mjs), which spawns the gateway
against an instant mock downstream so the number is purely Toolport's own overhead
(no model, no network, no API keys):

| Operation | Median |
|---|---|
| Handshake (one-time, per gateway start) | ~21 ms |
| `tools/list` (lazy, 3 tools) | ~0.2 ms |
| `toolport_search_tools` | ~0.1 ms |
| A tool call through Toolport vs. calling the server directly | **+~0.75 ms** |

Toolport adds well under a millisecond to a tool call. Real MCP servers take tens to
hundreds of ms each (a process or a network API), so that overhead is noise, and it
buys the ~90% token reduction above. (Numbers from a dev laptop over 200 iterations;
run it on yours: `node benchmark/latency.mjs`.)

## Honest caveats

- **Scope:** one frontier model (GPT-5.5), one machine, three read-only "list" tasks, 5
  runs each. Treat the *direction* (a large, consistent reduction at equal correctness) as
  the signal, not the exact percentage. The deterministic overhead numbers above need no
  such caveat, they're exact.
- **Correctness is graded, not eyeballed.** A run counts only if the answer contains the
  account's real items, so the 30/30 is "right," not just "finished." Token counts come
  from the model's reported `usage`.
- **Lazy adds search round-trips.** The total-token figures are already net of that. The
  trade-off only pays off past a handful of tools; for a single tiny server it's overkill.
- **Savings scale with your tool surface**, and that's the point: 74% at 63 tools, 91% at
  183, 99.6% definition-overhead at 415. The more you connect, the wider the gap.
