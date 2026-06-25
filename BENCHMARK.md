# Conduit token benchmark

**Routing MCP servers through Conduit's lazy discovery cut tokens by ~90% at the
same task success rate**, on a modest 3-server / 62-tool setup. The savings come
from not loading every tool's schema into the model's context on every request.

Reproduce it yourself: [`benchmark/`](benchmark/) (points at a local LM Studio / Ollama).

## Method

- **Servers:** Stripe (11 tools), Neon (31), Vercel (19) = **62 tools**.
- **Two modes**, same tasks, same model:
  - **flat** , every tool exposed directly (`CONDUIT_DISCOVERY=full`), the normal MCP setup.
  - **lazy** , Conduit advertises 3 meta-tools (`conduit_status`, `conduit_search_tools`,
    `conduit_call_tool`) and the agent searches/calls on demand (`CONDUIT_DISCOVERY=lazy`).
- **Model:** Qwen2.5-7B-Instruct, local via LM Studio.
- **Tasks (5 runs each):** list Stripe products; list Neon projects; list Vercel
  projects (a two-step that needs a team id first).
- **Measured:** tool-definition overhead (tokens every request pays just to list tools),
  total tokens to complete each task, and completion.

## Results

**Tool-definition overhead** , the tokens carried on *every* request:

| Mode | Tools exposed | Overhead / request |
|---|---|---|
| flat | 62 | **23,698 tokens** |
| lazy | 3 | **658 tokens** |

→ **97% less overhead, on every single call.** (Deterministic, identical across runs.)

**Total tokens to complete each task** (median of 5 runs):

| Task | flat | lazy | reduction |
|---|---|---|---|
| stripe-products | 71,612 | 9,839 | 86% |
| neon-projects | 48,683 | 2,840 | 94% |
| vercel-projects | 47,687 | 4,955 | 90% |
| **total** | **167,982** | **17,634** | **90%** |

**Completion: 15/15 in both modes.** Lazy discovery did not trade success for tokens.

## Why flat is so expensive

Flat mode re-sends all 62 tool schemas on **every** LLM call, so a 2-call task pays the
~24K overhead twice before counting any real work. Lazy mode pays ~660 tokens of meta-tool
overhead once and searches for what it needs. The more calls a task takes, the wider the gap.

## Measured on a real 14-server catalog

The 62-tool test above is deliberately small. Point [`benchmark/token-cost.mjs`](benchmark/token-cost.mjs)
at a real Conduit catalog (no model needed, it just measures the tool definitions)
and the gap widens fast. On a live 14-server setup of **415 tools**, the definitions
an agent loads on **every request** measure:

| | Per request |
|---|---|
| Without Conduit (all 415 tools) | **164,880 tokens** |
| With Conduit (3 meta-tools, flat) | **660 tokens** |
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
models' context alongside real work. At 200 agent requests/day it's roughly
**$3,000/month** in input tokens at Claude Sonnet prices (about $5,000 at Opus),
spent entirely on re-sending tool schemas. Conduit's meta-tools stay flat at 3 no
matter how many servers you add, which is why the reduction *grows* with your setup
(90% at 62 tools, 99.6% at 415).

The measured average here is ~397 tokens per tool, consistent with the ~387 the
public [calculator](https://conduitmcp.app/calculator) uses.

## Honest caveats

- **Small sample**, one model, one machine, three tasks. Treat the *direction* (a large,
  consistent reduction) as the signal, not the exact percentage.
- **Lazy adds search round-trips.** The 90% total-token figure is already net of that. The
  trade-off only pays off past a handful of tools; for a single tiny server it's overkill.
- **Savings scale with your tool surface.** 62 tools here; bigger setups save more, smaller
  save less. The per-request *overhead* reduction (97%) is the most stable number.
- Token counts come from the model's reported usage; completion means the agent produced a
  final answer (answers were eyeballed for correctness).
