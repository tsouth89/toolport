# Toolport token benchmark

Quantifies Toolport's core claim, that lazy discovery (3 meta-tools the agent
searches) keeps context flat where flat tool exposure (every server's tools loaded
into every request) does not, by running the **same agent tasks** against your
local LLM under both modes and measuring tokens, tool calls, and completion.

It's framed the same way as the [mcpico benchmark](https://github.com/lxg2it/mcpico/blob/main/BENCHMARK.md),
so the numbers are directly comparable: lazy mode makes **more tool calls**
(search round-trips) but should use **far fewer tokens** because it never dumps
every schema into context.

## No-model catalog report (`token-cost.mjs`)

Want the headline numbers without standing up a local LLM? `token-cost.mjs` reads
the catalog Toolport already built and reports, deterministically: per-server
definition tokens, the per-tool size distribution, how much of each model's context
window the definitions eat, the reduction-vs-tool-count scaling curve, and monthly
dollar cost across request volumes.

```bash
node benchmark/token-cost.mjs            # auto-reads the active profile's cache
node benchmark/token-cost.mjs <path>     # or point at a specific tool-cache JSON
```

With no argument it resolves Toolport's data dir for you (Windows `%APPDATA%\Conduit`,
macOS `~/Library/Application Support/Conduit`, Linux `~/.config/Conduit`). A
profile-scoped client writes `tool-cache-<profile>.json`; the unscoped default is
`tool-cache.json`, which is what the auto-path uses.

## Run the agent-loop benchmark

```bash
# 1. Build the gateway
npm run build:gateway        # or: cargo build --release --bin toolport-gateway

# 2. Connect a few servers in Toolport, and edit the TASKS in bench.js to match them.

# 3. Start a local OpenAI-compatible LLM
#    LM Studio: load a model and start the server (default http://localhost:1234)
#    Ollama:    it serves an OpenAI-compatible API on http://localhost:11434/v1

# 4. Run
node benchmark/bench.js
MODEL="qwen2.5-7b-instruct" node benchmark/bench.js
LLM_URL="http://localhost:11434/v1/chat/completions" MODEL="qwen2.5:7b" node benchmark/bench.js
```

## What it reports

Per task and as totals, for each mode:

- **tokens**: summed from the LLM's `usage.total_tokens` across every request in the agent loop. This is the headline metric.
- **tool calls**: how many tool invocations the agent made (lazy mode includes its search calls).
- **completion**: whether the agent produced a final answer. Eyeball the printed answers for actual correctness; this is a coarse success flag, not a grader.

And the summary line: tools exposed (flat vs 3), total-token delta as a percent, and tasks completed.

## Reading the results honestly

- **Small sample.** A handful of tasks and single runs are noisy. Run it a few times; treat the _direction_ as the signal, not the exact percentage.
- **The trade-off is real and intentional.** Lazy mode trades extra tool calls (search → call) for fewer total tokens. The table shows both so you're not hiding the round-trip cost.
- **Flat mode may error** on small models, dumping every tool schema can overflow the context window. That's a finding, not a bug: it's exactly the failure lazy discovery avoids. The harness records it as an error rather than crashing.
- **Savings concentrate on smaller models** (mcpico saw ~60% on a 9B, ~8% on a 35B). Run it on a small _and_ a mid model to show that, it's the local-model story.

## Caveats

- Token counts depend on your runtime reporting `usage` (LM Studio and Ollama do).
- Tasks must match servers you actually have connected; the defaults assume Resend / Neon / Vercel.
- This measures the agent loop, not just the static tool-definition size. The static
  size (3 schemas vs hundreds) is the upper bound; the loop shows what you actually pay.
