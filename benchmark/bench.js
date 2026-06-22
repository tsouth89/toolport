// Conduit token benchmark.
//
// Quantifies the headline claim ("hundreds of tool defs collapse to 3, context
// stays flat") by running the SAME agent tasks against your local LLM twice:
//
//   - flat: the gateway exposes every downstream tool directly (CONDUIT_DISCOVERY=full)
//   - lazy: the gateway exposes 3 meta-tools and the agent searches (CONDUIT_DISCOVERY=lazy)
//
// It reports total tokens, tool calls, and completion per task, so the trade-off
// is honest: lazy makes MORE tool calls (search round-trips) but should use FAR
// fewer tokens because it never dumps every schema into context. Same framing as
// the mcpico benchmark, so the numbers are directly comparable.
//
// Prereqs:
//   1. Build the gateway:   npm run build:gateway   (or: cargo build --release --bin conduit-gateway)
//   2. Connect some servers in Conduit (the tasks below should match what you have).
//   3. Run a local OpenAI-compatible LLM:
//        - LM Studio: start the server (default http://localhost:1234)
//        - Ollama:    OLLAMA_HOST has an OpenAI-compatible /v1 endpoint on :11434
//
// Run:
//   node benchmark/bench.js
//   MODEL="qwen2.5-7b-instruct" node benchmark/bench.js
//   LLM_URL="http://localhost:11434/v1/chat/completions" MODEL="qwen2.5:7b" node benchmark/bench.js

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const LLM_URL = process.env.LLM_URL || "http://localhost:1234/v1/chat/completions";
const MODEL = process.env.MODEL || "local-model";
const GATEWAY = process.env.GATEWAY || defaultGateway();
const MAX_STEPS = Number(process.env.MAX_STEPS || 12);
const CONNECT_WAIT_MS = Number(process.env.CONNECT_WAIT_MS || 5000);
const TOOL_RESULT_CAP = 8000; // trim huge tool outputs so one result can't skew the run

// Edit to match the servers you have connected. Keep them single + multi-step so
// the comparison shows both the easy win and the round-trip cost of lazy mode.
const TASKS = [
  { name: "single-email", prompt: "List the subject lines of my 3 most recent emails sent via Resend." },
  { name: "single-projects", prompt: "List my Neon projects (just the names)." },
  { name: "multi-step", prompt: "List my Vercel projects. If a team id is required, find it first, then use it." },
];

function defaultGateway() {
  const exe = process.platform === "win32" ? "conduit-gateway.exe" : "conduit-gateway";
  const release = join(ROOT, "src-tauri", "target", "release", exe);
  const debug = join(ROOT, "src-tauri", "target", "debug", exe);
  if (existsSync(release)) return release;
  if (existsSync(debug)) return debug;
  return release; // report the missing release path in the error
}

// --- minimal MCP-over-stdio client for the gateway ---
class Gateway {
  constructor(discovery) {
    this.proc = spawn(GATEWAY, [], {
      env: { ...process.env, CONDUIT_DISCOVERY: discovery },
      stdio: ["pipe", "pipe", "inherit"],
    });
    this.proc.on("error", (e) => {
      console.error(`\nCould not start gateway at ${GATEWAY}: ${e.message}`);
      console.error("Build it first: npm run build:gateway");
      process.exit(1);
    });
    this.rl = createInterface({ input: this.proc.stdout });
    this.pending = new Map();
    this.id = 0;
    this.rl.on("line", (line) => {
      let msg;
      try { msg = JSON.parse(line); } catch { return; }
      const cb = msg.id != null && this.pending.get(msg.id);
      if (cb) { this.pending.delete(msg.id); cb(msg); }
    });
  }
  rpc(method, params) {
    const id = ++this.id;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  async init() {
    await this.rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "conduit-bench", version: "1" },
    });
    // Give downstream servers time to connect so flat-mode tools/list is populated.
    await new Promise((r) => setTimeout(r, CONNECT_WAIT_MS));
  }
  async tools() {
    const r = await this.rpc("tools/list", {});
    return r.result?.tools || [];
  }
  async call(name, args) {
    const r = await this.rpc("tools/call", { name, arguments: args || {} });
    return r.result ?? r.error ?? {};
  }
  stop() { try { this.proc.kill(); } catch {} }
}

function toOpenAITools(mcpTools) {
  return mcpTools.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description || "",
      parameters: t.inputSchema || { type: "object" },
    },
  }));
}

async function chat(messages, tools) {
  const res = await fetch(LLM_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: MODEL, messages, tools, tool_choice: "auto", temperature: 0 }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`LLM ${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

async function runTask(gw, oaiTools, prompt) {
  const messages = [
    { role: "system", content: "You are a helpful assistant. Use the available tools to complete the task, then give a short final answer." },
    { role: "user", content: prompt },
  ];
  let tokens = 0, calls = 0, steps = 0, done = false, error = null;
  try {
    for (; steps < MAX_STEPS; steps++) {
      const res = await chat(messages, oaiTools);
      tokens += res.usage?.total_tokens || 0;
      const m = res.choices?.[0]?.message;
      if (!m) break;
      messages.push(m);
      const toolCalls = m.tool_calls || [];
      if (toolCalls.length === 0) { done = true; break; } // produced a final answer
      for (const c of toolCalls) {
        calls++;
        let args = {};
        try { args = JSON.parse(c.function.arguments || "{}"); } catch {}
        const result = await gw.call(c.function.name, args);
        messages.push({
          role: "tool",
          tool_call_id: c.id,
          content: JSON.stringify(result).slice(0, TOOL_RESULT_CAP),
        });
      }
    }
  } catch (e) {
    error = e.message; // e.g. flat mode overflowing the model's context window
  }
  const answer = messages.filter((m) => m.role === "assistant" && m.content).pop()?.content || "";
  return { tokens, calls, steps, done, error, answer: answer.slice(0, 200) };
}

async function benchMode(discovery) {
  const gw = new Gateway(discovery);
  await gw.init();
  const mcpTools = await gw.tools();
  const oaiTools = toOpenAITools(mcpTools);
  console.log(`\n[${discovery}] gateway exposes ${mcpTools.length} tools`);
  const rows = [];
  for (const task of TASKS) {
    const r = await runTask(gw, oaiTools, task.prompt);
    rows.push({ task: task.name, ...r });
    const status = r.error ? `ERROR (${r.error})` : r.done ? "done" : "incomplete";
    console.log(`  ${task.name.padEnd(16)} ${String(r.tokens).padStart(7)} tok  ${String(r.calls).padStart(2)} calls  ${status}`);
  }
  gw.stop();
  return { toolCount: mcpTools.length, rows };
}

function totals(modeRows) {
  return modeRows.reduce(
    (a, r) => ({ tokens: a.tokens + r.tokens, calls: a.calls + r.calls, done: a.done + (r.done ? 1 : 0) }),
    { tokens: 0, calls: 0, done: 0 }
  );
}

(async () => {
  console.log(`gateway: ${GATEWAY}`);

  // TOOLS_ONLY: just report how many tools each mode exposes (no LLM needed).
  // The headline number on its own ("N tools collapse to 3"), and a quick check
  // that the gateway handshake works before you spend a full benchmark run.
  if (process.env.TOOLS_ONLY) {
    for (const mode of ["full", "lazy"]) {
      const gw = new Gateway(mode);
      await gw.init();
      const tools = await gw.tools();
      console.log(`[${mode}] exposes ${tools.length} tools`);
      gw.stop();
    }
    process.exit(0);
  }

  console.log(`llm:     ${MODEL} @ ${LLM_URL}`);

  const flat = await benchMode("full");
  const lazy = await benchMode("lazy");

  const tf = totals(flat.rows), tl = totals(lazy.rows);
  const pct = tf.tokens ? Math.round((1 - tl.tokens / tf.tokens) * 100) : 0;

  console.log("\n=== summary ===");
  console.log(`tools exposed:   flat ${flat.toolCount}   lazy ${lazy.toolCount}`);
  console.log(`total tokens:    flat ${tf.tokens}   lazy ${tl.tokens}   (${pct >= 0 ? "-" : "+"}${Math.abs(pct)}%)`);
  console.log(`total toolcalls: flat ${tf.calls}   lazy ${tl.calls}   (lazy trades extra search calls for fewer tokens)`);
  console.log(`tasks completed: flat ${tf.done}/${TASKS.length}   lazy ${tl.done}/${TASKS.length}`);
  console.log("\nNote: token counts come from your LLM's usage field; success is whether the");
  console.log("agent produced a final answer (eyeball the answers for correctness). Small n,");
  console.log("run it a few times - treat the direction as the signal, not the exact number.");
})();
