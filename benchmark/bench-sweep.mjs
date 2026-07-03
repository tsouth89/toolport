#!/usr/bin/env node
// Toolport token benchmark, swept across catalog size.
//
// Answers the question the static token-cost.mjs can't: as you ENABLE MORE
// SERVERS, what happens to the *end-to-end* agent loop, in both modes, on the
// SAME tasks? The hypothesis the marketing rests on:
//
//   - lazy stays roughly FLAT in tokens regardless of catalog size (it only
//     searches for the 2-3 tools a task needs), and keeps completing.
//   - flat grows LINEARLY and eventually overflows the model's context and
//     starts FAILING tasks.
//
// For each (server-count x mode x RUNS passes) it records total tokens (median +
// range), tool calls, completion, and the deterministic tool-def overhead, then
// writes a console table, results.csv, and a markdown summary for BENCHMARK.md / the site.
//
// It NEVER touches your real config: each pass writes a temp registry (copying
// your real server definitions verbatim, so keychain secrets still resolve by id)
// and points the gateway at it via CONDUIT_REGISTRY.
//
// Prereqs:
//   1. Build the gateway:   npm run build:gateway
//   2. Auth the servers used by TASKS + the "noise" servers in Toolport (one-time).
//   3. Run a local OpenAI-compatible LLM (LM Studio :1234 or Ollama :11434).
//
// Run:
//   node benchmark/bench-sweep.mjs
//   RUNS=10 MODEL="qwen2.5-7b-instruct" node benchmark/bench-sweep.mjs
//   COUNTS="3,6,10,15" node benchmark/bench-sweep.mjs
//   LLM_URL="http://localhost:11434/v1/chat/completions" MODEL="qwen2.5:7b" node benchmark/bench-sweep.mjs

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import {
  existsSync,
  readFileSync,
  writeFileSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { homedir, platform, tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const LLM_URL = process.env.LLM_URL || "http://localhost:1234/v1/chat/completions";
const MODEL = process.env.MODEL || "local-model";
// Optional bearer key for cloud/OpenAI-compatible endpoints (OpenAI, OpenRouter,
// etc.). Local servers (LM Studio/Ollama) ignore it; leave unset for those.
const LLM_API_KEY = process.env.LLM_API_KEY || "";
const GATEWAY = process.env.GATEWAY || defaultGateway();
const RUNS = Number(process.env.RUNS || 10);
const MAX_STEPS = Number(process.env.MAX_STEPS || 12);
const CONNECT_WAIT_MS = Number(process.env.CONNECT_WAIT_MS || 6000);
const TOOL_RESULT_CAP = 8000;
const OUT_DIR = process.env.OUT_DIR || HERE;

// Tasks and the server id each one needs. Those servers are ALWAYS enabled in
// every sweep step, so the task stays answerable while the catalog grows around
// it. Edit ids to match your registry (run with no model to see your server ids).
// `expect`: ground-truth strings a CORRECT answer must contain. Kept OUT of this
// committed file (they're real account data); they're loaded at runtime from the
// gitignored benchmark/expect.local.json if present (see expect.local.example.json).
// A run counts as correct only if the agent's final answer contains every expected
// string, so "done" can't hide a wrong or "I couldn't do it" answer. No local file =
// tasks run ungraded (correct shows as n/a).
const TASKS = [
  {
    name: "stripe-products",
    required: "stripe",
    expect: [],
    prompt: "List my Stripe products (just the names).",
  },
  {
    name: "neon-projects",
    required: "neon",
    expect: [],
    prompt: "List my Neon projects (just the names).",
  },
  {
    name: "vercel-projects",
    required: "vercel",
    expect: [],
    prompt:
      "List my Vercel projects. If a team id is required, find it first, then use it.",
  },
];

// Fill `expect` from the local, gitignored ground-truth file if it exists.
try {
  const local = JSON.parse(readFileSync(join(HERE, "expect.local.json"), "utf8"));
  for (const t of TASKS) if (Array.isArray(local[t.name])) t.expect = local[t.name];
} catch {
  // No expect.local.json; tasks run ungraded.
}

function defaultGateway() {
  const exe = process.platform === "win32" ? "toolport-gateway.exe" : "toolport-gateway";
  const release = join(ROOT, "src-tauri", "target", "release", exe);
  const debug = join(ROOT, "src-tauri", "target", "debug", exe);
  if (existsSync(release)) return release;
  if (existsSync(debug)) return debug;
  return release;
}

function conduitDir() {
  if (platform() === "win32") return join(homedir(), "AppData", "Roaming", "Conduit");
  if (platform() === "darwin")
    return join(homedir(), "Library", "Application Support", "Conduit");
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "Conduit");
}

function loadRealRegistry() {
  const p = process.env.CONDUIT_REGISTRY || join(conduitDir(), "registry.json");
  if (!existsSync(p)) {
    console.error(`No registry at ${p}. Set CONDUIT_REGISTRY or run Toolport once.`);
    process.exit(1);
  }
  return { path: p, reg: JSON.parse(readFileSync(p, "utf8")) };
}

// Build the ordered list of server counts to test. Required servers are always
// in; "noise" is drawn from the rest of the servers enabled in the real active
// profile (so they're already authed). conduit's own gateway entry is excluded.
function planSweep(reg) {
  const required = [...new Set(TASKS.map((t) => t.required))];
  const active = reg.profiles?.find((p) => p.id === reg.activeProfileId);
  const enabled = new Set(active?.enabledServerIds || []);
  const noise = (reg.servers || [])
    .map((s) => s.id)
    .filter((id) => id !== "conduit" && !required.includes(id) && enabled.has(id));

  const want = (process.env.COUNTS || "")
    .split(",")
    .map((x) => Number(x.trim()))
    .filter((n) => Number.isFinite(n) && n > 0);
  const maxN = required.length + noise.length;
  const counts = (
    want.length ? want : [required.length, required.length + 3, required.length + 7, maxN]
  )
    .map((n) => Math.min(maxN, Math.max(required.length, n)))
    .filter((n, i, a) => a.indexOf(n) === i)
    .sort((a, b) => a - b);

  return counts.map((n) => ({
    count: n,
    serverIds: [...required, ...noise.slice(0, n - required.length)],
  }));
}

// Write a temp registry enabling exactly `serverIds`, copying server defs verbatim
// so transports/commands/auth (keyed by server id in the keychain) still resolve.
function writeTempRegistry(dir, reg, serverIds, lazy) {
  const path = join(dir, `registry-${serverIds.length}-${lazy ? "lazy" : "full"}.json`);
  const out = {
    ...reg,
    profiles: [{ id: "sweep", name: "Sweep", enabledServerIds: serverIds }],
    activeProfileId: "sweep",
    lazyDiscovery: lazy,
  };
  writeFileSync(path, JSON.stringify(out));
  return path;
}

// --- minimal MCP-over-stdio client (same protocol as bench.js) ---
class Gateway {
  constructor(regPath, discovery) {
    this.proc = spawn(GATEWAY, [], {
      env: {
        ...process.env,
        CONDUIT_REGISTRY: regPath,
        CONDUIT_PROFILE: "sweep",
        CONDUIT_DISCOVERY: discovery,
      },
      stdio: ["pipe", "pipe", "ignore"],
    });
    this.proc.on("error", (e) => {
      console.error(
        `\nCould not start gateway at ${GATEWAY}: ${e.message}\nBuild it: npm run build:gateway`,
      );
      process.exit(1);
    });
    this.rl = createInterface({ input: this.proc.stdout });
    this.pending = new Map();
    this.id = 0;
    this.rl.on("line", (line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      const cb = msg.id != null && this.pending.get(msg.id);
      if (cb) {
        this.pending.delete(msg.id);
        cb(msg);
      }
    });
  }
  rpc(method, params) {
    const id = ++this.id;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.proc.stdin.write(
        JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n",
      );
    });
  }
  async init() {
    await this.rpc("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "conduit-sweep", version: "1" },
    });
    await new Promise((r) => setTimeout(r, CONNECT_WAIT_MS));
  }
  async tools() {
    return (await this.rpc("tools/list", {})).result?.tools || [];
  }
  async call(name, args) {
    const r = await this.rpc("tools/call", { name, arguments: args || {} });
    return r.result ?? r.error ?? {};
  }
  stop() {
    try {
      this.proc.kill();
    } catch {}
  }
}

function normalizeParams(schema) {
  const s =
    schema && typeof schema === "object" && !Array.isArray(schema) ? { ...schema } : {};
  if (!s.type) s.type = "object";
  if (s.type === "object" && (s.properties == null || typeof s.properties !== "object"))
    s.properties = {};
  return s;
}
const toOpenAITools = (mcp) =>
  mcp.map((t) => ({
    type: "function",
    function: {
      name: t.name,
      description: t.description || "",
      parameters: normalizeParams(t.inputSchema),
    },
  }));

async function chat(messages, tools) {
  const headers = {
    "Content-Type": "application/json",
    ...(LLM_API_KEY ? { Authorization: `Bearer ${LLM_API_KEY}` } : {}),
  };
  // Retry rate limits (429) and transient 5xx with backoff, so free-tier limits
  // slow the run down instead of corrupting it. Honors Retry-After when present.
  //
  // Cache-busting is OPT-IN (BENCH_NOCACHE=1). Provider prompt caching does NOT
  // change the reported token counts (we read full `usage`) and never returns a
  // stale completion (it's recomputed at temperature 0), so leaving it on just
  // makes a token-heavy flat run much cheaper. Set BENCH_NOCACHE=1 only if you want
  // to force fully independent samples (e.g. for variance analysis).
  const noCache = ["1", "true", "yes", "on"].includes(
    (process.env.BENCH_NOCACHE || "").toLowerCase(),
  );
  let res;
  for (let attempt = 0; ; attempt++) {
    const msgs =
      noCache && messages[0]?.role === "system"
        ? [
            {
              ...messages[0],
              content: `${messages[0].content}\n[uncached: ${randomUUID()}]`,
            },
            ...messages.slice(1),
          ]
        : messages;
    const body = JSON.stringify({
      model: MODEL,
      messages: msgs,
      tools,
      tool_choice: "auto",
      temperature: 0,
    });
    res = await fetch(LLM_URL, { method: "POST", headers, body });
    if (res.ok) break;
    if ((res.status === 429 || res.status >= 500) && attempt < 6) {
      const ra = Number(res.headers.get("retry-after"));
      const waitMs =
        Number.isFinite(ra) && ra > 0 ? ra * 1000 : Math.min(30000, 1000 * 2 ** attempt);
      await new Promise((r) => setTimeout(r, waitMs));
      continue;
    }
    break;
  }
  if (!res.ok)
    throw new Error(
      `LLM ${res.status}: ${(await res.text().catch(() => "")).slice(0, 300)}`,
    );
  return res.json();
}

// Deterministic: tokens EVERY request pays just to describe the tools.
async function measureOverhead(tools) {
  try {
    const res = await chat([{ role: "user", content: "hi" }], tools);
    return { tokens: res.usage?.prompt_tokens ?? null, overflow: false };
  } catch (e) {
    const m = /n_keep:\s*(\d+)/.exec(e.message);
    return { tokens: m ? Number(m[1]) : null, overflow: true };
  }
}

async function runTask(gw, oaiTools, prompt) {
  const messages = [
    {
      role: "system",
      content:
        "You are a helpful assistant. Use the available tools to complete the task, then give a short final answer.",
    },
    { role: "user", content: prompt },
  ];
  let tokens = 0,
    calls = 0,
    done = false,
    error = null;
  try {
    for (let steps = 0; steps < MAX_STEPS; steps++) {
      const res = await chat(messages, oaiTools);
      tokens += res.usage?.total_tokens || 0;
      const m = res.choices?.[0]?.message;
      if (!m) break;
      messages.push(m);
      const toolCalls = m.tool_calls || [];
      if (toolCalls.length === 0) {
        done = true;
        break;
      }
      for (const c of toolCalls) {
        calls++;
        let args = {};
        try {
          args = JSON.parse(c.function.arguments || "{}");
        } catch {}
        const result = await gw.call(c.function.name, args);
        messages.push({
          role: "tool",
          tool_call_id: c.id,
          content: JSON.stringify(result).slice(0, TOOL_RESULT_CAP),
        });
      }
    }
  } catch (e) {
    error = e.message;
  }
  const answer =
    messages
      .filter(
        (m) =>
          m.role === "assistant" && typeof m.content === "string" && m.content.trim(),
      )
      .pop()?.content || "";
  return { tokens, calls, done, error, answer };
}

const median = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor((s.length - 1) / 2)];
};

// An answer that looks like a failure/apology rather than a result. Used so a
// "done" agent that gave up ("I couldn't list them") never counts as correct.
const ERROR_LIKE =
  /\b(error|failed|unable|couldn'?t|can ?not|can'?t|unauthor|forbidden|denied|no access|not authenticated|don'?t have)\b/i;

// Grade a single answer against the task's ground-truth `expect` list:
//   true/false when graded, null when the task has no `expect` (ungraded).
// Correct requires the answer to NOT look like a failure AND to contain every
// expected string (case-insensitive). Strict on purpose: short list tasks.
function gradeAnswer(answer, expect) {
  if (!expect || expect.length === 0) return null;
  if (!answer || ERROR_LIKE.test(answer)) return false;
  const a = answer.toLowerCase();
  return expect.every((e) => a.includes(String(e).toLowerCase()));
}

async function benchAt(regPath, count, serverIds, mode) {
  const gw = new Gateway(regPath, mode);
  await gw.init();
  const mcpTools = await gw.tools();
  const oaiTools = toOpenAITools(mcpTools);
  const overhead = await measureOverhead(oaiTools);
  const tasks = [];
  for (const task of TASKS) {
    const trials = [];
    for (let i = 0; i < RUNS; i++) trials.push(await runTask(gw, oaiTools, task.prompt));
    const toks = trials.map((t) => t.tokens);
    const graded = Array.isArray(task.expect) && task.expect.length > 0;
    const correct = graded
      ? trials.filter((t) => gradeAnswer(t.answer, task.expect) === true).length
      : null;
    tasks.push({
      task: task.name,
      median: median(toks),
      lo: Math.min(...toks),
      hi: Math.max(...toks),
      done: trials.filter((t) => t.done).length,
      graded,
      correct,
      err: trials.find((t) => t.error)?.error || null,
      // Keep two sample answers per task for human audit.
      samples: trials.slice(0, 2).map((t) => (t.answer || "").slice(0, 300)),
    });
  }
  gw.stop();
  await new Promise((r) => setTimeout(r, 500)); // let it die before the next spawn
  return { mode, count, toolCount: mcpTools.length, overhead, tasks };
}

(async () => {
  console.log(`gateway: ${GATEWAY}`);
  console.log(`llm:     ${MODEL} @ ${LLM_URL}`);
  console.log(`runs:    ${RUNS} per task per (mode x server-count)\n`);

  const { reg } = loadRealRegistry();
  const sweep = planSweep(reg);
  console.log("sweep plan (servers always include the task servers):");
  for (const s of sweep)
    console.log(`  ${String(s.count).padStart(2)} servers: ${s.serverIds.join(", ")}`);

  const dir = mkdtempSync(join(tmpdir(), "conduit-sweep-"));
  const results = [];
  let prevFullTools = 0; // to catch servers that silently failed to connect
  try {
    for (const step of sweep) {
      for (const mode of ["full", "lazy"]) {
        const regPath = writeTempRegistry(dir, reg, step.serverIds, mode === "lazy");
        process.stdout.write(`\n[${step.count} servers / ${mode}] connecting...`);
        const r = await benchAt(regPath, step.count, step.serverIds, mode);
        const ovf = r.overhead.overflow ? " (OVERFLOWS)" : "";
        const totalTok = r.tasks.reduce((a, t) => a + (t.median || 0), 0);
        const totalDone = r.tasks.reduce((a, t) => a + t.done, 0);
        const denom = TASKS.length * RUNS;
        const isGraded = r.tasks.some((t) => t.graded);
        const totalCorrect = r.tasks.reduce((a, t) => a + (t.correct ?? 0), 0);
        const correctStr = isGraded
          ? `, ${totalCorrect}/${denom} correct`
          : ", correct n/a (set `expect`)";
        console.log(
          ` ${r.toolCount} tools, overhead ${r.overhead.tokens ?? "?"}${ovf}, total median ${totalTok} tok, ${totalDone}/${denom} done${correctStr}`,
        );
        // A larger server set that exposes no more tools than a smaller one means
        // some servers never connected/listed in time (the catalog is incomplete,
        // so this step's numbers are not comparable). Flag it loudly.
        if (mode === "full") {
          if (r.toolCount <= prevFullTools) {
            console.log(
              `  ! WARNING: ${step.count} servers exposed only ${r.toolCount} tools ` +
                `(<= the previous step's ${prevFullTools}). Some servers did not connect in time. ` +
                `Raise CONNECT_WAIT_MS (currently ${CONNECT_WAIT_MS}) and re-run this step; this row is unreliable.`,
            );
          }
          prevFullTools = Math.max(prevFullTools, r.toolCount);
        }
        results.push(r);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }

  // Ensure the output directory exists (it may be a fresh OUT_DIR).
  mkdirSync(OUT_DIR, { recursive: true });

  // --- CSV (one row per server-count x mode x task) ---
  const csv = [
    "servers,mode,toolCount,overheadTokens,overflow,task,medianTokens,loTokens,hiTokens,done,correct,graded,runs",
  ];
  for (const r of results)
    for (const t of r.tasks)
      csv.push(
        [
          r.count,
          r.mode,
          r.toolCount,
          r.overhead.tokens ?? "",
          r.overhead.overflow,
          t.task,
          t.median,
          t.lo,
          t.hi,
          t.done,
          t.correct ?? "",
          t.graded,
          RUNS,
        ].join(","),
      );
  const csvPath = join(OUT_DIR, "sweep-results.csv");
  writeFileSync(csvPath, csv.join("\n") + "\n");

  // --- answers log (human audit: did "done" actually produce the right answer?) ---
  const ans = [`# Sample agent answers (${MODEL}), for correctness audit`, ""];
  for (const r of results) {
    for (const t of r.tasks) {
      const grade = t.graded ? ` [${t.correct}/${RUNS} correct]` : " [ungraded]";
      ans.push(`## ${r.count} servers / ${r.mode} / ${t.task}${grade}`);
      if (!t.samples.some((s) => s)) ans.push("(no answer, e.g. context overflow)");
      t.samples.forEach(
        (s, i) => s && ans.push(`  sample ${i + 1}: ${s.replace(/\s+/g, " ")}`),
      );
      ans.push("");
    }
  }
  const ansPath = join(OUT_DIR, "answers.txt");
  writeFileSync(ansPath, ans.join("\n") + "\n");

  // --- markdown summary (per server-count, flat vs lazy totals) ---
  const byCount = new Map();
  for (const r of results) {
    const o = byCount.get(r.count) || { count: r.count };
    const totalTok = r.tasks.reduce((a, t) => a + (t.median || 0), 0);
    const totalDone = r.tasks.reduce((a, t) => a + t.done, 0);
    const graded = r.tasks.some((t) => t.graded);
    const totalCorrect = r.tasks.reduce((a, t) => a + (t.correct ?? 0), 0);
    o[r.mode] = {
      tools: r.toolCount,
      overhead: r.overhead,
      totalTok,
      totalDone,
      totalCorrect,
      graded,
    };
    byCount.set(r.count, o);
  }
  const denom = TASKS.length * RUNS;
  // Only show the correctness columns if at least one task was graded (expect set).
  const anyGraded = results.some((r) => r.tasks.some((t) => t.graded));
  const cScore = (m) => (m ? (m.graded ? `${m.totalCorrect}/${denom}` : "n/a") : "—");
  const md = [
    `## Token cost vs. catalog size (median of ${RUNS} runs/task, ${MODEL})`,
    "",
    `| Servers | Flat overhead/req | Lazy overhead/req | Flat total tokens | Lazy total tokens | Reduction | Flat done | Lazy done |${anyGraded ? " Flat correct | Lazy correct |" : ""}`,
    `|---|---|---|---|---|---|---|---|${anyGraded ? "---|---|" : ""}`,
  ];
  for (const o of [...byCount.values()].sort((a, b) => a.count - b.count)) {
    const f = o.full,
      l = o.lazy;
    const fOv = f?.overhead.overflow ? "OVERFLOW" : (f?.overhead.tokens ?? "?");
    const red =
      f?.totalTok && l?.totalTok
        ? `${Math.round((1 - l.totalTok / f.totalTok) * 100)}%`
        : "—";
    const correctCols = anyGraded ? ` ${cScore(f)} | ${cScore(l)} |` : "";
    md.push(
      `| ${o.count} (${f?.tools ?? "?"} tools) | ${fOv} | ${l?.overhead.tokens ?? "?"} | ${f?.totalTok ?? "—"} | ${l?.totalTok ?? "—"} | ${red} | ${f?.totalDone ?? 0}/${denom} | ${l?.totalDone ?? 0}/${denom} |${correctCols}`,
    );
  }
  const mdPath = join(OUT_DIR, "sweep-summary.md");
  writeFileSync(mdPath, md.join("\n") + "\n");

  console.log(`\nWrote ${csvPath}`);
  console.log(`Wrote ${mdPath}`);
  console.log(`Wrote ${ansPath}`);
  console.log("\n" + md.join("\n"));
})();
