#!/usr/bin/env node
// Retrieval-recall benchmark for lazy discovery.
//
// The token benchmark (bench-sweep.mjs) shows lazy discovery is cheap and works on
// DIRECT lookups. This measures the harder, separate question behind the "the agent
// never misses a tool" claim: when you describe a need in natural language, does
// `toolport_search_tools` actually surface the right tool, and how highly does it
// rank it? That is recall, and it is the thing that, if weak, both hurts accuracy
// AND adds wasted search round-trips (eroding the token win).
//
// No model needed: this drives the gateway's search directly and is deterministic.
// It exercises YOUR connected catalog, so misses reflect your real servers.
//
// Run:
//   npm run build:gateway   (once)
//   node benchmark/retrieval.mjs                      # lexical baseline
//
// A/B with semantic search (needs an OpenAI-compatible /v1/embeddings endpoint,
// e.g. LM Studio with an embedding model loaded). Same harness, env-toggled:
//   $env:CONDUIT_SEMANTIC="on"
//   $env:CONDUIT_EMBED_ENDPOINT="http://localhost:1234/v1/embeddings"
//   $env:CONDUIT_EMBED_MODEL="text-embedding-nomic-embed-text-v1.5"
//   node benchmark/retrieval.mjs
// Compare the recall@5 / MRR between the two runs; that delta is the semantic lift.
//
// Each case lists acceptable tool-name fragments; a case is a "hit" if a tool whose
// name contains one of them appears in the top-k results. A miss on a capability you
// actually have connected is a real retrieval gap, exactly what we want to find.

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CONNECT_WAIT_MS = Number(process.env.CONNECT_WAIT_MS || 12000);
const K = Number(process.env.K || 10); // results to request / rank within

function defaultGateway() {
  const exe = process.platform === "win32" ? "toolport-gateway.exe" : "toolport-gateway";
  const release = join(ROOT, "src-tauri", "target", "release", exe);
  const debug = join(ROOT, "src-tauri", "target", "debug", exe);
  return existsSync(release) ? release : debug;
}
const GATEWAY = process.env.GATEWAY || defaultGateway();

// (need, acceptable tool-name fragments). Mix of direct lookups and paraphrased /
// indirect needs, which is where lexical search is most likely to miss. Edit to
// match the servers you have connected; a case for a capability you don't have will
// just show as a miss (note it).
const CASES = [
  // --- direct (should be easy). Tightened to the actual action tool name so a
  //     loose substring (e.g. any "...project...") can't count as a false hit. ---
  {
    q: "list my stripe products",
    want: ["list_products", "stripe_api_read", "search_stripe_resources"],
    kind: "direct",
  },
  { q: "list my neon projects", want: ["list_projects"], kind: "direct" },
  { q: "list my vercel projects", want: ["list_projects"], kind: "direct" },
  {
    q: "list my github repositories",
    want: ["list_repositor", "search_repositor"],
    kind: "direct",
  },
  // --- paraphrased / indirect (the hard cases) ---
  {
    q: "charge a customer's credit card",
    want: ["payment_intent", "create_charge", "stripe_api_write"],
    kind: "paraphrase",
  },
  {
    q: "who are my paying customers",
    want: ["list_customer", "search_customer", "customer"],
    kind: "paraphrase",
  },
  {
    q: "open a pull request for my branch",
    want: ["create_pull_request", "pull_request"],
    kind: "paraphrase",
  },
  {
    q: "spin up a database branch to test a migration",
    want: ["create_branch", "prepare_database_migration"],
    kind: "paraphrase",
  },
  {
    q: "run a SQL query against my database",
    want: ["run_sql", "execute_sql", "run_query", "execute_postgres"],
    kind: "paraphrase",
  },
  {
    q: "send a welcome email to a new signup",
    want: ["send_email", "send-email", "emails_send"],
    kind: "paraphrase",
  },
  {
    q: "roll back my last deployment",
    want: ["rollback", "redeploy", "promote", "revert"],
    kind: "paraphrase",
  },
  {
    q: "what's my revenue this month",
    want: ["revenue", "overview_metric", "list_metric", "balance"],
    kind: "paraphrase",
  },
  { q: "refund a payment", want: ["refund"], kind: "paraphrase" },
  {
    q: "inspect my supabase database schema",
    want: ["list_tables", "execute_sql", "list_extensions"],
    kind: "paraphrase",
  },
];

// --- minimal MCP-over-stdio client ---
class Gateway {
  constructor() {
    this.proc = spawn(GATEWAY, [], {
      env: { ...process.env, CONDUIT_DISCOVERY: "lazy" },
      stdio: ["pipe", "pipe", "ignore"],
    });
    this.proc.on("error", (e) => {
      console.error(
        `Could not start gateway at ${GATEWAY}: ${e.message}\nBuild it: npm run build:gateway`,
      );
      process.exit(1);
    });
    this.rl = createInterface({ input: this.proc.stdout });
    this.pending = new Map();
    this.id = 0;
    this.rl.on("line", (line) => {
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        return;
      }
      const cb = m.id != null && this.pending.get(m.id);
      if (cb) {
        this.pending.delete(m.id);
        cb(m);
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
      clientInfo: { name: "retrieval-bench", version: "1" },
    });
    await new Promise((r) => setTimeout(r, CONNECT_WAIT_MS));
  }
  async search(query, limit) {
    const r = await this.rpc("tools/call", {
      name: "toolport_search_tools",
      arguments: { query, limit },
    });
    const text = r.result?.content?.[0]?.text ?? "";
    // The result embeds the matches as a JSON-ish block; pull tool names in order.
    return [...text.matchAll(/"name"\s*:\s*"([^"]+)"/g)].map((m) => m[1]);
  }
  stop() {
    try {
      this.proc.kill();
    } catch {}
  }
}

function rankOf(names, want) {
  for (let i = 0; i < names.length; i++) {
    const lower = names[i].toLowerCase();
    if (want.some((w) => lower.includes(w.toLowerCase()))) return i + 1; // 1-based
  }
  return 0; // miss
}

(async () => {
  console.log(`gateway: ${GATEWAY}`);
  const semOn = ["on", "1", "true", "yes"].includes(
    (process.env.CONDUIT_SEMANTIC || "").toLowerCase(),
  );
  console.log(
    semOn
      ? `mode:    SEMANTIC (embed: ${process.env.CONDUIT_EMBED_MODEL || "?"} @ ${process.env.CONDUIT_EMBED_ENDPOINT || "?"})`
      : "mode:    LEXICAL (set CONDUIT_SEMANTIC=on + CONDUIT_EMBED_ENDPOINT/MODEL for semantic)",
  );
  console.log(`retrieval recall over ${CASES.length} cases, top-${K}\n`);
  const gw = new Gateway();
  await gw.init();

  const rows = [];
  for (const c of CASES) {
    const names = await gw.search(c.q, K);
    const rank = rankOf(names, c.want);
    rows.push({ ...c, rank, top: names.slice(0, 3) });
    const status = rank === 0 ? "MISS" : `#${rank}`;
    console.log(`  [${c.kind.padEnd(10)}] ${status.padStart(5)}  ${c.q}`);
    if (rank === 0)
      console.log(`           top results: ${names.slice(0, 5).join(", ") || "(none)"}`);
  }
  gw.stop();

  const hit1 = rows.filter((r) => r.rank === 1).length;
  const hit5 = rows.filter((r) => r.rank > 0 && r.rank <= 5).length;
  const mrr = rows.reduce((a, r) => a + (r.rank > 0 ? 1 / r.rank : 0), 0) / rows.length;
  const byKind = (k) => rows.filter((r) => r.kind === k);
  const recall5 = (rs) =>
    rs.length
      ? `${rs.filter((r) => r.rank > 0 && r.rank <= 5).length}/${rs.length}`
      : "0/0";

  console.log("\n=== summary ===");
  console.log(`recall@1:  ${hit1}/${rows.length}`);
  console.log(`recall@5:  ${hit5}/${rows.length}`);
  console.log(`MRR:       ${mrr.toFixed(3)}`);
  console.log(`  direct cases    recall@5: ${recall5(byKind("direct"))}`);
  console.log(`  paraphrase cases recall@5: ${recall5(byKind("paraphrase"))}`);
  const misses = rows.filter((r) => r.rank === 0);
  if (misses.length) {
    console.log(
      `\nmisses (${misses.length}) — a real gap if you have the capability connected:`,
    );
    for (const m of misses)
      console.log(`  - "${m.q}"  (wanted name containing: ${m.want.join(" / ")})`);
  }
  console.log(
    "\nParaphrase recall is the number that backs (or breaks) the 'never misses a tool'",
  );
  console.log(
    "claim. If it's low, that's the case for semantic search; see docs/specs/semantic-search.md.",
  );
})();
