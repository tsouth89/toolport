#!/usr/bin/env node
// Measures the per-request token cost of a real MCP tool catalog: the tool
// definitions an agent loads into context on every request without lazy
// discovery, broken down by server, plus the savings from Conduit's 3-meta-tool
// lazy mode and the dollar cost at current model input prices.
//
// Usage:
//   node token-cost.mjs <path-to-tool-cache.json> [lazyFloorTokens]
//
// The tool cache is the aggregated catalog Conduit builds (an array of tool
// objects with namespaced `server__tool` names). The token estimate mirrors the
// gateway's own: serialized JSON length / 4.

import { readFileSync } from "node:fs";

const path = process.argv[2];
const LAZY_FLOOR = Number(process.argv[3] || 660); // 3 meta-tools, measured
if (!path) {
  console.error("usage: node token-cost.mjs <tool-cache.json> [lazyFloorTokens]");
  process.exit(1);
}

const tools = JSON.parse(readFileSync(path, "utf8"));
const est = (obj) => Math.ceil(JSON.stringify(obj).length / 4);
const fmt = (n) => Math.round(n).toLocaleString("en-US");

const byServer = new Map();
let total = 0;
for (const t of tools) {
  const tok = est(t);
  total += tok;
  const server = String(t.name || "").split("__")[0] || "(unknown)";
  const s = byServer.get(server) || { tools: 0, tokens: 0 };
  s.tools += 1;
  s.tokens += tok;
  byServer.set(server, s);
}

const rows = [...byServer.entries()]
  .map(([server, s]) => ({ server, ...s }))
  .sort((a, b) => b.tokens - a.tokens);

const reduction = ((1 - LAZY_FLOOR / total) * 100).toFixed(1);
const saved = total - LAZY_FLOOR;

// Input-token list prices ($/1M), current as of June 2026.
const PRICES = [
  ["Claude Sonnet ($3/M)", 3],
  ["Claude Opus ($5/M)", 5],
  ["GPT-5.4 ($2.50/M)", 2.5],
  ["Gemini 2.5 Pro ($1.25/M)", 1.25],
];

console.log(
  `\nMCP tool-catalog token cost: ${tools.length} tools across ${byServer.size} servers\n`,
);
console.log("Per server (definition tokens loaded on every request):");
for (const r of rows) {
  console.log(
    `  ${r.server.padEnd(24)} ${String(r.tools).padStart(4)} tools  ${fmt(r.tokens).padStart(9)} tokens`,
  );
}
console.log("");
console.log(`Without Conduit:  ${fmt(total)} tokens / request`);
console.log(`With Conduit:     ${fmt(LAZY_FLOOR)} tokens / request (3 meta-tools, flat)`);
console.log(`Reduction:        ${reduction}%`);
console.log("");
console.log("Monthly savings at 200 agent requests/day:");
for (const [label, price] of PRICES) {
  const monthly = (saved / 1e6) * price * 200 * 30;
  console.log(`  ${label.padEnd(26)} $${fmt(monthly)}/month`);
}
console.log("");
