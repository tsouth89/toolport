#!/usr/bin/env node
// Measures the latency Toolport's gateway adds, in milliseconds.
//
// Spawns the gateway against the mock downstream (instant responses) so we isolate
// Toolport's OWN overhead, then times the handshake and the steady-state per-call
// round-trip for the lazy meta-tools over N iterations (median + p95). Also calls
// the mock directly, so the difference on the tool-call path is purely what Toolport
// adds. Deterministic and offline: no model, no network, no API keys.
//
//   node benchmark/latency.mjs [iterations]      (default 200)
//
// Needs a debug build first:
//   cargo build --manifest-path src-tauri/Cargo.toml --bins

import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEBUG = join(__dirname, "..", "src-tauri", "target", "debug");
const exe = (n) => join(DEBUG, process.platform === "win32" ? `${n}.exe` : n);
const GATEWAY = exe("toolport-gateway");
const MOCK = exe("mock-mcp-server");
const N = Math.max(20, Number(process.argv[2] || 200));

for (const [label, p] of [
  ["gateway", GATEWAY],
  ["mock server", MOCK],
]) {
  if (!existsSync(p)) {
    console.error(
      `Missing ${label} at ${p}\nBuild it first:\n  cargo build --manifest-path src-tauri/Cargo.toml --bins`,
    );
    process.exit(1);
  }
}

const now = () => Number(process.hrtime.bigint()) / 1e6;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const stats = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const at = (q) => s[Math.min(s.length - 1, Math.floor(s.length * q))];
  return { median: at(0.5), p95: at(0.95), min: s[0], max: s[s.length - 1] };
};

// Minimal line-delimited JSON-RPC client over a child's stdio.
function client(proc) {
  const pending = new Map();
  let buf = "";
  proc.stdout.on("data", (d) => {
    buf += d.toString();
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        continue;
      }
      if (m.id != null && pending.has(m.id)) {
        pending.get(m.id)(m);
        pending.delete(m.id);
      }
    }
  });
  let id = 0;
  return {
    call: (method, params) =>
      new Promise((res) => {
        const myId = ++id;
        pending.set(myId, res);
        proc.stdin.write(
          JSON.stringify({ jsonrpc: "2.0", id: myId, method, params }) + "\n",
        );
      }),
    notify: (method, params) =>
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n"),
  };
}

const timed = async (fn) => {
  const t = now();
  await fn();
  return now() - t;
};
const loop = async (fn, n) => {
  const xs = [];
  for (let k = 0; k < n; k++) xs.push(await timed(fn));
  return stats(xs);
};

const INIT = {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "bench", version: "0" },
};

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "conduit-lat-"));
  const regPath = join(dir, "registry.json");
  writeFileSync(
    regPath,
    JSON.stringify({
      version: 1,
      servers: [
        {
          id: "mock",
          name: "Mock",
          transport: "stdio",
          command: MOCK,
          args: [],
          env: [],
        },
      ],
      profiles: [{ id: "bench", name: "Bench", enabledServerIds: ["mock"] }],
      activeProfileId: "bench",
      lazyDiscovery: true,
    }),
  );

  // 1) The mock directly: discover a tool name and measure the bare call latency.
  const mk = spawn(MOCK, [], { stdio: ["pipe", "pipe", "ignore"] });
  const m = client(mk);
  await m.call("initialize", INIT);
  m.notify("notifications/initialized");
  await sleep(200);
  const tools = (await m.call("tools/list", {})).result?.tools || [];
  if (!tools.length) {
    console.error("mock advertised no tools; cannot benchmark the call path");
    process.exit(1);
  }
  const bare = tools[0].name;
  for (let k = 0; k < 15; k++) await m.call("tools/call", { name: bare, arguments: {} });
  const direct = await loop(() => m.call("tools/call", { name: bare, arguments: {} }), N);

  // 2) Through the gateway.
  const gw = spawn(GATEWAY, [], {
    env: {
      ...process.env,
      CONDUIT_REGISTRY: regPath,
      CONDUIT_PROFILE: "bench",
      CONDUIT_DISCOVERY: "lazy",
    },
    stdio: ["pipe", "pipe", "ignore"],
  });
  const g = client(gw);
  const handshake = await timed(() => g.call("initialize", INIT));
  g.notify("notifications/initialized");
  await sleep(1200); // let the mock connect so the catalog is populated

  for (let k = 0; k < 15; k++) await g.call("tools/list", {}); // warm up
  const list = await loop(() => g.call("tools/list", {}), N);
  const search = await loop(
    () =>
      g.call("tools/call", {
        name: "toolport_search_tools",
        arguments: { query: "a", limit: 25 },
      }),
    N,
  );
  const gwCall = await loop(
    () =>
      g.call("tools/call", {
        name: "toolport_call_tool",
        arguments: { name: `mock__${bare}`, arguments: {} },
      }),
    N,
  );

  mk.stdin.end();
  mk.kill();
  gw.stdin.end();
  gw.kill();
  rmSync(dir, { recursive: true, force: true });

  const row = (label, x) =>
    `  ${label.padEnd(28)}${x.median.toFixed(2).padStart(6)} ms   (p95 ${x.p95.toFixed(2)})`;
  console.log(`\nToolport gateway latency  (mock downstream, ${N} iterations, median)\n`);
  console.log(
    `  ${"handshake (one-time)".padEnd(28)}${handshake.toFixed(2).padStart(6)} ms`,
  );
  console.log(row("tools/list (lazy, 4 core tools)", list));
  console.log(row("toolport_search_tools", search));
  console.log(row("toolport_call_tool -> mock", gwCall));
  console.log(row("mock tool call (direct)", direct));
  const overhead = gwCall.median - direct.median;
  console.log(
    `\n  => Toolport adds ~${overhead.toFixed(2)} ms per tool call vs calling the server directly.`,
  );
  console.log(
    `     Real servers take tens to hundreds of ms each, so that overhead is noise,`,
  );
  console.log(
    `     and it buys ~90% fewer tokens. See BENCHMARK.md for the token numbers.\n`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
