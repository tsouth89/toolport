// Build the toolport-gateway binary and stage it where Tauri's `externalBin`
// bundler expects it: `src-tauri/binaries/toolport-gateway-<target-triple><ext>`.
// Runs as part of `beforeBuildCommand`, so a packaged app always ships a gateway
// matching the target.
//
// By default it builds for the host triple. Set CONDUIT_SIDECAR_TARGET to a target
// triple (e.g. "x86_64-apple-darwin") to cross-build the gateway for that target.
// Pass `--debug` to stage a debug build instead.
import { execSync } from "node:child_process";
import {
  mkdirSync,
  copyFileSync,
  existsSync,
  writeFileSync,
  chmodSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";

function hostTriple() {
  const out = execSync("rustc -vV", { encoding: "utf8" });
  const line = out.split("\n").find((l) => l.startsWith("host:"));
  if (!line) throw new Error("could not determine host target triple from `rustc -vV`");
  return line.split(":")[1].trim();
}

const debug = process.argv.includes("--debug");
const profile = debug ? "debug" : "release";
const ext = process.platform === "win32" ? ".exe" : "";
const requested = process.env.CONDUIT_SIDECAR_TARGET || "";

const destDir = join("src-tauri", "binaries");
mkdirSync(destDir, { recursive: true });

function gatewayPathFor(triple) {
  const sub = triple ? join(triple, profile) : profile;
  return join("src-tauri", "target", sub, `toolport-gateway${ext}`);
}

function buildGateway(triple) {
  const targetArg = triple ? `--target ${triple} ` : "";
  console.log(
    `[sidecar] building toolport-gateway (${profile}) ${triple ? "for " + triple : "(host)"}`,
  );
  execSync(`cargo build ${debug ? "" : "--release "}${targetArg}--bin toolport-gateway`, {
    cwd: "src-tauri",
    stdio: "inherit",
  });
  const src = gatewayPathFor(triple);
  if (!existsSync(src)) throw new Error(`built gateway not found at ${src}`);
  return src;
}

// The staged file must carry the triple Tauri will look for at bundle time.
const stagedTriple = requested || hostTriple();
const dest = join(destDir, `toolport-gateway-${stagedTriple}${ext}`);

// Break the chicken-and-egg: the gateway's own build (via the shared build.rs ->
// tauri_build) validates this externalBin path exists at compile time. Seed a
// placeholder so that check passes; we overwrite it with the real binary below.
if (!existsSync(dest)) {
  writeFileSync(dest, "");
}

try {
  const src = buildGateway(requested || undefined);
  copyFileSync(src, dest);
} catch (e) {
  // Don't leave the empty placeholder behind - it would ship as a 0-byte gateway.
  rmSync(dest, { force: true });
  throw e;
}

// On macOS/Linux the bundled sidecar must be executable.
if (process.platform !== "win32") {
  chmodSync(dest, 0o755);
}
console.log(`[sidecar] staged -> ${dest}`);
