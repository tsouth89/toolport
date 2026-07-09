import { describe, it, expect } from "vitest";
import { isDownloadLauncher } from "./launcher";

describe("isDownloadLauncher", () => {
  it("matches the bare launchers", () => {
    for (const cmd of ["npx", "uvx", "bunx"]) {
      expect(isDownloadLauncher(cmd, ["-y", "@scope/pkg"]), cmd).toBe(true);
    }
  });

  it("matches launchers behind absolute paths and Windows shims", () => {
    expect(isDownloadLauncher("/usr/local/bin/npx", ["-y", "pkg"])).toBe(true);
    expect(isDownloadLauncher("C:\\Program Files\\nodejs\\npx.cmd", ["pkg"])).toBe(true);
    expect(isDownloadLauncher("NPX.EXE", ["pkg"])).toBe(true);
  });

  it("matches package managers only in their download-then-run form", () => {
    expect(isDownloadLauncher("pnpm", ["dlx", "some-mcp"])).toBe(true);
    expect(isDownloadLauncher("yarn", ["dlx", "some-mcp"])).toBe(true);
    expect(isDownloadLauncher("npm", ["exec", "some-mcp"])).toBe(true);
    expect(isDownloadLauncher("npm", ["x", "some-mcp"])).toBe(true);
    expect(isDownloadLauncher("pipx", ["run", "some-mcp"])).toBe(true);

    expect(isDownloadLauncher("pnpm", ["run", "start"])).toBe(false);
    expect(isDownloadLauncher("yarn", ["start"])).toBe(false);
    expect(isDownloadLauncher("npm", ["start"])).toBe(false);
    expect(isDownloadLauncher("pipx", [])).toBe(false);
  });

  it("normalizes a packed command string like the backend spawn path", () => {
    expect(isDownloadLauncher("npx -y @scope/pkg", [])).toBe(true);
    expect(isDownloadLauncher("pnpm dlx some-mcp", [])).toBe(true);
    // A real path with spaces is not split, so it stays a non-launcher.
    expect(isDownloadLauncher("/opt/my tools/server --stdio", [])).toBe(false);
  });

  it("leaves ordinary commands alone", () => {
    expect(isDownloadLauncher(null, [])).toBe(false);
    expect(isDownloadLauncher("node", ["server.js"])).toBe(false);
    expect(isDownloadLauncher("python", ["-m", "some_mcp"])).toBe(false);
    expect(isDownloadLauncher("docker", ["run", "npx"])).toBe(false);
    expect(isDownloadLauncher("/opt/npx-tools/server", [])).toBe(false);
  });
});
