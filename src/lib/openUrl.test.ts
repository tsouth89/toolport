import { describe, it, expect, vi, beforeEach } from "vitest";

const openUrl = vi.fn(async () => {});

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: (...args: unknown[]) => openUrl(...args),
}));

// Import after mock so the module binds to the mock.
const { openExternal } = await import("./openUrl");

describe("openExternal", () => {
  beforeEach(() => {
    openUrl.mockClear();
  });

  it("allows http and https URLs through to the opener", async () => {
    await openExternal("https://example.com/docs");
    await openExternal("http://localhost:3000");
    expect(openUrl).toHaveBeenCalledWith("https://example.com/docs");
    expect(openUrl).toHaveBeenCalledWith("http://localhost:3000");
    expect(openUrl).toHaveBeenCalledTimes(2);
  });

  it("refuses file:, javascript:, malformed, and empty inputs", async () => {
    await openExternal("file:///etc/passwd");
    await openExternal("javascript:alert(1)");
    await openExternal("not a url");
    await openExternal(null);
    await openExternal(undefined);
    expect(openUrl).not.toHaveBeenCalled();
  });
});
