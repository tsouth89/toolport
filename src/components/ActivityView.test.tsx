// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ActivityView } from "./ActivityView";
import * as api from "@/lib/api";
import type { AuditEntry } from "@/lib/types";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    getAuditLog: vi.fn(),
    getAuditStats: vi.fn().mockResolvedValue({ total: 0, errors: 0, servers: [] }),
    getSavingsSummary: vi.fn().mockResolvedValue({ tokensSaved: 0 }),
    getSecurityEvents: vi.fn().mockResolvedValue([]),
    getSearchTraces: vi.fn().mockResolvedValue([]),
    getInspectLog: vi.fn().mockResolvedValue([]),
    getToolIdentities: vi.fn().mockResolvedValue([]),
  };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({
  save: vi.fn(),
}));

describe("ActivityView key stability", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("keeps an expanded failing CallRow open across refetches when a new call is prepended", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const failingEntry: AuditEntry = {
      ts: 1000,
      server: "db-server",
      tool: "query_db",
      ok: false,
      error: "FATAL: connection refused at 127.0.0.1:5432",
    };

    const newEntry: AuditEntry = {
      ts: 2000,
      server: "api-server",
      tool: "fetch_user",
      ok: true,
    };

    // First fetch returns the failing call
    vi.mocked(api.getAuditLog).mockResolvedValueOnce([failingEntry]);

    const { rerender } = render(<ActivityView refreshKey={0} registry={null} />);

    // Wait for initial async load
    await act(async () => {
      await Promise.resolve();
    });

    // Expand the "Recent calls" section
    const recentCallsBtn = screen.getByRole("button", { name: /Recent calls/i });
    await user.click(recentCallsBtn);

    // Verify the failing call row is present and click it to expand
    const callRow = screen.getByRole("button", { name: /db-server/i });
    await user.click(callRow);

    // Verify error text is displayed
    expect(screen.getByText("FATAL: connection refused at 127.0.0.1:5432")).toBeDefined();

    // Next poll returns the same failing entry plus one new entry prepended at the front
    vi.mocked(api.getAuditLog).mockResolvedValueOnce([newEntry, failingEntry]);

    // Rerender with new refreshKey (simulating 3s tick poll)
    rerender(<ActivityView refreshKey={1} registry={null} />);

    await act(async () => {
      await Promise.resolve();
    });

    // Assert that the expanded error text is STILL in the document
    expect(screen.getByText("FATAL: connection refused at 127.0.0.1:5432")).toBeDefined();
  });

  it("handles duplicate timestamps cleanly without unmounting existing expanded rows", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });

    const entry1: AuditEntry = {
      ts: 1000,
      server: "same-server",
      tool: "same-tool",
      ok: false,
      error: "Error 1",
    };

    const entry2: AuditEntry = {
      ts: 1000,
      server: "same-server",
      tool: "same-tool",
      ok: false,
      error: "Error 2",
    };

    vi.mocked(api.getAuditLog).mockResolvedValueOnce([entry1]);

    const { rerender } = render(<ActivityView refreshKey={0} registry={null} />);

    await act(async () => {
      await Promise.resolve();
    });

    await user.click(screen.getByRole("button", { name: /Recent calls/i }));
    await user.click(screen.getByRole("button", { name: /same-server/i }));

    expect(screen.getByText("Error 1")).toBeDefined();

    // Prepend entry2 with the exact same millisecond timestamp
    vi.mocked(api.getAuditLog).mockResolvedValueOnce([entry2, entry1]);

    rerender(<ActivityView refreshKey={1} registry={null} />);

    await act(async () => {
      await Promise.resolve();
    });

    // Error 1 should still be visible because entry1's key was stable
    expect(screen.getByText("Error 1")).toBeDefined();
  });
});
