import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ActivityView } from "./ActivityView";
import type { AuditEntry } from "@/lib/types";

const getAuditLog = vi.fn();

vi.mock("@/lib/api", () => ({
  clearActivityLogs: vi.fn(),
  exportAuditToPath: vi.fn(),
  getAuditLog: (...a: unknown[]) => getAuditLog(...a),
  getAuditStats: vi.fn(() => Promise.resolve(null)),
  getInspectLog: vi.fn(() => Promise.resolve([])),
  getSavingsSummary: vi.fn(() => Promise.resolve(null)),
  getSearchTraces: vi.fn(() => Promise.resolve([])),
  getSecurityEvents: vi.fn(() => Promise.resolve([])),
  getToolIdentities: vi.fn(() => Promise.resolve([])),
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}));

vi.mock("@/lib/toast", () => ({ toastError: vi.fn() }));

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));

function entry(over: Partial<AuditEntry> = {}): AuditEntry {
  return {
    ts: 1700000000000,
    server: "github",
    tool: "create_issue",
    ok: true,
    durationMs: 120,
    ...over,
  };
}

const failed = entry({
  ts: 1700000001000,
  tool: "merge_pr",
  ok: false,
  error: "403: token lacks repo scope",
});
const initialLog = [failed, entry()];
// Same list with a fresh call prepended, as the 3s live tick would refetch it.
const refreshedLog = [entry({ ts: 1700000002000, tool: "list_issues" }), ...initialLog];

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  getAuditLog.mockResolvedValue(initialLog);
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("ActivityView recent calls", () => {
  it("keeps an expanded error row open across a live-poll refetch", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    render(<ActivityView refreshKey={0} registry={null} />);

    await act(async () => {});
    await user.click(screen.getByRole("button", { name: /recent calls/i }));

    // Expand the failed call's error detail.
    await user.click(screen.getByText("merge_pr"));
    expect(screen.getByText("403: token lacks repo scope")).toBeInTheDocument();

    // Next poll returns the same entries with a new call prepended.
    getAuditLog.mockResolvedValue(refreshedLog);
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    expect(screen.getByText("list_issues")).toBeInTheDocument();
    expect(screen.getByText("403: token lacks repo scope")).toBeInTheDocument();
  });
});
