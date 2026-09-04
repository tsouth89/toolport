import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ActivityView } from "./ActivityView";
import type { AuditEntry, SearchTrace } from "@/lib/types";

const getAuditLog = vi.fn();
const getSearchTraces = vi.fn();
const getSecurityEvents = vi.fn();
const getToolIdentities = vi.fn();
const getInspectLog = vi.fn();

const clearActivityLogs = vi.fn();

vi.mock("@/lib/api", () => ({
  clearActivityLogs: (...a: unknown[]) => clearActivityLogs(...a),
  exportAuditToPath: vi.fn(),
  getAuditLog: (...a: unknown[]) => getAuditLog(...a),
  getAuditStats: vi.fn(() => Promise.resolve(null)),
  getInspectLog: (...a: unknown[]) => getInspectLog(...a),
  getSavingsSummary: vi.fn(() => Promise.resolve(null)),
  getSearchTraces: (...a: unknown[]) => getSearchTraces(...a),
  getSecurityEvents: (...a: unknown[]) => getSecurityEvents(...a),
  getToolIdentities: (...a: unknown[]) => getToolIdentities(...a),
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
  getSearchTraces.mockResolvedValue([]);
  getSecurityEvents.mockResolvedValue([]);
  getToolIdentities.mockResolvedValue([]);
  getInspectLog.mockResolvedValue([]);
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("ActivityView trust-state loading", () => {
  it("shows initial loading without claiming protection is clear", () => {
    getAuditLog.mockReturnValue(new Promise(() => {}));
    getSecurityEvents.mockReturnValue(new Promise(() => {}));

    render(<ActivityView refreshKey={0} registry={null} />);

    expect(screen.getByText("Loading activity…")).toBeInTheDocument();
    expect(screen.getByText("Checking protection status…")).toBeInTheDocument();
    expect(screen.queryByText("Protection active.")).not.toBeInTheDocument();
  });

  it("treats a successful empty read as verified empty", async () => {
    getAuditLog.mockResolvedValue([]);
    getSecurityEvents.mockResolvedValue([]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    expect(screen.getByText("No tool calls yet")).toBeInTheDocument();
    expect(screen.getByText("Protection active.")).toBeInTheDocument();
  });

  it("shows an unknown security state with retry after the initial read fails", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getAuditLog.mockResolvedValue([]);
    getSecurityEvents
      .mockRejectedValueOnce(new Error("unreadable"))
      .mockResolvedValueOnce([]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    expect(screen.getByText("Couldn't verify protection status.")).toBeInTheDocument();
    expect(screen.getByText(/this is not an all-clear/i)).toBeInTheDocument();
    expect(screen.queryByText("Protection active.")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry protection status" }));
    await act(async () => {});

    expect(screen.getByText("Protection active.")).toBeInTheDocument();
    expect(
      screen.queryByText("Couldn't verify protection status."),
    ).not.toBeInTheDocument();
  });

  it("preserves last-known security findings when a live refresh fails", async () => {
    const finding = {
      ts: 1700000000000,
      type: "tool_poison_flag",
      server: "github",
      tool: "github__create_issue",
      change: "poison",
      severity: "high" as const,
    };
    getSecurityEvents
      .mockResolvedValueOnce([finding])
      .mockRejectedValueOnce(new Error("locked"));

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});
    expect(screen.getByText("github__create_issue")).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    expect(screen.getByText("Security status may be out of date.")).toBeInTheDocument();
    expect(screen.getByText("github__create_issue")).toBeInTheDocument();
    expect(screen.queryByText("Protection active.")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Retry protection status" }),
    ).toBeInTheDocument();
  });

  it("does not restore cleared calls when the post-clear refetch fails", async () => {
    const { toast } = await import("sonner");
    clearActivityLogs.mockResolvedValue(undefined);
    getAuditLog
      .mockResolvedValueOnce(initialLog)
      .mockRejectedValueOnce(new Error("locked"));

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});
    expect(screen.getByText(/last 2/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear activity" }));
    await act(async () => {});

    expect(toast.success).toHaveBeenCalledWith("Cleared retained activity");
    expect(screen.queryByText(/last 2/)).not.toBeInTheDocument();
    expect(
      screen.getByText(/can't verify that the log is still empty/i),
    ).toBeInTheDocument();
  });

  it("ignores an audit read that started before the clear and resolved after it", async () => {
    const { toast } = await import("sonner");
    clearActivityLogs.mockResolvedValue(undefined);
    let resolveStale!: (rows: AuditEntry[]) => void;
    getAuditLog
      .mockResolvedValueOnce(initialLog)
      .mockReturnValueOnce(
        new Promise<AuditEntry[]>((res) => {
          resolveStale = res;
        }),
      )
      .mockRejectedValueOnce(new Error("locked"));

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});
    expect(screen.getByText(/last 2/)).toBeInTheDocument();

    // A live tick starts a refetch that is still in flight when the user clears.
    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    fireEvent.click(screen.getByRole("button", { name: "Clear activity" }));
    // The pre-clear read resolves with the deleted rows in the same flush as the
    // clear finishing, before its effect's cleanup has run.
    resolveStale(initialLog);
    await act(async () => {});

    expect(toast.success).toHaveBeenCalledWith("Cleared retained activity");
    expect(screen.queryByText(/last 2/)).not.toBeInTheDocument();
    expect(
      screen.getByText(/can't verify that the log is still empty/i),
    ).toBeInTheDocument();
  });

  it("does not turn a last-known empty audit log into a current all-clear", async () => {
    getAuditLog.mockResolvedValueOnce([]).mockRejectedValueOnce(new Error("locked"));

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});
    expect(screen.getByText("No tool calls yet")).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    expect(screen.getByText("Activity may be out of date.")).toBeInTheDocument();
    expect(screen.getByText("No current activity status")).toBeInTheDocument();
    expect(screen.queryByText("No tool calls yet")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Retry activity log" }),
    ).toBeInTheDocument();
  });

  it("preserves last-known calls and offers retry when a live refresh fails", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getAuditLog
      .mockResolvedValueOnce(initialLog)
      .mockRejectedValueOnce(new Error("locked"));

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});
    await user.click(screen.getByRole("button", { name: /recent calls/i }));

    await act(async () => {
      vi.advanceTimersByTime(3000);
    });

    expect(screen.getByText("Activity may be out of date.")).toBeInTheDocument();
    expect(screen.getByText("merge_pr")).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load activity")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Retry activity log" }),
    ).toBeInTheDocument();
  });

  it("shows an initial audit error with retry instead of a false empty log", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getAuditLog.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce([]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    expect(screen.getByText("Couldn't load activity")).toBeInTheDocument();
    expect(screen.queryByText("No tool calls yet")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry activity log" }));
    await act(async () => {});
    expect(screen.getByText("No tool calls yet")).toBeInTheDocument();
  });
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

  it("shows the pseudonymization count, and flags a pass that did not fully apply", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getAuditLog.mockResolvedValue([
      entry({ tool: "redacted_call", piiReplaced: 3 }),
      entry({
        ts: 1700000003000,
        tool: "leaky_call",
        piiReplaced: 2,
        piiIncomplete: true,
      }),
      entry({ ts: 1700000004000, tool: "matched_nothing", piiReplaced: 0 }),
      entry({ ts: 1700000005000, tool: "redaction_off" }),
    ]);
    render(<ActivityView refreshKey={0} registry={null} />);

    await act(async () => {});
    await user.click(screen.getByRole("button", { name: /recent calls/i }));

    expect(screen.getByText("3 pseudonymized")).toBeInTheDocument();

    // The fail-open case has to read as a warning, not as a tidy count: values reached
    // the model in the clear even though redaction was on.
    const incomplete = screen.getByText("2 pseudonymized, incomplete");
    expect(incomplete).toBeInTheDocument();
    expect(incomplete).toHaveAttribute(
      "title",
      expect.stringContaining("did not fully apply"),
    );

    // A pass that matched nothing, and a call made with redaction off, both stay silent —
    // a badge on every row would bury the two cases above.
    expect(screen.queryByText(/0 pseudonymized/)).not.toBeInTheDocument();
    expect(screen.getAllByText(/pseudonymized/)).toHaveLength(2);

    // The values are the point of the feature and must never reach this view.
    expect(document.body.textContent).not.toMatch(/@example\.com/);
  });
});

describe("ActivityView discovery", () => {
  it("shows an error with retry instead of a false empty state when discovery traces fail to load (#728)", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getSearchTraces.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce([]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    expect(screen.getByText("Couldn't load discovery.")).toBeInTheDocument();
    expect(screen.queryByText(/Nothing searched yet/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Retry loading discovery" }));
    await act(async () => {});
    expect(screen.getByText(/Nothing searched yet/)).toBeInTheDocument();
  });

  it("shows a tiny nonzero saving without rounding it down to zero", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    const trace: SearchTrace = {
      ts: 1700000000000,
      query: "tiny savings",
      top: "github.search",
      names: ["github.search"],
      returned: 1,
      total: 20,
      returnedTokens: 1999,
      flatTokens: 2000,
      savedTokens: 1,
      escalated: false,
    };
    getSearchTraces.mockResolvedValue([trace]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    await user.click(screen.getByRole("button", { name: /Discovery/ }));
    const row = screen.getByRole("button", { name: /tiny savings/i });
    await user.click(row);

    expect(row.parentElement).toHaveTextContent(/<0\.1% less this turn\)\./);
    expect(row.parentElement).not.toHaveTextContent(/\(0% less this turn\)\./);
  });
});

describe("ActivityView tool identities", () => {
  it("shows an error with retry instead of hiding the panel when identities fail to load (#728)", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getToolIdentities
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce([]);

    render(<ActivityView refreshKey={0} registry={null} />);
    await act(async () => {});

    expect(screen.getByText("Couldn't load tool identities.")).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Retry loading tool identities" }),
    );
    await act(async () => {});
    expect(screen.queryByText("Couldn't load tool identities.")).not.toBeInTheDocument();
  });
});

describe("ActivityView live inspector", () => {
  it("shows an error with retry instead of a false empty state when the inspect log fails to load (#728)", async () => {
    const user = userEvent.setup({
      advanceTimers: (ms) => vi.advanceTimersByTime(ms),
    });
    getInspectLog.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce([]);

    // LiveInspector only mounts while live inspection is on (ActivityView.tsx:1772).
    render(<ActivityView refreshKey={0} registry={{ liveInspect: true } as never} />);
    await act(async () => {});

    expect(screen.getByText("Couldn't load live inspector.")).toBeInTheDocument();
    expect(
      screen.queryByText(/No calls captured yet\. Run a tool/),
    ).not.toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Retry loading live inspector" }),
    );
    await act(async () => {});
    expect(screen.getByText(/No calls captured yet\. Run a tool/)).toBeInTheDocument();
  });
});
