import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QuarantineAlert } from "./QuarantineAlert";
import type { QuarantinedTool } from "@/lib/api";

const listQuarantined = vi.fn();
const releaseQuarantine = vi.fn();
const toastError = vi.fn();

vi.mock("@/lib/api", () => ({
  listQuarantined: (...a: unknown[]) => listQuarantined(...a),
  releaseQuarantine: (...a: unknown[]) => releaseQuarantine(...a),
}));
vi.mock("@/lib/toast", () => ({ toastError: (...a: unknown[]) => toastError(...a) }));

function tool(over: Partial<QuarantinedTool> = {}): QuarantinedTool {
  return {
    server: "linear",
    tool: "linear__save_issue",
    reason: "a destructive tool's definition changed",
    ts: Date.now(),
    profile: "",
    ...over,
  };
}

beforeEach(() => {
  listQuarantined.mockReset();
  releaseQuarantine.mockReset();
  toastError.mockReset();
});

describe("QuarantineAlert", () => {
  it("renders nothing when no tool is quarantined", async () => {
    listQuarantined.mockResolvedValue([]);
    render(<QuarantineAlert />);
    await waitFor(() => expect(listQuarantined).toHaveBeenCalled());
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("surfaces the blocked tool and the reason it was blocked", async () => {
    // The reason is the whole point of the surface: it is what makes re-approving an
    // informed decision rather than a reflex, so it must be on screen, not behind a click.
    listQuarantined.mockResolvedValue([tool()]);
    render(<QuarantineAlert />);

    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();
    expect(screen.getByText("linear__save_issue")).toBeInTheDocument();
    expect(
      screen.getByText("a destructive tool's definition changed"),
    ).toBeInTheDocument();
  });

  it("re-approves through the profile-scoped API and re-reads the list", async () => {
    // Empty profile is the no-profile store; the backend maps it to None. Passing the
    // wrong profile would silently release nothing.
    listQuarantined.mockResolvedValueOnce([tool({ profile: "work" })]);
    releaseQuarantine.mockResolvedValue(undefined);
    listQuarantined.mockResolvedValue([]);

    render(<QuarantineAlert />);
    await userEvent.click(await screen.findByRole("button", { name: /re-approve/i }));

    expect(releaseQuarantine).toHaveBeenCalledWith("work", "linear__save_issue");
    await waitFor(() =>
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument(),
    );
  });

  it("keeps the card up and reports the error when re-approval fails", async () => {
    // Failing closed matters here: silently dropping the card would read as "unblocked"
    // when the tool is still blocked.
    listQuarantined.mockResolvedValue([tool()]);
    releaseQuarantine.mockRejectedValue(new Error("locked"));

    render(<QuarantineAlert />);
    await userEvent.click(await screen.findByRole("button", { name: /re-approve/i }));

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("stays hidden after dismissal, but reopens when a NEW tool is quarantined", async () => {
    // Dismissal is scoped to the set that was on screen. A blanket "dismissed" flag would
    // hide a later, unrelated quarantine, which is exactly the silent-failure mode this
    // surface exists to remove.
    listQuarantined.mockResolvedValue([tool()]);
    render(<QuarantineAlert />);

    await userEvent.click(await screen.findByRole("button", { name: /keep blocked/i }));
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();

    listQuarantined.mockResolvedValue([tool(), tool({ tool: "linear__delete_issue" })]);
    // Longer than the 2s poll interval, since the reopen depends on the next poll landing.
    expect(
      await screen.findByRole("alertdialog", {}, { timeout: 4000 }),
    ).toBeInTheDocument();
    expect(screen.getByText("linear__delete_issue")).toBeInTheDocument();
  });

  it("keeps the current list when a poll fails instead of flashing all-clear", async () => {
    listQuarantined.mockResolvedValueOnce([tool()]);
    render(<QuarantineAlert />);
    expect(await screen.findByRole("alertdialog")).toBeInTheDocument();

    listQuarantined.mockRejectedValue(new Error("backend down"));
    // Give the poll a chance to land and (incorrectly) clear the list.
    await new Promise((r) => setTimeout(r, 2100));
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});
