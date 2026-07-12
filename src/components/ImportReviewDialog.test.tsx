import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ImportReviewDialog } from "./ImportReviewDialog";
import type { ImportItem } from "@/lib/types";

function items(): ImportItem[] {
  return [
    {
      key: "a",
      name: "stripe",
      transport: "stdio",
      command: "npx",
      args: ["stripe-mcp"],
      url: null,
      isNew: true,
    },
    {
      key: "b",
      name: "linear",
      transport: "http",
      command: null,
      args: [],
      url: "https://mcp.linear.app/mcp",
      isNew: true,
    },
    {
      key: "c",
      name: "shellsrv",
      transport: "stdio",
      command: "bash",
      args: ["-c", "echo hi"],
      url: null,
      isNew: true,
    },
  ];
}

function renderDialog(overrides: Partial<Parameters<typeof ImportReviewDialog>[0]> = {}) {
  const onConfirm = vi.fn();
  const onOpenChange = vi.fn();
  render(
    <ImportReviewDialog
      open
      items={items()}
      onConfirm={onConfirm}
      onOpenChange={onOpenChange}
      {...overrides}
    />,
  );
  return { onConfirm, onOpenChange };
}

describe("ImportReviewDialog", () => {
  it("starts with every server selected and confirms them all", async () => {
    const { onConfirm } = renderDialog();
    // Button label reflects the full selection.
    await userEvent.click(screen.getByRole("button", { name: /import 3 servers/i }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(new Set(onConfirm.mock.calls[0][0])).toEqual(new Set(["a", "b", "c"]));
  });

  it("excludes a server from the confirm payload after it's deselected", async () => {
    const { onConfirm } = renderDialog();
    // Toggle "linear" off by clicking its row.
    await userEvent.click(screen.getByText("linear"));
    expect(screen.getByRole("button", { name: /import 2 servers/i })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: /import 2 servers/i }));
    expect(onConfirm).toHaveBeenCalledWith(expect.arrayContaining(["a", "c"]));
    expect(onConfirm.mock.calls[0][0]).not.toContain("b");
  });

  it("disables import when nothing is selected", async () => {
    renderDialog();
    for (const name of ["stripe", "linear", "shellsrv"]) {
      await userEvent.click(screen.getByText(name));
    }
    const cta = screen.getByRole("button", { name: /select a server/i });
    expect(cta).toBeDisabled();
  });

  it("cancel dismisses without confirming", async () => {
    const { onConfirm, onOpenChange } = renderDialog();
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("flags a shell-command server so the user can't import it blindly", () => {
    renderDialog();
    expect(screen.getByText(/runs a shell command/i)).toBeInTheDocument();
  });

  it("renders nothing when closed", () => {
    const { container } = render(
      <ImportReviewDialog
        open={false}
        items={items()}
        onConfirm={vi.fn()}
        onOpenChange={vi.fn()}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});
