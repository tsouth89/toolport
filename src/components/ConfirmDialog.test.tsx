import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ConfirmDialog } from "./ConfirmDialog";

function renderControlledDialog(
  overrides: Partial<Parameters<typeof ConfirmDialog>[0]> = {},
) {
  const onConfirm = vi.fn();
  const onOpenChange = vi.fn();

  render(
    <ConfirmDialog
      open
      title="Delete item?"
      description="This action cannot be undone."
      onConfirm={onConfirm}
      onOpenChange={onOpenChange}
      {...overrides}
    />,
  );

  return { onConfirm, onOpenChange };
}

describe("ConfirmDialog", () => {
  it("calls onConfirm and requests to close when it resolves", async () => {
    const { onConfirm, onOpenChange } = renderControlledDialog();

    await userEvent.click(screen.getByRole("button", { name: /confirm/i }));

    expect(onConfirm).toHaveBeenCalledTimes(1);

    await waitFor(() => {
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });
  });

  it("stays open and re-enables buttons when onConfirm rejects", async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error("Failed"));
    const { onOpenChange } = renderControlledDialog({ onConfirm });

    await userEvent.click(screen.getByRole("button", { name: /confirm/i }));

    expect(screen.getByText("Delete item?")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /confirm/i })).toBeEnabled();

      expect(screen.getByRole("button", { name: /cancel/i })).toBeEnabled();
    });

    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });

  it("closes on cancel without calling onConfirm", async () => {
    const onConfirm = vi.fn();

    render(
      <ConfirmDialog
        trigger={<button>Open dialog</button>}
        title="Delete item?"
        onConfirm={onConfirm}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /open dialog/i }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("notifies controlled usage without changing internal open state", async () => {
    const { onOpenChange } = renderControlledDialog();

    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(onOpenChange).toHaveBeenCalledWith(false);

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Delete item?")).toBeInTheDocument();
  });
});
