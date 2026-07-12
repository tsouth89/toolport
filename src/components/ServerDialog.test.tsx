import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ServerDialog } from "./ServerDialog";

describe("ServerDialog", () => {
  it("opens from its trigger and shows the add form", async () => {
    render(<ServerDialog trigger={<button>Add server</button>} onSaved={vi.fn()} />);
    expect(screen.queryByText("Add MCP server")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Add server" }));
    expect(screen.getByText("Add MCP server")).toBeInTheDocument();
    expect(screen.getByLabelText("Name")).toBeInTheDocument();
  });

  it("gates the Add button until the required fields are filled", async () => {
    render(<ServerDialog trigger={<button>Add server</button>} onSaved={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Add server" }));

    // Empty name + command => blocked.
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Name"), "stripe");
    // Name alone isn't enough for a stdio server; the command is still missing.
    expect(screen.getByRole("button", { name: "Add" })).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Command"), "npx");
    expect(screen.getByRole("button", { name: "Add" })).toBeEnabled();
  });

  it("closes on Cancel when it owns its open state (header add flow)", async () => {
    render(<ServerDialog trigger={<button>Add server</button>} onSaved={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Add server" }));
    expect(screen.getByText("Add MCP server")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByText("Add MCP server")).not.toBeInTheDocument();
  });

  it("delegates dismissal to onClose when the parent controls it (autoOpen flow)", async () => {
    const onClose = vi.fn();
    render(
      <ServerDialog
        trigger={<button>ignored</button>}
        onSaved={vi.fn()}
        autoOpen
        onClose={onClose}
      />,
    );
    // autoOpen renders it open immediately.
    expect(screen.getByText("Add MCP server")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
