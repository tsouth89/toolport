import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ProfileBar } from "./ProfileBar";
import type { Registry } from "@/lib/types";

vi.mock("sonner", () => ({ toast: { success: vi.fn() } }));
vi.mock("@/lib/toast", () => ({ toastError: vi.fn() }));
vi.mock("@/lib/api", () => ({
  createProfile: vi.fn(),
  deleteProfile: vi.fn(),
  setActiveProfile: vi.fn(),
}));

const registry: Registry = {
  version: 1,
  servers: [],
  profiles: [{ id: "default", name: "Default", enabledServerIds: [] }],
  activeProfileId: "default",
};

async function openDialog() {
  await userEvent.click(screen.getByRole("button", { name: /new profile/i }));
  return screen.getByLabelText(/name/i);
}

describe("ProfileBar", () => {
  it("clears the new profile name after cancelling the dialog", async () => {
    render(<ProfileBar registry={registry} onChange={vi.fn()} />);

    await userEvent.type(await openDialog(), "Work");
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(await openDialog()).toHaveValue("");
  });

  it("clears the new profile name when the dialog closes via Escape", async () => {
    render(<ProfileBar registry={registry} onChange={vi.fn()} />);

    await userEvent.type(await openDialog(), "Personal");
    await userEvent.keyboard("{Escape}");

    expect(await openDialog()).toHaveValue("");
  });
});
