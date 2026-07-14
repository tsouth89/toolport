import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Registry } from "@/lib/types";

const api = vi.hoisted(() => ({
  teamConnect: vi.fn(),
  teamJoinPoll: vi.fn(),
  teamSync: vi.fn(),
  teamDisconnect: vi.fn(),
  teamPushPreview: vi.fn(),
  teamPush: vi.fn(),
  setServerEnabled: vi.fn(),
}));

vi.mock("@/lib/api", () => api);
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(vi.fn()),
}));

import { TeamsView } from "./TeamsView";

const registry: Registry = {
  version: 1,
  servers: [],
  profiles: [{ id: "default", name: "Default", enabledServerIds: [] }],
  activeProfileId: "default",
  team: {
    serverUrl: "https://teams.toolport.app",
    teamId: "team-1",
    role: "admin",
    lastVersion: 6,
  },
};

describe("TeamsView shared-server update", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("shows a deterministic diff and does not push until the admin confirms", async () => {
    const preview = {
      baseVersion: 7,
      localFingerprint: "preview-fingerprint",
      added: ["Alpha", "beta"],
      changed: ["GitHub"],
      removed: ["Legacy"],
    };
    api.teamPushPreview.mockResolvedValue(preview);
    api.teamPush.mockResolvedValue(8);

    render(<TeamsView registry={registry} onRegistryChange={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Update shared servers" }));

    expect(await screen.findByText("Added (2)")).toBeInTheDocument();
    expect(screen.getByText("Changed (1)")).toBeInTheDocument();
    expect(screen.getByText("Removed (1)")).toBeInTheDocument();
    for (const name of ["Alpha", "beta", "GitHub", "Legacy"]) {
      expect(screen.getByText(name)).toBeInTheDocument();
    }
    expect(api.teamPush).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Replace shared servers" }));
    await waitFor(() => expect(api.teamPush).toHaveBeenCalledWith(preview));
    expect(await screen.findByText(/now version 8/i)).toBeInTheDocument();
  });

  it("discards a stale confirmation and requires a fresh preview", async () => {
    const preview = {
      baseVersion: 7,
      localFingerprint: "preview-fingerprint",
      added: [],
      changed: ["GitHub"],
      removed: [],
    };
    api.teamPushPreview.mockResolvedValue(preview);
    api.teamPush.mockRejectedValue(
      new Error("The team config changed; nothing was overwritten."),
    );

    render(<TeamsView registry={registry} onRegistryChange={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Update shared servers" }));
    await userEvent.click(
      await screen.findByRole("button", { name: "Replace shared servers" }),
    );

    expect(
      await screen.findByText(/team config changed; nothing was overwritten/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Replace shared servers" }),
    ).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Update shared servers" }));
    await waitFor(() => expect(api.teamPushPreview).toHaveBeenCalledTimes(2));
  });
});
