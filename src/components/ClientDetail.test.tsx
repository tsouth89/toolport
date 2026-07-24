import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ClientDetail } from "./ClientDetail";
import type { DetectedClient, Registry } from "@/lib/types";

const installGateway = vi.fn();
const uninstallGateway = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/lib/api", () => ({
  installGateway: (...a: unknown[]) => installGateway(...a),
  uninstallGateway: (...a: unknown[]) => uninstallGateway(...a),
  migrateClient: vi.fn(),
  setClientDiscovery: vi.fn(),
  addServer: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  },
}));

vi.mock("@/lib/toast", () => ({
  toastError: (...a: unknown[]) => toastError(...a),
}));

function client(over: Partial<DetectedClient> = {}): DetectedClient {
  return {
    id: "claude-desktop",
    name: "Claude Desktop",
    usesConnectors: false,
    configPath: "C:\\Users\\me\\Claude\\claude_desktop_config.json",
    configExists: true,
    gatewayInstalled: false,
    appPresent: true,
    servers: [],
    pluginServers: [],
    error: null,
    ...over,
  };
}

function emptyRegistry(): Registry {
  return {
    version: 1,
    servers: [],
    profiles: [],
    activeProfileId: null,
  };
}

beforeEach(() => {
  installGateway.mockReset();
  uninstallGateway.mockReset();
  toastSuccess.mockReset();
  toastError.mockReset();
});

describe("ClientDetail connect toast (SOU-317)", () => {
  it("tells the user to restart the client after a successful Connect", async () => {
    // Without this, the UI says "Connected" while Claude Desktop (and most peers)
    // still has the old MCP config in memory and Toolport looks broken.
    installGateway.mockResolvedValue({ backup: false });
    render(
      <ClientDetail
        client={client()}
        registry={emptyRegistry()}
        onChanged={() => {}}
        onRegistryChange={() => {}}
      />,
    );

    await userEvent.click(screen.getByRole("button", { name: /connect to toolport/i }));

    await waitFor(() =>
      expect(installGateway).toHaveBeenCalledWith("claude-desktop", undefined),
    );
    expect(toastSuccess).toHaveBeenCalledWith(
      "Connected Toolport to Claude Desktop",
      expect.objectContaining({
        description: "Restart Claude Desktop so it loads Toolport.",
      }),
    );
  });

  it("includes scope detail after the restart nudge when connecting with a profile", async () => {
    installGateway.mockResolvedValue({ backup: false });
    // Seed clientScopes so the component's profile state initializes to Work.
    const reg = emptyRegistry();
    reg.profiles = [{ id: "p1", name: "Work", enabledServerIds: [] }];
    reg.clientScopes = { "claude-desktop": "Work" };

    render(
      <ClientDetail
        client={client()}
        registry={reg}
        onChanged={() => {}}
        onRegistryChange={() => {}}
      />,
    );

    // Already connected would show Disconnect; for connect we need uninstalled.
    // clientScopes still pre-fills the profile picker for a fresh connect.
    await userEvent.click(screen.getByRole("button", { name: /connect to toolport/i }));

    await waitFor(() =>
      expect(installGateway).toHaveBeenCalledWith("claude-desktop", "Work"),
    );
    expect(toastSuccess).toHaveBeenCalledWith(
      "Connected Toolport to Claude Desktop",
      expect.objectContaining({
        description:
          'Restart Claude Desktop so it loads Toolport. Scoped to the "Work" profile.',
      }),
    );
  });
});
