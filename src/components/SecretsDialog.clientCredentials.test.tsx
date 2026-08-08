import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SecretsDialog } from "./SecretsDialog";
import type { Registry, ServerEntry } from "@/lib/types";

const setClientCredentials = vi.fn();
const clearClientCredentials = vi.fn();
const hasClientSecret = vi.fn();
const toastError = vi.fn();

vi.mock("@/lib/api", () => ({
  setClientCredentials: (...a: unknown[]) => setClientCredentials(...a),
  clearClientCredentials: (...a: unknown[]) => clearClientCredentials(...a),
  hasClientSecret: (...a: unknown[]) => hasClientSecret(...a),
  secretStatus: vi.fn().mockResolvedValue([]),
  hasAuthToken: vi.fn().mockResolvedValue(false),
  probeAuth: vi.fn().mockResolvedValue({ kind: "oauth", guidance: null }),
  setSecret: vi.fn(),
  deleteSecret: vi.fn(),
  setAuthToken: vi.fn(),
  clearAuthToken: vi.fn(),
  authenticateOauth: vi.fn(),
}));

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  },
}));

vi.mock("@/lib/toast", () => ({
  toastError: (...a: unknown[]) => toastError(...a),
}));

vi.mock("@/lib/openUrl", () => ({ openExternal: vi.fn() }));

function server(over: Partial<ServerEntry> = {}): ServerEntry {
  return {
    id: "srv-1",
    name: "Headless MCP",
    transport: "http",
    command: null,
    args: [],
    env: [],
    url: "https://mcp.example.com/mcp",
    source: "manual",
    ...over,
  };
}

const registry = {} as Registry;

async function openDialog(entry: ServerEntry) {
  const user = userEvent.setup();
  render(<SecretsDialog server={entry} onSaved={vi.fn()} />);
  await user.click(screen.getByRole("button"));
  return user;
}

describe("SecretsDialog client credentials (SBS-524)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    hasClientSecret.mockResolvedValue(false);
    setClientCredentials.mockResolvedValue(registry);
    clearClientCredentials.mockResolvedValue(registry);
  });

  it("keeps headless auth behind a disclosure so browser sign-in stays primary", async () => {
    const user = await openDialog(server());
    expect(screen.queryByPlaceholderText("Client ID")).not.toBeInTheDocument();

    await user.click(
      screen.getByText(/No browser available\? Use a client id and secret/i),
    );
    expect(screen.getByPlaceholderText("Client ID")).toBeInTheDocument();
  });

  /// The secret must never be read back out of the keychain, only its existence.
  it("asks only whether a secret exists, never for its value", async () => {
    await openDialog(server({ clientCredentials: { clientId: "abc" } }));
    await waitFor(() => expect(hasClientSecret).toHaveBeenCalledWith("srv-1"));
    // There is no API that returns the secret, and the form must not be seeded
    // with one.
    await waitFor(() =>
      expect(screen.getByPlaceholderText("Client ID")).toHaveValue("abc"),
    );
    const secretField = screen.getByPlaceholderText(/Client secret/i);
    expect(secretField).toHaveValue("");
  });

  it("sends trimmed values and null for the optional fields left blank", async () => {
    const user = await openDialog(server());
    await user.click(
      screen.getByText(/No browser available\? Use a client id and secret/i),
    );
    await user.type(screen.getByPlaceholderText("Client ID"), "  client-abc  ");
    await user.type(screen.getByPlaceholderText(/^Client secret$/i), "s3cret");
    await user.click(screen.getByRole("button", { name: "Save client credentials" }));

    await waitFor(() =>
      expect(setClientCredentials).toHaveBeenCalledWith(
        "srv-1",
        "client-abc",
        "s3cret",
        null,
        null,
      ),
    );
  });

  /// Editing scopes must not force re-entering the credential.
  it("submits a blank secret when one is already stored, to keep it", async () => {
    hasClientSecret.mockResolvedValue(true);
    const user = await openDialog(
      server({ clientCredentials: { clientId: "client-abc" } }),
    );
    await waitFor(() => expect(hasClientSecret).toHaveBeenCalled());

    await user.type(screen.getByPlaceholderText(/Scopes \(optional/i), "mcp:read");
    await user.click(screen.getByRole("button", { name: "Save client credentials" }));

    await waitFor(() =>
      expect(setClientCredentials).toHaveBeenCalledWith(
        "srv-1",
        "client-abc",
        "",
        null,
        "mcp:read",
      ),
    );
  });

  /// The backend also rejects this, but its message describes stored state; the
  /// first-time user needs a direct instruction.
  it("requires a secret the first time, before calling the backend", async () => {
    hasClientSecret.mockResolvedValue(false);
    const user = await openDialog(server());
    await user.click(
      screen.getByText(/No browser available\? Use a client id and secret/i),
    );
    await user.type(screen.getByPlaceholderText("Client ID"), "client-abc");
    await user.click(screen.getByRole("button", { name: "Save client credentials" }));

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(setClientCredentials).not.toHaveBeenCalled();
  });

  /// The secret is never shown again and may have to be re-issued, so a single
  /// stray click must not destroy it.
  it("does not remove credentials until the destructive action is confirmed", async () => {
    hasClientSecret.mockResolvedValue(true);
    const user = await openDialog(
      server({ clientCredentials: { clientId: "client-abc" } }),
    );
    await waitFor(() => expect(hasClientSecret).toHaveBeenCalled());

    await user.click(screen.getByRole("button", { name: "Remove client credentials" }));
    expect(clearClientCredentials).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(clearClientCredentials).toHaveBeenCalledWith("srv-1"));
  });

  it("refuses to save without a client id instead of calling the backend", async () => {
    const user = await openDialog(server());
    await user.click(
      screen.getByText(/No browser available\? Use a client id and secret/i),
    );
    await user.click(screen.getByRole("button", { name: "Save client credentials" }));

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(setClientCredentials).not.toHaveBeenCalled();
  });
});
