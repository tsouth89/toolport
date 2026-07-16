import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import type { DetectedClient } from "@/lib/types";

// Poll target: watch the local audit log for the first new call.
const getAuditLog = vi.fn();
vi.mock("@/lib/api", () => ({ getAuditLog: (n: number) => getAuditLog(n) }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/lib/toast", () => ({ toastError: vi.fn() }));
// ClientLogo loads vendored SVGs via import.meta.glob; stub it so the test stays focused.
vi.mock("@/components/ClientLogo", () => ({ ClientLogo: () => null }));

import { VerifyCall } from "./Onboarding";

const client = {
  id: "cursor",
  name: "Cursor",
  appPresent: true,
  gatewayInstalled: true,
  servers: [],
  pluginServers: [],
  configPath: "",
} as unknown as DetectedClient;

describe("VerifyCall", () => {
  beforeEach(() => getAuditLog.mockReset());

  it("celebrates the first new call after the snapshot", async () => {
    // First read = snapshot (one old call at ts 100); subsequent polls surface a newer one.
    getAuditLog
      .mockResolvedValueOnce([{ ts: 100, server: "GitHub", tool: "old", ok: true }])
      .mockResolvedValue([
        { ts: 200, server: "GitHub", tool: "get_me", ok: true },
        { ts: 100, server: "GitHub", tool: "old", ok: true },
      ]);

    render(<VerifyCall client={client} onOpenPlayground={vi.fn()} pollMs={5} />);

    await waitFor(() => expect(screen.getByText(/It works/)).toBeInTheDocument());
    // Names the tool + server that succeeded.
    expect(screen.getByText("get_me")).toBeInTheDocument();
    expect(screen.getByText("GitHub")).toBeInTheDocument();
  });

  it("shows recovery guidance when no call arrives before the deadline", async () => {
    // The log never advances past the snapshot, so nothing is ever "fresh".
    getAuditLog.mockResolvedValue([{ ts: 100, server: "GitHub", tool: "old", ok: true }]);

    render(
      <VerifyCall client={client} onOpenPlayground={vi.fn()} pollMs={5} timeoutMs={20} />,
    );

    await waitFor(() => expect(screen.getByText(/No call yet/)).toBeInTheDocument());
    expect(screen.getByText(/Restart Cursor/)).toBeInTheDocument();
    // Never falsely celebrates.
    expect(screen.queryByText(/It works/)).not.toBeInTheDocument();
  });

  it("offers the Playground fallback while waiting", () => {
    getAuditLog.mockResolvedValue([]);
    const onOpenPlayground = vi.fn();
    render(<VerifyCall client={client} onOpenPlayground={onOpenPlayground} pollMs={5} />);
    const btn = screen.getByRole("button", { name: /Playground/ });
    btn.click();
    expect(onOpenPlayground).toHaveBeenCalledOnce();
  });
});
