import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Check, ShieldAlert, X } from "lucide-react";
import { decideApproval, listPendingApprovals } from "@/lib/api";
import type { PendingApproval } from "@/lib/types";
import { toastError } from "@/lib/toast";

const REASON_LABEL: Record<PendingApproval["reason"], string> = {
  destructive: "destructive",
  untrusted_source: "untrusted source",
  destructive_and_untrusted: "destructive · untrusted source",
};

/**
 * The human-in-the-loop approval queue: tool calls the gateway is holding until you
 * approve or deny them. Blocking, so it is mounted globally (visible from any view) and
 * renders nothing when the queue is empty. It polls as a safety net and refreshes
 * immediately on the gateway's `approval-pending` / `approval-resolved` events.
 */
export function PendingApprovals() {
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setPending(await listPendingApprovals());
    } catch {
      // Broker not up yet / transient — keep the current list rather than flashing empty.
    }
  }, []);

  useEffect(() => {
    void refresh();
    const poll = setInterval(() => void refresh(), 2000);
    const unlisten = Promise.all([
      listen("approval-pending", () => void refresh()),
      listen("approval-resolved", () => void refresh()),
    ]);
    return () => {
      clearInterval(poll);
      void unlisten.then((fns) => fns.forEach((f) => f()));
    };
  }, [refresh]);

  const decide = async (id: string, approved: boolean) => {
    setBusy(id);
    try {
      await decideApproval(id, approved);
      setPending((p) => p.filter((x) => x.id !== id));
    } catch (e) {
      toastError(`Couldn't record your decision: ${e}`);
      void refresh();
    } finally {
      setBusy(null);
    }
  };

  if (pending.length === 0) return null;

  return (
    <div className="fixed inset-x-0 top-0 z-50 flex justify-center px-4 pt-3">
      <div className="w-full max-w-2xl rounded-lg border border-warning/50 bg-background/95 p-4 shadow-lg backdrop-blur">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-warning">
          <ShieldAlert className="h-4 w-4" />
          {pending.length} tool call{pending.length > 1 ? "s" : ""} awaiting your approval
        </div>
        <ul className="space-y-2">
          {pending.map((a) => (
            <li key={a.id} className="rounded-md border border-border bg-card p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate font-mono text-sm">
                    {a.server}
                    <span className="text-muted-foreground"> · </span>
                    {a.tool}
                  </div>
                  <div className="mt-0.5 text-xs text-muted-foreground">
                    {a.client ? `${a.client} · ` : ""}
                    {REASON_LABEL[a.reason]}
                  </div>
                  <pre className="mt-2 max-h-32 overflow-auto rounded bg-muted p-2 text-xs">
                    {JSON.stringify(a.arguments, null, 2)}
                  </pre>
                </div>
                <div className="flex shrink-0 gap-2">
                  <button
                    disabled={busy === a.id}
                    onClick={() => void decide(a.id, true)}
                    className="inline-flex items-center gap-1 rounded-md bg-info px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
                  >
                    <Check className="h-3.5 w-3.5" /> Approve
                  </button>
                  <button
                    disabled={busy === a.id}
                    onClick={() => void decide(a.id, false)}
                    className="inline-flex items-center gap-1 rounded-md border border-border px-3 py-1.5 text-xs font-medium disabled:opacity-50"
                  >
                    <X className="h-3.5 w-3.5" /> Deny
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
