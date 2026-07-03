import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { listen } from "@tauri-apps/api/event";
import { Check, Globe, Loader2, Monitor, ShieldAlert, Trash2, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { decideApproval, listPendingApprovals, type ApprovalScope } from "@/lib/api";
import type { PendingApproval } from "@/lib/types";
import { toastError } from "@/lib/toast";

/** Fail-closed window (must match approval::DEFAULT_TIMEOUT_SECS on the gateway). A
 * pending call that isn't decided within this is auto-denied, so we show a countdown. */
const TIMEOUT_MS = 120_000;

type Reason = PendingApproval["reason"];

/** How each gate reason presents: label, badge tone, and an icon. */
const REASON: Record<Reason, { label: string; className: string; Icon: typeof Trash2 }> = {
  destructive: {
    label: "Destructive",
    className: "bg-destructive/10 text-destructive",
    Icon: Trash2,
  },
  untrusted_source: {
    label: "Untrusted source",
    className: "bg-warning/15 text-warning",
    Icon: Globe,
  },
  destructive_and_untrusted: {
    label: "Destructive · untrusted",
    className: "bg-destructive/10 text-destructive",
    Icon: Trash2,
  },
};

/**
 * The human-in-the-loop approval queue: tool calls the gateway is holding until you
 * approve or deny them. The call BLOCKS on your decision, so this is mounted globally
 * (actionable from any view) and renders nothing when the queue is empty. It polls as a
 * safety net and refreshes immediately on the gateway's `approval-pending` /
 * `approval-resolved` events.
 */
export function PendingApprovals() {
  const [pending, setPending] = useState<PendingApproval[]>([]);
  // Ids with a decision in flight: shown dimmed + disabled, removed authoritatively by the
  // resolved event / poll (NOT optimistically), so a poll landing before the backend
  // reflects the decision can't flicker the row back looking un-decided.
  const [resolving, setResolving] = useState<Set<string>>(new Set());
  // Fallback only: first-sighting time per id, used to drive the countdown if a pending
  // entry ever lacks the broker's authoritative deadlineMs (older backend / transient).
  const seenAt = useRef<Map<string, number>>(new Map());
  const [now, setNow] = useState(() => Date.now());
  const dialogRef = useRef<HTMLDivElement>(null);
  const prevCount = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const list = await listPendingApprovals();
      setPending(list);
      // Prune resolving ids the backend has confirmed gone (authoritative removal).
      setResolving((s) => {
        const ids = new Set(list.map((p) => p.id));
        const next = new Set([...s].filter((id) => ids.has(id)));
        return next.size === s.size ? s : next;
      });
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

  // Tick once a second while anything is pending, to drive the countdown.
  useEffect(() => {
    if (pending.length === 0) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [pending.length]);

  // Record first-sighting for new ids; drop entries that are gone.
  useEffect(() => {
    const ids = new Set(pending.map((p) => p.id));
    const t = Date.now();
    for (const p of pending) if (!seenAt.current.has(p.id)) seenAt.current.set(p.id, t);
    for (const id of seenAt.current.keys()) if (!ids.has(id)) seenAt.current.delete(id);
  }, [pending]);

  const decide = async (id: string, approved: boolean, scope: ApprovalScope = "once") => {
    setResolving((s) => new Set(s).add(id));
    try {
      await decideApproval(id, approved, scope);
      // Intentionally NOT removed here — the approval-resolved event + poll remove it.
    } catch (e) {
      toastError(`Couldn't record your decision: ${e}`);
      setResolving((s) => {
        const n = new Set(s);
        n.delete(id);
        return n;
      });
      void refresh();
    }
  };

  // When the queue first appears, move focus into the dialog so keyboard / screen-reader
  // users are taken to the (fail-closed, time-boxed) decision instead of silently missing it.
  useEffect(() => {
    if (prevCount.current === 0 && pending.length > 0) dialogRef.current?.focus();
    prevCount.current = pending.length;
  }, [pending.length]);

  if (pending.length === 0) return null;

  // Escape denies the oldest still-pending item — a fail-safe keyboard shortcut (deny is
  // the safe direction; the agent just retries).
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      const first = pending.find((p) => !resolving.has(p.id));
      if (first) void decide(first.id, false);
    }
  };

  return (
    <div className="pointer-events-none fixed inset-x-0 top-0 z-50 flex justify-center px-4 pt-4">
      {/* Soft scrim to draw the eye without blocking the rest of the app. */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-40 bg-gradient-to-b from-background/70 to-transparent" />
      <div
        ref={dialogRef}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        role="alertdialog"
        aria-modal="false"
        aria-label="Tool calls awaiting your approval"
        className="animate-in fade-in slide-in-from-top-2 pointer-events-auto relative w-full max-w-lg overflow-hidden rounded-xl border border-warning/40 bg-popover/95 shadow-2xl ring-1 ring-warning/10 backdrop-blur outline-none focus-visible:ring-2 focus-visible:ring-warning"
      >
        {/* Announce count changes to screen readers without re-announcing on every countdown
         * tick (the visible timer lives elsewhere; this text only changes when the count does). */}
        <div aria-live="assertive" className="sr-only">
          {pending.length} tool call{pending.length > 1 ? "s" : ""} awaiting your approval. Press
          Escape to deny.
        </div>
        <header className="flex items-center gap-3 border-b border-border/60 px-4 py-3">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-warning/15 text-warning">
            <ShieldAlert className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="text-sm font-semibold leading-tight">Approval required</div>
            <div className="text-xs text-muted-foreground">
              {pending.length} tool call{pending.length > 1 ? "s" : ""} held — no decision auto-denies
            </div>
          </div>
        </header>

        <ul className="max-h-[70vh] divide-y divide-border/60 overflow-auto">
          {pending.map((a) => {
            const reason = REASON[a.reason];
            // Count down to the broker's authoritative deadline; fall back to
            // first-sighting + timeout only if deadlineMs is somehow absent, so the
            // timer is never blank.
            const deadline = a.deadlineMs || (seenAt.current.get(a.id) ?? now) + TIMEOUT_MS;
            const remaining = Math.max(0, Math.ceil((deadline - now) / 1000));
            const pct = Math.max(0, Math.min(100, (remaining / (TIMEOUT_MS / 1000)) * 100));
            const urgent = remaining <= 20;
            const isBusy = resolving.has(a.id);
            return (
              <li key={a.id} className="px-4 py-3.5">
                <div className="mb-2 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 font-mono text-sm">
                      <span className="truncate text-muted-foreground">{a.server}</span>
                      <span className="text-muted-foreground/50">/</span>
                      <span className="truncate font-medium text-foreground">{a.tool}</span>
                    </div>
                    {a.client && (
                      <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Monitor className="size-3" />
                        Requested by {a.client}
                      </div>
                    )}
                  </div>
                  <Badge className={reason.className}>
                    <reason.Icon className="size-3" />
                    {reason.label}
                  </Badge>
                </div>

                <div className="mb-3">
                  <div className="mb-1 text-[0.7rem] font-medium uppercase tracking-wide text-muted-foreground">
                    Arguments
                  </div>
                  <pre className="max-h-36 overflow-auto rounded-md border border-border/60 bg-muted/40 p-2.5 font-mono text-xs leading-relaxed">
                    {JSON.stringify(a.arguments, null, 2)}
                  </pre>
                </div>

                <div className="flex items-center justify-between gap-3">
                  <div
                    className={
                      "flex items-center gap-1.5 text-xs tabular-nums " +
                      (urgent ? "text-destructive" : "text-muted-foreground")
                    }
                  >
                    <span
                      aria-hidden
                      className="inline-block h-1 w-16 overflow-hidden rounded-full bg-border"
                    >
                      <span
                        className={
                          "block h-full rounded-full transition-[width] duration-1000 ease-linear " +
                          (urgent ? "bg-destructive" : "bg-warning")
                        }
                        style={{ width: `${pct}%` }}
                      />
                    </span>
                    {remaining}s left
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={isBusy}
                      onClick={() => void decide(a.id, false)}
                    >
                      {isBusy ? <Loader2 className="animate-spin" /> : <X />}
                      Deny
                    </Button>
                    <Button
                      size="sm"
                      disabled={isBusy}
                      onClick={() => void decide(a.id, true)}
                      className="bg-[color-mix(in_oklch,var(--success),black_16%)] text-white shadow-sm hover:bg-[color-mix(in_oklch,var(--success),black_26%)]"
                    >
                      {isBusy ? <Loader2 className="animate-spin" /> : <Check />}
                      Approve
                    </Button>
                  </div>
                </div>

                {/* Skip the prompt for this tool next time - curbs approval fatigue. */}
                <div className="mt-2 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-muted-foreground">
                  <span>Skip next time?</span>
                  <button
                    disabled={isBusy}
                    onClick={() => void decide(a.id, true, "session")}
                    className="font-medium text-foreground/80 underline-offset-2 hover:text-foreground hover:underline disabled:opacity-50"
                  >
                    Allow for this session
                  </button>
                  <span className="text-muted-foreground/40">·</span>
                  <button
                    disabled={isBusy}
                    onClick={() => void decide(a.id, true, "always")}
                    className="font-medium text-foreground/80 underline-offset-2 hover:text-foreground hover:underline disabled:opacity-50"
                  >
                    Always allow this tool
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
