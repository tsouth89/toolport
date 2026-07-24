import { useCallback, useEffect, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { listQuarantined, releaseQuarantine, type QuarantinedTool } from "@/lib/api";
import { toastError } from "@/lib/toast";
import { Button } from "@/components/ui/button";
import { fmtTs } from "@/lib/utils";

/** Matches the PendingApprovals cadence so the two attention surfaces feel equally live. */
const POLL_MS = 2000;

/** Stable identity for a quarantine entry. Profile-scoped: the same tool can be
 * blocked in one profile and fine in another. */
function entryKey(q: QuarantinedTool): string {
  return `${q.profile}\u0000${q.tool}`;
}

/** A signature for the whole set, so a dismissal can be scoped to exactly what was
 * on screen: dismissing "these two" must not also hide a third that appears later.
 *
 * Includes each entry's `ts`, which is load-bearing. Keyed on name alone, a tool that
 * was dismissed, later re-approved, and then drifted AGAIN would produce an identical
 * signature and stay hidden behind the old dismissal - silently suppressing a brand new
 * quarantine, which is the exact failure this surface exists to prevent. A fresh
 * quarantine gets a fresh timestamp. */
function setSignature(items: QuarantinedTool[]): string {
  return items
    .map((q) => `${entryKey(q)}@${q.ts}`)
    .sort()
    .join("|");
}

function whenLabel(ts: number): string {
  const mins = Math.floor((Date.now() - ts) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return fmtTs(ts, "date");
}

/**
 * Global alert for tools the integrity layer has blocked after a high-risk change.
 *
 * Before this existed the only signal was an agent call failing, and the only way to
 * act was to go hunting through Settings (SOU-293). It is mounted app-wide so the
 * state is visible wherever you are.
 *
 * Anchored BOTTOM-centre on purpose. `PendingApprovals` owns the top of the screen and
 * is genuinely time-critical (a held tool call with a countdown); a quarantine is
 * persistent and waits. Two top-anchored `z-50` cards would simply overlap.
 *
 * Deliberately NOT a one-click "allow": re-approving is accepting a supply-chain
 * change, so the reason stays the prominent element and the action reads as a
 * decision rather than a dismissal. Fast to find, deliberate to act on.
 */
export function QuarantineAlert({ onReview }: { onReview?: () => void }) {
  const [items, setItems] = useState<QuarantinedTool[]>([]);
  const [releasing, setReleasing] = useState<Set<string>>(new Set());
  const [dismissedFor, setDismissedFor] = useState<string | null>(null);
  // Monotonic request id: `release` refreshes while the interval may already have a poll
  // in flight, so an older response can land last and momentarily resurrect a tool the
  // user just re-approved. Only the newest request is allowed to write.
  const reqId = useRef(0);

  const refresh = useCallback(async () => {
    const id = ++reqId.current;
    try {
      const list = await listQuarantined();
      if (id === reqId.current) setItems(list);
    } catch {
      // Backend not up yet or a transient failure: keep the current list rather than
      // flashing empty, which would read as "all clear" when nothing was verified.
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(t);
  }, [refresh]);

  const signature = setSignature(items);
  const dismissed = dismissedFor !== null && dismissedFor === signature;

  async function release(q: QuarantinedTool) {
    const k = entryKey(q);
    setReleasing((s) => new Set(s).add(k));
    try {
      await releaseQuarantine(q.profile, q.tool);
      // Re-read rather than removing optimistically: the gateway reconciles the store
      // on its own tick, and the list is the authority on what is still blocked.
      await refresh();
    } catch (e) {
      toastError(`Couldn't re-approve ${q.tool}: ${e}`);
    } finally {
      setReleasing((s) => {
        const next = new Set(s);
        next.delete(k);
        return next;
      });
    }
  }

  if (items.length === 0 || dismissed) return null;

  const many = items.length > 1;

  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-0 z-40 flex justify-center px-4 pb-4">
      <div
        role="region"
        aria-label={`${items.length} tool${many ? "s" : ""} blocked after a high-risk change`}
        className="animate-in fade-in slide-in-from-bottom-2 pointer-events-auto relative w-full max-w-lg overflow-hidden rounded-xl border border-warning/40 bg-popover/95 shadow-2xl ring-1 ring-warning/10 backdrop-blur"
      >
        {/* Announced politely rather than moving focus. This card appears while you are
            working, so stealing focus would be hostile; it is a status surface, not a
            dialog, which is why it is a labelled region rather than an alertdialog. */}
        <div aria-live="polite" className="sr-only">
          {items.length} tool{many ? "s" : ""} blocked after a high-risk change.
        </div>
        <div className="flex items-start gap-2.5 border-b border-border/60 px-4 py-3">
          <ShieldAlert
            className="mt-0.5 size-4 shrink-0 text-warning"
            aria-hidden="true"
          />
          <div className="min-w-0">
            <p className="text-sm font-medium">
              {items.length} tool{many ? "s" : ""} blocked after a high-risk change
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Toolport hid {many ? "these" : "this"} from every client. Re-approve only if
              you expected the change.
            </p>
          </div>
        </div>

        <ul className="max-h-64 divide-y divide-border/60 overflow-y-auto">
          {items.map((q) => {
            const k = entryKey(q);
            const busy = releasing.has(k);
            return (
              <li key={k} className="flex items-start gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs">{q.tool}</p>
                  {/* The reason / detail is the point of the card, so it stays prominent:
                      it is what makes re-approving an informed decision instead of a
                      reflex. Prefer the concrete annotation delta when present (SOU-305). */}
                  <p className="mt-0.5 text-xs text-warning">
                    {q.detail ? q.detail : q.reason}
                  </p>
                  {q.detail ? (
                    <p className="mt-0.5 text-[11px] text-muted-foreground">{q.reason}</p>
                  ) : null}
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    {q.server}
                    {q.profile ? ` · ${q.profile}` : ""} · {whenLabel(q.ts)}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void release(q)}
                  className="shrink-0"
                >
                  {busy ? "Re-approving…" : "Re-approve"}
                </Button>
              </li>
            );
          })}
        </ul>

        <div className="flex items-center justify-end gap-2 border-t border-border/60 px-4 py-2.5">
          {onReview && (
            <Button size="sm" variant="ghost" onClick={onReview}>
              Review in Settings
            </Button>
          )}
          {/* Scoped to the current set, so a NEW quarantine re-opens the card rather
              than inheriting an earlier dismissal. */}
          <Button size="sm" variant="ghost" onClick={() => setDismissedFor(signature)}>
            Keep blocked
          </Button>
        </div>
      </div>
    </div>
  );
}
