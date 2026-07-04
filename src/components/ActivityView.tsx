import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Fingerprint,
  History,
  ScrollText,
  Search,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import { fmtTokens } from "@/lib/utils";
import { toastError } from "@/lib/toast";
import {
  getAuditLog,
  getAuditStats,
  getInspectLog,
  getSavingsSummary,
  getSearchTraces,
  getSecurityEvents,
  getToolIdentities,
  type SecurityEvent,
} from "@/lib/api";
import type {
  AuditEntry,
  AuditStats,
  InspectEntry,
  Registry,
  SavingsSummary,
  SearchTrace,
  ServerStat,
  ToolIdentity,
} from "@/lib/types";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** Compact latency string: "180 ms" or "1.2 s", or a dash when unmeasured. */
function fmtMs(ms: number | null): string {
  if (ms == null) return "-";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

/** Models for the dollar estimate, input-token list prices ($/1M), grouped by
 *  provider. Matches the public calculator at toolport.app/calculator. */
const SAVINGS_MODELS = [
  {
    group: "Anthropic",
    items: [
      { label: "Claude Opus", price: 5 },
      { label: "Claude Sonnet", price: 3 },
      { label: "Claude Haiku", price: 1 },
    ],
  },
  {
    group: "OpenAI",
    items: [
      { label: "GPT-5.5", price: 5 },
      { label: "GPT-5.4", price: 2.5 },
      { label: "GPT-5.4 mini", price: 0.75 },
    ],
  },
  {
    group: "Google",
    items: [
      { label: "Gemini 2.5 Pro", price: 1.25 },
      { label: "Gemini 2.5 Flash", price: 0.3 },
    ],
  },
];
const SAVINGS_MODEL_PRICE = new Map(
  SAVINGS_MODELS.flatMap((g) => g.items).map((m) => [m.label, m.price]),
);

/** Dollar value of saved input tokens, scaled to the number's size. */
function fmtDollars(n: number): string {
  if (n >= 1000) return `$${Math.round(n).toLocaleString()}`;
  if (n >= 10) return `$${n.toFixed(0)}`;
  return `$${n.toFixed(2)}`;
}

/** A badge describing one security event by kind. */
function eventBadge(e: SecurityEvent): { label: string; cls: string } {
  if (e.type === "result_injection") {
    return {
      label: "injected result",
      cls: "bg-destructive/15 text-destructive",
    };
  }
  if (e.type === "tool_poison_flag") {
    return {
      label: "suspicious content",
      cls: "bg-destructive/15 text-destructive",
    };
  }
  if (e.type === "pins_load_failed") {
    return {
      label: "integrity baseline lost",
      cls: "bg-destructive/15 text-destructive",
    };
  }
  if (e.change === "changed") {
    return { label: "changed", cls: "bg-warning/15 text-warning" };
  }
  return { label: "new tool", cls: "bg-owned/15 text-owned" };
}

const SECURITY_DISMISSED_KEY = "conduit.security.dismissed";

/** High-signal, interrupting events vs benign, quiet-history churn. The backend now
 * tags a `severity`; for events written before that (no field) we classify by type:
 * poison / injected-result / lost-baseline are high, a plain tool_drift is benign. */
function eventSeverity(e: SecurityEvent): "high" | "info" {
  if (e.severity === "high" || e.severity === "info") return e.severity;
  if (
    e.type === "tool_poison_flag" ||
    e.type === "result_injection" ||
    e.type === "pins_load_failed"
  ) {
    return "high";
  }
  return "info";
}

/** Durable per-event key for dismissal: identity (type, server, tool, change, severity),
 * NOT the timestamp. A benign drift that re-flags later (e.g. RevenueCat revising a beta
 * tool again) collapses to the same key, so dismissing it once keeps it dismissed instead
 * of returning as a brand-new, undismissable notice. Server + change are kept so tool-less
 * events (e.g. pins_load_failed) don't collide and dismiss each other. Severity is kept so
 * dismissing a tool's benign change never masks a later HIGH-severity change on that same
 * tool (e.g. it turns destructive) - that must still interrupt. */
function securityKey(e: SecurityEvent): string {
  return `${e.type}:${e.server ?? ""}:${e.tool ?? ""}:${e.change}:${eventSeverity(e)}`;
}

/** Unique React list key. `securityKey` is deliberately timestamp-free (so dismissal is
 * durable), but two un-collapsed instances of the same drift can be on screen at once,
 * so the render key still needs the timestamp to stay unique. */
function renderKey(e: SecurityEvent): string {
  return `${securityKey(e)}:${e.ts}`;
}

/** Each connected client runs its own gateway process, so a single server tool change
 * is flagged once PER client against the shared baseline, producing identical notices.
 * Collapse those: keep only the newest of any (type, server, tool, change, severity) seen
 * within a short window, so genuinely-separate changes over time are preserved. Severity
 * is part of the identity so a benign `info` revision can never collapse (and hide) a
 * later `high` one on the same tool - that loud signal must survive the dedupe. */
function dedupeSecurity(events: SecurityEvent[]): SecurityEvent[] {
  const WINDOW_MS = 10 * 60 * 1000;
  const newestFirst = [...events].sort((a, b) => b.ts - a.ts);
  const kept: SecurityEvent[] = [];
  for (const e of newestFirst) {
    const dupe = kept.some(
      (k) =>
        k.type === e.type &&
        k.server === e.server &&
        k.tool === e.tool &&
        k.change === e.change &&
        eventSeverity(k) === eventSeverity(e) &&
        Math.abs(k.ts - e.ts) <= WINDOW_MS,
    );
    if (!dupe) kept.push(e);
  }
  return kept;
}

function loadDismissed(): Set<string> {
  try {
    const raw = localStorage.getItem(SECURITY_DISMISSED_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

/** Calm, always-on "you're protected" state, shown whenever there are no live
 * security notices. A protection the user never sees builds no trust, so we make
 * the integrity + content-defense watch visible even when nothing is wrong. */
function SecurityResting() {
  return (
    <div className="mb-4 flex items-center gap-2 rounded-lg border border-border/60 bg-muted/30 px-4 py-2.5 text-xs text-muted-foreground">
      <ShieldCheck className="size-4 shrink-0 text-owned" />
      <span>
        <span className="font-medium text-foreground">Protection active.</span> Toolport
        watches every tool for tampering (rug pulls), poisoned definitions, and injected
        output (agentjacking). No issues right now.
      </span>
    </div>
  );
}

/** Surfaces tool security events: a tool you approved changed (rug-pull signal),
 * a known server added one, a tool definition contains injection-like content
 * (poisoning), or a tool returned data that looks like injected instructions
 * (agentjacking, which Toolport labels as data before the agent sees it).
 * Collapsible, and each notice can be dismissed once you've reviewed it. */
function SecurityNotices({
  events,
  onDismiss,
}: {
  events: SecurityEvent[];
  onDismiss: (e: SecurityEvent) => void;
}) {
  const [open, setOpen] = useState(true);
  return (
    <div className="mb-4 rounded-lg border border-warning/40 bg-warning/5 p-4">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 text-left"
      >
        <ShieldAlert className="size-4 shrink-0 text-warning" />
        <h3 className="text-sm font-medium text-warning">Tool security notices</h3>
        <span className="rounded-full bg-warning/15 px-1.5 py-0.5 text-xs font-medium text-warning">
          {events.length}
        </span>
        <ChevronRight
          className={`ml-auto size-4 text-warning/70 transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
      </button>
      {open && (
        <>
          <p className="mt-2 mb-3 max-w-2xl text-xs text-muted-foreground">
            A tool changed after you approved it, a tool's definition contains
            instruction-like content, or a tool returned data that looks like injected
            instructions. Usually benign, but it's how rug pulls, tool poisoning, and
            agentjacking work, so Toolport flags it (and labels suspicious tool output as
            data). Dismiss the ones you've reviewed.
          </p>
          <ul className="space-y-1.5 text-xs">
            {events.slice(0, 10).map((e) => {
              const badge = eventBadge(e);
              return (
                <li key={renderKey(e)} className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <span className={`rounded px-1.5 py-0.5 font-medium ${badge.cls}`}>
                      {badge.label}
                    </span>
                    <code className="font-mono text-foreground">{e.tool}</code>
                    {e.signatures && e.signatures.length > 0 && (
                      <span className="text-muted-foreground">
                        ({e.signatures.join(", ")})
                      </span>
                    )}
                    <span className="ml-auto text-muted-foreground">
                      {new Date(e.ts).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                    <button
                      onClick={() => onDismiss(e)}
                      aria-label="Dismiss this notice"
                      className="rounded p-0.5 text-muted-foreground/60 transition-colors hover:bg-warning/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-warning"
                    >
                      <X className="size-3.5" />
                    </button>
                  </div>
                  {e.evidence && (
                    <p className="ml-1 max-w-2xl border-l-2 border-warning/40 pl-2 font-mono text-[11px] leading-relaxed break-words text-muted-foreground">
                      matched: “{e.evidence}”
                    </p>
                  )}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}

/** A quiet, non-interrupting history of benign tool-definition churn: a
 * non-destructive tool's description or schema was revised with its safety hints
 * intact (vendors routinely revise beta tools server-side). Collapsed by default,
 * muted styling, no badge or warning color, it's viewable for the record, not an
 * alert. The loud, actionable signal (poison, destructive change, safety-annotation
 * downgrade) stays in SecurityNotices. Dismissal is durable per drift identity, so
 * clearing a recurring benign change keeps it quiet when the vendor churns it again. */
function QuietDriftHistory({
  events,
  onDismiss,
  onDismissAll,
}: {
  events: SecurityEvent[];
  onDismiss: (e: SecurityEvent) => void;
  onDismissAll: () => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-4 rounded-lg border border-border/60 bg-muted/20 p-3">
      <div className="flex w-full items-center gap-2 text-xs text-muted-foreground">
        <button
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="flex flex-1 items-center gap-2 text-left"
        >
          <History className="size-3.5 shrink-0" />
          <span className="font-medium text-foreground/80">New &amp; changed tools</span>
          <span className="rounded-full bg-muted px-1.5 py-0.5 font-medium">
            {events.length}
          </span>
          <ChevronRight
            className={`ml-auto size-3.5 transition-transform ${open ? "rotate-90" : ""}`}
          />
        </button>
        <button
          onClick={onDismissAll}
          className="shrink-0 rounded px-2 py-0.5 font-medium text-muted-foreground/70 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border"
        >
          Dismiss all
        </button>
      </div>
      {open && (
        <>
          <p className="mt-2 mb-2 max-w-2xl text-xs text-muted-foreground">
            New tools first seen, and benign, non-destructive changes to tools you've
            already approved (vendors revise beta tools server-side). Kept for the record,
            not flagged as a risk, the approval and destructive-tool gates still guard
            every call. Dismiss any you've reviewed.
          </p>
          <ul className="space-y-1 text-xs">
            {events.slice(0, 20).map((e) => (
              <li key={renderKey(e)} className="flex items-center gap-2">
                <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                  {e.change === "added" ? "new tool" : "changed"}
                </span>
                <code className="font-mono text-muted-foreground">{e.tool}</code>
                <span className="ml-auto text-muted-foreground/70">
                  {new Date(e.ts).toLocaleString(undefined, {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
                <button
                  onClick={() => onDismiss(e)}
                  aria-label="Dismiss this change"
                  className="rounded p-0.5 text-muted-foreground/50 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border"
                >
                  <X className="size-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/** Hero stat: tool-definition tokens (and dollars) lazy discovery kept out of
 *  agent context, with a one-click share so users can flex their savings. */
function SavingsBanner({ savings }: { savings: SavingsSummary }) {
  const [modelLabel, setModelLabel] = useState("Claude Sonnet");
  const price = SAVINGS_MODEL_PRICE.get(modelLabel) ?? 3;
  const dollars = (savings.tokensSaved / 1_000_000) * price;
  const since =
    savings.sinceTs > 0
      ? new Date(savings.sinceTs).toLocaleDateString(undefined, {
          month: "short",
          day: "numeric",
        })
      : null;
  const details = [
    `across ${savings.listLoads.toLocaleString()} tool-list load${savings.listLoads === 1 ? "" : "s"}`,
    savings.peakCatalog > 4
      ? `biggest catalog collapsed ${savings.peakCatalog} tools to a handful`
      : null,
    since ? `since ${since}` : null,
  ].filter(Boolean);

  const share = async () => {
    const text =
      `Toolport keeps ~${fmtTokens(savings.tokensSaved)} tokens of MCP tool definitions out of my agent's ` +
      `context so far. One local gateway for all my MCP servers: toolport.app`;
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Savings copied, paste them anywhere");
    } catch {
      toastError("Couldn't copy to clipboard");
    }
  };

  return (
    <div className="mb-6 rounded-lg border border-success/30 bg-success/[0.06] p-4">
      <div className="flex items-center gap-2">
        <Sparkles className="size-4 text-success" />
        <span className="text-sm font-medium text-muted-foreground">
          Tool definitions lazy discovery keeps out of context
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-end gap-x-6 gap-y-1">
        <span className="text-3xl font-semibold tabular-nums text-success">
          ≈ {fmtTokens(savings.tokensSaved)}{" "}
          <span className="text-base font-normal text-muted-foreground">tokens</span>
        </span>
        <span className="text-xl font-semibold tabular-nums text-muted-foreground">
          ≈ {fmtDollars(dollars)}
          <span className="ml-1 text-xs font-normal text-muted-foreground/70">
            illustrative
          </span>
        </span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Select value={modelLabel} onValueChange={setModelLabel}>
          <SelectTrigger
            aria-label="Model for the dollar estimate"
            className="h-7 w-fit gap-1.5 px-2 py-1 text-xs text-muted-foreground"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SAVINGS_MODELS.map((g) => (
              <SelectGroup key={g.group}>
                <SelectLabel>{g.group}</SelectLabel>
                {g.items.map((m) => (
                  <SelectItem key={m.label} value={m.label}>
                    at {m.label} (${m.price}/1M)
                  </SelectItem>
                ))}
              </SelectGroup>
            ))}
          </SelectContent>
        </Select>
        <button
          onClick={share}
          className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs text-muted-foreground transition hover:text-foreground"
        >
          <Share2 className="size-3.5" /> Share
        </button>
      </div>
      <p className="mt-2.5 text-xs text-muted-foreground">
        {details.join(" · ")}. Estimated, counted once per tool-list load. Clients with
        built-in tool search (Claude, VS Code) benefit less.
      </p>
    </div>
  );
}

function errCell(errors: number, errorRate: number) {
  return errors > 0 ? `${(errorRate * 100).toFixed(0)}%` : "0";
}

/** One server row that expands to reveal its per-tool breakdown. */
function ServerRow({ s }: { s: ServerStat }) {
  const [open, setOpen] = useState(false);
  const tools = s.tools ?? [];
  const expandable = tools.length > 0;
  return (
    <>
      <tr
        className={`border-b last:border-0 ${expandable ? "cursor-pointer hover:bg-muted/30" : ""}`}
        onClick={() => expandable && setOpen((o) => !o)}
      >
        <td className="px-3 py-2 font-medium">
          <span className="flex min-w-0 items-center gap-1.5">
            {expandable ? (
              <ChevronRight
                className={`size-3.5 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
              />
            ) : (
              <span className="inline-block size-3.5" />
            )}
            <span className="truncate">{s.server}</span>
          </span>
        </td>
        <td className="px-3 py-2 text-right tabular-nums">{s.calls}</td>
        <td
          className={`px-3 py-2 text-right tabular-nums ${
            s.errors > 0 ? "text-destructive" : "text-muted-foreground"
          }`}
        >
          {errCell(s.errors, s.errorRate)}
        </td>
        <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
          {fmtMs(s.avgMs)}
        </td>
        <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
          {fmtMs(s.p95Ms)}
        </td>
      </tr>
      {open &&
        tools.map((t) => (
          <tr
            key={t.tool}
            className="border-b border-border/40 bg-muted/20 last:border-0"
          >
            <td className="py-1.5 pr-3 pl-9 font-mono text-xs text-muted-foreground">
              {t.tool}
            </td>
            <td className="px-3 py-1.5 text-right text-xs tabular-nums text-muted-foreground">
              {t.calls}
            </td>
            <td
              className={`px-3 py-1.5 text-right text-xs tabular-nums ${
                t.errors > 0 ? "text-destructive" : "text-muted-foreground"
              }`}
            >
              {errCell(t.errors, t.errorRate)}
            </td>
            <td className="px-3 py-1.5 text-right text-xs tabular-nums text-muted-foreground">
              {fmtMs(t.avgMs)}
            </td>
            <td className="px-3 py-1.5 text-right text-xs tabular-nums text-muted-foreground">
              {fmtMs(t.p95Ms)}
            </td>
          </tr>
        ))}
    </>
  );
}

/** One recent-call row. A failed call with a captured error message expands to
 * show why it failed; latency is shown inline. Args/results aren't recorded in
 * the audit log (it's an append-only governance record), so they're not shown. */
function CallRow({ e }: { e: AuditEntry }) {
  const [open, setOpen] = useState(false);
  const hasDetail = !e.ok && !!e.error;
  return (
    <div className="rounded-md border border-border/50 text-sm">
      <div
        className={`flex items-center gap-3 px-3 py-2 ${
          hasDetail ? "cursor-pointer hover:bg-muted/30" : ""
        }`}
        onClick={() => hasDetail && setOpen((o) => !o)}
        {...(hasDetail ? { role: "button", "aria-expanded": open, tabIndex: 0 } : {})}
      >
        {hasDetail ? (
          <ChevronRight
            className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${
              open ? "rotate-90" : ""
            }`}
          />
        ) : (
          <span className="inline-block size-3.5 shrink-0" />
        )}
        {e.held ? (
          <ShieldAlert className="size-4 shrink-0 text-warning" />
        ) : e.ok ? (
          <CheckCircle2 className="size-4 shrink-0 text-success" />
        ) : (
          <XCircle className="size-4 shrink-0 text-destructive" />
        )}
        <span className="min-w-0 truncate font-medium">{e.server}</span>
        <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
          {e.tool}
        </span>
        {e.client && (
          <span
            className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground"
            title="Client that made this call"
          >
            {e.client}
          </span>
        )}
        <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">
          {fmtMs(e.durationMs ?? null)}
        </span>
        <span className="shrink-0 text-xs text-muted-foreground">
          {new Date(e.ts).toLocaleString()}
        </span>
      </div>
      {open && e.error && (
        <div className="border-t border-border/50 bg-destructive/5 px-3 py-2 pl-9">
          <p className="font-mono text-xs whitespace-pre-wrap break-words text-destructive">
            {e.error}
          </p>
        </div>
      )}
    </div>
  );
}

function StatsPanel({ stats }: { stats: AuditStats }) {
  // The three summary cards are the glanceable health check and stay visible; the full
  // per-server table (can be 20+ rows) collapses by default so it stops being a wall
  // below the security lane. It's one tap when you actually want the breakdown.
  const [tableOpen, setTableOpen] = useState(false);
  if (stats.total === 0) return null;
  const errPct = (stats.errorRate * 100).toFixed(stats.errorRate < 0.1 ? 1 : 0);
  return (
    <div className="mb-6 flex flex-col gap-3">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">{stats.total}</div>
          <div className="text-xs text-muted-foreground">calls logged</div>
        </div>
        <div
          className={`rounded-lg border p-3 ${stats.errors > 0 ? "border-destructive/40 bg-destructive/[0.04]" : ""}`}
        >
          <div
            className={`text-2xl font-semibold tabular-nums ${stats.errors > 0 ? "text-destructive" : ""}`}
          >
            {stats.errors}
          </div>
          <div className="text-xs text-muted-foreground">errors ({errPct}%)</div>
        </div>
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">
            {stats.servers.length}
          </div>
          <div className="text-xs text-muted-foreground">active servers</div>
        </div>
      </div>

      <button
        onClick={() => setTableOpen((v) => !v)}
        aria-expanded={tableOpen}
        className="flex w-fit items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <ChevronRight
          className={`size-4 transition-transform ${tableOpen ? "rotate-90" : ""}`}
        />
        Per-server breakdown
        <span className="text-xs font-normal text-muted-foreground/70">
          {stats.servers.length} {stats.servers.length === 1 ? "server" : "servers"}
        </span>
      </button>

      {tableOpen && (
        <>
          <div className="overflow-hidden rounded-lg border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-left text-xs text-muted-foreground">
                  <th className="px-3 py-2 font-medium">Server</th>
                  <th className="px-3 py-2 text-right font-medium">Calls</th>
                  <th className="px-3 py-2 text-right font-medium">Errors</th>
                  <th className="px-3 py-2 text-right font-medium">Avg</th>
                  <th className="px-3 py-2 text-right font-medium">p95</th>
                </tr>
              </thead>
              <tbody>
                {stats.servers.map((s) => (
                  <ServerRow key={s.server} s={s} />
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground/70">
            Click a server to see its per-tool breakdown.
          </p>
        </>
      )}
    </div>
  );
}

/** Pretty-print a captured body. A truncation marker (a plain string like
 * "<truncated N bytes>") is shown as-is; everything else is JSON-formatted. */
function fmtBody(v: unknown): string {
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

/** One captured call. Expands to show the pretty-printed request + response JSON. */
function InspectRow({ e }: { e: InspectEntry }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-md border border-border/50 text-sm">
      <div
        className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/30"
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
        tabIndex={0}
      >
        <ChevronRight
          className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
        {e.ok ? (
          <CheckCircle2 className="size-4 shrink-0 text-success" />
        ) : (
          <XCircle className="size-4 shrink-0 text-destructive" />
        )}
        <span className="min-w-0 truncate font-medium">{e.server}</span>
        <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
          {e.tool}
        </span>
        {e.client && (
          <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
            {e.client}
          </span>
        )}
        <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">
          {fmtMs(e.durationMs ?? null)}
        </span>
        <span className="shrink-0 text-xs text-muted-foreground">
          {new Date(e.ts).toLocaleTimeString()}
        </span>
      </div>
      {open && (
        <div className="border-t border-border/50 bg-muted/20 px-3 py-2 pl-9">
          <div className="mb-1 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
            Request
          </div>
          <pre className="mb-3 overflow-x-auto rounded bg-background/60 p-2 font-mono text-xs whitespace-pre-wrap break-words">
            {fmtBody(e.request)}
          </pre>
          <div className="mb-1 text-[11px] font-medium tracking-wide text-muted-foreground uppercase">
            Response
          </div>
          <pre className="overflow-x-auto rounded bg-background/60 p-2 font-mono text-xs whitespace-pre-wrap break-words">
            {fmtBody(e.response)}
          </pre>
        </div>
      )}
    </div>
  );
}

/** One recorded search: the query, what matched, and how much tool-definition context
 * this search put into the model vs. loading the whole catalog. Expands to the full
 * list of returned tool names. */
function DiscoveryRow({ t }: { t: SearchTrace }) {
  const [open, setOpen] = useState(false);
  const pct = t.flatTokens > 0 ? Math.round((t.savedTokens / t.flatTokens) * 100) : 0;
  const hit = t.returned > 0;
  return (
    <div className="rounded-md border border-border/50 text-sm">
      <div
        className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/30"
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
        tabIndex={0}
      >
        <ChevronRight
          className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
        <Search className="size-4 shrink-0 text-owned" />
        <span className="min-w-0 truncate font-mono text-xs">
          &ldquo;{t.query || "(empty)"}&rdquo;
        </span>
        {t.client && (
          <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
            {t.client}
          </span>
        )}
        {t.escalated && (
          <span className="shrink-0 rounded bg-warning/15 px-1.5 py-0.5 text-[11px] text-warning">
            loop-broken
          </span>
        )}
        {t.mode === "semantic" && (
          <span className="shrink-0 rounded bg-owned/10 px-1.5 py-0.5 text-[11px] text-owned">
            semantic
          </span>
        )}
        <span className="ml-auto shrink-0 text-xs tabular-nums text-muted-foreground">
          {hit ? `${t.returned} of ${t.total}` : "no match"}
        </span>
        <span className="shrink-0 text-xs text-muted-foreground">
          {new Date(t.ts).toLocaleTimeString()}
        </span>
      </div>
      {open && (
        <div className="border-t border-border/50 bg-muted/20 px-3 py-2 pl-9 text-xs">
          {hit ? (
            t.ranking && t.ranking.length > 0 ? (
              <div className="mb-2 space-y-1">
                {t.ranking.map((r) => (
                  <div key={r.name} className="flex items-baseline gap-2">
                    <span className="w-5 shrink-0 text-right tabular-nums text-[11px] text-muted-foreground">
                      #{r.rank}
                    </span>
                    <span
                      className={`shrink-0 font-mono text-[11px] ${
                        r.name === t.top ? "text-owned" : "text-foreground"
                      }`}
                    >
                      {r.name}
                    </span>
                    <span className="min-w-0 truncate text-[11px] text-muted-foreground">
                      {r.pinned
                        ? "pinned prerequisite"
                        : r.matched.length > 0
                          ? `matched ${r.matched.join(", ")}`
                          : t.mode === "semantic"
                            ? "semantic match"
                            : "—"}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mb-2 flex flex-wrap gap-1">
                {t.names.map((n) => (
                  <span
                    key={n}
                    className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${
                      n === t.top
                        ? "bg-owned/15 text-owned"
                        : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {n}
                  </span>
                ))}
              </div>
            )
          ) : (
            <div className="mb-2 text-muted-foreground">No tools matched this query.</div>
          )}
          <div className="text-muted-foreground">
            Put{" "}
            <span className="font-medium text-foreground">
              ≈{fmtTokens(t.returnedTokens)}
            </span>{" "}
            tokens of tool schemas into context, vs{" "}
            <span className="font-medium text-foreground">
              ≈{fmtTokens(t.flatTokens)}
            </span>{" "}
            to load the whole catalog
            {t.flatTokens > 0 ? <> ({pct}% less this turn).</> : "."}
          </div>
        </div>
      )}
    </div>
  );
}

/** Collapsible discovery panel: the in-path proof that lazy discovery is working.
 * Lists recent toolport_search_tools calls with what matched and the exact per-turn
 * tool-definition token overhead. Self-hides until something has searched. Always-on,
 * local, bounded. */
function DiscoveryTraces({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<SearchTrace[]>([]);
  // Collapsed by default: this is glanceable telemetry, not an alert, and the list can run
  // to 100 rows. Leading with it open was a big part of the Activity tab feeling busy.
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    getSearchTraces(100)
      .then((e) => alive && setEntries(e))
      .catch(() => alive && setEntries([]));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  if (entries.length === 0)
    return (
      <div className="mb-6 rounded-lg border border-border/60 bg-muted/20 p-4 text-xs text-muted-foreground">
        <div className="mb-1 flex items-center gap-2">
          <Search className="size-4 shrink-0 text-owned" />
          <span className="font-medium text-foreground/80">Discovery</span>
        </div>
        With lazy discovery on, this shows every tool search your agents run, what
        matched, why it ranked, and the context tokens it kept out of the model. Nothing
        searched yet.
      </div>
    );

  return (
    <div className="mb-6 rounded-lg border border-owned/30 bg-owned/[0.04] p-4">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 text-left"
      >
        <Search className="size-4 shrink-0 text-owned" />
        <h3 className="text-sm font-medium">Discovery</h3>
        <span className="rounded-full bg-owned/15 px-1.5 py-0.5 text-xs font-medium text-owned">
          {entries.length}
        </span>
        <ChevronRight
          className={`ml-auto size-4 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
      </button>
      {open && (
        <>
          <p className="mt-2 mb-3 max-w-2xl text-xs text-muted-foreground">
            What the model searched for and what Toolport handed back. Each search returns
            only the matching tools, so just those schemas enter context instead of every
            tool on every turn. Match counts are exact; token figures are an ≈ estimate.
            Local and bounded: tool names only, never arguments or results.
          </p>
          <div className="flex flex-col gap-1">
            {entries.map((t, i) => (
              <DiscoveryRow key={`${t.ts}-${i}`} t={t} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/** One tool's identity card: the model-visible alias joined to its source server +
 * profiles, with the pinned definition fingerprint and first-seen / last-changed. */
function ToolIdentityRow({ t }: { t: ToolIdentity }) {
  const [open, setOpen] = useState(false);
  const fpShort = t.fingerprint.replace(/^v\d+:/, "").slice(0, 12) || "-";
  const fmtDate = (ms: number) => (ms > 0 ? new Date(ms).toLocaleDateString() : "-");
  return (
    <div className="rounded-md border border-border/50 text-sm">
      <div
        className="flex cursor-pointer items-center gap-3 px-3 py-2 hover:bg-muted/30"
        onClick={() => setOpen((o) => !o)}
        role="button"
        aria-expanded={open}
        tabIndex={0}
      >
        <ChevronRight
          className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
        <span className="min-w-0 truncate font-mono text-xs">{t.alias}</span>
        <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
          {t.serverName || t.serverId || "unattributed"}
        </span>
        {t.quarantined && (
          <span className="shrink-0 rounded bg-warning/15 px-1.5 py-0.5 text-[11px] text-warning">
            quarantined
          </span>
        )}
        <span
          className="ml-auto shrink-0 font-mono text-[11px] text-muted-foreground"
          title={t.fingerprint}
        >
          {fpShort}
        </span>
      </div>
      {open && (
        <div className="border-t border-border/50 bg-muted/20 px-3 py-2 pl-9 text-xs">
          <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1">
            <dt className="text-muted-foreground">Upstream tool</dt>
            <dd className="font-mono break-all">{t.upstream || "-"}</dd>
            <dt className="text-muted-foreground">Source server</dt>
            <dd>{t.serverName ? `${t.serverName} (${t.serverId})` : "unattributed"}</dd>
            <dt className="text-muted-foreground">Profiles</dt>
            <dd>{t.profiles.length ? t.profiles.join(", ") : "-"}</dd>
            <dt className="text-muted-foreground">Fingerprint</dt>
            <dd className="font-mono break-all">{t.fingerprint || "-"}</dd>
            {t.firstSeen > 0 ? (
              <>
                <dt className="text-muted-foreground">First seen</dt>
                <dd>{fmtDate(t.firstSeen)}</dd>
                <dt className="text-muted-foreground">Last changed</dt>
                <dd>{fmtDate(t.lastChanged)}</dd>
              </>
            ) : (
              <>
                <dt className="text-muted-foreground">History</dt>
                <dd className="text-muted-foreground/80">
                  Turn on integrity checking in Settings to track when this tool was first
                  seen and when it last changed.
                </dd>
              </>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}

/** Collapsible capability-provenance panel: every pinned tool's identity, so a human
 * can verify which server/profile an alias maps to and whether its definition drifted.
 * Self-hides until the gateway has pinned a baseline. */
function ToolIdentities({ refreshKey }: { refreshKey: number }) {
  const [rows, setRows] = useState<ToolIdentity[]>([]);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    getToolIdentities()
      .then((r) => alive && setRows(r))
      .catch(() => alive && setRows([]));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  if (rows.length === 0) return null;

  return (
    <div className="mb-6 rounded-lg border border-border/60 bg-muted/[0.04] p-4">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 text-left"
      >
        <Fingerprint className="size-4 shrink-0 text-muted-foreground" />
        <h3 className="text-sm font-medium">Tool identities</h3>
        <span className="rounded-full bg-muted px-1.5 py-0.5 text-xs font-medium text-muted-foreground">
          {rows.length}
        </span>
        <ChevronRight
          className={`ml-auto size-4 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
      </button>
      {open && (
        <>
          <p className="mt-2 mb-3 max-w-2xl text-xs text-muted-foreground">
            What each model-visible tool name actually maps to: its source server and
            profiles, the pinned definition fingerprint drift detection checks against,
            and when it was first seen or last changed. Prefixing helps the model pick a
            tool; this helps you verify what crossed the boundary.
          </p>
          <div className="flex flex-col gap-1">
            {rows.map((t) => (
              <ToolIdentityRow key={t.alias} t={t} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

/** Collapsible live inspector: a local "network tab" for MCP. Only rendered while
 * live inspection is on. Lists recent captured calls, each expandable to its raw
 * request + response JSON. Ephemeral, local, opt-in. */
function LiveInspector({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<InspectEntry[]>([]);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    let alive = true;
    getInspectLog(50)
      .then((e) => alive && setEntries(e))
      .catch(() => alive && setEntries([]));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  return (
    <div className="mb-6 rounded-lg border border-info/30 bg-info/[0.04] p-4">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 text-left"
      >
        <Activity className="size-4 shrink-0 text-info" />
        <h3 className="text-sm font-medium">Live inspector</h3>
        <span className="rounded-full bg-info/15 px-1.5 py-0.5 text-xs font-medium text-info">
          {entries.length}
        </span>
        <ChevronRight
          className={`ml-auto size-4 text-muted-foreground transition-transform ${
            open ? "rotate-90" : ""
          }`}
        />
      </button>
      {open && (
        <>
          <p className="mt-2 mb-3 max-w-2xl text-xs text-muted-foreground">
            Ephemeral, local, opt-in. While live inspection is on, Toolport keeps the last
            50 tool calls' arguments and results here so you can inspect them. This buffer
            is separate from the audit log, never leaves your machine, and clears when you
            turn inspection off or restart the gateway.
          </p>
          {entries.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No calls captured yet. Run a tool through Toolport and it'll show here.
            </p>
          ) : (
            <div className="flex flex-col gap-1">
              {entries.map((e, i) => (
                <InspectRow key={`${e.ts}-${e.server}-${e.tool}-${i}`} e={e} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export function ActivityView({
  refreshKey,
  registry,
}: {
  refreshKey: number;
  registry: Registry | null;
}) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [savings, setSavings] = useState<SavingsSummary | null>(null);
  const [serverFilter, setServerFilter] = useState<string>("");
  // Show ALL recent calls by default, not a pre-filtered errors-only view. Defaulting the
  // filter on made a healthy log read as "everything is failing"; the StatsPanel already
  // surfaces the true error rate, and the toggle is right there for triage.
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [security, setSecurity] = useState<SecurityEvent[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(loadDismissed);
  const [logOpen, setLogOpen] = useState(false);
  // Distinguish a load FAILURE (gateway unreachable / audit log unreadable) from a
  // genuinely empty log: both leave `entries` empty, but only one is an error. Without
  // this, a first-run backend failure renders the friendly "No tool calls yet" state
  // and hides that anything is wrong.
  const [loadError, setLoadError] = useState(false);

  useEffect(() => {
    let alive = true;
    getAuditLog(200)
      .then((e) => {
        if (!alive) return;
        setEntries(e);
        setLoadError(false);
      })
      .catch(() => {
        if (!alive) return;
        setEntries([]);
        setLoadError(true);
      });
    getAuditStats(2000)
      .then((s) => alive && setStats(s))
      .catch(() => alive && setStats(null));
    getSavingsSummary()
      .then((s) => alive && setSavings(s))
      .catch(() => alive && setSavings(null));
    getSecurityEvents(50)
      .then((s) => alive && setSecurity(s))
      .catch(() => alive && setSecurity([]));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  const liveSecurity = dedupeSecurity(security).filter(
    (e) => !dismissed.has(securityKey(e)),
  );
  // Split loud/actionable signal from benign churn so vendor revisions don't bury a real
  // poison or privilege-escalation flag (the failure this whole surface exists to avoid).
  //
  // A tool FIRST APPEARING is inventory, not a rug-pull: you never approved it, so it
  // can't have changed under you, and the destructive-tool + approval gates still guard
  // the actual call. So "added" always goes to the quiet lane, even when the new tool is
  // destructive (e.g. a server exposing `delete_*`). That keeps a bulk first-baseline
  // from masquerading as a wall of alarms. The loud lane stays for what genuinely needs
  // a human: poison, injected results, and a tool you already approved CHANGING.
  const isNewTool = (e: SecurityEvent) =>
    e.change === "added" &&
    e.type !== "tool_poison_flag" &&
    e.type !== "result_injection";
  const highSecurity = liveSecurity.filter(
    (e) => eventSeverity(e) === "high" && !isNewTool(e),
  );
  const infoSecurity = liveSecurity.filter(
    (e) => eventSeverity(e) !== "high" || isNewTool(e),
  );
  const dismissSecurity = (e: SecurityEvent) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(securityKey(e));
      try {
        localStorage.setItem(SECURITY_DISMISSED_KEY, JSON.stringify([...next]));
      } catch {
        // ignore storage failures; the dismissal just won't persist
      }
      return next;
    });
  };
  // Clear a whole batch at once (the quiet lane can hold dozens of first-sightings after
  // a re-baseline; making the user dismiss each would just recreate the noise problem).
  const dismissAllSecurity = (events: SecurityEvent[]) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      for (const e of events) next.add(securityKey(e));
      try {
        localStorage.setItem(SECURITY_DISMISSED_KEY, JSON.stringify([...next]));
      } catch {
        // ignore storage failures; the dismissal just won't persist
      }
      return next;
    });
  };

  const banner = (
    <>
      {/* Loud lane: the only thing here that may need a decision. */}
      {highSecurity.length > 0 ? (
        <SecurityNotices events={highSecurity} onDismiss={dismissSecurity} />
      ) : (
        <SecurityResting />
      )}
      {infoSecurity.length > 0 ? (
        <QuietDriftHistory
          events={infoSecurity}
          onDismiss={dismissSecurity}
          onDismissAll={() => dismissAllSecurity(infoSecurity)}
        />
      ) : null}
      {/* Calm lane: lead with the value stat people actually want to see, then keep the
          reference panels (discovery / identities / inspector) collapsed below it so they
          don't stack into a wall on first load. */}
      {savings && savings.tokensSaved > 0 ? <SavingsBanner savings={savings} /> : null}
      <DiscoveryTraces refreshKey={refreshKey} />
      <ToolIdentities refreshKey={refreshKey} />
      {registry?.liveInspect ? <LiveInspector refreshKey={refreshKey} /> : null}
    </>
  );

  const servers = useMemo(
    () => [...new Set((entries ?? []).map((e) => e.server))].sort(),
    [entries],
  );

  const visible = (entries ?? []).filter(
    (e) => (!serverFilter || e.server === serverFilter) && (!errorsOnly || !e.ok),
  );

  if (entries === null) {
    return (
      <div>
        {banner}
        <div className="flex items-center justify-center py-24 text-sm text-muted-foreground">
          Loading activity…
        </div>
      </div>
    );
  }

  if (loadError && entries.length === 0) {
    return (
      <div>
        {banner}
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
          <AlertTriangle className="size-10 text-destructive/70" />
          <div>
            <p className="font-medium">Couldn't load activity</p>
            <p className="max-w-md text-sm text-muted-foreground">
              Toolport couldn't reach the gateway or read the audit log. This is not an
              empty log, if the gateway isn't running, start it and refresh.
            </p>
          </div>
        </div>
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <div>
        {banner}
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
          <ScrollText className="size-10 text-muted-foreground/50" />
          <div>
            <p className="font-medium">No tool calls yet</p>
            <p className="max-w-md text-sm text-muted-foreground">
              Once a client runs a tool through Toolport, every call is recorded here,
              with per-server latency and error rates.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      {banner}
      {stats && <StatsPanel stats={stats} />}

      <button
        onClick={() => setLogOpen((v) => !v)}
        aria-expanded={logOpen}
        className="mb-2 flex w-full items-center gap-2 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
      >
        <ChevronRight
          className={`size-4 transition-transform ${logOpen ? "rotate-90" : ""}`}
        />
        Recent calls
        <span className="text-xs font-normal text-muted-foreground/70">
          last {entries.length} {entries.length === 1 ? "call" : "calls"}
        </span>
      </button>

      {logOpen && (
        <>
          <div className="mb-2 flex items-center gap-2">
            <Select
              value={serverFilter || "all"}
              onValueChange={(v) => setServerFilter(v === "all" ? "" : v)}
            >
              <SelectTrigger className="h-8 w-fit gap-1.5 text-sm">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All servers</SelectItem>
                {servers.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <button
              onClick={() => setErrorsOnly((v) => !v)}
              aria-pressed={errorsOnly}
              className={`h-8 rounded-md border px-2.5 text-sm transition-colors ${
                errorsOnly
                  ? "border-destructive/50 bg-destructive/10 text-destructive"
                  : "text-muted-foreground hover:bg-accent"
              }`}
            >
              Errors only
            </button>
            <span className="ml-auto text-xs text-muted-foreground">
              {visible.length} of {entries.length}
            </span>
          </div>

          <div className="flex flex-col gap-1">
            {visible.length === 0 ? (
              <p className="py-12 text-center text-sm text-muted-foreground">
                {errorsOnly && !serverFilter
                  ? `No errors in the last ${entries.length} calls.`
                  : "No calls match this filter."}
              </p>
            ) : (
              visible.map((e, i) => (
                <CallRow key={`${e.ts}-${e.server}-${e.tool}-${i}`} e={e} />
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
