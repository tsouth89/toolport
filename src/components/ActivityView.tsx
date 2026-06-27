import { useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  ChevronRight,
  ScrollText,
  Share2,
  ShieldAlert,
  Sparkles,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";
import {
  getAuditLog,
  getAuditStats,
  getSavingsSummary,
  getSecurityEvents,
  type SecurityEvent,
} from "@/lib/api";
import type {
  AuditEntry,
  AuditStats,
  SavingsSummary,
  ServerStat,
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

/** Compact token count: "1.84M", "23.4k", or the raw number when small. */
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return `${n}`;
}

/** Models for the dollar estimate, input-token list prices ($/1M), grouped by
 *  provider. Matches the public calculator at conduitmcp.app/calculator. */
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

/** Stable per-event key so a dismissal sticks across refreshes. */
function securityKey(e: SecurityEvent): string {
  return `${e.type}:${e.tool}:${e.ts}`;
}

function loadDismissed(): Set<string> {
  try {
    const raw = localStorage.getItem(SECURITY_DISMISSED_KEY);
    return new Set(raw ? (JSON.parse(raw) as string[]) : []);
  } catch {
    return new Set();
  }
}

/** Surfaces tool security events: a tool you approved changed (rug-pull signal),
 * a known server added one, a tool definition contains injection-like content
 * (poisoning), or a tool returned data that looks like injected instructions
 * (agentjacking, which Conduit labels as data before the agent sees it).
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
        <h3 className="text-sm font-medium text-warning">
          Tool security notices
        </h3>
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
            instruction-like content, or a tool returned data that looks like
            injected instructions. Usually benign, but it's how rug pulls, tool
            poisoning, and agentjacking work, so Conduit flags it (and labels
            suspicious tool output as data). Dismiss the ones you've reviewed.
          </p>
          <ul className="space-y-1.5 text-xs">
            {events.slice(0, 10).map((e, i) => {
              const badge = eventBadge(e);
              return (
                <li key={i} className="flex items-center gap-2">
                  <span
                    className={`rounded px-1.5 py-0.5 font-medium ${badge.cls}`}
                  >
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
                </li>
              );
            })}
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
    savings.peakCatalog > 3
      ? `biggest catalog collapsed ${savings.peakCatalog} tools to 3`
      : null,
    since ? `since ${since}` : null,
  ].filter(Boolean);

  const share = async () => {
    const text =
      `Conduit has saved me ~${fmtTokens(savings.tokensSaved)} tokens (~${fmtDollars(dollars)}) of MCP ` +
      `tool definitions so far. One local gateway for all my MCP servers, ~90% fewer tokens: conduitmcp.app`;
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Savings copied, paste them anywhere");
    } catch {
      toast.error("Couldn't copy to clipboard");
    }
  };

  return (
    <div className="mb-6 rounded-lg border border-success/30 bg-success/[0.06] p-4">
      <div className="flex items-center gap-2">
        <Sparkles className="size-4 text-success" />
        <span className="text-sm font-medium text-muted-foreground">
          What lazy discovery has saved you
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-end gap-x-6 gap-y-1">
        <span className="text-3xl font-semibold tabular-nums text-success">
          ≈ {fmtTokens(savings.tokensSaved)}{" "}
          <span className="text-base font-normal text-muted-foreground">
            tokens
          </span>
        </span>
        <span className="text-3xl font-semibold tabular-nums text-success">
          ≈ {fmtDollars(dollars)}
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
        {details.join(" · ")}. Estimated.
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

function StatsPanel({ stats }: { stats: AuditStats }) {
  if (stats.total === 0) return null;
  const errPct = (stats.errorRate * 100).toFixed(stats.errorRate < 0.1 ? 1 : 0);
  return (
    <div className="mb-6 flex flex-col gap-3">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">
            {stats.total}
          </div>
          <div className="text-xs text-muted-foreground">calls logged</div>
        </div>
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">
            {stats.errors}
          </div>
          <div className="text-xs text-muted-foreground">
            errors ({errPct}%)
          </div>
        </div>
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">
            {stats.servers.length}
          </div>
          <div className="text-xs text-muted-foreground">active servers</div>
        </div>
      </div>
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
    </div>
  );
}

export function ActivityView({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [savings, setSavings] = useState<SavingsSummary | null>(null);
  const [serverFilter, setServerFilter] = useState<string>("");
  const [errorsOnly, setErrorsOnly] = useState(true);
  const [security, setSecurity] = useState<SecurityEvent[]>([]);
  const [dismissed, setDismissed] = useState<Set<string>>(loadDismissed);
  const [logOpen, setLogOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    getAuditLog(200)
      .then((e) => alive && setEntries(e))
      .catch(() => alive && setEntries([]));
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

  const liveSecurity = security.filter((e) => !dismissed.has(securityKey(e)));
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

  const banner = (
    <>
      {liveSecurity.length > 0 && (
        <SecurityNotices events={liveSecurity} onDismiss={dismissSecurity} />
      )}
      {savings && savings.tokensSaved > 0 ? (
        <SavingsBanner savings={savings} />
      ) : null}
    </>
  );

  const servers = useMemo(
    () => [...new Set((entries ?? []).map((e) => e.server))].sort(),
    [entries],
  );

  const visible = (entries ?? []).filter(
    (e) =>
      (!serverFilter || e.server === serverFilter) && (!errorsOnly || !e.ok),
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

  if (entries.length === 0) {
    return (
      <div>
        {banner}
        <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
          <ScrollText className="size-10 text-muted-foreground/50" />
          <div>
            <p className="font-medium">No tool calls yet</p>
            <p className="max-w-md text-sm text-muted-foreground">
              Once a client runs a tool through Conduit, every call is recorded
              here, with per-server latency and error rates.
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
                <div
                  key={`${e.ts}-${e.server}-${e.tool}-${i}`}
                  className="flex items-center gap-3 rounded-md border border-border/50 px-3 py-2 text-sm"
                >
                  {e.ok ? (
                    <CheckCircle2 className="size-4 shrink-0 text-success" />
                  ) : (
                    <XCircle className="size-4 shrink-0 text-destructive" />
                  )}
                  <span className="min-w-0 truncate font-medium">
                    {e.server}
                  </span>
                  <span className="min-w-0 truncate font-mono text-xs text-muted-foreground">
                    {e.tool}
                  </span>
                  <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                    {new Date(e.ts).toLocaleString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
