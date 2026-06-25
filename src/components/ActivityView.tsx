import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, ChevronRight, ScrollText, Share2, Sparkles, XCircle } from "lucide-react";
import { toast } from "sonner";
import { getAuditLog, getAuditStats, getSavingsSummary } from "@/lib/api";
import type { AuditEntry, AuditStats, SavingsSummary, ServerStat } from "@/lib/types";

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
      toast.success("Savings copied, paste it anywhere");
    } catch {
      toast.error("Couldn't copy to clipboard");
    }
  };

  return (
    <div className="mb-6 rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-4">
      <div className="flex items-center gap-2">
        <Sparkles className="size-4 text-emerald-400" />
        <span className="text-sm font-medium text-muted-foreground">
          What lazy discovery has saved you
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-end gap-x-6 gap-y-1">
        <span className="text-3xl font-semibold tabular-nums text-emerald-400">
          ≈ {fmtTokens(savings.tokensSaved)}{" "}
          <span className="text-base font-normal text-muted-foreground">tokens</span>
        </span>
        <span className="text-3xl font-semibold tabular-nums text-emerald-400">
          ≈ {fmtDollars(dollars)}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <select
          value={modelLabel}
          onChange={(e) => setModelLabel(e.target.value)}
          aria-label="Model for the dollar estimate"
          className="rounded-md border border-white/10 bg-black/20 px-2 py-1 text-xs text-muted-foreground"
        >
          {SAVINGS_MODELS.map((g) => (
            <optgroup key={g.group} label={g.group}>
              {g.items.map((m) => (
                <option key={m.label} value={m.label}>
                  at {m.label} (${m.price}/1M)
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        <button
          onClick={share}
          className="inline-flex items-center gap-1.5 rounded-md border border-white/10 px-2.5 py-1 text-xs text-muted-foreground transition hover:text-foreground"
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
          <span className="flex items-center gap-1.5">
            {expandable ? (
              <ChevronRight
                className={`size-3.5 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
              />
            ) : (
              <span className="inline-block size-3.5" />
            )}
            {s.server}
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
          <tr key={t.tool} className="border-b border-border/40 bg-muted/20 last:border-0">
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
          <div className="text-2xl font-semibold tabular-nums">{stats.total}</div>
          <div className="text-xs text-muted-foreground">calls logged</div>
        </div>
        <div className="rounded-lg border p-3">
          <div className="text-2xl font-semibold tabular-nums">{stats.errors}</div>
          <div className="text-xs text-muted-foreground">errors ({errPct}%)</div>
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
  const [errorsOnly, setErrorsOnly] = useState(false);

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
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  const banner =
    savings && savings.tokensSaved > 0 ? <SavingsBanner savings={savings} /> : null;

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

      <div className="mb-2 flex items-center gap-2">
        <select
          value={serverFilter}
          onChange={(e) => setServerFilter(e.target.value)}
          className="h-8 rounded-md border bg-background px-2 text-sm"
        >
          <option value="">All servers</option>
          {servers.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <button
          onClick={() => setErrorsOnly((v) => !v)}
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
            No calls match this filter.
          </p>
        ) : (
          visible.map((e, i) => (
            <div
              key={`${e.ts}-${e.server}-${e.tool}-${i}`}
              className="flex items-center gap-3 rounded-md border border-border/50 px-3 py-2 text-sm"
            >
              {e.ok ? (
                <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />
              ) : (
                <XCircle className="size-4 shrink-0 text-destructive" />
              )}
              <span className="font-medium">{e.server}</span>
              <span className="font-mono text-xs text-muted-foreground">{e.tool}</span>
              <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                {new Date(e.ts).toLocaleString()}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
