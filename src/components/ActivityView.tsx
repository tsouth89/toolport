import { useEffect, useState } from "react";
import { CheckCircle2, ScrollText, XCircle } from "lucide-react";
import { getAuditLog, getAuditStats } from "@/lib/api";
import type { AuditEntry, AuditStats } from "@/lib/types";

/** Compact latency string: "180 ms" or "1.2 s", or a dash when unmeasured. */
function fmtMs(ms: number | null): string {
  if (ms == null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
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
              <tr key={s.server} className="border-b last:border-0">
                <td className="px-3 py-2 font-medium">{s.server}</td>
                <td className="px-3 py-2 text-right tabular-nums">{s.calls}</td>
                <td
                  className={`px-3 py-2 text-right tabular-nums ${
                    s.errors > 0 ? "text-destructive" : "text-muted-foreground"
                  }`}
                >
                  {s.errors > 0 ? `${(s.errorRate * 100).toFixed(0)}%` : "0"}
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
                  {fmtMs(s.avgMs)}
                </td>
                <td className="px-3 py-2 text-right tabular-nums text-muted-foreground">
                  {fmtMs(s.p95Ms)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function ActivityView({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);

  useEffect(() => {
    let alive = true;
    getAuditLog(200)
      .then((e) => alive && setEntries(e))
      .catch(() => alive && setEntries([]));
    getAuditStats(2000)
      .then((s) => alive && setStats(s))
      .catch(() => alive && setStats(null));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  if (entries === null) {
    return (
      <div className="flex items-center justify-center py-24 text-sm text-muted-foreground">
        Loading activity…
      </div>
    );
  }

  if (entries.length === 0) {
    return (
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
    );
  }

  return (
    <div>
      {stats && <StatsPanel stats={stats} />}
      <div className="flex flex-col gap-1">
      {(entries ?? []).map((e, i) => (
        <div
          key={i}
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
      ))}
      </div>
    </div>
  );
}
