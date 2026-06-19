import { useEffect, useState } from "react";
import { CheckCircle2, ScrollText, XCircle } from "lucide-react";
import { getAuditLog } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";

export function ActivityView({ refreshKey }: { refreshKey: number }) {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);

  useEffect(() => {
    let alive = true;
    getAuditLog(200)
      .then((e) => alive && setEntries(e))
      .catch(() => alive && setEntries([]));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  if (entries && entries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
        <ScrollText className="size-10 text-muted-foreground/50" />
        <div>
          <p className="font-medium">No tool calls yet</p>
          <p className="max-w-md text-sm text-muted-foreground">
            Once a client runs a tool through Conduit, every call is recorded here
            — the audit trail behind the governance story.
          </p>
        </div>
      </div>
    );
  }

  return (
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
  );
}
