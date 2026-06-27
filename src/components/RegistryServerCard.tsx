import { Copy, LogIn, Pencil, Star, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { promoteToCatalog } from "@/lib/api";
import type { ProbeResult, Registry, ServerEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { TransportPill } from "@/components/TransportPill";
import { SecretsDialog } from "@/components/SecretsDialog";
import { ServerDialog } from "@/components/ServerDialog";

interface Props {
  server: ServerEntry;
  registry: Registry | null;
  enabled: boolean;
  busy?: boolean;
  health?: ProbeResult;
  /** True while a health probe is in flight (so we can show "Checking…"). */
  probing?: boolean;
  onToggle: (enabled: boolean) => void;
  onRemove: () => void;
  onRegistryChange: (registry: Registry) => void;
  /** Re-run the health probe (e.g. after authenticating). */
  onReprobe?: () => void;
}

type Status = "disabled" | "checking" | "connected" | "needs-auth" | "error";

function statusOf(enabled: boolean, _probing: boolean, health?: ProbeResult): Status {
  if (!enabled) return "disabled";
  // No probe result yet (loading, or queued behind an in-flight probe): show as
  // checking either way.
  if (!health) return "checking";
  if (health.ok) return "connected";
  if (health.authRequired) return "needs-auth";
  return "error";
}

const DOT: Record<Status, string> = {
  disabled: "bg-muted-foreground/40",
  checking: "bg-muted-foreground/40 animate-pulse",
  connected: "bg-emerald-400",
  "needs-auth": "bg-amber-400",
  error: "bg-destructive",
};


export function RegistryServerCard({
  registry,
  server,
  enabled,
  busy,
  health,
  probing,
  onToggle,
  onRemove,
  onRegistryChange,
  onReprobe,
}: Props) {
  const target =
    server.command !== null
      ? [server.command, ...server.args].join(" ")
      : (server.url ?? "");
  const secretCount = server.env.filter((e) => e.secret).length;
  const status = statusOf(enabled, !!probing, health);

  const label =
    status === "connected"
      ? `${health?.toolCount ?? 0} tools`
      : status === "needs-auth"
        ? "Needs sign-in"
        : status === "error"
          ? "Error"
          : status === "checking"
            ? "Checking…"
            : "Disabled";

  const existingNames = new Set(
    registry?.servers.map((s) => s.name.toLowerCase()) ?? [],
  );

  const baseName = server.name.replace(/\s\(\d+\)$/, "");

  let duplicateName = `${baseName} (2)`;
  let index = 2;

  while (existingNames.has(duplicateName.toLowerCase())) {
    index++;
    duplicateName = `${baseName} (${index})`;
  }          

  return (
    <Card
      className={`group gap-0 overflow-hidden transition-colors ${
        enabled ? "border-ring/40" : "opacity-70"
      }`}
    >
      <CardContent className="flex flex-col gap-3 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <Switch
              checked={enabled}
              disabled={busy}
              onCheckedChange={onToggle}
              aria-label={`Toggle ${server.name}`}
            />
            <h3 className="truncate font-medium tracking-tight">{server.name}</h3>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <StatusPill
              status={status}
              label={label}
              error={health?.error ?? null}
            />
            <TransportPill transport={server.transport} />
          </div>
        </div>

        {target && (
          <code className="block truncate rounded-md bg-muted px-2 py-1.5 font-mono text-xs text-muted-foreground">
            {target}
          </code>
        )}

        {status === "needs-auth" && (
          <SecretsDialog
            server={server}
            onSaved={onRegistryChange}
            onChanged={onReprobe}
            trigger={
              <Button size="sm" className="w-full">
                <LogIn className="size-4" />
                Authenticate
              </Button>
            }
          />
        )}

        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {server.source && (
            <span className="truncate">{server.source.replace("imported:", "from ")}</span>
          )}
          <div className="ml-auto flex items-center gap-1">
            {secretCount > 0 && <span>{secretCount}</span>}
            <button
              aria-label={`Add ${server.name} to catalog`}
              title="Add to your catalog"
              onClick={() =>
                promoteToCatalog(server.id)
                  .then(() =>
                    toast.success(`Added ${server.name} to your catalog`),
                  )
                  .catch((e) => toast.error(`${e}`))
              }
              className="rounded p-1 text-muted-foreground/60 opacity-0 transition group-hover:opacity-100 focus-visible:opacity-100 hover:bg-accent hover:text-foreground"
            >
              <Star className="size-3.5" />
            </button>
            <SecretsDialog
              server={server}
              onSaved={onRegistryChange}
              onChanged={onReprobe}
            />
            <ServerDialog
              onSaved={onRegistryChange}
              initial={{ ...server, name: duplicateName }}
              trigger={
                <button
                  aria-label={`Duplicate ${server.name}`}
                  title="Add another account"
                  className="rounded p-1 text-muted-foreground/60 opacity-0 transition group-hover:opacity-100 focus-visible:opacity-100 hover:bg-accent hover:text-foreground"
                >
                  <Copy className="size-3.5" />
                </button>
              }
            />
            <ServerDialog
              onSaved={onRegistryChange}
              editId={server.id}
              initial={server}
              trigger={
                <button
                  aria-label={`Edit ${server.name}`}
                  className="rounded p-1 text-muted-foreground/60 opacity-0 transition group-hover:opacity-100 focus-visible:opacity-100 hover:bg-accent hover:text-foreground"
                >
                  <Pencil className="size-3.5" />
                </button>
              }
            />
            <button
              onClick={onRemove}
              disabled={busy}
              aria-label={`Remove ${server.name}`}
              className="rounded p-1 text-muted-foreground/60 opacity-0 transition group-hover:opacity-100 focus-visible:opacity-100 hover:bg-destructive/10 hover:text-destructive"
            >
              <Trash2 className="size-3.5" />
            </button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatusPill({
  status,
  label,
  error,
}: {
  status: Status;
  label: string;
  error: string | null;
}) {
  const pill = (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <span className={`size-2 rounded-full ${DOT[status]}`} />
      {label}
    </span>
  );
  // Only the error state has extra detail worth a tooltip.
  if (status === "error" && error) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{pill}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <p className="text-xs text-amber-400">{error}</p>
        </TooltipContent>
      </Tooltip>
    );
  }
  return pill;
}
