import { useState } from "react";
import {
  ChevronDown,
  Copy,
  KeyRound,
  LogIn,
  Pencil,
  Star,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import { promoteToCatalog } from "@/lib/api";
import type { ProbeResult, Registry, ServerEntry } from "@/lib/types";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { TransportPill } from "@/components/TransportPill";
import { SecretsDialog } from "@/components/SecretsDialog";
import { ServerDialog } from "@/components/ServerDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";

interface Props {
  server: ServerEntry;
  registry: Registry | null;
  enabled: boolean;
  busy?: boolean;
  health?: ProbeResult;
  onToggle: (enabled: boolean) => void;
  onRemove: () => void;
  onRegistryChange: (registry: Registry) => void;
  /** Re-run the health probe (e.g. after authenticating). */
  onReprobe?: () => void;
}

type Status = "disabled" | "checking" | "connected" | "needs-auth" | "error";

function statusOf(enabled: boolean, health?: ProbeResult): Status {
  if (!enabled) return "disabled";
  // No probe result yet (loading, or queued behind an in-flight probe): checking.
  if (!health) return "checking";
  if (health.ok) return "connected";
  if (health.authRequired) return "needs-auth";
  return "error";
}

const DOT: Record<Status, string> = {
  disabled: "bg-muted-foreground/40",
  checking: "bg-muted-foreground/40 animate-pulse",
  connected: "bg-success",
  "needs-auth": "bg-warning",
  error: "bg-destructive",
};

const ACTION =
  "inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

export function RegistryServerRow({
  registry,
  server,
  enabled,
  busy,
  health,
  onToggle,
  onRemove,
  onRegistryChange,
  onReprobe,
}: Props) {
  const [expanded, setExpanded] = useState(false);

  const target =
    server.command !== null
      ? [server.command, ...server.args].join(" ")
      : (server.url ?? "");
  const secretCount = server.env.filter((e) => e.secret).length;
  const status = statusOf(enabled, health);

  const label =
    status === "connected"
      ? `${health?.toolCount ?? 0} tool${health?.toolCount === 1 ? "" : "s"}`
      : status === "error"
        ? "Error"
        : status === "checking"
          ? "Checking…"
          : "Disabled";

  // Next free "Name (N)" for the duplicate-for-another-account action.
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

  const stop = (e: { stopPropagation: () => void }) => e.stopPropagation();

  return (
    <div
      className={`border-b border-border/60 last:border-b-0 ${enabled ? "" : "opacity-60"}`}
    >
      {/* Mouse users can click anywhere on the row to expand. Keyboard and screen
          reader users use the chevron button at the end. The row itself is not a
          button, so the toggle and Authenticate controls aren't nested inside one. */}
      <div
        onClick={() => setExpanded((v) => !v)}
        className="flex cursor-pointer items-center gap-3 px-3.5 py-2 transition-colors hover:bg-accent/40"
      >
        <span className="flex items-center" onClick={stop}>
          <Switch
            checked={enabled}
            disabled={busy}
            onCheckedChange={onToggle}
            aria-label={`Toggle ${server.name}`}
          />
        </span>

        <span
          className={`size-2 shrink-0 rounded-full ${DOT[status]}`}
          aria-hidden="true"
        />

        <span className="min-w-0 truncate text-sm font-medium">
          {server.name}
        </span>

        {server.source && (
          <span className="hidden max-w-40 shrink-0 truncate rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground md:inline">
            {server.source.replace("imported:", "from ")}
          </span>
        )}

        <span className="ml-auto flex shrink-0 items-center gap-2.5">
          {status === "needs-auth" ? (
            <SecretsDialog
              server={server}
              onSaved={onRegistryChange}
              onChanged={onReprobe}
              trigger={
                <button
                  onClick={stop}
                  className="inline-flex items-center gap-1.5 rounded-md border border-warning/40 px-2.5 py-1 text-xs text-warning transition-colors hover:bg-warning/10 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-warning"
                >
                  <LogIn className="size-3.5" />
                  Authenticate
                </button>
              }
            />
          ) : (
            <StatusLabel
              status={status}
              label={label}
              error={health?.error ?? null}
            />
          )}

          <TransportPill transport={server.transport} />

          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded((v) => !v);
            }}
            aria-expanded={expanded}
            aria-label={
              expanded
                ? `Hide ${server.name} details`
                : `Show ${server.name} details`
            }
            className="rounded p-0.5 text-muted-foreground/50 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            <ChevronDown
              className={`size-4 transition-transform ${
                expanded ? "rotate-180" : ""
              }`}
              aria-hidden="true"
            />
          </button>
        </span>
      </div>

      {expanded && (
        <div className="flex flex-col gap-2.5 px-3.5 pt-0.5 pb-3 pl-12">
          {target && (
            <code className="block rounded-md bg-muted px-2 py-1.5 font-mono text-xs break-all text-muted-foreground">
              {target}
            </code>
          )}
          {status === "error" && health?.error && (
            <p className="text-xs text-warning">{health.error}</p>
          )}

          <div className="flex flex-wrap items-center gap-1">
            <button
              className={ACTION}
              onClick={() =>
                promoteToCatalog(server.id)
                  .then(() =>
                    toast.success(`Added ${server.name} to your catalog`),
                  )
                  .catch((e) => toastError(`${e}`))
              }
            >
              <Star className="size-3.5" />
              Add to catalog
            </button>

            <SecretsDialog
              server={server}
              onSaved={onRegistryChange}
              onChanged={onReprobe}
              trigger={
                <button className={ACTION}>
                  <KeyRound className="size-3.5" />
                  Secrets{secretCount > 0 ? ` (${secretCount})` : ""}
                </button>
              }
            />

            <ServerDialog
              onSaved={onRegistryChange}
              initial={{ ...server, name: duplicateName }}
              trigger={
                <button className={ACTION} title="Add another account">
                  <Copy className="size-3.5" />
                  Duplicate
                </button>
              }
            />

            <ServerDialog
              onSaved={onRegistryChange}
              editId={server.id}
              initial={server}
              trigger={
                <button className={ACTION}>
                  <Pencil className="size-3.5" />
                  Edit
                </button>
              }
            />

            <ConfirmDialog
              trigger={
                <button
                  disabled={busy}
                  className={`${ACTION} hover:bg-destructive/10 hover:text-destructive`}
                >
                  <Trash2 className="size-3.5" />
                  Remove
                </button>
              }
              title={`Remove ${server.name}?`}
              description="This deletes the server from Conduit. Any saved secrets stay in your keychain."
              confirmLabel="Remove"
              destructive
              onConfirm={onRemove}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function StatusLabel({
  status,
  label,
  error,
}: {
  status: Status;
  label: string;
  error: string | null;
}) {
  const text = (
    <span className="text-xs whitespace-nowrap text-muted-foreground">
      {label}
    </span>
  );
  if (status === "error" && error) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{text}</TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <p className="text-xs text-warning">{error}</p>
        </TooltipContent>
      </Tooltip>
    );
  }
  return text;
}
