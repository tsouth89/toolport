import { useEffect, useState } from "react";
import {
  ArrowRight,
  Check,
  Download,
  Link2,
  Monitor,
  Plug,
  PlugZap,
  Puzzle,
  Shuffle,
  TriangleAlert,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import {
  addServer,
  installGateway,
  migrateClient,
  setClientDiscovery,
  uninstallGateway,
} from "@/lib/api";
import {
  importableServers,
  isGatewayServer,
  type DetectedClient,
  type ImportItem,
  type McpServer,
  type Registry,
  type ServerEntry,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TransportPill } from "@/components/TransportPill";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ImportReviewDialog } from "@/components/ImportReviewDialog";
import { clientRestartHint, connectSuccessDescription } from "@/lib/clientConnect";

interface Props {
  client: DetectedClient;
  registry: Registry | null;
  onChanged: () => void;
  onRegistryChange: (registry: Registry) => void;
}

/** One-line explainer per discovery mode, shown under the per-client picker. */
const DISCOVERY_HINT: Record<string, string> = {
  lazy: "Advertises a few meta-tools; the client searches, then calls. Fewest tokens.",
  grouped: "One help tool per server; the client expands a server before calling it.",
  full: "Advertises every tool up front. Most tokens, no discovery step.",
};

// Local-model desktop apps: users often run small / quantized models here that stumble on
// lazy's multi-step search-then-call chain, yet get flooded by the full catalog. Grouped
// (one hop per server) is the middle ground. Every other client is a hosted-model or
// agentic client that handles lazy's savings fine. This drives a RECOMMENDATION only; it
// never auto-applies, so an explicit user choice is never silently overridden.
const LOCAL_MODEL_CLIENTS = new Set(["lm-studio", "jan", "anythingllm"]);

/** The mode we suggest for a client, with a one-line why. Advisory, not enforced. */
function recommendedMode(clientId: string): { mode: string; why: string } {
  return LOCAL_MODEL_CLIENTS.has(clientId)
    ? { mode: "grouped", why: "local models do better browsing one server at a time" }
    : {
        mode: "lazy",
        why: "this client handles the search-then-call step and saves the most tokens",
      };
}

export function ClientDetail({ client, registry, onChanged, onRegistryChange }: Props) {
  const [busy, setBusy] = useState(false);
  // Snapshotted at dialog-open time so a registry-changed event mid-review can't
  // reshuffle `toImport` out from under the indices the user already confirmed.
  const [bulkImportServers, setBulkImportServers] = useState<McpServer[] | null>(null);
  // "" = expose all enabled servers (follow active profile); else scope to one.
  const [profile, setProfile] = useState("");
  const [migrateOpen, setMigrateOpen] = useState(false);
  const installed = client.gatewayInstalled;
  // Whether the client app is actually on this machine. We allow Disconnect even
  // when absent (to clean up a stale entry), but block a fresh Connect, writing a
  // config into a client that isn't installed just creates a file nothing reads.
  const present = client.appPresent;
  const profiles = registry?.profiles ?? [];
  // The scope Toolport last connected this client with ("" = follow the active
  // profile). Keep the picker in sync with it as the selected client changes.
  const currentScope = registry?.clientScopes?.[client.id] ?? "";
  useEffect(() => {
    setProfile(currentScope);
  }, [currentScope, client.id]);

  // Discovery: the global mode this client falls back to, and its own override (if any).
  // The gateway resolves env > per-client > global, so an override here applies live.
  const globalMode =
    registry?.discoveryMode?.toLowerCase() ||
    ((registry?.lazyDiscovery ?? true) ? "lazy" : "full");
  const clientMode = registry?.clientDiscovery?.[client.id] ?? "";
  const effectiveMode = clientMode || globalMode;
  const recommended = recommendedMode(client.id);

  /** Set or clear this client's discovery-mode override; applies live, no reconnect. */
  async function applyDiscovery(mode: string) {
    setBusy(true);
    try {
      const next = await setClientDiscovery(client.id, mode || null);
      onRegistryChange(next);
      toast.success(
        mode
          ? `${client.name} discovery set to "${mode}".`
          : `${client.name} now inherits the global discovery mode.`,
      );
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  /** How many servers a given scope ("" = active profile, else a named profile)
   * resolves to, for the "scoped to X · N servers" summary. */
  function scopeServerCount(scopeName: string): number {
    const target = scopeName
      ? profiles.find((p) => p.name.toLowerCase() === scopeName.toLowerCase())
      : (profiles.find((p) => p.id === registry?.activeProfileId) ?? profiles[0]);
    if (!target) return 0;
    // Exclude Toolport's own gateway entry so the count matches the Servers list (which
    // filters it out) instead of over-counting by one.
    const ids = new Set(
      (registry?.servers ?? []).filter((s) => !isGatewayServer(s)).map((s) => s.id),
    );
    return target.enabledServerIds.filter((id) => ids.has(id)).length;
  }

  /** The actual servers a scope resolves to, so a connected client shows WHAT it can
   * reach, not just a count. */
  function scopeServers(scopeName: string): { id: string; name: string }[] {
    const target = scopeName
      ? profiles.find((p) => p.name.toLowerCase() === scopeName.toLowerCase())
      : (profiles.find((p) => p.id === registry?.activeProfileId) ?? profiles[0]);
    if (!target) return [];
    const enabled = new Set(target.enabledServerIds);
    // Never surface the gateway's own "conduit" entry as a reachable server.
    return (registry?.servers ?? [])
      .filter((s) => enabled.has(s.id) && !isGatewayServer(s))
      .map((s) => ({ id: s.id, name: s.name }));
  }

  /** Re-apply a scope to an already-connected client (overwrites its gateway
   * entry's CONDUIT_PROFILE in place, no disconnect needed). */
  async function applyScope() {
    setBusy(true);
    try {
      await installGateway(client.id, profile || undefined);
      // Rescope rewrites the client's MCP config the same way Connect does; without a
      // restart hint the change is invisible until the next cold start (SOU-317).
      toast.success(
        profile
          ? `${client.name} scoped to "${profile}".`
          : `${client.name} now uses all enabled servers.`,
        { description: clientRestartHint(client.name) },
      );
      onChanged();
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }
  // Servers configured directly in the client (not the gateway) that migrate
  // would move into Toolport and strip from the client's config.
  const movable = client.servers.filter((s) => s.name.toLowerCase() !== "conduit");

  async function migrate() {
    setBusy(true);
    try {
      const result = await migrateClient(client.id, profile || undefined);
      onRegistryChange(result.registry);
      toast.success(
        `Moved ${result.moved.length} server${result.moved.length === 1 ? "" : "s"} into Toolport`,
        {
          description: `${client.name} now uses only the Toolport gateway. Config backed up.`,
        },
      );
      setMigrateOpen(false);
      onChanged();
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  const importedNames = new Set(
    (registry?.servers ?? []).map((s) => s.name.toLowerCase()),
  );
  const pluginNames = new Set(client.pluginServers.map((s) => s.name.toLowerCase()));

  // Every client-side server worth showing, deduped by name, minus Toolport's
  // own gateway entry. These exist here only as import candidates.
  const byName = new Map<string, McpServer>();
  for (const s of [...client.servers, ...client.pluginServers]) {
    if (s.name.toLowerCase() === "conduit") continue;
    if (!byName.has(s.name.toLowerCase())) byName.set(s.name.toLowerCase(), s);
  }
  const allServers = [...byName.values()];
  const toImport = importableServers(client, registry);
  const bulkImportPreview: ImportItem[] | null =
    bulkImportServers?.map((server, index) => ({
      key: String(index),
      name: server.name,
      transport: server.transport,
      command: server.command,
      args: server.args,
      url: server.url,
      isNew: true,
    })) ?? null;

  async function importOne(server: McpServer) {
    const isPlugin = pluginNames.has(server.name.toLowerCase());
    const entry: ServerEntry = {
      id: "",
      name: server.name,
      transport: server.transport,
      command: server.command,
      args: server.args,
      env: server.envKeys.map((key) => ({ key, value: null, secret: true })),
      url: server.url,
      source: `imported:${client.id}${isPlugin ? "-plugin" : ""}`,
    };
    const next = await addServer(entry);
    onRegistryChange(next);
    return next;
  }

  async function handleImportOne(server: McpServer) {
    setBusy(true);
    try {
      await importOne(server);
      toast.success(`Imported ${server.name} into Toolport`, {
        description: "Enable it to serve it to every client through the gateway.",
      });
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function handleImportAll() {
    setBulkImportServers(toImport);
  }

  async function confirmImportAll(selected: string[]) {
    const servers = bulkImportServers ?? [];
    setBusy(true);
    let ok = 0;
    const failed: string[] = [];
    const succeeded = new Set<string>();
    for (const key of selected) {
      const s = servers[Number(key)];
      if (!s) continue;
      try {
        await importOne(s);
        ok += 1;
        succeeded.add(key);
      } catch {
        failed.push(s.name);
      }
    }
    setBusy(false);
    if (failed.length === 0) {
      toast.success(`Imported ${ok} server${ok === 1 ? "" : "s"} into Toolport`);
      setBulkImportServers(null);
    } else {
      // Some imports failed. Drop ONLY the rows that succeeded so a re-confirm can't
      // re-import them; the failures (and any rows the user didn't select this time)
      // stay in the dialog to retry or import next.
      if (ok > 0) {
        toast.warning(`Imported ${ok}, couldn't import ${failed.join(", ")}`);
      } else {
        toastError(`Couldn't import ${failed.join(", ")}`);
      }
      setBulkImportServers(servers.filter((_, i) => !succeeded.has(String(i))));
    }
  }

  async function toggleInstall() {
    setBusy(true);
    try {
      if (installed) {
        await uninstallGateway(client.id);
        toast.success(`Disconnected Toolport from ${client.name}`);
      } else {
        const outcome = await installGateway(client.id, profile || undefined);
        // Restart is the load-bearing line (SOU-317): MCP clients typically do not
        // pick up a new gateway entry until relaunch. Scope/backup are secondary.
        toast.success(`Connected Toolport to ${client.name}`, {
          description: connectSuccessDescription(client.name, [
            profile ? `Scoped to the "${profile}" profile.` : null,
            !profile && outcome.backup ? "Previous config backed up." : null,
          ]),
        });
      }
      onChanged();
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Connection: the one thing that actually matters in a client. */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          {installed ? (
            <span className="mb-1 inline-flex items-center gap-1 rounded-full border border-success/30 bg-success/10 px-2 py-0.5 text-xs font-medium text-success">
              <Link2 className="size-3" />
              connected to Toolport
            </span>
          ) : (
            <span className="mb-1 inline-flex items-center gap-1 rounded-full border border-border bg-muted/40 px-2 py-0.5 text-xs font-medium text-muted-foreground">
              not connected
            </span>
          )}
          <p className="truncate font-mono text-xs text-muted-foreground">
            {client.configExists
              ? client.configPath
              : present
                ? "installed - no MCP config yet"
                : "not installed on this machine"}
          </p>
          {installed && (
            <p className="mt-1 text-xs text-muted-foreground">
              Sees{" "}
              <span className="font-medium text-foreground">
                {currentScope ? `the "${currentScope}" profile` : "all enabled servers"}
              </span>{" "}
              · {scopeServerCount(currentScope)} server
              {scopeServerCount(currentScope) === 1 ? "" : "s"}
            </p>
          )}
          {!present && !installed && (
            <p className="mt-1 text-xs text-warning">
              {client.name} doesn't appear to be installed here. Install it first, then
              connect.
            </p>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {profiles.length > 1 && (
            <Select
              value={profile || "__all__"}
              onValueChange={(v) => setProfile(v === "__all__" ? "" : v)}
            >
              <SelectTrigger size="sm" className="w-52">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__all__">All enabled servers</SelectItem>
                {profiles.map((p) => (
                  <SelectItem key={p.id} value={p.name}>
                    Only: {p.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {installed && profile !== currentScope && (
            <Button size="sm" onClick={applyScope} disabled={busy}>
              <Check className="size-4" />
              Apply scope
            </Button>
          )}
          {installed ? (
            <ConfirmDialog
              trigger={
                <Button size="sm" variant="outline" disabled={busy}>
                  <Plug className="size-4" />
                  Disconnect
                </Button>
              }
              title={`Disconnect Toolport from ${client.name}?`}
              description="This rewrites the client's MCP config to remove the gateway. You can reconnect anytime."
              confirmLabel="Disconnect"
              destructive
              onConfirm={toggleInstall}
            />
          ) : (
            <Button
              size="sm"
              variant="default"
              onClick={toggleInstall}
              disabled={busy || !present}
            >
              <PlugZap className="size-4" />
              Connect to Toolport
            </Button>
          )}
        </div>
      </div>

      {installed && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-border/60 bg-muted/20 px-3 py-2">
          <div className="min-w-0">
            <div className="text-xs font-medium text-foreground">
              Discovery mode
              {!clientMode && (
                <span className="ml-1.5 font-normal text-muted-foreground">
                  inheriting {globalMode}
                </span>
              )}
            </div>
            <p className="mt-0.5 text-2xs text-muted-foreground">
              {DISCOVERY_HINT[effectiveMode] ?? DISCOVERY_HINT.lazy}
            </p>
            {effectiveMode === recommended.mode ? (
              <p className="mt-0.5 text-2xs text-success">
                Recommended ({recommended.mode}), {recommended.why}.
              </p>
            ) : (
              <p className="mt-0.5 text-2xs text-muted-foreground/80">
                Recommended:{" "}
                <span className="font-medium text-foreground">{recommended.mode}</span>,{" "}
                {recommended.why}.
              </p>
            )}
          </div>
          <Select
            value={clientMode || "__inherit__"}
            onValueChange={(v) => applyDiscovery(v === "__inherit__" ? "" : v)}
          >
            <SelectTrigger size="sm" className="w-44 shrink-0" disabled={busy}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__inherit__">Inherit ({globalMode})</SelectItem>
              <SelectItem value="lazy">Lazy · fewest tokens</SelectItem>
              <SelectItem value="grouped">Grouped · per-server</SelectItem>
              <SelectItem value="full">Full · every tool</SelectItem>
            </SelectContent>
          </Select>
        </div>
      )}

      {installed ? (
        <div>
          <div className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            Servers it can reach
          </div>
          {scopeServers(currentScope).length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No enabled servers in this scope yet. Enable some under All servers.
            </p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {scopeServers(currentScope).map((s) => (
                <span
                  key={s.id}
                  className="rounded-md border border-border/60 bg-muted/40 px-2 py-1 font-mono text-[11px] text-foreground/90"
                >
                  {s.name}
                </span>
              ))}
            </div>
          )}
        </div>
      ) : scopeServerCount(profile) > 0 ? (
        <div className="flex flex-col gap-4">
          <p className="max-w-prose text-sm text-muted-foreground">
            Connect {client.name} once and it reaches your{" "}
            <span className="font-medium text-foreground">
              {scopeServerCount(profile)} managed server
              {scopeServerCount(profile) === 1 ? "" : "s"}
            </span>{" "}
            through one gateway, no re-wiring per project. Your keys stay in your
            keychain.
          </p>
          <GatewayFlow
            clientName={client.name}
            servers={scopeServers(profile).map((s) => s.name)}
          />
        </div>
      ) : (
        <p className="max-w-prose text-sm text-muted-foreground">
          Connect {client.name}, then enable servers under{" "}
          <span className="font-medium text-foreground">All servers</span> and
          they&apos;ll all route through Toolport, no per-client setup.
        </p>
      )}

      {client.usesConnectors && (
        <Card className="gap-0 border-info/20 bg-info/5">
          <CardContent className="flex gap-3 p-4">
            <Puzzle className="mt-0.5 size-4 shrink-0 text-info" />
            <div className="text-sm">
              <p className="font-medium">{client.name} manages servers as connectors</p>
              <p className="mt-1 text-muted-foreground">
                Those live in {client.name}'s Customize → Connectors and sync to your
                account, outside the local config files Toolport reads. Connecting
                Toolport adds a local gateway entry so your Toolport-managed servers
                appear in {client.name} too.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Import: client servers are sources to pull into Toolport. The WHOLE block only
          renders when the client actually has servers of its own to import - otherwise it
          used to show a header + a "how importing works" explainer describing Import / Move
          buttons that weren't on screen (an AI-agent client with no own servers). */}
      {allServers.length > 0 && (
        <div>
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-2xs font-semibold tracking-[0.09em] text-muted-foreground uppercase">
              Import into Toolport
            </span>
            <div className="flex items-center gap-1.5">
              {toImport.length > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-xs"
                  onClick={handleImportAll}
                  disabled={busy}
                >
                  <Download className="size-3" />
                  Import all ({toImport.length})
                </Button>
              )}
              {movable.length > 0 && (
                <Button
                  size="sm"
                  variant="default"
                  className="h-7 px-2 text-xs"
                  onClick={() => setMigrateOpen(true)}
                  disabled={busy}
                >
                  <Shuffle className="size-3" />
                  Move into gateway ({movable.length})
                </Button>
              )}
            </div>
          </div>
          <details className="mb-2">
            <summary className="cursor-pointer text-xs font-medium text-muted-foreground/80 hover:text-foreground">
              How importing works
            </summary>
            <ul className="mt-1.5 mb-1 space-y-0.5 text-xs text-muted-foreground">
              <li>
                <span className="font-medium text-foreground">Import</span> copies a
                server into Toolport; {client.name} keeps its own copy.
              </li>
              {movable.length > 0 && (
                <li>
                  <span className="font-medium text-foreground">Move into gateway</span>{" "}
                  copies it, then removes it from {client.name}'s config so the gateway is
                  the only source (plugin servers stay). The cutover that actually saves
                  context.
                </li>
              )}
            </ul>
          </details>
          {installed && toImport.length > 0 && movable.length > 0 && (
            <p className="mb-3 -mt-1 inline-flex items-start gap-1.5 rounded-md bg-warning/10 px-2 py-1 text-xs text-warning">
              <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
              <span>
                {client.name} is already connected to Toolport. Import on its own leaves a
                copy here too, so these tools load twice, once directly and once through
                the gateway. Use <span className="font-medium">Move into gateway</span> to
                avoid that.
              </span>
            </p>
          )}

          <div className="grid gap-2 sm:grid-cols-2">
            {allServers.map((server) => (
              <ServerMiniCard
                key={server.name}
                server={server}
                isPlugin={pluginNames.has(server.name.toLowerCase())}
                imported={importedNames.has(server.name.toLowerCase())}
                busy={busy}
                onImport={() => handleImportOne(server)}
              />
            ))}
          </div>

          {toImport.length === 0 && (
            <p className="mt-3 inline-flex items-center gap-1.5 text-xs text-success">
              <Check className="size-3.5" />
              Everything here is already in Toolport. Manage it under{" "}
              <span className="inline-flex items-center gap-0.5 font-medium">
                All servers <ArrowRight className="size-3" />
              </span>
            </p>
          )}
        </div>
      )}

      <Dialog open={migrateOpen} onOpenChange={setMigrateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Move {client.name} onto Toolport</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3 py-1 text-sm">
            <p className="text-muted-foreground">
              This imports{" "}
              <span className="font-medium text-foreground">
                {movable.length} server{movable.length === 1 ? "" : "s"}
              </span>{" "}
              from {client.name} into Toolport, then rewrites {client.name}'s config so it
              uses{" "}
              <span className="font-medium text-foreground">
                only the Toolport gateway
              </span>
              . The original config is backed up first.
            </p>
            <p className="rounded-md bg-warning/10 p-2 text-xs text-warning">
              Secret values (API keys, tokens) aren't carried over, they stay only in the
              backed-up config. After migrating, re-enter them under each server's secrets
              so the gateway can connect.
            </p>
            <div className="rounded-md bg-muted/40 p-2 font-mono text-xs text-muted-foreground">
              {movable.map((s) => s.name).join(", ")}
            </div>
            {client.pluginServers.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Note: {client.pluginServers.length} server
                {client.pluginServers.length === 1 ? "" : "s"} managed by {client.name}'s
                plugins or extensions can't be moved, only {client.name} controls those.
                They stay where they are (you can still import a copy above).
              </p>
            )}
            {profiles.length > 1 && (
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">
                  Scope this client to
                </span>
                <Select
                  value={profile || "__all__"}
                  onValueChange={(v) => setProfile(v === "__all__" ? "" : v)}
                >
                  <SelectTrigger size="sm" className="w-52">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__all__">All enabled servers</SelectItem>
                    {profiles.map((p) => (
                      <SelectItem key={p.id} value={p.name}>
                        Only: {p.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setMigrateOpen(false)}
              disabled={busy}
            >
              Cancel
            </Button>
            <Button onClick={migrate} disabled={busy}>
              <Shuffle className="size-4" />
              Move {movable.length} into Toolport
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ImportReviewDialog
        open={bulkImportPreview !== null}
        items={bulkImportPreview ?? []}
        busy={busy}
        title={`Review ${client.name} servers`}
        onOpenChange={(open) => {
          if (!open && !busy) setBulkImportServers(null);
        }}
        onConfirm={confirmImportAll}
      />
    </div>
  );
}

/** The product in one glance: client -> Toolport gateway -> the servers it reaches. Shows
 * the pitch concretely instead of describing it in prose. */
function GatewayFlow({ clientName, servers }: { clientName: string; servers: string[] }) {
  const shown = servers.slice(0, 4);
  const extra = servers.length - shown.length;
  const link = "mb-7 h-px w-8 shrink-0";
  return (
    <div className="flex flex-wrap items-center justify-center gap-1 rounded-xl border border-border/60 bg-card/40 px-4 py-5">
      <div className="flex flex-col items-center gap-2 text-center">
        <div className="grid size-14 place-items-center rounded-2xl border border-border bg-secondary text-xl">
          <Monitor className="size-6 text-muted-foreground" />
        </div>
        <div className="text-2xs font-semibold">{clientName}</div>
      </div>
      <div className={`${link} bg-gradient-to-r from-border to-primary`} />
      <div className="flex flex-col items-center gap-2 text-center">
        <div className="grid size-16 place-items-center rounded-2xl border border-primary/45 bg-primary/10 shadow-[0_0_0_5px_color-mix(in_oklch,var(--primary)_12%,transparent),0_16px_34px_-16px_color-mix(in_oklch,var(--primary)_50%,transparent)]">
          <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden="true">
            <circle
              cx="16"
              cy="16"
              r="13"
              fill="none"
              stroke="var(--brand)"
              strokeWidth="2.5"
            />
            <circle cx="16" cy="16" r="5" fill="var(--brand)" />
          </svg>
        </div>
        <div className="text-2xs font-semibold">
          Toolport
          <span className="block font-normal text-muted-foreground">gateway</span>
        </div>
      </div>
      <div className={`${link} bg-gradient-to-r from-primary to-border`} />
      <div className="flex flex-col gap-1">
        {shown.map((s) => (
          <span
            key={s}
            className="rounded-md border border-border/60 bg-card px-2 py-1 font-mono text-2xs text-muted-foreground"
          >
            {s}
          </span>
        ))}
        {extra > 0 && (
          <span className="px-2 font-mono text-2xs text-muted-foreground/60">
            +{extra} more
          </span>
        )}
      </div>
    </div>
  );
}

function ServerMiniCard({
  server,
  isPlugin,
  imported,
  busy,
  onImport,
}: {
  server: McpServer;
  isPlugin: boolean;
  imported: boolean;
  busy: boolean;
  onImport: () => void;
}) {
  return (
    <Card aria-disabled={imported} className={`gap-0 ${imported ? "opacity-70" : ""}`}>
      <CardContent className="flex flex-col gap-2 p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-1.5">
            <span className="truncate text-sm font-medium">{server.name}</span>
            {isPlugin && (
              <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                plugin
              </span>
            )}
          </div>
          <TransportPill transport={server.transport} />
        </div>
        <code className="truncate font-mono text-xs text-muted-foreground">
          {server.command
            ? [server.command, ...server.args].join(" ")
            : (server.url ?? "")}
        </code>
        <div className="flex justify-end">
          {imported ? (
            <span className="inline-flex items-center gap-1 text-xs text-success">
              <Check className="size-3" />
              in Toolport
            </span>
          ) : (
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-xs"
              onClick={onImport}
              disabled={busy}
            >
              <Download className="size-3" />
              Import
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
