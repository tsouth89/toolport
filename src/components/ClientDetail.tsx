import { useEffect, useState } from "react";
import { ArrowRight, Check, Download, Link2, Plug, PlugZap, Puzzle, Shuffle } from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import { addServer, installGateway, migrateClient, uninstallGateway } from "@/lib/api";
import {
  importableServers,
  type DetectedClient,
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

interface Props {
  client: DetectedClient;
  registry: Registry | null;
  onChanged: () => void;
  onRegistryChange: (registry: Registry) => void;
}

export function ClientDetail({
  client,
  registry,
  onChanged,
  onRegistryChange,
}: Props) {
  const [busy, setBusy] = useState(false);
  // "" = expose all enabled servers (follow active profile); else scope to one.
  const [profile, setProfile] = useState("");
  const [migrateOpen, setMigrateOpen] = useState(false);
  const installed = client.gatewayInstalled;
  // Whether the client app is actually on this machine. We allow Disconnect even
  // when absent (to clean up a stale entry), but block a fresh Connect, writing a
  // config into a client that isn't installed just creates a file nothing reads.
  const present = client.appPresent;
  const profiles = registry?.profiles ?? [];
  // The scope Conduit last connected this client with ("" = follow the active
  // profile). Keep the picker in sync with it as the selected client changes.
  const currentScope = registry?.clientScopes?.[client.id] ?? "";
  useEffect(() => {
    setProfile(currentScope);
  }, [currentScope, client.id]);

  /** How many servers a given scope ("" = active profile, else a named profile)
   * resolves to, for the "scoped to X · N servers" summary. */
  function scopeServerCount(scopeName: string): number {
    const target = scopeName
      ? profiles.find((p) => p.name.toLowerCase() === scopeName.toLowerCase())
      : (profiles.find((p) => p.id === registry?.activeProfileId) ?? profiles[0]);
    if (!target) return 0;
    const ids = new Set((registry?.servers ?? []).map((s) => s.id));
    return target.enabledServerIds.filter((id) => ids.has(id)).length;
  }

  /** Re-apply a scope to an already-connected client (overwrites its gateway
   * entry's CONDUIT_PROFILE in place, no disconnect needed). */
  async function applyScope() {
    setBusy(true);
    try {
      await installGateway(client.id, profile || undefined);
      toast.success(
        profile
          ? `${client.name} scoped to "${profile}".`
          : `${client.name} now uses all enabled servers.`,
      );
      onChanged();
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }
  // Servers configured directly in the client (not the gateway) that migrate
  // would move into Conduit and strip from the client's config.
  const movable = client.servers.filter(
    (s) => s.name.toLowerCase() !== "conduit",
  );

  async function migrate() {
    setBusy(true);
    try {
      const result = await migrateClient(client.id, profile || undefined);
      onRegistryChange(result.registry);
      toast.success(
        `Moved ${result.moved.length} server${result.moved.length === 1 ? "" : "s"} into Conduit`,
        {
          description: `${client.name} now uses only the Conduit gateway. Config backed up.`,
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

  // Every client-side server worth showing, deduped by name, minus Conduit's
  // own gateway entry. These exist here only as import candidates.
  const byName = new Map<string, McpServer>();
  for (const s of [...client.servers, ...client.pluginServers]) {
    if (s.name.toLowerCase() === "conduit") continue;
    if (!byName.has(s.name.toLowerCase())) byName.set(s.name.toLowerCase(), s);
  }
  const allServers = [...byName.values()];
  const toImport = importableServers(client, registry);

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
      toast.success(`Imported ${server.name} into Conduit`, {
        description: "Enable it to serve it to every client through the gateway.",
      });
    } catch (e) {
      toastError(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function handleImportAll() {
    setBusy(true);
    let ok = 0;
    const failed: string[] = [];
    for (const s of toImport) {
      try {
        await importOne(s);
        ok += 1;
      } catch {
        failed.push(s.name);
      }
    }
    setBusy(false);
    if (failed.length === 0) {
      toast.success(`Imported ${ok} server${ok === 1 ? "" : "s"} into Conduit`);
    } else if (ok > 0) {
      toast.warning(`Imported ${ok}, couldn't import ${failed.join(", ")}`);
    } else {
      toastError(`Couldn't import ${failed.join(", ")}`);
    }
  }

  async function toggleInstall() {
    setBusy(true);
    try {
      if (installed) {
        await uninstallGateway(client.id);
        toast.success(`Disconnected Conduit from ${client.name}`);
      } else {
        const outcome = await installGateway(client.id, profile || undefined);
        toast.success(`Connected Conduit to ${client.name}`, {
          description: profile
            ? `Scoped to the "${profile}" profile.`
            : outcome.backup
              ? "Previous config backed up."
              : undefined,
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
              connected to Conduit
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
              {client.name} doesn't appear to be installed here. Install it first,
              then connect.
            </p>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {profiles.length > 1 && (
            <Select value={profile || "__all__"} onValueChange={(v) => setProfile(v === "__all__" ? "" : v)}>
              <SelectTrigger size="sm" className="w-40">
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
              title={`Disconnect Conduit from ${client.name}?`}
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
              Connect to Conduit
            </Button>
          )}
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        Connect points {client.name} at Conduit so it uses your managed servers.
        Import copies this client's own servers into Conduit so it can manage them.
      </p>

      {client.usesConnectors && (
        <Card className="gap-0 border-info/20 bg-info/5">
          <CardContent className="flex gap-3 p-4">
            <Puzzle className="mt-0.5 size-4 shrink-0 text-info" />
            <div className="text-sm">
              <p className="font-medium">{client.name} manages servers as connectors</p>
              <p className="mt-1 text-muted-foreground">
                Those live in {client.name}'s Customize → Connectors and sync to your
                account, outside the local config files Conduit reads. Connecting Conduit
                adds a local gateway entry so your Conduit-managed servers appear in{" "}
                {client.name} too.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Import: client servers are sources to pull into Conduit, nothing more. */}
      <div>
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            Import into Conduit
          </span>
          <div className="flex items-center gap-1.5">
            {toImport.length > 0 && (
              <Button
                size="sm"
                variant="outline"
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
                variant="outline"
                className="h-7 px-2 text-xs"
                onClick={() => setMigrateOpen(true)}
                disabled={busy}
              >
                <Shuffle className="size-3" />
                Move config in ({movable.length})
              </Button>
            )}
          </div>
        </div>
        <p className="mb-3 text-xs text-muted-foreground">
          The servers {client.name} already has, from its config and any plugins
          (tagged below). Import what you want Conduit to manage; it becomes the
          source of truth and serves them back through the gateway. "Move config in"
          also clears the config-file ones out of {client.name}, plugin servers stay
          (only {client.name} can remove those).
        </p>

        {allServers.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {client.usesConnectors
              ? "No local servers in the config file to import."
              : "Nothing configured in this client to import."}
          </p>
        ) : (
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
        )}

        {toImport.length === 0 && allServers.length > 0 && (
          <p className="mt-3 inline-flex items-center gap-1.5 text-xs text-success">
            <Check className="size-3.5" />
            Everything here is already in Conduit. Manage it under{" "}
            <span className="inline-flex items-center gap-0.5 font-medium">
              All servers <ArrowRight className="size-3" />
            </span>
          </p>
        )}
      </div>

      <Dialog open={migrateOpen} onOpenChange={setMigrateOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Move {client.name} onto Conduit</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3 py-1 text-sm">
            <p className="text-muted-foreground">
              This imports{" "}
              <span className="font-medium text-foreground">
                {movable.length} server{movable.length === 1 ? "" : "s"}
              </span>{" "}
              from {client.name} into Conduit, then rewrites {client.name}'s config so it
              uses <span className="font-medium text-foreground">only the Conduit gateway</span>.
              The original config is backed up first.
            </p>
            <p className="rounded-md bg-warning/10 p-2 text-xs text-warning">
              Secret values (API keys, tokens) aren't carried over, they stay only
              in the backed-up config. After migrating, re-enter them under each
              server's secrets so the gateway can connect.
            </p>
            <div className="rounded-md bg-muted/40 p-2 font-mono text-xs text-muted-foreground">
              {movable.map((s) => s.name).join(", ")}
            </div>
            {client.pluginServers.length > 0 && (
              <p className="text-xs text-muted-foreground">
                Note: {client.pluginServers.length} server
                {client.pluginServers.length === 1 ? "" : "s"} managed by{" "}
                {client.name}'s plugins or extensions can't be moved, only{" "}
                {client.name} controls those. They stay where they are (you can
                still import a copy above).
              </p>
            )}
            {profiles.length > 1 && (
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground">Scope this client to</span>
                <Select
                  value={profile || "__all__"}
                  onValueChange={(v) => setProfile(v === "__all__" ? "" : v)}
                >
                  <SelectTrigger size="sm" className="w-40">
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
            <Button variant="outline" onClick={() => setMigrateOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={migrate} disabled={busy}>
              <Shuffle className="size-4" />
              Move {movable.length} into Conduit
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
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
    <Card
      aria-disabled={imported}
      className={`gap-0 ${imported ? "opacity-70" : ""}`}
    >
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
              in Conduit
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
