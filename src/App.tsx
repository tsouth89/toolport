import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Download,
  HeartPulse,
  Plus,
  RefreshCw,
  Search,
  ServerOff,
  Store,
  TriangleAlert,
} from "lucide-react";
import { toast } from "sonner";
import {
  detectClients,
  getRegistry,
  importServers,
  probeServers,
  removeServer,
  setServerEnabled,
} from "@/lib/api";
import {
  importableServers,
  isEnabled,
  isGatewayServer,
  type DetectedClient,
  type ProbeResult,
  type Registry,
  type ServerEntry,
} from "@/lib/types";
import { AppSidebar } from "@/components/AppSidebar";
import { RegistryServerCard } from "@/components/RegistryServerCard";
import { ClientDetail } from "@/components/ClientDetail";
import { ActivityView } from "@/components/ActivityView";
import { ServerDialog } from "@/components/ServerDialog";
import { CatalogView } from "@/components/CatalogView";
import { PlaygroundView } from "@/components/PlaygroundView";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";

function App() {
  const [registry, setRegistry] = useState<Registry | null>(null);
  const [clients, setClients] = useState<DetectedClient[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
  const [view, setView] = useState<"servers" | "activity" | "catalog" | "playground">("servers");
  const [activityKey, setActivityKey] = useState(0);
  const [health, setHealth] = useState<Record<string, ProbeResult>>({});
  const [probing, setProbing] = useState(false);
  const [query, setQuery] = useState("");

  const lastProbeRef = useRef(0);

  // Probe health quietly (no toast). Used on load and after authenticating, so
  // each server's status badge reflects reality without the user clicking around.
  const reprobe = useCallback(async () => {
    lastProbeRef.current = Date.now();
    setProbing(true);
    try {
      const results = await probeServers();
      setHealth(Object.fromEntries(results.map((r) => [r.serverId, r])));
    } catch {
      /* non-fatal: badges just stay in "checking" */
    } finally {
      setProbing(false);
    }
  }, []);

  // Refresh statuses when the user returns to the window, so a server that came
  // up (or went down) while they were away reflects reality without a manual
  // refresh. Guarded so rapid alt-tabbing doesn't re-spawn every server.
  useEffect(() => {
    const onFocus = () => {
      if (Date.now() - lastProbeRef.current > 20_000) void reprobe();
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [reprobe]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [reg, dc] = await Promise.all([getRegistry(), detectClients()]);
      setRegistry(reg);
      setClients(dc);
      setActivityKey((k) => k + 1);
      void reprobe();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [reprobe]);

  useEffect(() => {
    load();
  }, [load]);

  function selectClient(id: string | null) {
    setSelectedClientId(id);
    setView("servers");
  }

  // Catalog and Activity are top-level destinations, so leave any selected client.
  function selectView(v: "servers" | "activity" | "catalog" | "playground") {
    setSelectedClientId(null);
    setView(v);
  }

  const profileId = registry
    ? (registry.activeProfileId ?? registry.profiles[0]?.id)
    : undefined;
  // The gateway entry is Conduit itself, not a server it proxies - never list it.
  const servers = (registry?.servers ?? []).filter((s) => !isGatewayServer(s));
  const enabledCount = registry
    ? servers.filter((s) => isEnabled(registry, s.id)).length
    : 0;
  const connectedCount = servers.filter((s) => health[s.id]?.ok).length;

  // Bucket each server so the list can lead with what needs action. A server
  // needs attention when it's enabled but its probe failed (auth or error).
  type Group = "attention" | "active" | "disabled";
  const groupOf = (s: ServerEntry): Group => {
    if (!registry || !isEnabled(registry, s.id)) return "disabled";
    const h = health[s.id];
    return h && !h.ok ? "attention" : "active";
  };
  const attentionCount = servers.filter((s) => groupOf(s) === "attention").length;

  const q = query.trim().toLowerCase();
  const matches = (s: ServerEntry) =>
    !q ||
    s.name.toLowerCase().includes(q) ||
    (s.url ?? "").toLowerCase().includes(q) ||
    (s.command ?? "").toLowerCase().includes(q);
  const byName = (a: ServerEntry, b: ServerEntry) =>
    a.name.toLowerCase().localeCompare(b.name.toLowerCase());

  const visible = servers.filter(matches);
  const grouped: Record<Group, ServerEntry[]> = {
    attention: visible.filter((s) => groupOf(s) === "attention").sort(byName),
    active: visible.filter((s) => groupOf(s) === "active").sort(byName),
    disabled: visible.filter((s) => groupOf(s) === "disabled").sort(byName),
  };

  // Count what would actually be imported: drop the gateway entry and anything
  // already in the registry, then dedupe by name across clients (the backend
  // import dedupes too). Using raw server counts here made the banner promise
  // imports that the importer then correctly skipped.
  const importable = new Set(
    clients.flatMap((c) =>
      importableServers(c, registry).map((s) => s.name.toLowerCase()),
    ),
  ).size;
  const selectedClient = selectedClientId
    ? clients.find((c) => c.id === selectedClientId)
    : undefined;

  async function handleToggle(serverId: string, enabled: boolean) {
    if (!profileId) return;
    setBusyId(serverId);
    try {
      setRegistry(await setServerEnabled(profileId, serverId, enabled));
      // Enabling adds a server with no health entry yet, so its card would sit on
      // "Checking…" until a manual refresh. Probe now to resolve it. (Disabling
      // moves it to the disabled group, no probe needed.)
      if (enabled) void reprobe();
    } catch (e) {
      toast.error(`Couldn't toggle: ${e}`);
    } finally {
      setBusyId(null);
    }
  }

  async function handleRemove(serverId: string, name: string) {
    setBusyId(serverId);
    try {
      setRegistry(await removeServer(serverId));
      toast.success(`Removed "${name}"`);
    } catch (e) {
      toast.error(`Couldn't remove: ${e}`);
    } finally {
      setBusyId(null);
    }
  }

  async function handleProbe() {
    setProbing(true);
    try {
      const results = await probeServers();
      setHealth(Object.fromEntries(results.map((r) => [r.serverId, r])));
      const up = results.filter((r) => r.ok).length;
      toast.success(`${up} of ${results.length} servers healthy`);
    } catch (e) {
      toast.error(`Health check failed: ${e}`);
    } finally {
      setProbing(false);
    }
  }

  async function handleImport() {
    try {
      const before = registry?.servers.length ?? 0;
      const next = await importServers();
      setRegistry(next);
      const added = next.servers.length - before;
      toast.success(
        added > 0
          ? `Imported ${added} server${added === 1 ? "" : "s"}`
          : "Nothing new to import",
      );
    } catch (e) {
      toast.error(`Import failed: ${e}`);
    }
  }

  const serverCard = (server: ServerEntry) => (
    <RegistryServerCard
      key={server.id}
      server={server}
      enabled={registry ? isEnabled(registry, server.id) : false}
      busy={busyId === server.id}
      health={health[server.id]}
      probing={probing}
      onToggle={(en) => handleToggle(server.id, en)}
      onRemove={() => handleRemove(server.id, server.name)}
      onRegistryChange={setRegistry}
      onReprobe={reprobe}
    />
  );

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-screen bg-background text-foreground">
        <AppSidebar
          clients={clients}
          registry={registry}
          onRegistryChange={setRegistry}
          selectedClientId={selectedClientId}
          onSelectClient={selectClient}
          view={view}
          onSelectView={selectView}
        />

        <main className="flex min-w-0 flex-1 flex-col">
          <header className="flex items-center justify-between gap-4 border-b px-6 py-4">
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-lg font-semibold tracking-tight">
                {view === "activity"
                  ? "Activity"
                  : view === "catalog"
                    ? "Browse catalog"
                    : view === "playground"
                      ? "Playground"
                      : selectedClient
                        ? selectedClient.name
                        : "Servers"}
              </h1>
              <p className="truncate text-sm text-muted-foreground">
                {view === "activity"
                  ? "Tool calls routed through Conduit"
                  : view === "catalog"
                    ? "Add MCP servers from the registry"
                    : view === "playground"
                      ? "Invoke a server's tools and see the raw result"
                      : selectedClient
                        ? "MCP client"
                      : loading || !registry
                        ? "Loading…"
                        : `${enabledCount} of ${servers.length} enabled` +
                          (connectedCount ? ` · ${connectedCount} connected` : "") +
                          (attentionCount ? ` · ${attentionCount} need attention` : "")}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {view === "servers" && !selectedClient && (
                <>
                  <div className="relative">
                    <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search servers"
                      className="h-9 w-44 pl-8"
                    />
                  </div>
                  <Button size="sm" onClick={() => selectView("catalog")}>
                    <Store className="size-4" />
                    Browse catalog
                  </Button>
                  <ServerDialog
                    onSaved={setRegistry}
                    trigger={
                      <Button variant="outline" size="sm">
                        <Plus className="size-4" />
                        Add server
                      </Button>
                    }
                  />
                  <Button variant="outline" size="sm" onClick={handleImport}>
                    <Download className="size-4" />
                    Import
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleProbe}
                    disabled={probing}
                  >
                    <HeartPulse
                      className={`size-4 ${probing ? "animate-pulse" : ""}`}
                    />
                    Check health
                  </Button>
                </>
              )}
              <Button
                variant="ghost"
                size="icon"
                className="size-8"
                aria-label="Refresh"
                onClick={load}
                disabled={loading}
              >
                <RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`} />
              </Button>
            </div>
          </header>

          <ScrollArea className="flex-1">
            <div className="p-6">
              {view === "activity" ? (
                <ActivityView refreshKey={activityKey} />
              ) : view === "catalog" ? (
                <CatalogView registry={registry} onAdded={setRegistry} />
              ) : view === "playground" ? (
                <PlaygroundView registry={registry} onRegistryChange={setRegistry} />
              ) : selectedClient ? (
                <ClientDetail
                  client={selectedClient}
                  registry={registry}
                  onChanged={load}
                  onRegistryChange={setRegistry}
                />
              ) : loading && registry === null ? (
                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  {Array.from({ length: 6 }).map((_, i) => (
                    <Skeleton key={i} className="h-28 w-full rounded-xl" />
                  ))}
                </div>
              ) : error ? (
                <ErrorState message={error} />
              ) : servers.length === 0 ? (
                <EmptyState importable={importable} onImport={handleImport} />
              ) : visible.length === 0 ? (
                <div className="py-16 text-center text-sm text-muted-foreground">
                  No servers match "{query}".
                </div>
              ) : (
                <div className="flex flex-col gap-6">
                  <ServerGroup
                    title="Needs attention"
                    dot="bg-amber-400"
                    count={grouped.attention.length}
                  >
                    {grouped.attention.map(serverCard)}
                  </ServerGroup>
                  <ServerGroup
                    title="Active"
                    dot="bg-emerald-400"
                    count={grouped.active.length}
                  >
                    {grouped.active.map(serverCard)}
                  </ServerGroup>
                  <ServerGroup
                    title="Disabled"
                    dot="bg-muted-foreground/40"
                    count={grouped.disabled.length}
                  >
                    {grouped.disabled.map(serverCard)}
                  </ServerGroup>
                </div>
              )}
            </div>
          </ScrollArea>
        </main>
      </div>
      <Toaster position="bottom-right" />
    </TooltipProvider>
  );
}

/** A titled section of server cards. Renders nothing when empty, so the page
 * only shows the buckets that actually have servers. */
function ServerGroup({
  title,
  dot,
  count,
  children,
}: {
  title: string;
  dot: string;
  count: number;
  children: ReactNode;
}) {
  if (count === 0) return null;
  return (
    <section>
      <div className="mb-2 flex items-center gap-2">
        <span className={`size-2 rounded-full ${dot}`} />
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {title}
        </h2>
        <span className="text-xs text-muted-foreground/70">{count}</span>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{children}</div>
    </section>
  );
}

function EmptyState({
  importable,
  onImport,
}: {
  importable: number;
  onImport: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <ServerOff className="size-10 text-muted-foreground/50" />
      <div>
        <p className="font-medium">No servers in Conduit yet</p>
        <p className="text-sm text-muted-foreground">
          {importable > 0
            ? `Found ${importable} server${importable === 1 ? "" : "s"} in your installed clients. Import them to get started.`
            : "Add a server, or install one in a client and import it."}
        </p>
      </div>
      {importable > 0 && (
        <Button onClick={onImport}>
          <Download className="size-4" />
          Import {importable} from clients
        </Button>
      )}
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
      <TriangleAlert className="size-10 text-amber-400" />
      <div>
        <p className="font-medium">Couldn't reach the backend</p>
        <p className="max-w-md text-sm text-muted-foreground">
          {import.meta.env.DEV ? (
            <>
              Make sure you're running the desktop app with{" "}
              <code className="font-mono">npm run tauri dev</code>, not the
              browser-only dev server.
            </>
          ) : (
            <>Conduit's backend didn't start. Try quitting and reopening the app.</>
          )}
        </p>
        <p className="mt-2 font-mono text-xs text-muted-foreground/70">{message}</p>
      </div>
    </div>
  );
}

export default App;
