import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { listen } from "@tauri-apps/api/event";
import {
  ChevronDown,
  MoreHorizontal,
  Download,
  Plus,
  RefreshCw,
  Search,
  ServerOff,
  Store,
  TriangleAlert,
  WifiOff,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import {
  detectClients,
  getRegistry,
  importServers,
  probeServers,
  removeServer,
  setAllEnabled,
  setServerEnabled,
  teamSync,
} from "@/lib/api";
import {
  importableServers,
  isEnabled,
  isGatewayServer,
  type DetectedClient,
  type ProbeResult,
  type Registry,
  type ServerEntry,
  type View,
} from "@/lib/types";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { AppSidebar } from "@/components/AppSidebar";
import { PendingApprovals } from "@/components/PendingApprovals";
import { RegistryServerRow } from "@/components/RegistryServerRow";
import { ServerDialog } from "@/components/ServerDialog";

// Secondary destinations are code-split so the initial bundle only carries the
// default Servers view and the app chrome. Each mounts behind a Suspense
// fallback the first time it's opened. (Named exports, hence the .then wrap.)
const Onboarding = lazy(() =>
  import("@/components/Onboarding").then((m) => ({ default: m.Onboarding })),
);
const ClientDetail = lazy(() =>
  import("@/components/ClientDetail").then((m) => ({ default: m.ClientDetail })),
);
const ActivityView = lazy(() =>
  import("@/components/ActivityView").then((m) => ({ default: m.ActivityView })),
);
const CatalogView = lazy(() =>
  import("@/components/CatalogView").then((m) => ({ default: m.CatalogView })),
);
const PlaygroundView = lazy(() =>
  import("@/components/PlaygroundView").then((m) => ({ default: m.PlaygroundView })),
);
const TeamsView = lazy(() =>
  import("@/components/TeamsView").then((m) => ({ default: m.TeamsView })),
);
const SettingsView = lazy(() =>
  import("@/components/SettingsView").then((m) => ({ default: m.SettingsView })),
);
import { Button } from "@/components/ui/button";
import { Callout } from "@/components/Callout";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";

/** Above this many servers, "Disable all" asks for confirmation first. */
const BULK_DISABLE_CONFIRM_MIN = 3;

function App() {
  const [registry, setRegistry] = useState<Registry | null>(null);
  const [clients, setClients] = useState<DetectedClient[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [togglingAll, setTogglingAll] = useState(false);
  // Gates the "Disable all" bulk action behind a confirm when it turns off more
  // than a couple of servers, so one menu click can't silently kill a big set.
  const [confirmDisableAll, setConfirmDisableAll] = useState(false);
  const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
  const [view, setView] = useState<View>("servers");
  const [activityKey, setActivityKey] = useState(0);
  const [health, setHealth] = useState<Record<string, ProbeResult>>({});
  const [probing, setProbing] = useState(false);
  // Whether the app's Rust backend answered the last health probe. `probe_servers`
  // returns per-server failures as ok:false results; a *thrown* invoke instead means
  // the backend itself didn't respond, and without this the server badges would sit
  // on "Checking…" forever with no explanation. Optimistic default so the banner
  // only appears after a real failure.
  const [backendReachable, setBackendReachable] = useState(true);
  const [query, setQuery] = useState("");
  const [onboarded, setOnboarded] = useState(
    () => localStorage.getItem("conduit.onboarded") === "1",
  );
  const [showOnboarding, setShowOnboarding] = useState(false);
  // Step the wizard opens at (0 = Welcome). Set to the Connect step when resuming
  // after a catalog detour, so a browsing user still lands on the step that wires
  // Toolport into their tools.
  const [onboardingStep, setOnboardingStep] = useState(0);
  const [resumeAtConnect, setResumeAtConnect] = useState(false);

  const lastProbeRef = useRef(0);
  const probingRef = useRef(false);
  // Whether the most recent probe threw (vs. returned results or was skipped). Lets
  // the manual Refresh distinguish "health check failed" from "nothing to report" so
  // a thrown probe doesn't masquerade as a green success toast.
  const probeErroredRef = useRef(false);
  const loadedOnce = useRef(false);

  // Probe health quietly (no toast). Used on load and after authenticating, so
  // each server's status badge reflects reality without the user clicking around.
  const reprobe = useCallback(async (): Promise<ProbeResult[]> => {
    probeErroredRef.current = false;
    // Never stack probes. A probe spawns/reads every server (and on macOS can
    // trigger keychain prompts); overlapping runs amplify that into a storm,
    // especially since each dismissed prompt returns focus and could re-trigger.
    if (probingRef.current) return [];
    probingRef.current = true;
    lastProbeRef.current = Date.now();
    setProbing(true);
    try {
      const results = await probeServers();
      setHealth(Object.fromEntries(results.map((r) => [r.serverId, r])));
      setBackendReachable(true);
      return results;
    } catch {
      // Non-fatal: badges just stay in "checking". Record that it threw so a manual
      // refresh reports the failure instead of a false success (both return []), and
      // surface a persistent banner so the stale badges aren't read as real status.
      probeErroredRef.current = true;
      setBackendReachable(false);
      return [];
    } finally {
      setProbing(false);
      probingRef.current = false;
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

  // `announce` is set by the manual Refresh button: it waits for the health probe
  // and reports a summary toast. The silent path (initial load, focus refresh)
  // fires the probe without blocking or toasting.
  const load = useCallback(
    async (announce = false) => {
      setLoading(true);
      setError(null);
      try {
        const [reg, dc] = await Promise.all([getRegistry(), detectClients()]);
        setRegistry(reg);
        setClients(dc);
        loadedOnce.current = true;
        setActivityKey((k) => k + 1);
        if (announce) {
          const results = await reprobe();
          if (results.length > 0) {
            const up = results.filter((r) => r.ok).length;
            toast.success(`${up} of ${results.length} servers healthy`);
          } else if (probeErroredRef.current) {
            // The registry/clients reloaded, but the health probe itself threw.
            // Don't dress that up as a green success.
            toast.warning("Refreshed, but couldn't check server health");
          } else {
            // Registry/clients still reloaded; give feedback even when the probe
            // was skipped (already in flight) or there are no servers to report.
            toast.success("Refreshed");
          }
        } else {
          void reprobe();
        }
      } catch (e) {
        // After the first successful load, a refresh failure shouldn't blow away a
        // working list. Surface it as a toast and keep what's on screen.
        if (loadedOnce.current) {
          toastError(`Couldn't refresh: ${e}`);
        } else {
          setError(String(e));
        }
      } finally {
        setLoading(false);
      }
    },
    [reprobe],
  );

  useEffect(() => {
    load();
  }, [load]);

  // An agent toggling a server through the gateway writes the registry; the backend
  // watches that file and emits this event, so the UI reflects the change live
  // without a manual reload.
  useEffect(() => {
    const unlisten = listen<Registry>("registry-changed", (e) => {
      setRegistry(e.payload);
      setActivityKey((k) => k + 1);
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  // The backend signals an authoritative removal from a team (a 401/403 on the
  // membership heartbeat) so we can tell the member plainly rather than leaving them
  // to wonder why the team's servers vanished. The registry (team already cleared) is
  // pushed via the normal team_sync return / registry-changed path.
  useEffect(() => {
    const unlisten = listen("team-removed", () => {
      toast.warning(
        "You were removed from the team. Its shared servers have been removed from your setup.",
      );
    });
    return () => {
      void unlisten.then((f) => f());
    };
  }, []);

  // Keep a team member's shared server set AND security policy current even if they
  // never open the Teams tab: an admin tightening a force-quarantine / approval policy
  // must reach every member, not just those who happen to click "Sync now". Runs on
  // connect and on a modest interval; cheap when unchanged (the server 304s on an
  // unchanged config), and not tied to the Teams view. Keyed on the team id so it
  // starts on connect and tears down on disconnect/removal.
  const teamId = registry?.team?.teamId;
  useEffect(() => {
    if (!teamId) return;
    let cancelled = false;
    let running = false;
    const tick = async () => {
      if (running || cancelled) return;
      running = true;
      try {
        const fresh = await teamSync();
        if (!cancelled) setRegistry(fresh);
      } catch {
        // A transient network error is fine; the next tick retries. Removal is a clean
        // 401/403 the backend turns into a cleared team + the team-removed event, not a
        // throw, so it won't land here.
      } finally {
        running = false;
      }
    };
    void tick();
    const id = setInterval(tick, 5 * 60 * 1000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [teamId]);

  function selectClient(id: string | null) {
    setSelectedClientId(id);
    setView("servers");
  }

  // Catalog and Activity are top-level destinations, so leave any selected client.
  function selectView(v: View) {
    setSelectedClientId(null);
    setView(v);
  }

  const profileId = registry
    ? (registry.activeProfileId ?? registry.profiles[0]?.id)
    : undefined;
  // The gateway entry is Toolport itself, not a server it proxies - never list it.
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

  // Show the first-run wizard once, only on a genuinely fresh setup: no servers
  // and no client connected yet. Latched in its own state so a mid-flow connect
  // (which flips gatewayInstalled) doesn't unmount the dialog. Existing users,
  // and anyone who has dismissed it, never see it.
  useEffect(() => {
    if (onboarded || showOnboarding || resumeAtConnect || loading || !registry) return;
    const fresh = servers.length === 0 && !clients.some((c) => c.gatewayInstalled);
    if (fresh) setShowOnboarding(true);
  }, [
    onboarded,
    showOnboarding,
    resumeAtConnect,
    loading,
    registry,
    servers.length,
    clients,
  ]);

  // The wizard hands off to the catalog mid-flow (Add-servers step). When the user
  // navigates back out of the catalog, resume the wizard at the Connect step rather
  // than abandoning onboarding, so they don't silently skip connecting a client.
  useEffect(() => {
    if (resumeAtConnect && view !== "catalog" && !onboarded) {
      setOnboardingStep(2);
      setShowOnboarding(true);
      setResumeAtConnect(false);
    }
  }, [resumeAtConnect, view, onboarded]);

  function finishOnboarding() {
    localStorage.setItem("conduit.onboarded", "1");
    setOnboarded(true);
    setShowOnboarding(false);
    setResumeAtConnect(false);
    setOnboardingStep(0);
  }

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
      toastError(`Couldn't toggle: ${e}`);
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
      toastError(`Couldn't remove: ${e}`);
    } finally {
      setBusyId(null);
    }
  }

  async function handleToggleAll() {
    if (!profileId || togglingAll) return;
    const enable = enabledCount < servers.length;
    setTogglingAll(true);
    try {
      setRegistry(await setAllEnabled(profileId, enable));
      if (enable) void reprobe();
      toast.success(enable ? "Enabled all servers" : "Disabled all servers");
    } catch (e) {
      toastError(`Couldn't update servers: ${e}`);
    } finally {
      setTogglingAll(false);
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
      toastError(`Import failed: ${e}`);
    }
  }

  const serverRow = (server: ServerEntry) => (
    <RegistryServerRow
      key={server.id}
      server={server}
      registry={registry}
      enabled={registry ? isEnabled(registry, server.id) : false}
      busy={busyId === server.id}
      health={health[server.id]}
      onToggle={(en) => handleToggle(server.id, en)}
      onRemove={() => handleRemove(server.id, server.name)}
      onRegistryChange={setRegistry}
      onReprobe={reprobe}
    />
  );

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex h-screen overflow-hidden bg-background text-foreground">
        <AppSidebar
          clients={clients}
          registry={registry}
          onRegistryChange={setRegistry}
          selectedClientId={selectedClientId}
          onSelectClient={selectClient}
          view={view}
          onSelectView={selectView}
          onReplayOnboarding={() => {
            setOnboardingStep(0);
            setShowOnboarding(true);
          }}
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
                      : view === "teams"
                        ? "Teams"
                        : view === "settings"
                          ? "Settings"
                          : selectedClient
                            ? selectedClient.name
                            : "Servers"}
              </h1>
              <p className="truncate text-sm text-muted-foreground">
                {view === "activity"
                  ? "Tool calls routed through Toolport"
                  : view === "catalog"
                    ? "Add MCP servers from the registry"
                    : view === "playground"
                      ? "Invoke a server's tools and see the raw result"
                      : view === "teams"
                        ? "Share one MCP server set across your team"
                        : view === "settings"
                          ? "Global discovery and security policy"
                          : selectedClient
                            ? "MCP client"
                            : loading || !registry
                              ? "Loading…"
                              : "One gateway in front of every MCP server you run"}
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
                  <ServerDialog
                    onSaved={setRegistry}
                    existingNames={servers.map((s) => s.name)}
                    trigger={
                      <Button variant="outline" size="sm">
                        <Plus className="size-4" />
                        Add server
                      </Button>
                    }
                  />
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" aria-label="More actions">
                        <MoreHorizontal className="size-4" />
                      </Button>
                    </DropdownMenuTrigger>

                    <DropdownMenuContent align="end" className="w-38">
                      <DropdownMenuItem onClick={handleImport}>
                        <Download className="mr-2 size-4" />
                        <span>Import</span>
                      </DropdownMenuItem>

                      {servers.length > 0 && (
                        <DropdownMenuItem
                          onClick={() => {
                            // "Disable all" only shows when every server is enabled,
                            // so it turns off `servers.length`. Confirm when that's
                            // more than a couple; "Enable all" and small sets go
                            // straight through.
                            const disabling = enabledCount >= servers.length;
                            if (disabling && servers.length > BULK_DISABLE_CONFIRM_MIN) {
                              setConfirmDisableAll(true);
                            } else {
                              void handleToggleAll();
                            }
                          }}
                          // Gate on the flag handleToggleAll actually sets (togglingAll),
                          // not just busyId, so it can't be re-fired mid-run. Disabled
                          // while a search is active: it acts on ALL servers, so it must
                          // not silently toggle ones hidden by the filter.
                          disabled={togglingAll || busyId !== null || query.trim() !== ""}
                          title={
                            query.trim() !== ""
                              ? "Clear the search to enable or disable all servers"
                              : undefined
                          }
                        >
                          <ServerOff className="mr-2 size-4" />
                          <span>
                            {enabledCount < servers.length ? "Enable all" : "Disable all"}
                          </span>
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </>
              )}
              <Button
                variant="ghost"
                size="icon"
                className="size-8"
                aria-label="Refresh"
                title="Reload servers, clients, and health"
                onClick={() => load(true)}
                disabled={loading}
              >
                <RefreshCw
                  className={`size-4 ${loading || probing ? "animate-spin" : ""}`}
                />
              </Button>
            </div>
          </header>

          {!backendReachable && (
            <Callout
              variant="warning"
              role="status"
              className="mx-6 mt-3 flex items-center gap-3"
            >
              <WifiOff className="size-4 shrink-0" aria-hidden="true" />
              <span className="min-w-0 flex-1">
                Toolport's backend didn't respond to the last health check, so server
                status below may be stale.
              </span>
              <Button
                variant="outline"
                size="sm"
                className="shrink-0"
                onClick={() => void reprobe()}
                disabled={probing}
              >
                Retry
              </Button>
            </Callout>
          )}

          <ScrollArea className="min-h-0 flex-1">
            <div className="p-6">
              <Suspense
                fallback={
                  <div className="flex flex-col gap-2">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-11 w-full rounded-lg" />
                    ))}
                  </div>
                }
              >
                {view === "activity" ? (
                  <ActivityView refreshKey={activityKey} registry={registry} />
                ) : view === "catalog" ? (
                  <CatalogView registry={registry} onAdded={setRegistry} />
                ) : view === "playground" ? (
                  <PlaygroundView registry={registry} onRegistryChange={setRegistry} />
                ) : view === "teams" ? (
                  <TeamsView registry={registry} onRegistryChange={setRegistry} />
                ) : view === "settings" ? (
                  <SettingsView registry={registry} onRegistryChange={setRegistry} />
                ) : selectedClient ? (
                  <ClientDetail
                    client={selectedClient}
                    registry={registry}
                    onChanged={load}
                    onRegistryChange={setRegistry}
                  />
                ) : loading && registry === null ? (
                  <div className="flex flex-col gap-2">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-11 w-full rounded-lg" />
                    ))}
                  </div>
                ) : error ? (
                  <ErrorState message={error} />
                ) : servers.length === 0 ? (
                  <EmptyState
                    importable={importable}
                    onImport={handleImport}
                    onBrowseCatalog={() => selectView("catalog")}
                  />
                ) : visible.length === 0 ? (
                  <div className="py-16 text-center text-sm text-muted-foreground">
                    No servers match "{query}".
                  </div>
                ) : (
                  <div className="flex flex-col gap-5">
                    <StatusBar
                      total={servers.length}
                      connected={connectedCount}
                      attention={attentionCount}
                      disabled={servers.length - enabledCount}
                    />
                    <ServerGroup
                      title="Needs attention"
                      dot="bg-warning"
                      count={grouped.attention.length}
                    >
                      {grouped.attention.map(serverRow)}
                    </ServerGroup>
                    <ServerGroup
                      title="Active"
                      dot="bg-success"
                      count={grouped.active.length}
                    >
                      {grouped.active.map(serverRow)}
                    </ServerGroup>
                    <ServerGroup
                      title="Disabled"
                      dot="bg-muted-foreground/40"
                      count={grouped.disabled.length}
                      defaultCollapsed
                    >
                      {grouped.disabled.map(serverRow)}
                    </ServerGroup>
                  </div>
                )}
              </Suspense>
            </div>
          </ScrollArea>
        </main>
      </div>
      {showOnboarding && registry && (
        <Suspense fallback={null}>
          <Onboarding
            key={onboardingStep}
            initialStep={onboardingStep}
            clients={clients}
            registry={registry}
            onRegistryChange={setRegistry}
            onClientsRefresh={load}
            onBrowseCatalog={() => {
              setShowOnboarding(false);
              setResumeAtConnect(true);
              selectView("catalog");
            }}
            onProbe={reprobe}
            onFinish={finishOnboarding}
          />
        </Suspense>
      )}
      <PendingApprovals />
      <ConfirmDialog
        open={confirmDisableAll}
        onOpenChange={setConfirmDisableAll}
        title="Disable all servers?"
        description={`This turns off all ${servers.length} servers for this profile. Clients will lose their tools until you re-enable them.`}
        confirmLabel="Disable all"
        destructive
        onConfirm={handleToggleAll}
      />
      <Toaster position="bottom-right" />
    </TooltipProvider>
  );
}

/** At-a-glance server health as a row of chips: the primary status summary, promoted out
 * of the grey header caption into a scannable status bar with the same semantic dots the
 * groups use. */
function StatusBar({
  total,
  connected,
  attention,
  disabled,
}: {
  total: number;
  connected: number;
  attention: number;
  disabled: number;
}) {
  const chip =
    "inline-flex items-center gap-2 rounded-full border border-border/60 bg-card/50 px-3 py-1.5 text-xs font-semibold";
  const dot = "size-1.5 rounded-full";
  return (
    <div className="flex flex-wrap gap-2">
      <span className={chip}>
        <span className="tabular-nums">{total}</span>
        <span className="font-normal text-muted-foreground">servers</span>
      </span>
      <span className={chip}>
        <span className={`${dot} bg-success`} />
        <span className="tabular-nums">{connected}</span>
        <span className="font-normal text-muted-foreground">connected</span>
      </span>
      {attention > 0 && (
        <span className={`${chip} border-warning/40`}>
          <span className={`${dot} bg-warning`} />
          <span className="tabular-nums">{attention}</span>
          <span className="font-normal text-muted-foreground">
            need{attention === 1 ? "s" : ""} attention
          </span>
        </span>
      )}
      <span className={chip}>
        <span className={`${dot} bg-muted-foreground/40`} />
        <span className="tabular-nums">{disabled}</span>
        <span className="font-normal text-muted-foreground">disabled</span>
      </span>
    </div>
  );
}

/** A titled, collapsible section of server rows. Renders nothing when empty, so
 * the page only shows the buckets that have servers. Collapse state persists per
 * group; the Disabled bucket starts collapsed. */
function ServerGroup({
  title,
  dot,
  count,
  defaultCollapsed = false,
  children,
}: {
  title: string;
  dot: string;
  count: number;
  defaultCollapsed?: boolean;
  children: ReactNode;
}) {
  const storageKey = `conduit.group.${title.toLowerCase().replace(/\s+/g, "-")}`;
  const [collapsed, setCollapsed] = useState(() => {
    const v = localStorage.getItem(storageKey);
    return v === null ? defaultCollapsed : v === "1";
  });
  if (count === 0) return null;
  function toggle() {
    setCollapsed((c) => {
      const next = !c;
      localStorage.setItem(storageKey, next ? "1" : "0");
      return next;
    });
  }
  return (
    <section>
      <button
        onClick={toggle}
        aria-expanded={!collapsed}
        className="mb-2 flex w-full items-center gap-2 rounded text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      >
        <ChevronDown
          className={`size-3.5 text-muted-foreground/60 transition-transform ${
            collapsed ? "-rotate-90" : ""
          }`}
          aria-hidden="true"
        />
        <span className={`size-2 rounded-full ${dot}`} aria-hidden="true" />
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          {title}
        </h2>
        <span className="text-xs text-muted-foreground/70">{count}</span>
      </button>
      {!collapsed && (
        <div className="overflow-hidden rounded-xl border border-border/60 bg-card/40 shadow-[0_1px_0_rgba(255,255,255,.02)_inset,0_10px_28px_-24px_rgba(0,0,0,.9)]">
          {children}
        </div>
      )}
    </section>
  );
}

function EmptyState({
  importable,
  onImport,
  onBrowseCatalog,
}: {
  importable: number;
  onImport: () => void;
  onBrowseCatalog: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-24 text-center">
      <ServerOff className="size-10 text-muted-foreground/50" />
      <div>
        <p className="font-medium">No servers in Toolport yet</p>
        <p className="text-sm text-muted-foreground">
          {importable > 0
            ? `Found ${importable} server${importable === 1 ? "" : "s"} in your installed clients. Import them to get started.`
            : "Browse the catalog to add one, or import servers from a client."}
        </p>
      </div>
      {importable > 0 ? (
        <Button onClick={onImport}>
          <Download className="size-4" />
          Import {importable} from clients
        </Button>
      ) : (
        <Button onClick={onBrowseCatalog}>
          <Store className="size-4" />
          Browse catalog
        </Button>
      )}
    </div>
  );
}

function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
      <TriangleAlert className="size-10 text-warning" />
      <div>
        <p className="font-medium">Couldn't reach the backend</p>
        <p className="max-w-md text-sm text-muted-foreground">
          {import.meta.env.DEV ? (
            <>
              Make sure you're running the desktop app with{" "}
              <code className="font-mono">npm run tauri dev</code>, not the browser-only
              dev server.
            </>
          ) : (
            <>Toolport's backend didn't start. Try quitting and reopening the app.</>
          )}
        </p>
        <p className="mt-2 font-mono text-xs text-muted-foreground/70">{message}</p>
      </div>
    </div>
  );
}

export default App;
