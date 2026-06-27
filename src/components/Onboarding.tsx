import { useEffect, useState } from "react";
import {
  ArrowRight,
  Check,
  Download,
  Link2,
  Loader2,
  Plus,
  Store,
  Waypoints,
} from "lucide-react";
import { toast } from "sonner";
import {
  addCatalogServer,
  importServers,
  installGateway,
  popularCatalog,
} from "@/lib/api";
import {
  importableServers,
  isGatewayServer,
  type CatalogEntry,
  type DetectedClient,
  type Registry,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";

interface Props {
  /** Step to open at (0 = Welcome). Used to resume mid-flow. */
  initialStep?: number;
  clients: DetectedClient[];
  registry: Registry;
  onRegistryChange: (registry: Registry) => void;
  /** Re-detect clients after a connect, so their status reflects reality. */
  onClientsRefresh: () => void;
  /** Hand off to the catalog; the wizard resumes at the Connect step on return. */
  onBrowseCatalog: () => void;
  /** Mark onboarding complete (skipped or finished) and close. */
  onFinish: () => void;
}

/** First-run wizard. Shown only on a genuinely fresh setup (no servers, no
 * client connected) and skippable at every step. It drives the existing
 * import / connect / catalog flows so a new user reaches "my tools share these
 * servers" without hunting through the UI. */
export function Onboarding({
  initialStep = 0,
  clients,
  registry,
  onRegistryChange,
  onClientsRefresh,
  onBrowseCatalog,
  onFinish,
}: Props) {
  const [step, setStep] = useState(initialStep);

  const present = clients.filter((c) => c.appPresent);
  const importable = new Set(
    clients.flatMap((c) =>
      importableServers(c, registry).map((s) => s.name.toLowerCase()),
    ),
  ).size;
  // Live progress, so the final step reflects what the user actually did.
  const serverCount = registry.servers.filter((s) => !isGatewayServer(s)).length;
  const connectedCount = clients.filter((c) => c.gatewayInstalled).length;

  const steps = [
    <Welcome key="welcome" present={present} onNext={() => setStep(1)} />,
    <AddServers
      key="add"
      importable={importable}
      onImport={onRegistryChange}
      onBrowseCatalog={onBrowseCatalog}
      onNext={() => setStep(2)}
    />,
    <ConnectClients
      key="connect"
      present={present}
      onConnected={onClientsRefresh}
      onNext={() => setStep(3)}
    />,
    <Done
      key="done"
      serverCount={serverCount}
      connectedCount={connectedCount}
      onFinish={onFinish}
    />,
  ];

  return (
    <Dialog open onOpenChange={(o) => !o && onFinish()}>
      <DialogContent className="gap-0 sm:max-w-md" showCloseButton={false}>
        <div className="flex flex-col gap-5 py-1">
          {steps[step]}

          <div className="flex items-center justify-between border-t pt-4">
            <div className="flex items-center gap-1.5">
              {steps.map((_, i) => (
                <span
                  key={i}
                  className={`size-1.5 rounded-full transition-colors ${
                    i === step ? "bg-emerald-400" : "bg-muted-foreground/30"
                  }`}
                />
              ))}
            </div>
            {step < steps.length - 1 && (
              <button
                onClick={onFinish}
                className="text-xs text-muted-foreground transition hover:text-foreground"
              >
                Skip setup
              </button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function StepHeader({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex size-10 items-center justify-center rounded-xl bg-emerald-400/10 text-emerald-400">
        {icon}
      </div>
      <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
      <p className="text-sm text-muted-foreground">{children}</p>
    </div>
  );
}

function Welcome({
  present,
  onNext,
}: {
  present: DetectedClient[];
  onNext: () => void;
}) {
  const names = present.map((c) => c.name);
  const found =
    names.length === 0
      ? "We didn't detect any MCP clients yet. You can still add servers now, then connect a client once it's installed."
      : `We found ${listJoin(names)} on your machine. Conduit will sit between your tools and your servers, so you set each one up once.`;
  return (
    <>
      <StepHeader icon={<Waypoints className="size-5" />} title="Welcome to Conduit">
        One local gateway for all your MCP servers, shared by every AI tool.
        {" "}
        {found}
      </StepHeader>
      <Button onClick={onNext} className="self-start">
        Get started
        <ArrowRight className="size-4" />
      </Button>
    </>
  );
}

function AddServers({
  importable,
  onImport,
  onBrowseCatalog,
  onNext,
}: {
  importable: number;
  onImport: (r: Registry) => void;
  onBrowseCatalog: () => void;
  onNext: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [imported, setImported] = useState<number | null>(null);
  const [starters, setStarters] = useState<CatalogEntry[]>([]);
  const [adding, setAdding] = useState<string | null>(null);
  const [added, setAdded] = useState<Set<string>>(new Set());
  const [startersFailed, setStartersFailed] = useState(false);

  // A few popular servers for a one-click start, zero-config (no keys) first so
  // the user gets something that works immediately.
  useEffect(() => {
    let alive = true;
    popularCatalog()
      .then((all) => {
        if (!alive) return;
        const sorted = [...all].sort(
          (a, b) => a.envKeys.length - b.envKeys.length,
        );
        setStarters(sorted.slice(0, 4));
      })
      .catch(() => {
        if (alive) setStartersFailed(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  async function doImport() {
    setBusy(true);
    try {
      const next = await importServers();
      onImport(next);
      setImported(next.servers.filter((s) => !isGatewayServer(s)).length);
      toast.success("Imported servers from your clients");
    } catch (e) {
      toast.error(`Import failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function addStarter(entry: CatalogEntry) {
    setAdding(entry.name);
    try {
      onImport(await addCatalogServer(entry));
      setAdded((prev) => new Set(prev).add(entry.name));
      toast.success(`Added ${entry.name}`);
    } catch (e) {
      toast.error(`Couldn't add ${entry.name}: ${e}`);
    } finally {
      setAdding(null);
    }
  }

  return (
    <>
      <StepHeader icon={<Download className="size-5" />} title="Add your first servers">
        Pull in the servers you've already set up in other tools, or browse the
        catalog to add new ones.
      </StepHeader>

      <div className="flex flex-col gap-2">
        {importable > 0 && imported === null && (
          <Button onClick={doImport} disabled={busy}>
            {busy ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Download className="size-4" />
            )}
            Import {importable} from your clients
          </Button>
        )}
        {imported !== null && (
          <div className="flex items-center gap-2 rounded-md bg-emerald-400/10 px-3 py-2 text-sm text-emerald-400">
            <Check className="size-4" />
            Imported. Conduit now manages {imported} server
            {imported === 1 ? "" : "s"}.
          </div>
        )}

        {starters.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">
              Or add a popular one:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {starters.map((s) => {
                const isAdded = added.has(s.name);
                return (
                  <button
                    key={s.name}
                    onClick={() => !isAdded && addStarter(s)}
                    disabled={adding === s.name || isAdded}
                    title={s.description}
                    className={`flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs transition-colors ${
                      isAdded
                        ? "border-emerald-400/40 text-emerald-400"
                        : "hover:bg-accent disabled:opacity-60"
                    }`}
                  >
                    {adding === s.name ? (
                      <Loader2 className="size-3 animate-spin" />
                    ) : isAdded ? (
                      <Check className="size-3" />
                    ) : (
                      <Plus className="size-3" />
                    )}
                    {s.name}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {startersFailed && (
          <p className="text-xs text-muted-foreground">
            Couldn't load popular servers (are you offline?). You can still import
            or browse the catalog.
          </p>
        )}

        <Button variant="outline" onClick={onBrowseCatalog}>
          <Store className="size-4" />
          Browse the catalog
        </Button>
      </div>

      <Button variant="ghost" onClick={onNext} className="self-start">
        {imported !== null || added.size > 0 ? "Next" : "I'll add servers later"}
        <ArrowRight className="size-4" />
      </Button>
    </>
  );
}

function ConnectClients({
  present,
  onConnected,
  onNext,
}: {
  present: DetectedClient[];
  onConnected: () => void;
  onNext: () => void;
}) {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [done, setDone] = useState<Set<string>>(new Set());

  async function connect(client: DetectedClient) {
    setBusyId(client.id);
    try {
      await installGateway(client.id);
      setDone((prev) => new Set(prev).add(client.id));
      onConnected();
      toast.success(`Connected Conduit to ${client.name}`);
    } catch (e) {
      toast.error(`Couldn't connect: ${e}`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <StepHeader icon={<Link2 className="size-5" />} title="Connect a client">
        Point a tool at Conduit. It connects once, then sees every server you
        enable here, no per-tool setup.
      </StepHeader>

      {present.length === 0 ? (
        <p className="rounded-md bg-muted/50 px-3 py-2 text-sm text-muted-foreground">
          No clients detected yet. Install Claude Desktop, Cursor, VS Code, or
          another supported tool, then connect it from the sidebar.
        </p>
      ) : (
        <div className="flex flex-col gap-2">
          {present.map((client) => {
            const connected = done.has(client.id) || client.gatewayInstalled;
            return (
              <div
                key={client.id}
                className="flex items-center justify-between gap-2 rounded-md border px-3 py-2"
              >
                <span className="truncate text-sm">{client.name}</span>
                {connected ? (
                  <span className="flex shrink-0 items-center gap-1.5 text-xs text-emerald-400">
                    <Check className="size-3.5" />
                    Connected
                  </span>
                ) : (
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 shrink-0 px-2 text-xs"
                    onClick={() => connect(client)}
                    disabled={busyId === client.id}
                  >
                    {busyId === client.id ? (
                      <Loader2 className="size-3.5 animate-spin" />
                    ) : (
                      <Link2 className="size-3.5" />
                    )}
                    Connect
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      )}

      <Button onClick={onNext} className="self-start">
        {done.size > 0 ? "Next" : "Skip for now"}
        <ArrowRight className="size-4" />
      </Button>
    </>
  );
}

function Done({
  serverCount,
  connectedCount,
  onFinish,
}: {
  serverCount: number;
  connectedCount: number;
  onFinish: () => void;
}) {
  const ready = serverCount > 0 && connectedCount > 0;
  const missing = [
    serverCount === 0 ? "added a server" : null,
    connectedCount === 0 ? "connected a client" : null,
  ]
    .filter(Boolean)
    .join(" or ");
  return (
    <>
      <StepHeader
        icon={<Check className="size-5" />}
        title={ready ? "You're set up" : "Setup started"}
      >
        {ready ? (
          <>
            Conduit now manages {serverCount} server
            {serverCount === 1 ? "" : "s"} across {connectedCount} connected tool
            {connectedCount === 1 ? "" : "s"}. Toggle one on or off and your clients
            update live, no restart. And each client loads 3 search tools instead of
            every tool, so the agent's context stays small.
          </>
        ) : (
          <>
            You haven't {missing} yet. You can do both any time from the main
            screen: add or import servers, then connect a client so your tools share
            them.
          </>
        )}
      </StepHeader>
      <Button onClick={onFinish} className="self-start">
        {ready ? "Start using Conduit" : "Got it"}
        <ArrowRight className="size-4" />
      </Button>
    </>
  );
}

/** "Claude", "Claude and Cursor", "Claude, Cursor, and VS Code". */
function listJoin(items: string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  if (items.length === 2) return `${items[0]} and ${items[1]}`;
  return `${items.slice(0, -1).join(", ")}, and ${items[items.length - 1]}`;
}
