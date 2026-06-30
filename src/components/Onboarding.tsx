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
import { toastError } from "@/lib/toast";
import {
  addCatalogServer,
  importServers,
  installGateway,
  listStacks,
} from "@/lib/api";
import {
  importableServers,
  isGatewayServer,
  type DetectedClient,
  type ProbeResult,
  type Registry,
  type Stack,
} from "@/lib/types";
import { openUrl } from "@tauri-apps/plugin-opener";
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
  /** Probe server health for the Done step (returns per-server results). */
  onProbe: () => Promise<ProbeResult[]>;
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
  onProbe,
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
      registry={registry}
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
      registry={registry}
      serverCount={serverCount}
      connectedCount={connectedCount}
      onProbe={onProbe}
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
                    i === step ? "bg-success" : "bg-muted-foreground/30"
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
      <div className="flex size-10 items-center justify-center rounded-xl bg-success/10 text-success">
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
        One local gateway for all your MCP servers, shared by every AI tool, so your
        agent loads 3 tools instead of hundreds (about 90% fewer tokens) and every
        server is watched for tampering and prompt injection.
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
  registry,
  importable,
  onImport,
  onBrowseCatalog,
  onNext,
}: {
  registry: Registry;
  importable: number;
  onImport: (r: Registry) => void;
  onBrowseCatalog: () => void;
  onNext: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [imported, setImported] = useState<number | null>(null);
  const [stacks, setStacks] = useState<Stack[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  // True once the user has added a stack or imported, so "Next" replaces "later".
  const [touched, setTouched] = useState(false);

  useEffect(() => {
    listStacks()
      .then(setStacks)
      .catch(() => {});
  }, []);

  const have = new Set(registry.servers.map((s) => s.name.toLowerCase()));
  const stack = stacks.find((s) => s.id === selected) ?? null;

  async function doImport() {
    setBusy(true);
    try {
      const next = await importServers();
      onImport(next);
      setImported(next.servers.filter((s) => !isGatewayServer(s)).length);
      setTouched(true);
      toast.success("Imported servers from your clients");
    } catch (e) {
      toastError(`Import failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  /** Add every server in the chosen stack that isn't already in Conduit. */
  async function applyStack(s: Stack) {
    setApplying(true);
    const existing = new Set(registry.servers.map((x) => x.name.toLowerCase()));
    let last = registry;
    let added = 0;
    let needCreds = 0;
    try {
      for (const entry of s.servers) {
        if (existing.has(entry.name.toLowerCase())) continue;
        last = await addCatalogServer(entry);
        added++;
        if (entry.credentialsUrl || entry.envKeys.length > 0) needCreds++;
      }
      onImport(last);
      setTouched(true);
      toast.success(
        added > 0
          ? `Added ${added} server${added === 1 ? "" : "s"} from ${s.name}`
          : `${s.name}: every server is already in Conduit`,
        {
          description:
            needCreds > 0
              ? `${needCreds} need credentials. Use the "get key" links, then enable them.`
              : "Enable them next.",
        },
      );
    } catch (e) {
      toastError(`Couldn't set up ${s.name}: ${e}`);
    } finally {
      setApplying(false);
    }
  }

  return (
    <>
      <StepHeader icon={<Download className="size-5" />} title="Add your first servers">
        Pick what you work on and Conduit sets up a matching stack. You can also
        import from your other tools or browse the full catalog.
      </StepHeader>

      <div className="flex flex-col gap-3">
        {/* Role picker: each stack is a use case / role. */}
        {stacks.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">What do you work on?</span>
            <div className="flex flex-wrap gap-1.5">
              {stacks.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setSelected(s.id === selected ? null : s.id)}
                  className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${
                    s.id === selected
                      ? "border-success/50 bg-success/10 text-success"
                      : "hover:bg-accent"
                  }`}
                >
                  {s.name}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* The recommended stack for the chosen role. */}
        {stack && (
          <div className="flex flex-col gap-2 rounded-md border bg-muted/20 p-2.5">
            <p className="text-xs text-muted-foreground">{stack.description}</p>
            <div className="flex flex-col gap-1">
              {stack.servers.map((e) => (
                <div key={e.name} className="flex items-center gap-1.5 text-[11px]">
                  {have.has(e.name.toLowerCase()) ? (
                    <Check className="size-3 shrink-0 text-success" />
                  ) : (
                    <span className="inline-block size-3 shrink-0" />
                  )}
                  <span className="font-medium text-foreground">{e.name}</span>
                  {e.credentialsUrl && (
                    <button
                      onClick={() => openUrl(e.credentialsUrl!)}
                      className="text-info hover:underline"
                    >
                      get key
                    </button>
                  )}
                </div>
              ))}
            </div>
            <Button
              size="sm"
              className="self-start"
              disabled={applying}
              onClick={() => applyStack(stack)}
            >
              {applying ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <Plus className="size-3.5" />
              )}
              Add this stack
            </Button>
          </div>
        )}

        {importable > 0 && imported === null && (
          <Button variant="outline" onClick={doImport} disabled={busy}>
            {busy ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Download className="size-4" />
            )}
            Import {importable} from your clients
          </Button>
        )}
        {imported !== null && (
          <div className="flex items-center gap-2 rounded-md bg-success/10 px-3 py-2 text-sm text-success">
            <Check className="size-4" />
            Imported. Conduit now manages {imported} server
            {imported === 1 ? "" : "s"}.
          </div>
        )}

        <Button variant="outline" onClick={onBrowseCatalog}>
          <Store className="size-4" />
          Browse the full catalog
        </Button>
      </div>

      <Button variant="ghost" onClick={onNext} className="self-start">
        {touched ? "Next" : "I'll add servers later"}
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
      toastError(`Couldn't connect: ${e}`);
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
                  <span className="flex shrink-0 items-center gap-1.5 text-xs text-success">
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
  registry,
  serverCount,
  connectedCount,
  onProbe,
  onFinish,
}: {
  registry: Registry;
  serverCount: number;
  connectedCount: number;
  onProbe: () => Promise<ProbeResult[]>;
  onFinish: () => void;
}) {
  // Probe what was just added so we report the truth, not a blanket "you're set up"
  // over a server that can't actually start (a missing runtime is the #1 first-run
  // failure). Auth-pending servers are an expected next step, not a fault, so they're
  // excluded from the warning.
  const [health, setHealth] = useState<ProbeResult[] | null>(null);
  useEffect(() => {
    if (serverCount === 0) {
      setHealth([]);
      return;
    }
    let alive = true;
    onProbe()
      .then((r) => alive && setHealth(r))
      .catch(() => alive && setHealth([]));
    return () => {
      alive = false;
    };
  }, [serverCount, onProbe]);

  const nameFor = (id: string) =>
    registry.servers.find((s) => s.id === id)?.name ?? id;
  const broken = (health ?? []).filter((r) => !r.ok && !r.authRequired);

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
            update live, no restart. Each client loads 3 search tools instead of
            every tool, about 90% fewer tokens at the same task. And Conduit watches
            every server for tampering and prompt injection, see Activity.
          </>
        ) : (
          <>
            You haven't {missing} yet. You can do both any time from the main
            screen: add or import servers, then connect a client so your tools share
            them.
          </>
        )}
      </StepHeader>

      {broken.length > 0 && (
        <div className="flex flex-col gap-1 rounded-md bg-warning/10 px-3 py-2 text-sm">
          <span className="font-medium text-warning">
            {broken.length} server{broken.length === 1 ? "" : "s"} couldn't start:{" "}
            {broken.map((r) => nameFor(r.serverId)).join(", ")}
          </span>
          <span className="text-xs text-muted-foreground">
            They likely need a runtime that isn't installed (Node/npx or Python/uvx),
            or the command needs a fix. Retry from each server's card once it's sorted.
          </span>
        </div>
      )}

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
