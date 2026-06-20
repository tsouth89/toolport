import { useState } from "react";
import {
  ArrowRight,
  Check,
  Download,
  Link2,
  Loader2,
  Store,
  Waypoints,
} from "lucide-react";
import { toast } from "sonner";
import { importServers, installGateway } from "@/lib/api";
import {
  importableServers,
  type DetectedClient,
  type Registry,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";

interface Props {
  clients: DetectedClient[];
  registry: Registry;
  onRegistryChange: (registry: Registry) => void;
  /** Re-detect clients after a connect, so their status reflects reality. */
  onClientsRefresh: () => void;
  /** Leave the wizard and open the catalog. */
  onBrowseCatalog: () => void;
  /** Mark onboarding complete (skipped or finished) and close. */
  onFinish: () => void;
}

/** First-run wizard. Shown only on a genuinely fresh setup (no servers, no
 * client connected) and skippable at every step. It drives the existing
 * import / connect / catalog flows so a new user reaches "my tools share these
 * servers" without hunting through the UI. */
export function Onboarding({
  clients,
  registry,
  onRegistryChange,
  onClientsRefresh,
  onBrowseCatalog,
  onFinish,
}: Props) {
  const [step, setStep] = useState(0);

  const present = clients.filter((c) => c.appPresent);
  const importable = new Set(
    clients.flatMap((c) =>
      importableServers(c, registry).map((s) => s.name.toLowerCase()),
    ),
  ).size;

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
    <Done key="done" onFinish={onFinish} />,
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

  async function doImport() {
    setBusy(true);
    try {
      const next = await importServers();
      onImport(next);
      setImported(next.servers.length);
      toast.success("Imported servers from your clients");
    } catch (e) {
      toast.error(`Import failed: ${e}`);
    } finally {
      setBusy(false);
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
        <Button variant="outline" onClick={onBrowseCatalog}>
          <Store className="size-4" />
          Browse the catalog
        </Button>
      </div>

      <Button variant="ghost" onClick={onNext} className="self-start">
        {imported !== null ? "Next" : "I'll add servers later"}
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

function Done({ onFinish }: { onFinish: () => void }) {
  return (
    <>
      <StepHeader icon={<Check className="size-5" />} title="You're set up">
        Manage your servers here and they stay in sync across every connected
        tool. Toggle one on or off and your clients update live, no restart.
      </StepHeader>
      <Button onClick={onFinish} className="self-start">
        Start using Conduit
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
