import { useEffect, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Download,
  KeyRound,
  Link2,
  Loader2,
  Plus,
  ShieldCheck,
  Sparkles,
  Store,
  Users,
  Waypoints,
  Workflow,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import {
  addCatalogServer,
  importServers,
  installGateway,
  listStacks,
  previewImportServers,
  teamConnect,
  teamJoinPoll,
} from "@/lib/api";
import { teamUrlError } from "@/lib/teamUrl";
import { Input } from "@/components/ui/input";
import {
  importableServers,
  isGatewayServer,
  type DetectedClient,
  type ImportItem,
  type ProbeResult,
  type Registry,
  type Stack,
} from "@/lib/types";
import { openExternal } from "@/lib/openUrl";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { ImportReviewDialog } from "@/components/ImportReviewDialog";

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
  // A team member who was handed an invite code shouldn't have to click through
  // the solo flow to find a place to enter it. This branch drops them straight
  // into the join step and, on success, the team's servers arrive locally.
  const [joining, setJoining] = useState(false);

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
    <Welcome
      key="welcome"
      present={present}
      onNext={() => setStep(1)}
      onJoinTeam={() => setJoining(true)}
    />,
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
          {joining ? (
            <JoinTeam
              onBack={() => setJoining(false)}
              onRegistryChange={onRegistryChange}
              onClientsRefresh={onClientsRefresh}
              onFinish={onFinish}
            />
          ) : (
            <>
              {steps[step]}

              <div className="flex items-center justify-between border-t pt-4">
                <div
                  className="flex items-center gap-1.5"
                  role="progressbar"
                  aria-valuenow={step + 1}
                  aria-valuemin={1}
                  aria-valuemax={steps.length}
                  aria-label={`Setup step ${step + 1} of ${steps.length}`}
                >
                  {steps.map((_, i) => (
                    <span
                      key={i}
                      aria-hidden="true"
                      className={`size-1.5 rounded-full transition-colors ${
                        i === step ? "bg-success" : "bg-muted-foreground/30"
                      }`}
                    />
                  ))}
                </div>
                {step < steps.length - 1 && (
                  <button
                    type="button"
                    onClick={onFinish}
                    className="text-xs text-muted-foreground transition hover:text-foreground"
                  >
                    Skip setup
                  </button>
                )}
              </div>
            </>
          )}
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
  onJoinTeam,
}: {
  present: DetectedClient[];
  onNext: () => void;
  onJoinTeam: () => void;
}) {
  const names = present.map((c) => c.name);
  const found =
    names.length === 0
      ? "No MCP clients detected yet, you can still add servers now and connect a client once it's installed."
      : `Found ${listJoin(names)} on your machine, ready to point at the gateway.`;
  const benefits = [
    {
      icon: Workflow,
      title: "One gateway for every tool",
      body: "Set each MCP server up once; every AI client shares it.",
    },
    {
      icon: Sparkles,
      title: "Up to 91% fewer tokens",
      body: "Your agent loads a few meta-tools instead of hundreds of schemas.",
    },
    {
      icon: ShieldCheck,
      title: "Watched for tampering",
      body: "Every server is checked for rug-pulls and prompt injection.",
    },
  ];
  return (
    <>
      <StepHeader icon={<Waypoints className="size-5" />} title="Welcome to Toolport">
        One local gateway for all your MCP servers, shared by every AI tool.
      </StepHeader>
      <div className="grid gap-2.5">
        {benefits.map(({ icon: Icon, title, body }) => (
          <div key={title} className="flex items-start gap-3">
            <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Icon className="size-4" />
            </div>
            <div>
              <div className="text-sm font-medium">{title}</div>
              <div className="text-xs text-muted-foreground">{body}</div>
            </div>
          </div>
        ))}
      </div>
      <p className="text-sm text-muted-foreground">{found}</p>
      <Button onClick={onNext} className="self-start">
        Get started
        <ArrowRight className="size-4" />
      </Button>
      <div className="flex flex-col gap-1.5 border-t pt-4">
        <button
          type="button"
          onClick={onJoinTeam}
          className="flex items-center gap-2 text-left text-sm font-medium text-foreground transition hover:text-primary"
        >
          <Users className="size-4 shrink-0 text-muted-foreground" />
          Joining a team? Enter your invite code
          <ArrowRight className="size-3.5 shrink-0 text-muted-foreground" />
        </button>
        <button
          type="button"
          onClick={() => openExternal("https://toolport.app/teams")}
          className="self-start text-2xs text-muted-foreground transition hover:text-foreground"
        >
          What is Toolport for Teams? →
        </button>
      </div>
    </>
  );
}

const HOSTED_TEAMS_URL = "https://teams.toolport.app";

/** The team-member on-ramp. A person handed an invite code lands here from the
 * Welcome step, pastes it, and the team's shared servers arrive locally. The
 * hosted server is the default; self-hosting is a tucked-away advanced toggle so
 * the common case is a single field. */
function JoinTeam({
  onBack,
  onRegistryChange,
  onClientsRefresh,
  onFinish,
}: {
  onBack: () => void;
  onRegistryChange: (r: Registry) => void;
  onClientsRefresh: () => void;
  onFinish: () => void;
}) {
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [serverUrl, setServerUrl] = useState(HOSTED_TEAMS_URL);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [joined, setJoined] = useState(false);
  // Set while an approval-gated join waits for an admin; holds the values used to request it.
  const [pending, setPending] = useState<{
    serverUrl: string;
    requestToken: string;
    name?: string;
  } | null>(null);

  // Poll a pending, approval-gated join until an admin acts. A transient network error keeps
  // the wait alive; an explicit deny/expiry ends it with a message.
  useEffect(() => {
    if (!pending) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await teamJoinPoll(
          pending.serverUrl,
          pending.requestToken,
          pending.name,
        );
        if (cancelled) return;
        if (r.status === "connected" && r.registry) {
          setPending(null);
          onRegistryChange(r.registry);
          onClientsRefresh();
          setJoined(true);
        } else if (r.status === "denied") {
          setPending(null);
          setError("An admin declined your request to join this team.");
        } else if (r.status === "unknown") {
          setPending(null);
          setError("This join request expired. Ask for the link again and reconnect.");
        }
      } catch {
        // Transient: the next tick retries.
      }
    };
    void tick();
    const id = setInterval(tick, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);

  const join = async () => {
    setError(null);
    const urlError = teamUrlError(serverUrl);
    if (urlError) {
      setError(urlError);
      return;
    }
    if (!code.trim()) {
      setError("Enter the invite or connect code your team gave you.");
      return;
    }
    setBusy(true);
    try {
      const su = serverUrl.trim();
      const mn = name.trim() || undefined;
      const r = await teamConnect(su, code.trim(), mn);
      if (r.status === "pending" && r.requestToken) {
        // Approval-gated link: hold and poll (effect above) until an admin approves.
        setPending({ serverUrl: su, requestToken: r.requestToken, name: mn });
      } else if (r.status === "connected" && r.registry) {
        onRegistryChange(r.registry);
        onClientsRefresh();
        setJoined(true);
      } else {
        setError("The server returned an unexpected connect response.");
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (joined) {
    return (
      <>
        <StepHeader icon={<Check className="size-5" />} title="You're on the team">
          Your team's shared servers were added to your active profile. Local and LAN
          servers stay off until you review and enable them.
        </StepHeader>
        <Button onClick={onFinish} className="self-start">
          Finish setup
          <ArrowRight className="size-4" />
        </Button>
      </>
    );
  }

  return (
    <>
      <StepHeader icon={<Users className="size-5" />} title="Join your team">
        Paste the invite code your team shared. Toolport connects this device and pulls
        the team's server set.
      </StepHeader>
      <div className="grid gap-3">
        <label className="grid gap-1 text-sm">
          <span className="text-muted-foreground">Invite or connect code</span>
          <Input
            autoFocus
            placeholder="Paste your invite or connect code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !busy && join()}
          />
        </label>
        <label className="grid gap-1 text-sm">
          <span className="text-muted-foreground">Your name (optional)</span>
          <Input
            placeholder="e.g. Tyler"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        {advanced ? (
          <label className="grid gap-1 text-sm">
            <span className="text-muted-foreground">Team server URL</span>
            <Input
              placeholder="https://toolport.yourcompany.com"
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
            />
            <span className="text-xs text-muted-foreground">
              Only change this if your team runs its own self-hosted Toolport server.
            </span>
          </label>
        ) : (
          <button
            type="button"
            onClick={() => setAdvanced(true)}
            className="flex items-center gap-1.5 self-start text-2xs text-muted-foreground transition hover:text-foreground"
          >
            <KeyRound className="size-3" />
            Self-hosted server? Set a custom URL
          </button>
        )}
      </div>
      {error && (
        <p className="text-sm text-destructive" role="alert">
          {error}
        </p>
      )}
      <div className="flex items-center justify-between border-t pt-4">
        <button
          type="button"
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-muted-foreground transition hover:text-foreground"
        >
          <ArrowLeft className="size-3.5" />
          Back
        </button>
        {pending ? (
          <div className="flex items-center gap-2.5 rounded-lg border border-primary/40 bg-primary/5 px-3 py-2 text-sm">
            <Loader2 className="size-4 shrink-0 animate-spin text-primary" />
            <span className="text-muted-foreground">
              Waiting for an admin to approve you…
            </span>
            <button
              type="button"
              onClick={() => setPending(null)}
              className="ml-1 text-xs text-muted-foreground underline transition hover:text-foreground"
            >
              Cancel
            </button>
          </div>
        ) : (
          <Button onClick={join} disabled={busy}>
            {busy ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Users className="size-4" />
            )}
            Join team
          </Button>
        )}
      </div>
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
  const [importPreview, setImportPreview] = useState<ImportItem[] | null>(null);
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
      const preview = await previewImportServers();
      if (preview.length === 0) {
        toast.success("No new servers found in your clients");
        return;
      }
      setImportPreview(preview);
    } catch (e) {
      toastError(`Couldn't prepare import: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function confirmImport(selected: string[]) {
    setBusy(true);
    try {
      const next = await importServers(selected);
      onImport(next);
      setImported(next.servers.filter((s) => !isGatewayServer(s)).length);
      setTouched(true);
      toast.success("Imported servers from your clients");
      setImportPreview(null);
    } catch (e) {
      toastError(`Import failed: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  /** Add every server in the chosen stack that isn't already in Toolport. */
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
          : `${s.name}: every server is already in Toolport`,
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
        Pick what you work on and Toolport sets up a matching stack. You can also import
        from your other tools or browse the full catalog.
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
                      onClick={() => openExternal(e.credentialsUrl)}
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
            Imported. Toolport now manages {imported} server
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
      <ImportReviewDialog
        open={importPreview !== null}
        items={importPreview ?? []}
        busy={busy}
        onOpenChange={(open) => {
          if (!open && !busy) setImportPreview(null);
        }}
        onConfirm={confirmImport}
      />
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
      toast.success(`Connected Toolport to ${client.name}`);
    } catch (e) {
      toastError(`Couldn't connect: ${e}`);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <StepHeader icon={<Link2 className="size-5" />} title="Connect a client">
        Point a tool at Toolport. It connects once, then sees every server you enable
        here, no per-tool setup.
      </StepHeader>

      {present.length === 0 ? (
        <p className="rounded-md bg-muted/50 px-3 py-2 text-sm text-muted-foreground">
          No clients detected yet. Install Claude Desktop, Cursor, VS Code, or another
          supported tool, then connect it from the sidebar.
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
  // The probe itself can fail (gateway not up yet). That's distinct from "all
  // servers healthy": swallowing it to health=[] would show a confident "you're
  // set up" over servers we never actually checked, so track it separately.
  const [probeFailed, setProbeFailed] = useState(false);
  useEffect(() => {
    if (serverCount === 0) {
      setHealth([]);
      setProbeFailed(false);
      return;
    }
    let alive = true;
    onProbe()
      .then((r) => {
        if (!alive) return;
        setHealth(r);
        setProbeFailed(false);
      })
      .catch(() => {
        if (!alive) return;
        setHealth([]);
        setProbeFailed(true);
      });
    return () => {
      alive = false;
    };
  }, [serverCount, onProbe]);

  const nameFor = (id: string) => registry.servers.find((s) => s.id === id)?.name ?? id;
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
            Toolport now manages {serverCount} server
            {serverCount === 1 ? "" : "s"} across {connectedCount} connected tool
            {connectedCount === 1 ? "" : "s"}. Toggle one on or off and your clients
            update live, no restart. Each client loads 3 search tools instead of every
            tool, up to 91% fewer tokens at the same task success. And Toolport watches
            every server for tampering and prompt injection, see Activity.
          </>
        ) : (
          <>
            You haven't {missing} yet. You can do both any time from the main screen: add
            or import servers, then connect a client so your tools share them.
          </>
        )}
      </StepHeader>

      {broken.length > 0 && (
        <div className="flex flex-col gap-2 rounded-md bg-warning/10 px-3 py-2 text-sm">
          <span className="font-medium text-warning">
            {broken.length} server{broken.length === 1 ? "" : "s"} couldn't start
          </span>
          <ul className="flex flex-col gap-1.5">
            {broken.map((r) => (
              <li key={r.serverId} className="flex flex-col gap-0.5">
                <span className="text-xs font-medium text-foreground/80">
                  {nameFor(r.serverId)}
                </span>
                {r.error && (
                  <span className="max-h-20 overflow-y-auto text-xs break-words whitespace-pre-wrap text-muted-foreground">
                    {r.error}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <span className="text-xs text-muted-foreground">
            Most first-run failures are a missing runtime (Node/npx or Python/uvx) or a
            command that needs a fix. Sort it out, then retry from that server's card (the
            button below takes you to the main screen).
          </span>
        </div>
      )}

      {probeFailed && (
        <div className="rounded-md bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
          Couldn&apos;t verify your servers started, the health check didn&apos;t run.
          Open the main screen to see each server&apos;s live status.
        </div>
      )}

      <Button onClick={onFinish} className="self-start">
        {ready ? "Start using Toolport" : "Got it"}
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
