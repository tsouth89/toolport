import { useEffect, useState } from "react";
import {
  ArrowUpCircle,
  ChevronRight,
  ClipboardList,
  Compass,
  Download,
  FlaskConical,
  FolderOpen,
  Layers,
  Link2,
  Loader2,
  Puzzle,
  ScrollText,
  Settings,
  Share2,
  Store,
  Users,
  Zap,
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";
import { openExternal } from "@/lib/openUrl";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import type { Update } from "@tauri-apps/plugin-updater";
import {
  importableServers,
  type DetectedClient,
  type Registry,
  type SavingsSummary,
  type View,
} from "@/lib/types";
import { gatherDiagnostics, getSavingsSummary, openDataDir } from "@/lib/api";
import { fmtTokens } from "@/lib/utils";
import { checkForUpdate, installUpdate } from "@/lib/updater";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ProfileBar } from "@/components/ProfileBar";
import { ShareDialog } from "@/components/ShareDialog";

const FOCUS_RING =
  "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";
const NAV_ITEM = `flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${FOCUS_RING}`;
const ICON_BTN = `rounded text-muted-foreground transition hover:text-foreground ${FOCUS_RING}`;

/** Footer showing the running version, and an in-app update button when a newer
 * release is published. The check is best-effort: any failure (dev build,
 * offline, no manifest yet) just shows the current version. Clicking downloads,
 * installs, and relaunches into the new version. */
function VersionFooter({
  onImport,
  onReplay,
}: {
  onImport: (r: Registry) => void;
  onReplay: () => void;
}) {
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<Update | null>(null);
  const [installing, setInstalling] = useState(false);
  const [checking, setChecking] = useState(false);
  const [showNotes, setShowNotes] = useState(false);

  useEffect(() => {
    let alive = true;
    getVersion()
      .then((v) => {
        if (alive) setVersion(v);
      })
      .catch(() => {
        // Never let a failed version lookup hide the whole footer toolbar.
        if (alive) setVersion("?");
      });
    checkForUpdate()
      .then((r) => {
        if (alive && r.kind === "update") setUpdate(r.update);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  async function manualCheck() {
    if (checking || installing) return;
    setChecking(true);
    try {
      const r = await checkForUpdate();
      if (r.kind === "update") {
        setUpdate(r.update);
        setShowNotes(true);
      } else if (r.kind === "current") {
        toast.success("You're on the latest version");
      } else {
        toastError("Couldn't check for updates", {
          description: "You may be offline. Try again in a moment.",
        });
      }
    } finally {
      setChecking(false);
    }
  }

  async function applyUpdate() {
    if (!update) return;
    setInstalling(true);
    toast.info(`Updating to v${update.version}…`, {
      description: "Toolport will restart when it's done.",
    });
    try {
      await installUpdate(update);
    } catch (e) {
      setInstalling(false);
      toastError(`Update failed: ${e}`, {
        description: "You can download it manually from the releases page.",
        action: {
          label: "Open",
          onClick: () =>
            openExternal("https://github.com/tsouth89/toolport/releases/latest"),
        },
      });
    }
  }

  if (!version) return null;
  return (
    <div className="mt-auto flex items-center justify-between gap-2 border-t px-4 py-3 text-xs">
      {update ? (
        <button
          onClick={() => setShowNotes(true)}
          disabled={installing}
          className={`flex min-w-0 items-center gap-1.5 rounded text-success transition hover:underline disabled:opacity-70 ${FOCUS_RING}`}
        >
          {installing ? (
            <Loader2 className="size-3.5 shrink-0 animate-spin" />
          ) : (
            <ArrowUpCircle className="size-3.5 shrink-0" />
          )}
          <span className="truncate">
            {installing ? "Updating…" : `Update to v${update.version}`}
          </span>
        </button>
      ) : (
        <button
          onClick={manualCheck}
          disabled={checking}
          title="Check for updates"
          className={`rounded text-muted-foreground transition hover:text-foreground disabled:opacity-70 ${FOCUS_RING}`}
        >
          {checking ? "Checking…" : `Toolport v${version}`}
        </button>
      )}

      <UpdateNotes
        open={showNotes}
        onOpenChange={setShowNotes}
        update={update}
        installing={installing}
        onInstall={applyUpdate}
      />
      <div className="flex shrink-0 items-center gap-2">
        <ShareDialog
          onImported={onImport}
          trigger={
            <button
              title="Share or import a setup"
              aria-label="Share setup"
              className={ICON_BTN}
            >
              <Share2 className="size-3.5" />
            </button>
          }
        />
        <button
          onClick={onReplay}
          title="Run setup again"
          aria-label="Run setup again"
          className={ICON_BTN}
        >
          <Compass className="size-3.5" />
        </button>
        <button
          onClick={() => openDataDir().catch(() => {})}
          title="Open data folder (config, logs)"
          aria-label="Open data folder"
          className={ICON_BTN}
        >
          <FolderOpen className="size-3.5" />
        </button>
        <button
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(await gatherDiagnostics());
              toast.success("Diagnostics copied, paste them into your bug report");
            } catch {
              toastError("Could not copy diagnostics");
            }
          }}
          title="Copy diagnostics for a bug report"
          aria-label="Copy diagnostics"
          className={ICON_BTN}
        >
          <ClipboardList className="size-3.5" />
        </button>
      </div>
    </div>
  );
}

/** Release-notes dialog shown before installing an update, so the user sees
 * what's changing and confirms the restart. */
function UpdateNotes({
  open,
  onOpenChange,
  update,
  installing,
  onInstall,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  update: Update | null;
  installing: boolean;
  onInstall: () => void;
}) {
  if (!update) return null;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Update available: v{update.version}</DialogTitle>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          {update.body ? (
            <div className="max-h-60 overflow-y-auto rounded-md border bg-muted/30 p-3 text-sm whitespace-pre-wrap text-muted-foreground">
              {update.body}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              A new version is ready to install.
            </p>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              {installing ? "Hide" : "Later"}
            </Button>
            <Button onClick={onInstall} disabled={installing}>
              {installing ? (
                <>
                  <Loader2 className="size-4 animate-spin" /> Installing…
                </>
              ) : (
                <>
                  <ArrowUpCircle className="size-4" /> Install and restart
                </>
              )}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** Present clients (have a config or use connectors) first, then by how many
 * servers they manage, then alphabetical. Keeps not-installed clients at the
 * bottom. */
function sortClients(clients: DetectedClient[]): DetectedClient[] {
  const present = (c: DetectedClient) => (c.appPresent ? 1 : 0);
  const count = (c: DetectedClient) => c.servers.length + c.pluginServers.length;
  return [...clients].sort((a, b) => {
    if (present(a) !== present(b)) return present(b) - present(a);
    if (count(a) !== count(b)) return count(b) - count(a);
    return a.name.localeCompare(b.name);
  });
}

type ClientStatus = "active" | "empty" | "error" | "missing";

function statusOf(client: DetectedClient): ClientStatus {
  if (client.error) return "error";
  // "missing" means the app itself isn't here, not merely that MCP is
  // unconfigured. A present-but-unconfigured client (installed, no servers yet)
  // is "empty", so it reads as "ready" rather than "not found".
  if (!client.appPresent) return "missing";
  return client.servers.length > 0 ? "active" : "empty";
}

const dotClass: Record<ClientStatus, string> = {
  // These dots only render for NOT-connected clients (connected ones use the
  // green chain icon), so none of them should be green - green means connected.
  active: "bg-muted-foreground/50",
  empty: "bg-muted-foreground/40",
  error: "bg-warning",
  missing: "bg-muted-foreground/20",
};

interface RowProps {
  client: DetectedClient;
  importCount: number;
  selected: boolean;
  onSelect: () => void;
}

/** A client row is about two things only: is Toolport connected here, and is
 * there anything left to import. Raw server counts are deliberately gone -
 * client inventory isn't something you manage from the sidebar. */
function ClientRow({ client, importCount, selected, onSelect }: RowProps) {
  const status = statusOf(client);
  const missing = status === "missing";
  const connected = client.gatewayInstalled;

  // Label the exception, not the rule. The green chain icon already says
  // "connected", so we don't repeat the word on every row - that just buries the
  // one row that isn't connected under a wall of green. Only non-connected /
  // error / missing states get a status word, so "not connected" actually stands
  // out. The import backlog is a separate, secondary badge either way.
  const statusWord =
    status === "error"
      ? "error"
      : status === "missing"
        ? "not found"
        : connected
          ? null
          : "not connected";
  const showBadge = importCount > 0 && status !== "error" && status !== "missing";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          onClick={onSelect}
          className={`${NAV_ITEM} ${selected ? "bg-accent" : ""} ${
            missing ? "opacity-50" : ""
          }`}
        >
          {connected ? (
            <Link2 className="size-3.5 shrink-0 text-success" />
          ) : client.usesConnectors ? (
            <Puzzle className="size-3.5 shrink-0 text-info" />
          ) : (
            <span className={`size-2 shrink-0 rounded-full ${dotClass[status]}`} />
          )}
          <span className="truncate">{client.name}</span>
          <span className="ml-auto flex shrink-0 items-center gap-1.5">
            {showBadge && (
              <span className="inline-flex items-center gap-0.5 rounded-full bg-owned/15 px-1.5 text-[10px] font-medium text-owned">
                <Download className="size-2.5" />
                {importCount}
              </span>
            )}
            {statusWord && (
              <span
                className={`text-xs ${
                  status === "error" ? "text-warning" : "text-muted-foreground"
                }`}
              >
                {statusWord}
              </span>
            )}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" className="max-w-xs">
        <p className="font-mono text-xs break-all">
          {client.configPath || "path unavailable on this OS"}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {connected
            ? "Toolport is the gateway here. Other entries are just import sources."
            : "Connect Toolport here, and import any servers you want it to manage."}
        </p>
        {client.usesConnectors && (
          <p className="mt-1 text-xs text-info">
            Manages servers as account connectors, outside the config file.
          </p>
        )}
        {client.error && <p className="mt-1 text-xs text-warning">{client.error}</p>}
      </TooltipContent>
    </Tooltip>
  );
}

interface Props {
  clients: DetectedClient[];
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
  selectedClientId: string | null;
  onSelectClient: (id: string | null) => void;
  view: View;
  onSelectView: (view: View) => void;
  onReplayOnboarding: () => void;
}

export function AppSidebar({
  clients,
  registry,
  onRegistryChange,
  selectedClientId,
  onSelectClient,
  view,
  onSelectView,
  onReplayOnboarding,
}: Props) {
  const [showMissing, setShowMissing] = useState(false);
  const [savings, setSavings] = useState<SavingsSummary | null>(null);
  const sorted = sortClients(clients);
  const detectedClients = sorted.filter((c) => statusOf(c) !== "missing");
  const missingClients = sorted.filter((c) => statusOf(c) === "missing");

  // Surface the running token savings in the sidebar so the headline number isn't
  // hidden one click away in Activity. Refresh on a light interval as calls flow.
  useEffect(() => {
    let alive = true;
    const load = () =>
      getSavingsSummary()
        .then((s) => alive && setSavings(s))
        .catch(() => {});
    load();
    const id = setInterval(load, 60_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  // One sidebar nav row. The active row gets the accent background, a foreground
  // icon (not muted), and aria-current so screen readers announce the selection.
  const navItem = (
    Icon: typeof Layers,
    label: string,
    active: boolean,
    onClick: () => void,
  ) => (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={`${NAV_ITEM} ${active ? "bg-accent font-medium text-foreground" : "text-muted-foreground"}`}
    >
      <Icon
        className={`size-4 shrink-0 ${active ? "text-primary" : "text-muted-foreground"}`}
      />
      <span>{label}</span>
    </button>
  );

  return (
    <aside className="flex h-screen w-72 shrink-0 flex-col border-r bg-sidebar">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <svg className="size-8" viewBox="0 0 48 48" aria-hidden="true">
          <rect width="48" height="48" rx="11" fill="#1E3A66" />
          <circle
            cx="24"
            cy="24"
            r="18.28"
            fill="none"
            stroke="#ffffff"
            strokeWidth="8.44"
          />
          <g fill="#1E3A66">
            <polygon points="24.00,3.47 22.05,4.59 22.05,6.84 24.00,7.97 25.95,6.84 25.95,4.59" />
            <polygon points="42.28,21.75 40.33,22.88 40.33,25.12 42.28,26.25 44.23,25.12 44.23,22.88" />
            <polygon points="24.00,40.03 22.05,41.16 22.05,43.41 24.00,44.53 25.95,43.41 25.95,41.16" />
            <polygon points="5.72,21.75 3.77,22.88 3.77,25.12 5.72,26.25 7.67,25.12 7.67,22.88" />
          </g>
          <g fill="#ffffff">
            <polygon points="24.00,4.78 23.19,5.25 23.19,6.19 24.00,6.66 24.81,6.19 24.81,5.25" />
            <polygon points="42.28,23.06 41.47,23.53 41.47,24.47 42.28,24.94 43.09,24.47 43.09,23.53" />
            <polygon points="24.00,41.34 23.19,41.81 23.19,42.75 24.00,43.22 24.81,42.75 24.81,41.81" />
            <polygon points="5.72,23.06 4.91,23.53 4.91,24.47 5.72,24.94 6.53,24.47 6.53,23.53" />
          </g>
          <circle cx="24" cy="24" r="4.88" fill="#F97316" />
        </svg>
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">Toolport</div>
          <div className="text-xs text-muted-foreground">MCP control center</div>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        {registry && (
          <div className="px-3 pb-2">
            <div className="px-2.5 pb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
              Profile
            </div>
            <ProfileBar registry={registry} onChange={onRegistryChange} />
          </div>
        )}

        <nav aria-label="Views" className="flex flex-col gap-0.5 px-3 pt-2">
          {navItem(
            Layers,
            "All servers",
            view === "servers" && selectedClientId === null,
            () => onSelectClient(null),
          )}
          {navItem(Store, "Browse catalog", view === "catalog", () =>
            onSelectView("catalog"),
          )}
          {navItem(FlaskConical, "Playground", view === "playground", () =>
            onSelectView("playground"),
          )}
          {navItem(ScrollText, "Activity", view === "activity", () =>
            onSelectView("activity"),
          )}
          {navItem(Users, "Teams", view === "teams", () => onSelectView("teams"))}
          {navItem(Settings, "Settings", view === "settings", () =>
            onSelectView("settings"),
          )}
        </nav>

        {savings && savings.tokensSaved > 0 && (
          <button
            onClick={() => onSelectView("activity")}
            className="mx-3 mt-2 flex items-center gap-2 rounded-lg border border-success/30 bg-success/5 px-3 py-2 text-left text-xs transition-colors hover:bg-success/10"
            title="Tool-definition tokens lazy discovery has kept out of your agent's context. Click for the breakdown."
          >
            <Zap className="size-3.5 shrink-0 text-success" />
            <span className="text-muted-foreground">
              <span className="font-semibold text-foreground">
                {fmtTokens(savings.tokensSaved)}
              </span>{" "}
              tokens saved
            </span>
          </button>
        )}

        <div className="px-3 pt-3">
          <div className="px-2.5 pb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            Clients
          </div>
          <nav className="flex flex-col gap-0.5">
            {clients.length === 0 ? (
              <p className="px-2.5 py-1.5 text-xs text-muted-foreground">
                No MCP clients found. Install Claude Desktop, Cursor, or another supported
                tool, then refresh.
              </p>
            ) : (
              <>
                {detectedClients.map((client) => (
                  <ClientRow
                    key={client.id}
                    client={client}
                    importCount={importableServers(client, registry).length}
                    selected={view === "servers" && selectedClientId === client.id}
                    onSelect={() => onSelectClient(client.id)}
                  />
                ))}
                {missingClients.length > 0 && (
                  <>
                    <button
                      onClick={() => setShowMissing((v) => !v)}
                      className={`mt-1 flex w-full items-center gap-2 rounded-md px-2.5 py-1.5 text-left text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground ${FOCUS_RING}`}
                    >
                      <ChevronRight
                        className={`size-3.5 shrink-0 transition-transform ${showMissing ? "rotate-90" : ""}`}
                      />
                      <span>Not detected</span>
                      <span className="ml-auto">{missingClients.length}</span>
                    </button>
                    {showMissing &&
                      missingClients.map((client) => (
                        <ClientRow
                          key={client.id}
                          client={client}
                          importCount={importableServers(client, registry).length}
                          selected={view === "servers" && selectedClientId === client.id}
                          onSelect={() => onSelectClient(client.id)}
                        />
                      ))}
                  </>
                )}
              </>
            )}
          </nav>
        </div>
      </div>

      <VersionFooter onImport={onRegistryChange} onReplay={onReplayOnboarding} />
    </aside>
  );
}
