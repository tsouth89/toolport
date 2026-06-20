import { useEffect, useState } from "react";
import {
  ArrowUpCircle,
  FlaskConical,
  FolderOpen,
  Layers,
  Link2,
  Puzzle,
  ScrollText,
  Share2,
  Store,
} from "lucide-react";
import { getVersion } from "@tauri-apps/api/app";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  importableServers,
  type DetectedClient,
  type Registry,
} from "@/lib/types";
import { latestRelease, openDataDir } from "@/lib/api";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ProfileBar } from "@/components/ProfileBar";
import { ShareDialog } from "@/components/ShareDialog";

/** True if `latest` is a higher semver than `current` (tolerates a leading "v"). */
function isNewer(latest: string, current: string): boolean {
  const parse = (v: string) =>
    v.replace(/^v/, "").split(".").map((n) => parseInt(n, 10) || 0);
  const a = parse(latest);
  const b = parse(current);
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return false;
}

/** Footer showing the running version, and an update link when a newer release
 * exists. The update check is best-effort: any failure just shows the version. */
function VersionFooter({ onImport }: { onImport: (r: Registry) => void }) {
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    getVersion().then((v) => {
      if (!alive) return;
      setVersion(v);
      latestRelease()
        .then((tag) => {
          if (alive && isNewer(tag, v)) setUpdate(tag);
        })
        .catch(() => {});
    });
    return () => {
      alive = false;
    };
  }, []);

  if (!version) return null;
  return (
    <div className="mt-auto flex items-center justify-between gap-2 border-t px-4 py-3 text-xs">
      {update ? (
        <button
          onClick={() =>
            openUrl("https://github.com/tsouth89/conduit/releases/latest")
          }
          className="flex min-w-0 items-center gap-1.5 text-emerald-400 transition hover:underline"
        >
          <ArrowUpCircle className="size-3.5 shrink-0" />
          <span className="truncate">Update available ({update})</span>
        </button>
      ) : (
        <span className="text-muted-foreground">Conduit v{version}</span>
      )}
      <div className="flex shrink-0 items-center gap-2">
        <ShareDialog
          onImported={onImport}
          trigger={
            <button
              title="Share or import a setup"
              aria-label="Share setup"
              className="text-muted-foreground transition hover:text-foreground"
            >
              <Share2 className="size-3.5" />
            </button>
          }
        />
        <button
          onClick={() => openDataDir().catch(() => {})}
          title="Open data folder (config, logs)"
          aria-label="Open data folder"
          className="text-muted-foreground transition hover:text-foreground"
        >
          <FolderOpen className="size-3.5" />
        </button>
      </div>
    </div>
  );
}

/** Present clients (have a config or use connectors) first, then by how many
 * servers they manage, then alphabetical. Keeps not-installed clients at the
 * bottom. */
function sortClients(clients: DetectedClient[]): DetectedClient[] {
  const present = (c: DetectedClient) => (c.configExists || c.usesConnectors ? 1 : 0);
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
  active: "bg-emerald-400",
  empty: "bg-muted-foreground/40",
  error: "bg-amber-400",
  missing: "bg-muted-foreground/20",
};

interface RowProps {
  client: DetectedClient;
  importCount: number;
  selected: boolean;
  onSelect: () => void;
}

/** A client row is about two things only: is Conduit connected here, and is
 * there anything left to import. Raw server counts are deliberately gone -
 * client inventory isn't something you manage from the sidebar. */
function ClientRow({ client, importCount, selected, onSelect }: RowProps) {
  const status = statusOf(client);
  const missing = status === "missing" && !client.usesConnectors;
  const connected = client.gatewayInstalled;

  const right =
    status === "error"
      ? "error"
      : status === "missing"
        ? "not found"
        : importCount > 0
          ? `${importCount} to import`
          : connected
            ? "connected"
            : "ready";

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          onClick={onSelect}
          className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${
            selected ? "bg-accent" : ""
          } ${missing ? "opacity-50" : ""}`}
        >
          {connected ? (
            <Link2 className="size-3.5 shrink-0 text-emerald-400" />
          ) : client.usesConnectors ? (
            <Puzzle className="size-3.5 shrink-0 text-violet-400" />
          ) : (
            <span className={`size-2 shrink-0 rounded-full ${dotClass[status]}`} />
          )}
          <span className="truncate">{client.name}</span>
          <span
            className={`ml-auto shrink-0 text-xs ${
              importCount > 0 ? "text-sky-400" : "text-muted-foreground"
            }`}
          >
            {right}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" className="max-w-xs">
        <p className="font-mono text-xs break-all">
          {client.configPath || "path unavailable on this OS"}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          {connected
            ? "Conduit is the gateway here. Other entries are just import sources."
            : "Connect Conduit here, and import any servers you want it to manage."}
        </p>
        {client.usesConnectors && (
          <p className="mt-1 text-xs text-violet-300">
            Manages servers as account connectors, outside the config file.
          </p>
        )}
        {client.error && <p className="mt-1 text-xs text-amber-400">{client.error}</p>}
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
  view: "servers" | "activity" | "catalog" | "playground";
  onSelectView: (view: "servers" | "activity" | "catalog" | "playground") => void;
}

export function AppSidebar({
  clients,
  registry,
  onRegistryChange,
  selectedClientId,
  onSelectClient,
  view,
  onSelectView,
}: Props) {
  return (
    <aside className="flex w-72 shrink-0 flex-col border-r bg-sidebar">
      <div className="flex items-center gap-2.5 px-4 py-4">
        <svg className="size-8" viewBox="0 0 48 48" aria-hidden="true">
          <rect width="48" height="48" rx="12" fill="#34d399" />
          <g fill="none" stroke="#06140e" strokeWidth="2.9" strokeLinecap="round">
            <path d="M33.6 12.5 A 15 15 0 1 0 33.6 35.5" />
            <path d="M30.2 16.7 A 9.4 9.4 0 1 0 30.2 31.3" />
            <circle cx="33" cy="24" r="2.7" fill="#06140e" stroke="none" />
          </g>
        </svg>
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">Conduit</div>
          <div className="text-xs text-muted-foreground">MCP control center</div>
        </div>
      </div>

      {registry && (
        <div className="px-3 pb-2">
          <div className="px-2.5 pb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            Profile
          </div>
          <ProfileBar registry={registry} onChange={onRegistryChange} />
        </div>
      )}

      <div className="flex flex-col gap-0.5 px-3 pt-2">
        <button
          onClick={() => onSelectClient(null)}
          className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${
            view === "servers" && selectedClientId === null ? "bg-accent" : ""
          }`}
        >
          <Layers className="size-4 shrink-0 text-muted-foreground" />
          <span>All servers</span>
        </button>
        <button
          onClick={() => onSelectView("catalog")}
          className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${
            view === "catalog" ? "bg-accent" : ""
          }`}
        >
          <Store className="size-4 shrink-0 text-muted-foreground" />
          <span>Browse catalog</span>
        </button>
        <button
          onClick={() => onSelectView("playground")}
          className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${
            view === "playground" ? "bg-accent" : ""
          }`}
        >
          <FlaskConical className="size-4 shrink-0 text-muted-foreground" />
          <span>Playground</span>
        </button>
        <button
          onClick={() => onSelectView("activity")}
          className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-sm transition-colors hover:bg-accent ${
            view === "activity" ? "bg-accent" : ""
          }`}
        >
          <ScrollText className="size-4 shrink-0 text-muted-foreground" />
          <span>Activity</span>
        </button>
      </div>

      <div className="px-3 pt-3">
        <div className="px-2.5 pb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Clients
        </div>
        <nav className="flex flex-col gap-0.5">
          {clients.length === 0 ? (
            <p className="px-2.5 py-1.5 text-xs text-muted-foreground">
              No MCP clients found. Install Claude Desktop, Cursor, or another
              supported tool, then refresh.
            </p>
          ) : (
            sortClients(clients).map((client) => (
              <ClientRow
                key={client.id}
                client={client}
                importCount={importableServers(client, registry).length}
                selected={view === "servers" && selectedClientId === client.id}
                onSelect={() => onSelectClient(client.id)}
              />
            ))
          )}
        </nav>
      </div>

      <VersionFooter onImport={onRegistryChange} />
    </aside>
  );
}
