import { Boxes, Layers, Link2, Puzzle, ScrollText, Store } from "lucide-react";
import {
  importableServers,
  type DetectedClient,
  type Registry,
} from "@/lib/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ProfileBar } from "@/components/ProfileBar";

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
  if (!client.configExists) return "missing";
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
  view: "servers" | "activity" | "catalog";
  onSelectView: (view: "servers" | "activity" | "catalog") => void;
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
        <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <Boxes className="size-5" />
        </div>
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
          {sortClients(clients).map((client) => (
            <ClientRow
              key={client.id}
              client={client}
              importCount={importableServers(client, registry).length}
              selected={view === "servers" && selectedClientId === client.id}
              onSelect={() => onSelectClient(client.id)}
            />
          ))}
        </nav>
      </div>
    </aside>
  );
}
