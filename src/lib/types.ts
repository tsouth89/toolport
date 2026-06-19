export type Transport = "stdio" | "http" | "sse" | "unknown";

export interface McpServer {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  /** Env-variable names only. Values are never sent from the backend. */
  envKeys: string[];
  url: string | null;
}

export interface DetectedClient {
  id: string;
  name: string;
  usesConnectors: boolean;
  configPath: string;
  configExists: boolean;
  servers: McpServer[];
  /** Servers found outside the config file (e.g. Cursor plugins); read-only. */
  pluginServers: McpServer[];
  gatewayInstalled: boolean;
  error: string | null;
}

export interface WriteOutcome {
  path: string;
  backup: string | null;
}

export interface MigrateResult {
  registry: Registry;
  imported: number;
  moved: string[];
}

export interface AuditEntry {
  ts: number;
  server: string;
  tool: string;
  ok: boolean;
}

export interface ProbeResult {
  serverId: string;
  ok: boolean;
  toolCount: number;
  error: string | null;
  /** Failure looks like missing credentials (remote 401/403, or unvaulted secret). */
  authRequired: boolean;
}

export interface AuthInfo {
  kind: "none" | "oauth" | "token" | "unknown";
  vendor: string | null;
  tokenUrl: string | null;
  instructions: string | null;
}

/** An addable server from the catalog (curated seed or the live MCP Registry). */
export interface CatalogEntry {
  name: string;
  description: string;
  transport: Transport;
  command: string | null;
  args: string[];
  url: string | null;
  envKeys: string[];
  source: "curated" | "registry" | "user";
  homepage: string | null;
}

/** A server merged across every client that has it configured. */
export interface AggregatedServer {
  name: string;
  transport: Transport;
  command: string | null;
  url: string | null;
  args: string[];
  envKeys: string[];
  clients: { id: string; name: string }[];
}

/** Group the per-client server lists into one deduplicated, cross-client view. */
export function aggregateServers(clients: DetectedClient[]): AggregatedServer[] {
  const byName = new Map<string, AggregatedServer>();

  for (const client of clients) {
    for (const server of client.servers) {
      const key = server.name.toLowerCase();
      const existing = byName.get(key);
      if (existing) {
        existing.clients.push({ id: client.id, name: client.name });
      } else {
        byName.set(key, {
          name: server.name,
          transport: server.transport,
          command: server.command,
          url: server.url,
          args: server.args,
          envKeys: server.envKeys,
          clients: [{ id: client.id, name: client.name }],
        });
      }
    }
  }

  return [...byName.values()].sort((a, b) =>
    a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
  );
}

// --- Conduit registry (source of truth) ---

export interface EnvVar {
  key: string;
  value: string | null;
  secret: boolean;
}

export interface ServerEntry {
  id: string;
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  env: EnvVar[];
  url: string | null;
  source: string | null;
}

export interface Profile {
  id: string;
  name: string;
  enabledServerIds: string[];
}

export interface Registry {
  version: number;
  servers: ServerEntry[];
  profiles: Profile[];
  activeProfileId: string | null;
}

export function activeProfile(registry: Registry): Profile | undefined {
  return (
    registry.profiles.find((p) => p.id === registry.activeProfileId) ??
    registry.profiles[0]
  );
}

export function isEnabled(registry: Registry, serverId: string): boolean {
  return activeProfile(registry)?.enabledServerIds.includes(serverId) ?? false;
}

/** Whether a registry entry is Conduit's own gateway. It's infrastructure, not a
 * proxied server, so it shouldn't appear as a manageable server in the UI.
 * Mirrors `is_gateway_server` in the Rust backend. */
export function isGatewayServer(server: ServerEntry): boolean {
  const name = server.name.toLowerCase();
  return (
    server.id === "conduit" ||
    name === "conduit" ||
    (server.command?.toLowerCase().includes("conduit-gateway") ?? false)
  );
}

/** Servers a client has (config + plugins) that Conduit doesn't manage yet.
 * These are the only client-side entries worth surfacing - they're import
 * candidates. Conduit's own gateway entry is never importable. */
export function importableServers(
  client: DetectedClient,
  registry: Registry | null,
): McpServer[] {
  const have = new Set(
    (registry?.servers ?? []).map((s) => s.name.toLowerCase()),
  );
  return [...client.servers, ...client.pluginServers].filter(
    (s) =>
      s.name.toLowerCase() !== "conduit" && !have.has(s.name.toLowerCase()),
  );
}
