export type Transport = "stdio" | "http" | "sse" | "unknown";

/** The main content views, selected from the sidebar. */
export type View =
  | "servers"
  | "activity"
  | "catalog"
  | "playground"
  | "teams"
  | "settings";

export interface McpServer {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  /** Env-variable names only. Values are never sent from the backend. */
  envKeys: string[];
  url: string | null;
}

/** A server parsed from a pasted config snippet. Includes env-var values. */
export interface ParsedSnippetServer {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  url: string | null;
  env: { key: string; value: string | null }[];
}

export interface DetectedClient {
  id: string;
  name: string;
  usesConnectors: boolean;
  configPath: string;
  configExists: boolean;
  /** Whether the client app appears installed (its data dir exists), even if it
   * has no MCP config yet. Distinguishes "installed, no servers" from "not here". */
  appPresent: boolean;
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
  /** How long the call took, ms. Absent for records logged before timing. */
  durationMs?: number;
  /** Short failure message for a failed call (never args or result data). */
  error?: string;
  /** A destructive call held for confirmation (not a success and not an error). */
  held?: boolean;
  /** The registered HTTP client that made the call, when known. Absent for the
   * local desktop client and legacy/open tokens. */
  client?: string;
}

/** One live-inspection capture: a tool call's request args and response, plus timing.
 * Only present while live inspection is on. `request`/`response` are the raw captured
 * bodies (or a "<truncated N bytes>" marker string when the body exceeded the size cap). */
export interface InspectEntry {
  ts: number;
  client?: string;
  server: string;
  tool: string;
  request: unknown;
  response: unknown;
  ok: boolean;
  durationMs?: number;
}

export interface ProbeResult {
  serverId: string;
  ok: boolean;
  toolCount: number;
  error: string | null;
  /** Failure looks like missing credentials (remote 401/403, or unvaulted secret). */
  authRequired: boolean;
}

/** A tool as advertised by a downstream MCP server (raw `tools/list` entry). */
export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, JsonSchemaProp>;
    required?: string[];
  };
  /** MCP tool annotations. `destructiveHint` marks a tool that deletes/writes;
   * some servers also emit it at the top level, so both are tolerated. */
  annotations?: { destructiveHint?: boolean; [k: string]: unknown };
  destructiveHint?: boolean;
}

/** A resource as advertised by a downstream server (raw `resources/list` entry). */
export interface McpResource {
  uri: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

/** A prompt as advertised by a downstream server (raw `prompts/list` entry). */
export interface McpPrompt {
  name: string;
  title?: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
}

/** The subset of JSON Schema the playground form renders per argument. */
export interface JsonSchemaProp {
  type?: string | string[];
  description?: string;
  enum?: unknown[];
  default?: unknown;
  items?: JsonSchemaProp;
}

/** Raw MCP `tools/call` result: content blocks plus an error flag. */
export interface ToolCallResult {
  content?: Array<{ type: string; text?: string; [k: string]: unknown }>;
  isError?: boolean;
  [k: string]: unknown;
}

/** Per-tool aggregate within a server (calls, error rate, latency). */
export interface ToolStat {
  tool: string;
  calls: number;
  errors: number;
  errorRate: number;
  avgMs: number | null;
  p95Ms: number | null;
  lastTs: number;
}

/** Per-server aggregate from the audit log (calls, error rate, latency). */
export interface ServerStat {
  server: string;
  calls: number;
  errors: number;
  errorRate: number;
  avgMs: number | null;
  p95Ms: number | null;
  lastTs: number;
  /** Per-tool breakdown, busiest first. */
  tools: ToolStat[];
}

export interface AuditStats {
  total: number;
  errors: number;
  errorRate: number;
  servers: ServerStat[];
}

/** Cumulative tool-definition tokens lazy discovery kept out of client context. */
export interface SavingsSummary {
  tokensSaved: number;
  listLoads: number;
  peakCatalog: number;
  sinceTs: number;
}

export interface AuthInfo {
  kind: "none" | "oauth" | "token" | "unknown";
  vendor: string | null;
  tokenUrl: string | null;
  instructions: string | null;
}

/** One server a shared setup would add, shown for review before importing. */
export interface ImportItem {
  name: string;
  transport: Transport;
  command: string | null;
  args: string[];
  url: string | null;
  /** False if a server with this name is already present (import skips it). */
  isNew: boolean;
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
  /** Publishing namespace from the registry (who published it), if known. */
  publisher?: string | null;
  /** Curated browse-view grouping (e.g. "Databases"); absent for registry/user. */
  category?: string;
  /** Direct link to create this server's credential (provider token page). */
  credentialsUrl?: string;
  /** One-line hint on what credential to create (scopes, what to paste). */
  setupHint?: string;
  /** Placeholder for URL field when self-hosted (opens dialog on add). */
  urlHint?: string;
}

/** A curated "stack": a role-based bundle of catalog servers for guided setup. */
export interface Stack {
  id: string;
  name: string;
  description: string;
  /** The stack's servers, resolved to full catalog entries (with cred hints). */
  servers: CatalogEntry[];
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

// --- Toolport registry (source of truth) ---

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
  /** Original tool names switched off; hidden from clients by the gateway. */
  disabledTools?: string[];
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
  /** Global switch: hide and block every destructive-hinted tool. */
  denyDestructive?: boolean;
  /** Per-call confirmation: intercept destructive tools with a preview + token. */
  confirmDestructive?: boolean;
  /** Live request/response inspection: capture each tool call's args + result into a
   * small, separate, ephemeral local ring (last 50 calls) for the Activity inspector.
   * Off by default; never touches the audit log. */
  liveInspect?: boolean;
  /** Quarantine-on-drift: block a high-risk tool that changed until re-approved. */
  quarantineOnDrift?: boolean;
  /** Global switch: expose 3 meta-tools instead of the full catalog. */
  lazyDiscovery?: boolean;
  /** Opt-in: let an agent enable/disable servers via the gateway's control tools. */
  allowAgentControl?: boolean;
  /** Connection to a Toolport Teams server, if joined. Token lives in the keychain. */
  team?: TeamConnection | null;
  /** Per-server result-shaping budgets in bytes, keyed by server id. Absent =
   * global default; 0 = never shape (full fidelity); n = cap that server at n bytes. */
  resultBudgets?: Record<string, number>;
  /** Which profile each client was connected with, keyed by client id (e.g.
   * "cursor" -> "Billing"). Absent = that client follows the active profile. */
  clientScopes?: Record<string, string>;
  /** Consumers registered to reach the gateway over the HTTP/OpenAPI bridge,
   * each with its own hashed token and scope (multi-tenant bridge). */
  httpClients?: HttpClient[];
}

/** A consumer registered to reach the HTTP/OpenAPI bridge with its own token and
 * scope. The plaintext token is shown once at creation, never stored. */
export interface HttpClient {
  id: string;
  label: string;
  /** SHA-256 of the bearer token (the plaintext is never returned again). */
  tokenSha256: string;
  /** Profile this client is scoped to; empty = the full connected set. */
  profile: string;
}

/** A joined Toolport Teams server (the shared config-sync layer). */
export interface TeamConnection {
  serverUrl: string;
  teamId: string;
  /** "admin" | "member" */
  role: string;
  memberName?: string | null;
  /** Last team config version pulled. */
  lastVersion?: number;
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

/** Whether a registry entry is Toolport's own gateway. It's infrastructure, not a
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

/** Servers a client has (config + plugins) that Toolport doesn't manage yet.
 * These are the only client-side entries worth surfacing - they're import
 * candidates. Toolport's own gateway entry is never importable. */
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
