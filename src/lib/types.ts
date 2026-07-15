export type Transport = "stdio" | "http" | "sse" | "unknown";

/** The main content views, selected from the sidebar. */
export type View =
  "servers" | "activity" | "catalog" | "playground" | "teams" | "settings";

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
  /** How long a gated call waited for a human approval decision, ms. Present on
   * `kind:"approval"` records instead of durationMs (which is downstream exec time). */
  heldMs?: number;
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

/** One lazy-discovery search: what the model searched for and what came back, with
 * the ground-truth token cost of the results vs. loading the whole catalog. */
export interface SearchTrace {
  ts: number;
  client?: string;
  query: string;
  server?: string;
  top: string;
  names: string[];
  returned: number;
  total: number;
  /** Full count of appended recovery candidates. Absent on older traces. */
  fallbacks?: number;
  /** Tool-definition tokens the returned schemas cost this turn (≈). */
  returnedTokens: number;
  /** Tool-definition tokens advertising the whole (scoped) catalog would cost (≈). */
  flatTokens: number;
  /** flatTokens - returnedTokens: the context kept out of the model this turn. */
  savedTokens: number;
  /** The loop-breaker fired: repeated searches kept landing on the same top tool. */
  escalated: boolean;
  /** Ranker used: keyword-only (`lexical`) or semantic re-rank. Absent on older traces. */
  mode?: "lexical" | "semantic";
  /** Per-result explanation, in result order: why each tool surfaced. Absent on older
   * traces (fall back to `names`). */
  ranking?: SearchTraceRank[];
}

/** Why one tool surfaced in a lazy-discovery search. */
export interface SearchTraceRank {
  name: string;
  /** 1-based position in the returned results. */
  rank: number;
  /** Query terms this tool matched, e.g. "products (name)". Empty when it surfaced
   * without a keyword hit (a semantic match or a pinned prerequisite). */
  matched: string[];
  /** A pinned prerequisite prepended ahead of the ranked matches, not a query hit. */
  pinned: boolean;
  /** A zero-score recovery candidate appended because the direct search was weak. */
  fallback?: boolean;
}

/** One exposed tool's verifiable identity: the model-visible alias joined back to its
 * source server + profiles, with the integrity fingerprint and first-seen/last-changed. */
export interface ToolIdentity {
  alias: string;
  serverId: string;
  serverName: string;
  profiles: string[];
  upstream: string;
  fingerprint: string;
  firstSeen: number;
  lastChanged: number;
  quarantined: boolean;
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
  /** Downstream tool round-trips collapsed into single code-mode run_script calls.
   * Absent in older savings logs written before code mode. */
  roundTripsSaved?: number;
}

export interface AuthInfo {
  kind: "none" | "oauth" | "token" | "unknown";
  vendor: string | null;
  tokenUrl: string | null;
  instructions: string | null;
}

/** One server a shared setup would add, shown for review before importing. */
export interface ImportItem {
  /** Opaque key used to confirm a detected-client import. Absent for shared setups. */
  key?: string;
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
  /** Working directory for a stdio server. Unset = inherit the gateway's cwd.
   * `~` and `${VAR}` are expanded. Lets a server run in a project dir (#239). */
  cwd?: string | null;
}

export interface Profile {
  id: string;
  name: string;
  enabledServerIds: string[];
  /** Tool-granular scope ("FeatureSet"): server id -> the only tool names this profile
   * exposes on that server. A server absent = all its tools; empty/absent = server-granular
   * only. Enforced in tools/list, search, and the call guard. */
  toolScope?: Record<string, string[]>;
}

/** A folder -> profile auto-routing mapping (SOU-188): a client whose reported project
 * root is `path` or a descendant auto-scopes to `profile` (a profile id or name), the
 * longest matching path wins. Empty list = no folder routing. */
export interface FolderProfile {
  path: string;
  profile: string;
}

/** A tool call held awaiting a human decision (the HITL approval queue). */
export interface PendingApproval {
  id: string;
  client: string | null;
  server: string;
  tool: string;
  toolFingerprint?: string | null;
  reason: "destructive" | "untrusted_source" | "destructive_and_untrusted";
  arguments: unknown;
  /** Wall-clock epoch-ms when this call auto-denies; the overlay counts down to it. */
  deadlineMs: number;
}

/** A tool the user allowed to skip human approval (Settings "Allowed tools" list). */
export interface AllowedTool {
  key: string;
  server: string;
  tool: string;
  /** true = persisted ("always"); false = only for this app session. */
  persistent: boolean;
}

/** A per-tool exposure override, keyed in `Registry.toolOverrides` by server id then
 * original tool name. Rename and/or replace the description clients see; the call still
 * routes to the original downstream tool. */
export interface ToolOverride {
  name?: string;
  description?: string;
}

export interface Registry {
  version: number;
  servers: ServerEntry[];
  profiles: Profile[];
  activeProfileId: string | null;
  /** Folder -> profile auto-routing mappings. Absent/empty = no folder routing. */
  folderProfiles?: FolderProfile[];
  /** Per-tool exposure overrides (rename / re-describe), keyed by server id then original tool name. */
  toolOverrides?: Record<string, Record<string, ToolOverride>>;
  /** Tools pinned as lazy-discovery prerequisites, keyed by server id -> original tool names. */
  pinnedTools?: Record<string, string[]>;
  /** Global switch: hide and block every destructive-hinted tool. */
  denyDestructive?: boolean;
  /** Per-call confirmation: intercept destructive tools with a preview + token. */
  confirmDestructive?: boolean;
  /** Human-in-the-loop: hold a gated tool call until a person approves it in the app. */
  humanApproval?: boolean;
  /** Live request/response inspection: capture each tool call's args + result into a
   * small, separate, ephemeral local ring (last 50 calls) for the Activity inspector.
   * Off by default; never touches the audit log. */
  liveInspect?: boolean;
  /** Quarantine-on-drift: block a high-risk tool that changed until re-approved. */
  quarantineOnDrift?: boolean;
  /** Global switch: expose 4 meta-tools instead of the full catalog. */
  lazyDiscovery?: boolean;
  /** Global discovery mode ("full" | "lazy" | "grouped"). Takes precedence over
   * `lazyDiscovery`; absent = fall back to the `lazyDiscovery` bool. */
  discoveryMode?: string | null;
  /** Per-client discovery-mode override, keyed by client id (e.g. "cursor" ->
   * "grouped"). Absent = that client inherits the global mode. */
  clientDiscovery?: Record<string, string>;
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
function isGatewayIdentity(id: string, name: string, command: string | null): boolean {
  const normalizedId = id.toLowerCase();
  const normalizedName = name.toLowerCase();
  const normalizedCommand = command?.toLowerCase() ?? "";
  return (
    normalizedId === "conduit" ||
    normalizedId === "toolport" ||
    normalizedName === "conduit" ||
    normalizedName === "toolport" ||
    // Current binary name and the pre-rename one, so an entry written by an older
    // Toolport is still recognized as the gateway.
    normalizedCommand.includes("toolport-gateway") ||
    normalizedCommand.includes("conduit-gateway")
  );
}

export function isGatewayServer(server: ServerEntry): boolean {
  return isGatewayIdentity(server.id, server.name, server.command);
}

/** Servers a client has (config + plugins) that Toolport doesn't manage yet.
 * These are the only client-side entries worth surfacing - they're import
 * candidates. Toolport's own gateway entry is never importable. */
export function importableServers(
  client: DetectedClient,
  registry: Registry | null,
): McpServer[] {
  const have = new Set((registry?.servers ?? []).map((s) => s.name.toLowerCase()));
  return [...client.servers, ...client.pluginServers].filter(
    (server) =>
      !isGatewayIdentity(server.name, server.name, server.command) &&
      !have.has(server.name.toLowerCase()),
  );
}
