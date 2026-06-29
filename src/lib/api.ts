import { invoke } from "@tauri-apps/api/core";
import type {
  AuditEntry,
  AuditStats,
  AuthInfo,
  CatalogEntry,
  DetectedClient,
  ImportItem,
  McpPrompt,
  McpResource,
  McpTool,
  MigrateResult,
  ParsedSnippetServer,
  ProbeResult,
  Registry,
  SavingsSummary,
  ServerEntry,
  ToolCallResult,
  Stack,
  WriteOutcome,
} from "./types";

/** The hand-verified popular catalog (offline, instant). */
export function popularCatalog(): Promise<CatalogEntry[]> {
  return invoke<CatalogEntry[]>("popular_catalog");
}

/** Curated stacks: role-based server bundles for one-flow setup (offline). */
export function listStacks(): Promise<Stack[]> {
  return invoke<Stack[]>("list_stacks");
}

/** Search the catalog (your picks + curated, then the MCP Registry). */
export function searchCatalog(query: string): Promise<CatalogEntry[]> {
  return invoke<CatalogEntry[]>("search_catalog", { query });
}

/** Recent tool-call audit entries (newest first). */
export function getAuditLog(limit = 200): Promise<AuditEntry[]> {
  return invoke<AuditEntry[]>("get_audit_log", { limit });
}

/** Aggregated per-server stats (calls, error rate, latency) from the audit log. */
export function getAuditStats(window = 2000): Promise<AuditStats> {
  return invoke<AuditStats>("audit_stats", { window });
}

/** A tool-definition integrity event: a previously-approved tool changed
 * (rug-pull signal) or a known server added a tool. */
export interface SecurityEvent {
  ts: number;
  /** "tool_drift" (definition changed/added) or "tool_poison_flag" (injection in a definition). */
  type: string;
  /** Absent for events not tied to a specific tool (e.g. pins_load_failed). */
  server?: string;
  tool?: string;
  change: string;
  /** For tool_poison_flag: which heuristic signatures matched. */
  signatures?: string[];
}

/** Recent tool-definition integrity events (newest first). */
export function getSecurityEvents(limit = 100): Promise<SecurityEvent[]> {
  return invoke<SecurityEvent[]>("get_security_events", { limit });
}

/** Cumulative tokens lazy discovery has kept out of client context. */
export function getSavingsSummary(): Promise<SavingsSummary> {
  return invoke<SavingsSummary>("savings_summary");
}

/** A shareable diagnostics blob (version, registry summary, gateway log tail) for bug reports. */
export function gatherDiagnostics(): Promise<string> {
  return invoke<string>("gather_diagnostics");
}

/** Connect to each enabled server and report health + tool count. */
export function probeServers(): Promise<ProbeResult[]> {
  return invoke<ProbeResult[]>("probe_servers");
}

/** Connect to a (possibly unsaved) server entry to verify it works before
 * saving. Typed secret values ride in on `entry.env`; nothing is persisted. */
export function testServer(entry: ServerEntry): Promise<ProbeResult> {
  return invoke<ProbeResult>("test_server", { entry });
}

/** Result of registering an HTTP-bridge client: the updated registry plus the
 * plaintext bearer token, shown once and never returned again. */
export interface AddedHttpClient {
  registry: Registry;
  token: string;
}

/** Register an HTTP-bridge client scoped to a profile (empty = all servers).
 * Returns the one-time plaintext token to paste into the client. */
export function addHttpClient(
  label: string,
  profile?: string,
): Promise<AddedHttpClient> {
  return invoke<AddedHttpClient>("add_http_client", { label, profile });
}

/** Revoke a registered HTTP-bridge client by id. */
export function removeHttpClient(id: string): Promise<Registry> {
  return invoke<Registry>("remove_http_client", { id });
}

/** List the tools one server exposes (connects on demand). Playground picker. */
export function listServerTools(serverId: string): Promise<McpTool[]> {
  return invoke<McpTool[]>("list_server_tools", { serverId });
}

/** Invoke one tool on a server and return its raw MCP result. */
export function callTool(
  serverId: string,
  tool: string,
  args: Record<string, unknown>,
): Promise<ToolCallResult> {
  return invoke<ToolCallResult>("call_tool", { serverId, tool, arguments: args });
}

/** List the resources one server advertises (connects on demand). Playground. */
export function listServerResources(serverId: string): Promise<McpResource[]> {
  return invoke<McpResource[]>("list_server_resources", { serverId });
}

/** List the prompts one server advertises (connects on demand). Playground. */
export function listServerPrompts(serverId: string): Promise<McpPrompt[]> {
  return invoke<McpPrompt[]>("list_server_prompts", { serverId });
}

/** Read one resource by uri; returns the raw MCP result (`{ contents }`). */
export function readResource(serverId: string, uri: string): Promise<unknown> {
  return invoke("read_resource", { serverId, uri });
}

/** Get one prompt by name with arguments; returns the raw MCP result. */
export function getPrompt(
  serverId: string,
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  return invoke("get_prompt", { serverId, name, arguments: args });
}

/** Enable/disable one tool on a server (gateway hides+blocks disabled tools). */
export function setToolEnabled(
  serverId: string,
  tool: string,
  enabled: boolean,
): Promise<Registry> {
  return invoke<Registry>("set_tool_enabled", { serverId, tool, enabled });
}

/** Toggle the global destructive-tool deny switch. */
export function setDenyDestructive(deny: boolean): Promise<Registry> {
  return invoke<Registry>("set_deny_destructive", { deny });
}

/** Toggle per-call confirmation for destructive tools (intercept + preview + token). */
export function setConfirmDestructive(confirm: boolean): Promise<Registry> {
  return invoke<Registry>("set_confirm_destructive", { confirm });
}

/** Toggle global lazy discovery (meta-tools vs full catalog) for all clients. */
export function setLazyDiscovery(lazy: boolean): Promise<Registry> {
  return invoke<Registry>("set_lazy_discovery", { lazy });
}

/** Opt into agent control: let an agent enable/disable servers via the gateway. */
export function setAllowAgentControl(allow: boolean): Promise<Registry> {
  return invoke<Registry>("set_allow_agent_control", { allow });
}

export interface HttpBridgeStatus {
  running: boolean;
  port: number | null;
  url: string | null;
  token: string | null;
}

/** Start the supervised conduit-gateway HTTP/OpenAPI server (Open WebUI etc.). */
export function startHttpBridge(port?: number): Promise<HttpBridgeStatus> {
  return invoke<HttpBridgeStatus>("start_http_bridge", { port: port ?? null });
}

/** Stop the supervised HTTP/OpenAPI server. */
export function stopHttpBridge(): Promise<HttpBridgeStatus> {
  return invoke<HttpBridgeStatus>("stop_http_bridge");
}

/** Current HTTP/OpenAPI bridge status (reaps the child if it exited). */
export function httpBridgeStatus(): Promise<HttpBridgeStatus> {
  return invoke<HttpBridgeStatus>("http_bridge_status");
}

/** Join a Conduit Teams server with an invite code; merges the team's servers in. */
export function teamConnect(
  serverUrl: string,
  inviteCode: string,
  memberName?: string,
): Promise<Registry> {
  return invoke<Registry>("team_connect", {
    serverUrl,
    inviteCode,
    memberName: memberName ?? null,
  });
}

/** Pull the latest team config and re-merge it (no-op if unchanged). */
export function teamSync(): Promise<Registry> {
  return invoke<Registry>("team_sync");
}

/** Leave the team: remove its merged servers and clear the saved token. */
export function teamDisconnect(): Promise<Registry> {
  return invoke<Registry>("team_disconnect");
}

/** Admin: push the current local server set as the team's shared config; returns version. */
export function teamPush(): Promise<number> {
  return invoke<number>("team_push");
}

/** Probe every supported MCP client and read its current server configuration. */
export function detectClients(): Promise<DetectedClient[]> {
  return invoke<DetectedClient[]>("detect_clients");
}

/** Install the Conduit gateway into a client's config, optionally scoped to a
 * profile (by name). Omit profile to expose all enabled servers. */
export function installGateway(
  clientId: string,
  profile?: string,
): Promise<WriteOutcome> {
  return invoke<WriteOutcome>("install_gateway", {
    clientId,
    profile: profile ?? null,
  });
}

/** Remove the Conduit gateway from a client's config. */
export function uninstallGateway(clientId: string): Promise<WriteOutcome> {
  return invoke<WriteOutcome>("uninstall_gateway", { clientId });
}

/** Import a client's servers into Conduit, then leave the client with only the
 * Conduit gateway (optionally scoped to a profile). Backs up the config first. */
export function migrateClient(
  clientId: string,
  profile?: string,
): Promise<MigrateResult> {
  return invoke<MigrateResult>("migrate_client", {
    clientId,
    profile: profile ?? null,
  });
}

/** Store a secret env value in the OS keychain. */
export function setSecret(
  serverId: string,
  key: string,
  value: string,
): Promise<Registry> {
  return invoke<Registry>("set_secret", { serverId, key, value });
}

/** Remove a secret from the keychain and the server entry. */
export function deleteSecret(serverId: string, key: string): Promise<Registry> {
  return invoke<Registry>("delete_secret", { serverId, key });
}

/** For each env key, whether a value is currently vaulted. */
export function secretStatus(
  serverId: string,
  keys: string[],
): Promise<[string, boolean][]> {
  return invoke<[string, boolean][]>("secret_status", { serverId, keys });
}

/** Store a bearer token for a remote (http) server. */
export function setAuthToken(serverId: string, token: string): Promise<void> {
  return invoke<void>("set_auth_token", { serverId, token });
}

export function clearAuthToken(serverId: string): Promise<void> {
  return invoke<void>("clear_auth_token", { serverId });
}

export function hasAuthToken(serverId: string): Promise<boolean> {
  return invoke<boolean>("has_auth_token", { serverId });
}

/** Run the OAuth 2.1 browser flow for a remote server; vaults the access token. */
export function authenticateOauth(serverId: string, url: string): Promise<void> {
  return invoke<void>("authenticate_oauth", { serverId, url });
}

/** Detect what a remote server needs to connect (none/oauth/token) + guidance. */
export function probeAuth(url: string): Promise<AuthInfo> {
  return invoke<AuthInfo>("probe_auth", { url });
}

/** Open Conduit's data directory (registry, logs, audit) in the OS file manager. */
export function openDataDir(): Promise<void> {
  return invoke<void>("open_data_dir");
}

/** Serialize the user's servers into a shareable setup (no secret values),
 * optionally labelled with a name + description. */
export function exportConfig(
  name?: string,
  description?: string,
  serverNames?: string[],
): Promise<string> {
  return invoke<string>("export_config", {
    name: name ?? null,
    description: description ?? null,
    serverNames: serverNames ?? null,
  });
}

/** Write the shareable setup to a file on disk (path from a save dialog). */
export function exportConfigToPath(
  path: string,
  name?: string,
  description?: string,
  serverNames?: string[],
): Promise<void> {
  return invoke<void>("export_config_to_path", {
    path,
    name: name ?? null,
    description: description ?? null,
    serverNames: serverNames ?? null,
  });
}

/** Turn a shareable setup (from exportConfig) into a conduitmcp.app/s/<id> link. */
export function shareStack(setupJson: string): Promise<string> {
  return invoke<string>("share_stack", { setupJson });
}

/** Fetch a shared setup's JSON by id (resolving a conduit://import?s=<id> link). */
export function fetchSharedSetup(id: string): Promise<string> {
  return invoke<string>("fetch_shared_setup", { id });
}

/** Claim a share id captured from a deep link before the UI was listening. */
export function takePendingShared(): Promise<string | null> {
  return invoke<string | null>("take_pending_shared");
}

/** Import a shared setup, adding servers not already present. */
export function importConfig(json: string): Promise<Registry> {
  return invoke<Registry>("import_config", { json });
}

/** Read a shared-setup file from disk (path from an open dialog), size-capped. */
export function readSetupFile(path: string): Promise<string> {
  return invoke<string>("read_setup_file", { path });
}

/** Parse a shared setup and report what it would add, without importing. */
export function previewImport(json: string): Promise<ImportItem[]> {
  return invoke<ImportItem[]>("preview_import", { json });
}

/** Enable or disable every server in a profile at once. */
export function setAllEnabled(
  profileId: string,
  enabled: boolean,
): Promise<Registry> {
  return invoke<Registry>("set_all_enabled", { profileId, enabled });
}

/** Load Conduit's registry (servers + profiles). */
export function getRegistry(): Promise<Registry> {
  return invoke<Registry>("get_registry");
}

/** Pull servers from every detected client into the registry. */
export function importServers(): Promise<Registry> {
  return invoke<Registry>("import_servers");
}

/** Parse a pasted config snippet (JSON/TOML/YAML/CLI), auto-detecting format. */
export function parseServerSnippet(text: string): Promise<ParsedSnippetServer[]> {
  return invoke<ParsedSnippetServer[]>("parse_server_snippet", { text });
}

export function addServer(entry: ServerEntry): Promise<Registry> {
  return invoke<Registry>("add_server", { entry });
}

/** Add a catalog entry as a registry server (the user vaults any keys after). */
export function addCatalogServer(entry: CatalogEntry): Promise<Registry> {
  const server: ServerEntry = {
    id: "",
    name: entry.name,
    transport: entry.transport,
    command: entry.command,
    args: entry.args,
    env: entry.envKeys.map((key) => ({ key, value: null, secret: true })),
    url: entry.url,
    source: `catalog:${entry.source}`,
  };
  return addServer(server);
}

export function updateServer(entry: ServerEntry): Promise<Registry> {
  return invoke<Registry>("update_server", { entry });
}

export function removeServer(id: string): Promise<Registry> {
  return invoke<Registry>("remove_server", { id });
}

export function setServerEnabled(
  profileId: string,
  serverId: string,
  enabled: boolean,
): Promise<Registry> {
  return invoke<Registry>("set_server_enabled", { profileId, serverId, enabled });
}

export function createProfile(name: string): Promise<Registry> {
  return invoke<Registry>("create_profile", { name });
}

export function deleteProfile(id: string): Promise<Registry> {
  return invoke<Registry>("delete_profile", { id });
}

export function setActiveProfile(id: string): Promise<Registry> {
  return invoke<Registry>("set_active_profile", { id });
}
