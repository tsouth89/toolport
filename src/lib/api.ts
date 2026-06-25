import { invoke } from "@tauri-apps/api/core";
import type {
  AuditEntry,
  AuditStats,
  AuthInfo,
  CatalogEntry,
  DetectedClient,
  ImportItem,
  McpTool,
  MigrateResult,
  ProbeResult,
  Registry,
  SavingsSummary,
  ServerEntry,
  ToolCallResult,
  WriteOutcome,
} from "./types";

/** The hand-verified popular catalog (offline, instant). */
export function popularCatalog(): Promise<CatalogEntry[]> {
  return invoke<CatalogEntry[]>("popular_catalog");
}

/** Search the catalog (your picks + curated, then the MCP Registry). */
export function searchCatalog(query: string): Promise<CatalogEntry[]> {
  return invoke<CatalogEntry[]>("search_catalog", { query });
}

/** Promote one of your registry servers into your personal catalog. */
export function promoteToCatalog(serverId: string): Promise<void> {
  return invoke<void>("promote_to_catalog", { serverId });
}

/** Remove an entry from your personal catalog by name. */
export function unpromoteFromCatalog(name: string): Promise<void> {
  return invoke<void>("unpromote_from_catalog", { name });
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
  type: string;
  server: string;
  tool: string;
  change: string;
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

/** Toggle global lazy discovery (meta-tools vs full catalog) for all clients. */
export function setLazyDiscovery(lazy: boolean): Promise<Registry> {
  return invoke<Registry>("set_lazy_discovery", { lazy });
}

/** Opt into agent control: let an agent enable/disable servers via the gateway. */
export function setAllowAgentControl(allow: boolean): Promise<Registry> {
  return invoke<Registry>("set_allow_agent_control", { allow });
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
): Promise<string> {
  return invoke<string>("export_config", {
    name: name ?? null,
    description: description ?? null,
  });
}

/** Write the shareable setup to a file on disk (path from a save dialog). */
export function exportConfigToPath(
  path: string,
  name?: string,
  description?: string,
): Promise<void> {
  return invoke<void>("export_config_to_path", {
    path,
    name: name ?? null,
    description: description ?? null,
  });
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
