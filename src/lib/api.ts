import { invoke } from "@tauri-apps/api/core";
import type {
  AuditEntry,
  AuditStats,
  AuthInfo,
  CatalogEntry,
  DetectedClient,
  FolderProfile,
  ImportItem,
  InspectEntry,
  McpPrompt,
  McpResource,
  McpTool,
  MigrateResult,
  ParsedSnippetServer,
  AllowedTool,
  PendingApproval,
  ProbeResult,
  Registry,
  SavingsSummary,
  SearchTrace,
  ToolIdentity,
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
  /** For tool_poison_flag: a short de-obfuscated excerpt of the matched text, so the
   * flag is verifiable instead of an opaque label. Absent when no direct phrase matched
   * (e.g. an encoded payload) or on events written before evidence was captured. */
  evidence?: string;
  /** "high" = loud/actionable (poison, destructive-tool change, safety-annotation
   * downgrade); "info" = benign non-destructive schema churn for the quiet history.
   * Absent on events written before severity tiering; classified by type on read. */
  severity?: "high" | "info";
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
export function addHttpClient(label: string, profile?: string): Promise<AddedHttpClient> {
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

/** Pin/unpin a tool as a lazy-discovery prerequisite (search always surfaces it). */
export function setToolPinned(
  serverId: string,
  tool: string,
  pinned: boolean,
): Promise<Registry> {
  return invoke<Registry>("set_tool_pinned", { serverId, tool, pinned });
}

/** Toggle the global destructive-tool deny switch. */
export function setDenyDestructive(deny: boolean): Promise<Registry> {
  return invoke<Registry>("set_deny_destructive", { deny });
}

/** Toggle per-call confirmation for destructive tools (intercept + preview + token). */
export function setConfirmDestructive(confirm: boolean): Promise<Registry> {
  return invoke<Registry>("set_confirm_destructive", { confirm });
}

/** Toggle human-in-the-loop approval: hold a gated tool call (destructive, or from an
 * untrusted-provenance server) until a person approves or denies it in the app. */
export function setHumanApproval(on: boolean): Promise<Registry> {
  return invoke<Registry>("set_human_approval", { on });
}

/** Tool calls currently held awaiting a human decision (the approval queue). */
export function listPendingApprovals(): Promise<PendingApproval[]> {
  return invoke<PendingApproval[]>("list_pending_approvals");
}

/** How long an approval sticks: `once` (this call only), `session` (until the app
 * restarts), or `always` (persisted, skips the prompt for this tool from now on). */
export type ApprovalScope = "once" | "session" | "always";

/** Approve or deny a held tool call by id; the parked gateway call then runs or is refused.
 * On approve, `scope` controls whether future calls to the same tool skip the prompt. */
export function decideApproval(
  id: string,
  approved: boolean,
  scope: ApprovalScope = "once",
): Promise<void> {
  return invoke<void>("decide_approval", { id, approved, scope });
}

/** Tools currently allowed to skip human approval (persistent "always" + this session). */
export function listAllowedTools(): Promise<AllowedTool[]> {
  return invoke<AllowedTool[]>("list_allowed_tools");
}

/** Revoke an allowed tool so it requires approval again. */
export function revokeAllowedTool(key: string): Promise<void> {
  return invoke<void>("revoke_allowed_tool", { key });
}

/** Set (or clear) a per-tool exposure override, keyed by `(server, original tool)`:
 * rename and/or replace the description clients see. Blank name + description clears it.
 * The call still routes to the original downstream tool. */
export function setToolOverride(
  server: string,
  tool: string,
  name: string | null,
  description: string | null,
): Promise<Registry> {
  return invoke<Registry>("set_tool_override", { server, tool, name, description });
}

/** Remove a tool's exposure override, restoring the server's own name + description. */
export function clearToolOverride(server: string, tool: string): Promise<Registry> {
  return invoke<Registry>("clear_tool_override", { server, tool });
}

/** Toggle live request/response inspection (opt-in, off by default). When on, the
 * gateway captures each tool call's args + result into a small ephemeral local ring. */
export function setLiveInspect(enabled: boolean): Promise<Registry> {
  return invoke<Registry>("set_live_inspect", { enabled });
}

/** Recent live-inspection captures (newest first): each call's args + result. Empty
 * unless live inspection has been on. */
export function getInspectLog(limit = 50): Promise<InspectEntry[]> {
  return invoke<InspectEntry[]>("get_inspect_log", { limit });
}

/** Clear the live-inspection ring so no captured args/results linger. */
export function clearInspectLog(): Promise<void> {
  return invoke<void>("clear_inspect_log");
}

/** Recent lazy-discovery search traces (newest first): what the model searched for,
 * which tools matched, and the tool-definition tokens the results cost vs. loading the
 * whole catalog. Empty until something has searched. */
export function getSearchTraces(limit = 100): Promise<SearchTrace[]> {
  return invoke<SearchTrace[]>("get_search_traces", { limit });
}

/** Clear the search-trace log. */
export function clearSearchTraces(): Promise<void> {
  return invoke<void>("clear_search_traces");
}

/** Clear all retained local activity at once: audit log, discovery traces,
 * live-inspection captures, and the savings tally (incl. its carry-forward total).
 * Local, irreversible deletes; each log re-creates itself on the next event. */
export function clearActivityLogs(): Promise<void> {
  return invoke<void>("clear_activity_logs");
}

/** Every pinned tool's verifiable identity (alias -> server/profiles + fingerprint +
 * first-seen/last-changed) for the active profile. Empty until a baseline is pinned. */
export function getToolIdentities(): Promise<ToolIdentity[]> {
  return invoke<ToolIdentity[]>("list_tool_identities");
}

/** Toggle quarantine-on-drift: block a high-risk tool that drifted until re-approved. */
export function setQuarantineOnDrift(on: boolean): Promise<Registry> {
  return invoke<Registry>("set_quarantine_on_drift", { on });
}

/** A tool blocked after a high-risk drift, awaiting re-approval. */
export interface QuarantinedTool {
  server: string;
  tool: string;
  reason: string;
  ts: number;
  profile: string;
}

/** Tools currently quarantined (blocked after a high-risk drift), across profiles. */
export function listQuarantined(): Promise<QuarantinedTool[]> {
  return invoke<QuarantinedTool[]>("list_quarantined");
}

/** Re-approve a quarantined tool so the gateway re-exposes it on its next rebuild. */
export function releaseQuarantine(profile: string, tool: string): Promise<void> {
  return invoke<void>("release_quarantine", { profile, tool });
}

/** Toggle global lazy discovery (meta-tools vs full catalog) for all clients. */
export function setLazyDiscovery(lazy: boolean): Promise<Registry> {
  return invoke<Registry>("set_lazy_discovery", { lazy });
}

/** Override one client's discovery mode ("full" | "lazy" | "grouped"), or clear it
 * (`null`) so the client inherits the global mode. Applies live via the gateway's
 * per-client resolution, no reconnect needed. */
export function setClientDiscovery(
  clientId: string,
  mode: string | null,
): Promise<Registry> {
  return invoke<Registry>("set_client_discovery", { clientId, mode });
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

/** Start the supervised toolport-gateway HTTP/OpenAPI server (Open WebUI etc.). */
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

/**
 * Result of {@link teamConnect} / {@link teamJoinPoll}. `status` is:
 * - `connected` — joined; `registry` is the fresh merged state.
 * - `pending` — the link requires admin approval; poll `requestToken` via {@link teamJoinPoll}.
 * - `denied` — an admin declined the request.
 * - `unknown` — the request expired or is invalid; start over.
 */
export interface TeamConnectResult {
  status: "connected" | "pending" | "denied" | "unknown";
  registry?: Registry;
  requestToken?: string;
}

/** Join a Toolport Teams server with an invite or join-link code; merges the team's servers in. */
export function teamConnect(
  serverUrl: string,
  inviteCode: string,
  memberName?: string,
): Promise<TeamConnectResult> {
  return invoke<TeamConnectResult>("team_connect", {
    serverUrl,
    inviteCode,
    memberName: memberName ?? null,
  });
}

/**
 * Poll a pending, approval-gated join. Call on an interval after {@link teamConnect} returns
 * `status: "pending"`, passing back the `requestToken` and the same `memberName`. Resolves to
 * `connected` once an admin approves, or `pending` / `denied` / `unknown`.
 */
export function teamJoinPoll(
  serverUrl: string,
  requestToken: string,
  memberName?: string,
): Promise<TeamConnectResult> {
  return invoke<TeamConnectResult>("team_join_poll", {
    serverUrl,
    requestToken,
    memberName: memberName ?? null,
  });
}

/** Pull the latest team config and re-merge it (no-op if unchanged). */
export function teamSync(): Promise<Registry> {
  return invoke<Registry>("team_sync");
}

/**
 * Long-polling sync: parks on the server for up to `waitSecs` and returns the instant the
 * team config view changes (or the wait elapses), so a dashboard policy edit enforces in
 * ~1s. Drive it in a loop; it returns like {@link teamSync}.
 */
export function teamSyncWait(waitSecs: number): Promise<Registry> {
  return invoke<Registry>("team_sync_wait", { waitSecs });
}

/** Leave the team: remove its merged servers and clear the saved token. */
export function teamDisconnect(): Promise<Registry> {
  return invoke<Registry>("team_disconnect");
}

export interface TeamPushPreview {
  baseVersion: number;
  localFingerprint: string;
  added: string[];
  changed: string[];
  removed: string[];
}

/** Admin: compare the local server export with the team's current shared server list. */
export function teamPushPreview(): Promise<TeamPushPreview> {
  return invoke<TeamPushPreview>("team_push_preview");
}

/** Admin: apply an explicitly previewed shared-server replacement; returns version. */
export function teamPush(preview: TeamPushPreview): Promise<number> {
  return invoke<number>("team_push", {
    baseVersion: preview.baseVersion,
    localFingerprint: preview.localFingerprint,
  });
}

/** Probe every supported MCP client and read its current server configuration. */
export function detectClients(): Promise<DetectedClient[]> {
  return invoke<DetectedClient[]>("detect_clients");
}

/** Install the Toolport gateway into a client's config, optionally scoped to a
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

/** Remove the Toolport gateway from a client's config. */
export function uninstallGateway(clientId: string): Promise<WriteOutcome> {
  return invoke<WriteOutcome>("uninstall_gateway", { clientId });
}

/** Import a client's servers into Toolport, then leave the client with only the
 * Toolport gateway (optionally scoped to a profile). Backs up the config first. */
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

/** Open Toolport's data directory (registry, logs, audit) in the OS file manager. */
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

/** Export the audit/activity log to a file (path from a save dialog). */
export function exportAuditToPath(path: string, format: "csv" | "json"): Promise<void> {
  return invoke<void>("export_audit_to_path", { path, format });
}

/** Turn a shareable setup (from exportConfig) into a toolport.app/s/<id> link. */
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
export function setAllEnabled(profileId: string, enabled: boolean): Promise<Registry> {
  return invoke<Registry>("set_all_enabled", { profileId, enabled });
}

/** Load Toolport's registry (servers + profiles). */
export function getRegistry(): Promise<Registry> {
  return invoke<Registry>("get_registry");
}

/** One-time notice after the registry was recovered from `.bak` on launch. */
export interface RegistryRecoveryNotice {
  recoveredAtMs: number;
  reason: string;
  quarantinePath?: string | null;
}

export function takeRegistryRecoveryNotice(): Promise<RegistryRecoveryNotice | null> {
  return invoke<RegistryRecoveryNotice | null>("take_registry_recovery_notice");
}

/** Pull reviewed servers from every detected client into the registry. */
export function importServers(selected?: string[]): Promise<Registry> {
  return invoke<Registry>("import_servers", { selected });
}

/** Preview every detected-client server the bulk import would add. */
export function previewImportServers(): Promise<ImportItem[]> {
  return invoke<ImportItem[]>("preview_import_servers");
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

/** Set (or clear with `null`) a profile's tool-granular scope for one server (SOU-189):
 * the only original tool names that profile exposes on that server. `null`/empty = all. */
export function setProfileServerTools(
  profileId: string,
  serverId: string,
  tools: string[] | null,
): Promise<Registry> {
  return invoke<Registry>("set_profile_server_tools", {
    profileId,
    serverId,
    tools,
  });
}

/** Replace the folder -> profile auto-routing mappings (SOU-188). */
export function setFolderProfiles(mappings: FolderProfile[]): Promise<Registry> {
  return invoke<Registry>("set_folder_profiles", { mappings });
}
