import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Bot,
  Braces,
  Check,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  FolderOpen,
  FolderTree,
  Globe,
  Layers,
  Monitor,
  Moon,
  Pin,
  Power,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Sun,
  Trash2,
  UserCheck,
  X,
} from "lucide-react";
import {
  disable as disableAutostart,
  enable as enableAutostart,
  isEnabled as isAutostartEnabled,
} from "@tauri-apps/plugin-autostart";
import { open as openFolderDialog } from "@tauri-apps/plugin-dialog";
import { toastError } from "@/lib/toast";
import {
  addHttpClient,
  clearInspectLog,
  httpBridgeStatus,
  listAllowedTools,
  listQuarantined,
  listServerTools,
  setProfileServerTools,
  releaseQuarantine,
  revokeAllowedTool,
  removeHttpClient,
  setAllowAgentControl,
  setConfirmDestructive,
  setDenyDestructive,
  setCodeMode,
  setHumanApproval,
  setLazyDiscovery,
  setFolderProfiles,
  setLiveInspect,
  setQuarantineOnDrift,
  setToolPinned,
  startHttpBridge,
  stopHttpBridge,
  type HttpBridgeStatus,
  type QuarantinedTool,
} from "@/lib/api";
import type { AllowedTool, FolderProfile, Profile, Registry } from "@/lib/types";
import { isGatewayServer } from "@/lib/types";
import { useTheme, type Theme } from "@/lib/theme";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** The set of tools pinned as lazy-discovery prerequisites, with one-click unpin.
 * Pinning happens contextually (a tool's card in Playground); this is where you see
 * and manage the whole set. Reads `registry.pinnedTools` (server id -> tool names). */
function PinnedPrerequisites({
  registry,
  onRegistryChange,
}: {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const nameOf = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of registry?.servers ?? []) m.set(s.id, s.name);
    return m;
  }, [registry?.servers]);
  const pins = useMemo(() => {
    const out: { serverId: string; server: string; tool: string }[] = [];
    for (const [serverId, tools] of Object.entries(registry?.pinnedTools ?? {})) {
      for (const tool of tools) {
        out.push({ serverId, server: nameOf.get(serverId) ?? serverId, tool });
      }
    }
    return out.sort((a, b) =>
      `${a.server}${a.tool}`.localeCompare(`${b.server}${b.tool}`),
    );
  }, [registry?.pinnedTools, nameOf]);

  async function unpin(serverId: string, tool: string) {
    setBusy(`${serverId}:${tool}`);
    try {
      onRegistryChange(await setToolPinned(serverId, tool, false));
    } catch (e) {
      toastError(`Couldn't unpin the tool: ${e}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="rounded-lg border border-border/60 bg-muted/20 p-3">
      <div className="flex items-center gap-2 text-xs">
        <Pin className="size-3.5 shrink-0 text-info" />
        <span className="font-medium">Pinned prerequisites</span>
        <span className="rounded-full bg-muted px-1.5 py-0.5 text-muted-foreground">
          {pins.length}
        </span>
        <span className="ml-auto text-muted-foreground">
          always surfaced in search, with full schema
        </span>
      </div>
      {pins.length === 0 ? (
        <p className="mt-2 max-w-2xl text-xs text-muted-foreground">
          None yet. Pin a load-bearing tool (auth, list-before-act, or one whose
          description doesn&apos;t match your keywords) from its card in Playground, so
          lazy discovery never hides it.
        </p>
      ) : (
        <ul className="mt-2 space-y-1">
          {pins.map((p) => (
            <li
              key={`${p.serverId}:${p.tool}`}
              className="flex items-center gap-2 text-xs"
            >
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-foreground/90">
                {p.tool}
              </code>
              <span className="text-muted-foreground">{p.server}</span>
              <button
                onClick={() => unpin(p.serverId, p.tool)}
                disabled={busy === `${p.serverId}:${p.tool}`}
                aria-label={`Unpin ${p.tool}`}
                className="ml-auto rounded p-0.5 text-muted-foreground/60 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border disabled:opacity-50"
              >
                <X className="size-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Folder -> profile auto-routing (SOU-188): map a project folder to a profile so a client
 * opened in that folder auto-scopes to it, no manual profile switch. Reads/writes
 * `registry.folderProfiles`; the longest matching path wins at match time. stdio clients. */
function FolderRouting({
  registry,
  onRegistryChange,
}: {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}) {
  const mappings = registry?.folderProfiles ?? [];
  const profiles = registry?.profiles ?? [];
  const [path, setPath] = useState("");
  const [profile, setProfile] = useState("");
  const [busy, setBusy] = useState(false);

  async function save(next: FolderProfile[]) {
    setBusy(true);
    try {
      onRegistryChange(await setFolderProfiles(next));
    } catch (e) {
      toastError(`Couldn't save folder routing: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function browse() {
    try {
      const picked = await openFolderDialog({
        directory: true,
        multiple: false,
        title: "Choose a project folder",
      });
      if (typeof picked === "string") setPath(picked);
    } catch (e) {
      toastError(`Couldn't open the folder picker: ${e}`);
    }
  }

  async function add() {
    const p = path.trim();
    if (!p || !profile) return;
    // Replace any existing mapping for the same path rather than duplicating it.
    const next = [...mappings.filter((m) => m.path.trim() !== p), { path: p, profile }];
    await save(next);
    setPath("");
    setProfile("");
  }

  // A mapping's profile is stored as an id or name; show the profile's display name.
  const label = (ref: string) =>
    profiles.find((p) => p.id === ref || p.name === ref)?.name ?? ref;

  return (
    <div className="rounded-lg border border-border/60 bg-muted/20 p-3">
      <div className="flex items-center gap-2 text-xs">
        <FolderTree className="size-3.5 shrink-0 text-info" />
        <span className="font-medium">Project folder routing</span>
        <span className="rounded-full bg-muted px-1.5 py-0.5 text-muted-foreground">
          {mappings.length}
        </span>
        <span className="ml-auto text-muted-foreground">
          auto-scope a client by the folder it opens in
        </span>
      </div>
      {mappings.length > 0 && (
        <ul className="mt-2 space-y-1">
          {mappings.map((m) => (
            <li key={m.path} className="flex items-center gap-2 text-xs">
              <code className="truncate rounded bg-muted px-1.5 py-0.5 font-mono text-foreground/90">
                {m.path}
              </code>
              <span className="shrink-0 text-muted-foreground">&rarr;</span>
              <span className="shrink-0 text-foreground/90">{label(m.profile)}</span>
              <button
                onClick={() => save(mappings.filter((x) => x.path !== m.path))}
                disabled={busy}
                aria-label={`Remove routing for ${m.path}`}
                className="ml-auto rounded p-0.5 text-muted-foreground/60 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border disabled:opacity-50"
              >
                <X className="size-3.5" />
              </button>
            </li>
          ))}
        </ul>
      )}
      {profiles.length === 0 ? (
        <p className="mt-2 text-xs text-muted-foreground">
          Create a profile first, then map a folder to it here.
        </p>
      ) : (
        <div className="mt-2 flex items-center gap-2">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void add();
            }}
            placeholder="/path/to/project"
            className="min-w-0 flex-1 rounded border bg-background px-2 py-1 font-mono text-xs focus-visible:ring-1 focus-visible:ring-border focus-visible:outline-none"
          />
          <button
            type="button"
            onClick={() => void browse()}
            disabled={busy}
            aria-label="Browse for a project folder"
            title="Browse…"
            className="flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-xs font-medium hover:bg-muted disabled:opacity-50"
          >
            <FolderOpen className="size-3.5" />
            Browse
          </button>
          <Select value={profile} onValueChange={setProfile}>
            <SelectTrigger className="h-7 w-32 text-xs">
              <SelectValue placeholder="Profile" />
            </SelectTrigger>
            <SelectContent>
              {profiles.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <button
            onClick={() => void add()}
            disabled={busy || !path.trim() || !profile}
            className="shrink-0 rounded border px-2 py-1 text-xs font-medium hover:bg-muted disabled:opacity-50"
          >
            Add
          </button>
        </div>
      )}
    </div>
  );
}

interface Props {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}

/** A one-line security posture readout at the top of the Security section, so the user can
 * tell at a glance whether they're protected instead of mentally AND-ing every toggle. */
function PostureSummary({
  denyDestructive,
  confirmDestructive,
  humanApproval,
  quarantineOnDrift,
}: {
  denyDestructive: boolean;
  confirmDestructive: boolean;
  humanApproval: boolean;
  quarantineOnDrift: boolean;
}) {
  const active = [
    humanApproval && "human approval required",
    denyDestructive && "destructive tools blocked",
    confirmDestructive && "destructive calls confirmed",
    quarantineOnDrift && "drifted tools quarantined",
  ].filter(Boolean) as string[];
  // A hard gate (block or human-approval) = guarded; softer measures alone = partial.
  const gated = humanApproval || denyDestructive;
  const state = gated ? "guarded" : active.length > 0 ? "partial" : "open";
  const meta = {
    guarded: {
      Icon: ShieldCheck,
      ring: "border-success/30 bg-success/5",
      tint: "text-success",
      label: "Protected",
    },
    partial: {
      Icon: ShieldAlert,
      ring: "border-warning/35 bg-warning/5",
      tint: "text-warning",
      label: "Partly protected",
    },
    open: {
      Icon: ShieldX,
      ring: "border-destructive/35 bg-destructive/5",
      tint: "text-destructive",
      label: "Unprotected",
    },
  }[state];
  const { Icon } = meta;
  return (
    <div className={`flex items-start gap-3 rounded-lg border p-3 ${meta.ring}`}>
      <Icon className={`mt-0.5 size-4 shrink-0 ${meta.tint}`} />
      <p className="text-sm">
        <span className={`font-medium ${meta.tint}`}>{meta.label}.</span>{" "}
        <span className="text-muted-foreground">
          {state === "open"
            ? "No blocking or approval is active, so every tool call runs unattended."
            : `Active: ${active.join(", ")}.`}
        </span>
      </p>
    </div>
  );
}

/** Tool-granular scope for one profile (SOU-189): per enabled server, expand to pick exactly
 * which tools the profile exposes. All-checked = the whole server (no narrowing); unchecking
 * writes an allow-list that tools/list, search, and the call guard all honor. Tools load
 * lazily on expand. stdio clients (the per-profile router); the HTTP bridge is a follow-up. */
function ProfileToolScope({
  profile,
  registry,
  onRegistryChange,
}: {
  profile: Profile;
  registry: Registry;
  onRegistryChange: (r: Registry) => void;
}) {
  const serverName = useMemo(() => {
    const m = new Map<string, string>();
    // Toolport's own gateway is infrastructure, not a scopable server, so keep it out.
    for (const s of registry.servers) if (!isGatewayServer(s)) m.set(s.id, s.name);
    return m;
  }, [registry.servers]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [toolsByServer, setToolsByServer] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const scope = profile.toolScope ?? {};

  async function expand(serverId: string) {
    if (expanded === serverId) {
      setExpanded(null);
      return;
    }
    setExpanded(serverId);
    if (!toolsByServer[serverId]) {
      setLoading(serverId);
      try {
        const tools = await listServerTools(serverId);
        setToolsByServer((m) => ({ ...m, [serverId]: tools.map((t) => t.name) }));
      } catch (e) {
        toastError(`Couldn't load ${serverName.get(serverId) ?? serverId} tools: ${e}`);
      } finally {
        setLoading(null);
      }
    }
  }

  async function toggleTool(serverId: string, tool: string, allTools: string[]) {
    // Current in-scope set is the allow-list if present, else every tool.
    const current = new Set(scope[serverId] ?? allTools);
    if (current.has(tool)) current.delete(tool);
    else current.add(tool);
    // Every real tool selected -> clear the scope (whole server). Otherwise persist the
    // checked subset (which may be empty = expose no tools). `.every` (not a size compare)
    // so a stale entry from a since-removed tool can't fake an "all selected" state.
    const next = allTools.every((t) => current.has(t))
      ? null
      : allTools.filter((t) => current.has(t));
    setBusy(true);
    try {
      onRegistryChange(await setProfileServerTools(profile.id, serverId, next));
    } catch (e) {
      toastError(`Couldn't update tool scope: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  const servers = profile.enabledServerIds.filter((id) => serverName.has(id));
  if (servers.length === 0) return null;

  return (
    <div className="mt-1.5 flex flex-col gap-1">
      {servers.map((serverId) => {
        const allTools = toolsByServer[serverId];
        const scoped = scope[serverId];
        const badge = scoped
          ? allTools
            ? `${scoped.length} of ${allTools.length} tools`
            : `${scoped.length} tools`
          : "all tools";
        const open = expanded === serverId;
        return (
          <div key={serverId} className="rounded border border-border/50 bg-muted/10">
            <button
              onClick={() => expand(serverId)}
              className="flex w-full items-center gap-2 px-2 py-1.5 text-xs hover:bg-muted/30"
            >
              <ChevronRight
                className={`size-3.5 shrink-0 transition-transform ${open ? "rotate-90" : ""}`}
              />
              <span className="font-medium">{serverName.get(serverId)}</span>
              <span
                className={`ml-auto ${scoped ? "text-info" : "text-muted-foreground"}`}
              >
                {badge}
              </span>
            </button>
            {open && (
              <div className="border-t border-border/40 px-2 py-1.5">
                {loading === serverId ? (
                  <p className="text-xs text-muted-foreground">Loading tools…</p>
                ) : allTools && allTools.length > 0 ? (
                  <div className="flex flex-col gap-1">
                    {allTools.map((tool) => (
                      <label key={tool} className="flex items-center gap-2 text-xs">
                        <input
                          type="checkbox"
                          checked={scoped ? scoped.includes(tool) : true}
                          disabled={busy}
                          onChange={() => toggleTool(serverId, tool, allTools)}
                          className="size-3.5"
                        />
                        <code className="font-mono text-foreground/90">{tool}</code>
                      </label>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    No tools, or the server isn&apos;t reachable right now.
                  </p>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** Global discovery + security policy. These apply to every client uniformly, so
 * they live here rather than in the per-server Playground. */
export function SettingsView({ registry, onRegistryChange }: Props) {
  const { theme, setTheme } = useTheme();
  const lazyDiscovery = registry?.lazyDiscovery ?? true;
  const codeMode = registry?.codeMode ?? false;
  const denyDestructive = registry?.denyDestructive ?? false;
  const confirmDestructive = registry?.confirmDestructive ?? false;
  const humanApproval = registry?.humanApproval ?? false;
  const allowAgentControl = registry?.allowAgentControl ?? false;
  const quarantineOnDrift = registry?.quarantineOnDrift ?? false;
  const liveInspect = registry?.liveInspect ?? false;
  const [busy, setBusy] = useState(false);
  // Profile cards collapse so a big Default profile doesn't dump every server (and its
  // per-server tool rows) onto the page. Collapsed by default; the comma summary still shows.
  const [openProfiles, setOpenProfiles] = useState<Set<string>>(new Set());
  const [quarantined, setQuarantined] = useState<QuarantinedTool[]>([]);
  const [quarantineError, setQuarantineError] = useState(false);
  const [allowedTools, setAllowedTools] = useState<AllowedTool[]>([]);
  const [allowedError, setAllowedError] = useState(false);
  const [bridge, setBridge] = useState<HttpBridgeStatus | null>(null);
  const [bridgeError, setBridgeError] = useState(false);
  // Mask the bridge bearer token by default (grants any local process access to all
  // the user's tools); reveal on demand.
  const [showToken, setShowToken] = useState(false);
  const [bridgeBusy, setBridgeBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [newLabel, setNewLabel] = useState("");
  const [newProfile, setNewProfile] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);
  const [clientBusy, setClientBusy] = useState(false);
  const [autostartOn, setAutostartOn] = useState(false);

  const httpClients = registry?.httpClients ?? [];
  const profiles = registry?.profiles ?? [];
  const serverName = useMemo(() => {
    const m = new Map<string, string>();
    // Exclude Toolport's own gateway; it's infrastructure, not a profile-scopable server.
    for (const s of registry?.servers ?? []) if (!isGatewayServer(s)) m.set(s.id, s.name);
    return m;
  }, [registry?.servers]);

  // Launch-at-login is OS-level (managed by the autostart plugin), not registry state.
  useEffect(() => {
    isAutostartEnabled()
      .then(setAutostartOn)
      .catch(() => {});
  }, []);

  const toggleAutostart = async (on: boolean) => {
    setBusy(true);
    try {
      if (on) await enableAutostart();
      else await disableAutostart();
      setAutostartOn(on);
    } catch (e) {
      toastError(`Couldn't ${on ? "enable" : "disable"} launch at login: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  async function addClient() {
    if (!newLabel.trim()) return;
    setClientBusy(true);
    try {
      const res = await addHttpClient(newLabel.trim(), newProfile || undefined);
      onRegistryChange(res.registry);
      setNewToken(res.token);
      setNewLabel("");
    } catch (e) {
      toastError(`Couldn't add client: ${e}`);
    } finally {
      setClientBusy(false);
    }
  }

  async function removeClient(id: string) {
    try {
      onRegistryChange(await removeHttpClient(id));
    } catch (e) {
      toastError(`Couldn't remove client: ${e}`);
    }
  }

  // One-shot (not polled): the status only changes when the user toggles it here.
  // Exposed as a callback so a failed initial read can be retried explicitly, rather
  // than leaving the panel wedged until an app restart.
  const loadBridge = useCallback(() => {
    httpBridgeStatus()
      .then((s) => {
        setBridge(s);
        setBridgeError(false);
      })
      .catch(() => setBridgeError(true));
  }, []);
  useEffect(() => {
    loadBridge();
  }, [loadBridge]);

  useEffect(() => {
    const load = () =>
      listQuarantined()
        .then((q) => {
          setQuarantined(q);
          setQuarantineError(false);
        })
        // A failed poll must not read as "nothing quarantined": keep any prior
        // list and flag the error so the panel can say the status is stale.
        .catch(() => setQuarantineError(true));
    load();
    // Quarantine happens asynchronously in the gateway, so poll to keep the list fresh.
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const reapprove = async (q: QuarantinedTool) => {
    try {
      await releaseQuarantine(q.profile, q.tool);
      setQuarantined(await listQuarantined());
    } catch (e) {
      toastError(`Couldn't re-approve: ${e}`);
    }
  };

  // Tools the user allowed to skip human approval. Polled because "always allow" is chosen
  // from the approval overlay (a different component), so this keeps the list in sync.
  useEffect(() => {
    const load = () =>
      listAllowedTools()
        .then((t) => {
          setAllowedTools(t);
          setAllowedError(false);
        })
        .catch(() => setAllowedError(true));
    load();
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, []);

  const revokeAllowed = async (key: string) => {
    try {
      await revokeAllowedTool(key);
      setAllowedTools(await listAllowedTools());
    } catch (e) {
      toastError(`Couldn't revoke: ${e}`);
    }
  };

  const toggleBridge = async (on: boolean) => {
    setBridgeBusy(true);
    try {
      setBridge(on ? await startHttpBridge() : await stopHttpBridge());
      setBridgeError(false);
    } catch (e) {
      toastError(`Couldn't ${on ? "start" : "stop"} the HTTP endpoint: ${e}`);
    } finally {
      setBridgeBusy(false);
    }
  };

  const copy = (text: string, which: string) => {
    navigator.clipboard.writeText(text).then(
      () => {
        setCopied(which);
        setTimeout(() => setCopied(null), 1500);
      },
      () => {},
    );
  };

  const apply = (fn: (v: boolean) => Promise<Registry>) => async (v: boolean) => {
    setBusy(true);
    try {
      onRegistryChange(await fn(v));
    } catch (e) {
      toastError(`Couldn't update the setting: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  // Live inspection needs a step the plain `apply` helper doesn't: when turned OFF,
  // clear the ephemeral capture ring so nothing lingers on disk.
  const applyLiveInspect = async (on: boolean) => {
    setBusy(true);
    try {
      const reg = await setLiveInspect(on);
      if (!on) await clearInspectLog();
      onRegistryChange(reg);
    } catch (e) {
      toastError(`Couldn't update the setting: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (
    Icon: typeof Layers,
    on: boolean,
    accent: string,
    title: string,
    desc: string,
    onChange: (v: boolean) => void,
  ) => (
    <label className="flex items-center gap-2.5 rounded-md border px-3 py-2.5 text-sm">
      <Icon className={`size-4 shrink-0 ${on ? accent : "text-muted-foreground"}`} />
      <span className="flex min-w-0 flex-1 flex-col leading-tight">
        <span className="font-medium">{title}</span>
        <span className="text-xs text-muted-foreground">{desc}</span>
      </span>
      <Switch checked={on} onCheckedChange={onChange} disabled={busy} />
    </label>
  );

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          General
        </h2>
        {toggle(
          Power,
          autostartOn,
          "text-info",
          "Launch at login",
          "Start Toolport in the tray when you sign in, so it can hold tool calls for approval even before you open it",
          toggleAutostart,
        )}
        <div className="flex items-center gap-2.5 rounded-md border px-3 py-2.5 text-sm">
          <Sun className="size-4 shrink-0 text-info" />
          <span className="flex min-w-0 flex-1 flex-col leading-tight">
            <span className="font-medium">Appearance</span>
            <span className="text-xs text-muted-foreground">
              Light, dark, or follow your system setting.
            </span>
          </span>
          <div className="flex shrink-0 gap-0.5 rounded-md border bg-background p-0.5">
            {(
              [
                ["light", Sun, "Light"],
                ["system", Monitor, "System"],
                ["dark", Moon, "Dark"],
              ] as [Theme, typeof Sun, string][]
            ).map(([value, Icon, label]) => (
              <button
                key={value}
                onClick={() => setTheme(value)}
                aria-pressed={theme === value}
                title={label}
                className={`flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors ${
                  theme === value
                    ? "bg-muted font-medium text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                <Icon className="size-3.5" />
                {label}
              </button>
            ))}
          </div>
        </div>
      </section>
      {profiles.length > 0 && (
        <section className="flex flex-col gap-2">
          <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            Profiles
          </h2>
          <p className="text-xs text-muted-foreground">
            A profile is a named set of servers you can scope a client to. Expand a server
            to narrow it to specific tools (a "FeatureSet"); leaving every tool checked
            exposes the whole server. Tool narrowing applies to stdio clients (Claude
            Desktop, Cursor, VS Code, and the like); HTTP-bridge clients still see the
            whole server for now.
          </p>
          <div className="flex flex-col divide-y rounded-lg border">
            {profiles.map((p) => {
              const names = p.enabledServerIds
                .map((id) => serverName.get(id))
                .filter((n): n is string => !!n)
                .sort((a, b) => a.localeCompare(b));
              const active = p.id === registry?.activeProfileId;
              const isOpen = openProfiles.has(p.id);
              const toggle = () =>
                setOpenProfiles((prev) => {
                  const next = new Set(prev);
                  if (next.has(p.id)) next.delete(p.id);
                  else next.add(p.id);
                  return next;
                });
              return (
                <div key={p.id} className="flex flex-col gap-1 px-3 py-2.5">
                  <button
                    type="button"
                    onClick={toggle}
                    aria-expanded={isOpen}
                    disabled={names.length === 0}
                    className="flex items-center gap-2 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-border disabled:cursor-default"
                  >
                    <ChevronRight
                      className={`size-3.5 shrink-0 text-muted-foreground transition-transform ${
                        isOpen ? "rotate-90" : ""
                      } ${names.length === 0 ? "invisible" : ""}`}
                    />
                    <span className="text-sm font-medium">{p.name}</span>
                    {active && (
                      <span className="rounded-full bg-info/15 px-1.5 py-0.5 text-[10px] font-medium text-info">
                        active
                      </span>
                    )}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {names.length} {names.length === 1 ? "server" : "servers"}
                    </span>
                  </button>
                  {names.length === 0 ? (
                    <p className="pl-5 text-xs text-muted-foreground italic">
                      No servers in this profile.
                    </p>
                  ) : isOpen ? (
                    registry && (
                      <ProfileToolScope
                        profile={p}
                        registry={registry}
                        onRegistryChange={onRegistryChange}
                      />
                    )
                  ) : (
                    <p className="truncate pl-5 text-xs text-muted-foreground">
                      {names.join(", ")}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
          <FolderRouting registry={registry} onRegistryChange={onRegistryChange} />
        </section>
      )}
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Discovery
        </h2>
        {toggle(
          Layers,
          lazyDiscovery,
          "text-info",
          "Lazy discovery",
          "Expose 4 meta-tools, not the full catalog (all clients)",
          apply(setLazyDiscovery),
        )}
        {/* Pinned prerequisites is a refinement of lazy discovery (the tools it must never
            hide), not a peer feature, so nest it under the Lazy discovery toggle with an
            indent + left rail. It has no meaning when lazy discovery is off, so it collapses
            away entirely then. Code mode below is an independent capability and stays a
            full-width sibling. */}
        {lazyDiscovery ? (
          <div className="ml-4 border-l-2 border-border/50 pl-3">
            <PinnedPrerequisites
              registry={registry}
              onRegistryChange={onRegistryChange}
            />
          </div>
        ) : null}
        {toggle(
          Braces,
          codeMode,
          "text-info",
          "Code mode",
          "Let agents run one server-side script that calls many tools in a single round-trip (sandboxed; each call still respects profile scope and human approval)",
          apply(setCodeMode),
        )}
      </section>
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Security
        </h2>
        <PostureSummary
          denyDestructive={denyDestructive}
          confirmDestructive={confirmDestructive}
          humanApproval={humanApproval}
          quarantineOnDrift={quarantineOnDrift}
        />
        {toggle(
          ShieldAlert,
          denyDestructive,
          "text-warning",
          "Block destructive tools",
          "Hide any tool the server marks as able to delete or change data, from every client",
          apply(setDenyDestructive),
        )}
        {toggle(
          ShieldCheck,
          confirmDestructive,
          "text-info",
          "Confirm destructive tools",
          "Hold each destructive call for the agent to confirm before it runs",
          apply(setConfirmDestructive),
        )}
        {toggle(
          UserCheck,
          humanApproval,
          "text-info",
          "Require human approval",
          "Hold destructive or untrusted-server calls until you approve them in the app",
          apply(setHumanApproval),
        )}
        {toggle(
          ShieldX,
          quarantineOnDrift,
          "text-destructive",
          "Quarantine changed high-risk tools",
          "Block a destructive or poisoned tool that changes from its approved version, until you re-approve it",
          apply(setQuarantineOnDrift),
        )}
        {toggle(
          Bot,
          allowAgentControl,
          "text-success",
          "Allow agent control",
          "Let an agent turn servers on/off; your destructive-tool block always stays yours",
          apply(setAllowAgentControl),
        )}
        {toggle(
          Activity,
          liveInspect,
          "text-info",
          "Live request/response inspection",
          "Off by default. While on, Toolport captures each tool call's arguments and results to a small local, ephemeral buffer (the last 50 calls) so you can inspect them in Activity. This is separate from the audit log, never leaves your machine, and is cleared when you turn it off or restart the gateway.",
          applyLiveInspect,
        )}
        {quarantined.length === 0 && quarantineError && (
          <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-muted-foreground">
            <ShieldX className="size-4 shrink-0 text-destructive" />
            <span>Couldn&apos;t read quarantine status. Retrying every 15s.</span>
          </div>
        )}
        {quarantined.length > 0 && (
          <div className="flex flex-col gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5">
            <div className="flex items-center gap-2">
              <ShieldX className="size-4 shrink-0 text-destructive" />
              <span className="text-sm font-medium">Quarantined tools</span>
              <span className="text-xs text-muted-foreground">
                {quarantineError ? "status may be stale" : "blocked until you re-approve"}
              </span>
            </div>
            <ul className="flex flex-col gap-1.5">
              {quarantined.map((q) => (
                <li
                  key={`${q.profile}:${q.tool}`}
                  className="flex items-center gap-2 text-xs"
                >
                  <span className="min-w-0 truncate font-mono">{q.tool}</span>
                  <span
                    className="min-w-0 truncate text-muted-foreground"
                    title={q.reason}
                  >
                    {q.detail ? q.detail : q.reason}
                  </span>
                  <button
                    type="button"
                    onClick={() => reapprove(q)}
                    className="ml-auto shrink-0 rounded-md border bg-background px-2 py-0.5 text-[11px] font-medium hover:bg-accent"
                  >
                    Re-approve
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        {allowedTools.length === 0 && allowedError && (
          <div className="flex items-center gap-2 rounded-md border border-border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
            <UserCheck className="size-4 shrink-0 text-info" />
            <span>Couldn&apos;t read the allowed-tools list. Retrying every 10s.</span>
          </div>
        )}
        {allowedTools.length > 0 && (
          <div className="flex flex-col gap-2 rounded-md border border-border bg-muted/20 px-3 py-2.5">
            <div className="flex items-center gap-2">
              <UserCheck className="size-4 shrink-0 text-info" />
              <span className="text-sm font-medium">Allowed tools</span>
              <span className="text-xs text-muted-foreground">
                {allowedError ? "list may be stale" : "skip human approval"}
              </span>
            </div>
            <ul className="flex flex-col gap-1.5">
              {allowedTools.map((t) => (
                <li key={t.key} className="flex items-center gap-2 text-xs">
                  <span className="min-w-0 truncate font-mono">
                    {t.server}/{t.tool}
                  </span>
                  <span className="shrink-0 text-muted-foreground">
                    {t.persistent ? "always" : "this session"}
                  </span>
                  <button
                    type="button"
                    onClick={() => void revokeAllowed(t.key)}
                    className="ml-auto shrink-0 rounded-md border bg-background px-2 py-0.5 text-[11px] font-medium hover:bg-accent"
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Integrations
        </h2>
        <div className="flex flex-col gap-2 rounded-md border px-3 py-2.5">
          <label className="flex items-center gap-2.5 text-sm">
            <Globe
              className={`size-4 shrink-0 ${bridge?.running ? "text-success" : "text-muted-foreground"}`}
            />
            <span className="flex min-w-0 flex-1 flex-col leading-tight">
              <span className="font-medium">Open WebUI / HTTP endpoint</span>
              <span className="text-xs text-muted-foreground">
                Serve your tools over HTTP/OpenAPI for Open WebUI and any OpenAPI client
              </span>
            </span>
            <Switch
              checked={!!bridge?.running}
              onCheckedChange={toggleBridge}
              disabled={bridgeBusy}
            />
          </label>
          {bridgeError && bridge === null && (
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span>
                Couldn&apos;t read the HTTP endpoint status. The gateway may be starting
                up.
              </span>
              <button
                type="button"
                onClick={loadBridge}
                className="shrink-0 font-medium text-foreground underline underline-offset-2 hover:text-primary"
              >
                Retry
              </button>
            </p>
          )}
          {bridge?.running && bridge.url && (
            <>
              <div className="flex items-center gap-2 rounded border bg-muted/40 px-2 py-1.5">
                <span className="shrink-0 text-[11px] font-medium text-muted-foreground">
                  URL
                </span>
                <code className="min-w-0 flex-1 truncate text-xs">{bridge.url}</code>
                <button
                  type="button"
                  onClick={() => copy(bridge.url!, "url")}
                  title="Copy URL"
                  className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  {copied === "url" ? (
                    <Check className="size-3.5 text-success" />
                  ) : (
                    <Copy className="size-3.5" />
                  )}
                </button>
              </div>
              {bridge.token && (
                <div className="flex items-center gap-2 rounded border bg-muted/40 px-2 py-1.5">
                  <span className="shrink-0 text-[11px] font-medium text-muted-foreground">
                    Token
                  </span>
                  <code className="min-w-0 flex-1 truncate text-xs">
                    {showToken ? bridge.token : "•".repeat(24)}
                  </code>
                  <button
                    type="button"
                    onClick={() => setShowToken((s) => !s)}
                    title={showToken ? "Hide token" : "Reveal token"}
                    aria-label={showToken ? "Hide token" : "Reveal token"}
                    className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                  >
                    {showToken ? (
                      <EyeOff className="size-3.5" />
                    ) : (
                      <Eye className="size-3.5" />
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => copy(bridge.token!, "token")}
                    title="Copy token"
                    className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                  >
                    {copied === "token" ? (
                      <Check className="size-3.5 text-success" />
                    ) : (
                      <Copy className="size-3.5" />
                    )}
                  </button>
                </div>
              )}
              <p className="text-xs text-muted-foreground">
                In Open WebUI: Settings &rarr; Tools &rarr; add the URL as an OpenAPI
                server and paste the token as its API key (Bearer auth), then set Function
                Calling to Native (per chat). The token stops other local apps from
                calling your tools.
              </p>

              <div className="mt-1 flex flex-col gap-2 rounded border bg-muted/20 p-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[11px] font-medium text-muted-foreground">
                    Scoped clients
                  </span>
                  <span className="text-[11px] text-muted-foreground/70">
                    each gets its own token and server set
                  </span>
                </div>

                {httpClients.length > 0 && (
                  <ul className="flex flex-col gap-1">
                    {httpClients.map((c) => (
                      <li key={c.id} className="flex items-center gap-2 text-xs">
                        <span className="truncate font-medium">
                          {c.label || "(unnamed)"}
                        </span>
                        <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          {c.profile || "all servers"}
                        </span>
                        <button
                          type="button"
                          onClick={() => removeClient(c.id)}
                          aria-label={`Revoke ${c.label}`}
                          className="ml-auto shrink-0 rounded p-1 text-muted-foreground/60 hover:bg-destructive/10 hover:text-destructive"
                        >
                          <Trash2 className="size-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                {newToken && (
                  <>
                    <div className="flex items-center gap-2 rounded border border-success/30 bg-success/5 px-2 py-1.5">
                      <span className="shrink-0 text-[11px] font-medium text-success">
                        New token
                      </span>
                      <code className="min-w-0 flex-1 truncate text-xs">{newToken}</code>
                      <button
                        type="button"
                        onClick={() => copy(newToken, "newtoken")}
                        title="Copy token"
                        className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                      >
                        {copied === "newtoken" ? (
                          <Check className="size-3.5 text-success" />
                        ) : (
                          <Copy className="size-3.5" />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => setNewToken(null)}
                        aria-label="Dismiss"
                        className="shrink-0 rounded p-1 text-muted-foreground/60 hover:text-foreground"
                      >
                        <X className="size-3.5" />
                      </button>
                    </div>
                    <p className="text-[11px] text-warning">
                      Copy this token now, it won't be shown again.
                    </p>
                  </>
                )}

                <div className="flex items-center gap-2">
                  <input
                    value={newLabel}
                    onChange={(e) => setNewLabel(e.target.value)}
                    placeholder="Client name (e.g. Open WebUI)"
                    className="h-8 min-w-0 flex-1 rounded-md border border-input bg-transparent px-2 text-xs focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none"
                  />
                  {profiles.length > 0 && (
                    <Select
                      value={newProfile || "__all__"}
                      onValueChange={(v) => setNewProfile(v === "__all__" ? "" : v)}
                    >
                      <SelectTrigger
                        size="sm"
                        aria-label="Scope"
                        className="h-8 w-32 shrink-0 text-xs"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__all__">All servers</SelectItem>
                        {profiles.map((p) => (
                          <SelectItem key={p.id} value={p.name}>
                            {p.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                  <button
                    type="button"
                    onClick={addClient}
                    disabled={clientBusy || !newLabel.trim()}
                    className="h-8 shrink-0 rounded-md border bg-background px-2.5 text-xs font-medium hover:bg-accent disabled:opacity-50"
                  >
                    Add
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
