import { useEffect, useState } from "react";
import { Activity, Bot, Check, Copy, Globe, Layers, ShieldAlert, ShieldCheck, ShieldX, Trash2, UserCheck, X } from "lucide-react";
import { toastError } from "@/lib/toast";
import {
  addHttpClient,
  clearInspectLog,
  httpBridgeStatus,
  listQuarantined,
  releaseQuarantine,
  removeHttpClient,
  setAllowAgentControl,
  setConfirmDestructive,
  setDenyDestructive,
  setHumanApproval,
  setLazyDiscovery,
  setLiveInspect,
  setQuarantineOnDrift,
  startHttpBridge,
  stopHttpBridge,
  type HttpBridgeStatus,
  type QuarantinedTool,
} from "@/lib/api";
import type { Registry } from "@/lib/types";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Props {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}

/** Global discovery + security policy. These apply to every client uniformly, so
 * they live here rather than in the per-server Playground. */
export function SettingsView({ registry, onRegistryChange }: Props) {
  const lazyDiscovery = registry?.lazyDiscovery ?? true;
  const denyDestructive = registry?.denyDestructive ?? false;
  const confirmDestructive = registry?.confirmDestructive ?? false;
  const humanApproval = registry?.humanApproval ?? false;
  const allowAgentControl = registry?.allowAgentControl ?? false;
  const quarantineOnDrift = registry?.quarantineOnDrift ?? false;
  const liveInspect = registry?.liveInspect ?? false;
  const [busy, setBusy] = useState(false);
  const [quarantined, setQuarantined] = useState<QuarantinedTool[]>([]);
  const [bridge, setBridge] = useState<HttpBridgeStatus | null>(null);
  const [bridgeBusy, setBridgeBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [newLabel, setNewLabel] = useState("");
  const [newProfile, setNewProfile] = useState("");
  const [newToken, setNewToken] = useState<string | null>(null);
  const [clientBusy, setClientBusy] = useState(false);

  const httpClients = registry?.httpClients ?? [];
  const profiles = registry?.profiles ?? [];

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

  useEffect(() => {
    httpBridgeStatus()
      .then(setBridge)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const load = () => listQuarantined().then(setQuarantined).catch(() => {});
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

  const toggleBridge = async (on: boolean) => {
    setBridgeBusy(true);
    try {
      setBridge(on ? await startHttpBridge() : await stopHttpBridge());
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

  const apply =
    (fn: (v: boolean) => Promise<Registry>) => async (v: boolean) => {
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
          Discovery
        </h2>
        {toggle(
          Layers,
          lazyDiscovery,
          "text-info",
          "Lazy discovery",
          "Expose a few meta-tools, not the full catalog (all clients)",
          apply(setLazyDiscovery),
        )}
      </section>
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Security
        </h2>
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
        {quarantined.length > 0 && (
          <div className="flex flex-col gap-2 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5">
            <div className="flex items-center gap-2">
              <ShieldX className="size-4 shrink-0 text-destructive" />
              <span className="text-sm font-medium">Quarantined tools</span>
              <span className="text-xs text-muted-foreground">
                blocked until you re-approve
              </span>
            </div>
            <ul className="flex flex-col gap-1.5">
              {quarantined.map((q) => (
                <li
                  key={`${q.profile}:${q.tool}`}
                  className="flex items-center gap-2 text-xs"
                >
                  <span className="min-w-0 truncate font-mono">{q.tool}</span>
                  <span className="shrink-0 text-muted-foreground">{q.reason}</span>
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
          {bridge?.running && bridge.url && (
            <>
              <div className="flex items-center gap-2 rounded border bg-muted/40 px-2 py-1.5">
                <span className="shrink-0 text-[11px] font-medium text-muted-foreground">URL</span>
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
                  <code className="min-w-0 flex-1 truncate text-xs">{bridge.token}</code>
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
                In Open WebUI: Settings &rarr; Tools &rarr; add the URL as an OpenAPI server and paste
                the token as its API key (Bearer auth), then set Function Calling to Native (per chat).
                The token stops other local apps from calling your tools.
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
                        <span className="truncate font-medium">{c.label || "(unnamed)"}</span>
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
