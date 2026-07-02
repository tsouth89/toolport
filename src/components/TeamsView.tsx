import { useEffect, useState } from "react";
import { RefreshCw, LogOut, Upload, ShieldCheck, Users, Server, AlertTriangle } from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Callout } from "@/components/Callout";
import { TransportPill } from "@/components/TransportPill";
import { Input } from "@/components/ui/input";
import { teamConnect, teamSync, teamDisconnect, teamPush, setServerEnabled } from "@/lib/api";
import { isEnabled, activeProfile } from "@/lib/types";
import type { Registry } from "@/lib/types";

/**
 * Toolport Teams: join a team and have its shared MCP server set appear locally. The
 * team server holds only the server set + non-secret config, never a key, so after
 * connecting you still vault each server's secrets locally (Servers tab). That keeps
 * "no keys in the cloud" true even on a team.
 */
export function TeamsView({
  registry,
  onRegistryChange,
}: {
  registry: Registry | null;
  onRegistryChange: (r: Registry) => void;
}) {
  const team = registry?.team ?? null;
  const isAdmin = team?.role === "admin";
  const teamServers = (registry?.servers ?? []).filter((s) => s.source?.startsWith("team:"));

  const [serverUrl, setServerUrl] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [memberName, setMemberName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [skipNote, setSkipNote] = useState<string | null>(null);

  // Team servers that run a local command or hit a LAN address arrive OFF (the member
  // reviews + enables them below); link-local/metadata URLs are blocked outright. The
  // backend emits the counts so the state is explained, not a silent mystery.
  useEffect(() => {
    const un = listen<{ review: number; blocked: number }>("team-servers-review", (e) => {
      const { review, blocked } = e.payload;
      const parts: string[] = [];
      if (review > 0)
        parts.push(
          `${review} team server${review === 1 ? "" : "s"} run${review === 1 ? "s" : ""} a local command or a LAN address, so ${review === 1 ? "it's" : "they're"} off until you review and enable ${review === 1 ? "it" : "them"} below.`,
        );
      if (blocked > 0)
        parts.push(
          `${blocked} ${blocked === 1 ? "was" : "were"} blocked as unsafe (link-local or cloud-metadata URLs).`,
        );
      setSkipNote(parts.join(" "));
    });
    return () => {
      un.then((f) => f());
    };
  }, []);

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(label);
    setError(null);
    setNotice(null);
    setSkipNote(null);
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  }

  const onConnect = () =>
    run("connect", async () => {
      if (!serverUrl.trim() || !inviteCode.trim()) {
        throw new Error("Server URL and invite code are both required.");
      }
      const r = await teamConnect(serverUrl.trim(), inviteCode.trim(), memberName.trim() || undefined);
      onRegistryChange(r);
      setInviteCode("");
      setNotice("Connected. The team's servers were added to your active profile.");
    });

  const onSync = () =>
    run("sync", async () => {
      onRegistryChange(await teamSync());
      setNotice("Synced with the team.");
    });

  const onDisconnect = () =>
    run("disconnect", async () => {
      onRegistryChange(await teamDisconnect());
      setNotice("Left the team. Its servers were removed; your own are untouched.");
    });

  const onPush = () =>
    run("push", async () => {
      const v = await teamPush();
      setNotice(`Pushed your server set to the team (now version ${v}).`);
    });

  // Member consent: enable a review server (local command / LAN URL) into the active
  // profile after the confirm. Nothing from a team runs until this explicit opt-in.
  const onEnable = (serverId: string) =>
    run("enable", async () => {
      const pid = registry ? activeProfile(registry)?.id : undefined;
      if (!pid) throw new Error("No active profile to enable into.");
      onRegistryChange(await setServerEnabled(pid, serverId, true));
      setNotice("Enabled. That server now runs in your active profile.");
    });

  return (
    <div className="mx-auto max-w-2xl">
      <div className="mb-5 flex items-center gap-2">
        <Users className="size-5 text-muted-foreground" />
        <h2 className="text-base font-semibold">Toolport Teams</h2>
      </div>

      {error && (
        <Callout variant="danger" className="mb-4">
          {error}
        </Callout>
      )}
      {skipNote && (
        <Callout variant="warning" className="mb-4">
          {skipNote}
        </Callout>
      )}
      {notice && (
        <Callout variant="success" className="mb-4">
          {notice}
        </Callout>
      )}

      {!team ? (
        <div className="rounded-xl border bg-card p-5">
          <h3 className="text-sm font-medium">Connect to a team</h3>
          <p className="mt-1 mb-4 max-w-prose text-sm text-muted-foreground">
            Paste your team's Toolport Teams server URL and an invite code from your admin.
            The team's MCP servers will appear in your active profile. Your keys never leave
            your machine, you'll add each server's secrets locally afterward.
          </p>
          <div className="grid gap-3">
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Team server URL</span>
              <Input
                placeholder="https://conduit.yourcompany.com"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Invite code</span>
              <Input
                placeholder="ci_..."
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value)}
              />
            </label>
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Your name (optional)</span>
              <Input
                placeholder="e.g. Tyler"
                value={memberName}
                onChange={(e) => setMemberName(e.target.value)}
              />
            </label>
            <div>
              <Button onClick={onConnect} disabled={busy !== null}>
                {busy === "connect" ? "Connecting…" : "Connect"}
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid gap-4">
          <div className="rounded-xl border bg-card p-5">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">Connected</span>
                  <span className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground capitalize">
                    {team.role}
                  </span>
                </div>
                <p className="mt-1 truncate text-sm text-muted-foreground">{team.serverUrl}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Team {team.teamId} · config v{team.lastVersion ?? 0} · {teamServers.length}{" "}
                  shared {teamServers.length === 1 ? "server" : "servers"}
                </p>
              </div>
              <div className="flex shrink-0 gap-2">
                <Button variant="outline" size="sm" onClick={onSync} disabled={busy !== null}>
                  <RefreshCw className="size-3.5" />
                  {busy === "sync" ? "Syncing…" : "Sync now"}
                </Button>
                <ConfirmDialog
                  trigger={
                    <Button variant="outline" size="sm" disabled={busy !== null}>
                      <LogOut className="size-3.5" />
                      Leave
                    </Button>
                  }
                  title="Leave this team?"
                  description="This removes the team's shared servers from Toolport. Your own servers are untouched."
                  confirmLabel="Leave"
                  destructive
                  onConfirm={onDisconnect}
                />
              </div>
            </div>

            {isAdmin && (
              <div className="mt-4 flex items-center justify-between gap-4 rounded-lg border border-dashed bg-muted/30 px-4 py-3">
                <div className="min-w-0 text-sm">
                  <div className="flex items-center gap-1.5 font-medium">
                    <ShieldCheck className="size-3.5 text-success" /> Admin
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Push your current server set to the team. Secret values are never sent.
                  </p>
                </div>
                <Button size="sm" onClick={onPush} disabled={busy !== null}>
                  <Upload className="size-3.5" />
                  {busy === "push" ? "Pushing…" : "Push my setup"}
                </Button>
              </div>
            )}
          </div>

          <div className="rounded-xl border bg-card p-5">
            <h3 className="mb-1 text-sm font-medium">Shared servers</h3>
            {teamServers.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No servers from the team yet. An admin pushes the set, then Sync brings it here.
              </p>
            ) : (
              <>
                <ul className="mt-2 grid gap-2">
                  {teamServers.map((s) => {
                    const on = registry ? isEnabled(registry, s.id) : false;
                    const isLocal = s.transport === "stdio" || !!s.command;
                    const detail = s.command
                      ? [s.command, ...(s.args ?? [])].join(" ")
                      : s.url ?? "";
                    return (
                      <li
                        key={s.id}
                        className={`rounded-lg border px-3 py-2 text-sm ${on ? "border-border/60" : "border-warning/40 bg-warning/5"}`}
                      >
                        <div className="flex items-center gap-2">
                          <Server className="size-3.5 shrink-0 text-muted-foreground" />
                          <span className="truncate font-medium">{s.name}</span>
                          <TransportPill transport={s.transport} />
                          {on ? (
                            <span className="ml-auto flex shrink-0 items-center gap-1 text-xs text-success">
                              <ShieldCheck className="size-3.5" /> on
                            </span>
                          ) : (
                            <span className="ml-auto flex shrink-0 items-center gap-1 text-xs text-warning">
                              <AlertTriangle className="size-3.5" /> needs review
                            </span>
                          )}
                        </div>
                        {!on && (
                          <div className="mt-2 flex items-end justify-between gap-3">
                            <div className="min-w-0">
                              <p className="text-xs text-muted-foreground">
                                {isLocal
                                  ? "Runs this local command on your machine:"
                                  : "Connects to this private/LAN address:"}
                              </p>
                              <code className="block truncate font-mono text-xs text-foreground">
                                {detail}
                              </code>
                            </div>
                            <ConfirmDialog
                              trigger={
                                <Button size="sm" variant="outline" disabled={busy !== null} className="shrink-0">
                                  Enable
                                </Button>
                              }
                              title={`Enable "${s.name}"?`}
                              description={
                                isLocal
                                  ? `This runs a local command on your machine: ${detail}. Only enable it if you trust your team and recognize this command.`
                                  : `This connects Toolport to ${detail}, a private/LAN address. Only enable it if you trust your team.`
                              }
                              confirmLabel="Enable"
                              onConfirm={() => onEnable(s.id)}
                            />
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
                <p className="mt-3 text-xs text-muted-foreground">
                  Add each server's secrets in the Servers tab, they stay in your OS keychain.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
