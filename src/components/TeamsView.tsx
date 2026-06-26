import { useState } from "react";
import { RefreshCw, LogOut, Upload, ShieldCheck, Users, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { teamConnect, teamSync, teamDisconnect, teamPush } from "@/lib/api";
import type { Registry } from "@/lib/types";

/**
 * Conduit Teams: join a team and have its shared MCP server set appear locally. The
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

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(label);
    setError(null);
    setNotice(null);
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

  return (
    <div className="mx-auto max-w-2xl">
      <div className="mb-5 flex items-center gap-2">
        <Users className="size-5 text-muted-foreground" />
        <h2 className="text-base font-semibold">Conduit Teams</h2>
      </div>

      {error && (
        <div className="mb-4 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}
      {notice && (
        <div className="mb-4 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {notice}
        </div>
      )}

      {!team ? (
        <div className="rounded-xl border bg-card p-5">
          <h3 className="text-sm font-medium">Connect to a team</h3>
          <p className="mt-1 mb-4 max-w-prose text-sm text-muted-foreground">
            Paste your team's Conduit Teams server URL and an invite code from your admin.
            The team's MCP servers will appear in your active profile. Your keys never leave
            your machine, you'll add each server's secrets locally afterward.
          </p>
          <div className="grid gap-3">
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Team server URL</span>
              <Input
                placeholder="https://teams.yourcompany.com"
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
                <Button variant="outline" size="sm" onClick={onDisconnect} disabled={busy !== null}>
                  <LogOut className="size-3.5" />
                  Leave
                </Button>
              </div>
            </div>

            {isAdmin && (
              <div className="mt-4 flex items-center justify-between gap-4 rounded-lg border border-dashed bg-muted/30 px-4 py-3">
                <div className="min-w-0 text-sm">
                  <div className="flex items-center gap-1.5 font-medium">
                    <ShieldCheck className="size-3.5 text-emerald-400" /> Admin
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
                <ul className="mt-2 grid gap-1.5">
                  {teamServers.map((s) => (
                    <li key={s.id} className="flex items-center gap-2 text-sm">
                      <Server className="size-3.5 shrink-0 text-muted-foreground" />
                      <span className="truncate">{s.name}</span>
                      <span className="text-xs text-muted-foreground">{s.transport}</span>
                    </li>
                  ))}
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
