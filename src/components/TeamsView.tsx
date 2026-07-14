import { useEffect, useState } from "react";
import {
  RefreshCw,
  LogOut,
  Upload,
  ShieldCheck,
  Users,
  Server,
  AlertTriangle,
} from "lucide-react";
import { listen } from "@tauri-apps/api/event";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Callout } from "@/components/Callout";
import { TransportPill } from "@/components/TransportPill";
import { Input } from "@/components/ui/input";
import {
  teamConnect,
  teamJoinPoll,
  teamSync,
  teamDisconnect,
  teamPushPreview,
  teamPush,
  setServerEnabled,
} from "@/lib/api";
import { teamUrlError } from "@/lib/teamUrl";
import { isEnabled, activeProfile } from "@/lib/types";
import type { TeamPushPreview } from "@/lib/api";
import type { Registry } from "@/lib/types";

/** The hosted Toolport Teams instance, prefilled as the default. Self-hosters replace
 * it with their own server URL. */
const HOSTED_TEAMS_URL = "https://teams.toolport.app";

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
  const teamServers = (registry?.servers ?? []).filter((s) =>
    s.source?.startsWith("team:"),
  );

  const [serverUrl, setServerUrl] = useState(HOSTED_TEAMS_URL);
  const [inviteCode, setInviteCode] = useState("");
  const [memberName, setMemberName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [skipNote, setSkipNote] = useState<string | null>(null);
  const [pushPreview, setPushPreview] = useState<TeamPushPreview | null>(null);
  // Set while an approval-gated join waits for an admin. Holds the connect inputs so a poll
  // uses the values from when the request was made, not whatever the fields say later.
  const [pending, setPending] = useState<{
    serverUrl: string;
    requestToken: string;
    memberName?: string;
  } | null>(null);

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
      const urlError = teamUrlError(serverUrl);
      if (urlError) {
        throw new Error(urlError);
      }
      if (!inviteCode.trim()) {
        throw new Error("An invite or connect code is required.");
      }
      const su = serverUrl.trim();
      const mn = memberName.trim() || undefined;
      const r = await teamConnect(su, inviteCode.trim(), mn);
      if (r.status === "pending" && r.requestToken) {
        // An approval-gated link: nothing is joined yet. Hold here and poll (below) until an
        // admin approves or denies; the fields stay as-is so the request context is preserved.
        setPending({ serverUrl: su, requestToken: r.requestToken, memberName: mn });
        setNotice("Request sent. Waiting for an admin to approve you.");
        return;
      }
      if (r.status === "connected" && r.registry) {
        onRegistryChange(r.registry);
        setInviteCode("");
        setNotice("Connected. The team's servers were added to your active profile.");
        return;
      }
      throw new Error("The server returned an unexpected connect response.");
    });

  // While a join is pending admin approval, poll for the verdict. A transient network error
  // keeps the wait alive (a blip shouldn't cancel it); an explicit deny/expiry ends it.
  useEffect(() => {
    if (!pending) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await teamJoinPoll(
          pending.serverUrl,
          pending.requestToken,
          pending.memberName,
        );
        if (cancelled) return;
        if (r.status === "connected" && r.registry) {
          setPending(null);
          onRegistryChange(r.registry);
          setInviteCode("");
          setNotice("Approved. The team's servers were added to your active profile.");
        } else if (r.status === "denied") {
          setPending(null);
          setError("An admin declined your request to join this team.");
        } else if (r.status === "unknown") {
          setPending(null);
          setError("This join request expired. Ask for the link again and reconnect.");
        }
        // "pending" → keep waiting.
      } catch {
        // Transient: leave `pending` set so the next tick retries.
      }
    };
    void tick();
    const id = setInterval(tick, 4000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);

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

  const onPreviewPush = () =>
    run("preview-push", async () => {
      setPushPreview(await teamPushPreview());
    });

  const onPush = () =>
    run("push", async () => {
      if (!pushPreview) throw new Error("Review the shared-server update before saving.");
      const v = await teamPush(pushPreview);
      setPushPreview(null);
      setNotice(`Updated the team's shared servers (now version ${v}).`);
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

  // One row in the Shared-servers list. Extracted so the review and active groups
  // below can each render it.
  const renderTeamServer = (s: (typeof teamServers)[number]) => {
    const on = registry ? isEnabled(registry, s.id) : false;
    const isLocal = s.transport === "stdio" || !!s.command;
    const detail = s.command ? [s.command, ...(s.args ?? [])].join(" ") : (s.url ?? "");
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
            <Badge variant="success" className="ml-auto shrink-0">
              <ShieldCheck className="size-3" /> on
            </Badge>
          ) : (
            <Badge variant="warning" className="ml-auto shrink-0">
              <AlertTriangle className="size-3" /> needs review
            </Badge>
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
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy !== null}
                  className="shrink-0"
                >
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
  };

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
            Join your team's Toolport Teams server and its shared MCP servers appear in
            your active profile, kept in sync as your admin updates them.
          </p>
          <div className="mb-5 grid gap-2.5 sm:grid-cols-3">
            {[
              {
                icon: Server,
                title: "Shared server set",
                body: "Your admin curates the MCP servers; they show up in your profile.",
              },
              {
                icon: ShieldCheck,
                title: "Keys stay local",
                body: "The team holds config only, never a secret. You vault keys on your machine.",
              },
              {
                icon: RefreshCw,
                title: "Always in sync",
                body: "One source of truth; updates arrive when you Sync.",
              },
            ].map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="rounded-lg border border-border/60 bg-muted/20 p-3"
              >
                <div className="flex items-center gap-1.5 text-sm font-medium">
                  <Icon className="size-3.5 text-primary" />
                  {title}
                </div>
                <p className="mt-1 text-2xs leading-relaxed text-muted-foreground">
                  {body}
                </p>
              </div>
            ))}
          </div>
          <div className="grid gap-3">
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Team server URL</span>
              <Input
                placeholder="https://toolport.yourcompany.com"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
              />
              <span className="text-xs text-muted-foreground">
                Defaults to hosted Toolport Teams. Self-hosting? Replace it with your own
                server URL.
              </span>
            </label>
            <label className="grid gap-1 text-sm">
              <span className="text-muted-foreground">Invite or connect code</span>
              <Input
                placeholder="Paste your invite or connect code"
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value)}
              />
              <span className="text-xs text-muted-foreground">
                An invite code joins you to a team. A connect code links this device to a
                seat you already have.
              </span>
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
              {pending ? (
                <div className="flex items-center gap-3 rounded-lg border border-primary/40 bg-primary/5 p-3 text-sm">
                  <RefreshCw className="size-4 shrink-0 animate-spin text-primary" />
                  <span className="text-muted-foreground">
                    Waiting for an admin to approve your request. Leave this open, it
                    finishes on its own once they approve.
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="ml-auto shrink-0"
                    onClick={() => {
                      setPending(null);
                      setNotice(null);
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              ) : (
                <Button onClick={onConnect} disabled={busy !== null}>
                  {busy === "connect" ? "Connecting…" : "Connect"}
                </Button>
              )}
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
                <p className="mt-1 truncate text-sm text-muted-foreground">
                  {team.serverUrl}
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Team {team.teamId} · config v{team.lastVersion ?? 0} ·{" "}
                  {teamServers.length} shared{" "}
                  {teamServers.length === 1 ? "server" : "servers"}
                </p>
              </div>
              <div className="flex shrink-0 gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onSync}
                  disabled={busy !== null}
                >
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
                    Replace the team's shared servers with your current server set. Team
                    instructions and security policies are preserved; secrets are never
                    sent.
                  </p>
                </div>
                <Button size="sm" onClick={onPreviewPush} disabled={busy !== null}>
                  <Upload className="size-3.5" />
                  {busy === "preview-push" ? "Comparing…" : "Update shared servers"}
                </Button>
                <ConfirmDialog
                  open={pushPreview !== null}
                  onOpenChange={(open) => {
                    if (!open) setPushPreview(null);
                  }}
                  title="Replace the team's shared servers?"
                  description={
                    pushPreview && (
                      <div className="grid gap-3 text-left">
                        <p>
                          Only the shared server list changes. Team instructions, security
                          policies, and other settings stay unchanged.
                        </p>
                        {(
                          [
                            ["Added", pushPreview.added],
                            ["Changed", pushPreview.changed],
                            ["Removed", pushPreview.removed],
                          ] as const
                        ).map(([label, names]) => (
                          <div key={label}>
                            <div className="font-medium text-foreground">
                              {label} ({names.length})
                            </div>
                            {names.length > 0 ? (
                              <ul className="mt-1 max-h-24 list-disc overflow-y-auto pl-5">
                                {names.map((name, index) => (
                                  <li key={`${label}-${name}-${index}`}>{name}</li>
                                ))}
                              </ul>
                            ) : (
                              <div className="mt-1">None</div>
                            )}
                          </div>
                        ))}
                        <p>
                          If the team or your local servers change before saving, Toolport
                          will stop and ask you to review again instead of overwriting
                          anything.
                        </p>
                      </div>
                    )
                  }
                  confirmLabel="Replace shared servers"
                  onConfirm={onPush}
                />
              </div>
            )}
          </div>

          <div className="rounded-xl border bg-card p-5">
            <h3 className="mb-1 text-sm font-medium">Shared servers</h3>
            {teamServers.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No servers from the team yet. An admin pushes the set, then Sync brings it
                here.
              </p>
            ) : (
              <>
                {(() => {
                  // Attention-needed servers first (their own section), then the rest, each
                  // sorted alphabetically so the list is predictable to scan.
                  const byName = (a: (typeof teamServers)[number], b: typeof a) =>
                    a.name.localeCompare(b.name, undefined, { sensitivity: "base" });
                  const review = teamServers
                    .filter((s) => !(registry ? isEnabled(registry, s.id) : false))
                    .sort(byName);
                  const active = teamServers
                    .filter((s) => registry && isEnabled(registry, s.id))
                    .sort(byName);
                  return (
                    <>
                      {review.length > 0 && (
                        <div className="mt-3">
                          <div className="flex items-center gap-1.5 text-xs font-medium text-warning">
                            <AlertTriangle className="size-3.5" /> Needs review (
                            {review.length})
                          </div>
                          <p className="mt-1 mb-2 text-xs text-muted-foreground">
                            These run a local command or reach a LAN address, so they stay
                            off until you review and enable each one.
                          </p>
                          <ul className="grid gap-2">{review.map(renderTeamServer)}</ul>
                        </div>
                      )}
                      {active.length > 0 && (
                        <div className="mt-4">
                          <div className="flex items-center gap-1.5 text-xs font-medium text-success">
                            <ShieldCheck className="size-3.5" /> Active ({active.length})
                          </div>
                          <ul className="mt-2 grid gap-2">
                            {active.map(renderTeamServer)}
                          </ul>
                        </div>
                      )}
                    </>
                  );
                })()}
                <p className="mt-3 text-xs text-muted-foreground">
                  Add each server's secrets in the Servers tab, they stay in your OS
                  keychain.
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
