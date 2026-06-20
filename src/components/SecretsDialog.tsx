import { useState, type ReactNode } from "react";
import { Check, ExternalLink, KeyRound, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  authenticateOauth,
  clearAuthToken,
  deleteSecret,
  hasAuthToken,
  probeAuth,
  secretStatus,
  setAuthToken,
  setSecret,
} from "@/lib/api";
import type { AuthInfo, Registry, ServerEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface Props {
  server: ServerEntry;
  onSaved: (registry: Registry) => void;
  /** Custom trigger (defaults to the key icon). Use for a prominent "Authenticate" button. */
  trigger?: ReactNode;
  /** Called after any auth/secret change, so the caller can re-probe health. */
  onChanged?: () => void;
}

/** Where to get the API key for known key-based (stdio) servers, keyed by env var. */
const KEY_HINTS: Record<string, { url: string; hint: string }> = {
  RESEND_API_KEY: {
    url: "https://resend.com/api-keys",
    hint: "Create an API key in the Resend dashboard, then paste it here.",
  },
  OPENAI_API_KEY: {
    url: "https://platform.openai.com/api-keys",
    hint: "Create a secret key in the OpenAI dashboard, then paste it here.",
  },
  ANTHROPIC_API_KEY: {
    url: "https://console.anthropic.com/settings/keys",
    hint: "Create a key in the Anthropic console, then paste it here.",
  },
  GITHUB_TOKEN: {
    url: "https://github.com/settings/tokens",
    hint: "Create a personal access token in GitHub developer settings, then paste it here.",
  },
  GITHUB_PERSONAL_ACCESS_TOKEN: {
    url: "https://github.com/settings/tokens",
    hint: "Create a personal access token in GitHub developer settings, then paste it here.",
  },
  BRAVE_API_KEY: {
    url: "https://brave.com/search/api/",
    hint: "Create an API key in the Brave Search API dashboard, then paste it here.",
  },
};

/** A readable vendor name from an env-var key, e.g. RESEND_API_KEY -> "Resend". */
function vendorFromKey(key: string): string {
  const head = key.replace(/_(API_)?KEY$|_TOKEN$|_SECRET$/i, "").split("_")[0];
  if (!head) return "This server";
  return head.charAt(0).toUpperCase() + head.slice(1).toLowerCase();
}

export function SecretsDialog({ server, onSaved, trigger, onChanged }: Props) {
  const [open, setOpen] = useState(false);
  const [vaulted, setVaulted] = useState<Record<string, boolean>>({});
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [newKey, setNewKey] = useState("");
  const [newValue, setNewValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [authSet, setAuthSet] = useState(false);
  const [authInput, setAuthInput] = useState("");
  const [oauthBusy, setOauthBusy] = useState(false);
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const [probing, setProbing] = useState(false);

  const secretKeys = server.env.filter((e) => e.secret).map((e) => e.key);
  const isRemote = server.url !== null;
  const primaryKey = secretKeys[0];
  const keyHint = primaryKey ? KEY_HINTS[primaryKey] : undefined;

  async function refreshStatus() {
    if (secretKeys.length > 0) {
      try {
        const pairs = await secretStatus(server.id, secretKeys);
        setVaulted(Object.fromEntries(pairs));
      } catch {
        /* non-fatal */
      }
    } else {
      setVaulted({});
    }
    if (isRemote && server.url) {
      hasAuthToken(server.id)
        .then(setAuthSet)
        .catch(() => {});
      setProbing(true);
      setAuthInfo(null);
      probeAuth(server.url)
        .then(setAuthInfo)
        .catch(() => {})
        .finally(() => setProbing(false));
    }
  }

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) refreshStatus();
  }

  async function saveAuth() {
    if (!authInput) return;
    setBusy(true);
    try {
      await setAuthToken(server.id, authInput);
      setAuthSet(true);
      setAuthInput("");
      toast.success("Saved auth token");
      onChanged?.();
    } catch (e) {
      toast.error(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function clearAuth() {
    setBusy(true);
    try {
      await clearAuthToken(server.id);
      setAuthSet(false);
      toast.success("Cleared auth token");
      onChanged?.();
    } catch (e) {
      toast.error(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function doOauth() {
    if (!server.url) return;
    setOauthBusy(true);
    toast.info("Opening your browser to sign in…");
    try {
      await authenticateOauth(server.id, server.url);
      setAuthSet(true);
      toast.success("Authenticated");
      onChanged?.();
    } catch (e) {
      toast.error(`OAuth failed: ${e}`);
    } finally {
      setOauthBusy(false);
    }
  }

  async function save(key: string, value: string) {
    if (!value) return;
    setBusy(true);
    try {
      onSaved(await setSecret(server.id, key, value));
      setVaulted((v) => ({ ...v, [key]: true }));
      setInputs((i) => ({ ...i, [key]: "" }));
      toast.success(`Saved ${key}`);
      onChanged?.();
    } catch (e) {
      toast.error(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function remove(key: string) {
    setBusy(true);
    try {
      onSaved(await deleteSecret(server.id, key));
      toast.success(`Removed ${key}`);
      onChanged?.();
    } catch (e) {
      toast.error(`${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function addNew() {
    const k = newKey.trim();
    if (!k || !newValue) return;
    await save(k, newValue);
    setNewKey("");
    setNewValue("");
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        {trigger ?? (
          <button
            aria-label={`Manage secrets for ${server.name}`}
            className="rounded p-1 text-muted-foreground/60 transition hover:bg-accent hover:text-foreground"
          >
            <KeyRound className="size-3.5" />
          </button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Secrets for {server.name}</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-3 py-1">
          {isRemote && (
            <div className="flex flex-col gap-2.5 border-b pb-3">
              {probing && (
                <p className="text-xs text-muted-foreground">
                  Checking what this server needs…
                </p>
              )}

              {authInfo?.kind === "none" ? (
                <div className="flex items-start gap-2 rounded-md bg-emerald-400/10 p-2.5 text-xs text-emerald-300">
                  <Check className="mt-0.5 size-3.5 shrink-0" />
                  <span>
                    This server connects without auth. Just enable it — no token needed.
                  </span>
                </div>
              ) : (
                <>
                  {authInfo?.vendor && authInfo.instructions && (
                    <div className="rounded-md bg-muted/40 p-2.5 text-xs text-muted-foreground">
                      <span className="font-medium text-foreground">
                        {authInfo.vendor}:{" "}
                      </span>
                      {authInfo.instructions}
                      {authInfo.tokenUrl && (
                        <button
                          onClick={() => openUrl(authInfo.tokenUrl!)}
                          className="ml-1 inline-flex items-center gap-0.5 text-sky-400 hover:underline"
                        >
                          get a token
                          <ExternalLink className="size-3" />
                        </button>
                      )}
                    </div>
                  )}

                  <div className="flex flex-col gap-1.5">
                    <div className="flex items-center gap-2">
                      <Label className="text-xs">Access token</Label>
                      {authSet && (
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <Check className="size-3" />
                          vaulted
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <Input
                        type="password"
                        placeholder={authSet ? "•••••••• (set)" : "paste access token"}
                        value={authInput}
                        onChange={(e) => setAuthInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") saveAuth();
                        }}
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy || !authInput}
                        onClick={saveAuth}
                      >
                        Save
                      </Button>
                      {authSet && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                          aria-label="Clear auth token"
                          disabled={busy}
                          onClick={clearAuth}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      )}
                    </div>
                  </div>

                  {(authInfo == null ||
                    authInfo.kind === "oauth" ||
                    authInfo.kind === "unknown") && (
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={oauthBusy}
                      onClick={doOauth}
                    >
                      {oauthBusy
                        ? "Waiting for browser sign-in…"
                        : "Sign in with OAuth"}
                    </Button>
                  )}

                  {authInfo?.kind === "token" && (
                    <p className="text-[11px] text-muted-foreground">
                      This server needs a pasted token. OAuth sign-in isn't available here.
                    </p>
                  )}
                </>
              )}
            </div>
          )}

          {/* Key-based servers: the API key entry is the primary, obvious action. */}
          {secretKeys.length > 0 && (
            <div className="flex flex-col gap-3">
              {keyHint && (
                <div className="rounded-md bg-muted/40 p-2.5 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">
                    {vendorFromKey(primaryKey)}:{" "}
                  </span>
                  {keyHint.hint}
                  {keyHint.url && (
                    <button
                      onClick={() => openUrl(keyHint.url)}
                      className="ml-1 inline-flex items-center gap-0.5 text-sky-400 hover:underline"
                    >
                      get your key
                      <ExternalLink className="size-3" />
                    </button>
                  )}
                </div>
              )}

              {secretKeys.map((key) => (
                <div key={key} className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-2">
                    <Label className="text-sm font-medium">
                      {vendorFromKey(key)} API key
                    </Label>
                    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[10px] text-muted-foreground">
                      {key}
                    </code>
                    {vaulted[key] && (
                      <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                        <Check className="size-3" />
                        saved
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <Input
                      type="password"
                      placeholder={
                        vaulted[key]
                          ? "•••••••• (saved)"
                          : `paste your ${vendorFromKey(key)} API key`
                      }
                      value={inputs[key] ?? ""}
                      onChange={(e) =>
                        setInputs((i) => ({ ...i, [key]: e.target.value }))
                      }
                      onKeyDown={(e) => {
                        if (e.key === "Enter") save(key, inputs[key] ?? "");
                      }}
                    />
                    <Button
                      size="sm"
                      disabled={busy || !(inputs[key] ?? "")}
                      onClick={() => save(key, inputs[key] ?? "")}
                    >
                      Save
                    </Button>
                    {vaulted[key] && (
                      <Button
                        size="icon"
                        variant="ghost"
                        className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                        aria-label={`Remove ${key}`}
                        disabled={busy}
                        onClick={() => remove(key)}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {secretKeys.length === 0 && !isRemote && (
            <p className="text-sm text-muted-foreground">
              This server didn't declare an API key. If it needs one, add it as an
              environment variable below.
            </p>
          )}

          {/* Extra env secrets are an advanced case; collapse them unless they're
              the only option (a stdio server that declared no keys). */}
          <details
            className="mt-1 border-t pt-3"
            open={secretKeys.length === 0 && !isRemote}
          >
            <summary className="cursor-pointer text-xs text-muted-foreground select-none">
              Add another environment secret
            </summary>
            <div className="mt-2 flex items-center gap-2">
              <Input
                placeholder="ENV_NAME"
                className="font-mono"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
              />
              <Input
                type="password"
                placeholder="value"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
              />
              <Button
                size="icon"
                className="size-8 shrink-0"
                aria-label="Add secret"
                disabled={busy || !newKey.trim() || !newValue}
                onClick={addNew}
              >
                <Plus className="size-4" />
              </Button>
            </div>
          </details>
        </div>
      </DialogContent>
    </Dialog>
  );
}
