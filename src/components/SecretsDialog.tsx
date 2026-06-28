import { useRef, useState, type ReactNode } from "react";
import { Check, ExternalLink, KeyRound, Loader2, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
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

/** Turn a raw secret-store error into something actionable. On a headless or
 * keyring-less Linux box the backend surfaces an opaque Secret Service / D-Bus
 * string; explain in user terms that a running keyring is required. */
function secretErrorMessage(e: unknown): string {
  const msg = `${e}`;
  if (/secret service|freedesktop\.secret|keyring|dbus|d-bus/i.test(msg)) {
    return "No system keyring found. Conduit keeps secrets in your OS keyring; on Linux that needs a running Secret Service (e.g. gnome-keyring or KWallet). Start and unlock one, then retry.";
  }
  return msg;
}

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
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [authSet, setAuthSet] = useState(false);
  const [authInput, setAuthInput] = useState("");
  const [oauthBusy, setOauthBusy] = useState(false);
  const [authInfo, setAuthInfo] = useState<AuthInfo | null>(null);
  const [probing, setProbing] = useState(false);

  const secretKeys = server.env.filter((e) => e.secret).map((e) => e.key);
  // A server with a command is stdio (matches how the backend connects); only a
  // command-less, URL-based server is remote. Guards against a stray empty-string
  // url making a stdio server show the remote token/OAuth UI.
  const isRemote = !server.command;
  const primaryKey = secretKeys[0];
  const keyHint = primaryKey ? KEY_HINTS[primaryKey] : undefined;

  // Bumped each open so a slow status fetch from a previous open can't apply
  // after a newer one (or after the dialog closed).
  const runIdRef = useRef(0);

  async function refreshStatus() {
    const runId = ++runIdRef.current;
    const fresh = () => runId === runIdRef.current;
    if (secretKeys.length > 0) {
      try {
        const pairs = await secretStatus(server.id, secretKeys);
        if (fresh()) setVaulted(Object.fromEntries(pairs));
      } catch {
        /* non-fatal */
      }
    } else {
      setVaulted({});
    }
    if (isRemote && server.url) {
      hasAuthToken(server.id)
        .then((v) => fresh() && setAuthSet(v))
        .catch(() => {});
      setProbing(true);
      setAuthInfo(null);
      probeAuth(server.url)
        .then((v) => fresh() && setAuthInfo(v))
        .catch(() => {})
        .finally(() => fresh() && setProbing(false));
    }
  }

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) refreshStatus();
  }

  async function saveAuth() {
    if (!authInput) return;
    setBusyKey("auth");
    try {
      await setAuthToken(server.id, authInput);
      setAuthSet(true);
      setAuthInput("");
      toast.success("Saved auth token");
      onChanged?.();
    } catch (e) {
      toastError(secretErrorMessage(e));
    } finally {
      setBusyKey(null);
    }
  }

  async function clearAuth() {
    setBusyKey("auth-clear");
    try {
      await clearAuthToken(server.id);
      setAuthSet(false);
      toast.success("Cleared auth token");
      onChanged?.();
    } catch (e) {
      toastError(secretErrorMessage(e));
    } finally {
      setBusyKey(null);
    }
  }

  async function doOauth() {
    if (!server.url) return;
    setOauthBusy(true);
    toast.info("Opening your browser…", {
      description:
        "Sign in to the provider if prompted (you may need an existing account session), then approve access.",
    });
    try {
      await authenticateOauth(server.id, server.url);
      setAuthSet(true);
      toast.success("Authenticated");
      onChanged?.();
    } catch (e) {
      const msg = `${e}`;
      const blankHint = /state mismatch|timed out|closed/i.test(msg);
      toastError(`OAuth failed: ${msg}`, {
        description: blankHint
          ? "If the sign-in page was blank, your default browser (e.g. Safari) may block the local redirect. Set Chrome or Brave as default and try once more, or paste an access token above instead."
          : undefined,
      });
    } finally {
      setOauthBusy(false);
    }
  }

  async function save(key: string, value: string) {
    if (!value) return;
    setBusyKey(key);
    try {
      onSaved(await setSecret(server.id, key, value));
      setVaulted((v) => ({ ...v, [key]: true }));
      setInputs((i) => ({ ...i, [key]: "" }));
      toast.success(`Saved ${key}`);
      onChanged?.();
    } catch (e) {
      toastError(secretErrorMessage(e));
    } finally {
      setBusyKey(null);
    }
  }

  async function remove(key: string) {
    setBusyKey(`remove:${key}`);
    try {
      onSaved(await deleteSecret(server.id, key));
      toast.success(`Removed ${key}`);
      onChanged?.();
    } catch (e) {
      toastError(secretErrorMessage(e));
    } finally {
      setBusyKey(null);
    }
  }

  async function addNew() {
    const k = newKey.trim();
    if (!k || !newValue) return;
    setBusyKey("add");
    try {
      onSaved(await setSecret(server.id, k, newValue));
      setVaulted((v) => ({ ...v, [k]: true }));
      setInputs((i) => ({ ...i, [k]: "" }));
      toast.success(`Saved ${k}`);
      onChanged?.();
      setNewKey("");
      setNewValue("");
    } catch (e) {
      toastError(secretErrorMessage(e));
    } finally {
      setBusyKey(null);
    }
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
                <div className="flex items-start gap-2 rounded-md bg-success/10 p-2.5 text-xs text-success">
                  <Check className="mt-0.5 size-3.5 shrink-0" />
                  <span>
                    This server connects without auth. Just enable it, no token needed.
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
                          className="ml-1 inline-flex items-center gap-0.5 text-owned hover:underline"
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
                        <span className="inline-flex items-center gap-1 text-xs text-success">
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
                        disabled={busyKey !== null || !authInput}
                        onClick={saveAuth}
                      >
                        {busyKey === "auth" ? (
                          <>
                            <Loader2 className="size-4 animate-spin" />
                            Saving…
                          </>
                        ) : (
                          "Save"
                        )}
                      </Button>
                      {authSet && (
                        <Button
                          size="icon"
                          variant="ghost"
                          className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                          aria-label="Clear auth token"
                          disabled={busyKey !== null}
                          onClick={clearAuth}
                        >
                          {busyKey === "auth-clear" ? (
                            <Loader2 className="size-4 animate-spin" />
                          ) : (
                            <Trash2 className="size-4" />
                          )}
                        </Button>
                      )}
                    </div>
                  </div>

                  {(authInfo == null ||
                    authInfo.kind === "oauth" ||
                    authInfo.kind === "unknown") && (
                    <>
                      <Button
                        variant="secondary"
                        size="sm"
                        disabled={oauthBusy}
                        onClick={doOauth}
                      >
                        {oauthBusy ? (
                          <>
                            <Loader2 className="size-4 animate-spin" />
                            Waiting for browser sign-in…
                          </>
                        ) : (
                          "Sign in with OAuth"
                        )}
                      </Button>
                      {!oauthBusy && /mac/i.test(navigator.userAgent) && (
                        <p className="text-[11px] text-muted-foreground">
                          On macOS, set Chrome or Brave as your default browser
                          first. Safari can block the local sign-in redirect.
                        </p>
                      )}
                      {oauthBusy && (
                        <p className="text-[11px] text-muted-foreground">
                          Finish signing in and approve access in your browser. If
                          the page is blank, your default browser (e.g. Safari) may
                          block the local redirect, use Chrome or Brave, or paste an
                          access token above instead.
                        </p>
                      )}
                    </>
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
                      className="ml-1 inline-flex items-center gap-0.5 text-owned hover:underline"
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
                      <span className="inline-flex items-center gap-1 text-xs text-success">
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
                      disabled={busyKey !== null || !(inputs[key] ?? "")}
                      onClick={() => save(key, inputs[key] ?? "")}
                    >
                      {busyKey === key ? (
                        <>
                          <Loader2 className="size-4 animate-spin" />
                          Saving…
                        </>
                      ) : (
                        "Save"
                      )}
                    </Button>
                    {vaulted[key] && (
                      <Button
                        size="icon"
                        variant="ghost"
                        className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                        aria-label={`Remove ${key}`}
                        disabled={busyKey !== null}
                        onClick={() => remove(key)}
                      >
                        {busyKey === `remove:${key}` ? (
                          <Loader2 className="size-4 animate-spin" />
                        ) : (
                          <Trash2 className="size-4" />
                        )}
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
                disabled={busyKey !== null || !newKey.trim() || !newValue}
                onClick={addNew}
              >
                {busyKey === "add" ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Plus className="size-4" />
                )}
              </Button>
            </div>
          </details>
        </div>
      </DialogContent>
    </Dialog>
  );
}
