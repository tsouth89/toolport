import { useState, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardPaste,
  Loader2,
  Plus,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import {
  addServer,
  parseServerSnippet,
  setSecret,
  testServer,
  updateServer,
} from "@/lib/api";
import { formatArgs, parseArgs } from "@/lib/args";
import type { Registry, ServerEntry, Transport } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Props {
  trigger: ReactNode;
  onSaved: (registry: Registry) => void;
  /** When set, the dialog edits this server (vs. adding a new one). */
  editId?: string;
  /** Pre-fill values (for edit, or duplicating an existing server). */
  initial?: ServerEntry;
  /** Names of servers that already exist, to warn on a duplicate name. */
  existingNames?: string[];
  /** Open the dialog automatically on mount (used by catalog configure-add). */
  autoOpen?: boolean;
  /** Called when the dialog closes without saving (dismiss/cancel). */
  onClose?: () => void;
  /** Placeholder + helper text for the URL field when the server is self-hosted
   * (e.g. n8n, Langfuse). Shown as input placeholder and as an explanatory note
   * below the field. */
  urlHint?: string;
}

export function ServerDialog({
  trigger,
  onSaved,
  editId,
  initial,
  existingNames,
  autoOpen,
  onClose,
  urlHint,
}: Props) {
  const [open, setOpen] = useState(autoOpen ?? false);
  const [form, setForm] = useState({
    name: initial?.name ?? "",
    transport: (initial?.transport ?? "stdio") as Transport,
    command: initial?.command ?? "",
    args: formatArgs(initial?.args ?? []),
    url: initial?.url ?? "",
  });
  // Env vars (API keys etc.). Values are vaulted in the OS keychain, never stored
  // in the registry, so existing secrets show as declared keys with empty values.
  const [envRows, setEnvRows] = useState<{ key: string; value: string }[]>(
    initial?.env.map((e) => ({ key: e.key, value: "" })) ?? [],
  );
  const [busy, setBusy] = useState(false);
  const [test, setTest] = useState<{
    status: "idle" | "testing" | "ok" | "fail";
    message: string;
  }>({ status: "idle", message: "" });
  const isStdio = form.transport === "stdio";
  const editing = editId !== undefined;

  // Paste-from-config state.
  const [showPaste, setShowPaste] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [parsing, setParsing] = useState(false);

  // A prior test result is stale the moment the connection details change.
  function clearTest() {
    setTest((t) => (t.status === "idle" ? t : { status: "idle", message: "" }));
  }

  // The dialog instance is mounted persistently (e.g. the header "Add server"
  // button), so reset the form each time it opens - otherwise it keeps the last
  // entry's values instead of starting blank (or re-deriving from `initial`).
  function onOpenChange(next: boolean) {
    if (!next && onClose) {
      onClose();
      return;
    }
    if (next) {
      setForm({
        name: initial?.name ?? "",
        transport: (initial?.transport ?? "stdio") as Transport,
        command: initial?.command ?? "",
        args: formatArgs(initial?.args ?? []),
        url: initial?.url ?? "",
      });
      setEnvRows(initial?.env.map((e) => ({ key: e.key, value: "" })) ?? []);
      setTest({ status: "idle", message: "" });
      setShowPaste(false);
      setPasteText("");
    }
    setOpen(next);
  }

  function set<K extends keyof typeof form>(key: K, value: (typeof form)[K]) {
    setForm((f) => ({ ...f, [key]: value }));
    clearTest();
  }

  function setEnvRow(i: number, field: "key" | "value", value: string) {
    setEnvRows((rows) => rows.map((r, j) => (j === i ? { ...r, [field]: value } : r)));
    clearTest();
  }
  function addEnvRow() {
    setEnvRows((rows) => [...rows, { key: "", value: "" }]);
    clearTest();
  }
  function removeEnvRow(i: number) {
    setEnvRows((rows) => rows.filter((_, j) => j !== i));
    clearTest();
  }

  async function handleParse() {
    if (!pasteText.trim()) return;
    setParsing(true);
    try {
      const servers = await parseServerSnippet(pasteText);
      if (servers.length === 0) {
        toast.error("No servers found in the pasted config");
        return;
      }
      const s = servers[0];
      setForm({
        name: s.name || "",
        transport: (s.transport === "unknown" ? "stdio" : s.transport) as Transport,
        command: s.command ?? "",
        args: formatArgs(s.args),
        url: s.url ?? "",
      });
      setEnvRows(
        s.env.map((e) => ({
          key: e.key,
          value: e.value ?? "",
        })),
      );
      setTest({ status: "idle", message: "" });
      if (servers.length > 1) {
        toast.info(
          `Found ${servers.length} servers, filled "${s.name}". Add the rest separately.`,
        );
      } else {
        toast.success(`Parsed "${s.name}" from config`);
      }
      setShowPaste(false);
      setPasteText("");
    } catch (e) {
      toastError(`Could not parse: ${e}`);
    } finally {
      setParsing(false);
    }
  }

  // Build the entry from the form. For a real save the secret values are vaulted
  // separately (never written to the registry); for a connection test they ride
  // along on `env` so the probe can actually launch/authenticate the server.
  function buildEntry(withSecretValues: boolean): ServerEntry {
    const declared = envRows.filter((r) => r.key.trim());
    return {
      id: editId ?? "",
      name: form.name.trim(),
      transport: form.transport,
      command: isStdio ? form.command.trim() || null : null,
      args: isStdio ? parseArgs(form.args) : [],
      env: declared.map((r) => ({
        key: r.key.trim(),
        value: withSecretValues && r.value ? r.value : null,
        secret: true,
      })),
      url: isStdio ? null : form.url.trim() || null,
      source: initial?.source ?? "manual",
    };
  }

  // Per-transport validation. `errors` block Save; the duplicate-name case is a
  // soft warning, since duplicating a server per account is a real workflow.
  const nameTrim = form.name.trim();
  const urlTrim = form.url.trim();
  const cmdTrim = form.command.trim();
  const errors: string[] = [];
  if (!nameTrim) errors.push("Give the server a name.");
  if (isStdio) {
    if (!cmdTrim) errors.push("Enter the command to run (e.g. npx).");
  } else if (!urlTrim) {
    errors.push("Enter the server URL.");
  } else if (!/^https?:\/\//i.test(urlTrim)) {
    errors.push("The URL must start with http:// or https://.");
  }
  const ownName = editing ? initial?.name?.trim().toLowerCase() : undefined;
  const duplicateName =
    !!nameTrim &&
    nameTrim.toLowerCase() !== ownName &&
    (existingNames ?? []).some((n) => n.trim().toLowerCase() === nameTrim.toLowerCase());
  const canSave = errors.length === 0 && !busy && test.status !== "testing";

  async function handleTest() {
    setTest({ status: "testing", message: "" });
    try {
      const r = await testServer(buildEntry(true));
      if (r.ok) {
        setTest({
          status: "ok",
          message: `Connected. Found ${r.toolCount} tool${r.toolCount === 1 ? "" : "s"}.`,
        });
      } else {
        setTest({
          status: "fail",
          message: r.authRequired
            ? `Reachable, but needs credentials: ${r.error ?? "authentication required"}`
            : (r.error ?? "Could not connect."),
        });
      }
    } catch (e) {
      setTest({ status: "fail", message: String(e) });
    }
  }

  async function handleSave() {
    if (errors.length > 0) return;
    const entry = buildEntry(false);
    const declared = envRows.filter((r) => r.key.trim());
    setBusy(true);
    try {
      let result = editing ? await updateServer(entry) : await addServer(entry);
      // Vault any values the user entered now. setSecret keys by server id. For a
      // new server, add_server appends it, so it's the last entry - resolving by
      // name would pick the wrong one if two servers share a name.
      const id = editing ? editId : result.servers[result.servers.length - 1]?.id;
      if (id) {
        for (const r of declared) {
          if (r.value) result = await setSecret(id, r.key.trim(), r.value);
        }
      }
      onSaved(result);
      toast.success(editing ? `Saved ${entry.name}` : `Added ${entry.name}`);
      setOpen(false);
    } catch (e) {
      toastError(`Couldn't save ${entry.name}: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit server" : "Add MCP server"}</DialogTitle>
        </DialogHeader>

        {/* Paste-from-config: collapsible textarea that auto-detects format.
            Only shown when adding a new server, not when editing. */}
        {!editing && (
          <div className="rounded-md border">
            <button
              type="button"
              className="flex w-full items-center gap-2 px-3 py-2 text-sm font-medium text-muted-foreground transition hover:text-foreground"
              onClick={() => setShowPaste((v) => !v)}
            >
              {showPaste ? (
                <ChevronDown className="size-4" />
              ) : (
                <ChevronRight className="size-4" />
              )}
              <ClipboardPaste className="size-4" />
              Paste from client config
            </button>
            {showPaste && (
              <div className="flex flex-col gap-2 border-t px-3 pb-3 pt-2">
                <textarea
                  className="min-h-[100px] w-full resize-y rounded-md bg-muted/50 p-2 font-mono text-xs"
                  placeholder={
                    'Paste a config snippet from any client:\n\n• Claude Code: claude mcp add-json ...\n• Cursor/Windsurf/Antigravity: {"mcpServers": ...}\n• VS Code: {"servers": ...}\n• Codex: [mcp_servers.name]\n• Zed: {"context_servers": ...}'
                  }
                  value={pasteText}
                  onChange={(e) => setPasteText(e.target.value)}
                />
                <Button
                  variant="secondary"
                  size="sm"
                  className="self-end"
                  disabled={!pasteText.trim() || parsing}
                  onClick={handleParse}
                >
                  {parsing ? "Parsing…" : "Parse & fill"}
                </Button>
              </div>
            )}
          </div>
        )}

        <div className="flex flex-col gap-4 py-2">
          <div className="flex flex-col gap-2">
            <Label htmlFor="srv-name">Name</Label>
            <Input
              id="srv-name"
              autoFocus
              placeholder="revenuecat (work)"
              value={form.name}
              onChange={(e) => set("name", e.target.value)}
            />
          </div>

          <div className="flex flex-col gap-2">
            <Label>Transport</Label>
            <Select
              value={form.transport}
              onValueChange={(v) => set("transport", v as Transport)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="stdio">stdio (local command)</SelectItem>
                <SelectItem value="http">http (remote)</SelectItem>
                <SelectItem value="sse">sse (remote)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {isStdio ? (
            <>
              <div className="flex flex-col gap-2">
                <Label htmlFor="srv-cmd">Command</Label>
                <Input
                  id="srv-cmd"
                  placeholder="npx"
                  value={form.command}
                  onChange={(e) => set("command", e.target.value)}
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label htmlFor="srv-args">Arguments</Label>
                <Input
                  id="srv-args"
                  placeholder={
                    '-y @scope/package  (quote paths with spaces, e.g. "/Applications/My App.app/tool")'
                  }
                  value={form.args}
                  onChange={(e) => set("args", e.target.value)}
                />
              </div>
            </>
          ) : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="srv-url">URL</Label>
              <Input
                id="srv-url"
                placeholder={urlHint ?? "https://mcp.example.com/mcp"}
                value={form.url}
                onChange={(e) => set("url", e.target.value)}
              />
              {urlHint && (
                <p className="text-xs text-muted-foreground">
                  Enter the URL of your self-hosted instance. For example:{" "}
                  <code className="font-mono">{urlHint}</code>
                </p>
              )}
            </div>
          )}

          <div className="flex flex-col gap-2">
            <Label>Environment variables</Label>
            <p className="-mt-1 text-xs text-muted-foreground">
              API keys and other secrets the server needs (e.g.{" "}
              <code className="font-mono">RESEND_API_KEY</code>). Values are stored in
              your OS keychain, never in the config.
            </p>
            {envRows.map((row, i) => (
              <div key={i} className="flex items-center gap-2">
                <Input
                  placeholder="ENV_NAME"
                  className="font-mono"
                  value={row.key}
                  onChange={(e) => setEnvRow(i, "key", e.target.value)}
                />
                <Input
                  type="password"
                  placeholder={
                    initial?.env.some((e) => e.key === row.key) ? "•••• (saved)" : "value"
                  }
                  value={row.value}
                  onChange={(e) => setEnvRow(i, "value", e.target.value)}
                />
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-8 shrink-0 text-muted-foreground hover:text-destructive"
                  aria-label="Remove variable"
                  onClick={() => removeEnvRow(i)}
                >
                  <X className="size-4" />
                </Button>
              </div>
            ))}
            <Button
              variant="outline"
              size="sm"
              className="self-start"
              onClick={addEnvRow}
            >
              <Plus className="size-4" />
              Add variable
            </Button>
          </div>

          {(errors.length > 0 ||
            duplicateName ||
            test.status === "ok" ||
            test.status === "fail") && (
            <div className="flex flex-col gap-1.5 text-xs">
              {errors.map((msg) => (
                <p key={msg} className="text-destructive">
                  {msg}
                </p>
              ))}
              {duplicateName && (
                <p className="flex items-start gap-1.5 text-amber-600 dark:text-amber-500">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                  <span>
                    Another server is already named "{nameTrim}". That's fine for multiple
                    accounts; it'll be saved as a separate entry.
                  </span>
                </p>
              )}
              {test.status === "ok" && (
                <p className="flex items-start gap-1.5 text-emerald-600 dark:text-emerald-500">
                  <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" />
                  <span>{test.message}</span>
                </p>
              )}
              {test.status === "fail" && (
                <p className="flex items-start gap-1.5 text-destructive">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                  <span>{test.message}</span>
                </p>
              )}
            </div>
          )}
        </div>
        <DialogFooter className="sm:justify-between">
          <Button
            variant="ghost"
            onClick={handleTest}
            disabled={busy || errors.length > 0 || test.status === "testing"}
          >
            {test.status === "testing" ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Testing…
              </>
            ) : (
              "Test connection"
            )}
          </Button>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={handleSave} disabled={!canSave}>
              {busy ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  {editing ? "Saving…" : "Adding…"}
                </>
              ) : editing ? (
                "Save"
              ) : (
                "Add"
              )}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
