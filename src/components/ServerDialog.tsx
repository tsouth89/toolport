import { useState, type ReactNode } from "react";
import { Loader2, Plus, X } from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import { addServer, setSecret, updateServer } from "@/lib/api";
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
}

export function ServerDialog({ trigger, onSaved, editId, initial }: Props) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: initial?.name ?? "",
    transport: (initial?.transport ?? "stdio") as Transport,
    command: initial?.command ?? "",
    args: initial?.args.join(" ") ?? "",
    url: initial?.url ?? "",
  });
  // Env vars (API keys etc.). Values are vaulted in the OS keychain, never stored
  // in the registry, so existing secrets show as declared keys with empty values.
  const [envRows, setEnvRows] = useState<{ key: string; value: string }[]>(
    initial?.env.map((e) => ({ key: e.key, value: "" })) ?? [],
  );
  const [busy, setBusy] = useState(false);
  const isStdio = form.transport === "stdio";
  const editing = editId !== undefined;

  // The dialog instance is mounted persistently (e.g. the header "Add server"
  // button), so reset the form each time it opens - otherwise it keeps the last
  // entry's values instead of starting blank (or re-deriving from `initial`).
  function onOpenChange(next: boolean) {
    if (next) {
      setForm({
        name: initial?.name ?? "",
        transport: (initial?.transport ?? "stdio") as Transport,
        command: initial?.command ?? "",
        args: initial?.args.join(" ") ?? "",
        url: initial?.url ?? "",
      });
      setEnvRows(initial?.env.map((e) => ({ key: e.key, value: "" })) ?? []);
    }
    setOpen(next);
  }

  function set<K extends keyof typeof form>(key: K, value: (typeof form)[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function setEnvRow(i: number, field: "key" | "value", value: string) {
    setEnvRows((rows) => rows.map((r, j) => (j === i ? { ...r, [field]: value } : r)));
  }
  function addEnvRow() {
    setEnvRows((rows) => [...rows, { key: "", value: "" }]);
  }
  function removeEnvRow(i: number) {
    setEnvRows((rows) => rows.filter((_, j) => j !== i));
  }

  async function handleSave() {
    if (!form.name.trim()) return;
    const declared = envRows.filter((r) => r.key.trim());
    const entry: ServerEntry = {
      id: editId ?? "",
      name: form.name.trim(),
      transport: form.transport,
      command: isStdio ? form.command.trim() || null : null,
      args: isStdio ? form.args.split(/\s+/).filter(Boolean) : [],
      // Declare every env-var name as a secret; the values are vaulted separately
      // below (they never enter the registry file).
      env: declared.map((r) => ({ key: r.key.trim(), value: null, secret: true })),
      url: isStdio ? null : form.url.trim() || null,
      source: initial?.source ?? "manual",
    };
    setBusy(true);
    try {
      let result = editing ? await updateServer(entry) : await addServer(entry);
      // Vault any values the user entered now. setSecret keys by server id. For a
      // new server, add_server appends it, so it's the last entry - resolving by
      // name would pick the wrong one if two servers share a name.
      const id = editing
        ? editId
        : result.servers[result.servers.length - 1]?.id;
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
                  placeholder="-y @modelcontextprotocol/server-filesystem"
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
                placeholder="https://mcp.example.com/mcp"
                value={form.url}
                onChange={(e) => set("url", e.target.value)}
              />
            </div>
          )}

          <div className="flex flex-col gap-2">
            <Label>Environment variables</Label>
            <p className="-mt-1 text-xs text-muted-foreground">
              API keys and other secrets the server needs (e.g.{" "}
              <code className="font-mono">RESEND_API_KEY</code>). Values are stored
              in your OS keychain, never in the config.
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
                  placeholder={initial?.env.some((e) => e.key === row.key) ? "•••• (saved)" : "value"}
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
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={busy || !form.name.trim()}>
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
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
