import { useState, type ReactNode } from "react";
import { toast } from "sonner";
import { addServer, updateServer } from "@/lib/api";
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
  const isStdio = form.transport === "stdio";
  const editing = editId !== undefined;

  function set<K extends keyof typeof form>(key: K, value: (typeof form)[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function handleSave() {
    if (!form.name.trim()) return;
    const entry: ServerEntry = {
      id: editId ?? "",
      name: form.name.trim(),
      transport: form.transport,
      command: isStdio ? form.command.trim() || null : null,
      args: isStdio ? form.args.split(/\s+/).filter(Boolean) : [],
      // Carry env-var names when editing/duplicating; secret *values* live in
      // the keychain per server id, so a duplicate starts with fresh secrets.
      env: initial?.env ?? [],
      url: isStdio ? null : form.url.trim() || null,
      source: initial?.source ?? "manual",
    };
    try {
      const result = editing ? await updateServer(entry) : await addServer(entry);
      onSaved(result);
      toast.success(editing ? `Saved ${entry.name}` : `Added ${entry.name}`);
      setOpen(false);
    } catch (e) {
      toast.error(`${e}`);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
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
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={handleSave} disabled={!form.name.trim()}>
            {editing ? "Save" : "Add"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
