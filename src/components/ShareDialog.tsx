import { useEffect, useState, type ReactNode } from "react";
import { Check, Copy, FileDown, FileUp, Upload } from "lucide-react";
import { toast } from "sonner";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  exportConfig,
  exportConfigToPath,
  importConfig,
  importConfigFromPath,
} from "@/lib/api";
import type { Registry } from "@/lib/types";
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
  trigger: ReactNode;
  onImported: (registry: Registry) => void;
}

/** Share a curated server set with a teammate (and import theirs). Secret values
 * are never included - each person vaults their own keys after importing. This is
 * the no-backend version of "push a setup to your team". Export via clipboard or
 * a file; label it with a name + description so the recipient knows what it is. */
export function ShareDialog({ trigger, onImported }: Props) {
  const [open_, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [exported, setExported] = useState("");
  const [paste, setPaste] = useState("");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);

  // Re-serialize whenever the dialog opens or the label changes, so the textarea
  // and any file/clipboard export carry the current name + description.
  useEffect(() => {
    if (!open_) return;
    exportConfig(name, description)
      .then(setExported)
      .catch(() => setExported(""));
  }, [open_, name, description]);

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) {
      setPaste("");
      setCopied(false);
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(exported);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Couldn't copy automatically - select the text and copy it.");
    }
  }

  async function saveToFile() {
    try {
      const path = await save({
        title: "Save Conduit setup",
        defaultPath: `${slug(name) || "conduit-setup"}.json`,
        filters: [{ name: "Conduit setup", extensions: ["json"] }],
      });
      if (!path) return;
      await exportConfigToPath(path, name, description);
      toast.success("Saved setup to file");
    } catch (e) {
      toast.error(`Couldn't save: ${e}`);
    }
  }

  async function loadFromFile() {
    try {
      const path = await open({
        title: "Open a Conduit setup",
        multiple: false,
        directory: false,
        filters: [{ name: "Conduit setup", extensions: ["json"] }],
      });
      if (!path || typeof path !== "string") return;
      setBusy(true);
      const reg = await importConfigFromPath(path);
      onImported(reg);
      toast.success("Imported shared setup", {
        description: "Add any API keys each server needs, then enable them.",
      });
      setOpen(false);
    } catch (e) {
      toast.error(`Couldn't import: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  async function doImport() {
    if (!paste.trim()) return;
    setBusy(true);
    try {
      const reg = await importConfig(paste);
      onImported(reg);
      toast.success("Imported shared setup", {
        description: "Add any API keys each server needs, then enable them.",
      });
      setOpen(false);
    } catch (e) {
      toast.error(`Couldn't import: ${e}`);
    } finally {
      setBusy(false);
    }
  }

  const area =
    "w-full rounded-md border bg-background p-2.5 font-mono text-xs resize-none focus:outline-none focus:ring-1 focus:ring-ring";

  return (
    <Dialog open={open_} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Share setup</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-5 py-1">
          <div className="flex flex-col gap-2">
            <Label className="text-sm">Your setup</Label>
            <p className="text-xs text-muted-foreground">
              Send this to a teammate to share your server set. Secrets are never
              included - each person adds their own keys after importing.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Name (optional)"
                className="h-8 text-sm"
              />
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Description (optional)"
                className="h-8 text-sm"
              />
            </div>
            <textarea readOnly value={exported} rows={5} className={area} />
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                onClick={copy}
                disabled={!exported}
              >
                {copied ? (
                  <>
                    <Check className="size-3.5" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="size-3.5" /> Copy
                  </>
                )}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="h-8"
                onClick={saveToFile}
                disabled={!exported}
              >
                <FileDown className="size-3.5" /> Save to file
              </Button>
            </div>
          </div>

          <div className="flex flex-col gap-2 border-t pt-4">
            <Label className="text-sm">Import a setup</Label>
            <textarea
              placeholder="Paste a shared setup here"
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              rows={5}
              className={area}
            />
            <div className="flex flex-wrap gap-2">
              <Button onClick={doImport} disabled={busy || !paste.trim()}>
                <Upload className="size-4" />
                Import
              </Button>
              <Button variant="outline" onClick={loadFromFile} disabled={busy}>
                <FileUp className="size-4" />
                Load from file
              </Button>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/** A filesystem-safe slug for the default filename. */
function slug(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
