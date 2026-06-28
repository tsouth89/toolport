import { useEffect, useState, type ReactNode } from "react";
import {
  ArrowLeft,
  Check,
  Copy,
  FileDown,
  FileUp,
  Loader2,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import { open as openFile, save } from "@tauri-apps/plugin-dialog";
import {
  exportConfig,
  exportConfigToPath,
  importConfig,
  previewImport,
  readSetupFile,
} from "@/lib/api";
import type { ImportItem, Registry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { TransportPill } from "@/components/TransportPill";
import { Label } from "@/components/ui/label";

interface Props {
  trigger: ReactNode;
  onImported: (registry: Registry) => void;
}

/** Share a curated server set with a teammate (and import theirs). Secret values
 * are never included - each person vaults their own keys after importing. This is
 * the no-backend version of "push a setup to your team".
 *
 * A shared setup is untrusted input: each server carries a command that runs when
 * the server is enabled. So importing is two steps - preview exactly what would be
 * added (command/args/url), then confirm - rather than applying a pasted blob blind. */
export function ShareDialog({ trigger, onImported }: Props) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [exported, setExported] = useState("");
  const [paste, setPaste] = useState("");
  const [copied, setCopied] = useState(false);
  const [busyAction, setBusyAction] = useState<
    "preview-paste" | "preview-file" | "import" | null
  >(null);
  // When set, the dialog shows the review-and-confirm view for `pendingJson`.
  const [preview, setPreview] = useState<ImportItem[] | null>(null);
  const [pendingJson, setPendingJson] = useState("");

  useEffect(() => {
    if (!open) return;
    exportConfig(name, description)
      .then(setExported)
      .catch(() => setExported(""));
  }, [open, name, description]);

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) {
      setPaste("");
      setCopied(false);
      setPreview(null);
      setPendingJson("");
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(exported);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Couldn't copy automatically. Select the text and copy it.");
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

  // Parse + preview a candidate setup (paste or file) before importing anything.
  async function startPreview(json: string, source: "preview-paste" | "preview-file") {
    setBusyAction(source);
    try {
      const items = await previewImport(json);
      setPendingJson(json);
      setPreview(items);
    } catch (e) {
      toast.error(`Couldn't read that setup: ${e}`);
    } finally {
      setBusyAction(null);
    }
  }

  async function loadFromFile() {
    try {
      const path = await openFile({
        title: "Open a Conduit setup",
        multiple: false,
        directory: false,
        filters: [{ name: "Conduit setup", extensions: ["json"] }],
      });
      if (!path || typeof path !== "string") return;
      const json = await readSetupFile(path);
      await startPreview(json, "preview-file");
    } catch (e) {
      toast.error(`Couldn't open that file: ${e}`);
    }
  }

  async function confirmImport() {
    setBusyAction("import");
    try {
      onImported(await importConfig(pendingJson));
      toast.success("Imported shared setup", {
        description: "Add any API keys each server needs, then enable them.",
      });
      setOpen(false);
    } catch (e) {
      toast.error(`Couldn't import: ${e}`);
    } finally {
      setBusyAction(null);
    }
  }

  const newCount = preview?.filter((i) => i.isNew).length ?? 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{preview ? "Review this setup" : "Share setup"}</DialogTitle>
        </DialogHeader>

        {preview ? (
          <div className="flex flex-col gap-4 py-1">
            <p className="text-xs text-muted-foreground">
              These servers come from a shared file. Each runs the command shown when
              you enable it, so review them before importing. You'll add your own keys
              after.
            </p>
            <div className="flex max-h-72 flex-col gap-2 overflow-y-auto">
              {preview.map((item, i) => (
                <ImportRow key={`${item.name}-${i}`} item={item} />
              ))}
            </div>
            <div className="flex items-center justify-between gap-2 border-t pt-3">
              <Button variant="ghost" onClick={() => setPreview(null)} disabled={busyAction !== null}>
                <ArrowLeft className="size-4" />
                Back
              </Button>
              <Button onClick={confirmImport} disabled={busyAction !== null || newCount === 0}>
                {busyAction === "import" ? (
                  <>
                    <Loader2 className="size-4 animate-spin" />
                    Importing…
                  </>
                ) : (
                  <>
                    <Check className="size-4" />
                    {newCount === 0
                      ? "Nothing new to import"
                      : `Import ${newCount} server${newCount === 1 ? "" : "s"}`}
                  </>
                )}
              </Button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-5 py-1">
            <div className="flex flex-col gap-2">
              <Label className="text-sm">Your setup</Label>
              <p className="text-xs text-muted-foreground">
                Send this to a teammate to share your server set. Secrets are never
                included, each person adds their own keys after importing.
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
              <Textarea
                readOnly
                aria-label="Exported setup"
                value={exported}
                rows={5}
                className="resize-none font-mono text-xs"
              />
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
              <Textarea
                placeholder="Paste a shared setup here"
                aria-label="Paste a shared setup"
                value={paste}
                onChange={(e) => setPaste(e.target.value)}
                rows={5}
                className="resize-none font-mono text-xs"
              />
              <div className="flex flex-wrap gap-2">
                <Button
                  onClick={() => startPreview(paste, "preview-paste")}
                  disabled={busyAction !== null || !paste.trim()}
                >
                  {busyAction === "preview-paste" ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Reviewing…
                    </>
                  ) : (
                    <>
                      <Upload className="size-4" />
                      Review and import
                    </>
                  )}
                </Button>
                <Button variant="outline" onClick={loadFromFile} disabled={busyAction !== null}>
                  {busyAction === "preview-file" ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Loading…
                    </>
                  ) : (
                    <>
                      <FileUp className="size-4" />
                      Load from file
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

/** One reviewable server: name, what it runs, and a flag if it spawns a shell. */
function ImportRow({ item }: { item: ImportItem }) {
  const runs =
    item.command != null
      ? [item.command, ...item.args].join(" ")
      : (item.url ?? "");
  const shell = runsShell(item.command);
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="truncate text-sm font-medium">{item.name}</span>
        <TransportPill transport={item.transport} />
        {!item.isNew && (
          <span className="ml-auto shrink-0 text-xs text-muted-foreground">
            already added
          </span>
        )}
      </div>
      {runs && (
        <p className="mt-1 font-mono text-xs break-all text-muted-foreground">
          {runs}
        </p>
      )}
      {shell && (
        <p className="mt-1.5 flex items-center gap-1.5 text-xs text-warning">
          <ShieldAlert className="size-3.5 shrink-0" />
          Runs a shell command. Only import setups you trust.
        </p>
      )}
    </div>
  );
}

/** True if the command spawns a shell interpreter (extra scrutiny on import). */
function runsShell(command: string | null): boolean {
  if (!command) return false;
  const base = command
    .replace(/\\/g, "/")
    .split("/")
    .pop()!
    .toLowerCase()
    .replace(/\.exe$/, "");
  return ["cmd", "sh", "bash", "zsh", "powershell", "pwsh"].includes(base);
}

/** A filesystem-safe slug for the default filename. */
function slug(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
