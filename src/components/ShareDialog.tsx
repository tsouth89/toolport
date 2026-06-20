import { useState, type ReactNode } from "react";
import { Check, Copy, Upload } from "lucide-react";
import { toast } from "sonner";
import { exportConfig, importConfig } from "@/lib/api";
import type { Registry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";

interface Props {
  trigger: ReactNode;
  onImported: (registry: Registry) => void;
}

/** Share a curated server set with a teammate (and import theirs). Secret values
 * are never included - each person vaults their own keys after importing. This is
 * the no-backend version of "push a setup to your team". */
export function ShareDialog({ trigger, onImported }: Props) {
  const [open, setOpen] = useState(false);
  const [exported, setExported] = useState("");
  const [paste, setPaste] = useState("");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) {
      setPaste("");
      setCopied(false);
      exportConfig()
        .then(setExported)
        .catch(() => setExported(""));
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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Share setup</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-5 py-1">
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-2">
              <Label className="text-sm">Your setup</Label>
              <Button
                size="sm"
                variant="outline"
                className="h-7 px-2 text-xs"
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
            </div>
            <p className="text-xs text-muted-foreground">
              Send this to a teammate to share your server set. Secrets are never
              included - each person adds their own keys after importing.
            </p>
            <textarea readOnly value={exported} rows={6} className={area} />
          </div>

          <div className="flex flex-col gap-2 border-t pt-4">
            <Label className="text-sm">Import a setup</Label>
            <textarea
              placeholder="Paste a shared setup here"
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              rows={6}
              className={area}
            />
            <Button
              className="self-start"
              onClick={doImport}
              disabled={busy || !paste.trim()}
            >
              <Upload className="size-4" />
              Import
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
