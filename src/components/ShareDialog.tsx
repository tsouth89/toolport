import { useEffect, useState, type ReactNode } from "react";
import {
  ArrowLeft,
  Check,
  Copy,
  FileDown,
  FileUp,
  Link2,
  Loader2,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import { open as openFile, save } from "@tauri-apps/plugin-dialog";
import {
  exportConfig,
  exportConfigToPath,
  fetchSharedSetup,
  getRegistry,
  importConfig,
  previewImport,
  readSetupFile,
  shareStack,
  takePendingShared,
} from "@/lib/api";
import { listen } from "@tauri-apps/api/event";
import { isGatewayServer, type ImportItem, type Registry } from "@/lib/types";
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
  // The user's servers and which to include in the shared stack (default all).
  const [servers, setServers] = useState<{ name: string; transport: string }[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // A generated share link (conduitmcp.app/s/...), cleared when the export changes.
  const [shareLink, setShareLink] = useState("");
  const [linking, setLinking] = useState(false);

  // Load the server list on open so the user can choose a subset to share.
  useEffect(() => {
    if (!open) return;
    getRegistry()
      .then((reg) => {
        const list = reg.servers
          .filter((s) => !isGatewayServer(s))
          .map((s) => ({ name: s.name, transport: s.transport }));
        setServers(list);
        setSelected(new Set(list.map((s) => s.name)));
      })
      .catch(() => {});
  }, [open]);

  // Selection passed to the backend: undefined = share everything (also the
  // pre-load state), otherwise just the chosen subset.
  const allSelected = servers.length > 0 && selected.size === servers.length;
  const shareFilter =
    servers.length === 0 || allSelected ? undefined : Array.from(selected);

  useEffect(() => {
    if (!open) return;
    setShareLink(""); // the export changed, so any prior link is stale
    exportConfig(name, description, shareFilter)
      .then(setExported)
      .catch(() => setExported(""));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, name, description, selected, servers]);

  function onOpenChange(next: boolean) {
    setOpen(next);
    if (next) {
      setPaste("");
      setCopied(false);
      setPreview(null);
      setPendingJson("");
    }
  }

  async function createLink() {
    setLinking(true);
    try {
      const url = await shareStack(exported);
      setShareLink(url);
      navigator.clipboard.writeText(url).catch(() => {});
      toast.success("Share link created and copied");
    } catch (e) {
      toastError(`Couldn't create a link: ${e}`);
    } finally {
      setLinking(false);
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(exported);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toastError("Couldn't copy automatically. Select the text and copy it.");
    }
  }

  async function saveToFile() {
    try {
      const path = await save({
        title: "Save Toolport setup",
        defaultPath: `${slug(name) || "conduit-setup"}.json`,
        filters: [{ name: "Toolport setup", extensions: ["json"] }],
      });
      if (!path) return;
      await exportConfigToPath(path, name, description, shareFilter);
      toast.success("Saved setup to file");
    } catch (e) {
      toastError(`Couldn't save: ${e}`);
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
      toastError(`Couldn't read that setup: ${e}`);
    } finally {
      setBusyAction(null);
    }
  }

  async function loadFromFile() {
    try {
      const path = await openFile({
        title: "Open a Toolport setup",
        multiple: false,
        directory: false,
        filters: [{ name: "Toolport setup", extensions: ["json"] }],
      });
      if (!path || typeof path !== "string") return;
      const json = await readSetupFile(path);
      await startPreview(json, "preview-file");
    } catch (e) {
      toastError(`Couldn't open that file: ${e}`);
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
      toastError(`Couldn't import: ${e}`);
    } finally {
      setBusyAction(null);
    }
  }

  // Open the import review when a conduit://import?s=<id> deep link arrives (the
  // share page's "Open in Toolport" button), including one captured before mount.
  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    async function openShared(id: string) {
      try {
        const json = await fetchSharedSetup(id);
        if (cancelled) return;
        setOpen(true);
        await startPreview(json, "preview-paste");
      } catch (e) {
        toastError(`Couldn't open that shared stack: ${e}`);
      }
    }
    takePendingShared()
      .then((id) => {
        if (id && !cancelled) openShared(id);
      })
      .catch(() => {});
    listen<string>("import-shared", (event) => {
      if (event.payload) openShared(event.payload);
    })
      .then((un) => {
        if (cancelled) un();
        else unlisten = un;
      })
      .catch(() => {});
    return () => {
      cancelled = true;
      unlisten?.();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

              {servers.length > 0 && (
                <div className="flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">
                      Servers to include ({selected.size}/{servers.length})
                    </span>
                    <div className="flex gap-2 text-[11px]">
                      <button
                        type="button"
                        className="text-muted-foreground hover:text-foreground"
                        onClick={() => setSelected(new Set(servers.map((s) => s.name)))}
                      >
                        All
                      </button>
                      <button
                        type="button"
                        className="text-muted-foreground hover:text-foreground"
                        onClick={() => setSelected(new Set())}
                      >
                        None
                      </button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {servers.map((s) => {
                      const on = selected.has(s.name);
                      return (
                        <button
                          key={s.name}
                          type="button"
                          onClick={() =>
                            setSelected((prev) => {
                              const next = new Set(prev);
                              if (on) next.delete(s.name);
                              else next.add(s.name);
                              return next;
                            })
                          }
                          className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${
                            on
                              ? "border-success/50 bg-success/10 text-success"
                              : "text-muted-foreground hover:bg-accent"
                          }`}
                        >
                          {s.name}
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

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
                  className="h-8"
                  onClick={createLink}
                  disabled={
                    linking || !exported || (servers.length > 0 && selected.size === 0)
                  }
                >
                  {linking ? (
                    <>
                      <Loader2 className="size-3.5 animate-spin" /> Creating link…
                    </>
                  ) : (
                    <>
                      <Link2 className="size-3.5" /> Create share link
                    </>
                  )}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8"
                  onClick={copy}
                  disabled={!exported || (servers.length > 0 && selected.size === 0)}
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
                  disabled={!exported || (servers.length > 0 && selected.size === 0)}
                >
                  <FileDown className="size-3.5" /> Save to file
                </Button>
              </div>
              {shareLink && (
                <div className="flex items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5">
                  <Link2 className="size-3.5 shrink-0 text-success" />
                  <code className="min-w-0 flex-1 truncate text-xs">{shareLink}</code>
                  <button
                    type="button"
                    title="Copy link"
                    onClick={() => {
                      navigator.clipboard.writeText(shareLink).catch(() => {});
                    }}
                    className="shrink-0 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                  >
                    <Copy className="size-3.5" />
                  </button>
                </div>
              )}
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
  const privateHost = isPrivateHostUrl(item.url);
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
      {privateHost && (
        <p className="mt-1.5 flex items-center gap-1.5 text-xs text-warning">
          <ShieldAlert className="size-3.5 shrink-0" />
          Connects to a private or internal address. Only import setups you trust.
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

/** True if the URL targets a loopback, private-network, or cloud-metadata host -
 * a server that would read from inside your own machine or LAN. Mirrors the
 * backend host-privacy guard so an imported setup pointing inward is flagged. */
function isPrivateHostUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1") return true; // IPv6 loopback
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 127 || a === 10 || a === 0) return true; // loopback, private, this-host
    if (a === 192 && b === 168) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
  }
  return false;
}

/** A filesystem-safe slug for the default filename. */
function slug(s: string): string {
  return s
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
