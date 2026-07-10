import { useState } from "react";
import { Check, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TransportPill } from "@/components/TransportPill";
import type { ImportItem } from "@/lib/types";

interface Props {
  open: boolean;
  items: ImportItem[];
  busy?: boolean;
  title?: string;
  onOpenChange: (open: boolean) => void;
  onConfirm: (keys: string[]) => void;
}

/** Review and choose detected client servers before adding them to Toolport. */
export function ImportReviewDialog({
  open,
  items,
  busy = false,
  title = "Review servers to import",
  onOpenChange,
  onConfirm,
}: Props) {
  if (!open) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <ImportReviewContent
          items={items}
          busy={busy}
          title={title}
          onOpenChange={onOpenChange}
          onConfirm={onConfirm}
        />
      </DialogContent>
    </Dialog>
  );
}

function ImportReviewContent({
  items,
  busy = false,
  title = "Review servers to import",
  onOpenChange,
  onConfirm,
}: Omit<Props, "open">) {
  const keyedItems = items.map((item, index) => ({
    item,
    key: item.key ?? `${item.name}-${index}`,
  }));
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(keyedItems.map(({ key }) => key)),
  );

  const selectedCount = selected.size;
  return (
    <>
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
      </DialogHeader>
      <div className="flex flex-col gap-4 py-1">
        <p className="text-xs text-muted-foreground">
          Review the commands and URLs before adding them. You can leave any server
          unchecked and import only the ones you want.
        </p>
        <div className="flex max-h-72 flex-col gap-2 overflow-y-auto">
          {keyedItems.map(({ item, key }) => {
            const isSelected = selected.has(key);
            return (
              <button
                key={key}
                type="button"
                className={`rounded-md text-left transition-colors ${
                  isSelected ? "ring-1 ring-success/60" : "opacity-60"
                }`}
                onClick={() =>
                  setSelected((previous) => {
                    const next = new Set(previous);
                    if (isSelected) next.delete(key);
                    else next.add(key);
                    return next;
                  })
                }
              >
                <ImportRow item={item} selected={isSelected} />
              </button>
            );
          })}
        </div>
        <div className="flex items-center justify-between gap-2 border-t pt-3">
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button
            onClick={() => onConfirm(Array.from(selected))}
            disabled={busy || selectedCount === 0}
          >
            <Check className="size-4" />
            {selectedCount === 0
              ? "Select a server"
              : `Import ${selectedCount} server${selectedCount === 1 ? "" : "s"}`}
          </Button>
        </div>
      </div>
    </>
  );
}

/** One reviewable server: name, what it runs, and the relevant safety flags. */
export function ImportRow({ item, selected }: { item: ImportItem; selected?: boolean }) {
  const runs =
    item.command != null ? [item.command, ...item.args].join(" ") : (item.url ?? "");
  const shell = runsShell(item.command);
  const privateHost = isPrivateHostUrl(item.url);
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="flex items-center gap-2">
        {selected !== undefined && (
          <span
            aria-hidden="true"
            className={`size-3 rounded-sm border ${
              selected ? "border-success bg-success" : "border-muted-foreground"
            }`}
          />
        )}
        <span className="truncate text-sm font-medium">{item.name}</span>
        <TransportPill transport={item.transport} />
        {!item.isNew && (
          <span className="ml-auto shrink-0 text-xs text-muted-foreground">
            already added
          </span>
        )}
      </div>
      {runs && (
        <p className="mt-1 font-mono text-xs break-all text-muted-foreground">{runs}</p>
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

function isPrivateHostUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
  if (!match) return false;
  const first = Number(match[1]);
  const second = Number(match[2]);
  return (
    first === 127 ||
    first === 10 ||
    first === 0 ||
    (first === 192 && second === 168) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 169 && second === 254)
  );
}
