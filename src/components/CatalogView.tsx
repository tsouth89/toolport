import { useCallback, useEffect, useMemo, useState } from "react";
import { Check, ExternalLink, Loader2, Plus, Search, ShieldCheck, X } from "lucide-react";
import { toast } from "sonner";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  addServer,
  popularCatalog,
  searchCatalog,
  unpromoteFromCatalog,
} from "@/lib/api";
import type { CatalogEntry, Registry, ServerEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TransportPill } from "@/components/TransportPill";

/** Section order for the browse view; categories not listed fall to the end. */
const CATEGORY_ORDER = [
  "Your picks",
  "Code & infrastructure",
  "Databases",
  "Search & knowledge",
  "Web & automation",
  "Apps & productivity",
  "Local tools",
];

interface Props {
  registry: Registry | null;
  onAdded: (registry: Registry) => void;
}

export function CatalogView({ registry, onAdded }: Props) {
  const [query, setQuery] = useState("");
  const [popular, setPopular] = useState<CatalogEntry[]>([]);
  const [results, setResults] = useState<CatalogEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  const have = new Set((registry?.servers ?? []).map((s) => s.name.toLowerCase()));

  const reloadPopular = useCallback(() => {
    popularCatalog()
      .then(setPopular)
      .catch(() => {});
  }, []);

  useEffect(() => {
    reloadPopular();
  }, [reloadPopular]);

  async function removeFromCatalog(entry: CatalogEntry) {
    try {
      await unpromoteFromCatalog(entry.name);
      setResults((r) => r?.filter((e) => e.name !== entry.name) ?? null);
      reloadPopular();
      toast.success(`Removed ${entry.name} from your catalog`);
    } catch (e) {
      toast.error(`Couldn't remove ${entry.name}: ${e}`);
    }
  }

  // Live search as you type: debounce, and ignore stale responses so a slow
  // earlier query can't overwrite a newer one.
  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setResults(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    let cancelled = false;
    const t = setTimeout(() => {
      searchCatalog(q)
        .then((r) => {
          if (!cancelled) setResults(r);
        })
        .catch(() => {
          if (!cancelled) setResults([]);
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [query]);

  async function add(entry: CatalogEntry) {
    setBusy(entry.name);
    try {
      const server: ServerEntry = {
        id: "",
        name: entry.name,
        transport: entry.transport,
        command: entry.command,
        args: entry.args,
        env: entry.envKeys.map((key) => ({ key, value: null, secret: true })),
        url: entry.url,
        source: `catalog:${entry.source}`,
      };
      onAdded(await addServer(server));
      toast.success(`Added ${entry.name}`, {
        description: "Enable it, then authenticate if it needs credentials.",
      });
    } catch (e) {
      toast.error(`Couldn't add ${entry.name}: ${e}`);
    } finally {
      setBusy(null);
    }
  }

  const shown = results ?? popular;
  const browsing = results === null;

  // Browse view: group the popular picks into category sections. Search results
  // stay flat (they're query-driven, including the long-tail registry).
  const byCategory = useMemo(() => {
    const groups = new Map<string, CatalogEntry[]>();
    for (const e of popular) {
      const cat = e.source === "user" ? "Your picks" : e.category || "Other";
      const arr = groups.get(cat);
      if (arr) arr.push(e);
      else groups.set(cat, [e]);
    }
    const ord = (c: string) => {
      const i = CATEGORY_ORDER.indexOf(c);
      return i === -1 ? 999 : i;
    };
    return [...groups.entries()].sort((a, b) => ord(a[0]) - ord(b[0]));
  }, [popular]);

  const card = (entry: CatalogEntry) => (
    <CatalogCard
      key={`${entry.source}:${entry.name}`}
      entry={entry}
      added={have.has(entry.name.toLowerCase())}
      busy={busy === entry.name}
      onAdd={() => add(entry)}
      onRemove={
        entry.source === "user" ? () => removeFromCatalog(entry) : undefined
      }
    />
  );

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-4">
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        {loading && (
          <Loader2 className="absolute top-1/2 right-3 size-4 -translate-y-1/2 animate-spin text-muted-foreground" />
        )}
        <Input
          autoFocus
          value={query}
          placeholder="Search the MCP Registry (e.g. github, postgres, figma, slack)…"
          className="h-11 pl-9 text-base"
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {results !== null
            ? `${shown.length} result${shown.length === 1 ? "" : "s"} (popular picks first, then the MCP Registry)`
            : "Popular servers"}
        </span>
        {results !== null && (
          <button className="hover:text-foreground" onClick={() => setQuery("")}>
            Clear search
          </button>
        )}
      </div>

      {shown.length === 0 ? (
        <p className="py-20 text-center text-sm text-muted-foreground">
          {loading
            ? ""
            : results !== null
              ? `No servers match "${query}".`
              : "Catalog unavailable."}
        </p>
      ) : browsing ? (
        <div className="flex flex-col gap-6">
          {byCategory.map(([cat, entries]) => (
            <section key={cat}>
              <h2 className="mb-2 flex items-center gap-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                {cat}
                <span className="text-muted-foreground/60">{entries.length}</span>
              </h2>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {entries.map(card)}
              </div>
            </section>
          ))}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {shown.map(card)}
        </div>
      )}
    </div>
  );
}

/** Source-tier + publisher signal. Honest provenance: where the entry came
 * from and who published it, not a cryptographic attestation. */
function Provenance({ entry }: { entry: CatalogEntry }) {
  const tier =
    entry.source === "curated"
      ? { label: "Conduit verified", cls: "text-emerald-400" }
      : entry.source === "registry"
        ? { label: "MCP Registry", cls: "text-violet-300" }
        : { label: "Your pick", cls: "text-sky-400" };
  return (
    <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
      <ShieldCheck className={`size-3 shrink-0 ${tier.cls}`} />
      <span className={tier.cls}>{tier.label}</span>
      {entry.publisher && (
        <span className="truncate text-muted-foreground/70">
          · {entry.publisher}
        </span>
      )}
    </div>
  );
}

function CatalogCard({
  entry,
  added,
  busy,
  onAdd,
  onRemove,
}: {
  entry: CatalogEntry;
  added: boolean;
  busy: boolean;
  onAdd: () => void;
  onRemove?: () => void;
}) {
  const target = entry.command
    ? [entry.command, ...entry.args].join(" ")
    : (entry.url ?? "");
  return (
    <div className="flex flex-col gap-2 rounded-lg border p-3 transition-colors hover:border-ring/40">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="truncate text-sm font-medium">{entry.name}</span>
          {entry.source === "user" && (
            <span className="shrink-0 rounded-full bg-sky-400/10 px-1.5 py-0.5 text-[10px] font-medium text-sky-400">
              yours
            </span>
          )}
          {entry.homepage && (
            <button
              onClick={() => openUrl(entry.homepage!)}
              aria-label="Open docs"
              className="shrink-0 text-muted-foreground/60 hover:text-foreground"
            >
              <ExternalLink className="size-3" />
            </button>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {onRemove && (
            <button
              onClick={onRemove}
              aria-label="Remove from your catalog"
              title="Remove from your catalog"
              className="rounded p-0.5 text-muted-foreground/50 hover:bg-destructive/10 hover:text-destructive"
            >
              <X className="size-3.5" />
            </button>
          )}
          <TransportPill transport={entry.transport} />
        </div>
      </div>
      <p className="line-clamp-2 min-h-8 text-xs text-muted-foreground">
        {entry.description}
      </p>
      <code className="truncate font-mono text-[11px] text-muted-foreground/70">
        {target}
      </code>
      <Provenance entry={entry} />
      <div className="mt-auto flex justify-end pt-1">
        {added ? (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
            <Check className="size-3" />
            in Conduit
          </span>
        ) : (
          <Button
            size="sm"
            variant="outline"
            className="h-7 px-2 text-xs"
            disabled={busy}
            onClick={onAdd}
          >
            <Plus className="size-3" />
            Add
          </Button>
        )}
      </div>
    </div>
  );
}
