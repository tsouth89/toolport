import { useCallback, useEffect, useMemo, useState } from "react";
import { Check, ExternalLink, Loader2, Plus, Search, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { toastError } from "@/lib/toast";
import { openUrl } from "@tauri-apps/plugin-opener";
import { addServer, listStacks, popularCatalog, searchCatalog } from "@/lib/api";
import type { CatalogEntry, Registry, ServerEntry, Stack } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { TransportPill } from "@/components/TransportPill";
import { ServerDialog } from "@/components/ServerDialog";

/** Section order for the browse view; categories not listed fall to the end. */
const CATEGORY_ORDER = [
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
  const [popularLoading, setPopularLoading] = useState(true);
  const [popularError, setPopularError] = useState(false);
  // A failed live search is distinct from a genuinely empty result: without this a
  // network/registry failure would render as an innocent "no results for …".
  const [searchError, setSearchError] = useState(false);
  const [searchNonce, setSearchNonce] = useState(0);
  const [stacks, setStacks] = useState<Stack[]>([]);
  const [stackBusy, setStackBusy] = useState<string | null>(null);
  const [configEntry, setConfigEntry] = useState<CatalogEntry | null>(null);

  const have = new Set((registry?.servers ?? []).map((s) => s.name.toLowerCase()));

  useEffect(() => {
    listStacks()
      .then(setStacks)
      .catch(() => {});
  }, []);

  const reloadPopular = useCallback(() => {
    setPopularLoading(true);
    setPopularError(false);
    popularCatalog()
      .then(setPopular)
      .catch(() => setPopularError(true))
      .finally(() => setPopularLoading(false));
  }, []);

  useEffect(() => {
    reloadPopular();
  }, [reloadPopular]);

  // Live search as you type: debounce, and ignore stale responses so a slow
  // earlier query can't overwrite a newer one.
  useEffect(() => {
    const q = query.trim();
    if (!q) {
      setResults(null);
      setSearchError(false);
      setLoading(false);
      return;
    }
    setLoading(true);
    setSearchError(false);
    let cancelled = false;
    const t = setTimeout(() => {
      searchCatalog(q)
        .then((r) => {
          if (!cancelled) setResults(r);
        })
        .catch(() => {
          // Distinguish a failed search from an empty one so we can offer a retry
          // instead of implying the registry has nothing for this query.
          if (!cancelled) {
            setResults([]);
            setSearchError(true);
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }, 300);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [query, searchNonce]);

  /** Returns true if the entry needs the ServerDialog (has credentials, a
   * user-supplied URL, or args the user should review). False = safe to
   * immediate-add with no configuration. */
  function needsConfig(entry: CatalogEntry): boolean {
    return entry.urlHint != null || entry.envKeys.length > 0 || entry.args.length > 0;
  }

  async function add(entry: CatalogEntry) {
    // Self-hosted servers or entries with credentials/args: open the dialog
    // so the user can enter their URL, paste API keys, or adjust args before
    // the server is created.
    if (needsConfig(entry)) {
      setConfigEntry(entry);
      return;
    }
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
      toastError(`Couldn't add ${entry.name}: ${e}`);
    } finally {
      setBusy(null);
    }
  }

  /** Add every server in a stack that isn't already in Toolport, then point the
   * user at the credential steps for the ones that need them. */
  async function setupStack(stack: Stack) {
    setStackBusy(stack.id);
    const existing = new Set((registry?.servers ?? []).map((s) => s.name.toLowerCase()));
    let added = 0;
    let needCreds = 0;
    try {
      for (const entry of stack.servers) {
        if (existing.has(entry.name.toLowerCase())) continue;
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
        added++;
        if (entry.credentialsUrl || entry.envKeys.length > 0) needCreds++;
      }
      if (added === 0) {
        toast.success(`${stack.name}: every server is already in Toolport`);
      } else {
        toast.success(
          `Added ${added} server${added === 1 ? "" : "s"} from ${stack.name}`,
          {
            description:
              needCreds > 0
                ? `${needCreds} need credentials. Open "Setup steps" for the links.`
                : "Enable them under Servers.",
          },
        );
      }
    } catch (e) {
      toastError(`Couldn't finish setting up ${stack.name}: ${e}`);
    } finally {
      setStackBusy(null);
    }
  }

  const shown = results ?? popular;
  const browsing = results === null;

  // Browse view: group the popular picks into category sections. Search results
  // stay flat (they're query-driven, including the long-tail registry).
  const byCategory = useMemo(() => {
    const groups = new Map<string, CatalogEntry[]>();
    for (const e of popular) {
      const cat = e.category || "Other";
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
        browsing && popularLoading ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-28 rounded-lg" />
            ))}
          </div>
        ) : browsing && popularError ? (
          <div
            role="status"
            aria-live="polite"
            className="flex flex-col items-center gap-3 py-20 text-center"
          >
            <div>
              <p className="font-medium">Catalog could not load</p>
              <p className="max-w-md text-sm text-muted-foreground">
                Toolport could not load the curated picks. Try again in a moment.
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={reloadPopular}>
              Try again
            </Button>
          </div>
        ) : !browsing && searchError ? (
          <div
            role="status"
            aria-live="polite"
            className="flex flex-col items-center gap-3 py-20 text-center"
          >
            <div>
              <p className="font-medium">Search failed</p>
              <p className="max-w-md text-sm text-muted-foreground">
                Toolport couldn't reach the MCP Registry. Check your connection, then
                retry.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSearchNonce((n) => n + 1)}
            >
              Try again
            </Button>
          </div>
        ) : (
          !loading && (
            <div
              role="status"
              aria-live="polite"
              className="flex flex-col items-center gap-1 py-20 text-center"
            >
              <p className="font-medium">
                {results !== null
                  ? `No catalog results for "${query}"`
                  : "No popular servers available"}
              </p>
              <p className="max-w-md text-sm text-muted-foreground">
                {results !== null
                  ? "Try a provider name, app name, or shorter query. You can also clear the search to browse popular servers."
                  : "Use search to query the MCP Registry, or try again later if the browse list stays empty."}
              </p>
            </div>
          )
        )
      ) : browsing ? (
        <div className="flex flex-col gap-6">
          {stacks.length > 0 && (
            <StacksSection
              stacks={stacks}
              haveNames={have}
              busyId={stackBusy}
              onSetup={setupStack}
            />
          )}
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
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{shown.map(card)}</div>
      )}
      {configEntry && (
        <ServerDialog
          onSaved={(reg) => {
            onAdded(reg);
            setConfigEntry(null);
          }}
          onClose={() => setConfigEntry(null)}
          initial={{
            id: "",
            name: configEntry.name,
            transport: configEntry.transport,
            command: configEntry.command,
            args: configEntry.args,
            env: configEntry.envKeys.map((key) => ({
              key,
              value: null,
              secret: true,
            })),
            url: configEntry.url,
            source: `catalog:${configEntry.source}`,
          }}
          existingNames={(registry?.servers ?? []).map((s) => s.name)}
          autoOpen
          urlHint={configEntry.urlHint ?? undefined}
          trigger={<span className="hidden" />}
        />
      )}
    </div>
  );
}

/** "Quick start" stacks: role-based bundles you can add in one click, with the
 * credential steps spelled out per server. */
function StacksSection({
  stacks,
  haveNames,
  busyId,
  onSetup,
}: {
  stacks: Stack[];
  haveNames: Set<string>;
  busyId: string | null;
  onSetup: (s: Stack) => void;
}) {
  return (
    <section>
      <h2 className="mb-2 flex items-center gap-2 text-xs font-medium tracking-wide text-muted-foreground uppercase">
        Stacks
        <span className="font-normal text-muted-foreground/60 normal-case">
          one-click bundles for a use case
        </span>
      </h2>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {stacks.map((s) => (
          <StackCard
            key={s.id}
            stack={s}
            haveNames={haveNames}
            busy={busyId === s.id}
            onSetup={() => onSetup(s)}
          />
        ))}
      </div>
    </section>
  );
}

function StackCard({
  stack,
  haveNames,
  busy,
  onSetup,
}: {
  stack: Stack;
  haveNames: Set<string>;
  busy: boolean;
  onSetup: () => void;
}) {
  const [open, setOpen] = useState(false);
  const missing = stack.servers.filter((e) => !haveNames.has(e.name.toLowerCase()));
  const allAdded = missing.length === 0;
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-ring/20 bg-muted/20 p-3">
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-medium">{stack.name}</span>
        <span className="shrink-0 text-[11px] text-muted-foreground">
          {stack.servers.length} servers
        </span>
      </div>
      <p className="min-h-8 text-xs text-muted-foreground">{stack.description}</p>
      <div className="flex flex-wrap gap-1">
        {stack.servers.map((e) => (
          <span
            key={e.name}
            className={`rounded px-1.5 py-0.5 text-[11px] ${
              haveNames.has(e.name.toLowerCase())
                ? "bg-success/10 text-success"
                : "bg-muted text-muted-foreground"
            }`}
          >
            {e.name}
          </span>
        ))}
      </div>
      <div className="mt-auto flex items-center justify-between gap-2 pt-1">
        <button
          onClick={() => setOpen((o) => !o)}
          className="text-[11px] text-muted-foreground hover:text-foreground"
        >
          {open ? "Hide setup steps" : "Setup steps"}
        </button>
        {allAdded ? (
          <span className="inline-flex items-center gap-1 text-xs text-success">
            <Check className="size-3" />
            all added
          </span>
        ) : (
          <Button
            size="sm"
            variant="outline"
            className="h-7 px-2 text-xs"
            disabled={busy}
            onClick={onSetup}
          >
            {busy ? (
              <Loader2 className="size-3 animate-spin" />
            ) : (
              <Plus className="size-3" />
            )}
            Add {missing.length}
          </Button>
        )}
      </div>
      {open && (
        <div className="mt-1 flex flex-col gap-1.5 border-t pt-2">
          {stack.servers.map((e) => (
            <div key={e.name} className="text-[11px] leading-snug">
              <span className="font-medium text-foreground">{e.name}</span>
              {e.setupHint && (
                <span className="text-muted-foreground">: {e.setupHint}</span>
              )}
              {e.credentialsUrl && (
                <button
                  onClick={() => openUrl(e.credentialsUrl!)}
                  className="ml-1 inline-flex items-center gap-0.5 text-info hover:underline"
                >
                  get credential
                  <ExternalLink className="size-2.5" />
                </button>
              )}
            </div>
          ))}
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
      ? { label: "Toolport verified", cls: "text-success" }
      : entry.source === "registry"
        ? { label: "MCP Registry", cls: "text-info" }
        : { label: "Your pick", cls: "text-owned" };
  return (
    <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
      <ShieldCheck className={`size-3 shrink-0 ${tier.cls}`} />
      <span className={tier.cls}>{tier.label}</span>
      {entry.publisher && (
        <span className="truncate text-muted-foreground">· {entry.publisher}</span>
      )}
    </div>
  );
}

function CatalogCard({
  entry,
  added,
  busy,
  onAdd,
}: {
  entry: CatalogEntry;
  added: boolean;
  busy: boolean;
  onAdd: () => void;
}) {
  const target = entry.command
    ? [entry.command, ...entry.args].join(" ")
    : (entry.url ?? "");
  return (
    <div className="flex flex-col gap-2 rounded-lg border p-3 transition-colors hover:border-ring/40">
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="truncate text-sm font-medium">{entry.name}</span>
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
          <TransportPill transport={entry.transport} />
        </div>
      </div>
      <p className="line-clamp-2 min-h-8 text-xs text-muted-foreground">
        {entry.description}
      </p>
      <code title={target} className="truncate font-mono text-2xs text-muted-foreground">
        {target}
      </code>
      <Provenance entry={entry} />
      <div className="mt-auto flex justify-end pt-1">
        {added ? (
          <span className="inline-flex items-center gap-1 text-xs text-success">
            <Check className="size-3" />
            in Toolport
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
