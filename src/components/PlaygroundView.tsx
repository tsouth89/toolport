import { useEffect, useMemo, useState } from "react";
import {
  Check,
  CheckCircle2,
  ChevronRight,
  Copy,
  FileText,
  FlaskConical,
  Loader2,
  MessageSquare,
  Pencil,
  Pin,
  Play,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { toastError } from "@/lib/toast";
import {
  callTool,
  clearToolOverride,
  getPrompt,
  listServerPrompts,
  listServerResources,
  listServerTools,
  readResource,
  setToolEnabled,
  setToolPinned,
  setToolOverride,
} from "@/lib/api";
import type {
  JsonSchemaProp,
  McpPrompt,
  McpResource,
  McpTool,
  Registry,
  ToolCallResult,
} from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Callout } from "@/components/Callout";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/** A tool is destructive if it carries the MCP `destructiveHint` annotation. */
function isDestructive(tool: McpTool): boolean {
  return tool.annotations?.destructiveHint === true || tool.destructiveHint === true;
}

/** Editor to rename / re-describe a tool as clients see it (the security lever: locally
 * neutralize a misleading or injection-laden description). Collapsed by default; the call
 * still routes to the original downstream tool. Overrides are keyed by (server, original
 * tool name), so they're stable across renames and collision suffixes. */
function ToolOverrideEditor({
  serverId,
  tool,
  registry,
  onRegistryChange,
}: {
  serverId: string;
  tool: McpTool;
  registry: Registry | null;
  onRegistryChange: (r: Registry) => void;
}) {
  const current = registry?.toolOverrides?.[serverId]?.[tool.name];
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  // Re-sync the fields (and collapse) whenever the selected tool changes.
  useEffect(() => {
    setName(current?.name ?? "");
    setDescription(current?.description ?? "");
    setOpen(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverId, tool.name]);

  const hasOverride = !!current;

  const save = async () => {
    setBusy(true);
    try {
      onRegistryChange(
        await setToolOverride(serverId, tool.name, name || null, description || null),
      );
    } catch (e) {
      toastError(`Couldn't save override: ${e}`);
    } finally {
      setBusy(false);
    }
  };
  const reset = async () => {
    setBusy(true);
    try {
      onRegistryChange(await clearToolOverride(serverId, tool.name));
      setName("");
      setDescription("");
    } catch (e) {
      toastError(`Couldn't clear override: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-md border border-border/60 bg-muted/20">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 py-2 text-xs text-muted-foreground"
      >
        <Pencil className="size-3.5 shrink-0" />
        <span className="font-medium text-foreground/80">
          Override how clients see this tool
        </span>
        {hasOverride && (
          <span className="rounded-full bg-info/15 px-1.5 py-0.5 text-[10px] font-medium text-info">
            active
          </span>
        )}
        <ChevronRight
          className={`ml-auto size-3.5 transition-transform ${open ? "rotate-90" : ""}`}
        />
      </button>
      {open && (
        <div className="flex flex-col gap-2.5 border-t border-border/60 px-3 py-3">
          <p className="text-xs text-muted-foreground">
            Rename the tool or replace its description as every client sees it, e.g. to
            neutralize a misleading or injection-laden description. The call still runs
            the original server tool.
          </p>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">
              Name{" "}
              <span className="text-muted-foreground/60">
                (blank keeps <span className="font-mono">{tool.name}</span>)
              </span>
            </span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={tool.name}
              className="rounded-md border border-input bg-transparent px-2.5 py-1.5 font-mono text-xs shadow-sm focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">
              Description (blank keeps the server's)
            </span>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              placeholder={tool.description ?? "(server's description)"}
              className="rounded-md border border-input bg-transparent px-2.5 py-1.5 text-xs shadow-sm focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
            />
          </label>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void save()} disabled={busy}>
              Save override
            </Button>
            {hasOverride && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => void reset()}
                disabled={busy}
              >
                Reset to original
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/** First declared type of a JSON-schema property (schemas may list several). */
function primaryType(schema: JsonSchemaProp): string {
  return Array.isArray(schema.type)
    ? (schema.type[0] ?? "string")
    : (schema.type ?? "string");
}

/** Turn a form field's raw value into the JSON type the schema expects. */
function coerce(v: unknown, schema: JsonSchemaProp): unknown {
  if (typeof v !== "string") return v; // booleans arrive already typed
  const t = primaryType(schema);
  if (t === "number" || t === "integer") {
    const n = Number(v);
    return Number.isNaN(n) ? v : n;
  }
  if (t === "boolean") return v === "true";
  if (t === "object" || t === "array") {
    try {
      return JSON.parse(v);
    } catch {
      return v; // let the server reject it rather than swallowing the input
    }
  }
  return v;
}

/** Render the result content blocks as readable text. */
function renderResult(result: ToolCallResult): string {
  const blocks = result.content ?? [];
  if (blocks.length === 0) return JSON.stringify(result, null, 2);
  return blocks
    .map((b) =>
      b.type === "text" && b.text != null ? b.text : JSON.stringify(b, null, 2),
    )
    .join("\n");
}

interface FieldProps {
  name: string;
  schema: JsonSchemaProp;
  required: boolean;
  value: unknown;
  onChange: (v: unknown) => void;
}

/** One argument input, shaped by the property's JSON-schema type. */
function ArgField({ name, schema, required, value, onChange }: FieldProps) {
  const t = primaryType(schema);
  const id = `arg-${name}`;
  const enumVals = schema.enum;

  let control;
  if (enumVals && enumVals.length > 0) {
    control = (
      <Select value={value === undefined ? "" : String(value)} onValueChange={onChange}>
        <SelectTrigger id={id} className="h-9">
          <SelectValue placeholder="Select…" />
        </SelectTrigger>
        <SelectContent>
          {enumVals.map((e) => (
            <SelectItem key={String(e)} value={String(e)}>
              {String(e)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    );
  } else if (t === "boolean") {
    control = (
      <Switch
        id={id}
        checked={value === true || value === "true"}
        onCheckedChange={(c) => onChange(c)}
      />
    );
  } else if (t === "object" || t === "array") {
    control = (
      <Textarea
        id={id}
        value={typeof value === "string" ? value : ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={t === "array" ? "[ … ]" : "{ … }"}
        rows={3}
        className="font-mono text-xs"
      />
    );
  } else {
    control = (
      <Input
        id={id}
        type={t === "number" || t === "integer" ? "number" : "text"}
        value={value === undefined ? "" : String(value)}
        onChange={(e) => onChange(e.target.value)}
        placeholder={schema.default != null ? `default: ${String(schema.default)}` : ""}
        className="h-9"
      />
    );
  }

  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id} className="flex items-center gap-1.5">
        <span className="font-mono text-xs">{name}</span>
        {required && <span className="text-destructive">*</span>}
        <span className="text-xs font-normal text-muted-foreground">{t}</span>
      </Label>
      {schema.description && (
        <p className="text-xs text-muted-foreground">{schema.description}</p>
      )}
      {control}
    </div>
  );
}

/** Inline "connecting…" line shared by the resource/prompt panels. */
function Connecting({ label = "Connecting to server…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  );
}

/** Copy-to-clipboard button with a brief confirmation, for raw result / JSON blocks. */
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label="Copy to clipboard"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard unavailable; no-op */
        }
      }}
      className="ml-auto inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-2xs font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
    >
      {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/** A raw MCP result rendered as pretty JSON (or text), with a copy button. */
function ResultBlock({ title, value }: { title: string; value: unknown }) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        <div className="text-sm font-medium">{title}</div>
        <CopyButton text={text} />
      </div>
      <pre className="max-h-96 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap">
        {text}
      </pre>
    </div>
  );
}

/** Resources tab: list what the server advertises and read one on click. */
function ResourcesPanel({ serverId }: { serverId: string }) {
  const [resources, setResources] = useState<McpResource[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [readError, setReadError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    setResources(null);
    setSelected(null);
    setResult(null);
    setReadError(null);
    listServerResources(serverId)
      .then((r) => alive && setResources(r))
      .catch((e) => alive && setError(String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [serverId]);

  async function read(uri: string) {
    setSelected(uri);
    setReading(true);
    setResult(null);
    setReadError(null);
    try {
      setResult(await readResource(serverId, uri));
    } catch (e) {
      setReadError(String(e));
    } finally {
      setReading(false);
    }
  }

  if (loading) return <Connecting />;
  if (error) return <Callout variant="danger">{error}</Callout>;
  if (!resources || resources.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        This server advertises no resources.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label className="text-xs text-muted-foreground">
          Resources ({resources.length})
        </Label>
        <div className="flex flex-col divide-y rounded-lg border">
          {resources.map((r) => (
            <button
              key={r.uri}
              onClick={() => read(r.uri)}
              aria-pressed={selected === r.uri}
              className={`flex flex-col items-start gap-0.5 px-3 py-2 text-left ${
                selected === r.uri ? "bg-accent" : "hover:bg-muted/40"
              }`}
            >
              <span className="flex min-w-0 items-center gap-2">
                <span className="truncate font-mono text-sm">
                  {r.name ?? r.title ?? r.uri}
                </span>
                {r.mimeType && (
                  <Badge variant="outline" className="text-muted-foreground">
                    {r.mimeType}
                  </Badge>
                )}
              </span>
              <span className="truncate font-mono text-[11px] text-muted-foreground">
                {r.uri}
              </span>
              {r.description && (
                <span className="line-clamp-1 text-xs text-muted-foreground">
                  {r.description}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
      {reading && <Connecting label="Reading resource…" />}
      {readError && <Callout variant="danger">{readError}</Callout>}
      {result != null && <ResultBlock title="Resource contents" value={result} />}
    </div>
  );
}

/** Prompts tab: list prompts, fill any arguments, and render one. */
function PromptsPanel({ serverId }: { serverId: string }) {
  const [prompts, setPrompts] = useState<McpPrompt[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [args, setArgs] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [runError, setRunError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    setPrompts(null);
    setSelected(null);
    setResult(null);
    setRunError(null);
    listServerPrompts(serverId)
      .then((p) => alive && setPrompts(p))
      .catch((e) => alive && setError(String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [serverId]);

  const prompt = prompts?.find((p) => p.name === selected) ?? null;

  useEffect(() => {
    setArgs({});
    setResult(null);
    setRunError(null);
  }, [selected]);

  async function run() {
    if (!prompt) return;
    const missing = (prompt.arguments ?? [])
      .filter((a) => a.required && !args[a.name]?.trim())
      .map((a) => a.name);
    if (missing.length > 0) {
      setRunError(
        `Fill in required argument${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}`,
      );
      return;
    }
    setRunning(true);
    setResult(null);
    setRunError(null);
    try {
      setResult(await getPrompt(serverId, prompt.name, args));
    } catch (e) {
      setRunError(String(e));
    } finally {
      setRunning(false);
    }
  }

  if (loading) return <Connecting />;
  if (error) return <Callout variant="danger">{error}</Callout>;
  if (!prompts || prompts.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">This server advertises no prompts.</p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label className="text-xs text-muted-foreground">
          Prompts ({prompts.length})
        </Label>
        <div className="flex flex-col divide-y rounded-lg border">
          {prompts.map((p) => (
            <button
              key={p.name}
              onClick={() => setSelected(p.name)}
              aria-pressed={p.name === selected}
              className={`flex flex-col items-start gap-0.5 px-3 py-2 text-left ${
                p.name === selected ? "bg-accent" : "hover:bg-muted/40"
              }`}
            >
              <span className="truncate font-mono text-sm">{p.title ?? p.name}</span>
              {p.description && (
                <span className="line-clamp-1 text-xs text-muted-foreground">
                  {p.description}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {prompt && (
        <div className="flex flex-col gap-4 rounded-lg border bg-card p-4">
          {prompt.description && (
            <p className="text-sm text-muted-foreground">{prompt.description}</p>
          )}
          {(prompt.arguments ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">
              This prompt takes no arguments.
            </p>
          ) : (
            <div className="flex flex-col gap-4">
              {(prompt.arguments ?? []).map((a) => (
                <div key={a.name} className="flex flex-col gap-1.5">
                  <Label
                    htmlFor={`prompt-arg-${a.name}`}
                    className="flex items-center gap-1.5"
                  >
                    <span className="font-mono text-xs">{a.name}</span>
                    {a.required && <span className="text-destructive">*</span>}
                  </Label>
                  {a.description && (
                    <p className="text-xs text-muted-foreground">{a.description}</p>
                  )}
                  <Input
                    id={`prompt-arg-${a.name}`}
                    value={args[a.name] ?? ""}
                    onChange={(e) =>
                      setArgs((prev) => ({ ...prev, [a.name]: e.target.value }))
                    }
                    className="h-9"
                  />
                </div>
              ))}
            </div>
          )}
          <div>
            <Button onClick={run} disabled={running} size="sm">
              {running ? (
                <Loader2 className="size-4 animate-spin" />
              ) : (
                <Play className="size-4" />
              )}
              {running ? "Getting…" : "Get prompt"}
            </Button>
          </div>
        </div>
      )}

      {runError && <Callout variant="danger">{runError}</Callout>}
      {result != null && <ResultBlock title="Prompt messages" value={result} />}
    </div>
  );
}

interface PlaygroundProps {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}

export function PlaygroundView({ registry, onRegistryChange }: PlaygroundProps) {
  const servers = registry?.servers ?? [];
  const denyDestructive = registry?.denyDestructive ?? false;

  const [serverId, setServerId] = useState<string | null>(null);
  const [tab, setTab] = useState<"tools" | "resources" | "prompts">("tools");
  const [policyBusy, setPolicyBusy] = useState(false);
  const [tools, setTools] = useState<McpTool[] | null>(null);
  const [loadingTools, setLoadingTools] = useState(false);
  const [toolsError, setToolsError] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<string | null>(null);

  const [args, setArgs] = useState<Record<string, unknown>>({});
  const [rawMode, setRawMode] = useState(false);
  const [rawJson, setRawJson] = useState("{}");

  const [calling, setCalling] = useState(false);
  const [result, setResult] = useState<ToolCallResult | null>(null);
  const [callError, setCallError] = useState<string | null>(null);

  // Connect to the chosen server and pull its tool list.
  useEffect(() => {
    if (!serverId) {
      setTools(null);
      return;
    }
    let alive = true;
    setLoadingTools(true);
    setToolsError(null);
    setTools(null);
    setSelectedTool(null);
    setResult(null);
    setCallError(null);
    listServerTools(serverId)
      .then((t) => alive && setTools(t))
      .catch((e) => alive && setToolsError(String(e)))
      .finally(() => alive && setLoadingTools(false));
    return () => {
      alive = false;
    };
  }, [serverId]);

  const tool = useMemo(
    () => tools?.find((t) => t.name === selectedTool) ?? null,
    [tools, selectedTool],
  );
  const props = tool?.inputSchema?.properties ?? {};
  const required = useMemo(() => new Set(tool?.inputSchema?.required ?? []), [tool]);

  const serverEntry = useMemo(
    () => servers.find((s) => s.id === serverId) ?? null,
    [servers, serverId],
  );
  const disabledSet = useMemo(
    () => new Set(serverEntry?.disabledTools ?? []),
    [serverEntry],
  );
  const pinnedSet = useMemo(
    () => new Set(serverId ? (registry?.pinnedTools?.[serverId] ?? []) : []),
    [registry, serverId],
  );

  /** Is this tool exposed to clients right now? (per-tool off, or destructive
   * while the global switch is on, both hide it at the gateway.) */
  function isExposed(t: McpTool): boolean {
    if (disabledSet.has(t.name)) return false;
    if (denyDestructive && isDestructive(t)) return false;
    return true;
  }

  async function toggleTool(toolName: string, enabled: boolean) {
    if (!serverId) return;
    setPolicyBusy(true);
    try {
      onRegistryChange(await setToolEnabled(serverId, toolName, enabled));
    } catch (e) {
      toastError(`Couldn't update the tool: ${e}`);
    } finally {
      setPolicyBusy(false);
    }
  }

  async function togglePin(toolName: string, pinned: boolean) {
    if (!serverId) return;
    setPolicyBusy(true);
    try {
      onRegistryChange(await setToolPinned(serverId, toolName, pinned));
    } catch (e) {
      toastError(`Couldn't pin the tool: ${e}`);
    } finally {
      setPolicyBusy(false);
    }
  }

  // Fresh argument state whenever the selected tool changes.
  useEffect(() => {
    setArgs({});
    setResult(null);
    setCallError(null);
    setRawMode(false);
    setRawJson("{}");
  }, [selectedTool]);

  /** Assemble the arguments object from the form (or the raw JSON editor). */
  function buildArgs(): Record<string, unknown> | { error: string } {
    if (rawMode) {
      try {
        const parsed = JSON.parse(rawJson || "{}");
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          return { error: "Arguments must be a JSON object." };
        }
        return parsed as Record<string, unknown>;
      } catch (e) {
        return { error: `Invalid JSON: ${String(e)}` };
      }
    }
    const out: Record<string, unknown> = {};
    for (const [k, schema] of Object.entries(props)) {
      const v = args[k];
      if (v === undefined || v === "") continue;
      out[k] = coerce(v, schema as JsonSchemaProp);
    }
    const missing = [...required].filter((k) => !(k in out));
    if (missing.length > 0) {
      return {
        error: `Fill in required field${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}`,
      };
    }
    return out;
  }

  async function run() {
    if (!serverId || !selectedTool) return;
    const built = buildArgs();
    if ("error" in built && typeof built.error === "string") {
      setCallError(built.error);
      setResult(null);
      return;
    }
    setCalling(true);
    setResult(null);
    setCallError(null);
    try {
      const r = await callTool(serverId, selectedTool, built as Record<string, unknown>);
      setResult(r);
    } catch (e) {
      setCallError(String(e));
    } finally {
      setCalling(false);
    }
  }

  if (servers.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24 text-center">
        <FlaskConical className="size-10 text-muted-foreground/50" />
        <div>
          <p className="font-medium">No servers to test</p>
          <p className="max-w-md text-sm text-muted-foreground">
            Add a server to Toolport, then come back here to invoke its tools and see the
            raw results, without wiring up a client first.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex max-w-3xl flex-col gap-5">
      {/* Server picker */}
      <div className="flex w-64 flex-col gap-1.5">
        <Label className="text-xs text-muted-foreground">Server</Label>
        <Select value={serverId ?? ""} onValueChange={setServerId}>
          <SelectTrigger className="h-9">
            <SelectValue placeholder="Pick a server…" />
          </SelectTrigger>
          <SelectContent>
            {servers.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-[11px] text-muted-foreground">
          Tests any server directly, regardless of the active profile.
        </p>
      </div>

      {serverId && (
        <div className="flex w-fit gap-1 rounded-lg border bg-muted/30 p-1 text-sm">
          {(["tools", "resources", "prompts"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              aria-pressed={tab === t}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1 capitalize transition-colors ${
                tab === t
                  ? "bg-background font-medium shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {t === "resources" && <FileText className="size-3.5" />}
              {t === "prompts" && <MessageSquare className="size-3.5" />}
              {t}
            </button>
          ))}
        </div>
      )}

      {serverId && tab === "resources" && (
        <ResourcesPanel key={serverId} serverId={serverId} />
      )}
      {serverId && tab === "prompts" && (
        <PromptsPanel key={serverId} serverId={serverId} />
      )}

      {tab === "tools" && (
        <>
          {loadingTools && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> Connecting to server…
            </div>
          )}

          {toolsError && <Callout variant="danger">{toolsError}</Callout>}

          {/* Tool list: click to test, switch to enable/disable per client */}
          {tools && tools.length > 0 && (
            <div className="flex flex-col gap-1.5">
              <Label className="text-xs text-muted-foreground">
                Tools ({tools.length})
              </Label>
              <div className="flex flex-col divide-y rounded-lg border">
                {tools.map((t) => {
                  const destructive = isDestructive(t);
                  const exposed = isExposed(t);
                  const selected = t.name === selectedTool;
                  const perToolOff = disabledSet.has(t.name);
                  const pinned = pinnedSet.has(t.name);
                  return (
                    <div
                      key={t.name}
                      className={`flex items-center gap-3 px-3 py-2 ${selected ? "bg-accent" : ""}`}
                    >
                      <button
                        onClick={() => setSelectedTool(t.name)}
                        aria-pressed={selected}
                        className="flex min-w-0 flex-1 flex-col items-start gap-0.5 text-left"
                      >
                        <span className="flex min-w-0 items-center gap-2">
                          <span className="truncate font-mono text-sm">{t.name}</span>
                          {destructive && <Badge variant="warning">destructive</Badge>}
                          {!exposed && (
                            <span className="text-xs text-muted-foreground">hidden</span>
                          )}
                        </span>
                        {t.description && (
                          <span className="line-clamp-1 text-xs text-muted-foreground">
                            {t.description}
                          </span>
                        )}
                      </button>
                      <button
                        onClick={() => togglePin(t.name, !pinned)}
                        disabled={policyBusy}
                        title={
                          pinned
                            ? "Pinned: always surfaced in lazy-discovery search"
                            : "Pin as a prerequisite (always surfaced in search)"
                        }
                        aria-label={pinned ? `Unpin ${t.name}` : `Pin ${t.name}`}
                        aria-pressed={pinned}
                        className="shrink-0 rounded p-1 hover:bg-muted disabled:opacity-50"
                      >
                        <Pin
                          className={`size-4 ${
                            pinned ? "fill-current text-owned" : "text-muted-foreground"
                          }`}
                        />
                      </button>
                      <Switch
                        checked={!perToolOff}
                        onCheckedChange={(on) => toggleTool(t.name, on)}
                        disabled={policyBusy}
                        aria-label={`Enable ${t.name}`}
                      />
                    </div>
                  );
                })}
              </div>
              {denyDestructive && (
                <p className="text-xs text-muted-foreground">
                  Destructive tools are hidden from clients by the global switch even when
                  individually enabled.
                </p>
              )}
            </div>
          )}

          {/* Argument form for the selected tool */}
          {tool && (
            <div className="flex flex-col gap-4 rounded-lg border bg-card p-4">
              {tool.description && (
                <p className="text-sm text-muted-foreground">{tool.description}</p>
              )}
              {!isExposed(tool) && (
                <p className="flex items-center gap-1.5 text-xs text-warning">
                  <ShieldAlert className="size-3.5" />
                  Hidden from clients by policy. You can still test it here.
                </p>
              )}

              {serverId && (
                <ToolOverrideEditor
                  serverId={serverId}
                  tool={tool}
                  registry={registry}
                  onRegistryChange={onRegistryChange}
                />
              )}

              <div className="flex items-center justify-between">
                <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  Arguments
                </span>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  Raw JSON
                  <Switch checked={rawMode} onCheckedChange={setRawMode} />
                </label>
              </div>

              {rawMode ? (
                <textarea
                  value={rawJson}
                  onChange={(e) => setRawJson(e.target.value)}
                  rows={6}
                  spellCheck={false}
                  className="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-sm focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
                />
              ) : Object.keys(props).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  This tool takes no arguments.
                </p>
              ) : (
                <div className="flex flex-col gap-4">
                  {Object.entries(props).map(([name, schema]) => (
                    <ArgField
                      key={name}
                      name={name}
                      schema={schema as JsonSchemaProp}
                      required={required.has(name)}
                      value={args[name]}
                      onChange={(v) => setArgs((a) => ({ ...a, [name]: v }))}
                    />
                  ))}
                </div>
              )}

              <div>
                <Button onClick={run} disabled={calling} size="sm">
                  {calling ? (
                    <Loader2 className="size-4 animate-spin" />
                  ) : (
                    <Play className="size-4" />
                  )}
                  {calling ? "Calling…" : "Call tool"}
                </Button>
              </div>
            </div>
          )}

          {/* Call error (transport / connection failure) */}
          {callError && <Callout variant="danger">{callError}</Callout>}

          {/* Result */}
          {result && (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                {result.isError ? (
                  <XCircle className="size-4 text-destructive" />
                ) : (
                  <CheckCircle2 className="size-4 text-success" />
                )}
                {result.isError ? "Tool returned an error" : "Result"}
                <CopyButton text={renderResult(result)} />
              </div>
              <pre
                className={`max-h-96 overflow-auto rounded-lg border p-3 font-mono text-xs whitespace-pre-wrap ${
                  result.isError
                    ? "border-destructive/40 bg-destructive/5"
                    : "bg-muted/40"
                }`}
              >
                {renderResult(result)}
              </pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
