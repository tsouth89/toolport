import { useEffect, useMemo, useState } from "react";
import {
  CheckCircle2,
  FlaskConical,
  Loader2,
  Play,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { toastError } from "@/lib/toast";
import {
  callTool,
  listServerTools,
  setToolEnabled,
} from "@/lib/api";
import type {
  JsonSchemaProp,
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

/** First declared type of a JSON-schema property (schemas may list several). */
function primaryType(schema: JsonSchemaProp): string {
  return Array.isArray(schema.type) ? schema.type[0] ?? "string" : schema.type ?? "string";
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
    .map((b) => (b.type === "text" && b.text != null ? b.text : JSON.stringify(b, null, 2)))
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

interface PlaygroundProps {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}

export function PlaygroundView({ registry, onRegistryChange }: PlaygroundProps) {
  const servers = registry?.servers ?? [];
  const denyDestructive = registry?.denyDestructive ?? false;

  const [serverId, setServerId] = useState<string | null>(null);
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
  const required = useMemo(
    () => new Set(tool?.inputSchema?.required ?? []),
    [tool],
  );

  const serverEntry = useMemo(
    () => servers.find((s) => s.id === serverId) ?? null,
    [servers, serverId],
  );
  const disabledSet = useMemo(
    () => new Set(serverEntry?.disabledTools ?? []),
    [serverEntry],
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
      return { error: `Fill in required field${missing.length === 1 ? "" : "s"}: ${missing.join(", ")}` };
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
            Add a server to Conduit, then come back here to invoke its tools and
            see the raw results, without wiring up a client first.
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
                      {destructive && (
                        <Badge
                          variant="outline"
                          className="border-warning/40 text-warning"
                        >
                          destructive
                        </Badge>
                      )}
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
              Destructive tools are hidden from clients by the global switch even
              when individually enabled.
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
              className="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs shadow-sm focus-visible:ring-1 focus-visible:ring-ring focus-visible:outline-none"
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
          </div>
          <pre className="max-h-96 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap">
            {renderResult(result)}
          </pre>
        </div>
      )}
    </div>
  );
}
