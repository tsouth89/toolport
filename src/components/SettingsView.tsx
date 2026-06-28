import { useState } from "react";
import { Bot, Layers, ShieldAlert } from "lucide-react";
import { toastError } from "@/lib/toast";
import {
  setAllowAgentControl,
  setDenyDestructive,
  setLazyDiscovery,
} from "@/lib/api";
import type { Registry } from "@/lib/types";
import { Switch } from "@/components/ui/switch";

interface Props {
  registry: Registry | null;
  onRegistryChange: (registry: Registry) => void;
}

/** Global discovery + security policy. These apply to every client uniformly, so
 * they live here rather than in the per-server Playground. */
export function SettingsView({ registry, onRegistryChange }: Props) {
  const lazyDiscovery = registry?.lazyDiscovery ?? true;
  const denyDestructive = registry?.denyDestructive ?? false;
  const allowAgentControl = registry?.allowAgentControl ?? false;
  const [busy, setBusy] = useState(false);

  const apply =
    (fn: (v: boolean) => Promise<Registry>) => async (v: boolean) => {
      setBusy(true);
      try {
        onRegistryChange(await fn(v));
      } catch (e) {
        toastError(`Couldn't update the setting: ${e}`);
      } finally {
        setBusy(false);
      }
    };

  const toggle = (
    Icon: typeof Layers,
    on: boolean,
    accent: string,
    title: string,
    desc: string,
    onChange: (v: boolean) => void,
  ) => (
    <label className="flex items-center gap-2.5 rounded-md border px-3 py-2.5 text-sm">
      <Icon className={`size-4 shrink-0 ${on ? accent : "text-muted-foreground"}`} />
      <span className="flex min-w-0 flex-1 flex-col leading-tight">
        <span className="font-medium">{title}</span>
        <span className="text-xs text-muted-foreground">{desc}</span>
      </span>
      <Switch checked={on} onCheckedChange={onChange} disabled={busy} />
    </label>
  );

  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-6">
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Discovery
        </h2>
        {toggle(
          Layers,
          lazyDiscovery,
          "text-info",
          "Lazy discovery",
          "Expose 3 meta-tools, not the full catalog (all clients)",
          apply(setLazyDiscovery),
        )}
      </section>
      <section className="flex flex-col gap-2">
        <h2 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Security
        </h2>
        {toggle(
          ShieldAlert,
          denyDestructive,
          "text-warning",
          "Block destructive tools",
          "Hide every destructiveHint tool from all clients",
          apply(setDenyDestructive),
        )}
        {toggle(
          Bot,
          allowAgentControl,
          "text-success",
          "Allow agent control",
          "Let an agent turn servers on/off (the block above stays yours)",
          apply(setAllowAgentControl),
        )}
      </section>
    </div>
  );
}
