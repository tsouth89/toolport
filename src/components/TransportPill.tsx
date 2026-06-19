import { Globe, HelpCircle, Radio, Terminal } from "lucide-react";
import type { Transport } from "@/lib/types";

const meta: Record<
  Transport,
  { label: string; icon: typeof Terminal; className: string }
> = {
  stdio: {
    label: "stdio",
    icon: Terminal,
    className: "text-emerald-400 border-emerald-400/30 bg-emerald-400/10",
  },
  http: {
    label: "http",
    icon: Globe,
    className: "text-sky-400 border-sky-400/30 bg-sky-400/10",
  },
  sse: {
    label: "sse",
    icon: Radio,
    className: "text-violet-400 border-violet-400/30 bg-violet-400/10",
  },
  unknown: {
    label: "unknown",
    icon: HelpCircle,
    className: "text-muted-foreground border-border bg-muted",
  },
};

export function TransportPill({ transport }: { transport: Transport }) {
  const m = meta[transport];
  const Icon = m.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${m.className}`}
    >
      <Icon className="size-3" />
      {m.label}
    </span>
  );
}
