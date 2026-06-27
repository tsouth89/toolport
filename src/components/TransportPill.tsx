import { Globe, HelpCircle, Radio, Terminal } from "lucide-react";
import type { Transport } from "@/lib/types";

const meta: Record<
  Transport,
  { label: string; icon: typeof Terminal; className: string }
> = {
  stdio: {
    label: "stdio",
    icon: Terminal,
    className: "text-success border-success/30 bg-success/10",
  },
  http: {
    label: "http",
    icon: Globe,
    className: "text-owned border-owned/30 bg-owned/10",
  },
  sse: {
    label: "sse",
    icon: Radio,
    className: "text-info border-info/30 bg-info/10",
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
