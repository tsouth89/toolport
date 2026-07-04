import { Globe, HelpCircle, Radio, Terminal } from "lucide-react";
import type { Transport } from "@/lib/types";

// Transport is low-value, near-constant metadata, so it renders NEUTRAL: the icon plus a
// muted mono label. Semantic colors (green/amber/red) are reserved exclusively for health,
// so a healthy stdio server no longer shows two unrelated greens next to each other.
const meta: Record<Transport, { label: string; icon: typeof Terminal }> = {
  stdio: { label: "stdio", icon: Terminal },
  http: { label: "http", icon: Globe },
  sse: { label: "sse", icon: Radio },
  unknown: { label: "unknown", icon: HelpCircle },
};

export function TransportPill({ transport }: { transport: Transport }) {
  const m = meta[transport];
  const Icon = m.icon;
  return (
    <span
      aria-label={`Transport: ${m.label}`}
      className="inline-flex items-center gap-1 font-mono text-2xs text-muted-foreground/70"
    >
      <Icon className="size-3 opacity-70" aria-hidden="true" />
      <span aria-hidden="true">{m.label}</span>
    </span>
  );
}
