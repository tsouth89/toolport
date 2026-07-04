import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const DOT: Record<string, string> = {
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-destructive",
  muted: "bg-muted-foreground/60",
  brand: "bg-primary",
};

/**
 * The one uppercase micro-header used across every view. Replaces ~14 hand-rolled copies
 * that had drifted to three different sizes. Optional leading status dot, a count pill, a
 * leading icon, and a right-aligned action slot.
 */
export function SectionHeader({
  children,
  tone,
  count,
  icon,
  action,
  className,
}: {
  children: ReactNode;
  tone?: keyof typeof DOT;
  count?: number;
  icon?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "mb-2 flex items-center gap-2 text-2xs font-semibold tracking-[0.09em] text-muted-foreground uppercase",
        className,
      )}
    >
      {tone && <span className={cn("size-1.5 shrink-0 rounded-full", DOT[tone])} />}
      {icon}
      <span>{children}</span>
      {count != null && (
        <span className="rounded-full bg-secondary px-2 py-px text-2xs font-semibold tracking-normal text-muted-foreground tabular-nums">
          {count}
        </span>
      )}
      {action && <span className="ml-auto flex items-center gap-1.5">{action}</span>}
    </div>
  );
}
