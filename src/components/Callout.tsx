import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const VARIANTS = {
  danger: "border-destructive/40 bg-destructive/10 text-destructive",
  warning: "border-warning/40 bg-warning/10 text-warning",
  success: "border-success/40 bg-success/10 text-success",
  info: "border-info/40 bg-info/10 text-info",
} as const;

interface Props {
  variant?: keyof typeof VARIANTS;
  className?: string;
  children: ReactNode;
  /** ARIA role, e.g. "status" or "alert" for banners that should be announced. */
  role?: string;
}

/** A tinted message banner. One source of truth for the success / warning / info /
 * danger notice boxes that views used to hand-roll with inconsistent padding, radius,
 * and opacity. Colors come from the semantic accent tokens. */
export function Callout({ variant = "info", className, children, role }: Props) {
  return (
    <div
      role={role}
      className={cn("rounded-lg border px-3 py-2 text-sm", VARIANTS[variant], className)}
    >
      {children}
    </div>
  );
}
