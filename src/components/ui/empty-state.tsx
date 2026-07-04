import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * One center-stacked empty / first-run / error state, replacing ~5 near-identical copies.
 * Icon + title + one-line description + an optional action row.
 */
export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 py-20 text-center",
        className,
      )}
    >
      {icon && <div className="text-muted-foreground/50 [&_svg]:size-10">{icon}</div>}
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        {description && (
          <p className="mx-auto max-w-md text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {action && <div className="mt-1 flex items-center gap-2">{action}</div>}
    </div>
  );
}
