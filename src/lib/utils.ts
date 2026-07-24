import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a token count compactly: 1_234_567 -> "1.2M", 2_110_000_000 -> "2.1B",
 * 12_345 -> "12.3k". Rolls over at each 1000x so a large catalog reads as "2.1B"
 * rather than "2110.0M". Single source of truth so every surface (Activity,
 * Sidebar, share text, ...) shows the same rounded figure for the same number.
 */
export function fmtTokens(n: number): string {
  if (n >= 1_000_000_000_000) return `${(n / 1_000_000_000_000).toFixed(1)}T`;
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return `${n}`;
}

/**
 * Stable React keys for a newest-first list whose entries have no unique id.
 * Each key is the item's identity plus, on collision, an occurrence counter
 * counted from the END of the array, so prepending new entries never changes
 * the key of an existing row (an index-based suffix shifts on every prepend
 * and remounts each row, resetting its expand/collapse state). Identities can
 * collide (e.g. two calls to the same tool in the same millisecond), so the
 * counter keeps keys unique deterministically. "#" inside identities is
 * escaped to "##" so a generated "#n" suffix can never equal another
 * identity that happens to end in "#n" (the escaped form only contains "#"
 * in even-length runs, while the suffix adds a lone "#").
 */
export function stableListKeys<T>(items: T[], identity: (item: T) => string): string[] {
  const seen = new Map<string, number>();
  const keys = new Array<string>(items.length);
  for (let i = items.length - 1; i >= 0; i--) {
    const id = identity(items[i]);
    const n = seen.get(id) ?? 0;
    seen.set(id, n + 1);
    const escaped = id.replace(/#/g, "##");
    keys[i] = n === 0 ? escaped : `${escaped}#${n}`;
  }
  return keys;
}

/**
 * Format a ratio as a percent with the same adaptive precision everywhere.
 * When `floorNonZero` is true, tiny positive rates render as "<0.1%" instead
 * of rounding down to a misleading "0%".
 */
export function fmtPercent(
  rate: number,
  options: { floorNonZero?: boolean } = {},
): string {
  const percent = rate * 100;
  if (options.floorNonZero && percent > 0 && percent < 0.1) return "<0.1%";
  if (options.floorNonZero && percent === 0) return "<0.1%";
  return `${percent.toFixed(percent > 0 && percent < 10 ? 1 : 0)}%`;
}

/**
 * Format an epoch-ms timestamp for display. The default is the short
 * date-and-time shape used by most Activity rows; `"time"` and `"date"` are the
 * locale defaults for a single component, and `"monthDay"` is the compact
 * month-and-day used where the year would be noise (the savings banner).
 */
export function fmtTs(timestamp: number, format?: "time" | "date" | "monthDay"): string {
  if (format === "time") {
    return new Date(timestamp).toLocaleTimeString();
  } else if (format === "date") {
    return new Date(timestamp).toLocaleDateString();
  } else if (format === "monthDay") {
    return new Date(timestamp).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    });
  } else {
    return new Date(timestamp).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }
}
