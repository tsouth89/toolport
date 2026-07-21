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
