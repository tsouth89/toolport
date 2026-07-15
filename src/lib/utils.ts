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
