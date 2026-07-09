/**
 * Turn a raw downstream/probe error into a short, human-readable headline.
 *
 * A failed stdio spawn or remote connect can surface a multi-KB dump: a full
 * Node stack trace plus a giant OAuth authorize URL with dozens of scopes. Shown
 * verbatim in a status tooltip or row, that buries the one useful line
 * (`exited status 1`, `EADDRINUSE 127.0.0.1:39541`) and reads as broken. These
 * helpers pull out the signal and keep the noise available but out of the way.
 */

// Recognized signals, checked in order; first match wins. Each returns a short
// headline. Kept deliberately small: these are the failures users actually hit.
const PATTERNS: Array<[RegExp, (m: RegExpMatchArray) => string]> = [
  [
    /EADDRINUSE[^\n]*?(\d{1,3}(?:\.\d{1,3}){3}:\d+|:\d+)/i,
    (m) => `Port already in use (${m[1]})`,
  ],
  [/EADDRINUSE/i, () => "Port already in use"],
  [/ENOENT/i, () => "Command or file not found (ENOENT)"],
  [/ECONNREFUSED/i, () => "Connection refused"],
  [
    /timed out waiting for initialize|timed? ?out/i,
    () => "Timed out waiting for the server",
  ],
  [/\b401\b|unauthorized/i, () => "Authentication required (401)"],
  [/\b403\b|forbidden/i, () => "Access forbidden (403)"],
];

/**
 * Middle-truncate a long run of non-space characters (e.g. a giant OAuth URL) so
 * it stays on one readable line instead of dominating the message.
 */
export function truncateMiddle(s: string, max = 100): string {
  if (s.length <= max) return s;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}

/** Replace any long URL in `s` with a middle-truncated version. */
export function shortenUrls(s: string, max = 80): string {
  return s.replace(/https?:\/\/\S+/g, (u) => truncateMiddle(u, max));
}

/**
 * A one-line headline for an error. Prefers a recognized pattern, then an
 * `exited status N` line, then the last non-empty line, capped in length with any
 * long URL middle-truncated. Never throws; returns "Unknown error" for empty input.
 */
export function errorHeadline(raw: string | null | undefined): string {
  const text = (raw ?? "").trim();
  if (!text) return "Unknown error";

  for (const [re, fmt] of PATTERNS) {
    const m = text.match(re);
    if (m) return fmt(m);
  }

  const exit = text.match(/exit(?:ed)?\s+(?:with\s+)?(?:status|code)\s+(\d+)/i);
  if (exit) return `Exited with status ${exit[1]}`;

  const lastLine =
    text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .pop() ?? text;
  return truncateMiddle(shortenUrls(lastLine, 60), 160);
}
