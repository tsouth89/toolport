export function teamUrlError(raw: string): string | null {
  const value = raw.trim();
  if (!value) return "Server URL is required.";

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "Team server URL must start with https://.";
  }

  if (url.protocol === "https:") return null;
  if (url.protocol !== "http:") return "Team server URL must start with https://.";

  const host = url.hostname.toLowerCase();
  const loopback =
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "[::1]";

  return loopback
    ? null
    : "Team server URL must use https:// unless it is loopback HTTP for local development.";
}
