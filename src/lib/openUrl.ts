import { openUrl } from "@tauri-apps/plugin-opener";

/**
 * Open an external link, but only real web URLs.
 *
 * Some of these URLs originate from registry/vendor data (a catalog entry's
 * homepage, an auth hint's docs link), which is not fully trusted. Handing a
 * `file://` (Windows SMB -> NTLM-hash leak) or a custom-scheme handler URI to
 * the OS opener is a real risk, so allow only `http`/`https` through. The
 * backend also validates at the source (see `catalog.rs`); this is the matching
 * frontend guard so every `openUrl` call site is covered.
 *
 * Silently no-ops on a missing or non-web URL rather than throwing, since these
 * are all fire-and-forget click handlers.
 */
export function openExternal(url: string | null | undefined): Promise<void> {
  if (!url) return Promise.resolve();
  let protocol: string;
  try {
    protocol = new URL(url).protocol;
  } catch {
    console.warn(`openExternal: refusing to open unparseable URL: ${url}`);
    return Promise.resolve();
  }
  if (protocol !== "http:" && protocol !== "https:") {
    console.warn(`openExternal: refusing to open non-web URL: ${url}`);
    return Promise.resolve();
  }
  return openUrl(url);
}
