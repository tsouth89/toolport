import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

/** Best-effort check for a newer release via the Tauri updater. Returns null on
 * any failure (dev build, offline, or no manifest published yet) so callers can
 * just fall back to showing the current version. */
export async function checkForUpdate(): Promise<Update | null> {
  try {
    return await check();
  } catch {
    return null;
  }
}

/** Download + install the update, then relaunch into the new version. */
export async function installUpdate(update: Update): Promise<void> {
  await update.downloadAndInstall();
  await relaunch();
}
