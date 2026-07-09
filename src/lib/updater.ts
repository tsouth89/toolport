import { invoke } from "@tauri-apps/api/core";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

/** Outcome of an update check. `error` is distinct from `current` so the UI can
 * tell "you're up to date" apart from "couldn't reach the update server". */
export type UpdateCheck =
  | { kind: "update"; update: Update }
  | { kind: "current" }
  | { kind: "error"; message: string };

/** Check for a newer release via the Tauri updater. Never throws; failures
 * (dev build, offline, or no manifest published yet) come back as `error`. */
export async function checkForUpdate(): Promise<UpdateCheck> {
  try {
    const u = await check();
    return u?.available ? { kind: "update", update: u } : { kind: "current" };
  } catch (e) {
    return { kind: "error", message: String(e) };
  }
}

/** Download + install the update, then relaunch into the new version. */
export async function installUpdate(update: Update): Promise<void> {
  await invoke<number>("stop_spawned_gateways");
  await update.downloadAndInstall();
  await relaunch();
}
