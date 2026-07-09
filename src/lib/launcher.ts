/** Download-then-run launchers (npx, uvx, pnpm dlx, ...): the first spawn may have
 * to download the server package before it can answer, so a health probe can sit
 * in "checking" for a while on a cold cache. The UI uses this to name that wait
 * "Installing…" instead of letting it read as a stall. Mirrors the backend policy
 * in src-tauri/src/downstream.rs (`is_download_launcher`), including its
 * normalization of a config that packed the whole invocation into `command`.
 */
export function isDownloadLauncher(command: string | null, args: string[]): boolean {
  if (!command) return false;
  let cmd = command;
  let argv = args;
  // Backend `normalize_invocation`: a packed `"npx -y @scope/pkg"` with empty args
  // is split, but only when the first token is a bare program name (no path).
  if (args.length === 0) {
    const parts = command.split(/\s+/).filter(Boolean);
    const first = parts[0] ?? "";
    if (parts.length > 1 && !first.includes("/") && !first.includes("\\")) {
      cmd = first;
      argv = parts.slice(1);
    }
  }
  const base = (cmd.split(/[\\/]/).pop() ?? cmd)
    .toLowerCase()
    .replace(/\.(exe|cmd|ps1)$/, "");
  if (base === "npx" || base === "uvx" || base === "bunx") return true;
  const sub = argv[0];
  if ((base === "pnpm" || base === "yarn") && sub === "dlx") return true;
  if (base === "npm" && (sub === "exec" || sub === "x")) return true;
  if (base === "pipx" && sub === "run") return true;
  return false;
}
