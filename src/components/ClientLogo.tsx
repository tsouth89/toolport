import { cn } from "@/lib/utils";

/**
 * Official client brand logos.
 *
 * SVGs are vendored under src/assets/client-logos (no runtime dependency), sourced from
 * @lobehub/icons-static-svg (MIT) and simple-icons (CC0). Full-color marks keep their own
 * fills; monochrome marks are authored with `fill="currentColor"`, so they inherit the
 * surrounding text color and stay legible on both the light and dark (navy) themes.
 *
 * Each file is a 24x24 viewBox sized in `1em`, so the wrapper's font-size sets the render
 * size. Clients without a vendored logo fall back to a neutral monogram badge.
 */
const RAW = import.meta.glob("../assets/client-logos/*.svg", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

// basename (without .svg) -> raw SVG markup
const LOGOS: Record<string, string> = Object.fromEntries(
  Object.entries(RAW).map(([path, svg]) => [
    path.split("/").pop()!.replace(".svg", ""),
    svg,
  ]),
);

/**
 * Client id -> logo file basename. Most ids match their filename; the two Claude clients
 * share the Anthropic mark family but use distinct files. Ids absent here render a monogram
 * (VS Code, Continue, Jan, BoltAI, Pi, AnythingLLM have no clean official mark vendored yet).
 */
const CLIENT_LOGO: Record<string, string> = {
  "claude-desktop": "claude",
  "claude-code": "claude-code",
  cursor: "cursor",
  codex: "codex",
  antigravity: "antigravity",
  "gemini-cli": "gemini-cli",
  cline: "cline",
  "roo-code": "roo-code",
  kiro: "kiro",
  "lm-studio": "lm-studio",
  goose: "goose",
  hermes: "hermes",
  windsurf: "windsurf",
  warp: "warp",
  zed: "zed",
  "amazon-q": "amazon-q",
};

/** Initials for the monogram fallback: two letters for multi-word names, else two chars. */
function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

/**
 * The official brand logo for a client, or a neutral monogram badge when none is vendored.
 * Decorative: the client name always sits next to it, so it's aria-hidden.
 */
export function ClientLogo({
  id,
  name,
  size = 20,
  className,
}: {
  id: string;
  name: string;
  size?: number;
  className?: string;
}) {
  const svg = LOGOS[CLIENT_LOGO[id] ?? ""];

  if (svg) {
    return (
      <span
        aria-hidden
        className={cn("inline-flex shrink-0 items-center justify-center", className)}
        style={{ fontSize: size, lineHeight: 0, width: size, height: size }}
        dangerouslySetInnerHTML={{ __html: svg }}
      />
    );
  }

  return (
    <span
      aria-hidden
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md border bg-muted font-semibold text-muted-foreground",
        className,
      )}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.42) }}
    >
      {initials(name)}
    </span>
  );
}
