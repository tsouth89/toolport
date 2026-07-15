import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

/** The user's theme choice. `system` tracks the OS `prefers-color-scheme` live. */
export type Theme = "light" | "dark" | "system";

/** localStorage key. The inline bootstrap in index.html reads the same key to set the
 * initial `.dark` class before first paint, so keep them in sync. */
const STORAGE_KEY = "toolport-theme";

function readStored(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
    // No explicit choice yet. Preserve dark for EXISTING installs (they never opted into a
    // theme, so an upgrade shouldn't flip their app under them); default NEW installs to
    // `system`. `conduit.onboarded` is set once onboarding is done = an existing user. The
    // inline bootstrap in index.html makes the same decision so there's no flash.
    return localStorage.getItem("conduit.onboarded") === "1" ? "dark" : "system";
  } catch {
    // localStorage unavailable: dark matches the historical hardcoded app.
    return "dark";
  }
}

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

type ThemeCtx = {
  /** The user's choice (may be `system`). */
  theme: Theme;
  /** The concrete theme in effect right now (`system` resolved against the OS). */
  resolved: "light" | "dark";
  setTheme: (t: Theme) => void;
};

const Ctx = createContext<ThemeCtx | null>(null);

/** Owns the theme: persists the choice, applies it to `<html>`, and follows live OS
 * `prefers-color-scheme` changes while on `system`. The initial class is set by the inline
 * bootstrap in index.html (no flash of the wrong theme); this keeps it in sync afterward. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readStored);
  const [systemDark, setSystemDark] = useState<boolean>(prefersDark);

  // Track the OS preference so a `system` choice re-resolves when it changes. The setState
  // runs in the media-query event handler (not the effect body), so it never loops.
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  // Derived during render (not stored), so there's a single source of truth.
  const resolved: "light" | "dark" =
    theme === "system" ? (systemDark ? "dark" : "light") : theme;

  // Reflect onto `<html>`: the light palette is `:root`, `.dark` overrides it. Side effect
  // only (no setState), so no effect-loop concerns.
  useEffect(() => {
    document.documentElement.classList.toggle("dark", resolved === "dark");
  }, [resolved]);

  const setTheme = (t: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      // Persistence best-effort; the in-memory choice still applies this session.
    }
    setThemeState(t);
  };

  return <Ctx.Provider value={{ theme, resolved, setTheme }}>{children}</Ctx.Provider>;
}

// The hook lives with its provider (idiomatic); the fast-refresh rule only wants components
// in a component file, which is harmless here.
// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTheme must be used within a ThemeProvider");
  return ctx;
}
