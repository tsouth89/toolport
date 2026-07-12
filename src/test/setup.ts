// Vitest setup for React component tests. The existing src/lib tests use explicit
// vitest imports (globals off), so we register jest-dom matchers and Testing Library
// cleanup here rather than relying on auto-injected globals.
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

afterEach(() => cleanup());

// jsdom is missing a few DOM APIs that Radix UI (Dialog/Select) calls at runtime.
// Stub them so component tests can render those primitives without throwing.
if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}
const elemProto = Element.prototype as unknown as Record<string, unknown>;
for (const method of [
  "hasPointerCapture",
  "setPointerCapture",
  "releasePointerCapture",
  "scrollIntoView",
]) {
  if (typeof elemProto[method] !== "function") {
    elemProto[method] = () => {};
  }
}
