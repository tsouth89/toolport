import { describe, it, expect, vi, afterEach } from "vitest";
import { useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ErrorBoundary } from "./ErrorBoundary";

// A child that throws on render, to trip the boundary.
function Boom({ message = "boom" }: { message?: string }): never {
  throw new Error(message);
}

const fallback = (error: Error, reset: () => void) => (
  <div>
    <p>crashed: {error.message}</p>
    <button onClick={reset}>retry</button>
  </div>
);

// React logs caught render errors to console.error; silence it so the throwing
// tests don't spew noise (and restore after each).
function silenceErrors() {
  vi.spyOn(console, "error").mockImplementation(() => {});
}

describe("ErrorBoundary", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders children when nothing throws", () => {
    render(
      <ErrorBoundary fallback={fallback}>
        <span>all good</span>
      </ErrorBoundary>,
    );
    expect(screen.getByText("all good")).toBeInTheDocument();
  });

  it("shows the fallback with the thrown error instead of unmounting", () => {
    silenceErrors();
    render(
      <ErrorBoundary fallback={fallback}>
        <Boom message="kaboom" />
      </ErrorBoundary>,
    );
    expect(screen.getByText("crashed: kaboom")).toBeInTheDocument();
  });

  it("recovers when resetKey changes, e.g. navigating to another view", async () => {
    silenceErrors();
    function Harness() {
      const [view, setView] = useState<"crashy" | "safe">("crashy");
      return (
        <>
          <button onClick={() => setView("safe")}>go safe</button>
          <ErrorBoundary resetKey={view} fallback={fallback}>
            {view === "crashy" ? <Boom message="x" /> : <span>recovered view</span>}
          </ErrorBoundary>
        </>
      );
    }
    render(<Harness />);
    expect(screen.getByText("crashed: x")).toBeInTheDocument();

    await userEvent.click(screen.getByText("go safe"));
    expect(screen.getByText("recovered view")).toBeInTheDocument();
    expect(screen.queryByText(/^crashed:/)).not.toBeInTheDocument();
  });

  it("re-renders the children when the fallback's reset() runs and the cause is gone", async () => {
    silenceErrors();
    let shouldThrow = true;
    function Maybe() {
      if (shouldThrow) throw new Error("first render");
      return <span>healed</span>;
    }
    render(
      <ErrorBoundary fallback={fallback}>
        <Maybe />
      </ErrorBoundary>,
    );
    expect(screen.getByText("crashed: first render")).toBeInTheDocument();

    shouldThrow = false;
    await userEvent.click(screen.getByText("retry"));
    expect(screen.getByText("healed")).toBeInTheDocument();
  });
});
