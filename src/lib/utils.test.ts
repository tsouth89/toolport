import { describe, it, expect } from "vitest";
import { fmtTokens } from "./utils";

describe("fmtTokens", () => {
  it("renders small numbers as-is", () => {
    expect(fmtTokens(0)).toBe("0");
    expect(fmtTokens(-1)).toBe("-1");
    expect(fmtTokens(-5)).toBe("-5");
    expect(fmtTokens(42)).toBe("42");
    expect(fmtTokens(999)).toBe("999");
  });

  it("renders thousands with a k suffix", () => {
    expect(fmtTokens(1000)).toBe("1.0k");
    expect(fmtTokens(12345)).toBe("12.3k");
  });

  it("keeps the current boundary at 999999 as 1000.0k (not 1.0M)", () => {
    // Document current behavior intentionally — do not "fix" without product sign-off.
    expect(fmtTokens(999_999)).toBe("1000.0k");
  });

  it("renders millions with an M suffix", () => {
    expect(fmtTokens(1_000_000)).toBe("1.0M");
    expect(fmtTokens(1_234_567)).toBe("1.2M");
  });
});
