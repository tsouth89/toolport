import { describe, it, expect } from "vitest";
import { fmtTokens } from "./utils";

describe("fmtTokens", () => {
  it("renders small numbers as-is", () => {
    expect(fmtTokens(0)).toBe("0");
    expect(fmtTokens(1)).toBe("1");
    expect(fmtTokens(999)).toBe("999");
  });

  it("renders thousands with a k suffix", () => {
    expect(fmtTokens(1000)).toBe("1.0k");
    expect(fmtTokens(12345)).toBe("12.3k");
    expect(fmtTokens(999499)).toBe("999.5k");
  });

  it("renders millions with an M suffix", () => {
    expect(fmtTokens(1_000_000)).toBe("1.0M");
    expect(fmtTokens(1_234_567)).toBe("1.2M");
  });

  it("rolls over to B and T instead of thousands of M", () => {
    expect(fmtTokens(1_000_000_000)).toBe("1.0B");
    expect(fmtTokens(2_110_000_000)).toBe("2.1B");
    expect(fmtTokens(1_500_000_000_000)).toBe("1.5T");
  });

  it("handles the boundary at 999999 (rounds up to 1000.0k, not 1.0M)", () => {
    // 999999 is just below the 1_000_000 threshold, so it takes the "k" branch:
    // (999999 / 1000).toFixed(1) === "1000.0", giving "1000.0k" rather than "1.0M".
    expect(fmtTokens(999999)).toBe("1000.0k");
  });

  it("passes 0 and negative inputs through unformatted", () => {
    expect(fmtTokens(0)).toBe("0");
    expect(fmtTokens(-1)).toBe("-1");
    expect(fmtTokens(-12345)).toBe("-12345");
  });
});
