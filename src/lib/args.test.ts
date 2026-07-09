import { describe, it, expect } from "vitest";
import { parseArgs, formatArgs } from "./args";

// ─── parseArgs ─────────────────────────────────────────────────────────────

describe("parseArgs", () => {
  it("returns [] for an empty string", () => {
    expect(parseArgs("")).toEqual([]);
  });

  it("returns [] for whitespace-only input", () => {
    expect(parseArgs("   ")).toEqual([]);
  });

  it("parses a single arg", () => {
    expect(parseArgs("mcp")).toEqual(["mcp"]);
  });

  it("parses a simple multi-arg string", () => {
    expect(parseArgs("-y @modelcontextprotocol/server-filesystem")).toEqual([
      "-y",
      "@modelcontextprotocol/server-filesystem",
    ]);
  });

  it("parses a double-quoted path with spaces", () => {
    expect(
      parseArgs('"/Applications/Open Design.app/Contents/Resources/daemon-cli.mjs" mcp'),
    ).toEqual(["/Applications/Open Design.app/Contents/Resources/daemon-cli.mjs", "mcp"]);
  });

  it("parses a single-quoted path with spaces", () => {
    expect(
      parseArgs("'/Applications/Open Design.app/Contents/Resources/daemon-cli.mjs' mcp"),
    ).toEqual(["/Applications/Open Design.app/Contents/Resources/daemon-cli.mjs", "mcp"]);
  });

  it("collapses multiple whitespace runs between args", () => {
    expect(parseArgs("  -y   @scope/pkg  ")).toEqual(["-y", "@scope/pkg"]);
  });

  it("treats tabs and newlines as separators", () => {
    expect(parseArgs("-y\t@scope/pkg\nmcp")).toEqual(["-y", "@scope/pkg", "mcp"]);
  });

  it("produces an empty-string arg from empty double-quotes", () => {
    expect(parseArgs('"" mcp')).toEqual(["", "mcp"]);
  });

  it("produces an empty-string arg from empty single-quotes", () => {
    expect(parseArgs("'' mcp")).toEqual(["", "mcp"]);
  });

  it("concatenates mid-word double quotes with surrounding text", () => {
    expect(parseArgs('foo"bar baz"qux mcp')).toEqual(["foobar bazqux", "mcp"]);
  });

  it("parses adjacent quoted words separated by space", () => {
    expect(parseArgs('"foo" "bar" baz')).toEqual(["foo", "bar", "baz"]);
  });

  it("concatenates adjacent quoted segments without space", () => {
    expect(parseArgs('"foo""bar" baz')).toEqual(["foobar", "baz"]);
  });

  it("treats backslash as literal outside quotes (Windows path)", () => {
    expect(parseArgs("C:\\Users\\test mcp")).toEqual(["C:\\Users\\test", "mcp"]);
  });

  it("parses escaped double quotes inside double quotes", () => {
    expect(parseArgs('"say \\"hello\\""')).toEqual(['say "hello"']);
  });

  it("treats single quotes as literal inside double quotes", () => {
    expect(parseArgs('"it\'s here" mcp')).toEqual(["it's here", "mcp"]);
  });

  it("treats double quotes as literal inside single quotes", () => {
    expect(parseArgs("'say \"hi\"' mcp")).toEqual(['say "hi"', "mcp"]);
  });

  it("parses the exact Open Design daemon path (the original bug)", () => {
    expect(
      parseArgs(
        '"/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs" mcp',
      ),
    ).toEqual([
      "/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs",
      "mcp",
    ]);
  });

  it("handles leading and trailing whitespace", () => {
    expect(parseArgs("   -y @scope/pkg   ")).toEqual(["-y", "@scope/pkg"]);
  });

  it("parses an arg that is just a single quote char in double quotes", () => {
    expect(parseArgs('"\'" mcp')).toEqual(["'", "mcp"]);
  });

  it("parses an arg that is just a double quote char in single quotes", () => {
    expect(parseArgs("'\"' mcp")).toEqual(['"', "mcp"]);
  });

  it("parses command-like patterns from catalog", () => {
    expect(parseArgs("-y figma-developer-mcp --stdio")).toEqual([
      "-y",
      "figma-developer-mcp",
      "--stdio",
    ]);
  });

  it("parses multiple space-containing args", () => {
    expect(parseArgs('"path one" arg "path two"')).toEqual([
      "path one",
      "arg",
      "path two",
    ]);
  });

  it("parses escaped backslash inside double quotes", () => {
    expect(parseArgs('"escaped \\\\"')).toEqual(["escaped \\"]);
  });

  it("parses a Windows path with escaped backslashes inside double quotes", () => {
    expect(parseArgs('"C:\\\\Program Files\\\\"')).toEqual(["C:\\Program Files\\"]);
  });

  it("treats backslash-n inside double quotes as literal (both chars)", () => {
    expect(parseArgs('"foo\\nbar"')).toEqual(["foo\\nbar"]);
  });
});

// ─── formatArgs ────────────────────────────────────────────────────────────

describe("formatArgs", () => {
  it("formats an empty array as empty string", () => {
    expect(formatArgs([])).toBe("");
  });

  it("formats simple args without quoting", () => {
    expect(formatArgs(["-y", "@scope/pkg"])).toBe("-y @scope/pkg");
  });

  it("quotes a space-containing path", () => {
    expect(formatArgs(["/Applications/Open Design.app/daemon.mjs", "mcp"])).toBe(
      '"/Applications/Open Design.app/daemon.mjs" mcp',
    );
  });

  it("quotes an empty-string arg", () => {
    expect(formatArgs(["", "mcp"])).toBe('"" mcp');
  });

  it("quotes and escapes an arg containing double quotes", () => {
    expect(formatArgs(['say "hello"'])).toBe('"say \\"hello\\""');
  });

  it("quotes an arg containing a single quote", () => {
    expect(formatArgs(["it's here"])).toBe('"it\'s here"');
  });

  it("formats multiple space-containing args", () => {
    expect(formatArgs(["path one", "arg", "path two"])).toBe('"path one" arg "path two"');
  });

  it("escapes a trailing backslash in a quoted arg", () => {
    expect(formatArgs(["backslash: \\"])).toBe('"backslash: \\\\"');
  });

  it("escapes backslashes in a Windows path with spaces", () => {
    expect(formatArgs(["C:\\Program Files\\"])).toBe('"C:\\\\Program Files\\\\"');
  });
});

// ─── round-trip property: parseArgs(formatArgs(x)) === x ───────────────────

describe("round-trip", () => {
  const cases: { args: string[]; label: string }[] = [
    { args: [], label: "empty list" },
    { args: ["mcp"], label: "single arg" },
    {
      args: ["-y", "@modelcontextprotocol/server-filesystem"],
      label: "typical npx pattern",
    },
    {
      args: [
        "/Applications/Open Design.app/Contents/Resources/daemon/daemon-cli.mjs",
        "mcp",
      ],
      label: "Open Design daemon path",
    },
    {
      args: [
        "/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs",
        "mcp",
      ],
      label: "full Open Design path",
    },
    { args: ["path one", "arg", "path two"], label: "multiple space-containing args" },
    { args: ["", "mcp"], label: "empty string arg" },
    { args: ['say "hello"', "mcp"], label: "arg containing double quotes" },
    { args: ["it's here", "mcp"], label: "arg containing single quotes" },
    { args: ["C:\\Users\\test\\path", "mcp"], label: "Windows backslash path" },
    { args: ["-y", "figma-developer-mcp", "--stdio"], label: "figma pattern" },
    { args: ["--config", '{"key": "value"}'], label: "JSON config arg" },
    { args: ["backslash: \\"], label: "arg with trailing backslash" },
    {
      args: ["C:\\Program Files\\"],
      label: "Windows path with spaces and trailing backslash",
    },
    {
      args: ["--header", "Authorization:Bearer ${POSTHOG_AUTH_HEADER}"],
      label: "PostHog mcp-remote header with env placeholder",
    },
    {
      args: ["multiple  spaces", "tab\there"],
      label: "arg with multiple spaces and tab",
    },
  ];

  for (const { args, label } of cases) {
    it(`round-trips: ${label}`, () => {
      const formatted = formatArgs(args);
      const reparsed = parseArgs(formatted);
      expect(reparsed).toEqual(args);
    });
  }
});

// ─── regression: the original bug ──────────────────────────────────────────

describe("original bug regression", () => {
  it("the old naive split broke on space-containing paths", () => {
    const args = [
      "/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs",
      "mcp",
    ];

    // OLD (buggy): join with bare space, split on \s+ → 3 args instead of 2
    const oldFormatted = args.join(" ");
    const oldParsed = oldFormatted.split(/\s+/).filter(Boolean);
    expect(oldParsed).not.toEqual(args);
    expect(oldParsed).toHaveLength(3);
  });

  it("the new parseArgs/formatArgs round-trips losslessly", () => {
    const args = [
      "/Applications/Open Design.app/Contents/Resources/app/prebundled/daemon/daemon-cli.mjs",
      "mcp",
    ];
    expect(parseArgs(formatArgs(args))).toEqual(args);
  });
});
