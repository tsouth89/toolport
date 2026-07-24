import { describe, it, expect } from "vitest";
import { clientRestartHint, connectSuccessDescription } from "./clientConnect";

describe("clientRestartHint / connectSuccessDescription (SOU-317)", () => {
  it("puts the restart line first and keeps optional scope/backup notes", () => {
    expect(clientRestartHint("Claude Desktop")).toBe(
      "Restart Claude Desktop so it loads Toolport.",
    );
    expect(
      connectSuccessDescription("Claude Desktop", [
        'Scoped to the "Work" profile.',
        false,
        null,
      ]),
    ).toBe('Restart Claude Desktop so it loads Toolport. Scoped to the "Work" profile.');
    expect(connectSuccessDescription("Claude Desktop")).toBe(
      "Restart Claude Desktop so it loads Toolport.",
    );
  });
});
