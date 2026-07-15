import { describe, expect, it } from "vitest";
import {
  importableServers,
  isGatewayServer,
  type DetectedClient,
  type ServerEntry,
} from "./types";

describe("gateway identity", () => {
  it("recognizes the legacy toolport ID and name without relying on the command", () => {
    const server: ServerEntry = {
      id: "TOOLPORT",
      name: "Toolport",
      transport: "stdio",
      command: "manual-wrapper",
      args: [],
      env: [],
      url: null,
      source: null,
    };

    expect(isGatewayServer(server)).toBe(true);
  });

  it("never surfaces a legacy toolport entry as an import candidate", () => {
    const client: DetectedClient = {
      id: "claude-code",
      name: "Claude Code",
      usesConnectors: false,
      configPath: "config.json",
      configExists: true,
      appPresent: true,
      servers: [
        {
          name: "toolport",
          transport: "stdio",
          command: "manual-wrapper",
          args: [],
          envKeys: [],
          url: null,
        },
      ],
      pluginServers: [],
      gatewayInstalled: true,
      error: null,
    };

    expect(importableServers(client, null)).toEqual([]);
  });
});
