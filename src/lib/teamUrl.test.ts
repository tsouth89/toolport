import { describe, expect, it } from "vitest";

import { teamUrlError } from "./teamUrl";

describe("teamUrlError", () => {
  it("accepts https team servers", () => {
    expect(teamUrlError("https://teams.example.com")).toBeNull();
  });

  it("accepts loopback http for local development", () => {
    expect(teamUrlError("http://127.0.0.1:8787")).toBeNull();
    expect(teamUrlError("http://localhost:8787")).toBeNull();
    expect(teamUrlError("http://[::1]:8787")).toBeNull();
  });

  it("rejects cleartext public or LAN team servers", () => {
    expect(teamUrlError("http://teams.example.com")).toMatch(/https/);
    expect(teamUrlError("http://192.168.1.10:8787")).toMatch(/https/);
  });

  it("rejects missing or malformed URLs", () => {
    expect(teamUrlError("")).toMatch(/required/);
    expect(teamUrlError("teams.example.com")).toMatch(/https/);
  });
});
