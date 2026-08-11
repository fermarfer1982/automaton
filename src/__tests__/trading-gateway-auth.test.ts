import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { gatewayApiKeyPath, readGatewayApiKey } from "../trading/gateway-auth.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  for (const directory of temporaryDirectories.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe("external gateway API key", () => {
  it("accepts only an absolute, non-symlink key outside the workspace", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "automaton-key-"));
    temporaryDirectories.push(directory);
    const keyPath = path.join(directory, "gateway.key");
    fs.writeFileSync(keyPath, "B".repeat(43), { encoding: "ascii", mode: 0o600 });
    vi.stubEnv("AUTOMATON_MT5_API_KEY_FILE", keyPath);
    expect(gatewayApiKeyPath()).toBe(path.resolve(keyPath));
    expect(readGatewayApiKey()).toBe("B".repeat(43));
  });

  it("rejects malformed secrets", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "automaton-key-"));
    temporaryDirectories.push(directory);
    const keyPath = path.join(directory, "gateway.key");
    fs.writeFileSync(keyPath, "short\n", "ascii");
    vi.stubEnv("AUTOMATON_MT5_API_KEY_FILE", keyPath);
    expect(() => readGatewayApiKey()).toThrow("invalid format");
  });
});
