import fs from "node:fs";
import path from "node:path";
import type { LogEntry } from "../types.js";
import { StructuredLogger } from "../observability/logger.js";

const REDACTED = new Set([
  "password", "credential", "api_key", "apikey", "token", "secret", "private_key",
]);

function sanitize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [
      key,
      REDACTED.has(key.toLowerCase()) ? "[REDACTED]" : sanitize(child),
    ]));
  }
  return value;
}

export function configureTradingLabLogging(stateDirectory: string): void {
  const logDirectory = path.join(path.resolve(stateDirectory), "logs");
  if (fs.existsSync(logDirectory) && fs.lstatSync(logDirectory).isSymbolicLink()) {
    throw new Error("Trading laboratory log directory cannot be a symbolic link");
  }
  fs.mkdirSync(logDirectory, { recursive: true });
  StructuredLogger.setSink((entry: LogEntry) => {
    const day = entry.timestamp.slice(0, 10);
    const destination = path.join(logDirectory, `agent-${day}.jsonl`);
    fs.appendFileSync(destination, `${JSON.stringify(sanitize(entry))}\n`, { encoding: "utf8" });
  });
}
