import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const KEY_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;

export function researchApiKeyPath(): string {
  const configured =
    process.env.AUTOMATON_MT5_RESEARCH_API_KEY_FILE;

  if (!configured || !path.isAbsolute(configured)) {
    throw new Error(
      "AUTOMATON_MT5_RESEARCH_API_KEY_FILE " +
      "must be an absolute protected path",
    );
  }

  const resolved = path.resolve(configured);

  const workspace = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../..",
  );

  const relative = path.relative(
    workspace,
    resolved,
  );

  if (
    relative === "" ||
    (
      !relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative)
    )
  ) {
    throw new Error(
      "Research API key must remain outside " +
      "the Automaton workspace",
    );
  }

  if (fs.lstatSync(resolved).isSymbolicLink()) {
    throw new Error(
      "Research API key path cannot be a symbolic link",
    );
  }

  return resolved;
}

export function readResearchApiKey(): string {
  const value = fs.readFileSync(
    researchApiKeyPath(),
    "ascii",
  );

  if (
    value !== value.trim() ||
    !KEY_PATTERN.test(value)
  ) {
    throw new Error(
      "Protected research API key has invalid format",
    );
  }

  return value;
}
