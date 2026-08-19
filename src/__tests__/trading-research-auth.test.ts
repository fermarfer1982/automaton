import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  afterEach,
  describe,
  expect,
  it,
} from "vitest";

import {
  readResearchApiKey,
  researchApiKeyPath,
} from "../trading/research-auth.js";


const createdRoots: string[] = [];

function newTempRoot(): string {
  const root = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      "automaton-research-auth-",
    ),
  );

  createdRoots.push(root);

  return root;
}

afterEach(() => {
  delete process.env
    .AUTOMATON_MT5_RESEARCH_API_KEY_FILE;

  for (
    const root
    of createdRoots.splice(0)
  ) {
    fs.rmSync(
      root,
      {
        recursive: true,
        force: true,
      },
    );
  }
});

describe(
  "research auth",
  () => {
    it(
      "reads a protected external research key",
      () => {
        const root = newTempRoot();

        const keyPath = path.join(
          root,
          "research.key",
        );

        fs.writeFileSync(
          keyPath,
          "R".repeat(43),
          "ascii",
        );

        process.env
          .AUTOMATON_MT5_RESEARCH_API_KEY_FILE =
          keyPath;

        expect(
          researchApiKeyPath(),
        ).toBe(
          path.resolve(keyPath),
        );

        expect(
          readResearchApiKey(),
        ).toBe(
          "R".repeat(43),
        );
      },
    );

    it(
      "rejects relative credential paths",
      () => {
        process.env
          .AUTOMATON_MT5_RESEARCH_API_KEY_FILE =
          "research.key";

        expect(
          () => researchApiKeyPath(),
        ).toThrow(
          "must be an absolute protected path",
        );
      },
    );

    it(
      "rejects a credential path inside the workspace",
      () => {
        process.env
          .AUTOMATON_MT5_RESEARCH_API_KEY_FILE =
          path.join(
            process.cwd(),
            "never-create-research.key",
          );

        expect(
          () => researchApiKeyPath(),
        ).toThrow(
          "must remain outside",
        );
      },
    );

    it(
      "rejects invalid key format",
      () => {
        const root = newTempRoot();

        const keyPath = path.join(
          root,
          "research.key",
        );

        fs.writeFileSync(
          keyPath,
          "short",
          "ascii",
        );

        process.env
          .AUTOMATON_MT5_RESEARCH_API_KEY_FILE =
          keyPath;

        expect(
          () => readResearchApiKey(),
        ).toThrow(
          "invalid format",
        );
      },
    );
  },
);
