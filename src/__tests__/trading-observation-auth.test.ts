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
  observationApiKeyPath,
  readObservationApiKey,
} from "../trading/observation-auth.js";

const originalKeyPath =
  process.env.AUTOMATON_MT5_OBSERVATION_API_KEY_FILE;

afterEach(() => {
  if (originalKeyPath === undefined) {
    delete process.env
      .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE;
  } else {
    process.env
      .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE =
      originalKeyPath;
  }
});

describe("observation API key", () => {
  it("reads a valid protected key outside the workspace", () => {
    const directory = fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "automaton-observation-auth-",
      ),
    );

    try {
      const keyPath = path.join(
        directory,
        "observation.key",
      );

      fs.writeFileSync(
        keyPath,
        "B".repeat(43),
        "ascii",
      );

      process.env
        .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE =
        keyPath;

      expect(
        observationApiKeyPath(),
      ).toBe(
        path.resolve(keyPath),
      );

      expect(
        readObservationApiKey(),
      ).toBe(
        "B".repeat(43),
      );
    } finally {
      fs.rmSync(
        directory,
        {
          recursive: true,
          force: true,
        },
      );
    }
  });

  it("rejects a relative key path", () => {
    process.env
      .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE =
      "observation.key";

    expect(
      () => observationApiKeyPath(),
    ).toThrow(
      "absolute protected path",
    );
  });

  it("rejects a key located inside the workspace", () => {
    process.env
      .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE =
      path.join(
        process.cwd(),
        "never-create-observation.key",
      );

    expect(
      () => observationApiKeyPath(),
    ).toThrow(
      "outside the Automaton workspace",
    );
  });

  it("rejects malformed key contents", () => {
    const directory = fs.mkdtempSync(
      path.join(
        os.tmpdir(),
        "automaton-observation-auth-",
      ),
    );

    try {
      const keyPath = path.join(
        directory,
        "observation.key",
      );

      fs.writeFileSync(
        keyPath,
        `${"C".repeat(43)}\n`,
        "ascii",
      );

      process.env
        .AUTOMATON_MT5_OBSERVATION_API_KEY_FILE =
        keyPath;

      expect(
        () => readObservationApiKey(),
      ).toThrow(
        "invalid format",
      );
    } finally {
      fs.rmSync(
        directory,
        {
          recursive: true,
          force: true,
        },
      );
    }
  });
});