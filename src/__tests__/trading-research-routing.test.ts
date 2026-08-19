import fs from "node:fs";
import path from "node:path";

import {
  describe,
  expect,
  it,
} from "vitest";


describe(
  "trading research routing",
  () => {
    it(
      "routes every research tool through the dedicated research client",
      () => {
        const source = fs.readFileSync(
          path.resolve(
            process.cwd(),
            "src/trading/tools.ts",
          ),
          "utf8",
        );

        expect(
          source,
        ).toContain(
          'from "./research-client.js"',
        );

        const researchLines = source
          .split(/\r?\n/)
          .filter(
            (line) =>
              line.includes(
                "/v1/research/",
              ),
          );

        expect(
          researchLines,
        ).toHaveLength(5);

        for (
          const line
          of researchLines
        ) {
          expect(
            line.includes(
              "callResearch(",
            ) ||
            line.includes(
              "postResearchJson(",
            ),
          ).toBe(true);

          expect(
            line,
          ).not.toContain(
            "callGateway(",
          );

          expect(
            line,
          ).not.toMatch(
            /\bpostJson\(/,
          );
        }
      },
    );
  },
);
