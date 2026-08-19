import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock(
  "../trading/research-auth.js",
  () => ({
    readResearchApiKey:
      () => "R".repeat(43),
  }),
);

import {
  callResearch,
  postResearchJson,
} from "../trading/research-client.js";


afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function jsonResponse(
  body = '{"ok":true}',
): Response {
  return new Response(
    body,
    {
      status: 200,
      headers: {
        "content-type":
          "application/json",
      },
    },
  );
}

describe(
  "research client",
  () => {
    it(
      "uses exact loopback research namespace and dedicated header",
      async () => {
        const fetchMock = vi.fn()
          .mockResolvedValue(
            jsonResponse(),
          );

        vi.stubGlobal(
          "fetch",
          fetchMock,
        );

        await callResearch(
          "/v1/research/metrics",
        );

        expect(
          fetchMock,
        ).toHaveBeenCalledTimes(1);

        const [
          url,
          init,
        ] = fetchMock.mock.calls[0] as [
          URL,
          RequestInit,
        ];

        expect(
          url.toString(),
        ).toBe(
          "http://127.0.0.1:8765/v1/research/metrics",
        );

        expect(
          init.method,
        ).toBe("GET");

        expect(
          init.redirect,
        ).toBe("error");

        const headers = new Headers(
          init.headers,
        );

        expect(
          headers.get(
            "x-automaton-research-key",
          ),
        ).toBe(
          "R".repeat(43),
        );

        expect(
          headers.has(
            "x-automaton-key",
          ),
        ).toBe(false);
      },
    );

    it(
      "posts JSON through research credential only",
      async () => {
        const fetchMock = vi.fn()
          .mockResolvedValue(
            jsonResponse(),
          );

        vi.stubGlobal(
          "fetch",
          fetchMock,
        );

        await postResearchJson(
          "/v1/research/hypotheses",
          {
            hypothesis_id: "h1",
            thesis: "test",
          },
        );

        const [
          ,
          init,
        ] = fetchMock.mock.calls[0] as [
          URL,
          RequestInit,
        ];

        expect(
          init.method,
        ).toBe("POST");

        const headers = new Headers(
          init.headers,
        );

        expect(
          headers.get(
            "content-type",
          ),
        ).toBe(
          "application/json",
        );

        expect(
          headers.get(
            "x-automaton-research-key",
          ),
        ).toBe(
          "R".repeat(43),
        );

        expect(
          headers.has(
            "x-automaton-key",
          ),
        ).toBe(false);
      },
    );

    it(
      "rejects non-research routes before fetch",
      async () => {
        const fetchMock = vi.fn();

        vi.stubGlobal(
          "fetch",
          fetchMock,
        );

        await expect(
          callResearch(
            "/v1/status",
          ),
        ).rejects.toThrow(
          "must remain inside",
        );

        expect(
          fetchMock,
        ).not.toHaveBeenCalled();
      },
    );

    it(
      "rejects normalized namespace escape",
      async () => {
        const fetchMock = vi.fn();

        vi.stubGlobal(
          "fetch",
          fetchMock,
        );

        await expect(
          callResearch(
            "/v1/research/../trade/propose",
          ),
        ).rejects.toThrow(
          "escaped the protected namespace",
        );

        expect(
          fetchMock,
        ).not.toHaveBeenCalled();
      },
    );

    it(
      "rejects caller supplied gateway credential",
      async () => {
        const fetchMock = vi.fn();

        vi.stubGlobal(
          "fetch",
          fetchMock,
        );

        await expect(
          callResearch(
            "/v1/research/metrics",
            {
              headers: {
                "X-AUTOMATON-KEY":
                  "not-allowed",
              },
            },
          ),
        ).rejects.toThrow(
          "cannot override protected credentials",
        );

        expect(
          fetchMock,
        ).not.toHaveBeenCalled();
      },
    );
  },
);
