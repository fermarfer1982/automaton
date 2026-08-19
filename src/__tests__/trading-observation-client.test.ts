import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const auth = vi.hoisted(() => ({
  readObservationApiKey:
    vi.fn(() => "A".repeat(43)),
}));

vi.mock(
  "../trading/observation-auth.js",
  () => auth,
);

import {
  callObservation,
  callObservationJson,
} from "../trading/observation-client.js";

const originalFetch = globalThis.fetch;

const originalObservationUrl =
  process.env.AUTOMATON_MT5_OBSERVATION_URL;

beforeEach(() => {
  vi.clearAllMocks();

  delete process.env
    .AUTOMATON_MT5_OBSERVATION_URL;
});

afterEach(() => {
  globalThis.fetch = originalFetch;

  if (originalObservationUrl === undefined) {
    delete process.env
      .AUTOMATON_MT5_OBSERVATION_URL;
  } else {
    process.env.AUTOMATON_MT5_OBSERVATION_URL =
      originalObservationUrl;
  }

  vi.restoreAllMocks();
});

function jsonResponse(
  payload: unknown,
  status = 200,
): Response {
  return new Response(
    JSON.stringify(payload),
    {
      status,
      headers: {
        "content-type": "application/json",
      },
    },
  );
}

describe("observation client", () => {
  it("uses only the dedicated loopback service and observation key", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        mode: "OBSERVE_ONLY",
        execution_capable: false,
      }),
    );

    globalThis.fetch =
      fetchMock as typeof fetch;

    await callObservation(
      "/v1/status",
    );

    expect(
      fetchMock,
    ).toHaveBeenCalledTimes(1);

    const [
      requestUrl,
      requestInit,
    ] = fetchMock.mock.calls[0] as [
      URL,
      RequestInit,
    ];

    expect(
      String(requestUrl),
    ).toBe(
      "http://127.0.0.1:8766/v1/status",
    );

    expect(
      requestInit.method,
    ).toBe("GET");

    expect(
      requestInit.redirect,
    ).toBe("error");

    const headers = new Headers(
      requestInit.headers,
    );

    expect(
      headers.get(
        "x-automaton-observation-key",
      ),
    ).toBe(
      "A".repeat(43),
    );

    expect(
      headers.has(
        "x-automaton-key",
      ),
    ).toBe(false);
  });

  it("rejects routes outside /v1 before fetch", async () => {
    const fetchMock = vi.fn();

    globalThis.fetch =
      fetchMock as typeof fetch;

    await expect(
      callObservation("/health"),
    ).rejects.toThrow(
      "relative /v1 route",
    );

    expect(
      fetchMock,
    ).not.toHaveBeenCalled();
  });

  it("rejects normalized traversal outside /v1", async () => {
    const fetchMock = vi.fn();

    globalThis.fetch =
      fetchMock as typeof fetch;

    await expect(
      callObservation(
        "/v1/../../admin",
      ),
    ).rejects.toThrow(
      "protected /v1 boundary",
    );

    expect(
      fetchMock,
    ).not.toHaveBeenCalled();
  });

  it("remains pinned to the dedicated loopback origin despite environment override", async () => {
    process.env.AUTOMATON_MT5_OBSERVATION_URL =
      "https://example.com";

    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        mode: "OBSERVE_ONLY",
        execution_capable: false,
      }),
    );

    globalThis.fetch =
      fetchMock as typeof fetch;

    await callObservation(
      "/v1/status",
    );

    expect(
      fetchMock,
    ).toHaveBeenCalledTimes(1);

    const [
      requestUrl,
    ] = fetchMock.mock.calls[0] as [
      URL,
      RequestInit,
    ];

    expect(
      String(requestUrl),
    ).toBe(
      "http://127.0.0.1:8766/v1/status",
    );

    expect(
      String(requestUrl),
    ).not.toContain(
      "example.com",
    );
  });

  it("rejects non-JSON responses", async () => {
    globalThis.fetch =
      vi.fn().mockResolvedValue(
        new Response(
          "not-json",
          {
            status: 200,
            headers: {
              "content-type": "text/plain",
            },
          },
        ),
      ) as typeof fetch;

    await expect(
      callObservation("/v1/status"),
    ).rejects.toThrow(
      "non-JSON",
    );
  });

  it("rejects malformed JSON", async () => {
    globalThis.fetch =
      vi.fn().mockResolvedValue(
        new Response(
          "{",
          {
            status: 200,
            headers: {
              "content-type":
                "application/json",
            },
          },
        ),
      ) as typeof fetch;

    await expect(
      callObservation("/v1/status"),
    ).rejects.toThrow(
      "malformed JSON",
    );
  });

  it("rejects JSON arrays", async () => {
    globalThis.fetch =
      vi.fn().mockResolvedValue(
        jsonResponse([]),
      ) as typeof fetch;

    await expect(
      callObservation("/v1/status"),
    ).rejects.toThrow(
      "invalid JSON payload",
    );
  });

  it("fails closed on HTTP errors", async () => {
    globalThis.fetch =
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            error:
              "invalid_observation_key",
          },
          401,
        ),
      ) as typeof fetch;

    await expect(
      callObservation("/v1/status"),
    ).rejects.toThrow(
      "HTTP 401",
    );
  });

  it("returns parsed objects through callObservationJson", async () => {
    globalThis.fetch =
      vi.fn().mockResolvedValue(
        jsonResponse({
          execution_capable: false,
        }),
      ) as typeof fetch;

    const result =
      await callObservationJson<{
        execution_capable: boolean;
      }>("/v1/status");

    expect(
      result.execution_capable,
    ).toBe(false);
  });
});