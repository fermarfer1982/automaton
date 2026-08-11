import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../trading/gateway-auth.js", () => ({
  readGatewayApiKey: () => "A".repeat(43),
}));

import { callGateway } from "../trading/gateway-client.js";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("authenticated trading gateway client", () => {
  it("rejects routes that could escape the fixed loopback origin", async () => {
    await expect(callGateway("https://example.com/v1/health")).rejects.toThrow("relative /v1 route");
    await expect(callGateway("//example.com/v1/health")).rejects.toThrow("relative /v1 route");
  });

  it("adds authentication and rejects caller key overrides", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{"healthy":true}', {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "16" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(callGateway("/v1/health")).resolves.toBe('{"healthy":true}');
    const [, init] = fetchMock.mock.calls[0] as [URL, RequestInit];
    expect((init.headers as Headers).get("x-automaton-key")).toBe("A".repeat(43));
    expect(init.redirect).toBe("error");
    await expect(callGateway("/v1/health", {
      headers: { "x-automaton-key": "attacker" },
    })).rejects.toThrow("cannot override");
  });

  it("fails closed on non-JSON and malformed JSON responses", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("ok", {
      status: 200,
      headers: { "content-type": "text/plain", "content-length": "2" },
    })));
    await expect(callGateway("/v1/health")).rejects.toThrow("non-JSON");

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{", {
      status: 200,
      headers: { "content-type": "application/json", "content-length": "1" },
    })));
    await expect(callGateway("/v1/health")).rejects.toThrow("malformed JSON");
  });
});
