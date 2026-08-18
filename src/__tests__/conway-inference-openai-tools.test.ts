import { afterEach, describe, expect, it, vi } from "vitest";
import { createInferenceClient } from "../conway/inference.js";

const originalFetch = globalThis.fetch;

function successfulCompletion(model: string): Response {
  return new Response(
    JSON.stringify({
      id: "test-completion",
      model,
      choices: [
        {
          finish_reason: "stop",
          message: {
            role: "assistant",
            content: "ok",
          },
        },
      ],
      usage: {
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
      },
    }),
    {
      status: 200,
      headers: {
        "content-type": "application/json",
      },
    },
  );
}

function toolDefinition() {
  return {
    type: "function",
    function: {
      name: "noop",
      description: "Harmless compatibility test tool",
      parameters: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
    },
  };
}

function requestBody(
  fetchMock: ReturnType<typeof vi.fn>,
): Record<string, unknown> {
  expect(fetchMock).toHaveBeenCalledTimes(1);

  const init = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;

  expect(typeof init?.body).toBe("string");

  return JSON.parse(init?.body as string) as Record<string, unknown>;
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe("OpenAI gpt-5.6-luna tool compatibility", () => {
  it("sets reasoning_effort=none for OpenAI gpt-5.6-luna with tools", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      successfulCompletion("gpt-5.6-luna"),
    );

    globalThis.fetch = fetchMock as typeof fetch;

    const client = createInferenceClient({
      apiUrl: "https://api.conway.tech",
      apiKey: "test-conway-key",
      defaultModel: "gpt-5.6-luna",
      maxTokens: 32,
      openaiApiKey: "test-openai-key",
      forcedBackend: "openai",
    });

    await client.chat(
      [{ role: "user", content: "test" }],
      { tools: [toolDefinition()] as any },
    );

    const body = requestBody(fetchMock);

    expect(body.model).toBe("gpt-5.6-luna");
    expect(body.reasoning_effort).toBe("none");
    expect(body.tools).toBeDefined();
    expect(body.tool_choice).toBe("auto");
  });

  it("does not set reasoning_effort for OpenAI gpt-5.6-luna without tools", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      successfulCompletion("gpt-5.6-luna"),
    );

    globalThis.fetch = fetchMock as typeof fetch;

    const client = createInferenceClient({
      apiUrl: "https://api.conway.tech",
      apiKey: "test-conway-key",
      defaultModel: "gpt-5.6-luna",
      maxTokens: 32,
      openaiApiKey: "test-openai-key",
      forcedBackend: "openai",
    });

    await client.chat([
      { role: "user", content: "test" },
    ]);

    const body = requestBody(fetchMock);

    expect(body).not.toHaveProperty("reasoning_effort");
    expect(body).not.toHaveProperty("tools");
    expect(body).not.toHaveProperty("tool_choice");
  });

  it("does not change other OpenAI models with tools", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      successfulCompletion("gpt-5.2"),
    );

    globalThis.fetch = fetchMock as typeof fetch;

    const client = createInferenceClient({
      apiUrl: "https://api.conway.tech",
      apiKey: "test-conway-key",
      defaultModel: "gpt-5.2",
      maxTokens: 32,
      openaiApiKey: "test-openai-key",
      forcedBackend: "openai",
    });

    await client.chat(
      [{ role: "user", content: "test" }],
      { tools: [toolDefinition()] as any },
    );

    const body = requestBody(fetchMock);

    expect(body.model).toBe("gpt-5.2");
    expect(body).not.toHaveProperty("reasoning_effort");
    expect(body.tools).toBeDefined();
    expect(body.tool_choice).toBe("auto");
  });

  it("does not inject reasoning_effort into the Ollama backend", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      successfulCompletion("gpt-5.6-luna"),
    );

    globalThis.fetch = fetchMock as typeof fetch;

    const client = createInferenceClient({
      apiUrl: "https://api.conway.tech",
      apiKey: "test-conway-key",
      defaultModel: "gpt-5.6-luna",
      maxTokens: 32,
      ollamaBaseUrl: "http://127.0.0.1:11434",
      forcedBackend: "ollama",
    });

    await client.chat(
      [{ role: "user", content: "test" }],
      { tools: [toolDefinition()] as any },
    );

    const body = requestBody(fetchMock);

    expect(body.model).toBe("gpt-5.6-luna");
    expect(body).not.toHaveProperty("reasoning_effort");
    expect(body.tools).toBeDefined();
    expect(body.tool_choice).toBe("auto");
  });
});
