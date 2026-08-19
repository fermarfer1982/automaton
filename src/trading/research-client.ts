import {
  requireCredentialFreeLoopbackOrigin,
} from "./network.js";

import {
  readResearchApiKey,
} from "./research-auth.js";

const DEFAULT_RESEARCH_URL =
  "http://127.0.0.1:8765";

const MAX_RESPONSE_BYTES = 1_000_000;

function researchUrl(): URL {
  return requireCredentialFreeLoopbackOrigin(
    DEFAULT_RESEARCH_URL,
    "AUTOMATON_MT5_RESEARCH_URL",
  );
}

export async function callResearch(
  pathname: string,
  init?: RequestInit,
): Promise<string> {
  if (
    !pathname.startsWith("/v1/research/") ||
    pathname.startsWith("//")
  ) {
    throw new Error(
      "Research path must remain inside /v1/research/",
    );
  }

  const method = (
    init?.method || "GET"
  ).toUpperCase();

  if (
    method !== "GET" &&
    method !== "POST"
  ) {
    throw new Error(
      "Research client permits only GET or POST",
    );
  }

  const origin = researchUrl();

  const url = new URL(
    pathname,
    origin,
  );

  if (
    url.origin !== origin.origin ||
    !url.pathname.startsWith(
      "/v1/research/",
    )
  ) {
    throw new Error(
      "Research route escaped the protected namespace",
    );
  }

  const headers = new Headers(
    init?.headers,
  );

  if (
    headers.has("x-automaton-key") ||
    headers.has(
      "x-automaton-research-key",
    )
  ) {
    throw new Error(
      "Research callers cannot override protected credentials",
    );
  }

  headers.set(
    "accept",
    "application/json",
  );

  headers.set(
    "x-automaton-research-key",
    readResearchApiKey(),
  );

  if (init?.body) {
    headers.set(
      "content-type",
      "application/json",
    );
  }

  const response = await fetch(
    url,
    {
      ...init,
      method,
      headers,
      signal: AbortSignal.timeout(
        5_000,
      ),
      redirect: "error",
    },
  );

  const contentType =
    response.headers.get(
      "content-type",
    ) || "";

  if (
    !contentType
      .toLowerCase()
      .startsWith(
        "application/json",
      )
  ) {
    throw new Error(
      "Research service returned a non-JSON response",
    );
  }

  const rawContentLength =
    response.headers.get(
      "content-length",
    );

  const contentLength =
    rawContentLength === null
      ? null
      : Number(rawContentLength);

  if (
    contentLength !== null &&
    (
      !Number.isSafeInteger(
        contentLength,
      ) ||
      contentLength < 1 ||
      contentLength
        > MAX_RESPONSE_BYTES
    )
  ) {
    throw new Error(
      "Research response exceeds safety limit",
    );
  }

  const body = await response.text();

  if (
    new TextEncoder()
      .encode(body)
      .byteLength
      > MAX_RESPONSE_BYTES
  ) {
    throw new Error(
      "Research response exceeds safety limit",
    );
  }

  if (!response.ok) {
    throw new Error(
      `Research service failed closed with HTTP ` +
      `${response.status}: ${body.slice(0, 500)}`,
    );
  }

  let payload: unknown;

  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error(
      "Research service returned malformed JSON",
    );
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new Error(
      "Research service returned an invalid JSON payload",
    );
  }

  return body;
}

export async function callResearchJson<T>(
  pathname: string,
): Promise<T> {
  return JSON.parse(
    await callResearch(pathname),
  ) as T;
}

export function postResearchJson(
  pathname: string,
  body: unknown,
): Promise<string> {
  return callResearch(
    pathname,
    {
      method: "POST",
      body: JSON.stringify(body),
    },
  );
}
