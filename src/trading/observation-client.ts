import {
  requireCredentialFreeLoopbackOrigin,
} from "./network.js";

import {
  readObservationApiKey,
} from "./observation-auth.js";

const DEFAULT_OBSERVATION_URL =
  "http://127.0.0.1:8766";

const MAX_RESPONSE_BYTES = 1_000_000;

function observationUrl(): URL {
  return requireCredentialFreeLoopbackOrigin(
    DEFAULT_OBSERVATION_URL,
    "AUTOMATON_MT5_OBSERVATION_URL",
  );
}

export async function callObservation(
  pathname: string,
): Promise<string> {
  if (
    !pathname.startsWith("/v1/") ||
    pathname.startsWith("//")
  ) {
    throw new Error(
      "Observation path must be a relative /v1 route",
    );
  }

  const origin = observationUrl();

  const url = new URL(
    pathname,
    origin,
  );

  if (
    url.origin !== origin.origin ||
    !url.pathname.startsWith("/v1/")
  ) {
    throw new Error(
      "Observation route escaped the protected /v1 boundary",
    );
  }

  const headers = new Headers();

  headers.set(
    "accept",
    "application/json",
  );

  headers.set(
    "x-automaton-observation-key",
    readObservationApiKey(),
  );

  const response = await fetch(
    url,
    {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(5_000),
      redirect: "error",
    },
  );

  const contentType =
    response.headers.get("content-type") || "";

  if (
    !contentType
      .toLowerCase()
      .startsWith("application/json")
  ) {
    throw new Error(
      "Observation service returned a non-JSON response",
    );
  }

  const rawContentLength =
    response.headers.get("content-length");

  const contentLength =
    rawContentLength === null
      ? null
      : Number(rawContentLength);

  if (
    contentLength !== null &&
    (
      !Number.isSafeInteger(contentLength) ||
      contentLength < 1 ||
      contentLength > MAX_RESPONSE_BYTES
    )
  ) {
    throw new Error(
      "Observation response exceeds safety limit",
    );
  }

  const body = await response.text();

  if (
    new TextEncoder()
      .encode(body)
      .byteLength > MAX_RESPONSE_BYTES
  ) {
    throw new Error(
      "Observation response exceeds safety limit",
    );
  }

  if (!response.ok) {
    throw new Error(
      `Observation service failed closed with HTTP ` +
      `${response.status}: ${body.slice(0, 500)}`,
    );
  }

  let payload: unknown;

  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error(
      "Observation service returned malformed JSON",
    );
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new Error(
      "Observation service returned an invalid JSON payload",
    );
  }

  return body;
}

export async function callObservationJson<T>(
  pathname: string,
): Promise<T> {
  return JSON.parse(
    await callObservation(pathname),
  ) as T;
}