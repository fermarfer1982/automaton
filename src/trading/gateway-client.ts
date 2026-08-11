import { randomUUID } from "node:crypto";
import { requireCredentialFreeLoopbackOrigin } from "./network.js";
import { readGatewayApiKey } from "./gateway-auth.js";

const DEFAULT_GATEWAY_URL = "http://127.0.0.1:8765";
const MAX_RESPONSE_BYTES = 1_000_000;

function gatewayUrl(): URL {
  return requireCredentialFreeLoopbackOrigin(
    DEFAULT_GATEWAY_URL,
    "AUTOMATON_MT5_GATEWAY_URL",
  );
}

export async function callGateway(
  pathname: string,
  init?: RequestInit,
): Promise<string> {
  if (!pathname.startsWith("/v1/") || pathname.startsWith("//")) {
    throw new Error("MT5 gateway path must be a relative /v1 route");
  }
  const origin = gatewayUrl();
  const url = new URL(pathname, origin);
  if (url.origin !== origin.origin) {
    throw new Error("MT5 gateway route escaped the loopback origin");
  }
  const headers = new Headers(init?.headers);
  if (headers.has("x-automaton-key")) {
    throw new Error("Gateway callers cannot override the protected API key");
  }
  headers.set("accept", "application/json");
  headers.set("x-automaton-key", readGatewayApiKey());
  if (init?.body) headers.set("content-type", "application/json");
  const response = await fetch(url, {
    ...init,
    headers,
    signal: AbortSignal.timeout(5_000),
    redirect: "error",
  });
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    throw new Error("MT5 gateway returned a non-JSON response");
  }
  const rawContentLength = response.headers.get("content-length");
  const contentLength = rawContentLength === null ? null : Number(rawContentLength);
  if (contentLength !== null && (!Number.isSafeInteger(contentLength) || contentLength < 1 || contentLength > MAX_RESPONSE_BYTES)) {
    throw new Error("MT5 gateway response exceeds safety limit");
  }
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) {
    throw new Error("MT5 gateway response exceeds safety limit");
  }
  if (!response.ok) {
    throw new Error(`MT5 gateway failed closed with HTTP ${response.status}: ${body.slice(0, 500)}`);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    throw new Error("MT5 gateway returned malformed JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("MT5 gateway returned an invalid JSON payload");
  }
  return body;
}

export async function callGatewayJson<T>(pathname: string, init?: RequestInit): Promise<T> {
  return JSON.parse(await callGateway(pathname, init)) as T;
}

export function postJson(pathname: string, body: unknown, idempotent = false): Promise<string> {
  return callGateway(pathname, {
    method: "POST",
    headers: idempotent ? { "Idempotency-Key": randomUUID() } : undefined,
    body: JSON.stringify(body),
  });
}
