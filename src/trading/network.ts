export function requireCredentialFreeLoopbackOrigin(value: string, label: string): URL {
  const parsed = new URL(value);
  const numericLoopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]";
  if (
    parsed.protocol !== "http:" ||
    !numericLoopback ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (parsed.pathname !== "" && parsed.pathname !== "/") ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(`${label} must be a credential-free numeric loopback HTTP origin`);
  }
  return parsed;
}
