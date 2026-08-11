import type { AutomatonTool } from "../types.js";
import { requireCredentialFreeLoopbackOrigin } from "./network.js";

const DEFAULT_GATEWAY_URL = "http://127.0.0.1:8765";
const MAX_RESPONSE_BYTES = 1_000_000;

function gatewayUrl(): URL {
  return requireCredentialFreeLoopbackOrigin(
    DEFAULT_GATEWAY_URL,
    "AUTOMATON_MT5_GATEWAY_URL",
  );
}

async function callGateway(
  pathname: string,
  init?: RequestInit,
): Promise<string> {
  const url = new URL(pathname, gatewayUrl());
  const response = await fetch(url, {
    ...init,
    headers: {
      "accept": "application/json",
      ...(init?.body ? { "content-type": "application/json" } : {}),
    },
    signal: AbortSignal.timeout(5_000),
    redirect: "error",
  });
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (contentLength > MAX_RESPONSE_BYTES) {
    throw new Error("MT5 gateway response exceeds safety limit");
  }
  const body = await response.text();
  if (body.length > MAX_RESPONSE_BYTES) {
    throw new Error("MT5 gateway response exceeds safety limit");
  }
  if (!response.ok) {
    throw new Error(`MT5 gateway failed closed with HTTP ${response.status}: ${body.slice(0, 500)}`);
  }
  return body;
}

export function createTradingTools(): AutomatonTool[] {
  return [
    {
      name: "trading_lab_status",
      description: "Read sanitized health, mode, account-guard, XAUUSD market-data, and audit status from the local deterministic MT5 gateway.",
      category: "trading",
      riskLevel: "safe",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => callGateway("/v1/health"),
    },
    {
      name: "observe_xauusd",
      description: "Read the current XAUUSD bid, ask, spread, point, stop level, and volume constraints through the guarded local gateway.",
      category: "trading",
      riskLevel: "safe",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => callGateway("/v1/market/XAUUSD"),
    },
    {
      name: "review_trading_evidence",
      description: "Read strategy/version sample sizes and objective PnL, R, MFE, MAE, drawdown, expectancy, profit-factor, and evidence-sufficiency metrics from gateway-owned memory.",
      category: "trading",
      riskLevel: "safe",
      parameters: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => callGateway("/v1/research/metrics"),
    },
    {
      name: "propose_xauusd_trade",
      description: "Submit a research proposal for deterministic validation. This tool cannot select an account, change mode, or call MT5 execution directly.",
      category: "trading",
      riskLevel: "caution",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          proposal_id: { type: "string", maxLength: 128 },
          hypothesis_id: { type: "string", maxLength: 128 },
          strategy_id: { type: "string", maxLength: 128 },
          setup_id: { type: "string", maxLength: 128 },
          strategy_version: { type: "string", maxLength: 128 },
          symbol: { type: "string", enum: ["XAUUSD"] },
          side: { type: "string", enum: ["BUY", "SELL"] },
          volume: { type: "number", exclusiveMinimum: 0 },
          stop_loss: { type: ["number", "null"] },
          take_profit: { type: ["number", "null"] },
          magic_number: { type: "integer", minimum: 1 },
          position_management: { type: "string", enum: ["SINGLE_ENTRY"] },
          thesis: { type: "string", minLength: 1, maxLength: 4000 },
          session: { type: "string", maxLength: 128 },
          market_regime: { type: "string", maxLength: 128 },
        },
        required: [
          "proposal_id", "hypothesis_id", "strategy_id", "setup_id",
          "strategy_version", "symbol", "side", "volume", "stop_loss",
          "take_profit", "magic_number", "position_management", "thesis",
          "session", "market_regime",
        ],
      },
      execute: async (args) => callGateway("/v1/proposals", {
        method: "POST",
        body: JSON.stringify(args),
      }),
    },
  ];
}
