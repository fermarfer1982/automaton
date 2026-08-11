import type { AutomatonTool } from "../types.js";
import { callGateway, postJson } from "./gateway-client.js";

const noParameters = { type: "object", properties: {}, additionalProperties: false } as const;

export function createTradingTools(): AutomatonTool[] {
  return [
    {
      name: "trading_lab_status",
      description: "Read sanitized mode, identity, account-guard, market-data, exposure, and audit status.",
      category: "trading",
      riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/status"),
    },
    {
      name: "get_account_state",
      description: "Read sanitized DEMO account state and risk currency without receiving login or server identifiers.",
      category: "trading",
      riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/account"),
    },
    {
      name: "get_market_snapshot",
      description: "Read a compact XAUUSD snapshot with closed M1/M5/M15/H1 context, ATR, sessions, positions, and daily state.",
      category: "trading",
      riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/market/XAUUSD"),
    },
    {
      name: "get_candles",
      description: "Read a bounded series of closed XAUUSD candles for one allowed timeframe.",
      category: "trading",
      riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          timeframe: { type: "string", enum: ["M1", "M5", "M15", "H1"] },
          count: { type: "integer", minimum: 1, maximum: 500 },
        },
        required: ["timeframe", "count"],
      },
      execute: async (args) => callGateway(
        `/v1/candles/XAUUSD?timeframe=${encodeURIComponent(String(args.timeframe))}&count=${encodeURIComponent(String(args.count))}`,
      ),
    },
    {
      name: "get_positions",
      description: "Read current positions through the guarded gateway.",
      category: "trading",
      riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/positions"),
    },
    {
      name: "get_trade_history",
      description: "Read bounded XAUUSD deal history between timezone-aware UTC timestamps.",
      category: "trading",
      riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          from_utc: { type: "string", format: "date-time" },
          to_utc: { type: "string", format: "date-time" },
          limit: { type: "integer", minimum: 1, maximum: 1000 },
        },
        required: ["from_utc", "to_utc", "limit"],
      },
      execute: async (args) => {
        const query = new URLSearchParams({
          from: String(args.from_utc), to: String(args.to_utc),
          symbol: "XAUUSD", limit: String(args.limit),
        });
        return callGateway(`/v1/history?${query.toString()}`);
      },
    },
    {
      name: "get_daily_performance",
      description: "Read current UTC-day performance and exposure from the guarded account.",
      category: "trading",
      riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/daily-stats"),
    },
    {
      name: "record_trading_decision",
      description: "Persist one evidence-oriented HOLD or PROPOSE decision for a closed bar.",
      category: "trading",
      riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          decision_id: { type: "string", minLength: 1, maxLength: 128 },
          action: { type: "string", enum: ["HOLD", "PROPOSE"] },
          symbol: { type: "string", enum: ["XAUUSD"] },
          timeframe: { type: "string", enum: ["M1"] },
          bar_time_utc: { type: "string", format: "date-time" },
          reason: { type: "string", minLength: 1, maxLength: 4000 },
          hypothesis_id: { type: ["string", "null"], maxLength: 128 },
        },
        required: ["decision_id", "action", "symbol", "timeframe", "bar_time_utc", "reason", "hypothesis_id"],
      },
      execute: async (args) => postJson("/v1/research/decisions", args),
    },
    {
      name: "propose_trade",
      description: "Request deterministic validation of one XAUUSD market hypothesis. The gateway alone generates protected execution details and position size from monetary risk.",
      category: "trading",
      riskLevel: "caution",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          action: { type: "string", enum: ["OPEN_LONG", "OPEN_SHORT"] },
          symbol: { type: "string", enum: ["XAUUSD"] },
          entry_type: { type: "string", enum: ["MARKET"] },
          stop_loss: { type: "number", exclusiveMinimum: 0 },
          take_profit: { type: ["number", "null"], exclusiveMinimum: 0 },
          requested_risk_amount: { type: "number", exclusiveMinimum: 0 },
          hypothesis_id: { type: "string", minLength: 1, maxLength: 128 },
          strategy_id: { type: "string", minLength: 1, maxLength: 128 },
          setup_id: { type: "string", minLength: 1, maxLength: 128 },
          strategy_version: { type: "string", minLength: 1, maxLength: 128 },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          reason: { type: "string", minLength: 1, maxLength: 4000 },
          timeframe: { type: "string", enum: ["M1", "M5", "M15", "H1"] },
          market_regime: { type: "string", minLength: 1, maxLength: 128 },
        },
        required: [
          "action", "symbol", "entry_type", "stop_loss", "take_profit",
          "requested_risk_amount", "hypothesis_id", "strategy_id", "setup_id",
          "strategy_version", "confidence", "reason", "timeframe", "market_regime",
        ],
      },
      execute: async (args) => postJson("/v1/trade/propose", args, true),
    },
    {
      name: "close_position",
      description: "Request a full close of an owned XAUUSD position; OBSERVE_ONLY always denies execution.",
      category: "trading", riskLevel: "caution",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          ticket: { type: "integer", minimum: 1 },
          reason: { type: "string", minLength: 1, maxLength: 1000 },
        }, required: ["ticket", "reason"],
      },
      execute: async (args) => postJson("/v1/trade/close", args),
    },
    {
      name: "modify_position",
      description: "Request a risk-reducing SL/TP modification; widening or removing SL is forbidden.",
      category: "trading", riskLevel: "caution",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          ticket: { type: "integer", minimum: 1 },
          stop_loss: { type: "number", exclusiveMinimum: 0 },
          take_profit: { type: ["number", "null"], exclusiveMinimum: 0 },
          reason: { type: "string", minLength: 1, maxLength: 1000 },
        }, required: ["ticket", "stop_loss", "take_profit", "reason"],
      },
      execute: async (args) => postJson("/v1/trade/modify", args),
    },
    {
      name: "cancel_pending",
      description: "Request cancellation of an owned XAUUSD pending order.",
      category: "trading", riskLevel: "caution",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          ticket: { type: "integer", minimum: 1 },
          reason: { type: "string", minLength: 1, maxLength: 1000 },
        }, required: ["ticket", "reason"],
      },
      execute: async (args) => postJson("/v1/trade/cancel-pending", args),
    },
    {
      name: "save_trading_hypothesis",
      description: "Persist a falsifiable hypothesis without promoting it to a rule.",
      category: "trading", riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          hypothesis_id: { type: "string", minLength: 1, maxLength: 128 },
          thesis: { type: "string", minLength: 1, maxLength: 4000 },
        }, required: ["hypothesis_id", "thesis"],
      },
      execute: async (args) => postJson("/v1/research/hypotheses", args),
    },
    {
      name: "save_trade_review",
      description: "Persist a structured post-trade review tied to a closed trade.",
      category: "trading", riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: {
          review_id: { type: "string", minLength: 1, maxLength: 128 },
          trade_id: { type: "string", minLength: 1, maxLength: 128 },
          expected: { type: "string", minLength: 1, maxLength: 4000 },
          observed: { type: "string", minLength: 1, maxLength: 4000 },
          errors: { type: "string", maxLength: 4000 },
          strengths: { type: "string", maxLength: 4000 },
          learning: { type: "string", minLength: 1, maxLength: 4000 },
          hypothesis_effect: { type: "string", minLength: 1, maxLength: 1000 },
        }, required: [
          "review_id", "trade_id", "expected", "observed", "errors",
          "strengths", "learning", "hypothesis_effect",
        ],
      },
      execute: async (args) => postJson("/v1/research/reviews", args),
    },
    {
      name: "get_strategy_statistics",
      description: "Read sample sizes and objective PnL, R, MFE, MAE, drawdown, expectancy, and profit-factor evidence.",
      category: "trading", riskLevel: "safe",
      parameters: noParameters,
      execute: async () => callGateway("/v1/research/metrics"),
    },
    {
      name: "get_recent_trading_memory",
      description: "Read bounded structured trading memory from the gateway-owned research store.",
      category: "trading", riskLevel: "safe",
      parameters: {
        type: "object", additionalProperties: false,
        properties: { limit: { type: "integer", minimum: 1, maximum: 200 } },
        required: ["limit"],
      },
      execute: async (args) => callGateway(`/v1/research/memory?limit=${encodeURIComponent(String(args.limit))}`),
    },
  ];
}
