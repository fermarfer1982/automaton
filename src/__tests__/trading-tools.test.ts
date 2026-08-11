import { beforeEach, describe, expect, it, vi } from "vitest";

const gateway = vi.hoisted(() => ({
  callGateway: vi.fn().mockResolvedValue("{}"),
  postJson: vi.fn().mockResolvedValue("{}"),
}));
vi.mock("../trading/gateway-client.js", () => gateway);

import { createTradingTools } from "../trading/tools.js";

beforeEach(() => {
  gateway.callGateway.mockClear();
  gateway.postJson.mockClear();
});

describe("trading tool boundary", () => {
  it("exposes the guarded research and management API without MT5 controls", () => {
    const names = createTradingTools().map((tool) => tool.name);
    expect(names).toEqual([
      "trading_lab_status", "get_account_state", "get_market_snapshot", "get_candles",
      "get_positions", "get_trade_history", "get_daily_performance",
      "record_trading_decision", "propose_trade", "close_position", "modify_position",
      "cancel_pending", "save_trading_hypothesis", "save_trade_review",
      "get_strategy_statistics", "get_recent_trading_memory",
    ]);
  });

  it("does not let a proposal select volume, magic, account, server, or mode", async () => {
    const tool = createTradingTools().find((item) => item.name === "propose_trade");
    expect(tool).toBeDefined();
    const properties = (tool?.parameters.properties || {}) as Record<string, unknown>;
    for (const forbidden of ["volume", "magic", "magic_number", "account", "server", "mode", "trading_mode"]) {
      expect(properties).not.toHaveProperty(forbidden);
    }
    await tool?.execute({ symbol: "XAUUSD" }, {} as never);
    expect(gateway.postJson).toHaveBeenCalledWith(
      "/v1/trade/propose",
      { symbol: "XAUUSD" },
      true,
    );
  });
});
