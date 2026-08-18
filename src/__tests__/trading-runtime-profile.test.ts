import { describe, expect, it } from "vitest";
import type { AutomatonTool } from "../types.js";
import { resolveRuntimeProfile, selectRuntimeTools } from "../trading/runtime-profile.js";

function tool(name: string): AutomatonTool {
  return {
    name,
    description: name,
    category: "trading",
    riskLevel: "safe",
    parameters: { type: "object", properties: {} },
    execute: async () => "ok",
  };
}

describe("trading runtime profile", () => {
  it("defaults to trading_lab", () => {
    expect(resolveRuntimeProfile(undefined)).toBe("trading_lab");
  });

  it("fails closed for unknown profile values", () => {
    expect(() => resolveRuntimeProfile("unsafe")).toThrow();
  });

  it("removes all trading mutation, upstream, and installed tools", () => {
    const selected = selectRuntimeTools([
      tool("get_market_snapshot"),
      tool("record_trading_decision"),
      tool("save_trading_hypothesis"),
      tool("save_trade_review"),
      tool("propose_trade"),
      tool("close_position"),
      tool("modify_position"),
      tool("cancel_pending"),
      tool("remember_fact"),
      tool("save_procedure"),
      tool("set_goal"),
      tool("complete_goal"),
      tool("exec"),
      tool("git_push"),
      tool("transfer_credits"),
      tool("spawn_child"),
      tool("unknown_installed_tool"),
    ], "trading_lab");

    expect(selected.map((entry) => entry.name)).toEqual([
      "get_market_snapshot",
      "record_trading_decision",
      "save_trading_hypothesis",
      "save_trade_review",
    ]);
  });

  it("keeps trading mutation tools available only in upstream profile", () => {
    const tools = [
      tool("propose_trade"),
      tool("close_position"),
      tool("modify_position"),
      tool("cancel_pending"),
    ];

    expect(
      selectRuntimeTools(tools, "upstream").map((entry) => entry.name),
    ).toEqual([
      "propose_trade",
      "close_position",
      "modify_position",
      "cancel_pending",
    ]);
  });
});
