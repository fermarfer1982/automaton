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

  it("removes dangerous upstream and installed tools", () => {
    const selected = selectRuntimeTools([
      tool("get_market_snapshot"),
      tool("propose_trade"),
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
      "propose_trade",
    ]);
  });
});
