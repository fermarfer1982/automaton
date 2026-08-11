import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentTurn } from "../types.js";

const { callGatewayJson } = vi.hoisted(() => ({ callGatewayJson: vi.fn() }));
vi.mock("../trading/gateway-client.js", () => ({ callGatewayJson }));

import { recordProcessedTradingBar, TradingHeartbeat } from "../trading/heartbeat.js";

class MemoryStore {
  readonly values = new Map<string, string>();
  getKV(key: string): string | undefined { return this.values.get(key); }
  setKV(key: string, value: string): void { this.values.set(key, value); }
}

beforeEach(() => callGatewayJson.mockReset());

describe("closed-bar trading heartbeat", () => {
  it("wakes once for a new closed M1 bar and persists only a matching decision", async () => {
    const barTime = Date.parse("2026-08-11T10:00:00.000Z");
    callGatewayJson.mockImplementation(async (route: string) => {
      if (route === "/v1/health") return { exposure: { position_count: 0 } };
      return { candles: [{ time_msc: barTime }] };
    });
    const store = new MemoryStore();
    const wake = vi.fn();
    const heartbeat = new TradingHeartbeat(store, wake, vi.fn());

    await heartbeat.pollOnce();
    await heartbeat.pollOnce();
    expect(wake).toHaveBeenCalledTimes(1);
    expect(wake).toHaveBeenCalledWith("new_closed_m1_bar:2026-08-11T10:00:00.000Z");

    const turn = {
      toolCalls: [{
        name: "record_trading_decision",
        arguments: { bar_time_utc: "2026-08-11T10:00:00Z" },
      }],
    } as AgentTurn;
    recordProcessedTradingBar(turn, store);
    expect(store.getKV("trading.last_processed_bar.XAUUSD.M1"))
      .toBe("2026-08-11T10:00:00.000Z");
  });

  it("polls positions every cycle while exposed and wakes on closure", async () => {
    let positionCount = 1;
    callGatewayJson.mockImplementation(async (route: string) => {
      if (route === "/v1/health") return { exposure: { position_count: 1 } };
      if (route === "/v1/positions") return { count: positionCount };
      return { candles: [] };
    });
    const wake = vi.fn();
    const heartbeat = new TradingHeartbeat(new MemoryStore(), wake, vi.fn());

    await heartbeat.pollOnce();
    positionCount = 0;
    await heartbeat.pollOnce();
    expect(callGatewayJson).toHaveBeenCalledWith("/v1/positions");
    expect(wake).toHaveBeenCalledWith("position_closed_review_required");
  });
});
