import {
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const calls = vi.hoisted(() => ({
  observation:
    vi.fn().mockResolvedValue("{}"),
  gateway:
    vi.fn().mockResolvedValue("{}"),
  post:
    vi.fn().mockResolvedValue("{}"),
}));

vi.mock(
  "../trading/observation-client.js",
  () => ({
    callObservation:
      calls.observation,
  }),
);

vi.mock(
  "../trading/gateway-client.js",
  () => ({
    callGateway:
      calls.gateway,
    postJson:
      calls.post,
  }),
);

import {
  createTradingTools,
} from "../trading/tools.js";

function getTool(name: string) {
  const result =
    createTradingTools().find(
      (tool) => tool.name === name,
    );

  if (!result) {
    throw new Error(
      `Missing tool: ${name}`,
    );
  }

  return result;
}

async function execute(
  name: string,
  args: Record<string, unknown> = {},
): Promise<void> {
  await getTool(name).execute(
    args,
    {} as any,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe(
  "trading observation routing",
  () => {
    it(
      "routes all seven market/account reads only to Observation Service",
      async () => {
        await execute(
          "trading_lab_status",
        );

        await execute(
          "get_account_state",
        );

        await execute(
          "get_market_snapshot",
        );

        await execute(
          "get_candles",
          {
            timeframe: "M5",
            count: 20,
          },
        );

        await execute(
          "get_positions",
        );

        await execute(
          "get_trade_history",
          {
            from_utc:
              "2026-08-18T10:00:00Z",
            to_utc:
              "2026-08-18T11:00:00Z",
            limit: 100,
          },
        );

        await execute(
          "get_daily_performance",
        );

        expect(
          calls.observation,
        ).toHaveBeenCalledTimes(7);

        const routes =
          calls.observation.mock.calls.map(
            ([route]) => route,
          );

        expect(routes).toEqual([
          "/v1/status",
          "/v1/account",
          "/v1/market/XAUUSD",
          "/v1/candles/XAUUSD?timeframe=M5&count=20",
          "/v1/positions",
          "/v1/history?from=2026-08-18T10%3A00%3A00Z&to=2026-08-18T11%3A00%3A00Z&symbol=XAUUSD&limit=100",
          "/v1/daily-stats",
        ]);

        expect(
          calls.gateway,
        ).not.toHaveBeenCalled();

        expect(
          calls.post,
        ).not.toHaveBeenCalled();
      },
    );

    it(
      "keeps research operations on the existing gateway during B2.1",
      async () => {
        await execute(
          "record_trading_decision",
          {},
        );

        await execute(
          "save_trading_hypothesis",
          {},
        );

        await execute(
          "save_trade_review",
          {},
        );

        await execute(
          "get_strategy_statistics",
        );

        await execute(
          "get_recent_trading_memory",
          {
            limit: 1,
          },
        );

        expect(
          calls.observation,
        ).not.toHaveBeenCalled();

        expect(
          calls.post,
        ).toHaveBeenCalledTimes(3);

        expect(
          calls.post.mock.calls.map(
            ([route]) => route,
          ),
        ).toEqual([
          "/v1/research/decisions",
          "/v1/research/hypotheses",
          "/v1/research/reviews",
        ]);

        expect(
          calls.gateway.mock.calls.map(
            ([route]) => route,
          ),
        ).toEqual([
          "/v1/research/metrics",
          "/v1/research/memory?limit=1",
        ]);
      },
    );
  },
);