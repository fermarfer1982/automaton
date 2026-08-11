import type { AgentTurn } from "../types.js";
import { callGatewayJson } from "./gateway-client.js";

const BAR_KEY = "trading.last_processed_bar.XAUUSD.M1";
const WAKE_KEY = "trading.last_wake_bar.XAUUSD.M1";

interface KVStore {
  getKV(key: string): string | undefined;
  setKV(key: string, value: string): void;
}

interface CandlesResponse {
  candles?: Array<{ time_msc?: number }>;
}

interface HealthResponse {
  exposure?: { position_count?: number };
}

interface PositionsResponse {
  count?: number;
}

export function recordProcessedTradingBar(turn: AgentTurn, store: KVStore): void {
  const decision = turn.toolCalls.find(
    (call) => call.name === "record_trading_decision" && !call.error,
  );
  const timestamp = decision?.arguments.bar_time_utc;
  if (typeof timestamp !== "string" || !Number.isFinite(Date.parse(timestamp))) return;
  const normalized = new Date(timestamp).toISOString();
  if (store.getKV(WAKE_KEY) !== normalized) return;
  store.setKV(BAR_KEY, normalized);
}

export class TradingHeartbeat {
  private timer: ReturnType<typeof setInterval> | undefined;
  private inFlight = false;
  private lastHealthAt = 0;
  private previousPositionCount: number | undefined;

  constructor(
    private readonly store: KVStore,
    private readonly onWake: (reason: string) => void,
    private readonly onError: (message: string) => void,
  ) {}

  start(): void {
    if (this.timer) return;
    void this.tick();
    this.timer = setInterval(() => void this.tick(), 5_000);
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  async pollOnce(): Promise<void> {
    if (this.inFlight) return;
    this.inFlight = true;
    try {
      const now = Date.now();
      let positionCount = this.previousPositionCount;
      if (now - this.lastHealthAt >= 30_000) {
        const health = await callGatewayJson<HealthResponse>("/v1/health");
        positionCount = Number(health.exposure?.position_count || 0);
        this.lastHealthAt = now;
      }
      if ((positionCount || 0) > 0) {
        const positions = await callGatewayJson<PositionsResponse>("/v1/positions");
        positionCount = Number(positions.count || 0);
      }
      const candles = await callGatewayJson<CandlesResponse>(
        "/v1/candles/XAUUSD?timeframe=M1&count=1",
      );
      const barTimeMsc = candles.candles?.[0]?.time_msc;
      if (typeof barTimeMsc === "number" && Number.isFinite(barTimeMsc)) {
        const normalized = new Date(barTimeMsc).toISOString();
        const processed = this.store.getKV(BAR_KEY);
        const lastWake = this.store.getKV(WAKE_KEY);
        if ((!processed || normalized > processed) && normalized !== lastWake) {
          this.store.setKV(WAKE_KEY, normalized);
          this.onWake(`new_closed_m1_bar:${normalized}`);
        }
      }
      if (this.previousPositionCount !== undefined && this.previousPositionCount > 0 && positionCount === 0) {
        this.onWake("position_closed_review_required");
      }
      this.previousPositionCount = positionCount;
    } catch (error) {
      this.onError(error instanceof Error ? error.message : "trading heartbeat failed closed");
    } finally {
      this.inFlight = false;
    }
  }

  private tick(): Promise<void> {
    return this.pollOnce();
  }
}
