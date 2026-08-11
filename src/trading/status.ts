import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { AgentTurn, AutomatonConfig } from "../types.js";
import { getAutomatonDir } from "../identity/wallet.js";

interface TradingLabRuntimeStatus {
  schemaVersion: 1;
  profile: "trading_lab";
  runtimeWindowsSid: string;
  provider: "openai" | "anthropic" | "ollama";
  model: string;
  runtimeInstanceId: string;
  processStartedAt: string;
  lastTurnAt: string;
  lastInferenceAt: string;
  lastGatewayHealthAt?: string;
  lastMarketObservationAt?: string;
  lastResearchReviewAt?: string;
  lastProposalAt?: string;
}

const STATUS_PATH = path.join(getAutomatonDir(), "trading-lab-runtime-status.json");
const RUNTIME_INSTANCE_ID = randomUUID();
const PROCESS_STARTED_AT = new Date().toISOString();

function readExisting(): Partial<TradingLabRuntimeStatus> {
  try {
    const value = JSON.parse(fs.readFileSync(STATUS_PATH, "utf-8"));
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

export function recordTradingLabTurn(
  turn: AgentTurn,
  config: AutomatonConfig,
  runtimeWindowsSid: string,
): void {
  const provider = config.tradingLabProvider;
  if (!provider) throw new Error("Trading laboratory provider is absent");
  const now = new Date().toISOString();
  const previous = readExisting();
  const sameRuntime = previous.runtimeInstanceId === RUNTIME_INSTANCE_ID;
  const successfulTools = new Set(
    turn.toolCalls.filter((item) => !item.error).map((item) => item.name),
  );
  const status: TradingLabRuntimeStatus = {
    schemaVersion: 1,
    profile: "trading_lab",
    runtimeWindowsSid,
    provider,
    model: config.inferenceModel,
    runtimeInstanceId: RUNTIME_INSTANCE_ID,
    processStartedAt: PROCESS_STARTED_AT,
    lastTurnAt: now,
    lastInferenceAt: now,
    lastGatewayHealthAt: successfulTools.has("trading_lab_status")
      ? now : sameRuntime ? previous.lastGatewayHealthAt : undefined,
    lastMarketObservationAt: successfulTools.has("observe_xauusd")
      ? now : sameRuntime ? previous.lastMarketObservationAt : undefined,
    lastResearchReviewAt: successfulTools.has("review_trading_evidence")
      ? now : sameRuntime ? previous.lastResearchReviewAt : undefined,
    lastProposalAt: successfulTools.has("propose_xauusd_trade")
      ? now : sameRuntime ? previous.lastProposalAt : undefined,
  };
  const temporary = `${STATUS_PATH}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(status, null, 2), { mode: 0o600 });
  fs.renameSync(temporary, STATUS_PATH);
}
