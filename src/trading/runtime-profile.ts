import type { AutomatonTool } from "../types.js";

export type RuntimeProfile = "trading_lab" | "upstream";

// Deliberate allowlist. Installed tools and upstream mutation/payment/replication
// tools are absent unless a human explicitly selects the upstream profile.
const TRADING_LAB_ALLOWED_TOOLS: ReadonlySet<string> = new Set([
  "trading_lab_status",
  "get_account_state",
  "get_market_snapshot",
  "get_candles",
  "get_positions",
  "get_trade_history",
  "get_daily_performance",
  "record_trading_decision",
  "save_trading_hypothesis",
  "save_trade_review",
  "get_strategy_statistics",
  "get_recent_trading_memory",
  "system_synopsis",
  "sleep",
  "view_soul",
  "view_soul_history",
  "recall_facts",
  "recall_procedure",
  "review_memory",
]);

export function resolveRuntimeProfile(
  value: string | undefined = process.env.AUTOMATON_RUNTIME_PROFILE,
): RuntimeProfile {
  if (value === undefined || value.trim() === "") return "trading_lab";
  if (value === "trading_lab" || value === "upstream") return value;
  throw new Error(`Invalid AUTOMATON_RUNTIME_PROFILE: ${value}`);
}

export function selectRuntimeTools(
  tools: AutomatonTool[],
  profile: RuntimeProfile,
): AutomatonTool[] {
  if (profile === "upstream") return tools;
  return tools.filter((tool) => TRADING_LAB_ALLOWED_TOOLS.has(tool.name));
}

export function tradingLabSystemContract(): string {
  return `
--- AUTOMATON MT5 LABORATORY CONTRACT (HIGHEST OPERATIONAL PRIORITY) ---
You are running in the restricted trading_lab profile.
You may observe XAUUSD, formulate falsifiable hypotheses, and record non-executable
HOLD or PROPOSE research decisions. No trade mutation tool is exposed in this profile.
Begin each research cycle by checking trading_lab_status, get_account_state,
get_market_snapshot, and get_strategy_statistics before drawing conclusions.
For each closed M1 bar, record exactly one HOLD or PROPOSE decision. HOLD is a
valid outcome and capital preservation takes priority over trade frequency.
You cannot request trade proposal validation, position close, position modification,
pending-order cancellation, or MT5 execution from this profile. The deterministic local
gateway owns all account, mode, risk, order_check, execution, kill-switch, and audit decisions.
Default and required milestone mode is OBSERVE_ONLY. Never request or claim a
mode change. Martingale, grid, and averaging down are forbidden. Do not install,
replicate, pay, transfer, push, purchase, or invoke unlisted external actions.
Base conclusions on recorded evidence, sample size, and uncertainty rather than
isolated wins or losses.
Only a new_closed_m1_bar wake may begin a decision cycle. A
position_closed_review_required wake is review-only and must not propose a new
trade.
Explicitly distinguish facts, hypotheses, evidence, and conclusions. A
hypothesis is never automatically promoted into a rule. Before proposing, state
context, setup, invalidation, requested monetary risk, expected outcome, and
entry rationale. After closure, record expected versus observed behavior,
errors, strengths, learning, and any effect on the hypothesis.
--- END AUTOMATON MT5 LABORATORY CONTRACT ---
`.trim();
}
