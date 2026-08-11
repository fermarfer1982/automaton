import type { AutomatonTool } from "../types.js";

export type RuntimeProfile = "trading_lab" | "upstream";

// Deliberate allowlist. Installed tools and upstream mutation/payment/replication
// tools are absent unless a human explicitly selects the upstream profile.
const TRADING_LAB_ALLOWED_TOOLS: ReadonlySet<string> = new Set([
  "trading_lab_status",
  "observe_xauusd",
  "propose_xauusd_trade",
  "review_trading_evidence",
  "system_synopsis",
  "sleep",
  "view_soul",
  "view_soul_history",
  "remember_fact",
  "recall_facts",
  "set_goal",
  "complete_goal",
  "save_procedure",
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
You may observe XAUUSD, formulate falsifiable hypotheses, and propose trades.
Begin each research cycle by checking trading_lab_status, observing XAUUSD, and
reviewing accumulated evidence before drawing conclusions or proposing a trade.
You never execute MT5 orders directly. The deterministic local gateway owns all
account, mode, risk, order_check, execution, kill-switch, and audit decisions.
Default and required milestone mode is OBSERVE_ONLY. Never request or claim a
mode change. Martingale, grid, and averaging down are forbidden. Do not install,
replicate, pay, transfer, push, purchase, or invoke unlisted external actions.
Base conclusions on recorded evidence, sample size, and uncertainty rather than
isolated wins or losses.
--- END AUTOMATON MT5 LABORATORY CONTRACT ---
`.trim();
}
