import { createConfig, saveConfig } from "../config.js";
import { getAutomatonDir } from "../identity/wallet.js";
import type { AutomatonConfig, TreasuryPolicy } from "../types.js";
import { requireCredentialFreeLoopbackOrigin } from "./network.js";
import { getOrCreateTradingLabIdentity } from "./identity.js";
import { getCurrentWindowsIdentityProof } from "./windows-identity.js";
import { readObservationApiKey } from "./observation-auth.js";
import { readResearchApiKey } from "./research-auth.js";

const ZERO_TREASURY_POLICY: TreasuryPolicy = Object.freeze({
  maxSingleTransferCents: 0,
  maxHourlyTransferCents: 0,
  maxDailyTransferCents: 0,
  minimumReserveCents: 0,
  maxX402PaymentCents: 0,
  x402AllowedDomains: [],
  transferCooldownMs: 86_400_000,
  maxTransfersPerTurn: 0,
  maxInferenceDailyCents: 0,
  requireConfirmationAboveCents: 0,
});

const LAB_GENESIS_PROMPT = `
Operate exclusively as an evidence-driven XAUUSD research agent.
Observe market data through the trading tools, formulate falsifiable hypotheses,
submit only SINGLE_ENTRY proposals, record outcomes, and compare strategy/setup
versions with adequate sample sizes. Never execute MT5 directly. Never use
martingale, grid, or averaging down. Never install, replicate, pay, transfer,
purchase, push, register, or change protected security infrastructure.
`.trim();

export function createTradingLabConfigFromEnvironment(): AutomatonConfig {
  // Validate only the dedicated read/research credential paths and file shapes.
  // Secret values are never persisted in Automaton configuration or exposed
  // to the model.
  readObservationApiKey();
  readResearchApiKey();
  const providerValue = (process.env.AUTOMATON_LAB_PROVIDER || "").toLowerCase();
  if (!new Set(["openai", "anthropic", "ollama"]).has(providerValue)) {
    throw new Error("AUTOMATON_LAB_PROVIDER must be openai, anthropic, or ollama");
  }
  const provider = providerValue as "openai" | "anthropic" | "ollama";
  const model = (process.env.AUTOMATON_LAB_MODEL || "").trim();
  if (!model) throw new Error("AUTOMATON_LAB_MODEL is required");

  let ollamaBaseUrl: string | undefined;
  if (provider === "ollama") {
    ollamaBaseUrl = process.env.OLLAMA_BASE_URL;
    if (!ollamaBaseUrl) throw new Error("OLLAMA_BASE_URL is required for the ollama provider");
    requireCredentialFreeLoopbackOrigin(ollamaBaseUrl, "OLLAMA_BASE_URL");
  }

  const windowsIdentity = getCurrentWindowsIdentityProof();
  if (windowsIdentity.isAdministrator) {
    throw new Error("Automaton trading laboratory setup must run as a non-administrator identity");
  }

  const publicIdentity = getOrCreateTradingLabIdentity();
  const walletAddress = publicIdentity.address;

  const config = createConfig({
    name: process.env.AUTOMATON_LAB_NAME || "Automaton MT5 Researcher",
    genesisPrompt: LAB_GENESIS_PROMPT,
    creatorAddress: walletAddress,
    registeredWithConway: false,
    sandboxId: "trading-lab-local",
    walletAddress,
    apiKey: "",
    ollamaBaseUrl,
    treasuryPolicy: ZERO_TREASURY_POLICY,
    chainType: "evm",
  });
  config.inferenceModel = model;
  config.tradingLabProvider = provider;
  config.tradingLabStateDir = getAutomatonDir();
  config.tradingLabWindowsSid = windowsIdentity.sid;
  config.maxChildren = 0;
  config.socialRelayUrl = undefined;
  config.modelStrategy = {
    inferenceModel: model,
    lowComputeModel: model,
    criticalModel: model,
    maxTokensPerTurn: config.maxTokensPerTurn,
    hourlyBudgetCents: 0,
    sessionBudgetCents: 0,
    perCallCeilingCents: 0,
    enableModelFallback: false,
    anthropicApiVersion: "2023-06-01",
  };
  return config;
}

export function runTradingLabSetup(): AutomatonConfig {
  const config = createTradingLabConfigFromEnvironment();
  saveConfig(config);
  return config;
}
