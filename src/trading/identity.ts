import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import type { PrivateKeyAccount } from "viem";
import { getAutomatonDir } from "../identity/wallet.js";
import type { ChainIdentity } from "../identity/chain.js";

interface TradingLabIdentityFile {
  schemaVersion: 1;
  address: `0x${string}`;
  createdAt: string;
}

const IDENTITY_FILE = path.join(getAutomatonDir(), "trading-lab-identity.json");

function nonSigningAccount(address: `0x${string}`): PrivateKeyAccount {
  const disabled = () => {
    throw new Error("Signing is unavailable in the trading laboratory identity");
  };
  return {
    address,
    publicKey: "0x" as `0x${string}`,
    source: "custom",
    type: "local",
    signMessage: disabled as any,
    signTypedData: disabled as any,
    signTransaction: disabled as any,
    sign: disabled as any,
  } as unknown as PrivateKeyAccount;
}

function validateIdentity(value: unknown): TradingLabIdentityFile {
  if (!value || typeof value !== "object") throw new Error("Trading laboratory identity is invalid");
  const item = value as Record<string, unknown>;
  if (
    Object.keys(item).sort().join(",") !== "address,createdAt,schemaVersion" ||
    item.schemaVersion !== 1 ||
    typeof item.address !== "string" ||
    !/^0x[a-f0-9]{40}$/.test(item.address) ||
    typeof item.createdAt !== "string" ||
    !Number.isFinite(Date.parse(item.createdAt))
  ) {
    throw new Error("Trading laboratory identity schema is invalid");
  }
  return item as unknown as TradingLabIdentityFile;
}

export function tradingLabIdentityExists(): boolean {
  return fs.existsSync(IDENTITY_FILE);
}

export function loadTradingLabIdentity(): {
  account: PrivateKeyAccount;
  chainIdentity: ChainIdentity;
  chainType: "evm";
  address: string;
} {
  if (!fs.existsSync(IDENTITY_FILE)) {
    throw new Error("Trading laboratory public identity is absent; run --setup-trading-lab explicitly");
  }
  const value = validateIdentity(JSON.parse(fs.readFileSync(IDENTITY_FILE, "utf-8")));
  const account = nonSigningAccount(value.address);
  const chainIdentity: ChainIdentity = {
    chainType: "evm",
    address: value.address,
    signMessage: async () => {
      throw new Error("Signing is unavailable in the trading laboratory identity");
    },
  };
  return { account, chainIdentity, chainType: "evm", address: value.address };
}

export function getOrCreateTradingLabIdentity(): ReturnType<typeof loadTradingLabIdentity> {
  if (!fs.existsSync(IDENTITY_FILE)) {
    const directory = getAutomatonDir();
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const identity: TradingLabIdentityFile = {
      schemaVersion: 1,
      // Random public identifier only. No private key or signing material exists.
      address: `0x${randomBytes(20).toString("hex")}`,
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(IDENTITY_FILE, JSON.stringify(identity, null, 2), {
      mode: 0o600,
      flag: "wx",
    });
  }
  return loadTradingLabIdentity();
}
