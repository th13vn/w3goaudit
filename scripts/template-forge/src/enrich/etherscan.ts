import { cached } from "../util/cache.js";
import type { IncidentMeta } from "../types.js";

// Etherscan v2 multichain API uses a single base + chainid param.
const API = "https://api.etherscan.io/v2/api";

const CHAIN_ID: Record<string, number> = {
  ethereum: 1,
  bsc: 56,
  polygon: 137,
  arbitrum: 42161,
  avalanche: 43114,
  fantom: 250,
  optimism: 10,
  base: 8453,
};

/**
 * Fetch the verified source of the vulnerable contract (best-effort, cached).
 * Returns undefined when no key / no address / not verified.
 */
export async function getVerifiedSource(
  meta: IncidentMeta,
  apiKey: string,
): Promise<string | undefined> {
  if (!apiKey || !meta.vulnerableContract) return undefined;
  const chainId = CHAIN_ID[meta.chain] ?? 1;
  const url =
    `${API}?chainid=${chainId}&module=contract&action=getsourcecode` +
    `&address=${meta.vulnerableContract}&apikey=${apiKey}`;
  try {
    const body = await cached(
      "etherscan-source",
      `${chainId}:${meta.vulnerableContract}`,
      async () => {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`etherscan ${res.status}`);
        return await res.text();
      },
    );
    const json = JSON.parse(body) as {
      result?: { SourceCode?: string }[] | string;
    };
    if (typeof json.result === "string") return undefined; // error message
    const code = json.result?.[0]?.SourceCode;
    return code && code.length > 0 ? code : undefined;
  } catch {
    return undefined; // enrichment is best-effort; never block the pipeline
  }
}

/**
 * Fetch a compact summary of the attack transaction (to/from/value/input head).
 * Best-effort, cached. Full trace would need a tracing RPC; this stays light.
 */
export async function getTxSummary(
  meta: IncidentMeta,
  apiKey: string,
): Promise<string | undefined> {
  if (!apiKey || !meta.attackTx) return undefined;
  const chainId = CHAIN_ID[meta.chain] ?? 1;
  const url =
    `${API}?chainid=${chainId}&module=proxy&action=eth_getTransactionByHash` +
    `&txhash=${meta.attackTx}&apikey=${apiKey}`;
  try {
    const body = await cached(
      "etherscan-tx",
      `${chainId}:${meta.attackTx}`,
      async () => {
        const res = await fetch(url);
        if (!res.ok) throw new Error(`etherscan ${res.status}`);
        return await res.text();
      },
    );
    const json = JSON.parse(body) as {
      result?: { to?: string; from?: string; value?: string; input?: string };
    };
    const r = json.result;
    if (!r) return undefined;
    return [
      `from: ${r.from}`,
      `to: ${r.to}`,
      `value: ${r.value}`,
      `input[0:138]: ${(r.input ?? "").slice(0, 138)}`,
    ].join("\n");
  } catch {
    return undefined;
  }
}
