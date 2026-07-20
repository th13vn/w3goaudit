import { createHash } from "node:crypto";
import { IncidentMeta, Candidate, normalizeSeverity } from "../types.js";
import type { Repo } from "../store/repo.js";

const REPO = "SunWeb3Sec/DeFiHackLabs";
const TEST_ROOT = "src/test";

// Map an explorer host to a chain name.
const EXPLORER_CHAIN: Record<string, string> = {
  "etherscan.io": "ethereum",
  "bscscan.com": "bsc",
  "polygonscan.com": "polygon",
  "arbiscan.io": "arbitrum",
  "snowtrace.io": "avalanche",
  "ftmscan.com": "fantom",
  "optimistic.etherscan.io": "optimism",
  "basescan.org": "base",
};

function addrFromLine(text: string, label: string): string | undefined {
  const re = new RegExp(
    `//\\s*${label}\\s*:\\s*\\S*?(0x[a-fA-F0-9]{40})`,
    "i",
  );
  return text.match(re)?.[1];
}

function txFromLine(text: string, label: string): string | undefined {
  const re = new RegExp(`//\\s*${label}\\s*:\\s*\\S*?(0x[a-fA-F0-9]{64})`, "i");
  return text.match(re)?.[1];
}

/**
 * Extract the inline human-written root-cause prose from the PoC header. PoCs
 * frequently include a `// @Analysis` block describing the exploit; that text
 * is the best root cause and needs no network fetch. We collect comment lines
 * from the header that are prose — skipping section markers (`@KeyInfo`,
 * `@Info`, `@Analysis`), `Label : value` lines (addresses / tx / links), and
 * bare URLs.
 */
export function extractAnalysis(src: string): string {
  const prose: string[] = [];
  for (const raw of src.split("\n")) {
    const line = raw.trim();
    if (/^(interface|contract|library|abstract\s+contract)\b/.test(line)) break;
    if (!line.startsWith("//")) continue;
    const c = line.replace(/^\/+/, "").trim();
    if (!c) continue;
    if (c.startsWith("@")) continue; // @KeyInfo / @Info / @Analysis
    if (/^[A-Za-z][\w .\-]*:\s*\S/.test(c)) continue; // "Label : value"
    if (/^https?:\/\/\S+$/.test(c)) continue; // bare URL
    prose.push(c);
  }
  return prose.join(" ").replace(/\s+/g, " ").trim();
}

/** Detect the chain from any explorer host present in the PoC (longest host first). */
function detectChain(src: string, forkNetwork?: string): string {
  const hosts = Object.keys(EXPLORER_CHAIN).sort((a, b) => b.length - a.length);
  const found = hosts.find((h) => src.includes(h));
  if (found) return EXPLORER_CHAIN[found]!;
  if (forkNetwork) return forkNetwork.toLowerCase();
  return "ethereum";
}

/** Parse the header metadata of a DeFiHackLabs `*_exp.sol` PoC. */
export function parsePoc(src: string, repoPath: string): IncidentMeta {
  const name = (repoPath.split("/").pop() ?? repoPath).replace(
    /_exp\.sol$/i,
    "",
  );
  const date = repoPath.match(/(\d{4}-\d{2})/)?.[1];

  const lossText = src
    .match(/@KeyInfo\s*-\s*Total\s*Lost\s*:\s*(.+)/i)?.[1]
    ?.trim();

  const attacker = addrFromLine(src, "Attacker");
  const attackContract = addrFromLine(src, "Attack Contract");
  const vulnerableContract = addrFromLine(src, "Vulnerable Contract");
  const attackTx = txFromLine(src, "Attack Tx");

  // Reference links: all http(s) URLs in comment lines that are NOT the
  // attacker/attack/victim/tx explorer links (i.e. blogs, post-mortems, tweets).
  const known = new Set(
    [attacker, attackContract, vulnerableContract, attackTx].filter(
      Boolean,
    ) as string[],
  );
  const references: string[] = [];
  for (const line of src.split("\n")) {
    if (!line.trim().startsWith("//")) {
      if (line.includes("contract ")) break; // stop at first contract decl
      continue;
    }
    for (const url of line.match(/https?:\/\/[^\s)]+/g) ?? []) {
      const isKnownExplorer = [...known].some((a) => url.includes(a));
      if (!isKnownExplorer && !references.includes(url)) references.push(url);
    }
  }

  // Fork block: numeric literal in createSelectFork(...) or the variable it uses.
  let forkBlock: number | undefined;
  const fork = src.match(/createSelectFork\s*\(([^)]*)\)/);
  const network = fork?.[1]?.match(/"([^"]+)"/)?.[1];
  const inlineNum = fork?.[1]?.match(/(\d[\d_]{4,})/)?.[1];
  const assignedNum = src.match(/=\s*(\d[\d_]{4,})\s*;/)?.[1];
  const numStr = inlineNum ?? assignedNum;
  if (numStr) forkBlock = Number(numStr.replace(/_/g, ""));

  // Chain: from any explorer host in the PoC (robust to bare addresses), else
  // from the fork network string.
  const chain = detectChain(src, network);

  return IncidentMeta.parse({
    name,
    repoPath,
    date,
    lossText,
    attacker,
    attackContract,
    vulnerableContract,
    attackTx,
    references,
    forkBlock,
    chain,
    analysis: extractAnalysis(src),
  });
}

/** Stable candidate id for an incident. */
export function incidentId(repoPath: string): string {
  return `incident:${createHash("sha1").update(repoPath).digest("hex").slice(0, 12)}`;
}

/** Build a Candidate from parsed metadata + (optional) enrichment. */
export function toCandidate(
  meta: IncidentMeta,
  pocSource: string,
  enrich: { vulnerableSource?: string; txSummary?: string; blogText?: string },
): Candidate {
  return Candidate.parse({
    id: incidentId(meta.repoPath),
    kind: "incident",
    sourceRef: meta.repoPath,
    title: meta.name,
    severity: normalizeSeverity("HIGH"), // incidents are real exploits
    // Root cause prefers the inline @Analysis prose (no network); falls back to
    // any fetched blog text (currently disabled in StaticIncidentEnricher).
    rootCause: (meta.analysis || enrich.blogText || "").slice(0, 8000),
    code: enrich.vulnerableSource ?? "",
    poc: pocSource,
    txSummary: enrich.txSummary ?? "",
    blogText: enrich.blogText ?? "",
    tags: [],
    links: [
      ...(meta.references ?? []),
      ...([meta.attackTx, meta.vulnerableContract].filter(Boolean) as string[]),
    ],
    incident: meta,
  });
}

// ---- GitHub listing -------------------------------------------------------

export interface GitHubClient {
  /** List child entries (files/dirs) of a repo path. */
  listDir(repoPath: string): Promise<{ name: string; type: string; path: string }[]>;
  /** Fetch a raw text file from the repo. */
  getRaw(repoPath: string): Promise<string>;
}

export interface IncidentEnricher {
  vulnerableSource(meta: IncidentMeta): Promise<string | undefined>;
  txSummary(meta: IncidentMeta): Promise<string | undefined>;
  blogText(meta: IncidentMeta): Promise<string | undefined>;
}

export interface FetchIncidentsOpts {
  since?: string; // YYYY-MM lower bound (inclusive)
  limit?: number; // max new candidates this run
}

/**
 * List DeFiHackLabs PoCs, dedup, enrich (static-first), and upsert Candidates.
 * Cursor (`{ lastMonth, processedPaths }`) is checkpointed for resume; enrich
 * artifacts are cached by the enricher. `stop()` lets the caller pause between
 * incidents (graceful SIGINT) — when it returns true the loop stops and the
 * cursor is left where it is, so resume continues cleanly.
 */
export async function fetchIncidents(
  gh: GitHubClient,
  enricher: IncidentEnricher,
  repo: Repo,
  opts: FetchIncidentsOpts,
  stop: () => boolean = () => false,
): Promise<{ inserted: number; scanned: number }> {
  const months = (await gh.listDir(TEST_ROOT))
    .filter((e) => e.type === "dir" && /^\d{4}-\d{2}$/.test(e.name))
    .map((e) => e.name)
    .filter((m) => !opts.since || m >= opts.since)
    .sort();

  let inserted = 0;
  let scanned = 0;
  const cursor = (repo.getCursor("defihacklabs") as
    | { processedPaths?: string[] }
    | undefined) ?? { processedPaths: [] };
  const processed = new Set(cursor.processedPaths ?? []);

  for (const month of months) {
    if (stop()) break;
    const entries = await gh.listDir(`${TEST_ROOT}/${month}`);
    for (const e of entries) {
      if (stop()) break;
      if (e.type !== "file" || !/_exp\.sol$/i.test(e.name)) continue;
      if (processed.has(e.path)) continue;
      scanned++;
      const src = await gh.getRaw(e.path);
      const meta = parsePoc(src, e.path);
      const [vulnerableSource, txSummary, blogText] = await Promise.all([
        enricher.vulnerableSource(meta),
        enricher.txSummary(meta),
        enricher.blogText(meta),
      ]);
      const candidate = toCandidate(meta, src, {
        vulnerableSource,
        txSummary,
        blogText,
      });
      const { inserted: ins } = repo.upsertCandidate(candidate);
      if (ins) inserted++;
      processed.add(e.path);
      repo.setCursor("defihacklabs", {
        lastMonth: month,
        processedPaths: [...processed],
      });
      if (opts.limit && inserted >= opts.limit) return { inserted, scanned };
    }
  }
  return { inserted, scanned };
}

export const DEFIHACKLABS_REPO = REPO;
