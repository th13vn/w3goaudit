import {
  type Candidate,
  type TemplateArtifact,
  type VariantResult,
} from "../types.js";
import type { Repo } from "../store/repo.js";
import type { TestGateResult } from "../harness/gates.js";
import { currentArtifact } from "./stages.js";

export interface VariantInstance {
  variantId: string;
  kind: "recall" | "precision";
  expectedFire: boolean;
  sol: string;
}

/** Operations the improve loop needs. Real impl uses opencode + the harness. */
export interface ImproveDeps {
  generateVariants(
    c: Candidate,
    t: TemplateArtifact,
    nPerKind: number,
  ): Promise<VariantInstance[]> | VariantInstance[];
  /** Does the template fire on this source? */
  variantFires(t: TemplateArtifact, sol: string): Promise<boolean> | boolean;
  repair(
    c: Candidate,
    t: TemplateArtifact,
    machineLog: string,
  ): Promise<TemplateArtifact> | TemplateArtifact;
  /** Re-validate the canonical vuln/safe pair after a repair. */
  testGate(t: TemplateArtifact): Promise<TestGateResult> | TestGateResult;
}

export interface ImproveConfig {
  stableRounds: number; // K consecutive clean rounds required
  nPerKind?: number; // variants per kind per round (default 3)
  maxRounds?: number; // hard cap (default stableRounds + repairBudget)
  repairBudget?: number; // max repairs across the improve loop (default 3)
}

export interface ImproveResult {
  precision: number; // last round
  recall: number; // last round
  rounds: number;
  promoteEligible: boolean;
  shelved: boolean;
}

/**
 * Tune a verified candidate so it is neither too niche (misses recall variants)
 * nor too generic (fires on precision variants). Loops until `stableRounds`
 * consecutive clean rounds, repairing on any miss within `repairBudget`.
 *
 * Resume: each round's results are persisted to `variant_result`; a resumed run
 * reuses recorded rounds (recomputing the stable streak) and only generates +
 * scores rounds that have no rows yet.
 */
export async function runImprove(
  repo: Repo,
  deps: ImproveDeps,
  c: Candidate,
  cfg: ImproveConfig,
  stop: () => boolean = () => false,
): Promise<ImproveResult> {
  const nPerKind = cfg.nPerKind ?? 3;
  const repairBudget = cfg.repairBudget ?? 3;
  const maxRounds = cfg.maxRounds ?? cfg.stableRounds + repairBudget + 1;

  let artifact = currentArtifact(repo, c.id);
  if (!artifact) return zero(false);

  let stable = 0;
  let repairs = 0;
  let lastPrecision = 1;
  let lastRecall = 1;
  let round = 0;

  for (; round < maxRounds; round++) {
    if (stop()) break;

    // Resume: reuse a round already recorded.
    let results = repo.getVariantRound(c.id, round);
    if (results.length === 0) {
      const variants = await deps.generateVariants(c, artifact, nPerKind);
      results = [];
      for (const v of variants) {
        const actualFire = await deps.variantFires(artifact, v.sol);
        const r: VariantResult = {
          candidateId: c.id,
          variantId: v.variantId,
          kind: v.kind,
          expectedFire: v.expectedFire,
          actualFire,
          passed: actualFire === v.expectedFire,
        };
        repo.putVariantResult(r, round);
        results.push(r);
      }
    }

    const { precision, recall } = metrics(results);
    lastPrecision = precision;
    lastRecall = recall;
    const clean = results.every((r) => r.passed);

    if (clean) {
      stable++;
      if (stable >= cfg.stableRounds) {
        return {
          precision,
          recall,
          rounds: round + 1,
          promoteEligible: true,
          shelved: false,
        };
      }
      continue;
    }

    // Not clean -> reset streak and repair (if budget remains).
    stable = 0;
    if (repairs >= repairBudget) {
      repo.setStatus(c.id, "shelved");
      return {
        precision,
        recall,
        rounds: round + 1,
        promoteEligible: false,
        shelved: true,
      };
    }
    repairs++;
    const failing = results.filter((r) => !r.passed);
    const log = failNarrative(failing);
    const repaired = await deps.repair(c, artifact, log);
    const verdict = await deps.testGate(repaired);
    if (!verdict.passed) {
      // Repair broke the canonical pair; do not adopt it. Shelve if out of budget.
      if (repairs >= repairBudget) {
        repo.setStatus(c.id, "shelved");
        return zero(true, round + 1);
      }
      continue;
    }
    artifact = repaired;
    repo.putStageResult(c.id, "repair", repairs + 100, "ok", repaired); // high attempt id => latest
  }

  return {
    precision: lastPrecision,
    recall: lastRecall,
    rounds: round,
    promoteEligible: false,
    shelved: false,
  };
}

function metrics(results: VariantResult[]): {
  precision: number;
  recall: number;
} {
  const precisionSet = results.filter((r) => r.kind === "precision");
  const recallSet = results.filter((r) => r.kind === "recall");
  const precision = ratio(
    precisionSet.filter((r) => r.passed).length,
    precisionSet.length,
  );
  const recall = ratio(
    recallSet.filter((r) => r.passed).length,
    recallSet.length,
  );
  return { precision, recall };
}

function ratio(n: number, d: number): number {
  return d === 0 ? 1 : n / d;
}

function failNarrative(failing: VariantResult[]): string {
  const niche = failing.filter((r) => r.kind === "recall"); // should fire, didn't
  const noisy = failing.filter((r) => r.kind === "precision"); // should be silent, fired
  const parts: string[] = [];
  if (niche.length)
    parts.push(
      `TOO NICHE: missed ${niche.length} recall variant(s) (${niche
        .map((r) => r.variantId)
        .join(", ")}) — broaden the match to catch equivalent vulnerable shapes.`,
    );
  if (noisy.length)
    parts.push(
      `TOO GENERIC: fired on ${noisy.length} precision variant(s) (${noisy
        .map((r) => r.variantId)
        .join(", ")}) — tighten the match so safe look-alikes stay silent.`,
    );
  return parts.join("\n");
}

function zero(shelved: boolean, rounds = 0): ImproveResult {
  return { precision: 0, recall: 0, rounds, promoteEligible: false, shelved };
}
