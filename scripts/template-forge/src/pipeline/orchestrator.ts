import type { Repo } from "../store/repo.js";
import type { Logger } from "../log.js";
import { stepCandidate, type ForgeDeps, type StepConfig } from "./stages.js";

export interface RunForgeOpts {
  stop?: () => boolean;
  log?: Logger;
  /** Optional explicit candidate id list; defaults to all active candidates. */
  only?: string[];
}

export interface ForgeSummary {
  processed: number;
  cataloged: number;
  shelved: number;
  parked: number;
  paused: boolean;
}

/**
 * Drive every active candidate through the forge state machine until it reaches
 * a terminal status or the caller requests a stop. Each `stepCandidate` call is
 * a single, persisted transition, so a stop (graceful SIGINT) or a crash leaves
 * the candidate exactly at its last completed stage — resume continues from there.
 */
export async function runForge(
  repo: Repo,
  deps: ForgeDeps,
  cfg: StepConfig,
  opts: RunForgeOpts = {},
): Promise<ForgeSummary> {
  const stop = opts.stop ?? (() => false);
  const ids = opts.only ?? repo.getActiveCandidates().map((r) => r.id);
  let processed = 0;
  let paused = false;

  for (const id of ids) {
    if (stop()) {
      paused = true;
      break;
    }
    processed++;
    let advanced = true;
    while (advanced) {
      if (stop()) {
        paused = true;
        break;
      }
      advanced = await stepCandidate(repo, deps, cfg, id);
    }
    const row = repo.getCandidateRow(id);
    opts.log?.info(`candidate ${id} -> ${row?.status}`);
    if (paused) break;
  }

  const counts = repo.statusCounts();
  return {
    processed,
    cataloged: counts["cataloged"] ?? 0,
    shelved: counts["shelved"] ?? 0,
    parked: counts["parked"] ?? 0,
    paused,
  };
}
