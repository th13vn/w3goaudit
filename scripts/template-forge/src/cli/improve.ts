import { parseArgs } from "node:util";
import { runCli, fail } from "./_common.js";
import { makeImproveDeps } from "../pipeline/forge-deps.js";
import { runImprove } from "../pipeline/improve.js";

/**
 * Run the precision/recall variant-tuning loop on one verified candidate.
 *   npm run improve -- <candidateId> [--rounds K] [--per-kind N]
 */
runCli("improve", "improve", async ({ cfg, repo, stop, log }) => {
  const { values, positionals } = parseArgs({
    options: {
      rounds: { type: "string" },
      "per-kind": { type: "string" },
    },
    allowPositionals: true,
  });
  const id = positionals[0];
  if (!id) throw new Error("usage: npm run improve -- <candidateId>");
  const c = repo.getCandidate(id);
  if (!c) throw new Error(`candidate not found: ${id}`);

  const deps = makeImproveDeps(cfg);
  const r = await runImprove(
    repo,
    deps,
    c,
    {
      stableRounds: values.rounds ? Number(values.rounds) : cfg.IMPROVE_STABLE_ROUNDS,
      nPerKind: values["per-kind"] ? Number(values["per-kind"]) : 3,
    },
    () => stop.stopped(),
  );
  log.info(
    `improve ${id}: precision=${r.precision.toFixed(2)} recall=${r.recall.toFixed(
      2,
    )} rounds=${r.rounds} promoteEligible=${r.promoteEligible} shelved=${r.shelved}`,
  );
}).catch(fail);
