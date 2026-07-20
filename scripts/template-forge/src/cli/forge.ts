import { parseArgs } from "node:util";
import { runCli, fail } from "./_common.js";
import { makeForgeDeps } from "../pipeline/forge-deps.js";
import { runForge } from "../pipeline/orchestrator.js";

/**
 * Run the forge loop over all active (non-terminal) candidates. Idempotent and
 * resumable: completed stages are reused from the stage_result cache.
 *   npm run forge                          # all active candidates
 *   npm run forge -- --only <id>[,<id>]    # restrict to specific candidate ids
 */
runCli("forge", "forge", async ({ cfg, repo, stop, log }) => {
  const { values } = parseArgs({
    options: { only: { type: "string" } },
    allowPositionals: true,
  });
  const only = values.only
    ? values.only.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  const deps = makeForgeDeps(cfg, repo);
  const summary = await runForge(
    repo,
    deps,
    { repairMaxRetries: cfg.REPAIR_MAX_RETRIES },
    { stop: () => stop.stopped(), log, only },
  );
  log.info(
    `forge: processed=${summary.processed} cataloged=${summary.cataloged} ` +
      `shelved=${summary.shelved} parked=${summary.parked}`,
  );
  return { paused: summary.paused };
}).catch(fail);
