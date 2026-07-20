import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { loadDotEnv, loadConfig, FORGE_ROOT, type Config } from "../config.js";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";
import {
  createStopFlag,
  installSignalHandlers,
  withLock,
  type StopFlag,
} from "../util/signals.js";
import { Logger } from "../log.js";

export const DB_PATH = resolve(FORGE_ROOT, "state", "forge.db");

export interface CliCtx {
  cfg: Config;
  repo: Repo;
  runId: string;
  stop: StopFlag;
  log: Logger;
}

const RESUME_HINT: Record<string, string> = {
  fetch_incidents: "npm run fetch:incidents   # continues from the saved cursor",
  fetch_findings: "npm run fetch:findings   # continues from the saved page",
  forge: "npm run forge   # resumes active candidates from their last stage",
  improve: "npm run improve -- <candidateId>",
};

/**
 * Shared CLI harness: load env+config, open the DB, take the single-writer lock,
 * install graceful-pause handlers, create a run row, run `body`, then persist
 * the run status (paused|done) and print the resume command on pause.
 */
export async function runCli(
  kind: string,
  resumeKey: string,
  body: (ctx: CliCtx) => Promise<{ paused?: boolean } | void>,
): Promise<void> {
  loadDotEnv();
  const cfg = loadConfig();
  mkdirSync(resolve(FORGE_ROOT, "state"), { recursive: true });
  const db = openDb(DB_PATH);
  const repo = new Repo(db);
  const runId = `${kind}-${Date.now()}`;
  const stop = createStopFlag();
  const uninstall = installSignalHandlers(stop);
  const log = new Logger(runId);
  try {
    await withLock(repo, runId, async () => {
      repo.createRun(runId, kind, process.argv.slice(2));
      const res = await body({ cfg, repo, runId, stop, log });
      const paused = stop.stopped() || res?.paused === true;
      repo.setRunStatus(runId, paused ? "paused" : "done");
      if (paused) {
        log.warn(`PAUSED. Resume with:  ${RESUME_HINT[resumeKey] ?? "re-run the same command"}`);
      } else {
        log.info(`run ${runId} complete`);
      }
    });
  } finally {
    uninstall();
    db.close();
  }
}

/** Print a fatal error and exit non-zero. */
export function fail(err: unknown): never {
  console.error(`template-forge: ${(err as Error).message ?? err}`);
  process.exit(1);
}
