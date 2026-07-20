import { existsSync } from "node:fs";
import { loadDotEnv } from "../config.js";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";
import { DB_PATH, fail } from "./_common.js";

/**
 * Print per-status candidate counts, any resumable run, and the resume command.
 * Read-only: does not take the lock or create a run.
 *   npm run status
 */
function main(): void {
  loadDotEnv();
  if (!existsSync(DB_PATH)) {
    console.log("no state yet — run fetch:incidents / fetch:findings first.");
    return;
  }
  const repo = new Repo(openDb(DB_PATH));
  const counts = repo.statusCounts();
  const order = [
    "pending",
    "explored",
    "classified",
    "drafted",
    "tested",
    "regressed",
    "verified",
    "cataloged",
    "parked",
    "shelved",
    "promoted",
  ];
  console.log("Candidate status:");
  let total = 0;
  for (const s of order) {
    const n = counts[s] ?? 0;
    total += n;
    if (n > 0) console.log(`  ${s.padEnd(12)} ${n}`);
  }
  console.log(`  ${"TOTAL".padEnd(12)} ${total}`);

  const active = (counts["pending"] ?? 0) +
    (counts["explored"] ?? 0) +
    (counts["classified"] ?? 0) +
    (counts["drafted"] ?? 0) +
    (counts["tested"] ?? 0) +
    (counts["regressed"] ?? 0) +
    (counts["verified"] ?? 0);

  for (const kind of ["fetch_incidents", "fetch_findings", "forge", "improve"]) {
    const run = repo.getResumableRun(kind);
    if (run) console.log(`resumable ${kind} run: ${run.id} (${run.status})`);
  }
  if (active > 0)
    console.log(`\n${active} candidate(s) mid-pipeline — resume with: npm run forge`);
}

try {
  main();
} catch (e) {
  fail(e);
}
