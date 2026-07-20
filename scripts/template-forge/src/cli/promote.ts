import { parseArgs } from "node:util";
import { readFileSync, mkdirSync, copyFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { runCli, fail } from "./_common.js";
import { FORGE_ROOT } from "../config.js";
import { templateIdOf } from "../harness/gates.js";

const CANDIDATES = resolve(FORGE_ROOT, "candidates");
const OFFICIAL = resolve(FORGE_ROOT, "../../templates/official");

/**
 * Copy a cataloged candidate's template into templates/official/<severity>/ and
 * mark it promoted. This is the explicit human gate from candidate -> shipped.
 *   npm run promote -- <candidateId>
 */
runCli("promote", "forge", async ({ repo, log }) => {
  const { positionals } = parseArgs({ allowPositionals: true });
  const id = positionals[0];
  if (!id) throw new Error("usage: npm run promote -- <candidateId>");
  const row = repo.getCandidateRow(id);
  if (!row) throw new Error(`candidate not found: ${id}`);
  if (row.status !== "cataloged" && row.status !== "verified")
    throw new Error(
      `candidate ${id} is '${row.status}', not cataloged/verified — not promotable`,
    );

  const dir = join(CANDIDATES, id.replace(/[:/]/g, "_"));
  const tplPath = join(dir, "template.yaml");
  if (!existsSync(tplPath))
    throw new Error(`no template.yaml at ${tplPath} (run forge to catalog it first)`);

  const yaml = readFileSync(tplPath, "utf8");
  const sev = (yaml.match(/severity:\s*([A-Za-z]+)/)?.[1] ?? "medium").toLowerCase();
  const tplId = templateIdOf(yaml) || id.replace(/[:/]/g, "_");
  const destDir = join(OFFICIAL, sev);
  mkdirSync(destDir, { recursive: true });
  const dest = join(destDir, `${tplId}.yaml`);
  copyFileSync(tplPath, dest);
  repo.setStatus(id, "promoted");
  log.info(`promoted ${id} -> ${dest}`);
}).catch(fail);
