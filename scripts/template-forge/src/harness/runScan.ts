import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, isAbsolute } from "node:path";
import { FORGE_ROOT } from "../config.js";
import { Finding } from "../types.js";

/**
 * Invoke w3goaudit on a target with a single template (or template dir) and
 * return the parsed findings. The binary writes a result folder; we read
 * `corpus/findings.json` from it and then clean up.
 *
 * CLI shape (verified against w3goaudit v0.3.1):
 *   w3goaudit <targetPath> -t <templatePathOrDir> -o <outDir>
 * Output of interest: <outDir>/corpus/findings.json =
 *   { counts: { total, ... }, findings: [ { template_id, severity, location, ... } ] }
 */
export interface ScanResult {
  total: number;
  findings: Finding[];
  raw: string; // stderr+stdout for diagnostics / repair feedback
}

function binPath(rel: string): string {
  if (isAbsolute(rel)) return rel;
  // A bare command name (no path separator) like "w3goaudit": prefer the
  // repo-root binary if it exists, otherwise let the OS resolve it on PATH.
  if (!rel.includes("/")) {
    const atRoot = resolve(FORGE_ROOT, "..", "..", rel);
    return existsSync(atRoot) ? atRoot : rel;
  }
  return resolve(FORGE_ROOT, rel);
}

export function runScan(opts: {
  w3goauditBin: string;
  templatePath: string; // file or directory, absolute or forge-relative
  targetPath: string; // .sol file or directory, absolute or forge-relative
}): ScanResult {
  const bin = binPath(opts.w3goauditBin);
  const template = binPath(opts.templatePath);
  const target = binPath(opts.targetPath);
  const out = mkdtempSync(join(tmpdir(), "forge-scan-"));
  try {
    const proc = spawnSync(
      bin,
      [target, "-t", template, "-o", out, "--no-color"],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
    );
    const raw = `${proc.stdout ?? ""}\n${proc.stderr ?? ""}`.trim();
    let parsed: { counts?: { total?: number }; findings?: unknown[] };
    try {
      parsed = JSON.parse(
        readFileSync(join(out, "corpus", "findings.json"), "utf8"),
      );
    } catch (err) {
      // No findings file => scan failed (e.g. parse error, bad template).
      throw new Error(
        `runScan: no findings.json produced (exit ${proc.status}).\n${raw}`,
      );
    }
    const findings = (parsed.findings ?? []).map((f) => Finding.parse(f));
    return { total: parsed.counts?.total ?? findings.length, findings, raw };
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
