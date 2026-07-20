import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "./runScan.js";
import type { TemplateArtifact } from "../types.js";

/**
 * Extract the WQL `meta.id` from a template YAML so the gate can check that the
 * specific template (not some other one) fired. Falls back to "" if absent.
 */
export function templateIdOf(yaml: string): string {
  const m = yaml.match(/^\s*id:\s*["']?([A-Za-z0-9._-]+)["']?\s*$/m);
  return m?.[1] ?? "";
}

/** Materialize an artifact's yaml/sols into a temp dir for scanning. */
function materialize(t: TemplateArtifact): {
  dir: string;
  templatePath: string;
  vulnPath: string;
  safePath: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "forge-gate-"));
  const templatePath = join(dir, "template.yaml");
  const vulnPath = join(dir, "vuln.sol");
  const safePath = join(dir, "safe.sol");
  writeFileSync(templatePath, t.templateYaml);
  writeFileSync(vulnPath, t.vulnSol);
  writeFileSync(safePath, t.safeSol);
  return { dir, templatePath, vulnPath, safePath };
}

export interface TestGateResult {
  passed: boolean;
  fired: boolean; // template fired on vuln.sol
  silentOnSafe: boolean; // template did NOT fire on safe.sol
  log: string;
}

/**
 * TEST gate (machine ground truth): the template MUST fire on vuln.sol and MUST
 * stay silent on safe.sol. `fired`/`silentOnSafe` are evaluated against the
 * template's own meta.id so an unrelated template firing does not count.
 */
export function testGate(
  t: TemplateArtifact,
  w3goauditBin: string,
): TestGateResult {
  const id = templateIdOf(t.templateYaml) || t.templateId;
  const m = materialize(t);
  try {
    const onVuln = runScan({
      w3goauditBin,
      templatePath: m.templatePath,
      targetPath: m.vulnPath,
    });
    const onSafe = runScan({
      w3goauditBin,
      templatePath: m.templatePath,
      targetPath: m.safePath,
    });
    const fired = onVuln.findings.some((f) => f.template_id === id);
    const silentOnSafe = !onSafe.findings.some((f) => f.template_id === id);
    const passed = fired && silentOnSafe;
    const log = [
      `template=${id}`,
      `vuln: total=${onVuln.total} fired=${fired}`,
      `safe: total=${onSafe.total} silent=${silentOnSafe}`,
      !fired ? `--- vuln scan output ---\n${onVuln.raw}` : "",
      !silentOnSafe
        ? `--- safe scan output ---\n${onSafe.raw}`
        : "",
    ]
      .filter(Boolean)
      .join("\n");
    return { passed, fired, silentOnSafe, log };
  } finally {
    rmSync(m.dir, { recursive: true, force: true });
  }
}

/**
 * Does `templateYaml` fire on a single Solidity source? Used by the improve
 * loop to evaluate recall/precision variants.
 */
export function firesOnSource(
  templateYaml: string,
  sol: string,
  w3goauditBin: string,
): boolean {
  const id = templateIdOf(templateYaml);
  const dir = mkdtempSync(join(tmpdir(), "forge-var-"));
  const tpl = join(dir, "template.yaml");
  const src = join(dir, "variant.sol");
  writeFileSync(tpl, templateYaml);
  writeFileSync(src, sol);
  try {
    const res = runScan({
      w3goauditBin,
      templatePath: tpl,
      targetPath: src,
    });
    return res.findings.some((f) => f.template_id === id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface RegressionGateResult {
  passed: boolean; // true if the corpus stays clean
  fires: { file: string; line?: number }[]; // where it fired (overfit signal)
  log: string;
}

/**
 * REGRESSION gate: scan the entire known-safe corpus with ONLY this template.
 * Any finding is treated as a potential overfit / false-positive signal.
 */
export function regressionGate(
  t: TemplateArtifact,
  corpusDir: string,
  w3goauditBin: string,
): RegressionGateResult {
  const id = templateIdOf(t.templateYaml) || t.templateId;
  const m = materialize(t);
  try {
    const res = runScan({
      w3goauditBin,
      templatePath: m.templatePath,
      targetPath: corpusDir,
    });
    const fires = res.findings
      .filter((f) => f.template_id === id)
      .map((f) => ({ file: f.location?.file ?? "?", line: f.location?.line }));
    return {
      passed: fires.length === 0,
      fires,
      log: `template=${id} corpus=${corpusDir} fires=${fires.length}`,
    };
  } finally {
    rmSync(m.dir, { recursive: true, force: true });
  }
}
