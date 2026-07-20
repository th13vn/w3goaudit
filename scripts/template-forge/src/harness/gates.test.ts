import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { testGate, regressionGate, templateIdOf } from "./gates.js";
import { FORGE_ROOT } from "../config.js";
import type { TemplateArtifact } from "../types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n: string) => readFileSync(resolve(here, "__fixtures__", n), "utf8");
const W3GO = resolve(FORGE_ROOT, "../../w3goaudit");
const hasBin = existsSync(W3GO);

const artifact: TemplateArtifact = {
  candidateId: "test:reentrancy",
  templateId: "HIGH-REENTRANCY-PATTERN",
  templateYaml: hasBin ? fx("reentrancy.yaml") : "",
  vulnSol: hasBin ? fx("vuln.sol") : "",
  safeSol: hasBin ? fx("safe.sol") : "",
};

describe("templateIdOf", () => {
  it("extracts meta.id from yaml", () => {
    expect(templateIdOf("meta:\n  id: HIGH-FOO-BAR\n  severity: HIGH")).toBe(
      "HIGH-FOO-BAR",
    );
  });
  it("returns empty when absent", () => {
    expect(templateIdOf("query:\n  scope: entrypoint")).toBe("");
  });
});

describe.skipIf(!hasBin)("testGate (live w3goaudit)", () => {
  it("fires on vuln.sol and is silent on safe.sol", () => {
    const r = testGate(artifact, W3GO);
    expect(r.fired).toBe(true);
    expect(r.silentOnSafe).toBe(true);
    expect(r.passed).toBe(true);
  });

  it("fails when vuln and safe are swapped (must-fire violated)", () => {
    const broken: TemplateArtifact = {
      ...artifact,
      vulnSol: artifact.safeSol, // safe code can't fire => must-fire fails
    };
    const r = testGate(broken, W3GO);
    expect(r.fired).toBe(false);
    expect(r.passed).toBe(false);
  });
});

describe.skipIf(!hasBin)("regressionGate (live w3goaudit)", () => {
  it("reports clean on a corpus of only the safe fixture", () => {
    const r = regressionGate(
      artifact,
      resolve(here, "__fixtures__", "safe.sol"),
      W3GO,
    );
    expect(r.passed).toBe(true);
    expect(r.fires).toHaveLength(0);
  });

  it("reports fires on a corpus containing the vuln fixture", () => {
    const r = regressionGate(
      artifact,
      resolve(here, "__fixtures__", "vuln.sol"),
      W3GO,
    );
    expect(r.passed).toBe(false);
    expect(r.fires.length).toBeGreaterThan(0);
  });
});
