import { existsSync, mkdirSync, writeFileSync, appendFileSync, readFileSync } from "node:fs";
import { resolve, join, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { FORGE_ROOT, type Config } from "../config.js";
import {
  Classification,
  Verdict,
  RootCause,
  type Candidate,
  type TemplateArtifact,
  type Provenance,
} from "../types.js";
import { DraftOutput, VariantsOutput } from "../agent/schemas.js";
import { runStage, renderPrompt, type OpencodeOptions } from "../agent/opencode.js";
import { testGate, regressionGate, firesOnSource } from "../harness/gates.js";
import type { ForgeDeps } from "./stages.js";
import type { ImproveDeps, VariantInstance } from "./improve.js";
import type { Repo } from "../store/repo.js";

const KNOWLEDGE = resolve(FORGE_ROOT, "knowledge");
const CANDIDATES = resolve(FORGE_ROOT, "candidates");

// Minimal CWE / OWASP-SC mapping per detectability bucket (smart-contract
// taxonomy). Used for provenance tagging; the agent can refine later.
const BUCKET_TAXONOMY: Record<
  string,
  { cwe: string[]; owaspSc: string[] }
> = {
  primitive: { cwe: ["CWE-345"], owaspSc: ["SC05:2025"] },
  "missing-check": { cwe: ["CWE-284"], owaspSc: ["SC01:2025"] },
  taint: { cwe: ["CWE-20"], owaspSc: ["SC01:2025"] },
  ordering: { cwe: ["CWE-841"], owaspSc: ["SC05:2025"] },
};

function wqlCheatsheet(): string {
  const p = resolve(FORGE_ROOT, "docs", "wql-cheatsheet.md");
  if (existsSync(p)) return readFileSync(p, "utf8");
  return "See templates/INDEX.md. Use filter presets (unAuthenticated/unLocked), match with kind/sequence/inside/args+tainted_from, scope: entrypoint.";
}

const EMBEDDED_ROOTCAUSE_METHOD = `Fetch every reference link and on-chain page with your web tools.
Read the vulnerable source. Cross-reference sources; never fabricate. Produce STRICT JSON with:
summary, rootCause, vulnerableCode, fixedCode, triggerConditions[] (the must-have preconditions to
trigger the bug), attackFlow[], logicBug (bool), detectabilityHint
(primitive|missing-check|taint|ordering|NOT-detectable: reason), sources[].`;

function loadRootCauseSkill(cfg: Config): string {
  const candidates = [
    isAbsolute(cfg.ROOTCAUSE_SKILL_PATH)
      ? cfg.ROOTCAUSE_SKILL_PATH
      : resolve(FORGE_ROOT, cfg.ROOTCAUSE_SKILL_PATH),
    join(homedir(), ".claude/skills/finding-root-cause/SKILL.md"),
  ];
  for (const p of candidates) {
    if (existsSync(p)) return readFileSync(p, "utf8");
  }
  return EMBEDDED_ROOTCAUSE_METHOD;
}

/** Whether a candidate warrants the (web, token-heavy) AI exploration stage. */
export function needsExploration(c: Candidate, minChars: number): boolean {
  if (c.kind === "incident") return true; // PoCs lack inline analysis
  return (c.rootCause?.length ?? 0) < minChars; // rich findings skip it
}

function onchainSummary(c: Candidate): string {
  const m = c.incident;
  if (!m) return "(none)";
  return [
    m.chain ? `chain: ${m.chain}` : "",
    m.vulnerableContract ? `vulnerable: ${m.vulnerableContract}` : "",
    m.attackContract ? `attackContract: ${m.attackContract}` : "",
    m.attacker ? `attacker: ${m.attacker}` : "",
    m.attackTx ? `attackTx: ${m.attackTx}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

/** Build production ForgeDeps backed by opencode + the w3goaudit harness. */
export function makeForgeDeps(cfg: Config, repo?: Repo): ForgeDeps {
  const oc: OpencodeOptions = {
    bin: cfg.OPENCODE_BIN,
    model: cfg.OPENCODE_MODEL,
    attach: cfg.OPENCODE_ATTACH || undefined,
    maxRetries: 2,
  };
  const cheatsheet = wqlCheatsheet();

  const toArtifact = (c: Candidate, d: DraftOutput): TemplateArtifact => ({
    candidateId: c.id,
    templateId: d.templateId,
    templateYaml: d.templateYaml,
    vulnSol: d.vulnSol,
    safeSol: d.safeSol,
  });

  const skill = loadRootCauseSkill(cfg);

  return {
    explore(c): RootCause | null {
      if (!needsExploration(c, cfg.EXPLORE_MIN_ROOTCAUSE_CHARS)) return null;
      const prompt = renderPrompt("explore", {
        skill,
        kind: c.kind,
        title: c.title,
        severity: c.severity,
        chain: c.incident?.chain ?? "",
        links: (c.links ?? []).join("\n") || "(none)",
        onchain: onchainSummary(c),
        rootCause: c.rootCause,
        poc: c.poc,
        code: c.code,
      });
      // Explore is the only stage that browses the web (tools unrestricted).
      return runStage(prompt, RootCause, oc);
    },

    classify(c) {
      const prompt = renderPrompt("classify", {
        title: c.title,
        severity: c.severity,
        rootCause: c.rootCause,
        code: c.code || c.poc,
        triggerConditions: (c.triggerConditions ?? []).join("\n- "),
        detectabilityHint: c.detectabilityHint ?? "",
      });
      return runStage(prompt, Classification, oc);
    },

    draft(c, cls) {
      const prompt = renderPrompt("draft", {
        title: c.title,
        severity: c.severity,
        bucket: cls.bucket,
        targetPrimitive: cls.targetPrimitive,
        rootCause: c.rootCause,
        code: c.code || c.poc,
        fixedCode: c.fixedCode ?? "",
        triggerConditions: (c.triggerConditions ?? []).join("\n- "),
        wqlCheatsheet: cheatsheet,
      });
      return toArtifact(c, runStage(prompt, DraftOutput, oc));
    },

    repair(c, current, machineLog) {
      const prompt = renderPrompt("repair", {
        templateYaml: current.templateYaml,
        vulnSol: current.vulnSol,
        safeSol: current.safeSol,
        machineLog,
        wqlCheatsheet: cheatsheet,
      });
      return toArtifact(c, runStage(prompt, DraftOutput, oc));
    },

    testGate(t) {
      return testGate(t, cfg.W3GOAUDIT_BIN);
    },

    regressionGate(t) {
      return regressionGate(t, cfg.W3GOAUDIT_CORPUS, cfg.W3GOAUDIT_BIN);
    },

    verify(c, t) {
      const prompt = renderPrompt("verify", {
        title: c.title,
        rootCause: c.rootCause,
        templateYaml: t.templateYaml,
        vulnSol: t.vulnSol,
      });
      return runStage(prompt, Verdict, oc);
    },

    park(c, cls) {
      mkdirSync(KNOWLEDGE, { recursive: true });
      appendFileSync(
        join(KNOWLEDGE, "parked.jsonl"),
        JSON.stringify({
          id: c.id,
          kind: c.kind,
          title: c.title,
          sourceRef: c.sourceRef,
          bucket: cls.bucket,
          rationale: cls.rationale,
        }) + "\n",
      );
    },

    catalog(c, t, v): Provenance {
      const dir = join(CANDIDATES, c.id.replace(/[:/]/g, "_"));
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "template.yaml"), t.templateYaml);
      writeFileSync(join(dir, "vuln.sol"), t.vulnSol);
      writeFileSync(join(dir, "safe.sol"), t.safeSol);
      const bucket = repo?.getCandidateRow(c.id)?.bucket ?? "missing-check";
      const tax = BUCKET_TAXONOMY[bucket] ?? { cwe: [], owaspSc: [] };
      const prov: Provenance = {
        candidateId: c.id,
        links: c.links,
        cwe: tax.cwe,
        owaspSc: tax.owaspSc,
        confidence: v.confidence,
      };
      writeFileSync(
        join(dir, "provenance.json"),
        JSON.stringify({ ...prov, title: c.title, source: c.sourceRef }, null, 2),
      );
      return prov;
    },
  };
}

/** Build production ImproveDeps backed by opencode + the w3goaudit harness. */
export function makeImproveDeps(cfg: Config): ImproveDeps {
  const oc: OpencodeOptions = {
    bin: cfg.OPENCODE_BIN,
    model: cfg.OPENCODE_MODEL,
    attach: cfg.OPENCODE_ATTACH || undefined,
    maxRetries: 2,
  };
  const cheatsheet = wqlCheatsheet();
  return {
    generateVariants(c, t, nPerKind): VariantInstance[] {
      const prompt = renderPrompt("variants", {
        templateYaml: t.templateYaml,
        vulnSol: t.vulnSol,
        safeSol: t.safeSol,
        nVariants: String(nPerKind),
      });
      const out = runStage(prompt, VariantsOutput, oc);
      return out.variants.map((v) => ({
        variantId: v.variantId,
        kind: v.kind,
        expectedFire: v.expectedFire,
        sol: v.sol,
      }));
    },
    variantFires(t, sol) {
      return firesOnSource(t.templateYaml, sol, cfg.W3GOAUDIT_BIN);
    },
    repair(c, t, machineLog) {
      const prompt = renderPrompt("repair", {
        templateYaml: t.templateYaml,
        vulnSol: t.vulnSol,
        safeSol: t.safeSol,
        machineLog,
        wqlCheatsheet: cheatsheet,
      });
      const d = runStage(prompt, DraftOutput, oc);
      return {
        candidateId: c.id,
        templateId: d.templateId,
        templateYaml: d.templateYaml,
        vulnSol: d.vulnSol,
        safeSol: d.safeSol,
      };
    },
    testGate(t) {
      return testGate(t, cfg.W3GOAUDIT_BIN);
    },
  };
}
