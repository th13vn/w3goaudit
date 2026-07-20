import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";
import { Candidate, type TemplateArtifact } from "../types.js";
import { runImprove, type ImproveDeps, type VariantInstance } from "./improve.js";

const artifact = (id: string): TemplateArtifact => ({
  candidateId: id,
  templateId: "HIGH-X",
  templateYaml: "meta:\n  id: HIGH-X",
  vulnSol: "v",
  safeSol: "s",
});

function seed(repo: Repo, id = "c1"): Candidate {
  const c = Candidate.parse({
    id,
    kind: "finding",
    sourceRef: id,
    title: "t",
    severity: "HIGH",
  });
  repo.upsertCandidate(c);
  repo.putStageResult(id, "draft", 0, "ok", artifact(id)); // currentArtifact source
  return c;
}

function variants(nPerKind: number): VariantInstance[] {
  const out: VariantInstance[] = [];
  for (let i = 0; i < nPerKind; i++) {
    out.push({ variantId: `r${i}`, kind: "recall", expectedFire: true, sol: "rv" });
    out.push({
      variantId: `p${i}`,
      kind: "precision",
      expectedFire: false,
      sol: "pv",
    });
  }
  return out;
}

describe("runImprove", () => {
  let repo: Repo;
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("promotes after K clean rounds when all variants pass", async () => {
    const c = seed(repo);
    const deps: ImproveDeps = {
      generateVariants: (_, __, n) => variants(n),
      variantFires: (_, sol) => sol === "rv", // recall fires, precision silent => all pass
      repair: (_, t) => t,
      testGate: () => ({ passed: true, fired: true, silentOnSafe: true, log: "" }),
    };
    const r = await runImprove(repo, deps, c, { stableRounds: 2, nPerKind: 2 });
    expect(r.promoteEligible).toBe(true);
    expect(r.precision).toBe(1);
    expect(r.recall).toBe(1);
  });

  it("repairs on a recall miss (too niche), then converges", async () => {
    const c = seed(repo);
    let repaired = false;
    const deps: ImproveDeps = {
      generateVariants: (_, __, n) => variants(n),
      // before repair: recall variant does NOT fire (miss). after repair: fixed.
      variantFires: (_, sol) => (sol === "rv" ? repaired : false),
      repair: (_, t) => {
        repaired = true;
        return t;
      },
      testGate: () => ({ passed: true, fired: true, silentOnSafe: true, log: "" }),
    };
    const r = await runImprove(repo, deps, c, { stableRounds: 1, nPerKind: 1 });
    expect(repaired).toBe(true);
    expect(r.promoteEligible).toBe(true);
  });

  it("repairs on a precision false-fire (too generic)", async () => {
    const c = seed(repo);
    let repairs = 0;
    const deps: ImproveDeps = {
      generateVariants: (_, __, n) => variants(n),
      // precision variant fires (bad) until repaired, then stays silent (good)
      variantFires: (_, sol) => (sol === "rv" ? true : repairs === 0),
      repair: (_, t) => {
        repairs++;
        return t;
      },
      testGate: () => ({ passed: true, fired: true, silentOnSafe: true, log: "" }),
    };
    const r = await runImprove(repo, deps, c, { stableRounds: 1, nPerKind: 1 });
    expect(repairs).toBeGreaterThan(0);
    expect(r.promoteEligible).toBe(true);
  });

  it("shelves when repairs are exhausted", async () => {
    const c = seed(repo);
    const deps: ImproveDeps = {
      generateVariants: (_, __, n) => variants(n),
      variantFires: () => false, // recall always misses -> never clean
      repair: (_, t) => t,
      testGate: () => ({ passed: true, fired: true, silentOnSafe: true, log: "" }),
    };
    const r = await runImprove(repo, deps, c, {
      stableRounds: 2,
      nPerKind: 1,
      repairBudget: 2,
    });
    expect(r.shelved).toBe(true);
    expect(repo.getCandidateRow("c1")!.status).toBe("shelved");
  });

  it("RESUME: reuses a recorded round instead of regenerating", async () => {
    const c = seed(repo);
    // Pre-record round 0 as clean (all passed).
    repo.putVariantResult(
      {
        candidateId: "c1",
        variantId: "r0",
        kind: "recall",
        expectedFire: true,
        actualFire: true,
        passed: true,
      },
      0,
    );
    let generated = 0;
    const deps: ImproveDeps = {
      generateVariants: (_, __, n) => {
        generated++;
        return variants(n);
      },
      variantFires: (_, sol) => sol === "rv",
      repair: (_, t) => t,
      testGate: () => ({ passed: true, fired: true, silentOnSafe: true, log: "" }),
    };
    const r = await runImprove(repo, deps, c, { stableRounds: 2, nPerKind: 1 });
    // Round 0 reused (not generated); only round 1 generated -> generated === 1.
    expect(generated).toBe(1);
    expect(r.promoteEligible).toBe(true);
  });
});
