import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";
import { Candidate } from "../types.js";
import { runForge } from "./orchestrator.js";
import type { ForgeDeps, StepConfig } from "./stages.js";
import type { TestGateResult, RegressionGateResult } from "../harness/gates.js";

const CFG: StepConfig = { repairMaxRetries: 2 };

function seed(repo: Repo, id: string, title = "Reentrancy"): void {
  repo.upsertCandidate(
    Candidate.parse({
      id,
      kind: "finding",
      sourceRef: id,
      title,
      severity: "HIGH",
      rootCause: "external call before state write",
      code: "function f(){}",
    }),
  );
}

const artifact = (id: string) => ({
  candidateId: id,
  templateId: "HIGH-X",
  templateYaml: "meta:\n  id: HIGH-X",
  vulnSol: "v",
  safeSol: "s",
});

/** Tracks how many times each stage was invoked (to assert resume caching). */
class StubDeps implements ForgeDeps {
  calls = {
    explore: 0,
    classify: 0,
    draft: 0,
    repair: 0,
    test: 0,
    regress: 0,
    verify: 0,
    catalog: 0,
    park: 0,
  };
  constructor(
    private opts: {
      bucket?: string;
      testResults?: boolean[]; // sequence of testGate.passed
      regressPass?: boolean;
      rightReason?: boolean;
      explore?: any; // RootCause to return from explore (null = skip)
    } = {},
  ) {}
  explore(_c: any) {
    this.calls.explore++;
    return this.opts.explore ?? null;
  }
  classify(c: any) {
    this.calls.classify++;
    return {
      bucket: (this.opts.bucket ?? "ordering") as any,
      targetPrimitive: "sequence+state_write",
      rationale: "x",
    };
  }
  draft(c: any) {
    this.calls.draft++;
    return artifact(c.id);
  }
  repair(c: any) {
    this.calls.repair++;
    return artifact(c.id);
  }
  testGate(): TestGateResult {
    const seq = this.opts.testResults ?? [true];
    const passed = seq[Math.min(this.calls.test, seq.length - 1)] ?? true;
    this.calls.test++;
    return { passed, fired: passed, silentOnSafe: passed, log: "test-log" };
  }
  regressionGate(): RegressionGateResult {
    this.calls.regress++;
    const passed = this.opts.regressPass ?? true;
    return { passed, fires: passed ? [] : [{ file: "x.sol" }], log: "rl" };
  }
  verify(c: any) {
    this.calls.verify++;
    return {
      rightReason: this.opts.rightReason ?? true,
      rationale: "x",
      confidence: "HIGH" as const,
    };
  }
  park() {
    this.calls.park++;
  }
  catalog(c: any) {
    this.calls.catalog++;
    return { candidateId: c.id, links: [], cwe: [], owaspSc: [], confidence: "HIGH" as const };
  }
}

describe("runForge", () => {
  let repo: Repo;
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("walks a clean candidate pending -> cataloged", async () => {
    seed(repo, "c1");
    const deps = new StubDeps();
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c1")!.status).toBe("cataloged");
    expect(deps.calls).toMatchObject({
      explore: 1,
      classify: 1,
      draft: 1,
      test: 1,
      regress: 1,
      verify: 1,
      catalog: 1,
    });
  });

  it("explore enriches the candidate before classify", async () => {
    seed(repo, "ce");
    const deps = new StubDeps({
      explore: {
        summary: "s",
        rootCause: "reentrancy: call before write",
        vulnerableCode: "function withdraw(){ msg.sender.call(); bal=0; }",
        fixedCode: "function withdraw(){ bal=0; msg.sender.call(); }",
        triggerConditions: ["call before state write", "no guard"],
        attackFlow: ["1. deposit", "2. reenter"],
        logicBug: false,
        detectabilityHint: "ordering",
        sources: ["https://example.com"],
      },
    });
    await runForge(repo, deps, CFG);
    // the persisted candidate picked up explored fields
    const c = repo.getCandidate("ce")!;
    expect(c.code).toContain("msg.sender.call()");
    expect(c.fixedCode).toContain("bal=0; msg.sender.call()");
    expect(c.triggerConditions).toContain("no guard");
    expect(c.rootCause).toContain("Trigger conditions");
    expect(repo.getCandidateRow("ce")!.status).toBe("cataloged");
  });

  it("parks a NOT-detectable candidate", async () => {
    seed(repo, "c2");
    const deps = new StubDeps({ bucket: "NOT-detectable" });
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c2")!.status).toBe("parked");
    expect(deps.calls.park).toBe(1);
    expect(deps.calls.draft).toBe(0);
  });

  it("repairs then shelves when TEST keeps failing past the budget", async () => {
    seed(repo, "c3");
    // always fails -> repair until budget (2) exhausted -> shelved
    const deps = new StubDeps({ testResults: [false] });
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c3")!.status).toBe("shelved");
    expect(deps.calls.repair).toBe(2); // repairMaxRetries
  });

  it("repairs once then succeeds when TEST passes on the 2nd try", async () => {
    seed(repo, "c4");
    const deps = new StubDeps({ testResults: [false, true] });
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c4")!.status).toBe("cataloged");
    expect(deps.calls.repair).toBe(1);
  });

  it("shelves when the verifier rejects the right-reason check", async () => {
    seed(repo, "c5");
    const deps = new StubDeps({ rightReason: false });
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c5")!.status).toBe("shelved");
  });

  it("repairs on regression-gate overfit", async () => {
    seed(repo, "c6");
    // regression fails once then we re-run; make it pass after a repair by
    // flipping via a stateful stub.
    let regressCalls = 0;
    const deps = new StubDeps();
    deps.regressionGate = () => {
      regressCalls++;
      const passed = regressCalls > 1;
      return { passed, fires: passed ? [] : [{ file: "x.sol" }], log: "rl" };
    };
    await runForge(repo, deps, CFG);
    expect(repo.getCandidateRow("c6")!.status).toBe("cataloged");
    expect(deps.calls.repair).toBe(1);
  });

  it("RESUME: re-running does not re-invoke cached classify/draft", async () => {
    seed(repo, "c7");
    // First run stops right after 'drafted' via a stop flag that trips once
    // the candidate has been drafted.
    const deps = new StubDeps();
    let steps = 0;
    await runForge(repo, deps, CFG, {
      stop: () => repo.getCandidateRow("c7")?.status === "drafted" || steps++ > 50,
    });
    expect(repo.getCandidateRow("c7")!.status).toBe("drafted");
    const after1 = { ...deps.calls };

    // Resume with a FRESH deps instance: classify/draft must be reused from
    // cache (not re-invoked); the run completes to cataloged.
    const deps2 = new StubDeps();
    await runForge(repo, deps2, CFG);
    expect(repo.getCandidateRow("c7")!.status).toBe("cataloged");
    expect(deps2.calls.explore).toBe(0); // not re-invoked (status already past pending)
    expect(deps2.calls.classify).toBe(0); // reused from stage_result cache
    expect(deps2.calls.draft).toBe(0); // reused
    expect(deps2.calls.test).toBeGreaterThan(0); // gates re-run (cheap, machine)
    expect(after1.classify).toBe(1);
  });

  it("reports a paused summary when stopped early", async () => {
    seed(repo, "c8");
    const sum = await runForge(repo, new StubDeps(), CFG, { stop: () => true });
    expect(sum.paused).toBe(true);
    expect(repo.getCandidateRow("c8")!.status).toBe("pending");
  });
});
