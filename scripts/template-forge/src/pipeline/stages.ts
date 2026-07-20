import {
  Candidate,
  Classification,
  TemplateArtifact,
  Verdict,
  Provenance,
  RootCause,
} from "../types.js";
import type { Repo } from "../store/repo.js";
import type { TestGateResult, RegressionGateResult } from "../harness/gates.js";

/**
 * Pluggable reasoning + side-effect operations. The real implementation wires
 * opencode + the harness gates + filesystem; tests provide deterministic stubs.
 * Functions may be sync or async.
 */
export interface ForgeDeps {
  /**
   * AI root-cause exploration (browses reference links). Returns enriched root
   * cause, or null when exploration is skipped for this candidate.
   */
  explore(c: Candidate): Promise<RootCause | null> | RootCause | null;
  classify(c: Candidate): Promise<Classification> | Classification;
  draft(
    c: Candidate,
    cls: Classification,
  ): Promise<TemplateArtifact> | TemplateArtifact;
  repair(
    c: Candidate,
    current: TemplateArtifact,
    machineLog: string,
  ): Promise<TemplateArtifact> | TemplateArtifact;
  testGate(t: TemplateArtifact): Promise<TestGateResult> | TestGateResult;
  regressionGate(
    t: TemplateArtifact,
  ): Promise<RegressionGateResult> | RegressionGateResult;
  verify(c: Candidate, t: TemplateArtifact): Promise<Verdict> | Verdict;
  /** Persist a NOT-detectable candidate to the knowledge store. */
  park(c: Candidate, cls: Classification): Promise<void> | void;
  /** Persist a cataloged candidate (files + provenance) and return provenance. */
  catalog(
    c: Candidate,
    t: TemplateArtifact,
    v: Verdict,
  ): Promise<Provenance> | Provenance;
}

export interface StepConfig {
  repairMaxRetries: number;
}

/** Read the current template artifact (latest repair, else the draft). */
export function currentArtifact(
  repo: Repo,
  candidateId: string,
): TemplateArtifact | undefined {
  const repair = repo.getStageResult(candidateId, "repair");
  if (repair?.status === "ok" && repair.output)
    return TemplateArtifact.parse(repair.output);
  const draft = repo.getStageResult(candidateId, "draft");
  if (draft?.status === "ok" && draft.output)
    return TemplateArtifact.parse(draft.output);
  return undefined;
}

/**
 * Advance ONE candidate by exactly one stage transition. Returns true if it
 * advanced (caller loops), false if it is terminal / cannot progress.
 *
 * Resume: classify/draft/verify outputs are reused from `stage_result` when
 * present, so a resumed run never re-spends opencode on completed stages.
 */
export async function stepCandidate(
  repo: Repo,
  deps: ForgeDeps,
  cfg: StepConfig,
  candidateId: string,
): Promise<boolean> {
  const row = repo.getCandidateRow(candidateId);
  const c = repo.getCandidate(candidateId);
  if (!row || !c) return false;

  switch (row.status) {
    case "pending": {
      // AI root-cause exploration (browses links). May be skipped (null).
      const cached = repo.getStageResult(candidateId, "explore");
      if (!(cached?.status === "ok")) {
        const rc = await deps.explore(c);
        repo.putStageResult(candidateId, "explore", 0, "ok", rc);
        if (rc) repo.updateCandidatePayload(applyRootCause(c, RootCause.parse(rc)));
      }
      repo.advanceStatus(candidateId, "pending", "explored");
      return true;
    }

    case "explored": {
      const cls = await reuseOr(repo, candidateId, "classify", () =>
        deps.classify(repo.getCandidate(candidateId)!),
      ).then((o) => Classification.parse(o));
      if (cls.bucket === "NOT-detectable") {
        await deps.park(repo.getCandidate(candidateId)!, cls);
        repo.setStatus(candidateId, "parked");
        return false;
      }
      repo.advanceStatus(candidateId, "explored", "classified", cls.bucket);
      return true;
    }

    case "classified": {
      const clsRes = repo.getStageResult(candidateId, "classify");
      const cls = Classification.parse(clsRes!.output);
      const artifact = await reuseOr(repo, candidateId, "draft", () =>
        deps.draft(c, cls),
      ).then((o) => TemplateArtifact.parse(o));
      void artifact;
      repo.advanceStatus(candidateId, "classified", "drafted");
      return true;
    }

    case "drafted": {
      // TEST gate (+ bounded repair loop).
      const artifact = currentArtifact(repo, candidateId);
      if (!artifact) {
        repo.setStatus(candidateId, "shelved");
        return false;
      }
      const res = await deps.testGate(artifact);
      if (res.passed) {
        repo.putStageResult(candidateId, "test", 0, "ok", null, res.log);
        repo.advanceStatus(candidateId, "drafted", "tested");
        return true;
      }
      return await tryRepair(repo, deps, cfg, c, artifact, res.log, "test");
    }

    case "tested": {
      // REGRESSION gate (corpus must stay clean).
      const artifact = currentArtifact(repo, candidateId)!;
      const res = await deps.regressionGate(artifact);
      if (res.passed) {
        repo.putStageResult(candidateId, "regress", 0, "ok", null, res.log);
        repo.advanceStatus(candidateId, "tested", "regressed");
        return true;
      }
      const log = `REGRESSION: fired on ${res.fires.length} corpus file(s): ${res.fires
        .map((f) => f.file)
        .slice(0, 5)
        .join(", ")}`;
      // Overfit -> repair and re-run gates from 'drafted'.
      const advanced = await tryRepair(
        repo,
        deps,
        cfg,
        c,
        artifact,
        log,
        "regress",
      );
      if (advanced) repo.setStatus(candidateId, "drafted");
      return advanced;
    }

    case "regressed": {
      const artifact = currentArtifact(repo, candidateId)!;
      const verdict = await reuseOr(repo, candidateId, "verify", () =>
        deps.verify(c, artifact),
      ).then((o) => Verdict.parse(o));
      if (!verdict.rightReason) {
        repo.setStatus(candidateId, "shelved");
        return false;
      }
      repo.advanceStatus(candidateId, "regressed", "verified");
      return true;
    }

    case "verified": {
      const artifact = currentArtifact(repo, candidateId)!;
      const verdict = Verdict.parse(
        repo.getStageResult(candidateId, "verify")!.output,
      );
      const prov = await reuseOr(repo, candidateId, "catalog", () =>
        deps.catalog(c, artifact, verdict),
      ).then((o) => Provenance.parse(o));
      repo.putProvenance(prov);
      repo.advanceStatus(candidateId, "verified", "cataloged");
      return false; // terminal success
    }

    default:
      return false; // terminal (cataloged/parked/shelved/promoted)
  }
}

/** Run repair if budget remains, persisting a new artifact; else shelve. */
async function tryRepair(
  repo: Repo,
  deps: ForgeDeps,
  cfg: StepConfig,
  c: Candidate,
  artifact: TemplateArtifact,
  machineLog: string,
  failedStage: "test" | "regress",
): Promise<boolean> {
  const attempts = repo.countStageAttempts(c.id, "repair");
  repo.putStageResult(c.id, failedStage, attempts, "fail", null, machineLog);
  if (attempts >= cfg.repairMaxRetries) {
    repo.setStatus(c.id, "shelved");
    return false;
  }
  const repaired = TemplateArtifact.parse(
    await deps.repair(c, artifact, machineLog),
  );
  repo.putStageResult(c.id, "repair", attempts + 1, "ok", repaired);
  return true; // caller re-evaluates from current status
}

/** Merge an explore-stage RootCause into a candidate for downstream stages. */
export function applyRootCause(c: Candidate, rc: RootCause): Candidate {
  const richRootCause = [
    rc.summary,
    rc.rootCause,
    rc.triggerConditions.length
      ? `Trigger conditions:\n- ${rc.triggerConditions.join("\n- ")}`
      : "",
    rc.attackFlow.length ? `Attack flow:\n${rc.attackFlow.join("\n")}` : "",
    rc.detectabilityHint ? `Detectability: ${rc.detectabilityHint}` : "",
  ]
    .filter(Boolean)
    .join("\n\n");
  return Candidate.parse({
    ...c,
    rootCause: richRootCause || c.rootCause,
    code: rc.vulnerableCode || c.code,
    fixedCode: rc.fixedCode || c.fixedCode,
    triggerConditions: rc.triggerConditions.length
      ? rc.triggerConditions
      : c.triggerConditions,
    attackFlow: rc.attackFlow.length ? rc.attackFlow : c.attackFlow,
    logicBug: rc.logicBug,
    detectabilityHint: rc.detectabilityHint || c.detectabilityHint,
  });
}

/** Reuse a cached ok stage output, else produce + persist it. */
async function reuseOr(
  repo: Repo,
  candidateId: string,
  stage: "classify" | "draft" | "verify" | "catalog",
  produce: () => Promise<unknown> | unknown,
): Promise<unknown> {
  const cached = repo.getStageResult(candidateId, stage);
  if (cached?.status === "ok" && cached.output != null) return cached.output;
  const out = await produce();
  repo.putStageResult(candidateId, stage, 0, "ok", out);
  return out;
}
