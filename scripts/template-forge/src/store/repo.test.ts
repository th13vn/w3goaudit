import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "./db.js";
import { Repo } from "./repo.js";
import { Candidate } from "../types.js";

function mkCandidate(overrides: Partial<Candidate> = {}): Candidate {
  return Candidate.parse({
    id: "finding:abc",
    kind: "finding",
    sourceRef: "abc",
    title: "Reentrancy",
    severity: "HIGH",
    ...overrides,
  });
}

describe("Repo", () => {
  let repo: Repo;
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("upserts a candidate and finds it by status", () => {
    expect(repo.upsertCandidate(mkCandidate()).inserted).toBe(true);
    const pending = repo.getCandidatesByStatus("pending");
    expect(pending).toHaveLength(1);
    expect(pending[0]!.id).toBe("finding:abc");
  });

  it("dedups on (kind, source_ref)", () => {
    repo.upsertCandidate(mkCandidate());
    const second = repo.upsertCandidate(mkCandidate({ title: "Different" }));
    expect(second.inserted).toBe(false);
    expect(repo.getCandidatesByStatus("pending")).toHaveLength(1);
  });

  it("advanceStatus only moves when from matches", () => {
    repo.upsertCandidate(mkCandidate());
    expect(repo.advanceStatus("finding:abc", "pending", "classifying")).toBe(
      true,
    );
    // stale guard: from no longer matches
    expect(repo.advanceStatus("finding:abc", "pending", "drafting")).toBe(false);
    expect(repo.getCandidateRow("finding:abc")!.status).toBe("classifying");
  });

  it("records bucket on transition", () => {
    repo.upsertCandidate(mkCandidate());
    repo.advanceStatus("finding:abc", "pending", "classified", "taint");
    expect(repo.getCandidateRow("finding:abc")!.bucket).toBe("taint");
  });

  it("stage_result round-trips and drives resume", () => {
    repo.upsertCandidate(mkCandidate());
    expect(repo.isStageDone("finding:abc", "classify")).toBe(false);
    repo.putStageResult("finding:abc", "classify", 0, "ok", {
      bucket: "taint",
    });
    expect(repo.isStageDone("finding:abc", "classify")).toBe(true);
    expect(repo.isStageDone("finding:abc", "draft")).toBe(false);
    const r = repo.getStageResult("finding:abc", "classify");
    expect((r!.output as { bucket: string }).bucket).toBe("taint");
  });

  it("counts stage attempts (repair budget)", () => {
    repo.putStageResult("finding:abc", "test", 0, "fail", null);
    repo.putStageResult("finding:abc", "test", 1, "fail", null);
    expect(repo.countStageAttempts("finding:abc", "test")).toBe(2);
  });

  it("cursor round-trips for resume", () => {
    expect(repo.getCursor("solodit")).toBeUndefined();
    repo.setCursor("solodit", { page: 3 });
    expect(repo.getCursor("solodit")).toEqual({ page: 3 });
  });

  it("lock is single-writer", () => {
    expect(repo.acquireLock("run-1")).toBe(true);
    expect(repo.acquireLock("run-2")).toBe(false);
    repo.releaseLock("run-1");
    expect(repo.acquireLock("run-2")).toBe(true);
  });

  it("getResumableRun returns latest running/paused", () => {
    repo.createRun("r1", "forge", {});
    expect(repo.getResumableRun("forge")!.id).toBe("r1");
    repo.setRunStatus("r1", "done");
    expect(repo.getResumableRun("forge")).toBeUndefined();
  });

  it("getActiveCandidates excludes terminal", () => {
    repo.upsertCandidate(mkCandidate({ id: "finding:a", sourceRef: "a" }));
    repo.upsertCandidate(mkCandidate({ id: "finding:b", sourceRef: "b" }));
    repo.setStatus("finding:b", "cataloged");
    const active = repo.getActiveCandidates();
    expect(active.map((c) => c.id)).toEqual(["finding:a"]);
  });
});
