import { describe, it, expect } from "vitest";
import {
  Candidate,
  RootCause,
  normalizeSeverity,
  TERMINAL_STATUSES,
  CandidateStatus,
} from "./types.js";

describe("Candidate schema", () => {
  it("parses a minimal valid candidate with defaults", () => {
    const c = Candidate.parse({
      id: "finding:abc",
      kind: "finding",
      sourceRef: "abc",
      title: "Reentrancy in withdraw",
      severity: "HIGH",
    });
    expect(c.tags).toEqual([]);
    expect(c.rootCause).toBe("");
  });

  it("rejects an invalid severity", () => {
    expect(() =>
      Candidate.parse({
        id: "x",
        kind: "finding",
        sourceRef: "x",
        title: "t",
        severity: "SEV-1",
      }),
    ).toThrow();
  });

  it("rejects an invalid kind", () => {
    expect(() =>
      Candidate.parse({
        id: "x",
        kind: "blog",
        sourceRef: "x",
        title: "t",
        severity: "HIGH",
      }),
    ).toThrow();
  });
});

describe("RootCause schema", () => {
  it("parses a full explore output", () => {
    const rc = RootCause.parse({
      summary: "s",
      rootCause: "r",
      vulnerableCode: "v",
      fixedCode: "f",
      triggerConditions: ["a", "b"],
      attackFlow: ["1"],
      logicBug: true,
      detectabilityHint: "ordering",
      sources: ["u"],
    });
    expect(rc.triggerConditions).toHaveLength(2);
    expect(rc.logicBug).toBe(true);
  });

  it("applies defaults for a sparse output", () => {
    const rc = RootCause.parse({ rootCause: "only this" });
    expect(rc.triggerConditions).toEqual([]);
    expect(rc.logicBug).toBe(false);
    expect(rc.sources).toEqual([]);
  });
});

describe("normalizeSeverity", () => {
  it("maps variants to the enum", () => {
    expect(normalizeSeverity("high")).toBe("HIGH");
    expect(normalizeSeverity("Critical")).toBe("CRITICAL");
    expect(normalizeSeverity("med")).toBe("MEDIUM");
    expect(normalizeSeverity("informational")).toBe("INFO");
  });
});

describe("status enum", () => {
  it("terminal statuses are valid statuses", () => {
    for (const s of TERMINAL_STATUSES) {
      expect(CandidateStatus.safeParse(s).success).toBe(true);
    }
  });
});
