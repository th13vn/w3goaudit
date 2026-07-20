import { describe, it, expect } from "vitest";
import { needsExploration } from "./forge-deps.js";
import { Candidate } from "../types.js";

const mk = (over: Partial<Candidate>) =>
  Candidate.parse({
    id: "x",
    kind: "finding",
    sourceRef: "x",
    title: "t",
    severity: "HIGH",
    ...over,
  });

describe("needsExploration", () => {
  it("always explores incidents (PoCs lack inline analysis)", () => {
    expect(needsExploration(mk({ kind: "incident", rootCause: "" }), 400)).toBe(
      true,
    );
    // even a long incident rootCause still explores
    expect(
      needsExploration(mk({ kind: "incident", rootCause: "x".repeat(999) }), 400),
    ).toBe(true);
  });

  it("explores findings only when their root cause is thin", () => {
    expect(needsExploration(mk({ rootCause: "short" }), 400)).toBe(true);
    expect(needsExploration(mk({ rootCause: "x".repeat(500) }), 400)).toBe(
      false,
    );
  });
});
