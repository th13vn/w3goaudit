import { describe, it, expect } from "vitest";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  runStage,
  renderPrompt,
  availablePrompts,
  OpencodeStageError,
} from "./opencode.js";
import { Classification } from "../types.js";

const here = dirname(fileURLToPath(import.meta.url));
const stub = (n: string) => resolve(here, "__fixtures__", n);

describe("renderPrompt", () => {
  it("interpolates variables into a real prompt template", () => {
    const out = renderPrompt("classify", {
      title: "Arbitrary call",
      severity: "HIGH",
      rootCause: "target is user controlled",
      code: "x.call(data)",
    });
    expect(out).toContain("Arbitrary call");
    expect(out).toContain("target is user controlled");
    expect(out).not.toContain("${title}");
  });

  it("ships all stage prompts", () => {
    expect(availablePrompts().sort()).toEqual([
      "classify",
      "draft",
      "explore",
      "repair",
      "variants",
      "verify",
    ]);
  });
});

describe("runStage", () => {
  it("returns validated output from a well-behaved agent", () => {
    const out = runStage("classify this", Classification, {
      bin: stub("stub-ok.sh"),
      model: "test/model",
      maxRetries: 0,
    });
    expect(out.bucket).toBe("taint");
    expect(out.targetPrimitive).toBe("args+tainted_from");
  });

  it("throws after retries when output never matches schema", () => {
    expect(() =>
      runStage("classify this", Classification, {
        bin: stub("stub-bad.sh"),
        model: "test/model",
        maxRetries: 1,
      }),
    ).toThrow(OpencodeStageError);
  });

  it("throws when the agent writes no result file", () => {
    expect(() =>
      runStage("classify this", Classification, {
        bin: stub("stub-nofile.sh"),
        model: "test/model",
        maxRetries: 1,
      }),
    ).toThrow(/result file|attempts/i);
  });
});
