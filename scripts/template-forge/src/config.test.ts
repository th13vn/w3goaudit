import { describe, it, expect } from "vitest";
import { loadConfig } from "./config.js";

const base = {
  CYFRIN_API_KEY: "sk_test",
  OPENCODE_MODEL: "anthropic/claude-opus-4-8",
};

describe("loadConfig", () => {
  it("throws naming the missing required key", () => {
    expect(() => loadConfig({} as NodeJS.ProcessEnv)).toThrow(/CYFRIN_API_KEY/);
  });

  it("throws when OPENCODE_MODEL missing", () => {
    expect(() =>
      loadConfig({ CYFRIN_API_KEY: "sk_test" } as NodeJS.ProcessEnv),
    ).toThrow(/OPENCODE_MODEL/);
  });

  it("applies defaults when only required keys present", () => {
    const cfg = loadConfig(base as NodeJS.ProcessEnv);
    expect(cfg.RATE_LIMIT_RPS).toBe(1);
    expect(cfg.REPAIR_MAX_RETRIES).toBe(3);
    expect(cfg.IMPROVE_STABLE_ROUNDS).toBe(2);
    expect(cfg.SOLODIT_TRANSPORT).toBe("mcp");
    expect(cfg.OPENCODE_BIN).toBe("opencode");
    expect(cfg.W3GOAUDIT_BIN).toBe("../../w3goaudit");
  });

  it("coerces numeric env strings", () => {
    const cfg = loadConfig({
      ...base,
      RATE_LIMIT_RPS: "5",
      REPAIR_MAX_RETRIES: "1",
    } as NodeJS.ProcessEnv);
    expect(cfg.RATE_LIMIT_RPS).toBe(5);
    expect(cfg.REPAIR_MAX_RETRIES).toBe(1);
  });

  it("rejects an invalid transport", () => {
    expect(() =>
      loadConfig({ ...base, SOLODIT_TRANSPORT: "graphql" } as NodeJS.ProcessEnv),
    ).toThrow(/SOLODIT_TRANSPORT/);
  });
});
