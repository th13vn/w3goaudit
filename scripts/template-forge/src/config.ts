import { z } from "zod";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
/** Repo-relative root of the template-forge folder (scripts/template-forge). */
export const FORGE_ROOT = resolve(here, "..");

/**
 * Minimal .env loader (no dependency on dotenv). Parses KEY=VALUE lines from
 * `<FORGE_ROOT>/.env` into process.env without overwriting existing values.
 * Lines starting with `#` and blank lines are ignored.
 */
export function loadDotEnv(path = resolve(FORGE_ROOT, ".env")): void {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return; // no .env file — rely on the ambient environment
  }
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

const nonEmpty = z.string().min(1);

const ConfigSchema = z.object({
  CYFRIN_API_KEY: nonEmpty,
  ETHERSCAN_API_KEY: z.string().default(""),
  GITHUB_TOKEN: z.string().default(""),
  FORK_RPC_URL: z.string().default(""),
  OPENCODE_MODEL: nonEmpty,
  OPENCODE_BIN: z.string().default("opencode"),
  OPENCODE_ATTACH: z.string().default(""),
  W3GOAUDIT_BIN: z.string().default("../../w3goaudit"),
  W3GOAUDIT_CORPUS: z.string().default("../../test-data"),
  SOLODIT_TRANSPORT: z.enum(["mcp", "rest"]).default("mcp"),
  SOLODIT_API_BASE: z.string().default(""),
  RATE_LIMIT_RPS: z.coerce.number().positive().default(1),
  REPAIR_MAX_RETRIES: z.coerce.number().int().nonnegative().default(3),
  IMPROVE_STABLE_ROUNDS: z.coerce.number().int().positive().default(2),
  // Path to the finding-root-cause skill the `explore` stage loads. Default
  // resolves the repo's _ai-globals copy relative to FORGE_ROOT; embedded
  // fallback is used if the file is absent.
  ROOTCAUSE_SKILL_PATH: z
    .string()
    .default("../../../../../_ai-globals/skills/finding-root-cause/SKILL.md"),
  // Findings with rootCause shorter than this get AI exploration; longer ones skip it.
  EXPLORE_MIN_ROOTCAUSE_CHARS: z.coerce.number().int().nonnegative().default(400),
});

export type Config = z.infer<typeof ConfigSchema>;

/**
 * Load and validate configuration from the environment (after reading .env).
 * Throws an Error naming the first missing/invalid key.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = ConfigSchema.safeParse(env);
  if (!result.success) {
    const issue = result.error.issues[0];
    const key = issue?.path.join(".") ?? "config";
    throw new Error(
      `template-forge config error: ${key} — ${issue?.message ?? "invalid"}. ` +
        `Copy .env.example to .env and fill it in.`,
    );
  }
  return result.data;
}
