import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { ZodTypeAny, infer as zInfer } from "zod";

const here = dirname(fileURLToPath(import.meta.url));
const PROMPTS_DIR = resolve(here, "prompts");

/**
 * Load a prompt template by stage name and interpolate `${var}` placeholders.
 * Missing variables are left as the empty string.
 */
export function renderPrompt(
  stage: string,
  vars: Record<string, string>,
): string {
  const raw = readFileSync(join(PROMPTS_DIR, `${stage}.md`), "utf8");
  return raw.replace(/\$\{(\w+)\}/g, (_, k) => vars[k] ?? "");
}

export interface OpencodeOptions {
  bin: string; // OPENCODE_BIN
  model: string; // OPENCODE_MODEL (provider/model)
  attach?: string; // OPENCODE_ATTACH server url, optional
  cwd?: string; // --dir
  attachFiles?: string[]; // -f
  extraArgs?: string[];
  maxRetries?: number; // schema-mismatch retries (default 2)
}

/** Thrown when the agent never produced schema-valid output within the budget. */
export class OpencodeStageError extends Error {}

/**
 * Run one opencode stage headlessly and return its validated structured output.
 *
 * The agent is instructed (in the prompt) to write a single JSON object to the
 * path in the FORGE_OUT env var. We read + zod-validate that file. On invalid
 * or missing output we retry up to `maxRetries`, appending the validation error
 * to the prompt so the agent can correct itself.
 *
 * Verified opencode CLI (v1.17.x):
 *   opencode run "<msg>" --format json -m <model> --dir <d> \
 *     -f <file> --attach <url> --dangerously-skip-permissions
 */
export function runStage<S extends ZodTypeAny>(
  prompt: string,
  schema: S,
  opts: OpencodeOptions,
): zInfer<S> {
  const work = mkdtempSync(join(tmpdir(), "forge-oc-"));
  const outPath = join(work, "result.json");
  const maxRetries = opts.maxRetries ?? 2;
  try {
    let lastErr = "";
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      rmSync(outPath, { force: true });
      const fullPrompt = buildPrompt(prompt, outPath, lastErr);
      const args = ["run", fullPrompt, "--format", "json"];
      if (opts.model) args.push("-m", opts.model);
      if (opts.cwd) args.push("--dir", opts.cwd);
      if (opts.attach) args.push("--attach", opts.attach);
      args.push("--dangerously-skip-permissions");
      for (const f of opts.attachFiles ?? []) args.push("-f", f);
      if (opts.extraArgs) args.push(...opts.extraArgs);

      const proc = spawnSync(opts.bin, args, {
        encoding: "utf8",
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, FORGE_OUT: outPath },
      });

      if (!existsSync(outPath)) {
        lastErr = `No result file was written to FORGE_OUT. exit=${proc.status}. stderr: ${(proc.stderr ?? "").slice(0, 800)}`;
        continue;
      }
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(readFileSync(outPath, "utf8"));
      } catch (e) {
        lastErr = `Result file was not valid JSON: ${(e as Error).message}`;
        continue;
      }
      const result = schema.safeParse(parsedJson);
      if (result.success) return result.data;
      lastErr = `JSON did not match the required schema: ${result.error.issues
        .map((i) => `${i.path.join(".")}: ${i.message}`)
        .join("; ")}`;
    }
    throw new OpencodeStageError(
      `opencode stage failed after ${maxRetries + 1} attempts: ${lastErr}`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function buildPrompt(prompt: string, outPath: string, lastErr: string): string {
  const correction = lastErr
    ? `\n\nYOUR PREVIOUS ATTEMPT FAILED: ${lastErr}\nFix it and try again.`
    : "";
  return (
    `${prompt}\n\n` +
    `=== OUTPUT CONTRACT ===\n` +
    `Write your answer as a SINGLE JSON object to the file at this exact path:\n` +
    `${outPath}\n` +
    `(this path is also available in the FORGE_OUT environment variable). ` +
    `Write nothing else to that file. Do not wrap the JSON in markdown fences.` +
    correction
  );
}

/**
 * Convenience: write candidate context files into a temp dir and return their
 * paths for `attachFiles`. Caller is responsible for cleanup of the returned dir.
 */
export function stageContextFiles(
  files: Record<string, string>,
): { dir: string; paths: string[] } {
  const dir = mkdtempSync(join(tmpdir(), "forge-ctx-"));
  const paths: string[] = [];
  for (const [name, content] of Object.entries(files)) {
    const p = join(dir, name);
    writeFileSync(p, content);
    paths.push(p);
  }
  return { dir, paths };
}

/** List bundled prompt stage names (used by tests/docs). */
export function availablePrompts(): string[] {
  return readdirSync(PROMPTS_DIR)
    .filter((f) => f.endsWith(".md"))
    .map((f) => f.replace(/\.md$/, ""));
}
