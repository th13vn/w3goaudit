import { appendFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { FORGE_ROOT } from "./config.js";

const REPORTS = resolve(FORGE_ROOT, "reports");

export type Level = "info" | "warn" | "error";

/** Minimal structured logger: prints to stderr and appends to a run report. */
export class Logger {
  private readonly reportPath?: string;
  constructor(runId?: string) {
    if (runId) {
      mkdirSync(REPORTS, { recursive: true });
      this.reportPath = resolve(REPORTS, `${runId}.md`);
    }
  }

  log(level: Level, msg: string): void {
    const line = `[${level}] ${msg}`;
    if (level === "error") console.error(line);
    else console.error(line); // stderr keeps stdout clean for machine output
    if (this.reportPath) {
      appendFileSync(this.reportPath, `- ${line}\n`);
    }
  }

  info(msg: string): void {
    this.log("info", msg);
  }
  warn(msg: string): void {
    this.log("warn", msg);
  }
  error(msg: string): void {
    this.log("error", msg);
  }

  /** Append a free-form markdown section to the run report. */
  section(title: string, body: string): void {
    if (this.reportPath)
      appendFileSync(this.reportPath, `\n## ${title}\n\n${body}\n`);
  }
}
