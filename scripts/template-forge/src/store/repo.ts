import type { DB } from "./db.js";
import {
  Candidate,
  type CandidateStatus,
  type Stage,
  type VariantResult,
  type Provenance,
} from "../types.js";

function now(): string {
  return new Date().toISOString();
}

export interface RunRow {
  id: string;
  kind: string;
  started_at: string;
  status: string;
  args_json: string;
}

export interface CandidateRow {
  id: string;
  kind: string;
  source_ref: string;
  title: string;
  severity: string;
  bucket: string | null;
  status: CandidateStatus;
  payload_json: string;
}

/** Typed data-access layer over the SQLite database. */
export class Repo {
  constructor(private readonly db: DB) {}

  // ---- runs ----------------------------------------------------------------
  createRun(id: string, kind: string, args: unknown): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO run (id, kind, started_at, status, args_json)
         VALUES (?, ?, ?, 'running', ?)`,
      )
      .run(id, kind, now(), JSON.stringify(args ?? {}));
  }

  setRunStatus(id: string, status: string): void {
    this.db.prepare(`UPDATE run SET status = ? WHERE id = ?`).run(status, id);
  }

  /** Latest non-terminal run of a kind (status running|paused), if any. */
  getResumableRun(kind: string): RunRow | undefined {
    return this.db
      .prepare(
        `SELECT * FROM run WHERE kind = ? AND status IN ('running','paused')
         ORDER BY started_at DESC LIMIT 1`,
      )
      .get(kind) as RunRow | undefined;
  }

  // ---- candidates ----------------------------------------------------------
  /** Insert a candidate at status 'pending' unless it already exists (dedup). */
  upsertCandidate(c: Candidate): { inserted: boolean } {
    const existing = this.db
      .prepare(`SELECT id FROM candidate WHERE kind = ? AND source_ref = ?`)
      .get(c.kind, c.sourceRef) as { id: string } | undefined;
    if (existing) return { inserted: false };
    const ts = now();
    this.db
      .prepare(
        `INSERT INTO candidate
           (id, kind, source_ref, title, severity, bucket, status,
            created_at, updated_at, payload_json)
         VALUES (?, ?, ?, ?, ?, NULL, 'pending', ?, ?, ?)`,
      )
      .run(
        c.id,
        c.kind,
        c.sourceRef,
        c.title,
        c.severity,
        ts,
        ts,
        JSON.stringify(c),
      );
    return { inserted: true };
  }

  /** Overwrite a candidate's stored payload (used after the explore stage enriches it). */
  updateCandidatePayload(c: Candidate): void {
    this.db
      .prepare(
        `UPDATE candidate SET payload_json = ?, title = ?, severity = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(JSON.stringify(c), c.title, c.severity, now(), c.id);
  }

  getCandidate(id: string): Candidate | undefined {
    const row = this.db
      .prepare(`SELECT payload_json FROM candidate WHERE id = ?`)
      .get(id) as { payload_json: string } | undefined;
    return row ? Candidate.parse(JSON.parse(row.payload_json)) : undefined;
  }

  getCandidateRow(id: string): CandidateRow | undefined {
    return this.db
      .prepare(`SELECT * FROM candidate WHERE id = ?`)
      .get(id) as CandidateRow | undefined;
  }

  /** Candidates currently at a given status. */
  getCandidatesByStatus(status: CandidateStatus): CandidateRow[] {
    return this.db
      .prepare(`SELECT * FROM candidate WHERE status = ? ORDER BY created_at`)
      .all(status) as CandidateRow[];
  }

  /** All candidates whose status is not terminal (resume targets). */
  getActiveCandidates(): CandidateRow[] {
    return this.db
      .prepare(
        `SELECT * FROM candidate
         WHERE status NOT IN ('cataloged','parked','shelved','promoted')
         ORDER BY created_at`,
      )
      .all() as CandidateRow[];
  }

  /**
   * Optimistic status transition. Only moves the candidate when its current
   * status equals `from`. Returns true if a row changed.
   */
  advanceStatus(
    id: string,
    from: CandidateStatus,
    to: CandidateStatus,
    bucket?: string,
  ): boolean {
    const info = this.db
      .prepare(
        `UPDATE candidate SET status = ?, updated_at = ?,
           bucket = COALESCE(?, bucket)
         WHERE id = ? AND status = ?`,
      )
      .run(to, now(), bucket ?? null, id, from);
    return info.changes === 1;
  }

  /** Force status (used by terminal transitions from any state). */
  setStatus(id: string, to: CandidateStatus): void {
    this.db
      .prepare(`UPDATE candidate SET status = ?, updated_at = ? WHERE id = ?`)
      .run(to, now(), id);
  }

  statusCounts(): Record<string, number> {
    const rows = this.db
      .prepare(`SELECT status, COUNT(*) n FROM candidate GROUP BY status`)
      .all() as { status: string; n: number }[];
    return Object.fromEntries(rows.map((r) => [r.status, r.n]));
  }

  // ---- stage results (resume cache) ----------------------------------------
  putStageResult(
    candidateId: string,
    stage: Stage,
    attempt: number,
    status: "ok" | "fail",
    output: unknown,
    machineLog = "",
  ): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO stage_result
           (candidate_id, stage, attempt, status, output_json, machine_log, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        candidateId,
        stage,
        attempt,
        status,
        output == null ? null : JSON.stringify(output),
        machineLog,
        now(),
      );
  }

  /** Latest result for a stage, or undefined. Used to skip work on resume. */
  getStageResult(
    candidateId: string,
    stage: Stage,
  ): { status: string; output: unknown; attempt: number } | undefined {
    const row = this.db
      .prepare(
        `SELECT status, output_json, attempt FROM stage_result
         WHERE candidate_id = ? AND stage = ?
         ORDER BY attempt DESC LIMIT 1`,
      )
      .get(candidateId, stage) as
      | { status: string; output_json: string | null; attempt: number }
      | undefined;
    if (!row) return undefined;
    return {
      status: row.status,
      attempt: row.attempt,
      output: row.output_json ? JSON.parse(row.output_json) : null,
    };
  }

  isStageDone(candidateId: string, stage: Stage): boolean {
    const r = this.getStageResult(candidateId, stage);
    return r?.status === "ok";
  }

  countStageAttempts(candidateId: string, stage: Stage): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) n FROM stage_result WHERE candidate_id = ? AND stage = ?`,
      )
      .get(candidateId, stage) as { n: number };
    return row.n;
  }

  // ---- variant results -----------------------------------------------------
  putVariantResult(v: VariantResult, round: number): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO variant_result
           (candidate_id, variant_id, kind, expected, actual, passed, round, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        v.candidateId,
        v.variantId,
        v.kind,
        v.expectedFire ? 1 : 0,
        v.actualFire ? 1 : 0,
        v.passed ? 1 : 0,
        round,
        now(),
      );
  }

  getVariantRound(candidateId: string, round: number): VariantResult[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM variant_result WHERE candidate_id = ? AND round = ?`,
      )
      .all(candidateId, round) as {
      candidate_id: string;
      variant_id: string;
      kind: "recall" | "precision";
      expected: number;
      actual: number;
      passed: number;
    }[];
    return rows.map((r) => ({
      candidateId: r.candidate_id,
      variantId: r.variant_id,
      kind: r.kind,
      expectedFire: r.expected === 1,
      actualFire: r.actual === 1,
      passed: r.passed === 1,
    }));
  }

  // ---- provenance ----------------------------------------------------------
  putProvenance(p: Provenance): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO provenance
           (candidate_id, links_json, cwe, owasp_sc, confidence, dedup_of)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        p.candidateId,
        JSON.stringify(p.links),
        JSON.stringify(p.cwe),
        JSON.stringify(p.owaspSc),
        p.confidence,
        p.dedupOf ?? null,
      );
  }

  // ---- cursors -------------------------------------------------------------
  getCursor(source: string): unknown {
    const row = this.db
      .prepare(`SELECT cursor_json FROM fetch_cursor WHERE source = ?`)
      .get(source) as { cursor_json: string } | undefined;
    return row ? JSON.parse(row.cursor_json) : undefined;
  }

  setCursor(source: string, cursor: unknown): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO fetch_cursor (source, cursor_json, updated_at)
         VALUES (?, ?, ?)`,
      )
      .run(source, JSON.stringify(cursor), now());
  }

  // ---- single-writer lock --------------------------------------------------
  /** Acquire the advisory lock. Returns false if already held by someone else. */
  acquireLock(owner: string): boolean {
    const info = this.db
      .prepare(
        `UPDATE forge_lock SET owner = ?, taken_at = ?
         WHERE id = 1 AND owner IS NULL`,
      )
      .run(owner, now());
    return info.changes === 1;
  }

  releaseLock(owner: string): void {
    this.db
      .prepare(
        `UPDATE forge_lock SET owner = NULL, taken_at = NULL
         WHERE id = 1 AND owner = ?`,
      )
      .run(owner);
  }

  /** Run a function inside an immediate transaction. */
  tx<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }
}
