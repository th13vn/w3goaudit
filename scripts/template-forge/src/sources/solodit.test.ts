import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FixtureSoloditClient,
  fetchFindings,
  toCandidate,
  SoloditFinding,
} from "./solodit.js";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";

const here = dirname(fileURLToPath(import.meta.url));
const raw = JSON.parse(
  readFileSync(resolve(here, "__fixtures__", "solodit-findings.json"), "utf8"),
) as { items: unknown[] };

describe("FixtureSoloditClient", () => {
  it("filters to High+Medium and paginates", async () => {
    const c = new FixtureSoloditClient(raw, 1); // 1 per page
    const p0 = await c.searchVulnerabilities({ page: 0 });
    expect(p0.items).toHaveLength(1);
    expect(p0.nextPage).toBe(1);
    // f-003 (Informational) and f-004 (Low) are filtered out -> only 2 total.
    const p1 = await c.searchVulnerabilities({ page: 1 });
    expect(p1.items).toHaveLength(1);
    expect(p1.nextPage).toBeNull();
  });

  it("getFinding returns by id", async () => {
    const c = new FixtureSoloditClient(raw);
    expect((await c.getFinding("f-002"))?.slug).toBe("tx-origin-auth");
  });
});

describe("toCandidate", () => {
  it("maps a finding to a normalized candidate", () => {
    const f = SoloditFinding.parse(raw.items[0]);
    const cand = toCandidate(f);
    expect(cand.kind).toBe("finding");
    expect(cand.severity).toBe("HIGH");
    expect(cand.rootCause).toContain("CEI violation");
  });

  it("prefers fetched source over the snippet when longer", () => {
    const f = SoloditFinding.parse(raw.items[0]);
    const big = "// full source\n".repeat(50);
    expect(toCandidate(f, big).code).toBe(big);
  });
});

describe("fetchFindings", () => {
  let repo: Repo;
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("ingests only High+Medium, dedups, checkpoints page", async () => {
    const c = new FixtureSoloditClient(raw, 1);
    const r = await fetchFindings(c, repo, {});
    expect(r.inserted).toBe(2); // High + Medium only
    expect(repo.getCandidatesByStatus("pending")).toHaveLength(2);

    // resume-safe: second run inserts nothing new
    const r2 = await fetchFindings(c, repo, {});
    expect(r2.inserted).toBe(0);
  });

  it("respects the limit and saves the cursor", async () => {
    const c = new FixtureSoloditClient(raw, 1);
    const r = await fetchFindings(c, repo, { limit: 1 });
    expect(r.inserted).toBe(1);
    expect(repo.getCursor("solodit")).toBeDefined();
  });

  it("stop() pauses before fetching", async () => {
    const c = new FixtureSoloditClient(raw, 1);
    const r = await fetchFindings(c, repo, {}, undefined, () => true);
    expect(r.inserted).toBe(0);
  });

  it("calls deepSource for source enrichment", async () => {
    const c = new FixtureSoloditClient(raw, 10);
    let called = 0;
    await fetchFindings(c, repo, {}, async () => {
      called++;
      return undefined;
    });
    expect(called).toBe(2);
  });
});
