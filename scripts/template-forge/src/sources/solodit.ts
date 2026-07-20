import { createHash } from "node:crypto";
import { z } from "zod";
import { Candidate, normalizeSeverity, type Severity } from "../types.js";
import type { Repo } from "../store/repo.js";
import { TokenBucket } from "../util/ratelimit.js";

/** Raw Solodit finding shape (subset we consume). */
export const SoloditFinding = z.object({
  id: z.string(),
  slug: z.string().optional(),
  title: z.string(),
  impact: z.string(), // Critical|High|Medium|Low|Informational
  auditFirm: z.string().optional(),
  protocol: z.string().optional(),
  tags: z.array(z.string()).default([]),
  body: z.string().default(""),
  recommendation: z.string().default(""),
  code: z.string().default(""),
  links: z.array(z.string()).default([]),
});
export type SoloditFinding = z.infer<typeof SoloditFinding>;

export interface SearchOpts {
  impact?: Severity[]; // defaults to [HIGH, MEDIUM]
  page?: number;
}

export interface SearchPage {
  items: SoloditFinding[];
  nextPage: number | null;
}

export interface SoloditClient {
  searchVulnerabilities(opts: SearchOpts): Promise<SearchPage>;
  getFinding(id: string): Promise<SoloditFinding | undefined>;
}

// ---- Fixture client (tests + offline) ------------------------------------

/** Client backed by a static JSON blob. Paginates one item per page. */
export class FixtureSoloditClient implements SoloditClient {
  private readonly all: SoloditFinding[];
  constructor(raw: { items: unknown[] }, private readonly pageSize = 2) {
    this.all = raw.items.map((i) => SoloditFinding.parse(i));
  }
  async searchVulnerabilities(opts: SearchOpts): Promise<SearchPage> {
    const wanted = new Set(opts.impact ?? (["HIGH", "MEDIUM"] as Severity[]));
    const filtered = this.all.filter((f) =>
      wanted.has(normalizeSeverity(f.impact)),
    );
    const page = opts.page ?? 0;
    const start = page * this.pageSize;
    const items = filtered.slice(start, start + this.pageSize);
    const nextPage = start + this.pageSize < filtered.length ? page + 1 : null;
    return { items, nextPage };
  }
  async getFinding(id: string): Promise<SoloditFinding | undefined> {
    return this.all.find((f) => f.id === id);
  }
}

// ---- REST client ----------------------------------------------------------

/** Default Solodit findings endpoint (verified live 2026-06). */
export const SOLODIT_FINDINGS_URL =
  "https://solodit.cyfrin.io/api/v1/solodit/findings";

/** Raw shape of a finding row returned by the Solodit REST API. */
interface SoloditApiRow {
  id: number | string;
  slug?: string;
  title: string;
  impact: string; // HIGH | MEDIUM | LOW | ...
  summary?: string;
  content?: string; // markdown: severity + description + recommendation
  firm_name?: string;
  protocol_name?: string;
  source_link?: string;
  github_link?: string;
}

/**
 * Solodit REST client. Verified against the live API (2026-06):
 *   POST {base}            (base defaults to SOLODIT_FINDINGS_URL)
 *   header: X-Cyfrin-API-Key: <key>
 *   body:   { page: <1-based>, pageSize, filters: { impact: ["HIGH", ...] } }
 *   resp:   { findings: [...], metadata: { totalResults, currentPage, totalPages },
 *             rateLimit: { limit, remaining, reset } }
 */
export class RestSoloditClient implements SoloditClient {
  constructor(
    private readonly apiKey: string,
    private readonly base: string,
    private readonly bucket: TokenBucket,
    private readonly pageSize = 20,
  ) {}

  async searchVulnerabilities(opts: SearchOpts): Promise<SearchPage> {
    await this.bucket.take();
    const impact = (opts.impact ?? ["HIGH", "MEDIUM"]) as string[];
    const apiPage = (opts.page ?? 0) + 1; // API is 1-indexed
    const res = await fetch(this.base, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Cyfrin-API-Key": this.apiKey,
        "User-Agent": "template-forge",
      },
      body: JSON.stringify({
        page: apiPage,
        pageSize: this.pageSize,
        filters: { impact },
      }),
    });
    if (res.status === 429) {
      const ra = Number(res.headers.get("retry-after") ?? "0");
      this.bucket.onRetryAfter(Number.isFinite(ra) && ra > 0 ? ra : undefined);
      throw new Error("solodit 429 rate-limited");
    }
    if (!res.ok) throw new Error(`solodit ${res.status}: ${await res.text()}`);
    const json = (await res.json()) as {
      findings?: SoloditApiRow[];
      metadata?: { currentPage?: number; totalPages?: number };
    };
    const rows = json.findings ?? [];
    const current = json.metadata?.currentPage ?? apiPage;
    const totalPages = json.metadata?.totalPages ?? current;
    // nextPage is 0-based for our internal loop.
    const nextPage = current < totalPages ? (opts.page ?? 0) + 1 : null;
    return { items: rows.map(rowToFinding), nextPage };
  }

  async getFinding(id: string): Promise<SoloditFinding | undefined> {
    // The list endpoint carries full content; a dedicated lookup is not needed.
    return undefined;
  }
}

/** Map a raw Solodit API row to our normalized finding shape. */
function rowToFinding(r: SoloditApiRow): SoloditFinding {
  const body = [r.summary, r.content].filter(Boolean).join("\n\n");
  return SoloditFinding.parse({
    id: String(r.id),
    slug: r.slug,
    title: r.title,
    impact: r.impact,
    auditFirm: r.firm_name,
    protocol: r.protocol_name,
    tags: [],
    body,
    recommendation: "",
    code: "",
    links: [r.source_link, r.github_link].filter(
      (x): x is string => typeof x === "string" && x.length > 0,
    ),
  });
}

// ---- normalize + fetch loop ----------------------------------------------

export function soloditCandidateId(f: SoloditFinding): string {
  const ref = f.slug ?? f.id;
  return `finding:${createHash("sha1").update(ref).digest("hex").slice(0, 12)}`;
}

export function toCandidate(
  f: SoloditFinding,
  sourceCode?: string,
): Candidate {
  return Candidate.parse({
    id: soloditCandidateId(f),
    kind: "finding",
    sourceRef: f.slug ?? f.id,
    title: f.title,
    severity: normalizeSeverity(f.impact),
    rootCause: [f.body, f.recommendation].filter(Boolean).join("\n\n"),
    code: sourceCode && sourceCode.length > f.code.length ? sourceCode : f.code,
    tags: f.tags,
    links: f.links,
  });
}

export interface FetchFindingsOpts {
  impact?: Severity[];
  limit?: number;
  /** Optional client-side filter: only ingest findings whose title/body match. */
  keyword?: RegExp;
}

/**
 * Fetch Solodit findings (default High+Medium), dedup, optionally deep-fetch
 * source, and upsert Candidates. Page cursor is checkpointed for resume;
 * `stop()` pauses cleanly between pages.
 */
export async function fetchFindings(
  client: SoloditClient,
  repo: Repo,
  opts: FetchFindingsOpts,
  deepSource?: (links: string[]) => Promise<string | undefined>,
  stop: () => boolean = () => false,
): Promise<{ inserted: number; scanned: number }> {
  const impact = opts.impact ?? (["HIGH", "MEDIUM"] as Severity[]);
  const cursor = (repo.getCursor("solodit") as { page?: number } | undefined) ?? {
    page: 0,
  };
  let page = cursor.page ?? 0;
  let inserted = 0;
  let scanned = 0;

  for (;;) {
    if (stop()) break;
    const res = await client.searchVulnerabilities({ impact, page });
    for (const f of res.items) {
      scanned++;
      if (opts.keyword && !opts.keyword.test(`${f.title}\n${f.body}`)) continue;
      const source = deepSource ? await deepSource(f.links) : undefined;
      const { inserted: ins } = repo.upsertCandidate(toCandidate(f, source));
      if (ins) inserted++;
      if (opts.limit && inserted >= opts.limit) {
        repo.setCursor("solodit", { page });
        return { inserted, scanned };
      }
    }
    if (res.nextPage == null) {
      repo.setCursor("solodit", { page: page + 1, done: true });
      break;
    }
    page = res.nextPage;
    repo.setCursor("solodit", { page });
  }
  return { inserted, scanned };
}
