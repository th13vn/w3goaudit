import type { IncidentMeta } from "../types.js";
import type { IncidentEnricher } from "../sources/defihacklabs.js";
import { getVerifiedSource, getTxSummary } from "./etherscan.js";

/**
 * Static-first incident enrichment: verified source + tx summary via Etherscan.
 * Root cause comes from the PoC's inline `// @Analysis` prose (parsed by
 * defihacklabs.parsePoc), so no blog fetching is needed.
 *
 * NOTE: blog fetching is intentionally DISABLED for now (`blogText` returns
 * undefined). The reference links (often X/Twitter or JS-heavy pages) did not
 * yield useful static text via plain fetch; the inline analysis is better. The
 * `enrich/blogs.ts` helpers are kept for a future, better fetch strategy.
 */
export class StaticIncidentEnricher implements IncidentEnricher {
  constructor(private readonly etherscanKey: string) {}

  vulnerableSource(meta: IncidentMeta): Promise<string | undefined> {
    return getVerifiedSource(meta, this.etherscanKey);
  }

  txSummary(meta: IncidentMeta): Promise<string | undefined> {
    return getTxSummary(meta, this.etherscanKey);
  }

  async blogText(): Promise<string | undefined> {
    return undefined; // disabled — see class doc; root cause uses inline @Analysis
  }
}

/** Enricher that does nothing (used by --no-enrich or offline runs). */
export class NoopIncidentEnricher implements IncidentEnricher {
  async vulnerableSource(): Promise<undefined> {
    return undefined;
  }
  async txSummary(): Promise<undefined> {
    return undefined;
  }
  async blogText(): Promise<undefined> {
    return undefined;
  }
}
