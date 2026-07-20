import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { runCli, fail } from "./_common.js";
import {
  fetchFindings,
  FixtureSoloditClient,
  RestSoloditClient,
  SOLODIT_FINDINGS_URL,
  type SoloditClient,
} from "../sources/solodit.js";
import { fetchFindingSource } from "../enrich/github.js";
import { TokenBucket } from "../util/ratelimit.js";
import { normalizeSeverity, type Severity } from "../types.js";

/**
 * Pull Solodit findings (High+Medium by default) into candidates. Resumable via
 * the saved page cursor; rate-limited.
 *   npm run fetch:findings -- --severity High,Medium --limit 50
 *   npm run fetch:findings -- --fixture ./local-findings.json   # offline
 */
runCli("fetch_findings", "fetch_findings", async ({ cfg, repo, stop, log }) => {
  const { values } = parseArgs({
    options: {
      severity: { type: "string" },
      limit: { type: "string" },
      fixture: { type: "string" },
      keyword: { type: "string" },
      "no-source": { type: "boolean" },
    },
    allowPositionals: true,
  });

  const impact: Severity[] = (values.severity ?? "High,Medium")
    .split(",")
    .map((s) => normalizeSeverity(s));

  let client: SoloditClient;
  if (values.fixture) {
    client = new FixtureSoloditClient(
      JSON.parse(readFileSync(values.fixture, "utf8")),
    );
  } else if (cfg.SOLODIT_TRANSPORT === "rest") {
    client = new RestSoloditClient(
      cfg.CYFRIN_API_KEY,
      cfg.SOLODIT_API_BASE || SOLODIT_FINDINGS_URL,
      new TokenBucket(cfg.RATE_LIMIT_RPS),
    );
  } else {
    throw new Error(
      "SOLODIT_TRANSPORT=mcp is served via opencode's MCP tools, not the deterministic fetcher. " +
        "Use --fixture <file>, or set SOLODIT_TRANSPORT=rest + SOLODIT_API_BASE.",
    );
  }

  const r = await fetchFindings(
    client,
    repo,
    {
      impact,
      limit: values.limit ? Number(values.limit) : undefined,
      keyword: values.keyword ? new RegExp(values.keyword, "i") : undefined,
    },
    values["no-source"] ? undefined : fetchFindingSource,
    () => stop.stopped(),
  );
  log.info(`findings: inserted ${r.inserted}, scanned ${r.scanned}`);
}).catch(fail);
