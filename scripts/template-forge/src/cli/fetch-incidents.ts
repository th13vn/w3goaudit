import { parseArgs } from "node:util";
import { runCli, fail } from "./_common.js";
import { HttpGitHubClient } from "../util/github.js";
import {
  fetchIncidents,
  DEFIHACKLABS_REPO,
} from "../sources/defihacklabs.js";
import {
  StaticIncidentEnricher,
  NoopIncidentEnricher,
} from "../enrich/incident-enricher.js";

/**
 * Pull DeFiHackLabs incidents into candidates. Resumable via the saved cursor.
 *   npm run fetch:incidents -- --since 2024-01 --limit 20 [--no-enrich]
 */
runCli("fetch_incidents", "fetch_incidents", async ({ cfg, repo, stop, log }) => {
  const { values } = parseArgs({
    options: {
      since: { type: "string" },
      limit: { type: "string" },
      "no-enrich": { type: "boolean" },
    },
    allowPositionals: true,
  });
  const gh = new HttpGitHubClient(DEFIHACKLABS_REPO, cfg.GITHUB_TOKEN);
  const enricher = values["no-enrich"]
    ? new NoopIncidentEnricher()
    : new StaticIncidentEnricher(cfg.ETHERSCAN_API_KEY);

  const r = await fetchIncidents(
    gh,
    enricher,
    repo,
    {
      since: values.since,
      limit: values.limit ? Number(values.limit) : undefined,
    },
    () => stop.stopped(),
  );
  log.info(`incidents: inserted ${r.inserted}, scanned ${r.scanned}`);
}).catch(fail);
