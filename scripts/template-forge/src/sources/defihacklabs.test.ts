import { describe, it, expect, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parsePoc,
  fetchIncidents,
  incidentId,
  toCandidate,
  type GitHubClient,
  type IncidentEnricher,
} from "./defihacklabs.js";
import { NoopIncidentEnricher } from "../enrich/incident-enricher.js";
import { openDb } from "../store/db.js";
import { Repo } from "../store/repo.js";

const here = dirname(fileURLToPath(import.meta.url));
const gfox = readFileSync(
  resolve(here, "__fixtures__", "GFOX_exp.sol"),
  "utf8",
);
const bsc = readFileSync(resolve(here, "__fixtures__", "BSC_exp.sol"), "utf8");
const PATH = "src/test/2024-05/GFOX_exp.sol";
const BSC_PATH = "src/test/2025-11/JB_exp.sol";

describe("parsePoc (real GFOX fixture)", () => {
  const meta = parsePoc(gfox, PATH);

  it("extracts name and date from the path", () => {
    expect(meta.name).toBe("GFOX");
    expect(meta.date).toBe("2024-05");
  });

  it("extracts the KeyInfo loss", () => {
    expect(meta.lossText).toBe("330K");
  });

  it("extracts attacker/attack/victim addresses and tx", () => {
    expect(meta.attacker?.toLowerCase()).toBe(
      "0xfce19f8f823759b5867ef9a5055a376f20c5e454",
    );
    expect(meta.attackContract?.toLowerCase()).toBe(
      "0x86c68d9e13d8d6a70b6423ceb2aedb19b59f2aa5",
    );
    expect(meta.vulnerableContract?.toLowerCase()).toBe(
      "0x47c4b3144de2c87a458d510c0c0911d1903d1686",
    );
    expect(meta.attackTx?.toLowerCase()).toBe(
      "0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc",
    );
  });

  it("extracts the fork block", () => {
    expect(meta.forkBlock).toBe(19835924);
  });

  it("collects reference blog links but not the explorer fields", () => {
    expect(meta.references.some((r) => r.includes("neptunemutual.com"))).toBe(
      true,
    );
    expect(meta.references.every((r) => !r.includes("0xFcE19F8f"))).toBe(true);
  });

  it("defaults chain to ethereum for etherscan links", () => {
    expect(meta.chain).toBe("ethereum");
  });
});

describe("parsePoc (BSC fixture: bare addresses + inline @Analysis)", () => {
  const meta = parsePoc(bsc, BSC_PATH);

  it("parses bare (non-URL) addresses", () => {
    expect(meta.attacker).toBe("0xd99e1abfc5dd5034d7ff63828d16c5e945d1b856");
    expect(meta.attackContract).toBe(
      "0xcc21c75f9e13054667663f9ed37f41e65b52dee7",
    );
    expect(meta.vulnerableContract).toBe(
      "0x1b5732eb98911c25acf7bdfaffb9409782cae6d7",
    );
  });

  it("parses the attack tx from the bscscan URL", () => {
    expect(meta.attackTx).toBe(
      "0x54e120b8d62a9d7cef94bf51f1f5b8aa13565d76d8797a79afeeb25ed0e1dc25",
    );
  });

  it("detects chain=bsc from the explorer host even with bare addresses", () => {
    expect(meta.chain).toBe("bsc");
  });

  it("extracts the loss with units", () => {
    expect(meta.lossText).toBe("49958.06 USDT");
  });

  it("captures the inline @Analysis prose as analysis (no network)", () => {
    expect(meta.analysis).toContain("flash-borrowed WBNB");
    expect(meta.analysis).toContain("Venus collateral");
    // section markers and label/url lines are excluded
    expect(meta.analysis).not.toContain("@Analysis");
    expect(meta.analysis).not.toContain("Twitter Guy");
    expect(meta.analysis).not.toContain("https://");
  });
});

describe("toCandidate uses inline analysis as root cause", () => {
  it("sets rootCause from @Analysis without any enrichment", () => {
    const meta = parsePoc(bsc, BSC_PATH);
    const c = toCandidate(meta, bsc, {});
    expect(c.rootCause).toContain("flash-borrowed WBNB");
    expect(c.blogText).toBe("");
  });
});

// ---- fetchIncidents with a fake GitHub client ----------------------------

class FakeGitHub implements GitHubClient {
  constructor(private readonly files: Record<string, string>) {}
  async listDir(repoPath: string) {
    if (repoPath === "src/test")
      return [{ name: "2024-05", type: "dir", path: "src/test/2024-05" }];
    if (repoPath === "src/test/2024-05")
      return Object.keys(this.files)
        .filter((p) => p.startsWith("src/test/2024-05/"))
        .map((p) => ({ name: p.split("/").pop()!, type: "file", path: p }));
    return [];
  }
  async getRaw(repoPath: string) {
    const f = this.files[repoPath];
    if (!f) throw new Error(`missing ${repoPath}`);
    return f;
  }
}

describe("fetchIncidents", () => {
  let repo: Repo;
  const enricher: IncidentEnricher = new NoopIncidentEnricher();
  beforeEach(() => {
    repo = new Repo(openDb(":memory:"));
  });

  it("lists, dedups, and upserts candidates; advances cursor", async () => {
    const gh = new FakeGitHub({ [PATH]: gfox });
    const r1 = await fetchIncidents(gh, enricher, repo, {});
    expect(r1.inserted).toBe(1);
    expect(repo.getCandidatesByStatus("pending")).toHaveLength(1);
    const cur = repo.getCursor("defihacklabs") as { processedPaths: string[] };
    expect(cur.processedPaths).toContain(PATH);

    // Second run: already processed -> no new inserts (resume-safe).
    const r2 = await fetchIncidents(gh, enricher, repo, {});
    expect(r2.inserted).toBe(0);
  });

  it("respects the limit", async () => {
    const gh = new FakeGitHub({
      [PATH]: gfox,
      "src/test/2024-05/OTHER_exp.sol": gfox.replace("GFOX", "OTHER"),
    });
    const r = await fetchIncidents(gh, enricher, repo, { limit: 1 });
    expect(r.inserted).toBe(1);
  });

  it("stop() pauses the loop between incidents", async () => {
    const gh = new FakeGitHub({ [PATH]: gfox });
    const r = await fetchIncidents(gh, enricher, repo, {}, () => true);
    expect(r.inserted).toBe(0);
  });

  it("incidentId is stable for a path", () => {
    expect(incidentId(PATH)).toBe(incidentId(PATH));
  });
});
