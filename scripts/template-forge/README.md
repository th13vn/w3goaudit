# template-forge

Dev-time pipeline that turns real-world security knowledge into **precision WQL templates**
for [`w3goaudit`](../../). Two sources feed one machine-gated, opencode-driven loop:

- **Incidents** — [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) Foundry PoCs
  (root cause + runnable exploit + on-chain txs + blogs).
- **Findings** — the [Solodit API](https://solodit.cyfrin.io) (50k+ audit findings), High+Medium.

Core principle (from the parent `template-forge` design): **agents propose, the machine
disposes.** opencode does the reading/drafting/repair/judgement; a template is only kept when the
deterministic **TEST + REGRESSION** gates pass on a real `w3goaudit` scan, and only promoted after
the **improve** loop proves it is neither too niche (false negatives) nor too generic (noise).

The first forge stage, **`explore`**, is an AI root-cause agent (the only web-browsing stage): for
incidents (and thin findings) it fetches the reference links + on-chain pages — via the
`finding-root-cause` skill (`_ai-globals/skills/`) — and extracts a structured root cause
(vulnerable code, fixed code, must-have trigger conditions, logic-bug triage) that the downstream
stages consume. Configure it with `ROOTCAUSE_SKILL_PATH` / `EXPLORE_MIN_ROOTCAUSE_CHARS`.

`w3goaudit` stays a pure analyzer — it is used here only as a test oracle (invoked as a binary).

## Requirements

- **Node 25** (this repo's machine has an old Node 18 at `/usr/local/bin/node`; an nvm-managed
  Node 25 is shadowed in for interactive use). **Always run via `npm`** — `npm` resolves to the
  Node 25 toolchain. Running `npx` directly may pick the old Node and break the native SQLite addon.
- `opencode` on PATH (verified with 1.17.x), configured with a provider/model.
- The built `w3goaudit` binary at `../../w3goaudit`.

## Setup

```bash
cd scripts/template-forge
npm install
cp .env.example .env     # then fill it in (see below)
npm test                 # 70 tests, no network/opencode needed
```

### `.env`

| key | purpose |
|---|---|
| `CYFRIN_API_KEY` | Solodit API key (`sk_...`) |
| `ETHERSCAN_API_KEY` | incident enrichment (verified source + tx) |
| `GITHUB_TOKEN` | higher rate limits for DeFiHackLabs + finding-source pulls |
| `OPENCODE_MODEL` | opencode model id (`provider/model`, e.g. `anthropic/claude-opus-4-8`) |
| `OPENCODE_BIN` | path to opencode (default `opencode`) |
| `OPENCODE_ATTACH` | optional persistent opencode server url (amortizes startup) |
| `W3GOAUDIT_BIN` | path to the w3goaudit binary (default `../../w3goaudit`) |
| `W3GOAUDIT_CORPUS` | corpus dir for the regression gate (default `../../test-data`) |
| `FORK_RPC_URL` | optional, only for `--execute` PoC reproduction |
| `SOLODIT_TRANSPORT` | `mcp` \| `rest` (see `docs/research-solodit-api.md`) |
| `SOLODIT_API_BASE` | REST base URL (only when transport=rest) |
| `RATE_LIMIT_RPS`, `REPAIR_MAX_RETRIES`, `IMPROVE_STABLE_ROUNDS` | tunables |

## Commands

```bash
npm run fetch:incidents -- --since 2024-01 --limit 20   # DeFiHackLabs -> candidates
npm run fetch:findings  -- --severity High,Medium --limit 50   # Solodit -> candidates
#   offline / no API:  npm run fetch:findings -- --fixture src/sources/__fixtures__/solodit-findings.json --no-source

npm run forge                 # run the loop over all active candidates (opencode + gates)
npm run improve -- <id>       # precision/recall variant tuning on one candidate
npm run promote -- <id>       # copy a cataloged candidate into templates/official/<sev>/
npm run status                # counts + resume command
```

Outputs: confirmed templates land in `candidates/<id>/` (template.yaml + vuln.sol + safe.sol +
provenance.json). NOT-detectable findings are parked in `knowledge/parked.jsonl`. Per-run reports
go to `reports/`.

## Pause & resume

Any long command is interruptible. Press **Ctrl-C once** for a graceful pause (the current step
finishes and commits, the run is marked `paused`, and the resume command is printed). Re-run the
same command to resume — fetch continues from its cursor, and `forge` reuses completed
classify/draft/verify outputs from the cache (no re-spend on opencode). See `docs/pipeline.md`.

## Docs

- `docs/pipeline.md` — full flow, state machine, resume model, component map.
- `docs/wql-cheatsheet.md` — the detectable WQL surface the Drafter targets.
- `docs/research-solodit-api.md`, `docs/research-defihacklabs.md` — source research.
- Design + plan: `../../.vscode/specs/2026-06-24-template-forge-pipeline-{design,plan}.md`.
