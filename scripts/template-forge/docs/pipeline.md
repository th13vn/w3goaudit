# Pipeline — end-to-end flow

```
                 ┌──────────────────────┐        ┌──────────────────────┐
  DeFiHackLabs ──► fetch:incidents       │        │ fetch:findings        ◄── Solodit API
  (Foundry PoCs) │  parse header         │        │  High+Medium          │   (rate-limited)
                 │  enrich (Etherscan,   │        │  enrich (GitHub src)  │
                 │  blogs) static-first  │        │                       │
                 └──────────┬───────────┘        └───────────┬───────────┘
                            │   Candidate{incident}           │ Candidate{finding}
                            └───────────────┬─────────────────┘
                                            ▼
                                   SQLite: candidate (pending)
                                            ▼  forge
        ┌───────────────────────── forge loop (opencode + machine gates) ─────────────────────────┐
        │ explore (AI, web): fetch links + on-chain → root cause, vuln/fixed code, trigger conds   │
        │     │  (incidents always; thin findings only; uses finding-root-cause skill)             │
        │     ▼                                                                                     │
        │ classify ─► [NOT-detectable ─► knowledge/ (parked)]                                       │
        │     │                                                                                     │
        │     ▼ detectable                                                                          │
        │ draft (template.yaml + vuln.sol + safe.sol)                                               │
        │     ▼                                                                                     │
        │ TEST gate (machine): fire on vuln ∧ silent on safe ──fail──► repair (≤N) ──► back to TEST │
        │     ▼ pass                                                                                │
        │ REGRESSION gate (machine): silent across test-data/ ──fail──► repair ──► back to TEST     │
        │     ▼ pass                                                                                │
        │ verify (right-reason) ──reject──► shelved                                                 │
        │     ▼ accept                                                                              │
        │ catalog ─► candidates/<id>/ (template.yaml, vuln.sol, safe.sol, provenance.json)          │
        └───────────────────────────────────────────────────────────────────────────────────────┘
                                            ▼  improve  (precision/recall tuning)
        recall variants (must fire) + precision variants (must stay silent)
        ─ misses ─► repair (broaden) ;  false-fires ─► repair (tighten)
        ─ K consecutive clean rounds ─► promoteEligible
                                            ▼  promote (manual gate)
                              templates/official/<severity>/<id>.yaml
```

## Candidate status state machine (drives resume)

```
pending → explored → classified → drafted → tested → regressed → verified → cataloged
   │                      │            ▲repair│                                  │promote
 (explore: AI web)        │NOT-detect.  └──────┘ (test/regression failures)       ▼
                          ▼                                                   promoted
                       parked            any retries-exhausted/overfit ─► shelved
```

The `explore` stage runs the AI root-cause agent (the only web-browsing stage): it fetches the
candidate's reference links + on-chain pages (via the `finding-root-cause` skill) and writes back a
structured root cause — vulnerable code, fixed code, must-have trigger conditions, and a logic-bug
triage — which classify/draft then consume. It is `stage_result`-cached, so resume never re-spends it.

`stepCandidate` performs exactly one transition and commits it (status + `stage_result`) in a
transaction. So a crash or graceful pause leaves a candidate at its last completed stage.

## Resumability

- **Durable state** lives in `state/forge.db` (runs, candidate status, `stage_result` cache,
  `fetch_cursor`, lock) and on-disk `cache/`. Nothing important is memory-only.
- **Atomic steps**: each fetch page / stage transition commits before the next begins.
- **Graceful pause**: SIGINT/SIGTERM flips a stop flag; the in-flight step finishes and commits,
  the run is marked `paused`, and the resume command is printed. A second signal hard-exits.
- **Resume**: re-run the same command. `forge` reprocesses active candidates and reuses completed
  classify/draft/verify/catalog outputs from the `stage_result` cache (no re-spend on opencode);
  fetch resumes from `fetch_cursor`; enrichment reuses `cache/`.
- **Single-writer lock** (`forge_lock`) stops two runs from corrupting state.
- `npm run status` shows counts + the resume command.

## Components

| Area | Files |
|---|---|
| config / schemas | `src/config.ts`, `src/types.ts`, `src/agent/schemas.ts` |
| store / resume | `src/store/{db,repo}.ts`, `migrations.sql` |
| sources | `src/sources/{defihacklabs,solodit}.ts` |
| enrich | `src/enrich/{etherscan,blogs,github,incident-enricher}.ts`, `src/util/{github,cache}.ts` |
| agent | `src/agent/opencode.ts`, `src/agent/prompts/*.md` (incl. `explore.md`) |
| root-cause skill | `_ai-globals/skills/finding-root-cause/SKILL.md` (loaded by the explore stage) |
| harness (oracle) | `src/harness/{runScan,gates}.ts` |
| pipeline | `src/pipeline/{stages,orchestrator,improve,forge-deps}.ts` |
| cli | `src/cli/*.ts`, `src/util/signals.ts` |
