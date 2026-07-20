# cmd/w3goaudit — CLI

Cobra CLI entry point. The **root command is the scan**: `w3goaudit <path>` runs
the full `Reader → Builder → Database → Engine → Report` pipeline and writes a
result folder. There is **no `scan` subcommand**.

## Files

| File | Responsibility |
|---|---|
| `main.go` | Bootstraps cobra; maps any `RunE` error to `os.Exit(1)`. |
| `root.go` | Thin Cobra/config wrapper for root scan flags, plus the `version` subcommand. `rootCmd.Version` also wires `--version`. |
| `scan_options.go` | Immutable `scanOptions`/`databaseLoadOptions`, strict-import policy, and the scan-local `executeScan` pipeline. |
| `scan_console.go` | Writer-injected progress and console rendering used by concurrent scan pipelines. |
| `helpers.go` | Scan-local database source/cache loading, logger setup, persisted import-warning rendering, and output helpers. |
| `build.go` | `build` subcommand — build a database JSON without scanning; shares strict-import and local-logger behavior with root scans. |
| `extract*.go` | `extract` subcommands (source/context/workflow/involve/bundle) and their renderers. `extract_resolve.go` centralizes exact-ID/name/selector lookup and rejects ambiguous queries with sorted candidates. |
| `config_cli.go` | Config resolution + `--update-templates` handling. |
| `scan_filters.go` | Template selection (explicit `--template` vs embedded official pack) and severity/include/exclude filtering. |
| `completion.go` | Shell completion. |
| `update.go` | `--update` (self-update via `go install …@latest`). |

## Invariants

- **Exit codes:** any pipeline/report-write error propagates from `RunE` → `os.Exit(1)`. A failed report write must return non-zero.
- **stdout vs files:** `--stdout` prints the summary only and writes no files; `run.log` and the result bundle are both gated on `!stdoutOnly` (so the manifest's `run.log` reference is always valid).
- **Machine-readable output stays clean:** warnings (import resolution, unresolved imports) go to **stderr**, never stdout.
- **Source/cache parity:** unresolved-import warnings are rendered from persisted database diagnostics after either source build or `--db` load. `--strict-imports` applies the same fail-closed gate in both modes and in `build`; the default remains tolerant.
- **Isolation:** `runScan` snapshots Cobra/config state once. `executeScan` reads only immutable options and injects one logger/writer set through reader, builder, cache loading, engine, template loading, and report generation, so concurrent scans cannot cross streams.
- **Version:** `Version` (`root.go`) is the single source of truth — it feeds the `version` subcommand, `--version`, and the SARIF driver version. Bump it on release.
- **Extract identity:** contract queries accept exact `file#Contract` IDs or unique case-insensitive names. Function queries accept exact function IDs, `Contract.selector`, full selectors, 4-byte signatures, or unique bare names. Ambiguous queries fail; map order never selects a result. Inherited state/context/bundle data walks the selected contract's exact `LinearizedBaseIDs`, so duplicate base names cannot cross-wire an exact query.
- **Extract diff identity:** contracts compare as slash-normalized source paths
  relative to each database's own `ProjectRoot`, plus `#Contract`; functions
  compare by full selector with a declaration-name fallback only for legacy
  selector-less entries. Equivalent checkout roots align while duplicate names
  and overload changes remain separate.

## Change checklist

`LinearizedBases` may retain unresolved display entries and is never zipped by
index with compact `LinearizedBaseIDs`. Inheritance and bundle kinds map a
display name only when one exact object of that name is present in the selected
contract's exact MRO; unresolved or ambiguous entries stay `unknown`.

- New flag/command → update `docs/usage.md` and `README.md`.
- Behavior change to output artifacts → update `docs/workflows.md` / `docs/extension-output.md` as applicable.
- Keep the root INDEX.md package map in sync.
