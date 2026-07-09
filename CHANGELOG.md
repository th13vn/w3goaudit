# Changelog

## Unreleased — v0.4: Precise source locations (breaking output schema)

AST nodes and declarations now carry column and byte-offset ranges, not just
line numbers, closing the gap between "which line" and "which exact span" for
downstream tooling (editor jump-to, precise highlighting, diffing across
edits):

- **`StartCol`/`EndCol`/`StartByte`/`EndByte`** added to `types.ASTNode`,
  `Function`, `Modifier`, `Contract`, `StateVariable`, `Event`, `Struct`,
  `Enum`, and `Parameter` — 1-based columns, character byte offsets, zero for
  synthetic nodes with no source counterpart.
- **Interior AST nodes are now located, not just declaration roots.** Every
  statement/expression/assembly node built by `pkg/builder`'s AST builder
  passes through a dispatch chokepoint (`buildStatement`, `buildExpression`,
  `buildAssemblyOperation`, `buildAssemblyCall`, `buildInlineAssembly`, plus
  the `BuildFunctionAST`/`BuildModifierAST` roots) that stamps a real span via
  the new `pkg/builder/location.go` helpers (`spanFields`/`applySpan`).
- **Call sites carry a column and byte offset too:** `types.FunctionCall` and
  `types.CallEdge` gained `Col`/`Byte` alongside the existing `Line`.
- `StateWrite.Line` / `Guard.Line` (per-function effects facts) are now
  populated from the underlying AST node's `StartLine`.
- **Output schema bumped `1.0.0` → `2.0.0` (breaking):** consumers parsing
  `data/overview.json` / `data/findings.json` should check `schemaVersion`
  before assuming shape compatibility.
- Requires `github.com/th13vn/solast-go` **v0.1.7**, which added `Loc`/`Range`
  accessors on call/member/index postfix expressions.

## v0.3.1 - 2026-06-22

- Removed old benchmark results and scripts from the repository.
- Bumped CLI version to `0.3.1`.

## v0.3.0 - 2026-06-22

Compared with the previous `0.2.0` CLI version. This release changes the scan
experience from "print or write one report file" into an audit workspace that is
ready for humans, automation, and AI-assisted review.

### Scan Output And Report Workspace

- Default scans now write a result folder named after the scanned project, file,
  or database.
- The folder always includes `overview.md`, `findings.md`, `results.sarif`,
  `run.log`, and `corpus/{database.json,findings.json,overview.json}`.
- Each main contract gets its own folder with `state-changes.md` and one
  workflow file per entry function.
- HTML is now an optional mirror via `--html`; JSON and SARIF are always part of
  the result folder.

Mechanism: `report.WriteBundle` owns folder generation, while the CLI opens
`run.log` before scanning and routes all verbose package logs into it.

### Template Home And Updates

- Added `~/.w3goaudit/config.yml` and a managed template home at
  `~/.w3goaudit/templates`.
- First run attempts to download the latest `th13vn/w3goaudit-templates`
  release, with the embedded official pack kept as the offline fallback.
- Added `--update-templates` to refresh the template home and `--update` to
  self-update via `go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest`.

Mechanism: new `pkg/home` handles config loading, release lookup, zip download,
safe extraction, `.version` tracking, and fallback behavior.

### CLI UX Changes

- Bumped CLI version from `0.2.0` to `0.3.0`.
- Added short flags for common workflows: `-t`, `-o`, `-d`, `-v`, `-H`, `-q`,
  `-s`, `-m`, `-i`, `-e`, `-l`, `-T`, and `-u`.
- Added exact severity filtering with `--severity`; `--min-severity` remains a
  threshold filter, and the two are mutually exclusive.
- Console output is now title-only by default for large scans; full detail lives
  in the result folder or is shown with `--verbose`.
- Missing output directories are created automatically for build/report outputs.
- Unresolved inheritance references are surfaced after scans.

Compatibility note: the old direct format flags (`--json`, `--md`, `--sarif`)
were replaced by the result-folder model; use `--stdout` for console-only output
and `--html` for optional HTML files.

### Analysis Accuracy

- Added builder phase 7: per-function effects analysis for direct state writes,
  guards, branch conditions, modifiers, sender checks, and `tx.origin` usage.
- Access-control detection now separates privileged authorization from
  caller self-scoping. `require(from == msg.sender)` is not treated as owner or
  role access control.
- Added the `unCheckedSender` preset for detectors where self-scoping is a valid
  mitigation, especially arbitrary `transferFrom`.
- `super` call resolution is now context-aware across all most-derived C3
  linearization leaves, avoiding reachability false negatives in cooperative
  multiple inheritance.
- Build output and report ordering are more deterministic.
- Tolerant parser recovery now logs warnings when recovered parse errors may
  have dropped contracts, functions, or state.

Mechanism: `types.SemanticFacts.FunctionEffects` stores the new effects, the
state matrix reads them through call-graph reachability, and the call graph adds
deduplicated context-specific `super` edges after the normal build.

### Detector Pack

- Reorganized `templates/official` into severity folders:
  `critical/`, `high/`, and `medium/`.
- Curated the embedded official pack to 25 production detectors, focused on
  critical/high/medium security signal and removing low/info noise.
- Detector IDs now use severity-prefixed names such as
  `CRITICAL-SELFDESTRUCT-UNPROTECTED`, `HIGH-ARBITRARY-TRANSFERFROM`, and
  `MEDIUM-UNCHECKED-SEND`.
- Added `templates/test/taint-probe-parameter.yaml` for focused taint testing.

### Reports And SARIF

- Overview reports now show each main contract's Solidity pragma version.
- State-change reports map state variables to direct writers and reachable entry
  points.
- Workflow files summarize signature, access control, guards, branch conditions,
  transitive state effects, and a call workflow.
- SARIF now uses the SchemaStore SARIF 2.1.0 schema URL.

### Benchmarks And Tests

- Added a self-contained `benchmarks/` suite comparing W3GoAudit against
  Slither, Semgrep Decurity rules, and 4naly3er-style detectors.
- Added benchmark corpora, fixtures, WQL template ports, and runner scripts.
- Added tests for result bundle creation, deterministic database builds,
  context-aware `super`, complex C3 inheritance, storage-anchored access control,
  effects extraction, and severity filtering.
- Added new Solidity fixtures for C3, `super`, mixed coding styles, access
  control, parser edge cases, and taint stress.

### Dependencies

- Updated `github.com/th13vn/solast-go` from `v0.1.4` to `v0.1.6`.
