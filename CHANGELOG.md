# Changelog

## Unreleased — `query:` composition (breaking template syntax)

Templates are now `meta:` plus one `query:` container — the former top-level
`select`/`from`/`where` triple moved under `query:` (all 106 repository
templates migrated; finding output verified byte-identical on the security
corpus, and the competitive benchmark gate passes: precision 65.27%,
detection 100%, zero failed cases).

- **`query.or:`** — one detector, several alternative shapes: a list of
  complete branch queries under one `meta`. Each branch anchors its own
  finding (own `select`, `where`, optional `from`; a query-level `from` is
  the shared default, and cross-scope branches are allowed). Lowered to one
  `QueryBlock` per branch (new `Template.Queries` IR field, additive JSON);
  the engine executes every block and unions the findings, deduplicating
  identical matched locations.
- **`query.and:`** — multi-site joined findings: a query-level `from:` names
  the join scope (contract scopes join per contract via the synthetic
  inheritance-aware AST; function scopes per function), and every branch
  (own `select`/`where`/`label:`) must match in the same scope instance.
  Branch sites surface in `Finding.Related` under their labels. Lowered onto
  the existing contract-scope `all:`-of-branches machinery. Context-level
  matchers are rejected inside `and:` branches (a filter applies to the
  whole scope instance).
- One composition level; `and:`/`or:` cannot mix with each other or with a
  sibling `select:`/`where:`; malformed shapes fail at load with pointed
  errors.
- **`arg.any:`** — matches when SOME positional call argument satisfies the
  sub-rule (receivers/call options excluded, as with `arg.N`).
- **`and:` in `where`** — exact alias of `all:` for logic symmetry.
- Conflicting scalar matchers (two `name:` constraints on one node) now fail
  with a fix-it error suggesting `all:` branches.
- SDK: `ParseTemplate`/`LoadTemplate` accept only the new document shape;
  the exported evaluator IR gains `Template.Queries` and `Rule.ArgAny`.

## Unreleased — Full correctness and release hardening

- Added immutable scan-local logging/options across the reader, builder,
  database loader, engine, template loader, and report generator. Deprecated
  package-global verbose wrappers remain only for exported SDK compatibility.
- Persisted sorted analysis-quality diagnostics through source builds and JSON
  cache loads. Every bundle writes `data/diagnostics.json`; manifests expose
  `analysisComplete` and per-severity diagnostic counts. `--strict-imports`
  applies the same fail-closed import policy to source scans, `--db` scans, and
  `build`, while the default remains tolerant.
- Canonicalized internal identities as `absPath#Contract` and
  `absPath#Contract.selector(types)`. Contracts/main-contract entries now carry
  exact `LinearizedBaseIDs`; call edges carry exact resolved contract IDs;
  identity-sensitive lookup rejects unresolved ambiguity instead of guessing.
- Hardened extract queries: exact contract/function IDs, selectors, 4-byte
  signatures, and unique names are supported; ambiguous input fails with sorted
  candidates.
- Reworked Foundry import resolution with real TOML parsing, active
  `FOUNDRY_PROFILE`, context-qualified/specificity-ordered remappings, fallback
  after missing targets, canonical import provenance, and sub-project boundaries.
- Hardened template archive installation with 64 MiB compressed, 8 MiB per-file,
  128 MiB decompressed, 4,096 accepted-file, and 8,192 ZIP-entry caps plus a
  rollback-safe staged directory swap.
- Corrected manifest scope/count semantics (`projectRoot`, `scanTarget`,
  compatibility `target`; contracts/interfaces/libraries/declarations) and
  indexed diagnostics plus optional HTML artifacts.
- Added fixed-clock report builders. Finding/content ordering is deterministic;
  real generated timestamps vary unless `GeneratorOptions.Now` /
  `BundleOptions.Now` supplies a fixed clock.
- Added reusable release gates for format/tidy/vet/staticcheck/gocyclo,
  Markdown links, normal/race/shuffled tests, host/ARM64 builds, govulncheck,
  official scan artifacts, and the competitive benchmark. The project uses
  `go.mod`'s Go version, raised to 1.26.5 because govulncheck found reachable
  standard-library advisories in older supported toolchains (fixes require
  >=1.25.12).
- Made Docker Compose the only supported competitive-benchmark host workflow.
  The image derives and verifies Go directly from `go.mod`, requested scanners
  fail closed, and output is confined to `benchmarks/results/`. The threshold
  checker enforces precision >= 65%, recall >= 95%, and zero failed cases from
  recomputed raw counts. A fresh image/competitive run is not currently claimed:
  verification remains externally blocked until the completed lockfile hash for
  the pinned 4naly3er commit is recovered and reviewed.
- Template YAML is strictly `meta` plus `query:`; unknown keys are rejected
  at every level. The obsolete `templates/security/` lane was deleted; the
  retained inventory is 25 official + 5 feature-test + 76 benchmark = 106 WQL
  templates.

## v0.4.0 - 2026-07-13: Precise source locations (breaking output schema)

AST nodes and declarations now carry column and byte-offset ranges, not just
line numbers, closing the gap between "which line" and "which exact span" for
downstream tooling (editor jump-to, precise highlighting, diffing across
edits):

- **`StartCol`/`EndCol`/`StartByte`/`EndByte`** added to `types.ASTNode`,
  `Function`, `Modifier`, `Contract`, `StateVariable`, `Event`, `Struct`,
  `Enum`, and `Parameter` — one-based Unicode-code-point columns and zero-based,
  half-open UTF-8 byte offsets, zero for synthetic nodes with no source counterpart.
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
- **Extension data layer:** `WriteBundle` now also emits `data/nav.json`
  (`report.BuildNavJSON` — navigable symbols, reverse call edges, and
  interface→implementation mappings) and `data/explorer.json`
  (`report.BuildExplorerJSON` — one entry per deployable contract with
  ordered constants/storage, entry functions, and getters), both carrying
  the precise `SrcRange` locations above. `data/manifest.json` indexes them
  under `files.data.nav` / `files.data.explorer`. See
  [`docs/extension-output.md`](docs/extension-output.md) for the schema.
- **WQL query language** (`select`/`from`/`where`, uniform matchers,
  intuitive-polarity presets) is the template syntax; all 106
  official/benchmark/feature-test templates use it. See
  [`docs/wql-syntax.md`](docs/wql-syntax.md).

### Fixes (v0.4.0)

- **Deterministic finding output.** `ExecuteAll` now applies a total-order sort
  (`SortFindings`) before returning, so `findings.json`, `results.sarif`, and
  the per-group order in `findings.md` are byte-stable across runs. Previously
  findings were emitted in Go map-iteration order and shuffled every run.
- **Precise spans reach findings.** `Finding.Location` and `primaryAst` now
  carry the matched node's `col`/`endLine`/`endCol`/`startByte`/`endByte`, and
  SARIF declares `columnKind: unicodeCodePoints` and emits
  `startColumn`/`endColumn`/`endLine`. It deliberately omits
  `charOffset`/`charLength` because W3GoAudit offsets are UTF-8 bytes, not SARIF
  character offsets. Reachability steps carry a per-hop `file` so cross-contract
  SARIF traces point at the right file.
- **Same-name contract resolution.** Entry-function IDs, main-contract
  detection, source excerpts, call targets, extraction, and report consumers now
  carry exact source/contract/function identities. `Function.SourceFile`,
  `ResolvedContractID`, and `LinearizedBaseIDs` keep a mock and real contract
  with the same name separate; unresolved ambiguity is not repaired with a
  lexicographic or same-directory guess.
- **Reentrancy sequence FN.** A call used as an `if`-condition followed by a
  state write in the body is now matched by `sequence` rules (the condition and
  body were wrongly treated as mutually-exclusive arms).
- **WQL fail-open / dead paths closed.** A mixed context+AST `any:` and a
  multi-kind (list) `select:` are now rejected at load with actionable errors
  instead of silently over-matching / never matching.
- **Round-trip & robustness.** `DataFlowGraph` rebuilds its index after a `--db`
  round-trip; modifier ASTs are built with contract state-variable context;
  template download is size-capped and swapped in atomically; unresolved imports
  are surfaced instead of silently dropped; source excerpts handle block
  comments and word-boundary function matching; nav.json symbol IDs and ordering
  are collision-free. `--version` is wired and the CLI version is `0.4.0`.

## Unreleased — Standardized result-folder layout (output tree)

The result folder was reorganized from a flat pile (an all-contracts
`overview.md` dump plus one per-contract folder at the top level) into a
navigable, tool-conventional tree:

- **New root landing files:** `README.md` (counts + a Contents table linking
  every artifact) and `summary.md` (metrics + findings-by-severity + a rules-hit
  table sorted by severity then occurrence count).
- **`overview.md` is now an index, not a dump:** project metrics plus a
  one-row-per-contract table (entry-point / state-var / finding counts and a link
  into `contracts/`). The full per-contract detail moved into each contract's own
  `README.md`.
- **`corpus/` → `data/`**, and a new **`data/manifest.json`** machine index
  (tool, scope, counts, every artifact's relative path, and a `contracts[]` list)
  so a consumer discovers the whole folder from one file. A legacy `corpus/`
  folder from an older run is removed automatically.
- **Per-contract folders moved under `contracts/` and mirror source paths:**
  `contracts/<relative-source-path-without-ext>/<ContractName>/` with a new
  per-contract `README.md`, plus the existing `state-changes.md` and
  `workflows/`. Because the path encodes the source file, same-named contracts in
  different files no longer collide (no `Name__<filestem>` suffix). The
  `contracts/` tree is regenerated wholesale each run (idempotent; no stale
  folders).
- Reuse a pre-built DB via `--db data/database.json` (was `--db
  corpus/database.json`).

## Unreleased — Engine quality & correctness cleanups

Internal hardening from a self-review of the precision work (no template-syntax
changes):

- **Contract-scope related sites:** the synthetic `decl.contract` AST is now
  built **once** per contract and held in a single-slot memo; the match pass and
  `Finding.Related` enrichment share one tree instead of rebuilding it (bounded
  memory — a new contract evicts the previous, since each is visited once).
  Per-branch site collection now gathers *all* function sub-rules of a branch
  (`containedFunctionRules`), so an `any:` of several function shapes is faithful.
- **Single field-classification source of truth:** `presentRuleFields()` tags
  each Rule field `classAST` / `classContext` / `classDual`; `checkRule`,
  `ruleHasASTFields`, and `ruleHasContextFields` all read it (no more three
  hand-synced lists).
- **`unchecked_var`** now requires the bounding guard to use an **ordering**
  comparison (`<`/`<=`/`>`/`>=`), so `require(a != b); … a - b` is correctly
  flagged (was a false negative).
- **`attrInCSV`** requires the node to actually carry the attribute, so
  `mutability: nonpayable` in `match:` no longer spuriously matches attribute-less
  nodes.
- **Report extraction** anchors the function-start search to a word boundary
  (`function withdraw` no longer matches `withdrawAll`).
- Renamed the Go field `Rule.SourceRegex` → `Rule.Regex` to match the `regex:`
  keyword (no YAML change).

## Unreleased — WQL keyword simplification (breaking template syntax)

Historical record. These evaluator-facing YAML keywords are not accepted by
the current loader; see `docs/wql-syntax.md` for the current syntax. The
change renamed:

- `source_regex:` → `regex:`
- `visibility_filter:` → `visibility:` and `mutability_filter:` → `mutability:`
  (one keyword each, valid in both `filter:` and `match:` — function precondition
  in filter, node-attribute match in match)
- `unguarded:` → `unchecked_var:`
- `not_bitwise_context:` (interim) → generic `statement_contains:` sub-rule

Docs (`docs/wql-syntax.md`) rewritten: implicit-AND emphasized (no need to wrap
sibling fields in `all:`), a complete Node Kinds reference (incl. the Declaration
group), and a fuller attributes table (`call_receiver`, `has_value`, `has_gas`,
`has_salt`, `call_option`, `parent`, …).

## Unreleased — Detector precision & access-control accuracy

False-positive reduction across the official pack, validated on a real on-chain
target (SpiceFiNFT4626) and the competitive benchmark.

### Engine / access-control analysis (`pkg/types/function.go`)

- **Privileged access control vs. item ownership are now distinguished.**
  `ownerOf(tokenId) == msg.sender` (a getter the caller indexes with a resource
  id of their own choosing) is item-ownership *self-scoping*, not a privileged
  gate — `getterIsResourceScoped`. It no longer counts toward `IsAccessControlled`
  (so `deposit`/`mint`-style functions are no longer mis-marked access-controlled)
  and instead feeds `ComparesCallerIdentity`.
- `ComparesCallerIdentity` is now **interprocedural**: it follows a `msg.sender`
  forwarded into a callee (`_withdraw(msg.sender, …)` → `ownerOf(id) != caller`).
  The `unCheckedSender` preset therefore treats item-ownership scoping as a valid
  mitigation (the ETH analogue of `require(from == msg.sender)`).
- Fixed `unwrapTypeCast` to unwrap only genuine type names (`address`, `uintN`, …)
  so a one-arg getter like `ownerOf(id)` is no longer mistaken for a cast.
- Fixed the interprocedural auth descent to resolve callees by bare name
  (`calleeNameMatches`) — previously it compared against the full selector and
  silently never matched.

### New WQL predicates (`pkg/engine`)

- `unchecked_var` — on arithmetic `binary_op`, matches only when operands were not
  range-checked by a preceding `require`/`assert`/`if` guard.
- `statement_contains` — a generic statement-scoped sibling search (sub-rule
  matched against the node's nearest enclosing statement). The operator
  vocabulary lives in the template; used as `not: { statement_contains: … }` by
  incorrect-exp to exclude a `^` that shares a statement with another bitwise op.
- `label` — optional name on a `match.all` branch, surfaced in `Finding.Related`.

### Builder

- A `0x…` number literal is now tagged `subtype: hex` (not `number`).

### Official templates

- `arbitrary-send-eth`: `preset: unAuthenticated` → `unCheckedSender` (clears
  owner-gated NFT-vault withdrawals; still flags genuine arbitrary sends).
- `incorrect-exp`: flags `base ^ exp` / `2 ^ 8` / `10 ^ 18` (simple operands,
  `not_bitwise_context`); excludes OpenZeppelin `Math.average`/`mulDiv` and hex masks.
- `unchecked-arithmetic`: scoped to state-mutating functions and `unchecked_var`
  arithmetic; excludes pure library math and range-checked subtraction.

### Benchmark

- Competitive corpus is now governed by the Unreleased quality gate above; the
  previous 105/109, 60.0%-precision snapshot is retained only in repository
  history rather than documented as the current baseline.

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
