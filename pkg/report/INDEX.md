# pkg/report - Report Generation

## Purpose

Generates human-readable reports from the audit results and database, supporting multiple formats (Markdown, HTML, JSON, Console, **SARIF 2.1.0**) with rich visualizations.

Every file output is **split into two files**: an overview half (project stats, contracts, inheritance, call graph) and a findings half (issues, severity-sorted, with refs/fix). Reviewers can diff them independently across runs. SARIF is single-file by design (the SARIF schema mandates one document per run).

## Reachability-aware findings — quick map

Every `engine.Finding` can carry three optional structured fields populated
by the engine (see `pkg/engine/INDEX.md`, "Matched-node attribution &
Reachability"):

- `Reachability` — call chain from an externally-callable entry function
  down to the function that hosts the dangerous statement
- `EntryPoint` — auditor-actionable fix-here function
- `PrimaryAST` — kind / name / line of the matched AST node

Per-format treatment:

| Format | File | Where it renders the trace |
|---|---|---|
| Console | `cmd/w3goaudit/root.go` *(driver)* | `↳ via …` + `↳ fix-here: …` continuation lines under `Location:` |
| JSON | `json_split.go` *(passthrough)* | `findings[].reachability.steps[]`, `findings[].entryPoint`, `findings[].primaryAst` — emitted with `omitempty` |
| SARIF 2.1.0 | `sarif.go` | One `result.relatedLocations[]` per hop (`entry:` / `hop:` / `host:`); `result.properties.entryPoint` + `result.properties.primaryAst` |
| Markdown findings | `scan_formats.go::FormatFindingsAsMarkdown` (via `renderFindingTraceMarkdown`) | Dotted-level list block (`.`, `..`, `...`) inside each occurrence `<details>` |
| HTML findings | `scan_formats.go::FormatFindingsAsHTML` (via `renderFindingTraceHTML`) | `<div class="w3a-trace">` with depth-scaled `margin-left` per `<li class="w3a-trace-step">` |

The fields are populated regardless of the `LocationSource` setting on the
engine; `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1` only changes which step of
the chain `Location.Function` / `Location.Contract` itself names.

## Key Files

### generator.go
Main entry point for report generation.

**Key Types:** (`SummaryReport`/`ContractSummary`/`FunctionSummary` are defined
in `summary.go`; `generator.go` populates them)
- `Generator` - Orchestrates summary generation
- `SummaryReport` - Structured summary data ready for rendering
- `ContractSummary` - Per-contract summary data
- `FunctionSummary` - Per-function analysis data

**Determinism:** function lists (`sortedFunctionSummaries`) and the "Defined in
X" groupings in the Markdown/HTML renderers are sorted before output, so reports
are byte-stable across runs and diff cleanly.

**Key Functions:**
- `NewGenerator(db)` - Create generator
- `GenerateSummary()` - Produce `SummaryReport` from database
    - Detects git repository and extracts remote URL/branch
    - Calculates metrics (Files, Contracts, nSLOC, etc.)
    - Identifies main contracts
    - Builds call graphs and inheritance graphs (Mermaid)

**Mermaid node ID hashing:**
- `sanitizeMermaidNode` uses FNV-64a (previously FNV-32a). A 32-bit hash
  has ~1% collision probability over 10 000 distinct nodes (birthday
  paradox); large codebases routinely have more functions than that, and
  a collision silently merged two nodes in the graph output. 64-bit makes
  the risk astronomically small.

### bundle.go

Writes the **result folder** — the default output of a scan (v0.3). One call,
`WriteBundle(dir, db, summary, findings, tool, BundleOptions{HTML})`, produces:

```
<dir>/overview.md, findings.md, results.sarif
<dir>/corpus/{database.json, findings.json, overview.json}   # canonical DB lives here only
<dir>/<MainContract>/state-changes.md
<dir>/<MainContract>/workflows/<entryFn>.md
```

- Folder name dedup: `contractDirNames` disambiguates duplicate contract names
  (across files) as `Name__<filestem>`; `workflowFileNames` disambiguates
  overloaded entries as `<fn>__<selector>.md`. All names go through `sanitizeName`.
- `pruneStaleContractDirs` removes per-contract folders from a previous run that
  aren't in the current scan (re-scan is idempotent); it only touches dirs that
  contain `state-changes.md`/`workflows/` and never `corpus/`.
- `renderStateChanges(mc, rows)` renders the reachability matrix (see
  `state_matrix.go`); falls back to a plain variable list when rows are absent.
- `renderWorkflow(mc, fn, *types.FunctionEffects, stateWrites)` renders one
  entry-function context block: Signature, Auth/Access Control (modifiers,
  msg.sender checks, ⚠ Unprotected, ⚠ tx.origin), Guards/Checks, Branch
  Conditions, State Effects (transitive), Call Workflow mermaid. Effects come
  from `Database.Semantics.FunctionEffects` (builder Phase 7).
- `run.log` is NOT written here — the CLI owns it (open for the whole scan).
  HTML mirrors are added only when `BundleOptions.HTML` is set.

### state_matrix.go

Computes the per-contract state-change matrix consumed by `state-changes.md` and
the workflow files' State-Effects section.

- `BuildStateMatrix(db, main, states) []StateRow` — for each state variable:
  the functions that write it (`Written By`) and the entry points that reach a
  writer transitively (`Reachable From`).
- `stateMatrixBuilder` resolves functions across `main.LinearizedBases`
  (most-derived wins), follows intra-contract calls (`isIntraContractCall`:
  internal/self/inherited/super/library/modifier) for the reachability closure,
  and reads writes from `Database.Semantics.GetFunctionEffects`.

### html.go
Interactive HTML report renderer.

**Features:**
- **Interactive Graphs**: Uses `vis.js` visualization for call graphs and inheritance.
- **Full Screen Mode**: dedicated overlay for complex graphs.
- **PDF Export**: Built-in print/export button.
- **Grouped Entry Points**: Hierarchical grouping (Access Control > Definition Source).
- **Rich Metrics**: Visual cards for project stats (nSLOC, Framework, etc.).
- **Git URL Links**: Clickable links to repository files (GitHub/GitLab).

> **Output safety:** the findings HTML (`scan_formats.go`) HTML-escapes every
> interpolation — including the scanned-source code excerpt, which is
> attacker-controlled — to prevent stored XSS. Reference URLs are emitted as
> anchors only for `http(s)` schemes; other schemes render as escaped text.

**Key Functions:**
- `ToHTML()` - Renders `SummaryReport` to standalone HTML string.

### markdown.go
Static Markdown report renderer.

**Features:**
- **Static Graphs**: Embeds `mermaid` code blocks (compatible with GitHub/VSCode).
- **Grouped Entry Points**: Uses `<details>` tags for collapsible sections, grouped by Access Control.
- **Simplified Summaries**: Concise function signatures (Name - Sig - Modifiers).
- **Git URL Links**: File paths rendered as clickable links to repository.
- **Inheritance three-view layout**: the overview's `### Inheritance` block
  renders three complementary views in order — ASCII tree (parent → child
  drawing), flattened single line `Child → … → Parent` (the C3 MRO
  direction auditors and LLMs reason in), then the interactive Mermaid
  diagram. `renderInheritanceFlattened()` produces the middle view from
  `ContractSummary.InheritanceChain`. The HTML renderer (`html.go`) mirrors
  this three-view structure.

**Key Functions:**
- `ToMarkdown()` - Renders `SummaryReport` to Markdown string.
- `renderInheritanceFlattened()` - Single-line C3 MRO (derived → base).

### summary.go
Output structures for reports.

**Features:**
- Defines `SummaryReport` and `ContractSummary` structs.
- `ContractSummary.Version` — the Solidity pragma of the file defining the
  contract (e.g. `^0.8.20`), surfaced per main contract in the overview and the
  per-contract folder.
- `GitInfo` struct includes:
    - `RemoteURL` - Web URL of repository (e.g., `https://github.com/user/repo`)
    - `Branch` - Current branch name (e.g., `main`)
- `Stats` struct includes:
    - `TotalFiles`, `TotalContracts`
    - `NSLOC` (Normalized Source Lines of Code)
    - `Framework` (Foundry, Hardhat, etc.)
    - `TotalEntryFunctions`

### json_split.go

Schema-stable JSON output structures.

**Key types:**
- `OverviewJSON` — overview half (`schemaVersion`, `tool`, `generatedAt`, `stats`, `overview`)
- `FindingsJSON` — findings half (`schemaVersion`, `tool`, `generatedAt`, `counts`, `findings`)
- `ToolMeta`, `FindingsCounts` — shared shapes

**Constants:**
- `SchemaVersion` (currently `"1.0.0"`) — bumped on any breaking change to the JSON shape; consumers should refuse to parse on a major-version mismatch.

**Finding fields surfaced under each `findings[]` entry:**

The JSON renderer is a passthrough — every exported field on `engine.Finding`
is serialized. In addition to the established
`template_id` / `severity` / `confidence` / `title` / `message` /
`recommendation` / `location` / `references[]` / `fix` keys, three optional
structured fields are emitted (with `omitempty`) when the engine has them:

```jsonc
{
  "reachability": {
    "steps": [
      { "contract": "...", "function": "...", "visibility": "external", "line": 344 },
      { "contract": "...", "function": "...", "visibility": "internal", "line": 348 },
      { "contract": "...", "function": "...", "visibility": "internal", "line": 352 }
    ]
  },
  "entryPoint": { "contract": "...", "function": "...", "authVerdict": "", "authReasons": [] },
  "primaryAst": { "kind": "call.external", "name": "transferFrom", "startLine": 352 }
}
```

These keys are absent in JSON for findings without a chain (e.g. contract-
scope or source-scope matches), so today's JSON consumers parse the same
shape they did before — the new fields are strictly additive.

### sarif.go

SARIF 2.1.0 emitter for GitHub Code Scanning, Defect Dojo, SonarQube, etc.

**Key function:** `FormatFindingsAsSARIF(findings, tool, projectRoot) (string, error)`

Maps W3GoAudit severity to SARIF level (`error`/`warning`/`note`) and to
GitHub's `properties.security-severity` (CVSS-style 0–10). Each unique
TemplateID becomes one rule entry.

**Portability fix:**
- `projectRoot` is used to emit **relative** `artifactLocation.uri` values
  with `uriBaseId: "srcRoot"`, plus a top-level `originalUriBaseIds.srcRoot`
  declaration. Previously the emitter produced absolute paths
  (`/Users/.../Token.sol`) that broke when SARIF was uploaded to a GitHub
  Code Scanning runner on a different machine.
- `fullyQualifiedName` only joins with `.` when **both** contract and
  function names are non-empty. Contract-scope findings used to emit
  `"MyToken."` (trailing dot) which violates the SARIF spec and made
  some consumers silently drop the logical location.
- Helpers: `sarifArtifactURI(absFile, projectRoot)`, `pathToFileURI(p)`.

**Reachability in SARIF output:**

Findings with a populated `Reachability` chain emit one
`result.relatedLocations[]` entry per hop, with the message text labeled
`entry: <fqn>` for hop 0, `host: <fqn>` for the last hop, and `hop: <fqn>`
for intermediates. The hop's `physicalLocation.region.startLine` is the
function header (or the dangerous statement's line for the host hop, when
available). This is the format GitHub Code Scanning and the SARIF viewer in
VS Code render as a navigable trace beneath the primary issue.

`Finding.EntryPoint` and `Finding.PrimaryAST` are surfaced under
`result.properties.entryPoint` and `result.properties.primaryAst`
respectively — GitHub renders these directly in the issue body. The fields
are emitted only when non-empty so SARIF for findings without a chain
(contract-scope, source-scope) stays unchanged.

### console.go

Console rendering helpers.

**Key types:**
- `ColorMode` — `ColorAuto` (default, TTY-aware), `ColorAlways`, `ColorNever`

**Key functions:**
- `IsTerminal(w)` — pure-stdlib TTY detection
- `PrintConsoleSummaryHeader(...)` — top banner: `N findings: a CRITICAL, b HIGH... · scanned X contracts in Yms`
- `Colorize`, `SeverityColor` — ANSI helpers, no-op when colors disabled
- `NO_COLOR` env (https://no-color.org) is honored unconditionally

The CLI also passes a `plainMode` flag (derived from `--no-color` / `NO_COLOR`
/ non-TTY) into `printCombinedConsole` and `printFindings` so emoji
decorations are suppressed consistently with the header.

**Title-only console by default:** `printFindings` in `cmd/w3goaudit/root.go`
prints only the numbered finding title per severity group on the terminal,
because the full per-finding block overflowed narrow terminals on large scans.
The full detail (`Location:`, `Confidence:`, `Details:`, and the reachability
continuation below) is always written to the result folder (`findings.md`,
`corpus/findings.json`) and is teed to the terminal only when `--verbose` is
set. The footer prints a one-line hint pointing at the result folder /
`--verbose` when not verbose.

**Reachability continuation line (verbose console only):** when a finding's
`Reachability` has more than one hop, the `--verbose` console path prints two
additional indented lines under the standard `Location:` block:

```
↳ via Contract.entry() ⇒ Contract._helper() ⇒ Contract._host()
↳ fix-here: Contract.entry
```

This keeps the one-line summary compatible with grep / piping while still
surfacing the auditor-actionable fix site on console output.

### scan_formats.go

Markdown and HTML findings rendering plus shared helpers.

**Key changes:**
- `groupFindings()` now synthesizes a key from
  `(severity, title, file, function, line)` when `TemplateID` is empty,
  so two unrelated empty-ID findings no longer collapse into one entry.
- `SetReportProjectRoot(root)` / `relPathForReport(absFile)` — wired in
  from the CLI before rendering so `formatLocation` emits paths relative
  to the project root (with `filepath.Base` fallback for files outside).
  Previously the report only showed basenames, which made duplicate
  filenames (`/src/Token.sol` vs `/test/mocks/Token.sol`) ambiguous.

**Reachability trace rendering:**

Each per-occurrence block now embeds a rich call-chain trace produced from
`Finding.Reachability` + `Finding.EntryPoint` (populated by the engine — see
`pkg/engine/INDEX.md`, Matched-node attribution & Reachability).

- `renderFindingTraceMarkdown(*engine.Finding) string` — Markdown fragment.
  Lays out the file path, the fix-here entry, then a dotted-level list
  showing every hop from entry to host:

  ```
  **File:** `…/arbitrary-transferfrom.sol`
  **Entry point (fix-here):** `VulnerableSwappedArgsForward.depositFrom`
  **Reachability path** (entry → … → host of dangerous statement):
  - `.`   `…depositFrom()`  *(external, L344)*  ← entry
  - `..`  `…_stage()`       *(internal, L348)*
  - `...` **`…_commit()`**  *(internal, L352)*  ← dangerous statement
  ```

- `renderFindingTraceHTML(*engine.Finding) string` — HTML counterpart.
  Emits a `<div class="w3a-trace">` block containing semantic markup:
  `<div class="w3a-trace-file">`, `<div class="w3a-trace-entry">`,
  `<ol class="w3a-trace-path">` with `<li class="w3a-trace-step">` items
  whose inline `margin-left` scales per depth so the visual ladder matches
  the Markdown variant.
- `htmlEscape(s) string` — tiny replacement of `& < > " '` so contract
  names and file paths embedded in the trace block stay safe to render.

**CSS additions (HTML output):** a `.w3a-trace` rules block lives in the
inline `<style>` of `FormatFindingsAsHTML`. It uses the existing CSS
variables (`--bg-secondary`, `--text-muted`, `--high`, `--medium`) so the
trace block honors light/dark themes without extra theming surface.

### code_extract.go

Source-code excerpt for finding rendering.

**Key changes:**
- `extractCodeForFinding` is now defensive against stale or out-of-range
  line numbers: explicit error comments when the file is missing, `Line==0`,
  or `Line > EOF`. Previously these conditions silently produced an empty
  code block.
- Scanner buffer increased to 1 MB to handle minified or generated
  Solidity sources that exceed the default 64 KB token size.

## Usage Flow

```go
// 1. Build summary
gen := report.NewGenerator(db)
summary := gen.GenerateSummary()

// 2a. Render markdown / HTML (overview + findings rendered separately).
//     Each occurrence carries a reachability trace block when
//     finding.Reachability is populated by the engine.
overviewMD  := summary.ToMarkdown()
findingsMD  := report.FormatFindingsAsMarkdown(findings, db)

overviewHTML := summary.ToHTML()
findingsHTML := report.FormatFindingsAsHTML(findings, db)

// 2b. Or build versioned JSON documents. The findings JSON passes the new
//     reachability / entryPoint / primaryAst fields through unchanged.
tool := report.ToolMeta{Name: "w3goaudit", Version: "0.3.0"}
ovJSON := report.BuildOverviewJSON(tool, summary, db.GetStats())
fdJSON := report.BuildFindingsJSON(tool, findings)

// 2c. Or emit SARIF for CI integration. projectRoot enables relative URIs +
//     originalUriBaseIds.srcRoot (required for GitHub Code Scanning
//     portability). When a finding has a Reachability chain, it is emitted
//     as result.relatedLocations[] with properties.entryPoint and
//     properties.primaryAst on the result.
sarif, _ := report.FormatFindingsAsSARIF(findings, tool, db.ProjectRoot)
```

Reading the structured trace data from SDK code:

```go
for _, f := range findings {
    if f.Reachability == nil { continue }
    for i, step := range f.Reachability.Steps {
        fmt.Printf("  step[%d]: %s.%s() L%d (%s)\n",
            i, step.Contract, step.Function, step.Line, step.Visibility)
    }
    if f.EntryPoint != nil {
        fmt.Printf("  fix-here: %s.%s\n", f.EntryPoint.Contract, f.EntryPoint.Function)
    }
    if f.PrimaryAST != nil {
        fmt.Printf("  matched: %s (%s) at L%d\n",
            f.PrimaryAST.Kind, f.PrimaryAST.Name, f.PrimaryAST.Start)
    }
}
```

## File Layout

A scan writes a **result folder** (v0.3) via `WriteBundle` (`bundle.go`):

```
<output>/
├── overview.md            # SummaryReport.ToMarkdown(); pragma Version per contract
├── findings.md            # FormatFindingsAsMarkdown
├── results.sarif          # FormatFindingsAsSARIF (always)
├── run.log                # written by the CLI (always)
├── corpus/                # machine-readable mirror
│   ├── database.json      # canonical DB (reuse via --db corpus/database.json)
│   ├── findings.json      # BuildFindingsJSON
│   └── overview.json      # BuildOverviewJSON
└── <MainContract>/
    ├── state-changes.md   # reachability matrix (state_matrix.go)
    └── workflows/<entryFn>.md
```

`--html` additionally emits `overview.html` + `findings.html`. The default
folder name and the `--stdout` (no-files) path are owned by
`cmd/w3goaudit/root.go`; the `report` package owns the folder's internal layout
via `WriteBundle`. The previous `-o report.<ext>` split (`splitOutputPaths`) and
the `--json`/`--md`/`--format` selectors were removed.

## Styling

- **HTML**: Dark mode theme (Tokyo Night inspired), responsive layout, interactive tables/graphs. Findings HTML carries `lang="en"`, semantic `<main>`/`<section>`/`<article>`, ARIA labels on severity badges and locations, focus rings for keyboard navigation, and a skip-to-findings link for screen readers.
- **Markdown**: GitHub-flavored markdown, semantic HTML for specialized layouts (collapsible details).
