# W3GoAudit

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/th13vn/w3goaudit.svg)](https://pkg.go.dev/github.com/th13vn/w3goaudit)

A Go-based CLI & SDK for auditing Solidity smart contracts using rule-based templates with WQL query language.

---

## Quick Start

```bash
# Install (templates download on first run; embedded pack is the offline fallback)
go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest

# Scan contracts → writes a ./contracts-audit result folder
# (the "-audit" suffix is the collision guard: the output can't overwrite the scanned dir)
w3goaudit ./contracts/

# Scan one file into a named folder
w3goaudit Token.sol -o audit/

# Use a custom template directory
w3goaudit ./contracts/ -t ./my-templates/

# Only high + critical findings
w3goaudit ./contracts/ -s high,critical

# Print the summary only, write nothing
w3goaudit ./contracts/ -q

# Build database
w3goaudit build ./contracts/ -o database.json

# Extract contract info — every extract subcommand can build from a source
# path (like the scan) or load a pre-built database with --db
w3goaudit extract main ./contracts/
w3goaudit extract inheritance MyToken ./contracts/
w3goaudit extract entry MyToken --db database.json
```

Example console output:

```
▶ Reading sources: ./contracts/
▶ Building database: 74 files, 164 contracts, 1203 functions
▶ Scanning: 25 templates (~/.w3goaudit/templates)
▶ Writing report: ./contracts-audit

81 findings: 65 HIGH, 16 MEDIUM · scanned 74 contracts in 51ms
── Findings ──────────────────────────────────────────────
  🟠 HIGH (65 findings)
  1. Arbitrary transferFrom Call
  2. Unchecked ERC20 transfer / transferFrom Return Value
  ... (titles only on console; full detail in findings.md, or use --verbose)

📂 Results written to: ./contracts-audit
```

Results land in a folder — `README.md` (landing page), `summary.md`,
`overview.md`, `findings.md`, `results.sarif`, `run.log`, a machine-readable
`data/` folder (JSON + DB + manifest index), and a `contracts/` tree (one
sub-folder per main contract, mirroring source paths) with per-entry workflow
files and a state-change report. See [Result folder layout](#result-folder-layout).

---

## Features

- **AST Parsing** - Parse Solidity using [solast-go](https://github.com/th13vn/solast-go)
- **Contract Database** - Comprehensive database with inheritance, entry points, call graphs
- **Semantic Type Facts** - Parameters, state variables, locals, casts, and call receivers carry lightweight type facts so WQL can stay simple while call classification becomes more precise
- **C3 Linearization** - Proper Solidity inheritance resolution
- **Function Selectors** - Calculate 4-byte keccak256 selectors
- **Call Graph** - Recursive tracing with filtered built-ins and optimized styling
- **Exact Identity** - Internal contracts use `absPath#Contract`; functions use
  `absPath#Contract.selector(types)`. Exact C3 `LinearizedBaseIDs` and resolved
  import provenance prevent duplicate names in different files from cross-wiring.
- **Precise Locations** - One-based, half-open Unicode-code-point columns plus
  zero-based, half-open UTF-8 byte offsets. SARIF declares
  `columnKind: unicodeCodePoints` and never emits byte offsets as
  `charOffset`/`charLength`.
- **WQL Templates** - Powerful query language for security pattern matching, with load-time validation (regex, preset names, filter/match placement) so typos fail fast instead of producing silent zero-finding scans. Includes a source-scope `regex` matcher for rare raw-source predicates and contract-scope AST matching for same-contract local/inherited combination rules.
- **Result Folder** - One opinionated folder per scan: a `README.md` landing page, `summary.md`, `overview.md` (metrics + in-scope contract index), `findings.md`, always-on `results.sarif` + `run.log`, a machine-readable `data/` (`manifest.json`, reusable `database.json`, findings/overview, always-on `diagnostics.json`, plus nav/explorer data for the editor extension), and a `contracts/` tree mirroring source paths. Opt-in **fully offline** HTML mirror with `--html` (graph library embedded — no CDN request).
- **Per-Entry Workflow Files** - For every entry function, a self-contained context block (signature, auth / access control, guards & checks, branch conditions, transitive state effects, Mermaid call workflow) — built to be fed to a human or an AI auditor.
- **State-Change Matrix** - Per contract, each state variable mapped to the functions that write it and the entry points that reach a writer (reverse call-graph walk).
- **Self-Provisioning Templates** - Downloads the latest [`w3goaudit-templates`](https://github.com/th13vn/w3goaudit-templates) release on first run (nuclei-style, no git clone), refreshable with `--update-templates`; embedded official pack is the always-available offline fallback. Extraction is size/file-count capped and installed with a rollback-safe staged directory swap. The GitHub zipball is TLS-authenticated but not checksum/signature verified.
- **Reachability-Aware Findings** - Every finding can carry the full call chain from an externally-callable entry down to the function that hosts the dangerous statement: structured `reachability.steps[]` + `entryPoint` (auditor's fix-here pointer) + `primaryAst` in JSON, `relatedLocations` in SARIF, dotted-level trace block in Markdown / HTML, `↳ via …` continuation line on the `--verbose` console. Multi-site findings also carry `related[]`, and Markdown renders all matched sites with full function context.
- **SARIF 2.1.0** - Always emitted (`results.sarif`) for GitHub Code Scanning, with portable relative URIs + `srcRoot`; fail-closed template loading, `NO_COLOR`-aware console.
- **Project Detection** - Auto-detect Foundry, Hardhat, Truffle
- **Git Integration** - Auto-detect git repos and generate clickable file links to GitHub/GitLab
- **Advanced Metrics** - nSLOC, Access Control Analysis, Grouped Entry Points
- **Source Extraction** - Extract function source, context bundles, and full transitive workflow source

---

## Documentation

Comprehensive guides available in [`docs/`](./docs):

- **[Workflows](./docs/workflows.md)** - Detailed internal workflows with diagrams
- **[Usage Guide](./docs/usage.md)** - Complete CLI and SDK reference
- **[SDK Documentation](./docs/sdk.md)** - Comprehensive SDK API reference and integration guide
- **[WQL Syntax](./docs/wql-syntax.md)** - Template writing reference
- **[Project Overview](./docs/project-overview.md)** - Architecture and design
- **[Internals](./docs/internals.md)** - Technical deep-dive: functions, workflows, algorithms (C3, taint, access-control), and precision/edge-case decisions

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/th13vn/w3goaudit
cd w3goaudit

# Build
go build -o w3goaudit ./cmd/w3goaudit

# Move to PATH (optional)
sudo mv w3goaudit /usr/local/bin/
```

### Via Go Install

```bash
go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest
```

### Self-Update

```bash
w3goaudit --update   # re-runs `go install …@latest` (requires the Go toolchain)
```

---

## Result Folder Layout

Every scan (unless `--stdout/-q`) writes a result folder, optimized to feed a
human or AI auditor:

```
<output>/
├── README.md              # landing page: counts + links to everything
├── summary.md             # metrics + findings-by-severity + rules-hit tables
├── overview.md            # metrics + in-scope contract index (table, links into contracts/)
├── findings.md            # human-readable findings
├── results.sarif          # SARIF 2.1.0 (always)
├── run.log                # full verbose detail (always; replaces --log)
├── data/                  # machine-readable output
│   ├── manifest.json      # index: tool, scope, counts, file list, per-contract refs
│   ├── database.json      # canonical DB — reuse via --db data/database.json
│   ├── findings.json
│   ├── overview.json
│   ├── diagnostics.json    # analysis-quality diagnostics; [] when complete
│   ├── nav.json           # flat symbol/caller/interface-impl index (extension)
│   └── explorer.json      # per-main-contract model: constants, storage, entry/getter fns
└── contracts/             # one sub-tree per main contract, mirroring source paths
    └── <relative-source-path-without-ext>/
        └── <ContractName>/
            ├── README.md          # per-contract landing: findings + architecture detail
            ├── state-changes.md   # state var → Written By (fns) → Reachable From (entries)
            └── workflows/
                ├── <entryFn>.md             # one file per entry function
                └── <entryFn>__<selector>.md # overloads disambiguated by 4-byte selector
```

The default folder name is the scanned project dir name (or `.sol` file stem);
`-o/--output` overrides it, and `-audit` is appended if the default would collide
with the scanned directory. Each `workflows/<entryFn>.md` records the signature
(selector, 4-byte, payable, version), auth / access control (modifiers,
`msg.sender` checks, ⚠ Unprotected, ⚠ tx.origin), guards/checks, branch
conditions, transitive state effects, and a Mermaid call-workflow diagram.

`data/manifest.json` distinguishes the detected `projectRoot` from the original
`scanTarget` (`target` is the compatibility alias), separates declaration
category counts, exposes `analysisComplete`/diagnostic counts, and indexes every
emitted artifact. Finding/content ordering is deterministic; generated
timestamps vary unless SDK callers inject a fixed report/bundle clock.

---

## CLI Quick Reference

### Commands

| Command               | Description                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------------ |
| *(default)*           | Scan contracts — stats, overview, findings                                                       |
| `build`               | Build contract database (JSON)                                                                   |
| `extract main`        | Main (deployable) contracts in a project                                                         |
| `extract entry`       | Entry point functions for a contract                                                             |
| `extract inheritance` | C3 linearization (derived → base) — must be a main contract                                      |
| `extract statevar`    | State variables (including inherited, storage order)                                             |
| `extract selector`    | Function selectors (4-byte hashes)                                                               |
| `extract involve`     | Every entry-point workflow that reaches a function, one Mermaid chart per entry                  |
| `extract workflow`    | Full transitive source for an entry function (report-ready)                                      |
| `extract bundle`      | **LLM-ready** one-document context: source + callers + callees + state + inheritance + selectors |
| `extract context`     | Combined context package for a function                                                          |
| `extract source`      | Raw Solidity source for a function                                                               |
| `extract diff`        | Compare two pre-built databases                                                                  |
| `completion`          | Generate shell completions                                                                       |
| `version`             | Show version information                                                                         |

The root command **is** the scan (there is no `scan` subcommand). Every scan
flag has a long and short form: `-o/--output`, `-t/--template`, `-d/--db`,
`-v/--verbose`, `-s/--severity` (exact set), `-m/--min-severity` (threshold),
`-i/--include`, `-e/--exclude`, `-l/--list-templates`, `-H/--html`,
`-q/--stdout`, `--strict-imports`, `-T/--update-templates`, `-u/--update`.
`--severity` and `--min-severity` are mutually exclusive. Import resolution is
tolerant by default; use `--strict-imports` when unresolved imports must fail
the source scan or an equivalent `--db` cache scan. Import warnings are always
written to stderr.

`extract` subcommands are listed widest-scope first (project → contract →
function → utility). Like the scan, each one (except `diff`) can **build from a
source path** — `extract <name> ./contracts/` — or load a pre-built database
with `--db`. Extract output defaults to **markdown**; pass `--format=json` (or
`-o file.json`) for the machine-readable shape.

Contract queries accept an exact `file#Contract` ID or a unique name. Function
queries accept an exact function ID, `Contract.selector`, a full selector, a
4-byte signature, or a unique bare name. Ambiguous queries fail with sorted
candidates instead of selecting by map order; `--contract` follows the same
exact-ID-or-unique-name rule.

### Examples

```bash
# Default scan → writes a ./contracts-audit result folder (collision guard adds "-audit")
w3goaudit ./contracts/

# Scan one file into a named folder
w3goaudit Token.sol -o audit/

# Use a custom template directory
w3goaudit ./contracts/ -t ./templates/official/

# Only high + critical (exact set), or a threshold + exclude glob
w3goaudit ./contracts/ -s high,critical
w3goaudit ./contracts/ -m medium -e 'HIGH-WEAK-PRNG'

# Also emit the HTML mirror, or print the summary only (write nothing)
w3goaudit ./contracts/ -H
w3goaudit ./contracts/ -q

# List the active template set (no path needed)
w3goaudit -l

# Re-scan a pre-built database (e.g. the DB from a previous run)
w3goaudit -d ./contracts/data/database.json

# Fail closed when any persisted/source import is unresolved
w3goaudit ./contracts/ --strict-imports
w3goaudit -d ./contracts/data/database.json --strict-imports

# Refresh templates from the latest release; update the tool itself
w3goaudit --update-templates
w3goaudit --update

# Extract directly from source (builds the database on the fly)
w3goaudit extract main ./contracts/
w3goaudit extract statevar MyToken ./contracts/

# …or build once and reuse the database across many extracts
w3goaudit build ./contracts/ -o db.json
w3goaudit extract entry MyToken --db db.json
w3goaudit extract selector MyToken --db db.json
w3goaudit extract diff --db1 old.json --db2 new.json

# LLM-ready bundle: one markdown document with source + callers/callees + state + inheritance
w3goaudit extract bundle withdraw --db db.json --contract MyToken -o bundle.md

# Every workflow that reaches a function, as markdown for AI agents
w3goaudit extract involve withdraw --db db.json --format=md

# Shell completion
source <(w3goaudit completion bash)
```

For complete usage, see [Usage Guide](./docs/usage.md).

---

## SDK Quick Reference

```go
import (
    "github.com/th13vn/w3goaudit/pkg/reader"
    "github.com/th13vn/w3goaudit/pkg/builder"
    "github.com/th13vn/w3goaudit/pkg/engine"
)

// Read sources
r := reader.New()
sources, _ := r.Read("./contracts/")

// Build database
b := builder.New()
db, _ := b.Build(sources)

// Execute template
e := engine.New(db)
tmpl, _ := engine.LoadTemplate("./template.yaml")
findings := e.Execute(tmpl)
```

For complete SDK documentation, see [Usage Guide](./docs/usage.md#sdk-usage).

---

## WQL Template Example

```yaml
meta:
  id: SEC-REEN-001
  title: Potential Reentrancy
  severity: HIGH
  confidence: MEDIUM
  description: External call before state variable update
  recommendation: Apply Check-Effects-Interactions pattern

query:
  from: entry_function     # public/external functions of main contracts
  where:
    - not: { preset: reentrancy_guarded }
    - sequence:
        - block: outgoing_call
        - block: state_write
```

This is **WQL** (W3GoAudit Query Language) — a YAML template is `meta` plus
one `query:` (`select`/`from`/`where`, or a query-level `and:`/`or:`
composition). All 106 repository templates (25 official, 5 feature-test, and
76 benchmark) use it; see the
[WQL Syntax Guide](./docs/wql-syntax.md) for the full language reference.

---

## Project Structure

```
w3goaudit/
├── cmd/w3goaudit/          # CLI entry point (root scan, build, extract, completion)
├── pkg/
│   ├── reader/             # File discovery and loading
│   ├── logging/            # Immutable scan-local logger
│   ├── builder/            # Database construction (7 phases incl. per-fn effects)
│   ├── engine/             # WQL template execution
│   ├── home/               # ~/.w3goaudit config + template home (release download)
│   ├── types/              # Core data structures
│   └── report/             # Result-folder bundle, state matrix, console/MD/HTML/SARIF
├── templates/              # WQL detection templates (official/ embedded via go:embed)
│   ├── official/              # Curated official pack (embedded fallback; split by severity: critical/ high/ medium/)
│   └── test/                  # Engine feature-exercise templates
├── benchmarks/             # Docker Compose benchmark, 76 WQL ports, corpora, fixtures, results/
├── test-data/              # Test contracts (core/, security/)
└── docs/                   # Comprehensive documentation
```

---

## Key Workflows

### 1. Scan Workflow

```
Input → Reader → Builder → Database → Engine → Findings → Result-folder bundle
```

1. Discover `.sol` files
2. Parse with solast-go
3. Build database (inheritance, call graph, selectors, per-function effects)
4. Load WQL templates (home → embedded fallback)
5. Execute queries
6. Generate findings
7. Write the result folder (overview, findings, SARIF, run.log, data/, per-contract workflows + state-changes)

### 2. Build Workflow

Build phases:
1. Parse files
2. Build ASTs, data flow, and semantic type facts
3. Calculate selectors
4. Build inheritance (C3)
5. Build call graph
6. Calculate entry points
7. Analyze per-function effects (state writes, guards, access control)

### 3. Default Scan (Combined) Workflow

The default scan combines stats, overview, and findings:
- Statistics (files, contracts, functions, nSLOC)
- Contract hierarchy with call graphs (Mermaid diagrams)
- Security findings (when templates provided)

For detailed workflows, see [Workflows Documentation](./docs/workflows.md).

---

## Database Structure

The contract database contains:

- **Contracts** - All contracts with kind, inheritance, functions, state variables
- **Functions** - Visibility, modifiers, parameters, selectors, AST trees
- **Inheritance** - C3 linearization for proper method resolution
- **Call Graph** - Internal/external call edges with line numbers
- **Entry Points** - Public/external functions per main contract
- **Main Contracts** - Deployable contracts ranked by inheritance depth

---

## Testing

Development uses the exact Go version declared by `go.mod` (currently
Go 1.26.5). This security-driven floor includes the standard-library fixes
required by govulncheck. Before release, run formatting, `go mod tidy -diff`,
vet, staticcheck, cyclomatic complexity, Markdown links,
normal/race/shuffled tests, host and Linux ARM64 builds, govulncheck, a full
official scan/artifact smoke test, and the Docker Compose competitive benchmark
locally or in user-owned external automation.

```bash
# Build database
w3goaudit build test-data/core/build-database/ -o test-db.json --verbose

# Security scan → writes a test-data/security result folder
w3goaudit test-data/security/ --template templates/official/ -o scan-report/

# Project overview (always part of the scan — see overview.md in the folder)
w3goaudit test-data/core/build-database/ -o overview-out/

# Competitive quality gate: precision >= 0.65, recall >= 0.95, failed cases = 0.
# Docker Compose is the only supported host entry point. The Dockerfile derives
# and verifies the Go version directly from go.mod.
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

See [benchmarks/README.md](./benchmarks/README.md) for suites, tool selection,
output ownership, and the fail-closed contract.

Test contracts are documented in:
- [test-data/security/README.md](./test-data/security/README.md)
- [test-data/core/build-database/README.md](./test-data/core/build-database/README.md)

---

## Roadmap

### Current Features

- AST parsing and contract database
- C3 inheritance linearization
- Recursive call graph building
- Per-function effects analysis (state writes, guards, access control)
- WQL query language
- Result-folder output: Markdown + SARIF + JSON data/ + per-entry workflows + state-change matrix
- Self-provisioning template home (`~/.w3goaudit`) with release download + embedded fallback
- CLI and SDK
- Source/context/workflow extraction for report writing

### Planned Features 🔜

- Repository scanning (GitHub)
- On-chain contract fetching (Etherscan API)
- Enhanced data flow analysis
- Visualization exports (Mermaid, DOT)
- LSP integration for IDE support
- Template marketplace

For complete roadmap, see [Project Overview](./docs/project-overview.md#roadmap).

---

## Contributing

Contributions are welcome — especially **new detectors**, which you can write in
YAML without touching Go. See **[CONTRIBUTING.md](./CONTRIBUTING.md)** for a
"write your first detector in 5 minutes" walkthrough, the dev setup, and the PR
checklist.

To report a vulnerability **in the tool itself**, see
**[SECURITY.md](./SECURITY.md)** (please don't open a public issue).

---

## License

[MIT](./LICENSE) © th13vn. Third-party dependency and trademark notices are in
[NOTICE](./NOTICE).

---

## Links

- **Documentation**: [docs/](./docs)
- **Templates**: [templates/](./templates)
- **Test Data**: [test-data/](./test-data)
- **AST Parser**: [solast-go](https://github.com/th13vn/solast-go)
