# W3GoAudit

[![CI](https://github.com/th13vn/w3goaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/th13vn/w3goaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/th13vn/w3goaudit.svg)](https://pkg.go.dev/github.com/th13vn/w3goaudit)

A Go-based CLI & SDK for auditing Solidity smart contracts using rule-based templates with WQL query language.

---

## Quick Start

```bash
# Install (the official detector pack is embedded in the binary)
go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest

# Scan contracts — uses the built-in official pack by default
w3goaudit ./contracts/

# Or point at a custom template directory
w3goaudit ./contracts/ --template ./my-templates/

# CI gating: exit non-zero (code 2) on any HIGH+ finding, emit SARIF
w3goaudit ./contracts/ --fail-on high --sarif -o report.sarif

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
81 findings: 65 HIGH, 16 MEDIUM · scanned 74 contracts in 51ms
── Findings ──────────────────────────────────────────────
  🟠 HIGH (65 findings)
  🟡 MEDIUM (16 findings)
```

---

## Features

- **AST Parsing** - Parse Solidity using [solast-go](https://github.com/th13vn/solast-go)
- **Contract Database** - Comprehensive database with inheritance, entry points, call graphs
- **Semantic Type Facts** - Parameters, state variables, locals, casts, and call receivers carry lightweight type facts so WQL can stay simple while call classification becomes more precise
- **C3 Linearization** - Proper Solidity inheritance resolution
- **Function Selectors** - Calculate 4-byte keccak256 selectors
- **Call Graph** - Recursive tracing with filtered built-ins and optimized styling
- **WQL Templates** - Powerful query language for security pattern matching, with load-time validation (regex, preset names, filter/match placement) so typos fail fast instead of producing silent zero-finding scans. Includes scope-aware `source_regex` for rare raw-source predicates.
- **Multiple Outputs** - JSON (versioned schema), Markdown, HTML (interactive, PDF export), Console, **SARIF 2.1.0** (GitHub Code Scanning, with portable relative URIs + `srcRoot`)
- **Two-File Reports** - File output always splits into `<name>.overview.<ext>` (project structure) and `<name>.findings.<ext>` (issues), so reviewers can diff them independently
- **Reachability-Aware Findings** - Every finding can carry the full call chain from an externally-callable entry down to the function that hosts the dangerous statement: structured `reachability.steps[]` + `entryPoint` (auditor's fix-here pointer) + `primaryAst` in JSON, `relatedLocations` in SARIF, dotted-level trace block in Markdown / HTML, `↳ via …` continuation line in console. Opt in to matched-node `Location` attribution (Slither/Semgrep-style) with `--location-source matched` or `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1`.
- **CI-Ready** - SARIF 2.1.0 for GitHub Code Scanning, fail-closed template loading, checked file writes, `NO_COLOR`-aware console, overwrite warnings on existing `-o` targets
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

---

## CLI Quick Reference

### Commands

| Command | Description |
|---------|-------------|
| *(default)* | Scan contracts — stats, overview, findings |
| `build` | Build contract database (JSON) |
| `extract main` | Main (deployable) contracts in a project |
| `extract entry` | Entry point functions for a contract |
| `extract inheritance` | C3 linearization (derived → base) — must be a main contract |
| `extract statevar` | State variables (including inherited, storage order) |
| `extract selector` | Function selectors (4-byte hashes) |
| `extract involve` | Every entry-point workflow that reaches a function, one Mermaid chart per entry |
| `extract workflow` | Full transitive source for an entry function (report-ready) |
| `extract bundle` | **LLM-ready** one-document context: source + callers + callees + state + inheritance + selectors |
| `extract context` | Combined context package for a function |
| `extract source` | Raw Solidity source for a function |
| `extract diff` | Compare two pre-built databases |
| `completion` | Generate shell completions |
| `version` | Show version information |

`extract` subcommands are listed widest-scope first (project → contract →
function → utility). Like the scan, each one (except `diff`) can **build from a
source path** — `extract <name> ./contracts/` — or load a pre-built database
with `--db`.

Output defaults to **markdown** (human/LLM-friendly); pass `--format=json` (or
`-o file.json`) for the machine-readable shape. Format is also inferred from the
`-o` file extension.

### Examples

```bash
# Default scan (console)
w3goaudit ./contracts/

# Scan with templates
w3goaudit ./contracts/ --template ./templates/official/

# Markdown report — produces report.overview.md + report.findings.md
w3goaudit ./contracts/ --template ./templates/official/ --md -o report.md

# JSON (versioned schema) — produces report.overview.json + report.findings.json
w3goaudit ./contracts/ --template ./templates/official/ --json -o report.json

# HTML — produces report.overview.html + report.findings.html
w3goaudit ./contracts/ --template ./templates/official/ --html -o report.html

# SARIF 2.1.0 for GitHub Code Scanning (additive: combine with any other format)
w3goaudit ./contracts/ --template ./templates/official/ --md -o report.md --sarif

# CI gate (exit 2 on HIGH+, evaluated before display filters), filtering, inventory
w3goaudit ./contracts/ --fail-on high
w3goaudit ./contracts/ --min-severity medium --exclude 'SEC-PRNG-*'
w3goaudit ./contracts/ --list-templates

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
  scope: entrypoint  # Public/external functions only
  filter:
    not:
      modifier: (?i)(nonReentrant|lock|guard)
  match:
    # Find: external call → state modification
    contains:
      sequence:
        - kind: outgoing_call
        - kind: state_write
```

For complete WQL syntax, see [WQL Syntax Guide](./docs/wql-syntax.md).

---

## Project Structure

```
w3goaudit/
├── cmd/w3goaudit/          # CLI entry point (root, build, extract, completion)
├── pkg/
│   ├── reader/             # File discovery and loading
│   ├── builder/            # Database construction (6 phases)
│   ├── engine/             # WQL template execution
│   ├── types/              # Core data structures
│   └── report/             # Multi-format output (console/JSON/MD/HTML/SARIF)
├── templates/              # WQL detection templates (official/ embedded via go:embed)
│   ├── official/              # Curated official pack (embedded in the binary)
│   └── test/                  # Engine feature-exercise templates
├── test-data/              # Test contracts (core/, security/)
└── docs/                   # Comprehensive documentation
```

---

## Key Workflows

### 1. Scan Workflow

```
Input → Reader → Builder → Database → Engine → Findings → Report
```

1. Discover `.sol` files
2. Parse with solast-go
3. Build database (inheritance, call graph, selectors)
4. Load WQL templates
5. Execute queries
6. Generate findings
7. Format output

### 2. Build Workflow

Build phases:
1. Parse files
2. Build ASTs, data flow, and semantic type facts
3. Calculate selectors
4. Build inheritance (C3)
5. Build call graph
6. Calculate entry points

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

```bash
# Build database
w3goaudit build test-data/core/build-database/ -o test-db.json --verbose

# Security scan
w3goaudit test-data/security/ --template templates/official/ --md -o scan-report.md

# Project overview (now part of default scan)
w3goaudit test-data/core/build-database/ --md -o summary.md
```

Test contracts are documented in:
- [test-data/security/README.md](./test-data/security/README.md)
- [test-data/core/build-database/README.md](./test-data/core/build-database/README.md)

---

## Roadmap

### Current Features

- AST parsing and contract database
- C3 inheritance linearization
- Recursive call graph building
- WQL query language
- Multiple output formats (console, JSON, Markdown, HTML)
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
