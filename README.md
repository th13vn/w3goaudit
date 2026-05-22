# W3GoAudit Engine

A Go-based CLI & SDK for auditing Solidity smart contracts using rule-based templates with WQL query language.

---

## Quick Start

```bash
# Install
go install github.com/th13vn/w3goaudit-engine/cmd/w3goaudit@latest

# Scan contracts (default command)
w3goaudit ./contracts/ --template ./templates/

# Build database
w3goaudit build ./contracts/ -o database.json

# Extract contract info
w3goaudit extract entry MyToken --db database.json
w3goaudit extract inheritance MyToken --db database.json
```

---

## Features

- **AST Parsing** - Parse Solidity using [solast-go](https://github.com/th13vn/solast-go)
- **Contract Database** - Comprehensive database with inheritance, entry points, call graphs
- **C3 Linearization** - Proper Solidity inheritance resolution
- **Function Selectors** - Calculate 4-byte keccak256 selectors
- **Call Graph** - Recursive tracing with filtered built-ins and optimized styling
- **WQL Templates** - Powerful query language for security pattern matching, with load-time validation (regex, preset names, filter/match placement) so typos fail fast instead of producing silent zero-finding scans
- **Multiple Outputs** - JSON (versioned schema), Markdown, HTML (interactive, PDF export), Console, **SARIF 2.1.0** (GitHub Code Scanning, with portable relative URIs + `srcRoot`)
- **Two-File Reports** - File output always splits into `<name>.overview.<ext>` (project structure) and `<name>.findings.<ext>` (issues), so reviewers can diff them independently
- **CI-Ready** - SARIF 2.1.0 for GitHub Code Scanning, CWE/OWASP metadata on findings, `NO_COLOR`-aware console, overwrite warnings on existing `-o` targets
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
git clone https://github.com/th13vn/w3goaudit-engine
cd w3goaudit-engine

# Build
go build -o w3goaudit ./cmd/w3goaudit

# Move to PATH (optional)
sudo mv w3goaudit /usr/local/bin/
```

### Via Go Install

```bash
go install github.com/th13vn/w3goaudit-engine/cmd/w3goaudit@latest
```

---

## CLI Quick Reference

### Commands

| Command | Description |
|---------|-------------|
| *(default)* | Scan contracts — stats, overview, findings |
| `build` | Build contract database (JSON) |
| `extract entry` | Entry point functions for a main contract |
| `extract main` | Main (deployable) contracts (accepts a source path **or** `--db`) |
| `extract inheritance` | C3 linearization (derived → base) — must be a main contract |
| `extract involve` | Every entry-point workflow that reaches a function, one Mermaid chart per entry |
| `extract statevar` | State variables (including inherited, storage order) |
| `extract selector` | Function selectors (4-byte hashes) |
| `extract diff` | Compare two databases |
| `extract source` | Raw Solidity source for a function |
| `extract context` | Combined context package for a function |
| `extract bundle` | **LLM-ready** one-document context: source + callers + callees + state + inheritance + selectors |
| `extract workflow` | Full transitive source for an entry function (report-ready) |

All `extract` subcommands accept `--format=json` (default) or `--format=md`
(markdown, optimized for LLM context windows). Format is inferred from the
`-o` file extension when not specified.
| `completion` | Generate shell completions |
| `version` | Show version information |

### Examples

```bash
# Default scan (console)
w3goaudit ./contracts/

# Scan with templates
w3goaudit ./contracts/ --template ./templates/security/

# Markdown report — produces report.overview.md + report.findings.md
w3goaudit ./contracts/ --template ./templates/ --md -o report.md

# JSON (versioned schema) — produces report.overview.json + report.findings.json
w3goaudit ./contracts/ --template ./templates/ --json -o report.json

# HTML — produces report.overview.html + report.findings.html
w3goaudit ./contracts/ --template ./templates/ --html -o report.html

# SARIF 2.1.0 for GitHub Code Scanning (additive: combine with any other format)
w3goaudit ./contracts/ --template ./templates/ --md -o report.md --sarif

# Build database, then extract info
w3goaudit build ./contracts/ -o db.json
w3goaudit extract entry MyToken --db db.json
w3goaudit extract selector MyToken --db db.json
w3goaudit extract diff --db1 old.json --db2 new.json

# LLM-ready bundle: one markdown document with source + callers/callees + state + inheritance
w3goaudit extract bundle withdraw --db db.json --contract MyToken -o bundle.md

# Any extract can render markdown for AI agents
w3goaudit extract callgraph withdraw --db db.json --format=md

# Shell completion
source <(w3goaudit completion bash)
```

For complete usage, see [Usage Guide](./docs/usage.md).

---

## SDK Quick Reference

```go
import (
    "github.com/th13vn/w3goaudit-engine/pkg/reader"
    "github.com/th13vn/w3goaudit-engine/pkg/builder"
    "github.com/th13vn/w3goaudit-engine/pkg/engine"
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
  match:
    # Exclude functions with reentrancy guards
    not:
      mods: (?i)(nonReentrant|lock|guard)
    
    # Find: external call → state modification
    has:
      seq:
        - kind: external_call
        - kind: assignment
          attr:
            is_state_var: true
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
│   ├── report/             # Multi-format output
│   └── testing/            # Test utilities
├── templates/              # Security and test templates
├── test-data/              # Test contracts
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
2. Build ASTs
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
w3goaudit build test-data/build-database/ -o test-db.json --verbose

# Security scan
w3goaudit test-data/security/ --template templates/ --md -o scan-report.md

# Project overview (now part of default scan)
w3goaudit test-data/build-database/ --md -o summary.md
```

Test contracts are documented in:
- [test-data/security/TEST_CONTRACTS.md](./test-data/security/TEST_CONTRACTS.md)
- [test-data/build-database/README.md](./test-data/build-database/README.md)

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

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Update documentation
5. Submit a pull request

See [Project Overview](./docs/project-overview.md#contributing) for guidelines.

---

## License

MIT License

---

## Links

- **Documentation**: [docs/](./docs)
- **Templates**: [templates/](./templates)
- **Test Data**: [test-data/](./test-data)
- **AST Parser**: [solast-go](https://github.com/th13vn/solast-go)
