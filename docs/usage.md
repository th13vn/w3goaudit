# W3GoAudit Usage Guide

Complete guide for using W3GoAudit as a CLI tool and Go SDK.

---

## Table of Contents

- [Installation](#installation)
- [CLI Usage](#cli-usage)
  - [Default Scan (No Subcommand)](#default-scan)
  - [Build Command](#build-command)
  - [Extract Commands](#extract-commands)
  - [Completion Command](#completion-command)
  - [Version and Help](#version-and-help)
- [SDK Usage](#sdk-usage)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- **Go 1.21+** installed
- **Git** for cloning repository

### Build from Source

```bash
# Clone the repository
git clone https://github.com/th13vn/w3goaudit
cd w3goaudit

# Build the binary
go build -o w3goaudit ./cmd/w3goaudit

# Optionally, move to PATH
sudo mv w3goaudit /usr/local/bin/

# Verify installation
w3goaudit version
```

### Install via Go

```bash
# Install directly from repository
go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest

# Verify installation (ensure $GOPATH/bin is in your PATH)
w3goaudit version
```

---

## CLI Usage

### Default Scan

**Scan Solidity contracts and display project overview + security findings.**

When no subcommand is given, w3goaudit runs the default scan. Output order:
1. **Stats** — Project statistics (files, contracts, functions, nSLOC)
2. **Overview** — Main contracts with inheritance, entry points, call graphs
3. **Findings** — Security issues grouped by severity (if templates provided)

#### Basic Syntax

```bash
w3goaudit <path> [flags]
w3goaudit --db <database.json> [flags]
```

#### Flags

| Flag | Type | Description |
|------|------|-------------|
| `--template <path>` | string | Path to template file or directory |
| `-o, --output <file>` | string | Output base path. File output **always splits** into `<stem>.overview.<ext>` and `<stem>.findings.<ext>` |
| `--db <file>` | string | Use pre-built database JSON file (skip reading/building) |
| `--verbose [file]` | string | Enable verbose logging (optional file path, default: stdout) |
| `--json` | bool | Emit JSON (versioned, `schemaVersion: 1.0.0`) |
| `--html` | bool | Emit HTML (interactive, vis.js graphs, accessible) |
| `--md` | bool | Emit Markdown (GitHub-flavored) |
| `--sarif` | bool | **Additive.** Also emit SARIF 2.1.0 to `<stem>.sarif` (relative URIs + `originalUriBaseIds.srcRoot`, portable across CI runners) |
| `--no-color` | bool | Disable ANSI color in console output. Auto-disabled when stdout isn't a TTY; `NO_COLOR` env always wins |

**Behavior notes:**

- Only one of `--json`, `--html`, `--md` may be set; combinations error
  immediately instead of silently picking one.
- `-o report.html` without an explicit format flag infers HTML from the
  extension (`.html`/`.htm` → HTML, `.json` → JSON, `.md`/`.markdown` → MD,
  `.sarif` → SARIF, anything else → MD). Previously this silently
  defaulted to MD.
- `--template README.md` is rejected before YAML parsing — only `.yaml` /
  `.yml` files or directories are accepted.
- `NO_COLOR` env (https://no-color.org) is honored everywhere — the
  summary header, per-section emoji, and severity icons all suppress.
- Writing to an existing `-o` target prints
  `Replacing existing file: <path>` so a CI loop doesn't silently overwrite
  a previous report without notice. Writing to a directory errors clearly.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Success (scan completed) |
| `1` | Runtime error (bad path, parse failure, invalid flag value) |

#### Examples

**Scan a directory (console output):**
```bash
w3goaudit ./contracts/
```

**Scan with security templates:**
```bash
w3goaudit ./contracts/ --template ./templates/security/
```

**Generate Markdown report (always splits into two files):**
```bash
w3goaudit ./contracts/ --template ./templates/ --md -o report.md
# Produces:
#   report.overview.md   ← project overview, stats, call graphs, inheritance
#   report.findings.md   ← security findings grouped by severity, with CWE/OWASP/refs/fix
```

**Generate JSON output (versioned schema):**
```bash
w3goaudit ./contracts/ --template ./templates/ --json -o report.json
# Produces:
#   report.overview.json   ← { schemaVersion, tool, generatedAt, stats, overview }
#   report.findings.json   ← { schemaVersion, tool, generatedAt, counts, findings[] }
```

**Generate HTML report (split into two files):**
```bash
w3goaudit ./contracts/ --template ./templates/ --html -o report.html
# Produces:
#   report.overview.html   ← interactive overview with vis.js graphs
#   report.findings.html   ← security findings (accessible, ARIA, keyboard-navigable)
```

**Emit SARIF for GitHub Code Scanning (additive — combine with any other format):**
```bash
w3goaudit ./contracts/ --template ./templates/ --md -o report.md --sarif
# Adds report.sarif on top of the markdown split.
```

**Use pre-built database (faster, no rebuild):**
```bash
# Build database once
w3goaudit build ./contracts/ -o db.json

# Reuse for multiple scans
w3goaudit --db db.json --template ./templates/ --json
```

**Verbose output:**
```bash
w3goaudit ./contracts/ --verbose
w3goaudit ./contracts/ --verbose=scan.log  # Log to file
```

#### Console Output Example

```
╔══════════════════════════════════════════════════════════════╗
║                    W3GoAudit Scan Results                    ║
╚══════════════════════════════════════════════════════════════╝

  📁 Files:       5
  📝 Contracts:   8 (Interfaces: 2, Libraries: 1)
  🔧 Functions:   45 (Entry: 12)
  🏗️  Main:        3

── Main Contracts ──────────────────────────────────────────────

  📋 DeFiVault
     Source: src/DeFiVault.sol
     Inheritance: DeFiVault → ReentrancyGuard → Ownable → Context
     Entry Points: 8
       → deposit(deposit(uint256)) [whenNotPaused]
       → withdraw(withdraw(uint256)) [whenNotPaused]
       → setStrategy(setStrategy(address)) [onlyOwner]

── Findings ────────────────────────────────────────────────────

  🟠 HIGH (2 findings)
  ────────────────────────────────────────────────────────
  1. Potential Reentrancy
     Location: DeFiVault.sol:142 in withdraw()
     Confidence: MEDIUM
     Details: External calls occur before state variable updates

  ════════════════════════════════════════════════════════
  Scan Complete. Total Issues: 2
  Use -o report.md --md to generate full report.
```

---

### Build Command

**Build contract database without running security scans.**

```bash
w3goaudit build <path> -o <output.json> [flags]
```

#### Flags

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `-o, --output <file>` | string | **Yes** | Output JSON file path |
| `--db <file>` | string | No | Load existing database instead of rebuilding |
| `--verbose [file]` | string | No | Enable verbose logging |

#### Examples

```bash
w3goaudit build ./contracts/ -o database.json
w3goaudit build ./contracts/ -o database.json --verbose
```

---

### Extract Commands

**Extract specific information from a contract database.**

All extract commands accept `-o <file>` for file output and support two
output formats:

| Flag / inference | Result |
|---|---|
| `--format=json` *(default)* | Machine-readable JSON, every output carries `schemaVersion: "1.0.0"` |
| `--format=md` | Markdown rendering optimized for AI-agent / LLM context windows |
| `-o report.md` (no `--format`) | Inferred as markdown from extension |
| `-o report.json` (no `--format`) | Inferred as JSON from extension |

The markdown form uses headers, tables, and fenced code blocks — token-
efficient for LLMs and readable for humans pasting into PRs. The new
`extract bundle` subcommand produces a single LLM-ready document combining
a function's source, callers, callees, state variables, inheritance, and
the contract's selector table; it defaults to markdown.

#### extract entry

Extract entry point functions for a contract.

```bash
w3goaudit extract entry <contract-name> --db <database.json> [-o output.json]
```

**Example:**
```bash
w3goaudit extract entry DeFiVault --db database.json
```

**Output:**
```json
{
  "contract": "DeFiVault",
  "sourceFile": "/path/to/DeFiVault.sol",
  "entryCount": 15,
  "entryFunctions": [
    {
      "name": "withdraw",
      "selector": "withdraw(uint256)",
      "signature": "2e1a7d4d",
      "visibility": "external",
      "mutability": "",
      "modifiers": ["whenNotPaused"],
      "startLine": 162,
      "endLine": 177
    }
  ]
}
```

#### extract main

Extract main (deployable) contracts. Accepts either a source path (builds
the database on the fly) **or** a pre-built `--db`.

```bash
w3goaudit extract main <path> [-o output.md]
w3goaudit extract main --db <database.json> [-o output.json]
```

#### extract involve

For each entry-point function in the project, walk the call graph from
that entry. If the named function is reachable, emit a Mermaid flowchart
of the path. Replaces the older `extract callgraph` — auditors care about
"which user-facing functions are affected if I audit this helper", not
about a flat edge list.

```bash
w3goaudit extract involve <function-name> --db <database.json> [-o output.md]
```

**Examples:**

```bash
# Which entry points reach _settle?
w3goaudit extract involve _settle --db database.json

# JSON form for scripting / SDK consumption
w3goaudit extract involve _checkOwner --db database.json --format=json
```

The markdown output is one `## entrypoint Contract.func` section per
reachable entry, each with its own ```mermaid block. The entry node is
styled orange; the target function is red. Edges carry the call type
(internal / inherited / library / super / etc.) as labels.

#### extract inheritance

Show the C3 linearization chain (method resolution order, derived → base)
for a **main contract**. The argument MUST be a deployable contract;
interfaces, libraries, and abstract-only contracts are rejected with the
list of valid main contracts (so you can correct the typo immediately).

```bash
w3goaudit extract inheritance <main-contract-name> --db <database.json> [-o output.json]
```

**Output:**
```json
{
  "contract": "DeFiVault",
  "linearizedBases": ["DeFiVault", "Pausable", "ReentrancyGuard", "Ownable", "Context"],
  "inheritanceWeight": 5,
  "baseContracts": ["Ownable", "ReentrancyGuard", "Pausable"],
  "chain": [
    {"order": 1, "name": "DeFiVault", "kind": "contract"},
    {"order": 2, "name": "Pausable", "kind": "abstract"},
    {"order": 3, "name": "ReentrancyGuard", "kind": "abstract"}
  ]
}
```

#### extract statevar

List all state variables (including inherited) in storage order.

```bash
w3goaudit extract statevar <contract-name> --db <database.json> [-o output.json]
```

#### extract selector

List all function selectors (4-byte keccak256 hashes) for a contract.

```bash
w3goaudit extract selector <contract-name> --db <database.json> [-o output.json]
```

#### extract diff

Compare two databases and show added/removed/changed contracts and functions.

```bash
w3goaudit extract diff --db1 <old.json> --db2 <new.json> [-o output.json]
```

**Output:**
```json
{
  "added": {"contracts": ["NewContract"]},
  "removed": {"contracts": ["OldContract"]},
  "changed": [
    {
      "contract": "ModifiedContract",
      "addedFunctions": ["newFunc"],
      "removedFunctions": ["oldFunc"]
    }
  ]
}
```

#### extract source

Extract raw Solidity source lines for a named function. Useful for copying into finding reports.

```bash
w3goaudit extract source <function-name> --db <database.json> [--contract <name>] [-o output.json]
```

**Example:**
```bash
w3goaudit extract source withdraw --db database.json --contract DeFiVault
```

**Output:**
```json
{
  "contract": "DeFiVault",
  "function": "withdraw",
  "file": "/path/to/DeFiVault.sol",
  "startLine": 142,
  "endLine": 165,
  "sourceCode": "function withdraw(uint256 amount) external whenNotPaused {\n  ..."
}
```

#### extract context

Extract a complete context package for a function: source + call edges (both directions) + state variables + contract inheritance. Suitable for feeding into analysis or report writing.

```bash
w3goaudit extract context <function-name> --db <database.json> [--contract <name>] [-o output.json]
```

**Example:**
```bash
w3goaudit extract context withdraw --db database.json -o ctx.json
```

**Output fields:** `function` (source + metadata), `contract` (kind + inheritance), `callees`, `callers`, `stateVars`

#### extract bundle ⭐ LLM-Ready One-Document Context

Single self-contained document for **feeding to an AI agent / LLM as
conversation context**. Combines `source` + `callgraph` (both directions)
+ `statevar` + `inheritance` + `selector` for one function in one output.

```bash
w3goaudit extract bundle <function-name> --db <database.json> \
  [--contract <name>] [--format=md|json] [-o output.md]
```

Defaults to markdown — that's the LLM-native form. JSON via
`--format=json` (or `-o file.json`) keeps the same fields under a stable
`schemaVersion` for scripting.

**Sections in the markdown output (in order):**

1. Contract identity (name, kind, source file, MRO summary)
2. Function signature (selector, visibility, mutability, modifiers, lines)
3. Source code (fenced ` ```solidity ` block)
4. Callees (functions this function reaches)
5. Callers (functions that reach this function)
6. State variables in storage order (incl. inherited)
7. Full C3 inheritance chain
8. Contract's full selector table (collapsed `<details>` block)

**Examples:**

```bash
# Paste straight into Claude / GPT
w3goaudit extract bundle withdraw --db database.json --contract DeFiVault -o bundle.md

# As JSON for SDK / pipeline consumers
w3goaudit extract bundle transfer --db database.json --format=json -o bundle.json
```

#### extract workflow ⭐ Report-Ready Source Bundle

Extract **full transitive source** for an entry function — the function itself plus all internal/inherited functions it calls, recursively. Produces a self-contained code bundle for writing finding reports without manually chasing helper functions.

```bash
w3goaudit extract workflow <entry-function-name> --db <database.json> \
  [--contract <name>] [--depth <n>] [-o output.json]
```

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--contract` | — | Restrict search to a specific contract |
| `--depth` | `10` | Maximum call depth to recurse |

**Example:**
```bash
# Get complete workflow source for the withdraw function
w3goaudit extract workflow withdraw --db database.json --contract DeFiVault -o workflow.json

# The combinedSource field is copy-paste ready for reports:
cat workflow.json | jq -r .combinedSource
```

**Output:**
```json
{
  "entryFunction": "withdraw",
  "entryContract": "DeFiVault",
  "totalFunctions": 4,
  "functions": [
    {"contract": "DeFiVault", "function": "withdraw", "callDepth": 0, "sourceCode": "..."},
    {"contract": "DeFiVault", "function": "_processWithdraw", "callDepth": 1, "sourceCode": "..."},
    {"contract": "ReentrancyGuard", "function": "_nonReentrantBefore", "callDepth": 2, "sourceCode": "..."}
  ],
  "combinedSource": "// ─── DeFiVault.withdraw (depth 0, ...) ───\nfunction withdraw...\n"
}
```

---

### Completion Command

**Generate shell completion scripts.**

```bash
w3goaudit completion [bash|zsh|fish|powershell]
```

#### Setup

**Bash:**
```bash
source <(w3goaudit completion bash)
# Or add to .bashrc:
echo 'source <(w3goaudit completion bash)' >> ~/.bashrc
```

**Zsh:**
```bash
w3goaudit completion zsh > "${fpath[1]}/_w3goaudit"
```

**Fish:**
```bash
w3goaudit completion fish | source
```

---

### Version and Help

```bash
w3goaudit version
w3goaudit --help
w3goaudit build --help
w3goaudit extract --help
w3goaudit extract entry --help
w3goaudit extract workflow --help
```

---

## SDK Usage

Use W3GoAudit as a Go library in your projects.

### Installation

```bash
go get github.com/th13vn/w3goaudit
```

### Basic Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/th13vn/w3goaudit/pkg/builder"
    "github.com/th13vn/w3goaudit/pkg/engine"
    "github.com/th13vn/w3goaudit/pkg/reader"
)

func main() {
    r := reader.New()
    sources, err := r.Read("./contracts/")
    if err != nil { log.Fatal(err) }

    b := builder.New()
    db, err := b.Build(sources)
    if err != nil { log.Fatal(err) }

    e := engine.New(db)
    tmpl, err := engine.LoadTemplate("./template.yaml")
    if err != nil { log.Fatal(err) }

    findings := e.Execute(tmpl)
    fmt.Printf("Found %d issues\n", len(findings))
}
```

### API Reference

See [SDK Documentation](./sdk.md) for full API reference.

---

## Output Formats

All file output formats **always split** into an overview file and a findings file, so reviewers can diff them independently across runs. SARIF is the one exception — the SARIF schema mandates a single document per run.

### Console (Default)

Human-readable, severity-grouped, with a one-line summary header at the top:

```
128 findings: 3 CRITICAL, 33 HIGH, 92 LOW · scanned 164 contracts in 131ms
```

ANSI color is auto-disabled when stdout isn't a TTY (so piped output stays clean). `--no-color` and the `NO_COLOR` env var also disable color.

### JSON (`--json`) — Split, Versioned

Both files carry `schemaVersion: "1.0.0"`. Bumped on any breaking change to the shape; consumers should refuse to parse on a major-version mismatch.

| File | Content |
|---|---|
| `<stem>.overview.json` | `{ schemaVersion, tool, generatedAt, stats, overview }` |
| `<stem>.findings.json` | `{ schemaVersion, tool, generatedAt, counts, findings[] }` |

Each finding includes optional `cwe[]`, `owasp[]`, `references[]`, `fix`, and `recommendation`.

When no `-o` is given, a single combined document is written to stdout.

### Markdown (`--md`) — Split

| File | Content |
|---|---|
| `<stem>.overview.md` | Project summary, stats, Mermaid call graphs, inheritance diagrams, entry point tables |
| `<stem>.findings.md` | Severity-sorted findings with CWE links to MITRE, OWASP refs, recommendation, suggested fix, and references |

### HTML (`--html`) — Split, Accessible

| File | Content |
|---|---|
| `<stem>.overview.html` | Interactive report with vis.js call graphs, full-screen mode, PDF export |
| `<stem>.findings.html` | Findings table with severity badges, collapsible code snippets, CWE/OWASP links |

A11y: `lang="en"`, semantic `<main>`/`<section>`/`<article>`, ARIA labels on severity badges and locations, focus rings for keyboard nav, skip-to-findings link.

### SARIF (`--sarif`) — CI Integration

Additive: combine with any other format. Always written to `<stem>.sarif` (single file — schema requirement).

- SARIF 2.1.0
- Severity → SARIF level: `CRITICAL`/`HIGH` → `error`, `MEDIUM` → `warning`, `LOW`/`INFO` → `note`
- `properties.security-severity` carries a CVSS-style 0–10 score (consumed by GitHub Code Scanning)
- `properties.cwe` carries `CWE-N` strings; `tags[]` carries `external/cwe/cwe-N` for filtering
- One rule entry per unique TemplateID; one result entry per finding

---

## Configuration

### Project Detection

W3GoAudit automatically detects:
- **Foundry:** `foundry.toml`
- **Hardhat:** `hardhat.config.js` or `.ts`
- **Truffle:** `truffle-config.js`

### Excluded Directories

Automatically skipped: `node_modules/`, `out/`, `artifacts/`, `cache/`, `test/`, `lib/`, `mocks/`, `broadcast/`

### Template Locations

Templates can be single files (`--template ./reentrancy.yaml`) or directories (`--template ./templates/`).

---

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `No Solidity files found` | Check path, ensure `.sol` files aren't in excluded dirs |
| `Template not found` | Use absolute path or relative from current directory |
| `Parse errors` | Ensure valid Solidity syntax |
| `No findings` | Use `--verbose` to verify templates loaded and matched |
| `Permission denied` | Check file permissions |
| `Out of memory` | Scan subdirectories separately, use `build` to cache |
| `extract workflow` returns 1 function | Call graph not built — ensure source is accessible, not just a cached DB without disk fallback |

### Verbose Debugging

```bash
w3goaudit ./contracts/ --verbose          # Verbose to stdout
w3goaudit ./contracts/ --verbose=debug.log  # Verbose to file
```
