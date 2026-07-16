# W3GoAudit Usage Guide

Complete guide for using W3GoAudit as a CLI tool and Go SDK.

---

## Table of Contents

- [Installation](#installation)
- [Competitive Benchmark](#competitive-benchmark)
- [CLI Usage](#cli-usage)
  - [Default Scan (No Subcommand)](#default-scan)
  - [Result Folder Layout](#result-folder-layout)
  - [Build Command](#build-command)
  - [Extract Commands](#extract-commands)
  - [Completion Command](#completion-command)
  - [Version and Help](#version-and-help)
- [SDK Usage](#sdk-usage)
- [Result Folder & Artifacts](#result-folder--artifacts)
- [Configuration](#configuration)
- [Templates & Updates](#templates--updates)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- The exact Go version declared by `go.mod` (currently **Go 1.26.5**; also
  required for `--update`). This is a security-driven toolchain floor: the
  standard-library advisory fixes required by govulncheck need Go >=1.25.12.
- **Git** only if building from a clone

### Install via Go (recommended)

```bash
# Install directly from the module
go install github.com/th13vn/w3goaudit/cmd/w3goaudit@latest

# Verify installation (ensure $GOPATH/bin is on your PATH)
w3goaudit version
```

On first run, w3goaudit creates `~/.w3goaudit/` (config + template home) and
attempts to download the published template pack — see
[Templates & Updates](#templates--updates). It falls back to the embedded
official pack when offline, so it always works out of the box.

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

For source contributors, use the Go version from `go.mod` and run formatting,
`go mod tidy -diff`, vet, staticcheck v0.6.1/gocyclo v0.6.0, Markdown link
checks, normal/race/shuffled tests, host and Linux ARM64 builds, govulncheck
v1.1.4, an official-template scan with manifest/JSON/SARIF/offline-HTML
validation, and the Docker Compose competitive benchmark (precision >= 0.65,
recall >= 0.95, zero failed cases) locally or in user-owned external
automation.

### Self-Update

```bash
# Re-runs `go install …@latest` to upgrade w3goaudit in place
w3goaudit --update      # or -u
```

`--update` uses your local Go toolchain (no platform binaries are shipped). If
`go` is not on your PATH it reports a clear message instead of failing opaquely.

---

## Competitive Benchmark

Docker Compose is the only supported benchmark host entry point. The image
contains the pinned compared scanners, and its Dockerfile derives and verifies
the Go version directly from the repository's `go.mod`.

```bash
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

The host owns only `benchmarks/results/<RUN_NAME>/`; it does not run the Python
benchmark runner directly or install scanner toolchains. The image verifies
the reviewed generated-lock hash for the pinned 4naly3er commit. See
[`benchmarks/README.md`](../benchmarks/README.md) for suites and tool selection.

---

## CLI Usage

### Default Scan

**Scan Solidity contracts and write a result folder.**

When no subcommand is given, w3goaudit runs the default scan. It is the scan —
there is no `scan` subcommand. The terminal shows staged progress and a summary;
the full results are written to a **result folder** (see
[Result Folder Layout](#result-folder-layout)):

1. **Progress** — `▶ Reading sources`, `▶ Building database`, `▶ Scanning`, `▶ Writing report`
2. **Summary header** — severity counts, elapsed time, contract count
3. **Findings** — grouped by severity. The console shows **titles only** (one
   line per finding) to stay within terminal width; full per-finding detail
   (location, reachability trace, related matched sites, message,
   recommendation) is written to the result folder (`findings.md`,
   `data/findings.json`). Re-run with
   `--verbose` to tee the full detail to the terminal as well.
4. **⚠ Unresolved references** — bases/imports the builder could not resolve (when any)
5. **Result location** — where the folder landed

#### Basic Syntax

```bash
w3goaudit <path> [flags]
w3goaudit --db <data/database.json> [flags]
```

#### Flags

Every flag has a long and short form.

| Flag                         | Short | Type   | Description                                                                                                                                                      |
| ---------------------------- | ----- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--output`                   | `-o`  | string | Result folder path. Default: a folder named after the scanned project dir (or `.sol` file stem); `-audit` is appended if that would collide with the scanned dir |
| `--template`                 | `-t`  | string | Template file or directory. Precedence: `--template` > `~/.w3goaudit/templates/` (when populated) > embedded official pack                                       |
| `--db`                       | `-d`  | string | Load a pre-built database JSON (e.g. `data/database.json`) instead of parsing source                                                                           |
| `--verbose`                  | `-v`  | bool   | Show detailed progress on the terminal. Full detail is **always** written to `run.log` regardless of this flag                                                   |
| `--severity`                 | `-s`  | string | Report **exactly** these severities, comma-separated (e.g. `high,critical`)                                                                                      |
| `--min-severity`             | `-m`  | string | Report findings at or above this threshold (`critical`/`high`/`medium`/`low`/`info`)                                                                             |
| `--include`                  | `-i`  | string | Comma-separated template-ID glob(s); only matching findings are reported                                                                                         |
| `--exclude`                  | `-e`  | string | Comma-separated template-ID glob(s); matching findings are suppressed                                                                                            |
| `--list-templates`           | `-l`  | bool   | List the templates that would run (id, severity, confidence, title) and exit — **no path needed**                                                                |
| `--html`                     | `-H`  | bool   | Also emit `overview.html` + `findings.html` into the result folder                                                                                               |
| `--stdout`                   | `-q`  | bool   | Print the summary to the terminal only; write **no** files                                                                                                       |
| `--no-color`                 |       | bool   | Disable ANSI color in console output; `NO_COLOR` env always wins                                                                                                 |
| `--ignore-invalid-templates` |       | bool   | Skip invalid templates in a directory instead of failing the scan                                                                                                |
| `--strict-imports`           |       | bool   | Fail when any Solidity import is unresolved; applies identically to source builds and persisted `--db` diagnostics                                               |
| `--update-templates`         | `-T`  | bool   | Refresh `~/.w3goaudit/templates` from the latest published release and exit                                                                                      |
| `--update`                   | `-u`  | bool   | Update w3goaudit itself via `go install …@latest` and exit                                                                                                       |

> `--severity` (exact set) and `--min-severity` (threshold) are **mutually
> exclusive** — setting both is an error.

**Behavior notes:**

- **Markdown is the human format and JSON lives in `data/`** — there are no
  `--json`/`--md`/`--format` flags. SARIF (`results.sarif`) and the verbose
  `run.log` are always written.
- The result folder is **overwritten in place** on a re-scan; the `contracts/`
  tree is regenerated wholesale, so no stale per-contract folders survive.
- `--template README.md` is rejected before YAML parsing — only `.yaml` /
  `.yml` files or directories are accepted.
- Template directories fail closed by default. A malformed template, missing
  `meta.id`, missing `meta.severity`, or a directory with zero valid templates
  returns an error. Use `--ignore-invalid-templates` only for mixed/ad-hoc
  directories where skipping bad files is intentional.
- Import resolution is tolerant by default, but every unresolved import is
  persisted as a database diagnostic and warned on stderr. `--strict-imports`
  converts that same diagnostic into an error for both source scans and
  `--db` cache scans, so cache reuse cannot silently weaken the policy.
- `NO_COLOR` (https://no-color.org) is honored everywhere — the summary header,
  per-section emoji, and severity icons all suppress.
- Bug location is hardcoded to the best provenance: the dangerous-node
  `file:line:col` is the primary anchor, with the `entry ⇒ … ⇒ sink` chain and a
  fix-here pointer when the sink is reached through internal calls.

> **Removed in v0.3:** `--format`, `--json`, `--md`, `--html`-as-format,
> `--fail-on`, `--location-source`, and `--log`. `run.log` replaces `--log`;
> format flags are gone because the folder always carries Markdown + SARIF + JSON.

#### Examples

**Scan a directory → `./contracts/` result folder (default name):**
```bash
w3goaudit ./contracts/
```

**Scan one file into a named folder:**
```bash
w3goaudit Token.sol -o audit/
```

**Use a custom template directory:**
```bash
w3goaudit ./contracts/ -t ./my-templates/
```

**Only high + critical findings (exact set):**
```bash
w3goaudit ./contracts/ -s high,critical
```

**Threshold instead of exact set:**
```bash
w3goaudit ./contracts/ -m medium -e 'HIGH-WEAK-PRNG'
```

**Also emit the HTML mirror:**
```bash
w3goaudit ./contracts/ -H
```

**Print summary only, write nothing:**
```bash
w3goaudit ./contracts/ -q
```

**Re-scan a pre-built database (faster, no rebuild):**
```bash
# Build once
w3goaudit build ./contracts/ -o db.json

# …or reuse the DB (data/database.json) from a previous scan
w3goaudit -d ./contracts/data/database.json
```

**Fail closed on unresolved imports (source or cache):**
```bash
w3goaudit ./contracts/ --strict-imports
w3goaudit -d ./contracts/data/database.json --strict-imports
```

**List the active template set (no path required):**
```bash
w3goaudit -l
```

**Verbose terminal output (full detail is always in run.log):**
```bash
w3goaudit ./contracts/ -v
```

#### Console Output Example

```
▶ Reading sources: ./contracts/
▶ Building database: 5 files, 8 contracts, 45 functions
▶ Scanning: 25 templates (~/.w3goaudit/templates)
▶ Writing report: ./contracts-audit

2 findings: 2 HIGH · scanned 3 contracts in 131ms

── Findings ────────────────────────────────────────────────────

  🟠 HIGH (2 findings)
  ────────────────────────────────────────────────────────
  1. Potential Reentrancy
  2. Unchecked ERC20 transfer return value

  ════════════════════════════════════════════════════════
  Scan Complete. Total Issues: 2
  (full detail in the result folder; re-run with --verbose for console detail)

📂 Results written to: ./contracts-audit
   README.md · summary.md · overview.md · findings.md · results.sarif · run.log
   data/ (manifest.json, findings.json, overview.json, diagnostics.json, database.json, nav.json, explorer.json)
   contracts/<path>/<Contract>/ (README.md, state-changes.md, workflows/)
```

---

### Result Folder Layout

Every scan (unless `--stdout/-q`) writes an opinionated result folder, optimized
to be fed to a human or an AI auditor:

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
│   ├── nav.json           # extension navigation index (symbols, callers, interfaceImpl)
│   └── explorer.json      # extension explorer model (per-contract constants/storage/entries/getters)
└── contracts/             # one sub-tree per main contract, mirroring source paths
    └── <relative-source-path-without-ext>/
        └── <ContractName>/
            ├── README.md          # per-contract landing: findings + architecture detail
            ├── state-changes.md   # state var → Written By (fns) → Reachable From (entries)
            └── workflows/
                ├── <entryFn>.md             # one file per entry function
                └── <entryFn>__<selector>.md # overloads disambiguated by 4-byte selector
```

**Naming & dedup:**

- The default folder name is the scanned project directory name (or the `.sol`
  file stem). `-o/--output` overrides the full path. If the default would equal
  the scanned directory, `-audit` is appended so source is never overwritten.
  `config.yml: output.base_dir` redirects where default-named folders are created.
- Per-contract folders live under `contracts/` and mirror the source layout:
  `contracts/<relative-source-path-without-ext>/<ContractName>/`. Because the
  path already encodes the source file, contracts that share a name in different
  files never collide — no `Name__<filestem>` suffix is needed. Contract names
  are sanitized to filesystem-safe components.
- The `contracts/` tree is regenerated wholesale on every run, so a re-scan is
  idempotent (no stale folders from deleted contracts).
- `data/database.json` is the **only** copy of the database; reuse it with
  `--db data/database.json`.
- `data/diagnostics.json` is always present. It distinguishes analyzer coverage
  loss (unresolved imports/bases, parser recovery/skips, invalid locations,
  unresolved identity) from security findings and is identical for source and
  equivalent `--db` scans.
- `data/manifest.json` is the machine index. `projectRoot` is the detected
  project root; `scanTarget` is the selected file/directory represented by the
  database; `target` is a compatibility alias of `scanTarget`. It exposes
  `analysisComplete`, diagnostic counts, separate declaration-category counts,
  and only those optional HTML paths that were actually emitted.

**Per-entry-function workflow file**
(`contracts/<path>/<Contract>/workflows/<entryFn>.md`)
is a self-contained context block for one entry point:

- **Signature** — selector, 4-byte hash, `payable`, pragma version of the file
- **Auth / Access Control** — modifiers, inline `msg.sender` checks, an explicit
  **⚠ Unprotected** marker when neither is present, and a **⚠ tx.origin** warning
- **Guards / Checks** — every `require` / `assert` / `revert` condition
- **Branch Conditions** — `if` conditions that gate logic
- **State Effects** — state variables written transitively (directly or via
  internal calls), cross-linked to `state-changes.md`
- **Call Workflow** — a Mermaid call-graph diagram (internal → external/library/ETH calls)

**State-change matrix** (`<MainContract>/state-changes.md`) lists, per state
variable: its type, where it is defined, the functions that **write** it, and —
walking the reverse call graph — the **entry points** that reach a writer.

---

### Build Command

**Build contract database without running security scans.**

```bash
w3goaudit build <path> -o <output.json> [flags]
```

#### Flags

| Flag                  | Type   | Required | Description                                  |
| --------------------- | ------ | -------- | -------------------------------------------- |
| `-o, --output <file>` | string | **Yes**  | Output JSON file path                        |
| `--db <file>`         | string | No       | Load existing database instead of rebuilding |
| `--verbose[=<file>]`  | string | No       | Enable verbose logging; omit the value for stdout or provide a log-file path |
| `--strict-imports`    | bool   | No       | Fail before writing JSON when an import diagnostic is unresolved |

#### Examples

```bash
w3goaudit build ./contracts/ -o database.json
w3goaudit build ./contracts/ -o database.json --verbose
w3goaudit build ./contracts/ -o database.json --verbose=/tmp/build.log
w3goaudit build ./contracts/ -o database.json --strict-imports
```

The resulting `database.json` can later be re-scanned with
`w3goaudit --db database.json`.

---

### Extract Commands

**Extract specific information from a contract database.**

All extract commands accept `-o <file>` for file output and support two
output formats:

| Flag / inference                 | Result                                                               |
| -------------------------------- | -------------------------------------------------------------------- |
| `--format=md` *(default)*        | Markdown rendering optimized for AI-agent / LLM context windows      |
| `--format=json`                  | Machine-readable JSON, every output carries `schemaVersion: "1.0.0"` |
| `-o report.md` (no `--format`)   | Inferred as markdown from extension                                  |
| `-o report.json` (no `--format`) | Inferred as JSON from extension                                      |

The markdown form uses headers, tables, and fenced code blocks — token-
efficient for LLMs and readable for humans pasting into PRs. The
`extract bundle` subcommand produces a single LLM-ready document combining
a function's source, callers, callees, state variables, inheritance, and
the contract's selector table; like every other extract subcommand it
defaults to markdown.

Every extract subcommand **except `diff`** accepts an optional trailing
source `[path]` argument to build the database on the fly (same as the root
scan and `extract main`), so `--db` is not strictly required — pass either a
pre-built `--db <database.json>` or a source path.

The canonical subcommand order is widest→narrowest scope: `main`, `entry`,
`inheritance`, `statevar`, `selector`, `involve`, `workflow`, `bundle`,
`context`, `source`, `diff`.

**Identity and ambiguity:** contract arguments accept an exact
`file#Contract` ID or a unique case-insensitive name. Function arguments accept
an exact `file#Contract.selector(types)` ID, `Contract.selector`, a full
selector, a 4-byte signature, or a unique bare name. `--contract` accepts an
exact contract ID or a unique name. Ambiguous input fails with sorted candidate
IDs instead of selecting by map/declaration order. Inherited state, inheritance
kind, context, workflow, and bundle data walk the exact `LinearizedBaseIDs` C3
chain.

#### extract main

Extract main (deployable) contracts. Accepts either a source path (builds
the database on the fly) **or** a pre-built `--db`.

```bash
w3goaudit extract main <path> [-o output.md]
w3goaudit extract main --db <database.json> [-o output.json]
```

#### extract entry

Extract entry point functions for a contract.

```bash
w3goaudit extract entry <contract-name> [path] [-o output.md]
w3goaudit extract entry <contract-name> --db <database.json> [-o output.json]
```

**Examples:**
```bash
# Build the database on the fly from a source path
w3goaudit extract entry MyToken ./contracts/

# Or reuse a pre-built database
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

#### extract inheritance

Show the C3 linearization chain (method resolution order, derived → base)
for a **main contract**. The argument MUST be a deployable contract;
interfaces, libraries, and abstract-only contracts are rejected with the
list of valid main contracts (so you can correct the typo immediately).

```bash
w3goaudit extract inheritance <main-contract-name> [path] [-o output.md]
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
w3goaudit extract statevar <contract-name> [path] [-o output.md]
w3goaudit extract statevar <contract-name> --db <database.json> [-o output.json]
```

#### extract selector

List all function selectors (4-byte keccak256 hashes) for a contract.

```bash
w3goaudit extract selector <contract-name> [path] [-o output.md]
w3goaudit extract selector <contract-name> --db <database.json> [-o output.json]
```

#### extract involve

For each entry-point function in the project, walk the call graph from
that entry. If the named function is reachable, emit a Mermaid flowchart
of the path. Replaces the older `extract callgraph` — auditors care about
"which user-facing functions are affected if I audit this helper", not
about a flat edge list.

```bash
w3goaudit extract involve <function-name> [path] [-o output.md]
w3goaudit extract involve <function-name> --db <database.json> [-o output.md]
```

**Examples:**

```bash
# Which entry points reach _settle? (build the DB on the fly)
w3goaudit extract involve _settle ./contracts/

# Or against a pre-built database, JSON form for scripting / SDK consumption
w3goaudit extract involve _checkOwner --db database.json --format=json
```

The markdown output is one `## entrypoint Contract.func` section per
reachable entry, each with its own ```mermaid block. The entry node is
styled orange; the target function is red. Edges carry the call type
(internal / inherited / library / super / etc.) as labels.

#### extract workflow ⭐ Report-Ready Source Bundle

Extract **full transitive source** for an entry function — the function itself plus all internal/inherited functions it calls, recursively. Produces a self-contained code bundle for writing finding reports without manually chasing helper functions.

```bash
w3goaudit extract workflow <entry-function-name> [path] \
  [--contract <name>] [--depth <n>] [-o output.md]
w3goaudit extract workflow <entry-function-name> --db <database.json> \
  [--contract <name>] [--depth <n>] [-o output.json]
```

**Flags:**
| Flag         | Default | Description                            |
| ------------ | ------- | -------------------------------------- |
| `--contract` | —       | Restrict search to a specific contract |
| `--depth`    | `10`    | Maximum call depth to recurse          |

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

#### extract bundle ⭐ LLM-Ready One-Document Context

Single self-contained document for **feeding to an AI agent / LLM as
conversation context**. Combines `source` + `callgraph` (both directions)
+ `statevar` + `inheritance` + `selector` for one function in one output.

```bash
w3goaudit extract bundle <function-name> [path] \
  [--contract <name>] [--format=md|json] [-o output.md]
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

#### extract context

Extract a complete context package for a function: source + call edges (both directions) + state variables + contract inheritance. Suitable for feeding into analysis or report writing.

```bash
w3goaudit extract context <function-name> [path] [--contract <name>] [-o output.md]
w3goaudit extract context <function-name> --db <database.json> [--contract <name>] [-o output.json]
```

**Example:**
```bash
w3goaudit extract context withdraw --db database.json -o ctx.json
```

**Output fields:** `function` (source + metadata), `contract` (kind + inheritance), `callees`, `callers`, `stateVars`

#### extract source

Extract raw Solidity source lines for a named function. Useful for copying into finding reports.

```bash
w3goaudit extract source <function-name> [path] [--contract <name>] [-o output.md]
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

#### extract diff

Compare two databases and show added/removed/changed contracts and functions.
Unlike the other extract subcommands, `diff` does not accept a trailing source
path — it always compares two pre-built databases.

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

## Result Folder & Artifacts

A scan writes one result folder (see [Result Folder Layout](#result-folder-layout)).
`results.sarif`, `run.log`, and the `data/` JSON are always produced; the HTML
mirror is opt-in via `--html/-H`.

Finding ordering and generated content are deterministic, but real
`generatedAt` timestamps vary between runs. SDK callers that need a byte-stable
bundle can inject a fixed clock through `report.GeneratorOptions.Now` and
`report.BundleOptions.Now`; the bundle uses that one UTC instant consistently.

### Console (Terminal)

Staged progress lines, then a one-line summary header:

```
2 findings: 2 HIGH · scanned 3 contracts in 131ms
```

ANSI color is auto-disabled when stdout isn't a TTY (so piped output stays clean).
`--no-color` and the `NO_COLOR` env var also disable color. When a rule matched in
an internal helper the entrypoint reaches, each finding carries a reachability
continuation under its `Location:` line:

```
Location: …/Vault.sol:352 in _commit()
↳ via VulnerableSwappedArgsForward.depositFrom() ⇒ …_stage() ⇒ …_commit()
↳ fix-here: VulnerableSwappedArgsForward.depositFrom
```

By default the console lists **finding titles only** (one line each) so output
fits the terminal; the `Location:`/`Confidence:`/`Details:` block and the
reachability continuation shown above are printed to the terminal only under
`--verbose`. The full detail is always written to `findings.md` and
`data/findings.json` in the result folder.

### Markdown — `overview.md` + `findings.md`

| File          | Content                                                                                                                                                                                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `overview.md` | All main contracts with their pragma version, stats, Mermaid call graphs, inheritance, entry-point tables                                                                                                                                                                                                           |
| `findings.md` | Severity-sorted findings with recommendation, suggested fix, and references. Each occurrence includes a **reachability trace block** when present — file path, entry-point (fix-here), and a dotted-level list (`.`, `..`, `...`) from the entry function down to the host of the dangerous statement, with line numbers per hop. Multi-site findings also include `All matched sites` and full matched-function excerpts |

Per-main-contract folders add `state-changes.md` and one
`workflows/<entryFn>.md` per entry point (see
[Result Folder Layout](#result-folder-layout) for their structure).

### JSON — `data/`

Machine-readable mirror; each carries `schemaVersion: "2.0.0"`.

| File                   | Content                                                           |
| ---------------------- | ----------------------------------------------------------------- |
| `data/database.json` | Canonical database (reusable via `--db`); carries scan target, source snapshots, exact MRO IDs, and diagnostics |
| `data/overview.json` | `{ schemaVersion, tool, generatedAt, projectRoot, scanTarget, analysisComplete, diagnosticCounts, stats, overview }` |
| `data/findings.json` | `{ schemaVersion, tool, generatedAt, counts, findings[] }`        |
| `data/diagnostics.json` | `{ schemaVersion, generatedAt, analysisComplete, counts, diagnostics[] }`; always emitted |
| `data/nav.json` | `{ schemaVersion, symbols[], callers[], interfaceImpl[] }` — navigation index for the VSCode extension |
| `data/explorer.json` | `{ schemaVersion, contracts[] }` — per-deployable-contract constants/storage/entryFunctions/getters, for the extension's explorer tab |

See [`docs/extension-output.md`](./extension-output.md) for the full `nav.json` / `explorer.json` schema.

Each finding includes optional `references[]`, `fix`, and `recommendation`.
Findings can also carry structured context fields:

```jsonc
{
  "location": { "file": "...", "contract": "...", "function": "...", "line": 352 },
  "primaryAst": { "kind": "call.external", "name": "transferFrom", "startLine": 0 },
  "reachability": {
    "steps": [
      { "contract": "VulnerableSwappedArgsForward", "function": "depositFrom", "visibility": "external", "line": 344 },
      { "contract": "VulnerableSwappedArgsForward", "function": "_stage",      "visibility": "internal", "line": 348 },
      { "contract": "VulnerableSwappedArgsForward", "function": "_commit",     "visibility": "internal", "line": 352 }
    ]
  },
  "entryPoint": { "contract": "VulnerableSwappedArgsForward", "function": "depositFrom" },
  "related": [
    {
      "label": "payable msg.value entrypoint",
      "file": ".../Vault.sol",
      "contract": "Vault",
      "function": "depositETH",
      "line": 120,
      "kind": "decl.function",
      "name": "depositETH"
    }
  ]
}
```

`reachability.steps[0]` is the externally-callable entry; the last step hosts the
dangerous statement. `entryPoint` is the auditor-actionable fix-here pointer.
`related[]` lists every source site that contributed to a multi-condition
finding, such as each payable `msg.value` function and the inherited multicall
function in a contract-scope combination rule. Each entry's `label` is taken
from the matched `where`-level `all:` branch's `label:` field in the template
(falling back to `condition N` when the branch has none).

### HTML (`--html/-H`) — Accessible

| File            | Content                                                                  |
| --------------- | ------------------------------------------------------------------------ |
| `overview.html` | Interactive report with vis.js call graphs, full-screen mode, PDF export |
| `findings.html` | Findings table with severity badges and collapsible code snippets        |

A11y: `lang="en"`, semantic `<main>`/`<section>`/`<article>`, ARIA labels on
severity badges and locations, focus rings for keyboard nav, skip-to-findings link.

### SARIF — `results.sarif`

Always written (single file — schema requirement).

- SARIF 2.1.0, portable relative URIs + `originalUriBaseIds.srcRoot`
- Severity → SARIF level: `CRITICAL`/`HIGH` → `error`, `MEDIUM` → `warning`, `LOW`/`INFO` → `note`
- `properties.security-severity` carries a CVSS-style 0–10 score (GitHub Code Scanning)
- One rule entry per unique TemplateID; one result entry per finding
- Every run declares `columnKind: unicodeCodePoints`. `startColumn`/`endColumn`
  are one-based, half-open Unicode-code-point columns. W3GoAudit's byte offsets
  are zero-based, half-open UTF-8 bytes and are deliberately not emitted as
  SARIF `charOffset`/`charLength`.
- For findings that traversed an internal call chain, `result.relatedLocations[]`
  lists every hop from entry to host; `result.properties.entryPoint` and
  `result.properties.primaryAst` carry the fix-here pointer and matched AST node

---

## Configuration

### `~/.w3goaudit/config.yml`

On first run, w3goaudit creates `~/.w3goaudit/` and writes a default `config.yml`.
Every key is a default that any CLI flag overrides.

```yaml
templates:
  dir: ""                          # template home ("" = ~/.w3goaudit/templates)
  repo: th13vn/w3goaudit-templates # releases source for --update-templates
output:
  base_dir: ""                     # "" = current dir; else write result folders here
  html: false                      # also emit overview.html + findings.html
scan:
  min_severity: ""                 # default --min-severity threshold
  strict_imports: false            # fail when any source/cache import is unresolved
  exclude_paths:                   # reserved: paths skipped during discovery
    - node_modules
    - lib
    - out
    - "**/test/**"
    - "**/mocks/**"
  workers: 0                       # reserved: 0 = auto
report:
  repo_base: ""                    # reserved: "" = relative source links; else a repo base URL
color: auto                        # auto | never
```

The keys consumed today are `templates.dir`, `templates.repo`, `output.base_dir`,
`output.html`, `scan.min_severity`, `scan.strict_imports`, and `color`. `scan.exclude_paths`,
`scan.workers`, and `report.repo_base` are reserved for future use.

### Project Detection

W3GoAudit automatically detects:
- **Foundry:** `foundry.toml`
- **Hardhat:** `hardhat.config.js` or `.ts`
- **Truffle:** `truffle-config.js`

### Excluded Directories

Automatically skipped: `node_modules/`, `out/`, `artifacts/`, `cache/`, `test/`, `lib/`, `mocks/`, `broadcast/`

### Environment Variables

| Variable     | Effect                                                            |
| ------------ | ----------------------------------------------------------------- |
| `NO_COLOR=1` | Disable ANSI color in the console output (also via `--no-color`). |

---

## Templates & Updates

w3goaudit provisions templates nuclei-style — from the latest GitHub Release of
the templates repo, **not** via `git clone`.

### Precedence

`--template <path>` > `~/.w3goaudit/templates/` (when populated) > the embedded
official pack (always available, offline fallback).

### First-run download

On first run, if `~/.w3goaudit/templates/` is empty, w3goaudit downloads the
`zipball` of the latest release of `th13vn/w3goaudit-templates`
(https://github.com/th13vn/w3goaudit-templates — release `v1.0.0`, 25 templates),
extracts the `.yaml`/`.yml`/`.md` files into the home, and records the tag in
`templates/.version`. If the download fails (offline, repo/release unreachable),
it falls back to the embedded pack — no hard failure, just a notice.

Archive handling is resource-limited: 64 MiB compressed, 8 MiB per extracted
file, 128 MiB total decompressed, 4,096 accepted files, and 8,192 total ZIP
entries. Extraction is staged beside the destination and swapped into place;
the prior directory is restored if installation fails. GitHub source zipballs
are authenticated by TLS but do not provide a digest/signature, so the managed
pack is not independently content-authenticated.

### `--update-templates / -T`

```bash
w3goaudit --update-templates    # or -T
```

Queries the latest release tag; if newer than the local `.version` it downloads
and replaces the home, otherwise reports "already up to date". If no published
release is reachable, it prints a graceful notice (using the embedded pack) and
exits 0 — not an error.

---

## Troubleshooting

### Common Issues

| Problem                               | Solution                                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `No Solidity files found`             | Check path, ensure `.sol` files aren't in excluded dirs                                           |
| `Template not found`                  | Use absolute path or relative from current directory                                              |
| `Parse errors`                        | Ensure valid Solidity syntax                                                                      |
| `No findings`                         | Use `--verbose` to verify templates loaded and matched, or inspect `run.log` in the result folder |
| `Permission denied`                   | Check file permissions                                                                            |
| `Out of memory`                       | Scan subdirectories separately, use `build` to cache                                              |
| `extract workflow` returns 1 function | Call graph not built — ensure source is accessible, not just a cached DB without disk fallback    |

### Verbose Debugging

```bash
w3goaudit ./contracts/ --verbose   # tee detail to the terminal
# Full detail is always captured in <output>/run.log, regardless of --verbose.
```
