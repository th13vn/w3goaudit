# W3GoAudit Workflows

This document explains the internal workflows of W3GoAudit, detailing how the engine processes Solidity contracts for security analysis.

## Overview

W3GoAudit has three main workflows:

1. **Scan Workflow** - Analyze contracts with security templates
2. **Build Workflow** - Construct contract database
3. **Default Scan Workflow** - Scan + generate project reports (combined)

All workflows share a common foundation: **Reader → Builder → Database**.

---

## 1. Scan Workflow

**Command:** `w3goaudit <path> [--template <template-path>]`

**Purpose:** Scan Solidity contracts for vulnerabilities using WQL templates.
Omitting `--template` uses `~/.w3goaudit/templates/` when populated, else the
embedded official pack (see §3 for the full flag set and filtering).

### High-Level Flow

```mermaid
graph LR
    A[Input Path] --> B[Reader]
    B --> C[Source Files]
    C --> D[Builder]
    D --> E[Database]
    F[Templates] --> G[Engine]
    E --> G
    G --> H[Findings]
    H --> I[Bundle Writer]
    I --> J[Result Folder]
```

### Detailed Steps

#### Phase 1: File Reading
**Component:** [`pkg/reader`](../pkg/reader)

1. **Detect input type** (file or directory)
2. **Recursively discover** `.sol` files
3. **Skip excluded directories**: `node_modules`, `out`, `artifacts`, `test`, `lib`, etc.
4. **Read file contents** into memory
5. **Detect project root** and framework (Foundry/Hardhat/Truffle)

**Code:** [reader.go](../pkg/reader/reader.go)

#### Phase 2: Database Building
**Component:** [`pkg/builder`](../pkg/builder)

The builder constructs a comprehensive database through **7 phases**:

**Phase 1: Parse Files**
- Parse each `.sol` file using [solast-go](https://github.com/th13vn/solast-go)
- Extract contracts, interfaces, libraries
- Extract functions, state variables, structs, events
- Store pragma and import information

**Phase 2: Build ASTs & Semantic Facts**
- Convert raw AST into simplified tree structure
- Build AST for each function body
- Support for all Solidity statement types
- Infer lightweight `TypeInfo` for parameters, state variables, locals, casts,
  builtin address expressions, and member-call receivers
- Store facts in `Database.Semantics` and mirror key facts onto AST attributes
  such as `type_kind` and `receiver_type_kind`

**Phase 3: Calculate Function Selectors**
- Generate function signatures (e.g., `transfer(address,uint256)`)
- Resolve struct types to tuple format
- Calculate 4-byte keccak256 selectors

**Phase 4: Build Inheritance**
- Apply **C3 linearization** for proper method resolution order
- Calculate inheritance weights
- Resolve base contracts

**Phase 5: Build Call Graph**
- Identify internal, external, self, super, and low-level calls
- Resolve call targets using inheritance chain
- Track line numbers for all calls
- Context-aware `super` post-pass (`ResolveSuperAcrossLeaves`): bind each
  `super.f()` to the next definition in **every** instantiation leaf's MRO
  (sound union, additive + deduplicated), since Solidity resolves `super`
  against the most-derived contract being instantiated — not the contract where
  the call textually appears. Closes a reachability gap on cooperative diamonds.

**Phase 6: Calculate Entry Points**
- Identify main contracts (deployable)
- Find public/external functions
- Resolve inherited functions to their final implementation

**Phase 7: Analyze Per-Function Effects**
- Walk each function's AST and record durable `FunctionEffects`:
  - **Write facts** — state variables written (with write kind: `=`, compound
    assignment, `delete`, `.push`/`.pop`, mapping/array/struct element writes)
  - **Guard facts** — `require`/`assert`/`revert` conditions and `if`/ternary
    branch conditions
  - **Auth facts** — modifiers, inline `msg.sender` checks, `tx.origin` use,
    controlled vs unprotected
- These facts feed the per-contract state-change matrix and the per-entry
  workflow files written in Phase 5 (report generation)
- **Code:** [effects.go](../pkg/builder/effects.go)

**Code:** [builder.go](../pkg/builder/builder.go)

```mermaid
graph TD
    A[Source Files] --> B[Phase 1: Parse Files]
    B --> C[Phase 2: Build ASTs + Semantic Facts]
    C --> D[Phase 3: Calculate Selectors]
    D --> E[Phase 4: Build Inheritance]
    E --> F[Phase 5: Build Call Graph]
    F --> G[Phase 6: Calculate Entry Points]
    G --> G2[Phase 7: Per-Function Effects]
    G2 --> H[Complete Database]
```

#### Phase 3: Template Loading
**Component:** [`pkg/engine`](../pkg/engine), [`pkg/home`](../pkg/home)

1. **Resolve the template source** by precedence: `--template` (explicit path) >
   `~/.w3goaudit/templates/` (when populated) > embedded official pack. On first
   run, `pkg/home` provisions the template home from the latest release of
   `th13vn/w3goaudit-templates` (zipball download, nuclei-style), falling back to
   the embedded pack when offline.
2. **Load template file(s)** from YAML
3. **Parse template structure**: meta + query
4. **Validate template syntax**
5. **Fail closed on invalid template directories** — by default, one invalid
   template or zero valid templates aborts the scan; `--ignore-invalid-templates`
   is the explicit ad-hoc escape hatch
6. **Store in engine**

**Code:** [template.go](../pkg/engine/template.go)

#### Phase 4: Query Execution
**Component:** [`pkg/engine`](../pkg/engine)

**Execution flow:**

```mermaid
graph TD
    A[Template] --> B{Query Scope}
    B -->|all_contract| C[Iterate All Contracts]
    B -->|main_contract| D[Iterate Main Contracts]
    B -->|function| E[Iterate All Functions]
    B -->|entrypoint| F[Iterate Entry Functions]
    
    C --> G[Verify Match Rules]
    D --> G
    E --> G
    F --> G
    
    G --> H{Match?}
    H -->|Yes| I[Create Finding]
    H -->|No| J[Skip]
    I --> K[Findings List]
```

**Verification process** ([verify.go](../pkg/engine/verify.go)):

1. **Parse match rules** (`all` / `any` / `not` / `sequence` / `contains` / `inside`)
2. **Check atomic matchers**: `kind`, `name` (regex), `attr` — when the rule has a
   surface predicate AND the full branch succeeds, the engine records the
   matched AST node as the finding's `PrimaryAST` (the dangerous statement
   to report). Failed branches roll back their provisional capture.
3. **Evaluate context helpers**: `modifier`, `extends`, `regex`, `has_guard`
4. **Traverse AST** for `contains` (descendants) / `inside` (ancestors) operators
5. **Check `sequence`** for ordered patterns
6. **Perform taint analysis** for source tracking, including caller argument bindings when entrypoints invoke internal helpers — the call chain traversed becomes the finding's `Reachability` (entry → … → host of `PrimaryAST`)

**Advanced features:**
- **Recursive internal call tracing**: Engine follows entrypoint → helper call chains and maps caller argument taint onto callee parameters; the chain itself is preserved on the finding
- **Inheritance-aware matching**: Checks base contracts and modifiers
- **Contract-scope AST matching**: Contract scopes run `match:` on a synthetic
  `decl.contract` root containing cloned function ASTs from the linearized
  inheritance chain, so one `match.all` can prove multiple local/inherited
  same-contract conditions
- **Argument position matching**: Validates specific function arguments
- **Related matched sites**: Multi-condition contract findings can carry
  `Finding.Related`, which reports every contributing source site and not only
  the primary location
- **Bug location**: hardcoded to the best provenance — the dangerous-node
  `file:line:col` is the primary anchor, with the `Reachability` chain and
  `EntryPoint` fix-here pointer populated whenever the sink is reached through
  internal calls (no flag; the `--location-source` switch was removed in v0.3)

#### Phase 5: Report Generation (Result Folder)
**Component:** [`pkg/report`](../pkg/report) — `WriteBundle`

The findings, the database, and the summary are written to a single
**result folder** (`report.WriteBundle`, [bundle.go](../pkg/report/bundle.go)).
There is no format flag: Markdown + SARIF + a JSON data/ are always produced; an
HTML mirror is opt-in via `--html`.

```mermaid
graph TD
    A[Findings + Database + Summary] --> B[WriteBundle]
    B --> C[overview.md / findings.md]
    B --> D[results.sarif]
    B --> E[data/ database.json, findings.json, overview.json]
    B --> F["per-contract: state-changes.md + workflows/&lt;entryFn&gt;.md"]
    B -->|--html| G[overview.html / findings.html]
    H[CLI] --> I[run.log: full verbose detail, always]
```

**Top-level artifacts:**
- `overview.md` — all main contracts with their pragma version, stats, call graphs
- `findings.md` — severity-sorted findings with recommendation, fix,
  references, per-occurrence reachability trace blocks, and `All matched sites`
  blocks for multi-site findings
- `results.sarif` — SARIF 2.1.0 (always)
- `data/{database.json,findings.json,overview.json}` — machine-readable mirror;
  the canonical database lives only here and is reusable via `--db`
- `run.log` — full verbose detail, always written by the CLI regardless of `--verbose`

**Per-main-contract folders** (built using the Phase-7 effects):
- `state-changes.md` — each state variable, the functions that write it, and the
  entry points that reach a writer (reverse call-graph walk;
  [state_matrix.go](../pkg/report/state_matrix.go))
- `workflows/<entryFn>.md` — one self-contained context block per entry function:
  signature (selector, 4-byte, payable, version), auth/access control (modifiers,
  `msg.sender` checks, ⚠ Unprotected, ⚠ tx.origin), guards/checks, branch
  conditions, transitive state effects, and a Mermaid call workflow

**Output includes (across the artifacts):**
- Severity grouping (CRITICAL → HIGH → MEDIUM → LOW → INFO)
- Location information (file, contract, function, line)
- Vulnerability description, recommendation, code snippets, confidence
- **Reachability trace** (when populated): full call chain from entry to host:
  - JSON — `reachability.steps[]`, `entryPoint`, `primaryAst`, `related[]`
  - SARIF — `result.relatedLocations[]` + `result.properties.entryPoint` / `…primaryAst`
  - Markdown — per-occurrence trace block with dotted-level indentation and line numbers per hop; related matched sites include full function excerpts
  - HTML — `<div class="w3a-trace">` with depth-scaled `margin-left`
  - Console — `↳ via Entry.func() ⇒ … ⇒ host()` and `↳ fix-here: …` continuation lines

**Code:** [report/](../pkg/report)

---

## 2. Build Workflow

**Command:** `w3goaudit build <path> -o <output.json>`

**Purpose:** Build contract database without running security scans.

### Flow Diagram

```mermaid
graph LR
    A[Input Path] --> B[Reader]
    B --> C[Source Files]
    C --> D[Builder: 7 Phases]
    D --> E[Database]
    E --> F[JSON Export]
```

### Use Cases

1. **Export database** for external analysis tools
2. **Debug database structure** during development
3. **Cache database** for large projects
4. **Inspect** contracts, functions, and call graphs

### Database Structure

The output JSON contains:

```javascript
{
  "contracts": {
    "path#ContractName": {
      "name": "ContractName",
      "kind": "contract|interface|library",
      "sourceFile": "/absolute/path",
      "functions": [...],
      "stateVars": [...],
      "structs": [...],
      "events": [...],
      "bases": [...],
      "linearizedBases": [...],
      "inheritanceWeight": 0
    }
  },
  "mainContracts": {
    "path#MainContract": ["funcID1", "funcID2", ...]
  },
  "sourceFiles": [...],
  "projectRoot": "/path/to/project"
}
```

**Key fields:**
- `linearizedBases` - C3 linearization order
- `mainContracts` - Deployable contracts with entry function IDs
- `functions[].Calls` - Call graph edges
- `functions[].Selector` - 4-byte function selector

---

## 3. Default Scan Workflow

**Command:** `w3goaudit <path>` (optionally `-t <dir>`, `-o <folder>`, `-H`, etc.)

**Purpose:** The scan is the root command (there is no `scan` subcommand). It
builds the database, runs the templates, prints a terminal summary, and writes
the result folder (overview, findings, SARIF, run.log, data/, per-contract
workflows + state-changes).

**Template source:** precedence is `--template` (explicit path) >
`~/.w3goaudit/templates/` (when populated) > the embedded official pack, so a
bare `w3goaudit <path>` produces findings with no repository checkout.

**Filtering & inventory:**

- `--severity/-s high,critical` — report **exactly** those severities.
- `--min-severity/-m high` — report findings at or above the threshold.
  (`--severity` and `--min-severity` are mutually exclusive.)
- `--include/-i` / `--exclude/-e <id-globs>` — narrow the reported findings by template ID.
- `--list-templates/-l` — print the rule inventory that would run, then exit (no path needed).
- `--html/-H` — also emit `overview.html` + `findings.html`; `--stdout/-q` prints the summary only and writes no files.

The terminal shows staged progress (`▶ Reading sources`, `▶ Building database`,
`▶ Scanning`, `▶ Writing report`), a summary header, findings, an unresolved-
references section, and the result-folder location. Full verbose detail is always
captured in `<output>/run.log`.

> **Removed in v0.3:** `--fail-on` (CI gating dropped — this is an audit tool, not
> a gate), `--format`/`--json`/`--md`/`--html`-as-format (the folder always
> carries Markdown + SARIF + JSON), `--location-source`, and `--log`.

### Flow Diagram

```mermaid
graph LR
    A[Input Path] --> B[Reader]
    B --> C[Source Files]
    C --> D[Builder]
    D --> E[Database]
    E --> F[Engine + Report]
    F --> G[Console Summary]
    F --> H[Result Folder]
    H --> I[overview.md / findings.md / results.sarif / run.log]
    H --> J[data/ JSON]
    H --> K[per-contract workflows + state-changes]
    H -->|--html| L[HTML mirror]
```

### Report Contents

**Generated report includes:**

1. **Project Statistics**
   - Total files, contracts, interfaces, libraries
   - Functions count (total and entry functions)
   - Main contracts list

2. **Contract Analysis**
   - Contract hierarchy and inheritance
   - Function visibility breakdown
   - State mutability distribution

3. **Main Contracts Details**
   - Entry points per contract
   - Inheritance tree
   - Function modifiers

4. **Call Graph Visualization**
   - Mermaid diagrams for each main contract
   - Internal call flows
   - External call identification

5. **Security Surface Analysis**
   - Public/external functions
   - Payable functions
   - Functions with external calls

**Code:** [report/summary.go](../pkg/report/summary.go), [report/generator.go](../pkg/report/generator.go)

---

## Internal Workflows

### AST Traversal and Matching

**Used by:** Engine verification

```mermaid
graph TD
    A[AST Root] --> B{Matcher Type}
    B -->|contains| C[Walk Descendants]
    B -->|inside| D[Walk Ancestors]
    B -->|kind| E[Check Node Kind]
    B -->|name regex| F[Pattern Match Name]
    B -->|attr| G[Check Attributes]
    
    C --> H[Find Matching Nodes]
    D --> H
    E --> H
    F --> H
    G --> H
    
    H --> I{Found?}
    I -->|Yes| J[Return True]
    I -->|No| K[Return False]
```

**Supported AST node kinds** (dot-notation; a prefix like `call` matches any
`call.*`):
- Statements: `stmt.assign`, `stmt.if`, `stmt.loop`, `stmt.try_catch`,
  `stmt.emit`, `stmt.return`, `stmt.block`, `stmt.unchecked`
- Calls: `call.internal`, `call.external`, `call.create`,
  `call.lowlevel{,.call,.delegatecall,.staticcall}`,
  `call.builtin{,.transfer,.send,.selfdestruct}`
- Expressions: `expr.identifier`, `expr.literal`, `expr.binary_op`,
  `expr.unary_op`, `expr.member_access`, `expr.index_access`,
  `expr.conditional`, `expr.tuple`

### WQL Query Verification

**Process for evaluating a match rule:**

1. **Parse operator** (`all` / `any` / `not` / `sequence` / `contains` / `inside` / atomic)
2. **For `all`**: All sub-rules must match (AND)
3. **For `any`**: At least one sub-rule must match (OR)
4. **For `not`**: Sub-rule must NOT match
5. **For `sequence`**: Sub-rules must match in order on children
6. **For `contains`**: Search descendants for match
7. **For `inside`**: Search ancestors for match
8. **For atomic**: Check `kind` / `name` regex / `attr` directly

### Recursive Internal Call Tracing (Interprocedural)

**Purpose:** Reach a dangerous statement that lives in an internal helper the
entrypoint calls, and record the call chain so the finding is auditor-actionable

When a rule matches inside an internal helper, the engine walks the call graph
from each entrypoint into its (transitive) internal callees, maps caller
argument taint onto the callee parameters, and — on a match — records the
traversed chain as the finding's `Reachability` (entry → … → host of
`PrimaryAST`), with `EntryPoint` set to the externally-callable fix-here
function. A visited set prevents infinite recursion on cyclic call graphs.

```mermaid
graph TD
    A[Entry Function] --> B[Walk Internal Callees]
    B --> C{Already Visited?}
    C -->|Yes| D[Skip: Prevent Recursion]
    C -->|No| E[Mark Visited]
    E --> F[Bind Caller Args → Callee Params]
    F --> G[Verify Rule Against Callee]
    G --> H{Match?}
    H -->|Yes| I[Record Reachability chain + EntryPoint]
    H -->|No| B
```

**Code:** [engine.go](../pkg/engine/engine.go), [verify.go](../pkg/engine/verify.go)

### Taint Analysis

**Purpose:** Track where identifiers originate from

**Sources tracked** (the four values `tainted_from` accepts):
- `parameter` - Function parameters (user input)
- `state_var` - Contract state variables
- `local_var` - Local variables
- `sender` - Caller identity (`msg.sender` / `tx.origin`)

**Use case example:**
Detect when a user-controlled parameter is passed to a dangerous function. The
WQL key is `tainted_from` and `args` is indexed by argument position:

```yaml
args:
  0:
    tainted_from: parameter  # First argument comes from user input
```

---

## Performance Considerations

### Reader Optimizations
- Skip common build/test directories
- Stream file reading
- Parallel file discovery (ready for future enhancement)

### Builder Optimizations
- Single-pass parsing with solast-go
- Lazy AST building (only when needed)
- Efficient struct resolution via global map
- Call graph memoization

### Engine Optimizations
- Early exit on non-matching scopes
- Efficient AST traversal with visitor pattern
- Visited set for recursive tracing (prevents infinite loops)

### Report Optimizations
- Template-based HTML generation
- Mermaid diagrams (client-side rendering)
- Streaming JSON output

---

## Error Handling

### Reader
- **Invalid paths**: Clear error messages
- **Non-Solidity files**: Skipped with warning in verbose mode
- **Permission errors**: Reported and skipped

### Builder
- **Parse errors**: File reported, continues with other files
- **Tolerance mode**: Continues on recoverable syntax errors
- **Missing contracts**: Skipped in call graph resolution

### Engine  
- **Invalid templates**: Validation errors with line numbers
- **Unknown operators**: Clear syntax error messages
- **Regex errors**: Pattern compilation errors reported

### Report
- **File write errors**: Permission issues reported
- **Invalid output paths**: Created if parent directory exists

---

## Example Workflow Execution

### Full Scan Example

```bash
w3goaudit ./contracts/ \
  --template ./templates/official/reentrancy-pattern.yaml \
  -o report/ \
  --verbose
```

**What happens:**

1. **Reader** discovers all `.sol` files in `./contracts/`
2. **Builder** parses files and builds the database (7 phases, incl. per-function effects)
3. **Engine** loads `reentrancy-pattern.yaml` template
4. **Engine** iterates entry functions (scope: entrypoint)
5. **Engine** verifies each function against template rules
6. **Engine** creates findings for matches
7. **Report** writes the `report/` result folder (overview, findings, SARIF, data/, per-contract workflows + state-changes)
8. **CLI** prints the terminal summary and captures full detail in `report/run.log`

**Verbose output shows:**
- Files discovered
- Project root detected
- Framework detected
- Database statistics
- Templates loaded (and their source: home or embedded)
- Findings count

---

## Related Documentation

- [Usage Guide](./usage.md) - CLI commands and SDK usage
- [WQL Syntax](./wql-syntax.md) - Template writing guide
- [Project Overview](./project-overview.md) - Architecture and design
