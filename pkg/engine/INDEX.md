# pkg/engine - WQL Template Execution

## Purpose

Executes WQL templates against the contract database to find security vulnerabilities.

## Key Files

### engine.go
Main query execution engine.

**Exports:**
- `Engine` struct - Holds database reference
- `New(db)` - Create engine with database
- `Execute(template)` - Run single template
- `ExecuteAll(templates)` - Run multiple templates
- `Finding` struct - Vulnerability finding result
- `Location` struct - Finding location info
- `MaxRuleRecursionDepth` - Constant cap (64) on `Verify` recursion depth
- `MaxInterproceduralTaintDepth` - Constant cap (12) on recursive internal-call taint tracing

**Thread-safety:** `Engine` is **NOT** safe for
concurrent use. `currentFunction`, `currentContract`, `currentSourceFile`,
and `recursionDepth` are mutated during a scan. SDK consumers that want
parallelism must allocate one `Engine` per goroutine. This contract is
documented inline at the struct definition.

**Execution Scopes:**
- `all_contract` - Every contract/interface/library
- `main_contract` - Only main deployable contracts
- `function` - All functions
- `entrypoint` - Public/external functions of main contracts (most common)
- `contract` - Contract-type definitions only
- `library` - Library-type definitions only
- `abstract` - Abstract contract definitions only

**Filter Support:**
- When `filter:` is present, evaluates those rules first
- Only functions/contracts passing the filter are then checked against `match:`
- Auto-separation: engine detects whether a `not:` rule is filter-level or AST-level; no manual split needed

**Context Management:**
- Stores `currentFunction` and `currentContract` for recursive call tracing
- Stores `currentTaintEnv` while matching so helper parameters can inherit the caller's actual argument sources
- Used by verify.go for advanced checks

**Location accuracy:**
- Function findings resolve source files from the exact `absPath#Contract.selector` function ID when scanning entrypoints, and from the loop contract when scanning all functions. This avoids duplicate contract names in different files corrupting benchmark labels and finding locations.

### verbose.go
Debug logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

**Output Prefix:** None (clean output)

**What it logs:**
- Template loading: `✓ Loaded template: <id> (<path>)` or `⚠️  Skipping invalid template <path>: <error>`
- Template execution (start and completion)
- Number of templates being executed
- Findings count per template
- Total findings across all templates

**Output Configuration:**
- Default: Writes to stdout
- File output: Use `SetVerboseWriter()` to redirect to a file

---

### template.go
WQL template loading and parsing.

**Exports:**
- `Template` struct - Parsed template structure
- `TemplateMeta` struct - Template metadata
- `QueryBlock` struct - Query definition (scope, filter, match)
- `Rule` struct - WQL rule (recursive structure)
- `Scope` type - Scope constants
- `LoadTemplate(path)` - Load single YAML file
- `LoadTemplates(dir)` - Load all templates from directory (recursive, logs warnings for invalid/incomplete templates)
- `ParseTemplate(yaml)` - Parse template from string
- `MatchesRegex(pattern, value)` - Regex helper

**Template Structure:**
```yaml
meta:
  id, title, severity, confidence, description, recommendation
query:
  scope
  filter:     # function/contract-level preconditions (optional)
  match:      # AST pattern matching
```

**Rule Fields (Default logic is AND if multiple fields are set):**
- **Logic:** `all`, `any`, `not`, `sequence`
- **Atomic:** `kind`, `name`, `attr` (+ inline `is_state_var`, `operator`, `visibility`, `mutability`)
- **Traversal:** `contains`, `inside`
- **Filter (function-level preconditions):**
  - `modifier` — regex match on function modifiers
  - `extends` — regex match on inherited contracts
  - `func_name` — regex match on function name
  - `visibility_filter` — comma-separated: `public,external,internal,private`
  - `mutability_filter` — comma-separated: `payable,view,pure,nonpayable`
  - `has_guard` — rule: function body must contain a matching guard
  - `version` — Solidity version constraint
  - `preset` — built-in preset check
  - `has_param` — function has parameter by name
- **Call:** `args: {N: Rule}` or `arg.N:` flat keys (equivalent)
- **Taint:** `tainted_from`
- **Binary:** `left`, `right`

**Argument Matching Notations (equivalent):**
- `args: { 0: ..., 1: ... }`
- `arg.0: ...`, `arg.1: ...`

**Template Validation:**
- `LoadTemplates()` logs `⚠️ Skipping template <path>` with the error when:
  - YAML is malformed
  - `meta.id` is missing
  - `meta.severity` is missing
- `validateRulePlacement()` rejects AST-level fields inside `filter:` and filter-level fields inside `match:` with a precise error
- `validateRegexes()` compiles every regex pattern at load time and
  rejects invalid patterns immediately. A bad regex never silently falls
  back to case-insensitive substring matching.
- `validatePresets()` rejects any `preset:` name that isn't in
  `BuiltinPresets`. A typo like `preset: unAuthenticatd` errors at load
  with the list of known presets.
- `validateKinds()` rejects any `kind:` value that isn't a registered AST
  kind (see `types.allRegisteredKinds`), a known semantic group
  (`types.KnownSemanticGroups`), or a known dotted prefix
  (`call`, `check`, `stmt`, `expr`, `decl`, `asm`). Typos like
  `kind: outgoing_calls` (plural), `kind: call.lowlevel` (missing
  `.call`/`.delegatecall`/`.staticcall` suffix), and `kind: ".*"`
  (regex doesn't apply to `kind:`) error at load with the list of
  acceptable forms. Previously they silently matched nothing at scan time.
- Previously silent failures — now visible under `--verbose`

**Normalization:**
- `normalizeQueryBlock()` — recurses into filter/match and normalizes rules
- `normalizeRule()` — promotes inline attrs (is_state_var, operator) into Attr map
- `normalizeArgNKeys()` / `mergeArgsFromYAML()` —
  walks the parsed Rule tree in lockstep with the raw YAML so `arg.N` flat
  keys nested inside `contains:`, `sequence:`, `all:`, `any:`, `not:` and
  inside `args:` map values all populate the correct `Rule.Args`.
  Previously only the top-level `match:` / `filter:` mapping was scanned
  and any nested `arg.N` was silently dropped.

**Regex performance & safety:**
- `compileRegexCached(pattern)` memoizes compiled regexes in a process-wide
  `sync.Map`. A pattern referenced from N AST nodes is now compiled once,
  not N times.
- `MatchesRegex(pattern, value)` uses the cache and returns false on
  invalid patterns (load-time validation should have caught those).

---

### verify.go
WQL rule verification logic (THE CORE).

**Main Function:**
- `Verify(node, rule)` - Recursive rule matching, depth-bounded by
  `MaxRuleRecursionDepth = 64`. Deeply-nested rules
  (e.g. pathological `not: { not: { not: ... } }`) abort the branch with
  a verbose log instead of overflowing the Go stack.

**Logic Operators:**
- `verifyAll()` - AND logic (all sub-rules must match)
- `verifyAny()` - OR logic (at least one must match)
- `verifySeq()` - Sequence matching (ordered descendants, non-contiguous).
  *Deferred to stage-3:* matches in DFS source order, not execution order,
  so cross-branch matches (e.g. `if/else` where call is in one branch and
  state-write in the other) currently produce false positives. Tracked in
  `.vscode/2026-05-08-invariant-audit.md` §2.5.
- Negation via `not`

**Traversal Operators:**
- `verifyHas()` / `contains` - Search descendants (depth-first, first match)
- `verifyInside()` / `inside` - Search ancestors

**Atomic Matchers:**
- `matchAtomic()` - Check kind, name, attr on node
- `matchArgs()` - Validate function call arguments
  - Skips metadata children tagged `call_receiver` or `call_option`, so `args.0`
    stays the first Solidity argument even though receivers and call options are
    preserved in the AST for taint-aware templates.
- `checkTaint()` - Track expression sources (parameter/state_var/local_var)
  with context-sensitive overrides for internal helper calls. Indexed
  arguments like `from[i]` inherit the base expression's taint.
- Interprocedural taint follows entrypoint → internal helper calls. For
  example, `_deposit(from, amount)` maps the callee's `from` parameter to
  `parameter`, while `_deposit(msg.sender, amount)` maps it to sender identity
  and does not satisfy `tainted_from: parameter`.
- Simple local aliases are propagated in the active function environment, so
  `address payer = from; _deposit(payer, amount)` remains parameter-tainted.

**Filter Helpers:**
- `checkFunctionContext()` - Check modifiers, inheritance, func_name, visibility_filter, mutability_filter, has_guard
- `VerifyAtFunction()` - Entry point for function-scope verification (auto-separates filter vs AST checks)
- `VerifyAtFunctionWithCallees()` - Entry-point match helper that follows internal calls with context-sensitive argument taint
- `VerifyAtContract()` - Entry point for contract-scope verification

**Kind Matching (`matchKind`):**

| Kind / Group | Matches |
|---|---|
| `outgoing_call` | All external calls + asm.call/delegatecall/staticcall |
| `eth_transfer` | transfer/send/call/asm.call |
| `delegatecall` | lowlevel delegatecall + asm.delegatecall |
| `check` | check.require, check.assert, check.revert |
| `guard` | Alias for `check` |
| `guard.require` | Alias for `check.require` |
| `guard.assert` | Alias for `check.assert` |
| `guard.revert` | Alias for `check.revert` |
| `token_call` | `call.external` (pair with `name:` for ERC20/ERC721) |
| `state_write` | stmt.assign (is_state_var=true) + asm.sstore |
| `state_read` | expr.identifier (state_var) + asm.sload |
| `any_call` | All Solidity call kinds (no asm), including `call.builtin.selfdestruct` |
| `selfdestruct` | `asm.selfdestruct` + `call.builtin.selfdestruct` (Solidity-level `selfdestruct(addr)` and `suicide(addr)`) |
| Prefix match | `call` → all `call.*`, `asm` → all `asm.*`, etc. |
| `guard.*` prefix | Remapped to `check.*` |

**Filter Predicates in `checkFunctionContext()`:**

| Field | Effect |
|---|---|
| `func_name: REGEX` | Filter by function name regex |
| `visibility_filter: a,b` | Filter by comma-separated visibility values |
| `mutability_filter: a,b` | Filter by comma-separated mutability values |
| `has_guard: {rule}` | Function body must contain a check.*/guard node matching rule |

**`IsContextOnly()`:**  
Returns `true` if a rule contains ONLY filter-level fields (modifier, extends, version, preset, func_name, visibility_filter, mutability_filter, has_guard) and NO AST-level fields (kind, name, contains, etc.).

**Binary Matching:**
- Handles `left`/`right` for member_access, assignment, binary_op

---

### presets.go
Built-in preset checks for common patterns.

**Exports:**
- `PresetFunc` type - Function signature for presets
- `BuiltinPresets` map - Registry of preset functions
- `IsKnownPreset(name)` - Used by template load to reject typos

**Polarity reminder:** every preset returns `true` for the **vulnerable**
case. Use them WITHOUT a `not:` wrapper in `filter:` — the rule passes
exactly when you want to scan further.

```yaml
filter:
  preset: unLocked   # ← no `not:`; passes for unguarded functions
```

**Unknown presets are rejected at load**: a typo like
`preset: unAuthenticatd` previously matched every function silently
(scan-time fallback was `true`). It now errors at load with the list of
known presets, and the runtime fallback returns `false`.

**Available Presets:**

#### unAuthenticated
Returns `true` (= vulnerable) when function has **no access control**. Checks in order:
1. Auth modifier regex: `(?i)(onlyOwner|onlyAdmin|onlyOperator|onlyRole|onlyGuardian|onlyGovernor|onlyGovernance|onlyGov|onlyManager|onlyController|auth|authorized|requiresAuth|onlyMinter|onlyPauser)`
2. Internal auth call heuristic: calls matching `(?i)(_?check|_?require|_?verify|_?validate|_?enforce).(Owner|Auth|Admin|Role|Sender|Access|Permission)`
3. AST check: `msg.sender`/`tx.origin`/`_msgSender()` compared against owner/admin patterns
4. Recursive check: walks internal/inherited/self/super call chain into base contracts

```yaml
filter:
  preset: unAuthenticated   # scan only unauthenticated entry points
```

#### unLocked
Returns `true` (= vulnerable) when function has **no reentrancy guard**.

Modifier regex (single source of truth — all reentrancy templates route
through this preset to prevent regex drift across the corpus):
`(?i)(nonReentrant|noReentrancy|lock|locked|guard|mutex|reentrancyGuard)`

```yaml
filter:
  preset: unLocked          # scan only unguarded functions
```

---

### verify_test.go
Original test suite for verification logic.

### wql_improvements_test.go
Extended test suite for engine features.

**Tests:**
- `TestMatchKindGuardAlias` — guard/guard.* alias resolution
- `TestMatchKindTokenCall` — token_call semantic group
- `TestCanonicalSyntaxAccepted` — `filter:` + `match:` parses correctly
- `TestContextFuncNameFilter` — func_name regex matching
- `TestContextVisibilityFilter` — visibility_filter comma-separated matching
- `TestContextMutabilityFilter` — mutability_filter matching
- `TestContextHasGuard` — has_guard sub-rule matching
- `TestArgNYAMLParsing` — arg.N YAML key parsing
- `TestLoadTemplateValidation` — invalid YAML returns error (not silence)
- `TestIsContextOnly` — IsContextOnly covers all filter-level fields

---

## Execution Flow

```
Template → validateRulePlacement() → normalizeQueryBlock() → Engine → Scope Selection → checkFunctionContext() → Verify AST Rules → Generate Findings
```

**For each scope item:**
1. Check filter (modifier, extends, func_name, visibility_filter, mutability_filter, has_guard, presets, version)
2. Verify AST rules in `match:` (kind, name, contains, sequence, etc.)
3. If match, create Finding with location

---

## Integration Points

**Input:** `*types.Database` from builder  
**Input:** `*Template` from LoadTemplate  
**Output:** `[]*Finding` with severity, location, description

---

## Design Notes

- **Recursive verification** allows complex nested rules
- **Taint analysis** tracks where identifiers come from
- **Recursive call tracing** finds external calls through internal call chains
- **Filter-aware** auto-separates function-level vs AST-level checks
- **Preset system** provides reusable common checks
- **Performance** uses early exits and visited sets to prevent infinite loops
- **Binary matching** supports left/right for complex expression matching
- **Normalization** happens at load time — zero overhead at scan time
- **Silent failures fixed** — invalid templates now emit warnings under `--verbose`
