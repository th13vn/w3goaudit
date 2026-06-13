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
- `Finding` struct - Vulnerability finding result (now carries optional
  `Reachability`, `PrimaryAST`, `EntryPoint`)
- `Location` struct - Finding location info
- `ReachabilityPath`, `ReachStep` - Call chain from entry to host of the
  dangerous statement
- `NodeRef` - Matched AST node identification (kind / name / range)
- `EntryRef` - Auditor-actionable fix-here pointer
- `LocationSource` (enum: `LocationSourceVerifier`, `LocationSourceMatchedNode`)
- `Engine.SetLocationSource(LocationSource)` - Override the location mode;
  the env var `WGAUDIT_LOCATION_FROM_MATCHED_NODE` still takes precedence
- `MaxRuleRecursionDepth` - Constant cap (64) on `Verify` recursion depth
- `MaxInterproceduralTaintDepth` - Constant cap (12) on recursive internal-call taint tracing
- `MaxTaintFixpointPasses` - Constant cap (8) on intra-function taint dataflow fixpoint iteration (`buildFunctionTaintEnv`)

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
- `source` - Raw source-file regex checks for non-AST rules
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

**Matched-node attribution & Reachability (additive, opt-in default):**

Every `Finding` carries three optional fields populated whenever the engine
can determine them; they are always emitted when present, regardless of the
location-source mode:

- `Finding.PrimaryAST` (`*NodeRef`) — the matched AST node's `kind` / `name` /
  `startLine`. This is the *dangerous statement* the rule was anchored on.
- `Finding.Reachability` (`*ReachabilityPath`) — ordered list of `ReachStep`s
  from an externally-callable entry function down to the function that hosts
  `PrimaryAST`. Single-step paths (the match happened in the entry directly)
  are still emitted so reports always have something to render.
- `Finding.EntryPoint` (`*EntryRef`) — the auditor-actionable fix-here function;
  today this is `Reachability.Steps[0]` (the entry). When the semantic
  access-control analyzer ships, it becomes the highest hop with a
  sub-Verified `AuthVerdict`.

**Location provenance switch:**

The engine supports two location-derivation modes via `LocationSource`:

- `LocationSourceVerifier` *(default)* — preserves today's behavior:
  `Location.Function` / `Location.Contract` come from the verifier-function
  context (typically the entrypoint that started the match), `Location.Line`
  comes from the matched node when available. Backward-compatible for every
  existing JSON / SARIF / report consumer.
- `LocationSourceMatchedNode` — every field of `Location` comes from the
  matched AST node's enclosing function/modifier. Aligns w3goaudit's
  attribution with SARIF / Slither / Semgrep conventions (report at the
  dangerous statement, carry the entry hop in `EntryPoint`).

The switch is opt-in:

- Env var: `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1` (also accepts `true` /
  `matched`).
- API: `Engine.SetLocationSource(LocationSourceMatchedNode)`. The env var
  takes precedence over the API setting so CI/scripts can flip the mode
  without touching code.

**How the capture works (internal):**

- `Engine.match *matchTrace` — set to a fresh struct by `executeOnEntryFunctions`
  before each match attempt; cleared after. Records `Primary` (the first
  committed atomic match) and `Chain` (the call chain that reached `Primary`).
- `Verify` populates `e.match.Primary` when `matchAtomic` returns true AND the
  current rule has at least one surface predicate (`hasAtomicPredicate`).
  This means logical containers (`any:`/`contains:`/`sequence:` wrappers)
  don't capture themselves — only the leaf predicate they anchor on does.
  Captures are transactional: if later constraints on the same branch fail
  (`args`, `left`/`right`, `all`, `contains`, etc.), `Primary` is rolled back
  so reports point at the node that actually satisfied the rule.
- `verifyAtFunctionWithCallees` extends the call chain as it recurses into
  internal callees; on the first successful match, the chain is stashed into
  `e.match.Chain`. A separate `ipChains map[*ASTNode]ipPath` tracks chains for
  the `verifyInterproceduralSequence` path (used by `sequence:` rules).
- `buildLocation` and `enrichFindingFromTrace` consume the trace at the
  `executeOn*` boundary to produce the final `Location` (mode-dependent) plus
  the optional fields. `hostFunctionFor` walks the matched node's parent
  chain to resolve `decl.function` / `decl.modifier` ancestors and their
  contract.

### verbose.go
Debug logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

**Output Prefix:** None (clean output)

**What it logs:**
- Template loading: `✓ Loaded template: <id> (<path>)`; lenient loading also logs `⚠️  Skipping invalid template <path>: <error>`
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
- `TemplateLoadOptions` - Directory loading policy (`IgnoreInvalid`)
- `QueryBlock` struct - Query definition (scope, filter, match)
- `Rule` struct - WQL rule (recursive structure)
- `Scope` type - Scope constants
- `LoadTemplate(path)` - Load single YAML file
- `LoadTemplates(dir)` - Load all templates from directory recursively, fail-closed on invalid/incomplete templates or zero valid templates
- `LoadTemplatesWithOptions(dir, opts)` - Optional lenient loading (`IgnoreInvalid: true`)
- `LoadTemplatesLenient(dir)` - Convenience wrapper for old skip-invalid behavior in ad-hoc tooling
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
- **Source:** `source_regex` as a scope-aware raw-text predicate
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
- `LoadTemplate()` / `ParseTemplate()` require `meta.id` and `meta.severity`
  and reject malformed YAML or invalid WQL before execution.
- `LoadTemplates()` is fail-closed: one invalid template in the directory
  aborts the load, and a directory with zero valid templates errors. Use
  `LoadTemplatesWithOptions(dir, TemplateLoadOptions{IgnoreInvalid: true})`
  or `LoadTemplatesLenient()` only when skipping invalid files is intentional.
- `validateRulePlacement()` rejects AST-level fields inside `filter:` and filter-level fields inside `match:` with a precise error
- `validateRegexes()` compiles every regex pattern at load time and
  rejects invalid patterns immediately. A bad regex never silently falls
  back to case-insensitive substring matching.
- `validatePresets()` rejects any `preset:` name that isn't in
  `BuiltinPresets`. A typo like `preset: unAuthenticatd` errors at load
  with the list of known presets.
- `validateKinds()` rejects any `kind:` value that isn't a registered AST
  kind (see `types.allRegisteredKinds`), a known semantic group
  (`types.KnownSemanticGroups`), a single-segment prefix
  (`call`, `check`, `stmt`, `expr`, `decl`, `asm`), or a **multi-segment prefix**
  of a registered kind (`call.lowlevel`, `call.builtin`). `IsKnownKind` and
  `matchKind` accept the same prefix forms. Typos like `kind: outgoing_calls`
  (plural) or `kind: ".*"` error at load with the list of acceptable forms.
- `validateScope()` rejects an unknown `scope:` (e.g. `functions`); an empty
  scope is allowed and defaults to `entrypoint`. Previously an unknown scope
  silently fell through to entrypoint, changing what code was scanned.
- `validateRuleValues()` rejects out-of-vocabulary `tainted_from`
  (`parameter`/`state_var`/`local_var`/`sender`), `visibility_filter`,
  `mutability_filter`, and malformed `version:` constraints.
- `finalizeTemplate()` also rejects an out-of-enum `severity:` (must be
  CRITICAL/HIGH/MEDIUM/LOW/INFO — otherwise the finding vanishes from the
  Markdown/HTML reports), AST operators at a **contract scope**
  (`validateContractScopeRule` — they would otherwise match every contract), and
  a `scope: source` template that lacks a top-level `match.source_regex` or
  carries a `filter:`.
- All of the recursive validators share one `walkRules` visitor, so a new Rule
  field is validated in one place instead of N hand-rolled walkers that drift.
- The same pipeline is shared by `LoadTemplate` (files), `ParseTemplate`
  (inline/SDK), and `LoadTemplatesFromFS` (embedded `fs.FS` packs).
- Invalid templates abort by default; lenient mode logs skipped files under `--verbose`.

**Normalization:**
- `normalizeQueryBlock()` — recurses into filter/match and normalizes rules
- `normalizeRule()` — promotes inline attrs (is_state_var, operator, visibility,
  mutability) into the Attr map so the matcher reads them uniformly
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
  Matches in DFS source order, with a control-flow constraint: consecutive
  matches must co-execute on a single path. `sameExecutionPath()` rejects pairs
  that first diverge into mutually-exclusive arms of a common control structure,
  via `areExclusiveArms()`:
  - `stmt.if` — `then` vs `else` (the condition expression stays sequential);
  - `expr.conditional` — the two ternary arms (`conditional_part` true/false);
  - `stmt.try_catch` — the success body vs any catch clause, and two distinct
    catch clauses (`try_part` body/catch:N); the always-executing try expression
    (`try_part = expr`) co-executes with whichever arm fires and is never
    exclusive.

  This kills cross-branch and cross-try/catch false positives (e.g. an
  `outgoing_call` in a try body never forms a CEI sequence with a `state_write`
  in a catch). It is a branch-arm check via lowest-common-ancestor, **not a full
  CFG** — loops are still treated as straight-line, there is no dominance /
  reachability reasoning (a `return`/`revert` between two nodes does not break
  the sequence), and interprocedural (inlined) nodes share no ancestor so the
  constraint safely no-ops there.
- Negation via `not`

**Traversal Operators:**
- `verifyHas()` / `contains` - Search descendants (depth-first, first match)
- `verifyInside()` / `inside` - Search ancestors

**Atomic Matchers:**
- `matchAtomic()` - Check kind, name, attr on node
- `attr` also sees semantic type facts mirrored by the builder, including
  `type_kind`, `receiver_type`, `receiver_type_kind`, and
  `receiver_type_is_address`; no new WQL syntax is required.
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
- `buildFunctionTaintEnv()` builds that environment as a **bounded dataflow
  fixpoint** (`MaxTaintFixpointPasses = 8`), not a single forward pass. Variable
  declarations with initializers participate (the builder lowers them to
  `stmt.assign`), and carrying the environment across passes lets a later
  definition feed an earlier use — loop-carried taint and out-of-source-order
  aliases converge (see `TestTaintFixpointPropagatesLoopCarriedAlias`). Updates
  remain **strong** (each assignment overwrites its target), so reassignment to
  a sender identity still kills parameter taint and the context-sensitive
  precision is preserved. It is flow-sensitive over straight-line code and
  fixpoint-convergent over loops, but still **not path-sensitive**: it does not
  track which branch a definition came from, and taint does not yet flow out
  through a callee's return value.

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

**Source regex:** `source_regex` is scope-aware. With `scope: source` it scans
each raw source file; with contract/function scopes it checks the current
contract/function snippet; inside AST matching it checks the node source range
when line data is available. Use it for exact syntax that is not represented
well in the AST, not as a replacement for context, taint, or call matching.
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
Returns `true` if a rule contains ONLY filter-level fields (modifier, extends, version, preset, func_name, visibility_filter, mutability_filter, has_guard, has_param, source_regex) and NO AST-level fields (kind, name, contains, etc.).

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
1. Check filter (modifier, extends, func_name, visibility_filter, mutability_filter, has_guard, has_param, source_regex, presets, version)
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
