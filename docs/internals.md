# W3GoAudit Internals — Technical Deep-Dive

A by-the-code walkthrough of how w3goaudit works end to end: the pipeline, every
package's responsibilities and key functions, the algorithms chosen and **why**,
and the specific cases / edge-case decisions that shape behavior.

This is the *engineering* companion to the higher-level [`project-overview.md`](project-overview.md).
For the WQL template language see [`wql-syntax.md`](wql-syntax.md); for CLI/SDK
see [`usage.md`](usage.md) / [`sdk.md`](sdk.md). Each package also has a focused
`pkg/*/INDEX.md` with `file:line` change-checklists — those are the source of
truth when editing; this document explains how the pieces fit together.

> **Accuracy note:** functions are referenced by name + file; exact line numbers
> drift, so trust the function name. The AST-kind and semantic-group lists here
> are extracted from `pkg/types/ast.go` and are authoritative.

---

## 1. Philosophy & Differentiators

w3goaudit is an **AST-based, template-driven** Solidity static analyzer written
in Go. Detectors are **data** (WQL YAML templates), not code; the engine is a
generic pattern matcher. Design goals, in priority order:

1. **Precision for auditors** — false positives and false negatives are both
   first-class enemies. Much of the engine's complexity exists to avoid FPs
   (branch-arm exclusivity, type-cast vs getter disambiguation, item-ownership
   vs privileged access control) without sacrificing recall.
2. **Lightweight** — no SMT solver, no symbolic execution. Pure AST + call-graph
   + bounded dataflow. Fast on 500+ contract codebases.
3. **Reproducibility** — deterministic ordering/content, a cacheable database
   (`build` → `scan --db`), and fixed-clock report APIs when timestamps must be
   byte-stable too.
4. **Extensibility** — users write their own WQL templates; the engine stays
   detector-agnostic (no per-detector logic baked into Go).

Compared to peers: **Slither** (rich detectors, but Python/compiler-bound),
**Semgrep** (great query UX, weaker Solidity semantics), **CodeQL** (powerful
dataflow, heavy). w3goaudit's niche: a fast, C3-inheritance-aware, call-graph-
integrated engine with a user-extensible query language.

---

## 2. The Pipeline

```
 .sol files                                                     result folder
     │                                                                ▲
     ▼                                                                │
┌─────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ reader  │──▶│ builder  │──▶│ Database │──▶│  engine  │──▶│  report  │
│ discover│   │ 7 phases │   │ (types)  │   │ WQL exec │   │ workspace│
│ +imports│   │          │   │          │   │ +findings│   │ md/json/ │
└─────────┘   └──────────┘   └──────────┘   └──────────┘   │ sarif/html│
                                  ▲              ▲          └──────────┘
                            templates/ (WQL) ────┘
```

The CLI uses `NewWithOptions` constructors with one immutable
`pkg/logging.Logger`; deprecated global verbose wrappers remain only for legacy
SDK constructors. The data flow is `Reader` → `Builder` → `*types.Database` →
`Engine` → `[]*Finding` → `report.WriteBundle(...)`.

The **Database is the contract** between front-half (parse/build) and back-half
(match/report). It is fully serializable, so `w3goaudit build -o db.json` then
`w3goaudit <path> --db db.json` skips re-parsing.

---

## 3. Layer 1 — `pkg/reader`: Discovery & Import Resolution

**Entry:** `Read(path)` auto-detects file vs directory → `ReadFile` / `ReadDirectory`.

- **Directory walk** (`ReadDirectory`) is a recursive `filepath.Walk` that skips a
  fixed `skipDirs` set: `node_modules`, `out`, `artifacts`, `cache`, `lib`,
  `test(s)`, `script(s)`, `mock(s)`, `broadcast`, `coverage`, `typechain*`,
  `deployments`, `dependencies`, … — i.e. dependency/build/test noise that would
  drown real findings.
- **Canonicalization** (`canonicalPath`) resolves symlinks (`EvalSymlinks`) then
  `Clean`s, falling back to `Abs`. This is the **dedup linchpin**: the same file
  reached as `./A.sol` and `sub/../A.sol` must load once, or the Database gets
  duplicate contract definitions. A `loadedPaths` map keyed by canonical path
  enforces it.
- **BOM stripping** (`stripBOM`) removes a UTF-8 BOM before regex anchors
  (`^pragma`, `^import`) run — otherwise they silently fail on BOM-prefixed files.
- Each file gets a SHA-256 checksum and its pragma stored.

**Import resolution** (`resolver.go`) supports **monorepos with per-sub-project
remappings**:
- `findSubRoot(fromFile)` walks **upward** to the nearest `foundry.toml` /
  `remappings.txt` / `hardhat.config.*` / `truffle-config.js` (bounded by the
  scan root); `subProjectFor` memoizes each sub-project's remappings, so
  `packages/x/src/Foo.sol` resolves against `packages/x/`'s config, not the git root.
- Remapping precedence: `remappings.txt` → `foundry.toml remappings=[...]` →
  framework defaults (forge-std, `lib/*/src/`, OpenZeppelin) → fallback search
  (`node_modules/` → `lib/` → project root → as-is).
- `ResolveImports` loads transitively with an iterative loop over a growing
  `SourceFiles` slice, dedup-guarded against import cycles.
- Import directives are lexed with Solidity comment/string rules and decoded
  escapes. Foundry TOML is parsed structurally; only the active
  `FOUNDRY_PROFILE` participates. Context-qualified remappings are ranked by
  context then prefix specificity, and a missing/non-file target falls through
  to later mappings and project fallbacks. `SourceFile.ResolvedImports` records
  the canonical selected targets for exact identity and cache parity.
- Every authored import occurrence also becomes one serialized
  `SourceFile.ImportBindings` entry. The reader records the raw path and
  canonical resolved file without deduplicating repeated directives; Phase 1
  enriches that occurrence with unit and named-symbol aliases. Named and
  namespace aliases therefore survive database-cache round trips.

---

## 4. Layer 2 — `pkg/builder`: The 7 Build Phases

`Builder.Build(sources)` runs seven phases in order; each populates part of the
Database. Parsing is tolerant — one broken file is logged and skipped, never
aborts the build (an audit target with one bad file should still yield findings).

| Phase | Function | Produces |
|------|----------|----------|
| **1. Parse** | `parseFile` (solast-go `ParseWithErrors`, tolerant) | `db.Contracts` (names, kinds, functions, state vars, modifiers, pragma); raw file AST cached on `SourceFile.AST` for Phase 5 |
| **2. AST + dataflow + semantics** | `buildASTs` → `BuildFunctionAST`/`BuildModifierAST` | per-function `*ASTNode` trees, `db.DataFlow` edges, `db.Semantics.Symbols` (types) |
| **3. Selectors** | `calculateFunctionSelectors` | `fn.Selector` (canonical text) + `fn.Signature` (4-byte hash), with struct→tuple resolution |
| **4. Inheritance** | `buildInheritance` → `c3Linearize` | `contract.LinearizedBases` (C3 MRO, derived-first) + `InheritanceWeight` |
| **5. Call graph** | `buildCallGraph` + `ResolveSuperAcrossLeaves` | `db.CallGraph.Edges`, `Function.Calls`, `Modifier.Calls` |
| **6. Entry points** | `db.CalculateMainContracts` | `db.MainContracts` (deployable contracts + resolved entry functions) |
| **7. Effects** | `analyzeEffects` | `db.Semantics.FunctionEffects` (state writes, guards, auth) |

*(The skill historically called this "6 phases" — effects analysis is a distinct
7th phase in `builder.go`.)*

Determinism is enforced throughout: functions are sorted by
`(contract, startLine, endLine, name)` before AST building; modifiers by
`(startLine, endLine, name)`; contracts iterated by sorted ID; taint sets sorted
alphabetically. This makes `db.DataFlow.Edges` and the serialized database
byte-reproducible (critical for cache validation and golden tests).

### 4.1 AST construction (`ast_builder.go`)

`BuildFunctionAST` lowers the solast-go parse tree into w3goaudit's simplified,
dot-notation `ASTNode` kinds (see §6.2 for the full list). Key decisions:

- **Kind assignment** is a switch on statement/expression type. Control-structure
  *test* expressions are tagged `cond_role` (`if`/`loop`/`ternary`) so a template
  can match `if (true)` without also matching `if (c) return true;` — something
  recursive `contains` alone cannot express.
- **Call classification** (`classifyMemberAccessCall`) is *type-aware*, using the
  semantic facts: `addr.transfer(x)` (1-arg, primitive address) → `call.builtin.transfer`;
  `token.transfer(to,amt)` (2-arg, interface) → `call.external`; type casts
  `IERC20(addr)` / `uint256(x)` → `call.internal` (not an external call). When the
  receiver type can't be resolved it falls back to arity/syntax heuristics.
- **Literal subtype** (`buildLiteral`): a `0x…` number literal is tagged
  `subtype: hex` (not `number`), even though the grammar calls it a NumberLiteral —
  so `incorrect-exp` can tell `10 ^ 18` (decimal, likely `**` typo) from
  `x ^ 0xFF` (intentional bitmask).
- **Call metadata as tagged children:** the receiver of a member call gets a
  child with `call_receiver: true`; `{value:}`/`{gas:}`/`{salt:}` set
  `has_value`/`has_gas`/`has_salt` and attach the value expression as a
  `call_option` child. The engine's positional `args:` matcher skips these
  metadata children. (Powers `arbitrary-send-eth`'s `attr: {has_value: true}`.)
- **Member access** stores the base identifier as the `parent` attribute
  (`msg` for `msg.sender`) so `tx.origin` vs `msg.sender` are distinguishable.
- **Coverage fixes** baked in: `unchecked { }`, do/while bodies, and the *success*
  body of `try/catch` (`try_part` tags) are all walked — earlier they were dropped,
  causing false negatives.
- **Solidity `for` runtime order:** the simplified loop node stores
  initialization, condition, body, then post. Missing optional clauses are
  omitted, so sequence traversal observes the same relative execution order
  as Solidity.
- **Expression-owned spans:** an `ExpressionStatement` returns its semantic
  expression node directly. The statement dispatcher does not overwrite that
  node with the enclosing semicolon-inclusive statement range, so calls and
  other expression findings end before `;` in both ASCII and Unicode source.

### 4.2 C3 linearization (`inheritance.go`) — *algorithm & why*

Solidity's method-resolution order is **C3 linearization** (same as CPython).
`c3Linearize` computes, for contract C with written bases `B_1..B_n`:

```
L[C] = C + merge( L[B_n], …, L[B_1], [B_n, …, B_1] )
```

The base list is **reversed** because Solidity reads `is A, B, C` left-to-right
but treats the *last* base as most-derived. `c3Merge` applies the canonical
"first head appearing in no other list's tail" rule until all lists drain. This
**provably matches solc** (it's the real MRO, not a heuristic that diverges on
diamonds). Cycle protection (`inProgress` map) degrades to self-only on cyclic
inheritance; `memo` caches completed linearizations (deep OZ hierarchies share
ancestors). Output is derived-first. Pinned by `TestC3DiamondMatchesSolc`,
`TestC3MergeCanonicalClassicExample`, etc.

**Why it matters downstream:** the synthetic contract AST (§7.2), internal-call
resolution, and `super` resolution all walk `LinearizedBases` derived-first to
pick the *runtime* implementation.

`LinearizedBases` is display/compatibility data and may retain unresolved base
names. `LinearizedBaseIDs` is the compact exact chain, so the slices are not
assumed to be index-aligned. Display consumers map a name only when one exact
contract of that name exists in the selected contract's exact MRO.

### 4.3 Builder-time taint / dataflow

Within a function, `buildSymbolTable` seeds exact inherited state variables
base-first, then derived state, function parameters, and named returns. Later
local declarations overlay those bindings. Parameters are tainted as
`["parameter"]` and state variables as `["state_var"]`; assignments propagate
taint to their LHS (updating the symbol table so later uses inherit it) and emit
`db.DataFlow` edges.
`computeTaint` aggregates a subtree's sources (deduped, sorted). This is a
*single-pass, intra-procedural* pass that populates `ASTNode.TaintSources` -
distinct from the engine's context-sensitive fixpoint (§7.5). Declaration-aware
scope frames cover Solidity blocks and for-loop initializers. They restore only
names declared in that scope, including kind, type, taint, raw data location,
and exact state RefID; assignments to existing outer symbols remain in flow.

### 4.4 Call graph (`callgraph.go`)

`analyzeFunction` walks each function body (reusing Phase 1's cached AST),
classifying call sites by type (`internal`/`external`/`self`/`super`/`library`/
`lowlevel_*`/`modifier`). Modifier bodies are also walked (so auth helpers called
from modifiers are visible). Target resolution disambiguates overloads by arg
count, and resolves through the C3 MRO. A parsed known-arity call with no
same-name declaration of that arity remains unresolved with empty exact target
fields and one `identity.unresolved` diagnostic; a unique wrong-arity target is
never selected by name. `ResolveSuperAcrossLeaves` is a
post-phase that, for every contract treated as an instantiation leaf, binds each
`super` call to the next definition in *that leaf's* MRO — additive and deduped,
so a function only reachable via `super` from a specific leaf isn't falsely
unreachable.

### 4.5 Semantic facts (`semantic.go` + `pkg/types/semantic.go`)

`resolveTypeInfo` infers a `TypeInfo` (name, kind ∈ primitive/contract/interface/
library/abstract/struct/array/mapping, `IsAddress`, `IsPayable`, confidence) for
parameters, state vars, locals, casts, index/member expressions. Facts are stored
in `db.Semantics.Symbols` *and* mirrored onto AST attributes (`type`, `type_kind`,
`receiver_type*`, …) — but only stable, useful ones, so WQL can match on them
while the durable record stays in `Database.Semantics`. Confidence is
`high`/`medium`/`low`; unknown types fall back to syntax heuristics. Phase 7's
`analyzeFunctionEffects` records per-function `StateWrites`, `Guards`, and `Auth`
(reconstructing condition text via `astText` since nodes don't store source
positions).

---

## 5. Layer 3 — `pkg/types`: Core Data Structures

### 5.1 Database & resolution

`Database` holds `ProjectRoot`, the original `ScanTarget`, durable
`Diagnostics`, `SourceFiles`, `Contracts` (keyed `absPath#Name`),
`MainContracts`, `CallGraph`, `DataFlow`, and `Semantics`. ID formats:
- Contract: `absPath#ContractName`
- Function: `absPath#ContractName.selector(argTypes)`
- Modifier: `absPath#ContractName.modifierName`

Lookup hardening:
- `GetContractByID` — O(1), use when you have an ID.
- `GetContractByName` / `ResolveContractName` — deterministic compatibility
  helpers for callers that knowingly accept name-only behavior.
- `ResolveContractNameExact(name, fromFile)` — exact-only: use the current file
  plus occurrence-level `ImportBindings` and canonical resolved imports, then
  return ambiguity rather than guessing. Named aliases expose only their local
  name, while namespace aliases resolve qualified names such as `V.Base` in the
  exact imported source.
  A sole repository-wide candidate is exact only when `fromFile` is empty;
  source-scoped calls still require same-file or import provenance.
- `ResolveContractNameExactWithStatus(name, fromFile)` — returns
  `Resolved`, `Missing`, `Ambiguous`, or `BindingMissing` status so diagnostics
  can distinguish an authored alias whose imported declaration is absent.
- `LinearizedContracts(contract)` — materialize the exact
  `LinearizedBaseIDs` C3 chain for identity-sensitive consumers.

When a legacy cache has only display `LinearizedBases`, normalization records
one incomplete `identity.unresolved` diagnostic for every base entry that exact
source/import resolution reports missing, binding-missing, or ambiguous.

Core inheritance, call graph, engine, report, navigation, state, workflow, and
extract paths use exact objects/IDs. Same-directory proximity is never accepted
as proof of identity.

### 5.2 ASTNode & the full kind set

`ASTNode{ Kind, Name, Value, RefID, RefKind, TaintSources, Attributes, Parent,
Children, StartLine, EndLine, StartCol, EndCol, StartByte, EndByte }`.
`RefKind` ∈ `parameter`/`state_var`/`local_var`
drives taint provenance.

**Complete kind list** (from `ast.go`):

- **Calls:** `call.internal`, `call.external`, `call.lowlevel.call`,
  `call.lowlevel.delegatecall`, `call.lowlevel.staticcall`, `call.builtin.transfer`,
  `call.builtin.send`, `call.builtin.selfdestruct`, `call.create`
- **Checks:** `check.require`, `check.assert`, `check.revert`
- **Statements:** `stmt.assign`, `stmt.state_mutation`, `stmt.if`, `stmt.loop`,
  `stmt.return`, `stmt.emit`, `stmt.try_catch`, `stmt.block`, `stmt.unchecked`
- **Expressions:** `expr.identifier`, `expr.literal`, `expr.binary_op`,
  `expr.unary_op`, `expr.member_access`, `expr.index_access`, `expr.conditional`,
  `expr.tuple`
- **Declarations:** `decl.contract`, `decl.function`, `decl.modifier`,
  `decl.variable`, `decl.parameter`
- **Assembly:** `asm.block`, `asm.call`, `asm.delegatecall`, `asm.staticcall`,
  `asm.sstore`, `asm.sload`, `asm.selfdestruct`, `asm.create`, `asm.create2`,
  `asm.log0`–`asm.log4`, `asm.return`, `asm.revert`, `asm.operation` (catch-all
  for any other opcode, e.g. `mload`/`mstore`/`add`).

### 5.3 Semantic groups (what each WQL group includes)

Implemented as `Is*` helpers in `ast.go`; the engine's `matchKind` calls them:

| Group | Kinds |
|---|---|
| `outgoing_call` | external + all `call.lowlevel.*` + `call.builtin.transfer`/`send` + `call.create` + `asm.call`/`delegatecall`/`staticcall` (**not** internal) |
| `any_call` | the Solidity call kinds incl. `call.internal` + `call.builtin.selfdestruct` (no asm) |
| `eth_transfer` | `call.builtin.transfer`, `call.builtin.send`, `call.lowlevel.call`, `asm.call` |
| `delegatecall` | `call.lowlevel.delegatecall`, `asm.delegatecall` |
| `external_call` | `call.external` (pair with a `name:` regex for ERC-20/721 token methods) |
| `check` / `guard` | `check.require`/`assert`/`revert` (`guard.*` aliases to `check.*`) |
| `state_write` | `stmt.assign` with `is_state_var`; `stmt.state_mutation` storage-array `push`/`pop`; state-targeted unary `delete`/`++`/`--`; `asm.sstore` |
| `state_read` | `expr.identifier` with `RefKind==state_var` + `asm.sload` |
| `selfdestruct` | `call.builtin.selfdestruct` + `asm.selfdestruct` |

Builtin dynamic-storage-array `push`/`pop` is represented by
`stmt.state_mutation`, not by a `call.*` node or callgraph edge. Classification
requires raw `storage` data location plus valid builtin arity (`push` 0/1,
`pop` 0). Memory/calldata calls, fixed arrays, and extension-only arities retain
library resolution and exact callgraph edges. State-target detection follows only the
mutated lvalue root: identifiers must resolve as state variables, while index
and member accesses recurse only through their base or receiver. A state
variable used merely as an index into a local array does not make the local
mutation a state write. The builder also consults the active symbol
classification, so a local storage alias that shadows a state-array name fails
closed rather than inheriting the shadowed declaration's state identity.
A `stmt.state_mutation` storage mutation is not a `call.*` node.
AST symbol construction seeds contract state first, then overlays function or
modifier parameters, named returns, and later local declarations. Detached
modifier-argument expressions use the same order. This keeps `RefKind`, type
facts, taint, and mutation classification aligned when a storage-array or
scalar parameter has the same name as a state variable.
Known storage parameters and local storage aliases may use
`stmt.state_mutation` with `is_state_var=false`; this models the non-call
builtin while effects and WQL remain fail closed. Inherited state symbols are
seeded exactly before Phase 4 by recursively resolving authored bases through
source/import provenance, while Phase 5 consumes the completed exact C3 MRO.

### 5.4 The Selector/Signature naming inversion

`Function.Selector` holds the canonical **text** (`"transfer(address,uint256)"`);
`Function.Signature` holds the 4-byte **hash** (`"a9059cbb"`). This is inverted
from common usage, kept for JSON back-compat — see the field comment.

### 5.5 JSON caching & `RestoreASTParents`

Round-trips (serialized): `SourceFile.Content`, `SourceFile.ImportBindings`,
`Function.AST`, `CallGraph.Edges`, `Database.Semantics`, `LinearizedBases`.
`FunctionCall.argCount` is presence-aware: an absent legacy field decodes to
`-1`, while explicit zero is always serialized and survives repeated round
trips.
Each additive `ImportBinding` carries `importPath`, optional canonical
`resolvedFile`, optional `unitAlias`, and optional `symbols[]` entries with
`symbol` plus local `alias`. **Not** serialized: `SourceFile.AST`
(re-parsed from Content), `ASTNode.Parent` (rebuilt by `RestoreASTParents`),
`CallGraph.outgoing/incoming` (rebuilt by `EnsureIndex`). Parents are dropped to
keep JSON compact and reconstructed on load, so ancestor-based helpers (`inside`,
guards, taint) behave identically with `--db`.

---

## 6. Layer 4 — `pkg/engine`: WQL Execution (the core)

### 6.1 Template lifecycle

A WQL document is meta plus one query: block. Strict parsing then performs:
`TemplateDoc.lower()` → evaluator `Template`/`QueryBlock`/`Rule` IR →
`finalizeTemplate` (per query block). Unknown keys at any level are rejected
by the strict parser. A query-level `or:` lowers to one QueryBlock per
branch (`Template.Queries`), executed as a location-deduplicated union;
`and:` lowers to one block of labeled `Rule.All` branches at the join scope.
Each joined branch must guarantee a positive reportable anchor and traceable
AST evidence; absence-only and regex-only branches are rejected before
execution, while regex may refine an AST-anchored branch. Traceable AST evidence
has higher capture priority than a coarse regex/root fallback, so it owns the
branch's Primary/Related span. Every positive-polarity sequence nested in a
select-less match must obtain positive actionable evidence from its first step;
negative-polarity sequences under `not:` remain refinement evidence. The
exported IR values
describe evaluator execution and are not a supported YAML schema.
Deprecated evaluator-IR Go/JSON fields `source_regex`, `visibility_filter`, and
`mutability_filter` normalize into canonical fields before validation or
execution. Conflicting non-empty values fail closed, and the aliases are never
accepted by the WQL YAML decoder.
Before typed decoding/lowering, raw query nodes require every explicitly
authored `select`/`from`/branch `label` to be a non-null, non-empty scalar and
every explicitly authored `where` to be a non-null, non-empty sequence.
This validation is composition-neutral: all four authored fields are checked
for both `and:` and `or:` branches before composition-specific lowering.
Lowering rejects vacuous nested matcher maps/lists, empty required strings,
`unchecked_var: false`, and signed or non-decimal `arg.N` keys.

When `mergeRuleInto` receives repeated sibling `not:` fragments, it delegates
them to `mergeNotInto`: the first occupies `Rule.Not`, while each later sibling
is appended as `Rule{Not: ...}` in `Rule.All`. Thus `not A` plus `not B` remains
`(not A) and (not B)`, rather than the weaker `not (A and B)`.

Finalization runs:
`validateTemplateMeta` (requires id+severity) → `validateScope` (rejects unknown
scopes) → `normalizeRule` (promotes inline attrs like `operator` into `Attr`,
expands `arg.N` flat keys, compiles+caches regexes) → `validateRulePlacement`
(`checkRule`) → `validateRuleValues` (vocab for `tainted_from`, version
constraints, presets, kinds). Loading is **fail-closed**: one invalid template
aborts the load unless `--ignore-invalid-templates`.

**Single field-classification table.** `presentRuleFields(r)` tags every Rule
field `classAST` / `classContext` / `classDual`. It is the *one* source of truth,
consumed by `checkRule` (placement: AST fields forbidden in `filter:`, context
fields forbidden in `match:`), `ruleHasASTFields`, and `ruleHasContextFields`.
Dual fields (`regex`, `visibility`, `mutability`) are legal in both layers.
Adding a field = editing one table.

### 6.2 Scopes & dispatch

`Execute` switches on `Query.Scope` to an `executeOn*` function:

| Scope | Executor | Iterates |
|---|---|---|
| `source` | `executeOnSourceFiles` | raw file text (`regex` only) |
| `entrypoint` | `executeOnEntryFunctions` | public/external entry fns of main contracts |
| `function` | `executeOnAllFunctions` | every function |
| `contract`/`library`/`abstract` | `executeOnContractsByKind` | kind-filtered contracts |
| `all_contract` | `executeOnAllContracts` | every contract |
| `main_contract` | `executeOnMainContracts` | `db.MainContracts` |

**Synthetic contract AST.** Contract scopes match `match:` against a synthetic
`decl.contract` root whose children are cloned `decl.function` ASTs from the C3
inheritance chain — so a `contains:` rule can span local *and* inherited
functions. Built by `buildContractAST` and held in a **single-slot memo**
(`contractASTContract`/`contractASTRoot`, reset each `Execute`): the match pass
(`verifyAtContract`) and the related-site enrichment share one tree; a new
contract evicts the previous (bounded memory, since each contract is visited once).

### 6.3 The `Verify` recursion

`Verify(node, rule)` is the heart. Order (fail-fast):
`matchAtomic` → `left`/`right` → `args` → `unchecked_var` → `statement_contains`
→ `all`/`any`/`not` → `sequence` → `contains`/`inside`. Guarded by
`MaxRuleRecursionDepth = 64` against pathological nesting. Before compatibility
normalization, a deep-copy pass applies the same bound across pointer, slice,
and `Args` map Rule shapes while tracking active source pointers for cycles.
Supported nested `Attr` maps and slices, including values supplied through
exported `Rule.IsStateVar`, share that depth budget and active
container tracking: self/mixed cycles and depth 65 fail closed, while depth 64
and shared DAGs remain valid. Malformed programmatic graphs therefore fail
closed before `walkRules` or `Verify` can recurse. On the first atomic match it records the node as
`matchTrace.Primary` (the "dangerous statement"), rolling back if a later
constraint fails — so a finding points at the node that actually satisfied the
rule.
Sequence candidates add their own checkpoint: a subtree/path rejection or
failed suffix restores the prior primary, while a complete suffix commits it.
Name-only member-side matching captures the enclosing member-access node when
no deeper primary exists. Placement validation also recurses through
`statement_contains` at the current AST layer.

- `matchKind` resolves **exact kinds**, **semantic groups** (§5.3), **prefixes**
  (`call` matches all `call.*`, `call.lowlevel` matches `call.lowlevel.*`), and
  `guard.*`→`check.*` aliases.
- `matchAtomic` checks kind, name/value (cached regex), `attr` map, `visibility`/
  `mutability` (via `attrInCSV` — comma-separated "is one of", and it *requires
  the node to carry the attribute* so attr-less nodes don't spuriously match
  `mutability: nonpayable`), `regex` (scoped source), and `tainted_from`.

### 6.4 Traversal & the special operators

- **`contains`** (`verifyHas`): DFS descendants for the first match.
- **`inside`** (`verifyInside`): walk ancestors.
- **`sequence`** (`verifySeq`): ordered, non-contiguous matches in one linear
  extension of an execution-event partial order. Ordinary sibling statements
  retain source order. Receiver, option, argument, assignment RHS, return,
  emit, check, and similar value subtrees precede their enclosing effect; calls
  precede inlined callees. Distinct pre-effect sibling subtrees are unordered
  and may match either relative order. `sameExecutionPath`/
  `areExclusiveArms` still reject mutually-exclusive arms (then/else of an
  `if`, ternary arms, and try body/catch). This kills the dominant reentrancy FP where
  `if (c){ call(); } else { state = x; }` matched `sequence:[outgoing_call, state_write]`
  even though they can never both execute. Interprocedural events additionally
  own a unique occurrence, exact reachability path, and accumulated
  caller/callee arm tokens. Conflicting tokens reject mutually exclusive
  cross-tree matches, and reused callee AST pointers cannot overwrite the
  selected occurrence's path. Raw subtree ancestry and `sameExecutionPath`
  apply only when both events belong to the same function expansion; repeated
  expansions of one AST are ordered by event edges and checked with their
  occurrence-specific arm tokens.
- **`statement_contains`** (`statementContains`): searches the **nearest enclosing
  statement** (closest `stmt.*`/`check.*`/`decl.variable` ancestor) for a sub-rule
  — narrower than `inside`, wider than `contains`. Generic: the operator vocabulary
  lives in the template. Used (with `not:`) by `incorrect-exp` to exclude a `^`
  that shares a statement with another bitwise operator.
- **`unchecked_var`** (`operandsGuardedBefore`): for unsigned `left - right` and
  `left -= right`, matches unless the local AST path proves `left >= right`.
  The proof structurally normalizes the actual stable operands, accepts exact
  `left >= right` / `right <= left` relations in an immediately preceding
  `require`/`assert`, a dominating safe `if` arm whose subtraction is the first
  executable operation through `stmt.block`/`stmt.unchecked` wrappers, or
  fallthrough after the unsafe arm unconditionally exits with no effect in the
  surviving arm. At each sequential container, a prior sibling must itself be
  the accepted proof; otherwise the search stops instead of trusting an outer
  condition. The complete condition and every additional `require`/`assert`
  argument must be structurally effect-free before any fact is accepted.
  Assignments, declarations, emits, internal calls, external calls,
  and nested control statements therefore fail closed. Before any proof is
  accepted, `subtractionExpressionPathIsEffectFree` validates the complete
  intra-statement path. Pure binary/member/index/tuple/conditional wrappers,
  non-mutating unary wrappers, returns, and simple assignments are allowlisted
  only when every sibling is structurally effect-free. Call ancestors,
  assignment-expression siblings, creation, increment/decrement, delete,
  unknown wrappers, unstable operands, and signed subtraction fail closed.

### 6.5 Taint matching

Public `tainted: parameter|state_var|local_var|sender|user_controlled` lowers to
`Rule.TaintedFrom` and is checked via `checkTaint`
→ `expressionTaints`, consulting the active `currentTaintEnv`. The engine builds
that env with `buildFunctionTaintEnv` — a **bounded dataflow fixpoint**
(`MaxTaintFixpointPasses = 8`): parameters seed as `"parameter"`, each assignment
re-applies using the taint computed so far, converging chained/loop-carried
aliases (`a = b; b = from;` reaches `a` on a later pass). **Strong updates**
preserve precision: `from = msg.sender` leaves `from` as *sender identity*, not
generic parameter taint. Interprocedural matching binds a callee's parameters to
the taint of the caller's arguments (`bindCalleeTaint`), bounded by
`MaxInterproceduralTaintDepth = 12`.

Internal-callee resolution identifies the exact call site by UTF-8 byte, then
line plus Unicode column, and uses line-only metadata only for one physical
same-name site. Resolved internal, inherited, self, super, and library calls
consume the recorded exact contract ID and full selector. Both interprocedural
walkers pass the current caller function explicitly at every recursion depth,
so nested overloads and runtime `super` binding use the correct call metadata.
They consider every Solidity `call.*` node but follow only recorded internal,
inherited, self, super, or library call types; non-internal AST shapes require
usable metadata. Callee parameters bind only Solidity arguments, excluding
member receivers and call options. Legacy name/arity fallback is restricted to
genuine `call.internal` nodes and succeeds only for one distinct selector in
the runtime exact MRO; overload ambiguity and arity mismatch return no callee.

Caller identity is `msg.sender`, `tx.origin`, or the exact zero-argument
internal context helper `_msgSender()`. Recorded metadata, when present, must
identify an internal/inherited/super arity-zero call with selector
`_msgSender()`. Database-backed checks become authoritative only after exact
owner/MRO resolution is available; that usable context disproves identity when
the zero-parameter helper is absent or only a nonzero overload exists. A
non-nil empty or unresolvable database is unavailable context, so an exact
synthetic zero-argument `call.internal` keeps the compatibility fallback. Bare
identifiers, state/local/parameter names, external/self calls, and unresolved
calls keep their ordinary parameter/local/state provenance.

### 6.6 Access-control analysis (the crown jewel) — `pkg/types/function.go`

Two distinct concepts, deliberately separated:

**`IsAccessControlled(db)` – privileged access control.** Returns true only
when exact bodies prove a gate to a contract-fixed principal. Names alone never
prove authorization. Applied modifiers require exact resolved modifier-call
metadata and are evaluated from their real AST and recursive helper behavior.
Guarded modifier parameters are bound to persisted call-site argument ASTs, so
`onlyRole(isOperator[msg.sender])` is recognized while
`onlyOwner(amount)` plus `require(amount > 0)` is rejected. Internal helpers
likewise require an exact resolved contract ID and full selector before their
body is followed. Direct function guards use the same whole-condition proof.

Authorization proof is whole-condition, polarity-aware, and
enforcement-positive. `require(auth)` and `assert(auth)` require truth, while
`if (!auth) revert` is the equivalent false-branch form. Observational
conditions such as `if (auth) emit Seen()` and negative truth requirements such
as `require(auth == false)` do not gate normal execution. Logical composition
is conservative: every alternative of a truthy `||` must prove authorization.
Standard `hasRole(FIXED_ROLE, caller)` predicates require a direct or forwarded
caller identity and reject freely caller-selected role operands. Parameterized
modifiers preserve fixed operands separately from authorization booleans, so
`onlyRole(ADMIN_ROLE)` can bind the modifier's `role` parameter while
`onlyRole(userRole)` cannot. All three binding sets participate in the
per-analysis context key. Exact internal recursion propagates caller,
authorization-boolean, and fixed bindings from the single AST call node whose
line/byte location matches the recorded call; it does not union every
same-named call expression.

The `hasRole` name and argument shape are not sufficient. The AST call is
correlated by exact location to resolved internal `FunctionCall` metadata, and
the exact callee must have a concrete, unconditional return proving membership
from an access mapping under the bound fixed-role and caller parameters. A
bodyless, unresolved, ambiguous, dynamic external, or constant-true decoy
fails closed. Direct and returned nested mappings flatten every selector key:
exactly one key must be caller identity and every other key must be fixed rather
than a function argument. Multiple identity selectors such as
`roles[msg.sender][tx.origin]` are not privileged membership proof.

Recursive traversal uses a fresh per-analysis recursion stack and memo. Its key
combines exact body identity with the sorted set of parameters bound to caller
identity, preventing an earlier plain call from suppressing a later
`helper(msg.sender)` context while bounding cycles and repeated work.

The authority test is `isOwnerComparison`/`isCallerControlledTarget`: the *other*
operand must be something the caller **cannot** choose — a state var, a fixed
getter (`owner()`, `hasRole(ROLE, msg.sender)`), an immutable/constant,
`address(this)`, or a hardcoded literal address. Comparing against a **function
argument** is self-authorization, not a privileged gate.
The access-control and self-scoping walkers use the same exact `_msgSender()`
identity rule as engine taint, including recorded call metadata, exact MRO
resolution, local aliases, forwarded arguments, owner comparisons, and getter
resource checks.

**`ComparesCallerIdentity(databases ...*Database)` – caller self-scoping.** A caller identity compared
(in a guard) against *any* operand, including item-ownership: `ownerOf(tokenId)
== msg.sender`. Also interprocedural (same descent + forwarding). This is *not*
privileged access control — it scopes the caller to their own resource ("you can
only act on your own behalf/asset"), the ETH/NFT analogue of
`require(from == msg.sender)`. The optional database preserves the historical
no-argument SDK call; the first non-nil database enables exact interprocedural
resolution.

Two precision sub-decisions live here:
- **`getterIsResourceScoped`** — a getter indexed by a caller-chosen argument
  (`ownerOf(tokenId)`) is *resource self-scoping*, not privileged; `owner()`
  (no arg) and `hasRole(ROLE, msg.sender)` (no free selector) stay privileged. So
  `ownerOf(id) == msg.sender` feeds `ComparesCallerIdentity`, **not**
  `IsAccessControlled` — this is what stops NFT-vault `deposit`/`withdraw` from
  being mis-marked access-controlled.
- **`unwrapTypeCast`** — strips a one-arg call only when the callee is an actual
  type name (`address`, `uintN`, `payable`, …, via `isTypeCastName`), so the
  getter `ownerOf(tokenId)` is **not** mistaken for a cast and collapsed to
  `tokenId`.

**Presets** (`presets.go`) expose property-true checks:
- `access_controlled` = `IsAccessControlled`
- `caller_checked` = `IsAccessControlled || ComparesCallerIdentity` (self-scoping
  is a valid mitigation for `arbitrary-transferfrom` and `arbitrary-send-eth`)
- `reentrancy_guarded` = a reentrancy-guard modifier is present
Vulnerability detectors use ordinary `not:` when the property must be absent.
Unknown preset names are rejected at load (`IsKnownPreset`).

### 6.7 Location provenance, reachability & related sites

`matchTrace` captures `Primary` (the matched node) and `Chain`/`ChainContracts`
(the interprocedural path). From it the executor builds:
- **`Location`** — by `LocationSource`: `LocationSourceVerifier` (default;
  contract/function from verifier context, line from matched node) or
  `LocationSourceMatchedNode` (everything from the matched node — SARIF/Slither
  convention; opt-in via `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1` or
  `Engine.SetLocationSource`; there is no current CLI `--location-source` flag).
- **`Reachability`** (`enrichFindingFromTrace`) — entry→…→host `ReachStep`s.
- **`EntryPoint`** — the auditor-actionable fix-here function.
- **`Finding.Related`** (`enrichContractRelatedLocations`) — for contract-scope
  combination rules, every contributing site per internal `Rule.All` branch, labeled from
  the branch's `label:` (else `condition N`). Sites are found with
  `containedFunctionRules` (all function sub-rules of a branch, so an `any:` of
  several function shapes is faithful), matched against the **shared** synthetic
  AST (no rebuild). A positive synthetic contract-root branch emits a
  deterministic contract/file-level site with no borrowed function or precise
  byte/column span.

Matched-node location mode always takes line, columns, and bytes from
`Primary`. Host file/contract/function prefer the final trace-chain hop, then
the enclosing declaration, then verifier fallbacks. Contract-related
enumeration retains the successful contract-root trace and uses its primary as
a fallback only when no per-function site can be enumerated.

Contract-scope locations anchor on `Primary` only when it has a real source
line. In that precise case, the range plus host contract/function and source
come from the exact enclosing cloned AST node. A location-less primary remains
at the verified contract/file level and does not borrow a function or line from
synthetic ancestry. Union identity is therefore one canonical file/span key
whenever a span is supplied by `PrimaryAST` or `Location`, with kind treated
as optional provenance: an unknown result is retained provisionally, replaced
by the first concrete result at that span, and removed from the remembered
state. Unknown-first and unknown-last orders therefore agree while different
known kinds remain distinct. For inherited
entry functions, verification still receives the derived/deployment contract
for MRO and callee resolution, but reachability files prefer each exact
`Function.SourceFile` so the final host points to the owning base source.

---

## 7. Layer 5 — `pkg/report`: Output

`WriteBundle` produces a **result folder** (an audit workspace), not one file:

```
<out>/
├── README.md                   # FormatFolderReadme (landing page)
├── summary.md                  # FormatSummaryMarkdown (metrics + rules-hit)
├── overview.md                 # FormatOverviewMarkdown (metrics + contract index)
├── findings.md                 # FormatFindingsAsMarkdown
├── results.sarif               # FormatFindingsAsSARIF (always)
├── run.log                     # CLI tees verbose logs here
├── data/{manifest.json, database.json, findings.json, overview.json, diagnostics.json, nav.json, explorer.json}
├── contracts/<rel-src-path-no-ext>/<MainContract>/
│   ├── README.md               # FormatContractReadme (findings + detail)
│   ├── state-changes.md        # reachability/state-write matrix
│   └── workflows/<entryFn>.md  # per-entry-point context
└── overview.html + findings.html   # only with --html
```

Formatters:
- **Markdown** (`FormatFindingsAsMarkdown`) — grouped by severity/template, one
  `<details>` per occurrence, a dotted reachability trace block, and
  `renderRelatedLocationsMarkdown` ("All matched sites" + full-function excerpts).
- **JSON** — additive structured fields (`reachability`, `entryPoint`,
  `primaryAst`, `related`), all `omitempty` so old consumers parse unchanged.
- **SARIF 2.1.0** (`FormatFindingsAsSARIF`) — **relative** `artifactLocation.uri`
  with `uriBaseId: srcRoot` (portable across machines), one `relatedLocations[]`
  per reachability hop (`entry:`/`hop:`/`host:` labels), severity → level +
  `security-severity`, and a guard against trailing-dot logical names
  (`"MyToken."`) on contract-scope findings.
- **HTML** — accessible dark-mode mirror.
- **Code extraction** (`code_extract.go`) — `extractFullFunctionForLocation` finds
  the declaration via `declaresFunction` (word-boundary, so `withdraw` ≠
  `withdrawAll`) and the closing brace via `findBlockEnd` (brace-matching with
  string/comment stripping).

Generator call graphs, state matrices, and workflow closure share one exact
call resolver. Recorded contract IDs/full selectors are verified first;
legacy metadata searches exact runtime-MRO objects and succeeds only for one
distinct selector at the known or unknown arity. Ambiguity is omitted.

Determinism: function lists and "Defined in" groupings are sorted; Mermaid node
IDs use FNV-64a (32-bit collided ~1% over 10k nodes); contract folders mirror
source paths and overloaded workflow files use `<fn>__<selector>.md`.
`BundleOptions.Now` supplies one UTC timestamp to every bundle artifact; without
a fixed clock, deterministic content still has intentionally varying timestamps.

---

## 8. `cmd/w3goaudit`: CLI

Cobra-based. **The root command IS the scan** (`w3goaudit <path>`) — there is no
`scan` subcommand. `runScan`: load config → first-run provision `~/.w3goaudit`
→ load/build DB → build summary → load templates → `Execute` per template →
filter (severity, include/exclude globs) → `WriteBundle` → console summary.

Key flags: `-t/--template`, `-o/--output`, `-d/--db`, `-v/--verbose`, `-H/--html`,
`-q/--stdout`, `--ignore-invalid-templates`, `-s/--severity`, `-m/--min-severity`,
`-i/--include`/`-e/--exclude`, `-l/--list-templates`, `-T/--update-templates`,
`-u/--update`, and `--strict-imports`. The strict-import gate consumes the same
persisted import diagnostics for source and `--db` scans and runs before
template execution/report generation.

Subcommands: `build` (parse → `database.json`), `extract` (query a DB: `main`,
`entry`, `inheritance`, `statevar`, `selector`, `involve`, `workflow`, `bundle`,
`context`, `source`, `diff`).

Inheritance and bundle extracts never zip display MRO names with compact exact
IDs. Self maps to the selected contract; other display names receive a kind
only when exactly one matching object is present in that contract's exact MRO.

**Template precedence** (`pkg/home`): `--template` > `~/.w3goaudit/templates/`
(downloaded from `th13vn/w3goaudit-templates` on first run) > the embedded
`official/` pack (`templates/embed.go`). The retained lanes are
`templates/official/` (25 distributable detectors), `templates/test/` (5 engine
feature templates), and `benchmarks/templates/` (76 competitive detector
ports), all WQL.

---

## 9. Algorithms Chosen — and Why

| Algorithm | Where | Why this choice |
|---|---|---|
| **C3 linearization** | `inheritance.go` | The real Solidity/CPython MRO; provably matches solc on diamonds (vs. a heuristic that diverges). |
| **Bounded taint fixpoint** | `buildFunctionTaintEnv` | Converges chained/loop-carried aliases without unbounded iteration; strong updates keep sender-vs-parameter precision. Cap 8 passes. |
| **Interprocedural descent with cycle detection + depth caps** | `IsAccessControlled`, taint walker | Follows entry→helper flows (real bugs hide behind internal calls) while staying bounded on recursive/cyclic graphs (depth 12/64). |
| **Local operand-bound proof** | `unchecked_var` | Exact unsigned operands plus effect-free statement and expression topology prove only relations that remain valid at the subtraction; intervening effects and effectful expression siblings end the proof. |
| **Single-slot synthetic-AST memo** | `contractAST` | Dedup build between match and enrichment without holding every contract's tree (a map would grow unbounded — each contract is visited once). |
| **Process-wide regex cache** | `compileRegexCached` (`sync.Map`) | A pattern referenced by N nodes compiles once. |
| **Type-aware call classification** | `classifyMemberAccessCall` | Distinguishes `addr.transfer(x)` (ETH) from `token.transfer(to,x)` (ERC-20) using inferred receiver type, falling back to arity. |
| **Branch-arm exclusivity for sequence** | `areExclusiveArms` | CEI/reentrancy patterns must co-execute; mutually-exclusive arms are not a real sequence. |
| **Single field-classification table** | `presentRuleFields` | One place to classify a WQL field as AST/context/dual; the three consumers can't drift. |

---

## 10. Specific / Edge Cases (the precision decisions)

These are the deliberate calls that separate w3goaudit's output from a naive matcher:

1. **Item ownership ≠ access control.** `ownerOf(tokenId) == msg.sender` is
   self-scoping (`ComparesCallerIdentity`), not privileged (`IsAccessControlled`).
   Prevents NFT-vault `deposit`/`mint`/`redeem`/`withdraw` from being mis-marked
   protected. (`getterIsResourceScoped`)
2. **Getter vs. type cast.** `ownerOf(id)` is a getter, `address(x)` is a cast —
   `unwrapTypeCast` only unwraps real type names, so the ownership authority isn't
   collapsed to its argument.
3. **Forwarded `msg.sender`.** `_withdraw(msg.sender, …)` then
   `ownerOf(id) != caller` is recognized via `forwardedCallerParams` —
   interprocedurally, in both auth and self-scoping analysis.
4. **Selector vs. bare name.** Callees resolve by the bare name extracted from the
   stored selector (`bareFuncName`); a raw `Name == "_withdraw(address,…)"`
   comparison silently never matched (this was a real dead-path bug).
5. **`unchecked_var` requires an enforced exact bound.** `require(a >= b)`
   immediately before `a - b` is safe; `require(a <= b)`, unrelated ordering,
   a non-terminating `if`, a write or call between an `if` condition and the
   subtraction, a surviving fallthrough arm with effects, or signed subtraction
   is not. Only transparent block/unchecked wrappers may precede a subtraction
   protected by a dominating arm. The subtraction's own statement must also use
   an allowlisted expression path with structurally effect-free siblings, so
   `sink((a = 0), a - b)` remains a finding after either an `if` or `require`
   bound.
6. **Hex literals.** `0xFF` → `subtype: hex`, so `incorrect-exp` flags `10 ^ 18`
   but not `x ^ 0xFF`.
7. **`incorrect-exp` shape.** Flags `^` only with simple value operands (id/decimal)
   *and* `not statement_contains` another bitwise op — catches `base ^ exp` while
   ignoring `(a & b) + (a ^ b)/2` and `(3*d) ^ 2`.
8. **Sequence can't cross *mutually-exclusive* branches.** `if/else` then-vs-else
   arms, ternary true-vs-false arms, and try/catch body-vs-catch arms are
   exclusive (reentrancy FP killer). But the `if` **condition** co-executes with
   whichever arm runs, so a call in the condition followed by a state write in the
   body IS a valid sequence — `isConditionExpr` identifies the condition by its
   builder-set `cond_role="if"` attribute, not by kind prefix (a call-typed
   condition like `if (t.call(...))` used to be misread as an arm → missed
   reentrancy).
9. **Type-cast-in-guard.** `require(x != address(0))` casts don't register as
   outgoing calls (reentrancy FP killer).
10. **Decoy modifiers.** An auth-named modifier with a no-op body doesn't count as
    access control.
11. **Exact contract resolution.** Duplicate `Token` declarations cannot
    cross-wire: core paths use exact current objects, canonical resolved imports,
    `ResolvedContractID`, and `LinearizedBaseIDs`; unresolved ambiguity remains a
    diagnostic instead of becoming a same-directory/lexicographic guess.
12. **Canonical path dedup, BOM stripping, tolerant parsing** — robustness at the
    reader/parser boundary so one odd file doesn't corrupt or abort the build.
13. **Unicode columns vs. UTF-8 bytes.** The builder ignores the parser's
    byte-oriented column field and converts byte ranges with one cached sparse
    per-source index. `StartCol`/`EndCol` are one-based, half-open Unicode-code-
    point columns; `StartByte`/`EndByte` are zero-based, half-open UTF-8 bytes.
    SARIF declares `unicodeCodePoints` and never emits the bytes as
    `charOffset`/`charLength`. LSP positions are separately zero-based and
    commonly UTF-16, so consumers must convert rather than reuse these fields.
14. **Deterministic findings.** `Engine.ExecuteAll` applies a total-order sort
    (`SortFindings`: file → line → col → primaryAst → template → contract →
    function → entry/reachability signature) before returning. Per-scope
    execution iterates Go maps, so without this the same scan emitted the same
    findings in a different order every run (noisy diffs, unstable SARIF/CI).
15. **Same-name resolution extended.** Beyond inheritance/call resolution (item
    11), entry-function IDs, main-contract detection, source excerpts, and the
    report explorer/state-matrix/generator resolve via `ResolveContractName`
    (or the contract's own pointer for `LinearizedBases[0]`); functions carry
    `SourceFile` so source lookup never re-resolves by name.
16. **Modifier bodies get contract context.** `BuildModifierAST` receives the
    owning contract + db, so state-variable references inside a modifier (e.g. a
    reentrancy guard's `locked` writes) are classified (`is_state_var`, taint) —
    previously modifier ASTs were built context-free and those facts were lost.
17. **Fail-closed WQL lowering.** A mixed context+AST `any:` and a multi-kind
    (list) `select:` are rejected at load rather than silently over-matching /
    never matching — see [wql-syntax.md](wql-syntax.md).
18. **Sibling negations stay independent.** Repeated `not:` items in one
    `where` list lower to separate conjunction branches. Merging their children
    would turn `not A and not B` into `not (A and B)`, producing false positives
    whenever only one safety property is present.
19. **Auth helper identity is exact.** `_msgSender()` counts only as a
    zero-argument internal helper confirmed by metadata and exact MRO resolution
    when available. Empty or unresolvable database state is not negative proof;
    usable exact owner/MRO context can disprove the helper. Same-named
    identifiers/calls and overloads never borrow caller provenance.
20. **Provenance is transactional and span-first.** Failed sequence candidates
    restore their primary, matched-node locations always use the primary span,
    final trace hops own host identity, and union dedup replaces provisional
    unknown provenance with the first concrete kind while retaining distinct
    concrete kinds.

---

## 11. Performance & Limits

- Caps: `MaxRuleRecursionDepth=64`, `MaxInterproceduralTaintDepth=12`,
  `MaxTaintFixpointPasses=8`.
- The Rule depth cap includes supported nested `Attr` containers; active cycles
  fail closed without rejecting shared DAG values.
- Benchmark fallback attribution uses one length- and newline-preserving
  Solidity lexer for declaration matching and brace counting, masking comments,
  quoted strings, and escapes so fake declarations/braces cannot shift a site.
- Regex compiled once and cached; synthetic AST built once per contract.
- The Database is cacheable (`build` → `--db`), so re-scans skip parsing.
- Source/cache paths preserve normalized diagnostics and source snapshots;
  report excerpts prefer the analyzed `SourceFile.Content` over live disk.
- `Engine` is **not** concurrency-safe (mutable execution-context fields); use one
  Engine per goroutine.
- Validation is load-time (regex, kind, preset, version, placement) — no silent
  semantic drift at scan time.

---

## 12. Extending the Codebase

See the skill (`w3goaudit-dev`) and the per-package `INDEX.md` change-checklists.
Quick map:

- **New AST kind** → `pkg/types/ast.go` (constant + semantic-group membership) →
  `pkg/builder/ast_builder.go` (emit it) → `pkg/engine` `matchKind` if special →
  `docs/wql-syntax.md` + `pkg/types/INDEX.md`.
- **New WQL operator** → `Rule` field + `presentRuleFields` class in
  `pkg/engine/template.go` → verify logic in `pkg/engine/verify.go` (wire into
  `normalizeRule`/`walkRules` if it holds a sub-rule) → test + `docs/wql-syntax.md`
  + `pkg/engine/INDEX.md`.
- **New semantic fact** → `pkg/types/semantic.go` + `pkg/builder/semantic.go`,
  mirror onto AST attrs only when useful to WQL.
- **New detector** → `templates/official/*.yaml` + `test-data/security/` fixtures
  (Vulnerable* + Safe*) + `templates/INDEX.md`.

---

## Related Documentation

- [`project-overview.md`](project-overview.md) — architecture & design decisions (higher-level)
- [`wql-syntax.md`](wql-syntax.md) — the WQL template language reference
- [`workflows.md`](workflows.md) — scan/build/report pipelines
- [`usage.md`](usage.md) / [`sdk.md`](sdk.md) — CLI & Go SDK
- `pkg/*/INDEX.md` — per-package responsibilities, key types/functions, change checklists
