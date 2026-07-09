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
3. **Reproducibility** — deterministic ordering everywhere, byte-stable JSON,
   a cacheable database (`build` → `scan --db`).
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

`reader.New().Read(path)` → `builder.New().Build(sources)` → `*types.Database` →
`engine.New(db).Execute(tmpl)` per template → `[]*Finding` → `report.WriteBundle(...)`.

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
- **Known limitation:** the first matching remapping prefix wins even if the
  mapped file is absent (no fall-through). Remapped packages like
  `@openzeppelin/...` are resolved heuristically, not via full import-scope rules.

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

### 4.3 Builder-time taint / dataflow

Within a function, `buildSymbolTable` seeds parameters as `["parameter"]` and
state vars as `["state_var"]`; assignments propagate taint to their LHS (updating
the symbol table so later uses inherit it) and emit `db.DataFlow` edges.
`computeTaint` aggregates a subtree's sources (deduped, sorted). This is a
*single-pass, intra-procedural* pass that populates `ASTNode.TaintSources` —
distinct from the engine's context-sensitive fixpoint (§7.5). Known limitation:
flat per-function symbol table mis-handles block-scoped shadowing.

### 4.4 Call graph (`callgraph.go`)

`analyzeFunction` walks each function body (reusing Phase 1's cached AST),
classifying call sites by type (`internal`/`external`/`self`/`super`/`library`/
`lowlevel_*`/`modifier`). Modifier bodies are also walked (so auth helpers called
from modifiers are visible). Target resolution disambiguates overloads by arg
count, and resolves through the C3 MRO. `ResolveSuperAcrossLeaves` is a
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

`Database` holds `SourceFiles`, `Contracts` (keyed `absPath#Name`),
`MainContracts`, `CallGraph`, `DataFlow`, `Semantics`. ID formats:
- Contract: `absPath#ContractName`
- Function: `absPath#ContractName.selector(argTypes)`
- Modifier: `absPath#ContractName.modifierName`

Lookup hardening:
- `GetContractByID` — O(1), use when you have an ID.
- `GetContractByName` — deterministic **lex-min** on collisions (two `Token.sol`
  in `/src` and `/test/mocks`), logs the ambiguity.
- `ResolveContractName(name, fromFile)` — **scope-aware**: prefers a candidate in
  the same file → same directory → a relative import in `fromFile` → else lex-min.
  Used by inheritance and call resolution so a project's real `Token` isn't
  confused with `test/mocks/Token`.

### 5.2 ASTNode & the full kind set

`ASTNode{ Kind, Name, Value, RefID, RefKind, TaintSources, Attributes, Parent,
Children, StartLine, EndLine }`. `RefKind` ∈ `parameter`/`state_var`/`local_var`
drives taint provenance.

**Complete kind list** (from `ast.go`):

- **Calls:** `call.internal`, `call.external`, `call.lowlevel.call`,
  `call.lowlevel.delegatecall`, `call.lowlevel.staticcall`, `call.builtin.transfer`,
  `call.builtin.send`, `call.builtin.selfdestruct`, `call.create`
- **Checks:** `check.require`, `check.assert`, `check.revert`
- **Statements:** `stmt.assign`, `stmt.if`, `stmt.loop`, `stmt.return`, `stmt.emit`,
  `stmt.try_catch`, `stmt.block`, `stmt.unchecked`
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
| `token_call` | `call.external` (pair with a `name:` regex for ERC-20/721) |
| `check` / `guard` | `check.require`/`assert`/`revert` (`guard.*` aliases to `check.*`) |
| `state_write` | `stmt.assign` with `is_state_var` + `asm.sstore` |
| `state_read` | `expr.identifier` with `RefKind==state_var` + `asm.sload` |
| `selfdestruct` | `call.builtin.selfdestruct` + `asm.selfdestruct` |

### 5.4 The Selector/Signature naming inversion

`Function.Selector` holds the canonical **text** (`"transfer(address,uint256)"`);
`Function.Signature` holds the 4-byte **hash** (`"a9059cbb"`). This is inverted
from common usage, kept for JSON back-compat — see the field comment.

### 5.5 JSON caching & `RestoreASTParents`

Round-trips (serialized): `SourceFile.Content`, `Function.AST`, `CallGraph.Edges`,
`Database.Semantics`, `LinearizedBases`. **Not** serialized: `SourceFile.AST`
(re-parsed from Content), `ASTNode.Parent` (rebuilt by `RestoreASTParents`),
`CallGraph.outgoing/incoming` (rebuilt by `EnsureIndex`). Parents are dropped to
keep JSON compact and reconstructed on load, so ancestor-based helpers (`inside`,
guards, taint) behave identically with `--db`.

---

## 6. Layer 4 — `pkg/engine`: WQL Execution (the core)

### 6.1 Template lifecycle

YAML → `LoadTemplate`/`ParseTemplate` → `finalizeTemplate`, which runs:
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
`MaxRuleRecursionDepth = 64` against pathological nesting. On the first atomic
match it records the node as `matchTrace.Primary` (the "dangerous statement"),
rolling back if a later constraint fails — so a finding points at the node that
actually satisfied the rule.

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
- **`sequence`** (`verifySeq`): ordered, non-contiguous descendant matches on a
  single execution path. `sameExecutionPath`/`areExclusiveArms` reject two matches
  that land in mutually-exclusive arms (then/else of an `if`, the two ternary arms,
  body-vs-catch of a try). This kills the dominant reentrancy FP where
  `if (c){ call(); } else { state = x; }` matched `sequence:[outgoing_call, state_write]`
  even though they can never both execute.
- **`statement_contains`** (`statementContains`): searches the **nearest enclosing
  statement** (closest `stmt.*`/`check.*`/`decl.variable` ancestor) for a sub-rule
  — narrower than `inside`, wider than `contains`. Generic: the operator vocabulary
  lives in the template. Used (with `not:`) by `incorrect-exp` to exclude a `^`
  that shares a statement with another bitwise operator.
- **`unchecked_var`** (`operandsGuardedBefore` + `conditionBoundsOperands`): on an
  arithmetic `binary_op`, matches only when no earlier `require`/`assert`/`if`
  guard *both* references **every** operand identifier **and** uses an **ordering**
  comparison (`<`/`<=`/`>`/`>=`). "Before" is **document/DFS order**, not line
  number (expression nodes have no reliable `StartLine`). `require(a != b)` does
  not count (equality doesn't bound a subtraction).

### 6.5 Taint matching

`tainted_from: parameter|state_var|local_var|sender` is checked via `checkTaint`
→ `expressionTaints`, consulting the active `currentTaintEnv`. The engine builds
that env with `buildFunctionTaintEnv` — a **bounded dataflow fixpoint**
(`MaxTaintFixpointPasses = 8`): parameters seed as `"parameter"`, each assignment
re-applies using the taint computed so far, converging chained/loop-carried
aliases (`a = b; b = from;` reaches `a` on a later pass). **Strong updates**
preserve precision: `from = msg.sender` leaves `from` as *sender identity*, not
generic parameter taint. Interprocedural matching binds a callee's parameters to
the taint of the caller's arguments (`bindCalleeTaint`), bounded by
`MaxInterproceduralTaintDepth = 12`.

### 6.6 Access-control analysis (the crown jewel) — `pkg/types/function.go`

Two distinct concepts, deliberately separated:

**`IsAccessControlled(db)` — privileged access control.** Returns true when the
function is gated to a contract-fixed principal, via (recursive, cycle-guarded):
1. an **auth-named modifier** (`onlyOwner`/`onlyRole`/…) whose body actually
   carries an auth signal (guard / `if` / `msg.sender` ref) — empty decoy
   modifiers `modifier auth(){ _; }` are rejected (`modifierLooksProtective`);
2. a modifier that **calls an auth helper** (`modifierCallsAuthHelper`);
3. an **internal call to an auth-named helper** (verb+noun: `_checkOwner`,
   `requireAuth`, …);
4. an **AST guard** comparing a caller identity against a *contract-fixed
   authority* (`isAuthCheck`), or
5. the same found **interprocedurally** by descending into internal callees
   (`resolveInternalCallee`, which matches by the **bare** function name extracted
   from the stored selector via `calleeNameMatches`/`bareFuncName`, preferring the
   runtime impl via the deployment contract's MRO), forwarding caller-identity
   arguments through `forwardedCallerParams`.

The authority test is `isOwnerComparison`/`isCallerControlledTarget`: the *other*
operand must be something the caller **cannot** choose — a state var, a fixed
getter (`owner()`, `hasRole(ROLE, msg.sender)`), an immutable/constant,
`address(this)`, or a hardcoded literal address. Comparing against a **function
argument** is self-authorization, not a privileged gate.

**`ComparesCallerIdentity(db)` — caller self-scoping.** A caller identity compared
(in a guard) against *any* operand, including item-ownership: `ownerOf(tokenId)
== msg.sender`. Also interprocedural (same descent + forwarding). This is *not*
privileged access control — it scopes the caller to their own resource ("you can
only act on your own behalf/asset"), the ETH/NFT analogue of
`require(from == msg.sender)`.

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

**Presets** (`presets.go`) wrap these for templates — each returns *true for the
vulnerable case* (use in `filter:` without `not:`):
- `unAuthenticated` = `!IsAccessControlled`
- `unCheckedSender` = `!IsAccessControlled && !ComparesCallerIdentity` (self-scoping
  is a valid mitigation — used by `arbitrary-transferfrom` and `arbitrary-send-eth`)
- `unLocked` = no reentrancy-guard modifier
Unknown preset names are rejected at load (`IsKnownPreset`).

### 6.7 Location provenance, reachability & related sites

`matchTrace` captures `Primary` (the matched node) and `Chain`/`ChainContracts`
(the interprocedural path). From it the executor builds:
- **`Location`** — by `LocationSource`: `LocationSourceVerifier` (default;
  contract/function from verifier context, line from matched node) or
  `LocationSourceMatchedNode` (everything from the matched node — SARIF/Slither
  convention; opt-in via `WGAUDIT_LOCATION_FROM_MATCHED_NODE=1` / `--location-source`).
- **`Reachability`** (`enrichFindingFromTrace`) — entry→…→host `ReachStep`s.
- **`EntryPoint`** — the auditor-actionable fix-here function.
- **`Finding.Related`** (`enrichContractRelatedLocations`) — for contract-scope
  combination rules, every contributing site per `match.all` branch, labeled from
  the branch's `label:` (else `condition N`). Sites are found with
  `containedFunctionRules` (all function sub-rules of a branch, so an `any:` of
  several function shapes is faithful), matched against the **shared** synthetic
  AST (no rebuild).

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
├── data/{manifest.json, database.json, findings.json, overview.json}
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

Determinism: function lists and "Defined in" groupings are sorted; Mermaid node
IDs use FNV-64a (32-bit collided ~1% over 10k nodes); duplicate contract/overload
names are disambiguated (`Name__<filestem>`, `<fn>__<selector>.md`).

---

## 8. `cmd/w3goaudit`: CLI

Cobra-based. **The root command IS the scan** (`w3goaudit <path>`) — there is no
`scan` subcommand. `runScan`: load config → first-run provision `~/.w3goaudit`
→ load/build DB → build summary → load templates → `Execute` per template →
filter (severity, include/exclude globs) → `WriteBundle` → console summary.

Key flags: `-t/--template`, `-o/--output`, `-d/--db`, `-v/--verbose`, `-H/--html`,
`-q/--stdout`, `--ignore-invalid-templates`, `-s/--severity`, `-m/--min-severity`,
`-i/--include`/`-e/--exclude`, `-l/--list-templates`, `-T/--update-templates`,
`-u/--update`.

Subcommands: `build` (parse → `database.json`), `extract` (query a DB: `main`,
`entry`, `inheritance`, `statevar`, `selector`, `involve`, `workflow`, `bundle`,
`context`, `source`, `diff`).

**Template precedence** (`pkg/home`): `--template` > `~/.w3goaudit/templates/`
(downloaded from `th13vn/w3goaudit-templates` on first run) > the embedded
`official/` pack (`templates/embed.go`). Three template lanes exist —
`templates/official/` (distributable), `benchmarks/templates/` (competitive
benchmark detectors), `templates/security/` (legacy `SEC-*`).

---

## 9. Algorithms Chosen — and Why

| Algorithm | Where | Why this choice |
|---|---|---|
| **C3 linearization** | `inheritance.go` | The real Solidity/CPython MRO; provably matches solc on diamonds (vs. a heuristic that diverges). |
| **Bounded taint fixpoint** | `buildFunctionTaintEnv` | Converges chained/loop-carried aliases without unbounded iteration; strong updates keep sender-vs-parameter precision. Cap 8 passes. |
| **Interprocedural descent with cycle detection + depth caps** | `IsAccessControlled`, taint walker | Follows entry→helper flows (real bugs hide behind internal calls) while staying bounded on recursive/cyclic graphs (depth 12/64). |
| **Document-order "before"** | `unchecked_var` | Expression/statement nodes lack reliable line numbers; DFS order is robust. |
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
5. **`unchecked_var` requires an ordering guard.** `require(a >= b)` bounds
   `a - b`; `require(a != b)` does not — equality/inequality are excluded.
6. **Hex literals.** `0xFF` → `subtype: hex`, so `incorrect-exp` flags `10 ^ 18`
   but not `x ^ 0xFF`.
7. **`incorrect-exp` shape.** Flags `^` only with simple value operands (id/decimal)
   *and* `not statement_contains` another bitwise op — catches `base ^ exp` while
   ignoring `(a & b) + (a ^ b)/2` and `(3*d) ^ 2`.
8. **Sequence can't cross branches.** `if/else`, ternary arms, try/catch arms are
   mutually exclusive (reentrancy FP killer).
9. **Type-cast-in-guard.** `require(x != address(0))` casts don't register as
   outgoing calls (reentrancy FP killer).
10. **Decoy modifiers.** An auth-named modifier with a no-op body doesn't count as
    access control.
11. **Scope-aware contract resolution.** A `test/mocks/Token` doesn't shadow the
    real `Token` during inheritance/call resolution.
12. **Canonical path dedup, BOM stripping, tolerant parsing** — robustness at the
    reader/parser boundary so one odd file doesn't corrupt or abort the build.

---

## 11. Performance & Limits

- Caps: `MaxRuleRecursionDepth=64`, `MaxInterproceduralTaintDepth=12`,
  `MaxTaintFixpointPasses=8`.
- Regex compiled once and cached; synthetic AST built once per contract.
- The Database is cacheable (`build` → `--db`), so re-scans skip parsing.
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
