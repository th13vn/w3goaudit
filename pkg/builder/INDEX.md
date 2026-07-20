# pkg/builder - Database Construction

## Purpose

Parses Solidity AST and builds a comprehensive contract database through 7 phases.

## Key Files

### builder.go
Main orchestrator for the 7-phase build process.

**Exports:**
- `Builder` struct
- `New()` - Create a builder using deprecated package-global verbose logging
- `NewWithOptions(Options{Logger, ProjectRoot, ScanTarget, Diagnostics})` - Create a scan-local builder with durable scan metadata and reader diagnostics; a nil logger is disabled
- `Build(sources)` - Main entry point (7 phases)
- `GetDatabase()` - Get built database

**Build Phases:**
1. **Parse Files** - Extract contracts/functions from AST
2. **Build ASTs, Data Flow & Semantic Facts** - Create simplified AST trees for function bodies, calculate static parameter/variable intra-procedural taint flows into `Database.DataFlow`, and populate lightweight type facts in `Database.Semantics`.
3. **Calculate Selectors** - Generate function signatures and 4-byte selectors
4. **Build Inheritance** - Apply C3 linearization
5. **Build Call Graph** - Resolve all function calls
6. **Calculate Entry Points** - Identify main contracts and their entry functions
7. **Analyze Effects** (`effects.go`) - Walk each function's AST to record
   per-function `FunctionEffects` (state writes, require/assert/revert + branch
   guards, access control) into `Database.Semantics.FunctionEffects`.

Phase 2 visits functions and modifiers in a total order keyed by exact owning
source/contract before source position and name. This keeps serialized data-flow
edges deterministic even when two files declare the same contract, function,
modifier, and line layout.

Phase 1 also enriches the reader's occurrence-aligned
`SourceFile.ImportBindings` with solast-go `UnitAlias` and `SymbolAliases`.
Named and namespace aliases therefore remain serialized for exact inheritance,
semantic type, library, callgraph, entry-point, and cache resolution.

### effects.go
Phase-7 per-function effects analysis.

- `analyzeEffects()` iterates every contract's functions, computing
  `types.FunctionEffects` keyed by function ID.
- State writes are detected from `stmt.assign` nodes flagged `is_state_var`
  (kind `assign`/`compound`), `stmt.state_mutation` storage-array `push`/`pop`,
  state-targeted `delete`/`++`/`--` unary ops, and `asm.sstore`.
  Mutation targets follow only the lvalue root: index/member nodes recurse
  through their base/receiver, never through index expressions or unrelated
  descendants. Local targets therefore stay local even when their index is a
  state variable.
- Guards come from `check.require`/`check.assert`/`check.revert`/`stmt.if`
  nodes; their condition text is reconstructed from the AST via `astText`
  (rendered from the tree, not sliced from source text — even though nodes
  now carry `StartLine`/`StartCol`/`StartByte`, below). `StateWrite.Line` /
  `Guard.Line` are populated from each node's `StartLine` (v0.4).
- Auth: function modifiers remain descriptive metadata, while
  `AuthInfo.Controlled` delegates to `Function.IsAccessControlled(db)` so only
  exact modifier bodies and invocation arguments, inline caller checks, or
  recursively resolved internal auth helpers prove privileged access. Names
  alone never prove authorization, and observational `if` conditions or
  false-polarity checks do not count. Normal execution must require the
  authorization predicate to be true, through `require`/`assert` or an
  equivalent negated-revert gate. `msg.sender`/`tx.origin` references in guard
  conditions remain available as descriptive sender-check metadata.
  Consumed by `pkg/report` (`state_matrix.go`, `bundle.go`).

### verbose.go
Deprecated compatibility logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

New builders keep the injected `*logging.Logger` on the object and forward the
same logger to `Database`, `InheritanceBuilder`, and `CallGraphBuilder`. Legacy
constructors keep routing through the serialized global writer for source
compatibility; normal scan-local builds never consult global logging state.

**Output Prefix:** None (clean output)

**What it logs:**
- All 7 build phases (start and completion)
- File parsing progress
- Contract extraction with types and function counts
- AST building statistics
- Number of main contracts found

**Output Configuration:**
- Default: Writes to stdout
- File output: Use `SetVerboseWriter()` to redirect to a file

### contract.go
Contract extraction from raw AST.

**Key Type:**
- `ContractExtractor` - Walks AST and extracts contract definitions

**What it extracts:**
- Contract name, kind (contract/interface/library)
- Functions with visibility, modifiers, parameters
- State variables
- Structs and events
- Base contracts (inheritance)

**Uses:** `solast-go` parser to get raw AST

### location.go
Source-location helpers shared by `ast_builder.go` (v0.4).

**Core helpers:**
- `sourceLocator` indexes each `SourceFile` once. It stores one entry per line,
  plus sparse entries only for multibyte runes (start/end byte and cumulative
  extra UTF-8 bytes) and the first invalid byte. The same locator is threaded
  through contract extraction, simplified-AST construction, and call-graph
  analysis.
- `sourceSpan` carries 1-based lines/columns and 0-based half-open UTF-8 byte
  offsets. Parser line numbers and ranges remain canonical; parser columns are
  ignored because solast-go counts bytes on non-ASCII lines.
- Column lookup validates the endpoint against the indexed line, rejects
  offsets inside a multibyte rune or after invalid UTF-8, then binary-searches
  the sparse rune entries. Complexity is O(log m) per endpoint for `m`
  non-ASCII runes on that line, after O(source bytes) indexing; memory is
  O(lines + non-ASCII runes), not O(source bytes).
- `(*sourceLocator).span(node)` converts both endpoints and
  `(*sourceLocator).apply(dst, node)` stamps an AST node. If a byte range is
  outside its reported line, reversed, or splits invalid UTF-8, line and byte
  fields remain available, both columns are omitted, and exactly one durable
  `location.invalid` diagnostic is recorded for that source file.

Depends on `github.com/th13vn/solast-go` **v0.1.7**, which added `Loc`/`Range`
accessors to call/member/index postfix expressions — the source of call-site
`Col`/`Byte` on `types.FunctionCall`/`types.CallEdge` (see
[`pkg/types/INDEX.md`](../types/INDEX.md#callgraphgo)).

### ast_builder.go
Builds simplified AST trees for function bodies.

**Exports:**
- `BuildFunctionAST()` - Convert raw AST to simplified tree; applies its own
  span as the function-body root. The exported compatibility wrapper obtains
  source content from `db.SourceFiles`; the builder's internal path reuses the
  cached per-file locator. A nil database remains SDK-compatible: direct state
  symbols come from the provided contract with exact owner RefIDs, while only
  inherited lookup is unavailable.
- `BuildModifierAST(moddef)` - Original one-argument SDK compatibility API.
- `BuildModifierASTWithContext(moddef, contract, db)` - Contextual modifier
  builder used by new callers. Takes the owning contract + db so the modifier body's identifier references resolve
  (state-variable names get `is_state_var`/`RefKind`/taint source). Callers must
  pass the owning contract — `buildASTs` builds a modifier→contract map from
  `db.Contracts` since `types.Modifier` has no contract back-reference. Building
  a modifier AST with `nil` context (the old signature) silently missed every
  state-write/taint fact inside modifier bodies. With context, local and exact
  inherited state identifiers receive owner RefIDs even though modifiers have
  no function context; parameter/local IDs remain function-dependent.

**Interior-node locations (v0.4):** every interior node is stamped via a
dispatch-wrapper chokepoint rather than ad hoc call sites, so no statement or
expression type can be added without a location:
- `buildStatement()` calls `buildStatementInner()` then `locator.apply(node, stmt)`.
- `buildExpression()` calls `buildExpressionInner()` then `locator.apply(node, expr)`.
- `buildAssemblyOperation()` / `buildAssemblyCall()` follow the same
  `*Inner` + `locator.apply` pattern for assembly opcodes/calls.
- `buildAssemblyOperationInner()` is only the type dispatcher; local
  definitions, assignments, blocks, if/switch/for control flow, and conditions
  are implemented by focused private builders. This preserves the single
  location-stamping chokepoint while keeping each Yul state transition isolated.
- `buildInlineAssembly()` applies its own span directly (single call site,
  no `*Inner` split).

All recursive callers (`buildBlock`, `buildAssemblyBlock`, condition/branch
builders, …) go through these wrappers, so switching a leaf case from a
direct `types.NewASTNode(...)` return to calling deeper into the dispatcher
does not lose location coverage. `types.ASTNode.StartCol/EndCol/StartByte/
EndByte` are zero only for genuinely synthetic nodes (e.g. a generic
fallback node built directly in a `default:` branch without a matching
`ast.Node`).

**AST Node Types:**

Kinds use dot-notation (the `Kind*` constants in `pkg/types/ast.go`):

| Category | Kinds |
|----------|-------|
| Statements | `stmt.assign`, `stmt.state_mutation`, `stmt.loop`, `stmt.if`, `stmt.try_catch`, `stmt.emit`, `stmt.return`, `stmt.block`, `stmt.unchecked` |
| Expressions | `expr.identifier`, `expr.literal`, `expr.binary_op`, `expr.unary_op`, `expr.member_access`, `expr.index_access`, `expr.conditional`, `expr.tuple` |
| Calls | `call.internal`, `call.external`, `call.lowlevel.*`, `call.builtin.*`, `call.create` |
| Checks | `check.require`, `check.assert`, `check.revert` |

**Statement-form coverage notes:**

- `revert("msg")` and `revert CustomError(args)` both parse as `*ast.RevertStatement`
  (NOT as a `require`-style call) and produce a `check.revert` node, with the
  revert arguments attached as children for `args:` matching.
- `do { ... } while (c)` produces a `stmt.loop` with `loop_type=do_while`.
- Solidity `for` children use runtime order: initialization, condition, body,
  then post expression. Optional initialization, condition, and post clauses
  are omitted safely.
- `unchecked { ... }` produces a `stmt.unchecked` block; its body statements and
  calls are preserved.
- Compound assignments `%= &= |= ^= <<= >>=` (as well as `= += -= *= /=`) produce
  `stmt.assign` and participate in state-write / taint analysis.
- Tuple expressions and declaration-style tuple assignments preserve exact
  positions through serialized `tuple_index` child attributes and a
  `tuple_arity` root attribute. Holes do not renumber later components.
  Multi-target assignments also persist `assignment_lhs_count`, including Yul
  definitions and assignments, so cache-loaded semantic lowering separates all
  LHS values from the single RHS exactly.
- `new Contract(args)` produces a `call.create` node (and a call-graph creation edge).
- Inline-assembly `ok := delegatecall(...)` (an `AssemblyAssignment`, no `let`) has
  its RHS classified (`asm.delegatecall`, `asm.call`, …) instead of being dropped;
  `AssemblyIf`/`AssemblySwitch`/`AssemblyFor` bodies are also walked. Yul
  `for` analysis follows runtime mutation order (`pre`, condition, body, post),
  so body taint reaches post sinks. It builds the loop AST once, then runs a
  bounded monotone **state-only fixpoint** over those existing condition/body/
  post nodes: `headNext = join(loopInput, transfer(head))` until stable. This
  captures loop-carried flows that need multiple iterations (for example
  `a := b; b := source`) without duplicating AST nodes. Identifier taints seen
  on later iterations are unioned into the existing sink nodes, and the stable
  head remains the after-state so the zero-iteration path is preserved.
- Each Yul `let` binding receives a scope-distinct RefID containing its exact
  function identity, binding position, declaration span, name span, and name.
  Reads and assignments reuse that RefID through lexical shadowing. When exact
  source provenance is unavailable, the builder leaves RefID empty rather than
  inventing pointer-based identity.
- Function selectors are computed from canonical parameter types before Phase 2
  AST construction. Parameter, named-return, local, tuple-target, and Yul RefIDs
  therefore remain distinct across overloads. Direct SDK or legacy inputs with
  no canonical selector leave those function-scoped RefIDs empty instead of
  falling back to a bare function name.
- Every Solidity local declaration uses the exact function ID plus its stable
  declaration byte range and name. Nested block declarations that shadow the
  same name therefore receive distinct roots, all reads and assignments reuse
  the active declaration root, and scope exit restores the outer root. Missing
  selector or declaration provenance leaves the local RefID empty so semantic
  lowering can fail closed.
- Yul declaration-name recovery masks comments and quoted strings while
  preserving byte positions before it searches for the code-level `:=`
  delimiter, so misleading names or delimiters in comments and strings cannot
  become declaration provenance.

**Call Classification:**

`classifyMemberAccessCall(name, argCount, receiverType)` routes each
member-access call using inferred receiver type facts when available, then falls
back to the historical method-name and argument-count heuristic. This keeps WQL
templates simple while avoiding known false classifications such as a
one-argument interface method named `transfer` being treated as an ETH transfer.

| Solidity expression | Args | Kind | Notes |
|---|---:|---|---|
| `addr.transfer(amt)` | 1 | `call.builtin.transfer` | ETH builtin when receiver type is primitive `address`; reverts on failure |
| `token.transfer(to, amt)` | 2 | `call.external` | ERC20-shape — also matched by `token_call` semantic group |
| `oneArgToken.transfer(to)` | 1 | `call.external` | Type-aware: receiver is an interface/contract, not primitive address |
| `addr.send(amt)` | 1 | `call.builtin.send` | ETH builtin, returns bool |
| `addr.call(data)` | any | `call.lowlevel.call` | `has_value`/`has_gas` attrs set if `{value:}` / `{gas:}` modifier present |
| `addr.call{value:x}("")` | any | `call.lowlevel.call` | `has_value = true` attribute on node; the `x` expression is added as a child tagged `call_option=value` |
| `addr.delegatecall(data)` | any | `call.lowlevel.delegatecall` | |
| `addr.staticcall(data)` | any | `call.lowlevel.staticcall` | |
| `address(0)`, `uint256(x)`, `IERC20(token)` | any | `call.internal` | Type/interface casts are not external calls and do not satisfy `outgoing_call` |
| `selfdestruct(addr)` | 1 | `call.builtin.selfdestruct` | Solidity-level builtin; `suicide(addr)` aliases here. The `selfdestruct` semantic group unions this with `asm.selfdestruct` |
| `require(cond, ...)` | any | `check.require` | |
| `assert(cond)` | any | `check.assert` | |
| `revert(...)` / `revert CustomError()` | any | `check.revert` | |
| `foo()` (named) | any | `call.internal` | |
| `pool.swap(...)` (any other member) | any | `call.external` | |
| dynamic storage `array.push(...)` / `array.pop()` | push 0/1, pop 0 | `stmt.state_mutation` | Builtin only for raw `storage` data location and valid builtin arity; `is_state_var` is true only for an exact state lvalue root |
| memory/calldata `array.push/pop` extension | library arity | `call.external` AST + exact library callgraph edge | `using L for T[]` resolution is preserved; method name alone never suppresses the call |
| fixed-array or extension-only-arity `push/pop` | library arity | `call.external` AST + exact library callgraph edge | Not a dynamic-array builtin |

"state_write" matches state assignments, storage-array "push"/"pop",
state-targeted "delete"/"++"/"--", and assembly "sstore". Storage-array
mutations are not calls. Phase 5 therefore does not emit callgraph edges for
real builtin array `push`/`pop` operations. Known storage parameters and local
storage aliases use `stmt.state_mutation` with `is_state_var=false`, avoiding a
false outgoing call while keeping effects and WQL fail closed.

State-array classification consults `symbolTable`, the active symbol
classification, rather than the declaration-only state-name set. A local
storage alias that shadows a state-array declaration therefore does not gain
`stmt.state_mutation` or `is_state_var` merely from its name.
Symbol seeding follows Solidity shadowing precedence in every AST construction
path: contract state first, then function or modifier parameters, then named
returns and traversal-time locals. The same order is used for detached
modifier-argument expressions, so `RefKind`, semantic type facts, taint, and
state-write classification agree when a parameter shadows storage.
Solidity block and for-initializer scopes snapshot only declared names and
restore their prior kind, type, taint, raw data location, and exact state RefID
on exit. Assignments to existing outer variables are not rolled back.

Phase 2 seeds inherited state variables base-first through exact
`ResolveContractNameExact` results from parsed source/import bindings, skipping
unresolved or ambiguous bases rather than guessing. Phase 5 uses
`Database.LinearizedContracts` in reverse order for base-first state seeding.
Derived declarations and then parameters/locals retain shadowing precedence.

Raw Solidity data location is tracked privately for state (`storage`), raw
parameters, named returns, and local declarations. This fact, dynamic-array
shape, and builtin arity jointly distinguish array builtins from same-named
library extensions.

**`FunctionCallOptions` preservation:** the `{value: x, gas: y, salt: z}`
modifier map on a low-level call is no longer dropped at parse time
(ast_builder.go:582). For each named option:

- `has_value: true` attribute set when `{value: ...}` is present; the
  expression for the ETH amount is attached as a child node tagged
  `call_option=value` so taint analysis can reach it.
- `has_gas: true` attribute set when `{gas: ...}` is present.
- `has_salt: true` attribute set when `{salt: ...}` is present (CREATE2).

Templates use this via `attr: has_value: true` to discriminate ETH-bearing
low-level calls from plain function-routing calls. See [`templates/official/high/arbitrary-send-eth.yaml`](../../templates/official/high/arbitrary-send-eth.yaml) for usage.

**Call receiver preservation:** member-call receivers are attached as tagged
children with `attr.call_receiver = true`, e.g. `target` in
`target.delegatecall(data)` or `to` in `to.transfer(amount)`. The engine's
`args:` matcher skips this metadata child, so `args.0` still means the first
Solidity argument. Templates can now distinguish tainted receivers from tainted
calldata. When the direct receiver child has a name, that name is also copied
onto the selected call node as `receiver_name`. This lets WQL constrain the
direct receiver without matching nested argument or call-option descendants.
`builder_test.go` pins fresh materialization and JSON round-trip persistence of
this additive fact independently of the engine's legacy-cache fallback.

**Semantic type facts:** `semantic.go` and `ASTBuilder` infer lightweight
`TypeInfo` for parameters, state variables, local declarations, simple
assignments, casts, builtin address expressions, and index expressions. Facts
are stored in `Database.Semantics.Symbols` and mirrored onto AST attributes:

- `type`, `type_kind`, `type_confidence` on typed expression nodes
- `receiver_type`, `receiver_type_kind`, `receiver_type_confidence` on call nodes
- `receiver_type_is_address` on primitive-address receivers

Unknown or complex expressions keep the previous heuristic behavior.

**Member Access Attributes:**
- Stores `parent` attribute for member accesses
- Example: For `tx.origin`, stores `parent="tx"`, `name="origin"`
- Enables correct detection of `tx.origin` vs `msg.sender`

**Condition Tagging (`cond_role`):**
- The test expression of `if`, `while`, and `for` statements is tagged with a
  `cond_role` attribute on its node: `"if"` for `if`, `"loop"` for `while`/`for`.
- The ternary condition (`buildConditional`) is tagged `cond_role="ternary"`
  (alongside its existing `conditional_part="condition"`).
- This lets templates distinguish a constant *condition* (`if (true)`) from a
  boolean literal living in the branch body (`if (c) return true;`), which the
  recursive `contains` operator cannot do on its own. Used by
  `templates/official/medium/boolean-cst.yaml`.

**Literal Subtype (`subtype`):**
- `buildLiteral()` tags each `expr.literal` with `subtype`: `number`, `string`,
  `bool`, or `hex`. Templates match `attr: { subtype: bool }` to target boolean
  literals precisely (avoids matching a string literal `"true"`). A `0x…` number
  literal (e.g. `0xFF`) is tagged `hex`, not `number`, even though the grammar
  classifies it `NumberLiteral` — so value-vs-bitmask templates (incorrect-exp)
  treat `10 ^ 18` (decimal, likely `**` typo) differently from `x ^ 0xFF` (mask).
- Literal AST attributes also preserve `literal_class` as `numeric_decimal`,
  `numeric_hex`, or `hex_string`, plus the original numeric
  `subdenomination`. This keeps hexadecimal numbers distinct from `hex"..."`
  byte strings and lets semantic lowering evaluate Solidity units exactly.
  Yul hexadecimal numbers use the same consistent `subtype: hex` plus
  `literal_class: numeric_hex` pair as Solidity hexadecimal numbers.

**Assembly Block Handling:**
- `buildAssemblyBlock()` - Process inline assembly
- Identifies `call`, `delegatecall`, `staticcall` opcodes
- Creates appropriate AST nodes for assembly calls
- Yul blocks maintain their own lexical scope stack. `let` declarations shadow
  same-named Solidity parameters/state variables only inside their block, and
  Yul local assignments update the local's taint/type facts. References outside
  the nested block fall back to the surrounding Yul or Solidity symbol.
- With no Yul-local shadow, legal assignments to Solidity parameters, named
  returns, and locals update the surrounding taint/type state. Explicit clean
  writes are retained as empty overrides, so a sanitized parameter does not
  regain declaration-time taint on its next assembly reference.
- Yul control-flow joins snapshot the outer symbol state and active Yul scopes.
  `if` joins input with its optional body; `switch` analyzes cases independently
  and also includes input when there is no default; `for` iterates a state-only
  body→post transfer to a fixpoint while joining the zero-iteration input at
  every head. Nested Yul `if`/`switch`/`for` models are replayed with the same
  lexical-scope and branch semantics. Taint sources are sorted unions (a
  branch-only sanitizer cannot erase another path), while type facts survive
  only when every feasible path and observed iteration agrees.

**Unchecked Block Handling:**
- Solidity `unchecked { ... }` blocks are represented as `stmt.unchecked`.
- Child statements are preserved under the unchecked node, allowing templates
  such as `templates/official/medium/unchecked-arithmetic.yaml` to match arithmetic
  inside the block.

**Try/Catch Handling (`buildTryStatement`):**
- `try expr { body } catch { ... }` is represented as `stmt.try_catch`. The try
  expression, the success body, and **every catch clause body** are now built
  into the AST (previously only the expression was kept, so dangerous code inside
  try/catch bodies was invisible to templates).
- Each child is tagged with a `try_part` attribute: `expr` (the call, runs on
  every path), `body` (success arm), and `catch:N` (the N-th catch arm). The
  engine's `sameExecutionPath`/`areExclusiveArms` use these tags so a `sequence`
  cannot pair a node in the body with one in a catch (they never co-execute).

**Low-level Call Signature Extraction:**
- Extracts selector from hex literals (first 4 bytes)
- Parses `abi.encodeWithSelector()` calls
- Parses `abi.encodeWithSignature()` calls
- Stores as `called_signature` attribute

### inheritance.go
C3 linearization algorithm for proper Solidity inheritance.

**Exports:**
- `InheritanceBuilder` struct
- `NewInheritanceBuilder(db)`
- `Build()` - Process all contracts
- `GetInheritedFunctions(contractName)` - Get all inherited functions

**What it does:**
- Calculates compatibility/display `LinearizedBases` and canonical exact
  `LinearizedBaseIDs` using the same C3 algorithm
- **Parent Order:** Right-to-left (rightmost parent in `is` clause is most derived-like)
- **Output Order:** Derived-first (most derived contract first, most base last)
- Computes `InheritanceWeight` (depth in hierarchy)
- Matches Solidity compiler's method resolution order
- Exact-ID C3 merge keys prevent same-named contracts in different files from
  collapsing into one identity. Unresolved names remain visible in the display
  slice; ambiguous base identities are omitted from the exact slice and record
  `identity.unresolved` instead of choosing a plausible wrong contract.

**Iteration Pattern:**
- **For override resolution** (find most-derived impl): iterate **forward**
- **For base-first processing** (state vars, function collection): iterate **reverse**

**Cycle protection & memoization:**
- `InheritanceBuilder.inProgress` tracks contracts currently being linearized.
  `c3Linearize` consults it; cyclic inheritance (`A is B; B is A`) returns a
  `cyclic inheritance detected at <name>` error and falls back to self-only
  linearization for that contract instead of recursing until the Go stack
  overflows.
- `InheritanceBuilder.memo` caches each contract's completed linearization
  (keyed by contract ID) so shared ancestors in deep (OpenZeppelin-style)
  hierarchies are linearized once, not re-derived per descendant. Results
  produced via a cyclic-parent skip are intentionally **not** memoized (they are
  context-sensitive partial answers).
- `c3Merge` is the **canonical forward-order C3 merge** (Solidity / CPython): at
  each step it selects the first list head that appears in no other list's tail.
  `c3Linearize` reverses the direct base list first, because Solidity treats the
  last-listed base as most derived (`L[C] = C + merge(L[B_n]…L[B_1], [B_n…B_1])`).
  This is provably the MRO solc computes — not a heuristic that can diverge on
  deep diamonds. Verified by `TestC3Linearization` (`02-inheritance.sol`),
  `TestC3DiamondMatchesSolc` (`07-diamond.sol`), and `TestC3MergeCanonicalClassicExample`
  (the classic K1/K2/K3/Z example that distinguishes true C3 from the old
  chain-draining variant → `[Z, K1, K2, K3, D, A, B, C, E, O]`).
  `TestC3ClassicKZEndToEnd` (`11-c3-classic-kz.sol`) re-runs that same classic
  example through the FULL `c3Linearize` pipeline from Solidity source (base-list
  reversal + merge), guarding the reversal step the in-isolation merge test does
  not cover. The asymmetric
  Base/Left/Right/Middle/Derived diamond in `10-override-state-order.sol` pins C3
  linearization, state-variable storage order, and MRO function-override binding
  together; `TestCodingStylesParsing` (`13-coding-styles.sol`) adds
  constructor-argument bases (`is Priced(100)`), interface-of-interfaces, an
  abstract mid-chain contract, multi-target `override(Base, Middle)`, and a
  six-contract storage-layout assertion. Output stays
  derived-first for readable display and method-resolution scans. An inconsistent
  hierarchy (which solc rejects) degrades gracefully: `c3Merge` forces the first
  remaining head and logs, rather than aborting the build.

### callgraph.go
Function call graph construction.

**Exports:**
- `CallGraphBuilder` struct
- `NewCallGraphBuilder(db)`
- `Build()` - Build call graph for all contracts
- `ResolveSuperAcrossLeaves()` - Context-aware `super` resolution post-pass (see below)

**What it tracks:**
- Internal calls (within contract)
- External calls (to other contracts)
- Low-level calls (call/delegatecall/staticcall)
- Self calls (`this.function()`)
- Super calls (`super.function()`)
- Transfer ETH calls (`.transfer()`, `.send()`)
- Contract creation (`new C(...)`) as an external creation edge
- **Modifier bodies**: `analyzeContract` now walks `ModifierDefinition`
  sub-nodes, attaching discovered calls to `Modifier.Calls` (previously always
  empty) and emitting edges rooted at the modifier ID. `IsAccessControlled`
  uses this to recognize a non-auth-named modifier that gates via an auth
  helper (`modifier gate { _enforceOwner(); _; }`).
- **Modifier invocation arguments**: resolved modifier calls retain detached
  simplified argument ASTs in `FunctionCall.Arguments`. This lets semantic auth
  analysis derive authorization-boolean bindings such as
  `onlyRole(isOperator[msg.sender])` separately from fixed operands such as
  `onlyRole(ADMIN_ROLE)`, without trusting the modifier name. Caller-selected
  arguments remain unbound.

**Statement traversal:** `analyzeNode` walks `unchecked { }` blocks, `do/while`
bodies, `try` **success bodies** (previously only the catch clauses were
walked), and calls embedded in `emit`/`revert` arguments — closing
false-negative gaps for code that places calls in those positions. The main
type switch delegates variable declarations, try statements, call arguments,
binary assignments, tuples, and call options to private helpers; call
classification similarly separates identifier/member/cast/library/option
receivers before the shared edge-emission path.
For an outer call, traversal records that call once, then walks its expression
and positional arguments once. Nested receiver calls (`helper().ping()`) and
option-value calls (`ping{gas: helper()}()`) therefore receive exact edges
without duplicating the outer call or arguments.

**Stores:** `Function.Calls` / `Modifier.Calls` with resolved target information,
including additive `ResolvedContractID` exact identities.

**Exact identity:** builder traversal stores the current source file, contract,
function, and modifier as exact object pointers. The raw AST contract is matched
with `file#Contract`; calls are attached directly to those objects rather than
re-resolving a short name. Internal, `super`, modifier, explicit typed, and
library targets walk `Database.LinearizedContracts` or source-scoped exact
resolution. Edge `From`/`To` IDs are therefore always constructed from the
owning objects' source files. Dynamic and low-level targets may remain
unresolved normally; `identity.unresolved` is reserved for genuinely ambiguous
or missing AST/type identities. `callgraph_identity_test.go` and
`test-data/core/identity-collision/` pin two independent `Token` contracts so
their function/modifier edges can never cross files.

Raw AST functions are attached to extracted `Function` objects by exact byte
span, with a full parameter-type-list fallback for location-less legacy input.
Name+line and name+arity are never sufficient, so overloads declared on the
same line stay separate. Target overload resolution deduplicates overridden
selectors derived-first, uses known argument types, and leaves genuinely
ambiguous same-arity calls unresolved instead of selecting declaration order.
When parsed arguments are present and no same-name declaration has the observed
arity, the call also remains unresolved with empty exact target fields and one
durable `identity.unresolved` diagnostic. A unique wrong-arity declaration is
never selected as a compatibility fallback.

Option-wrapped member calls reuse the normal member classifier, so
`this.helper{value: ...}(arg)` retains exact `self` metadata while low-level
address calls still classify through their low-level call name.

Extension-library resolution honors `UsingDirective.ForType`, receiver type,
and call arity (including the implicit receiver parameter). More than one
applicable library or overload remains unresolved; it is never resolved by map
or declaration order.

**Context-aware `super` resolution (`ResolveSuperAcrossLeaves`):** in Solidity,
`super.f()` binds against the C3 linearization of the **most-derived contract
being instantiated**, not the contract where the call textually appears. The
per-call resolver in `resolveTarget` only knows the textual contract's own MRO,
so for a cooperative diamond it records the *standalone* target and misses the
*in-leaf* target (e.g. `StepB.step → Root.step` but not `StepB.step → StepA.step`
when `StepB` runs as part of `Full`, whose MRO is `[Full, StepB, StepA, Root]`).
This phase-5 post-pass walks **every** contract's exact-ID MRO as a potential
instantiation leaf and, for each `super` call site hosted by a contract in that
MRO, adds an edge to the next contract in *that* leaf's MRO that defines the
function (exact selector preferred, otherwise unique arity — `nextDefInMRO`). It is
**additive** (standalone edges kept) and **deduplicated by `(From,To)`**, so the
result is the **sound union** of super targets over all instantiation contexts.
Without it, a function reached only through an intermediate contract's `super`
call looks unreachable from a derived leaf's entry point (a reachability
false-negative). Iteration is deterministic (sorted contract IDs). Verified by
`TestSuperChainContextSensitivity` (`12-super-chain.sol`) and
`TestSuperSharedMixinMultipleLeaves` (`14-super-multi-leaf.sol` — a shared mixin
reached by two distinct leaves whose `super` targets differ; pins the exact
7-edge union with no spurious extras).

**Deterministic iteration:** `Build()` sorts the source-file map keys before
walking, so call-graph construction is reproducible across runs. Per-file parse
failures emit a verbose log instead of being silently skipped. Caller IDs use
the exact current function object's full selector, including dotted user-defined
types (`f(Lib.Type)`).

**Parse-once:** Phase 1 stashes each file's parsed `*ast.SourceUnit` on
`SourceFile.AST`; the call-graph phase reuses it instead of re-parsing every
file (re-parses only for a database reloaded from JSON, where the tree is not
serialized).

**Yul assignment parser compatibility:** solast-go v0.1.7 tokenizes Yul `:=` as
`COLON` + `ASSIGN` even though its assembly parser expects a single assignment
token. `parser_input.go` supplies both Phase 1 and the call-graph fallback with
a temporary, same-byte-length input where `:=` becomes ` =` only inside a real
inline `assembly { ... }` region. Ordinary Solidity, quoted strings, and
line/block comments are skipped, while original
`SourceFile.Content` and all byte/line/column ranges remain unchanged.
The normalization pass is a small explicit lexical-state scanner whose code,
quoted-string, line-comment, and block-comment transitions are isolated in
private methods; replacements and byte-for-byte position preservation are
unchanged.

**Tolerant-parse guard:** Phase 1 calls `parser.ParseWithErrors` (solast-go
≥ v0.1.6) instead of `parser.Parse`. Tolerant parsing recovers from syntax
errors so one broken file doesn't abort the build, but it previously did so
*silently* — a parser desync (e.g. a struct field named with a contextual
keyword like `from`, fixed in solast-go v0.1.5) could drop the rest of a
contract body, producing false negatives in every detector with no signal.
`parseFile` now emits a verbose `⚠️` warning naming the file, the recovered
error count, and the first error+line whenever tolerant recovery occurred. It
also persists one `parse.recovered` diagnostic for every recovered parser error;
a fatal file skip records `parse.skipped`. After inheritance, every unresolved
base reference records `inheritance.base_unresolved` with its referring file
and base symbol. All are marked incomplete and are normalized before `Build`
returns. Policy is unchanged (the build still proceeds by default), but the
coverage loss now survives JSON cache round-trips.

**Assembly opcode coverage:** `classifyAssemblyCall` recognizes the full
security-relevant Yul opcode set: `create`, `create2`, `log0`–`log4`, `revert`,
`return`, plus `call`, `delegatecall`, `staticcall`, `sstore`, `sload`,
`selfdestruct`. (This classifier lives in `ast_builder.go`; the call-graph
builder consumes the resulting kinds.)

## Build Flow

`InheritanceBuilder.GetInheritedFunctions(name)` retains its historical SDK
signature, requires a unique contract name, walks exact linearized objects, and
seeds selector suppression from the selected contract before returning unique
base functions in derived-first order. `ExpressionStatement` keeps the semantic
expression's already stamped range, excluding the semicolon; other real
statements retain the central statement-location chokepoint.

```
Options metadata + reader diagnostics → Sources → Parse → AST Trees + Semantic Facts → Selectors → Inheritance → Call Graph → Entry Points → normalized Database diagnostics
```

## Integration Points

**Input:** `[]*types.SourceFile` from reader
**Output:** `*types.Database` for engine
