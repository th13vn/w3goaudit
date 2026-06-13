# pkg/builder - Database Construction

## Purpose

Parses Solidity AST and builds a comprehensive contract database through 6 phases.

## Key Files

### builder.go
Main orchestrator for the 6-phase build process.

**Exports:**
- `Builder` struct
- `New()` - Create builder instance
- `Build(sources)` - Main entry point (6 phases)
- `GetDatabase()` - Get built database

**Build Phases:**
1. **Parse Files** - Extract contracts/functions from AST
2. **Build ASTs, Data Flow & Semantic Facts** - Create simplified AST trees for function bodies, calculate static parameter/variable intra-procedural taint flows into `Database.DataFlow`, and populate lightweight type facts in `Database.Semantics`.
3. **Calculate Selectors** - Generate function signatures and 4-byte selectors
4. **Build Inheritance** - Apply C3 linearization
5. **Build Call Graph** - Resolve all function calls
6. **Calculate Entry Points** - Identify main contracts and their entry functions

### verbose.go
Debug logging infrastructure.

**Exports:**
- `VerboseEnabled` - Global flag to enable/disable verbose logging
- `VerboseLog(format, args...)` - Conditional verbose logging function
- `SetVerboseWriter(w io.Writer)` - Set custom output writer for verbose logs (default: os.Stdout)

**Output Prefix:** None (clean output)

**What it logs:**
- All 6 build phases (start and completion)
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

### ast_builder.go
Builds simplified AST trees for function bodies.

**Exports:**
- `BuildFunctionAST()` - Convert raw AST to simplified tree

**AST Node Types:**

Kinds use dot-notation (the `Kind*` constants in `pkg/types/ast.go`):

| Category | Kinds |
|----------|-------|
| Statements | `stmt.assign`, `stmt.loop`, `stmt.if`, `stmt.try_catch`, `stmt.emit`, `stmt.return`, `stmt.block`, `stmt.unchecked` |
| Expressions | `expr.identifier`, `expr.literal`, `expr.binary_op`, `expr.unary_op`, `expr.member_access`, `expr.index_access`, `expr.conditional`, `expr.tuple` |
| Calls | `call.internal`, `call.external`, `call.lowlevel.*`, `call.builtin.*`, `call.create` |
| Checks | `check.require`, `check.assert`, `check.revert` |

**Statement-form coverage notes:**

- `revert("msg")` and `revert CustomError(args)` both parse as `*ast.RevertStatement`
  (NOT as a `require`-style call) and produce a `check.revert` node, with the
  revert arguments attached as children for `args:` matching.
- `do { ... } while (c)` produces a `stmt.loop` with `loop_type=do_while`.
- `unchecked { ... }` produces a `stmt.unchecked` block; its body statements and
  calls are preserved.
- Compound assignments `%= &= |= ^= <<= >>=` (as well as `= += -= *= /=`) produce
  `stmt.assign` and participate in state-write / taint analysis.
- Tuple assignment `(a, b) = (b, a)` produces an `expr.tuple` node preserving each
  component.
- `new Contract(args)` produces a `call.create` node (and a call-graph creation edge).
- Inline-assembly `ok := delegatecall(...)` (an `AssemblyAssignment`, no `let`) has
  its RHS classified (`asm.delegatecall`, `asm.call`, …) instead of being dropped;
  `AssemblyIf`/`AssemblySwitch`/`AssemblyFor` bodies are also walked.

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

**`FunctionCallOptions` preservation:** the `{value: x, gas: y, salt: z}`
modifier map on a low-level call is no longer dropped at parse time
(ast_builder.go:582). For each named option:

- `has_value: true` attribute set when `{value: ...}` is present; the
  expression for the ETH amount is attached as a child node tagged
  `call_option=value` so taint analysis can reach it.
- `has_gas: true` attribute set when `{gas: ...}` is present.
- `has_salt: true` attribute set when `{salt: ...}` is present (CREATE2).

Templates use this via `attr: has_value: true` to discriminate ETH-bearing
low-level calls from plain function-routing calls. See [`templates/official/arbitrary-send-eth.yaml`](../../templates/official/arbitrary-send-eth.yaml) for usage.

**Call receiver preservation:** member-call receivers are attached as tagged
children with `attr.call_receiver = true`, e.g. `target` in
`target.delegatecall(data)` or `to` in `to.transfer(amount)`. The engine's
`args:` matcher skips this metadata child, so `args.0` still means the first
Solidity argument. Templates can now distinguish tainted receivers from tainted
calldata.

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
  `templates/official/boolean-cst.yaml`.

**Literal Subtype (`subtype`):**
- `buildLiteral()` tags each `expr.literal` with `subtype`: `number`, `string`,
  `bool`, or `hex`. Templates match `attr: { subtype: bool }` to target boolean
  literals precisely (avoids matching a string literal `"true"`).

**Assembly Block Handling:**
- `buildAssemblyBlock()` - Process inline assembly
- Identifies `call`, `delegatecall`, `staticcall` opcodes
- Creates appropriate AST nodes for assembly calls

**Unchecked Block Handling:**
- Solidity `unchecked { ... }` blocks are represented as `stmt.unchecked`.
- Child statements are preserved under the unchecked node, allowing templates
  such as `templates/official/unchecked-arithmetic.yaml` to match arithmetic
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
- Calculates `LinearizedBases` using C3 algorithm
- **Parent Order:** Right-to-left (rightmost parent in `is` clause is most derived-like)
- **Output Order:** Derived-first (most derived contract first, most base last)
- Computes `InheritanceWeight` (depth in hierarchy)
- Matches Solidity compiler's method resolution order

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
  chain-draining variant → `[Z, K1, K2, K3, D, A, B, C, E, O]`). The asymmetric
  Base/Left/Right/Middle/Derived diamond in `10-override-state-order.sol` pins C3
  linearization, state-variable storage order, and MRO function-override binding
  together. Output stays
  derived-first for readable display and method-resolution scans. An inconsistent
  hierarchy (which solc rejects) degrades gracefully: `c3Merge` forces the first
  remaining head and logs, rather than aborting the build.

### callgraph.go
Function call graph construction.

**Exports:**
- `CallGraphBuilder` struct
- `NewCallGraphBuilder(db)`
- `Build()` - Build call graph for all contracts

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

**Statement traversal:** `analyzeNode` walks `unchecked { }` blocks, `do/while`
bodies, `try` **success bodies** (previously only the catch clauses were
walked), and calls embedded in `emit`/`revert` arguments — closing
false-negative gaps for code that places calls in those positions.

**Stores:** `Function.Calls` / `Modifier.Calls` with resolved target information.

**Deterministic iteration:** `Build()` sorts the source-file map keys before
walking, so call-graph construction is reproducible across runs. Per-file parse
failures emit a verbose log instead of being silently skipped. From-IDs use
`SplitN`/`Join` so selectors containing dots (`f(Lib.Type)`) are not truncated.

**Parse-once:** Phase 1 stashes each file's parsed `*ast.SourceUnit` on
`SourceFile.AST`; the call-graph phase reuses it instead of re-parsing every
file (re-parses only for a database reloaded from JSON, where the tree is not
serialized).

**Assembly opcode coverage:** `classifyAssemblyCall` recognizes the full
security-relevant Yul opcode set: `create`, `create2`, `log0`–`log4`, `revert`,
`return`, plus `call`, `delegatecall`, `staticcall`, `sstore`, `sload`,
`selfdestruct`. (This classifier lives in `ast_builder.go`; the call-graph
builder consumes the resulting kinds.)

## Build Flow

```
Sources → Parse → AST Trees + Semantic Facts → Selectors → Inheritance → Call Graph → Entry Points → Database
```

## Integration Points

**Input:** `[]*types.SourceFile` from reader
**Output:** `*types.Database` for engine
