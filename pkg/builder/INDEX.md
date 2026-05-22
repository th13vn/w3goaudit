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
2. **Build ASTs & Data Flow** - Create simplified AST trees for function bodies and calculate static parameter/variable intra-procedural taint flows into `Database.DataFlow`.
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

| Category | Types |
|----------|-------|
| Statements | `assignment`, `loop`, `if`, `try_catch`, `emit`, `return`, `block` |
| Expressions | `identifier`, `literal`, `binary_op`, `member_access`, `index_access` |

**Call Classification:**

`classifyMemberAccessCall(name, argCount)` (ast_builder.go:603) routes each
member-access call by *both* the method name AND the number of arguments. Arg
count is the strongest syntactic disambiguator available at parse time —
Solidity AST does not carry receiver-type info to this layer, so the parser
cannot otherwise tell `payable(addr).transfer(amt)` from `IERC20(t).transfer(to, amt)`.

| Solidity expression | Args | Kind | Notes |
|---|---:|---|---|
| `addr.transfer(amt)` | 1 | `call.builtin.transfer` | ETH builtin, reverts on failure |
| `token.transfer(to, amt)` | 2 | `call.external` | ERC20-shape — also matched by `token_call` semantic group |
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
low-level calls from plain function-routing calls. See [`templates/security/arbitrary_send_eth.yaml`](../../templates/security/arbitrary_send_eth.yaml) for usage.

**Call receiver preservation:** member-call receivers are attached as tagged
children with `attr.call_receiver = true`, e.g. `target` in
`target.delegatecall(data)` or `to` in `to.transfer(amount)`. The engine's
`args:` matcher skips this metadata child, so `args.0` still means the first
Solidity argument. Templates can now distinguish tainted receivers from tainted
calldata.

**Member Access Attributes:**
- Stores `parent` attribute for member accesses
- Example: For `tx.origin`, stores `parent="tx"`, `name="origin"`
- Enables correct detection of `tx.origin` vs `msg.sender`

**Assembly Block Handling:**
- `buildAssemblyBlock()` - Process inline assembly
- Identifies `call`, `delegatecall`, `staticcall` opcodes
- Creates appropriate AST nodes for assembly calls

**Unchecked Block Handling:**
- Solidity `unchecked { ... }` blocks are represented as `stmt.unchecked`.
- Child statements are preserved under the unchecked node, allowing templates
  such as `templates/security/unchecked_arithmetic.yaml` to match arithmetic
  inside the block.

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

**Cycle protection:**
- `InheritanceBuilder.inProgress` tracks contracts currently being linearized.
  Both `c3Linearize` and `c3LinearizeInternal` consult it; cyclic inheritance
  (`A is B; B is A`) now returns a `cyclic inheritance detected at <name>`
  error and falls back to self-only linearization for that contract instead
  of recursing until the Go stack overflows.
- `c3Merge` carries a `TODO(stage-3)` note: it uses chain-draining in reverse
  list order; canonical C3 (Solidity/CPython) uses forward order with strict
  "no-tail" semantics. Outputs match on non-diamond inheritance; diamond
  cases need test fixtures before the algorithm can safely be replaced. See
  `.vscode/2026-05-08-invariant-audit.md` §1.4.

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

**Stores:** `Function.Calls` field with resolved target information

**Deterministic iteration:** `Build()` now sorts the
source-file map keys before walking, so call-graph construction is
reproducible across runs. Per-file parse failures emit a verbose log
instead of being silently skipped — previously a file with a syntax issue
disappeared from the graph with no diagnostic.

**Assembly opcode coverage:** `classifyAssemblyCall`
recognizes the full security-relevant Yul opcode set:
`create`, `create2`, `log0`–`log4`, `revert`, `return`, in addition to the
existing `call`, `delegatecall`, `staticcall`, `sstore`, `sload`,
`selfdestruct`. Factory patterns (`create2`) and event-via-asm
(`log0`–`log4`) are now reachable from templates.

## Build Flow

```
Sources → Parse → AST Trees → Selectors → Inheritance → Call Graph → Entry Points → Database
```

## Integration Points

**Input:** `[]*types.SourceFile` from reader
**Output:** `*types.Database` for engine
