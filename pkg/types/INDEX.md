# pkg/types - Core Data Structures

## Purpose

Defines all core data structures used throughout the codebase.

## Key Files

### database.go
Central database structure.

**Main Type:**
```go
type Database struct {
    ProjectRoot   string
    SourceFiles   map[string]*SourceFile
    Contracts     map[string]*Contract
    MainContracts map[string]*MainContractEntry  // contractID → entry with funcs + linearization
    CallGraph     *CallGraph
}

type MainContractEntry struct {
    EntryFunctions  []string  // resolved entry function IDs
    LinearizedBases []string  // C3 linearization (most derived first)
}
```

**Key Functions:**
- `NewDatabase()` - Create empty database and instantiate `DataFlow`
- `AddContract(contract)` - Add contract with auto-ID generation
- `GetContract(id)` - Get by ID (format: `path#ContractName`)
- `GetContractByID(id)` - Exact O(1) lookup by fully-qualified ID
- `GetContractByName(name)` - Lex-min deterministic match on collisions
- `FindContractsByName(name)` - Returns every contract sharing a name (explicit collision handling)
- `CalculateMainContracts()` - Identify deployable contracts
- `GetStats()` - Database statistics
- `LoadFromJSON(path)` - Load pre-built database from JSON file (for caching) and restore serialized AST parent pointers
- `GetFunctionSource(fn)` - Extract raw Solidity source lines for a function (see source.go)
- `RestoreASTParents()` - Rebuild `ASTNode.Parent` links after JSON round-trips so `inside`, guard, and taint helpers behave the same with `--db`

**Contract lookup hardening:**

Duplicate contract names are common (e.g., `/src/Token.sol#Token` AND
`/test/mocks/Token.sol#Token`). The original `GetContractByName` returned
the first map iteration match — non-deterministic across runs. The new
implementation collects every candidate and returns the one with the
lex-min fully-qualified ID; ambiguities emit a verbose log. Prefer
`GetContractByID` whenever the caller already has an ID — it's O(1) and
unambiguous. Use `FindContractsByName` when you need to handle the
collision explicitly.

**ID Formats:**
- Contract ID: `absPath#ContractName`
- Function ID: `absPath#ContractName.functionSelector`

### source.go
Source extraction helpers added on `*Database`.

**Key Functions:**
```go
// GetFunctionSource returns raw Solidity source for a function (StartLine–EndLine).
// Reads from in-memory Content first; falls back to disk read for cached DBs.
func (db *Database) GetFunctionSource(fn *Function) string

// GetFunctionSourceByName finds by contract+function name and returns (source, *Function).
func (db *Database) GetFunctionSourceByName(contractName, funcName string) (string, *Function)
```

**Lookup chain:**
1. Resolve `fn.ContractName` → `*Contract` → `contract.SourceFile`
2. Check `db.SourceFiles[path].Content` (in-memory, set during build)
3. Fallback: `os.ReadFile(path)` (disk read for JSON-cached databases)

### source_file.go
Source file metadata.

**Main Type:**
```go
type SourceFile struct {
    Path     string
    Content  string
    Checksum string  // SHA256 of content
    Contracts []string
    Imports   []string
    AST       interface{}   // NOT serialized (json:"-")
}
```

> **JSON round-trip caveat** (see `TODO(stage-3)` in `database.go`): the
> raw `SourceFile.AST` carries `json:"-"`, so a `build → JSON → scan --db`
> cycle drops it. `Function.AST` IS serialized, so per-function rules still
> work; only operators that walk the source-file tree are affected.
> Tracked in `.vscode/2026-05-08-invariant-audit.md` §5.9.

### contract.go
Contract representation.

**Main Type:**
```go
type Contract struct {
    ID                string
    Name              string
    Kind              string  // contract|interface|library|abstract
    SourceFile        string
    Functions         []*Function
    StateVars         []*StateVariable
    Structs           []*Struct
    Events            []*Event
    BaseContracts     []string
    LinearizedBases   []string  // C3 linearization (derived-first order)
    InheritanceWeight int
}
```

**LinearizedBases Order:**
- Most derived (current contract) first, most base contract last

**Contract Kinds:**
- `contract` - Regular deployable contract
- `interface` - Interface definition
- `library` - Library
- `abstract` - Abstract contract

### function.go
Function representation.

**Main Type:**
```go
type Function struct {
    Name            string
    ContractName    string
    Visibility      string  // public|external|internal|private
    StateMutability string  // ""(nonpayable)|payable|view|pure
    Modifiers       []string
    Parameters      []*Parameter
    Returns         []*Parameter
    Selector        string  // 4-byte hex (0x12345678)
    Signature       string  // "transfer(address,uint256)"
    AST             *ASTNode
    Calls           []*FunctionCall
    StartLine       int
    EndLine         int
}
```

**Key Methods:**
- `IsEntrypoint()` - Check if public/external
- `GetSelector(structDefs)` - Calculate selector
- `GetSignature(structDefs)` - Generate signature
- `IsAccessControlled(db)` - Detect access-control modifiers, sender/role guards, and recursive internal auth checks. Recognized role-style modifiers include owner/admin/operator/role/guardian/governance/manager/controller/minter/pauser variants.

### ast.go
AST node structure for queries.

**Main Type:**
```go
type ASTNode struct {
    Kind       string  // AST node type
    Name       string
    Value      string
    Children   []*ASTNode
    Parent     *ASTNode
    Attributes map[string]interface{}
    RefKind    string  // parameter|state_var|local_var (for taint)
    StartLine  int
    EndLine    int
}
```

**AST Kinds — Dot-Notation:**

| Category | Kinds |
|----------|-------|
| **Call** | `call.internal`, `call.external`, `call.lowlevel.call`, `call.lowlevel.delegatecall`, `call.lowlevel.staticcall`, `call.builtin.transfer`, `call.builtin.send`, `call.builtin.selfdestruct`, `call.create` |
| **Check** | `check.require`, `check.assert`, `check.revert` |
| **Statement** | `stmt.assign`, `stmt.if`, `stmt.loop`, `stmt.return`, `stmt.emit`, `stmt.try_catch`, `stmt.block`, `stmt.unchecked` |
| **Expression** | `expr.identifier`, `expr.literal`, `expr.binary_op`, `expr.unary_op`, `expr.member_access`, `expr.index_access`, `expr.conditional` |
| **Declaration** | `decl.function`, `decl.contract`, `decl.variable`, `decl.parameter`, `decl.modifier` |
| **Assembly** | `asm.call`, `asm.delegatecall`, `asm.staticcall`, `asm.sstore`, `asm.sload`, `asm.selfdestruct`, `asm.create`, `asm.create2`, `asm.log0`, `asm.log1`, `asm.log2`, `asm.log3`, `asm.log4`, `asm.revert`, `asm.return`, `asm.operation` |

**Semantic Group Functions:**

| Function | Matches | WQL Kind Alias |
|----------|---------|----------------|
| `IsOutgoingCall()` | All calls to external code (reentrancy surface) | `outgoing_call` |
| `IsETHTransfer()` | ETH value transfers only | `eth_transfer` |
| `IsDelegatecall()` | delegatecall operations | `delegatecall` |
| `IsCheck()` | require/assert/revert | `check` |
| `IsGuard()` | require/assert/revert (alias for IsCheck) | `guard`, `guard.require`, `guard.assert`, `guard.revert` |
| `IsTokenCall()` | call.external (pair with `name:` for ERC20/ERC721) | `token_call` |
| `IsAnyCall()` | All call types including internal | `any_call` |
| `IsKnownKind()` | Returns true for any registered AST kind, semantic group, or dotted prefix. Used by `engine.validateKinds` at template-load time | — |

> `IsGuard()` is an alias for `IsCheck()` — enables `kind: guard`, `kind: guard.require`, etc. in WQL templates. `IsTokenCall()` maps to `call.external` for ERC20/ERC721 semantic matching with `kind: token_call`.

> **`selfdestruct` semantic group** unions `call.builtin.selfdestruct`
> (the Solidity-level `selfdestruct(addr)` / `suicide(addr)` builtin) with
> `asm.selfdestruct` (the inline-assembly `selfdestruct` opcode). Templates
> using `kind: selfdestruct` match both forms.

**Closed sets exposed for engine validation:**
- `KnownSemanticGroups` (`map[string]bool`) — every semantic-group name accepted by `matchKind`
- `IsKnownKind(kind string) bool` — used by `engine.validateKinds` to reject `kind:` typos at template-load time. See [`pkg/engine/INDEX.md`](../engine/INDEX.md#templatego) for the load pipeline.


**Traversal Methods:**
- `WalkDescendants(visitor)` - Visit all descendants
- `WalkAncestors(visitor)` - Visit all ancestors
- `AddChild(node)` - Add child node
- `RestoreParents()` - Rebuild parent links recursively after JSON deserialization
- `GetAttribute(key)` / `SetAttribute(key, val)` - Attributes

**Special Attributes:**

| Attribute | Used In | Description |
|-----------|---------|-------------|
| `parent` | `member_access` | Parent expression name (e.g., "tx" for `tx.origin`) |
| `operator` | `binary_op`, `assignment` | Operator string (e.g., "==", "=") |
| `called_signature` | `external_call` | Function selector for low-level calls |
| `call_receiver` | call receiver child | Marks the receiver expression of a member call, e.g. `target` in `target.delegatecall(data)` |
| `call_option` | call option child | Marks `{value:}`, `{gas:}`, or related call option expressions attached to a call node |

### callgraph.go
Call graph structures.

**Main Types:**
```go
type FunctionCall struct {
    CallType         string
    Target           string
    Resolved         bool
    ResolvedContract string
    ResolvedFunction string
    Line             int
}

type CallGraph struct {
    Edges map[string][]*CallEdge
}
```

**Call Types:**

| Category | Types |
|----------|-------|
| Internal | `internal`, `inherited`, `library` |
| External | `external`, `self` |
| Special | `super`, `modifier` |
| Low-level | `lowlevel_call`, `lowlevel_delegate`, `lowlevel_static` |
| ETH Transfer | `transfer_eth` |

## Design Philosophy

- **Immutable IDs** - Contract/function IDs include file path for uniqueness
- **Rich metadata** - Capture all relevant Solidity information
- **Query-friendly** - AST designed for pattern matching
- **JSON serializable** - All types can be marshaled for caching
- **Self-contained** - Each type has helper methods
- **Call type granularity** - Distinguish between different call semantics
