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
    DataFlow      *DataFlowGraph
    Semantics     *SemanticFacts
}

type MainContractEntry struct {
    EntryFunctions  []string  // resolved entry function IDs
    LinearizedBases []string  // C3 linearization (most derived first)
}
```

**Key Functions:**
- `NewDatabase()` - Create empty database and instantiate `DataFlow` and `Semantics`
- `AddContract(contract)` - Add contract with auto-ID generation
- `GetContract(id)` - Get by ID (format: `path#ContractName`)
- `GetContractByID(id)` - Exact O(1) lookup by fully-qualified ID
- `GetContractByName(name)` - Lex-min deterministic match on collisions
- `ResolveContractName(name, fromFile)` - Scope-aware resolution: prefers a
  candidate in the same file, same directory, or one a relative import in
  `fromFile` resolves to, before falling back to lex-min. Used by inheritance and
  internal-call resolution so duplicate names pick the in-scope definition.
- `FindContractsByName(name)` - Returns every contract sharing a name (explicit collision handling)
- `UnresolvedBases()` - Sorted base-contract names referenced in inheritance but absent from the DB (unresolved imports); surfaced by the CLI as "⚠ Unresolved references"
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

When the caller has a *referring* file (the contract whose base or callee is
being resolved), prefer `ResolveContractName(name, fromFile)`: it disambiguates
collisions by scope — same file, then same directory, then a relative import in
`fromFile` that resolves exactly to a candidate — and only falls back to lex-min
when scope is unavailable. C3 linearization (`pkg/builder/inheritance.go`) and
internal-call resolution (`pkg/engine`) use it so a project's real `Token` is not
confused with a `test/mocks/Token`. It is a heuristic, not full import-scope
resolution (remapped imports such as `@openzeppelin/...` are not resolved here).

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

### SourceFile (defined in database.go)
Source file metadata.

**Main Type:**
```go
type SourceFile struct {
    Path     string
    Content  string        // serialized (json:"content,omitempty")
    Checksum string  // SHA256 of content
    Contracts []string
    Imports   []string
    AST       interface{}   // NOT serialized (json:"-"); holds the Phase-1 *ast.SourceUnit
}
```

> The Phase-1 parsed tree is stashed on `AST` and reused by the call-graph phase
> to avoid re-parsing every file. It is not serialized; a database reloaded from
> JSON re-parses from `Content` when the call graph is rebuilt.

> **JSON round-trip behavior:** `Content` IS serialized, so a
> `build → JSON → scan --db` cycle is self-contained — source-text predicates
> (`source_regex`, `scope: source`) reproduce identical findings even when the
> original files are no longer on disk. `Function.AST` is also serialized, so
> per-function rules work after a reload. Only `SourceFile.AST` (the raw
> solast-go file tree) is dropped (`json:"-"`); it does not round-trip through
> JSON and no current operator walks it. The engine still falls back to reading
> a file from disk when `Content` is empty (databases built before content
> serialization) and emits a verbose `WARN` when neither is available, so a
> source-scope scan against a relocated legacy database is loud, not silent.

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
    Selector        string  // canonical signature text, e.g. "transfer(address,uint256)"
    Signature       string  // 4-byte hex of keccak256(Selector), e.g. "a9059cbb"
    AST             *ASTNode
    Calls           []*FunctionCall
    StartLine       int
    EndLine         int
}
```

> **Naming caveat:** these field names are inverted relative to common industry
> usage, where "selector" means the 4-byte hash and "signature" the text form.
> Here `Selector` holds the canonical *text* and `Signature` the 4-byte *hash*.
> The names are kept for JSON/back-compat stability; see the field comments in
> `function.go`.

**Key Methods:**
- `IsEntrypoint()` - true for public/external functions that are not view/pure and not the constructor
- `GetSelector(structDefs)` - Calculate canonical signature text (with struct→tuple resolution)
- `GetSignature(structDefs)` - Generate the 4-byte hash
- `IsAccessControlled(db)` - Detect **privileged** access control: auth modifiers, recursive internal auth checks, and caller-identity guards. Recognized role-style modifiers include owner/admin/operator/role/guardian/governance/manager/controller/minter/pauser variants. When a modifier name matches the auth pattern, the helper additionally validates the modifier's **body** — resolving the definition through the contract's linearized bases and requiring at least one auth-shaped signal (a guard, an `if`/ternary, or a `msg.sender`/`tx.origin` reference) before trusting the name. This catches the empty-decoy bypass (`modifier auth() { _; }`) while preserving compatibility with synthetic tests where no body is available (falls back to trusting the name when the definition can't be resolved). The internal-auth-call fallback recognizes verb+noun helper names — a guard verb (`check`/`require`/`verify`/`validate`/`enforce`) followed by an auth noun (`owner`/`auth`/`admin`/`role`/`sender`/`access`/`permission`), joined directly or by underscores — so both camelCase (`_checkOwner`) and snake_case (`_check_owner`) helpers match.
  - **Caller-identity guard rule (storage-anchored):** a comparison of a caller identity (`msg.sender`/`tx.origin`/`_msgSender()`) counts as access control **only** when the other operand is something the caller cannot control — a state variable, a state-reading getter (`owner()`, `ownerOf(id)`, `hasRole(...)`), a state mapping/struct, an immutable, a constant, `address(this)`, or a **hardcoded literal address** (`require(msg.sender == 0xAbC…)`). Comparing against a **function argument** (or an argument-derived local) is *self-authorization*, not a privileged gate, and does NOT count — e.g. `require(from == msg.sender)` where `from` is a parameter is permissionless. Provenance is read from the AST node's `RefKind` (`parameter`/`state_var`/`local_var`) and `TaintSources` (a local is caller-controlled only when tainted solely from `parameter`), with the function's parameter set as a backstop. `_msgSender()` (all forms, including custom calldata-decoding overrides) is accepted as a caller-identity source; an insecure custom `_msgSender()` is a separate concern for a WQL template, not this heuristic.
- `ComparesCallerIdentity()` - Detect caller **self-scoping**: a caller identity compared (inside a guard/condition) against any operand, *including a function argument* (`require(from == msg.sender)`, `if (from != msg.sender) revert`, `assert(request.from == msg.sender)`). This is NOT privileged access control — it binds a sensitive value to the caller ("you can only act on your own behalf"). Used by detectors (e.g. arbitrary `transferFrom`, the `unCheckedSender` preset) that treat self-scoping as a valid mitigation. Keep distinct from `IsAccessControlled` so entry-point classification still treats self-scoped functions as permissionless.

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
| `type` / `type_kind` / `type_confidence` | typed expressions | Lightweight inferred type facts on identifiers, casts, index expressions, member accesses, and cast calls |
| `receiver_type` / `receiver_type_kind` | calls | Inferred member-call receiver type used for type-aware classification; available to WQL through `attr` |

### semantic.go
Lightweight semantic facts serialized with the database.

**Main Types:**
```go
type TypeInfo struct {
    Name        string // e.g. address, IERC20, mapping(address => uint256)
    BaseName    string // storage/payable/array-normalized base
    Kind        string // primitive, contract, interface, library, abstract, struct, array, mapping, unknown
    ContractID  string
    IsAddress   bool
    IsPayable   bool
    Confidence  string // high, medium, low
    Source      string // parameter, state_var, local_var, type_cast, builtin, ...
    ElementType string // array element type (when Kind == array)
    KeyType     string // mapping key type   (when Kind == mapping)
    ValueType   string // mapping value type (when Kind == mapping)
}

type SemanticFacts struct {
    Symbols         map[string]*SemanticSymbol   // RefID -> symbol fact
    FunctionEffects map[string]*FunctionEffects  // function ID -> effects
}

// Per-function analysis facts (builder Phase 7), consumed by the report layer.
type FunctionEffects struct {
    StateWrites []StateWrite // state vars written directly
    Guards      []Guard      // require/assert/revert + if conditions, in order
    Auth        AuthInfo     // modifiers, msg.sender checks, tx.origin, controlled?
}
type StateWrite struct { Var, Kind string; Line int }   // kind: assign|compound|delete|sstore
type Guard      struct { Kind, Expr string; Line int }   // kind: require|assert|revert|if
type AuthInfo   struct { Modifiers, SenderChecks []string; UsesTxOrigin, Controlled bool }
```

`SetFunctionEffects` / `GetFunctionEffects` access the map by function ID
(`MakeFunctionID(sourceFile, contract, selector)`). These facts serialize into
`corpus/database.json` and power `state-changes.md` and the per-entry workflow
files. (WQL exposure of these facts is intentionally out of scope for now.)

**What is inferred today:**
- Function parameters, state variables, and local declarations
- Simple local assignment propagation from typed expressions and casts
- User-defined type/interface/contract casts such as `IERC20(token)`
- Builtin address facts such as `msg.sender`, `tx.origin`, and `msg.value`
- Member-call receiver facts, e.g. `receiver_type_kind: interface`
- Per-function effects: state writes, guards, and access control (`FunctionEffects`)

These facts are intentionally an MVP semantic layer, not a full solc-compatible
type checker. Unknown or complex types remain low-confidence and classification
falls back to existing heuristics.

### callgraph.go
Call graph structures.

**Main Types:**
```go
// FunctionCall is defined in function.go (records one call site, used by
// Function.Calls and Modifier.Calls).
type FunctionCall struct {
    Target           string
    ContractName     string
    ResolvedContract string
    ResolvedFunction string
    Signature        string       // 4-byte selector, when applicable
    CallType         CallType
    TargetKind       ContractKind
    Line             int
    Resolved         bool
    ArgCount         int          // -1 means unknown (old JSON)
}

type CallGraph struct {
    Edges    []*CallEdge          // serialized
    outgoing map[string][]*CallEdge // caller -> callees (rebuilt via EnsureIndex)
    incoming map[string][]*CallEdge // callee -> callers (rebuilt via EnsureIndex)
}
```

> `outgoing`/`incoming` are unexported and not serialized; after loading a
> database from JSON, call `CallGraph.EnsureIndex()` before using
> `GetCallees`/`GetCallers`.

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
