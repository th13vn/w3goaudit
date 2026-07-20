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
    ScanTarget    string
    Diagnostics   []Diagnostic
    SourceFiles   map[string]*SourceFile
    Contracts     map[string]*Contract
    MainContracts map[string]*MainContractEntry  // contractID → entry with funcs + linearization
    CallGraph     *CallGraph
    DataFlow      *DataFlowGraph
    Semantics     *SemanticFacts
}

type MainContractEntry struct {
    EntryFunctions    []string  // resolved entry function IDs
    LinearizedBases   []string  // compatibility/display names, derived first
    LinearizedBaseIDs []string  // exact file#Contract C3 identities
}
```

**Key Functions:**
- `NewDatabase()` - Create empty database and instantiate `DataFlow` and `Semantics`
- `NewDatabaseWithOptions(DatabaseOptions{Logger})` - Create a database with scan-local logging
- `AddContract(contract)` - Add contract with auto-ID generation
- `GetContract(id)` - Get by ID (format: `path#ContractName`)
- `GetContractByID(id)` - Exact O(1) lookup by fully-qualified ID
- `GetContractByName(name)` - Lex-min deterministic match on collisions
- `ResolveContractName(name, fromFile)` - Scope-aware resolution: prefers a
  candidate in the same file, same directory, or one a relative import in
  `fromFile` resolves to, before falling back to lex-min. Used by inheritance and
  internal-call resolution so duplicate names pick the in-scope definition.
- `ResolveContractNameExact(name, fromFile)` - Source-scoped exact search over
  same-file declarations, structured named/namespace aliases, canonical direct
  imports, and legacy relative provenance; returns `(nil, false)` rather than
  guessing.
- `ResolveContractNameExactWithStatus(name, fromFile)` - Additive diagnostic
  view distinguishing resolved, missing, ambiguous, and missing imported
  binding states while preserving the historical bool-returning method.
- `LinearizedContracts(contract)` - Returns exact contract objects in C3 order
  from `LinearizedBaseIDs`; old schema-2.0.0 caches without IDs use exact self
  plus source-scoped name fallback. The lookup is read-only and never appends
  diagnostics while reports/navigation consume the database.
- `FindContractsByName(name)` - Returns every contract sharing a name (explicit collision handling)
- `UnresolvedBases()` - Sorted base-contract names referenced in inheritance but absent from the DB (unresolved imports); surfaced by the CLI as "⚠ Unresolved references"
- `CalculateMainContracts()` - Identify deployable contracts
- `GetStats()` - Database statistics
- `LoadFromJSON(path)` - Load pre-built database from JSON file (for caching) and restore serialized AST parent pointers
- `LoadFromJSONWithOptions(path, LoadOptions{Logger})` - Load a cache with scan-local logging retained for later database lookups
- `GetFunctionSource(fn)` - Extract raw Solidity source lines for a function (see source.go)
- `RestoreASTParents()` - Rebuild `ASTNode.Parent` links after JSON round-trips so `inside`, guard, and taint helpers behave the same with `--db`
- `AddDiagnostic(diagnostic)` - Append a durable structured analysis-quality record
- `NormalizeDiagnostics()` - Record every unresolved legacy name-only MRO entry
  before reporting, deduplicate exact records, and sort by the stable serialized total order
- `AnalysisComplete()` - False when any diagnostic records known incomplete analysis

### diagnostic.go

Durable analysis-quality diagnostics shared by reader, builder, cache loading,
and later report/CLI surfaces. `Diagnostic` carries a stable code, severity,
phase, message, optional file/line/import/symbol context, and an `Incomplete`
flag. These are distinct from security findings: they explain what source or
semantic coverage the analyzer could not establish.

Stable codes include `import.unresolved`, `parse.skipped`, `parse.recovered`,
`inheritance.base_unresolved`, `location.invalid`, `identity.unresolved`, and
`analysis.semantic_unsupported`. The semantic code records an exact AST shape
that the internal lowering layer could not model and marks analysis incomplete.
`SortDiagnostics` orders records by severity, code, file, line, import path,
symbol, message, then deterministic tie-breakers. `Database.NormalizeDiagnostics`
also removes records identical across every serialized field. Cache loading
calls normalization after legacy field backfills, so every name-only MRO entry
that is missing, binding-missing, or ambiguous produces an incomplete
`identity.unresolved` before any read-only `LinearizedContracts` caller builds
summaries, navigation, or reports.

`Database.ScanTarget` persists the original source file/directory separately
from `ProjectRoot`. Both it and `Diagnostics` are additive JSON fields, so old
cache files load with an empty target and diagnostic collection.

**Contract lookup hardening:**

**Logging:** the database stores an unexported, non-serialized logger. Builder
and cache-load option constructors inject it, so ambiguity/fallback diagnostics
stay in the owning scan's log after construction or JSON load. Legacy
constructors still use the deprecated package-global writer.

Duplicate contract names are common (e.g., `/src/Token.sol#Token` AND
`/test/mocks/Token.sol#Token`). The original `GetContractByName` returned
the first map iteration match — non-deterministic across runs. The new
implementation collects every candidate and returns the one with the
lex-min fully-qualified ID; ambiguities emit a verbose log. Prefer
`GetContractByID` whenever the caller already has an ID — it's O(1) and
unambiguous. Use `FindContractsByName` when you need to handle the
collision explicitly.

`ResolveContractName(name, fromFile)` remains a deterministic compatibility
helper for callers that knowingly accept name-only fallback (same file,
same-directory/relative-import hints, then lex-min). Identity-sensitive C3,
call-graph, engine, report, navigation, workflow/state, and extract paths use
exact objects, `ResolveContractNameExact`, `ResolvedContractID`, and
`LinearizedBaseIDs` instead.

Identity-sensitive code uses `ResolveContractNameExact` instead: it never turns
an unresolved collision into a plausible but wrong contract. The builder emits
`identity.unresolved` only when an AST/type/base identity genuinely cannot be
mapped to one exact contract; dynamic/low-level external calls are expected to
remain unresolved and do not produce this diagnostic.

`ResolveContractNameExact` checks the caller's structured
`SourceFile.ImportBindings` and canonical `ResolvedImports` before any
compatibility fallback. `import {Base as Parent}` maps only `Parent` to the
exact imported `Base`, while `import * as V` maps only `V.Base`; aliases do not
expose the original bare symbol. A direct `../vendor/Token.sol`
or a remapped dependency wins over an unrelated `src/Token.sol` beside the
caller. Older caches without provenance reconstruct only relative raw imports,
and otherwise remain ambiguous; exact resolution never uses directory proximity.

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
1. Use `fn.SourceFile` (recorded at build time) — unambiguous under name
   collisions. Only fall back to resolving `fn.ContractName` → `*Contract` →
   `contract.SourceFile` for databases built before `SourceFile` existed.
2. Check `db.SourceFiles[path].Content` (in-memory, set during build)
3. Fallback: `os.ReadFile(path)` (disk read for JSON-cached databases)

> `Function.SourceFile` is the absolute path of the defining file, stamped by
> the builder. Prefer it over name-based contract resolution for any per-function
> file lookup. `DataFlowGraph.GetSourcesFor`/`GetDestinationsFor` call
> `EnsureIndex()` so the adjacency maps are rebuilt after a `--db` round-trip
> (they are unexported and lost during JSON serialization), mirroring `CallGraph`.

When loading legacy caches where nested `Function.SourceFile` is absent,
`LoadFromJSON` backfills it from the exact owning `Contract.SourceFile` object.
It never re-resolves the contract by short name, so duplicate contract names
remain separated.

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
    ResolvedImports []string // canonical files actually selected by reader
    ImportBindings []ImportBinding // occurrence-level exact path + aliases
    AST       interface{}   // NOT serialized (json:"-"); holds the Phase-1 *ast.SourceUnit
}
```

`ImportBinding{ImportPath, ResolvedFile, UnitAlias, Symbols}` is additive JSON.
Each `ImportSymbolBinding{Symbol, Alias}` preserves one named import. Older
caches without the field retain the strict direct-import fallback.

> The Phase-1 parsed tree is stashed on `AST` and reused by the call-graph phase
> to avoid re-parsing every file. It is not serialized; a database reloaded from
> JSON re-parses from `Content` when the call graph is rebuilt.

> **JSON round-trip behavior:** `Content` IS serialized, so a
> `build → JSON → scan --db` cycle is self-contained — source-text predicates
> (`regex`, `scope: source`) reproduce identical findings even when the
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
    LinearizedBases   []string  // compatibility/display C3 names
    LinearizedBaseIDs []string  // exact derived-first file#Contract IDs
    InheritanceWeight int
    StartLine, EndLine, StartCol, EndCol, StartByte, EndByte int  // see ast.go note above
}
```

**LinearizedBases Order:**
- Most derived (current contract) first, most base contract last
- `LinearizedBaseIDs` has the same order for every resolvable contract and is
  canonical for identity-sensitive consumers. `LinearizedBases` remains for
  schema-2.0.0 compatibility and human-readable output.
- For legacy caches without exact IDs, `Database.LinearizedContracts` uses
  strict source-scoped resolution. Ambiguous bases are omitted and record one
  `identity.unresolved`; it never calls the lexicographic compatibility lookup.

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
    StartCol        int  // 1-based Unicode-code-point column of StartLine
    EndCol          int  // 1-based Unicode-code-point column of EndLine
    StartByte       int  // 0-based UTF-8 byte offset into the source file
    EndByte         int  // 0-based UTF-8 byte offset into the source file
}
```

> **Precise locations (v0.4):** `StartCol`/`EndCol`/`StartByte`/`EndByte` are new
> alongside the pre-existing `StartLine`/`EndLine`. Columns are 1-based
> Unicode-code-point counts; byte offsets are 0-based UTF-8 offsets into the
> source file's `Content`, with half-open `[start, end)` ranges. All four are
> zero only for synthetic nodes with no source counterpart. Engine declaration
> clones, including `decl.contract` roots, copy the exact stored declaration
> spans instead of guessing them from source text.
> The same six fields (`StartLine/EndLine/StartCol/EndCol/StartByte/EndByte`)
> also exist on `Modifier`, `Contract`, `StateVariable`, `Event`, `Struct`,
> `Enum`, and `Parameter` (declared in `contract.go`/`function.go`) — not
> repeated verbatim below. They are populated by the builder via
> `pkg/builder/location.go`'s cached `sourceLocator`; see
> [`pkg/builder/INDEX.md`](../builder/INDEX.md#locationgo).

> **Naming caveat:** these field names are inverted relative to common industry
> usage, where "selector" means the 4-byte hash and "signature" the text form.
> Here `Selector` holds the canonical *text* and `Signature` the 4-byte *hash*.
> The names are kept for JSON/back-compat stability; see the field comments in
> `function.go`.

**Key Methods:**
- `IsEntrypoint()` - true for public/external functions that are not view/pure and not the constructor
- `GetSelector(structDefs)` - Calculate canonical signature text (with struct→tuple resolution)
- `GetSignature(structDefs)` - Generate the 4-byte hash
- `IsAccessControlled(db)` - Detect **privileged** access control from exact
  bodies and call-site bindings. Modifier and helper names are descriptive only:
  applied modifiers require a resolved `CallTypeModifier` target, internal
  helpers require a resolved exact contract ID plus full selector, and their
  actual AST or recursive behavior must prove caller authorization. Modifier
  invocation argument ASTs bind guarded parameters to expressions such as
  `isOperator[msg.sender]`. The recursive analysis uses a per-call recursion
  stack and memo keyed by exact body identity plus sorted forwarded-caller,
  authorization-boolean, and fixed-operand parameter sets, so one binding
  context cannot suppress another. Recursive internal calls bind arguments from
  the one AST call site matching exact recorded line/byte metadata, then
  propagate all three sets into the exact resolved callee; same-name call sites
  are never merged.
  Authorization is polarity-aware and enforcement-positive: normal execution
  must require the predicate to be true through `require`/`assert`, or require
  it through an equivalent failing `if (...) revert` branch. Observational
  `if` statements and `require(allowed == false)` do not authorize. Standard
  `hasRole(FIXED_ROLE, caller)` checks require a direct or forwarded caller and
  a contract-fixed role operand. The `hasRole` AST call must correlate to one
  exact resolved internal call whose concrete body returns membership from an
  access mapping under the same fixed-role/caller bindings. Unresolved,
  ambiguous, external, bodyless, or decoy implementations fail closed. Nested
  access mappings require exactly one caller-identity selector and every other
  key to be fixed. No package-global auth cache is used.
  - **Caller-identity guard rule (storage-anchored):** a comparison of a caller identity (`msg.sender`/`tx.origin`/`_msgSender()`) counts as access control **only** when the other operand is a **contract-fixed authority** the caller cannot control — a state variable, a fixed getter (`owner()`, `getOwner()`), a role check (`hasRole(ROLE, msg.sender)`), a state mapping/struct, an immutable, a constant, `address(this)`, or a **hardcoded literal address** (`require(msg.sender == 0xAbC…)`). Comparing against a **function argument** (or an argument-derived local) is *self-authorization*, not a privileged gate, and does NOT count — e.g. `require(from == msg.sender)` where `from` is a parameter is permissionless. Provenance is read from the AST node's `RefKind` (`parameter`/`state_var`/`local_var`) and `TaintSources` (a local is caller-controlled only when tainted solely from `parameter`), with the function's parameter set as a backstop. `_msgSender()` is accepted only as an exact zero-argument `call.internal` whose recorded metadata, when present, is internal/inherited/super with selector `_msgSender()`. Database resolution becomes authoritative only after it identifies the exact owning contract/MRO: a resolved owner with no zero-parameter helper, or only a nonzero overload, disproves caller identity. A non-nil empty or unresolvable database is unavailable context, so the exact synthetic zero-argument internal-call compatibility shape remains valid. Same-named state/local/parameter identifiers and external/self/unresolved calls remain ordinary values.
    - **Exact owner availability:** when `Function.SourceFile` is present, only the exact `SourceFile#ContractName` database ID makes resolution authoritative. A unique same-named contract in another file is unavailable context and cannot disprove the synthetic compatibility shape.
    - **Privileged access control vs. owner-of-item check:** these are distinct and must not be conflated. `msg.sender == owner()` / `hasRole(ROLE, msg.sender)` gate to a **contract-fixed principal** → access control. `ownerOf(tokenId) == msg.sender` only asserts *"you own the item you named"* — a getter the **caller indexes with a resource id of their own choosing** → **item-ownership self-scoping**, the NFT analogue of `require(from == msg.sender)`. It does NOT restrict *who* can call (anyone holding some token qualifies), so it is treated as caller-controlled (`getterIsResourceScoped`) and does **not** count toward `IsAccessControlled`. It belongs to `ComparesCallerIdentity` instead.
    - **Getter vs. type-cast operand:** the authority operand is unwrapped only for genuine *type casts* (`address(x)`, `payable(x)`, `uintN`/`bytesN`, …, via `isTypeCastName`). A single-argument call to a non-type callee is a **getter, not a cast** — `ownerOf(tokenId)` is kept intact (then classified as resource-scoped per above) rather than collapsed to its `tokenId` argument.
    - **Forwarded caller identity (interprocedural):** when the recursive descent follows an internal call, parameters bound to a caller-identity argument at the call site (`_withdraw(msg.sender, …)`) are tracked (`forwardedCallerParams`) and treated as caller-identity sources inside the callee. A forwarded caller compared to a **contract-fixed authority** (`owner() == caller`) counts as access control; compared to a **caller-selected resource getter** (`ownerOf(tokenId) != caller`) it is self-scoping (see `ComparesCallerIdentity`), not access control. Privileged access-control descent requires exact resolved contract and selector metadata; self-scoping retains its documented legacy/synthetic compatibility resolver.
- `ComparesCallerIdentity(databases ...*Database)` - Detect caller **self-scoping**: a caller identity compared (inside a guard/condition) against any operand – `require(from == msg.sender)`, `if (from != msg.sender) revert`, and **item-ownership** scopes like `ownerOf(tokenId) == msg.sender`. **Interprocedural:** it follows the same forwarded-caller-identity descent as `IsAccessControlled` (`resolveInternalCallee` + `forwardedCallerParams`), so an entry point that forwards `msg.sender` into a helper which checks `ownerOf(tokenId) != caller` is recognized. This is NOT privileged access control – it binds the action to the caller's own resource ("you can only act on your own behalf/asset"). The canonical `caller_checked` preset treats this self-scoping as a valid mitigation for arbitrary `transferFrom` and arbitrary-send-ETH detectors. Keep it distinct from `IsAccessControlled` so entry-point classification still treats self-scoped functions as permissionless. The first non-nil database enables exact recursive resolution; the zero-argument call remains compatible.
- `UniqueID(structDefs)` hashes the exact `MakeFunctionID(SourceFile, ContractName, selector)` identity; selector-less declarations fall back to their function name. Legacy/synthetic functions without `SourceFile` retain the old short-name-compatible behavior.

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
    StartCol   int  // 1-based Unicode-code-point column of StartLine
    EndCol     int  // 1-based Unicode-code-point column of EndLine
    StartByte  int  // 0-based UTF-8 byte offset into the source file
    EndByte    int  // 0-based UTF-8 byte offset into the source file
}
```

> **Interior-node locations (v0.4):** `StartCol`/`EndCol`/`StartByte`/`EndByte`
> are populated on interior AST nodes too, not just function/modifier roots —
> every statement and expression built via the `pkg/builder` dispatch
> wrappers (`buildStatement`, `buildExpression`, `buildAssemblyOperation`,
> `buildAssemblyCall`, `buildInlineAssembly`) carries a real span sourced from
> solast-go's `Loc`/`Range`. Zero on synthetic nodes (no source counterpart).
> See [`pkg/builder/INDEX.md`](../builder/INDEX.md#locationgo) for the
> chokepoint mechanism.

**AST Kinds — Dot-Notation:**

| Category | Kinds |
|----------|-------|
| **Call** | `call.internal`, `call.external`, `call.lowlevel.call`, `call.lowlevel.delegatecall`, `call.lowlevel.staticcall`, `call.builtin.transfer`, `call.builtin.send`, `call.builtin.selfdestruct`, `call.create` |
| **Check** | `check.require`, `check.assert`, `check.revert` |
| **Statement** | `stmt.assign`, `stmt.state_mutation`, `stmt.if`, `stmt.loop`, `stmt.return`, `stmt.emit`, `stmt.try_catch`, `stmt.block`, `stmt.unchecked` |
| **Expression** | `expr.identifier`, `expr.literal`, `expr.binary_op`, `expr.unary_op`, `expr.member_access`, `expr.index_access`, `expr.conditional` |
| **Declaration** | `decl.function`, `decl.contract`, `decl.variable`, `decl.parameter`, `decl.modifier` |
| **Assembly** | `asm.call`, `asm.delegatecall`, `asm.staticcall`, `asm.sstore`, `asm.sload`, `asm.selfdestruct`, `asm.create`, `asm.create2`, `asm.log0`, `asm.log1`, `asm.log2`, `asm.log3`, `asm.log4`, `asm.revert`, `asm.return`, `asm.operation` |

> **Synthetic contract ASTs:** persisted function ASTs are rooted at
> `decl.function`. The engine creates synthetic `decl.contract` roots at
> contract scopes (`main_contract`, `all_contract`, `contract`, `library`,
> `abstract`). Each root carries the exact contract declaration span and source
> file. Its exact-MRO children include active functions deduplicated by
> canonical selector, state-variable and modifier declarations, and function,
> return, or modifier parameter declarations tagged by `parameter_role`. Every
> inherited declaration retains its exact owning source file and stored span.
> These trees are execution context for WQL and are not persisted as
> source-file ASTs in the database.

**Semantic Group Functions:**

| Function | Matches | WQL Kind Alias |
|----------|---------|----------------|
| `IsOutgoingCall()` | All calls to external code (reentrancy surface) | `outgoing_call` |
| `IsETHTransfer()` | ETH value transfers only | `eth_transfer` |
| `IsDelegatecall()` | delegatecall operations | `delegatecall` |
| `IsCheck()` | require/assert/revert | `check` |
| `IsGuard()` | require/assert/revert (alias for IsCheck) | `guard`, `guard.require`, `guard.assert`, `guard.revert` |
| `IsTokenCall()` | call.external (pair with `name:` for ERC20/ERC721) | `external_call` plus `name:` |
| `IsAnyCall()` | All call types including internal | `any_call` |
| `IsKnownKind()` | Returns true for any registered AST kind, semantic group, or dotted prefix. Used by `engine.validateKinds` at template-load time | — |

> `IsGuard()` is an alias for `IsCheck()` and backs public `block: guard`,
> `block: require`, `block: assert`, and `block: revert`. `IsTokenCall()` is an
> evaluator helper; public ERC20/ERC721 matching uses `block: external_call`
> plus `name:`.

> **`selfdestruct` semantic group** unions `call.builtin.selfdestruct`
> (the Solidity-level `selfdestruct(addr)` / `suicide(addr)` builtin) with
> `asm.selfdestruct` (the inline-assembly `selfdestruct` opcode). Templates
> using `block: selfdestruct` match both forms.

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
| `operator` | `binary_op`, `assignment`, `state_mutation`, `unary_op` | Operator string (for example, `==`, `=`, `push`, `pop`, `delete`, `++`, `--`) |
| `is_state_var` | `assignment`, `state_mutation` | True when the write target is a directly identified state variable or one of its indexed/member descendants |
| `called_signature` | `external_call` | Function selector for low-level calls |
| `call_receiver` | call receiver child | Marks the receiver expression of a member call, e.g. `target` in `target.delegatecall(data)` |
| `receiver_name` | member call node | Name of the direct tagged receiver child when available; nested argument/call-option receivers do not affect it |
| `call_option` | call option child | Marks `{value:}`, `{gas:}`, or related call option expressions attached to a call node |
| `type` / `type_kind` / `type_confidence` | typed expressions | Lightweight inferred type facts on identifiers, casts, index expressions, member accesses, and cast calls |
| `data_location` | identifiers | Raw Solidity `storage`/`memory`/`calldata` location retained privately by the builder and mirrored when present |
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
type StateWrite struct { Var, Kind string; Line int }   // kind: assign|compound|push|pop|delete|increment|decrement|sstore
type Guard      struct { Kind, Expr string; Line int }   // kind: require|assert|revert|if
type AuthInfo   struct { Modifiers, SenderChecks []string; UsesTxOrigin, Controlled bool }
```

`AuthInfo.Modifiers` is descriptive. `AuthInfo.Controlled` is true only when
`Function.IsAccessControlled(db)` proves privileged access from exact modifier
bodies, inline caller checks, or recursively resolved internal auth helpers.

`SetFunctionEffects` / `GetFunctionEffects` access the map by function ID
(`MakeFunctionID(sourceFile, contract, selector)`). These facts serialize into
`data/database.json` and power `state-changes.md` and the per-entry workflow
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
    ResolvedContractID string      // exact file#Contract identity
    ResolvedFunction string
    Signature        string       // 4-byte selector, when applicable
    CallType         CallType
    TargetKind       ContractKind
    Line             int
    Col              int          // 1-based Unicode-code-point column (v0.4)
    Byte             int          // 0-based UTF-8 byte offset (v0.4)
    Resolved         bool
    ArgCount         int          // -1 means absent/unknown legacy JSON; 0 is real
    Arguments        []*ASTNode   // detached modifier call-site arguments, when recorded
}

// CallEdge (callgraph.go) carries the same ResolvedContractID and Col/Byte
// fields as FunctionCall, sourced from the same resolved target/call site.
type CallGraph struct {
    Edges    []*CallEdge          // serialized
    outgoing map[string][]*CallEdge // caller -> callees (rebuilt via EnsureIndex)
    incoming map[string][]*CallEdge // callee -> callers (rebuilt via EnsureIndex)
}
```

> `outgoing`/`incoming` are unexported and not serialized; after loading a
> database from JSON, call `CallGraph.EnsureIndex()` before using
> `GetCallees`/`GetCallers`.

`ResolvedContract` remains the short display/compatibility name.
`ResolvedContractID` is additive JSON (`resolvedContractId`) and is populated
only when the resolver has one exact contract object. Older schema-2.0.0 cache
files load with it empty and retain their existing name fields.

Builder calls with known parsed arguments do not use a unique-name fallback
when no declaration has the observed arity. Their call and edge remain
unresolved with empty exact target fields, and one durable
`identity.unresolved` diagnostic records the target name and arity.

`FunctionCall` uses presence-aware JSON decoding for `argCount`. Legacy cache
objects with no field load as `-1`; newly serialized zero-argument calls always
emit `"argCount": 0`, and repeated JSON round trips preserve zero.

Resolved modifier invocations additionally serialize simplified argument ASTs
in `FunctionCall.Arguments`. `Database.RestoreASTParents` restores these trees
after cache loading so source and `--db` access-control analysis agree.

**Call Types:**

| Category | Types |
|----------|-------|
| Internal | `internal`, `inherited`, `library` |
| External | `external`, `self` |
| Special | `super`, `modifier` |
| Low-level | `lowlevel_call`, `lowlevel_delegate`, `lowlevel_static` |
| ETH Transfer | `transfer_eth` |

## Design Philosophy

`ResolveContractNameExact` accepts a sole global candidate only without source
context; a non-empty referring file still requires same-file or import
provenance. `ComparesCallerIdentity(db ...*Database)` preserves the historical
zero-argument SDK call and uses the first non-nil database for exact recursive
analysis.

- **Immutable IDs** - Contract/function IDs include file path for uniqueness
- **Rich metadata** - Capture all relevant Solidity information
- **Query-friendly** - AST designed for pattern matching
- **JSON serializable** - All types can be marshaled for caching
- **Self-contained** - Each type has helper methods
- **Call type granularity** - Distinguish between different call semantics
