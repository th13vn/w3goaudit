# Extension Output — `nav.json` + `explorer.json` + `xref.json`

Every scan's result folder (see [Result Folder Layout](./usage.md#result-folder-layout))
writes three additional files under `data/` alongside `manifest.json`,
`database.json`, `findings.json`, `overview.json`, and `diagnostics.json`:

- **`data/nav.json`** — a flat, symbol-level navigation index: every
  declaration in the database, the reverse call graph, and
  interface→implementation edges. Built by `report.BuildNavJSON` (`pkg/report/nav.go`).
- **`data/explorer.json`** — a per-deployable-contract model: ordered
  constants/storage variables and entry/getter functions. Built by
  `report.BuildExplorerJSON` (`pkg/report/explorer.go`).
- **`data/xref.json`** — a precise, type-resolved cross-reference index
  (`declarations[]` + `references[]`) for regex-free go-to-definition and
  find-references. Built by `report.BuildXrefJSON` (`pkg/report/xref.go`).

All three are written by `report.WriteBundle` in the same step as
`manifest.json`, and are indexed in `manifest.json` under `files.data.nav` /
`files.data.explorer` / `files.data.xref`. They exist to let a **static
consumer** — the w3goaudit VSCode extension, an LSP-like navigation panel, or
any other downstream tool — build jump-to-definition, find-references,
"who calls this", and a per-contract explorer tree **without re-parsing
Solidity**. They are read directly off disk; nothing here requires the CLI to
run a server.

All three documents share a `schemaVersion` field, currently `"2.0.0"`
(`report.SchemaVersion`), the same version used by `overview.json` /
`findings.json`. Consumers should refuse to parse on a major-version
mismatch, per the general JSON versioning policy (see
[`docs/usage.md`](./usage.md)).

## Shared: `SrcRange`

Every location in all three files uses the same shape:

```jsonc
{
  "file": "/abs/or/project-relative/path/Token.sol",
  "startLine": 12,   // 1-based
  "startCol": 5,     // 1-based
  "endLine": 12,
  "endCol": 42,
  "startByte": 301,  // 0-based byte offset into the file
  "endByte": 338
}
```

- Line and column are **1-based Unicode-code-point positions** (line 1, col 1 is the
  first character of the file). The range is **half-open**: `startCol` is the
  column of the first character, `endCol` is the column just *past* the last
  character (so `endCol - startCol` is the code-point width on a single line).
  This matches SARIF when the run declares `columnKind: unicodeCodePoints`.
  It does **not** directly match LSP: LSP lines/characters are zero-based and
  default to UTF-16 code units unless a negotiated position encoding says
  otherwise.
- `startByte`/`endByte` are **0-based**, half-open **UTF-8 byte** offsets into
  the source file — raw byte offsets, **not** character/code-point offsets (they
  differ once non-ASCII appears). Useful for exact substring extraction or
  diffing across edits without re-tokenizing. Do not feed them to a consumer
  expecting character offsets (e.g. SARIF `charOffset`) without converting.
- Fields are `omitempty`: a synthetic or location-less declaration (e.g. a
  compiler-injected node) may emit a partial or empty range rather than
  zeros that look like "line 0, col 0".

## `data/nav.json`

```jsonc
{
  "schemaVersion": "2.0.0",
  "symbols": [ /* NavSymbol[] */ ],
  "callers": [ /* NavCaller[], omitempty */ ],
  "interfaceImpl": [ /* NavInterfaceImpl[], omitempty */ ]
}
```

### `symbols[]`

One entry per navigable declaration in the database — **every** contract in
scope, not just deployable/main contracts (contrast with `explorer.json`
below, which is main-contracts-only).

```jsonc
{
  "id": "/src/Token.sol#Token.transfer(address,uint256)",
  "kind": "function",       // "contract" | "function" | "stateVar"
  "name": "transfer",
  "selector": "transfer(address,uint256)",  // functions only, omitempty
  "range": { "...": "SrcRange" }
}
```

- **`kind: "contract"`** — one per `Contract` in the database (main
  contracts, libraries, interfaces, abstract contracts all included).
- **`kind: "function"`** — one per function declared directly on a
  contract (not flattened across inheritance; a derived contract's nav
  entries are its own declared functions only — use `interfaceImpl` or the
  database's `LinearizedBases` to resolve overrides).
- **`kind: "stateVar"`** — one per state variable declared directly on a
  contract.

### ID formats

| Symbol kind | ID shape | Example |
| --- | --- | --- |
| Contract | `file#Contract` | `/src/Token.sol#Token` |
| Function | `file#Contract.selector` | `/src/Token.sol#Token.transfer(address,uint256)` |
| State variable | `contractID.varName` | `/src/Token.sol#Token.balances` |

Function IDs are produced by `types.MakeFunctionID(file, contract, selector)`
and are the same IDs used throughout the database (call graph, effects,
findings), so `nav.json` IDs can be cross-referenced against
`data/database.json` and `data/findings.json` directly.

### `callers[]`

The reverse call graph – one entry per resolved edge whose fully qualified
callee ID maps to an existing exact contract function. Unresolved bare names,
malformed IDs, missing contracts, and missing selectors are omitted rather than
published as navigable targets:

```jsonc
{
  "callee": "/src/Token.sol#Token._burn(address,uint256)",
  "caller": "/src/Token.sol#Token.burn(uint256)",
  "site": { "...": "SrcRange (call-site location, no end/byte guarantee beyond start)" }
}
```

`callee`/`caller` are function IDs in the same `file#Contract.selector`
shape as `symbols[].id`. `site` is the location of the **call expression**
itself (where the call happens), not the callee's declaration — use it to
jump to "show me where this is called from" at the exact call site.

### `interfaceImpl[]`

Maps each interface method to the concrete implementation an extension
would jump to on "go to implementation":

```jsonc
{
  "interface": "/src/IToken.sol#IToken",
  "method": "transfer(address,uint256)",
  "implementation": "/src/Token.sol#Token.transfer(address,uint256)"
}
```

For each interface method, the implementing contract is found by walking
its exact `LinearizedBaseIDs` (C3 MRO) derived-first and taking the first function
with a matching selector and a real body — i.e. the most-derived override,
matching Solidity's own dispatch semantics.

### Determinism

`symbols`, `callers`, and `interfaceImpl` are each sorted before the file is
written (by ID, then by callee/caller/site-line/site-column/site-byte, then by
interface/method respectively), so re-running a scan on unchanged sources
produces a byte-identical `nav.json` — safe to diff across runs.

## `data/explorer.json`

```jsonc
{
  "schemaVersion": "2.0.0",
  "contracts": [ /* ExplorerContract[] */ ]
}
```

One `ExplorerContract` per **deployable (main) contract** — the same scope
as `summary.MainContracts` / `contracts/` folders, not every contract in the
database. This is the model for an extension's "Explorer" tab: pick a
deployed contract, see its state and its callable surface, in a sensible
order.

```jsonc
{
  "id": "/src/Token.sol#Token",
  "name": "Token",
  "kind": "contract",
  "range": { "...": "SrcRange" },
  "constants": [ /* ExplorerStateVar[], omitempty */ ],
  "storage": [ /* ExplorerStateVar[], omitempty */ ],
  "entryFunctions": [ /* ExplorerFunc[], omitempty */ ],
  "getters": [ /* ExplorerFunc[], omitempty */ ]
}
```

`id` is the same `file#Contract` shape used by `nav.json`'s contract
symbols, so the two files cross-reference directly.

### `constants` / `storage`

State variables inherited from every base in the MRO, walked **most-base-
first** (i.e. `LinearizedBases` reversed, since that list is derived-first)
so the order matches real EVM storage-slot layout: base-contract slots
first, then the contract's own declarations, each in source declaration
order.

`constant`/`immutable` variables (no storage slot) go into `constants`;
everything else goes into `storage`.

```jsonc
{
  "name": "owner",
  "typeName": "address",
  "visibility": "public",
  "constant": false,
  "immutable": true,       // omitempty
  "range": { "...": "SrcRange" }
}
```

ID convention for a state variable in this context (matching `nav.json`):
`contractID.varName`, e.g. `/src/Token.sol#Token.owner` — not embedded as a
field here (the object nests under its owning `ExplorerContract.id`), but
constructible the same way if a flat ID is needed.

### `entryFunctions` / `getters`

Functions walked **derived-first** along the MRO — first selector wins, so
an override in a derived contract shadows the base declaration, matching
real dispatch. Constructors and functions without a selector are skipped.

- **`entryFunctions`** — state-mutating public/external functions
  (`fn.IsEntrypoint()`): the callable surface that changes state.
- **`getters`** — public/external `view`/`pure` functions: read-only
  callable surface, separated out so an extension can render them
  differently (e.g. collapsed by default, or grouped as "read" vs "write").

```jsonc
{
  "name": "transfer",
  "selector": "transfer(address,uint256)",
  "signature": "a9059cbb",
  "visibility": "external",
  "mutability": "nonpayable",
  "modifiers": ["whenNotPaused"],   // omitempty
  "range": { "...": "SrcRange" }
}
```

`selector` is the canonical `Function.Selector` text. `signature` is the
four-byte Keccak `Function.Signature` value.

### Determinism

`contracts[]` is sorted by `id`. Within a contract, `constants`/`storage`
preserve base-to-derived, declaration order (deterministic by
construction — no secondary sort needed since `LinearizedBaseIDs` is itself
a deterministic MRO). `entryFunctions`/`getters` likewise follow the
deterministic MRO walk order.

## `data/xref.json`

A third data-layer artifact (`report.BuildXrefJSON`, `pkg/report/xref.go`),
indexed by `manifest.json` under `files.data.xref` and sharing the same
`schemaVersion`. It gives the extension **precise, type-resolved**
go-to-definition and find-references without any regex fallback: two flat,
deterministic tables.

```jsonc
{
  "schemaVersion": "2.0.0",
  "declarations": [
    { "id": "<canonical decl id>", "kind": "stateVar", "name": "POOL_MANAGER",
      "range": { "file": "...", "startLine": 72, "startCol": 5, "endLine": 72, "endCol": 48, "startByte": 2201, "endByte": 2244 } }
  ],
  "references": [
    { "file": "...", "range": { "startLine": 359, "startCol": 9, "endLine": 359, "endCol": 21, "startByte": 15975, "endByte": 15987 },
      "refId": "...#SatoHook.POOL_MANAGER", "refKind": "state_var" }
  ]
}
```

- `declarations[]` (`XrefDecl`) — every jump target, keyed by its canonical
  `id`, with `kind` ∈ `contract|interface|library|function|modifier|event|error|struct|enum|stateVar|parameter|local|udvt`,
  the `name`, and the name/decl `range` (`SrcRange`). IDs: `file#Contract`
  (contract), `file#Contract.selector` (function, `types.MakeFunctionID`,
  selector-or-name fallback), `contractID.member` (stateVar/event/error/struct/
  enum/modifier), `functionID.paramName` (parameter), `file#TypeName` (a
  user-defined value type), and the AST node's own `refId` for a `local`.
  Deduplicated by `id` (first wins).
- `references[]` (`XrefRef`) — one entry per resolved occurrence: the `file`,
  the occurrence `range` (its own `file` omitted — the entry's `file` is
  authoritative), the `refId` (a declaration id), and `refKind` ∈
  `state_var|parameter|local_var|function|library|event|error|modifier|type|udvt`.

**Go-to-definition:** find the reference whose `range` covers the cursor →
`refId` → `declarations[refId].range`. **Find-references:** group `references`
by `refId`. This subsumes the call-graph "who-calls" and, where a reference is
present, replaces the regex fallbacks entirely.

**Coverage / precision (v0.4):** occurrence ranges point at the exact
identifier/name token or the call expression. Resolved reference kinds:

- **identifiers** — state vars, parameters, locals, emitted when the builder can
  pin an exact position (member/call receivers, array-index bases, assignment
  lvalues; see `pkg/builder/AI.md`, "Identifier position backfill").
- **calls** — internal/external/self/super and library `using` calls
  (`x.toUint128()`, `Lib.foo()`) bind to the resolved function via the call graph
  (`function` / `library`).
- **UDVT `wrap`/`unwrap`** — bind to the user-defined value type decl (`udvt`).
- **type casts** — `IToken(x)` binds to the type decl (`type`).
- **errors / events / modifiers** — `revert X()`, `emit E()`, and applied
  modifiers bind to their declarations.

Interior operands and struct/enum member positions that solast does not provide
are omitted rather than approximated; a consumer may keep a textual last resort
only for those. Both tables are sorted with total-order tiebreakers
(declarations by `id`→`kind`→`name`→line; references by
`file`→`startLine`→`startCol`→`startByte`→`refId`) so the artifact is byte-stable
across runs.

## Consumption model

The human reports are not an editor data dependency. W3Solidity and other
editor consumers discover only `files.data.nav`, `files.data.explorer`,
`files.data.findings`, and `files.data.xref`. Consolidating Markdown and HTML
therefore does not require an editor schema change.

All three files are plain, static JSON — no server, no long-lived process, no
schema negotiation beyond checking `schemaVersion`. A consumer:

1. Reads `data/manifest.json` to discover the relative paths
   (`files.data.nav`, `files.data.explorer`, `files.data.xref`) alongside every
   other artifact.
2. Loads `nav.json` once per scan to build a symbol table + reverse-call
   index in memory (ID → `SrcRange`, ID → `[]NavCaller`).
3. Loads `explorer.json` once per scan to populate an explorer tree keyed
   by main-contract ID.
4. Loads `xref.json` once per scan to build a declaration table
   (`refId` → `SrcRange`) plus an occurrence index for go-to-definition and
   find-references; a cursor position maps to the reference whose `range`
   covers it.
5. Uses `SrcRange.file` + 1-based line/col (or the byte offsets, for exact
   substring extraction) to open the source file and jump to or highlight
   the exact span — no re-parsing of Solidity required.

Because all three are regenerated on every `WriteBundle` call, re-scanning after
an edit simply produces a fresh, self-consistent set of files; there is no
incremental-update protocol to implement on the consumer side.
