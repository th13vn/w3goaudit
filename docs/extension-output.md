# Extension Output — `nav.json` + `explorer.json`

Every scan's result folder (see [Result Folder Layout](./usage.md#result-folder-layout))
writes two additional files under `data/` alongside `manifest.json`,
`database.json`, `findings.json`, `overview.json`, and `diagnostics.json`:

- **`data/nav.json`** — a flat, symbol-level navigation index: every
  declaration in the database, the reverse call graph, and
  interface→implementation edges. Built by `report.BuildNavJSON` (`pkg/report/nav.go`).
- **`data/explorer.json`** — a per-deployable-contract model: ordered
  constants/storage variables and entry/getter functions. Built by
  `report.BuildExplorerJSON` (`pkg/report/explorer.go`).

Both are written by `report.WriteBundle` in the same step as `manifest.json`,
and both are indexed in `manifest.json` under `files.data.nav` /
`files.data.explorer`. They exist to let a **static consumer** — the
w3goaudit VSCode extension, an LSP-like navigation panel, or any other
downstream tool — build jump-to-definition, "who calls this", and a
per-contract explorer tree **without re-parsing Solidity**. They are read
directly off disk; nothing here requires the CLI to run a server.

Both documents share a `schemaVersion` field, currently `"2.0.0"`
(`report.SchemaVersion`), the same version used by `overview.json` /
`findings.json`. Consumers should refuse to parse on a major-version
mismatch, per the general JSON versioning policy (see
[`docs/usage.md`](./usage.md)).

## Shared: `SrcRange`

Every location in both files uses the same shape:

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

The reverse call graph — one entry per edge in `db.CallGraph.Edges`:

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
written (by ID, then by callee/caller/site-line, then by
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
  "signature": "transfer(address,uint256)",
  "visibility": "external",
  "mutability": "nonpayable",
  "modifiers": ["whenNotPaused"],   // omitempty
  "range": { "...": "SrcRange" }
}
```

### Determinism

`contracts[]` is sorted by `id`. Within a contract, `constants`/`storage`
preserve base-to-derived, declaration order (deterministic by
construction — no secondary sort needed since `LinearizedBaseIDs` is itself
a deterministic MRO). `entryFunctions`/`getters` likewise follow the
deterministic MRO walk order.

## Consumption model

Both files are plain, static JSON — no server, no long-lived process, no
schema negotiation beyond checking `schemaVersion`. A consumer:

1. Reads `data/manifest.json` to discover the relative paths
   (`files.data.nav`, `files.data.explorer`) alongside every other artifact.
2. Loads `nav.json` once per scan to build a symbol table + reverse-call
   index in memory (ID → `SrcRange`, ID → `[]NavCaller`).
3. Loads `explorer.json` once per scan to populate an explorer tree keyed
   by main-contract ID.
4. Uses `SrcRange.file` + 1-based line/col (or the byte offsets, for exact
   substring extraction) to open the source file and jump to or highlight
   the exact span — no re-parsing of Solidity required.

Because both are regenerated on every `WriteBundle` call, re-scanning after
an edit simply produces a fresh, self-consistent pair of files; there is no
incremental-update protocol to implement on the consumer side.
