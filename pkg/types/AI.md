# pkg/types – serialized data model

Defines the database, contracts, functions, AST, identities, diagnostics,
call graph, semantic facts, and bounded queries consumed by builder, engine,
reporter, SDK, and extension.

## Key files

| File | Responsibility |
|---|---|
| database.go | Database, source files, stats, cache metadata |
| contract.go | Contract declarations and inheritance IDs |
| function.go | Functions, modifiers, selectors, effects, auth |
| ast.go | Simplified AST nodes and source spans |
| source.go | Source identity and file content |
| callgraph.go | Calls, edges, and exact references |
| semantic.go | Type and effect semantic facts |
| authorization.go | Authorization and initializer facts |
| transaction_context.go | Versioned loop-scoped value facts |
| diagnostic.go | Parse, import, and location diagnostics |

## Invariants

- Contract IDs are absPath#Contract; function IDs include the canonical
  selector. Exact IDs prevent duplicate names from cross-wiring.
- Selectors are canonical text. Signatures are four-byte Keccak values.
- Columns are one-based Unicode code points. Byte offsets are zero-based,
  half-open UTF-8 ranges. Synthetic nodes omit spans.
- AST and declaration copies are deterministic and safe to serialize.
- Versioned fact slices return normalized deep copies. Legacy caches report an
  unavailable capability instead of weaker guessed evidence.
- Bounded queries require caller limits and exact identities.
- Unknown or ambiguous semantic evidence remains unknown.

## Change checklist

Any serialized field, identity, span, or fact-version change needs mutation and
round-trip tests, root/package AI updates, SDK/output docs, and source/cache
parity verification.
