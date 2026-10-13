# pkg/builder – database construction

Builds the deterministic database from reader sources. Ordered passes parse
Solidity, build AST and type facts, resolve identities and inheritance,
construct the call graph, calculate entries, analyze effects and authorization,
and record transaction-context and external-boundary evidence.

## Key files

| File | Responsibility |
|---|---|
| builder.go | Orchestrates passes and builder options |
| parser_input.go | Legacy and Yul input normalization |
| contract.go | Contracts, functions, declarations, modifiers, aliases |
| ast_builder.go | Simplified statement/expression AST and locations |
| location.go | Unicode columns, UTF-8 byte ranges, diagnostics |
| inheritance.go | Exact C3 linearization |
| callgraph.go | Call resolution and edges |
| effects.go | State writes, guards, and per-function effects |
| authorization*.go | Authorization and initializer facts |
| transaction_context.go | Proven loop-scoped msg.value effects |
| external_boundaries.go | Protocol-neutral external-boundary facts |
| semantic.go | Type and semantic fact assembly |

## Build order

1. Parse sources and retain original bytes and spans.
2. Build AST, data flow, and semantic type facts.
3. Calculate selectors and signatures.
4. Resolve identities and C3 inheritance.
5. Build the call graph and entry points.
6. Analyze effects and authorization.
7. Build positive transaction-context facts.
8. Build external-boundary facts and WQL attributes.

## Invariants

- Exact identities include source paths. Duplicate names never cross-wire.
- Columns are one-based Unicode code points. Byte ranges are zero-based,
  half-open UTF-8 offsets. Invalid conversion keeps lines and bytes and records
  one location.invalid diagnostic.
- State writes follow the lvalue root. Index expressions do not turn locals into
  state writes.
- Names alone do not prove access control. Unknown and ambiguous evidence stays
  fail-closed.
- Transaction-context facts require positive bounded provenance. Conditional,
  tuple, reassigned, unresolved, and observational flows stay unknown.
- External-boundary facts are evidence, not vulnerability verdicts.
- Scan-local builders use injected logging and diagnostics.

## Change checklist

Add mutation-pinned tests for parser, identity, location, fact, or effect changes.
Update pkg/types/AI.md, root AI.md, docs/internals.md, and output docs when
serialized facts or locations change. Run source/cache parity tests.
