# Semantic hardening fixtures

This directory is the canonical fixture lane for the internal program-point
semantic analyzer in `pkg/engine`. Future stages place focused Solidity cases
here for access-path construction, exact value provenance, control-state
merges, operation ordering, and CFG-sensitive behavior.

`access-paths.sol` covers exact nested struct fields, tuple positions and holes,
fixed and dynamic array indexes, mapping keys, persistent storage members,
casts, calls, delete/increment/decrement, Yul lexical shadowing, sload/sstore
slot identity, generic Yul memory operations, and nested Solidity local
shadowing. The local-shadow case pins reads before, inside, and after the nested
scope plus dynamic indexes under both declaration identities. The engine tests
also verify that serialized AST metadata produces identical lowering after a
database JSON round-trip.

The tuple cases include repeated identical call sites, reversed target names,
holes, single populated destructuring lanes at every position, and an exact
tuple-literal lane source. Package-level fix regressions additionally cover
inherited runtime contracts, cross-function persistent slots, nested-effect
postorder, malformed legacy facts and nested tuple consumers, Solidity numeric
units, path ownership, terminal classification, and deterministic unsupported
diagnostics.

Fixtures here must not introduce new serialized semantic-engine or report
fields unless a separate approved change explicitly requires them. Task 2 adds
only durable AST attributes, exact RefIDs, and the shared unsupported-analysis
diagnostic code while keeping schema 2.0.0.
