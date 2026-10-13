# templates – WQL detector pack

Contains the embedded official WQL pack plus feature-test and benchmark
materials. Official templates are release inputs. Two private, ignored lanes
sit beside it and are never part of the pack: templates/candidates/ holds
generic detectors under evaluation, and templates/incidents/ holds
protocol-named rules derived from one real exploit each. Their fixtures live in
the matching ignored test-data/ folders.

## Layout

- official/critical, official/high, official/medium: shipped detectors.
- test/: engine feature and language fixtures.
- embed.go: embeds the official pack for offline fallback.

Core v0.7.0 embeds the same 20-detector official tree published as pack v3.0.1.
The pack requires v0.7.0 for the intentional_divide_rounding semantic matcher.

## Authoring contract

Use canonical WQL: metadata plus one query block with select/from/where, or
one-level and/or composition. Do not add detector-specific engine syntax.
Prefer semantic, type, taint, reachability, and authorization evidence over
names or raw regex. Regex can refine AST evidence but cannot replace it.

The official `delegatecall` rule matches a `delegatecall` whose target flows from a parameter or caller identity, so both direct user input and caller-derived targets remain covered.

Severity is part of a detector ID and only changes with a renamed ID.
Confidence follows measured precision on the real corpus (on-chain-scripts plus
the audited bug-bounty targets): a rule whose remaining hits are mostly guards
or designs the engine does not model yet ships at LOW or MEDIUM. Every
precision change needs a regression in
`pkg/engine/false_positive_corpus_regression_test.go` that keeps the
vulnerable shape.

Official pack loading is fail-closed. Every detector needs vulnerable, safe,
structural, ambiguous, and unresolved controls where relevant. Validate source-
built and cached-database scans and inspect deterministic evidence.

Transaction-context templates match only proven loop-scoped msg.value effects;
unknown or conditional provenance stays silent. External-boundary templates
consume versioned evidence and do not declare vulnerabilities by themselves.
Authorization presets remain fail-closed on unknown.

## Change checklist

Run focused template tests, official-pack parity, source/cache parity, and the
competitive gate. Update README, WQL docs, package indexes, and CHANGELOG.md for
shipped detector changes. Keep candidate and incident rules and fixtures local.
