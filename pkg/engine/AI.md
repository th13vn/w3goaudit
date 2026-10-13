# pkg/engine – WQL execution

Loads, validates, lowers, and executes canonical WQL templates against a
Database, then creates deterministic findings with locations, evidence, and
reachability.

## Key files

| File | Responsibility |
|---|---|
| engine.go | Lifecycle, execution, logger, location mode |
| template.go | Template loading and metadata |
| wql.go | Strict YAML decoding and lowering |
| wql_catalog.go | Supported scopes, attributes, and matchers |
| verify.go | Query verification and matching |
| semantic_model.go | Evaluator model and evidence |
| semantic_analysis.go | Taint, reachability, semantic checks |
| semantic_lower.go | Rule lowering and composition |
| presets.go | Public parameterized presets |

## WQL contract

A document is metadata plus one query block. A block uses select/from/where or
one-level and/or composition. Unknown keys, YAML merge keys, empty required
values, malformed matcher graphs, repeated structural relations, and unsupported
aliases fail closed before execution. Templates author from and where; filter
and match are internal evaluator concepts.

and joins labeled branches at one scope and requires a positive reportable anchor.
or executes branches as a union and deduplicates only the same precise site.
Contract scopes match a synthetic contract declaration with resolved functions.
Regex can refine AST evidence but cannot be its only provenance.

## Finding contract

Matched-node location is the default. entryPoint and reachability carry the
external entry hop. Related sites retain additional evidence. Resolved library
matches promote the outer protocol call while retaining inner AST evidence.
SARIF uses Unicode-code-point columns and exact hop files.

## Invariants

- Loading is fail-closed unless IgnoreInvalid is explicit.
- Deprecated aliases are normalized on deep copies with cycle and depth checks.
- Caller-owned maps and slices are never mutated.
- Deterministic ordering and precise-site identity do not depend on provenance
  entry path.
- Unknown authorization, taint, reachability, and fact evidence does not become
  a positive finding by accident.
- The engine has no model transport or AI review path.

## Change checklist

Add vulnerable, safe, ambiguous, and unresolved fixtures for detector behavior.
Run focused WQL tests, official-pack parity, source/cache parity, and full gates.
Update docs/wql-syntax.md, templates/AI.md, and output docs when language or
evidence changes.
