# Semantic wrapper template authoring

Status: approved design
Date: 2026-09-04
Scope: W3GoAudit WQL authoring UX

## 1. Problem

The authorization/runtime-inheritance slice currently exposes engine evidence
fields directly to template authors:

```yaml
- not:
    attr:
      auth_verdict: protected
      auth_principal: expected_external
      auth_expected_principal: '(?i)^(pool|pair)$'
      auth_dominates: dominates
```

This is precise, but it leaks evaluator and evidence-ABI details into the
primary authoring surface. A human or AI author must understand function
filters, AST matching, verdicts, principal kinds, dominance, anchored regex,
and negative proof logic just to express one semantic intent:

> report a callback unless its caller is proven to be the expected pool or pair

The raw `attr` form remains valuable for experts, SDK callers, exact identity
queries, and debugging. It should not be the default language that authors
learn first.

## 2. Goals and non-goals

### Goals

1. Make common security intent readable without knowledge of internal fact names.
2. Give humans and AI agents a small, closed, discoverable vocabulary.
3. Compile deterministically to the existing `Rule` and authorization facts.
4. Preserve raw WQL compatibility and output schema `2.0.0`.
5. Keep protocol vocabulary in templates, not in production engine branches.
6. Make positive safety proofs fail closed when facts are absent, unknown,
   unresolved, ambiguous, partial, or after the sensitive site.
7. Provide errors that explain the friendly form and show a valid example.

### Non-goals

- Do not replace the canonical `select`/`from`/`where` grammar.
- Do not remove raw `attr` or the existing parameterless `preset` API.
- Do not add AI, model transport, network access, or probabilistic matching to
  the core scanner.
- Do not infer protocol behavior from names in production code.
- Do not expose source-path-dependent RefIDs in the beginner syntax.
- Do not add a generic untyped `semantic:` bag that can grow without a closed
  schema.

## 3. Authoring layers

W3GoAudit will have three intentional layers:

```text
Friendly semantic wrappers  ->  canonical WQL/Rule IR  ->  deterministic evaluator
Raw WQL attr/evidence       ->  canonical WQL/Rule IR  ->  deterministic evaluator
```

### Friendly authoring layer

Use domain wrappers with closed schemas:

- `authorization` for caller authorization and principal proof.
- `initializer` for initializer/proxy lifecycle proof.
- `runtime` for virtual and `super` dispatch evidence.

These wrappers are semantic predicates. Their fields are not copied to AST
nodes and are not new serialized finding fields. They lower to existing
function-level authorization attributes.

### Expert layer

Raw evidence attributes remain supported:

```yaml
attr:
  auth_verdict: protected
  auth_expected_principal_ref: '.*#PoolHook\.pool$'
```

This layer is for exact declaration identity, unusual protocol rules,
regression tests, and Agent SDK workflows.

### Execution layer

The evaluator continues to execute the existing `Template`, `QueryBlock`, and
`Rule` IR. No evaluator branch will know whether a condition came from a
wrapper or raw WQL.

## 4. Canonical friendly grammar

A wrapper is a single matcher object and can appear wherever a context-level
matcher is valid, including under `not`, `any`, and context-only `and` groups.
It cannot appear inside AST traversal matchers such as `has`, `in`, `left`,
`right`, `receiver`, `arg.N`, or `sequence`.

### 4.1 Authorization wrapper

```yaml
authorization:
  expected_principal: [pool, pair]
```

The fields below are the closed version-1 vocabulary. They are alternatives
or refinements, not a requirement to populate every field in one object.

The wrapper must contain at least one recognized field. Fields in one wrapper
are ANDed. `expected_principal` accepts one string or a non-empty list of
strings; list entries are OR alternatives. The compiler treats each entry as
an exact normalized expression token, escapes it, and creates an anchored
match. Authors do not write regex for this field.

Supported fields in version 1:

| Field | Type | Meaning | Lowering |
|---|---|---|---|
| `protected` | boolean | Require a proven privileged authorization guard | `auth_verdict: protected` |
| `self_scoped` | boolean | Require caller self-scoping, not privileged access | `auth_verdict: self_scoped` and `auth_principal: caller_self_scope` |
| `expected_principal` | string or list of strings | Require an external expected principal expression | `auth_verdict: protected`, `auth_principal: expected_external`, anchored `auth_expected_principal` |
| `role` | boolean | Require proven role membership | `auth_verdict: protected`, `auth_principal: role` |
`protected`, `self_scoped`, and `role` only accept `true` in version 1. A
negative condition is expressed with WQL `not`, not by writing `false` inside
the wrapper. This keeps the meaning of a wrapper as a positive proof and
prevents accidental matches against `unknown`.

Every positive `authorization` wrapper implicitly requires full-path coverage.
The compiler always adds `auth_dominates: dominates`; authors do not write a
control-flow term for the normal secure case. Raw `attr.auth_dominates` remains
available to expert templates that intentionally inspect `partial`,
`after_site`, or `unknown` evidence.

Examples:

```yaml
# Any proven authorization
- authorization:
    protected: true

# Caller can act only on its own resource
- authorization:
    self_scoped: true

# Caller must be checked against pool or pair, before the operation
- authorization:
    expected_principal: [pool, pair]

# A role membership guard that applies before the operation
- authorization:
    role: true
```

### 4.2 Initializer wrapper

```yaml
initializer:
  entry: true
  mutex: true
  takeover: [possible, unknown]
  atomic: after_guard
  constructor_disabled: true
  proxy: unknown
```

Fields in one wrapper are ANDed. `takeover` accepts one state or a non-empty
list of states. Supported fields in version 1:

| Field | Type | Meaning | Lowering |
|---|---|---|---|
| `entry` | boolean | Require an initializer entrypoint | `initializer_entry: true` |
| `mutex` | boolean | Require a proven one-time initialization mutex | `one_time_mutex: true` |
| `takeover` | `possible`, `unknown`, or list | Match first-call takeover lifecycle state | `first_call_takeover` |
| `atomic` | `before_guard`, `after_guard`, or `unknown` | Match initialization write/guard ordering | `atomic_initialization` |
| `constructor_disabled` | boolean | Require constructor disable evidence | `constructor_disable: true` |
| `proxy` | lifecycle state | Match proxy linkage state | `proxy_linkage` |

Version 1 accepts `proxy: unknown` as the only currently proven-safe-to-
serialize lifecycle state. Future states can be added without changing the
wrapper shape.

Example:

```yaml
- initializer:
    entry: true
    takeover: [possible, unknown]
- not:
    authorization:
      protected: true
```

### 4.3 Runtime wrapper

```yaml
runtime:
  authorization: protected
  dispatch: [virtual, super]
```

Fields in one wrapper are ANDed. Supported fields in version 1:

| Field | Type | Meaning | Lowering |
|---|---|---|---|
| `authorization` | `protected`, `self_scoped`, or `unknown` | Authorization verdict of the selected runtime target | `auth_verdict` |
| `dispatch` | `virtual`, `super`, or list | Require the corresponding exact dispatch reason | `auth_reason` |

`dispatch: [virtual, super]` means either dispatch mechanism can satisfy the
predicate. The compiler maps `virtual` to `virtual_override` and `super` to
`super` in the exact reason set. `runtime.contract` and selected function IDs
remain expert-only because they are source-identity fields.

Example:

```yaml
- runtime:
    authorization: protected
    dispatch: [virtual, super]
```

## 5. Composition and polarity

Wrappers are positive proofs. They follow the existing WQL polarity rules:

```yaml
# Report if the callback proof is absent, wrong, partial, or unknown
- not:
  authorization:
    expected_principal: [pool, pair]
```

The compiler lowers this to one context `Rule.Not` whose attributes are
evaluated together. It must not split the fields into independent negations,
because that would report a function when only one part of the proof is
missing.

All positive wrapper predicates fail closed:

- absent facts do not match;
- `unknown` verdicts do not match;
- `partial` and `after_site` dominance do not match `dominates: true`;
- unresolved helper/modifier bindings do not match;
- ambiguous runtime candidates do not match;
- caller-selected principals do not match `expected_principal`.

`false` values are not accepted for proof fields in version 1. Authors use
`not` for absence or exclusion. This keeps templates readable and makes AI
generation less likely to invert a safety condition accidentally.

## 6. Protocol vocabulary boundary

The engine remains protocol-neutral. The wrapper compiler knows only the
semantic category `expected_principal`; it does not know what `pool`, `pair`,
`manager`, or `vault` means. Those names remain template data:

```yaml
authorization:
  expected_principal: [pool, pair]
```

The engine only sees the compiled exact expression predicate. This preserves
the boundary:

```text
Engine proves exact evidence
Template supplies protocol vocabulary
Agent may inspect both layers
```

## 7. Diagnostics and explainability

The loader must reject malformed wrapper documents before execution. Errors
must identify the wrapper, field, expected type, allowed values, and one valid
example. Required messages include:

```text
where.authorization.expected_principal must be a string or a non-empty list of strings
example: authorization: {expected_principal: [pool, pair]}

where.initializer.atomic must be one of before_guard, after_guard, unknown

where.authorization.auth_expected_principal_ref is an expert evidence field;
use authorization.expected_principal for portable template matching
```

An optional later `w3goaudit template explain` command should display both the
friendly wrapper and the compiled canonical attributes. It is not required to
land the grammar change, but the compiler should expose an internal
explanation structure so the command can be added without reimplementing
lowering.

Example explanation:

```text
Friendly predicate:
  authorization.expected_principal = [pool, pair]

Compiled evidence:
  auth_verdict = protected
  auth_principal = expected_external
  auth_expected_principal = ^(?:pool|pair)$
  auth_dominates = dominates
```

## 8. Compatibility

- Existing templates using `preset`, `attr`, `has`, `sequence`, and all other
  canonical WQL constructs remain valid.
- Raw authorization attributes remain valid and continue to be the exact
  escape hatch.
- Friendly wrappers are additive syntax. They do not change the serialized
  database, finding, report, or manifest schema.
- Official templates are not migrated automatically. Candidate templates are
  the first migration target and must produce byte-equivalent findings to their
  raw-attribute versions.
- A wrapper lowers before normal rule placement validation. The resulting
  context attributes follow the same `filter` versus `match` rules as raw
  authorization attributes.
- The existing parameterless `preset` vocabulary remains unchanged. Wrappers
  are used for parameterized semantic predicates, not as an overloaded preset
  map.

## 9. Candidate migration examples

### Expected-principal callback

```yaml
query:
  select: function
  from: entry_function
  where:
    - func_name: '(?i)^(uniswapV2Call|uniswapV3SwapCallback|uniswapV3FlashCallback|uniswapV3MintCallback)$'
    - not:
        authorization:
          expected_principal: [pool, pair]
```

### V4 manager callback

```yaml
query:
  select: function
  from: entry_function
  where:
    - func_name: '(?i)^(before|after)(Initialize|AddLiquidity|RemoveLiquidity|Swap|Donate)$'
    - not:
        authorization:
          expected_principal: manager
```

### Initializer takeover

```yaml
query:
  select: function
  from: entry_function
  where:
    - initializer:
        entry: true
        takeover: [possible, unknown]
    - not:
        authorization:
          protected: true
```

### Runtime inherited authorization

```yaml
query:
  select: function
  from: entry_function
  where:
    - runtime:
        authorization: protected
        dispatch: [virtual, super]
```

## 10. Implementation and test boundary

Implementation should be a separate approved plan. The plan must include:

1. RED tests for each wrapper's accepted shape, malformed values, unknown
   fields, empty maps, scalar/list handling, and placement restrictions.
2. GREEN lowering tests asserting exact `Rule` output, including anchored
   expression generation and OR-list behavior.
3. Source/cache execution equivalence for all four candidate templates.
4. Friendly-versus-raw finding equivalence tests.
5. Unknown, unresolved, partial, after-site, wrong-principal, and ambiguous
   runtime fail-closed fixtures.
6. Deterministic serialization and template ordering tests.
7. Documentation and WQL catalog updates with a beginner cookbook.
8. Official pack byte-identity check and an explicit promotion stop.

Acceptance is achieved only when an auditor can understand each migrated
candidate without reading `pkg/engine/verify.go`, while the compiled rule and
finding set remain identical to the raw evidence version.

## 11. Recommended decision

Adopt `authorization`, `initializer`, and `runtime` as the friendly semantic
wrapper vocabulary. Keep `attr` as the expert evidence API. Do not add a
generic `semantic` namespace or overload `preset`. Implement the wrappers first
for candidate templates, add explainability after the compiler is stable, and
defer official-template migration to a separate owner-approved review.
