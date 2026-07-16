# WQL Syntax Guide

Complete reference for writing security templates using the W3GoAudit Query
Language (WQL). A template is a YAML document with `meta` plus
`select`/`from`/`where`. All 106 repository templates (25 official, 5
feature-test, and 76 benchmark) use this syntax.

This reference is accurate to the **implementation** —
[`pkg/engine/wql_v2.go`](../pkg/engine/wql_v2.go) (parser + lowering to evaluator
`Rule` IR) and [`pkg/engine/wql_v2_catalog.go`](../pkg/engine/wql_v2_catalog.go)
(the exact block-kind / attribute / preset name tables) — not just the design
spec. Where the two ever disagree, the code wins.

---

## Table of Contents

- [1. Template Shape](#1-template-shape)
- [Query Composition: `and:` / `or:`](#query-composition-and--or)
- [2. `select` — What to Find](#2-select--what-to-find)
- [3. `from` — Scope Table](#3-from--scope-to-search)
- [4. `where` — The Matcher Grammar](#4-where--the-matcher-grammar)
- [5. Block-Kind Catalog](#5-block-kind-catalog)
- [6. Attribute Catalog](#6-attribute-catalog)
- [7. Presets](#7-presets)
- [8. Taint](#8-taint)
- [9. Worked Examples](#9-worked-examples)

---

## 1. Template Shape

A WQL source document has exactly two top-level keys: `meta` and `query`.
`query` holds either one `select`/`from`/`where` query, or a one-level
`and:`/`or:` composition of branch queries (see
[Query Composition](#query-composition-and--or)). Unknown keys are rejected
at every level. There is no public `filter:`/`match:` split — `from` picks
the scope to search, `where` is a flat list of matchers (implicit AND) that
constrain it. The loader compiles this authoring surface into evaluator
`Template`/`QueryBlock`/`Rule` IR (`TemplateDoc.lower()` in `wql_v2.go`).
Those Go values are execution IR, not another supported YAML schema.

```yaml
meta:
  id: delegatecall-user-input
  title: Delegatecall to user-controlled target
  severity: CRITICAL
  confidence: HIGH
  description: >
    ...
  recommendation: >
    ...
  references:               # optional
    - https://swcregistry.io/docs/SWC-112
  fix: "..."                # optional

query:
  select: delegatecall      # WHAT to find & report (a block kind)
  from: entry_function      # WHERE to search (a scope)
  where:                    # list of matchers, implicit AND
    - arg.0: { tainted: parameter }
    - not: { preset: access_controlled }
```

`meta.id` and `meta.severity` are required at load time;
`severity` must be one of `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`.

The loader is strict: a template without `query:`, or with unknown keys at
any level, is rejected at load time.

---

## Query Composition: `and:` / `or:`

`query:` composes whole queries, one level deep. Exactly one of the three
forms may be used: a single `select`/`from`/`where`, an `and:` list, or an
`or:` list. This is different from `any:`/`all:` inside `where`, which
compose *matchers on nodes*; query composition composes *complete queries*,
each with its own anchor.

### `or:` — union of queries

One detector that fires on several alternative shapes, without duplicating
`meta` across files. Each branch is a complete query and anchors its own
finding; the result is the union of all branches' findings, deduplicated by
matched location. A query-level `from:` is the branches' shared default;
branches may override it (cross-scope branches are allowed).

```yaml
meta:
  id: unprotected-selfdestruct-or-delegatecall
  severity: CRITICAL

query:
  from: entry_function        # shared default scope
  or:
    - select: selfdestruct
      where: [ not: { preset: access_controlled } ]
    - select: delegatecall
      where:
        - not: { preset: access_controlled }
        - arg.0: { tainted: parameter }   # branch-specific constraint
```

Each branch may carry its own context conditions (presets, `modifier:`,
`func_name:`, ...) — that is the reason `or:` branches compile to separate
query blocks instead of one merged rule. `label:` is not allowed on `or:`
branches (there is no multi-site output to name).

### `and:` — joined queries

"Both patterns hold in the same X." The query-level `from:` is **required**
and names the join scope; each branch describes one required site with its
own `select`, `where`, and optional `label:`. One finding is produced per
scope instance (e.g. per contract) in which **every** branch matches; each
branch's matched sites appear in `Finding.Related` under its label.

```yaml
meta:
  id: payable-multicall-value-reuse
  severity: HIGH

query:
  from: main_contract         # the join scope: same contract
  and:
    - label: msg.value accounting
      select: member
      where:
        - name: ^value$
        - parent: ^msg$
    - label: batch entry
      select: function
      where: [ name: ^multicall$ ]
```

Rules:

- `from:` is required on the query and forbidden on `and:` branches; the join
  scope must be structural (`from: source` is rejected).
- Join scopes: the contract scopes (`main_contract`, `contract`,
  `any_contract`, `library`, `abstract`) join per contract (evaluated against
  the synthetic inheritance-aware contract AST); `entry_function`/`function`
  join per function.
- Branch `where` matchers must be AST-level. Context-level matchers
  (`preset:`, `modifier:`, `func_name:`, `version:`, `base:`, `has_param:`,
  `guarded_by:`) are rejected inside `and:` branches — a context filter
  applies to the whole scope instance, so a per-branch one would silently
  widen to every branch. Express such conditions structurally (e.g.
  `has: { block: function, mutability: payable }`).
- At least two branches; one composition level (no `and:`/`or:` inside a
  branch); `and:`/`or:` cannot be mixed with each other or with a sibling
  `select:`/`where:`.

---

## 2. `select` — What to Find

`select` names the scalar block kind (§5) whose match becomes the finding's
anchor node.

- **Scalar** — one block kind, e.g. `select: delegatecall`. The matched node
  of that kind is the finding's `PrimaryAST`.
- **List (combo)** — *not supported.* `select: [kind_a, kind_b]` is rejected
  at load time: a list cannot say which site each `where` constraint belongs
  to. Both intents have first-class forms instead:
  - *"A **or** B"* (alternative shapes, one detector) → a query-level `or:`
    composition — each branch carries its own `select` and constraints.
  - *"A **and** B in the same scope"* (multi-site finding) → a query-level
    `and:` composition, or a single `select` with `has:` sub-rules in
    `where` (one per extra site). Example:

  ```yaml
  query:
    select: delegatecall          # primary anchor site
    from: main_contract
    where:
      - has: { block: function, name: ^multicall$ }   # second required site
  ```
- **Optional only with a complete root matcher** — when `select` is omitted,
  `where` must already contain an actionable AST-layer match evaluated at the
  selected scope root. Supported examples include a top-level `sequence:`, a
  root `has:`/`all:`/`any:` structure, or a contract-root `regex:` detector
  such as `templates/official/high/proxy-storage-collision.yaml`. Context-only
  predicates such as `func_name:`, `modifier:`, or a preset are not enough by
  themselves. Omitting `select` without an AST/root matcher is a load-time
  error. `from: source` is a separate regex-only case: use one top-level
  `regex:` matcher and omit `select`.

### `select` with `sequence`

`sequence:` is already a scope-search construct, so it remains at the match
root instead of being wrapped in `has:`. Its first step is the finding anchor:

- without `select`, the first step must define its own actionable anchor;
- with `select`, the scalar kind must equal the first step's `block`, or it may
  fill in a simple first step that has predicates but no `block`;
- a conflicting kind or a composite first-step anchor (`any:`/`all:`) is
  rejected instead of silently ignoring `select`.

---

## 3. `from` — Scope to Search

| `from` | Meaning |
|---|---|
| `entry_function` | Public/external state-mutating functions of main (deployable) contracts; follows internal callees. **Default** when `from` is omitted. |
| `function` | Every function everywhere. |
| `contract` | Contract-kind-filtered contract scope (contracts only). |
| `library` | Library-kind-filtered contract scope. |
| `abstract` | Abstract-contract-kind-filtered contract scope. |
| `main_contract` | Deployable contracts only, evaluated against a synthetic `decl.contract` AST built from the contract's linearized inheritance chain (so a rule can span local and inherited functions in one contract context). |
| `any_contract` | Every contract/interface/library. |
| `source` | Raw source-file text — regex-only (`where` may contain nothing but a top-level `regex:` matcher). |

Contract scopes (`contract`, `library`, `abstract`, `main_contract`,
`any_contract`) run `where` against the synthetic contract AST; each
top-level `all:` branch may carry a `label:` used to name its matched site in
`Finding.Related`.

---

## 4. `where` — The Matcher Grammar

`where` is a list; sibling items are implicit **AND** (an explicit `and:`
group also exists as an alias of `all:`). Every item is a one-key matcher
map. Matchers nest uniformly: a
matcher's value can itself be a matcher map, and the same matcher forms are
legal at any nesting depth (inside `has:`, `in:`, `arg.N:`, `sequence:`
elements, `any:`/`all:` branches, and `not:`).

### Leaf matchers

| Matcher | Meaning |
|---|---|
| `block: <kind>` | Node is of the given block kind (§5). |
| `name: <regex>` | Identifier / call / function name matches (unanchored regex). |
| `<attribute>: <value>` | A semantic attribute (§6) — bare key form, e.g. `visibility: public,external`. |
| `preset: <name>` | A named property (§7), e.g. `preset: access_controlled`. |
| `regex: <pattern>` | Raw-text match, **line-scoped to the enclosing selected block** (falls back to function → contract → file when a node has no range). |
| `tainted: <source>` | Value traces to `parameter`\|`state_var`\|`local_var`\|`sender` (§8). |

### Structural matchers

| Matcher | Meaning |
|---|---|
| `arg.N: <matcher>` | The Nth call argument (0-based) matches. List form is invalid — one matcher per `arg.N` key. |
| `arg.any: <matcher>` | SOME positional call argument matches. Receivers and call options (`{value:}`/`{gas:}`) are not arguments, exactly as with `arg.N`. |
| `has: <matcher>` | Some **descendant** of the node matches. |
| `in: <matcher>` | Some **ancestor** of the node matches. |
| `guarded_by: <matcher>` | A guard/modifier in the function's guard context matches. |
| `sequence: [<matcher>, ...]` | Ordered, same-execution-path occurrence of each matcher in turn (reentrancy / CEI patterns). Rejects pairs that first diverge into mutually exclusive branch arms (`if`/`else`, ternary arms, `try`/`catch` arms). |
| `left: <matcher>` | Left operand of a binary/assignment/member-access node matches. |
| `right: <matcher>` | Right operand matches. |
| `statement_has: <matcher>` | Sub-rule matched against the node's nearest enclosing statement (narrower than `in:`, wider than `has:`) — e.g. "no other bitwise operator in this same statement". |
| `unchecked_var: true` | On an arithmetic `binary` node, true when no preceding guard in the same function bounds every operand with an ordering comparison before an `unchecked { ... }` use. |
| `modifier: <regex>` | Function has a modifier whose name matches. |
| `base: <regex>` | Contract-scope: the contract (or an ancestor in its inheritance chain) matches. |
| `func_name: <regex>` | Function name matches (function-level precondition, independent of the AST node's own `name:`). |
| `version: <constraint>` | Solidity pragma version constraint, e.g. `">=0.8.0"`. |
| `has_param: <name>` | Function has a parameter with this name. |

### Logic

| Matcher | Meaning |
|---|---|
| `any: [<matcher>, ...]` | OR. |
| `not: <matcher>` | Negation. |
| `all: [<matcher>, ...]` | Explicit AND grouping — used to group a branch inside `any:`/`not:`, or to name multi-site combination findings: each branch may set `label:` as a sibling key alongside its own matchers, which labels its sites in `Finding.Related`. |
| `and: [<matcher>, ...]` | Exact alias of `all:`. |

Every structural/logic matcher recurses uniformly:

```yaml
- not:
    has:
      block: require
      regex: "msg\\.sender"
```

### `attr:` wrapper form

Attributes can also be grouped under a single `attr:` map when several apply
to the same node:

```yaml
- attr:
    has_value: true
    has_gas: true
```

This is equivalent to two bare-key matchers (`has_value: true`, `has_gas:
true`) ANDed together.

---

## 5. Block-Kind Catalog

Every name below is resolved by `blockKindToIR` (`wql_v2_catalog.go`) — usable
in `select:` and as `block: <kind>` in `where`.

**Calls**

| WQL name | Evaluator IR kind |
|---|---|
| `call` | `any_call` — any internal/external/low-level call |
| `outgoing_call` | `outgoing_call` — any call this function makes outward |
| `external_call` | `call.external` |
| `internal_call` | `call.internal` |
| `delegatecall` | `delegatecall` group — `call.lowlevel.delegatecall` + `asm.delegatecall` |
| `staticcall` | `call.lowlevel.staticcall` (Solidity-level only; no merged asm group yet) |
| `lowlevel_call` | `call.lowlevel.call` |
| `create` | `call.create` (Solidity-level only; no merged asm group yet) |
| `eth_transfer` | `eth_transfer` group — `.transfer`/`.send`/`call{value:}` |
| `selfdestruct` | `selfdestruct` group — `call.builtin.selfdestruct` + `asm.selfdestruct` |
| `builtin_transfer` | `call.builtin.transfer` — `address.transfer(...)` |
| `builtin_send` | `call.builtin.send` — `address.send(...)` |
| `builtin_selfdestruct` | `call.builtin.selfdestruct` (Solidity-level only; use `selfdestruct` for the +asm alias) |

**Guards / checks**

| WQL name | Evaluator IR kind |
|---|---|
| `guard` | `check` — any require/assert/revert |
| `require` | `check.require` |
| `assert` | `check.assert` |
| `revert` | `check.revert` |

**State**

| WQL name | Evaluator IR kind |
|---|---|
| `state_write` | `state_write` — `stmt.assign` on a state var, or `asm.sstore` |
| `state_read` | `state_read` — state-var identifier read, or `asm.sload` |

**Statements**

| WQL name | IR kind | WQL name | IR kind |
|---|---|---|---|
| `assign` | `stmt.assign` | `return` | `stmt.return` |
| `if` | `stmt.if` | `emit` | `stmt.emit` |
| `loop` | `stmt.loop` | `try_catch` | `stmt.try_catch` |
| `unchecked` | `stmt.unchecked` | `block` | `stmt.block` |

**Expressions**

| WQL name | IR kind | WQL name | IR kind |
|---|---|---|---|
| `identifier` | `expr.identifier` | `member` | `expr.member_access` |
| `literal` | `expr.literal` | `index` | `expr.index_access` |
| `binary` | `expr.binary_op` | `ternary` | `expr.conditional` |
| `unary` | `expr.unary_op` | `tuple` | `expr.tuple` |

**Declarations**

| WQL name | IR kind | WQL name | IR kind |
|---|---|---|---|
| `function` | `decl.function` | `variable` | `decl.variable` |
| `contract` | `decl.contract` | `parameter` | `decl.parameter` |
| `modifier` | `decl.modifier` | | |

**Assembly**

| WQL name | IR kind | WQL name | IR kind |
|---|---|---|---|
| `asm` | `asm.block` | `asm_staticcall` | `asm.staticcall` |
| `asm_sstore` | `asm.sstore` | `asm_create` | `asm.create` |
| `asm_sload` | `asm.sload` | `asm_selfdestruct` | `asm.selfdestruct` |
| `asm_delegatecall` | `asm.delegatecall` | `asm_revert` | `asm.revert` |
| `asm_call` | `asm.call` | `asm_return` | `asm.return` |

> `asm_log` is **not** implemented (no single evaluator kind covers all
> `asm.log0`..`asm.log4` arities); it is documented in the design spec but
> intentionally absent from `blockKindToIRTable` — using it errors at load
> with "unknown block kind".

---

## 6. Attribute Catalog

Resolved by `attrNameToIR` (`wql_v2_catalog.go`). `name`, `visibility`,
`mutability`, and `tainted` are handled directly as their own matcher forms
(§4), not through this table.

**Core**

| WQL attribute | Meaning | Evaluator IR key |
|---|---|---|
| `receiver` | bool — node is the receiver child of a member call | `call_receiver` |
| `signature` | anchored regex on the called function signature | `called_signature` |
| `has_value` | bool — call carries `{value: ...}` | `has_value` |
| `has_gas` | bool — call carries `{gas: ...}` | `has_gas` |
| `call_option` | `"value"` or `"gas"` marker on a call-option child | `call_option` |
| `operator` | anchored regex, e.g. `"=="`, `"/"`, `"\\*"` | `operator` |
| `type` | anchored regex on the resolved type | `type` |
| `type_kind` | anchored regex on the type kind | `type_kind` |
| `literal_kind` | `number`/`string`/`bool`/`hex` | `subtype` |
| `is_state_var` | bool | `is_state_var` |

**Advanced**

| WQL attribute | Meaning | Evaluator IR key |
|---|---|---|
| `has_salt` | bool — `create2`-style salt present | `has_salt` |
| `parent` | parent-node marker | `parent` |
| `cond_role` | `if`/`loop`/`ternary` | `cond_role` |
| `conditional_part` | `condition`/`true`/`false` | `conditional_part` |
| `try_part` | `expr`/`body`/`catch:N` | `try_part` |
| `loop_type` | `for`/`while`/`do_while` | `loop_type` |
| `receiver_type` | resolved receiver type | `receiver_type` |
| `receiver_type_kind` | resolved receiver type kind | `receiver_type_kind` |
| `receiver_type_is_address` | bool | `receiver_type_is_address` |

String-valued attributes and `signature` are **anchored** regex (must match
the whole value); `name`/`regex`/`func_name`/`modifier`/`base` are
**unanchored**. `visibility`/`mutability` are comma-separated "one of" lists
(`visibility: public,external`).

---

## 7. Presets

Evaluator presets return `true` for the **vulnerable** case (the safety
property's absence). WQL presets name the safety **property** itself, so
they read naturally either asserted or negated. `presetToIR` performs the
polarity flip during lowering.

| Preset (property = true) | Property | Vulnerable expression |
|---|---|---|
| `access_controlled` | Privileged access control is present — owner/admin/role modifier, an internal auth-helper call, or a `msg.sender`/`tx.origin` guard against a hardcoded/storage owner, checked recursively through internal/inherited calls. | `not: { preset: access_controlled }` |
| `caller_checked` | Either the function is access-controlled, OR it self-scopes the caller — binds a sensitive argument to `msg.sender` (`require(from == msg.sender)`), including the **item-ownership** form `ownerOf(tokenId) == msg.sender` (and its interprocedural forwarded equivalents). | `not: { preset: caller_checked }` |
| `reentrancy_guarded` | A reentrancy-guard modifier (`nonReentrant`/`lock`/`mutex`/etc.) is present. | `not: { preset: reentrancy_guarded }` |

**Item-ownership vs. access control:** `caller_checked` deliberately keeps
these distinct. `ownerOf(tokenId) == msg.sender` satisfies `caller_checked`
(the caller can only act on a resource they own — a valid mitigation for
detectors like arbitrary `transferFrom`/arbitrary-send-ETH) but does **not**
satisfy `access_controlled` (it is not privileged/role-based access control).
Pick `access_controlled` when only a privileged role should be allowed to
call at all; pick `caller_checked` when self-scoping the caller to their own
resource is an acceptable mitigation.

Presets compose anywhere in `where`, including under `any:`/`not:`.

---

## 8. Taint

`tainted: <source>` matches a value that traces back to one of:

- `parameter` — a function parameter
- `state_var` — a state variable
- `local_var` — a local variable
- `sender` — `msg.sender`/`tx.origin`/`_msgSender()` identity

The evaluator performs flow-sensitive
intra-function dataflow (a bounded fixpoint over straight-line code and
loops), interprocedural tracing through internal helper calls (with
context-sensitive argument binding — `_deposit(from, amount)` vs.
`_deposit(msg.sender, amount)` are distinguished), and simple local-alias
propagation. It is **not** path-sensitive and does not track taint flowing
out through a callee's return value.

Express a source→sink check with `tainted:` on the sink node, typically
nested under `arg.N:` or `has:`:

```yaml
- arg.0: { tainted: parameter }
```

```yaml
- has:
    block: identifier
    receiver: true
    tainted: parameter
```

---

## 9. Worked Examples

### A. Delegatecall to a user-controlled target

`templates/official/critical/delegatecall-user-input.yaml`

```yaml
query:
  from: entry_function
  select: delegatecall
  where:
    - not: { preset: access_controlled }
    - has:
        block: identifier
        receiver: true
        tainted: parameter
```

Finds a `delegatecall` whose call receiver traces to a function parameter, on
a function with no privileged access control.

### B. Reentrancy — external call before state write, no guard

`templates/official/high/reentrancy-pattern.yaml`

```yaml
query:
  from: entry_function
  where:
    - not: { preset: reentrancy_guarded }
    - sequence:
        - any:
            - block: eth_transfer
            - block: delegatecall
        - block: state_write
```

Requires the function to lack a reentrancy guard and an ETH-bearing/low-level
call or `delegatecall` to occur before a state write on the same execution path
(CEI violation). Every sequence step supplies its own block kind, so no
top-level `select` is needed.

### C. Unprotected initializer

`templates/official/high/unprotected-initializer.yaml`

```yaml
query:
  from: entry_function
  where:
    - func_name: (?i)^(initialize|initialise|init|__init|setup)$
    - not: { preset: access_controlled }
    - not: { modifier: "(?i)(initializer|reinitializer)" }
    - has: { block: state_write }
    - not:
        has:
          block: guard
          has:
            block: identifier
            name: ^_initializersDisabled$
```

No `select:` — the whole match is expressed in `where` against the
`entry_function` scope root: a function named like an initializer, with no
access control and no `initializer`/`reinitializer` modifier, that writes
state and isn't gated behind an `_initializersDisabled()` guard.

### D. Arbitrary `transferFrom` — item-ownership vs. access control

`templates/official/high/arbitrary-transferfrom.yaml`

```yaml
query:
  from: entry_function
  select: external_call
  where:
    - not: { preset: caller_checked }
    - name: ^transferFrom$
    - arg.0: { tainted: parameter }
```

Uses `arg.0:` to require the `from` argument be parameter-tainted, and
`caller_checked` (not `access_controlled`) so that `require(from ==
msg.sender)` is correctly treated as a valid mitigation here.

---
