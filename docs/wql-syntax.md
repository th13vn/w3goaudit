# WQL Syntax Guide

Complete reference for writing security templates using the W3GoAudit Query
Language (WQL) **v2** — the primary template syntax as of v0.4. All 106
official, benchmark, and feature-test templates shipped in this repository
are written in v2. The legacy v1 `query:` syntax is still accepted by the
loader (auto-detected) and documented in the [migration appendix](#migrating-from-v1)
for anyone maintaining old templates, but new templates should use v2.

This reference is accurate to the **implementation** —
[`pkg/engine/wql_v2.go`](../pkg/engine/wql_v2.go) (parser + lowering to the v1
`Rule` IR) and [`pkg/engine/wql_v2_catalog.go`](../pkg/engine/wql_v2_catalog.go)
(the exact block-kind / attribute / preset name tables) — not just the design
spec. Where the two ever disagree, the code wins.

---

## Table of Contents

- [1. Template Shape](#1-template-shape)
- [2. `select` — What to Find](#2-select--what-to-find)
- [3. `from` — Scope Table](#3-from--scope-to-search)
- [4. `where` — The Matcher Grammar](#4-where--the-matcher-grammar)
- [5. Block-Kind Catalog](#5-block-kind-catalog)
- [6. Attribute Catalog](#6-attribute-catalog)
- [7. Presets](#7-presets)
- [8. Taint](#8-taint)
- [9. Worked Examples](#9-worked-examples)
- [Migrating from v1](#migrating-from-v1)

---

## 1. Template Shape

A WQL v2 template is a YAML file with `meta` (unchanged from v1) plus three
top-level query keys: `select`, `from`, `where`. There is no `filter:`/`match:`
split — `from` picks the scope to search, `where` is a flat list of matchers
(implicit AND) that constrain it. The engine still runs the same v1 evaluator
underneath; v2 is purely a friendlier authoring surface that the loader lowers
into the v1 `Template`/`Rule` IR (`TemplateV2.lower()` in `wql_v2.go`).

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

select: delegatecall        # WHAT to find & report (a block kind)
from: entry_function        # WHERE to search (a scope)
where:                      # list of matchers, implicit AND
  - arg.0: { tainted: parameter }
  - not: { preset: access_controlled }
```

`meta` fields are unchanged: `id` and `severity` are required at load time;
`severity` must be one of `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`.

The loader auto-detects v1 vs v2 per file: a document with a top-level
`select` and/or `from` (and no top-level `query`) is parsed as v2
(`isV2Source` in `wql_v2.go`); anything else falls back to the v1 `query:`
loader. You never declare which version a file uses — it's inferred from
its shape.

---

## 2. `select` — What to Find

`select` names the block kind(s) (§5) whose matches become the finding's
anchor node(s).

- **Scalar** — one block kind, e.g. `select: delegatecall`. The matched node
  of that kind is the finding's `PrimaryAST`.
- **List (combo)** — `select: [kind_a, kind_b]` finds a `from`-scope that
  contains **all** listed kinds; every matched site is attached to the
  finding via the multi-site `Finding.Related` mechanism (each branch gets a
  positional label like `site 1`/`site 2` unless overridden with `label:` in
  a nested `all:` branch — see §4). `where` matchers merge onto the
  **first** listed kind only; use labeled `all:` branches inside `where` for
  per-kind constraints (worked example in the language spec §11.C).
- **Optional** — `select` may be omitted entirely. When it is, `where` must
  fully define the match on its own — there is no implicit "find a node of
  this kind" step. This is used for **contract-scope pure-regex** detectors
  that have no single AST anchor: `from: contract` plus a `where:` built out
  of `has: { regex: ... }` / `all:` / `not:` branches evaluates directly at
  the scope root (see `templates/official/high/proxy-storage-collision.yaml`
  for a real example). Omitting `select` with nothing usable in `where`
  is a load-time error (`buildMatch`: *"select: required for scope ... unless
  where contains AST-level matchers"*).

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

`where` is a list; sibling items are implicit **AND** — there is no `and:`
keyword. Every item is a one-key matcher map. Matchers nest uniformly: a
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
| `has: <matcher>` | Some **descendant** of the node matches. |
| `in: <matcher>` | Some **ancestor** of the node matches. |
| `guarded_by: <matcher>` | A guard/modifier in the function's guard context matches. |
| `sequence: [<matcher>, ...]` | Ordered, same-execution-path occurrence of each matcher in turn (reentrancy / CEI patterns). Rejects pairs that first diverge into mutually exclusive branch arms (`if`/`else`, ternary arms, `try`/`catch` arms). |
| `left: <matcher>` | Left operand of a binary/assignment/member-access node matches. |
| `right: <matcher>` | Right operand matches. |
| `statement_has: <matcher>` | Sub-rule matched against the node's nearest enclosing statement (narrower than `in:`, wider than `has:`) — e.g. "no other bitwise operator in this same statement". |
| `unchecked_var: true` | On an arithmetic `binary` node, true when no preceding guard in the same function bounds every operand with an ordering comparison before an `unchecked { ... }` use. |
| `modifier: <regex>` | Function has a modifier whose name matches. |
| `base: <regex>` | Contract-scope: the contract (or an ancestor in its inheritance chain) matches (v1 `extends:`). |
| `func_name: <regex>` | Function name matches (function-level precondition, independent of the AST node's own `name:`). |
| `version: <constraint>` | Solidity pragma version constraint, e.g. `">=0.8.0"`. |
| `has_param: <name>` | Function has a parameter with this name. |

### Logic

| Matcher | Meaning |
|---|---|
| `any: [<matcher>, ...]` | OR. |
| `not: <matcher>` | Negation. |
| `all: [<matcher>, ...]` | Explicit AND grouping — used to group a branch inside `any:`/`not:`, or to carry a `label:` for combo-`select` multi-site naming. Each branch may also set `label:` as a sibling key alongside its own matchers. |

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

Every name below is resolved by `blockKindToV1` (`wql_v2_catalog.go`) — usable
in `select:` and as `block: <kind>` in `where`.

**Calls**

| v2 name | Underlying v1 kind |
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

| v2 name | Underlying v1 kind |
|---|---|
| `guard` | `check` — any require/assert/revert |
| `require` | `check.require` |
| `assert` | `check.assert` |
| `revert` | `check.revert` |

**State**

| v2 name | Underlying v1 kind |
|---|---|
| `state_write` | `state_write` — `stmt.assign` on a state var, or `asm.sstore` |
| `state_read` | `state_read` — state-var identifier read, or `asm.sload` |

**Statements**

| v2 name | v1 kind | v2 name | v1 kind |
|---|---|---|---|
| `assign` | `stmt.assign` | `return` | `stmt.return` |
| `if` | `stmt.if` | `emit` | `stmt.emit` |
| `loop` | `stmt.loop` | `try_catch` | `stmt.try_catch` |
| `unchecked` | `stmt.unchecked` | `block` | `stmt.block` |

**Expressions**

| v2 name | v1 kind | v2 name | v1 kind |
|---|---|---|---|
| `identifier` | `expr.identifier` | `member` | `expr.member_access` |
| `literal` | `expr.literal` | `index` | `expr.index_access` |
| `binary` | `expr.binary_op` | `ternary` | `expr.conditional` |
| `unary` | `expr.unary_op` | `tuple` | `expr.tuple` |

**Declarations**

| v2 name | v1 kind | v2 name | v1 kind |
|---|---|---|---|
| `function` | `decl.function` | `variable` | `decl.variable` |
| `contract` | `decl.contract` | `parameter` | `decl.parameter` |
| `modifier` | `decl.modifier` | | |

**Assembly**

| v2 name | v1 kind | v2 name | v1 kind |
|---|---|---|---|
| `asm` | `asm.block` | `asm_staticcall` | `asm.staticcall` |
| `asm_sstore` | `asm.sstore` | `asm_create` | `asm.create` |
| `asm_sload` | `asm.sload` | `asm_selfdestruct` | `asm.selfdestruct` |
| `asm_delegatecall` | `asm.delegatecall` | `asm_revert` | `asm.revert` |
| `asm_call` | `asm.call` | `asm_return` | `asm.return` |

> `asm_log` is **not** implemented (no single v1 kind covers all
> `asm.log0`..`asm.log4` arities); it is documented in the design spec but
> intentionally absent from `blockKindToV1Table` — using it errors at load
> with "unknown block kind".

---

## 6. Attribute Catalog

Resolved by `attrNameToV1` (`wql_v2_catalog.go`). `name`, `visibility`,
`mutability`, and `tainted` are handled directly as their own matcher forms
(§4), not through this table.

**Core**

| v2 attribute | Meaning | Underlying v1 key |
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

| v2 attribute | Meaning | Underlying v1 key |
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
(`visibility: public,external`), matching v1.

---

## 7. Presets

v1 presets all returned `true` for the **vulnerable** case (a documented
footgun — the property's *absence*). v2 presets are renamed to describe the
safety **property** itself, so they read naturally either asserted or
negated. Semantics are preserved exactly (`presetToV1` in
`wql_v2_catalog.go` does the polarity flip during lowering).

| v2 preset (property = true) | Property | Vulnerable expression |
|---|---|---|
| `access_controlled` | Privileged access control is present — owner/admin/role modifier, an internal auth-helper call, or a `msg.sender`/`tx.origin` guard against a hardcoded/storage owner, checked recursively through internal/inherited calls. | `not: { preset: access_controlled }` |
| `caller_checked` | Either the function is access-controlled, OR it self-scopes the caller — binds a sensitive argument to `msg.sender` (`require(from == msg.sender)`), including the **item-ownership** form `ownerOf(tokenId) == msg.sender` (and its interprocedural forwarded equivalents). | `not: { preset: caller_checked }` |
| `reentrancy_guarded` | A reentrancy-guard modifier (`nonReentrant`/`lock`/`mutex`/etc.) is present. | `not: { preset: reentrancy_guarded }` |
| `user_controlled` | Reachable from external/tainted input (parameter or `msg.sender`). No v1 preset counterpart — lowered as `tainted: parameter` on the matched node. | `preset: user_controlled` (asserted directly, not negated) |

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

The engine performs the propagation (unchanged from v1): flow-sensitive
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
from: entry_function
select: state_write
where:
  - not: { preset: reentrancy_guarded }
  - sequence:
      - any:
          - block: eth_transfer
          - block: delegatecall
      - block: state_write
```

Anchors on a `state_write`, requires the function to lack a reentrancy guard,
and requires an ETH-bearing/low-level call or `delegatecall` to occur
earlier on the same execution path (CEI violation).

### C. Unprotected initializer

`templates/official/high/unprotected-initializer.yaml`

```yaml
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

## Migrating from v1

The v1 `query: { scope, filter, match }` syntax still loads (the loader
auto-detects it) but new templates should use v2. Key mapping:

| v1 | v2 |
|---|---|
| `query.scope` | `from` |
| `query.filter` + `query.match` | collapsed into `from` + `where` (no layer split — the loader derives the filter/AST split automatically) |
| `kind:` | `block:` (renamed values — see §5) |
| `name:` | `name:` (unchanged) |
| `contains:` | `has:` |
| `inside:` | `in:` |
| `statement_contains:` | `statement_has:` |
| `args: {N: ...}` / `arg.N:` | `arg.N:` (unchanged) |
| `tainted_from:` | `tainted:` |
| `has_guard:` | `guarded_by:` |
| `modifier:` | `modifier:` (unchanged) |
| `extends:` | `base:` |
| `func_name:` | `func_name:` (unchanged) |
| `version:` | `version:` (unchanged) |
| `left:` / `right:` | `left:` / `right:` (unchanged) |
| `unchecked_var:` | `unchecked_var:` (unchanged) |
| `preset: unAuthenticated` (bare) | `not: { preset: access_controlled }` |
| `preset: unCheckedSender` (bare) | `not: { preset: caller_checked }` |
| `preset: unLocked` (bare) | `not: { preset: reentrancy_guarded }` |
| `all:` / `any:` / `not:` / `sequence:` | unchanged |
| `label:` | unchanged (sibling key on an `all:` branch) |
| `regex:` | unchanged, but now block-line-scoped instead of whole-function/contract-scoped |
| `visibility:` / `mutability:` | unchanged (comma-separated attribute matchers) |

See `templates/security/*.yaml` for real v1 examples still shipped as legacy
seeds, and the language spec
(`.vscode/specs/2026-07-09-wql-v2-language-spec.md`) §10 for the full
rationale behind each rename.
