# WQL Syntax Guide

Complete reference for writing security templates using the W3GoAudit Query Language (WQL).

---

## Table of Contents

- [Template Structure](#template-structure)
- [Query Scopes](#query-scopes)
- [Filter Block](#filter-block)
- [Match Block](#match-block)
- [Logic Operators](#logic-operators)
- [Atomic Matchers](#atomic-matchers)
- [Node Kinds](#node-kinds)
- [Semantic Groups](#semantic-groups)
- [Traversal Operators](#traversal-operators)
- [Taint Analysis](#taint-analysis)
- [Call-Specific Matching](#call-specific-matching)
- [Complete Examples](#complete-examples)

---

## Template Structure

A WQL template is a YAML file with two top-level blocks: `meta` and `query`.

```yaml
meta:
  id: SEC-REEN-001
  title: "Reentrancy via External Call"
  severity: HIGH
  confidence: MEDIUM
  description: "..."
  recommendation: "..."

  # Optional metadata. All formatters surface these; SARIF output passes
  references:
    - https://swcregistry.io/docs/SWC-107
    - https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/
  fix: "Apply Checks-Effects-Interactions, or use a reentrancy guard."

query:
  scope: entrypoint

  # Layer 1: Function/contract-level preconditions
  filter:
    not:
      modifier: (?i)(nonReentrant|lock)

  # Layer 2: AST pattern matching
  match:
    sequence:
      - kind: outgoing_call
      - kind: state_write
```

The engine validates that `filter:` contains only filter-level fields and `match:` contains only AST-level fields. Putting AST fields like `kind:` inside `filter:` (or vice versa) returns a precise error at load time. `source_regex` is the exception: it is scope-aware and may be used in either block.

---

## Query Scopes

| Scope           | Description                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------------- |
| `entrypoint`    | Public/external functions of main contracts (most common)                                             |
| `function`      | All functions in all contracts                                                                        |
| `main_contract` | Only deployable main contracts                                                                        |
| `all_contract`  | Every contract/interface/library                                                                      |
| `contract`      | Contract-type definitions only                                                                        |
| `library`       | Library-type definitions only                                                                         |
| `abstract`      | Abstract contract definitions only                                                                    |
| `source`        | Raw source-file text. Useful for file-level `source_regex` checks such as Unicode control characters. |

---

## Filter Block

The `filter:` block defines function/contract-level **preconditions**. Matching against `match:` is only attempted on items that pass all filter checks.

```yaml
filter:
  modifier: (?i)(onlyOwner|auth)          # function HAS this modifier (regex)
  extends: ERC20                           # contract extends ERC20 (regex)
  version: ">=0.8.0"                       # Solidity version constraint
  has_param: from                          # function has parameter named 'from'
  source_regex: "msg\\.value"              # scoped raw source check
  func_name: ^(withdraw|deposit)$          # function name matches regex
  visibility_filter: public,external       # comma-separated visibility list
  mutability_filter: payable               # comma-separated mutability list
  has_guard:                               # function body has a guard matching this rule
    contains:
      kind: expr.member_access
      name: msg\.sender

  not:
    modifier: (?i)(nonReentrant|lock)      # function does NOT have this modifier
```

### Filter Field Reference

| Field               | Description                                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `modifier`          | Regex match against `fn.Modifiers[]`                                                                                                                                                 |
| `extends`           | Regex match against `contract.LinearizedBases[]`                                                                                                                                     |
| `version`           | Solidity pragma version constraint (`>=`, `<=`, `>`, `<`, `==`)                                                                                                                      |
| `has_param`         | Exact parameter name match in `fn.Parameters[]`                                                                                                                                      |
| `source_regex`      | Regex match against the current function or contract source snippet                                                                                                                  |
| `func_name`         | Regex match against function name                                                                                                                                                    |
| `visibility_filter` | Comma-separated: `public`, `external`, `internal`, `private`                                                                                                                         |
| `mutability_filter` | Comma-separated: `payable`, `view`, `pure`, `nonpayable`                                                                                                                             |
| `has_guard`         | Rule — function body must contain a matching `check.*` node                                                                                                                          |
| `preset`            | Built-in preset (returns true for the *vulnerable* case — use WITHOUT `not:` to scan vulnerable functions). Known names: `unAuthenticated` (no privileged access control), `unCheckedSender` (no privileged access control AND no caller self-scoping like `require(from == msg.sender)`), `unLocked` (no reentrancy guard). Unknown names error at load. |
| `not`               | Negate all conditions inside                                                                                                                                                         |

---

## Match Block

The `match:` block describes what code patterns to find in the function/contract body.

> **Default logic is AND.** When multiple fields are set in the same rule, ALL must match. You don't need to wrap them in `all:` explicitly.

```yaml
# These two are equivalent:
match:
  kind: call.external
  name: ^transferFrom$

match:
  all:
    - kind: call.external
    - name: ^transferFrom$
```

### Core Operators

| Operator       | Purpose                                    |
| -------------- | ------------------------------------------ |
| `kind`         | Match node type                            |
| `name`         | Match node name (regex)                    |
| `source_regex` | Match raw source text for the active scope |
| `contains`     | Search descendants                         |
| `inside`       | Search ancestors                           |
| `sequence`     | Ordered pattern                            |
| `all`          | AND logic (explicit)                       |
| `any`          | OR logic                                   |
| `not`          | Negation                                   |

---

## Logic Operators

### `all` — AND

```yaml
all:
  - contains: { kind: outgoing_call }
  - contains: { kind: state_write }
```

### `any` — OR

```yaml
any:
  - contains: { kind: call.builtin.transfer }
  - contains: { kind: call.builtin.send }
```

### `not` — Negation

```yaml
not:
  contains:
    kind: check.require
```

### `sequence` — Ordered (non-contiguous)

```yaml
sequence:
  - kind: outgoing_call
  - kind: state_write
```

> `sequence` collects all descendants depth-first and finds the pattern in source order. Does not require adjacency.
>
> **Control-flow aware:** consecutive matches must be able to co-execute on a
> single path. Two matches that fall into mutually-exclusive arms of the same
> control structure do **not** form a sequence:
>
> - the `then` vs `else` of an `if` — `if (c) { extCall(); } else { state = x; }`
>   does not match `sequence: [outgoing_call, state_write]`;
> - the two arms of a ternary (`cond ? a : b`);
> - the success body vs a `catch` clause of a `try/catch`, and two distinct
>   `catch` clauses — a call in the try body never sequences with a write in a
>   catch. (The try expression itself runs on every path, so it still sequences
>   with code in either arm.)
>
> This is a branch-arm check, **not a full CFG**: loops are still treated as
> straight-line, and there is no dominance reasoning — a `return`/`revert`
> sitting between two matches does not break the sequence.

---

## Atomic Matchers

### `kind` — Node Type

Supports exact match, prefix match, and semantic groups:

```yaml
kind: call.external              # Exact kind
kind: call                       # Prefix: matches all call.* kinds
kind: outgoing_call              # Semantic group
kind: guard                      # Alias for check
kind: guard.require              # Alias for check.require
kind: token_call                 # call.external for ERC20/ERC721 (pair with name:)
```

### `name` — Name/Value Match (regex)

```yaml
name: ^transferFrom$             # Exact name
name: (?i)(transfer|approve)     # Case-insensitive regex
name: "tx\\.origin"              # Escaped dot — quoted, doubled backslash
```

**Regex escaping (canonical form):** always use a **quoted string with
doubled backslashes** when the pattern contains regex metacharacters. The
bare `tx\.origin` (unquoted) works on some YAML parsers and silently
breaks on others — quoting + double-escape is portable.

Invalid regex patterns are rejected at template load, with an error naming the
offending field and the bad pattern. The previous silent fallback to
case-insensitive substring matching is gone.

### Inline Attributes

```yaml
# Inline attributes (flat). operator is anchored: this matches exactly "=", not "==".
kind: stmt.assign
is_state_var: true
operator: "="

# Nested attr (also works)
kind: stmt.assign
attr:
  is_state_var: true
```

**Common node attributes** (match via inline keys or `attr:`). String attribute
values are matched as **anchored** regexes — the pattern must describe the whole
value, so `operator: "="` matches exactly `=` and never `==`/`!=`/`>=`. (Only the
`name:` field is substring-matched.) Boolean values accept either a YAML bool
(`conditional_part: true`) or the quoted string form (`conditional_part: 'true'`).

| Attribute                              | Set on                                  | Values                                                       | Example use                                |
| -------------------------------------- | --------------------------------------- | ------------------------------------------------------------ | ------------------------------------------ |
| `operator`                             | `expr.binary_op`, `stmt.assign`         | `==`, `!=`, `&&`, `\|\|`, `+`, `=`, …                        | `operator: '==\|!='` (anchored)            |
| `subtype`                              | `expr.literal`                          | `number`, `string`, `bool`, `hex`                            | `attr: { subtype: bool }`                  |
| `cond_role`                            | condition of `if`/`while`/`for`/ternary | `if`, `loop`, `ternary`                                      | `attr: { cond_role: 'if\|ternary' }`       |
| `conditional_part`                     | children of `expr.conditional`          | `condition`, `true`, `false`                                | `attr: { conditional_part: true }`         |
| `try_part`                             | children of `stmt.try_catch`            | `expr`, `body`, `catch:N`                                   | `attr: { try_part: body }`                 |
| `loop_type`                            | `stmt.loop`                             | `for`, `while`, `do_while`                                   | `attr: { loop_type: while }`               |
| `is_state_var`                         | assignment target                       | `true`/`false`                                               | `is_state_var: true`                       |
| `type` / `type_kind`                   | typed expressions                       | `address`, `IERC20`; `primitive`, `interface`, `contract`, … | `attr: { type_kind: interface }`           |
| `receiver_type` / `receiver_type_kind` | member-call nodes                       | inferred receiver type and kind                              | `attr: { receiver_type_kind: interface }`  |
| `receiver_type_is_address`             | member-call nodes                       | `true` on primitive-address receivers                        | `attr: { receiver_type_is_address: true }` |

`cond_role` marks the *test expression* of a control structure, so you can match
a boolean literal that is genuinely a condition (`if (true)`) without also
matching one in the branch body (`if (c) return true;`) — the recursive
`contains` operator alone cannot make that distinction. Pair it with
`left`/`right` to require a literal be a *direct* operand of an operator:

```yaml
# Boolean-constant misuse: `x == true`, `a && false`, or `if (true)`
match:
  contains:
    any:
      - kind: expr.binary_op           # x == true / a && false
        operator: '^(==|!=|&&|\|\|)$'
        any:
          - left:  { kind: expr.literal, attr: { subtype: bool } }
          - right: { kind: expr.literal, attr: { subtype: bool } }
      - kind: expr.literal             # if (true) / true ? a : b
        attr: { subtype: bool, cond_role: '^(if|ternary)$' }
```

Semantic type attributes come from the database semantic layer. They are
best-effort facts for parameters, state variables, locals, casts, builtin address
expressions, and member-call receivers. Unknown receiver types fall back to the
older syntax/arity heuristics, so templates should prefer semantic groups such
as `token_call` and use these attributes only when the type distinction matters.

### `source_regex` — Scoped Raw Source Text

Use this when a rule needs exact source syntax that is not cleanly represented
in the Solidity AST. It is scope-aware:

- `scope: source` scans each whole source file and reports the matching line.
- `scope: contract`, `all_contract`, or `main_contract` checks the current contract source.
- `scope: function` or `entrypoint` checks the current function source.
- Inside an AST match, it first checks the current node's line range when available, then falls back to the current function/contract/file.

```yaml
query:
  scope: source
  match:
    source_regex: "(?i)import \".*ERC2771.*\\.sol\""
```

```yaml
query:
  scope: function
  filter:
    visibility_filter: public,external
    source_regex: "msg\\.value"
  match:
    kind: call.external
```

Prefer AST/context fields when they express the vulnerability. For example, a
Thirdweb-style ERC2771Context + Multicall rule should use inherited-base
context, not import text:

```yaml
query:
  scope: contract
  filter:
    all:
      - extends: (?i)^ERC2771Context$
      - extends: (?i)^Multicall$
  match: {}
```

---

## Node Kinds

### Call Kinds

| Kind                         | Solidity Example                         |
| ---------------------------- | ---------------------------------------- |
| `call.internal`              | `_mint(to, amt)`, `super.foo()`          |
| `call.external`              | `token.transfer(to, amt)`, `pool.swap()` |
| `call.lowlevel.call`         | `addr.call{value:x}(data)`               |
| `call.lowlevel.delegatecall` | `addr.delegatecall(data)`                |
| `call.lowlevel.staticcall`   | `addr.staticcall(data)`                  |
| `call.builtin.transfer`      | `payable(addr).transfer(x)`              |
| `call.builtin.send`          | `payable(addr).send(x)`                  |
| `call.create`                | `new Token(args)`                        |

### Check Kinds

| Kind            | Solidity Example                        |
| --------------- | --------------------------------------- |
| `check.require` | `require(cond, "msg")`                  |
| `check.assert`  | `assert(invariant)`                     |
| `check.revert`  | `revert("msg")`, `revert CustomError()` |

### Statement Kinds

| Kind             | Solidity Example     |
| ---------------- | -------------------- |
| `stmt.assign`    | `balance = 0`        |
| `stmt.if`        | `if (cond) { ... }`  |
| `stmt.loop`      | `for/while/do-while` |
| `stmt.return`    | `return value`       |
| `stmt.emit`      | `emit Transfer(...)` |
| `stmt.try_catch` | `try ... catch ...`  |
| `stmt.block`     | `{ ... }`            |
| `stmt.unchecked` | `unchecked { ... }`  |

### Expression Kinds

| Kind                 | Solidity Example              |
| -------------------- | ----------------------------- |
| `expr.identifier`    | `balance`, `owner`            |
| `expr.literal`       | `100`, `"hello"`, `true`      |
| `expr.binary_op`     | `a + b`, `x == y`             |
| `expr.unary_op`      | `!flag`, `i++`                |
| `expr.member_access` | `msg.sender`, `token.balance` |
| `expr.index_access`  | `balances[addr]`              |
| `expr.conditional`   | `cond ? a : b`                |
| `expr.tuple`         | `(a, b)` in `(a, b) = (b, a)` |

### Assembly Kinds

| Kind               | Solidity Example             |
| ------------------ | ---------------------------- |
| `asm.block`        | `assembly { ... }`           |
| `asm.call`         | `call(gas, to, val, ...)`    |
| `asm.delegatecall` | `delegatecall(gas, to, ...)` |
| `asm.staticcall`   | `staticcall(gas, to, ...)`   |
| `asm.sstore`       | `sstore(slot, val)`          |
| `asm.sload`        | `sload(slot)`                |
| `asm.selfdestruct` | `selfdestruct(addr)`         |
| `asm.operation`    | `mload`, `mstore`, etc.      |

---

## Semantic Groups

Semantic groups match multiple kinds based on security concern:

| Group           | Matches                                  | Use Case                              |
| --------------- | ---------------------------------------- | ------------------------------------- |
| `outgoing_call` | All calls to external code               | Reentrancy detection                  |
| `eth_transfer`  | `.transfer()`, `.send()`, `.call{value}` | ETH drain detection                   |
| `delegatecall`  | `.delegatecall()`, `asm delegatecall`    | Arbitrary execution                   |
| `check`         | `require()`, `assert()`, `revert()`      | Guard detection                       |
| `guard`         | Same as `check`                          | Alias — `kind: guard` = `kind: check` |
| `guard.require` | `check.require`                          | Alias                                 |
| `guard.assert`  | `check.assert`                           | Alias                                 |
| `guard.revert`  | `check.revert`                           | Alias                                 |
| `token_call`    | `call.external`                          | ERC20/ERC721 calls; pair with `name:` |
| `state_write`   | Assignment to state var + `asm sstore`   | State modification                    |
| `state_read`    | State var read + `asm sload`             | Storage reads                         |
| `any_call`      | All call types including internal        | Call graph analysis                   |
| `selfdestruct`  | `selfdestruct()` + `asm selfdestruct`    | Destruction detection                 |

### Prefix Matching

The dot-notation enables prefix matching:

```yaml
kind: call              # Matches all call.* (internal, external, lowlevel, builtin)
kind: call.lowlevel     # Matches call.lowlevel.call, .delegatecall, .staticcall
kind: check             # Matches check.require, check.assert, check.revert
kind: guard             # Alias: matches guard.require, guard.assert, guard.revert
kind: asm               # Matches all asm.* operations
kind: stmt              # Matches all stmt.* statements
kind: expr              # Matches all expr.* expressions
```

### token_call Usage

`token_call` matches any `call.external` node. Always combine with `name:` to restrict to specific ERC20/ERC721 methods:

```yaml
contains:
  kind: token_call
  name: ^(transfer|transferFrom|approve|safeTransfer|safeTransferFrom)$
```

---

## Traversal Operators

### `contains` — Descendant Search

```yaml
contains:
  kind: outgoing_call
  name: ^transfer$
```

Searches recursively through all descendants. Nesting `contains` is supported:

```yaml
# Find a delegatecall with user-controlled target
contains:
  kind: delegatecall
  args:
    0:
      kind: expr.identifier
      tainted_from: parameter
```

### `inside` — Ancestor Search

```yaml
contains:
  kind: expr.member_access
  name: tx\.origin
  inside:
    kind: stmt.if
```

Checks if the matched node is inside an ancestor of the specified kind.

---

## Taint Analysis

### `tainted_from`

```yaml
tainted_from: parameter      # Value comes from function parameter, including expressions like from[i]
tainted_from: state_var       # Value comes from state variable
tainted_from: local_var       # Value comes from local variable
tainted_from: sender          # Value derives from msg.sender / tx.origin (caller identity)
```

`tainted_from` accepts only those four values; any other value is rejected at
template load (it would otherwise silently match nothing at scan time).

> **Interprocedural caveat:** at `entrypoint` scope, structural `sequence:` rules
> are evaluated over the inlined call-graph view, but `contains:`/`all:`/`not:`
> predicates are applied **per function** (the entrypoint and each internal
> callee independently). A `not: { contains: guard }` therefore does not let a
> guard in the entrypoint suppress a match in a helper, and an `all:` cannot
> straddle entrypoint + helper except via `sequence:`. Use `sequence:` when you
> need a cross-function ordering.

For `entrypoint` scans, taint is context-sensitive across internal helper
calls. If an external function calls `_deposit(from, amount)`, the callee's
`from` parameter remains `parameter`-tainted. If it calls
`_deposit(msg.sender, amount)`, the callee's `from` parameter is treated as
sender identity and does not match `tainted_from: parameter`.

Simple local aliases are propagated before internal calls:

```solidity
address payer = from;        // payer is parameter-tainted
_deposit(payer, amount);

address payer = msg.sender;  // payer is sender identity, not arbitrary input
_deposit(payer, amount);
```

Member-call receivers are also available to taint-aware templates as a tagged
child with `attr.call_receiver = true`. This lets a detector distinguish the
receiver in `target.delegatecall(data)` from the calldata argument `data`:

```yaml
contains:
  kind: delegatecall
  contains:
    attr:
      call_receiver: true
    tainted_from: parameter
```

---

## Call-Specific Matching

### `args` — Argument Matching

Two equivalent notations are accepted:

```yaml
# Nested map (numeric keys)
args:
  0:                           # First argument
    kind: expr.identifier
    tainted_from: parameter

# Flat arg.N keys (equivalent)
arg.0:
  kind: expr.identifier
  tainted_from: parameter
```

> **Common mistake:** Do NOT write `args: [{kind: ...}]` (list syntax). Only map syntax works.

`args.N` indexes Solidity arguments only. Metadata children such as
`call_receiver` and `{value:}` call-option expressions are skipped, so `args.0`
continues to mean the first source-level argument even for
`target.call{value: amount}(data)`.

---

## Complete Examples

### Reentrancy Detection

```yaml
meta:
  id: HIGH-REENTRANCY-PATTERN
  title: Potential Reentrancy
  severity: HIGH
  confidence: MEDIUM

query:
  scope: entrypoint

  filter:
    not:
      modifier: (?i)(nonReentrant|lock|guard)

  match:
    sequence:
      - kind: outgoing_call
      - kind: state_write
```

### Arbitrary transferFrom

```yaml
meta:
  id: HIGH-ARBITRARY-TRANSFERFROM
  title: Arbitrary transferFrom Call
  severity: HIGH
  confidence: MEDIUM

query:
  scope: entrypoint

  filter:
    preset: unAuthenticated

  match:
    contains:
      kind: token_call
      name: ^transferFrom$
      args:
        0:
          tainted_from: parameter
```

### tx.origin Authentication

```yaml
meta:
  id: MEDIUM-TX-ORIGIN-AUTH
  title: tx.origin Used for Authentication
  severity: MEDIUM
  confidence: HIGH

query:
  scope: function

  match:
    contains:
      kind: expr.member_access
      name: tx\.origin
      inside:
        kind: stmt.if
```

### Unprotected selfdestruct

```yaml
meta:
  id: CRITICAL-SELFDESTRUCT-UNPROTECTED
  title: Unprotected selfdestruct
  severity: CRITICAL
  confidence: HIGH

query:
  scope: entrypoint

  filter:
    not:
      modifier: (?i)(onlyOwner|onlyAdmin|onlyRole|requiresAuth|auth|admin)

  match:
    contains:
      kind: selfdestruct
```

### Payable Functions Without Event

```yaml
meta:
  id: SEC-EVENT-PAYABLE-001
  title: Payable Function Missing Event
  severity: LOW
  confidence: HIGH

query:
  scope: function

  filter:
    visibility_filter: public,external
    mutability_filter: payable

  match:
    all:
      - contains:
          kind: state_write
      - not:
          contains:
            kind: stmt.emit
```
