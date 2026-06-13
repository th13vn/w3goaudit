# templates/ - Security Detector Templates

## Purpose

WQL templates for smart-contract security scanning. Each `.yaml` file is a
self-contained detector. The `official/` pack is embedded in the binary
(`//go:embed`) and runs by default; point `--template` at any file or directory
to override it.

## Curation Policy

Only **HIGH / MEDIUM / CRITICAL** severity templates ship here. LOW and INFO
severities (and gas-optimisation rules) have been removed — they produce
noise that drowns out genuine findings. Templates that cannot be made
precise (e.g. detectors with no way to distinguish a true positive from a
legitimate pattern) are also out.

## Directory Structure

```
templates/
├── official/   # Curated official detector pack (25) — embedded; run THIS to audit
└── test/       # WQL feature-test templates (NOT production detectors)
```

> **`official/` is the pack you scan with.** It is the curated, best-of-breed
> set of hand-written W3GoAudit-native detectors. It is embedded in the binary,
> so a bare `w3goaudit ./contracts/` uses it automatically — no `--template`
> flag required. Point `--template templates/official/` explicitly when running
> from a source checkout.
>
> `test/` is **not** a production detector set — it holds low-confidence
> feature-exercise templates paired with fixtures in
> [`../test-data/core/engine-features/`](../test-data/core/engine-features/) to
> smoke-test WQL engine operators (`sequence`, `inside`, semantic groups,
> `args` + `tainted_from`). Run it with
> `w3goaudit test-data/core/engine-features/ --template templates/test/`.
> Do not point production scans at it.

## official/ — Curated Detectors

Templates are exercised against fixtures under
[`../test-data/security/`](../test-data/security/). Detectors whose
**FP exclusions** matter (e.g. `selfdestruct-unprotected`'s inline-guard
carve-out, `tx-origin-auth`'s `msg.sender == tx.origin` whitelist) have
dedicated `Vulnerable*`/`Safe*` fixtures named after the template. Some
contracts named `Safe_*` for one vulnerability class intentionally still
contain other bug classes, so whole-directory scans are assessed by
template/category rather than by name prefix alone.

> **Classification metadata (cwe/owasp):** templates currently carry `references`
> (SWC/EIP/Slither links) for classification. Dedicated `cwe`/`owasp` fields are
> not yet emitted — adding them requires `engine.TemplateMeta` fields plus SARIF
> `taxa` propagation, tracked as a follow-up. Until then, use `references`.

| ID | Severity | File | Detects |
|---|---|---|---|
| `SEC-DEST-001` | CRITICAL | `selfdestruct-unprotected.yaml` | `selfdestruct(...)` (Solidity-level OR assembly opcode) reachable from an unauthenticated entrypoint (`preset: unAuthenticated` — modifiers, inline sender guards, and recursive auth helpers) |
| `SEC-DELEG-001` | CRITICAL | `delegatecall-user-input.yaml` | `delegatecall` whose target flows from a function parameter |
| `SEC-ETH-001` | HIGH | `arbitrary-send-eth.yaml` | Unprotected ETH withdrawal via `.transfer` / `.send` / `.call{value:}` |
| `SEC-ERC20-001` | HIGH | `arbitrary-transferfrom.yaml` | `transferFrom(from, ...)` where `from` is user-controlled across entrypoint/helper flows and lacks sender/auth validation |
| `SEC-ERC20-002` | HIGH | `unchecked-erc20-transfer.yaml` | ERC20 `transfer` / `transferFrom` whose bool return is discarded |
| `SEC-GEN-REENTRANCY` | HIGH | `reentrancy-pattern.yaml` | CEI violation — ETH-bearing call / raw low-level `.call` / `delegatecall` followed by a state write, on a function lacking a reentrancy guard |
| `SEC-REENTRANCY-002` | HIGH | `reentrancy-balance.yaml` | `balanceOf` → external-call → balance-read pattern without a reentrancy guard (delta-snapshot exploit) |
| `SEC-DELEG-002` | HIGH | `delegatecall-in-loop.yaml` | `delegatecall` inside a `for`/`while` body (payable-multicall ETH reuse) |
| `SEC-UPGRADE-001` | HIGH | `unprotected-initializer.yaml` | `initialize/init/setup` entrypoint that writes state with no access control or `initializer` guard |
| `SEC-PRNG-001` | HIGH | `weak-prng.yaml` | Modulo over `block.timestamp` / `block.number` / `block.prevrandao` / `blockhash` |
| `SEC-MSGVAL-001` | HIGH | `msg-value-in-loop.yaml` | `msg.value` referenced inside a loop body in a `payable` entrypoint (multicall ETH reuse) |
| `SEC-MATH-003` | HIGH | `incorrect-exp.yaml` | `^` (bitwise XOR) used in arithmetic context — "developer meant `**`" foot-gun |
| `SEC-HASH-001` | HIGH | `encode-packed-collision.yaml` | `keccak256(abi.encodePacked(...))` over ≥2 user-controlled dynamic args (ambiguous packing → collision) |
| `SEC-PROXY-001` | HIGH | `proxy-storage-collision.yaml` | Proxy subclass declares plain mutable storage alongside a constructor (implementation slot collision) |
| `SEC-SIG-001` | HIGH | `ecdsa-recover-malleable.yaml` | `ECDSA.recover` result keyed by the raw `signature` bytes (malleability replay) |
| `SEC-CALL-001` | HIGH | `arbitrary-low-level-call.yaml` | Unauthenticated entrypoint forwards a user-controlled target AND calldata into a low-level `.call` |
| `SEC-OWNER-001` | HIGH | `unrestricted-transferownership.yaml` | `transferOwnership` entrypoint writes owner-like state from a parameter with no access control |
| `SEC-SEND-001` | MEDIUM | `unchecked-send.yaml` | `addr.send(amt)` whose bool return is discarded |
| `SEC-LOWLEVEL-CALL-001` | MEDIUM | `unchecked-lowlevel-call.yaml` | Low-level `.call(data)` / `.call{value:}(data)` whose `(bool, bytes)` return is discarded |
| `SEC-EQ-001` | MEDIUM | `dangerous-strict-equality.yaml` | `==` / `!=` against `address(this).balance`, `balanceOf(...)`, `block.timestamp`, `block.number` |
| `SEC-MATH-002` | MEDIUM | `divide-before-multiply.yaml` | `(a / b) * c` shape — divide is the left operand of a multiply (precision-loss bug) |
| `SEC-MUTABILITY-001` | MEDIUM | `view-pure-modifies-state.yaml` | `view` / `pure` function that writes state (including inline-assembly `sstore` bypass) |
| `SEC-TXORIGIN-001` | MEDIUM | `tx-origin-auth.yaml` | `tx.origin` used inside any guard (`require` / `assert` / `if` / ternary) |
| `SEC-MATH-001` | MEDIUM | `unchecked-arithmetic.yaml` | Arithmetic inside `unchecked { ... }` on Solidity `>=0.8.0` |
| `SEC-BOOL-001` | MEDIUM | `boolean-cst.yaml` | Boolean literal misused as a comparison/logical operand (`x == true`, `a && false`) or directly as an `if`/ternary condition (`if (true)`). Plain `return true` / `flag = false` / `while (true)` are not flagged |

`references` is **optional** — present only where a canonical smart-contract
reference exists (SWC registry, Slither wiki, Solidity docs, EIPs). The engine
propagates references to findings; Markdown / HTML / JSON / SARIF formatters
surface them, and SARIF emits GitHub `security-severity` scores.

---

## Template Structure

```yaml
meta:
  id: STRING
  title: STRING
  severity: LEVEL               # INFO|LOW|MEDIUM|HIGH|CRITICAL
  confidence: LEVEL             # LOW|MEDIUM|HIGH
  description: STRING
  recommendation: STRING

query:
  scope: SCOPE                  # entrypoint|function|main_contract|all_contract|contract|library|abstract

  filter:                       # Function/contract-level preconditions (optional)
    modifier: REGEX             # function HAS this modifier
    func_name: REGEX            # function name matches regex
    visibility_filter: a,b      # comma-separated: public,external,internal,private
    mutability_filter: a,b      # comma-separated: payable,view,pure,nonpayable
    has_guard:                  # function body must contain a guard matching this rule
      contains:
        kind: expr.identifier
        name: PATTERN
    not:                        # Negate filter conditions
      modifier: REGEX

  match:                        # AST pattern matching
    # Default logic is AND — all fields must match
    # Rules: contains, name, sequence, tainted_from, kind, etc.
    sequence:
      - kind: outgoing_call
      - kind: state_write
```

---

## WQL Features Demonstrated

### Semantic Groups

```yaml
# guard (= check): detect require/assert/revert
contains:
  kind: guard.require

# token_call: detect ERC20/ERC721 external calls
contains:
  kind: token_call
  name: ^(transfer|transferFrom|approve|safeTransfer|safeTransferFrom)$
```

### Filter Predicates

```yaml
filter:
  # Match only functions named withdraw or deposit
  func_name: ^(withdraw|deposit)$

  # Match only public or external functions
  visibility_filter: public,external

  # Match only payable functions
  mutability_filter: payable

  # Match only functions that have a msg.sender guard
  has_guard:
    contains:
      kind: expr.member_access
      name: msg\.sender
```

### Presets

Every built-in preset returns `true` for the **vulnerable** case, so use
them WITHOUT a `not:` wrapper in `filter:`. The filter passes only for the
functions you actually want to scan further.

```yaml
filter:
  preset: unAuthenticated    # scan only entry points lacking access control
```

```yaml
filter:
  preset: unLocked           # scan only functions lacking a reentrancy guard
```

Unknown preset names are rejected at template load with the list of
known presets, so typos like `preset: unAuthenticatd` fail fast.

### Taint Analysis
```yaml
tainted_from: parameter  # or state_var, local_var; entrypoint scans propagate through internal helper calls
```

Member-call receivers are preserved as tagged children, so receiver-tainted
sinks can be expressed without confusing calldata arguments:

```yaml
contains:
  kind: delegatecall
  contains:
    attr:
      call_receiver: true
    tainted_from: parameter
```

### Argument Matching

Two equivalent notations:

```yaml
# Nested map
args:
  0:
    kind: expr.identifier
    tainted_from: parameter

# Flat keys
arg.0:
  kind: expr.identifier
  tainted_from: parameter
```

### Version Checking
```yaml
filter:
  version: ">=0.8.0"  # or <0.8.0, >0.7.0, etc.
```

### Left/Right Matching
```yaml
kind: expr.member_access
left:
  name: tx
right:
  name: origin
```

### Regex Escaping

`name:`, `modifier:`, `extends:`, `func_name:` and string-valued
attributes are all interpreted as Go regular expressions. Escape regex
metacharacters using **quoted strings with doubled backslashes** so the
YAML parser preserves the backslash:

```yaml
# correct — quoted, doubled backslash
name: "tx\\.origin"

# fragile — bare backslash works by accident on some YAML parsers
name: tx\.origin
```

Invalid regexes (e.g. unterminated groups) are rejected at template
load with the line of the offending field. There is no silent fallback
to substring matching.

---

## Adding New Templates

1. Pick the right directory:
   - `official/` — curated, audit-grade patterns with optional `references`.
   - `test/` — low-confidence feature-exercise templates for WQL operators
     (paired with `../test-data/core/engine-features/`), NOT production detectors.
2. Follow WQL syntax (see [../docs/wql-syntax.md](../docs/wql-syntax.md)).
3. Test against fixtures in [`../test-data/security/`](../test-data/security/):
   add a `Vulnerable_*` / `Safe_*` pair named after the detector.
4. Verify the `Vulnerable_*` cases trigger and the `Safe_*` cases do not.
5. Add the template to the table in this INDEX.md.

---

## Usage

`--template` is single-valued and accepts either a file or a directory. When
given a directory it walks every `.yaml` underneath. When omitted, the embedded
`official/` pack is used.

```bash
# Audit with the built-in official pack (the normal case — no flag needed)
w3goaudit ./contracts/

# Equivalent, pointing at the pack explicitly from a source checkout
w3goaudit ./contracts/ --template templates/official/

# Run a single specific detector
w3goaudit ./contracts/ --template templates/official/reentrancy-pattern.yaml

# Full integration scan with verbose log
w3goaudit test-data/security/ --template templates/official/ --verbose=/tmp/scan.log
```

Template directories fail closed by default. Use `--ignore-invalid-templates`
only for ad-hoc mixed directories; skipped files are then reported with
`--verbose`:
```
Loaded template: SEC-ERC20-001 (templates/official/arbitrary-transferfrom.yaml)
Skipping invalid template broken.yaml: parse YAML: yaml: line 3: ...
Skipping template missing-id.yaml: missing meta.id
```
