# templates/ - Security Detector Templates

## Purpose

WQL templates for smart-contract security scanning. Each `.yaml` file is a
self-contained detector. The `official/` pack is embedded in the binary
(`//go:embed`) and serves as the always-available offline fallback.

## Template Language: WQL

**All templates under `official/` and `test/` (this directory), plus every
benchmark template under `../benchmarks/templates/` (slither-inspired,
decurity-semgrep-inspired, 4naly3er-inspired) — 106 templates total — are
written in WQL** (`select`/`from`/`where`). See
[`../docs/wql-syntax.md`](../docs/wql-syntax.md) for the full language
reference.

### Template precedence (v0.3)

A scan resolves templates in this order (see `cmd/w3goaudit/scan_filters.go`):

1. `--template <file|dir>` — explicit override (highest).
2. `~/.w3goaudit/templates/` — the **template home**, populated nuclei-style on
   first run by downloading the latest release of
   [`th13vn/w3goaudit-templates`](https://github.com/th13vn/w3goaudit-templates)
   (zipball, not `git clone`). Refresh with `w3goaudit --update-templates`.
   Managed by `pkg/home` (see its INDEX).
3. The embedded `official/` pack — used when the home is empty or a download
   failed (offline, repo/release missing). The tool never hard-fails on a
   download error.

This `templates/official/` directory in the repo is both the embedded pack and
the seed content published to the `w3goaudit-templates` release.

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
└── test/       # WQL feature-test templates (5; NOT production detectors)
```

(The 76 benchmark templates — Decurity/Slither/4naly3er-inspired — live under
`../benchmarks/templates/`, outside this directory; see
[`../benchmarks/README.md`](../benchmarks/README.md).)

> **`official/` is the pack you scan with.** It is the curated, best-of-breed
> set of hand-written W3GoAudit-native detectors. It is embedded in the binary,
> so a bare `w3goaudit ./contracts/` uses it automatically — no `--template`
> flag required. Point `--template templates/official/` explicitly when running
> from a source checkout.
>
> `test/` is **not** a production detector set — it holds low-confidence
> feature-exercise templates paired with fixtures in
> [`../test-data/core/engine-features/`](../test-data/core/engine-features/) to
> smoke-test WQL engine operators. The five templates are:
> `feature-sequence.yaml` (`sequence` operator), `feature-inside.yaml`
> (`has` + `in` ancestor traversal), `feature-eth-transfer.yaml`
> (`eth_transfer` semantic group), `feature-args-taint.yaml` (`arg.N` +
> `tainted`), and `taint-probe-parameter.yaml` (`TEST-TAINT-PARAM`, an
> INFO probe that isolates pure parameter-taint reachability into
> `transferFrom` arg0 with **no** access-control filter — used for taint stress
> testing). Run them with
> `w3goaudit test-data/core/engine-features/ --template templates/test/`.
> Do not point production scans at it.

## official/ — Curated Detectors

Templates are exercised against fixtures under
[`../test-data/security/`](../test-data/security/). Detectors whose
**FP exclusions** matter (e.g. `selfdestruct-unprotected`'s inline-guard
carve-out, `tx-origin-auth`'s `msg.sender == tx.origin` whitelist,
`incorrect-exp`'s literal-base gate vs. intentional XOR, `unchecked-arithmetic`'s
pure/view library-math exclusion) have
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
| `CRITICAL-SELFDESTRUCT-UNPROTECTED` | CRITICAL | `critical/selfdestruct-unprotected.yaml` | `selfdestruct(...)` (Solidity-level OR assembly opcode) reachable from an entrypoint without the `access_controlled` safety property (modifiers, inline sender/role guards, and recursive auth helpers) |
| `CRITICAL-DELEGATECALL-USER-INPUT` | CRITICAL | `critical/delegatecall-user-input.yaml` | `delegatecall` whose target flows from a function parameter |
| `HIGH-ARBITRARY-SEND-ETH` | HIGH | `high/arbitrary-send-eth.yaml` | Unprotected ETH withdrawal via `.transfer` / `.send` / `.call{value:}`. Negates the `caller_checked` safety property, so functions that self-scope the caller to a resource they own are cleared without misclassifying item ownership as privileged access control |
| `HIGH-ARBITRARY-TRANSFERFROM` | HIGH | `high/arbitrary-transferfrom.yaml` | `transferFrom(from, ...)` where `from` is user-controlled across entrypoint/helper flows and the function neither has privileged access control nor self-scopes the caller (`not: { preset: caller_checked }`; `require(from == msg.sender)` is safe) |
| `HIGH-UNCHECKED-ERC20-TRANSFER` | HIGH | `high/unchecked-erc20-transfer.yaml` | ERC20 `transfer` / `transferFrom` whose bool return is discarded |
| `HIGH-REENTRANCY-PATTERN` | HIGH | `high/reentrancy-pattern.yaml` | CEI violation — ETH-bearing call / raw low-level `.call` / `delegatecall` followed by a state write, on a function lacking a reentrancy guard |
| `HIGH-REENTRANCY-BALANCE` | HIGH | `high/reentrancy-balance.yaml` | `balanceOf` → external-call → balance-read pattern without a reentrancy guard (delta-snapshot exploit) |
| `HIGH-DELEGATECALL-IN-LOOP` | HIGH | `high/delegatecall-in-loop.yaml` | `delegatecall` inside a `for`/`while` body (payable-multicall ETH reuse) |
| `HIGH-UNPROTECTED-INITIALIZER` | HIGH | `high/unprotected-initializer.yaml` | `initialize/init/setup` entrypoint that writes state with no access control or `initializer` guard |
| `HIGH-WEAK-PRNG` | HIGH | `high/weak-prng.yaml` | Modulo over `block.timestamp` / `block.number` / `block.prevrandao` / `blockhash` |
| `HIGH-MSG-VALUE-IN-LOOP` | HIGH | `high/msg-value-in-loop.yaml` | `msg.value` referenced inside a loop body in a `payable` entrypoint (multicall ETH reuse) |
| `HIGH-INCORRECT-EXP` | HIGH | `high/incorrect-exp.yaml` | `^` (bitwise XOR) used where `**` was meant. Flags `base ^ exp`, `2 ^ 8`, `10 ^ 18` — both operands simple (identifier/decimal) and no other bitwise operator in the same statement (`statement_has`). Excludes genuine XOR in OpenZeppelin-style math and hex masks |
| `HIGH-ENCODE-PACKED-COLLISION` | HIGH | `high/encode-packed-collision.yaml` | `keccak256(abi.encodePacked(...))` over ≥2 user-controlled dynamic args (ambiguous packing → collision) |
| `HIGH-PROXY-STORAGE-COLLISION` | HIGH | `high/proxy-storage-collision.yaml` | Proxy subclass declares plain mutable storage alongside a constructor (implementation slot collision) |
| `HIGH-ECDSA-RECOVER-MALLEABLE` | HIGH | `high/ecdsa-recover-malleable.yaml` | `ECDSA.recover` result keyed by the raw `signature` bytes (malleability replay) |
| `HIGH-ARBITRARY-LOW-LEVEL-CALL` | HIGH | `high/arbitrary-low-level-call.yaml` | Unauthenticated entrypoint forwards a user-controlled target AND calldata into a low-level `.call` |
| `HIGH-UNRESTRICTED-TRANSFEROWNERSHIP` | HIGH | `high/unrestricted-transferownership.yaml` | `transferOwnership` entrypoint writes owner-like state from a parameter with no access control |
| `MEDIUM-UNCHECKED-SEND` | MEDIUM | `medium/unchecked-send.yaml` | `addr.send(amt)` whose bool return is discarded |
| `MEDIUM-UNCHECKED-LOWLEVEL-CALL` | MEDIUM | `medium/unchecked-lowlevel-call.yaml` | Low-level `.call(data)` / `.call{value:}(data)` whose `(bool, bytes)` return is discarded |
| `MEDIUM-DANGEROUS-STRICT-EQUALITY` | MEDIUM | `medium/dangerous-strict-equality.yaml` | `==` / `!=` against `address(this).balance`, `balanceOf(...)`, `block.timestamp`, `block.number` |
| `MEDIUM-DIVIDE-BEFORE-MULTIPLY` | MEDIUM | `medium/divide-before-multiply.yaml` | `(a / b) * c` shape — divide is the left operand of a multiply (precision-loss bug) |
| `MEDIUM-VIEW-PURE-MODIFIES-STATE` | MEDIUM | `medium/view-pure-modifies-state.yaml` | `view` / `pure` function that writes state (including inline-assembly `sstore` bypass) |
| `MEDIUM-TX-ORIGIN-AUTH` | MEDIUM | `medium/tx-origin-auth.yaml` | `tx.origin` used inside any guard (`require` / `assert` / `if` / ternary) |
| `MEDIUM-UNCHECKED-ARITHMETIC` | MEDIUM | `medium/unchecked-arithmetic.yaml` | Arithmetic inside `unchecked { ... }` on Solidity `>=0.8.0`, **scoped to state-mutating functions** (`mutability: payable,nonpayable`) and **only when operands are not range-checked first** (`unchecked_var: true`). Excludes `pure`/`view` library math (SafeMath/Math/Strings) and guarded subtraction like `require(a>=b); … a-b` (OpenZeppelin `SafeERC20.safeDecreaseAllowance`) |
| `MEDIUM-BOOLEAN-CST` | MEDIUM | `medium/boolean-cst.yaml` | Boolean literal misused as a comparison/logical operand (`x == true`, `a && false`) or directly as an `if`/ternary condition (`if (true)`). Plain `return true` / `flag = false` / `while (true)` are not flagged |

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
  references:                   # optional list of canonical refs (SWC/Slither/EIP)
    - https://swcregistry.io/docs/SWC-105
  fix: STRING                   # optional suggested fix snippet

query:
  select: BLOCK_KIND            # optional scalar; omit only with a complete root/sequence matcher
  from: SCOPE                   # entry_function|function|main_contract|any_contract|contract|library|abstract|source
  where:                        # matcher list; siblings are implicit AND
    - func_name: ^withdraw$
    - not: { preset: access_controlled }
    - has:
        block: eth_transfer
```

`query:` may instead hold a one-level `and:` (multi-site join on a shared
`from:` scope, branch `label:`s surfacing in `Finding.Related`) or `or:`
(union of branch queries under one meta, deduplicated by location) — see
[`../docs/wql-syntax.md`](../docs/wql-syntax.md#query-composition-and--or).

At contract scopes (`main_contract`, `any_contract`, `contract`, `library`,
`abstract`), `where:` runs on a synthetic `decl.contract` AST whose children are
resolved function ASTs from the contract's C3 linearized inheritance chain. Use
this for same-contract combination detectors that need multiple conditions in one
contract context, such as payable `msg.value` entrypoints plus inherited
`Multicall.multicall`, without falling back to `regex`.

---

## WQL Features Demonstrated

### Structural and semantic matching

```yaml
query:
  select: external_call
  from: entry_function
  where:
    - name: ^transferFrom$
    - arg.0: { tainted: parameter }
    - not: { preset: caller_checked }
```

Use `has:` for descendant matching, `in:` for ancestor matching, and semantic
block kinds such as `eth_transfer`, `delegatecall`, `state_write`, and `guard`.

### Sequence matching

```yaml
query:
  from: entry_function
  where:
    - not: { preset: reentrancy_guarded }
    - sequence:
        - block: eth_transfer
        - block: state_write
```

The first sequence step is the anchor. If `select` is present, it must match
that step's `block` (or fill a simple unkinded first step); conflicting or
composite anchors are rejected. A fully specified sequence can omit `select`.

### Presets

WQL presets name safety properties: `access_controlled`, `caller_checked`,
and `reentrancy_guarded`. Vulnerability detectors normally negate the property,
for example `not: { preset: access_controlled }`. Unknown preset names fail at
template load.

### Taint Analysis

```yaml
- arg.0: { tainted: parameter }  # also state_var, local_var, sender
```

Member-call receivers are preserved as tagged children, so receiver-tainted
sinks can be expressed without confusing calldata arguments:

```yaml
query:
  select: delegatecall
  where:
    - has:
        block: identifier
        receiver: true
        tainted: parameter
```

### Argument Matching

```yaml
query:
  where:
    - arg.0:
        block: identifier
        tainted: parameter
```

### Version Checking

```yaml
query:
  where:
    - version: ">=0.8.0"  # or <0.8.0, >0.7.0, etc.
```

### Left/Right Matching

```yaml
query:
  select: member
  where:
    - left: { name: ^tx$ }
    - right: { name: ^origin$ }
```

### Regex Escaping

`name:`, `modifier:`, `base:`, `func_name:` and string-valued
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
2. Write it in **WQL** (`meta` plus `query:` — `select`/`from`/`where`, or a
   query-level `and:`/`or:` composition) — see
   [../docs/wql-syntax.md](../docs/wql-syntax.md).
3. Test against fixtures in [`../test-data/security/`](../test-data/security/):
   add a `Vulnerable_*` / `Safe_*` pair named after the detector.
4. Verify the `Vulnerable_*` cases trigger and the `Safe_*` cases do not.
5. Add the template to the table in this INDEX.md.

## Competitive quality gate

Detector changes must preserve both vulnerable and safe controls. The W3GoAudit
competitive suite is accepted only with precision >= 0.65, recall >= 0.95, and
zero failed cases; the threshold tool recomputes metrics from TP/FP/FN instead
of trusting rounded report fields.

```bash
FOURNALY3ER_LOCK_SHA256=<reviewed hash> \
  docker compose -f benchmarks/compose.yaml run --rm benchmark
```

Docker Compose is the only supported benchmark host entry point. Its Dockerfile
derives and verifies Go directly from `go.mod`; scanners are pinned inside the
image and output is confined to `benchmarks/results/`. The reviewed hash is
still an external blocker, so this checkout does not claim a fresh image or
competitive run.

---

## Usage

`--template` is single-valued and accepts either a file or a directory. When
given a directory it walks every `.yaml` underneath. When omitted, the scanner
uses `~/.w3goaudit/templates` when populated, then falls back to the embedded
`official/` pack.

```bash
# Audit with the built-in official pack (the normal case — no flag needed)
w3goaudit ./contracts/

# Equivalent, pointing at the pack explicitly from a source checkout
w3goaudit ./contracts/ --template templates/official/

# Run a single specific detector
w3goaudit ./contracts/ --template templates/official/high/reentrancy-pattern.yaml

# Full integration scan with terminal detail (run.log is always written)
w3goaudit test-data/security/ --template templates/official/ --verbose
```

Template directories fail closed by default. Use `--ignore-invalid-templates`
only for ad-hoc mixed directories; skipped files are then reported with
`--verbose`:
```
Loaded template: HIGH-ARBITRARY-TRANSFERFROM (templates/official/high/arbitrary-transferfrom.yaml)
Skipping invalid template broken.yaml: parse YAML: yaml: line 3: ...
Skipping template missing-id.yaml: missing meta.id
```
