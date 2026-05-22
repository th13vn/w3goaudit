# templates/ - Security Detector Templates

## Purpose

WQL templates for smart-contract security scanning. Each `.yaml` file is a
self-contained detector loaded by `--template` at scan time.

## Curation Policy

Only **HIGH / MEDIUM / CRITICAL** severity templates ship here. LOW and INFO
severities (and gas-optimisation rules) have been removed — they produce
noise that drowns out genuine findings. Templates that cannot be made
precise (e.g. detectors with no way to distinguish a true positive from a
legitimate pattern) are also out.

## Directory Structure

```
templates/
├── security/             # Hand-written security detectors (19)
├── slither-inspired/     # Slither-equivalent detectors (20, HIGH/MEDIUM only)
├── 4naly3er-insppired/   # 4naly3er-equivalent detectors (14, HIGH/MEDIUM only)
└── realworld-inspired/   # Replays of real-world incidents (6, incident-specific)
```

> All four directories are production detectors. To scan with everything,
> point `--template` at `templates/` and use `--dedupe` to collapse the
> known overlaps between directories (see [Known Overlaps](#known-overlaps)).
> To narrow a scan, target a single subdirectory.

## security/ — Hand-Written Detectors

Each template is verified against focused fixtures under [`../test-data/security/`](../test-data/security/). Some contracts named `Safe_*` for one vulnerability class intentionally still contain other bug classes, so whole-directory scans are assessed by template/category rather than by name prefix alone. TP/FP/recall notes are in [`../docs/template-quality-analysis.md`](../docs/template-quality-analysis.md) and the latest full-pack benchmark report under `.vscode/`.

| ID | Severity | File | Detects |
|---|---|---|---|
| `SEC-DEST-001` | CRITICAL | `selfdestruct_unprotected.yaml` | `selfdestruct(...)` (Solidity-level OR assembly `selfdestruct` opcode) reachable from an entrypoint with no auth modifier |
| `SEC-DELEG-001` | CRITICAL | `delegatecall_user_input.yaml` | `delegatecall` whose target flows from a function parameter |
| `SEC-ETH-001` | HIGH | `arbitrary_send_eth.yaml` | Unprotected ETH withdrawal via `.transfer(amt)` / `.send(amt)` / `.call{value:}` — uses `has_value` attr (P0-2) to distinguish ETH-bearing `.call` |
| `SEC-ERC20-001` | HIGH | `arbitrary_transferfrom.yaml` | `transferFrom(from, ...)` where `from` is user-controlled across entrypoint/helper flows and lacks sender/auth validation |
| `SEC-ERC20-002` | HIGH | `unchecked_erc20_transfer.yaml` | ERC20 `transfer` / `transferFrom` whose bool return is discarded (ETH `.transfer(amt)` excluded — parser disambiguates by arg count via P0-1) |
| `SEC-GEN-REENTRANCY` | HIGH | `reentrancy_pattern.yaml` | Generic CEI violation — outbound call before state write (no reentrancy guard) |
| `SEC-REENTRANCY-002` | HIGH | `reentrancy_balance.yaml` | `balanceOf` → external-call → balance-read pattern without reentrancy guard (delta-snapshot exploit) |
| `SEC-DELEG-002` | HIGH | `delegatecall_in_loop.yaml` | `delegatecall` inside `for`/`while` body (payable-multicall ETH reuse) |
| `SEC-UPGRADE-001` | HIGH | `unprotected_initializer.yaml` | `initialize/init/setup` entrypoint that writes state with no access control or `initializer` guard |
| `SEC-PRNG-001` | HIGH | `weak_prng.yaml` | Modulo over `block.timestamp`/`block.number`/`block.difficulty`/`block.prevrandao`/`blockhash` (Chainlink-VRF replacement) |
| `SEC-MSGVAL-001` | HIGH | `msg_value_in_loop.yaml` | `msg.value` referenced inside a loop body in a `payable` entrypoint (multicall ETH reuse) |
| `SEC-MATH-003` | HIGH | `incorrect_exp.yaml` | `^` (bitwise XOR) used in arithmetic context — classic "developer meant `**`" foot-gun |
| `SEC-SEND-001` | MEDIUM | `unchecked_send.yaml` | `addr.send(amt)` whose bool return is discarded |
| `SEC-LOWLEVEL-CALL-001` | MEDIUM | `unchecked_lowlevel_call.yaml` | Low-level `.call(data)` / `.call{value:}(data)` whose `(bool, bytes)` return is discarded |
| `SEC-EQ-001` | MEDIUM | `dangerous_strict_equality.yaml` | `==` / `!=` against `address(this).balance`, `balanceOf(...)`, `block.timestamp`, `block.number` — externally manipulable values |
| `SEC-MATH-002` | MEDIUM | `divide_before_multiply.yaml` | `(a / b) * c` shape — divide is the left operand of a multiply (precision-loss bug) |
| `SEC-MUTABILITY-001` | MEDIUM | `view_pure_modifies_state.yaml` | `view` / `pure` function that writes state (including inline-assembly `sstore` bypass) |
| `SEC-TXORIGIN-001` | MEDIUM | `tx_origin_auth.yaml` | `tx.origin` used inside any guard (`require` / `assert` / `if` / ternary) — phishing-vector auth check |
| `SEC-MATH-001` | MEDIUM | `unchecked_arithmetic.yaml` | Arithmetic inside `unchecked { ... }` on Solidity `>=0.8.0` |

All `security/*` templates carry curated metadata:
`cwe`, `owasp` (OWASP SC Top 10 2025 IDs), and `references` (SWC links,
Slither wiki entries, Solidity docs). The engine propagates these to
findings; Markdown / HTML / JSON / SARIF formatters all surface them, and
SARIF emits CWE tags + GitHub `security-severity` scores.

## slither-inspired/ — Slither-Equivalent Detectors

HIGH and MEDIUM severity only. Detectors that are inherently noisy (e.g. assembly use, low-level calls, solc version) have been dropped. Template IDs are `SLITHER-*`.

**HIGH (12):** `arbitrary-send-erc20`, `arbitrary-send-eth`, `controlled-delegatecall`, `delegatecall-loop`, `incorrect-exp`, `msg-value-loop`, `reentrancy-balance`, `reentrancy-eth`, `suicidal`, `unchecked-transfer`, `unprotected-upgrade`, `weak-prng`

**MEDIUM (8):** `boolean-cst`, `constant-function-state`, `divide-before-multiply`, `incorrect-equality`, `reentrancy-no-eth`, `tx-origin`, `unchecked-lowlevel`, `unchecked-send`

## 4naly3er-inspired/ — 4naly3er-Equivalent Detectors

> Folder is named `4naly3er-insppired/` on disk (double "p"). Paths below use the actual name.

HIGH and MEDIUM severity only. All `GAS-*` and `L-*` (low) detectors removed. Template IDs are `4NALY3ER-H-*` / `4NALY3ER-M-*`.

**HIGH (4) — `H-*`:** `comparison-outside-condition`, `delegatecall-in-loop`, `msg-value-in-loop`, `wsteth-price-steth`

**MEDIUM (10) — `M-*`:** `approve-zero-first`, `avoid-tx-origin`, `block-number-l2`, `centralization-risk`, `deprecated-chainlink-latest-answer`, `erc721-safe-mint`, `erc721-safe-transfer-from`, `fee-over-100`, `stale-oracle-data`, `unchecked-erc20-transfer`

## realworld-inspired/ — Incident Replays

Narrow, incident-specific patterns. Zero findings on generic codebases is expected — they trigger only on contracts with the matching shape. All six are HIGH severity.

| ID | File | Replays |
|---|---|---|
| `RW-ALKEMI-001` | `alkemi_self_liquidation.yaml` | Alkemi self-liquidation guard missing |
| `RW-AMTOKEN-001` | `deferred_burn_manipulation.yaml` | Deferred-burn price manipulation (AM/MT Token) |
| `RW-DBXEN-001` | `dbxen_msgsender_inconsistency.yaml` | Mixed `msg.sender` / `_msgSender()` in one function (DBXen) |
| `RW-ETHERFREAKERS-001` | `etherfreakers_transfer_hook_cei.yaml` | ETH payout → NFT transfer → state-write CEI violation |
| `RW-GOOSE-001` | `goose_finance_deposit_before_harvest.yaml` | Shares minted before harvest/sync (Goose Finance) |
| `RW-MTTOKEN-001` | `mt_buy_restriction_bypass.yaml` | Whitelist early-return short-circuits restriction (MT Token) |

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
   - `security/` — hand-curated patterns with full `cwe` / `owasp` / `references` metadata.
   - `slither-inspired/` — direct port of a Slither detector.
   - `4naly3er-insppired/` — direct port of a 4naly3er detector.
   - `realworld-inspired/` — replay of a specific incident with the on-chain trail in the description.
2. Follow WQL syntax (see [../docs/wql-syntax.md](../docs/wql-syntax.md)).
3. Test against vulnerable contracts in `../test-data/security/`:
   - `test-slither-detectors.sol` — `Vulnerable_*` / `Safe_*` pairs for Slither detectors
   - `test-4naly3er-detectors.sol` — `Vulnerable_*` / `Safe_*` pairs for 4naly3er detectors
   - `test-arbitrary-transferfrom.sol` / `test-interprocedural-taint.sol` / `test-reentrancy.sol` / `reentrancy-simple.sol` — focused fixtures
4. Verify the `Vulnerable_*` cases trigger and the `Safe_*` cases do not.
5. Add the template to the table in this INDEX.md.

---

## Usage

`--template` is single-valued and accepts either a file or a directory. When
given a directory it walks every `.yaml` underneath. Run one directory at a
time, or point at `templates/` to run them all.

```bash
# Scan with hand-written security detectors
w3goaudit ./contracts/ --template templates/security/

# Scan with all Slither-equivalent detectors
w3goaudit ./contracts/ --template templates/slither-inspired/

# Scan with all 4naly3er-equivalent detectors
w3goaudit ./contracts/ --template templates/4naly3er-insppired/

# Replay known real-world incidents
w3goaudit ./contracts/ --template templates/realworld-inspired/

# Run every production detector at once and collapse duplicates
w3goaudit ./contracts/ --template templates/ --dedupe

# Scan with a single specific template
w3goaudit ./contracts/ --template templates/security/reentrancy_pattern.yaml

# Full integration scan with verbose log
w3goaudit test-data/ --template templates/ --verbose=/tmp/scan.log
```

Template errors are reported with `--verbose`:
```
Loaded template: SEC-ERC20-001 (templates/security/arbitrary_transferfrom.yaml)
Skipping invalid template broken.yaml: parse YAML: yaml: line 3: ...
Skipping template missing-id.yaml: missing meta.id
```

---

## Known Overlaps

Several detectors exist in more than one directory because `slither-inspired/`, `4naly3er-insppired/`, and `security/` each implement them from their own perspective. They produce overlapping findings:

| Pattern | Templates that overlap |
|---|---|
| tx.origin auth | `slither-inspired/tx-origin`, `4naly3er-insppired/M-avoid-tx-origin`, `security/tx_origin_auth` |
| delegatecall in loop | `slither-inspired/delegatecall-loop`, `4naly3er-insppired/H-delegatecall-in-loop` |
| msg.value in loop | `slither-inspired/msg-value-loop`, `4naly3er-insppired/H-msg-value-in-loop` |
| Unchecked ERC20 transfer | `slither-inspired/unchecked-transfer`, `4naly3er-insppired/M-unchecked-erc20-transfer` |
| Generic reentrancy | `slither-inspired/reentrancy-eth`, `slither-inspired/reentrancy-no-eth`, `security/reentrancy_pattern` |
| Selfdestruct without auth | `slither-inspired/suicidal`, `security/selfdestruct_unprotected` |
| Arbitrary transferFrom | `slither-inspired/arbitrary-send-erc20`, `security/arbitrary_transferfrom` |
| Controlled delegatecall | `slither-inspired/controlled-delegatecall`, `security/delegatecall_user_input` |

Use `--dedupe` at scan time to collapse findings sharing `(file, line, function, severity)`.
