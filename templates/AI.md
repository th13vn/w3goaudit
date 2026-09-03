# templates/ - Security Detector Templates

## Purpose

WQL templates for smart-contract security scanning. Each `.yaml` file is a
self-contained detector. The `official/` pack is embedded in the binary
(`//go:embed`) and serves as the always-available offline fallback.

## Template Language: WQL

**A WQL document is `meta` plus one `query` block, with an optional top-level
`ai` review policy.** All templates under
`official/` and `test/` (this directory), plus every
benchmark template under `../scripts/benchmark/templates/` (slither-inspired,
decurity-semgrep-inspired, 4naly3er-inspired) — 120 templates total — are
written in WQL (`query:` containing `select`/`from`/`where` or composition). See
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

> **Deterministic boundary:** WQL documents contain exactly `meta` plus one
> `query`. The scanner rejects model-review keys. External Assistant workflows
> may inspect deterministic output but do not participate in official finding
> generation.

## Curation Policy

Only **HIGH / MEDIUM / CRITICAL** severity templates ship here. LOW and INFO
severities (and gas-optimisation rules) have been removed — they produce
noise that drowns out genuine findings. Templates that cannot be made
precise (e.g. detectors with no way to distinguish a true positive from a
legitimate pattern) are also out.

**Worked example of the precision bar.** A generic "external call then state
write" reentrancy rule (the benchmark lane's `SLITHER-REENTRANCY-NO-ETH`) was
evaluated for promotion and **rejected**: it fired on 36 sites across
`../test-data/security/`, 17 of them deliberate safe controls, because
pull-then-credit *is* the correct ERC20 deposit shape. Narrowing it to a
user-controlled call target silenced it entirely, including its own vulnerable
fixture. The precise signal it was reaching for is already covered by
`HIGH-ERC777-CALLBACK-REENTRANCY` and `HIGH-ERC721-CALLBACK-REENTRANCY`, so it
stays in the benchmark lane. Prefer a narrow detector plus a benchmark-lane
sibling over a broad one in `official/`.

## Directory Structure

```
templates/
├── official/   # Curated official detector pack (39) — embedded; run THIS to audit
└── test/       # WQL feature-test templates (5; NOT production detectors)
```

(The 76 benchmark templates — Decurity/Slither/4naly3er-inspired — live under
`../scripts/benchmark/templates/`, outside this directory; see
[`../scripts/benchmark/README.md`](../scripts/benchmark/README.md).)

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
| `CRITICAL-DELEGATECALL-USER-INPUT` | CRITICAL | `critical/delegatecall-user-input.yaml` | `delegatecall` whose target flows from a parameter or caller identity |
| `HIGH-ARBITRARY-SEND-ETH` | HIGH | `high/arbitrary-send-eth.yaml` | Unprotected ETH withdrawal via `.transfer` / `.send` / `.call{value:}`. Negates the `caller_checked` safety property, so functions that self-scope the caller to a resource they own are cleared without misclassifying item ownership as privileged access control |
| `HIGH-ARBITRARY-TRANSFERFROM` | HIGH | `high/arbitrary-transferfrom.yaml` | `transferFrom(from, ...)` where `from` is user-controlled across entrypoint/helper flows and the function neither has privileged access control nor self-scopes the caller (`not: { preset: caller_checked }`; `require(from == msg.sender)` is safe) |
| `HIGH-UNCHECKED-ERC20-TRANSFER` | HIGH | `high/unchecked-erc20-transfer.yaml` | ERC20 `transfer` / `transferFrom` whose bool return is discarded |
| `HIGH-REENTRANCY-PATTERN` | HIGH | `high/reentrancy-pattern.yaml` | CEI violation — ETH-bearing call or raw low-level `.call` followed by a state write, on a function lacking a reentrancy guard. Excludes `delegatecall` (same-context execution, not reentry — see `CRITICAL-DELEGATECALL-USER-INPUT`) |
| `HIGH-REENTRANCY-BALANCE` | HIGH | `high/reentrancy-balance.yaml` | `balanceOf` → external-call → balance-read pattern without a reentrancy guard (delta-snapshot exploit) |
| `HIGH-DELEGATECALL-IN-LOOP` | HIGH | `high/delegatecall-in-loop.yaml` | `delegatecall` inside a `for`/`while` body (payable-multicall ETH reuse) |
| `HIGH-UNPROTECTED-INITIALIZER` | HIGH | `high/unprotected-initializer.yaml` | `initialize/init/setup` entrypoint that writes state with no access control and no **proven** one-time guard (`preset: initializer_guarded` — an enforcing check on a state flag that the function, a helper, or a sibling such as the constructor sets). Covers OpenZeppelin's `initializer` modifier, Euler's `if (initialized) revert; initialized = true;`, Axelar's split `if (_isInitialized()) revert; _initialize();`, and the `_disableInitializers()` pattern |
| `HIGH-WEAK-PRNG` | HIGH | `high/weak-prng.yaml` | Modulo over `block.timestamp` / `block.number` / `block.prevrandao` / `blockhash`, excluding a modulo by a power of two — `uint32(block.timestamp % 2**32)` is Uniswap V2's slot-packing truncation, not a random draw |
| `HIGH-MSG-VALUE-IN-LOOP` | HIGH | `high/msg-value-in-loop.yaml` | `msg.value` referenced inside a loop body in a `payable` entrypoint (multicall ETH reuse) |
| `HIGH-INCORRECT-EXP` | HIGH | `high/incorrect-exp.yaml` | `^` (bitwise XOR) used where `**` was meant. Flags `base ^ exp`, `2 ^ 8`, `10 ^ 18` — both operands simple (identifier/decimal) and no other bitwise operator in the same statement (`statement_has`). Excludes genuine XOR in OpenZeppelin-style math and hex masks |
| `HIGH-ENCODE-PACKED-COLLISION` | HIGH | `high/encode-packed-collision.yaml` | `keccak256(abi.encodePacked(...))` over ≥2 user-controlled dynamic args (ambiguous packing → collision) |
| `HIGH-PROXY-STORAGE-COLLISION` | HIGH | `high/proxy-storage-collision.yaml` | Proxy subclass declares plain mutable storage alongside a constructor (implementation slot collision) |
| `HIGH-ECDSA-RECOVER-MALLEABLE` | HIGH | `high/ecdsa-recover-malleable.yaml` | `ECDSA.recover` result keyed by the raw `signature` bytes (malleability replay) |
| `HIGH-ARBITRARY-LOW-LEVEL-CALL` | HIGH | `high/arbitrary-low-level-call.yaml` | Unauthenticated entrypoint forwards a user-controlled target AND calldata into a low-level `.call` |
| `HIGH-UNRESTRICTED-TRANSFEROWNERSHIP` | HIGH | `high/unrestricted-transferownership.yaml` | `transferOwnership` entrypoint writes owner-like state from a parameter with no access control |
| `MEDIUM-UNCHECKED-SEND` | MEDIUM | `medium/unchecked-send.yaml` | `addr.send(amt)` whose bool return is discarded |
| `MEDIUM-UNCHECKED-LOWLEVEL-CALL` | MEDIUM | `medium/unchecked-lowlevel-call.yaml` | Low-level `.call(data)` / `.call{value:}(data)` whose `(bool, bytes)` return is discarded |
| `MEDIUM-DANGEROUS-STRICT-EQUALITY` | MEDIUM | `medium/dangerous-strict-equality.yaml` | `==` / `!=` against `address(this).balance` or `balanceOf(...)`; also `block.timestamp`/`block.number` but only when the other operand is caller-controlled, so Aave's same-block cache short-circuit (`if (reserve.lastUpdateTimestamp == block.timestamp) return cachedIndex;`) is not reported |
| `MEDIUM-DIVIDE-BEFORE-MULTIPLY` | MEDIUM | `medium/divide-before-multiply.yaml` | `(a / b) * c` shape — divide is the left operand of a multiply (precision-loss bug) |
| `MEDIUM-VIEW-PURE-MODIFIES-STATE` | MEDIUM | `medium/view-pure-modifies-state.yaml` | `view` / `pure` function that writes state (including inline-assembly `sstore` bypass) |
| `MEDIUM-TX-ORIGIN-AUTH` | MEDIUM | `medium/tx-origin-auth.yaml` | `tx.origin` used inside any guard (`require` / `assert` / `if` / ternary) |
| `MEDIUM-UNCHECKED-ARITHMETIC` | MEDIUM | `medium/unchecked-arithmetic.yaml` | Arithmetic inside `unchecked { ... }` on Solidity `>=0.8.0`, **anchored on the operation** (not the block, so a whole-function `unchecked` wrapper still names the exact expression), **scoped to state-mutating functions** (`mutability: payable,nonpayable`), and **only when operands are not range-checked first** (`unchecked_var: true`). Limited to operations that are an exploit primitive: `*`, `-`, and `+` only when an operand is caller-controlled. `/` cannot overflow and is excluded; counter/nonce increments (`nonce + 1`, `numElements + 1`) are excluded because the value can never be driven to the type maximum. Also excludes `pure`/`view` library math and guarded subtraction like `require(a>=b); … a-b` (OpenZeppelin `SafeERC20.safeDecreaseAllowance`) |
| `HIGH-READONLY-REENTRANCY-CURVE` | HIGH | `high/readonly-reentrancy-curve.yaml` | Curve `get_virtual_price()` read without first poking a reentrancy-locked pool entry point (`remove_liquidity` / `claim_admin_fees`). Read-only reentrancy: your own `nonReentrant` does not help because the attacker never re-enters you |
| `HIGH-READONLY-REENTRANCY-BALANCER` | HIGH | `high/readonly-reentrancy-balancer.yaml` | Balancer Vault `getPoolTokens` or rate-provider `getRate` read without `VaultReentrancyLib.ensureNotInVaultContext` / `manageUserBalance`. `or:`-composed over the two read shapes |
| `HIGH-NO-SLIPPAGE-CHECK` | HIGH | `high/no-slippage-check.yaml` | Uniswap-style router swap with `amountOutMin` hardcoded to `0` (arg 0 for ETH-in, arg 1 for token-in), or set to max uint — fully sandwichable |
| `HIGH-UNISWAP-CALLBACK-UNPROTECTED` | HIGH | `high/uniswap-callback-unprotected.yaml` | `uniswapV2Call` / `uniswapV3SwapCallback` / `uniswapV3FlashCallback` / `uniswapV3MintCallback` callable without asserting the caller is the pool (no `access_controlled`, no `verifyCallback`-style helper) |
| `HIGH-UNISWAP-V4-HOOK-UNPROTECTED` | HIGH | `high/uniswap-v4-hook-unprotected.yaml` | Uniswap V4 hook entry point (`beforeSwap`, `afterAddLiquidity`, …) that is `external` without `onlyPoolManager` or an equivalent caller assertion |
| `HIGH-ORACLE-PRICE-UPDATE-UNRESTRICTED` | HIGH | `high/oracle-price-update-unrestricted.yaml` | Oracle/price-named entrypoint writes state from a caller parameter with no access control — anyone sets the protocol's reference price |
| `HIGH-ERC20-PUBLIC-BURN` | HIGH | `high/erc20-public-burn.yaml` | Public `burn` forwards a caller-supplied account into `_burn` with no access control and no allowance spend — destroys anyone's balance and moves `totalSupply` |
| `HIGH-ERC721-CALLBACK-REENTRANCY` | HIGH | `high/erc721-callback-reentrancy.yaml` | Unguarded entrypoint reaching `_checkOnERC721Received`, so `onERC721Received` on a caller-chosen recipient runs before mint caps / allowlists are consumed |
| `HIGH-ERC777-CALLBACK-REENTRANCY` | HIGH | `high/erc777-callback-reentrancy.yaml` | Unguarded entrypoint invoking an ERC777 `tokensReceived` hook — an apparently inert token transfer that executes recipient code (imBTC class) |
| `MEDIUM-STALE-ORACLE-DATA` | MEDIUM | `medium/stale-oracle-data.yaml` | `latestRoundData()` consumed with no guard anywhere in the function, so neither the answer nor its age is validated |
| `MEDIUM-DEPRECATED-CHAINLINK-LATESTANSWER` | MEDIUM | `medium/deprecated-chainlink-latestanswer.yaml` | Deprecated Chainlink `latestAnswer()`, which cannot report round completeness or staleness and may return `0` instead of reverting |
| `MEDIUM-ORACLE-LP-SPOT-PRICE` | MEDIUM | `medium/oracle-lp-spot-price.yaml` | Price getter dividing pool reserves / underlying by `totalSupply` (directly or via a `div` library) — flash-loan manipulable spot ratio |
| `MEDIUM-ORACLE-CURVE-SPOT-PRICE` | MEDIUM | `medium/oracle-curve-spot-price.yaml` | Curve `get_p()` (instantaneous spot price) read and returned, instead of the smoothed `price_oracle()` |
| `MEDIUM-BIDI-CHARACTERS` | MEDIUM | `medium/bidi-characters.yaml` | Unicode bidirectional control characters in source (Trojan Source): rendered text disagrees with compiled code, defeating review. `scope: source`, so it reports once per occurrence |
| `MEDIUM-BOOLEAN-CST` | MEDIUM | `medium/boolean-cst.yaml` | Boolean literal that makes an expression constant: a logical operand (`a && false`, `b \|\| true`) or an `if`/ternary condition (`if (true)`) — both leave a dead branch. `x == false` / `x == true` are NOT flagged: they are a verbose `!x`/`x`, a style preference and the idiomatic mutex spelling (`require(msgValSpent_ == false)`), which this pack's policy excludes. Plain `return true` / `flag = false` / `while (true)` are not flagged either |

`references` is **optional** — present only where a canonical smart-contract
reference exists (SWC registry, Slither wiki, Solidity docs, EIPs). The engine
propagates references to findings; Markdown / HTML / JSON / SARIF formatters
surface them, and SARIF emits GitHub `security-severity` scores.

The benchmark `DECURITY-ACCESSIBLE-SELFDESTRUCT` rule shares the canonical
`selfdestruct` category with Slither suicidal: any unauthenticated reachable
selfdestruct is vulnerable, including a fixed beneficiary. Beneficiary taint is
not part of that category; access control is the safe property.

---

## Candidate Authorization Pack

The staged authorization/runtime-inheritance candidates live under `candidate/authorization/`. They are not embedded in the official pack and must pass vulnerable, safe, wrong-principal, unresolved, source/cache, and deterministic-output gates before promotion.

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

The top-level authoring surface is exactly `meta` plus one `query`. Unknown
keys, including the removed `ai` key, are rejected. Keep semantic reasoning in
deterministic WQL, engine facts, test fixtures, and evidence artifacts. A future
external Assistant may investigate scanner output but does not participate in
official finding generation.

`query:` may instead hold a one-level `and:` (multi-site join on a shared
`from:` scope, branch `label:`s surfacing in `Finding.Related`) or `or:`
(union of branch queries under one meta, deduplicated by location) — see
[`../docs/wql-syntax.md`](../docs/wql-syntax.md#query-composition-and--or).
Every query-level `and:` branch must expose a positive reportable anchor;
absence-only branches are rejected because they cannot contribute a primary or
related site. Positive contract-root branches contribute contract/file related
sites.
Explicitly authored `select`/`from`/branch `label` values must be non-null,
non-empty scalars, and explicitly authored `where` values must be non-null,
non-empty matcher lists. Empty nested matcher maps/lists, empty required
strings, `unchecked_var: false`, and signed/non-decimal `arg.N` keys are
rejected at load.
Repeated sibling `not:` items remain independent implicit-AND predicates:
`not A` plus `not B` means `(not A) and (not B)`; the lowering step never
combines their children into `not (A and B)`.
A where-only query with actionable AST evidence defaults to
`entry_function`; context-only where clauses remain invalid because they
cannot anchor a finding.

At contract scopes (`main_contract`, `any_contract`, `contract`, `library`,
`abstract`), `where:` runs on a synthetic `decl.contract` AST whose children are
resolved function ASTs from the contract's C3 linearized inheritance chain. Use
this for same-contract combination detectors that need multiple conditions in one
contract context, such as payable `msg.value` entrypoints plus inherited
`Multicall.multicall`, without falling back to `regex`.
Declaration nodes retain exact kinds, owning files, and spans. Active inherited
functions are deduplicated by canonical selector, so derived overrides win and
overloads remain distinct.

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
`state_write` covers state assignments, dynamic-storage-array `push`/`pop`,
state-targeted `delete`/`++`/`--`, and `asm.sstore`; storage mutations are not
modeled as calls. `guarded_by` matches inline guards or an exact applied
modifier body. A modifier name alone does not imply access control.
The Decurity-inspired basic-arithmetic-underflow benchmark template also uses
`unchecked_var: true` on both binary `-` and assignment `-=` shapes, so an
enforced local proof of the exact unsigned relation `left >= right` suppresses
the subtraction without relying on file, contract, function, or variable
names. Solidity 0.8 matches must sit inside an explicit `unchecked` block;
ordinary checked subtraction is not an underflow finding. Reversed/unrelated
inequalities, non-terminating branches, intervening statements, effectful
condition operands or additional guard arguments, signed arithmetic, and
unstable expressions remain findings.

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
Solidity `for` children participate in runtime order: initialization,
condition, body, then post.

The benchmark `SLITHER-REENTRANCY-NO-ETH` sequence excludes only a selected
call whose direct `receiver_name` is exactly `this`: an external self-call has
a fixed immediate target and cannot directly transfer control to an
attacker-selected target, even though the self-called function may still
transitively call untrusted code. A nested `this.*` call inside an
outer call's argument or call option does not change that outer call's direct
receiver, so other external-call receivers remain covered.

### Presets

WQL presets name safety properties: `access_controlled`, `caller_checked`,
and `reentrancy_guarded`. Vulnerability detectors normally negate the property,
for example `not: { preset: access_controlled }`. Unknown preset names fail at
template load.

All three are proven from **bodies**, not names. `reentrancy_guarded` requires an
applied modifier that checks a state variable and writes it before `_;` — a real
mutex — so guards named `reEntrantAgent` or `singleEntry` are recognized while a
modifier merely named `lock` that enforces nothing is not.
`access_controlled` dispatches `virtual` internal calls through the runtime
contract's MRO, so an abstract auth hook such as
`UUPSUpgradeable._authorizeUpgrade` resolves to the deploying contract's
`onlyOwner` override rather than the bodyless base declaration.

### Taint Analysis

```yaml
- arg.0: { tainted: user_controlled }
```

`user_controlled` means parameter or caller-identity taint. Use the narrower
`parameter`, `state_var`, `local_var`, or `sender` source when detector intent
requires that exact provenance. Caller identity recognizes `msg.sender`,
`tx.origin`, and an exact zero-argument internal `_msgSender()` helper confirmed
by call metadata and exact MRO resolution when available, not same-named
identifiers, state/local/parameter names, external/self/unresolved calls, or
overloads.

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

The constraint is intersected with the **range** the file's pragma permits, not
compared to a single version. `pragma solidity >=0.7.0 <0.9.0;` therefore
satisfies `version: ">=0.8.0"`, because such a file can compile on 0.8.x —
previously only the first version triple in the pragma was read, so this common
spelling was silently skipped. Caret (`^0.8.20`), tilde (`~0.8.4`), comparator
chains, `||` alternatives, and partial versions (`^0.8`, `0.8`) are all
understood. A pragma or constraint that cannot be parsed skips the check rather
than excluding the file.

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
2. Write it in **WQL** (`meta` plus one `query:` block containing `select`/`from`/`where`, or a
   query-level `and:`/`or:` composition). See
   [../docs/wql-syntax.md](../docs/wql-syntax.md).
3. Test against fixtures in [`../test-data/security/`](../test-data/security/):
   add a `Vulnerable_*` / `Safe_*` pair named after the detector.
4. Verify the vulnerable cases trigger and all safe and fixed controls remain quiet.
5. Add the template to the table in this AI.md.
6. Do not promote a detector into `official/` until its deterministic,
   parse-loss, regression, and precision gates all pass.

## Competitive quality gate

Detector changes must preserve both vulnerable and safe controls. The W3GoAudit
competitive suite is accepted only with precision >= 0.65, recall >= 0.95, and
zero failed cases; the threshold tool recomputes metrics from TP/FP/FN instead
of trusting rounded report fields.

```bash
docker compose -f scripts/benchmark/compose.yaml run --rm benchmark
```

Docker Compose is the only supported benchmark host entry point. Its Dockerfile
derives and verifies Go directly from `go.mod`; scanners are pinned inside the
image and output is confined to `benchmarks/results/`. The reviewed generated-lock
hash for the pinned 4naly3er commit is built into the Dockerfile, so the canonical
command requires no external hash argument.

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
