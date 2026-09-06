# templates/ - WQL Detector Pack

## Purpose

This directory contains the W3GoAudit WQL templates. `official/` is the
embedded, deterministic security pack used by default. `test/` contains small
feature exercises for the WQL engine and is never a production pack. Benchmark
templates live in the dev-only `scripts/benchmark/` harness.

WQL is intentionally small: every document is `meta` plus one `query` block.
The scanner has no runtime authoring surface, candidate pack, model review, or
authored `unknown` value. Inheritance, C3 linearization, virtual dispatch, and
`super` dispatch are engine behavior. Missing, unresolved, ambiguous, or
incomplete positive semantic evidence fails closed.

Official detector metadata follows one readable style: sentence-case titles,
mechanism-focused descriptions, actionable recommendations, and stable references.
Comments in official YAML explain only a non-obvious matcher boundary or semantic
scope; implementation history and benchmark anecdotes belong in tests or reports,
not in production detector files. The mechanical-cleanup pass preserves every ID,
severity, confidence, query scope, and matcher meaning. Semantic merges and new
detectors require a separate evidence-backed change.

## Pack precedence

The CLI resolves templates in this order:

1. `--template <file|dir>` when explicitly supplied.
2. `~/.w3goaudit/templates/` when a released pack is installed.
3. The embedded `official/` directory as the offline fallback.

The repository `official/` tree is the source used by the embedded binary. The
sibling `../w3goaudit-templates` repository is a separate release artifact and
must not be edited as part of core development.

## Directory layout

```text
templates/
├── official/   # trusted production detectors; current inventory is filesystem-derived
└── test/       # five WQL feature tests, not production detectors
```

The current official inventory is **20 templates**. Tests derive the count and
IDs from the filesystem, so a future pack change cannot leave a stale catalog
claim behind.

## Canonical authoring

Use ordinary WQL matchers and direct parameterized presets:

```yaml
query:
  from: entry_function
  select: external_call
  where:
    - not:
        preset:
          authorization:
            type: protected
            principal: [owner, pair, pool]
    - arg.0:
        tainted: user_controlled
```

`authorization.type` is either `protected` or `self_sender`. A protected
predicate may list several principal alternatives, or use the explicit
`principal: {regex: "..."}` escape hatch. Principal literals are trimmed,
deduplicated, sorted, and matched as complete values. Use `self_sender` when a
caller may act only on its own resource. Express a required safety property as
an ordinary positive preset and its absence with `not:`.

The engine does not treat a generic success check such as `require(ok)` as
authorization. This keeps ordinary wrappers traversable for taint analysis; an
ambiguous overloaded helper remains unavailable to positive authorization
predicates instead of being guessed.

Initializer takeover is intentionally one small public predicate:

```yaml
query:
  from: entry_function
  select: function
  where:
    - func_name: '(?i)^(initialize|initialise|init|__init|setup)$'
    - preset:
        initializer:
          takeover: possible
```

The preset consumes internal lifecycle evidence. Mutex state, constructor
disabling, proxy linkage, deployment authority, and atomicity are not public
attributes. A name regex may narrow entry functions before the preset runs.

Presence-only markers do not carry vacuous Boolean values:

```yaml
receiver:
  tainted: parameter

unchecked_var:
```

Use structured options or regex for refinement. Do not write `receiver: true`,
`unchecked_var: true`, `runtime:`, `runtime_contract:`, candidate templates, or
semantic compatibility aliases. Unknown matcher values are rejected at load.

## Official detector inventory

| ID | Severity | File | Mechanism |
|---|---|---|---|
| `CRITICAL-DELEGATECALL-USER-INPUT` | CRITICAL | `critical/delegatecall-user-input.yaml` | `delegatecall` whose target flows from a parameter or caller identity; the entry must not be protected. |
| `CRITICAL-SELFDESTRUCT-UNPROTECTED` | CRITICAL | `critical/selfdestruct-unprotected.yaml` | Reachable selfdestruct without protected authorization. |
| `HIGH-ARBITRARY-LOW-LEVEL-CALL` | HIGH | `high/arbitrary-low-level-call.yaml` | Unprotected low-level call with caller-controlled target and calldata. |
| `HIGH-ENCODE-PACKED-COLLISION` | HIGH | `high/encode-packed-collision.yaml` | Multiple caller-controlled dynamic values are packed before hashing. |
| `HIGH-INCORRECT-EXP` | HIGH | `high/incorrect-exp.yaml` | Simple-value `^` expression likely mistaken for exponentiation. |
| `HIGH-MSG-VALUE-IN-LOOP` | HIGH | `high/msg-value-in-loop.yaml` | Payable entry repeats a proven `msg.value` state write, ETH-bearing call, or exact stateful helper. |
| `HIGH-NO-SLIPPAGE-CHECK` | HIGH | `high/no-slippage-check.yaml` | Router swap uses an unbounded minimum-output value. |
| `HIGH-REENTRANCY-PATTERN` | HIGH | `high/reentrancy-pattern.yaml` | ETH-bearing or raw call precedes a state write without a proven guard. |
| `HIGH-UNCHECKED-ERC20-TRANSFER` | HIGH | `high/unchecked-erc20-transfer.yaml` | ERC20 transfer result is discarded or captured without a proven check. |
| `HIGH-UNPROTECTED-INITIALIZER` | HIGH | `high/unprotected-initializer.yaml` | Named initializer can be taken over on its first call. |
| `HIGH-UNRESTRICTED-TRANSFEROWNERSHIP` | HIGH | `high/unrestricted-transferownership.yaml` | Owner-like state is written from caller input without protection. |
| `HIGH-WEAK-PRNG` | HIGH | `high/weak-prng.yaml` | Block context is reduced into a pseudo-random choice. |
| `MEDIUM-BIDI-CHARACTERS` | MEDIUM | `medium/bidi-characters.yaml` | Unicode bidirectional controls can disguise source review. |
| `MEDIUM-DANGEROUS-STRICT-EQUALITY` | MEDIUM | `medium/dangerous-strict-equality.yaml` | Exact equality depends on an externally influenced balance or value. |
| `MEDIUM-DIVIDE-BEFORE-MULTIPLY` | MEDIUM | `medium/divide-before-multiply.yaml` | A division is the left operand of a multiplication. |
| `MEDIUM-TX-ORIGIN-AUTH` | MEDIUM | `medium/tx-origin-auth.yaml` | `tx.origin` participates in an authentication guard. |
| `MEDIUM-UNCHECKED-ARITHMETIC` | MEDIUM | `medium/unchecked-arithmetic.yaml` | Exploit-relevant arithmetic appears in an unchecked state-mutating path. |
| `MEDIUM-UNCHECKED-LOWLEVEL-CALL` | MEDIUM | `medium/unchecked-lowlevel-call.yaml` | Low-level call result is discarded or captured without a proven check. |
| `MEDIUM-UNCHECKED-SEND` | MEDIUM | `medium/unchecked-send.yaml` | `send` result is discarded or captured without a proven check. |
| `MEDIUM-VIEW-PURE-MODIFIES-STATE` | MEDIUM | `medium/view-pure-modifies-state.yaml` | View or pure code writes state, including assembly `sstore`. |

Unsupported protocol-specific or weakly evidenced mechanisms are deliberately
not represented in this trusted inventory. Their fixtures may remain useful
for engine regression and benchmark work, but the official pack reports only
mechanisms that can be proven generically.

### External result handling

The three unchecked-result detectors use the existing semantic boundary bridge,
not statement-shape exclusions. The positive predicate is: result disposition is
`discarded` or `captured`, and `boundary_result_checked` is `no`. An assignment is
therefore not a safety proof. Direct conditions, later checks, returned values,
consumed values, no-result operations, and unavailable or ambiguous evidence are
outside these detectors. Unknown semantic facts remain internal and fail closed;
templates do not author an `unknown` matcher.

```yaml
- any:
    - and:
        - boundary_result_disposition: ^discarded$
        - boundary_result_checked: ^no$
    - and:
        - boundary_result_disposition: ^captured$
        - boundary_result_checked: ^no$
```

### Transaction-context accounting

`HIGH-MSG-VALUE-IN-LOOP` no longer reports every textual `msg.value` reference.
It selects a loop structurally, then requires a descendant source/effect node
with all three positive attributes:

```yaml
- has:
    attr:
      transaction_context_source: ^msg_value$
      transaction_context_use: ^(state_write|call_value|stateful_internal_call)$
      transaction_context_repeatability: ^possible$
```

The builder proves these attributes from exact AST and call-graph evidence. A
direct state write, storage mutation, ETH call-value position, or resolved
stateful internal/inherited/`self`/`super` helper can match. Event, condition,
local-only, return-only, normal external calldata, pure/unresolved helper,
single-iteration, statically unreachable, branch-merged, reassigned-alias, and
unsupported loop cases remain outside the detector. There is no authored
negative or `unknown` value: missing positive evidence fails closed.
`TransactionContextFactsVersion` is `1.0.0`; the same facts survive database
cache round trips. A legacy cache has no capability and must be rebuilt from
source instead of falling back to the former textual-reference behavior.

## Validation workflow

For every detector:

1. Add vulnerable, safe, and structural-variant fixtures.
2. Add unresolved or ambiguous controls when semantic evidence is involved.
3. Run the focused detector test and the official-pack contract tests.
4. Compare source-built and cached-database scans.
5. Repeat the scan and inspect deterministic finding order and evidence.
6. Update this file, `README.md`, the relevant `AI.md`, and `docs/` in the same
   change.

Use `go test ./pkg/engine -run 'TestOfficialPack|TestPromotedDetectors'` for
focused pack checks, then the full repository gates before committing.
