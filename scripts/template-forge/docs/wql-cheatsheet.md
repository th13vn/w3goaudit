# WQL Cheatsheet — the detectable surface

This is the surface the Drafter/Repair agents may target. If a finding cannot be
expressed with these primitives, it is `NOT-detectable` and must be parked.

## Template skeleton

```yaml
meta:
  id: HIGH-SHORT-KEBAB-ID        # SCREAMING-KEBAB, severity-prefixed
  title: "Human readable title"
  severity: CRITICAL | HIGH | MEDIUM | LOW | INFO
  confidence: HIGH | MEDIUM | LOW
  description: >
    What the rule detects and why it matters.
  recommendation: >
    How to fix it.
  references:                    # optional
    - https://...

query:
  scope: entrypoint              # analyze each external/public entry point
  filter:                        # optional precondition on the function
    preset: unAuthenticated      # | unLocked | ...
  match:
    ...                          # the AST/dataflow pattern
```

## Buckets → primitives

### primitive (known-bad API)
Match the dangerous call/opcode directly.
```yaml
match:
  contains:
    kind: call.lowlevel.delegatecall      # tx.origin, ecrecover, selfdestruct, weak-prng, encodePacked...
```

### missing-check (state-changing entry without a guard)
Use a `filter` precondition; the entry point lacks the guard.
```yaml
filter:
  preset: unAuthenticated   # walks modifiers + inline msg.sender/owner checks + recursive auth in callees
match:
  contains:
    kind: state_write        # or a specific sink (eth_transfer, etc.)
```

### taint (user input → dangerous sink)
Use `args` + `tainted_from`.
```yaml
match:
  contains:
    kind: call.lowlevel.call
    all:
      - contains: { attr: { call_receiver: true }, tainted_from: parameter }
      - args: { 0: { tainted_from: parameter } }
```

### ordering (external call before state write — reentrancy-shaped)
Use `sequence` (ordered) / `inside`, plus state-write facts. Pair with
`filter: preset: unLocked` (no reentrancy guard).
```yaml
filter:
  preset: unLocked
match:
  sequence:
    - any:
        - kind: eth_transfer       # .transfer/.send/.call{value:} + raw .call
        - kind: delegatecall
    - kind: state_write
```

## Useful match building blocks

- `kind:` — AST node kind. Common: `call.lowlevel.call`, `call.lowlevel.delegatecall`,
  `call.builtin.transfer`, `call.builtin.send`, `state_write`, `asm.call`. Semantic
  groups: `eth_transfer`, `delegatecall`.
- `contains:` — node appears anywhere in the entry point (incl. recursed callees).
- `sequence:` — ordered list of sub-matches (A before B).
- `inside:` — sub-match nested within another.
- `all: / any:` — boolean composition of sub-matches.
- `args: { <index>: { tainted_from: parameter } }` — argument taint from a parameter.
- `attr: { call_receiver: true }` — the matched value is the call target/receiver.
- `filter.preset:` — `unAuthenticated` (no access control), `unLocked` (no reentrancy guard).

## Precision rules of thumb

- Prefer a `filter` precondition + a specific sink over a broad `contains`.
- For taint rules, always anchor on `tainted_from: parameter` so constants don't match.
- For ordering rules, restrict the call kinds to genuinely re-enterable ones
  (`eth_transfer`, `delegatecall`) — typed ERC20 calls are a common false-positive source.
- A template must stay SILENT on the safe fixture and across the whole `test-data/` corpus.
