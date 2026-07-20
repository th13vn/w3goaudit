# security/

W3GoAudit-native fixtures for the official security detectors in
[`../../templates/official/`](../../templates/official/).

## Layout

All `.sol` files sit directly in this directory. The inventory distinguishes
deep bug-class matrices, focused engine regressions, and fixtures owned by one
promoted official detector. A promoted fixture may contain more than one
`Vulnerable_*`/`Safe_*` pair when false-positive exclusions need dedicated
coverage. The 17 files below are the complete canonical inventory; there are no
duplicate aggregate `test-*` fixtures.

Interprocedural transfer-from coverage is folded into the deep matrix below.
Slither- and 4naly3er-derived benchmark fixtures are maintained as split cases
under [`../../benchmarks/fixtures/`](../../benchmarks/fixtures/), not as
aggregate files in this directory.

### Fixture inventory

| File | Ownership | Coverage |
|---|---|---|
| `arbitrary-low-level-call.sol` | Promoted detector fixture | `HIGH-ARBITRARY-LOW-LEVEL-CALL`; vulnerable user-controlled target/calldata and authenticated safe control. |
| `arbitrary-send-eth.sol` | Promoted detector fixture | `HIGH-ARBITRARY-SEND-ETH`; unprotected value transfer and owner-gated safe control. |
| `arbitrary-transferfrom.sol` | Deep bug-class matrix | `HIGH-ARBITRARY-TRANSFERFROM`; 36 declarations covering aliases, helper hops, structs, arrays, returned values, argument reordering, invariants, and safe controls. |
| `boolean-cst.sol` | Promoted detector matrix | `MEDIUM-BOOLEAN-CST`; nine misuse functions plus safe return, assignment, call-argument, mapping, and `while (true)` controls. |
| `dataflow.sol` | Focused engine regression | Minimal interprocedural taint propagation independent of a detector-specific fixture. |
| `ecdsa-recover-malleable.sol` | Promoted detector fixture | `HIGH-ECDSA-RECOVER-MALLEABLE`; raw-signature replay risk and digest-keyed safe control. |
| `encode-packed-collision.sol` | Promoted detector fixture | `HIGH-ENCODE-PACKED-COLLISION`; multiple dynamic packed arguments and an unambiguous safe encoding. |
| `incorrect-exp.sol` | Promoted detector matrix | `HIGH-INCORRECT-EXP`; mistaken XOR shapes plus intentional bitwise-XOR exclusions. |
| `proxy-storage-collision.sol` | Promoted detector matrix | `HIGH-PROXY-STORAGE-COLLISION`; vulnerable proxy storage plus immutable and non-proxy safe controls. |
| `reentrancy-simple.sol` | Focused engine regression | Direct, nested, and recursive helper sequences plus CEI and guarded safe cases. Drives `TestInterproceduralSequenceFindsCallsInsideInternalHelpers`. |
| `reentrancy.sol` | Deep bug-class matrix | `HIGH-REENTRANCY-PATTERN`; 14 vault, bank, and auction variants using `.call{value:}`, `.transfer`, `.send`, and raw `.call`, with safe and edge controls. |
| `selfdestruct-unprotected.sol` | Promoted detector matrix | `CRITICAL-SELFDESTRUCT-UNPROTECTED`; unguarded destruction plus modifier and inline-caller-guard safe controls. |
| `tx-origin-auth.sol` | Promoted detector matrix | `MEDIUM-TX-ORIGIN-AUTH`; unsafe authorization, the deliberate `msg.sender == tx.origin` EOA check exclusion, and `msg.sender` authorization. |
| `unchecked-arithmetic.sol` | Promoted detector matrix | `MEDIUM-UNCHECKED-ARITHMETIC` plus the real Decurity underflow template; vulnerable unchecked math, exact enforced bounds, reversed/unrelated/non-terminating/wrong-polarity guards, mutating dominating/fallthrough arms, effectful conjunction/disjunction operands and guard messages, intervening and ancestor internal/external calls, effectful sibling expressions with unspecified evaluation order, transparent and pure-expression safe controls, signed arithmetic, and pure-library exclusions. |
| `unprotected-initializer.sol` | Focused detector regression | Actual official and benchmark unprotected-initializer templates; vulnerable initializer plus access-control-only, one-time initializer-modifier-only, and disable-guard-only safe controls. |
| `unrestricted-transferownership.sol` | Promoted detector fixture | `HIGH-UNRESTRICTED-TRANSFEROWNERSHIP`; unrestricted owner write and access-controlled safe control. |
| `user-controlled-caller-identity.sol` | Focused detector regression | Actual official and benchmark templates for delegatecall, low-level call, transferOwnership, and accessible selfdestruct; exact internal `_msgSender()` plus caller/parameter vulnerabilities, same-named state/local/external/nonzero-call controls, fixed-target controls where the category requires taint, fixed-beneficiary unprotected selfdestruct, and access-controlled safe controls. A dedicated guard matrix proves both `IsAccessControlled` and `ComparesCallerIdentity` accept only the metadata/MRO-resolved zero-argument internal helper. Also pins retained parameter-only transferFrom and ETH-recipient templates, including a parameter named `_msgSender`. |

## Used by

- Focused `pkg/engine/*_test.go` regressions (taint, reentrancy sequences,
  unchecked arithmetic, arbitrary ETH transfer, and detector edge cases)
- The documented full-pack scan:
  `w3goaudit test-data/security/ --template templates/official/`
