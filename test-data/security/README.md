# security/

General, W3GoAudit-native fixtures for the official security detectors in
[`../../templates/official/`](../../templates/official/).

## Layout

All `.sol` files sit directly in this directory — no subdirectories. They pair
with the official pack and explore each bug class in **depth**: the deep ones
cover many variants of one vulnerability (`arbitrary-transferfrom.sol` alone has
36 contracts spanning alias / internal-helper / struct / array forwards), and
the remainder are one `Vulnerable_*`/`Safe_*` pair per promoted detector.

### Root fixtures

Deep, W3GoAudit-native bug-class fixtures:

| File | Bug class / purpose |
|---|---|
| `arbitrary-transferfrom.sol` | ERC20 `transferFrom` with user-controlled `from` — the deepest fixture: alias / internal-helper / array-element / struct / return-helper forwards, plus invariant safe cases. 36 contracts. |
| `reentrancy.sol` | Classic reentrancy patterns — `.call{value:}`, `.transfer`, `.send`, raw `.call` — across vault / auction / withdraw shapes. |
| `reentrancy-simple.sol` | Minimal CEI-violation example. Drives `TestInterproceduralSequenceFindsCallsInsideInternalHelpers`. |
| `unchecked-arithmetic.sol` | `unchecked { … }` blocks on Solidity ≥ 0.8, including a bounded-safe edge case. |
| `dataflow.sol` | Minimal interprocedural taint-propagation fixture. |

One `Vulnerable_*`/`Safe_*` fixture per promoted detector:

| File | Detector |
|---|---|
| `boolean-cst.sol` | `MEDIUM-BOOLEAN-CST` Boolean constant misuse |
| `encode-packed-collision.sol` | `HIGH-ENCODE-PACKED-COLLISION` `abi.encodePacked` hash collision |
| `proxy-storage-collision.sol` | `HIGH-PROXY-STORAGE-COLLISION` Proxy storage layout collision |
| `ecdsa-recover-malleable.sol` | `HIGH-ECDSA-RECOVER-MALLEABLE` Signature malleability |
| `arbitrary-low-level-call.sol` | `HIGH-ARBITRARY-LOW-LEVEL-CALL` Arbitrary low-level call |
| `unrestricted-transferownership.sol` | `HIGH-UNRESTRICTED-TRANSFEROWNERSHIP` Unrestricted `transferOwnership` |

## Used by

- `pkg/engine/interprocedural_taint_test.go` (taint propagation, unchecked-arithmetic
  visibility)
- The documented full-pack scan:
  `w3goaudit test-data/security/ --template templates/official/`
