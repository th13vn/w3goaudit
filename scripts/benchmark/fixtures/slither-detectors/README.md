# slither-detectors/

One `.sol` file per Slither detector. Each fragment is self-contained (SPDX +
pragma + shared interfaces + a `Vulnerable_*` / `Safe_*` pair) so it can be
scanned standalone, and the directory can also be scanned as a whole.

Pair with templates in `../../templates/slither-inspired/` (template IDs
`SLITHER-*`) for parity checks against upstream Slither.

## Fragments (27)

| Fragment | Contracts |
|---|---|
| `arbitrary-send-erc20.sol` | `Vulnerable_ArbitrarySendERC20`, `Safe_ArbitrarySendERC20` |
| `arbitrary-send-eth.sol` | `Vulnerable_ArbitrarySendEth`, `Safe_ArbitrarySendEth` |
| `assembly.sol` | `Vulnerable_Assembly`, `Safe_Assembly` |
| `assert-state-change.sol` | `Vulnerable_AssertStateChange`, `Safe_AssertStateChange` |
| `boolean-cst.sol` | `Vulnerable_BooleanCst`, `Safe_BooleanCst` |
| `calls-loop.sol` | `Vulnerable_CallsLoop`, `Safe_CallsLoop` |
| `constant-function-state.sol` | `Vulnerable_ConstantFunctionState`, `Safe_ConstantFunctionState` |
| `controlled-delegatecall.sol` | `Vulnerable_ControlledDelegatecall`, `Safe_ControlledDelegatecall` |
| `costly-loop.sol` | `Vulnerable_CostlyLoop`, `Safe_CostlyLoop` |
| `delegatecall-loop.sol` | `Vulnerable_DelegatecallLoop`, `Safe_DelegatecallLoop` |
| `divide-before-multiply.sol` | `Vulnerable_DivideBeforeMultiply`, `Safe_DivideBeforeMultiply` |
| `incorrect-equality.sol` | `Vulnerable_IncorrectEquality`, `Safe_IncorrectEquality` |
| `incorrect-exp.sol` | `Vulnerable_IncorrectExp`, `Safe_IncorrectExp` |
| `low-level-calls.sol` | `Vulnerable_LowLevelCalls`, `Safe_LowLevelCalls` |
| `msg-value-loop.sol` | `Vulnerable_MsgValueLoop`, `Safe_MsgValueLoop` |
| `reentrancy-balance.sol` | `Vulnerable_ReentrancyBalance`, `Safe_ReentrancyBalance` |
| `reentrancy-eth.sol` | `Vulnerable_ReentrancyEth`, `Safe_ReentrancyEth` |
| `reentrancy-events.sol` | `Vulnerable_ReentrancyEvents`, `Safe_ReentrancyEvents` |
| `reentrancy-no-eth.sol` | `Vulnerable_ReentrancyNoEth`, `Safe_ReentrancyNoEth` |
| `suicidal.sol` | `Vulnerable_Suicidal`, `Safe_Suicidal` |
| `timestamp.sol` | `Vulnerable_Timestamp`, `Safe_Timestamp` |
| `tx-origin.sol` | `Vulnerable_TxOrigin`, `Safe_TxOrigin` |
| `unchecked-low-level.sol` | `Vulnerable_UncheckedLowLevel`, `Safe_UncheckedLowLevel` |
| `unchecked-send.sol` | `Vulnerable_UncheckedSend`, `Safe_UncheckedSend` |
| `unchecked-transfer.sol` | `Vulnerable_UncheckedTransfer`, `Safe_UncheckedTransfer` |
| `unprotected-upgrade.sol` | `Vulnerable_UnprotectedUpgrade`, `Safe_UnprotectedUpgrade` |
| `weak-prng.sol` | `Vulnerable_WeakPRNG`, `Safe_WeakPRNG` |

## Benchmark workflow

```bash
SUITE=slither \
TOOLS=w3goaudit,slither \
docker compose -f benchmarks/compose.yaml run --rm benchmark
```

Run this from the repository root. All pinned scanners are installed in the
shared image. The Dockerfile derives and verifies Go directly from the root
`go.mod` and verifies the reviewed generated-lock hash for the pinned 4naly3er
commit. See `../../README.md` for the full Compose contract.
