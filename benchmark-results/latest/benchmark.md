# Static Analyzer Benchmark

- Generated: `2026-05-22T09:31:01.023777+00:00`
- Corpus: `W3GoAudit all security template bug corpus`
- Cases: `7`

## Summary

| Tool      |        Status | Version                       | Cases | Runtime ms |  Raw | Scoped | Precision |  Recall |     F1 |
| --------- | ------------: | ----------------------------- | ----: | ---------: | ---: | -----: | --------: | ------: | -----: |
| w3goaudit |            ok | w3goaudit version 0.2.0 (dev) |     7 |     346.81 |  108 |    108 |    78.70% | 100.00% | 88.08% |
| slither   | partial_error | 0.11.3                        |     7 |    5873.19 |  148 |     76 |    35.53% |  31.76% | 33.54% |
| aderyn    |       skipped |                               |     0 |          0 |    0 |      0 |         - |       - |      - |
| semgrep   |       skipped |                               |     0 |          0 |    0 |      0 |         - |       - |      - |
| solhint   | partial_error | 6.2.1                         |     7 |   13476.12 |  515 |      3 |    66.67% |   2.35% |  4.55% |

## By Category

| Tool      | Category                  |   TP |   FP |   FN | Precision |  Recall |      F1 |
| --------- | ------------------------- | ---: | ---: | ---: | --------: | ------: | ------: |
| w3goaudit | arbitrary-send-eth        |    3 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | arbitrary-transferfrom    |   13 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | controlled-delegatecall   |    3 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | dangerous-strict-equality |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | delegatecall-loop         |    2 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | divide-before-multiply    |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | incorrect-exp             |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | msg-value-loop            |    2 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | reentrancy                |   11 |   21 |    0 |    34.38% | 100.00% |  51.16% |
| w3goaudit | reentrancy-balance        |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | selfdestruct              |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | tx-origin                 |    2 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | unchecked-arithmetic      |    1 |    1 |    0 |    50.00% | 100.00% |  66.67% |
| w3goaudit | unchecked-erc20-transfer  |   33 |    1 |    0 |    97.06% | 100.00% |  98.51% |
| w3goaudit | unchecked-lowlevel-call   |    4 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | unchecked-send            |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | unprotected-initializer   |    2 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | view-pure-state-write     |    1 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| w3goaudit | weak-prng                 |    2 |    0 |    0 |   100.00% | 100.00% | 100.00% |
| slither   | arbitrary-send-eth        |    0 |    2 |    3 |     0.00% |   0.00% |   0.00% |
| slither   | arbitrary-transferfrom    |    5 |   13 |    8 |    27.78% |  38.46% |  32.26% |
| slither   | controlled-delegatecall   |    0 |    0 |    3 |     0.00% |   0.00% |   0.00% |
| slither   | dangerous-strict-equality |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | delegatecall-loop         |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| slither   | divide-before-multiply    |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | incorrect-exp             |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | msg-value-loop            |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| slither   | reentrancy                |    7 |    4 |    4 |    63.64% |  63.64% |  63.64% |
| slither   | reentrancy-balance        |    0 |   19 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | selfdestruct              |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | tx-origin                 |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| slither   | unchecked-arithmetic      |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | unchecked-erc20-transfer  |   12 |   11 |   21 |    52.17% |  36.36% |  42.86% |
| slither   | unchecked-lowlevel-call   |    3 |    0 |    1 |   100.00% |  75.00% |  85.71% |
| slither   | unchecked-send            |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | unprotected-initializer   |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| slither   | view-pure-state-write     |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| slither   | weak-prng                 |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| solhint   | arbitrary-send-eth        |    0 |    0 |    3 |     0.00% |   0.00% |   0.00% |
| solhint   | arbitrary-transferfrom    |    0 |    0 |   13 |     0.00% |   0.00% |   0.00% |
| solhint   | controlled-delegatecall   |    0 |    0 |    3 |     0.00% |   0.00% |   0.00% |
| solhint   | dangerous-strict-equality |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | delegatecall-loop         |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| solhint   | divide-before-multiply    |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | incorrect-exp             |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | msg-value-loop            |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| solhint   | reentrancy                |    2 |    1 |    9 |    66.67% |  18.18% |  28.57% |
| solhint   | reentrancy-balance        |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | selfdestruct              |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | tx-origin                 |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| solhint   | unchecked-arithmetic      |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | unchecked-erc20-transfer  |    0 |    0 |   33 |     0.00% |   0.00% |   0.00% |
| solhint   | unchecked-lowlevel-call   |    0 |    0 |    4 |     0.00% |   0.00% |   0.00% |
| solhint   | unchecked-send            |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | unprotected-initializer   |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |
| solhint   | view-pure-state-write     |    0 |    0 |    1 |     0.00% |   0.00% |   0.00% |
| solhint   | weak-prng                 |    0 |    0 |    2 |     0.00% |   0.00% |   0.00% |

## Misses And Noise

### w3goaudit

- False negatives: `0`
- False positives: `23`
  - `4naly3er-detectors` `unchecked-erc20-transfer` `Vulnerable_ERC721SafeTransferFrom.sendNFT()`
  - `arbitrary-transferfrom` `reentrancy` `EdgeCaseInternal.deposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeAdminDeposit.adminDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeAliasReassignmentForward.depositFrom()`
  - `arbitrary-transferfrom` `reentrancy` `SafeBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDeposit1.deposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDeposit2.depositFrom()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDepositWithAssert.depositFrom()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDepositWithIf.depositFrom()`
  - `arbitrary-transferfrom` `reentrancy` `SafeRoleBasedDeposit.operatorDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeRoleGuardedWrapper.operatorDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeSenderAliasForward.deposit()`
  - ... 11 more

### slither

- False negatives: `58`
  - `4naly3er-detectors` `controlled-delegatecall` `Vulnerable_DelegateCallInLoop.multiExecute()`
  - `4naly3er-detectors` `delegatecall-loop` `Vulnerable_DelegateCallInLoop.multiExecute()`
  - `4naly3er-detectors` `msg-value-loop` `Vulnerable_MsgValueInLoop.batchDeposit()`
  - `4naly3er-detectors` `tx-origin` `Vulnerable_TxOrigin.withdraw()`
  - `4naly3er-detectors` `unchecked-erc20-transfer` `Vulnerable_CentralizationRisk.drainTo()`
  - `4naly3er-detectors` `unchecked-erc20-transfer` `Vulnerable_UncheckedERC20Transfer.pay()`
  - `4naly3er-detectors` `unprotected-initializer` `Vulnerable_DisableInitImpl.initialize()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasReassignmentForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableInternalForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableNestedForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableStructForward.deposit()`
  - ... 46 more
- False positives: `49`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeAdminDeposit.adminDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDeposit2.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDepositWithAssert.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDepositWithIf.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeRoleBasedDeposit.operatorDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeRoleGuardedWrapper._internalDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeValidatedWrapper._internalDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasForward._internalDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasReassignmentForward._internalDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableInternalForward._internalDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableNestedForward._internalDeposit()`
  - ... 37 more

### solhint

- False negatives: `83`
  - `4naly3er-detectors` `controlled-delegatecall` `Vulnerable_DelegateCallInLoop.multiExecute()`
  - `4naly3er-detectors` `delegatecall-loop` `Vulnerable_DelegateCallInLoop.multiExecute()`
  - `4naly3er-detectors` `msg-value-loop` `Vulnerable_MsgValueInLoop.batchDeposit()`
  - `4naly3er-detectors` `tx-origin` `Vulnerable_TxOrigin.withdraw()`
  - `4naly3er-detectors` `unchecked-erc20-transfer` `Vulnerable_CentralizationRisk.drainTo()`
  - `4naly3er-detectors` `unchecked-erc20-transfer` `Vulnerable_UncheckedERC20Transfer.pay()`
  - `4naly3er-detectors` `unprotected-initializer` `Vulnerable_DisableInitImpl.initialize()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableAliasReassignmentForward.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableDeposit.deposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableInternalForward.depositFrom()`
  - ... 71 more
- False positives: `1`
  - `reentrancy` `reentrancy` `SafeBank3.withdrawWithGuard()`

## Run Status

| Tool      | Case                   | Status | Exit | Runtime ms |  Raw | Scoped | Error                                                                                                                                              |
| --------- | ---------------------- | -----: | ---: | ---------: | ---: | -----: | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| w3goaudit | arbitrary-transferfrom |     ok |    0 |      92.89 |   54 |     54 |                                                                                                                                                    |
| w3goaudit | reentrancy             |     ok |    0 |      40.86 |    5 |      5 |                                                                                                                                                    |
| w3goaudit | reentrancy-simple      |     ok |    0 |      35.27 |    4 |      4 |                                                                                                                                                    |
| w3goaudit | dataflow               |     ok |    0 |      32.17 |    3 |      3 |                                                                                                                                                    |
| w3goaudit | slither-detectors      |     ok |    0 |      53.39 |   32 |     32 |                                                                                                                                                    |
| w3goaudit | 4naly3er-detectors     |     ok |    0 |      62.31 |    8 |      8 |                                                                                                                                                    |
| w3goaudit | unchecked-arithmetic   |     ok |    0 |      29.92 |    2 |      2 |                                                                                                                                                    |
| slither   | arbitrary-transferfrom |     ok |  255 |     1767.9 |   99 |     63 |                                                                                                                                                    |
| slither   | reentrancy             |     ok |  255 |      855.9 |   21 |      4 |                                                                                                                                                    |
| slither   | reentrancy-simple      |     ok |  255 |     770.34 |   14 |      7 |                                                                                                                                                    |
| slither   | dataflow               |     ok |  255 |     635.06 |   10 |      3 |                                                                                                                                                    |
| slither   | slither-detectors      |  error |    1 |      580.8 |    0 |      0 | expected output was not written: benchmark-results/latest/raw/slither-detectors.slither.json                                                       |
| slither   | 4naly3er-detectors     |  error |    1 |     592.71 |    0 |      0 | expected output was not written: benchmark-results/latest/raw/4naly3er-detectors.slither.json                                                      |
| slither   | unchecked-arithmetic   |     ok |  255 |     670.48 |    4 |      0 |                                                                                                                                                    |
| solhint   | arbitrary-transferfrom |     ok |    1 |     3395.3 |  267 |      0 |                                                                                                                                                    |
| solhint   | reentrancy             |     ok |    1 |    1682.71 |  131 |      4 |                                                                                                                                                    |
| solhint   | reentrancy-simple      |     ok |    1 |    1651.93 |   70 |      0 |                                                                                                                                                    |
| solhint   | dataflow               |     ok |    1 |    1521.82 |   18 |      0 |                                                                                                                                                    |
| solhint   | slither-detectors      |  error |    1 |    1820.31 |    0 |      0 | could not parse solhint JSON for test-data/security/test-slither-detectors.sol: Unterminated string starting at: line 1 column 65516 (char 65515)  |
| solhint   | 4naly3er-detectors     |  error |    1 |     1840.5 |    0 |      0 | could not parse solhint JSON for test-data/security/test-4naly3er-detectors.sol: Unterminated string starting at: line 1 column 65490 (char 65489) |
| solhint   | unchecked-arithmetic   |     ok |    1 |    1563.55 |   29 |      0 |                                                                                                                                                    |
