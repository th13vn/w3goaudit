# Static Analyzer Benchmark

- Generated: `2026-05-22T08:48:51.753825+00:00`
- Corpus: `W3GoAudit security benchmark seed corpus`
- Cases: `3`

## Summary

| Tool | Status | Version | Cases | Runtime ms | Raw | Scoped | Precision | Recall | F1 |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|
| w3goaudit | ok | w3goaudit version 0.2.0 (dev) | 3 | 91.6 | 15 | 15 | 100.00% | 100.00% | 100.00% |
| slither | ok | 0.11.3 | 3 | 2796.58 | 120 | 46 | 21.74% | 66.67% | 32.79% |
| aderyn | skipped |  | 0 | 0 | 0 | 0 | - | - | - |
| semgrep | skipped |  | 0 | 0 | 0 | 0 | - | - | - |
| solhint | ok | 6.2.1 | 3 | 5209.16 | 398 | 3 | 66.67% | 13.33% | 22.22% |

## By Category

| Tool | Category | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| w3goaudit | arbitrary-transferfrom | 10 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| w3goaudit | reentrancy | 5 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| slither | arbitrary-transferfrom | 5 | 13 | 5 | 27.78% | 50.00% | 35.71% |
| slither | reentrancy | 5 | 23 | 0 | 17.86% | 100.00% | 30.30% |
| solhint | arbitrary-transferfrom | 0 | 0 | 10 | 0.00% | 0.00% | 0.00% |
| solhint | reentrancy | 2 | 1 | 3 | 66.67% | 40.00% | 50.00% |

## Misses And Noise

### w3goaudit

- False negatives: `0`
- False positives: `0`

### slither

- False negatives: `5`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableAliasForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableAliasReassignmentForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableInternalForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableNestedForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableStructForward.deposit()`
- False positives: `36`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeAdminDeposit.adminDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDeposit2.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDepositWithAssert.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeDepositWithIf.depositFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `SafeRoleBasedDeposit.operatorDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `EdgeCaseInternal._internalDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeAdminDeposit.adminDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDeposit1.deposit()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDeposit2.depositFrom()`
  - `arbitrary-transferfrom` `reentrancy` `SafeDepositWithAssert.depositFrom()`
  - ... 24 more

### solhint

- False negatives: `13`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableBatchDeposit.batchDeposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableDeposit.deposit()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableNoAuth.withdrawFrom()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableStaking.stake()`
  - `arbitrary-transferfrom` `arbitrary-transferfrom` `VulnerableSwap.swap()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableAliasForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableAliasReassignmentForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableInternalForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableNestedForward.depositFrom()`
  - `arbitrary-transferfrom-internal-flows` `arbitrary-transferfrom` `VulnerableStructForward.deposit()`
  - `reentrancy` `reentrancy` `VulnerableAuction.refund()`
  - `reentrancy` `reentrancy` `VulnerableBank1.withdraw()`
  - ... 1 more
- False positives: `1`
  - `reentrancy` `reentrancy` `SafeBank3.withdrawWithGuard()`

## Run Status

| Tool | Case | Status | Exit | Runtime ms | Raw | Scoped | Error |
|---|---|---:|---:|---:|---:|---:|---|
| w3goaudit | arbitrary-transferfrom | ok | 0 | 29.95 | 5 | 5 |  |
| w3goaudit | arbitrary-transferfrom-internal-flows | ok | 0 | 31.31 | 5 | 5 |  |
| w3goaudit | reentrancy | ok | 0 | 30.34 | 5 | 5 |  |
| slither | arbitrary-transferfrom | ok | 255 | 1023.82 | 59 | 22 |  |
| slither | arbitrary-transferfrom-internal-flows | ok | 255 | 850.12 | 40 | 17 |  |
| slither | reentrancy | ok | 255 | 922.64 | 21 | 7 |  |
| solhint | arbitrary-transferfrom | ok | 1 | 1754.75 | 164 | 0 |  |
| solhint | arbitrary-transferfrom-internal-flows | ok | 1 | 1721.42 | 103 | 0 |  |
| solhint | reentrancy | ok | 1 | 1732.99 | 131 | 4 |  |
