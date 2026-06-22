# 4naly3er-detectors/

One `.sol` file per 4naly3er detector. Each fragment is self-contained
(SPDX + pragma + shared interfaces/libraries + a `Vulnerable_*` / `Safe_*` pair).
Pair with templates in `../../templates/4naly3er-inspired/` (template IDs
`4NALY3ER-H-*` / `4NALY3ER-M-*`) for parity checks. Note the benchmark ships
WQL templates for the 14 High/Medium 4naly3er security detectors, not for all
37 fixtures here.

## Fragments (37)

| Fragment | Contracts |
|---|---|
| `address-zero-check.sol` | `Vulnerable_AddressZeroCheck`, `Safe_AddressZeroCheck` |
| `approve-zero-first.sol` | `Vulnerable_ApproveZeroFirst`, `Safe_ApproveZeroFirst` |
| `block-number-l2.sol` | `Vulnerable_BlockNumberL2`, `Safe_BlockNumberL2` |
| `bool-compare.sol` | `Vulnerable_BoolCompare`, `Safe_BoolCompare` |
| `cache-array-length.sol` | `Vulnerable_CacheArrayLength`, `Safe_CacheArrayLength` |
| `centralization-risk.sol` | `Vulnerable_CentralizationRisk`, `Safe_CentralizationRisk` |
| `comparison-outside-condition.sol` | `Vulnerable_ComparisonOutsideCondition`, `Safe_ComparisonOutsideCondition` |
| `custom-errors.sol` | `Vulnerable_CustomErrors`, `Safe_CustomErrors` |
| `delegate-call-in-loop.sol` | `Vulnerable_DelegateCallInLoop`, `Safe_DelegateCallInLoop` |
| `deprecated-approve.sol` | `Vulnerable_DeprecatedApprove`, `Safe_DeprecatedApprove` |
| `deprecated-chainlink.sol` | `Vulnerable_DeprecatedChainlink`, `Safe_DeprecatedChainlink` |
| `deprecated-safe-approve.sol` | `Vulnerable_DeprecatedSafeApprove`, `Safe_DeprecatedSafeApprove` |
| `deprecated-setup-role.sol` | `Vulnerable_DeprecatedSetupRole`, `Safe_DeprecatedSetupRole` |
| `disable-init-impl.sol` | `Vulnerable_DisableInitImpl`, `Safe_DisableInitImpl` |
| `div0-not-prevented.sol` | `Vulnerable_Div0NotPrevented`, `Safe_Div0NotPrevented` |
| `ecrecover.sol` | `Vulnerable_Ecrecover`, `Safe_Ecrecover` |
| `encode-packed.sol` | `Vulnerable_EncodePacked`, `Safe_EncodePacked` |
| `erc721-safe-mint.sol` | `Vulnerable_ERC721SafeMint`, `Safe_ERC721SafeMint` |
| `erc721-safe-transfer-from.sol` | `Vulnerable_ERC721SafeTransferFrom`, `Safe_ERC721SafeTransferFrom` |
| `ext-call-loop.sol` | `Vulnerable_ExtCallLoop`, `Safe_ExtCallLoop` |
| `fee-over100.sol` | `Vulnerable_FeeOver100`, `Safe_FeeOver100` |
| `immutable-constructor.sol` | `Vulnerable_ImmutableConstructor`, `Safe_ImmutableConstructor` |
| `initialize-default-value.sol` | `Vulnerable_InitializeDefaultValue`, `Safe_InitializeDefaultValue` |
| `long-revert-string.sol` | `Vulnerable_LongRevertString`, `Safe_LongRevertString` |
| `mint-burn-zero.sol` | `Vulnerable_MintBurnZero`, `Safe_MintBurnZero` |
| `msg-sender-gas.sol` | `Vulnerable_MsgSenderGas`, `Safe_MsgSenderGas` |
| `msg-value-in-loop.sol` | `Vulnerable_MsgValueInLoop`, `Safe_MsgValueInLoop` |
| `post-increment.sol` | `Vulnerable_PostIncrement`, `Safe_PostIncrement` |
| `stale-oracle-data.sol` | `Vulnerable_StaleOracleData`, `Safe_StaleOracleData` |
| `this-external.sol` | `Vulnerable_ThisExternal`, `Safe_ThisExternal` |
| `timestamp-deadline.sol` | `Vulnerable_TimestampDeadline`, `Safe_TimestampDeadline` |
| `two-step-owner.sol` | `Vulnerable_TwoStepOwner`, `Safe_TwoStepOwner` |
| `tx-origin.sol` | `Vulnerable_TxOrigin`, `Safe_TxOrigin` |
| `unchecked-erc20-transfer.sol` | `Vulnerable_UncheckedERC20Transfer`, `Safe_UncheckedERC20Transfer` |
| `unchecked-increments.sol` | `Vulnerable_UncheckedIncrements`, `Safe_UncheckedIncrements` |
| `unsafe-casting.sol` | `Vulnerable_UnsafeCasting`, `Safe_UnsafeCasting` |
| `wst-eth-price.sol` | `Vulnerable_WstEthPrice`, `Safe_WstEthPrice` |

## Run

```bash
# Whole directory
w3goaudit benchmarks/fixtures/4naly3er-detectors/ --template benchmarks/templates/4naly3er-inspired/

# One detector
w3goaudit benchmarks/fixtures/4naly3er-detectors/tx-origin.sol \
  --template benchmarks/templates/4naly3er-inspired/M-avoid-tx-origin.yaml
```
