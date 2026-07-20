# decurity-semgrep-inspired/

One `.sol` file per Decurity Semgrep rule, plus advanced variants. Pair with
templates in `../../templates/decurity-semgrep-inspired/` (template IDs
`DECURITY-*`) and the vendored Semgrep rules in
`../../config/semgrep-decurity/` for the parity benchmark.

## Adversarial bypass fixtures

Six fragments were added to stress both AST-aware and surface-syntactic
detectors with deliberate evasion patterns. Filenames make the technique
explicit (`-asm`, `-cast`, `-struct-forward`, `-conditional`, `-inherited`,
`-fake-modifier`). Each pairs a `Vulnerable*` contract that should still be
detected with a `Safe*` counterpart that should not.

| Bypass file | Evasion technique | w3goaudit | semgrep |
|---|---|:---:|:---:|
| `accessible-selfdestruct-asm.sol` | Yul `assembly { selfdestruct(...) }` instead of the Solidity-level builtin | ✓ | ✗ |
| `accessible-selfdestruct-cast.sol` | `payable(address(uint160(...)))` round-trip on the beneficiary | ✓ | ✗ |
| `bad-transfer-from-inherited.sol` | Dangerous helper defined in an `abstract` base, exposed via no-modifier derived wrapper | ✓ | ✗ |
| `arbitrary-low-level-call-conditional.sol` | Caller-controlled target dispatched to `.call` **or** `.staticcall` via if/else | ✓ | ✓ |
| `delegatecall-struct-forward.sol` | User-controlled target wrapped in a struct field, forwarded across an internal helper | ✓ | ✗ |
| `unrestricted-transfer-ownership-fake-modifier.sol` | Empty modifier **named** `auth` (decoy that defeats name-based access-control heuristics) | ✓ | ✗ |

### What the bypasses showed

- **5 of 6** evade Semgrep — every indirection / type-cast / assembly form.
  Surface-syntactic matching can't follow taint through helpers, struct
  fields, inheritance chains, or assembly operands.
- **All 6** are detected by w3goaudit. The accessible-selfdestruct rule models
  unauthenticated reachability, not beneficiary taint, so Solidity, helper,
  cast, fixed-beneficiary, and Yul forms share the same canonical category.
- **The empty-`auth`-modifier bypass surfaced a real heuristic bug** in
  `pkg/types/function.go`: the `IsAccessControlled` regex trusted modifier
  *names* without inspecting bodies. Fixed in this session — the helper now
  resolves the modifier definition (through the contract's linearized bases
  when needed) and requires at least one auth-shape signal (a guard, an if,
  or a `msg.sender`/`tx.origin` reference) in the body before trusting an
  auth-shaped name. When the definition cannot be resolved (synthetic
  fixtures, inherited from out-of-scope bases), the helper falls back to
  trusting the name so existing tests keep passing.

## Fragments (69)

| Fragment | Contracts |
|---|---|
| `accessible-selfdestruct-helper.sol` | `VulnerableAccessibleSelfdestructHelper` |
| `accessible-selfdestruct.sol` | `VulnerableAccessibleSelfdestruct` |
| `arbitrary-low-level-call-alias.sol` | `VulnerableArbitraryLowLevelCallAlias` |
| `arbitrary-low-level-call-owner-only.sol` | `SafeArbitraryLowLevelCallOwnerOnly` |
| `arbitrary-low-level-call.sol` | `VulnerableArbitraryLowLevelCall` |
| `bad-transfer-from-access-control.sol` | `VulnerableBadTransferFromAccessControl` |
| `bad-transfer-from-internal-flow.sol` | `VulnerableBadTransferFromInternalFlow` |
| `balancer-get-rate.sol` | `VulnerableBalancerGetRate` |
| `balancer-pool-tokens.sol` | `VulnerableBalancerPoolTokens` |
| `basic-arithmetic-underflow-alias.sol` | `VulnerableBasicArithmeticUnderflowAlias` with an explicit Solidity 0.8 `unchecked` subtraction alias true positive |
| `basic-arithmetic-underflow.sol` | `VulnerableBasicArithmeticUnderflow` with explicit Solidity 0.8 `unchecked` binary/assignment overloads and guarded `unchecked` controls |
| `basic-oracle-manipulation.sol` | `VulnerableBasicOracleManipulation` |
| `bidi-characters.sol` | `VulnerableBidiCharacters` |
| `compound-borrow-fresh.sol` | `VulnerableCompoundBorrowFresh` |
| `compound-precision-loss.sol` | `VulnerableCompoundPrecisionLoss` |
| `compound-sweep-token-alias.sol` | `VulnerableCompoundSweepTokenAlias` |
| `compound-sweep-token.sol` | `VulnerableCompoundSweepToken` |
| `curve-readonly-reentrancy.sol` | `VulnerableCurveReadonlyReentrancy` |
| `delegatecall-alias.sol` | `VulnerableDelegatecallAlias` |
| `delegatecall-to-arbitrary-address.sol` | `VulnerableDelegatecallToArbitraryAddress` |
| `encode-packed-collision-nested.sol` | `VulnerableEncodePackedCollisionNested` |
| `encode-packed-collision.sol` | `VulnerableEncodePackedCollision` |
| `erc20-public-burn.sol` | `VulnerableERC20PublicBurn` |
| `erc20-public-transfer.sol` | `VulnerableERC20PublicTransfer` |
| `erc677-reentrancy.sol` | `VulnerableERC677Reentrancy` |
| `erc721-arbitrary-transfer-from.sol` | `VulnerableERC721ArbitraryTransferFrom` |
| `erc721-reentrancy.sol` | `VulnerableERC721Reentrancy` |
| `erc777-reentrancy.sol` | `VulnerableERC777Reentrancy` |
| `exact-balance-at-least.sol` | `SafeExactBalanceAtLeast` |
| `exact-balance-check.sol` | `VulnerableExactBalanceCheck` |
| `gearbox-path-confusion.sol` | `VulnerableGearboxPathConfusion` |
| `incorrect-use-of-blockhash.sol` | `VulnerableIncorrectUseOfBlockhash` |
| `keeper-oracle-manipulation.sol` | `VulnerableKeeperOracleManipulation` |
| `missing-assignment.sol` | `VulnerableMissingAssignment` |
| `msg-value-multicall-helper.sol` | `VulnerableMsgValueMulticallHelper` |
| `msg-value-multicall.sol` | `VulnerableMsgValueMulticall` |
| `no-slippage-check.sol` | `VulnerableNoSlippageCheck` |
| `no-slippage-exact-eth.sol` | `VulnerableNoSlippageExactETH` |
| `no-slippage-user-bound.sol` | `SafeNoSlippageUserBound` |
| `olympus-call-order.sol` | `VulnerableOlympusCallOrder` |
| `open-zeppelin-ecdsa-recover.sol` | `VulnerableOpenZeppelinECDSARecover` |
| `oracle-price-update-helper.sol` | `VulnerableOraclePriceUpdateHelper` |
| `oracle-price-update-not-restricted.sol` | `VulnerableOraclePriceUpdateNotRestricted` |
| `oracle-uses-curve-spot-price.sol` | `VulnerableOracleUsesCurveSpotPrice` |
| `proxy-storage-collision.sol` | `VulnerableProxyStorageCollision` |
| `proxy-storage-no-collision.sol` | `SafeProxyStorageNoCollision` |
| `public-transfer-fees-supporting-tax-tokens.sol` | `VulnerablePublicTransferFeesSupportingTaxTokens` |
| `redacted-cartel-approval-bug.sol` | `VulnerableRedactedCartelApprovalBug` |
| `rigoblock-missing-access-control.sol` | `VulnerableRigoblockMissingAccessControl` |
| `sense-missing-oracle-access-control.sol` | `VulnerableSenseMissingOracleAccessControl` |
| `superfluid-ctx-injection.sol` | `VulnerableSuperfluidCtxInjection` |
| `tecra-coin-burn-from-bug.sol` | `VulnerableTecraCoinBurnFromBug` |
| `thirdweb-combination.sol` | `VulnerableThirdwebCombination` |
| `thirdweb-forwarder-batch.sol` | `VulnerableThirdwebForwarderBatch` |
| `thirdweb-only-erc2771.sol` | `SafeThirdwebOnlyERC2771` |
| `thirdweb-only-multicall.sol` | `SafeThirdwebOnlyMulticall` |
| `transfer-from-sender-bound.sol` | `SafeTransferFromSenderBound` |
| `uniswap-callback-not-protected.sol` | `VulnerableUniswapCallbackNotProtected` |
| `uniswap-callback-verified.sol` | `SafeUniswapCallbackVerified` |
| `uniswap-v4-callback-not-protected.sol` | `VulnerableUniswapV4CallbackNotProtected` |
| `uniswap-v4-callback-only-manager.sol` | `SafeUniswapV4CallbackOnlyManager` with a configured manager sender check |
| `unrestricted-transfer-ownership-helper.sol` | `VulnerableUnrestrictedTransferOwnershipHelper` |
| `unrestricted-transfer-ownership.sol` | `VulnerableUnrestrictedTransferOwnership` |

## Benchmark workflow

Use the Docker Compose workflow documented in `../../README.md`, with
`SUITE=decurity` and `TOOLS=w3goaudit,semgrep` supplied to that command. The
benchmark does not support a helper script or direct host-runner invocation.

For focused detector development, pair a fixture in this directory with the
same-named WQL file under `../../templates/decurity-semgrep-inspired/` and the
vendored Semgrep rule under `../../config/semgrep-decurity/`.
