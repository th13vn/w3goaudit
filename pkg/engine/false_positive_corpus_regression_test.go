package engine

import (
	"strings"
	"testing"
)

// Regressions from the 2026-10-12 real-corpus triage of the official pack
// (on-chain-scripts plus 18 audited bug-bounty targets). Each test pairs the
// production false-positive shapes with the vulnerable shape the rule must
// keep, and runs the whole shipped pack through scanSourceWithPack.

// findingsFor keeps the "TEMPLATE-ID|Contract.function" entries of the given
// templates.
func findingsFor(got []string, templateIDs ...string) []string {
	var matched []string
	for _, finding := range got {
		for _, id := range templateIDs {
			if strings.HasPrefix(finding, id+"|") {
				matched = append(matched, finding)
				break
			}
		}
	}
	return matched
}

// Every `^` the pack reported on the corpus was a real XOR: OpenZeppelin
// 5.1's branchless `Math.ternary` (`b ^ ((a ^ b) * c)`), a signed sign test
// (Fluid `(a ^ b) < 0`) and a named bit mask (Royco `Cache`). A decimal
// exponent typo stays reported.
func TestIncorrectExpIgnoresRealXor(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
library SafeCastLike { function toUint(bool b) internal pure returns (uint256 u) { assembly { u := iszero(iszero(b)) } } }
contract Bits {
    uint256 private constant _CACHE_SET_MASK = 1 << 255;
    uint256 public x;
    function ternary(bool condition, uint256 a, uint256 b) external returns (uint256) {
        x = b ^ ((a ^ b) * SafeCastLike.toUint(condition));
        return x;
    }
    function sameSign(int256 a, int256 b) external returns (bool) {
        x = 1;
        return (a ^ b) >= 0;
    }
    function clearFlag(uint256 slotValue) external returns (uint256) {
        x = slotValue ^ _CACHE_SET_MASK;
        return x;
    }
    function scale(uint256 amount, uint256 decimals) external returns (uint256) {
        x = amount * (10 ^ decimals);
        return x;
    }
}`)
	assertFindings(t, findingsFor(got, "HIGH-INCORRECT-EXP"), []string{"HIGH-INCORRECT-EXP|Bits.scale"})
}

// 73 of the 77 corpus findings were Foundry `setUp()` fixtures in `*.t.sol`
// spell tests that sit outside any `test/` folder. Foundry's hook is exactly
// `setUp`; a lowercase `setup` (Gnosis Safe) and the usual initializer names
// stay covered.
func TestUnprotectedInitializerIgnoresFoundrySetUp(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract SpellTest {
    address public owner;
    uint256 public chainFork;
    function setUp() public {
        owner = msg.sender;
        chainFork = 1;
    }
}
contract Vault {
    address public owner;
    function initialize(address newOwner) external { owner = newOwner; }
}
contract SafeLike {
    address public owner;
    uint256 public threshold;
    function setup(address newOwner) external { owner = newOwner; threshold = 1; }
}`)
	assertFindings(t, findingsFor(got, "HIGH-UNPROTECTED-INITIALIZER"), []string{
		"HIGH-UNPROTECTED-INITIALIZER|SafeLike.setup",
		"HIGH-UNPROTECTED-INITIALIZER|Vault.initialize",
	})
}

// tx.origin was reported where it authenticates nobody: hashed with the block
// number into a same-block guard (Pareto IdleCDO `_checkSameTx`), and compared
// with a literal sentinel to detect an eth_call simulation (dHEDGE
// AutomationBase). Comparing it with a stored principal stays reported, in a
// require or in an if that reverts.
func TestTxOriginAuthNeedsTxOriginAsAComparedPrincipal(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract Guards {
    address public owner;
    bytes32 private lastCallerBlock;
    uint256 public x;
    function sameTx() external {
        if (keccak256(abi.encodePacked(tx.origin, block.number)) == lastCallerBlock) { revert("same block"); }
        lastCallerBlock = keccak256(abi.encodePacked(tx.origin, block.number));
        x = 1;
    }
    function simulateOnly() external {
        if (tx.origin == address(0) || tx.origin == address(0x1111000000000000000000000000000000001111)) { x = 2; }
    }
    function withdraw() external {
        require(tx.origin == owner, "not owner");
        x = 3;
    }
    function sweep() external {
        if (owner != tx.origin) { revert("not owner"); }
        x = 4;
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-TX-ORIGIN-AUTH"), []string{
		"MEDIUM-TX-ORIGIN-AUTH|Guards.sweep",
		"MEDIUM-TX-ORIGIN-AUTH|Guards.withdraw",
	})
}

// The function-signature regex accepted any two dynamic parameters, so Aera
// ProvisionerV2 was reported for hashing only static values while its
// unrelated `bytes` parameters went elsewhere. Two dynamic values packed
// together stay reported.
func TestEncodePackedCollisionNeedsDynamicPackedArguments(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract Hashes {
    mapping(bytes32 => bool) public used;
    function staticPack(address user, uint256 nonce, bytes calldata data, bytes calldata signature) external returns (bytes32 h) {
        h = keccak256(abi.encodePacked(user, nonce));
        used[h] = data.length > signature.length;
    }
    function dynamicPack(string calldata a, string calldata b) external returns (bytes32 h) {
        h = keccak256(abi.encodePacked(a, b));
        used[h] = true;
    }
}`)
	assertFindings(t, findingsFor(got, "HIGH-ENCODE-PACKED-COLLISION"), []string{"HIGH-ENCODE-PACKED-COLLISION|Hashes.dynamicPack"})
}

// Strict equality on a balance or the block clock is dangerous only when an
// outsider can steer one side. The corpus reported a struct field named
// `balance` (Lista SlisBNBProvider wallets), a same-transaction delta
// (`balanceOf(this) - before == amount`), a block number hashed into a guard
// (Pareto), a struct field named `timestamp` (Ostium orders) and stored
// caches compared with the clock (Alchemix, Aave ReserveLogic through a
// storage pointer). A donation-steerable balance and a caller-chosen deadline
// stay reported.
func TestStrictEqualityNeedsAnOutsiderSteerableOperand(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
interface IERC20 { function balanceOf(address a) external view returns (uint256); }
contract Accounting {
    struct Wallet { uint256 balance; bool active; }
    struct Order { uint256 timestamp; uint256 price; }
    struct Account { uint256 lastMintBlock; uint256 debt; }
    struct Reserve { uint40 lastUpdateTimestamp; uint256 index; }
    mapping(address => Wallet) public wallets;
    mapping(uint256 => Order) public orders;
    mapping(uint256 => Account) public accounts;
    Reserve public reserve;
    IERC20 public token;
    uint256 public total;
    bytes32 private lastCaller;
    function removeWallet(address w) external {
        require(wallets[w].balance == 0, "not empty");
        delete wallets[w];
    }
    function pull(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        total += amount;
        require(token.balanceOf(address(this)) - before == amount, "fee on transfer");
    }
    function oncePerBlock() external {
        require(keccak256(abi.encodePacked(msg.sender, block.number)) != lastCaller, "same block");
        lastCaller = keccak256(abi.encodePacked(msg.sender, block.number));
    }
    function execute(uint256 id, uint256 ts) external {
        Order memory order = orders[id];
        require(order.timestamp == ts, "stale");
        total = order.price;
    }
    function repay(uint256 id) external {
        require(block.number != accounts[id].lastMintBlock, "same block");
        accounts[id].debt = 0;
    }
    function normalizedIndex() external returns (uint256) {
        total = _index(reserve);
        return total;
    }
    function _index(Reserve storage r) internal view returns (uint256) {
        if (r.lastUpdateTimestamp == block.timestamp) { return r.index; }
        return r.index * 2;
    }
    function drained() external returns (bool) {
        total = 0;
        return token.balanceOf(address(this)) == total;
    }
    function exactValue() external returns (bool) {
        total = 1;
        return address(this).balance == 1 ether;
    }
    function claimAt(uint256 deadline) external returns (bool) {
        total = deadline;
        return deadline == block.timestamp;
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-DANGEROUS-STRICT-EQUALITY"), []string{
		"MEDIUM-DANGEROUS-STRICT-EQUALITY|Accounting.claimAt",
		"MEDIUM-DANGEROUS-STRICT-EQUALITY|Accounting.drained",
		"MEDIUM-DANGEROUS-STRICT-EQUALITY|Accounting.exactValue",
	})
}

// Most reentrancy findings on the corpus were a protocol's own fixed token
// moved through a SafeERC20-style wrapper whose calldata carries msg.sender
// (Lista PSM.sell, VeLista), or a `safeTransferFrom` on a receiver whose type
// was lost to an unresolved SafeERC20 import. Neither hands control to code
// the caller chose. ETH sent to the caller, a caller-chosen token moved
// through the same wrapper, and a typed hook-capable token pulled from the
// caller (TestHighLevelSafeTransferFromCanExposeReentrancy) stay reported.
func TestReentrancyIgnoresFixedTokensThroughTransferWrappers(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
interface IToken { function transfer(address to, uint256 v) external returns (bool); }
library FixedTransfers {
    function safeTransfer(IToken token, address to, uint256 value) internal {
        (bool ok, bytes memory ret) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, value));
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "transfer failed");
    }
}
library ChosenTransfers {
    function safeTransfer(IToken token, address to, uint256 value) internal {
        (bool ok, bytes memory ret) = address(token).call(abi.encodeWithSelector(token.transfer.selector, to, value));
        require(ok && (ret.length == 0 || abi.decode(ret, (bool))), "transfer failed");
    }
}
contract Psm {
    using FixedTransfers for IToken;
    using SafeERC20 for IERC20;
    IToken public immutable lisUSD;
    IERC20 public collateral;
    uint256 public fees;
    mapping(address => uint256) public credit;
    constructor(IToken t) { lisUSD = t; }
    function sell(uint256 amount) external {
        lisUSD.safeTransfer(msg.sender, amount);
        fees += amount / 100;
    }
    function deposit(uint256 amount) external {
        collateral.safeTransferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
    function withdrawEth(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        credit[msg.sender] -= amount;
    }
}
contract Router {
    using ChosenTransfers for IToken;
    mapping(address => uint256) public credit;
    function payOut(IToken token, uint256 amount) external {
        token.safeTransfer(msg.sender, amount);
        credit[msg.sender] -= amount;
    }
}`)
	assertFindings(t, findingsFor(got, "HIGH-REENTRANCY-PATTERN"), []string{
		"HIGH-REENTRANCY-PATTERN|ChosenTransfers.safeTransfer",
		"HIGH-REENTRANCY-PATTERN|Psm.withdrawEth",
	})
}

// 16 of the 27 CRITICAL delegatecall findings were OpenZeppelin and Aave
// transparent proxies: `ifAdmin` runs the body only for the admin and sends
// everyone else to the fallback, so a non-admin never reaches the
// delegatecall. The authorization facts accept only an `if` whose other arm
// reverts and read this guard as absent. An "EOA only" branch on
// `msg.sender == tx.origin` authorizes nobody and stays reported, as does an
// unguarded dispatcher.
func TestDelegatecallRecognizesAdminDispatchGuard(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract TransparentProxy {
    address private _admin;
    address private _impl;
    modifier ifAdmin() {
        if (msg.sender == _admin) {
            _;
        } else {
            _fallback();
        }
    }
    function _fallback() internal {
        (bool ok, ) = _impl.delegatecall(msg.data);
        require(ok, "fallback failed");
    }
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable ifAdmin {
        _impl = newImplementation;
        (bool ok, ) = newImplementation.delegatecall(data);
        require(ok, "init failed");
    }
}
contract EoaOnly {
    uint256 public runs;
    modifier onlyEoa() {
        if (msg.sender == tx.origin) {
            _;
        }
    }
    function run(address target, bytes calldata data) external onlyEoa {
        runs += 1;
        (bool ok, ) = target.delegatecall(data);
        require(ok, "run failed");
    }
}
contract Open {
    uint256 public runs;
    function run(address target, bytes calldata data) external {
        runs += 1;
        (bool ok, ) = target.delegatecall(data);
        require(ok, "run failed");
    }
}`)
	assertFindings(t, findingsFor(got, "CRITICAL-DELEGATECALL-USER-INPUT"), []string{
		"CRITICAL-DELEGATECALL-USER-INPUT|EoaOnly.run",
		"CRITICAL-DELEGATECALL-USER-INPUT|Open.run",
	})
}

// LI.FI swap facets and GasZip only make a caller-supplied call after a
// contract+selector allowlist accepts the exact target and `bytes4` selector
// (`if (!LibAllowList.contractSelectorIsAllowed(callTo, bytes4(data[:4])))
// revert`). That is the mitigation the rule recommends. An allowlist on
// something else (the token) leaves target and calldata free and stays
// reported, as does an unchecked dispatcher.
func TestArbitraryLowLevelCallHonorsSelectorAllowlist(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
library AllowList {
    function contractSelectorIsAllowed(mapping(address => mapping(bytes4 => bool)) storage list, address target, bytes4 selector) internal view returns (bool) {
        return list[target][selector];
    }
}
contract Facet {
    mapping(address => mapping(bytes4 => bool)) private allowed;
    mapping(address => bool) public allowedTokens;
    uint256 public calls;
    function swapIfStatement(address callTo, bytes calldata data) external {
        if (!AllowList.contractSelectorIsAllowed(allowed, callTo, bytes4(data[:4]))) { revert("not allowed"); }
        calls += 1;
        (bool ok, ) = callTo.call(data);
        require(ok, "swap failed");
    }
    function swapRequire(address callTo, bytes calldata data) external {
        require(isWhitelisted(callTo, bytes4(data[:4])), "not allowed");
        calls += 1;
        (bool ok, ) = callTo.call(data);
        require(ok, "swap failed");
    }
    function isWhitelisted(address target, bytes4 selector) public view returns (bool) {
        return allowed[target][selector];
    }
    function tokenOnly(address token, address callTo, bytes calldata data) external {
        if (!allowedTokens[token]) { revert("token not allowed"); }
        calls += 1;
        (bool ok, ) = callTo.call(data);
        require(ok, "swap failed");
    }
    function open(address callTo, bytes calldata data) external {
        calls += 1;
        (bool ok, ) = callTo.call(data);
        require(ok, "call failed");
    }
}`)
	assertFindings(t, findingsFor(got, "HIGH-ARBITRARY-LOW-LEVEL-CALL"), []string{
		"HIGH-ARBITRARY-LOW-LEVEL-CALL|Facet.open",
		"HIGH-ARBITRARY-LOW-LEVEL-CALL|Facet.tokenOnly",
	})
}

// Unchecked arithmetic was reported on values bounded by construction: a
// bitmap offset `(balance % 8) * 32` (Fluid ERC721), a constant rescale
// `value * 1e3`, a masked counter step `(packed & X30) + 1` and a rounding
// step `q + (c ? 0 : 1)`. A product or sum with a caller-controlled operand and
// an unguarded subtraction stay reported.
func TestUncheckedArithmeticIgnoresBoundedByConstruction(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract Packed {
    uint256 internal constant X30 = 0x3fffffff;
    mapping(address => uint256) public balanceOf;
    mapping(uint256 => uint256) public slots;
    uint256 public packed;
    uint256 public price;
    function slotOffset(address owner) external {
        uint256 b = balanceOf[owner];
        unchecked { slots[0] = (b % 8) * 32; }
    }
    function rescale() external {
        uint256 v = packed;
        unchecked { packed = v * 1e3; }
    }
    function bump() external {
        unchecked { packed = (packed & X30) + 1; }
    }
    function roundUp(uint256 a, uint256 b) external {
        uint256 q = a / b;
        bool exact = q * b == a;
        unchecked { packed = q + (exact ? 0 : 1); }
    }
    function cost(uint256 amount) external {
        unchecked { packed = amount * price; }
    }
    function credit(uint256 amount) external {
        unchecked { packed = packed + amount; }
    }
    function debit(uint256 amount) external {
        unchecked { packed = packed - amount; }
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-UNCHECKED-ARITHMETIC"), []string{
		"MEDIUM-UNCHECKED-ARITHMETIC|Packed.cost",
		"MEDIUM-UNCHECKED-ARITHMETIC|Packed.credit",
		"MEDIUM-UNCHECKED-ARITHMETIC|Packed.debit",
	})
}

// Fluid (instadapp) computes prices multiply-first unless the value is large
// enough to overflow, and only then divides first:
// `p < 1e50 ? (p * 1e27) / q : (p / q) * 1e27`. Nine of the corpus
// divide-before-multiply sites were these overflow fallbacks. A plain
// divide-first and one under an ordinary-sized bound stay reported.
func TestDivideBeforeMultiplyIgnoresOverflowFallback(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract Prices {
    uint256 public last;
    function ternaryFallback(uint256 p, uint256 q) external {
        last = p < 1e50 ? (p * 1e27) / q : (p / q) * 1e27;
    }
    function ifFallback(uint256 x, uint256 d, uint256 s) external {
        if (x < 1e38) {
            last = (x * s) / d;
        } else {
            last = (x / d) * s;
        }
    }
    function rewardPerToken(uint256 amount, uint256 total) external {
        last = (amount / total) * 1e18;
    }
    function smallBound(uint256 x, uint256 d, uint256 s) external {
        if (x < 1e18) {
            last = (x / d) * s;
        }
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-DIVIDE-BEFORE-MULTIPLY"), []string{
		"MEDIUM-DIVIDE-BEFORE-MULTIPLY|Prices.rewardPerToken",
		"MEDIUM-DIVIDE-BEFORE-MULTIPLY|Prices.smallBound",
	})
}

// The rule matched by name only, so a multi-token ledger's
// `transfer(to, id, amount)` (dHEDGE DytmWithdrawProcessor on IDytmOffice)
// was reported as an unchecked ERC20 transfer. ERC20 `transfer` takes two
// arguments and `transferFrom` three; an unchecked ERC20 call stays reported.
func TestUncheckedErc20TransferMatchesErc20Arity(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
interface IOffice { function transfer(address to, uint256 id, uint256 amount) external returns (bool); }
interface ILedger { function transferFrom(address from, address to, uint256 id, uint256 amount) external returns (bool); }
interface IERC20Like { function transfer(address to, uint256 amount) external returns (bool); }
contract Processor {
    IOffice public office;
    ILedger public ledger;
    IERC20Like public token;
    uint256 public processed;
    function moveShares(address to, uint256 id, uint256 amount) external {
        office.transfer(to, id, amount);
        processed += amount;
    }
    function moveLedger(address from, address to, uint256 id, uint256 amount) external {
        ledger.transferFrom(from, to, id, amount);
        processed += amount;
    }
    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
        processed += amount;
    }
}`)
	assertFindings(t, findingsFor(got, "HIGH-UNCHECKED-ERC20-TRANSFER"), []string{"HIGH-UNCHECKED-ERC20-TRANSFER|Processor.pay"})
}

// ERC-4337 accounts pay the EntryPoint's prefund with an unchecked call
// (`payable(msg.sender).call{value: missingAccountFunds}("")` in
// `_payPrefund`): the EntryPoint verifies the deposit itself, so the result is
// ignored by design (Circle modular wallets, eth-infinitism BaseAccount). An
// unchecked value call elsewhere stays reported.
func TestUncheckedLowLevelCallIgnoresAccountPrefund(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
contract Account {
    uint256 public nonce;
    function validateUserOp(bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256) {
        nonce += uint256(userOpHash) & 1;
        _payPrefund(missingAccountFunds);
        return 0;
    }
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            nonce += success ? 0 : 0;
        }
    }
    function sweep(address payable to) external {
        to.call{value: address(this).balance}("");
        nonce += 1;
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-UNCHECKED-LOWLEVEL-CALL"), []string{"MEDIUM-UNCHECKED-LOWLEVEL-CALL|Account.sweep"})
}

// The guard that bounds an unchecked subtraction is often separated from it by
// a declaration or an event: `require(bal >= amount); uint256 fee = amount /
// 100; emit Fee(fee); unchecked { bal -= amount; }` (LI.FI FeeForwarder,
// StakeWise VaultState, Spark SparkVault). Those statements cannot change the
// operands, so the guard still holds. An intervening write to an operand, an
// external call, or a declaration that shadows an operand still breaks it.
func TestUncheckedArithmeticGuardSurvivesInertStatements(t *testing.T) {
	got := scanSourceWithPack(t, `pragma solidity ^0.8.20;
interface IToken { function transfer(address to, uint256 v) external returns (bool); }
contract Vault {
    event Fee(uint256 fee);
    uint256 public bal;
    uint256 public fees;
    IToken public token;
    function declarationBetween(uint256 amount) external {
        require(bal >= amount, "low");
        uint256 fee = amount / 100;
        uint256 unused;
        emit Fee(fee);
        unchecked { bal = bal - amount; }
        fees += fee + unused;
    }
    function declarationInArm(uint256 amount) external {
        if (amount <= bal) {
            uint256 fee = amount / 100;
            unchecked { bal = bal - amount; }
            fees += fee;
        }
    }
    function writeBetween(uint256 amount) external {
        require(bal >= amount, "low");
        bal = bal / 2;
        unchecked { fees = bal - amount; }
    }
    function callBetween(uint256 amount) external {
        require(bal >= amount, "low");
        token.transfer(msg.sender, amount);
        unchecked { bal = bal - amount; }
    }
}`)
	assertFindings(t, findingsFor(got, "MEDIUM-UNCHECKED-ARITHMETIC"), []string{
		"MEDIUM-UNCHECKED-ARITHMETIC|Vault.callBetween",
		"MEDIUM-UNCHECKED-ARITHMETIC|Vault.writeBetween",
	})
}
