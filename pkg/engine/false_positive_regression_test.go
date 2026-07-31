package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// scanSourceWithPack builds one source string and runs the whole shipped
// official pack over it, returning "TEMPLATE-ID|Contract.function" for each
// finding. Running the full pack (rather than one template) is deliberate: these
// regressions came from a real scan where several detectors fired on the same
// production idiom, and a fix for one must not shift the noise to another.
func scanSourceWithPack(t *testing.T, source string) []string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Subject.sol")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	root := repoRoot(t)
	templates, err := LoadTemplates(filepath.Join(root, "templates/official"))
	if err != nil {
		t.Fatalf("load official pack: %v", err)
	}
	var got []string
	for _, finding := range NewWithOptions(db, Options{}).ExecuteAll(templates) {
		got = append(got, finding.TemplateID+"|"+
			finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)
	return got
}

func assertFindings(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings mismatch\n got:\n  %s\nwant:\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// TestStateIndexedTargetIsNotUserControlled covers the proxy-dispatch idiom that
// produced CRITICAL false positives on CrocSwapDex, Curve, and OpenZeppelin
// UUPS: a call target read out of a governance-controlled state mapping, indexed
// by a caller-supplied key.
//
// The attacker chooses the INDEX, not the ADDRESS. Only governance can populate
// the mapping, so the target is state provenance, not user-controlled — the same
// rule `lvalueStateVarName` already applies for state-write matching, where
// `tmp[stateIndex]` is local rather than a state write.
func TestStateIndexedTargetIsNotUserControlled(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ProxyDispatch {
    mapping(uint16 => address) private proxyPaths_;
    address public authority_;

    function setProxy(uint16 idx, address impl) external {
        require(msg.sender == authority_, "not authority");
        proxyPaths_[idx] = impl;
    }

    // SAFE: the delegatecall target is governance-controlled state.
    function userCmd(uint16 callpath, bytes calldata cmd) external returns (bytes memory) {
        require(proxyPaths_[callpath] != address(0));
        (bool ok, bytes memory out) = proxyPaths_[callpath].delegatecall(cmd);
        require(ok);
        return out;
    }

    // VULNERABLE: the target comes straight from the caller.
    function evilCmd(address target, bytes calldata cmd) external {
        (bool ok, ) = target.delegatecall(cmd);
        require(ok);
    }
}`
	assertFindings(t, scanSourceWithPack(t, source), []string{
		"CRITICAL-DELEGATECALL-USER-INPUT|ProxyDispatch.evilCmd",
	})
}

// TestParameterIndexedBaseStaysTainted is the other half of the rule above: when
// the BASE is caller-controlled, indexing it does not launder the taint. This is
// the documented `from[i]` behavior and must survive the fix.
func TestParameterIndexedBaseStaysTainted(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IToken { function transferFrom(address f, address t, uint256 a) external returns (bool); }
contract BatchPull {
    IToken public token;
    mapping(address => uint256) public bal;

    // VULNERABLE: froms[] is a parameter, so froms[i] is still caller-chosen.
    function batch(address[] calldata froms, uint256 amount) external {
        for (uint256 i = 0; i < froms.length; i++) {
            require(token.transferFrom(froms[i], address(this), amount), "pull failed");
            bal[froms[i]] += amount;
        }
    }
}`
	got := scanSourceWithPack(t, source)
	want := "HIGH-ARBITRARY-TRANSFERFROM|BatchPull.batch"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("indexing a parameter array must keep its taint; got %v, want %q present", got, want)
	}
}

// TestGuardedSubtractionInCallArgument covers 9 of the 21 unchecked-arithmetic
// false positives from the real scan — every one of them inside OpenZeppelin's
// own ERC20/SafeERC20.
//
// `require(a >= b); unchecked { f(..., a - b); }` is the canonical guarded
// subtraction. The bound proof rejected it because the subtraction's expression
// path has a CALL ancestor. That rejection is over-broad: Solidity evaluates all
// arguments before the callee runs, so the ENCLOSING call cannot mutate the
// operands first. Only effectful SIBLING arguments are a real hazard.
//
// The repository fixture that was supposed to cover this used a plain assignment
// (`balances[user] = bal - amount`), which is why the real shape was never caught.
func TestGuardedSubtractionInCallArgument(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract GuardedSub {
    mapping(address => mapping(address => uint256)) private _allowances;

    function _approve(address o, address s, uint256 v) internal {
        _allowances[o][s] = v;
    }

    function wrap(uint256 v) internal pure returns (uint256) { return v; }

    // SAFE: OpenZeppelin ERC20._spendAllowance shape.
    function spendAllowance(address owner, address spender, uint256 amount) external {
        uint256 currentAllowance = _allowances[owner][spender];
        require(currentAllowance >= amount, "insufficient allowance");
        unchecked {
            _approve(owner, spender, currentAllowance - amount);
        }
    }

    // SAFE: SafeERC20.safeDecreaseAllowance shape, nested two calls deep.
    function decreaseAllowance(address spender, uint256 value) external {
        unchecked {
            uint256 oldAllowance = _allowances[msg.sender][spender];
            require(oldAllowance >= value, "below zero");
            _approve(msg.sender, spender, wrap(oldAllowance - value));
        }
    }

    // VULNERABLE: no guard.
    function unguarded(address owner, address spender, uint256 amount) external {
        uint256 currentAllowance = _allowances[owner][spender];
        unchecked {
            _approve(owner, spender, currentAllowance - amount);
        }
    }
}`
	assertFindings(t, scanSourceWithPack(t, source), []string{
		"MEDIUM-UNCHECKED-ARITHMETIC|GuardedSub.unguarded",
	})
}

// TestEffectfulSiblingArgumentStillFails keeps the hazard the call-ancestor rule
// was protecting against: a sibling argument that can mutate the operands, where
// Solidity does not fix evaluation order relative to the subtraction.
func TestEffectfulSiblingArgumentStillFails(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract EffectfulSibling {
    mapping(address => uint256) private bal;
    uint256 private counter;

    function bump() internal returns (uint256) {
        counter += 1;
        return counter;
    }

    function sink(uint256 a, uint256 b) internal {
        bal[msg.sender] = a + b;
    }

    // VULNERABLE: bump() may run before the subtraction and is effectful, so the
    // guard cannot be trusted to still hold.
    function spend(uint256 amount) external {
        uint256 current = bal[msg.sender];
        require(current >= amount, "insufficient");
        unchecked {
            sink(current - amount, bump());
        }
    }
}`
	got := scanSourceWithPack(t, source)
	want := "MEDIUM-UNCHECKED-ARITHMETIC|EffectfulSibling.spend"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("an effectful sibling argument must still defeat the bound proof; got %v", got)
	}
}

// TestBodyProvenMutexGuardIsRecognized covers the reentrancy false positives on
// CrocSwapDex: `reEntrantAgent` and `reEntrantApproved` are textbook mutexes
// (check the lock is free, take it, run, release) but their names contain none of
// nonReentrant/lock/guard/mutex, so a name-only preset missed them. Their sibling
// `reEntrantLock` was recognized purely because it happens to contain "lock" —
// the same guard family, half detected, decided by naming taste.
func TestBodyProvenMutexGuardIsRecognized(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MutexGuards {
    address private lockHolder_;
    mapping(address => uint256) public shares;

    // Textbook mutex, name matches no known guard pattern.
    modifier reEntrantAgent() {
        require(lockHolder_ == address(0));
        lockHolder_ = msg.sender;
        _;
        lockHolder_ = address(0);
    }

    // Boolean-flag variant, also unrecognizable by name.
    modifier singleEntry() {
        require(!entered);
        entered = true;
        _;
        entered = false;
    }

    bool private entered;

    // SAFE: body-proven mutex.
    function withdraw(uint256 amount) external reEntrantAgent {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }

    // SAFE: body-proven boolean flag.
    function withdrawFlagged(uint256 amount) external singleEntry {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }

    // VULNERABLE: no guard.
    function withdrawUnguarded(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }
}`
	got := scanSourceWithPack(t, source)
	for _, finding := range got {
		if strings.HasSuffix(finding, ".withdraw") || strings.HasSuffix(finding, ".withdrawFlagged") {
			t.Errorf("body-proven mutex guard not recognized: %s", finding)
		}
	}
	want := "HIGH-REENTRANCY-PATTERN|MutexGuards.withdrawUnguarded"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the unguarded control must still be reported; got %v", got)
	}
}

// TestModifierWithoutLockBodyIsNotAGuard keeps the body check honest: a modifier
// that merely reads state, or takes a lock without ever checking it, is not a
// reentrancy guard no matter how it is named.
func TestModifierWithoutLockBodyIsNotAGuard(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FakeGuards {
    address private lockHolder_;
    mapping(address => uint256) public shares;

    // Observational only: reads the lock but never enforces it.
    modifier observes() {
        emit Seen(lockHolder_);
        _;
    }

    event Seen(address who);

    // VULNERABLE: the observes modifier proves nothing.
    function withdraw(uint256 amount) external observes {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }
}`
	got := scanSourceWithPack(t, source)
	want := "HIGH-REENTRANCY-PATTERN|FakeGuards.withdraw"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("a modifier that does not enforce a lock must not count as a guard; got %v", got)
	}
}

// TestOneSiteIsReportedOnce covers the largest single source of perceived noise in
// the real scan: 20 of 92 findings (22%) were repeat reports of a dangerous site
// already reported, once per entry function that reaches it. A router with six
// `removeLiquidity*` variants sharing one internal helper produced six findings
// for one line.
//
// The reachability path differs per entry and is genuine information, but the
// defect is one defect. It is reported once, at the site, with the remaining
// entry points available in the finding's context.
func TestOneSiteIsReportedOnce(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IToken { function transferFrom(address f, address t, uint256 a) external returns (bool); }
contract FanOut {
    IToken public token;
    mapping(address => uint256) public bal;

    function _pull(uint256 amount) internal {
        token.transferFrom(msg.sender, address(this), amount);
        bal[msg.sender] += amount;
    }

    function depositA(uint256 a) external { _pull(a); }
    function depositB(uint256 a) external { _pull(a); }
    function depositC(uint256 a) external { _pull(a); }
    function depositD(uint256 a) external { _pull(a); }
}`
	got := scanSourceWithPack(t, source)
	unchecked := 0
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-UNCHECKED-ERC20-TRANSFER|") {
			unchecked++
		}
	}
	if unchecked != 1 {
		t.Errorf("one unchecked transfer reached from 4 entry points produced %d findings, want 1: %v",
			unchecked, got)
	}
}

// TestBodylessDeclarationIsNotAFindingSite covers the last class from the real
// scan: 7 of 71 findings landed on interface stubs in Uniswap's IHooks.sol.
//
// An interface (or abstract) function declaration has no body, no modifiers, and
// no deployed code. It can never prove access control or a reentrancy guard, so
// EVERY detector that negates a safety preset fires on it — and none of those
// reports is actionable, because there is nothing at that location to fix. The
// implementing contract is scanned separately and is where a real finding belongs.
//
// This is enforced in the engine rather than per-template so a future
// `not: {preset: …}` detector cannot reintroduce the class.
func TestBodylessDeclarationIsNotAFindingSite(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IHooks {
    function beforeSwap(address sender, bytes calldata data) external returns (bytes4);
    function afterSwap(address sender, bytes calldata data) external returns (bytes4);
}

abstract contract BaseHook is IHooks {
    address public poolManager;
    // Declared but not implemented here: the override lives in the deriving contract.
    function beforeSwap(address sender, bytes calldata data) external virtual returns (bytes4);
}

contract RealHook is BaseHook {
    uint256 public swaps;

    // VULNERABLE and real: deployed code, externally callable, no caller check.
    function beforeSwap(address, bytes calldata) external override returns (bytes4) {
        swaps += 1;
        return this.beforeSwap.selector;
    }

    // SAFE: gated on the pool manager.
    function afterSwap(address, bytes calldata) external override returns (bytes4) {
        require(msg.sender == poolManager, "not manager");
        swaps += 1;
        return this.afterSwap.selector;
    }
}`
	got := scanSourceWithPack(t, source)
	for _, finding := range got {
		if strings.Contains(finding, "|IHooks.") || strings.Contains(finding, "|BaseHook.") {
			t.Errorf("bodyless declaration reported as a finding site: %s", finding)
		}
	}
	// The real implementation must still be found, so the guard suppresses only
	// non-sites and not the detector itself.
	want := "HIGH-UNISWAP-V4-HOOK-UNPROTECTED|RealHook.beforeSwap"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the implemented hook must still be reported; got %v", got)
	}
}

// TestInterproceduralLocationFileMatchesLine covers the defect that made real
// findings impossible to triage: for a match found in an inlined callee, the
// finding reported the ENTRY function's file together with the MATCHED NODE's
// line. When the callee lives in another file the pair is incoherent, and it
// routinely pointed past the end of the named file — OpenZeppelin
// UUPSUpgradeable.sol has 112 lines and the finding said line 185, because the
// delegatecall is really in AddressUpgradeable.sol.
//
// A location whose line does not exist in its own file reads as a false positive
// even when the underlying match is sound, because nothing is there to inspect.
// Location.File must always name the file that contains Location.Line;
// buildContractLocation already did this, and the function-scope path did not.
func TestInterproceduralLocationFileMatchesLine(t *testing.T) {
	dir := t.TempDir()
	helper := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library CallHelper {
    // Padding so this file's line numbers cannot coincide with the entry file's.
    // 1
    // 2
    // 3
    // 4
    // 5
    // 6
    // 7
    // 8
    // 9
    // 10
    function raw(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory out) = target.delegatecall(data);
        require(ok, "call failed");
        return out;
    }
}`
	entry := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "./Helper.sol";
contract Entry {
    function run(address target, bytes calldata data) external {
        CallHelper.raw(target, data);
    }
}`
	if err := os.WriteFile(filepath.Join(dir, "Helper.sol"), []byte(helper), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Entry.sol"), []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}

	rdr := reader.New()
	if _, err := rdr.Read(dir); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := rdr.ResolveImports(dir); err != nil {
		t.Fatalf("resolve imports: %v", err)
	}
	sources := rdr.GetAllSources()
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/critical/delegatecall-user-input.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("expected the interprocedural delegatecall to be found")
	}
	for _, finding := range findings {
		content, err := os.ReadFile(finding.Location.File)
		if err != nil {
			t.Fatalf("finding names an unreadable file %q: %v", finding.Location.File, err)
		}
		lines := strings.Count(string(content), "\n") + 1
		if finding.Location.Line > lines {
			t.Errorf("Location.File = %s has %d lines but Location.Line = %d;\n"+
				"the file and line must describe the same place",
				filepath.Base(finding.Location.File), lines, finding.Location.Line)
		}
	}
}

// TestReceiverRuleMatchesOnlyTheDirectReceiver covers the single largest remaining
// false-positive source: `has: { receiver: true, tainted: user_controlled }` searches
// ALL descendants of the call, so the receiver of a NESTED member call inside the
// encoded arguments satisfied it.
//
// CrocSwapDex's `proxyPaths_[CrocSlots.MICRO_PROXY_IDX].delegatecall(
// abi.encodeWithSignature("sweepSwap(…)", curve.pullPriceTick(), …))` was reported
// CRITICAL because `curve` — the receiver of the nested `pullPriceTick()` call — is
// caller-derived, even though the delegatecall's own target is a constant-index read
// of governance-controlled storage.
//
// `receiver:` with a nested rule evaluates against the call's DIRECT tagged receiver
// child only, which is the guarantee `receiver_name` already provides for names.
func TestReceiverRuleMatchesOnlyTheDirectReceiver(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Slots { uint16 internal constant MICRO_PROXY_IDX = 131; }

library CurveMath {
    struct Cache { uint256 v; }
    function pullPriceTick(Cache memory c) internal pure returns (int24) { return int24(uint24(c.v)); }
}

contract StorageLayout {
    address[65536] internal proxyPaths_;
}

abstract contract ProxyCaller is StorageLayout {
    using CurveMath for CurveMath.Cache;

    // SAFE: constant-index state read as the target; the only caller-controlled
    // receiver in the subtree belongs to the nested pullPriceTick() call.
    function callSwap(CurveMath.Cache memory curve, uint256 swap) internal {
        (bool success,) = proxyPaths_[Slots.MICRO_PROXY_IDX].delegatecall(
            abi.encodeWithSignature("sweepSwap(int24,uint256)", curve.pullPriceTick(), swap));
        require(success);
    }
}

contract LongPath is ProxyCaller {
    function userCmd(uint256 swap) external {
        CurveMath.Cache memory c = CurveMath.Cache(swap);
        callSwap(c, swap);
    }
}

contract Evil {
    // VULNERABLE: the delegatecall's own receiver is caller-supplied.
    function userCmd(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}`
	got := scanSourceWithPack(t, source)
	for _, finding := range got {
		if strings.Contains(finding, "LongPath.") {
			t.Errorf("nested call receiver satisfied a direct-receiver check: %s", finding)
		}
	}
	want := "CRITICAL-DELEGATECALL-USER-INPUT|Evil.userCmd"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the genuinely arbitrary delegatecall must still be reported; got %v", got)
	}
}

// TestFixedSelectorCalldataIsNotArbitrary covers the other half of the
// arbitrary-call FPs: calldata the CONTRACT builds with a pinned selector.
//
// `token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value))`
// is Uniswap's TransferHelper — the caller chooses the arguments but not the
// function, so it is not a confused deputy. Reporting it as an arbitrary low-level
// call flagged `TransferHelper.safeTransferFrom` in four separate projects.
// An attacker-CHOSEN selector must still be reported.
func TestFixedSelectorCalldataIsNotArbitrary(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function transferFrom(address, address, uint256) external returns (bool); }
contract Helper {
    // SAFE: pinned selector, caller supplies only the arguments.
    function safeTransferFrom(address token, address from, address to, uint256 value) external {
        (bool ok, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "STF");
    }

    // SAFE: pinned signature literal.
    function pinnedSignature(address target, uint256 v) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("sweep(uint256)", v));
        require(ok);
    }

    // VULNERABLE: the caller supplies the whole calldata blob.
    function arbitraryBlob(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok);
    }

    // VULNERABLE: the caller chooses the selector.
    function arbitrarySelector(address target, bytes4 sel, bytes calldata args) external {
        (bool ok, ) = target.call(abi.encodePacked(sel, args));
        require(ok);
    }
}`
	got := scanSourceWithPack(t, source)
	var arbitrary []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-ARBITRARY-LOW-LEVEL-CALL|") {
			arbitrary = append(arbitrary, finding)
		}
	}
	want := []string{
		"HIGH-ARBITRARY-LOW-LEVEL-CALL|Helper.arbitraryBlob",
		"HIGH-ARBITRARY-LOW-LEVEL-CALL|Helper.arbitrarySelector",
	}
	if strings.Join(arbitrary, "\n") != strings.Join(want, "\n") {
		t.Errorf("arbitrary-call findings mismatch\n got: %v\nwant: %v", arbitrary, want)
	}
}

// TestEcdsaMalleabilityNeedsSignatureKeyedReplayGuard covers the ECDSA false
// positives. The bug this detector targets is a replay guard keyed by the RAW
// SIGNATURE BYTES — `used[signature] = true` — which a malleated signature slips
// past. A guard keyed by anything else is the correct pattern.
//
// The old rule accepted any state write with a caller-derived index after a
// `recover`, so `battles[battleId] = …` matched: an id-keyed claim flag, which is
// exactly how replay SHOULD be prevented, and irrelevant to malleability.
func TestEcdsaMalleabilityNeedsSignatureKeyedReplayGuard(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library ECDSA { function recover(bytes32 h, bytes memory s) internal pure returns (address) { return address(uint160(uint256(h) ^ s.length)); } }
contract Claims {
    address public judge;
    mapping(uint256 => bool) public claimed;
    mapping(bytes => bool) public usedSignature;

    // SAFE: the replay guard is keyed by the claim id, not the signature.
    function claimById(uint256 battleId, bytes memory signature) external {
        address signer = ECDSA.recover(keccak256(abi.encode(battleId)), signature);
        require(signer == judge, "forged");
        claimed[battleId] = true;
    }

    // VULNERABLE: the replay guard is keyed by the raw signature bytes, so a
    // malleated (r, s') pair is a different key for the same authorization.
    function claimBySignature(uint256 battleId, bytes memory signature) external {
        address signer = ECDSA.recover(keccak256(abi.encode(battleId)), signature);
        require(signer == judge, "forged");
        usedSignature[signature] = true;
    }
}`
	got := scanSourceWithPack(t, source)
	var ecdsa []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-ECDSA-RECOVER-MALLEABLE|") {
			ecdsa = append(ecdsa, finding)
		}
	}
	want := []string{"HIGH-ECDSA-RECOVER-MALLEABLE|Claims.claimBySignature"}
	if strings.Join(ecdsa, "\n") != strings.Join(want, "\n") {
		t.Errorf("ECDSA findings mismatch\n got: %v\nwant: %v", ecdsa, want)
	}
}

// TestReadOnlyReentrancyDoesNotMatchGenericGetRate covers the false positives from
// my own promoted Balancer detector. `getRate()` is a ubiquitous name for any rate
// provider — Shell/Curve's `Assimilators.getRate` triggered it three times — so the
// bare name cannot identify a Balancer Vault read. Only the Vault-specific
// `getPoolTokens` shape is precise enough to ship; the `getRate` variant stays in
// the benchmark lane.
func TestReadOnlyReentrancyDoesNotMatchGenericGetRate(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IAssimilator { function getRate() external view returns (uint256); }
interface IBalancerVault {
    function getPoolTokens(bytes32 poolId) external view returns (address[] memory, uint256[] memory, uint256);
}
contract Pricing {
    IBalancerVault public vault;

    // NOT a Balancer read: a generic rate provider with an unrelated interface.
    function assimilatorRate(address assim) external view returns (uint256) {
        return IAssimilator(assim).getRate();
    }

    // VULNERABLE: unguarded Balancer Vault composition read.
    function poolValue(bytes32 poolId) external view returns (uint256 total) {
        (, uint256[] memory balances, ) = vault.getPoolTokens(poolId);
        for (uint256 i = 0; i < balances.length; i++) { total += balances[i]; }
    }
}`
	got := scanSourceWithPack(t, source)
	var readonly []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-READONLY-REENTRANCY-BALANCER|") {
			readonly = append(readonly, finding)
		}
	}
	want := []string{"HIGH-READONLY-REENTRANCY-BALANCER|Pricing.poolValue"}
	if strings.Join(readonly, "\n") != strings.Join(want, "\n") {
		t.Errorf("read-only reentrancy findings mismatch\n got: %v\nwant: %v", readonly, want)
	}
}

// TestCustomRoleSystemWithAssemblyStorageIsRecognized covers the last
// false-positive class from the real scan: Axelar's `RolesBase`, where the role
// bitmap is read with `assembly { accountRoles := sload(key) }` on a key derived
// from the account. There is no mapping access to recognize and no authorizing body
// to descend into, so a role-gated `burn` was reported as a public burn.
//
// Recognition requires three independent signals — an authority-named call, a
// forwarded caller identity, and an enforcing position — because any one alone
// over-accepts. The negative controls below pin that.
func TestCustomRoleSystemWithAssemblyStorageIsRecognized(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract RolesBase {
    error MissingRole(address account, uint8 role);

    function _rolesKey(address account) internal view virtual returns (bytes32) {
        return keccak256(abi.encode("roles", account));
    }

    function _getRoles(address account) internal view returns (uint256 accountRoles) {
        bytes32 key = _rolesKey(account);
        assembly { accountRoles := sload(key) }
    }

    function _hasRole(uint256 accountRoles, uint8 role) internal pure returns (bool) {
        return accountRoles & (1 << role) != 0;
    }

    modifier onlyRole(uint8 role) {
        if (!_hasRole(_getRoles(msg.sender), role)) revert MissingRole(msg.sender, role);
        _;
    }
}

contract Token is RolesBase {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }

    // SAFE: gated by the custom role system.
    function burn(address account, uint256 amount) external onlyRole(uint8(1)) {
        _burn(account, amount);
    }
}

contract Unguarded {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }

    // VULNERABLE: no gate at all.
    function burn(address account, uint256 amount) external {
        _burn(account, amount);
    }
}`
	got := scanSourceWithPack(t, source)
	for _, finding := range got {
		if strings.Contains(finding, "|Token.burn") {
			t.Errorf("custom role system not recognized as access control: %s", finding)
		}
	}
	want := "HIGH-ERC20-PUBLIC-BURN|Unguarded.burn"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("the unguarded burn must still be reported; got %v", got)
	}
}

// TestCallerIndexedValueLookupIsNotAuthorization is the negative control for the
// rule above: a caller-indexed read of a VALUE (balance, stake) is enforcing and
// forwards a caller identity, but proves nothing about who may call — anyone can
// acquire a balance. Only the authority vocabulary separates the two.
func TestCallerIndexedValueLookupIsNotAuthorization(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function getBalance(address account) internal view returns (uint256) {
        return balanceOf[account];
    }

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }

    // VULNERABLE: a balance check is not an authorization gate.
    function burn(address account, uint256 amount) external {
        require(getBalance(msg.sender) > 0, "no balance");
        _burn(account, amount);
    }
}`
	got := scanSourceWithPack(t, source)
	want := "HIGH-ERC20-PUBLIC-BURN|Vault.burn"
	found := false
	for _, finding := range got {
		if finding == want {
			found = true
		}
	}
	if !found {
		t.Errorf("a caller-indexed balance check must not count as authorization; got %v", got)
	}
}

// TestUncheckedArithmeticTargetsExploitableOperations covers the largest remaining
// noise class: 12 of 52 findings on a real corpus, almost all of them deliberate,
// commented, bounded `unchecked` blocks.
//
// Two defects, both visible here. The finding anchored on the `unchecked {` STATEMENT
// rather than the arithmetic, so a gas-optimized whole-function `unchecked` wrapper
// produced one unactionable finding for an entire body ("which operation?"). And every
// operator matched, including counter and index arithmetic against a literal —
// `nonce + 1`, `numElements - 1` — whose overflow requires the value to already sit at
// the type maximum.
//
// What remains exploitable inside `unchecked`: underflow on subtraction, and overflow
// on multiplication or on addition of two non-literal operands. Division cannot
// overflow at all.
func TestUncheckedArithmeticTargetsExploitableOperations(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Unchecked {
    mapping(uint256 => uint256) public nonceLookup;
    uint8 public numElements;
    uint96 public ticketPrice;
    mapping(address => uint256) public bal;

    // SAFE: nonce increment by a literal.
    function bumpNonce(uint256 key) external {
        unchecked { nonceLookup[key] = nonceLookup[key] + 1; }
    }

    // SAFE: index decrement by a literal, guarded above.
    function popElement() external {
        require(numElements > 0, "empty");
        unchecked { numElements = uint8(numElements - 1); }
    }

    // SAFE: division cannot overflow.
    function share(uint256 total, uint256 parts) external {
        require(parts > 0, "zero");
        unchecked { bal[msg.sender] = total / parts; }
    }

    // VULNERABLE: multiplication in a small type.
    function buy(uint96 tickets) external {
        unchecked { bal[msg.sender] += ticketPrice * tickets; }
    }

    // VULNERABLE: addition of two non-literal operands.
    function extend(uint32 duration, uint32 base) external {
        unchecked { numElements = uint8(duration + base); }
    }

    // VULNERABLE: unguarded subtraction can underflow.
    function withdraw(uint256 amount) external {
        unchecked { bal[msg.sender] = bal[msg.sender] - amount; }
    }
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "Unchecked.sol")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t),
		"templates/official/medium/unchecked-arithmetic.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	var got []string
	for _, finding := range New(db).Execute(tmpl) {
		got = append(got, finding.Location.Function)
		// Every finding must point at the arithmetic, so an auditor can see which
		// operation is at risk rather than the whole block.
		if finding.PrimaryAST == nil || finding.PrimaryAST.Kind != types.KindExprBinaryOp {
			t.Errorf("%s: primary AST = %+v, want the binary operation",
				finding.Location.Function, finding.PrimaryAST)
		}
	}
	sort.Strings(got)
	want := []string{"buy", "extend", "withdraw"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

// TestFindingsAnchorOnTheDangerousStatementByDefault pins that a finding names the
// place the bug IS, not the entry point that can reach it.
//
// With verifier attribution (the old default) `Location.File`/`Line` came from the
// matched node while `Location.Contract`/`Function` came from the entry function, so
// an interprocedural finding read `LongPath.userCmd` while pointing at
// `ProxyCaller.sol:163` — a line inside a different contract entirely. 8 of 52
// findings on a real project disagreed with themselves that way, and an editor
// jumping to the location landed somewhere the named function does not exist.
//
// Matched-node attribution makes every Location field describe one place. The entry
// point is not lost: it moves to `EntryPoint` (the auditor-actionable "fix here"
// hop) and to `Reachability`.
func TestFindingsAnchorOnTheDangerousStatementByDefault(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library TransferHelper {
    // The dangerous statement lives here, in a shared library.
    function safeEtherSend(address to, uint256 value) internal {
        (bool ok, ) = to.call{value: value}("");
        require(ok, "send failed");
    }
}

contract Vault {
    mapping(address => uint256) public shares;

    // The externally-callable entry point that reaches it.
    function withdraw(uint256 amount) external {
        TransferHelper.safeEtherSend(msg.sender, amount);
        shares[msg.sender] -= amount;
    }
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "Vault.sol")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := reader.New().Read(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t),
		"templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("expected the interprocedural CEI violation to be found")
	}
	for _, finding := range findings {
		// The dangerous statement is in TransferHelper, so that is what the
		// location must name — all fields agreeing on one place.
		if finding.Location.Contract != "TransferHelper" {
			t.Errorf("Location.Contract = %q, want TransferHelper (where the statement is)",
				finding.Location.Contract)
		}
		if finding.Location.Function != "safeEtherSend" {
			t.Errorf("Location.Function = %q, want safeEtherSend", finding.Location.Function)
		}
		// And the entry point must still be reachable from the finding.
		if finding.EntryPoint == nil || finding.EntryPoint.Function != "withdraw" {
			t.Errorf("EntryPoint = %+v, want the Vault.withdraw entry hop", finding.EntryPoint)
		}
	}
}

// TestVerifierAttributionRemainsAvailable keeps the old shape reachable for any
// consumer that indexes findings by entry point.
func TestVerifierAttributionRemainsAvailable(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
library TransferHelper {
    function safeEtherSend(address to, uint256 value) internal {
        (bool ok, ) = to.call{value: value}("");
        require(ok, "send failed");
    }
}
contract Vault {
    mapping(address => uint256) public shares;
    function withdraw(uint256 amount) external {
        TransferHelper.safeEtherSend(msg.sender, amount);
        shares[msg.sender] -= amount;
    }
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "Vault.sol")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, _ := reader.New().Read(path)
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t),
		"templates/official/high/reentrancy-pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	engine := New(db)
	engine.SetLocationSource(LocationSourceVerifier)
	findings := engine.Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	if findings[0].Location.Function != "withdraw" {
		t.Errorf("verifier mode Location.Function = %q, want the entry function withdraw",
			findings[0].Location.Function)
	}
}

// TestOneTimeInitGuardIsRecognized covers the unprotected-initializer false
// positives. The detector only knew two spellings of "already initialized": the
// OpenZeppelin `initializer` modifier, and a guard literally naming
// `_initializersDisabled`. Anything else was reported.
//
// The general shape is the same mutex the reentrancy work already proves: an
// enforcing check reads a state flag, and the function sets that flag. Both real
// cases below use it — Euler's `if (initialized) revert; initialized = true;`
// directly, and Axelar's `if (_isInitialized()) revert; _initialize();` through
// helpers, which requires following internal calls on both sides.
func TestOneTimeInitGuardIsRecognized(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DirectFlag {
    bool public initialized;
    address public owner;
    error AlreadyInitialized();

    // SAFE: enforcing check on a flag this function then sets.
    function initialize(address proxyCreator) public {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
        owner = proxyCreator;
    }
}

contract HelperFlag {
    bool private _initialized;
    string public name;
    error AlreadyInitialized();

    function _isInitialized() internal view returns (bool) {
        return _initialized;
    }

    function _initialize() internal {
        _initialized = true;
    }

    // SAFE: the read and the write both live in internal helpers.
    function init(string calldata tokenName) external {
        if (_isInitialized()) revert AlreadyInitialized();
        _initialize();
        name = tokenName;
    }
}

// Axelar InterchainToken verbatim: the flag is an explicit storage slot, so both
// halves of the mutex are inline assembly — sload under the check, sstore for the
// write. Matching only stmt.assign saw the read and missed the write.
contract AsmSlotFlag {
    bytes32 internal constant INITIALIZED_SLOT = 0xc778385ecb3e8cecb82223fa1f343ec6865b2d64c65b0c15c7e8aef225d9e214;
    string public name;
    error AlreadyInitialized();

    function _isInitialized() internal view returns (bool initialized) {
        assembly {
            initialized := sload(INITIALIZED_SLOT)
        }
    }

    function _initialize() internal {
        assembly {
            sstore(INITIALIZED_SLOT, true)
        }
    }

    // SAFE: one-time-init proven through an assembly storage slot.
    function init(string calldata tokenName) external {
        if (_isInitialized()) revert AlreadyInitialized();
        _initialize();
        name = tokenName;
    }
}

contract AsmSlotMismatch {
    bytes32 internal constant INITIALIZED_SLOT = 0xc778385ecb3e8cecb82223fa1f343ec6865b2d64c65b0c15c7e8aef225d9e214;
    bytes32 internal constant OTHER_SLOT = 0xa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90;
    address public owner;
    error AlreadyInitialized();

    function _isInitialized() internal view returns (bool initialized) {
        assembly {
            initialized := sload(INITIALIZED_SLOT)
        }
    }

    // VULNERABLE: the write lands on a DIFFERENT slot, so the flag it tests is
    // never set and the check can be passed forever.
    function init(address newOwner) external {
        if (_isInitialized()) revert AlreadyInitialized();
        assembly {
            sstore(OTHER_SLOT, true)
        }
        owner = newOwner;
    }
}

contract Unguarded {
    address public owner;

    // VULNERABLE: anyone can call this repeatedly and take ownership.
    function initialize(address newOwner) external {
        owner = newOwner;
    }
}

contract ObservationalOnly {
    bool public initialized;
    address public owner;

    // VULNERABLE: reads the flag but never enforces it, and never sets it.
    function initialize(address newOwner) external {
        emit Seen(initialized);
        owner = newOwner;
    }

    event Seen(bool flag);
}`
	got := scanSourceWithPack(t, source)
	var init []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-UNPROTECTED-INITIALIZER|") {
			init = append(init, finding)
		}
	}
	want := []string{
		"HIGH-UNPROTECTED-INITIALIZER|AsmSlotMismatch.init",
		"HIGH-UNPROTECTED-INITIALIZER|ObservationalOnly.initialize",
		"HIGH-UNPROTECTED-INITIALIZER|Unguarded.initialize",
	}
	if strings.Join(init, "\n") != strings.Join(want, "\n") {
		t.Errorf("initializer findings mismatch\n got: %v\nwant: %v", init, want)
	}
}

// TestBooleanConstantOnlyFlagsConstantFoldingShapes narrows boolean-constant misuse
// to the forms that are actually a logic error.
//
// `a && false` and `if (true)` make the expression constant, so a branch is dead —
// that is a bug. `x == false` is just a verbose `!x`, which is a style preference, and
// it is how CrocSwap writes its mutex checks (`require(msgValSpent_ == false, "DS")`).
// Flagging it at MEDIUM contradicts the pack's own curation policy, which excludes
// style and informational rules because they drown out real findings.
func TestBooleanConstantOnlyFlagsConstantFoldingShapes(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Bools {
    bool private msgValSpent_;
    bool private flag;
    uint256 public v;

    // SAFE: a verbose !x, and the idiomatic mutex check.
    function verboseNot() external {
        require(msgValSpent_ == false, "DS");
        msgValSpent_ = true;
    }

    // SAFE: verbose x.
    function verboseIs() external view returns (bool) {
        return flag == true;
    }

    // VULNERABLE: the conjunction is always false, so the guard never fires.
    function deadConjunction(bool ok) external {
        if (ok && false) { v = 1; }
    }

    // VULNERABLE: the disjunction is always true, so the guard is a no-op.
    function deadDisjunction(bool ok) external {
        require(ok || true, "never reverts");
        v = 2;
    }

    // VULNERABLE: dead branch.
    function deadCondition() external {
        if (true) { v = 3; }
    }
}`
	got := scanSourceWithPack(t, source)
	var bools []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "MEDIUM-BOOLEAN-CST|") {
			bools = append(bools, finding)
		}
	}
	want := []string{
		"MEDIUM-BOOLEAN-CST|Bools.deadCondition",
		"MEDIUM-BOOLEAN-CST|Bools.deadConjunction",
		"MEDIUM-BOOLEAN-CST|Bools.deadDisjunction",
	}
	if strings.Join(bools, "\n") != strings.Join(want, "\n") {
		t.Errorf("boolean-constant findings mismatch\n got: %v\nwant: %v", bools, want)
	}
}

// TestWeakPrngIgnoresPowerOfTwoTruncation separates randomness from bit-packing.
//
// A weak PRNG takes a modulo by a participant count or similar bound, so the result
// selects a winner. `uint32(block.timestamp % 2**32)` is Uniswap V2's `_update`
// truncating a timestamp to fit a packed slot — the value is not used as a random
// draw, and a modulo by a power of two is truncation by construction.
func TestWeakPrngIgnoresPowerOfTwoTruncation(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Prng {
    uint32 public blockTimestampLast;
    address[] public players;
    address public winner;

    // SAFE: truncation for slot packing, the Uniswap V2 idiom.
    function update() external {
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        blockTimestampLast = blockTimestamp;
    }

    // VULNERABLE: a winner drawn from block state.
    function draw() external {
        winner = players[block.timestamp % players.length];
    }
}`
	got := scanSourceWithPack(t, source)
	var prng []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-WEAK-PRNG|") {
			prng = append(prng, finding)
		}
	}
	want := []string{"HIGH-WEAK-PRNG|Prng.draw"}
	if strings.Join(prng, "\n") != strings.Join(want, "\n") {
		t.Errorf("weak-PRNG findings mismatch\n got: %v\nwant: %v", prng, want)
	}
}

// TestStrictEqualityAllowsSameBlockCacheCheck separates a manipulable strict
// comparison from the standard same-block short-circuit.
//
// `if (reserve.lastUpdateTimestamp == block.timestamp) return cachedIndex;` is Aave's
// "already updated this block" cache check, and all three real occurrences carried an
// explicit `// slither-disable-next-line incorrect-equality`. Comparing a STORED
// timestamp to the current one detects sameness; it does not let anyone influence the
// outcome, because the stored value is written by the contract itself.
//
// The manipulable shapes stay: a balance can be forced to an exact value by a
// transfer, and a caller-supplied deadline compared strictly to `block.timestamp`
// hands the miner a one-second lever.
func TestStrictEqualityAllowsSameBlockCacheCheck(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 { function balanceOf(address a) external view returns (uint256); }
contract Pool {
    struct Reserve { uint256 lastUpdateTimestamp; uint256 liquidityIndex; }
    Reserve public reserve;
    IERC20 public token;
    uint256 public total;

    // SAFE: same-block cache short-circuit against a contract-written timestamp.
    function getNormalizedIncome() external view returns (uint256) {
        uint256 timestamp = reserve.lastUpdateTimestamp;
        if (timestamp == block.timestamp) {
            return reserve.liquidityIndex;
        }
        return reserve.liquidityIndex * 2;
    }

    // VULNERABLE: a forced transfer can make this exactly equal.
    function checkBalance() external view returns (bool) {
        return token.balanceOf(address(this)) == total;
    }

    // VULNERABLE: caller-supplied deadline compared strictly to the block clock.
    function claimAt(uint256 deadline) external view returns (bool) {
        return deadline == block.timestamp;
    }
}`
	got := scanSourceWithPack(t, source)
	var eq []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "MEDIUM-DANGEROUS-STRICT-EQUALITY|") {
			eq = append(eq, finding)
		}
	}
	want := []string{
		"MEDIUM-DANGEROUS-STRICT-EQUALITY|Pool.checkBalance",
		"MEDIUM-DANGEROUS-STRICT-EQUALITY|Pool.claimAt",
	}
	if strings.Join(eq, "\n") != strings.Join(want, "\n") {
		t.Errorf("strict-equality findings mismatch\n got: %v\nwant: %v", eq, want)
	}
}

// TestDelegatecallIsNotReentrancy covers the delegatecall false positives the
// real-corpus scan produced: 3 of 7 HIGH-REENTRANCY-PATTERN findings were
// delegatecall-only sites (CrocSwap `ProxyCaller.callSwap`/`callCrossFlag` into
// an admin-set sidecar, Eesee `MulticallPayable.multicall` into
// `address(this)`).
//
// Delegatecall runs the callee's code in THIS contract's context — same
// storage, same guard slot — so re-entry through it is the contract calling
// its own code, not attacker-injected reentry. An attacker-influenced
// delegatecall target is arbitrary code execution and belongs to
// CRITICAL-DELEGATECALL-USER-INPUT, not to the CEI detector.
func TestDelegatecallIsNotReentrancy(t *testing.T) {
	source := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Sidecars {
    mapping(uint256 => address) internal proxyPaths_;
    mapping(address => uint256) public shares;
    uint256 public total;

    // SAFE: delegatecall into a governance-set sidecar, then a state write.
    // Not reentrancy — the sidecar executes in this contract's own context.
    function callSwap(bytes calldata payload) external {
        (bool ok, bytes memory out) = proxyPaths_[1].delegatecall(payload);
        require(ok);
        total = out.length;
    }

    // SAFE: self-delegatecall multicall, then a state write.
    function multicall(bytes[] calldata data) external {
        for (uint256 i; i < data.length; ++i) {
            (bool ok, ) = address(this).delegatecall(data[i]);
            require(ok);
        }
        total = data.length;
    }

    // VULNERABLE control: a real external call before the state write.
    function withdraw(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        shares[msg.sender] -= amount;
    }
}`
	got := scanSourceWithPack(t, source)
	var reentrancy []string
	for _, finding := range got {
		if strings.HasPrefix(finding, "HIGH-REENTRANCY-PATTERN|") {
			reentrancy = append(reentrancy, finding)
		}
	}
	want := []string{"HIGH-REENTRANCY-PATTERN|Sidecars.withdraw"}
	if strings.Join(reentrancy, "\n") != strings.Join(want, "\n") {
		t.Errorf("reentrancy findings mismatch\n got: %v\nwant: %v", reentrancy, want)
	}
}
