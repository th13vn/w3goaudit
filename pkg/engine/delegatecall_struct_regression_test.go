package engine

import (
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

func TestOfficialDelegatecallFindsUserControlledStructFieldForwardedThroughHelper(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/delegatecall-struct-forward.sol"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	b := builder.New()
	if _, err := b.Build(sources); err != nil {
		t.Fatalf("build database: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/critical/delegatecall-user-input.yaml"))
	if err != nil {
		t.Fatalf("load official template: %v", err)
	}
	var vulnerable, safe bool
	for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
		switch {
		case finding.Location.Contract == "VulnerableDelegatecallStruct" && finding.EntryPoint != nil && finding.EntryPoint.Function == "exec":
			if finding.Location.Function != "_run" {
				t.Fatalf("expected dangerous statement in _run, got %q", finding.Location.Function)
			}
			vulnerable = true
		case finding.Location.Contract == "SafeDelegatecallStruct":
			safe = true
		}
	}
	if !vulnerable {
		t.Fatal("official delegatecall detector missed VulnerableDelegatecallStruct.exec")
	}
	if safe {
		t.Fatal("official delegatecall detector reported SafeDelegatecallStruct")
	}
}

// The OpenZeppelin idiom `address(target).functionDelegateCall(data)` reaches
// this detector only through three layers: solast-go v0.1.12 parsing a
// statement that starts with an elementary conversion, using-for resolution on
// a conversion receiver, and taint through the library receiver binding. Before
// them, an unguarded entry written this way produced no finding at all. The
// same call behind an OpenZeppelin-shaped onlyRole, as in the Rarible DAO
// UpgradeExecutor, must stay silent, which needs the authorization facts to
// prove `_roles[role].members[_msgSender()]` through hasRole.
func TestOfficialDelegatecallFindsAddressLibraryIdiomOnConversionReceiver(t *testing.T) {
	b := buildDBFromSource(t, `pragma solidity ^0.8.20;
library Address {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
abstract contract Context {
    function _msgSender() internal view virtual returns (address) { return msg.sender; }
}
abstract contract AccessControl is Context {
    struct RoleData { mapping(address => bool) members; bytes32 adminRole; }
    mapping(bytes32 => RoleData) private _roles;
    modifier onlyRole(bytes32 role) { _checkRole(role); _; }
    function hasRole(bytes32 role, address account) public view virtual returns (bool) {
        return _roles[role].members[account];
    }
    function _checkRole(bytes32 role) internal view virtual { _checkRole(role, _msgSender()); }
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) revert("AccessControl: missing role");
    }
}
contract OpenExecutor {
    using Address for address;
    function execute(address upgrade, bytes memory data) external {
        address(upgrade).functionDelegateCall(data);
    }
}
contract RoleExecutor is AccessControl {
    using Address for address;
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    function execute(address upgrade, bytes memory data) external onlyRole(EXECUTOR_ROLE) {
        address(upgrade).functionDelegateCall(data);
    }
}`)
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/critical/delegatecall-user-input.yaml"))
	if err != nil {
		t.Fatalf("load official template: %v", err)
	}
	var open, guarded bool
	for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
		if finding.EntryPoint == nil {
			continue
		}
		switch finding.EntryPoint.Contract {
		case "OpenExecutor":
			open = true
		case "RoleExecutor":
			guarded = true
		}
	}
	if !open {
		t.Fatal("official delegatecall detector missed address(upgrade).functionDelegateCall in an unguarded entry")
	}
	if guarded {
		t.Fatal("official delegatecall detector reported the onlyRole(EXECUTOR_ROLE) executor")
	}
}

// A `using L for T` extension call passes its receiver as the library's first
// parameter. `token.safeTransferFrom(msg.sender, address(this), amount)` must
// bind the state-held token, not msg.sender, to SafeERC20's `token`; binding
// the written arguments from parameter 0 made the low-level call inside the
// library look caller-targeted and raised HIGH-ARBITRARY-LOW-LEVEL-CALL on an
// ordinary deposit. A caller-supplied token must still taint the receiver.
func TestTaintBindsUsingForReceiverAsFirstLibraryParameter(t *testing.T) {
	b := buildDBFromSource(t, `pragma solidity ^0.8.20;
interface IToken { function transferFrom(address f, address t, uint256 v) external returns (bool); }
library Safe {
    function safeTransferFrom(IToken token, address from, address to, uint256 value) internal {
        _call(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }
    function _call(IToken token, bytes memory data) private {
        (bool ok, ) = address(token).call(data);
        require(ok);
    }
}
contract FixedToken {
    using Safe for IToken;
    IToken public token;
    function deposit(uint256 amount) external { token.safeTransferFrom(msg.sender, address(this), amount); }
}
contract ChosenToken {
    using Safe for IToken;
    function deposit(IToken token, uint256 amount) external { token.safeTransferFrom(msg.sender, address(this), amount); }
}`)
	sites := func(source string) map[string]bool {
		t.Helper()
		tmpl, err := ParseTemplate(`meta: {id: T, title: t, severity: INFO, confidence: LOW, description: t, recommendation: t}
query:
  select: lowlevel_call
  from: entry_function
  where:
    - receiver: {tainted: ` + source + `}
`)
		if err != nil {
			t.Fatalf("parse template: %v", err)
		}
		got := map[string]bool{}
		for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
			if finding.EntryPoint != nil {
				got[finding.EntryPoint.Contract] = true
			}
		}
		return got
	}
	if got := sites("sender"); len(got) != 0 {
		t.Fatalf("library receiver tainted by msg.sender in %v; the receiver is the extension's token", got)
	}
	if got := sites("parameter"); !got["ChosenToken"] || got["FixedToken"] {
		t.Fatalf("parameter-tainted receiver = %v, want ChosenToken only", got)
	}
}

// A value returned by a non-virtual internal helper carries the taint of what
// the helper returns, not the union of its arguments. Curve's
// `(_o, _t) = getOriginAndTarget(curve, _origin, _target)` returns entries of
// an admin-maintained assimilator registry; treating them as caller-chosen
// raised CRITICAL-DELEGATECALL-USER-INPUT on its swap path. A helper that
// returns its argument must still propagate caller control, and a virtual
// helper keeps the conservative argument union because an override may
// return anything.
func TestTaintFollowsNonVirtualHelperReturnValues(t *testing.T) {
	b := buildDBFromSource(t, `pragma solidity ^0.8.20;
contract Registry {
    struct Assimilator { address addr; uint8 ix; }
    mapping(address => Assimilator) internal assimilators;
    function _lookup(address token) private view returns (Assimilator memory) {
        Assimilator memory a = assimilators[token];
        require(a.addr != address(0), "unsupported");
        return a;
    }
    function _passthrough(address target) private pure returns (address) { return target; }
    function _lookupVirtual(address token) internal view virtual returns (address) { return assimilators[token].addr; }
}
contract FromRegistry is Registry {
    function swap(address token, bytes memory data) external {
        Assimilator memory a = _lookup(token);
        (bool ok, ) = a.addr.delegatecall(data);
        require(ok);
    }
}
contract FromCaller is Registry {
    function swap(address target, bytes memory data) external {
        address t = _passthrough(target);
        (bool ok, ) = t.delegatecall(data);
        require(ok);
    }
}
contract FromVirtual is Registry {
    function swap(address token, bytes memory data) external {
        address t = _lookupVirtual(token);
        (bool ok, ) = t.delegatecall(data);
        require(ok);
    }
}`)
	tmpl, err := LoadTemplate(filepath.Join(repoRoot(t), "templates/official/critical/delegatecall-user-input.yaml"))
	if err != nil {
		t.Fatalf("load official template: %v", err)
	}
	got := map[string]bool{}
	for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
		if finding.EntryPoint != nil {
			got[finding.EntryPoint.Contract] = true
		}
	}
	if got["FromRegistry"] {
		t.Error("registry lookup through a private helper reported as a user-controlled delegatecall")
	}
	if !got["FromCaller"] {
		t.Error("caller-supplied target returned by a private helper was not reported")
	}
	if !got["FromVirtual"] {
		t.Error("virtual helper lost the conservative argument taint")
	}
}

// Sequence steps that depend on taint are matched against events inlined from
// internal helpers in the helper's own context, and an expanded sequence still
// has to satisfy the rule's other root-level constraints. Before, any
// `tainted:` step disabled the interprocedural expansion outright (so a CEI
// rule needing a caller-chosen receiver missed every call made in a helper),
// and a pure sequence match skipped the other constraints (so a `not: has:`
// exclusion was ignored whenever the expansion matched). Each entry calls its
// own helper because the engine reports one finding per site.
func TestInterproceduralSequenceUsesCalleeTaintAndRootConstraints(t *testing.T) {
	b := buildDBFromSource(t, `pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) balances;
    address owner;
    uint256 fee;
    function _send(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
    function withdrawToCaller(uint256 amount) external {
        _send(msg.sender, amount);
        balances[msg.sender] -= amount;
    }
    function withdrawToOwner(uint256 amount) external {
        _send(owner, amount);
        balances[msg.sender] -= amount;
    }
    function _sendWithFee(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
    function withdrawWithFee(uint256 amount) external {
        _sendWithFee(msg.sender, amount);
        balances[msg.sender] -= amount;
        fee += 1;
    }
}`)
	run := func(where string) map[string]bool {
		t.Helper()
		tmpl, err := ParseTemplate(`meta: {id: T, title: t, severity: INFO, confidence: LOW, description: t, recommendation: t}
query:
  from: entry_function
  where:
` + where)
		if err != nil {
			t.Fatalf("parse template: %v", err)
		}
		got := map[string]bool{}
		for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
			if finding.EntryPoint != nil {
				got[finding.EntryPoint.Function] = true
			}
		}
		return got
	}
	sequence := `    - sequence:
        - block: eth_transfer
          receiver: {tainted: sender}
        - block: state_write
`
	got := run(sequence)
	if !got["withdrawToCaller"] || !got["withdrawWithFee"] || got["withdrawToOwner"] {
		t.Fatalf("sender-receiver sequence through a helper = %v, want withdrawToCaller and withdrawWithFee only", got)
	}
	got = run(sequence + `    - not:
        has:
          block: identifier
          name: ^fee$
`)
	if !got["withdrawToCaller"] || got["withdrawWithFee"] {
		t.Fatalf("root exclusion ignored after an expanded sequence match: %v", got)
	}
}

// A negated sequence at a function's root also sees steps inside internal
// helpers, so an exclusion such as "no ETH is sent on this path" is not
// defeated by moving the send into a helper. (With a `select` and no positive
// root sequence, `where` is evaluated at the selected node instead.)
func TestNegatedRootSequenceSeesHelperSteps(t *testing.T) {
	b := buildDBFromSource(t, `pragma solidity ^0.8.20;
contract Payer {
    uint256 public count;
    function _pay(address to) internal { (bool ok, ) = to.call{value: 1}(""); require(ok); }
    function viaHelper(address to) external { _pay(to); count += 1; }
    function noSend() external { count += 1; }
}`)
	tmpl, err := ParseTemplate(`meta: {id: T, title: t, severity: INFO, confidence: LOW, description: t, recommendation: t}
query:
  from: entry_function
  where:
    - sequence:
        - block: state_write
    - not:
        sequence:
          - block: eth_transfer
`)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	got := map[string]bool{}
	for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
		if finding.EntryPoint != nil {
			got[finding.EntryPoint.Function] = true
		}
	}
	if got["viaHelper"] || !got["noSend"] {
		t.Fatalf("negated sequence through a helper = %v, want noSend only", got)
	}
}
