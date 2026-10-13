package builder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// buildFromSource is a small helper: parse+build a database from one source.
func buildFromSource(t *testing.T, src string) *types.Database {
	t.Helper()
	db, err := New().Build([]*types.SourceFile{{Path: "/tmp/T.sol", Content: src}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return db
}

func effectsOf(db *types.Database, contract, selector string) *types.FunctionEffects {
	id := types.MakeFunctionID("/tmp/T.sol", contract, selector)
	return db.Semantics.GetFunctionEffects(id)
}

func TestEffectsStateWritesAndGuards(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    mapping(address => uint256) balances;

    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}`
	db := buildFromSource(t, src)

	// setOwner: writes `owner`, has a require with msg.sender, so it's controlled.
	fe := effectsOf(db, "Vault", "setOwner(address)")
	if fe == nil {
		t.Fatal("no effects for setOwner")
	}
	if !hasWrite(fe, "owner") {
		t.Errorf("setOwner should write owner; writes=%v", fe.StateWrites)
	}
	if len(fe.Guards) == 0 {
		t.Error("setOwner should have a require guard")
	}
	if !fe.Auth.Controlled || len(fe.Auth.SenderChecks) == 0 {
		t.Errorf("setOwner should be access-controlled via msg.sender; auth=%+v", fe.Auth)
	}

	// deposit: writes `balances` via compound assignment; unprotected.
	fd := effectsOf(db, "Vault", "deposit()")
	if fd == nil {
		t.Fatal("no effects for deposit")
	}
	if !hasWrite(fd, "balances") {
		t.Errorf("deposit should write balances; writes=%v", fd.StateWrites)
	}
	if fd.Auth.Controlled {
		t.Error("deposit should be unprotected")
	}
}

func TestAuthorizationHelperIgnoresLowLevelCallSuccessCheck(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Wrapper {
    function open(address target, bytes calldata data) external { _call(target, data); }
    function _call(address target, bytes calldata data) internal { (bool ok,) = target.call(data); require(ok); }
}`)
	fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Wrapper", "open(address,bytes)"))
	if !ok {
		t.Fatal("missing authorization fact")
	}
	if fact.Verdict != types.AuthorizationUnprotected {
		t.Fatalf("low-level success check classified as authorization: %+v", fact)
	}
}

func TestAuthorizationFactsCaptureRuntimeAndPrincipalEvidence(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract AuthFacts {
    address owner;
    function withdraw() external {
        require(msg.sender == owner, "owner");
    }
    function open() external {}
}`)
	if db.Semantics == nil || db.Semantics.AuthorizationFactsVersion != types.AuthorizationFactsVersion {
		t.Fatalf("authorization facts version = %q", db.Semantics.AuthorizationFactsVersion)
	}
	ownerID := types.MakeFunctionID("/tmp/T.sol", "AuthFacts", "withdraw()")
	fact, ok := db.GetAuthorizationFactByID(ownerID)
	if !ok {
		t.Fatalf("missing authorization fact %q", ownerID)
	}
	if fact.Verdict != types.AuthorizationProtected {
		t.Fatalf("withdraw verdict = %q, want protected: %+v", fact.Verdict, fact)
	}
	if fact.PrincipalKind != types.PrincipalExpectedExternal {
		t.Fatalf("withdraw principal = %q, want expected_external: %+v", fact.PrincipalKind, fact)
	}
	openID := types.MakeFunctionID("/tmp/T.sol", "AuthFacts", "open()")
	open, ok := db.GetAuthorizationFactByID(openID)
	if !ok || open.Verdict != types.AuthorizationUnprotected {
		t.Fatalf("open fact = %+v, ok=%v, want unprotected", open, ok)
	}
}

func TestEffectsDoNotTreatEveryModifierAsAccessControl(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EffectsAuth {
    address owner;
    event Seen(address who);
    modifier emitsEvent() { emit Seen(msg.sender); _; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    function open() external emitsEvent {}
    function closed() external onlyOwner {}
}`)
	open := effectsOf(db, "EffectsAuth", "open()")
	closed := effectsOf(db, "EffectsAuth", "closed()")
	if open == nil || closed == nil {
		t.Fatalf("missing effects: open=%+v closed=%+v", open, closed)
	}
	if open.Auth.Controlled {
		t.Errorf("unrelated modifier marked access-controlled: %+v", open.Auth)
	}
	if !closed.Auth.Controlled {
		t.Errorf("onlyOwner not recognized: %+v", closed.Auth)
	}
}

func TestEffectsRequireExactSemanticAuthorization(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EffectsExactAuth {
    address owner;
    mapping(address => bool) isOperator;

    modifier onlyOwner(uint256 amount) {
        require(amount > 0, "amount");
        _;
    }

    modifier gate() {
        _enforceOwner();
        _;
    }

    modifier onlyRole(bool requirement) {
        require(requirement, "role");
        _;
    }

    function modifierDecoy(uint256 amount) external onlyOwner(amount) {}
    function helperDecoy() external { _checkOwner(); }
    function exactModifier() external gate {}
    function exactHelper() external { _forwardAuth(); }
    function exactRole() external onlyRole(isOperator[msg.sender]) {}

    function _checkOwner() internal {}
    function _forwardAuth() internal { _enforceOwner(); }
    function _enforceOwner() internal view {
        require(msg.sender == owner, "owner");
    }
}`)

	for _, selector := range []string{"modifierDecoy(uint256)", "helperDecoy()"} {
		fe := effectsOf(db, "EffectsExactAuth", selector)
		if fe == nil {
			t.Fatalf("missing effects for %s", selector)
		}
		if fe.Auth.Controlled {
			t.Errorf("auth-named decoy %s marked controlled: %+v", selector, fe.Auth)
		}
	}

	contract := db.GetContractByName("EffectsExactAuth")
	if contract == nil {
		t.Fatal("missing EffectsExactAuth contract")
	}
	for _, selector := range []string{"exactModifier()", "exactHelper()", "exactRole()"} {
		fe := effectsOf(db, "EffectsExactAuth", selector)
		fn := functionBySelector(contract, selector)
		if fe == nil || fn == nil {
			t.Fatalf("missing exact auth result for %s: effects=%+v function=%+v", selector, fe, fn)
		}
		if !fe.Auth.Controlled {
			t.Errorf("exact semantic auth %s not persisted: %+v", selector, fe.Auth)
		}
		if fn.IsAccessControlled(nil) {
			t.Errorf("%s should require database resolution", selector)
		}
	}
}

func TestEffectsModifierArgumentsRequirePositiveEnforcement(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EffectsPolarity {
    address owner;
    mapping(address => bool) isOperator;
    event Seen(address who);

    modifier requireFalse(bool allowed) {
        require(allowed == false, "disabled");
        _;
    }

    modifier observe(bool allowed) {
        if (allowed) emit Seen(msg.sender);
        _;
    }

    modifier requireTrue(bool allowed) {
        require(allowed, "role");
        _;
    }

    function negative() external requireFalse(isOperator[msg.sender]) {}
    function observational() external observe(isOperator[msg.sender]) {}
    function directObservation() external {
        if (msg.sender == owner) emit Seen(msg.sender);
    }
    function positive() external requireTrue(isOperator[msg.sender]) {}
}`)

	for _, selector := range []string{"negative()", "observational()", "directObservation()"} {
		fe := effectsOf(db, "EffectsPolarity", selector)
		if fe == nil {
			t.Fatalf("missing effects for %s", selector)
		}
		if fe.Auth.Controlled {
			t.Errorf("non-enforcing condition %s marked controlled: %+v", selector, fe.Auth)
		}
	}
	positive := effectsOf(db, "EffectsPolarity", "positive()")
	if positive == nil || !positive.Auth.Controlled {
		t.Fatalf("truthy enforcing modifier not controlled: %+v", positive)
	}
}

func TestAuthorizationOrRequiresAuthorizationBranches(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OrAuthorization {
    address admin;
    mapping(address => bool) isOperator;
    mapping(address => uint256) balances;
    uint256 value;

    function protectedOrRole() external {
        require(msg.sender == admin || isOperator[msg.sender]);
        value = 1;
    }

    function protectedOrBalance() external {
        require(msg.sender == admin || balances[msg.sender] > 0);
        value = 2;
    }
}`)
	for _, tc := range []struct {
		selector string
		want     types.AuthorizationVerdict
	}{
		{selector: "protectedOrRole()", want: types.AuthorizationProtected},
		{selector: "protectedOrBalance()", want: types.AuthorizationUnprotected},
	} {
		contract := db.GetContractByName("OrAuthorization")
		fn := functionBySelector(contract, tc.selector)
		if fn == nil {
			t.Fatalf("missing function %s", tc.selector)
		}
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID(contract.SourceFile, contract.Name, fn.Selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", tc.selector)
		}
		if fact.Verdict != tc.want {
			t.Fatalf("%s verdict = %q, want %q: %+v", tc.selector, fact.Verdict, tc.want, fact)
		}
	}
}

func TestUnresolvedAuthorizationFallbackIgnoresBusinessValidators(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract UnresolvedHelpers {
    uint256 value;
    function businessValidation(uint256 amount) external {
        validateAmount(amount);
        value = amount;
    }
    function missingGuard() external {
        checkOwner();
        value = 1;
    }
}`)
	if got := effectsOf(db, "UnresolvedHelpers", "businessValidation(uint256)"); got == nil || got.Auth.Controlled {
		t.Fatalf("unresolved business validator became authorization: %+v", got)
	}
	contract := db.GetContractByName("UnresolvedHelpers")
	if contract == nil {
		t.Fatal("missing UnresolvedHelpers contract")
	}
	for _, tc := range []struct {
		selector string
		want     types.AuthorizationVerdict
	}{
		{"businessValidation(uint256)", types.AuthorizationUnprotected},
		{"missingGuard()", types.AuthorizationUnknown},
	} {
		fn := functionBySelector(contract, tc.selector)
		if fn == nil {
			t.Fatalf("missing function %s", tc.selector)
		}
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID(contract.SourceFile, contract.Name, fn.Selector))
		if !ok || fact.Verdict != tc.want {
			t.Fatalf("%s authorization = %+v, want %q", tc.selector, fact, tc.want)
		}
	}
}

func TestEffectsRecognizeExactRoleGates(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract EffectsRoles {
    bytes32 constant FIXED_ROLE = keccak256("FIXED_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;
    event Seen(address who);

    function hasRole(bytes32 role, address account) internal view returns (bool) {
        return roles[role][account];
    }

    modifier fixedRole() {
        require(hasRole(FIXED_ROLE, msg.sender), "role");
        _;
    }

    function modifierRole() external fixedRole {}
    function helperRole() external { _checkRole(msg.sender); }
    function selectedRole(bytes32 role) external {
        require(hasRole(role, msg.sender), "role");
    }
    function observationalRole() external {
        if (hasRole(FIXED_ROLE, msg.sender)) emit Seen(msg.sender);
    }

    function _checkRole(address account) internal view {
        if (!hasRole(FIXED_ROLE, account)) revert("role");
    }
}`)

	for _, selector := range []string{"modifierRole()", "helperRole()"} {
		fe := effectsOf(db, "EffectsRoles", selector)
		if fe == nil || !fe.Auth.Controlled {
			t.Errorf("exact enforced role gate %s not controlled: %+v", selector, fe)
		}
	}
	for _, selector := range []string{"selectedRole(bytes32)", "observationalRole()"} {
		fe := effectsOf(db, "EffectsRoles", selector)
		if fe == nil {
			t.Fatalf("missing role effects for %s", selector)
		}
		if fe.Auth.Controlled {
			t.Errorf("non-fixed or observational role gate %s marked controlled: %+v", selector, fe.Auth)
		}
	}
}

func TestEffectsRequireFixedRoleBindingsAndExactMembership(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ParameterizedRole {
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;

    function hasRole(bytes32 role, address account) internal view returns (bool) {
        return roles[role][account];
    }

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "role");
        _;
    }

    function adminAction() external onlyRole(ADMIN_ROLE) {}
    function callerSelected(bytes32 role) external onlyRole(role) {}
}

contract DecoyRole {
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    function hasRole(bytes32, address) internal pure returns (bool) {
        return true;
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "role");
        _;
    }

    function decoyAction() external onlyAdmin {}
}

contract DirectRoleMap {
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;

    function fixedRole() external {
        require(roles[ADMIN_ROLE][msg.sender], "role");
    }

    function callerSelectedRole(bytes32 role) external {
        require(roles[role][msg.sender], "role");
    }
}`)

	assertEffectControlled(t, db, "ParameterizedRole", "adminAction()", true)
	assertEffectControlled(t, db, "ParameterizedRole", "callerSelected(bytes32)", false)
	assertEffectControlled(t, db, "DecoyRole", "decoyAction()", false)
	assertEffectControlled(t, db, "DirectRoleMap", "fixedRole()", true)
	assertEffectControlled(t, db, "DirectRoleMap", "callerSelectedRole(bytes32)", false)
}

func TestParameterizedRoleBindingRoundTrip(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CachedParameterizedRole {
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;
    function hasRole(bytes32 role, address account) internal view returns (bool) {
        return roles[role][account];
    }
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "role");
        _;
    }
    function adminAction() external onlyRole(ADMIN_ROLE) {}
    function callerSelected(bytes32 role) external onlyRole(role) {}
}`)
	contract := db.GetContractByName("CachedParameterizedRole")
	admin := functionBySelector(contract, "adminAction()")
	selected := functionBySelector(contract, "callerSelected(bytes32)")
	if admin == nil || selected == nil {
		t.Fatalf("missing role functions: admin=%+v selected=%+v", admin, selected)
	}
	if !admin.IsAccessControlled(db) || selected.IsAccessControlled(db) {
		t.Fatalf("unexpected source role results: admin=%v selected=%v", admin.IsAccessControlled(db), selected.IsAccessControlled(db))
	}

	loaded := roundTripEffectsDatabase(t, db)
	loadedContract := loaded.GetContractByName("CachedParameterizedRole")
	loadedAdmin := functionBySelector(loadedContract, "adminAction()")
	loadedSelected := functionBySelector(loadedContract, "callerSelected(bytes32)")
	if loadedAdmin == nil || loadedSelected == nil {
		t.Fatalf("missing cached role functions: admin=%+v selected=%+v", loadedAdmin, loadedSelected)
	}
	if !loadedAdmin.IsAccessControlled(loaded) || loadedSelected.IsAccessControlled(loaded) {
		t.Fatalf("unexpected cached role results: admin=%v selected=%v", loadedAdmin.IsAccessControlled(loaded), loadedSelected.IsAccessControlled(loaded))
	}
}

func TestEffectsPropagateExactHelperBindings(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract BindingChains {
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    mapping(bytes32 => mapping(address => bool)) roles;
    mapping(address => bool) isOperator;

    function hasRole(bytes32 role, address account) internal view returns (bool) {
        return roles[role][account];
    }

    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    modifier authGate(bool allowed) {
        _checkAllowed(allowed);
        _;
    }

    function adminAction() external onlyRole(ADMIN_ROLE) {}
    function callerSelected(bytes32 role) external onlyRole(role) {}
    function booleanAction() external authGate(isOperator[msg.sender]) {}

    function _checkRole(bytes32 role) internal view {
        require(hasRole(role, msg.sender), "role");
    }

    function _checkAllowed(bool allowed) internal pure {
        require(allowed, "role");
    }
}

contract MultiCallerRoleMap {
    mapping(address => mapping(address => bool)) roles;
    mapping(address => bool) isOperator;

    function multiCaller() external {
        require(roles[msg.sender][tx.origin], "role");
    }

    function singleCaller() external {
        require(isOperator[msg.sender], "role");
    }
}`)

	assertEffectControlled(t, db, "BindingChains", "adminAction()", true)
	assertEffectControlled(t, db, "BindingChains", "callerSelected(bytes32)", false)
	assertEffectControlled(t, db, "BindingChains", "booleanAction()", true)
	assertEffectControlled(t, db, "MultiCallerRoleMap", "multiCaller()", false)
	assertEffectControlled(t, db, "MultiCallerRoleMap", "singleCaller()", true)
}

func TestModifierArgumentsRoundTripPreservesAccessControl(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CachedRole {
    mapping(address => bool) isOperator;
    modifier onlyRole(bool allowed) { require(allowed, "role"); _; }
    function run() external onlyRole(isOperator[msg.sender]) {}
}`)
	contract := db.GetContractByName("CachedRole")
	fn := functionBySelector(contract, "run()")
	if fn == nil || !fn.IsAccessControlled(db) {
		t.Fatalf("source-built run() should be controlled: %+v", fn)
	}
	call := modifierCall(fn)
	if call == nil || len(call.Arguments) != 1 || len(call.Arguments[0].Children) == 0 {
		t.Fatalf("modifier arguments not persisted before cache: %+v", call)
	}

	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write database: %v", err)
	}
	loaded, err := types.LoadFromJSON(path)
	if err != nil {
		t.Fatalf("load database: %v", err)
	}
	loadedContract := loaded.GetContractByName("CachedRole")
	loadedFn := functionBySelector(loadedContract, "run()")
	loadedCall := modifierCall(loadedFn)
	if loadedCall == nil || len(loadedCall.Arguments) != 1 || len(loadedCall.Arguments[0].Children) == 0 {
		t.Fatalf("modifier arguments missing after cache: %+v", loadedCall)
	}
	if loadedCall.Arguments[0].Children[0].Parent != loadedCall.Arguments[0] {
		t.Fatal("modifier argument parent links were not restored")
	}
	if !loadedFn.IsAccessControlled(loaded) {
		t.Fatal("cache-loaded run() lost access-control result")
	}
}

func TestAnalyzeFunctionEffectsNilFunction(t *testing.T) {
	fe := analyzeFunctionEffects(nil, types.NewDatabase())
	if fe == nil {
		t.Fatal("nil function should yield empty effects")
	}
	if len(fe.StateWrites) != 0 || len(fe.Guards) != 0 || fe.Auth.Controlled {
		t.Fatalf("nil function yielded non-empty effects: %+v", fe)
	}
}

func TestStateWriteAndGuardHaveLines(t *testing.T) {
	src := `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    address owner;
    mapping(address => uint256) balances;

    function setOwner(address o) external {
        require(msg.sender == owner, "not owner");
        owner = o;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}`
	db := buildFromSource(t, src)

	fe := effectsOf(db, "Vault", "setOwner(address)")
	if fe == nil {
		t.Fatal("no effects for setOwner")
	}
	if len(fe.StateWrites) == 0 {
		t.Fatal("expected setOwner to have state writes")
	}
	for _, w := range fe.StateWrites {
		if w.Line == 0 {
			t.Errorf("state write %q has Line == 0 (should be populated now)", w.Var)
		}
	}
	if len(fe.Guards) == 0 {
		t.Fatal("expected setOwner to have guards")
	}
	for _, g := range fe.Guards {
		if g.Line == 0 {
			t.Errorf("guard %q has Line == 0", g.Expr)
		}
	}
}

func TestEffectsCoverStorageMutationForms(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Mutations {
    uint256[] values;
    uint256 counter;
    function mutate(uint256 x) external {
        values.push(x);
        values.pop();
        delete values[0];
        counter++;
        --counter;
    }
}`)
	fe := effectsOf(db, "Mutations", "mutate(uint256)")
	if fe == nil {
		t.Fatal("no effects for mutate")
	}
	got := map[string]bool{}
	for _, write := range fe.StateWrites {
		got[write.Kind+":"+write.Var] = true
	}
	for _, want := range []string{
		"push:values", "pop:values", "delete:values",
		"increment:counter", "decrement:counter",
	} {
		if !got[want] {
			t.Errorf("missing %q; writes=%+v", want, fe.StateWrites)
		}
	}
	fn := funcByName(t, db, "Mutations", "mutate")
	for _, node := range fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if strings.HasPrefix(node.Kind, "call.") {
			t.Errorf("%s classified as %q", node.Name, node.Kind)
		}
	}
}

func TestStorageMutationClassificationRejectsLocalAliasAndCallgraphEdges(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MutationReceivers {
    uint256[] values;
    function mutate(uint256 x) external {
        values.push(x);
        values.pop();
        uint256[] storage localAlias = values;
        localAlias.push(x);
        localAlias.pop();
    }
}`)
	fn := funcByName(t, db, "MutationReceivers", "mutate")
	mutationCalls := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	})
	if len(mutationCalls) != 4 {
		t.Fatalf("push/pop node count = %d, want 4; nodes=%+v", len(mutationCalls), mutationCalls)
	}
	for _, node := range mutationCalls {
		receiverIsState := firstStateVar(node) == "values"
		if receiverIsState {
			if node.Kind != "stmt.state_mutation" {
				t.Errorf("direct state %s classified as %q", node.Name, node.Kind)
			}
			if !node.GetAttributeBool("is_state_var") {
				t.Errorf("direct state mutation %q missing is_state_var", node.Name)
			}
			if op := node.GetAttributeString("operator"); op != node.Name {
				t.Errorf("direct state mutation operator = %q, want %q", op, node.Name)
			}
		} else if node.Kind != types.KindStmtStateMutation || node.GetAttributeBool("is_state_var") {
			t.Errorf("local storage alias %s builtin mismatch: kind=%q attrs=%v", node.Name, node.Kind, node.Attributes)
		}
	}
	for _, call := range fn.Calls {
		if call.Target == "push" || call.Target == "pop" {
			t.Errorf("storage array mutation emitted callgraph call: %+v", call)
		}
	}
}

func TestLegacyVarStorageAliasKeepsCanonicalLocalIdentity(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.4.24;
contract LegacyAliasIdentity {
    struct Account { uint256 balance; }
    mapping(address => Account) accounts;
    function withdraw() public {
        var account = accounts[msg.sender];
        account.balance -= 1;
    }
}`)
	fn := funcByName(t, db, "LegacyAliasIdentity", "withdraw")
	var alias, writeTarget *types.ASTNode
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind == types.KindExprIdentifier && node.Name == "account" {
			if alias == nil {
				alias = node
			}
		}
		if node.Kind == types.KindStmtAssign && len(node.Children) > 0 {
			if target := node.Children[0].FindDescendant(func(n *types.ASTNode) bool {
				return n.Kind == types.KindExprIdentifier && n.Name == "account"
			}); target != nil {
				writeTarget = target
			}
		}
		return true
	})
	if alias == nil || writeTarget == nil {
		t.Fatalf("legacy storage alias nodes missing: alias=%+v target=%+v", alias, writeTarget)
	}
	if alias.RefKind != "local_var" || writeTarget.RefKind != "local_var" {
		t.Fatalf("legacy alias RefKind = %q/%q, want local_var/local_var", alias.RefKind, writeTarget.RefKind)
	}
	if alias.RefID == "" || alias.RefID != writeTarget.RefID {
		t.Fatalf("legacy alias RefID = %q/%q, want one canonical local identity", alias.RefID, writeTarget.RefID)
	}
	if alias.GetAttributeString("data_location") != "storage" || writeTarget.GetAttributeString("data_location") != "storage" {
		t.Fatalf("legacy alias data locations = %q/%q, want storage/storage", alias.GetAttributeString("data_location"), writeTarget.GetAttributeString("data_location"))
	}
}

func TestLegacyVarValueTypeRemainsLocal(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.4.24;
contract LegacyValueCopy {
    mapping(address => uint256) balances;
    function withdraw() public {
        var balance = balances[msg.sender];
        balance -= 1;
    }
}`)
	fn := funcByName(t, db, "LegacyValueCopy", "withdraw")
	var write *types.ASTNode
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind == types.KindStmtAssign && node.GetAttributeString("operator") == "-=" {
			write = node
		}
		return true
	})
	if write == nil || len(write.Children) == 0 {
		t.Fatalf("legacy value-copy assignment missing: %+v", write)
	}
	if write.GetAttributeBool("is_state_var") {
		t.Fatalf("legacy value copy classified as state write: %+v", write)
	}
	target := write.Children[0]
	if target.Kind != types.KindExprIdentifier || target.Name != "balance" {
		target = target.FindDescendant(func(node *types.ASTNode) bool {
			return node.Kind == types.KindExprIdentifier && node.Name == "balance"
		})
	}
	if target == nil {
		t.Fatal("legacy value-copy target missing")
	}
	if got := target.GetAttributeString("data_location"); got != "" {
		t.Fatalf("legacy value-copy data location = %q, want empty", got)
	}
}

func TestEffectsRejectLocalUnaryMutations(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract LocalMutations {
    function mutate(uint256 x) external {
        uint256 temporary = x;
        temporary++;
        --temporary;
        delete temporary;
    }
}`)
	fe := effectsOf(db, "LocalMutations", "mutate(uint256)")
	if fe == nil {
		t.Fatal("no effects for mutate")
	}
	if len(fe.StateWrites) != 0 {
		t.Fatalf("local unary operations recorded as state writes: %+v", fe.StateWrites)
	}
}

func TestEffectsFollowOnlyMutatedLValueRoot(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MutationTargets {
    uint256 counter;
    mapping(uint256 => uint256) values;

    function mutateLocal(uint256[] memory tmp) external {
        tmp[counter]++;
        --tmp[counter];
        delete tmp[counter];
    }

    function mutateState() external {
        values[counter]++;
        --values[counter];
        delete values[counter];
    }
}`)
	local := effectsOf(db, "MutationTargets", "mutateLocal(uint256[])")
	if local == nil {
		t.Fatal("no effects for mutateLocal")
	}
	if len(local.StateWrites) != 0 {
		t.Fatalf("state index leaked into local mutation effects: %+v", local.StateWrites)
	}
	state := effectsOf(db, "MutationTargets", "mutateState()")
	if state == nil {
		t.Fatal("no effects for mutateState")
	}
	got := map[string]bool{}
	for _, write := range state.StateWrites {
		got[write.Kind+":"+write.Var] = true
	}
	for _, want := range []string{"increment:values", "decrement:values", "delete:values"} {
		if !got[want] {
			t.Errorf("missing nested state mutation %q; writes=%+v", want, state.StateWrites)
		}
	}
}

func TestStorageMutationClassificationHonorsLocalShadowing(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ShadowedMutation {
    uint256[] values;
    uint256[] backing;

    function mutate(uint256 x) external {
        uint256[] storage values = backing;
        values.push(x);
        values.pop();
    }
}`)
	fn := funcByName(t, db, "ShadowedMutation", "mutate")
	for _, node := range fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if node.Kind != types.KindStmtStateMutation || node.GetAttributeBool("is_state_var") {
			t.Errorf("shadowing local %s builtin mismatch: kind=%q attrs=%v", node.Name, node.Kind, node.Attributes)
		}
	}
	fe := effectsOf(db, "ShadowedMutation", "mutate(uint256)")
	if fe == nil {
		t.Fatal("no effects for mutate")
	}
	if len(fe.StateWrites) != 0 {
		t.Fatalf("shadowing local alias recorded as state writes: %+v", fe.StateWrites)
	}
}

func TestFunctionParametersShadowStateMutationTargets(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ParameterShadowing {
    uint256[] values;
    uint256 counter;

    function mutateArray(uint256[] storage values, uint256 x) internal {
        values.push(x);
        values.pop();
    }

    function mutateScalar(uint256 counter) internal {
        counter++;
        --counter;
        delete counter;
    }
}`)
	arrayFn := funcByName(t, db, "ParameterShadowing", "mutateArray")
	for _, node := range arrayFn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if node.Kind != types.KindStmtStateMutation || node.GetAttributeBool("is_state_var") {
			t.Errorf("storage parameter %s builtin mismatch: kind=%q attrs=%v", node.Name, node.Kind, node.Attributes)
		}
		if len(node.Children) == 0 || node.Children[0].Name != "values" || node.Children[0].RefKind != "parameter" {
			t.Errorf("storage parameter receiver lost parameter identity: children=%+v", node.Children)
		}
	}
	arrayEffects := effectsOf(db, "ParameterShadowing", "mutateArray(uint256[],uint256)")
	if arrayEffects == nil {
		t.Fatal("no effects for mutateArray")
	}
	if len(arrayEffects.StateWrites) != 0 {
		t.Fatalf("storage parameter mutations recorded as state writes: %+v", arrayEffects.StateWrites)
	}

	scalarFn := funcByName(t, db, "ParameterShadowing", "mutateScalar")
	for _, node := range scalarFn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindExprUnaryOp
	}) {
		if len(node.Children) == 0 || node.Children[0].Name != "counter" || node.Children[0].RefKind != "parameter" {
			t.Errorf("scalar parameter operand lost parameter identity: children=%+v", node.Children)
		}
	}
	scalarEffects := effectsOf(db, "ParameterShadowing", "mutateScalar(uint256)")
	if scalarEffects == nil {
		t.Fatal("no effects for mutateScalar")
	}
	if len(scalarEffects.StateWrites) != 0 {
		t.Fatalf("scalar parameter unary operations recorded as state writes: %+v", scalarEffects.StateWrites)
	}
}

func TestModifierAndDetachedArgumentParametersShadowStateVariables(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ModifierParameterShadowing {
    uint256 counter;

    modifier gate(uint256 counter) {
        counter++;
        _;
    }

    function run(uint256 counter) external gate(counter) {}
}`)
	contract := db.GetContractByName("ModifierParameterShadowing")
	if contract == nil {
		t.Fatal("ModifierParameterShadowing contract not found")
	}
	var modifier *types.Modifier
	for _, candidate := range contract.Modifiers {
		if candidate != nil && candidate.Name == "gate" {
			modifier = candidate
			break
		}
	}
	if modifier == nil || modifier.AST == nil {
		t.Fatal("gate modifier AST not found")
	}
	unary := modifier.AST.FindDescendant(func(n *types.ASTNode) bool {
		return n.Kind == types.KindExprUnaryOp
	})
	if unary == nil || len(unary.Children) == 0 || unary.Children[0].RefKind != "parameter" {
		t.Fatalf("modifier parameter lost shadowing identity: unary=%+v", unary)
	}

	fn := funcByName(t, db, "ModifierParameterShadowing", "run")
	call := modifierCall(fn)
	if call == nil || len(call.Arguments) != 1 || call.Arguments[0].RefKind != "parameter" {
		t.Fatalf("detached modifier argument lost function-parameter identity: call=%+v", call)
	}
}

func hasWrite(fe *types.FunctionEffects, v string) bool {
	for _, w := range fe.StateWrites {
		if w.Var == v {
			return true
		}
	}
	return false
}

func functionBySelector(contract *types.Contract, selector string) *types.Function {
	if contract == nil {
		return nil
	}
	for _, fn := range contract.Functions {
		if fn != nil && fn.Selector == selector {
			return fn
		}
	}
	return nil
}

func modifierCall(fn *types.Function) *types.FunctionCall {
	if fn == nil {
		return nil
	}
	for _, call := range fn.Calls {
		if call != nil && call.CallType == types.CallTypeModifier {
			return call
		}
	}
	return nil
}

func assertEffectControlled(t *testing.T, db *types.Database, contract, selector string, want bool) {
	t.Helper()
	fe := effectsOf(db, contract, selector)
	if fe == nil {
		t.Fatalf("missing effects for %s.%s", contract, selector)
	}
	if fe.Auth.Controlled != want {
		t.Errorf("%s.%s controlled = %v, want %v; auth=%+v", contract, selector, fe.Auth.Controlled, want, fe.Auth)
	}
}

func roundTripEffectsDatabase(t *testing.T, db *types.Database) *types.Database {
	t.Helper()
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write database: %v", err)
	}
	loaded, err := types.LoadFromJSON(path)
	if err != nil {
		t.Fatalf("load database: %v", err)
	}
	return loaded
}

func TestAuthorizationLifecycleFactsDistinguishMutexAndTakeover(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Lifecycle {
    bool initialized;
    function initialize(address who) external {
        require(!initialized);
        initialized = true;
    }
    function setup() external {
        initialized = true;
    }
}`)
	id := types.MakeFunctionID("/tmp/T.sol", "Lifecycle", "initialize(address)")
	fact, ok := db.GetAuthorizationFactByID(id)
	if !ok {
		t.Fatalf("missing lifecycle fact %q", id)
	}
	if !fact.InitializerEntry || !fact.OneTimeMutex {
		t.Fatalf("lifecycle flags = %+v", fact)
	}
	if fact.FirstCallTakeover != "unknown" {
		t.Fatalf("first-call takeover = %q, want unknown", fact.FirstCallTakeover)
	}
	if fact.AtomicInitialization != "after_guard" {
		t.Fatalf("atomicity = %q, want after_guard", fact.AtomicInitialization)
	}
}

func TestAuthorizationFactsCaptureStructuralExpectedPrincipalAndRefIDs(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract ExternalPrincipal {
    address counterparty;
    function receiveResult(bytes calldata) external {
        require(msg.sender == counterparty);
    }
}`)
	id := types.MakeFunctionID("/tmp/T.sol", "ExternalPrincipal", "receiveResult(bytes)")
	fact, ok := db.GetAuthorizationFactByID(id)
	if !ok {
		t.Fatalf("missing external-principal fact %q", id)
	}
	if fact.Verdict != types.AuthorizationProtected || fact.PrincipalKind != types.PrincipalExpectedExternal {
		t.Fatalf("external-principal auth = %+v", fact)
	}
	wantRef := "/tmp/T.sol#ExternalPrincipal.counterparty"
	if fact.ExpectedPrincipal != "counterparty" || len(fact.ExpectedPrincipalRefIDs) != 1 || fact.ExpectedPrincipalRefIDs[0] != wantRef {
		t.Fatalf("expected principal evidence missing: %+v", fact)
	}
	if len(fact.Evidence) != 1 || fact.Evidence[0].GuardRange.StartLine == 0 ||
		len(fact.Evidence[0].RefIDs) != 1 || fact.Evidence[0].RefIDs[0] != wantRef {
		t.Fatalf("exact guard evidence missing: %+v", fact.Evidence)
	}
}

func TestAuthorizationFactsResolveUniqueRuntimeOverride(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
abstract contract Base {
    function _authorize() internal virtual;
    function upgrade() external { _authorize(); }
}
contract Derived is Base {
    address owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function _authorize() internal override onlyOwner {}
}`)
	baseID := types.MakeFunctionID("/tmp/T.sol", "Base", "upgrade()")
	fact, ok := db.GetAuthorizationFactByID(baseID)
	if !ok {
		t.Fatalf("missing runtime fact %q", baseID)
	}
	wantRuntime := "/tmp/T.sol#Derived"
	wantSelected := types.MakeFunctionID("/tmp/T.sol", "Derived", "_authorize()")
	if fact.SelectedFunctionID != wantSelected || fact.RuntimeContractID != wantRuntime ||
		fact.Verdict != types.AuthorizationProtected || fact.Dominance != types.AuthorizationDominates {
		t.Fatalf("runtime dispatch evidence incomplete: %+v", fact)
	}
	if len(fact.Evidence) != 1 || fact.Evidence[0].GuardKind != "virtual_override" {
		t.Fatalf("runtime guard evidence = %+v", fact.Evidence)
	}
}

// A declaration inherited by several main contracts has no single runtime.
// When every runtime reaches the same result through the same implementation
// and evidence, that result holds wherever the function runs and is kept,
// with RuntimeContractID left empty. The fail-closed test below pins the
// disagreeing case.
func TestAuthorizationFactsUseAgreedRuntimeAlternatives(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
abstract contract Base {
    address authority;
    uint256 x;
    modifier gate() { require(msg.sender == authority); _; }
    function act() external gate { x = 1; }
}
contract First is Base {}
contract Second is Base {}`)
	id := types.MakeFunctionID("/tmp/T.sol", "Base", "act()")
	fact, ok := db.GetAuthorizationFactByID(id)
	if !ok {
		t.Fatalf("missing shared runtime fact %q", id)
	}
	if fact.Verdict != types.AuthorizationProtected || fact.RuntimeContractID != "" ||
		!containsString(fact.Reasons, "runtime.alternatives.agree") {
		t.Fatalf("agreeing runtimes = %+v, want protected with no single runtime", fact)
	}
}

func TestAuthorizationFactsFailClosedForAmbiguousRuntimeAlternatives(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
abstract contract Base {
    function _authorize() internal virtual;
    function upgrade() external { _authorize(); }
}
contract First is Base {
    address authority;
    modifier gate() { require(msg.sender == authority); _; }
    function _authorize() internal override gate {}
}
contract Second is Base {
    function _authorize() internal override {}
}`)
	id := types.MakeFunctionID("/tmp/T.sol", "Base", "upgrade()")
	fact, ok := db.GetAuthorizationFactByID(id)
	if !ok {
		t.Fatalf("missing ambiguous runtime fact %q", id)
	}
	if fact.Verdict != types.AuthorizationUnknown || fact.RuntimeContractID != "" || fact.SelectedFunctionID != "" {
		t.Fatalf("ambiguous runtime must fail closed: %+v", fact)
	}
	if !containsString(fact.Reasons, "runtime.alternatives.ambiguous") ||
		!containsString(fact.Limitations, types.DiagnosticIdentity) {
		t.Fatalf("ambiguous runtime explanation missing: %+v", fact)
	}
}

// OpenZeppelin AccessControl stores roles in a struct field,
// `_roles[role].members[account]` (`hasRole[account]` since v5), not in a
// nested mapping. The struct field adds no key, so the chain is the same role
// lookup as `roles[role][account]`. Before this was recognized, every
// onlyRole-gated function read as unprotected, which turned the Rarible
// UpgradeExecutor's onlyRole(EXECUTOR_ROLE) delegatecall into a CRITICAL
// "user-controlled delegatecall" finding.
func TestAuthorizationFactsProveStructMemberRoleMapping(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
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
    function _grantRole(bytes32 role, address account) internal virtual { _roles[role].members[account] = true; }
}
contract Executor is AccessControl {
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    function execute(address target, bytes memory data) external onlyRole(EXECUTOR_ROLE) {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
    function executeAs(bytes32 role, address target, bytes memory data) external onlyRole(role) {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
}`)
	fixed, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Executor", "execute(address,bytes)"))
	if !ok || fixed.Verdict != types.AuthorizationProtected || fixed.Dominance != types.AuthorizationDominates {
		t.Fatalf("fixed onlyRole over a struct role mapping = %+v, ok=%v, want dominating protected", fixed, ok)
	}
	selected, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Executor", "executeAs(bytes32,address,bytes)"))
	if !ok || selected.Verdict == types.AuthorizationProtected {
		t.Fatalf("caller-selected role = %+v, ok=%v, must not be proven protected", selected, ok)
	}
}

// OpenZeppelin Ownable compares a zero-argument getter with `_msgSender()` in
// a helper that is declared below the modifier. Each of those three facts used
// to break the proof on its own. The controls pin what must stay unproven: a
// helper that runs after the placeholder, item self-scoping through a getter
// with arguments, and a getter that just returns the caller.
func TestAuthorizationFactsProveOpenZeppelinOwnable(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
abstract contract Context {
    function _msgSender() internal view virtual returns (address) { return msg.sender; }
}
abstract contract Ownable is Context {
    address private _owner;
    modifier onlyOwner() { _checkOwner(); _; }
    modifier checkedAfter() { _; _checkOwner(); }
    function owner() public view virtual returns (address) { return _owner; }
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) revert("Ownable: caller is not the owner");
    }
}
contract Vault is Ownable {
    mapping(uint256 => address) private _owners;
    uint256 x;
    function ownerOf(uint256 id) public view returns (address) { return _owners[id]; }
    function caller() internal view returns (address) { return msg.sender; }
    function setX(uint256 v) external onlyOwner { x = v; }
    function setLate(uint256 v) external checkedAfter { x = v; }
    function setItem(uint256 id, uint256 v) external { require(ownerOf(id) == _msgSender(), "not item owner"); x = v; }
    function setSelf(uint256 v) external { require(caller() == _msgSender(), "tautology"); x = v; }
}`)
	fact := func(selector string) *types.AuthorizationFact {
		t.Helper()
		f, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Vault", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		return f
	}
	if f := fact("setX(uint256)"); f.Verdict != types.AuthorizationProtected || f.Dominance != types.AuthorizationDominates {
		t.Fatalf("onlyOwner = %+v, want dominating protected", f)
	}
	for _, selector := range []string{"setLate(uint256)", "setItem(uint256,uint256)", "setSelf(uint256)"} {
		if f := fact(selector); f.Verdict == types.AuthorizationProtected {
			t.Errorf("%s must not be proven protected: %+v", selector, f)
		}
	}
}

// A helper parameter bound to a caller-selected value may be compared against a
// principal, but it never stands in for the caller. `_checkAdmin(user)` with
// `require(a == admin)` used to read as protected, although the caller passes
// user = admin and walks through. The same helper reached with msg.sender is a
// real guard.
func TestAuthorizationFactsNeverTreatCallerSelectedValueAsCaller(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract P {
    address admin;
    uint256 x;
    function _checkAdmin(address a) internal view { require(a == admin, "no"); }
    function isAdmin(address a) internal view returns (bool) { return a == admin; }
    function helperGuard(address user, uint256 v) external { _checkAdmin(user); x = v; }
    function predicateGuard(address user, uint256 v) external { require(isAdmin(user), "no"); x = v; }
    function helperSender(uint256 v) external { _checkAdmin(msg.sender); x = v; }
    function predicateSender(uint256 v) external { require(isAdmin(msg.sender), "no"); x = v; }
}`)
	for selector, want := range map[string]bool{
		"helperGuard(address,uint256)":    false,
		"predicateGuard(address,uint256)": false,
		"helperSender(uint256)":           true,
		"predicateSender(uint256)":        true,
	} {
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "P", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		if got := fact.Verdict == types.AuthorizationProtected; got != want {
			t.Errorf("%s protected = %v, want %v: %+v", selector, got, want, fact)
		}
	}
}

// OpenZeppelin UUPS proxies authorize upgrades in an override written with an
// unnamed parameter, `function _authorizeUpgrade(address) internal override
// onlyOwner {}`. An unnamed parameter cannot be read, so it needs no binding;
// refusing to bind it used to skip the helper and leave upgradeToAndCall
// unprotected, which reported a CRITICAL user-controlled delegatecall on every
// UUPS implementation.
func TestAuthorizationFactsBindUnnamedHelperParameters(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
abstract contract Ownable {
    address private _owner;
    modifier onlyOwner() { require(msg.sender == _owner, "not owner"); _; }
}
abstract contract UUPS {
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual {
        _authorizeUpgrade(newImplementation);
        (bool ok, ) = newImplementation.delegatecall(data);
        require(ok);
    }
    function _authorizeUpgrade(address newImplementation) internal virtual;
}
contract Impl is Ownable, UUPS {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}`)
	fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "UUPS", "upgradeToAndCall(address,bytes)"))
	if !ok || fact.RuntimeContractID != "/tmp/T.sol#Impl" || fact.Verdict != types.AuthorizationProtected {
		t.Fatalf("UUPS upgradeToAndCall through an unnamed-parameter override = %+v, ok=%v, want protected in Impl", fact, ok)
	}
}

// Caller identity copied into a local stays caller identity only while every
// write to that local is caller identity. The controls reassign the alias from
// a parameter through plain Solidity, Yul, and tuple destructuring; each must
// lose the self-scoping proof.
func TestAuthorizationFactsFollowExactCallerIdentityAliases(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Vault {
    mapping(uint256 => address) public ownerOf;
    function _withdraw(address caller, uint256 id) internal {
        if (ownerOf[id] != caller) revert("not owner");
        delete ownerOf[id];
    }
    function direct(uint256 id) external { _withdraw(msg.sender, id); }
    function aliased(uint256 id) external { address sender = msg.sender; _withdraw(sender, id); }
    function aliasOfAlias(uint256 id) external { address a = msg.sender; address b = a; _withdraw(b, id); }
    function reassigned(uint256 id, address user, bool flag) external {
        address sender = msg.sender;
        if (flag) sender = user;
        _withdraw(sender, id);
    }
    function yulReassigned(uint256 id, address user) external {
        address sender = msg.sender;
        assembly { sender := user }
        _withdraw(sender, id);
    }
    function tupleReassigned(uint256 id, address user) external {
        address sender = msg.sender;
        uint256 other;
        (sender, other) = (user, id);
        _withdraw(sender, other);
    }
}`)
	for selector, want := range map[string]bool{
		"direct(uint256)":                  true,
		"aliased(uint256)":                 true,
		"aliasOfAlias(uint256)":            true,
		"reassigned(uint256,address,bool)": false,
		"yulReassigned(uint256,address)":   false,
		"tupleReassigned(uint256,address)": false,
	} {
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Vault", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		if got := fact.Verdict == types.AuthorizationSelfScoped; got != want {
			t.Errorf("%s self_scoped = %v, want %v: %+v", selector, got, want, fact)
		}
	}
}

// `revert ERC20InvalidSender(...)` is recorded as a call to an unresolved
// function whose name contains "sender". It is a revert payload, not a guard
// helper, so an OpenZeppelin-style transfer that forwards an aliased
// _msgSender() into _transfer must not become unknown because of it.
func TestAuthorizationFactsIgnoreCustomErrorRevertPayloads(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
interface IERC20Errors { error ERC20InvalidSender(address sender); }
contract Token is IERC20Errors {
    mapping(address => uint256) balances;
    function _msgSender() internal view returns (address) { return msg.sender; }
    function _transfer(address from, address to, uint256 value) internal {
        if (from == address(0)) revert ERC20InvalidSender(address(0));
        balances[from] -= value;
        balances[to] += value;
    }
    function transfer(address to, uint256 value) external {
        address owner = _msgSender();
        _transfer(owner, to, value);
    }
}`)
	fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Token", "transfer(address,uint256)"))
	if !ok || fact.Verdict == types.AuthorizationUnknown {
		t.Fatalf("transfer = %+v, ok=%v; a custom-error revert payload must not make it unknown", fact, ok)
	}
}

// Axelar's acceptOwnership loads the pending owner through an assembly getter
// into a local and compares it with msg.sender. A zero-argument getter is a
// contract-held principal, so the single-assignment local proves exactly what
// comparing the getter directly proves. A local whose value is ambiguous (two
// assignments) is still an authorization check and must fail closed as
// unknown rather than vanish. An EOA check against tx.origin is not
// authorization.
// An `emit RoleSet(...)` is recorded as an unresolved call whose name passes
// the guard-word test on "role". It is an event payload, not a guard helper:
// an unguarded role setter must read as unprotected, not unknown, or every
// negated authorization preset silently skips it.
func TestAuthorizationFactsIgnoreEventPayloads(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Governor {
    event RoleSet(bytes32 indexed role, address indexed account, bool status);
    event OwnershipTransferred(address indexed previous, address indexed next);
    address owner;
    mapping(bytes32 => mapping(address => bool)) roles;
    function setRole(bytes32 role, address account) external {
        roles[role][account] = true;
        emit RoleSet(role, account, true);
    }
    function transferOwnership(address next) external {
        emit OwnershipTransferred(owner, next);
        owner = next;
    }
    function guardedSetRole(bytes32 role, address account) external {
        require(msg.sender == owner, "not owner");
        roles[role][account] = true;
        emit RoleSet(role, account, true);
    }
}`)
	for selector, want := range map[string]types.AuthorizationVerdict{
		"setRole(bytes32,address)":        types.AuthorizationUnprotected,
		"transferOwnership(address)":      types.AuthorizationUnprotected,
		"guardedSetRole(bytes32,address)": types.AuthorizationProtected,
	} {
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Governor", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		if fact.Verdict != want {
			t.Errorf("%s verdict = %s, want %s: %+v", selector, fact.Verdict, want, fact)
		}
	}
}

func TestAuthorizationFactsClassifyLocalPrincipals(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Owned {
    bytes32 internal constant _PENDING_SLOT = keccak256("pending");
    address backup;
    uint256 x;
    function pendingOwner() public view returns (address owner) {
        assembly { owner := sload(_PENDING_SLOT) }
    }
    function backupOwner() public view returns (address) { return backup; }
    function acceptOwnership() external {
        address newOwner = pendingOwner();
        if (newOwner != msg.sender) revert("InvalidOwner");
        x = 1;
    }
    function acceptDirect() external {
        if (pendingOwner() != msg.sender) revert("InvalidOwner");
        x = 2;
    }
    function acceptAmbiguous(bool flag) external {
        address expected = pendingOwner();
        if (flag) expected = backupOwner();
        if (expected != msg.sender) revert("InvalidOwner");
        x = 3;
    }
    function eoaOnly() external {
        require(msg.sender == tx.origin, "no contracts");
        x = 4;
    }
}`)
	for selector, want := range map[string]types.AuthorizationVerdict{
		"acceptOwnership()":     types.AuthorizationProtected,
		"acceptDirect()":        types.AuthorizationProtected,
		"acceptAmbiguous(bool)": types.AuthorizationUnknown,
		"eoaOnly()":             types.AuthorizationUnprotected,
	} {
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Owned", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		if fact.Verdict != want {
			t.Errorf("%s verdict = %s, want %s: %+v", selector, fact.Verdict, want, fact)
		}
	}
}

// A modifier that receives a caller-selected argument blocks the proof only
// when it could be authorization. A Uniswap router's `ensure(deadline)` has no
// authorization-shaped condition and calls nothing, so it is input
// validation and leaves the function's own verdict alone. An account modifier
// that delegates to a helper, as Euler's onlyOwnerOrOperator does, still
// fails closed, and so does one whose helper cannot be resolved (here
// `_verify`, as if inherited from a base missing from the sources), since the
// helper may hold the guard.
func TestAuthorizationFactsIgnoreInputValidationModifiers(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Router {
    mapping(address => mapping(address => bool)) operators;
    uint256 x;
    error Expired();
    modifier ensure(uint256 deadline) { require(deadline >= block.timestamp, "EXPIRED"); _; }
    modifier ensureCustom(uint256 deadline) { if (deadline < block.timestamp) revert Expired(); _; }
    modifier onlyOwnerOrOperator(address account) { _authenticate(account); _; }
    modifier verified(address account) { _verify(account); _; }
    function _authenticate(address account) internal view {
        require(account == msg.sender || operators[account][msg.sender], "unauthorized");
    }
    function swap(uint256 deadline) external ensure(deadline) { x = 1; }
    function swapCustom(uint256 deadline) external ensureCustom(deadline) { x = 2; }
    function act(address account) external onlyOwnerOrOperator(account) { x = 3; }
    function actVerified(address account) external verified(account) { x = 4; }
}`)
	for selector, want := range map[string]types.AuthorizationVerdict{
		"swap(uint256)":        types.AuthorizationUnprotected,
		"swapCustom(uint256)":  types.AuthorizationUnprotected,
		"act(address)":         types.AuthorizationUnknown,
		"actVerified(address)": types.AuthorizationUnknown,
	} {
		fact, ok := db.GetAuthorizationFactByID(types.MakeFunctionID("/tmp/T.sol", "Router", selector))
		if !ok {
			t.Fatalf("missing authorization fact for %s", selector)
		}
		if fact.Verdict != want {
			t.Errorf("%s verdict = %s, want %s: %+v", selector, fact.Verdict, want, fact)
		}
	}
}

func TestAuthorizationFactsKeepSuperDispatchOnExactBase(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract Base {
    address authority;
    function act() public virtual { require(msg.sender == authority); }
}
contract Derived is Base {
    function act() public override { super.act(); }
}`)
	id := types.MakeFunctionID("/tmp/T.sol", "Derived", "act()")
	fact, ok := db.GetAuthorizationFactByID(id)
	if !ok {
		t.Fatalf("missing super authorization fact %q", id)
	}
	wantSelected := types.MakeFunctionID("/tmp/T.sol", "Base", "act()")
	if fact.Verdict != types.AuthorizationProtected || fact.SelectedFunctionID != wantSelected ||
		fact.RuntimeContractID != "/tmp/T.sol#Derived" {
		t.Fatalf("super dispatch evidence = %+v", fact)
	}
	if len(fact.Evidence) != 1 || fact.Evidence[0].GuardKind != "super" {
		t.Fatalf("super guard evidence = %+v", fact.Evidence)
	}
}

func TestAuthorizationRuntimeFixtureMatrix(t *testing.T) {
	db := buildFixture(t, "../../test-data/security/authorization-runtime")
	principalFile := fixtureAbs(t, "../../test-data/security/authorization-runtime/principals.sol")
	runtimeFile := fixtureAbs(t, "../../test-data/security/authorization-runtime/runtime.sol")
	lifecycleFile := fixtureAbs(t, "../../test-data/security/authorization-runtime/lifecycle.sol")

	tests := []struct {
		file, contract, selector      string
		verdict                       types.AuthorizationVerdict
		principal                     types.AuthorizationPrincipalKind
		dominance                     types.AuthorizationDominance
		runtimeContract, selectedFunc string
		reason, limitation            string
	}{
		{principalFile, "PrincipalMatrix", "directOwner()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "exactRole()", types.AuthorizationProtected, types.PrincipalRole, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "fixedStatePrincipal()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "immutablePrincipal()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "literalPrincipal()", types.AuthorizationProtected, types.PrincipalFixedAddress, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "callerSelfScope(address)", types.AuthorizationSelfScoped, types.PrincipalCallerSelfScope, types.AuthorizationDominates, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "internalHelper()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkOwner()"), "helper.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "appliedModifier()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", "", "modifier.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "wrongBranch(bool)", types.AuthorizationUnknown, types.PrincipalExpectedExternal, types.AuthorizationPartial, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "guardAfterOperation()", types.AuthorizationUnknown, types.PrincipalExpectedExternal, types.AuthorizationAfterSite, "", "", "guard.proven", ""},
		{principalFile, "PrincipalMatrix", "modifierAfterOperation()", types.AuthorizationUnknown, types.PrincipalExpectedExternal, types.AuthorizationAfterSite, "", "", "modifier.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "modifierFixedPrincipal()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", "", "modifier.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "modifierSelectedPrincipal(address)", types.AuthorizationSelfScoped, types.PrincipalCallerSelfScope, types.AuthorizationDominates, "", "", "modifier.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "modifierFixedRole()", types.AuthorizationProtected, types.PrincipalRole, types.AuthorizationDominates, "", "", "modifier.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "modifierSelectedRole(bytes32)", types.AuthorizationUnknown, types.PrincipalUnknown, types.AuthorizationUnknownDom, "", "", "modifier.binding.caller_selected", types.DiagnosticIdentity},
		{principalFile, "PrincipalMatrix", "helperForwardedCaller()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkPrincipal(address,address)"), "helper.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "helperFixedPrincipal()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkSender(address)"), "helper.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "helperSelectedPrincipal(address)", types.AuthorizationSelfScoped, types.PrincipalCallerSelfScope, types.AuthorizationDominates, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkPrincipal(address,address)"), "helper.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "helperFixedRole()", types.AuthorizationProtected, types.PrincipalRole, types.AuthorizationDominates, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkRole(bytes32,address)"), "helper.guard.proven", ""},
		{principalFile, "PrincipalMatrix", "helperSelectedRole(bytes32)", types.AuthorizationUnknown, types.PrincipalUnknown, types.AuthorizationUnknownDom, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_checkRole(bytes32,address)"), "helper.binding.caller_selected", types.DiagnosticIdentity},
		{principalFile, "PrincipalMatrix", "helperOverloadAmbiguous(uint256)", types.AuthorizationUnknown, types.PrincipalUnknown, types.AuthorizationUnknownDom, "", types.MakeFunctionID(principalFile, "PrincipalMatrix", "_ambiguous(uint256)"), "helper.binding.caller_selected", types.DiagnosticIdentity},
		{principalFile, "PrincipalMatrix", "helperTrulyAmbiguous()", types.AuthorizationUnknown, types.PrincipalUnknown, types.AuthorizationUnknownDom, "", "", "helper.unresolved", types.DiagnosticIdentity},
		{runtimeFile, "RuntimeBase", "upgrade()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, types.MakeContractID(runtimeFile, "RuntimeProtected"), types.MakeFunctionID(runtimeFile, "RuntimeProtected", "_authorize()"), "virtual_override.guard.proven", ""},
		{runtimeFile, "SuperProtected", "act()", types.AuthorizationProtected, types.PrincipalExpectedExternal, types.AuthorizationDominates, types.MakeContractID(runtimeFile, "SuperProtected"), types.MakeFunctionID(runtimeFile, "SuperBase", "act()"), "super.guard.proven", ""},
		{runtimeFile, "AmbiguousBase", "execute()", types.AuthorizationUnknown, types.PrincipalUnknown, types.AuthorizationUnknownDom, "", "", "runtime.alternatives.ambiguous", types.DiagnosticIdentity},
	}

	for _, tc := range tests {
		t.Run(tc.contract+"."+tc.selector, func(t *testing.T) {
			id := types.MakeFunctionID(tc.file, tc.contract, tc.selector)
			fact, ok := db.GetAuthorizationFactByID(id)
			if !ok {
				t.Fatalf("missing fact %q", id)
			}
			if fact.Verdict != tc.verdict || fact.PrincipalKind != tc.principal || fact.Dominance != tc.dominance {
				t.Fatalf("fact classification = %+v", fact)
			}
			if tc.runtimeContract != "" && fact.RuntimeContractID != tc.runtimeContract {
				t.Fatalf("runtime contract = %q, want %q", fact.RuntimeContractID, tc.runtimeContract)
			}
			if fact.SelectedFunctionID != tc.selectedFunc {
				t.Fatalf("selected function = %q, want %q", fact.SelectedFunctionID, tc.selectedFunc)
			}
			if tc.reason != "" && !containsString(fact.Reasons, tc.reason) {
				t.Fatalf("reasons = %v, want %q", fact.Reasons, tc.reason)
			}
			if tc.limitation != "" && !containsString(fact.Limitations, tc.limitation) {
				t.Fatalf("limitations = %v, want %q", fact.Limitations, tc.limitation)
			}
			if len(fact.Evidence) > 0 && fact.Evidence[0].GuardRange.File == "" {
				t.Fatalf("guard range lost exact file: %+v", fact.Evidence[0])
			}
		})
	}

	mutex, _ := db.GetAuthorizationFactByID(types.MakeFunctionID(lifecycleFile, "MutexOnly", "initialize(address)"))
	if mutex == nil || !mutex.OneTimeMutex || mutex.FirstCallTakeover != "unknown" || mutex.AtomicInitialization != "after_guard" {
		t.Fatalf("mutex lifecycle = %+v", mutex)
	}
	takeover, _ := db.GetAuthorizationFactByID(types.MakeFunctionID(lifecycleFile, "FirstCallTakeover", "initialize(address)"))
	if takeover == nil || takeover.FirstCallTakeover != "possible" {
		t.Fatalf("takeover lifecycle = %+v", takeover)
	}
	disabled, _ := db.GetAuthorizationFactByID(types.MakeFunctionID(lifecycleFile, "DisabledImplementation", "initialize(address)"))
	if disabled == nil || !disabled.ConstructorDisable || disabled.FirstCallTakeover != "unknown" || disabled.ProxyLinkage != "unknown" {
		t.Fatalf("disabled implementation lifecycle = %+v", disabled)
	}
	proxyNamed, _ := db.GetAuthorizationFactByID(types.MakeFunctionID(lifecycleFile, "ProxyNamedOnly", "initialize(address)"))
	if proxyNamed == nil || proxyNamed.ProxyLinkage != "unknown" {
		t.Fatalf("name-only proxy linkage must stay unknown: %+v", proxyNamed)
	}
}

func TestAuthorizationFactsPreserveSourceCacheParity(t *testing.T) {
	db := buildFixture(t, "../../test-data/security/authorization-runtime")
	want, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	loaded := roundTripEffectsDatabase(t, db)
	got, err := loaded.AuthorizationFactsSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("authorization facts changed across cache round trip\nsource=%s\ncache=%s", wantJSON, gotJSON)
	}
}
