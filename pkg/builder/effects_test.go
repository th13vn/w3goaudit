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
