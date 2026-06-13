package builder

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const statementsFixture = "../../test-data/core/build-database/09-statements.sol"

// funcByName returns the first function with the given name in a contract.
func funcByName(t *testing.T, db *types.Database, contract, fn string) *types.Function {
	t.Helper()
	c := db.GetContractByName(contract)
	if c == nil {
		t.Fatalf("contract %q not found", contract)
	}
	for _, f := range c.Functions {
		if f.Name == fn {
			return f
		}
	}
	t.Fatalf("function %s.%s not found", contract, fn)
	return nil
}

// TestRevertStatementProducesCheckRevert verifies that both revert forms
// (`revert("msg")` and `revert CustomError(args)`) produce check.revert nodes.
// Previously revert parsed as *ast.RevertStatement and fell through to an
// opaque "statement" node, so check.revert was never emitted.
func TestRevertStatementProducesCheckRevert(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "guardedRevert")
	if fn.AST == nil {
		t.Fatal("guardedRevert has no AST")
	}

	reverts := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindCheckRevert
	})
	if len(reverts) != 2 {
		t.Fatalf("guardedRevert check.revert count = %d, want 2 (kinds: %v)", len(reverts), astKinds(fn.AST))
	}

	// One revert names the custom error; its argument is exposed as a child.
	namedErr := false
	for _, r := range reverts {
		if r.Name == "Unauthorized" {
			namedErr = true
			if len(r.Children) == 0 {
				t.Error("revert Unauthorized(to) should expose its argument as a child")
			}
		}
	}
	if !namedErr {
		t.Error("expected a check.revert node named Unauthorized")
	}
}

// TestUncheckedAndDoWhileCallsInCallGraph verifies that calls inside unchecked{}
// blocks and do/while loops reach the call graph (both were previously dropped).
func TestUncheckedAndDoWhileCallsInCallGraph(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	abs := fixtureAbs(t, statementsFixture)
	db.CallGraph.EnsureIndex()

	caller := abs + "#StatementForms.loopAndUnchecked(ICallee)"
	callees := db.CallGraph.GetCallees(caller)
	if !hasEdgeToName(callees, "ping") {
		t.Errorf("loopAndUnchecked should call ping() (inside unchecked{} in a do/while); got %v", edgeCalledNames(callees))
	}

	// The do/while body must also be present in the AST as a loop.
	fn := funcByName(t, db, "StatementForms", "loopAndUnchecked")
	loops := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtLoop && n.GetAttributeString("loop_type") == "do_while"
	})
	if len(loops) == 0 {
		t.Errorf("loopAndUnchecked should contain a do_while loop; kinds: %v", astKinds(fn.AST))
	}
}

// TestTryBodyCallsInCallGraph verifies the try success body is analyzed (its
// calls were previously dropped while catch clauses were kept).
func TestTryBodyCallsInCallGraph(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	abs := fixtureAbs(t, statementsFixture)
	db.CallGraph.EnsureIndex()

	caller := abs + "#StatementForms.tryBody(ICallee)"
	callees := db.CallGraph.GetCallees(caller)
	if !hasEdgeToName(callees, "helperConsume") {
		t.Errorf("tryBody should call helperConsume() from the try success body; got %v", edgeCalledNames(callees))
	}
}

// TestCompoundAndTupleAssignments verifies bitwise/modulo compound assignments
// produce stmt.assign (state writes) and tuple assignment preserves targets.
func TestCompoundAndTupleAssignments(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "compoundAndTuple")

	assigns := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign
	})
	// flags &= a; flags |= b; total %= (a+1); (a,b)=(b,a); total = a+b  => 5 assigns
	if len(assigns) < 5 {
		t.Errorf("compoundAndTuple stmt.assign count = %d, want >= 5; kinds: %v", len(assigns), astKinds(fn.AST))
	}

	// At least one compound assignment must be flagged as a state-var write.
	stateWrite := false
	for _, a := range assigns {
		if a.GetAttributeBool("is_state_var") {
			op := a.GetAttributeString("operator")
			if op == "&=" || op == "|=" || op == "%=" {
				stateWrite = true
			}
		}
	}
	if !stateWrite {
		t.Error("expected a compound-assignment state write (&=, |=, or %=) on a state variable")
	}

	// Tuple assignment preserves an expr.tuple node.
	if !astHasKind(fn.AST, types.KindExprTuple) {
		t.Errorf("compoundAndTuple should contain an expr.tuple node; kinds: %v", astKinds(fn.AST))
	}
}

// TestAssemblyDelegatecallAssignment verifies `ok := delegatecall(...)` (an
// AssemblyAssignment, not a let-definition) has its RHS classified as
// asm.delegatecall instead of being dropped into a generic node.
func TestAssemblyDelegatecallAssignment(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmDelegate")
	if !astHasKind(fn.AST, types.KindAsmDelegatecall) {
		t.Errorf("asmDelegate should classify `ok := delegatecall(...)` as asm.delegatecall; kinds: %v", astKinds(fn.AST))
	}
}

// TestNewExpressionCreateEdge verifies `new Deployed(v)` produces a call.create
// node and a call-graph creation edge to the deployed contract.
func TestNewExpressionCreateEdge(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "deploy")
	if !astHasKind(fn.AST, types.KindCallCreate) {
		t.Errorf("deploy should contain a call.create node; kinds: %v", astKinds(fn.AST))
	}

	abs := fixtureAbs(t, statementsFixture)
	db.CallGraph.EnsureIndex()
	callees := db.CallGraph.GetCallees(abs + "#StatementForms.deploy(uint256)")
	if !hasEdgeToName(callees, "Deployed") {
		t.Errorf("deploy should have a creation edge to Deployed; got %v", edgeCalledNames(callees))
	}
}

// TestModifierBodyCallsPopulated verifies modifier bodies are walked into
// Modifier.Calls and that IsAccessControlled recognizes a non-auth-named
// modifier (`gate`) that calls an auth helper (`_enforceOwner`).
func TestModifierBodyCallsPopulated(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	c := db.GetContractByName("StatementForms")

	var gate *types.Modifier
	for _, m := range c.Modifiers {
		if m.Name == "gate" {
			gate = m
		}
	}
	if gate == nil {
		t.Fatal("modifier gate not found")
	}
	if len(gate.Calls) == 0 {
		t.Fatal("modifier gate should have its body calls populated (was empty)")
	}
	foundEnforce := false
	for _, call := range gate.Calls {
		if call.Target == "_enforceOwner" {
			foundEnforce = true
		}
	}
	if !foundEnforce {
		t.Errorf("modifier gate should call _enforceOwner; got %v", gate.Calls)
	}

	// deploy() is gated by `gate`, which is access-controlled via the helper.
	deploy := funcByName(t, db, "StatementForms", "deploy")
	if !deploy.IsAccessControlled(db) {
		t.Error("deploy() should be access-controlled via modifier gate -> _enforceOwner")
	}
}
