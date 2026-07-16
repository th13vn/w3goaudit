package builder

import (
	"strings"
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

// TestAssemblyLocalShadowing verifies that a Yul `let` gets block scope and
// does not inherit taint from a same-named Solidity parameter. References
// before and after the nested block must still resolve to the parameter.
func TestAssemblyLocalShadowing(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmShadow")
	receivers := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindExprIdentifier && n.Name == "receiver" && n.GetAttributeBool("assembly")
	})
	if len(receivers) != 4 {
		t.Fatalf("asmShadow assembly receiver count = %d, want 4", len(receivers))
	}

	var parameters, locals int
	for _, receiver := range receivers {
		switch receiver.RefKind {
		case "parameter":
			parameters++
			if len(receiver.TaintSources) != 1 || receiver.TaintSources[0] != "parameter" {
				t.Errorf("parameter receiver taint = %v, want [parameter]", receiver.TaintSources)
			}
		case "local_var":
			locals++
			if len(receiver.TaintSources) != 0 {
				t.Errorf("shadowed Yul receiver taint = %v, want none", receiver.TaintSources)
			}
		default:
			t.Errorf("assembly receiver RefKind = %q, want parameter or local_var", receiver.RefKind)
		}
	}
	if parameters != 2 || locals != 2 {
		t.Errorf("asmShadow receiver resolution: parameters=%d locals=%d, want 2 each", parameters, locals)
	}
}

// TestAssemblyAssignmentsUpdateSoliditySymbols verifies Yul assignments to
// Solidity parameters, locals, and named return variables update the outer
// taint state. The clean overwrite is an FP regression; the two taint copies
// are FN regressions.
func TestAssemblyAssignmentsUpdateSoliditySymbols(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmOuterSymbols")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 3 {
		t.Fatalf("asmOuterSymbols pop count = %d, want 3", len(pops))
	}

	assertAssemblyArgTaint(t, pops[0], "sanitized", false)
	assertAssemblyArgTaint(t, pops[1], "copied", true)
	assertAssemblyArgTaint(t, pops[2], "result", true)

	// The parser sees a same-width normalized copy, but AST locations must still
	// slice the untouched source at the original Yul := token.
	assigns := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign && n.GetAttributeBool("assembly")
	})
	if len(assigns) != 3 {
		t.Fatalf("asmOuterSymbols assembly assignment count = %d, want 3", len(assigns))
	}
	source := db.SourceFiles[fn.SourceFile].Content
	for _, assign := range assigns {
		if assign.StartByte < 0 || assign.EndByte > len(source) || assign.StartByte >= assign.EndByte {
			t.Fatalf("invalid assignment byte range [%d,%d) for source length %d", assign.StartByte, assign.EndByte, len(source))
		}
		snippet := source[assign.StartByte:assign.EndByte]
		if !strings.Contains(snippet, ":=") {
			t.Errorf("assignment range [%d,%d) = %q, want original := token", assign.StartByte, assign.EndByte, snippet)
		}
	}
}

// TestAssemblyForUsesRuntimeBodyPostOrder verifies mutable taint analysis uses
// Yul's runtime order: pre -> condition -> body -> post. The body taints the
// Solidity local before the post sink, and the post sanitizer leaves the
// after-loop sink clean.
func TestAssemblyForUsesRuntimeBodyPostOrder(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmForRuntimeOrder")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 2 {
		t.Fatalf("asmForRuntimeOrder pop count = %d, want 2", len(pops))
	}

	assertAssemblyArgTaint(t, pops[0], "current", true)
	assertAssemblyArgTaint(t, pops[1], "current", false)
}

// TestAssemblyIfMergesOptionalBodyState verifies an optional Yul if body cannot
// sanitize every path and that taint introduced only in the body remains
// possible after the join. It covers both Solidity symbols and Yul locals.
func TestAssemblyIfMergesOptionalBodyState(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmIfPathMerge")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 5 {
		t.Fatalf("asmIfPathMerge pop count = %d, want 5", len(pops))
	}

	for i, name := range []string{"outerSanitized", "outerCopied", "outerType", "localSanitized", "localCopied"} {
		assertAssemblyArgTaint(t, pops[i], name, true)
	}
	if got := pops[1].Children[0].GetAttributeString("type"); got != "address" {
		t.Errorf("assembly pop(outerCopied) type = %q, want address when all paths agree", got)
	}
	assertAssemblyArgTypeUnknown(t, pops[2], "outerType")
	assertAssemblyArgTypeUnknown(t, pops[4], "localCopied")
}

// TestAssemblySwitchMergesExclusiveCases verifies cases start from the same
// input state and merge by union. Because there is no default, the unmatched
// input path is included too.
func TestAssemblySwitchMergesExclusiveCases(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmSwitchPathMerge")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 2 {
		t.Fatalf("asmSwitchPathMerge pop count = %d, want 2", len(pops))
	}

	assertAssemblyArgTaint(t, pops[0], "sanitized", true)
	assertAssemblyArgTaint(t, pops[1], "copied", true)
}

// TestAssemblyForMergesZeroIterationState verifies the loop after-state joins
// the input (zero iterations) with one body-before-post iteration.
func TestAssemblyForMergesZeroIterationState(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmZeroIterationMerge")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 2 {
		t.Fatalf("asmZeroIterationMerge pop count = %d, want 2", len(pops))
	}

	assertAssemblyArgTaint(t, pops[0], "sanitized", true)
	assertAssemblyArgTaint(t, pops[1], "copied", true)
}

// TestAssemblyForPropagatesLoopCarriedTaintToFixpoint covers a flow that needs
// two runtime iterations: the first copies source into b; the second copies b
// into a. Analysis must update the already-built pop(a) node by union rather
// than rebuilding/duplicating the loop subtree.
func TestAssemblyForPropagatesLoopCarriedTaintToFixpoint(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "asmForLoopCarried")
	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 2 {
		t.Fatalf("asmForLoopCarried pop count = %d, want 2 (no duplicated AST nodes)", len(pops))
	}

	assertAssemblyArgTaint(t, pops[0], "a", true)
	assertAssemblyArgTaint(t, pops[1], "a", true)
}

func assemblyCallsByName(root *types.ASTNode, name string) []*types.ASTNode {
	return root.CollectDescendants(func(n *types.ASTNode) bool {
		return n.GetAttributeBool("assembly") && n.Name == name
	})
}

func assertAssemblyArgTaint(t *testing.T, call *types.ASTNode, name string, wantTainted bool) {
	t.Helper()
	if len(call.Children) != 1 {
		t.Fatalf("assembly %s child count = %d, want 1", call.Name, len(call.Children))
	}
	arg := call.Children[0]
	if arg.Name != name {
		t.Fatalf("assembly %s arg = %q, want %q", call.Name, arg.Name, name)
	}
	gotTainted := false
	for _, source := range arg.TaintSources {
		if source == "parameter" {
			gotTainted = true
		}
	}
	if gotTainted != wantTainted {
		t.Errorf("assembly %s(%s) parameter taint = %v, want %v (all taints: %v)", call.Name, name, gotTainted, wantTainted, arg.TaintSources)
	}
}

func assertAssemblyArgTypeUnknown(t *testing.T, call *types.ASTNode, name string) {
	t.Helper()
	if len(call.Children) != 1 || call.Children[0].Name != name {
		t.Fatalf("assembly %s argument mismatch for %q", call.Name, name)
	}
	arg := call.Children[0]
	if got := arg.GetAttributeString("type"); got != "" {
		t.Errorf("assembly %s(%s) type = %q, want unknown after disagreeing path types", call.Name, name, got)
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
