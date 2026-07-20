package builder

import (
	"strconv"
	"strings"
	"testing"

	"github.com/th13vn/solast-go/pkg/ast"
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

func TestTupleMetadataPreservesHolesAndAssignmentLHSCount(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TupleMetadata {
    function pair() internal pure returns (uint256, uint256) { return (1, 2); }
    function run() external {
        (uint256 first, uint256 second) = pair();
        (first, , second) = (second, 0, first);
    }
}`)
	fn := funcByName(t, db, "TupleMetadata", "run")
	assigns := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign
	})
	if len(assigns) != 2 {
		t.Fatalf("assignment count = %d, want 2", len(assigns))
	}
	if got := assigns[0].GetAttributeString("assignment_lhs_count"); got != "2" {
		t.Fatalf("declaration assignment_lhs_count = %q, want 2", got)
	}
	if len(assigns[0].Children) < 2 || assigns[0].Children[0].GetAttributeString("tuple_index") != "0" || assigns[0].Children[1].GetAttributeString("tuple_index") != "1" {
		t.Fatalf("declaration tuple indexes not preserved: %+v", assigns[0].Children)
	}

	if got := assigns[1].GetAttributeString("tuple_arity"); got != "3" {
		t.Fatalf("tuple_arity = %q, want 3", got)
	}
	if len(assigns[1].Children) < 2 || assigns[1].Children[0].GetAttributeString("tuple_index") != "0" || assigns[1].Children[1].GetAttributeString("tuple_index") != "2" {
		t.Fatalf("tuple hole shifted child positions: %+v", assigns[1].Children)
	}
	if assigns[1].Children[0].Name != "first" || assigns[1].Children[1].Name != "second" || assigns[1].Children[0].RefID == "" || assigns[1].Children[1].RefID == "" {
		t.Fatalf("tuple assignment targets lost exact identities: first=%+v second=%+v", assigns[1].Children[0], assigns[1].Children[1])
	}
}

func TestAssemblyAssignmentLHSCountIsSerializedOnAST(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AssemblyLHS {
    function run() external pure returns (uint256 x, uint256 y) {
        assembly {
            let a, b := 1, 2
            x, y := a, b
        }
    }
}`)
	fn := funcByName(t, db, "AssemblyLHS", "run")
	nodes := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.GetAttributeBool("assembly") && (n.Kind == types.KindDeclVariable || n.Kind == types.KindStmtAssign)
	})
	if len(nodes) != 2 {
		t.Fatalf("assembly multi-LHS node count = %d, want 2", len(nodes))
	}
	for _, node := range nodes {
		if got := node.GetAttributeString("assignment_lhs_count"); got != "2" {
			t.Errorf("%s assignment_lhs_count = %q, want 2", node.Kind, got)
		}
	}
}

func TestAssemblyNestedShadowingUsesExactDeclarationRefIDs(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AssemblyIdentity {
    function run(uint256 i, uint256 j) external {
        assembly {
            let shadow := i
            pop(shadow)
            {
                let shadow := j
                pop(shadow)
                shadow := i
                pop(shadow)
            }
            pop(shadow)
        }
    }
}`)
	fn := funcByName(t, db, "AssemblyIdentity", "run")
	definitions := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindDeclVariable && n.GetAttributeBool("assembly")
	})
	if len(definitions) != 2 || len(definitions[0].Children) == 0 || len(definitions[1].Children) == 0 {
		t.Fatalf("assembly definitions = %+v, want two declarations", definitions)
	}
	outerID := definitions[0].Children[0].RefID
	innerID := definitions[1].Children[0].RefID
	if outerID == "" || innerID == "" || outerID == innerID {
		t.Fatalf("Yul declaration RefIDs not exact: outer=%q inner=%q", outerID, innerID)
	}

	pops := assemblyCallsByName(fn.AST, "pop")
	if len(pops) != 4 {
		t.Fatalf("pop count = %d, want 4", len(pops))
	}
	if pops[0].Children[0].RefID != outerID || pops[1].Children[0].RefID != innerID || pops[2].Children[0].RefID != innerID || pops[3].Children[0].RefID != outerID {
		t.Fatalf("lexical reads did not reuse declaration identities: outer=%q inner=%q reads=%q,%q,%q,%q", outerID, innerID, pops[0].Children[0].RefID, pops[1].Children[0].RefID, pops[2].Children[0].RefID, pops[3].Children[0].RefID)
	}
	assigns := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign && n.GetAttributeBool("assembly")
	})
	if len(assigns) != 1 || len(assigns[0].Children) == 0 || assigns[0].Children[0].RefID != innerID {
		t.Fatalf("Yul assignment target did not reuse inner declaration identity: %+v", assigns)
	}
}

func TestOverloadedFunctionsUseCanonicalSelectorRefIDs(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract OverloadedIdentity {
    function f(uint256 input) external returns (uint256 result) {
        uint256 local = input;
        assembly { let y := local pop(y) }
        return local;
    }
    function f(address input) external returns (address result) {
        address local = input;
        assembly { let y := local pop(y) }
        return local;
    }
}`)
	contract := db.GetContractByName("OverloadedIdentity")
	if contract == nil || len(contract.Functions) != 2 {
		t.Fatalf("overloaded functions = %+v", contract)
	}
	seen := map[string]bool{}
	for _, fn := range contract.Functions {
		want := types.MakeFunctionID(fn.SourceFile, fn.ContractName, fn.Selector)
		for _, node := range collectBuilderNodes(fn.AST, func(node *types.ASTNode) bool { return node.RefID != "" }) {
			if !strings.HasPrefix(node.RefID, want) {
				t.Fatalf("%s binding RefID %q lacks canonical selector", fn.Selector, node.RefID)
			}
			seen[node.RefID] = true
		}
	}
	if len(seen) < 6 {
		t.Fatalf("too few distinct overloaded binding identities: %v", seen)
	}
}

func TestLiteralAttributesPreserveClassAndSubdenomination(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LiteralFacts {
    function f() external pure {
        uint256 a = 1 ether;
        uint256 b = 0x03;
        bytes memory c = hex"03";
    }
}`)
	fn := funcByName(t, db, "LiteralFacts", "f")
	literals := fn.AST.CollectDescendants(func(node *types.ASTNode) bool { return node.Kind == types.KindExprLiteral })
	facts := map[string][2]string{}
	for _, literal := range literals {
		facts[literal.Value] = [2]string{literal.GetAttributeString("literal_class"), literal.GetAttributeString("subdenomination")}
	}
	hexString := (&ASTBuilder{}).buildLiteral(&ast.HexLiteral{Value: "03"})
	facts[hexString.Value] = [2]string{hexString.GetAttributeString("literal_class"), hexString.GetAttributeString("subdenomination")}
	if facts["1"] != [2]string{"numeric_decimal", "ether"} || facts["0x03"][0] != "numeric_hex" || facts["03"][0] != "hex_string" {
		t.Fatalf("literal facts = %v", facts)
	}
	assemblyHex := buildAssemblyLiteral(&ast.AssemblyLiteral{Value: "0x40", Kind: "number"})
	if assemblyHex.GetAttributeString("literal_class") != "numeric_hex" || assemblyHex.GetAttributeString("subtype") != "hex" {
		t.Fatalf("assembly hex literal facts = %+v", assemblyHex.Attributes)
	}
}

func TestAssemblyDeclarationNameRecoverySkipsComments(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CommentIdentity {
    function f(uint256 input) external pure {
        assembly {
            let /* shadow in block comment */ shadow := input
            pop(shadow)
        }
    }
}`)
	fn := funcByName(t, db, "CommentIdentity", "f")
	defs := fn.AST.CollectDescendants(func(node *types.ASTNode) bool {
		return node.Kind == types.KindDeclVariable && node.GetAttributeBool("assembly")
	})
	if len(defs) != 1 || len(defs[0].Children) == 0 {
		t.Fatalf("Yul definition missing: %+v", defs)
	}
	refID := defs[0].Children[0].RefID
	if !strings.Contains(refID, ":shadow") {
		t.Fatalf("Yul RefID missing name: %q", refID)
	}
	parts := strings.Split(refID, ":")
	if len(parts) < 8 {
		t.Fatalf("Yul RefID shape = %q", refID)
	}
	nameStart, err := strconv.Atoi(parts[len(parts)-3])
	if err != nil {
		t.Fatalf("Yul name start in %q: %v", refID, err)
	}
	source := db.SourceFiles[fn.SourceFile].Content
	if source[nameStart:nameStart+len("shadow")] != "shadow" || strings.HasPrefix(source[nameStart:], "shadow in block") {
		t.Fatalf("Yul RefID selected comment text at %d: %q", nameStart, source[nameStart:nameStart+len("shadow")])
	}
}

func TestAssemblyShadowDeclarationRecoveryMasksDelimiterText(t *testing.T) {
	cases := []string{
		"let // shadow := fake\n shadow := input",
		"let /* shadow := fake */ shadow := input",
		"let 'shadow := fake' shadow := input",
		`let "shadow := fake" shadow := input`,
	}
	for _, declaration := range cases {
		file := "/tmp/YulMask.sol"
		db := types.NewDatabase()
		db.SourceFiles[file] = &types.SourceFile{Path: file, Content: declaration}
		builder := &ASTBuilder{db: db, function: &types.Function{SourceFile: file}}
		rng := ast.Range{0, len(declaration)}
		start, end, ok := builder.assemblyDeclarationNameSpan("shadow", &ast.Identifier{Name: "shadow"}, &rng)
		if !ok || declaration[start:end] != "shadow" || start != strings.LastIndex(declaration, "shadow") {
			t.Fatalf("declaration recovery selected masked text in %q: start=%d end=%d ok=%v", declaration, start, end, ok)
		}
	}
}

func TestSolidityLocalShadowingUsesDeclarationRefIDs(t *testing.T) {
	db := buildFixture(t, "../../test-data/core/semantic-hardening/access-paths.sol")
	fn := funcByName(t, db, "AccessPaths", "localShadow")
	xReads := fn.AST.CollectDescendants(func(node *types.ASTNode) bool {
		return node.Kind == types.KindExprIdentifier && node.Name == "x"
	})
	if len(xReads) < 5 {
		t.Fatalf("x binding count = %d, want at least 5", len(xReads))
	}
	var ids []string
	for _, node := range xReads {
		if node.RefID == "" {
			t.Fatalf("local x at byte %d lacks exact declaration RefID", node.StartByte)
		}
		ids = append(ids, node.RefID)
	}
	unique := map[string]bool{}
	for _, id := range ids {
		unique[id] = true
	}
	if len(unique) != 2 {
		t.Fatalf("shadowed Solidity locals resolved to %d identities, want 2: %v", len(unique), ids)
	}
	outerID := ids[0]
	innerID := ""
	for _, id := range ids {
		if id != outerID {
			innerID = id
			break
		}
	}
	if innerID == "" || ids[len(ids)-1] != outerID {
		t.Fatalf("scope exit did not restore outer local: %v", ids)
	}
	if !strings.Contains(outerID, ":local:") || !strings.Contains(innerID, ":local:") {
		t.Fatalf("local identities omit declaration provenance: outer=%q inner=%q", outerID, innerID)
	}
}

func collectBuilderNodes(root *types.ASTNode, predicate func(*types.ASTNode) bool) []*types.ASTNode {
	if root == nil {
		return nil
	}
	var nodes []*types.ASTNode
	if predicate(root) {
		nodes = append(nodes, root)
	}
	nodes = append(nodes, root.CollectDescendants(predicate)...)
	return nodes
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

func TestForStatementChildrenFollowRuntimeOrder(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ForOrder {
    function guard(uint256 i) internal pure returns (bool) { return i < 2; }
    function step(uint256 i) internal pure returns (uint256) { return i + 1; }
    function body(uint256) internal pure {}
    function run() external {
        for (uint256 i = 0; guard(i); i = step(i)) {
            body(i);
        }
    }
}`)
	fn := funcByName(t, db, "ForOrder", "run")
	loops := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtLoop &&
			n.GetAttributeString("loop_type") == "for"
	})
	if len(loops) != 1 {
		t.Fatalf("for loop count = %d, want 1", len(loops))
	}
	guard := directChildContainingCall(loops[0], "guard")
	body := directChildContainingCall(loops[0], "body")
	step := directChildContainingCall(loops[0], "step")
	if guard < 0 || body < 0 || step < 0 {
		t.Fatalf("indexes guard=%d body=%d step=%d; kinds=%v",
			guard, body, step, astKinds(loops[0]))
	}
	if !(guard < body && body < step) {
		t.Fatalf("order guard=%d body=%d step=%d, want guard < body < step",
			guard, body, step)
	}
	post := loops[0].Children[step]
	if post.Kind != types.KindStmtAssign {
		t.Fatalf("post kind = %q, want %q", post.Kind, types.KindStmtAssign)
	}
	if len(post.Children) != 2 || post.Children[0].Name != "i" ||
		post.Children[1].Name != "step" || !strings.HasPrefix(post.Children[1].Kind, "call.") {
		t.Fatalf("post children = %+v, want identifier i then call step", post.Children)
	}
	stepCall := post.Children[1]
	if stepCall.StartLine == 0 || stepCall.EndLine == 0 || stepCall.EndByte <= stepCall.StartByte {
		t.Fatalf("post call span = line %d:%d bytes [%d,%d), want real source span",
			stepCall.StartLine, stepCall.EndLine, stepCall.StartByte, stepCall.EndByte)
	}
}

func directChildContainingCall(parent *types.ASTNode, name string) int {
	for i, child := range parent.Children {
		if child.Name == name && strings.HasPrefix(child.Kind, "call.") {
			return i
		}
		if child.FindDescendant(func(n *types.ASTNode) bool {
			return n.Name == name && strings.HasPrefix(n.Kind, "call.")
		}) != nil {
			return i
		}
	}
	return -1
}

func TestForStatementOptionalClausesBuildSafely(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OptionalFor {
    function run(uint256 i) external {
        for (;;) { break; }
        for (; i < 1;) { i++; }
        for (uint256 j = 0;; j++) { break; }
    }
}`)
	fn := funcByName(t, db, "OptionalFor", "run")
	loops := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtLoop &&
			n.GetAttributeString("loop_type") == "for"
	})
	if len(loops) != 3 {
		t.Fatalf("for loop count = %d, want 3", len(loops))
	}
	for i, loop := range loops {
		for j, child := range loop.Children {
			if child == nil {
				t.Fatalf("for loop %d child %d is nil", i, j)
			}
		}
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
