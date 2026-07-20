package engine

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSemanticLowerSingleLaneTupleDestructuringSourceCacheParity(t *testing.T) {
	assert := func(t *testing.T, db *types.Database) []string {
		t.Helper()
		fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "singleLaneHoles")
		lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
		assignments := collectNodes(fn.AST, func(node *types.ASTNode) bool {
			arity, ok := semanticAttributeIntExact(node, "tuple_arity")
			lhsCount, lhsOK := semanticAttributeIntExact(node, "assignment_lhs_count")
			return node.Kind == types.KindStmtAssign && ok && lhsOK && arity > 1 && lhsCount == 1
		})
		if len(assignments) != 4 {
			all := collectNodes(fn.AST, func(node *types.ASTNode) bool { return node.Kind == types.KindStmtAssign })
			var facts []string
			for _, assignment := range all {
				facts = append(facts, assignment.GetAttributeString("tuple_arity")+"/"+assignment.GetAttributeString("assignment_lhs_count"))
			}
			t.Fatalf("single-lane tuple assignment count = %d, want 4; assignments=%v", len(assignments), facts)
		}
		fingerprints := make([]string, 0, len(assignments))
		seen := map[int]bool{}
		sourcedLane := false
		for _, assignment := range assignments {
			indexes := lowered.ByNode[assignment]
			if len(indexes) != 1 {
				t.Fatalf("single-lane assignment at byte %d emitted %d operations, want 1", assignment.StartByte, len(indexes))
			}
			op := lowered.Operations[indexes[0]]
			if op.Kind != semanticOpAssign || len(op.Writes) != 1 || len(op.Inputs) != 1 || op.Inputs[0].Path == nil {
				t.Fatalf("single-lane destructure is not one exact pair: %+v", op)
			}
			position, ok := semanticAttributeIntExact(assignment.Children[0], "tuple_index")
			if !ok {
				t.Fatalf("single-lane LHS lacks tuple_index: %+v", assignment.Children[0])
			}
			segments := op.Inputs[0].Path.Segments
			if len(segments) != 1 || segments[0].Kind != segmentTuple || segments[0].Index != position {
				t.Fatalf("LHS position %d mapped to input %+v", position, segments)
			}
			if pathRootName(op.Writes[0]) != assignment.Children[0].Name {
				t.Fatalf("write %q does not match LHS %q", pathRootName(op.Writes[0]), assignment.Children[0].Name)
			}
			if !reflect.DeepEqual(accessPathKeys(op.Reads), accessPathKeys(op.Inputs[0].Sources)) {
				t.Fatalf("lane sources differ from reads: reads=%v sources=%v", op.Reads, op.Inputs[0].Sources)
			}
			if len(op.Inputs[0].Sources) == 1 && pathRootName(op.Inputs[0].Sources[0]) == "c" {
				sourcedLane = true
			}
			seen[position] = true
			fingerprints = append(fingerprints, semanticOperationFingerprint(&semanticFunction{Function: lowered.Function, Contract: lowered.Contract, Operations: []*semanticOp{op}, ByNode: map[*types.ASTNode][]int{assignment: {0}}})...)
		}
		if !seen[0] || !seen[1] || !seen[2] {
			t.Fatalf("single-lane positions = %v, want 0,1,2", seen)
		}
		if !sourcedLane {
			t.Fatal("single-lane tuple literal did not preserve the selected lane source")
		}
		return fingerprints
	}

	freshDB := buildSemanticFixture(t, "access-paths.sol")
	fresh := assert(t, freshDB)
	raw, err := json.Marshal(freshDB)
	if err != nil {
		t.Fatal(err)
	}
	var cached types.Database
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatal(err)
	}
	cached.RestoreASTParents()
	if got := assert(t, &cached); !reflect.DeepEqual(got, fresh) {
		t.Fatalf("single-lane source/cache parity failed:\nfresh=%v\ncached=%v", fresh, got)
	}
}

func TestSemanticLowerMalformedNestedTupleValuesFailClosed(t *testing.T) {
	file := "/tmp/NestedTuple.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "NestedTuple"), Name: "NestedTuple", SourceFile: file}
	makeIdentifier := func(name string, position int) *types.ASTNode {
		node := types.NewASTNode(types.KindExprIdentifier)
		node.Name, node.RefID, node.RefKind = name, contract.ID+".f.-"+name, "local_var"
		node.SetAttribute("tuple_index", position)
		return node
	}
	assertMalformed := func(t *testing.T, enclosing *types.ASTNode, malformed *types.ASTNode, nestedEffect *types.ASTNode) {
		t.Helper()
		root := types.NewASTNode(types.KindDeclFunction)
		root.AddChild(enclosing)
		fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
		db := types.NewDatabase()
		db.Contracts[contract.ID] = contract
		lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
		ops := operationForNode(t, lowered, enclosing)
		if len(ops) != 1 || ops[0].Kind != semanticOpUnknown {
			t.Fatalf("malformed tuple consumer remained concrete: %+v", ops)
		}
		if nestedEffect != nil {
			nestedOps := operationForNode(t, lowered, nestedEffect)
			if len(nestedOps) != 1 || nestedOps[0].Kind != semanticOpCall {
				t.Fatalf("nested effect was not preserved: %+v", nestedOps)
			}
		}
		diagnostics := semanticUnsupportedOnly(db.Diagnostics)
		if len(diagnostics) != 1 || diagnostics[0].Symbol != malformed.Kind {
			t.Fatalf("malformed tuple diagnostics = %+v, want one tuple diagnostic", diagnostics)
		}
	}

	callTuple := types.NewASTNode(types.KindExprTuple)
	nestedCall := types.NewASTNode(types.KindCallInternal)
	nestedCall.Name = "sideEffect"
	nestedCall.SetAttribute("tuple_index", 0)
	callTuple.AddChild(nestedCall)
	outerCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "sink"}
	outerCall.AddChild(callTuple)
	assertMalformed(t, outerCall, callTuple, nestedCall)

	checkTuple := types.NewASTNode(types.KindExprTuple)
	checkTuple.SetAttribute("tuple_arity", "2")
	checkTuple.AddChildren(makeIdentifier("left", 0), makeIdentifier("right", 0))
	check := &types.ASTNode{Kind: types.KindCheckRequire, Name: "require"}
	check.AddChild(checkTuple)
	assertMalformed(t, check, checkTuple, nil)

	validTuple := types.NewASTNode(types.KindExprTuple)
	validTuple.SetAttribute("tuple_arity", "3")
	validTuple.AddChildren(makeIdentifier("first", 0), makeIdentifier("third", 2))
	validCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "consume"}
	validCall.AddChild(validTuple)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(validCall)
	fn := &types.Function{Name: "valid", Selector: "valid()", ContractName: contract.Name, SourceFile: file, AST: root}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	op := operationForNode(t, lowered, validCall)[0]
	if op.Kind != semanticOpCall || len(op.Inputs) != 2 || op.Inputs[0].Path == nil || op.Inputs[1].Path == nil || op.Inputs[0].Path.Segments[0].Index != 0 || op.Inputs[1].Path.Segments[0].Index != 2 {
		t.Fatalf("valid tuple argument lost populated positions: %+v", op)
	}
	if len(semanticUnsupportedOnly(db.Diagnostics)) != 0 {
		t.Fatalf("valid tuple argument emitted unsupported diagnostics: %+v", db.Diagnostics)
	}
}

func accessPathKeys(paths []accessPath) []string {
	keys := make([]string, len(paths))
	for i := range paths {
		keys[i] = paths[i].Key()
	}
	return keys
}
