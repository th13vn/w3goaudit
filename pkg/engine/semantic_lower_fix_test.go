package engine

import (
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSemanticLowerTupleAssignmentsKeepLaneCorrespondence(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	assignments := collectNodes(fn.AST, func(node *types.ASTNode) bool {
		return node.Kind == types.KindStmtAssign && semanticAttributeInt(node, "tuple_arity") > 1
	})
	if len(assignments) < 4 {
		t.Fatalf("tuple assignment count = %d, want at least 4", len(assignments))
	}
	for _, assignment := range assignments {
		lhsCount := semanticAttributeInt(assignment, "assignment_lhs_count")
		indexes := lowered.ByNode[assignment]
		if len(indexes) != lhsCount {
			t.Fatalf("assignment at byte %d emitted %d operations, want %d", assignment.StartByte, len(indexes), lhsCount)
		}
		for lane, opIndex := range indexes {
			op := lowered.Operations[opIndex]
			if len(op.Writes) != 1 || len(op.Inputs) != 1 || op.Inputs[0].Path == nil {
				t.Fatalf("lane %d is not a self-contained write/input pair: %+v", lane, op)
			}
			wantPosition := semanticAttributeInt(assignment.Children[lane], "tuple_index")
			segments := op.Inputs[0].Path.Segments
			if len(segments) != 1 || segments[0].Kind != segmentTuple || segments[0].Index != wantPosition {
				t.Fatalf("lane %d position = %+v, want tuple position %d", lane, segments, wantPosition)
			}
			if pathRootName(op.Writes[0]) != assignment.Children[lane].Name {
				t.Fatalf("lane %d write = %q, want %q", lane, pathRootName(op.Writes[0]), assignment.Children[lane].Name)
			}
		}
	}
}

func TestSemanticLowerCacheIncludesRuntimeContract(t *testing.T) {
	db, fn, base, left, right := runtimeContextDatabase()
	analyzer := newSemanticAnalyzer(db)
	leftLowered := analyzer.lowerFunction(fn, left)
	rightLowered := analyzer.lowerFunction(fn, right)
	if leftLowered == rightLowered || leftLowered.Contract != left || rightLowered.Contract != right {
		t.Fatalf("runtime contexts shared stale lowering: left=%p/%p right=%p/%p", leftLowered, leftLowered.Contract, rightLowered, rightLowered.Contract)
	}
	if leftLowered.Operations[0].Provenance.ContractID != left.ID || rightLowered.Operations[0].Provenance.ContractID != right.ID {
		t.Fatalf("runtime contract provenance stale: left=%+v right=%+v", leftLowered.Operations[0].Provenance, rightLowered.Operations[0].Provenance)
	}
	owner := analyzer.lowerFunction(fn, nil)
	if owner.Contract != base || owner.Operations[0].Provenance.ContractID != base.ID {
		t.Fatalf("nil runtime contract did not resolve exact owner: %+v", owner.Operations[0].Provenance)
	}
}

func TestSemanticLowerLegacyFunctionUsesExactOwnerFallback(t *testing.T) {
	db, fn, base, _, _ := runtimeContextDatabase()
	legacy := *fn
	legacy.SourceFile = ""
	legacy.AST = fn.AST
	lowered := newSemanticAnalyzer(db).lowerFunction(&legacy, nil)
	if lowered.Contract != base || lowered.Operations[0].Provenance.File != base.SourceFile || lowered.Operations[0].Provenance.ContractID != base.ID {
		t.Fatalf("legacy owner fallback is not exact: contract=%p provenance=%+v", lowered.Contract, lowered.Operations[0].Provenance)
	}
}

func runtimeContextDatabase() (*types.Database, *types.Function, *types.Contract, *types.Contract, *types.Contract) {
	db := types.NewDatabase()
	file := "/tmp/Runtime.sol"
	read := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "value", RefID: file + "#Base.f.value", RefKind: "parameter"}
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(read)
	fn := &types.Function{Name: "f", Selector: "f(uint256)", ContractName: "Base", SourceFile: file, AST: root}
	base := &types.Contract{ID: types.MakeContractID(file, "Base"), Name: "Base", SourceFile: file, Functions: []*types.Function{fn}}
	left := &types.Contract{ID: types.MakeContractID(file, "Left"), Name: "Left", SourceFile: file, LinearizedBaseIDs: []string{types.MakeContractID(file, "Left"), base.ID}}
	right := &types.Contract{ID: types.MakeContractID(file, "Right"), Name: "Right", SourceFile: file, LinearizedBaseIDs: []string{types.MakeContractID(file, "Right"), base.ID}}
	db.Contracts[base.ID], db.Contracts[left.ID], db.Contracts[right.ID] = base, left, right
	return db, fn, base, left, right
}

func TestSemanticLowerPersistentSlotsAreContractScoped(t *testing.T) {
	db := types.NewDatabase()
	contract := &types.Contract{ID: "/tmp/Slots.sol#Slots", Name: "Slots", SourceFile: "/tmp/Slots.sol"}
	db.Contracts[contract.ID] = contract
	store := assemblySlotFunction("store", types.KindAsmSstore, numericLiteral("5"), contract)
	load := assemblySlotFunction("load", types.KindAsmSload, numericLiteral("5"), contract)
	storePath := persistentPath(t, newSemanticAnalyzer(db).lowerFunction(store, contract), semanticOpWrite)
	loadPath := persistentPath(t, newSemanticAnalyzer(db).lowerFunction(load, contract), semanticOpRead)
	if !storePath.Equal(loadPath) {
		t.Fatalf("same contract slot differs across functions: store=%+v load=%+v", storePath, loadPath)
	}
	dynamicStore := assemblySlotFunction("storeDynamic", types.KindAsmSstore, &types.ASTNode{Kind: types.KindExprIdentifier, Name: "slot", RefID: contract.ID + ".storeDynamic.slot", RefKind: "parameter"}, contract)
	dynamicLoad := assemblySlotFunction("loadDynamic", types.KindAsmSload, &types.ASTNode{Kind: types.KindExprIdentifier, Name: "slot", RefID: contract.ID + ".loadDynamic.slot", RefKind: "parameter"}, contract)
	if persistentPath(t, newSemanticAnalyzer(db).lowerFunction(dynamicStore, contract), semanticOpWrite).Equal(persistentPath(t, newSemanticAnalyzer(db).lowerFunction(dynamicLoad, contract), semanticOpRead)) {
		t.Fatal("distinct dynamic slot RefIDs collapsed")
	}
}

func assemblySlotFunction(name, kind string, slot *types.ASTNode, contract *types.Contract) *types.Function {
	op := types.NewASTNode(kind)
	op.Name = strings.TrimPrefix(kind, "asm.")
	op.AddChild(slot)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(op)
	return &types.Function{Name: name, Selector: name + "()", ContractName: contract.Name, SourceFile: contract.SourceFile, AST: root}
}

func persistentPath(t *testing.T, lowered *semanticFunction, kind semanticOpKind) accessPath {
	t.Helper()
	for _, op := range lowered.Operations {
		if op.Kind == kind {
			paths := op.Reads
			if kind == semanticOpWrite {
				paths = op.Writes
			}
			for _, path := range paths {
				if path.Root.Storage == storagePersistent {
					return path
				}
			}
		}
	}
	t.Fatal("persistent path not found")
	return accessPath{}
}

func TestSemanticLowerTupleTemporaryUsesOccurrenceIdentity(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	roots := uniqueStrings(tupleRootsForCallName(lowered, "pair"))
	if len(roots) < 2 {
		t.Fatalf("distinct pair() occurrences share tuple root: %v", roots)
	}

	syntheticRoot := types.NewASTNode(types.KindDeclFunction)
	for i := 0; i < 2; i++ {
		assign := types.NewASTNode(types.KindStmtAssign)
		assign.SetAttribute("assignment_lhs_count", "2")
		assign.SetAttribute("tuple_arity", "2")
		for lane, name := range []string{"a", "b"} {
			lhs := types.NewASTNode(types.KindExprIdentifier)
			lhs.Name, lhs.RefID, lhs.RefKind = name, "/tmp/S.sol#S.f.-"+name, "local_var"
			lhs.SetAttribute("tuple_index", strconv.Itoa(lane))
			assign.AddChild(lhs)
		}
		assign.AddChild(&types.ASTNode{Kind: types.KindCallInternal, Name: "pair"})
		syntheticRoot.AddChild(assign)
	}
	syntheticFn := &types.Function{Name: "f", Selector: "f()", ContractName: "S", SourceFile: "/tmp/S.sol", AST: syntheticRoot}
	syntheticContract := &types.Contract{ID: "/tmp/S.sol#S", Name: "S", SourceFile: "/tmp/S.sol"}
	syntheticDB := types.NewDatabase()
	syntheticDB.Contracts[syntheticContract.ID] = syntheticContract
	synthetic := newSemanticAnalyzer(syntheticDB).lowerFunction(syntheticFn, syntheticContract)
	syntheticRoots := uniqueStrings(tupleRootsForCallName(synthetic, "pair"))
	if len(syntheticRoots) != 2 || syntheticRoots[0] == syntheticRoots[1] {
		t.Fatalf("location-less occurrences share tuple root: %v", syntheticRoots)
	}
}

func uniqueStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func tupleRootsForCallName(lowered *semanticFunction, name string) []string {
	var roots []string
	for _, op := range lowered.Operations {
		if op.Provenance.Node != nil && op.Provenance.Node.Kind == types.KindStmtAssign {
			assignment := op.Provenance.Node
			lhsCount, ok := semanticAttributeIntExact(assignment, "assignment_lhs_count")
			if !ok || lhsCount < 0 || lhsCount >= len(assignment.Children) {
				continue
			}
			matchedRHS := false
			for _, rhs := range assignment.Children[lhsCount:] {
				if rhs != nil && rhs.Name == name && strings.HasPrefix(rhs.Kind, "call.") {
					matchedRHS = true
					break
				}
			}
			if !matchedRHS {
				continue
			}
			for _, input := range op.Inputs {
				if input.Path != nil && strings.Contains(input.Path.Root.RefID, ":tuple:") {
					roots = append(roots, input.Path.Root.RefID)
					break
				}
			}
		}
	}
	return roots
}

func TestSemanticLowerNestedEffectsEmitOnceInPostorder(t *testing.T) {
	baseCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "base"}
	indexCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "index"}
	index := types.NewASTNode(types.KindExprIndexAccess)
	index.AddChildren(baseCall, indexCall)
	inc := types.NewASTNode(types.KindExprUnaryOp)
	inc.SetAttribute("operator", "++")
	inc.AddChild(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "x", RefID: "/tmp/E.sol#E.f.x", RefKind: "parameter"})
	outer := types.NewASTNode(types.KindCallInternal)
	outer.Name = "sink"
	outer.AddChildren(index, inc)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(outer)
	fn := &types.Function{Name: "f", Selector: "f(uint256)", ContractName: "E", SourceFile: "/tmp/E.sol", AST: root}
	contract := &types.Contract{ID: "/tmp/E.sol#E", Name: "E", SourceFile: "/tmp/E.sol"}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	for _, node := range []*types.ASTNode{baseCall, indexCall, inc, outer} {
		if got := len(lowered.ByNode[node]); got != 1 {
			t.Fatalf("effect %s emitted %d times, want 1", node.Name+node.GetAttributeString("operator"), got)
		}
	}
	baseIndex := lowered.ByNode[baseCall][0]
	indexIndex := lowered.ByNode[indexCall][0]
	incIndex := lowered.ByNode[inc][0]
	outerIndex := lowered.ByNode[outer][0]
	if !(baseIndex < indexIndex && indexIndex < incIndex && incIndex < outerIndex) {
		t.Fatalf("not deterministic postorder: base=%d index=%d inc=%d outer=%d", baseIndex, indexIndex, incIndex, outerIndex)
	}
}

func TestSemanticLowerFailsClosedForMissingExactFacts(t *testing.T) {
	db := types.NewDatabase()
	analyzer := newSemanticAnalyzer(db)
	root := types.NewASTNode(types.KindDeclFunction)
	missing := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "shadowed", RefKind: "local_var"}
	badMember := &types.ASTNode{Kind: types.KindExprMemberAccess, Name: "field"}
	badAssign := types.NewASTNode(types.KindStmtAssign)
	badAssign.AddChildren(badMember, numericLiteral("1"))
	missingTuple := types.NewASTNode(types.KindStmtAssign)
	missingTuple.SetAttribute("assignment_lhs_count", "2")
	missingTuple.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "a", RefID: "/tmp/Missing.sol#C.f.-a"}, &types.ASTNode{Kind: types.KindExprIdentifier, Name: "b", RefID: "/tmp/Missing.sol#C.f.-b"}, &types.ASTNode{Kind: types.KindCallInternal, Name: "pair"})
	missingDeclarationCount := types.NewASTNode(types.KindDeclVariable)
	missingDeclarationCount.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "x", RefID: "/tmp/Missing.sol#C.f.-x"}, numericLiteral("1"))
	nestedMissing := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "nested", RefKind: "local_var"}
	callWithMissing := types.NewASTNode(types.KindCallInternal)
	callWithMissing.Name = "sink"
	callWithMissing.AddChild(nestedMissing)
	root.AddChildren(missing, badAssign, missingTuple, missingDeclarationCount, callWithMissing)
	fn := &types.Function{Name: "f", Selector: "f()", ContractName: "C", SourceFile: "/tmp/Missing.sol", AST: root}
	contract := &types.Contract{ID: "/tmp/Missing.sol#C", Name: "C", SourceFile: "/tmp/Missing.sol"}
	db.Contracts[contract.ID] = contract
	lowered := analyzer.lowerFunction(fn, contract)
	if len(lowered.ByNode[missing]) != 1 || lowered.Operations[lowered.ByNode[missing][0]].Kind != semanticOpUnknown {
		t.Fatalf("missing RefID did not fail closed: %+v", lowered.ByNode[missing])
	}
	if len(lowered.ByNode[badAssign]) == 0 || lowered.Operations[lowered.ByNode[badAssign][0]].Kind != semanticOpUnknown {
		t.Fatalf("unrepresentable lvalue did not fail closed: %+v", lowered.ByNode[badAssign])
	}
	for _, node := range []*types.ASTNode{missingTuple, missingDeclarationCount} {
		if len(lowered.ByNode[node]) == 0 || lowered.Operations[lowered.ByNode[node][0]].Kind != semanticOpUnknown {
			t.Fatalf("missing assignment metadata did not fail closed for %s", node.Kind)
		}
	}
	if ops := operationForNode(t, lowered, callWithMissing); len(ops) != 1 || ops[0].Kind != semanticOpUnknown {
		t.Fatalf("operation with nested missing RefID did not fail closed: %+v", ops)
	}
	msg := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "msg"}
	if _, ok := analyzer.pathForNode(msg, lowerContext{ScopeID: "scope"}); !ok {
		t.Fatal("canonical msg root was rejected")
	}
	nilAnalyzer := newSemanticAnalyzer(nil)
	nilLowered := nilAnalyzer.lowerFunction(fn, nil)
	if len(nilLowered.Operations) == 0 || len(nilAnalyzer.diagnostics) == 0 {
		t.Fatal("nil-database lowering did not retain fail-closed diagnostic")
	}
}

func TestSemanticLowerParsesSolidityIntegerConstants(t *testing.T) {
	cases := []struct {
		value, unit, class, want string
		ok                       bool
	}{
		{"03", "", "numeric_decimal", "3", true},
		{"1_000", "", "numeric_decimal", "1000", true},
		{"0x03", "", "numeric_hex", "3", true},
		{"1e2", "", "numeric_decimal", "100", true},
		{"1.5e2", "", "numeric_decimal", "150", true},
		{"1.5", "", "numeric_decimal", "", false},
		{"7", "wei", "numeric_decimal", "7", true},
		{"1", "gwei", "numeric_decimal", "1000000000", true},
		{"2", "ether", "numeric_decimal", "2000000000000000000", true},
		{"9", "seconds", "numeric_decimal", "9", true},
		{"2", "minutes", "numeric_decimal", "120", true},
		{"2", "hours", "numeric_decimal", "7200", true},
		{"2", "days", "numeric_decimal", "172800", true},
		{"1", "weeks", "numeric_decimal", "604800", true},
	}
	for _, tc := range cases {
		node := numericLiteral(tc.value)
		node.SetAttribute("literal_class", tc.class)
		if tc.class == "numeric_hex" {
			node.SetAttribute("subtype", "hex")
		}
		if tc.unit != "" {
			node.SetAttribute("subdenomination", tc.unit)
		}
		segment, ok := literalIndexSegment(node)
		if ok != tc.ok || ok && segment.Key != tc.want {
			t.Errorf("literal %s %s = key %q ok=%v, want %q ok=%v", tc.value, tc.unit, segment.Key, ok, tc.want, tc.ok)
		}
	}
	hexString := &types.ASTNode{Kind: types.KindExprLiteral, Value: "03", Attributes: map[string]interface{}{"subtype": "hex", "literal_class": "hex_string"}}
	if _, ok := literalIndexSegment(hexString); ok {
		t.Fatal("hex string became a numeric fixed index")
	}
}

func numericLiteral(value string) *types.ASTNode {
	return &types.ASTNode{Kind: types.KindExprLiteral, Value: value, Attributes: map[string]interface{}{"subtype": "number", "literal_class": "numeric_decimal"}}
}

func TestSemanticLowerValuesOwnIndependentPaths(t *testing.T) {
	node := &types.ASTNode{Kind: types.KindExprMemberAccess, Name: "field"}
	node.AddChild(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "value", RefID: "/tmp/O.sol#O.f.value", RefKind: "parameter"})
	value := newSemanticAnalyzer(nil).valueForNode(node, lowerContext{ScopeID: "/tmp/O.sol#O.f()"})
	if value.Path == nil || len(value.Sources) != 1 {
		t.Fatalf("value paths missing: %+v", value)
	}
	value.Path.Segments[0].Name = "changed"
	if value.Sources[0].Segments[0].Name != "field" {
		t.Fatal("Path and Sources share segment backing storage")
	}
}

func TestSemanticLowerClassifiesAllTerminals(t *testing.T) {
	root := types.NewASTNode(types.KindDeclFunction)
	revertNode := &types.ASTNode{Kind: types.KindCheckRevert, Name: "revert"}
	selfdestruct := &types.ASTNode{Kind: types.KindCallBuiltinSelfdestruct, Name: "selfdestruct"}
	stop := &types.ASTNode{Kind: types.KindAsmOperation, Name: "stop", Attributes: map[string]interface{}{"assembly": true}}
	invalid := &types.ASTNode{Kind: types.KindAsmOperation, Name: "invalid", Attributes: map[string]interface{}{"assembly": true}}
	requireNode := &types.ASTNode{Kind: types.KindCheckRequire, Name: "require"}
	root.AddChildren(revertNode, selfdestruct, stop, invalid, requireNode)
	fn := &types.Function{Name: "f", Selector: "f()", ContractName: "T", SourceFile: "/tmp/T.sol", AST: root}
	contract := &types.Contract{ID: "/tmp/T.sol#T", Name: "T", SourceFile: "/tmp/T.sol"}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	for _, node := range []*types.ASTNode{revertNode, selfdestruct, stop, invalid} {
		ops := operationForNode(t, lowered, node)
		if len(ops) != 1 || ops[0].Kind != semanticOpTerminal {
			t.Fatalf("%s lowered as %+v, want terminal", node.Name, ops)
		}
	}
	if ops := operationForNode(t, lowered, requireNode); len(ops) != 1 || ops[0].Kind != semanticOpCheck {
		t.Fatalf("require lowered as %+v, want check", ops)
	}
}

func TestSemanticUnsupportedDiagnosticsUseExactSitesAndSortedOrder(t *testing.T) {
	db := types.NewDatabase()
	contract := &types.Contract{ID: "/tmp/U.sol#U", Name: "U", SourceFile: "/tmp/U.sol"}
	db.Contracts[contract.ID] = contract
	makeFn := func(name string, starts ...int) *types.Function {
		root := types.NewASTNode(types.KindDeclFunction)
		for _, start := range starts {
			root.AddChild(&types.ASTNode{Kind: "expr.future", StartLine: 7, StartByte: start, EndByte: start + 1})
		}
		return &types.Function{Name: name, Selector: name + "()", ContractName: "U", SourceFile: contract.SourceFile, AST: root}
	}
	analyzer := newSemanticAnalyzer(db)
	analyzer.lowerFunction(makeFn("z", 20), contract)
	analyzer.lowerFunction(makeFn("a", 10, 12), contract)
	var diagnostics []types.Diagnostic
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticSemanticUnsupported {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	if len(diagnostics) != 3 {
		t.Fatalf("unsupported diagnostic count = %d, want 3: %+v", len(diagnostics), diagnostics)
	}
	messages := []string{diagnostics[0].Message, diagnostics[1].Message, diagnostics[2].Message}
	if !sort.StringsAreSorted(messages) || !strings.Contains(messages[0], "byte") {
		t.Fatalf("diagnostics lack stable site identity/order: %v", messages)
	}
}

func TestSemanticOperationFingerprintCoversCompleteModel(t *testing.T) {
	node := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "x", RefID: "x"}
	op := &semanticOp{ID: 0, Kind: semanticOpRead, Provenance: semanticRef{FunctionID: "f", ContractID: "c", File: "file", Node: node, OpIndex: 0}, Reads: []accessPath{{Root: accessRoot{RefID: "x"}}}, Inputs: []semanticValue{{State: controlDerived, Type: types.TypeInfo{Name: "uint256", Kind: types.TypeKindPrimitive}, Sources: []accessPath{{Root: accessRoot{RefID: "x"}}}, Provenance: semanticRef{Node: node}}}}
	lowered := &semanticFunction{Operations: []*semanticOp{op}, ByNode: map[*types.ASTNode][]int{node: {0}}}
	before := semanticOperationFingerprint(lowered)
	op.Inputs[0].State = controlFixed
	after := semanticOperationFingerprint(lowered)
	if reflect.DeepEqual(before, after) {
		t.Fatal("fingerprint omitted semantic input state")
	}
}

func TestSemanticLowerInheritedRuntimeSourceCacheParity(t *testing.T) {
	db, fn, _, left, right := runtimeContextDatabase()
	freshAnalyzer := newSemanticAnalyzer(db)
	freshLeft := semanticOperationFingerprint(freshAnalyzer.lowerFunction(fn, left))
	freshRight := semanticOperationFingerprint(freshAnalyzer.lowerFunction(fn, right))
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal runtime database: %v", err)
	}
	var cached types.Database
	if err := json.Unmarshal(data, &cached); err != nil {
		t.Fatalf("unmarshal runtime database: %v", err)
	}
	cached.RestoreASTParents()
	cachedBase := cached.GetContractByID("/tmp/Runtime.sol#Base")
	cachedLeft := cached.GetContractByID(left.ID)
	cachedRight := cached.GetContractByID(right.ID)
	if cachedBase == nil || len(cachedBase.Functions) != 1 || cachedLeft == nil || cachedRight == nil {
		t.Fatalf("cached runtime objects missing")
	}
	cachedAnalyzer := newSemanticAnalyzer(&cached)
	if got := semanticOperationFingerprint(cachedAnalyzer.lowerFunction(cachedBase.Functions[0], cachedLeft)); !reflect.DeepEqual(got, freshLeft) {
		t.Fatalf("left runtime cache parity failed:\nfresh=%v\ncached=%v", freshLeft, got)
	}
	if got := semanticOperationFingerprint(cachedAnalyzer.lowerFunction(cachedBase.Functions[0], cachedRight)); !reflect.DeepEqual(got, freshRight) {
		t.Fatalf("right runtime cache parity failed:\nfresh=%v\ncached=%v", freshRight, got)
	}
}
