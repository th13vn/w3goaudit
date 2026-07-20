package engine

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSemanticLowerRejectsSelectorlessOverloadsWithoutCacheCollision(t *testing.T) {
	db := types.NewDatabase()
	contract := &types.Contract{ID: "/tmp/Legacy.sol#Legacy", Name: "Legacy", SourceFile: "/tmp/Legacy.sol"}
	db.Contracts[contract.ID] = contract
	makeFn := func(start int, refID string) *types.Function {
		root := &types.ASTNode{Kind: types.KindDeclFunction, StartByte: start, EndByte: start + 10}
		root.AddChild(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "input", RefKind: "parameter", RefID: refID})
		return &types.Function{Name: "f", ContractName: "Legacy", SourceFile: contract.SourceFile, StartByte: start, EndByte: start + 10, AST: root}
	}
	first := makeFn(10, contract.ID+".f.uint")
	second := makeFn(30, contract.ID+".f.address")
	analyzer := newSemanticAnalyzer(db)
	firstLowered := analyzer.lowerFunction(first, contract)
	secondLowered := analyzer.lowerFunction(second, contract)
	for fn, lowered := range map[*types.Function]*semanticFunction{first: firstLowered, second: secondLowered} {
		if lowered.Function != fn || len(lowered.Operations) != 1 || lowered.Operations[0].Kind != semanticOpUnknown {
			t.Fatalf("selector-less overload did not fail closed independently: fn=%p lowered=%+v", fn, lowered)
		}
	}
	if firstLowered.Operations[0].Provenance.Node == secondLowered.Operations[0].Provenance.Node {
		t.Fatal("selector-less overloads reused one cached lowering")
	}
}

func TestSemanticLowerValidatesRuntimeAndOwnerIdentities(t *testing.T) {
	db, fn, base, left, _ := runtimeContextDatabase()
	tests := []struct {
		name    string
		fn      *types.Function
		runtime *types.Contract
		db      *types.Database
	}{
		{name: "malformed runtime id", fn: fn, runtime: &types.Contract{ID: "/tmp/Wrong.sol#Left", Name: left.Name, SourceFile: left.SourceFile}, db: db},
		{name: "foreign runtime object", fn: fn, runtime: &types.Contract{ID: left.ID, Name: left.Name, SourceFile: left.SourceFile}, db: db},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lowered := newSemanticAnalyzer(tc.db).lowerFunction(tc.fn, tc.runtime)
			if lowered.Contract != nil || len(lowered.Operations) != 1 || lowered.Operations[0].Kind != semanticOpUnknown {
				t.Fatalf("invalid runtime identity was trusted: %+v", lowered.Operations)
			}
		})
	}

	ambiguous := types.NewDatabase()
	for _, file := range []string{"/tmp/A.sol", "/tmp/B.sol"} {
		contract := &types.Contract{ID: types.MakeContractID(file, "Base"), Name: "Base", SourceFile: file}
		ambiguous.Contracts[contract.ID] = contract
	}
	legacy := *fn
	legacy.SourceFile = ""
	legacy.ContractName = "Base"
	runtime := ambiguous.GetContractByID("/tmp/A.sol#Base")
	lowered := newSemanticAnalyzer(ambiguous).lowerFunction(&legacy, runtime)
	if lowered.Contract != nil || len(lowered.Operations) != 1 || lowered.Operations[0].Kind != semanticOpUnknown {
		t.Fatalf("ambiguous legacy owner lookup used runtime as owner: %+v", lowered.Operations)
	}

	valid := newSemanticAnalyzer(db).lowerFunction(fn, left)
	if valid.Contract != left || valid.Operations[0].Provenance.File != base.SourceFile || valid.Operations[0].Provenance.ContractID != left.ID {
		t.Fatalf("valid inherited provenance split changed: contract=%p provenance=%+v", valid.Contract, valid.Operations[0].Provenance)
	}
}

func TestSemanticLowerRejectsInexactDynamicExpressionAliases(t *testing.T) {
	file := "/tmp/Alias.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "Alias"), Name: "Alias", SourceFile: file}
	makeBase := func(name, kind string) *types.ASTNode {
		return &types.ASTNode{Kind: types.KindExprIdentifier, Name: name, RefID: contract.ID + ".f." + name, RefKind: "local_var", Attributes: map[string]interface{}{"type_kind": kind}}
	}
	missing := func(name string) *types.ASTNode {
		return &types.ASTNode{Kind: types.KindExprIdentifier, Name: name, RefKind: "local_var"}
	}
	arrayIndex := types.NewASTNode(types.KindExprIndexAccess)
	arrayIndex.AddChildren(makeBase("values", types.TypeKindArray), missing("i"))
	mappingIndex := types.NewASTNode(types.KindExprIndexAccess)
	mappingIndex.AddChildren(makeBase("balances", types.TypeKindMapping), missing("key"))
	sstore := &types.ASTNode{Kind: types.KindAsmSstore, Name: "sstore"}
	sstore.AddChildren(missing("slot"), numericLiteral("1"))
	mstore := &types.ASTNode{Kind: types.KindAsmOperation, Name: "mstore", Attributes: map[string]interface{}{"assembly": true}}
	mstore.AddChildren(missing("offset"), numericLiteral("1"))
	yulMsg := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "msg", RefKind: "local_var", Attributes: map[string]interface{}{"assembly": true}}
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChildren(arrayIndex, mappingIndex, sstore, mstore, yulMsg)
	fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	for _, node := range []*types.ASTNode{arrayIndex, mappingIndex, sstore, mstore, yulMsg} {
		ops := operationForNode(t, lowered, node)
		if len(ops) != 1 || ops[0].Kind != semanticOpUnknown || len(ops[0].Reads) != 0 || len(ops[0].Writes) != 0 {
			t.Fatalf("inexact alias for %s produced concrete operation: %+v", node.Name+node.Kind, ops)
		}
	}
	if got := len(semanticUnsupportedOnly(db.Diagnostics)); got != 5 {
		t.Fatalf("unsupported diagnostics = %d, want one per inexact enclosing expression: %+v", got, db.Diagnostics)
	}

	msg := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "msg"}
	sender := types.NewASTNode(types.KindExprMemberAccess)
	sender.Name = "sender"
	sender.AddChild(msg)
	if path, ok := newSemanticAnalyzer(nil).pathForNode(sender, lowerContext{ScopeID: file + "#Alias.f()"}); !ok || path.Root.RefID != "environment:msg" {
		t.Fatalf("valid direct msg.sender path rejected: path=%+v ok=%v", path, ok)
	}
}

func TestSemanticLowerTupleMetadataIsStrictAndPositional(t *testing.T) {
	file := "/tmp/TupleStrict.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "TupleStrict"), Name: "TupleStrict", SourceFile: file}
	makeChild := func(name string, index any) *types.ASTNode {
		child := types.NewASTNode(types.KindExprIdentifier)
		child.Name, child.RefID, child.RefKind = name, contract.ID+".f.-"+name, "local_var"
		if index != nil {
			child.SetAttribute("tuple_index", index)
		}
		return child
	}
	cases := []struct {
		name  string
		arity any
		kids  []*types.ASTNode
	}{
		{name: "missing root arity", kids: []*types.ASTNode{makeChild("a", "0")}},
		{name: "missing index", arity: "1", kids: []*types.ASTNode{makeChild("a", nil)}},
		{name: "malformed index", arity: "1", kids: []*types.ASTNode{makeChild("a", "nope")}},
		{name: "non-integral cache index", arity: float64(1), kids: []*types.ASTNode{makeChild("a", 0.5)}},
		{name: "duplicate index", arity: "2", kids: []*types.ASTNode{makeChild("a", "0"), makeChild("b", "0")}},
		{name: "negative index", arity: "2", kids: []*types.ASTNode{makeChild("a", "-1")}},
		{name: "out of range index", arity: "2", kids: []*types.ASTNode{makeChild("a", "2")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tuple := types.NewASTNode(types.KindExprTuple)
			if tc.arity != nil {
				tuple.SetAttribute("tuple_arity", tc.arity)
			}
			tuple.AddChildren(tc.kids...)
			root := types.NewASTNode(types.KindDeclFunction)
			root.AddChild(tuple)
			fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
			db := types.NewDatabase()
			db.Contracts[contract.ID] = contract
			lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
			ops := operationForNode(t, lowered, tuple)
			if len(ops) != 1 || ops[0].Kind != semanticOpUnknown {
				t.Fatalf("malformed tuple metadata did not fail closed: %+v", ops)
			}
		})
	}

	tuple := types.NewASTNode(types.KindExprTuple)
	tuple.SetAttribute("tuple_arity", "3")
	tuple.AddChildren(makeChild("a", "0"), makeChild("c", "2"))
	ret := types.NewASTNode(types.KindStmtReturn)
	ret.AddChild(tuple)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(ret)
	fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	returnOp := operationForNode(t, lowered, ret)[0]
	if returnOp.Kind != semanticOpReturn || len(returnOp.Inputs) != 2 {
		t.Fatalf("tuple-hole return collapsed lanes: %+v", returnOp)
	}
	if returnOp.Inputs[0].Path == nil || returnOp.Inputs[1].Path == nil || returnOp.Inputs[0].Path.Segments[0].Index != 0 || returnOp.Inputs[1].Path.Segments[0].Index != 2 {
		t.Fatalf("tuple-hole return positions changed: %+v", returnOp.Inputs)
	}

	raw, err := json.Marshal(tuple)
	if err != nil {
		t.Fatal(err)
	}
	var cached types.ASTNode
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatal(err)
	}
	cachedReturn := types.NewASTNode(types.KindStmtReturn)
	cachedReturn.AddChild(&cached)
	cachedRoot := types.NewASTNode(types.KindDeclFunction)
	cachedRoot.AddChild(cachedReturn)
	cachedFn := &types.Function{Name: "cached", Selector: "cached()", ContractName: contract.Name, SourceFile: file, AST: cachedRoot}
	cachedLowered := newSemanticAnalyzer(db).lowerFunction(cachedFn, contract)
	cachedOp := operationForNode(t, cachedLowered, cachedReturn)[0]
	if cachedOp.Kind != semanticOpReturn || len(cachedOp.Inputs) != 2 {
		t.Fatalf("valid tuple metadata failed JSON round-trip: %s", raw)
	}

	assignmentCases := []struct {
		name      string
		rootArity any
		indexes   []any
	}{
		{name: "assignment missing root arity", indexes: []any{"0", "1"}},
		{name: "assignment missing index", rootArity: "2", indexes: []any{"0", nil}},
		{name: "assignment malformed index", rootArity: "2", indexes: []any{"0", "x"}},
		{name: "assignment duplicate index", rootArity: "2", indexes: []any{"0", "0"}},
		{name: "assignment out of range index", rootArity: "2", indexes: []any{"0", "2"}},
	}
	for _, tc := range assignmentCases {
		t.Run(tc.name, func(t *testing.T) {
			assignment := types.NewASTNode(types.KindStmtAssign)
			assignment.SetAttribute("assignment_lhs_count", "2")
			if tc.rootArity != nil {
				assignment.SetAttribute("tuple_arity", tc.rootArity)
			}
			assignment.AddChildren(makeChild("left", tc.indexes[0]), makeChild("right", tc.indexes[1]), &types.ASTNode{Kind: types.KindCallInternal, Name: "pair"})
			assignmentRoot := types.NewASTNode(types.KindDeclFunction)
			assignmentRoot.AddChild(assignment)
			assignmentFn := &types.Function{Name: "assignment", Selector: "assignment()", ContractName: contract.Name, SourceFile: file, AST: assignmentRoot}
			assignmentLowered := newSemanticAnalyzer(db).lowerFunction(assignmentFn, contract)
			ops := operationForNode(t, assignmentLowered, assignment)
			if len(ops) != 1 || ops[0].Kind != semanticOpUnknown {
				t.Fatalf("malformed assignment tuple metadata did not fail closed: %+v", ops)
			}
		})
	}
}

func TestSemanticUnsupportedDiagnosticsUseLocationlessOccurrencesAndCompleteKeys(t *testing.T) {
	base := types.Diagnostic{Code: types.DiagnosticSemanticUnsupported, Severity: types.DiagnosticWarning, Phase: "semantic", Message: "m", File: "f", Line: 1, ImportPath: "i", Symbol: "s", Incomplete: false}
	variants := []types.Diagnostic{base}
	for _, mutate := range []func(*types.Diagnostic){
		func(d *types.Diagnostic) { d.Severity = types.DiagnosticError },
		func(d *types.Diagnostic) { d.ImportPath = "other" },
		func(d *types.Diagnostic) { d.Incomplete = true },
	} {
		candidate := base
		mutate(&candidate)
		variants = append(variants, candidate)
	}
	keys := map[string]bool{}
	for _, diagnostic := range variants {
		keys[semanticDiagnosticKey(diagnostic)] = true
	}
	if len(keys) != len(variants) {
		t.Fatalf("diagnostic key omits serialized fields: %v", keys)
	}
	probeDB := types.NewDatabase()
	probeContract := &types.Contract{ID: "/tmp/Probe.sol#Probe", Name: "Probe", SourceFile: "/tmp/Probe.sol"}
	probeDB.Contracts[probeContract.ID] = probeContract
	probeNode := &types.ASTNode{Kind: "expr.future", StartByte: 10, EndByte: 11}
	probeRoot := types.NewASTNode(types.KindDeclFunction)
	probeRoot.AddChild(probeNode)
	probeFn := &types.Function{Name: "f", Selector: "f()", ContractName: probeContract.Name, SourceFile: probeContract.SourceFile, AST: probeRoot}
	newSemanticAnalyzer(probeDB).lowerFunction(probeFn, probeContract)
	probe := semanticUnsupportedOnly(probeDB.Diagnostics)
	if len(probe) != 1 {
		t.Fatalf("probe diagnostic count = %d, want 1", len(probe))
	}
	probe[0].Incomplete = false
	probeDB.Diagnostics = probe
	newSemanticAnalyzer(probeDB).lowerFunction(probeFn, probeContract)
	if len(semanticUnsupportedOnly(probeDB.Diagnostics)) != 2 {
		t.Fatalf("preexisting complete diagnostic suppressed required incomplete record: %+v", probeDB.Diagnostics)
	}

	makeDB := func(order []string) []string {
		db := types.NewDatabase()
		contract := &types.Contract{ID: "/tmp/Zero.sol#Zero", Name: "Zero", SourceFile: "/tmp/Zero.sol"}
		db.Contracts[contract.ID] = contract
		functions := map[string]*types.Function{}
		for _, name := range []string{"a", "z"} {
			root := types.NewASTNode(types.KindDeclFunction)
			root.AddChildren(&types.ASTNode{Kind: "expr.future"}, &types.ASTNode{Kind: "expr.future"})
			functions[name] = &types.Function{Name: name, Selector: name + "()", ContractName: contract.Name, SourceFile: contract.SourceFile, AST: root}
		}
		analyzer := newSemanticAnalyzer(db)
		for _, name := range order {
			analyzer.lowerFunction(functions[name], contract)
		}
		result := semanticDiagnosticFingerprint(semanticUnsupportedOnly(db.Diagnostics))
		if len(result) != 4 {
			t.Fatalf("location-less sibling diagnostics = %d, want 4: %v", len(result), result)
		}
		for _, fingerprint := range result {
			if !strings.Contains(fingerprint, "occurrence path") {
				t.Fatalf("location-less diagnostic lacks occurrence identity: %s", fingerprint)
			}
		}
		return result
	}
	forward := makeDB([]string{"a", "z"})
	reverse := makeDB([]string{"z", "a"})
	if !reflect.DeepEqual(forward, reverse) {
		t.Fatalf("diagnostic ordering depends on lowering order:\nforward=%v\nreverse=%v", forward, reverse)
	}
}

func TestSemanticLowerInheritedZeroOperationRuntimeSourceCacheParity(t *testing.T) {
	file := "/tmp/EmptyRuntime.sol"
	db := types.NewDatabase()
	root := types.NewASTNode(types.KindDeclFunction)
	fn := &types.Function{Name: "empty", Selector: "empty()", ContractName: "Base", SourceFile: file, AST: root}
	base := &types.Contract{ID: types.MakeContractID(file, "Base"), Name: "Base", SourceFile: file, Functions: []*types.Function{fn}}
	left := &types.Contract{ID: types.MakeContractID(file, "Left"), Name: "Left", SourceFile: file, LinearizedBaseIDs: []string{types.MakeContractID(file, "Left"), base.ID}}
	right := &types.Contract{ID: types.MakeContractID(file, "Right"), Name: "Right", SourceFile: file, LinearizedBaseIDs: []string{types.MakeContractID(file, "Right"), base.ID}}
	db.Contracts[base.ID], db.Contracts[left.ID], db.Contracts[right.ID] = base, left, right
	analyzer := newSemanticAnalyzer(db)
	freshLeft := semanticOperationFingerprint(analyzer.lowerFunction(fn, left))
	freshRight := semanticOperationFingerprint(analyzer.lowerFunction(fn, right))
	if reflect.DeepEqual(freshLeft, freshRight) {
		t.Fatal("zero-operation inherited runtime contexts collapsed")
	}
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	var cached types.Database
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatal(err)
	}
	cached.RestoreASTParents()
	cachedBase := cached.GetContractByID(base.ID)
	cachedLeft := cached.GetContractByID(left.ID)
	cachedRight := cached.GetContractByID(right.ID)
	if cachedBase == nil || len(cachedBase.Functions) != 1 || cachedLeft == nil || cachedRight == nil {
		t.Fatal("cached zero-operation runtime objects missing")
	}
	cachedAnalyzer := newSemanticAnalyzer(&cached)
	if got := semanticOperationFingerprint(cachedAnalyzer.lowerFunction(cachedBase.Functions[0], cachedLeft)); !reflect.DeepEqual(got, freshLeft) {
		t.Fatalf("zero-operation left runtime parity failed: fresh=%v cached=%v", freshLeft, got)
	}
	if got := semanticOperationFingerprint(cachedAnalyzer.lowerFunction(cachedBase.Functions[0], cachedRight)); !reflect.DeepEqual(got, freshRight) {
		t.Fatalf("zero-operation right runtime parity failed: fresh=%v cached=%v", freshRight, got)
	}
}

func TestSemanticFunctionFingerprintIncludesExactFunctionAndRuntimeIdentity(t *testing.T) {
	file := "/tmp/Fingerprint.sol"
	fnA := &types.Function{Name: "f", Selector: "f()", ContractName: "Base", SourceFile: file}
	fnB := &types.Function{Name: "g", Selector: "g()", ContractName: "Base", SourceFile: file}
	left := &types.Contract{ID: types.MakeContractID(file, "Left"), Name: "Left", SourceFile: file}
	right := &types.Contract{ID: types.MakeContractID(file, "Right"), Name: "Right", SourceFile: file}
	if reflect.DeepEqual(semanticOperationFingerprint(&semanticFunction{Function: fnA, Contract: left, ByNode: map[*types.ASTNode][]int{}}), semanticOperationFingerprint(&semanticFunction{Function: fnB, Contract: left, ByNode: map[*types.ASTNode][]int{}})) {
		t.Fatal("fingerprint omitted exact defining function identity")
	}
	if reflect.DeepEqual(semanticOperationFingerprint(&semanticFunction{Function: fnA, Contract: left, ByNode: map[*types.ASTNode][]int{}}), semanticOperationFingerprint(&semanticFunction{Function: fnA, Contract: right, ByNode: map[*types.ASTNode][]int{}})) {
		t.Fatal("fingerprint omitted exact runtime contract identity")
	}
}

func TestSemanticLowerOwnershipCoversReturnedAndCachedFields(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	analyzer := newSemanticAnalyzer(db)
	first := analyzer.lowerFunction(fn, contract)
	baseline := semanticOperationFingerprint(analyzer.lowerFunction(fn, contract))
	var target *semanticOp
	for _, operation := range first.Operations {
		if operation != nil && len(operation.Reads) > 0 && len(operation.Writes) > 0 && len(operation.Inputs) > 0 && operation.Inputs[0].Path != nil && len(operation.Inputs[0].Sources) > 0 {
			target = operation
			break
		}
	}
	if target == nil {
		t.Fatal("fixture has no operation covering every owned path field")
	}
	writeBefore := target.Writes[0].Key()
	inputBefore := target.Inputs[0].Path.Key()
	sourceBefore := target.Inputs[0].Sources[0].Key()
	target.Reads[0].Segments = append(target.Reads[0].Segments, pathSegment{Kind: segmentField, Name: "mutated-read"})
	if target.Writes[0].Key() != writeBefore || target.Inputs[0].Path.Key() != inputBefore || target.Inputs[0].Sources[0].Key() != sourceBefore {
		t.Fatal("returned read path aliases another returned field")
	}
	target.Writes[0].Segments = append(target.Writes[0].Segments, pathSegment{Kind: segmentField, Name: "mutated-write"})
	target.Inputs[0].Path.Segments = append(target.Inputs[0].Path.Segments, pathSegment{Kind: segmentField, Name: "mutated-input"})
	target.Inputs[0].Sources[0].Segments = append(target.Inputs[0].Sources[0].Segments, pathSegment{Kind: segmentField, Name: "mutated-source"})
	if got := semanticOperationFingerprint(analyzer.lowerFunction(fn, contract)); !reflect.DeepEqual(got, baseline) {
		t.Fatalf("returned mutation changed cached lowering:\nbefore=%v\nafter=%v", baseline, got)
	}
}

func TestSemanticLowerValidatesNumericUnderscoresAndUint256Bounds(t *testing.T) {
	invalid := []struct {
		value, class string
	}{
		{"1__0", "numeric_decimal"}, {"_1", "numeric_decimal"}, {"1_", "numeric_decimal"},
		{"1e_2", "numeric_decimal"}, {"0x_3", "numeric_hex"}, {"0x3_", "numeric_hex"},
		{"1e1000000", "numeric_decimal"},
	}
	for _, tc := range invalid {
		node := numericLiteral(tc.value)
		node.SetAttribute("literal_class", tc.class)
		if _, ok := parseSolidityIntegerConstant(node); ok {
			t.Errorf("invalid numeric literal %q was accepted", tc.value)
		}
	}
	valid := []string{"1_0", "1e2_0", "0x3_f", "115792089237316195423570985008687907853269984665640564039457584007913129639935"}
	for _, value := range valid {
		node := numericLiteral(value)
		if strings.HasPrefix(value, "0x") {
			node.SetAttribute("literal_class", "numeric_hex")
			node.SetAttribute("subtype", "hex")
		}
		if _, ok := parseSolidityIntegerConstant(node); !ok {
			t.Errorf("valid numeric literal %q was rejected", value)
		}
	}
	for _, value := range []string{
		"115792089237316195423570985008687907853269984665640564039457584007913129639936",
		"0x10000000000000000000000000000000000000000000000000000000000000000",
	} {
		node := numericLiteral(value)
		if strings.HasPrefix(value, "0x") {
			node.SetAttribute("literal_class", "numeric_hex")
			node.SetAttribute("subtype", "hex")
		}
		if _, ok := parseSolidityIntegerConstant(node); ok {
			t.Errorf("uint256 overflow literal %q was accepted", value)
		}
	}
	if _, ok := parseDecimalRational("1e" + strings.Repeat("9", 1000)); ok {
		t.Fatal("hostile exponent was accepted")
	}
}

func TestSemanticLowerSolidityLocalShadowAliasesStayDistinct(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "localShadow")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	var aliasesByRef = map[string]map[string]bool{}
	for _, node := range collectNodes(fn.AST, func(node *types.ASTNode) bool {
		return node.Kind == types.KindExprIndexAccess && len(node.Children) > 1 && node.Children[1].Name == "x"
	}) {
		indexRef := node.Children[1].RefID
		path, ok := newSemanticAnalyzer(db).pathForNode(node, lowerContext{ScopeID: types.MakeFunctionID(fn.SourceFile, fn.ContractName, fn.Selector), ContractID: contract.ID})
		if !ok || len(path.Segments) == 0 {
			t.Fatalf("dynamic local-shadow index did not lower exactly: node=%+v", node)
		}
		if aliasesByRef[indexRef] == nil {
			aliasesByRef[indexRef] = map[string]bool{}
		}
		aliasesByRef[indexRef][path.Segments[len(path.Segments)-1].AliasSet] = true
	}
	if len(aliasesByRef) != 2 {
		t.Fatalf("dynamic indexes use %d local identities, want 2: %v", len(aliasesByRef), aliasesByRef)
	}
	var allAliases []string
	for _, aliases := range aliasesByRef {
		if len(aliases) != 1 {
			t.Fatalf("one local binding produced multiple aliases: %v", aliasesByRef)
		}
		for alias := range aliases {
			allAliases = append(allAliases, alias)
		}
	}
	sort.Strings(allAliases)
	if len(allAliases) != 2 || allAliases[0] == allAliases[1] {
		t.Fatalf("shadowed locals collapsed dynamic aliases: %v", allAliases)
	}
	if len(lowered.Operations) == 0 {
		t.Fatal("localShadow produced no semantic operations")
	}
}

func semanticUnsupportedOnly(diagnostics []types.Diagnostic) []types.Diagnostic {
	var result []types.Diagnostic
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == types.DiagnosticSemanticUnsupported {
			result = append(result, diagnostic)
		}
	}
	return result
}
