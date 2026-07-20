package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestLowerFunctionKeepsIndependentStructAndNestedFieldPaths(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	target := findPaths(lowered.Operations, "request", "target")
	payload := findPaths(lowered.Operations, "request", "payload")
	nested := findPaths(lowered.Operations, "request", "inner", "amount")
	if len(target) == 0 || len(payload) == 0 || len(nested) == 0 {
		t.Fatalf("missing exact request paths: target=%v payload=%v nested=%v", target, payload, nested)
	}
	if target[0].Equal(payload[0]) || target[0].Equal(nested[0]) || payload[0].Equal(nested[0]) {
		t.Fatal("independent struct fields collapsed")
	}
	stored := findPaths(lowered.Operations, "stored", "inner", "amount")
	if len(stored) == 0 || stored[0].Root.Storage != storagePersistent {
		t.Fatalf("nested storage member root not preserved: %+v", stored)
	}
}

func TestLowerFunctionPreservesTuplePositionsIncludingHoles(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	positions := map[int]bool{}
	for _, path := range allSemanticPaths(lowered.Operations) {
		for _, segment := range path.Segments {
			if segment.Kind == segmentTuple {
				positions[segment.Index] = true
			}
		}
	}
	if !positions[0] || !positions[1] || !positions[2] {
		t.Fatalf("tuple positions including the post-hole position were not preserved: %v paths=%+v", positions, allOperationPaths(lowered.Operations))
	}
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticSemanticUnsupported && diagnostic.Symbol == types.KindExprTuple {
			t.Fatalf("preserved tuple metadata produced an unsupported diagnostic: %+v", diagnostic)
		}
	}
}

func TestLowerFunctionTupleWritesRemainExactLValues(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	var firstWrite, secondWrite bool
	for _, operation := range lowered.Operations {
		if operation == nil || operation.Kind != semanticOpAssign {
			continue
		}
		for _, path := range operation.Writes {
			for _, segment := range path.Segments {
				if segment.Kind == segmentTuple {
					t.Fatalf("tuple lane was invented as an LHS field: %+v", path)
				}
			}
			firstWrite = firstWrite || pathRootName(path) == "first"
			secondWrite = secondWrite || pathRootName(path) == "second"
		}
	}
	if !firstWrite || !secondWrite {
		t.Fatalf("tuple assignment lost exact LHS writes: first=%v second=%v", firstWrite, secondWrite)
	}
}

func TestLowerFunctionSeparatesFixedDynamicAndMappingIndexes(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	var fixed []pathSegment
	dynamic := map[string]int{}
	var mapping []pathSegment
	for _, path := range allOperationPaths(lowered.Operations) {
		if len(path.Segments) == 0 {
			continue
		}
		segment := path.Segments[len(path.Segments)-1]
		switch {
		case pathRootName(path) == "values" && segment.Kind == segmentFixedIndex:
			fixed = append(fixed, segment)
		case pathRootName(path) == "values" && segment.Kind == segmentDynamicIndex:
			dynamic[segment.AliasSet]++
		case pathRootName(path) == "balances" && segment.Kind == segmentMappingKey:
			mapping = append(mapping, segment)
		}
	}
	if len(fixed) == 0 || fixed[0].Index != 3 {
		t.Fatalf("fixed array index not preserved: %+v", fixed)
	}
	if len(dynamic) != 2 {
		t.Fatalf("dynamic i/j aliases collapsed or split unstably: %v", dynamic)
	}
	if len(mapping) == 0 {
		t.Fatal("mapping key was not distinguished from an array index")
	}
}

func TestSemanticLowerDynamicAliasIsStableAcrossAnalyzers(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	first := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	second := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	if got, want := dynamicAliases(first), dynamicAliases(second); !reflect.DeepEqual(got, want) {
		t.Fatalf("dynamic aliases are not stable: first=%v second=%v", got, want)
	}
}

func TestLowerFunctionDistinguishesCallsFromCastsAndWrappers(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	callNames := map[string]int{}
	for _, operation := range lowered.Operations {
		if operation != nil && operation.Kind == semanticOpCall {
			callNames[operation.Provenance.Node.Name]++
		}
	}
	if callNames["sink"] != 1 || callNames["pair"] == 0 {
		t.Fatalf("ordinary calls were not lowered exactly: %v", callNames)
	}
	if callNames["address"] != 0 || callNames["bytes"] != 0 {
		t.Fatalf("type casts were emitted as semantic calls: %v", callNames)
	}
}

func TestLowerFunctionLowersDeleteIncrementAndDecrementAsWrites(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	writesByOperator := map[string]int{}
	for _, operation := range lowered.Operations {
		if operation == nil || operation.Kind != semanticOpWrite || operation.Provenance.Node == nil {
			continue
		}
		operator := operation.Provenance.Node.GetAttributeString("operator")
		if operator != "" && len(operation.Writes) > 0 {
			writesByOperator[operator]++
		}
	}
	for _, operator := range []string{"delete", "++", "--"} {
		if writesByOperator[operator] == 0 {
			t.Fatalf("operator %q did not emit a write: %v", operator, writesByOperator)
		}
	}
}

func TestSemanticLowerYulShadowedLocalsHaveDistinctLexicalPaths(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	keys := map[string]bool{}
	for _, operation := range lowered.Operations {
		if operation == nil || operation.Provenance.Node == nil || operation.Provenance.Node.Kind != types.KindAsmSstore {
			continue
		}
		for _, path := range operation.Reads {
			if pathRootName(path) == "shadow" {
				keys[path.Key()] = true
			}
		}
	}
	if len(keys) != 2 {
		t.Fatalf("Yul shadowed locals do not have distinct lexical paths: %v", keys)
	}
}

func TestLowerFunctionKeepsExactProvenanceAndByNodeIndexes(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	selector := fn.Selector
	if selector == "" {
		selector = fn.Name
	}
	wantFunctionID := types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)

	for index, operation := range lowered.Operations {
		if operation == nil {
			t.Fatalf("nil operation at %d", index)
		}
		if operation.ID != index || operation.Provenance.OpIndex != index {
			t.Fatalf("unstable operation index at %d: id=%d provenance=%d", index, operation.ID, operation.Provenance.OpIndex)
		}
		if operation.Provenance.Node == nil || operation.Provenance.File != fn.SourceFile || operation.Provenance.ContractID != contract.ID || operation.Provenance.FunctionID != wantFunctionID {
			t.Fatalf("operation %d lost exact provenance: %+v", index, operation.Provenance)
		}
		indexes := lowered.ByNode[operation.Provenance.Node]
		found := false
		for _, mapped := range indexes {
			found = found || mapped == index
		}
		if !found {
			t.Fatalf("ByNode[%p] does not include operation %d: %v", operation.Provenance.Node, index, indexes)
		}
	}
}

func TestSemanticLowerUnknownNodeEmitsUnknownAndDeduplicatedDiagnostic(t *testing.T) {
	node := types.NewASTNode("expr.future_shape")
	fn := &types.Function{Name: "f", ContractName: "C", SourceFile: "/tmp/Future.sol", Selector: "f()", AST: types.NewASTNode(types.KindDeclFunction)}
	fn.AST.AddChild(node)
	contract := &types.Contract{ID: "/tmp/Future.sol#C", Name: "C", SourceFile: "/tmp/Future.sol", Functions: []*types.Function{fn}}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	analyzer := newSemanticAnalyzer(db)
	first := analyzer.lowerFunction(fn, contract)
	second := analyzer.lowerFunction(fn, contract)

	operations := operationForNode(t, first, node)
	if len(operations) != 1 || operations[0].Kind != semanticOpUnknown {
		t.Fatalf("unsupported node lowered as %+v", operations)
	}
	if first == second || !reflect.DeepEqual(semanticOperationFingerprint(first), semanticOperationFingerprint(second)) {
		t.Fatal("lowered function cache did not return an independent equivalent result")
	}
	count := 0
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticSemanticUnsupported {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("unsupported diagnostic count = %d, want 1: %+v", count, db.Diagnostics)
	}
}

func TestSemanticLowerKeepsDivergentStructFieldsSeparate(t *testing.T) {
	db := buildSemanticFixturePath(t, "test-data/core/engine-features/taint-stress.sol")
	fn, contract := semanticFixtureFunction(t, db, "Diverge_StructFieldFP", "f")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)

	from := findPaths(lowered.Operations, "s", "from")
	to := findPaths(lowered.Operations, "s", "to")
	if len(from) == 0 || len(to) == 0 || from[0].Equal(to[0]) {
		t.Fatalf("Diverge_StructFieldFP paths collapsed: from=%v to=%v", from, to)
	}
	var transferFromReads []accessPath
	for _, operation := range lowered.Operations {
		if operation != nil && operation.Kind == semanticOpCall && operation.Provenance.Node.Name == "transferFrom" {
			transferFromReads = append(transferFromReads, operation.Reads...)
		}
	}
	if !containsFieldPath(transferFromReads, "s", "from") || containsFieldPath(transferFromReads, "s", "to") {
		t.Fatalf("transferFrom did not retain only s.from: reads=%+v diagnostics=%+v", transferFromReads, semanticUnsupportedOnly(db.Diagnostics))
	}
}

func dynamicAliases(lowered *semanticFunction) []string {
	aliases := map[string]bool{}
	for _, path := range allOperationPaths(lowered.Operations) {
		for _, segment := range path.Segments {
			if segment.Kind == segmentDynamicIndex {
				aliases[segment.AliasSet] = true
			}
		}
	}
	result := make([]string, 0, len(aliases))
	for alias := range aliases {
		result = append(result, alias)
	}
	sort.Strings(result)
	return result
}

func containsFieldPath(paths []accessPath, root string, fields ...string) bool {
	for _, path := range paths {
		if pathRootName(path) == root && pathHasField(path, fields...) {
			return true
		}
	}
	return false
}

func TestSemanticLowerNormalizedExpressionAliasIsCollisionSafe(t *testing.T) {
	ctx := lowerContext{ScopeID: "scope"}
	a := types.NewASTNode(types.KindExprBinaryOp)
	a.SetAttribute("operator", "+")
	a.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "a:b"}, &types.ASTNode{Kind: types.KindExprIdentifier, Name: "c"})
	b := types.NewASTNode(types.KindExprBinaryOp)
	b.SetAttribute("operator", "+")
	b.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "a"}, &types.ASTNode{Kind: types.KindExprIdentifier, Name: "b:c"})
	left := normalizedExpressionAlias(a, ctx)
	right := normalizedExpressionAlias(b, ctx)
	if left == right || !strings.HasPrefix(left, "expr:1:") || !strings.HasPrefix(right, "expr:1:") {
		t.Fatalf("normalized aliases collided or lacked versioning: left=%q right=%q", left, right)
	}
}

func TestSemanticLowerCanonicalizesEquivalentFixedIndexes(t *testing.T) {
	base := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "values", RefID: "file#C.values", RefKind: "state_var", Attributes: map[string]interface{}{"type_kind": types.TypeKindArray, "type": "uint256[]"}}
	makeIndex := func(value string) *types.ASTNode {
		node := types.NewASTNode(types.KindExprIndexAccess)
		baseCopy := *base
		baseCopy.Attributes = map[string]interface{}{"type_kind": types.TypeKindArray, "type": "uint256[]"}
		class := "numeric_decimal"
		subtype := "number"
		if strings.HasPrefix(value, "0x") {
			class, subtype = "numeric_hex", "hex"
		}
		node.AddChildren(&baseCopy, &types.ASTNode{Kind: types.KindExprLiteral, Value: value, Attributes: map[string]interface{}{"subtype": subtype, "literal_class": class}})
		return node
	}
	analyzer := newSemanticAnalyzer(nil)
	ctx := lowerContext{ScopeID: "file#C.f()"}
	decimal, okDecimal := analyzer.pathForNode(makeIndex("3"), ctx)
	hexadecimal, okHex := analyzer.pathForNode(makeIndex("0x03"), ctx)
	underscored, okUnderscore := analyzer.pathForNode(makeIndex("0_3"), ctx)
	if !okDecimal || !okHex || !okUnderscore || !decimal.Equal(hexadecimal) || !decimal.Equal(underscored) {
		t.Fatalf("equivalent fixed indexes differ: decimal=%+v hex=%+v underscore=%+v", decimal, hexadecimal, underscored)
	}
}

func TestSemanticLowerKeepsTypedMappingLiteralKeysDistinct(t *testing.T) {
	base := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "labels", RefID: "file#C.labels", RefKind: "state_var", Attributes: map[string]interface{}{"type_kind": types.TypeKindMapping, "type": "mapping(string=>uint256)"}}
	makeIndex := func(value, subtype string) accessPath {
		node := types.NewASTNode(types.KindExprIndexAccess)
		baseCopy := *base
		baseCopy.Attributes = map[string]interface{}{"type_kind": types.TypeKindMapping, "type": "mapping(string=>uint256)"}
		attributes := map[string]interface{}{"subtype": subtype}
		if subtype == "number" {
			attributes["literal_class"] = "numeric_decimal"
		}
		node.AddChildren(&baseCopy, &types.ASTNode{Kind: types.KindExprLiteral, Value: value, Attributes: attributes})
		path, ok := newSemanticAnalyzer(nil).pathForNode(node, lowerContext{ScopeID: "file#C.f()"})
		if !ok {
			t.Fatalf("mapping path for %q was not built", value)
		}
		return path
	}
	leadingZero := makeIndex("03", "string")
	plain := makeIndex("3", "string")
	numeric := makeIndex("3", "number")
	if leadingZero.Equal(plain) || plain.Equal(numeric) || leadingZero.Equal(numeric) {
		t.Fatalf("typed mapping literal keys collapsed: leadingZero=%+v plain=%+v numeric=%+v", leadingZero, plain, numeric)
	}
}

func TestSemanticLowerAssemblyStorageSlotsAreExact(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	var store5, load5, load6 *accessPath
	for _, operation := range lowered.Operations {
		if operation == nil || operation.Provenance.Node == nil {
			continue
		}
		node := operation.Provenance.Node
		if node.Kind == types.KindAsmSstore && len(node.Children) > 0 && node.Children[0].Value == "5" && len(operation.Writes) > 0 {
			path := operation.Writes[0]
			store5 = &path
		}
		if node.Kind == types.KindAsmSload && len(node.Children) > 0 && len(operation.Reads) > 0 {
			for _, path := range operation.Reads {
				if path.Root.Storage != storagePersistent {
					continue
				}
				copy := path
				if node.Children[0].Value == "5" {
					load5 = &copy
				} else if node.Children[0].Value == "6" {
					load6 = &copy
				}
			}
		}
	}
	if store5 == nil || load5 == nil || load6 == nil || !store5.Equal(*load5) || store5.Equal(*load6) {
		t.Fatalf("assembly storage slots not exact: store5=%+v load5=%+v load6=%+v", store5, load5, load6)
	}
}

func TestSemanticLowerKeepsGenericYulMemoryOperations(t *testing.T) {
	db := buildSemanticFixture(t, "access-paths.sol")
	fn, contract := semanticFixtureFunction(t, db, "AccessPaths", "run")
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	byName := map[string][]*semanticOp{}
	for _, operation := range lowered.Operations {
		if operation != nil && operation.Provenance.Node != nil && operation.Provenance.Node.Kind == types.KindAsmOperation {
			byName[operation.Provenance.Node.Name] = append(byName[operation.Provenance.Node.Name], operation)
		}
	}
	for _, name := range []string{"mstore", "mstore8", "mload", "calldatacopy", "add", "pop"} {
		if len(byName[name]) == 0 {
			t.Fatalf("generic Yul operation %q was dropped: %v", name, byName)
		}
	}
	for _, name := range []string{"mstore", "mstore8", "calldatacopy"} {
		if byName[name][0].Kind != semanticOpWrite || !containsStorageClass(byName[name][0].Writes, storageMemory) {
			t.Fatalf("%s was not lowered as an exact memory write: %+v", name, byName[name][0])
		}
	}
	if byName["mload"][0].Kind != semanticOpRead || !containsStorageClass(byName["mload"][0].Reads, storageMemory) {
		t.Fatalf("mload was not lowered as an exact memory read: %+v", byName["mload"][0])
	}
	if byName["add"][0].Kind != semanticOpAssign || len(byName["add"][0].Inputs) == 0 {
		t.Fatalf("add was not lowered as a transform: %+v", byName["add"][0])
	}
}

func containsStorageClass(paths []accessPath, storage storageClass) bool {
	for _, path := range paths {
		if path.Root.Storage == storage {
			return true
		}
	}
	return false
}

func TestSemanticLowerSourceAndCacheParity(t *testing.T) {
	freshDB := buildSemanticFixture(t, "access-paths.sol")
	freshFn, freshContract := semanticFixtureFunction(t, freshDB, "AccessPaths", "run")
	freshLowered := newSemanticAnalyzer(freshDB).lowerFunction(freshFn, freshContract)

	data, err := json.Marshal(freshDB)
	if err != nil {
		t.Fatalf("marshal semantic database: %v", err)
	}
	cachePath := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		t.Fatalf("write semantic database cache: %v", err)
	}
	cachedDB, err := types.LoadFromJSON(cachePath)
	if err != nil {
		t.Fatalf("load semantic database cache: %v", err)
	}
	cachedFn, cachedContract := semanticFixtureFunction(t, cachedDB, "AccessPaths", "run")
	cachedLowered := newSemanticAnalyzer(cachedDB).lowerFunction(cachedFn, cachedContract)

	if got, want := semanticASTFactFingerprint(cachedFn.AST), semanticASTFactFingerprint(freshFn.AST); !reflect.DeepEqual(got, want) {
		t.Fatalf("semantic AST facts changed across cache round-trip:\nfresh=%v\ncached=%v", want, got)
	}
	if got, want := semanticOperationFingerprint(cachedLowered), semanticOperationFingerprint(freshLowered); !reflect.DeepEqual(got, want) {
		t.Fatalf("semantic lowering changed across cache round-trip:\nfresh=%v\ncached=%v", want, got)
	}
	if got, want := semanticDiagnosticFingerprint(cachedDB.Diagnostics), semanticDiagnosticFingerprint(freshDB.Diagnostics); !reflect.DeepEqual(got, want) {
		t.Fatalf("semantic diagnostics changed across cache round-trip:\nfresh=%v\ncached=%v", want, got)
	}
}

func semanticDiagnosticFingerprint(diagnostics []types.Diagnostic) []string {
	result := make([]string, len(diagnostics))
	for index, diagnostic := range diagnostics {
		result[index] = fmt.Sprintf("%s|%s|%s|%d|%s|%s|%t|%s", diagnostic.Code, diagnostic.Severity, diagnostic.File, diagnostic.Line, diagnostic.Phase, diagnostic.Symbol, diagnostic.Incomplete, diagnostic.Message)
	}
	return result
}

func semanticASTFactFingerprint(root *types.ASTNode) []string {
	var facts []string
	for _, node := range collectNodes(root, func(node *types.ASTNode) bool {
		return node.RefID != "" || node.GetAttributeString("tuple_index") != "" || node.GetAttributeString("tuple_arity") != "" || node.GetAttributeString("assignment_lhs_count") != ""
	}) {
		facts = append(facts, fmt.Sprintf("%s|%s|%d:%d|tuple=%s/%s|lhs=%s", node.Kind, node.RefID, node.StartByte, node.EndByte, node.GetAttributeString("tuple_index"), node.GetAttributeString("tuple_arity"), node.GetAttributeString("assignment_lhs_count")))
	}
	sort.Strings(facts)
	return facts
}

func semanticOperationFingerprint(lowered *semanticFunction) []string {
	if lowered == nil {
		return []string{"semantic-function:nil"}
	}
	functionIdentity := ""
	if lowered.Function != nil && lowered.Function.SourceFile != "" && lowered.Function.ContractName != "" && lowered.Function.Selector != "" {
		functionIdentity = types.MakeFunctionID(lowered.Function.SourceFile, lowered.Function.ContractName, lowered.Function.Selector)
	}
	runtimeIdentity := ""
	if lowered.Contract != nil && lowered.Contract.ID == types.MakeContractID(lowered.Contract.SourceFile, lowered.Contract.Name) {
		runtimeIdentity = lowered.Contract.ID
	}
	result := make([]string, 0, len(lowered.Operations)+len(lowered.ByNode)+2)
	result = append(result, "function|"+functionIdentity, "runtime|"+runtimeIdentity)
	for _, operation := range lowered.Operations {
		if operation == nil || operation.Provenance.Node == nil {
			result = append(result, "nil")
			continue
		}
		reads := make([]string, len(operation.Reads))
		for i := range operation.Reads {
			reads[i] = operation.Reads[i].Key()
		}
		writes := make([]string, len(operation.Writes))
		for i := range operation.Writes {
			writes[i] = operation.Writes[i].Key()
		}
		inputs := make([]string, len(operation.Inputs))
		for i, input := range operation.Inputs {
			path := ""
			if input.Path != nil {
				path = input.Path.Key()
			}
			sources := make([]string, len(input.Sources))
			for sourceIndex := range input.Sources {
				sources[sourceIndex] = input.Sources[sourceIndex].Key()
			}
			start, end := semanticNodeSpan(input.Provenance.Node)
			inputs[i] = fmt.Sprintf("state=%d,path=%s,type=%#v,sources=%s,prov=%s/%s/%s/%d/%s:%d:%d", input.State, path, input.Type, strings.Join(sources, ","), input.Provenance.FunctionID, input.Provenance.ContractID, input.Provenance.File, input.Provenance.OpIndex, semanticNodeFingerprint(input.Provenance.Node), start, end)
		}
		result = append(result, fmt.Sprintf("op|%d|%d|%s|%s|%s|%d|%s|%d:%d|%s|%s|%s", operation.ID, operation.Kind, operation.Provenance.FunctionID, operation.Provenance.ContractID, operation.Provenance.File, operation.Provenance.OpIndex, semanticNodeFingerprint(operation.Provenance.Node), operation.Provenance.Node.StartByte, operation.Provenance.Node.EndByte, strings.Join(reads, ","), strings.Join(writes, ","), strings.Join(inputs, ";")))
	}
	var byNode []string
	for node, indexes := range lowered.ByNode {
		byNode = append(byNode, fmt.Sprintf("node|%s|%d:%d|%v", semanticNodeFingerprint(node), node.StartByte, node.EndByte, indexes))
	}
	sort.Strings(byNode)
	result = append(result, byNode...)
	return result
}

func semanticNodeSpan(node *types.ASTNode) (int, int) {
	if node == nil {
		return 0, 0
	}
	return node.StartByte, node.EndByte
}

func semanticNodeFingerprint(node *types.ASTNode) string {
	if node == nil {
		return "nil"
	}
	return node.Kind + ":" + node.Name + ":" + node.RefID
}
