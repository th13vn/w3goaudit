package engine

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSemanticLowerInvalidMutationTargetsFailClosed(t *testing.T) {
	file := "/tmp/MutationExact.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "MutationExact"), Name: "MutationExact", SourceFile: file}
	makeExact := func(name string) *types.ASTNode {
		return &types.ASTNode{Kind: types.KindExprIdentifier, Name: name, RefID: contract.ID + ".f.-" + name, RefKind: "local_var", Attributes: map[string]interface{}{"type_kind": types.TypeKindArray}}
	}
	makeCall := func(name string) *types.ASTNode {
		return &types.ASTNode{Kind: types.KindCallInternal, Name: name}
	}
	makeTargets := func() []struct {
		name       string
		target     *types.ASTNode
		sideEffect *types.ASTNode
	} {
		missing := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "missing", RefKind: "local_var"}
		memberCall := makeCall("memberSideEffect")
		member := types.NewASTNode(types.KindExprMemberAccess)
		member.Name = "field"
		member.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "missingBase", RefKind: "local_var"}, memberCall)
		indexCall := makeCall("indexSideEffect")
		index := types.NewASTNode(types.KindExprIndexAccess)
		index.AddChildren(makeExact("values"), indexCall)
		return []struct {
			name       string
			target     *types.ASTNode
			sideEffect *types.ASTNode
		}{
			{name: "missing refid", target: missing},
			{name: "malformed member", target: member, sideEffect: memberCall},
			{name: "malformed index", target: index, sideEffect: indexCall},
		}
	}
	assert := func(t *testing.T, enclosing, target, sideEffect *types.ASTNode) {
		t.Helper()
		root := types.NewASTNode(types.KindDeclFunction)
		root.AddChild(enclosing)
		fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
		db := types.NewDatabase()
		db.Contracts[contract.ID] = contract
		lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
		ops := operationForNode(t, lowered, enclosing)
		if len(ops) != 1 || ops[0].Kind != semanticOpUnknown || len(ops[0].Writes) != 0 {
			t.Fatalf("invalid mutation emitted concrete/empty write: %+v", ops)
		}
		if sideEffect != nil {
			sideOps := operationForNode(t, lowered, sideEffect)
			if len(sideOps) != 1 || sideOps[0].Kind != semanticOpCall || sideOps[0].ID >= ops[0].ID {
				t.Fatalf("nested target effect not preserved in postorder: side=%+v mutation=%+v", sideOps, ops)
			}
		}
		diagnostics := semanticUnsupportedOnly(db.Diagnostics)
		if len(diagnostics) != 1 || diagnostics[0].Symbol != target.Kind {
			t.Fatalf("invalid mutation diagnostics = %+v, want one target diagnostic", diagnostics)
		}
	}

	for _, operator := range []string{"delete", "++", "--"} {
		for _, tc := range makeTargets() {
			t.Run("unary "+operator+" "+tc.name, func(t *testing.T) {
				unary := types.NewASTNode(types.KindExprUnaryOp)
				unary.SetAttribute("operator", operator)
				unary.AddChild(tc.target)
				assert(t, unary, tc.target, tc.sideEffect)
			})
		}
	}
	for _, tc := range makeTargets() {
		t.Run("state mutation "+tc.name, func(t *testing.T) {
			mutation := types.NewASTNode(types.KindStmtStateMutation)
			mutation.SetAttribute("operator", "push")
			mutation.AddChild(tc.target)
			assert(t, mutation, tc.target, tc.sideEffect)
		})
	}
}

func TestSemanticLowerTupleEffectsUseOnePostorderOwner(t *testing.T) {
	file := "/tmp/TupleEffects.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "TupleEffects"), Name: "TupleEffects", SourceFile: file}
	setPosition := func(node *types.ASTNode, position int) *types.ASTNode {
		if node.Attributes == nil {
			node.Attributes = map[string]interface{}{}
		}
		node.SetAttribute("tuple_index", position)
		return node
	}
	call := setPosition(&types.ASTNode{Kind: types.KindCallInternal, Name: "componentCall"}, 0)
	inc := types.NewASTNode(types.KindExprUnaryOp)
	inc.SetAttribute("operator", "++")
	inc.AddChild(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "x", RefID: contract.ID + ".f.x", RefKind: "local_var"})
	setPosition(inc, 1)
	indexCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "indexCall"}
	index := types.NewASTNode(types.KindExprIndexAccess)
	index.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "values", RefID: contract.ID + ".f.values", RefKind: "local_var", Attributes: map[string]interface{}{"type_kind": types.TypeKindArray}}, indexCall)
	setPosition(index, 2)
	badCall := &types.ASTNode{Kind: types.KindCallInternal, Name: "badIndexCall"}
	badIndex := types.NewASTNode(types.KindExprIndexAccess)
	badIndex.AddChildren(&types.ASTNode{Kind: types.KindExprIdentifier, Name: "missing", RefKind: "local_var"}, badCall)
	setPosition(badIndex, 3)
	tuple := types.NewASTNode(types.KindExprTuple)
	tuple.SetAttribute("tuple_arity", "4")
	tuple.AddChildren(call, inc, index, badIndex)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(tuple)
	fn := &types.Function{Name: "f", Selector: "f()", ContractName: contract.Name, SourceFile: file, AST: root}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	for _, effect := range []*types.ASTNode{call, inc, indexCall, badCall} {
		if got := len(lowered.ByNode[effect]); got != 1 {
			t.Fatalf("effect %s owns %d operations, want exactly 1", effect.Name+effect.GetAttributeString("operator"), got)
		}
	}
	order := []int{lowered.ByNode[call][0], lowered.ByNode[inc][0], lowered.ByNode[indexCall][0], lowered.ByNode[badCall][0]}
	if !sort.IntsAreSorted(order) {
		t.Fatalf("tuple effects are not deterministic postorder: %v", order)
	}
	tupleOps := operationForNode(t, lowered, tuple)
	if tupleOps[len(tupleOps)-1].Kind != semanticOpUnknown || tupleOps[len(tupleOps)-1].ID <= order[len(order)-1] {
		t.Fatalf("malformed tuple did not fail after child effects: tuple=%+v effects=%v", tupleOps, order)
	}
}

func TestSemanticLowerRecursiveValueExactnessSourceCache(t *testing.T) {
	file := "/tmp/RecursiveValue.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "RecursiveValue"), Name: "RecursiveValue", SourceFile: file}
	exact := func(name string) *types.ASTNode {
		node := types.NewASTNode(types.KindExprIdentifier)
		node.Name, node.RefID, node.RefKind = name, contract.ID+".f.-"+name, "local_var"
		return node
	}
	malformedTuple := func() *types.ASTNode {
		tuple := types.NewASTNode(types.KindExprTuple)
		child := exact("lane")
		child.SetAttribute("tuple_index", 0)
		tuple.AddChild(child)
		return tuple
	}
	wrappers := []struct {
		name string
		wrap func(*types.ASTNode) *types.ASTNode
	}{
		{name: "cast", wrap: func(tuple *types.ASTNode) *types.ASTNode {
			cast := types.NewASTNode(types.KindCallInternal)
			cast.Name = "uint256"
			cast.SetAttribute("type_source", "type_cast")
			cast.AddChild(tuple)
			return cast
		}},
		{name: "conditional", wrap: func(tuple *types.ASTNode) *types.ASTNode {
			conditional := types.NewASTNode(types.KindExprConditional)
			conditional.AddChildren(&types.ASTNode{Kind: types.KindExprLiteral, Value: "true", Attributes: map[string]interface{}{"subtype": "bool"}}, tuple, exact("fallback"))
			return conditional
		}},
		{name: "unary", wrap: func(tuple *types.ASTNode) *types.ASTNode {
			unary := types.NewASTNode(types.KindExprUnaryOp)
			unary.SetAttribute("operator", "-")
			unary.AddChild(tuple)
			return unary
		}},
		{name: "binary", wrap: func(tuple *types.ASTNode) *types.ASTNode {
			binary := types.NewASTNode(types.KindExprBinaryOp)
			binary.SetAttribute("operator", "+")
			binary.AddChildren(exact("left"), tuple)
			return binary
		}},
		{name: "nested tuple", wrap: func(tuple *types.ASTNode) *types.ASTNode {
			outer := types.NewASTNode(types.KindExprTuple)
			outer.SetAttribute("tuple_arity", "1")
			tuple.SetAttribute("tuple_index", 0)
			outer.AddChild(tuple)
			return outer
		}},
	}
	assertMalformed := func(t *testing.T, wrapperName string, argument, failing *types.ASTNode, cached bool) []string {
		t.Helper()
		call := &types.ASTNode{Kind: types.KindCallInternal, Name: "consume"}
		call.AddChild(argument)
		root := types.NewASTNode(types.KindDeclFunction)
		root.AddChild(call)
		fn := &types.Function{Name: wrapperName, Selector: wrapperName + "()", ContractName: contract.Name, SourceFile: file, AST: root}
		db := types.NewDatabase()
		contractCopy := *contract
		contractCopy.Functions = []*types.Function{fn}
		db.Contracts[contractCopy.ID] = &contractCopy
		runtime := &contractCopy
		if cached {
			raw, err := json.Marshal(db)
			if err != nil {
				t.Fatal(err)
			}
			var loaded types.Database
			if err := json.Unmarshal(raw, &loaded); err != nil {
				t.Fatal(err)
			}
			loaded.RestoreASTParents()
			db = &loaded
			runtime = db.GetContractByID(contract.ID)
			fn = runtime.Functions[0]
		}
		lowered := newSemanticAnalyzer(db).lowerFunction(fn, runtime)
		ops := operationForNode(t, lowered, fn.AST.Children[0])
		if len(ops) != 1 || ops[0].Kind != semanticOpUnknown {
			t.Fatalf("%s malformed recursive value remained concrete: %+v", wrapperName, ops)
		}
		diagnostics := semanticUnsupportedOnly(db.Diagnostics)
		if len(diagnostics) != 1 || diagnostics[0].Symbol != failing.Kind {
			t.Fatalf("%s diagnostics = %+v, want failing %s", wrapperName, diagnostics, failing.Kind)
		}
		return semanticOperationFingerprint(lowered)
	}
	for _, tc := range wrappers {
		t.Run(tc.name, func(t *testing.T) {
			failing := malformedTuple()
			argument := tc.wrap(failing)
			fresh := assertMalformed(t, tc.name, argument, failing, false)
			failingCached := malformedTuple()
			cachedArgument := tc.wrap(failingCached)
			cached := assertMalformed(t, tc.name, cachedArgument, failingCached, true)
			if !reflect.DeepEqual(fresh, cached) {
				t.Fatalf("%s source/cache mismatch:\nfresh=%v\ncached=%v", tc.name, fresh, cached)
			}
		})
	}

	missingTuple := types.NewASTNode(types.KindExprTuple)
	missingTuple.SetAttribute("tuple_arity", "1")
	missingLane := types.NewASTNode(types.KindExprIdentifier)
	missingLane.Name, missingLane.RefKind = "missing", "local_var"
	missingLane.SetAttribute("tuple_index", 0)
	missingTuple.AddChild(missingLane)
	assertMalformed(t, "missingLane", missingTuple, missingLane, false)

	inner := types.NewASTNode(types.KindExprTuple)
	inner.SetAttribute("tuple_arity", "3")
	inner.SetAttribute("tuple_index", 2)
	innerFirst, innerThird := exact("innerFirst"), exact("innerThird")
	innerFirst.SetAttribute("tuple_index", 0)
	innerThird.SetAttribute("tuple_index", 2)
	inner.AddChildren(innerFirst, innerThird)
	outer := types.NewASTNode(types.KindExprTuple)
	outer.SetAttribute("tuple_arity", "3")
	outerFirst := exact("outerFirst")
	outerFirst.SetAttribute("tuple_index", 0)
	outer.AddChildren(outerFirst, inner)
	call := &types.ASTNode{Kind: types.KindCallInternal, Name: "consumeValid"}
	call.AddChild(outer)
	root := types.NewASTNode(types.KindDeclFunction)
	root.AddChild(call)
	fn := &types.Function{Name: "valid", Selector: "valid()", ContractName: contract.Name, SourceFile: file, AST: root}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	lowered := newSemanticAnalyzer(db).lowerFunction(fn, contract)
	op := operationForNode(t, lowered, call)[0]
	positions := make([][]int, 0, len(op.Inputs))
	for _, input := range op.Inputs {
		var path []int
		if input.Path != nil {
			for _, segment := range input.Path.Segments {
				if segment.Kind == segmentTuple {
					path = append(path, segment.Index)
				}
			}
		}
		positions = append(positions, path)
	}
	want := [][]int{{0}, {2, 0}, {2, 2}}
	if op.Kind != semanticOpCall || !reflect.DeepEqual(positions, want) {
		t.Fatalf("valid nested tuple holes lost positions: got=%v want=%v op=%+v", positions, want, op)
	}
}

func TestSemanticLowerDeclarationLHSCountRanges(t *testing.T) {
	file := "/tmp/DeclRange.sol"
	contract := &types.Contract{ID: types.MakeContractID(file, "DeclRange"), Name: "DeclRange", SourceFile: file}
	identifier := func(name string) *types.ASTNode {
		return &types.ASTNode{Kind: types.KindExprIdentifier, Name: name, RefID: contract.ID + ".f.-" + name, RefKind: "local_var"}
	}
	cases := []struct {
		name       string
		lhs        any
		children   []*types.ASTNode
		wantKind   semanticOpKind
		wantNoOp   bool
		wantFailed bool
	}{
		{name: "zero", lhs: "0", children: []*types.ASTNode{identifier("x"), numericLiteral("1")}, wantKind: semanticOpUnknown, wantFailed: true},
		{name: "negative", lhs: "-1", children: []*types.ASTNode{identifier("x"), numericLiteral("1")}, wantKind: semanticOpUnknown, wantFailed: true},
		{name: "out of range", lhs: "3", children: []*types.ASTNode{identifier("x"), numericLiteral("1")}, wantKind: semanticOpUnknown, wantFailed: true},
		{name: "malformed", lhs: "bad", children: []*types.ASTNode{identifier("x"), numericLiteral("1")}, wantKind: semanticOpUnknown, wantFailed: true},
		{name: "declaration only", lhs: "2", children: []*types.ASTNode{identifier("x"), identifier("y")}, wantNoOp: true},
		{name: "initialized", lhs: "1", children: []*types.ASTNode{identifier("x"), numericLiteral("1")}, wantKind: semanticOpAssign},
	}
	assert := func(t *testing.T, tc struct {
		name       string
		lhs        any
		children   []*types.ASTNode
		wantKind   semanticOpKind
		wantNoOp   bool
		wantFailed bool
	}, cached bool) {
		t.Helper()
		decl := types.NewASTNode(types.KindDeclVariable)
		decl.SetAttribute("assignment_lhs_count", tc.lhs)
		decl.AddChildren(tc.children...)
		root := types.NewASTNode(types.KindDeclFunction)
		root.AddChild(decl)
		fn := &types.Function{Name: tc.name, Selector: tc.name + "()", ContractName: contract.Name, SourceFile: file, AST: root}
		db := types.NewDatabase()
		contractCopy := *contract
		contractCopy.Functions = []*types.Function{fn}
		db.Contracts[contractCopy.ID] = &contractCopy
		runtime := &contractCopy
		if cached {
			raw, err := json.Marshal(db)
			if err != nil {
				t.Fatal(err)
			}
			var loaded types.Database
			if err := json.Unmarshal(raw, &loaded); err != nil {
				t.Fatal(err)
			}
			loaded.RestoreASTParents()
			db = &loaded
			loadedContract := db.GetContractByID(contractCopy.ID)
			fn = loadedContract.Functions[0]
			decl = fn.AST.Children[0]
			runtime = loadedContract
		}
		lowered := newSemanticAnalyzer(db).lowerFunction(fn, runtime)
		indexes := lowered.ByNode[decl]
		if tc.wantNoOp {
			if len(indexes) != 0 || len(semanticUnsupportedOnly(db.Diagnostics)) != 0 {
				t.Fatalf("declaration-only form emitted operation/diagnostic: indexes=%v diagnostics=%+v", indexes, db.Diagnostics)
			}
			return
		}
		if len(indexes) != 1 || lowered.Operations[indexes[0]].Kind != tc.wantKind {
			t.Fatalf("%s lhs range lowered as indexes=%v operations=%+v", tc.name, indexes, lowered.Operations)
		}
		if got := len(semanticUnsupportedOnly(db.Diagnostics)); (got == 1) != tc.wantFailed {
			t.Fatalf("%s diagnostics=%+v", tc.name, db.Diagnostics)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert(t, tc, false)
			assert(t, tc, true)
		})
	}
}

func TestSemanticLowerRequiresDurableLiteralClass(t *testing.T) {
	legacy := []*types.ASTNode{
		{Kind: types.KindExprLiteral, Value: "1", Attributes: map[string]interface{}{"subtype": "number"}},
		{Kind: types.KindExprLiteral, Value: "1", Attributes: map[string]interface{}{"subtype": "number", "subdenomination": ""}},
		{Kind: types.KindExprLiteral, Value: "0x03", Attributes: map[string]interface{}{"subtype": "hex"}},
		{Kind: types.KindExprLiteral, Value: "03", Attributes: map[string]interface{}{"subtype": "hex"}},
		{Kind: types.KindExprLiteral, Value: "1", Attributes: map[string]interface{}{"subtype": "hex", "literal_class": "numeric_decimal"}},
		{Kind: types.KindExprLiteral, Value: "0x03", Attributes: map[string]interface{}{"subtype": "number", "literal_class": "numeric_hex"}},
		{Kind: types.KindExprLiteral, Value: "03", Attributes: map[string]interface{}{"subtype": "number", "literal_class": "hex_string"}},
	}
	for _, node := range legacy {
		raw, err := json.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		var cached types.ASTNode
		if err := json.Unmarshal(raw, &cached); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range []*types.ASTNode{node, &cached} {
			if _, ok := literalIndexSegment(candidate); ok {
				t.Errorf("legacy/inconsistent literal became fixed: %+v", candidate.Attributes)
			}
			if _, ok := mappingLiteralSegment(candidate); ok {
				t.Errorf("legacy/inconsistent literal became mapping identity: %+v", candidate.Attributes)
			}
			base := &types.ASTNode{Kind: types.KindExprIdentifier, Name: "values", RefID: "/tmp/L.sol#L.f.values", RefKind: "local_var", Attributes: map[string]interface{}{"type_kind": types.TypeKindArray}}
			index := types.NewASTNode(types.KindExprIndexAccess)
			index.AddChildren(base, candidate)
			if _, ok := newSemanticAnalyzer(nil).pathForNode(index, lowerContext{ScopeID: "/tmp/L.sol#L.f()"}); ok {
				t.Errorf("legacy/inconsistent literal became dynamic alias: %+v", candidate.Attributes)
			}
		}
	}
	numericHex := &types.ASTNode{Kind: types.KindExprLiteral, Value: "0x03", Attributes: map[string]interface{}{"subtype": "hex", "literal_class": "numeric_hex"}}
	hexString := &types.ASTNode{Kind: types.KindExprLiteral, Value: "03", Attributes: map[string]interface{}{"subtype": "hex", "literal_class": "hex_string"}}
	numericSegment, numericOK := mappingLiteralSegment(numericHex)
	stringSegment, stringOK := mappingLiteralSegment(hexString)
	if !numericOK || !stringOK || numericSegment.Key == stringSegment.Key {
		t.Fatalf("numeric hex and hex string identities collided: numeric=%+v/%v string=%+v/%v", numericSegment, numericOK, stringSegment, stringOK)
	}
	for _, ordinary := range []*types.ASTNode{
		{Kind: types.KindExprLiteral, Value: "hello", Attributes: map[string]interface{}{"subtype": "string"}},
		{Kind: types.KindExprLiteral, Value: "true", Attributes: map[string]interface{}{"subtype": "bool"}},
	} {
		if _, ok := mappingLiteralSegment(ordinary); !ok {
			t.Errorf("unambiguous literal lost subtype identity: %+v", ordinary)
		}
	}
}
