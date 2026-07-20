package engine

import (
	"fmt"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const provenanceUnionFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ProvenanceUnion {
    function run(address target, bytes calldata data) external {
        target.delegatecall(data);
    }
}
`

func TestOrUnionDeduplicatesSameSpanAcrossSourceAndASTProvenance(t *testing.T) {
	db := buildDBFromSource(t, provenanceUnionFixture).GetDatabase()
	contract := mustContractByName(t, db, "ProvenanceUnion")
	fn := mustFunctionByName(t, contract, "run")
	want := mustASTNode(t, fn.AST, types.KindCallLowlevelDelegate)

	sourceBranch := "    - from: source\n      where: [{regex: 'target\\.delegatecall\\(data\\)'}]"
	astBranch := "    - select: delegatecall\n      from: function"
	for _, tc := range []struct {
		name     string
		branches string
	}{
		{name: "source first", branches: sourceBranch + "\n" + astBranch},
		{name: "AST first", branches: astBranch + "\n" + sourceBranch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := ParseTemplate(fmt.Sprintf(`
meta: {id: provenance-union, severity: HIGH}
query:
  or:
%s
`, tc.branches))
			if err != nil {
				t.Fatalf("ParseTemplate: %v", err)
			}
			findings := New(db).Execute(tmpl)
			if len(findings) != 1 {
				for i, finding := range findings {
					t.Logf("finding %d: location=%+v primary=%+v reachability=%+v", i, finding.Location, finding.PrimaryAST, finding.Reachability)
				}
				t.Fatalf("findings = %d, want one precise site across provenance paths: %+v", len(findings), findings)
			}
			loc := findings[0].Location
			if loc.File != contract.SourceFile || loc.Line != want.StartLine || loc.Col != want.StartCol ||
				loc.EndLine != want.EndLine || loc.EndCol != want.EndCol ||
				loc.StartByte != want.StartByte || loc.EndByte != want.EndByte {
				t.Fatalf("location = %+v, want exact AST/source span [%d,%d)", loc, want.StartByte, want.EndByte)
			}
		})
	}
}

func TestOrUnionKeepsDifferentConcreteKindsAtSameSpan(t *testing.T) {
	const file = "/virtual/same-span.sol"
	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = "run"
	root.StartLine = 1
	root.EndLine = 3
	root.SetAttribute("contract", "SameSpan")
	root.SetAttribute("source_file", file)

	external := locatedNode(types.KindCallExternal, "external", 2, 5, 2, 12, 10, 20)
	internal := locatedNode(types.KindCallInternal, "internal", 2, 5, 2, 12, 10, 20)
	root.AddChild(external)
	root.AddChild(internal)

	fn := &types.Function{Name: "run", ContractName: "SameSpan", SourceFile: file, AST: root, StartLine: 1, EndLine: 3}
	contract := &types.Contract{
		ID:         types.MakeContractID(file, "SameSpan"),
		Name:       "SameSpan",
		Kind:       "contract",
		SourceFile: file,
		Functions:  []*types.Function{fn},
	}
	db := types.NewDatabase()
	db.Contracts[contract.ID] = contract
	db.SourceFiles[file] = &types.SourceFile{Path: file}
	tmpl := &Template{
		Meta:  TemplateMeta{ID: "same-span-kinds", Severity: "HIGH"},
		Query: QueryBlock{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallExternal}}},
		Queries: []QueryBlock{
			{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallExternal}}},
			{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallInternal}}},
		},
	}

	findings := New(db).Execute(tmpl)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want both concrete kinds at one span: %+v", len(findings), findings)
	}
	kinds := map[string]bool{}
	for _, finding := range findings {
		if finding.PrimaryAST == nil || finding.PrimaryAST.StartByte != 10 || finding.PrimaryAST.EndByte != 20 {
			t.Fatalf("finding lacks shared precise span: %+v", finding)
		}
		kinds[finding.PrimaryAST.Kind] = true
	}
	if !kinds[types.KindCallExternal] || !kinds[types.KindCallInternal] {
		t.Fatalf("kinds = %v, want external and internal", kinds)
	}
}

func TestOrUnionNormalizesUnknownKindIndependentlyOfBranchOrder(t *testing.T) {
	const (
		file    = "/virtual/unknown-kind-order.sol"
		content = "..........0123456789 trailing"
	)
	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = "run"
	root.StartLine = 1
	root.EndLine = 1
	root.SetAttribute("contract", "UnknownKindOrder")
	root.SetAttribute("source_file", file)

	external := locatedNode(types.KindCallExternal, "external", 1, 11, 1, 21, 10, 20)
	internal := locatedNode(types.KindCallInternal, "internal", 1, 11, 1, 21, 10, 20)
	root.AddChild(external)
	root.AddChild(internal)

	fn := &types.Function{
		Name: "run", ContractName: "UnknownKindOrder", SourceFile: file,
		AST: root, StartLine: 1, EndLine: 1,
	}
	contract := &types.Contract{
		ID:         types.MakeContractID(file, "UnknownKindOrder"),
		Name:       "UnknownKindOrder",
		Kind:       types.ContractKindContract,
		SourceFile: file,
		Functions:  []*types.Function{fn},
	}
	db := types.NewDatabase()
	db.AddContract(contract)
	db.SourceFiles[file] = &types.SourceFile{Path: file, Content: content}

	unknownBranch := QueryBlock{Scope: ScopeSource, Match: Rule{Regex: "0123456789"}}
	externalBranch := QueryBlock{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallExternal}}}
	internalBranch := QueryBlock{Scope: ScopeFunction, Match: Rule{Contains: &Rule{Kind: types.KindCallInternal}}}
	for _, tc := range []struct {
		name    string
		queries []QueryBlock
	}{
		{name: "unknown first", queries: []QueryBlock{unknownBranch, externalBranch, internalBranch}},
		{name: "unknown last", queries: []QueryBlock{externalBranch, internalBranch, unknownBranch}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := &Template{
				Meta:    TemplateMeta{ID: "unknown-kind-order", Severity: "HIGH"},
				Query:   tc.queries[0],
				Queries: tc.queries,
			}
			findings := New(db).Execute(tmpl)
			if len(findings) != 2 {
				t.Fatalf("findings = %d, want two concrete kinds: %+v", len(findings), findings)
			}
			wantKinds := []string{types.KindCallExternal, types.KindCallInternal}
			for i, finding := range findings {
				if finding.PrimaryAST == nil {
					t.Fatalf("finding %d retained unknown provenance: %+v", i, finding)
				}
				if finding.PrimaryAST.Kind != wantKinds[i] {
					t.Fatalf("finding %d kind = %q, want %q", i, finding.PrimaryAST.Kind, wantKinds[i])
				}
				if finding.PrimaryAST.StartByte != 10 || finding.PrimaryAST.EndByte != 20 {
					t.Fatalf("finding %d span = [%d,%d), want [10,20)", i, finding.PrimaryAST.StartByte, finding.PrimaryAST.EndByte)
				}
			}
		})
	}
}

func TestMatchedNodeLocationUsesPrimarySpanAndFinalTraceHost(t *testing.T) {
	for _, tc := range []struct {
		name          string
		declaration   *types.Function
		finalHost     *types.Function
		finalContract *types.Contract
		primary       *types.ASTNode
	}{
		{
			name:          "direct",
			declaration:   &types.Function{Name: "directHost", ContractName: "Direct", SourceFile: "/direct.sol", StartLine: 3},
			finalHost:     &types.Function{Name: "directHost", ContractName: "Direct", SourceFile: "/direct.sol", StartLine: 3},
			finalContract: &types.Contract{Name: "Direct", SourceFile: "/direct.sol"},
			primary:       locatedNode(types.KindStmtAssign, "balance", 7, 9, 7, 21, 70, 82),
		},
		{
			name:          "inherited cross file",
			declaration:   &types.Function{Name: "declaredBase", ContractName: "DeclaredBase", SourceFile: "/declared.sol", StartLine: 30},
			finalHost:     &types.Function{Name: "resolvedHost", ContractName: "ResolvedBase", SourceFile: "/resolved.sol", StartLine: 31},
			finalContract: &types.Contract{Name: "ResolvedBase", SourceFile: "/resolved.sol"},
			primary:       locatedNode(types.KindCallLowlevelDelegate, "delegatecall", 40, 11, 40, 35, 400, 424),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decl := types.NewASTNode(types.KindDeclFunction)
			decl.Name = tc.declaration.Name
			decl.StartLine = tc.declaration.StartLine
			decl.SetAttribute("contract", tc.declaration.ContractName)
			decl.SetAttribute("source_file", tc.declaration.SourceFile)
			decl.AddChild(tc.primary)

			trace := &matchTrace{
				Primary:        tc.primary,
				Chain:          []*types.Function{tc.finalHost},
				ChainContracts: []*types.Contract{tc.finalContract},
			}
			verifierFn := &types.Function{Name: "entry", ContractName: "Derived", SourceFile: "/derived.sol", StartLine: 2}
			verifierContract := &types.Contract{Name: "Derived", SourceFile: "/derived.sol"}
			engine := New(types.NewDatabase())
			engine.SetLocationSource(LocationSourceMatchedNode)
			loc := engine.buildLocation(trace, verifierFn, verifierContract, verifierContract.SourceFile)

			if loc.File != tc.finalHost.SourceFile || loc.Contract != tc.finalHost.ContractName || loc.Function != tc.finalHost.Name {
				t.Fatalf("host = %+v, want final trace host %s %s.%s", loc, tc.finalHost.SourceFile, tc.finalHost.ContractName, tc.finalHost.Name)
			}
			if loc.Line != tc.primary.StartLine || loc.Col != tc.primary.StartCol ||
				loc.EndLine != tc.primary.EndLine || loc.EndCol != tc.primary.EndCol ||
				loc.StartByte != tc.primary.StartByte || loc.EndByte != tc.primary.EndByte {
				t.Fatalf("span = %+v, want exact primary %+v", loc, tc.primary)
			}
		})
	}
}

func TestSequenceBacktrackingRestoresAbandonedPrimary(t *testing.T) {
	root := types.NewASTNode(types.KindDeclFunction)
	condition := types.NewASTNode(types.KindExprIdentifier)
	condition.SetAttribute("cond_role", "if")
	conditional := types.NewASTNode(types.KindStmtIf)
	thenBlock := types.NewASTNode(types.KindStmtBlock)
	elseBlock := types.NewASTNode(types.KindStmtBlock)
	callA := locatedNode(types.KindCallInternal, "callA", 3, 9, 3, 16, 20, 27)
	callB := locatedNode(types.KindCallInternal, "callB", 5, 9, 5, 16, 40, 47)
	write := locatedNode(types.KindStmtAssign, "balance", 6, 9, 6, 21, 48, 60)
	write.SetAttribute("is_state_var", true)
	thenBlock.AddChild(callA)
	elseBlock.AddChild(callB)
	elseBlock.AddChild(write)
	conditional.AddChild(condition)
	conditional.AddChild(thenBlock)
	conditional.AddChild(elseBlock)
	root.AddChild(conditional)

	engine := New(types.NewDatabase())
	trace, matched := engine.matchASTWithTrace(root, Rule{Sequence: []Rule{
		{Kind: types.KindCallInternal},
		{Kind: "state_write"},
	}})
	if !matched {
		t.Fatal("sequence did not match the co-executing callB/state-write path")
	}
	if trace.Primary != callB {
		t.Fatalf("primary = %+v, want callB at [%d,%d); abandoned callA=%+v", trace.Primary, callB.StartByte, callB.EndByte, callA)
	}
}

func TestJoinNameOnlyMemberSideCapturesMemberNode(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract MemberJoin {
    address public owner;
    uint256 public balance;
    function run() external {
        require(tx.origin == owner, "not owner");
        balance = 1;
    }
}
`
	tmpl, err := ParseTemplate(`
meta: {id: member-side-join, severity: HIGH}
query:
  from: function
  and:
    - label: origin member
      where:
        - has:
            left: {name: ^tx$}
            right: {name: ^origin$}
    - label: state write
      select: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "MemberJoin")
	fn := mustFunctionByName(t, contract, "run")
	member := mustNamedASTNode(t, fn.AST, types.KindExprMemberAccess, "origin")
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one joined function: %+v", len(findings), findings)
	}
	assertRelatedMatchesNode(t, findings[0], "origin member", contract.SourceFile, contract.Name, fn.Name, member)
}

func TestContractJoinRetainsRootTraceFallbackForCrossFunctionBranch(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract CrossFunctionJoin {
    uint256 public balance;
    function first(uint256 value) public { require(value > 0, "first"); }
    function second(address target) public { target.call(""); }
    function marker() public { balance = 1; }
}
`
	tmpl, err := ParseTemplate(`
meta: {id: contract-root-fallback, severity: HIGH}
query:
  from: main_contract
  and:
    - label: cross-function evidence
      where:
        - and:
            - has: {block: require}
            - has: {block: lowlevel_call}
    - label: marker write
      select: state_write
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "CrossFunctionJoin")
	first := mustFunctionByName(t, contract, "first")
	requireNode := mustASTNode(t, first.AST, types.KindCheckRequire)
	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want one contract join: %+v", len(findings), findings)
	}
	assertRelatedMatchesNode(t, findings[0], "cross-function evidence", contract.SourceFile, contract.Name, first.Name, requireNode)
}

func locatedNode(kind, name string, startLine, startCol, endLine, endCol, startByte, endByte int) *types.ASTNode {
	node := types.NewASTNode(kind)
	node.Name = name
	node.StartLine = startLine
	node.StartCol = startCol
	node.EndLine = endLine
	node.EndCol = endCol
	node.StartByte = startByte
	node.EndByte = endByte
	return node
}

func mustNamedASTNode(t *testing.T, root *types.ASTNode, kind, name string) *types.ASTNode {
	t.Helper()
	var found *types.ASTNode
	root.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind == kind && node.Name == name {
			found = node
			return false
		}
		return true
	})
	if found == nil {
		t.Fatalf("missing AST node %s %q", kind, name)
	}
	return found
}

func assertRelatedMatchesNode(t *testing.T, finding *Finding, label, file, contract, function string, node *types.ASTNode) {
	t.Helper()
	for _, related := range finding.Related {
		if related.Label != label {
			continue
		}
		if related.File != file || related.Contract != contract || related.Function != function ||
			related.Kind != node.Kind || related.Name != node.Name ||
			related.Line != node.StartLine || related.Col != node.StartCol ||
			related.EndLine != node.EndLine || related.EndCol != node.EndCol ||
			related.StartByte != node.StartByte || related.EndByte != node.EndByte {
			t.Fatalf("related %q = %+v, want exact node %+v", label, related, node)
		}
		return
	}
	t.Fatalf("missing related label %q; all=%+v", label, finding.Related)
}

func TestRecordedCallForNodeUsesPreciseSiteAndUniqueLineFallback(t *testing.T) {
	first := &types.FunctionCall{Target: "helper", Line: 10, Col: 5, Byte: 100}
	second := &types.FunctionCall{Target: "helper", Line: 10, Col: 20, Byte: 120}
	uniqueLine := &types.FunctionCall{Target: "helper", Line: 11, Col: 7, Byte: 160}
	e := New(types.NewDatabase())
	e.currentFunction = &types.Function{Calls: []*types.FunctionCall{first, second, uniqueLine}}

	byteNode := locatedNode(types.KindCallInternal, "helper", 10, 5, 10, 12, 120, 130)
	if got := e.recordedCallForNode(byteNode); got != second {
		t.Fatalf("byte match = %p, want second call %p", got, second)
	}

	columnNode := locatedNode(types.KindCallInternal, "helper", 10, 20, 10, 30, 0, 0)
	if got := e.recordedCallForNode(columnNode); got != second {
		t.Fatalf("line+column match = %p, want second call %p", got, second)
	}

	ambiguousLineNode := locatedNode(types.KindCallInternal, "helper", 10, 0, 10, 0, 0, 0)
	if got := e.recordedCallForNode(ambiguousLineNode); got != nil {
		t.Fatalf("ambiguous line-only match = %p, want nil", got)
	}

	uniqueLineNode := locatedNode(types.KindCallInternal, "helper", 11, 0, 11, 0, 0, 0)
	if got := e.recordedCallForNode(uniqueLineNode); got != uniqueLine {
		t.Fatalf("unique line-only match = %p, want %p", got, uniqueLine)
	}
}
