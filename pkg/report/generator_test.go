package report

import (
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func exactReportResolverFixture() (*types.Database, *types.Contract, *types.Contract, *types.Contract) {
	db := types.NewDatabase()
	wrongFn := &types.Function{
		Name: "step", ContractName: "Base", SourceFile: "/repo/a/Base.sol",
		Selector: "step(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}},
	}
	rightFn := &types.Function{
		Name: "step", ContractName: "Base", SourceFile: "/repo/z/Base.sol",
		Selector: "step(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}},
	}
	wrong := &types.Contract{Name: "Base", SourceFile: "/repo/a/Base.sol", Functions: []*types.Function{wrongFn}}
	right := &types.Contract{Name: "Base", SourceFile: "/repo/z/Base.sol", Functions: []*types.Function{rightFn}}
	entry := &types.Function{
		Name: "entry", ContractName: "Main", SourceFile: "/repo/Main.sol",
		Selector: "entry()", Visibility: types.VisibilityExternal,
		Calls: []*types.FunctionCall{{
			Target:             "step",
			ResolvedContract:   "Base",
			ResolvedContractID: "/repo/z/Base.sol#Base",
			ResolvedFunction:   "step(uint256)",
			CallType:           types.CallTypeInherited,
			Resolved:           true,
			ArgCount:           1,
		}},
	}
	main := &types.Contract{Name: "Main", SourceFile: "/repo/Main.sol", Functions: []*types.Function{entry}}
	db.AddContract(wrong)
	db.AddContract(right)
	db.AddContract(main)
	main.LinearizedBaseIDs = []string{main.ID, wrong.ID, right.ID}
	return db, main, wrong, right
}

func TestGeneratorUsesExactRecordedCallTarget(t *testing.T) {
	db, main, wrong, right := exactReportResolverFixture()
	graph := NewGenerator(db).generateFunctionCallGraph(main, "entry()")
	rightID := types.MakeFunctionID(right.SourceFile, right.Name, "step(uint256)")
	wrongID := types.MakeFunctionID(wrong.SourceFile, wrong.Name, "step(uint256)")
	if !strings.Contains(graph, sanitizeMermaidNode(rightID)) {
		t.Fatalf("graph missing exact recorded target %s:\n%s", rightID, graph)
	}
	if strings.Contains(graph, sanitizeMermaidNode(wrongID)) {
		t.Fatalf("graph borrowed same-named target %s:\n%s", wrongID, graph)
	}
}

func TestGeneratorLegacyCallUsesExactRuntimeMRODespiteGlobalNameCollision(t *testing.T) {
	db, main, _, right := exactReportResolverFixture()
	main.LinearizedBaseIDs = []string{main.ID, right.ID}
	call := main.Functions[0].Calls[0]
	call.ResolvedContractID = ""
	graph := NewGenerator(db).generateFunctionCallGraph(main, "entry()")
	rightID := types.MakeFunctionID(right.SourceFile, right.Name, "step(uint256)")
	if !strings.Contains(graph, sanitizeMermaidNode(rightID)) {
		t.Fatalf("legacy graph did not use exact runtime MRO target %s:\n%s", rightID, graph)
	}
}

func TestGeneratorLegacyLookupRequiresOneDistinctSelector(t *testing.T) {
	db := types.NewDatabase()
	contract := &types.Contract{
		Name:       "C",
		SourceFile: "/repo/C.sol",
		Functions: []*types.Function{
			{Name: "step", Selector: "step()"},
			{Name: "step", Selector: "step(address)", Parameters: []*types.Parameter{{TypeName: "address"}}},
			{Name: "step", Selector: "step(uint256)", Parameters: []*types.Parameter{{TypeName: "uint256"}}},
		},
	}
	db.AddContract(contract)
	contract.LinearizedBaseIDs = []string{contract.ID}
	g := NewGenerator(db)

	if owner, fn := g.findImplementationContract(contract, "step", 1); owner != nil || fn != nil {
		t.Fatalf("same-arity overload ambiguity resolved to (%#v, %#v), want nil", owner, fn)
	}
	if owner, fn := g.findImplementationContract(contract, "step", -1); owner != nil || fn != nil {
		t.Fatalf("unknown-arity overload ambiguity resolved to (%#v, %#v), want nil", owner, fn)
	}
	if owner, fn := g.findImplementationContract(contract, "step", 2); owner != nil || fn != nil {
		t.Fatalf("arity mismatch resolved to (%#v, %#v), want nil", owner, fn)
	}
	owner, fn := g.findImplementationContract(contract, "step", 0)
	if owner != contract || fn == nil || fn.Selector != "step()" {
		t.Fatalf("unique zero-arity selector = (%#v, %#v), want C.step()", owner, fn)
	}
}
