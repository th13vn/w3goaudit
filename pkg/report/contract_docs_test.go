package report

import (
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestFormatContractReportMarkdownConsolidatesDeepDive(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	file := "/repo/src/Vault.sol"
	entry := &types.Function{Name: "withdraw", Selector: "withdraw()", ContractName: "Vault", SourceFile: file, Visibility: types.VisibilityExternal}
	contract := &types.Contract{ID: types.MakeContractID(file, "Vault"), Name: "Vault", SourceFile: file, Kind: types.ContractKindContract, Functions: []*types.Function{entry}}
	db.AddContract(contract)
	db.MainContracts[contract.ID] = &types.MainContractEntry{EntryFunctions: []string{types.MakeFunctionID(file, "Vault", "withdraw()")}, LinearizedBaseIDs: []string{contract.ID}}
	db.Semantics.SetFunctionEffects(types.MakeFunctionID(file, "Vault", "withdraw()"), &types.FunctionEffects{
		StateWrites: []types.StateWrite{{Var: "balance", Kind: "assign", Line: 4}},
		Guards:      []types.Guard{{Kind: "require", Expr: "balance > 0", Line: 2}},
	})
	db.CallGraph.AddEdge(&types.CallEdge{
		From: types.MakeFunctionID(file, "Vault", "withdraw()"), To: "unknown.call", CalledName: "call",
		Type: types.CallTypeLowLevelCall, Line: 3, Col: 9, Resolved: false,
	})
	mc := &ContractSummary{
		Name: "Vault", SourceFile: file, Version: "^0.8.20", EntryFunctionCount: 1, StateVariableCount: 1,
		StateVariables: []*StateSummary{{Name: "balance", TypeName: "uint256", DefinedIn: "Vault"}},
		EntryFunctions: []*FunctionSummary{{Name: "withdraw", Selector: "withdraw()", Signature: "3ccfd60b", DefinedIn: "Vault"}},
	}
	findings := []*engine.Finding{{TemplateID: "HIGH-CALL", Severity: "HIGH", Title: "External call", Location: engine.Location{File: file, Contract: "Vault", Function: "withdraw", Line: 3}}}

	got := FormatContractReportMarkdown(mc, findings, db, nil, "/repo", "../../", "contracts/src/Vault__Vault.md")
	ordered := []string{"# Vault", "## Findings in This Contract", "## Architecture and Inheritance", "## State Changes", "## External Interactions", "## Entry-Point Workflows"}
	last := -1
	for _, section := range ordered {
		pos := strings.Index(got, section)
		if pos <= last {
			t.Fatalf("section %q missing or out of order:\n%s", section, got)
		}
		last = pos
	}
	for _, want := range []string{
		"../../audit.md#finding-high-call-", "balance", "balance > 0", "lowlevel_call",
		"unresolved", "withdraw()", "<details>", "Auth / Access Control", "State Effects",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("contract report missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "See [findings.md]") || strings.Contains(got, "state-changes.md") || strings.Contains(got, "workflows/") {
		t.Fatalf("contract report contains old file navigation:\n%s", got)
	}
}

func TestContractInteractionRowsAreDeterministic(t *testing.T) {
	db := types.NewDatabase()
	file := "/repo/C.sol"
	c := &types.Contract{ID: types.MakeContractID(file, "C"), Name: "C", SourceFile: file, Kind: types.ContractKindContract}
	db.AddContract(c)
	db.CallGraph.Edges = []*types.CallEdge{
		{From: types.MakeFunctionID(file, "C", "z()"), To: "b", Type: types.CallTypeExternal, Line: 9, Col: 2, Resolved: true},
		{From: types.MakeFunctionID(file, "C", "a()"), To: "a", Type: types.CallTypeLowLevelCall, Line: 3, Col: 2, Resolved: false},
	}
	mc := &ContractSummary{Name: "C", SourceFile: file, EntryFunctions: []*FunctionSummary{{Name: "z", Selector: "z()"}, {Name: "a", Selector: "a()"}}}
	rows := contractInteractionRows(db, mc)
	if len(rows) != 2 || rows[0].Caller != types.MakeFunctionID(file, "C", "a()") || rows[1].Caller != types.MakeFunctionID(file, "C", "z()") {
		t.Fatalf("interaction rows not sorted: %#v", rows)
	}
}

func TestContractReportMarksUnavailableExactDatabase(t *testing.T) {
	mc := &ContractSummary{Name: "C", SourceFile: "/repo/C.sol"}
	got := FormatContractReportMarkdown(mc, nil, types.NewDatabase(), nil, "/repo", "../", "contracts/C__C.md")
	if !strings.Contains(got, "not available from the analyzed database") {
		t.Fatalf("missing exact-data fallback:\n%s", got)
	}
}
