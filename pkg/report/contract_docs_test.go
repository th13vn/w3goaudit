package report

import (
	"fmt"
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

func TestContractReportRendersSemanticInteractionEvidenceOncePerFact(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	file := "/repo/src/Vault.sol"
	contractID := types.MakeContractID(file, "Vault")
	entryID := types.MakeFunctionID(file, "Vault", "withdraw(address,uint256)")
	contract := &types.Contract{
		ID: contractID, Name: "Vault", SourceFile: file, Kind: types.ContractKindContract,
		Functions: []*types.Function{{Name: "withdraw", Selector: "withdraw(address,uint256)", ContractName: "Vault", SourceFile: file, Visibility: types.VisibilityExternal}},
	}
	db.AddContract(contract)
	db.MainContracts[contractID] = &types.MainContractEntry{EntryFunctions: []string{entryID}, LinearizedBaseIDs: []string{contractID}}
	db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*types.ExternalBoundaryFact{{
		ID: "boundary-1", ContractID: contractID, FunctionID: entryID, Kind: types.KindCallLowlevelCall, CallType: types.CallTypeLowLevelCall,
		Range:    types.SemanticSourceRange{File: file, StartLine: 12, StartCol: 9},
		Target:   types.BoundaryTarget{Resolution: types.BoundaryTargetResolved, FunctionID: "/repo/src/Receiver.sol#Receiver.receiveFunds()"},
		Receiver: &types.BoundaryValue{Role: types.BoundaryValueRoleReceiver, Index: -1, Control: types.BoundaryValueCallerControlled},
		Value:    &types.BoundaryValue{Role: types.BoundaryValueRoleValue, Index: -1, Control: types.BoundaryValueStateDerived},
		Arguments: []types.BoundaryValue{
			{Role: types.BoundaryValueRoleArgument, Index: 0, Control: types.BoundaryValueCallerControlled},
			{Role: types.BoundaryValueRoleArgument, Index: 1, Control: types.BoundaryValueFixed},
		},
		Result:        types.BoundaryResult{Availability: types.BoundaryResultYes, Disposition: types.BoundaryResultCaptured, DirectCheck: types.BoundaryResultYes, Targets: []types.BoundaryValue{}, CheckSites: []types.SemanticSourceRange{}},
		ReentryClass:  types.BoundaryReentryPossible,
		ReachableFrom: []string{entryID},
		StateEffects: []types.BoundaryStateEffect{
			{Relation: types.BoundaryStateBefore, Name: "debt"},
			{Relation: types.BoundaryStateAfter, Name: "balance"},
			{Relation: types.BoundaryStateAfter, Name: "nonce"},
		},
		Limitations: []string{},
	}}
	// Duplicate raw edges must not duplicate a semantic fact row.
	for i := 0; i < 3; i++ {
		db.CallGraph.AddEdge(&types.CallEdge{From: entryID, To: "unknown.call", Type: types.CallTypeLowLevelCall, Line: 12, Resolved: false})
	}
	mc := &ContractSummary{
		Name: "Vault", SourceFile: file, EntryFunctionCount: 1,
		EntryFunctions: []*FunctionSummary{{Name: "withdraw", Selector: "withdraw(address,uint256)"}},
	}

	got := FormatContractReportMarkdown(mc, nil, db, nil, "/repo", "../../", "contracts/src/Vault__Vault.md")
	for _, want := range []string{
		"../../data/interactions.json", "withdraw(address,uint256)", entryID, types.KindCallLowlevelCall,
		"/repo/src/Receiver.sol#Receiver.receiveFunds()", "resolved", "receiver=caller_controlled",
		"value=state_derived", "arguments=1 caller_controlled, 1 fixed", "captured / checked=yes",
		"before=1, after=2", types.BoundaryReentryPossible, "src/Vault.sol:12:9",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("semantic interaction report missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "boundary-1") != 1 {
		t.Fatalf("semantic fact rendered more than once:\n%s", got)
	}
}

func TestContractReportBoundsSemanticInteractionRows(t *testing.T) {
	db := types.NewDatabase()
	file := "/repo/C.sol"
	contractID := types.MakeContractID(file, "C")
	contract := &types.Contract{ID: contractID, Name: "C", SourceFile: file, Kind: types.ContractKindContract}
	db.AddContract(contract)
	db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
	for i := 0; i < maxContractInteractionRows+3; i++ {
		db.Semantics.ExternalBoundaries = append(db.Semantics.ExternalBoundaries, &types.ExternalBoundaryFact{
			ID: fmt.Sprintf("boundary-%03d", i), ContractID: contractID, FunctionID: types.MakeFunctionID(file, "C", fmt.Sprintf("f%d()", i)),
			Kind: types.KindCallLowlevelCall, Range: types.SemanticSourceRange{File: file, StartLine: i + 1},
		})
	}
	mc := &ContractSummary{Name: "C", SourceFile: file}
	got := FormatContractReportMarkdown(mc, nil, db, nil, "/repo", "../", "contracts/C__C.md")
	if rows := strings.Count(got, "| `boundary-"); rows != maxContractInteractionRows {
		t.Fatalf("rendered semantic rows = %d, want %d", rows, maxContractInteractionRows)
	}
	if !strings.Contains(got, "3 additional interaction(s) omitted") || !strings.Contains(got, "../data/interactions.json") {
		t.Fatalf("bounded interaction notice missing:\n%s", got)
	}
}

func TestContractReportUsesCallGraphInteractionFallbackForLegacyCache(t *testing.T) {
	db := types.NewDatabase()
	file := "/repo/C.sol"
	entryID := types.MakeFunctionID(file, "C", "entry()")
	contract := &types.Contract{ID: types.MakeContractID(file, "C"), Name: "C", SourceFile: file, Kind: types.ContractKindContract}
	db.AddContract(contract)
	db.MainContracts[contract.ID] = &types.MainContractEntry{EntryFunctions: []string{entryID}}
	db.CallGraph.AddEdge(&types.CallEdge{From: entryID, To: "unknown.call", CalledName: "call", Type: types.CallTypeLowLevelCall, Line: 7, Resolved: false})
	mc := &ContractSummary{Name: "C", SourceFile: file, EntryFunctions: []*FunctionSummary{{Name: "entry", Selector: "entry()"}}}

	got := FormatContractReportMarkdown(mc, nil, db, nil, "/repo", "../", "contracts/C__C.md")
	for _, want := range []string{"Rich external-boundary facts are unavailable", "call-graph fallback", "lowlevel_call", "unresolved", "../data/interactions.json"} {
		if !strings.Contains(got, want) {
			t.Fatalf("legacy interaction fallback missing %q:\n%s", want, got)
		}
	}
}

func TestContractReportMarksUnavailableExactDatabase(t *testing.T) {
	mc := &ContractSummary{Name: "C", SourceFile: "/repo/C.sol"}
	got := FormatContractReportMarkdown(mc, nil, types.NewDatabase(), nil, "/repo", "../", "contracts/C__C.md")
	if !strings.Contains(got, "not available from the analyzed database") {
		t.Fatalf("missing exact-data fallback:\n%s", got)
	}
}
