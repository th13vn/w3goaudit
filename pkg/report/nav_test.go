package report

import (
	"encoding/json"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func navFixtureDB() *types.Database {
	db := types.NewDatabase()
	c := &types.Contract{
		ID: "/x.sol#C", Name: "C", Kind: types.ContractKindContract, SourceFile: "/x.sol",
		StartLine:      1,
		StateVariables: []*types.StateVariable{{Name: "x", TypeName: "uint256", StartLine: 2, StartCol: 5}},
		Functions: []*types.Function{
			{Name: "f", ContractName: "C", Selector: "f()", Visibility: types.VisibilityExternal, StartLine: 4, StartCol: 5},
			{Name: "g", ContractName: "C", Selector: "g()", Visibility: types.VisibilityInternal, StartLine: 8, StartCol: 5},
		},
	}
	db.Contracts[c.ID] = c
	// f calls g at line 5, col 9.
	db.CallGraph.Edges = append(db.CallGraph.Edges, &types.CallEdge{
		From: "/x.sol#C.f()", To: "/x.sol#C.g()", CalledName: "g", Type: types.CallTypeInternal,
		Line: 5, Col: 9, Byte: 120, Resolved: true, ResolvedContract: "C", ResolvedFunction: "g",
	})
	return db
}

func TestBuildNavJSON_SymbolsAndCallers(t *testing.T) {
	nav := BuildNavJSON(navFixtureDB())
	if nav.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %q", nav.SchemaVersion)
	}
	// Symbols: 1 contract + 2 functions + 1 state var = 4.
	kinds := map[string]int{}
	var fRange SrcRange
	for _, s := range nav.Symbols {
		kinds[s.Kind]++
		if s.ID == "/x.sol#C.f()" {
			fRange = s.Range
		}
	}
	if kinds["contract"] != 1 || kinds["function"] != 2 || kinds["stateVar"] != 1 {
		t.Errorf("symbol kinds = %v, want 1 contract / 2 function / 1 stateVar", kinds)
	}
	if fRange.StartLine != 4 || fRange.StartCol != 5 || fRange.File != "/x.sol" {
		t.Errorf("f symbol range = %+v, want line4 col5 /x.sol", fRange)
	}
	// Caller edge: g is called by f at the call-site range.
	if len(nav.Callers) != 1 {
		t.Fatalf("callers = %d, want 1", len(nav.Callers))
	}
	ce := nav.Callers[0]
	if ce.Callee != "/x.sol#C.g()" || ce.Caller != "/x.sol#C.f()" {
		t.Errorf("caller edge callee/caller = %q/%q", ce.Callee, ce.Caller)
	}
	if ce.Site.StartLine != 5 || ce.Site.StartCol != 9 || ce.Site.File != "/x.sol" {
		t.Errorf("caller site = %+v, want line5 col9 /x.sol", ce.Site)
	}
	b, _ := json.Marshal(nav)
	if !json.Valid(b) {
		t.Fatal("invalid JSON")
	}
}
