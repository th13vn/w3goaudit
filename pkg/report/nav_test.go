package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// buildReportFixture reads a fixture file under test-data/core/build-database
// and runs the full builder pipeline, returning the resulting database.
func buildReportFixture(t *testing.T, rel string) *types.Database {
	t.Helper()
	sources, err := reader.New().Read(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build %s: %v", rel, err)
	}
	return db
}

// contains is a tiny substring helper for assertions below.
func contains(s, sub string) bool { return strings.Contains(s, sub) }

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

func TestBuildNavJSON_DeterministicSymbolOrder(t *testing.T) {
	// Two contracts inserted with the higher-sorting ID first; symbols must
	// come back sorted by ID regardless of map-iteration order.
	db := types.NewDatabase()
	for _, spec := range []struct{ id, name, file string }{
		{"/z.sol#Zeta", "Zeta", "/z.sol"},
		{"/a.sol#Alpha", "Alpha", "/a.sol"},
	} {
		db.Contracts[spec.id] = &types.Contract{
			ID: spec.id, Name: spec.name, Kind: types.ContractKindContract, SourceFile: spec.file,
			Functions: []*types.Function{{Name: "f", ContractName: spec.name, Selector: "f()", StartLine: 2}},
		}
	}
	ids := func() []string {
		var out []string
		for _, s := range BuildNavJSON(db).Symbols {
			out = append(out, s.ID)
		}
		return out
	}
	first, second := ids(), ids()
	for i := 1; i < len(first); i++ {
		if first[i-1] > first[i] {
			t.Errorf("symbols not sorted: %q before %q", first[i-1], first[i])
		}
	}
	if len(first) != len(second) {
		t.Fatalf("nondeterministic length %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("nondeterministic order at %d: %q vs %q", i, first[i], second[i])
		}
	}
}

func TestBuildNavJSON_InterfaceImpl(t *testing.T) {
	db := buildReportFixture(t, "../../test-data/core/build-database/10-interface-impl.sol")
	nav := BuildNavJSON(db)
	var found bool
	for _, ii := range nav.InterfaceImpl {
		if ii.Method == "transfer(address,uint256)" &&
			contains(ii.Interface, "IToken") && contains(ii.Implementation, "#Token.") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected IToken.transfer -> Token.transfer mapping, got %+v", nav.InterfaceImpl)
	}
}
