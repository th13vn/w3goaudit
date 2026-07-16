package report

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestInterfaceImplementationUsesExactInterfaceIdentity(t *testing.T) {
	db := types.NewDatabase()
	aIface := &types.Contract{
		ID: "/a/I.sol#I", Name: "I", SourceFile: "/a/I.sol", Kind: types.ContractKindInterface,
		LinearizedBases: []string{"I"}, LinearizedBaseIDs: []string{"/a/I.sol#I"},
		Functions: []*types.Function{{Name: "ping", ContractName: "I", SourceFile: "/a/I.sol", Selector: "ping()"}},
	}
	zIface := &types.Contract{
		ID: "/z/I.sol#I", Name: "I", SourceFile: "/z/I.sol", Kind: types.ContractKindInterface,
		LinearizedBases: []string{"I"}, LinearizedBaseIDs: []string{"/z/I.sol#I"},
		Functions: []*types.Function{{Name: "ping", ContractName: "I", SourceFile: "/z/I.sol", Selector: "ping()"}},
	}
	body := types.NewASTNode(types.KindDeclFunction)
	impl := &types.Contract{
		ID: "/z/C.sol#C", Name: "C", SourceFile: "/z/C.sol", Kind: types.ContractKindContract,
		BaseContracts: []string{"I"}, LinearizedBases: []string{"C", "I"},
		LinearizedBaseIDs: []string{"/z/C.sol#C", "/z/I.sol#I"},
		Functions:         []*types.Function{{Name: "ping", ContractName: "C", SourceFile: "/z/C.sol", Selector: "ping()", AST: body}},
	}
	db.AddContract(aIface)
	db.AddContract(zIface)
	db.AddContract(impl)

	var aMapped, zMapped bool
	for _, mapping := range BuildNavJSON(db).InterfaceImpl {
		if mapping.Interface == aIface.ID {
			aMapped = true
		}
		if mapping.Interface == zIface.ID && mapping.Implementation == "/z/C.sol#C.ping()" {
			zMapped = true
		}
	}
	if aMapped || !zMapped {
		t.Fatalf("interface mappings crossed duplicate identities: %#v", BuildNavJSON(db).InterfaceImpl)
	}
}

func TestDuplicateNamesStayExactInReportArtifacts(t *testing.T) {
	db := buildReportFixture(t, "../../test-data/core/identity-collision")
	root, err := filepath.Abs("../../test-data/core/identity-collision")
	if err != nil {
		t.Fatal(err)
	}
	zFile := filepath.Join(root, "z", "Token.sol")
	aFile := filepath.Join(root, "a", "Token.sol")
	zRun := types.MakeFunctionID(zFile, "Token", "run()")
	zDanger := types.MakeFunctionID(zFile, "Token", "danger()")

	var found bool
	for _, caller := range BuildNavJSON(db).Callers {
		if caller.Caller != zRun {
			continue
		}
		if caller.Callee == zDanger {
			found = true
		}
		if strings.HasPrefix(caller.Callee, aFile+"#") {
			t.Fatalf("z.Token.run caller edge crossed into a.Token: %#v", caller)
		}
	}
	if !found {
		t.Fatal("missing exact z.Token.run -> z.Token.danger navigation edge")
	}

	summary := NewGenerator(db).GenerateSummary()
	var zSummary *ContractSummary
	for _, mc := range summary.MainContracts {
		if mc.SourceFile == zFile && mc.Name == "Token" {
			zSummary = mc
			break
		}
	}
	if zSummary == nil {
		t.Fatal("z.Token summary missing")
	}

	out := t.TempDir()
	if err := WriteBundle(out, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{}); err != nil {
		t.Fatal(err)
	}
	zDir := filepath.Join(out, filepath.FromSlash(contractFolderRel(db.ProjectRoot, zSummary)))
	state, err := os.ReadFile(filepath.Join(zDir, "state-changes.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(state), "destroyed") || strings.Contains(string(state), "safeCount") {
		t.Fatalf("z.Token state matrix crossed identities:\n%s", state)
	}

	workflowFiles, err := filepath.Glob(filepath.Join(zDir, "workflows", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	var workflows strings.Builder
	for _, path := range workflowFiles {
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		workflows.Write(b)
	}
	workflow := workflows.String()
	if !strings.Contains(workflow, "danger") || !strings.Contains(workflow, "destroyed") || strings.Contains(workflow, "safeCount") || strings.Contains(workflow, aFile) {
		t.Fatalf("z.Token workflow crossed identities:\n%s", workflow)
	}
}

func TestNavKeepsFallbackAndReceiveIDsDistinct(t *testing.T) {
	db := types.NewDatabase()
	c := &types.Contract{
		ID: "/C.sol#C", Name: "C", SourceFile: "/C.sol", Kind: types.ContractKindContract,
		Functions: []*types.Function{
			{Name: "fallback", ContractName: "C", SourceFile: "/C.sol", IsFallback: true},
			{Name: "receive", ContractName: "C", SourceFile: "/C.sol", IsReceive: true},
		},
	}
	db.AddContract(c)
	ids := map[string]bool{}
	for _, symbol := range BuildNavJSON(db).Symbols {
		if symbol.Kind == "function" {
			ids[symbol.ID] = true
		}
	}
	if !ids["/C.sol#C.fallback"] || !ids["/C.sol#C.receive"] || len(ids) != 2 {
		t.Fatalf("function IDs = %v", ids)
	}
}

func TestWriteBundleEmitsNavAndExplorer(t *testing.T) {
	db := navFixtureDB()
	dir := t.TempDir()
	err := WriteBundle(dir, db, &SummaryReport{}, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{})
	if err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}

	for _, name := range []string{"nav.json", "explorer.json"} {
		b, err := os.ReadFile(filepath.Join(dir, "data", name))
		if err != nil {
			t.Fatalf("reading data/%s: %v", name, err)
		}
		if !json.Valid(b) {
			t.Fatalf("data/%s: invalid JSON", name)
		}
		if !strings.Contains(string(b), `"schemaVersion": "`+SchemaVersion+`"`) {
			t.Errorf("data/%s: missing schemaVersion %q, got:\n%s", name, SchemaVersion, b)
		}
	}
}
