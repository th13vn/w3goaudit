package engine

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestDatabaseJSONRoundTripFindingsEquivalent guards the headline
// `build -> JSON -> scan --db` workflow: a database reloaded from JSON must
// produce byte-for-byte the same findings as the freshly built one. This is the
// single highest-value cache regression test — it exercises AST round-trip
// (including RestoreParents), call-graph index rebuild, and semantic facts all
// at once, across a realistic multi-pattern fixture.
func TestDatabaseJSONRoundTripFindingsEquivalent(t *testing.T) {
	root := repoRoot(t)

	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/core/build-database/09-statements.sol"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fresh, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// A spread of AST-level templates touching the new node kinds plus classics.
	templates := []*Template{
		{
			Meta:  TemplateMeta{ID: "RT-REVERT", Severity: "LOW", Confidence: "LOW"},
			Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Contains: &Rule{Kind: types.KindCheckRevert}}},
		},
		{
			Meta:  TemplateMeta{ID: "RT-CREATE", Severity: "LOW", Confidence: "LOW"},
			Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Contains: &Rule{Kind: types.KindCallCreate}}},
		},
		{
			Meta:  TemplateMeta{ID: "RT-DELEGATE", Severity: "LOW", Confidence: "LOW"},
			Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Contains: &Rule{Kind: types.KindAsmDelegatecall}}},
		},
		{
			Meta:  TemplateMeta{ID: "RT-TUPLE", Severity: "LOW", Confidence: "LOW"},
			Query: QueryBlock{Scope: ScopeEntrypoint, Match: Rule{Contains: &Rule{Kind: types.KindExprTuple}}},
		},
	}

	fingerprint := func(db *types.Database) []string {
		findings := New(db).ExecuteAll(templates)
		ids := make([]string, 0, len(findings))
		for _, f := range findings {
			ids = append(ids, fmt.Sprintf("%s@%s:%s:%d", f.TemplateID, f.Location.Contract, f.Location.Function, f.Location.Line))
		}
		sort.Strings(ids)
		return ids
	}

	before := fingerprint(fresh)
	if len(before) == 0 {
		t.Fatal("expected findings from the fresh database; fixture or templates regressed")
	}

	// Simulate `build` (marshal) then `scan --db` (LoadFromJSON via unmarshal).
	data, err := json.Marshal(fresh)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded types.Database
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	loaded.RestoreASTParents()
	if loaded.CallGraph != nil {
		loaded.CallGraph.EnsureIndex()
	}

	after := fingerprint(&loaded)

	if len(before) != len(after) {
		t.Fatalf("finding count changed across JSON round-trip: before=%d after=%d\nbefore=%v\nafter=%v",
			len(before), len(after), before, after)
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("finding %d differs across round-trip: before=%q after=%q", i, before[i], after[i])
		}
	}
}
