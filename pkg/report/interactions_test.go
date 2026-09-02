package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestBuildInteractionsJSONAvailableAndLegacyShapes(t *testing.T) {
	db := types.NewDatabase()
	db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*types.ExternalBoundaryFact{
		{ID: "z", Arguments: nil, ReachableFrom: []string{"entry"}},
		{ID: "a", Arguments: []types.BoundaryValue{}},
	}
	db.AddDiagnostic(types.Diagnostic{Code: "test.incomplete", Severity: types.DiagnosticWarning, Incomplete: true})

	doc := BuildInteractionsJSON(db)
	if doc.SchemaVersion != SchemaVersion || doc.FactsVersion != types.ExternalBoundaryFactsVersion || !doc.Available {
		t.Fatalf("available metadata = %+v", doc)
	}
	if doc.AnalysisComplete || doc.DiagnosticCounts.Warning != 1 {
		t.Fatalf("analysis metadata = complete=%v counts=%+v", doc.AnalysisComplete, doc.DiagnosticCounts)
	}
	if doc.Count != 2 || len(doc.Interactions) != 2 || doc.Interactions[0].ID != "a" || doc.Interactions[0].Arguments == nil || doc.Limitations == nil {
		t.Fatalf("available shape = %+v", doc)
	}

	legacy := BuildInteractionsJSON(types.NewDatabase())
	if legacy.SchemaVersion != SchemaVersion || legacy.FactsVersion != "" || legacy.Available || legacy.Count != 0 {
		t.Fatalf("legacy metadata = %+v", legacy)
	}
	if legacy.Interactions == nil || len(legacy.Interactions) != 0 || legacy.Limitations == nil || len(legacy.Limitations) != 1 || !strings.Contains(strings.ToLower(legacy.Limitations[0]), "rebuild") {
		t.Fatalf("legacy shape = %+v", legacy)
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"generatedAt"`)) || !bytes.Contains(raw, []byte(`"interactions":[]`)) {
		t.Fatalf("legacy JSON is timestamped or has a null array: %s", raw)
	}
}

func TestInteractionsJSONDeterministicAndIndependentFromDatabaseMutation(t *testing.T) {
	db := types.NewDatabase()
	db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*types.ExternalBoundaryFact{
		{ID: "z", ReachableFrom: []string{"b", "a", "a"}},
		{ID: "a", Arguments: []types.BoundaryValue{{Role: types.BoundaryValueRoleArgument, Index: 0, RefIDs: []string{"z", "a"}}}},
	}

	doc := BuildInteractionsJSON(db)
	before, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(BuildInteractionsJSON(db))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, second) {
		t.Fatalf("interaction bytes differ across builds\nfirst: %s\nsecond: %s", before, second)
	}

	db.Semantics.ExternalBoundaries[0].ID = "mutated"
	db.Semantics.ExternalBoundaries[1].Arguments[0].RefIDs[0] = "mutated"
	db.AddDiagnostic(types.Diagnostic{Code: "later", Severity: types.DiagnosticError, Incomplete: true})
	after, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("built interaction document aliased database state\nbefore: %s\nafter: %s", before, after)
	}
}

func TestWriteBundleEmitsAndIndexesInteractionsBeforeManifest(t *testing.T) {
	db := navFixtureDB()
	db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*types.ExternalBoundaryFact{{ID: "boundary-1", Arguments: []types.BoundaryValue{}}}
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return time.Unix(0, 0) }}).GenerateSummary()
	out := t.TempDir()
	stale := filepath.Join(out, "data", "interactions.json")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "old.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := WriteBundle(out, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{Now: func() time.Time { return time.Unix(0, 0) }}); err != nil {
		t.Fatal(err)
	}
	interactionPath := filepath.Join(out, "data", "interactions.json")
	raw, err := os.ReadFile(interactionPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc InteractionsJSON
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Available || doc.Count != 1 || len(doc.Interactions) != 1 {
		t.Fatalf("interactions artifact = %+v", doc)
	}

	manifestPath := filepath.Join(out, "data", "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest ManifestJSON
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Files.Data.Interactions != "data/interactions.json" {
		t.Fatalf("manifest interactions path = %q", manifest.Files.Data.Interactions)
	}
	interactionInfo, err := os.Stat(interactionPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestInfo, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifestInfo.ModTime().Before(interactionInfo.ModTime()) {
		t.Fatalf("manifest was written before its indexed interactions artifact: manifest=%s interactions=%s", manifestInfo.ModTime(), interactionInfo.ModTime())
	}
}
