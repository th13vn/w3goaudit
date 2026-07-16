package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestBuildDiagnosticsJSONCountsSortsAndDeduplicates(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 2, 3, 0, time.FixedZone("test", 7*60*60))
	db := types.NewDatabase()
	warning := types.Diagnostic{
		Code:       types.DiagnosticUnresolvedImport,
		Severity:   types.DiagnosticWarning,
		Phase:      "reader",
		File:       "/repo/z.sol",
		ImportPath: "./Missing.sol",
		Incomplete: true,
	}
	db.AddDiagnostic(warning)
	db.AddDiagnostic(types.Diagnostic{
		Code:     "build.note",
		Severity: types.DiagnosticInfo,
		Phase:    "builder",
		File:     "/repo/a.sol",
		Message:  "analysis note",
	})
	db.AddDiagnostic(warning)

	doc := BuildDiagnosticsJSONAt(now, db)
	if !doc.GeneratedAt.Equal(now.UTC()) {
		t.Fatalf("generatedAt = %v, want %v", doc.GeneratedAt, now.UTC())
	}
	if doc.AnalysisComplete {
		t.Fatal("analysisComplete = true with an incomplete diagnostic")
	}
	if doc.Counts.Info != 1 || doc.Counts.Warning != 1 || doc.Counts.Error != 0 {
		t.Fatalf("counts = %#v, want info=1 warning=1 error=0", doc.Counts)
	}
	if len(doc.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %#v, want two unique records", doc.Diagnostics)
	}
	if doc.Diagnostics[0].Severity != types.DiagnosticInfo || doc.Diagnostics[1].Severity != types.DiagnosticWarning {
		t.Fatalf("diagnostics are not in stable order: %#v", doc.Diagnostics)
	}

	empty := BuildDiagnosticsJSONAt(now, types.NewDatabase())
	if empty.Diagnostics == nil || !empty.AnalysisComplete {
		t.Fatalf("empty diagnostics = %#v complete=%v, want [] and true", empty.Diagnostics, empty.AnalysisComplete)
	}
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"diagnostics":[]`)) {
		t.Fatalf("empty diagnostics did not serialize as []: %s", raw)
	}
}

func TestUnknownDiagnosticSeverityIsCountedAndRendered(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	db.AddDiagnostic(types.Diagnostic{
		Code:       "future.diagnostic",
		Severity:   types.DiagnosticSeverity("future"),
		Phase:      "custom",
		Message:    "new severity from a newer producer",
		Incomplete: true,
	})
	now := time.Unix(0, 0)
	doc := BuildDiagnosticsJSONAt(now, db)
	if doc.Counts.Unknown != 1 || diagnosticCountTotal(doc.Counts) != len(doc.Diagnostics) {
		t.Fatalf("unknown diagnostic disappeared from counts: counts=%#v diagnostics=%#v", doc.Counts, doc.Diagnostics)
	}
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return now }}).GenerateSummary()
	manifest := BuildManifestAt(now, ToolMeta{Name: "w3goaudit"}, summary, nil, nil, db, false)
	if manifest.DiagnosticCounts.Unknown != 1 || manifest.AnalysisComplete {
		t.Fatalf("manifest unknown severity = counts=%#v complete=%v", manifest.DiagnosticCounts, manifest.AnalysisComplete)
	}
	readme := FormatFolderReadme(ToolMeta{Name: "w3goaudit"}, summary, nil)
	if !strings.Contains(readme, "1 unknown-severity diagnostic") {
		t.Fatalf("human report hid unknown severity:\n%s", readme)
	}
}

func TestManifestScopeCountsDiagnosticsOptionalFilesAndClock(t *testing.T) {
	now := time.Date(2026, 7, 14, 1, 2, 3, 0, time.FixedZone("test", 7*60*60))
	db := navFixtureDB()
	db.ProjectRoot = "/repo"
	db.ScanTarget = "/repo/src"
	db.Contracts["/repo/I.sol#I"] = &types.Contract{ID: "/repo/I.sol#I", Name: "I", Kind: types.ContractKindInterface}
	db.Contracts["/repo/L.sol#L"] = &types.Contract{ID: "/repo/L.sol#L", Name: "L", Kind: types.ContractKindLibrary}
	db.AddDiagnostic(types.Diagnostic{
		Code:       types.DiagnosticUnresolvedImport,
		Severity:   types.DiagnosticWarning,
		Incomplete: true,
	})
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return now }}).GenerateSummary()

	m := BuildManifestAt(now, ToolMeta{Name: "w3goaudit"}, summary, nil, nil, db, true)
	if !m.GeneratedAt.Equal(now.UTC()) {
		t.Fatalf("generatedAt = %v, want %v", m.GeneratedAt, now.UTC())
	}
	if m.Target != "/repo/src" || m.ProjectRoot != "/repo" || m.ScanTarget != "/repo/src" {
		t.Fatalf("manifest scope = target %q root %q scan %q", m.Target, m.ProjectRoot, m.ScanTarget)
	}
	if m.Stats.Contracts != 1 || m.Stats.Interfaces != 1 || m.Stats.Libraries != 1 || m.Stats.Declarations != 3 {
		t.Fatalf("manifest declaration stats = %#v", m.Stats)
	}
	if m.AnalysisComplete || m.DiagnosticCounts.Warning != 1 {
		t.Fatalf("manifest completeness = %v counts=%#v", m.AnalysisComplete, m.DiagnosticCounts)
	}
	if m.Files.Data.Diagnostics != "data/diagnostics.json" {
		t.Fatalf("diagnostics path = %q", m.Files.Data.Diagnostics)
	}
	if m.Files.OverviewHTML != "overview.html" || m.Files.FindingsHTML != "findings.html" {
		t.Fatalf("HTML paths = %q / %q", m.Files.OverviewHTML, m.Files.FindingsHTML)
	}

	withoutHTML := BuildManifestAt(now, ToolMeta{Name: "w3goaudit"}, summary, nil, nil, db, false)
	if withoutHTML.Files.OverviewHTML != "" || withoutHTML.Files.FindingsHTML != "" {
		t.Fatalf("optional HTML indexed when disabled: %#v", withoutHTML.Files)
	}

	overview := BuildOverviewJSONAt(now, ToolMeta{Name: "w3goaudit"}, summary, summary.Stats)
	if overview.ProjectRoot != m.ProjectRoot || overview.ScanTarget != m.ScanTarget || overview.AnalysisComplete != m.AnalysisComplete || overview.DiagnosticCounts != m.DiagnosticCounts {
		t.Fatalf("overview completeness/scope disagrees with manifest:\n overview=%#v\n manifest=%#v", overview, m)
	}
	if overview.Overview == nil || !overview.Overview.GeneratedAt.Equal(now.UTC()) {
		t.Fatalf("nested overview timestamp = %#v, want %v", overview.Overview, now.UTC())
	}
}

func TestManifestLegacyScanTargetFallsBackToProjectRoot(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return time.Unix(0, 0) }}).GenerateSummary()
	m := BuildManifestAt(time.Unix(0, 0), ToolMeta{Name: "w3goaudit"}, summary, nil, nil, db, false)
	if m.Target != "/repo" || m.ScanTarget != "/repo" {
		t.Fatalf("legacy target fallback = target %q scanTarget %q", m.Target, m.ScanTarget)
	}
}

func TestWriteBundleFixedClockIsByteStable(t *testing.T) {
	db := navFixtureDB()
	db.ProjectRoot, db.ScanTarget = "/repo", "/repo/src"
	now := time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC)
	differentSummaryTime := now.Add(24 * time.Hour)
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return differentSummaryTime }}).GenerateSummary()
	base := t.TempDir()
	left, right := filepath.Join(base, "left"), filepath.Join(base, "right")
	opts := BundleOptions{Now: func() time.Time { return now }}
	for _, out := range []string{left, right} {
		if err := WriteBundle(out, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, opts); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{
		"data/database.json",
		"data/findings.json",
		"data/overview.json",
		"data/diagnostics.json",
		"data/manifest.json",
		"data/nav.json",
		"data/explorer.json",
		"results.sarif",
	} {
		a, err := os.ReadFile(filepath.Join(left, rel))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(right, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs across fixed-clock bundles", rel)
		}
		if strings.Contains(string(a), differentSummaryTime.Format(time.RFC3339)) {
			t.Fatalf("%s retained the summary's pre-bundle timestamp", rel)
		}
	}
}

func TestLegacyFixedClockBundleDoesNotMutateDatabase(t *testing.T) {
	legacy := types.NewDatabase()
	legacy.ProjectRoot = "/repo"
	consumerFile := "/repo/C.sol"
	legacy.AddSourceFile(&types.SourceFile{Path: consumerFile, Imports: []string{"@dep/I.sol"}})
	for _, file := range []string{"/repo/a/I.sol", "/repo/z/I.sol"} {
		iface := &types.Contract{
			Name:       "I",
			SourceFile: file,
			Kind:       types.ContractKindInterface,
			Functions:  []*types.Function{{Name: "ping", Selector: "ping()", ContractName: "I", SourceFile: file}},
		}
		legacy.AddContract(iface)
	}
	body := types.NewASTNode(types.KindDeclFunction)
	legacy.AddContract(&types.Contract{
		Name:            "C",
		SourceFile:      consumerFile,
		Kind:            types.ContractKindContract,
		LinearizedBases: []string{"C", "I"},
		Functions: []*types.Function{{
			Name: "ping", Selector: "ping()", ContractName: "C", SourceFile: consumerFile, AST: body,
		}},
	})

	cache := filepath.Join(t.TempDir(), "legacy.json")
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := types.LoadFromJSON(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Diagnostics) != 1 || db.Diagnostics[0].Code != types.DiagnosticIdentity {
		t.Fatalf("legacy identity diagnostics were not enriched at load time: %#v", db.Diagnostics)
	}
	before, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC)
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return now }}).GenerateSummary()
	base := t.TempDir()
	left, right := filepath.Join(base, "left"), filepath.Join(base, "right")
	for _, out := range []string{left, right} {
		if err := WriteBundle(out, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{Now: func() time.Time { return now }}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("WriteBundle mutated the loaded legacy database")
	}
	for _, rel := range []string{
		"data/database.json", "data/findings.json", "data/overview.json",
		"data/diagnostics.json", "data/manifest.json", "data/nav.json",
		"data/explorer.json", "results.sarif",
	} {
		a, err := os.ReadFile(filepath.Join(left, rel))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(right, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("legacy fixed-clock artifact differs: %s", rel)
		}
	}
}

func TestExplicitProjectRootsDoNotUseLegacyGlobal(t *testing.T) {
	SetReportProjectRoot("/legacy/wrong")
	t.Cleanup(func() { SetReportProjectRoot("") })

	leftDB, rightDB := types.NewDatabase(), types.NewDatabase()
	leftDB.ProjectRoot, rightDB.ProjectRoot = "/left", "/right"
	leftFinding := []*engine.Finding{{
		TemplateID: "left", Severity: "LOW", Title: "left",
		Location: engine.Location{File: "/left/src/A.sol", Line: 1},
	}}
	rightFinding := []*engine.Finding{{
		TemplateID: "right", Severity: "LOW", Title: "right",
		Location: engine.Location{File: "/right/test/B.sol", Line: 1},
	}}

	left := FormatFindingsAsMarkdown(leftFinding, leftDB)
	right := FormatFindingsAsMarkdown(rightFinding, rightDB)
	if !strings.Contains(left, "src/A.sol") || strings.Contains(left, "/legacy") || strings.Contains(left, "/right") {
		t.Fatalf("left report used the wrong root:\n%s", left)
	}
	if !strings.Contains(right, "test/B.sol") || strings.Contains(right, "/legacy") || strings.Contains(right, "/left") {
		t.Fatalf("right report used the wrong root:\n%s", right)
	}
}

func TestWriteBundleEmitsDiagnosticsAndHumanLinks(t *testing.T) {
	db := navFixtureDB()
	db.ProjectRoot, db.ScanTarget = "/repo", "/repo/src"
	diagnostic := types.Diagnostic{
		Code:       types.DiagnosticUnresolvedImport,
		Severity:   types.DiagnosticWarning,
		Phase:      "reader",
		Message:    "missing import",
		Incomplete: true,
	}
	db.AddDiagnostic(diagnostic)
	db.AddDiagnostic(diagnostic)
	summary := NewGeneratorWithOptions(db, GeneratorOptions{Now: func() time.Time { return time.Unix(0, 0) }}).GenerateSummary()
	out := t.TempDir()
	if err := WriteBundle(out, db, summary, nil, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{Now: func() time.Time { return time.Unix(0, 0) }}); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"README.md", "overview.md"} {
		b, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if !strings.Contains(text, "data/diagnostics.json") || !strings.Contains(strings.ToLower(text), "incomplete") {
			t.Fatalf("%s does not expose incomplete diagnostics:\n%s", rel, text)
		}
	}
	b, err := os.ReadFile(filepath.Join(out, "data", "diagnostics.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"analysisComplete": false`)) || !bytes.Contains(b, []byte(`"code": "import.unresolved"`)) {
		t.Fatalf("unexpected diagnostics artifact:\n%s", b)
	}
	databaseBytes, err := os.ReadFile(filepath.Join(out, "data", "database.json"))
	if err != nil {
		t.Fatal(err)
	}
	var databaseCopy types.Database
	if err := json.Unmarshal(databaseBytes, &databaseCopy); err != nil {
		t.Fatal(err)
	}
	if len(databaseCopy.Diagnostics) != 1 {
		t.Fatalf("bundled database diagnostics = %#v, want one normalized record", databaseCopy.Diagnostics)
	}
}
