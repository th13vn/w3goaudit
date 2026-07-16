package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiagnosticsNormalizeAndRoundTrip(t *testing.T) {
	db := NewDatabase()
	duplicate := Diagnostic{
		Code:       DiagnosticUnresolvedImport,
		Severity:   DiagnosticWarning,
		Phase:      "reader",
		Message:    "missing import",
		File:       "/b.sol",
		ImportPath: "./X.sol",
		Incomplete: true,
	}
	db.AddDiagnostic(duplicate)
	db.AddDiagnostic(duplicate)
	db.AddDiagnostic(Diagnostic{
		Code:       DiagnosticParseRecovered,
		Severity:   DiagnosticWarning,
		Phase:      "builder",
		Message:    "recovered parser error",
		File:       "/a.sol",
		Line:       7,
		Incomplete: true,
	})

	db.NormalizeDiagnostics()
	if len(db.Diagnostics) != 2 {
		t.Fatalf("diagnostics = %#v, want two unique records", db.Diagnostics)
	}
	// The public ordering contract is severity, code, file, line, importPath,
	// symbol, message (with phase/incomplete as final total-order tie-breakers).
	if db.Diagnostics[0].Code != DiagnosticUnresolvedImport || db.Diagnostics[1].Code != DiagnosticParseRecovered {
		t.Fatalf("diagnostic order = %#v", db.Diagnostics)
	}
	if db.AnalysisComplete() {
		t.Fatal("AnalysisComplete() = true with incomplete diagnostics")
	}

	encoded, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Database
	if err := json.Unmarshal(encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	loaded.NormalizeDiagnostics()
	if !reflect.DeepEqual(db.Diagnostics, loaded.Diagnostics) {
		t.Fatalf("diagnostics changed across JSON round-trip:\n got: %#v\nwant: %#v", loaded.Diagnostics, db.Diagnostics)
	}
}

func TestDiagnosticsAnalysisCompleteAndLegacyJSON(t *testing.T) {
	db := NewDatabase()
	db.AddDiagnostic(Diagnostic{
		Code:     "analysis.note",
		Severity: DiagnosticInfo,
		Phase:    "builder",
		Message:  "informational only",
	})
	if !db.AnalysisComplete() {
		t.Fatal("informational complete diagnostic marked analysis incomplete")
	}

	var legacy Database
	if err := json.Unmarshal([]byte(`{"projectRoot":"/project"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ScanTarget != "" {
		t.Fatalf("legacy ScanTarget = %q, want empty", legacy.ScanTarget)
	}
	if len(legacy.Diagnostics) != 0 {
		t.Fatalf("legacy diagnostics = %#v, want empty", legacy.Diagnostics)
	}
	if !legacy.AnalysisComplete() {
		t.Fatal("legacy database without diagnostics should be complete")
	}

	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte(`{"projectRoot":"/project"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromJSON(path)
	if err != nil {
		t.Fatalf("LoadFromJSON legacy database: %v", err)
	}
	if loaded.ScanTarget != "" || loaded.Diagnostics == nil || len(loaded.Diagnostics) != 0 {
		t.Fatalf("loaded legacy metadata = target %q diagnostics %#v", loaded.ScanTarget, loaded.Diagnostics)
	}
}
