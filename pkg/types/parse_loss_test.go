package types

import "testing"

// TestIsParseLossSeparatesParseFromResolution pins the distinction the CLI relies
// on: parse codes mean the AST is missing, so the affected declarations are
// invisible to every detector. Resolution codes mean the AST exists and only a
// reference could not be bound, which is imprecision rather than blindness. The
// two get different console wording and different strict flags, so a code must
// never drift between the categories.
func TestIsParseLossSeparatesParseFromResolution(t *testing.T) {
	parseLoss := []string{DiagnosticParseRecovered, DiagnosticParseSkipped}
	notParseLoss := []string{
		DiagnosticUnresolvedImport,
		DiagnosticUnresolvedBase,
		DiagnosticIdentity,
		DiagnosticInvalidLocation,
		DiagnosticSemanticUnsupported,
		"",
		"some.unknown.code",
	}

	for _, code := range parseLoss {
		if !IsParseLoss(code) {
			t.Errorf("IsParseLoss(%q) = false, want true", code)
		}
	}
	for _, code := range notParseLoss {
		if IsParseLoss(code) {
			t.Errorf("IsParseLoss(%q) = true, want false", code)
		}
	}
}

func TestParseLossFilesDeduplicatesAndSorts(t *testing.T) {
	diagnostics := []Diagnostic{
		{Code: DiagnosticParseRecovered, File: "/z/Late.sol", Line: 9},
		{Code: DiagnosticUnresolvedImport, File: "/never/Counted.sol"},
		{Code: DiagnosticParseRecovered, File: "/a/Early.sol", Line: 1},
		{Code: DiagnosticParseRecovered, File: "/a/Early.sol", Line: 4},
		{Code: DiagnosticParseSkipped, File: "/m/Middle.sol"},
	}

	files, total := ParseLossFiles(diagnostics)
	if total != 4 {
		t.Errorf("total = %d, want 4 (every parse diagnostic, including repeats per file)", total)
	}
	want := []string{"/a/Early.sol", "/m/Middle.sol", "/z/Late.sol"}
	if len(files) != len(want) {
		t.Fatalf("files = %v, want %v", files, want)
	}
	for i, expected := range want {
		if files[i] != expected {
			t.Errorf("files[%d] = %q, want %q (sorted, deduplicated)", i, files[i], expected)
		}
	}
}

// TestParseLossFilesHandlesMissingFile covers a parse diagnostic with no file
// attribution: it must still be counted, since suppressing it would understate
// the loss, but it cannot appear in the file list.
func TestParseLossFilesHandlesMissingFile(t *testing.T) {
	files, total := ParseLossFiles([]Diagnostic{
		{Code: DiagnosticParseRecovered},
		{Code: DiagnosticParseRecovered, File: "/a/A.sol"},
	})
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(files) != 1 || files[0] != "/a/A.sol" {
		t.Errorf("files = %v, want only the attributed file", files)
	}
}

func TestParseLossFilesEmpty(t *testing.T) {
	files, total := ParseLossFiles(nil)
	if total != 0 || files != nil {
		t.Errorf("ParseLossFiles(nil) = (%v, %d), want (nil, 0)", files, total)
	}
	files, total = ParseLossFiles([]Diagnostic{{Code: DiagnosticIdentity, File: "/a/A.sol"}})
	if total != 0 || files != nil {
		t.Errorf("resolution-only diagnostics reported parse loss: (%v, %d)", files, total)
	}
}

// TestAnalysisCompleteReflectsIncompleteDiagnostics ties the diagnostic layer to
// the manifest flag that consumers read.
func TestAnalysisCompleteReflectsIncompleteDiagnostics(t *testing.T) {
	db := NewDatabase()
	if !db.AnalysisComplete() {
		t.Error("a database with no diagnostics should be complete")
	}
	db.AddDiagnostic(Diagnostic{Code: DiagnosticParseRecovered, Severity: DiagnosticWarning})
	if !db.AnalysisComplete() {
		t.Error("a diagnostic that is not marked Incomplete should not flip the flag")
	}
	db.AddDiagnostic(Diagnostic{Code: DiagnosticParseRecovered, Severity: DiagnosticWarning, Incomplete: true})
	if db.AnalysisComplete() {
		t.Error("an Incomplete diagnostic must make analysis incomplete")
	}
}
