package report

import (
	"time"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// DiagnosticCounts is the per-severity tally for analysis-quality diagnostics.
// Diagnostics describe analysis completeness and are independent of security
// finding severities.
type DiagnosticCounts struct {
	Info    int `json:"info"`
	Warning int `json:"warning"`
	Error   int `json:"error"`
	Unknown int `json:"unknown,omitempty"`
}

// DiagnosticsJSON is the durable machine-readable analysis-quality artifact.
type DiagnosticsJSON struct {
	SchemaVersion    string             `json:"schemaVersion"`
	GeneratedAt      time.Time          `json:"generatedAt"`
	AnalysisComplete bool               `json:"analysisComplete"`
	Counts           DiagnosticCounts   `json:"counts"`
	Diagnostics      []types.Diagnostic `json:"diagnostics"`
}

// BuildDiagnosticsJSON constructs a diagnostics document using the current UTC
// time. Use BuildDiagnosticsJSONAt when deterministic output is required.
func BuildDiagnosticsJSON(db *types.Database) *DiagnosticsJSON {
	return BuildDiagnosticsJSONAt(time.Now().UTC(), db)
}

// BuildDiagnosticsJSONAt constructs a diagnostics document at a caller-supplied
// timestamp. The returned records are deduplicated and total-order sorted
// without mutating the database.
func BuildDiagnosticsJSONAt(now time.Time, db *types.Database) *DiagnosticsJSON {
	diagnostics := diagnosticSnapshot(db)
	return &DiagnosticsJSON{
		SchemaVersion:    SchemaVersion,
		GeneratedAt:      now.UTC(),
		AnalysisComplete: analysisComplete(diagnostics, db != nil),
		Counts:           countDiagnostics(diagnostics),
		Diagnostics:      diagnostics,
	}
}

func diagnosticSnapshot(db *types.Database) []types.Diagnostic {
	if db == nil || len(db.Diagnostics) == 0 {
		return []types.Diagnostic{}
	}
	seen := make(map[types.Diagnostic]struct{}, len(db.Diagnostics))
	diagnostics := make([]types.Diagnostic, 0, len(db.Diagnostics))
	for _, diagnostic := range db.Diagnostics {
		if _, exists := seen[diagnostic]; exists {
			continue
		}
		seen[diagnostic] = struct{}{}
		diagnostics = append(diagnostics, diagnostic)
	}
	types.SortDiagnostics(diagnostics)
	return diagnostics
}

func countDiagnostics(diagnostics []types.Diagnostic) DiagnosticCounts {
	var counts DiagnosticCounts
	for _, diagnostic := range diagnostics {
		switch diagnostic.Severity {
		case types.DiagnosticInfo:
			counts.Info++
		case types.DiagnosticWarning:
			counts.Warning++
		case types.DiagnosticError:
			counts.Error++
		default:
			counts.Unknown++
		}
	}
	return counts
}

func analysisComplete(diagnostics []types.Diagnostic, databaseAvailable bool) bool {
	if !databaseAvailable {
		return false
	}
	for _, diagnostic := range diagnostics {
		if diagnostic.Incomplete {
			return false
		}
	}
	return true
}

func diagnosticCountTotal(counts DiagnosticCounts) int {
	return counts.Info + counts.Warning + counts.Error + counts.Unknown
}

func scanTarget(projectRoot, scanTarget string) string {
	if scanTarget != "" {
		return scanTarget
	}
	return projectRoot
}
