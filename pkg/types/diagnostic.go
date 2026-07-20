package types

import "sort"

// DiagnosticSeverity is the stable severity vocabulary for analysis
// diagnostics. Diagnostics describe analysis quality, not security findings.
type DiagnosticSeverity string

const (
	DiagnosticInfo    DiagnosticSeverity = "info"
	DiagnosticWarning DiagnosticSeverity = "warning"
	DiagnosticError   DiagnosticSeverity = "error"

	DiagnosticUnresolvedImport    = "import.unresolved"
	DiagnosticParseSkipped        = "parse.skipped"
	DiagnosticParseRecovered      = "parse.recovered"
	DiagnosticUnresolvedBase      = "inheritance.base_unresolved"
	DiagnosticInvalidLocation     = "location.invalid"
	DiagnosticIdentity            = "identity.unresolved"
	DiagnosticSemanticUnsupported = "analysis.semantic_unsupported"
)

// Diagnostic is a durable record of analysis loss or noteworthy analysis
// state. Incomplete marks records that mean the database may omit relevant
// source or semantic information.
type Diagnostic struct {
	Code       string             `json:"code"`
	Severity   DiagnosticSeverity `json:"severity"`
	Phase      string             `json:"phase"`
	Message    string             `json:"message"`
	File       string             `json:"file,omitempty"`
	Line       int                `json:"line,omitempty"`
	ImportPath string             `json:"importPath,omitempty"`
	Symbol     string             `json:"symbol,omitempty"`
	Incomplete bool               `json:"incomplete,omitempty"`
}

// SortDiagnostics applies the serialized diagnostic total order. The primary
// public key is severity, code, file, line, import path, symbol, and message;
// phase and incomplete are deterministic tie-breakers for otherwise distinct
// serialized records.
func SortDiagnostics(diagnostics []Diagnostic) {
	sort.Slice(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.Severity != right.Severity {
			return left.Severity < right.Severity
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if left.File != right.File {
			return left.File < right.File
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		if left.ImportPath != right.ImportPath {
			return left.ImportPath < right.ImportPath
		}
		if left.Symbol != right.Symbol {
			return left.Symbol < right.Symbol
		}
		if left.Message != right.Message {
			return left.Message < right.Message
		}
		if left.Phase != right.Phase {
			return left.Phase < right.Phase
		}
		return !left.Incomplete && right.Incomplete
	})
}
