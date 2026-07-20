package engine

import (
	"fmt"

	"github.com/th13vn/w3goaudit/pkg/types"
)

type lowerContext struct {
	Function    *types.Function
	Contract    *types.Contract
	ScopeID     string
	ContractID  string
	Occurrences map[*types.ASTNode]string
	Diagnostics *[]types.Diagnostic
}

type semanticAnalyzer struct {
	db             *types.Database
	lowered        map[string]*semanticFunction
	diagnosticKeys map[string]struct{}
	diagnostics    []types.Diagnostic
}

func newSemanticAnalyzer(db *types.Database) *semanticAnalyzer {
	analyzer := &semanticAnalyzer{
		db:             db,
		lowered:        make(map[string]*semanticFunction),
		diagnosticKeys: make(map[string]struct{}),
	}
	if db != nil {
		for _, diagnostic := range db.Diagnostics {
			analyzer.diagnosticKeys[semanticDiagnosticKey(diagnostic)] = struct{}{}
		}
	}
	return analyzer
}

func semanticDiagnosticKey(diagnostic types.Diagnostic) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%s\x00%s\x00%t", diagnostic.Code, diagnostic.Severity, diagnostic.Phase, diagnostic.Message, diagnostic.File, diagnostic.Line, diagnostic.ImportPath, diagnostic.Symbol, diagnostic.Incomplete)
}
