package report

import "github.com/th13vn/w3goaudit/pkg/types"

const unavailableInteractionsLimitation = "external-boundary facts are unavailable; rebuild the database from source"

// InteractionsJSON is the deterministic machine-readable external-boundary
// artifact. It intentionally has no timestamp so equal database content emits
// equal bytes.
type InteractionsJSON struct {
	SchemaVersion    string                        `json:"schemaVersion"`
	FactsVersion     string                        `json:"factsVersion"`
	Available        bool                          `json:"available"`
	AnalysisComplete bool                          `json:"analysisComplete"`
	DiagnosticCounts DiagnosticCounts              `json:"diagnosticCounts"`
	Count            int                           `json:"count"`
	Limitations      []string                      `json:"limitations"`
	Interactions     []*types.ExternalBoundaryFact `json:"interactions"`
}

// BuildInteractionsJSON snapshots the versioned external-boundary facts and
// analysis-quality metadata without retaining aliases to the database.
func BuildInteractionsJSON(db *types.Database) *InteractionsJSON {
	diagnostics := diagnosticSnapshot(db)
	doc := &InteractionsJSON{
		SchemaVersion:    SchemaVersion,
		AnalysisComplete: analysisComplete(diagnostics, db != nil),
		DiagnosticCounts: countDiagnostics(diagnostics),
		Limitations:      []string{},
		Interactions:     []*types.ExternalBoundaryFact{},
	}
	if db == nil {
		doc.Limitations = []string{unavailableInteractionsLimitation}
		return doc
	}
	facts, err := db.ExternalBoundarySnapshot()
	if err != nil {
		doc.Limitations = []string{unavailableInteractionsLimitation}
		return doc
	}
	doc.FactsVersion = types.ExternalBoundaryFactsVersion
	doc.Available = true
	doc.Count = len(facts)
	doc.Interactions = facts
	return doc
}
