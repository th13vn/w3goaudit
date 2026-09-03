package report

import "github.com/th13vn/w3goaudit/pkg/types"

type AuthorizationJSON struct {
	SchemaVersion string                     `json:"schemaVersion"`
	FactsVersion  string                     `json:"factsVersion"`
	Available     bool                       `json:"available"`
	Count         int                        `json:"count"`
	Limitations   []string                   `json:"limitations"`
	Facts         []*types.AuthorizationFact `json:"facts"`
}

func BuildAuthorizationJSON(db *types.Database) *AuthorizationJSON {
	doc := &AuthorizationJSON{SchemaVersion: SchemaVersion, Limitations: []string{}, Facts: []*types.AuthorizationFact{}}
	if db == nil {
		doc.Limitations = []string{"authorization facts unavailable; rebuild the database from source"}
		return doc
	}
	facts, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		doc.Limitations = []string{err.Error()}
		return doc
	}
	doc.Available = true
	doc.FactsVersion = types.AuthorizationFactsVersion
	doc.Count = len(facts)
	doc.Facts = facts
	return doc
}
