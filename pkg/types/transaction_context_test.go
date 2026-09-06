package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeTransactionContextFactsSortsDeduplicatesAndCopies(t *testing.T) {
	facts := []*TransactionContextFact{
		{
			ID: "fact-b", ContractID: "contract-b", ScopeID: "scope-b",
			Source: TransactionContextSourceMsgValue, Use: TransactionContextUseCallValue,
			Repeatability: TransactionContextRepeatabilityPossible,
			SourceRange:   SemanticSourceRange{File: "b.sol", StartByte: 20},
		},
		{
			ID: "fact-a", ContractID: "contract-a", ScopeID: "scope-a",
			Source: TransactionContextSourceMsgValue, Use: TransactionContextUseStateWrite,
			Repeatability: TransactionContextRepeatabilityPossible,
			SourceRange:   SemanticSourceRange{File: "a.sol", StartByte: 10},
		},
		{
			ID: "fact-a", ContractID: "contract-a", ScopeID: "scope-a",
			Source: TransactionContextSourceMsgValue, Use: TransactionContextUseStateWrite,
			Repeatability: TransactionContextRepeatabilityPossible,
			SourceRange:   SemanticSourceRange{File: "a.sol", StartByte: 10},
		},
	}
	got := NormalizeTransactionContextFacts(facts)
	if len(got) != 2 || got[0].ID != "fact-a" || got[1].ID != "fact-b" {
		t.Fatalf("normalized facts = %+v", got)
	}
	facts[0].Source = "mutated"
	facts[0].SourceRange.File = "mutated.sol"
	if got[1].Source != TransactionContextSourceMsgValue || got[1].SourceRange.File != "b.sol" {
		t.Fatal("normalized result retained caller-owned storage")
	}
}

func TestLegacyDatabaseHasNoTransactionContextCapability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte("{\"semantics\":{}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := LoadFromJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if db.Semantics == nil || db.Semantics.TransactionContextVersion != "" {
		t.Fatalf("legacy transaction context capability = %+v", db.Semantics)
	}
	if _, err := db.TransactionContextFactsSnapshot(); err != ErrTransactionContextFactsUnavailable {
		t.Fatalf("legacy snapshot error = %v, want %v", err, ErrTransactionContextFactsUnavailable)
	}
}

func TestTransactionContextFactsSurviveJSONRoundTrip(t *testing.T) {
	db := NewDatabase()
	db.Semantics.TransactionContextVersion = TransactionContextFactsVersion
	db.Semantics.TransactionContextFacts = []*TransactionContextFact{{
		ID: "fact", Source: TransactionContextSourceMsgValue,
		Use: TransactionContextUseStateWrite, Repeatability: TransactionContextRepeatabilityPossible,
	}}
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Database
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Semantics == nil || loaded.Semantics.TransactionContextVersion != TransactionContextFactsVersion || len(loaded.Semantics.TransactionContextFacts) != 1 {
		t.Fatalf("round-tripped facts = %+v", loaded.Semantics)
	}
}
