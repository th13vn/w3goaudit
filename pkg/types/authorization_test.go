package types

import "testing"

func TestAuthorizationFactsSnapshotIsDeterministicAndDetached(t *testing.T) {
	db := NewDatabase()
	db.Semantics.AuthorizationFactsVersion = AuthorizationFactsVersion
	db.Semantics.AuthorizationFacts = []*AuthorizationFact{{
		ID: "z", Verdict: AuthorizationUnknown, Reasons: []string{"b", "a"},
	}, {
		ID: "a", Verdict: AuthorizationProtected, Reasons: []string{"z"},
	}}
	got, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" {
		t.Fatalf("unexpected order: %+v", got)
	}
	got[0].Reasons[0] = "mutated"
	again, err := db.AuthorizationFactsSnapshot()
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if again[0].Reasons[0] == "mutated" {
		t.Fatal("snapshot aliases database")
	}
}

func TestAuthorizationFactsQueryValidatesLimitAndExactFilters(t *testing.T) {
	db := NewDatabase()
	db.Semantics.AuthorizationFactsVersion = AuthorizationFactsVersion
	db.Semantics.AuthorizationFacts = []*AuthorizationFact{{ID: "f1", ContractID: "c1", ScopeID: "s1", Verdict: AuthorizationProtected}, {ID: "f2", ContractID: "c2", ScopeID: "s2", Verdict: AuthorizationUnknown}}
	if _, err := db.QueryAuthorizationFacts(AuthorizationQuery{Limit: 0}); err == nil {
		t.Fatal("expected invalid limit")
	}
	page, err := db.QueryAuthorizationFacts(AuthorizationQuery{ContractID: "c1", ScopeID: "s1", Verdict: AuthorizationProtected, Limit: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "f1" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestAuthorizationFactsLegacyCacheIsUnavailable(t *testing.T) {
	db := NewDatabase()
	if _, err := db.AuthorizationFactsSnapshot(); err != ErrAuthorizationFactsUnavailable {
		t.Fatalf("err=%v, want unavailable", err)
	}
}
