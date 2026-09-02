package types

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestQueryExternalBoundariesRequiresAvailableBoundedExactFacts(t *testing.T) {
	db := NewDatabase()
	if _, err := db.QueryExternalBoundaries(ExternalBoundaryQuery{Limit: 10}); !errors.Is(err, ErrExternalBoundaryFactsUnavailable) {
		t.Fatalf("legacy query error = %v, want unavailable sentinel", err)
	}

	contract := &Contract{ID: MakeContractID("/src/Vault.sol", "Vault"), Name: "Vault", SourceFile: "/src/Vault.sol"}
	fn := &Function{Name: "withdraw", ContractName: contract.Name, SourceFile: contract.SourceFile, Selector: "withdraw(uint256)"}
	contract.Functions = []*Function{fn}
	db.AddContract(contract)
	db.MainContracts[contract.ID] = &MainContractEntry{EntryFunctions: []string{MakeFunctionID(fn.SourceFile, fn.ContractName, fn.Selector)}}
	db.Semantics.ExternalBoundaryVersion = ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*ExternalBoundaryFact{}

	for _, tc := range []struct {
		name  string
		query ExternalBoundaryQuery
	}{
		{name: "zero limit", query: ExternalBoundaryQuery{}},
		{name: "over limit", query: ExternalBoundaryQuery{Limit: MaxExternalBoundaryQueryLimit + 1}},
		{name: "negative offset", query: ExternalBoundaryQuery{Limit: 1, Offset: -1}},
		{name: "unknown contract", query: ExternalBoundaryQuery{Limit: 1, ContractID: "/src/Missing.sol#Missing"}},
		{name: "unknown function", query: ExternalBoundaryQuery{Limit: 1, FunctionID: "/src/Vault.sol#Vault.missing()"}},
		{name: "unknown entry", query: ExternalBoundaryQuery{Limit: 1, EntryFunctionID: "/src/Vault.sol#Vault.missing()"}},
		{name: "unknown kind", query: ExternalBoundaryQuery{Limit: 1, Kinds: []string{"call.protocol.magic"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.QueryExternalBoundaries(tc.query); err == nil {
				t.Fatal("query unexpectedly succeeded")
			}
		})
	}
}

func TestQueryExternalBoundariesFiltersPagesAndDeepCopies(t *testing.T) {
	db, contract, firstFunction, secondFunction := boundaryQueryDatabase(t)
	firstEntry := MakeFunctionID(firstFunction.SourceFile, firstFunction.ContractName, firstFunction.Selector)
	secondEntry := MakeFunctionID(secondFunction.SourceFile, secondFunction.ContractName, secondFunction.Selector)

	page, err := db.QueryExternalBoundaries(ExternalBoundaryQuery{
		ContractID:      contract.ID,
		EntryFunctionID: firstEntry,
		Kinds:           []string{KindCallLowlevelCall},
		Offset:          0,
		Limit:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 1 || !page.Truncated || page.Offset != 0 || page.Limit != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Items[0].ID != "a" || page.Items[0].Arguments[0].Index != 0 {
		t.Fatalf("first item = %+v", page.Items[0])
	}

	page.Items[0].ID = "mutated"
	page.Items[0].Arguments[0].TaintSources[0] = "mutated"
	stored, ok := db.GetExternalBoundaryByID("a")
	if !ok || stored.ID != "a" || stored.Arguments[0].TaintSources[0] != "parameter" {
		t.Fatalf("stored fact was mutated through query result: %+v", stored)
	}
	stored.ID = "changed again"
	if again, ok := db.GetExternalBoundaryByID("a"); !ok || again.ID != "a" {
		t.Fatalf("lookup did not return a deep copy: %+v", again)
	}

	secondPage, err := db.QueryExternalBoundaries(ExternalBoundaryQuery{FunctionID: secondEntry, Offset: 0, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if secondPage.Total != 1 || len(secondPage.Items) != 1 || secondPage.Items[0].ID != "c" || secondPage.Truncated {
		t.Fatalf("function-filtered page = %+v", secondPage)
	}
}

func TestExternalBoundaryFactsNormalizeDeterministically(t *testing.T) {
	facts := []*ExternalBoundaryFact{
		{ID: "z", Arguments: nil, ReachableFrom: []string{"b", "a", "a"}, Limitations: []string{"z", "a", "z"}},
		nil,
		{ID: "a", Arguments: []BoundaryValue{{Role: BoundaryValueRoleArgument, Index: 0, RefIDs: []string{"z", "a", "a"}, TaintSources: []string{"state_var", "parameter", "parameter"}}}},
	}
	got := NormalizeExternalBoundaryFacts(facts)
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" {
		t.Fatalf("normalized order = %+v", got)
	}
	if got[0].Arguments == nil || got[0].Arguments[0].Index != 0 {
		t.Fatalf("argument shape lost: %+v", got[0].Arguments)
	}
	if !reflect.DeepEqual(got[0].Arguments[0].RefIDs, []string{"a", "z"}) || !reflect.DeepEqual(got[0].Arguments[0].TaintSources, []string{"parameter", "state_var"}) {
		t.Fatalf("nested evidence not normalized: %+v", got[0].Arguments[0])
	}
	if got[1].Arguments == nil || !reflect.DeepEqual(got[1].ReachableFrom, []string{"a", "b"}) || !reflect.DeepEqual(got[1].Limitations, []string{"a", "z"}) {
		t.Fatalf("nil or set normalization failed: %+v", got[1])
	}
}

func TestGetFunctionByIDUsesExactSelectorIdentity(t *testing.T) {
	db := NewDatabase()
	contract := &Contract{ID: MakeContractID("/src/Vault.sol", "Vault"), Name: "Vault", SourceFile: "/src/Vault.sol"}
	first := &Function{Name: "withdraw", ContractName: contract.Name, SourceFile: contract.SourceFile, Selector: "withdraw(uint256)"}
	second := &Function{Name: "withdraw", ContractName: contract.Name, SourceFile: contract.SourceFile, Selector: "withdraw(address)"}
	contract.Functions = []*Function{first, second}
	db.AddContract(contract)

	got, ok := db.GetFunctionByID(MakeFunctionID(contract.SourceFile, contract.Name, second.Selector))
	if !ok || got != second {
		t.Fatalf("exact overload lookup = %p, %v; want %p, true", got, ok, second)
	}
	if got, ok := db.GetFunctionByID("/src/Vault.sol#Vault.withdraw"); ok || got != nil {
		t.Fatalf("name-only function lookup = %v, %v; want nil, false", got, ok)
	}
}

func TestQueryExternalBoundariesFiltersByExactEntryID(t *testing.T) {
	db, _, firstFunction, secondFunction := boundaryQueryDatabase(t)
	firstEntry := MakeFunctionID(firstFunction.SourceFile, firstFunction.ContractName, firstFunction.Selector)
	secondEntry := MakeFunctionID(secondFunction.SourceFile, secondFunction.ContractName, secondFunction.Selector)
	page, err := db.QueryExternalBoundaries(ExternalBoundaryQuery{EntryFunctionID: firstEntry, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("first entry page = %+v", page)
	}
	for _, fact := range page.Items {
		if !containsString(fact.ReachableFrom, firstEntry) || containsString(fact.ReachableFrom, secondEntry) {
			t.Fatalf("entry filter leaked fact: %+v", fact)
		}
	}
}

func TestLoadFromJSONInitializesLegacySemanticContainersWithoutEnablingBoundaryFacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte(`{"semantics":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := LoadFromJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if db.Semantics.Symbols == nil || db.Semantics.FunctionEffects == nil || db.Semantics.ExternalBoundaries == nil {
		t.Fatalf("legacy semantic containers were not initialized: %+v", db.Semantics)
	}
	if db.Semantics.ExternalBoundaryVersion != "" {
		t.Fatalf("legacy cache gained boundary capability version %q", db.Semantics.ExternalBoundaryVersion)
	}
	if _, err := db.QueryExternalBoundaries(ExternalBoundaryQuery{Limit: 1}); !errors.Is(err, ErrExternalBoundaryFactsUnavailable) {
		t.Fatalf("legacy boundary query error = %v, want unavailable", err)
	}
}

func boundaryQueryDatabase(t *testing.T) (*Database, *Contract, *Function, *Function) {
	t.Helper()
	db := NewDatabase()
	contract := &Contract{ID: MakeContractID("/src/Vault.sol", "Vault"), Name: "Vault", SourceFile: "/src/Vault.sol"}
	first := &Function{Name: "withdraw", ContractName: contract.Name, SourceFile: contract.SourceFile, Selector: "withdraw(uint256)"}
	second := &Function{Name: "forward", ContractName: contract.Name, SourceFile: contract.SourceFile, Selector: "forward(bytes)"}
	contract.Functions = []*Function{first, second}
	db.AddContract(contract)
	firstID := MakeFunctionID(first.SourceFile, first.ContractName, first.Selector)
	secondID := MakeFunctionID(second.SourceFile, second.ContractName, second.Selector)
	db.MainContracts[contract.ID] = &MainContractEntry{EntryFunctions: []string{firstID, secondID}}
	db.Semantics.ExternalBoundaryVersion = ExternalBoundaryFactsVersion
	db.Semantics.ExternalBoundaries = []*ExternalBoundaryFact{
		{ID: "c", ContractID: contract.ID, FunctionID: secondID, Kind: KindCallLowlevelDelegate, ReachableFrom: []string{secondID}},
		{ID: "b", ContractID: contract.ID, FunctionID: firstID, Kind: KindCallLowlevelCall, ReachableFrom: []string{firstID}},
		{ID: "a", ContractID: contract.ID, FunctionID: firstID, Kind: KindCallLowlevelCall, ReachableFrom: []string{firstID}, Arguments: []BoundaryValue{{Role: BoundaryValueRoleArgument, Index: 0, TaintSources: []string{"parameter"}}}},
	}
	db.Semantics.ExternalBoundaries = NormalizeExternalBoundaryFacts(db.Semantics.ExternalBoundaries)
	return db, contract, first, second
}
