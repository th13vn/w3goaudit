package report

import (
	"encoding/json"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func explorerFixtureDB() *types.Database {
	db := types.NewDatabase()
	c := &types.Contract{
		ID: "/x.sol#Vault", Name: "Vault", Kind: types.ContractKindContract,
		SourceFile: "/x.sol", LinearizedBases: []string{"Vault"}, LinearizedBaseIDs: []string{"/x.sol#Vault"},
		StartLine: 3, StartCol: 1,
		StateVariables: []*types.StateVariable{
			{Name: "MAX", TypeName: "uint256", Visibility: "public", IsConstant: true, StartLine: 4},
			{Name: "owner", TypeName: "address", Visibility: "public", StartLine: 5},
			{Name: "balances", TypeName: "mapping(address=>uint256)", Visibility: "internal", StartLine: 6},
		},
		Functions: []*types.Function{
			{Name: "deposit", ContractName: "Vault", Visibility: types.VisibilityExternal, StateMutability: types.StateMutabilityPayable, Selector: "deposit()", Signature: "0xaabbccdd", StartLine: 8},
			{Name: "balanceOf", ContractName: "Vault", Visibility: types.VisibilityPublic, StateMutability: types.StateMutabilityView, Selector: "balanceOf(address)", StartLine: 12},
			{Name: "_helper", ContractName: "Vault", Visibility: types.VisibilityInternal, StartLine: 16},
		},
	}
	db.Contracts[c.ID] = c
	db.MainContracts[c.ID] = &types.MainContractEntry{LinearizedBases: []string{"Vault"}, LinearizedBaseIDs: []string{"/x.sol#Vault"}}
	return db
}

func TestBuildExplorerJSON(t *testing.T) {
	got := BuildExplorerJSON(explorerFixtureDB())
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", got.SchemaVersion, SchemaVersion)
	}
	if len(got.Contracts) != 1 {
		t.Fatalf("contracts = %d, want 1", len(got.Contracts))
	}
	ec := got.Contracts[0]
	if ec.ID != "/x.sol#Vault" || ec.Name != "Vault" {
		t.Errorf("contract id/name = %q/%q", ec.ID, ec.Name)
	}
	// MAX is a constant; owner + balances are storage (source order preserved).
	if len(ec.Constants) != 1 || ec.Constants[0].Name != "MAX" {
		t.Errorf("constants = %+v, want [MAX]", ec.Constants)
	}
	if len(ec.Storage) != 2 || ec.Storage[0].Name != "owner" || ec.Storage[1].Name != "balances" {
		t.Errorf("storage = %+v, want [owner balances]", ec.Storage)
	}
	if ec.Storage[0].Range.StartLine != 5 {
		t.Errorf("owner range line = %d, want 5", ec.Storage[0].Range.StartLine)
	}
	// deposit is entry-callable (payable external); balanceOf is a getter (view); _helper is neither.
	if len(ec.EntryFunctions) != 1 || ec.EntryFunctions[0].Name != "deposit" {
		t.Errorf("entryFunctions = %+v, want [deposit]", ec.EntryFunctions)
	}
	if ec.EntryFunctions[0].Selector != "deposit()" {
		t.Errorf("deposit selector = %q", ec.EntryFunctions[0].Selector)
	}
	if len(ec.Getters) != 1 || ec.Getters[0].Name != "balanceOf" {
		t.Errorf("getters = %+v, want [balanceOf]", ec.Getters)
	}
	// JSON shape round-trips.
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !json.Valid(b) {
		t.Fatal("invalid JSON")
	}
}
