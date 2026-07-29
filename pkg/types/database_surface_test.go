package types

import (
	"sort"
	"testing"
)

// databaseFixture builds a small but realistic database: one deployable contract
// inheriting an abstract base, one interface, one library, and a duplicate
// contract name in a second file so identity behavior is exercised rather than
// assumed.
func databaseFixture() *Database {
	db := NewDatabase()

	vault := &Contract{
		Name:       "Vault",
		Kind:       ContractKindContract,
		SourceFile: "/src/Vault.sol",
		Functions: []*Function{
			{Name: "deposit", ContractName: "Vault", SourceFile: "/src/Vault.sol",
				Visibility: "external", Selector: "deposit(uint256)"},
			{Name: "peek", ContractName: "Vault", SourceFile: "/src/Vault.sol",
				Visibility: "external", StateMutability: "view", Selector: "peek()"},
			{Name: "_settle", ContractName: "Vault", SourceFile: "/src/Vault.sol",
				Visibility: "internal", Selector: "_settle()"},
		},
		StateVariables: []*StateVariable{{Name: "total"}},
	}
	base := &Contract{
		Name: "VaultBase", Kind: ContractKindAbstract, SourceFile: "/src/VaultBase.sol",
	}
	iface := &Contract{
		Name: "IVault", Kind: ContractKindInterface, SourceFile: "/src/IVault.sol",
	}
	lib := &Contract{
		Name: "VaultMath", Kind: ContractKindLibrary, SourceFile: "/src/VaultMath.sol",
	}
	// Same short name, different file: identity lookups must keep these apart.
	mock := &Contract{
		Name: "Vault", Kind: ContractKindContract, SourceFile: "/test/mocks/Vault.sol",
	}

	for _, contract := range []*Contract{vault, base, iface, lib, mock} {
		db.AddContract(contract)
		db.SourceFiles[contract.SourceFile] = &SourceFile{Path: contract.SourceFile}
	}
	return db
}

func TestContractIDAndKindPredicates(t *testing.T) {
	db := databaseFixture()

	vault := db.GetContractByID("/src/Vault.sol#Vault")
	if vault == nil {
		t.Fatal("exact ID lookup failed")
	}
	if got := vault.ID; got != "/src/Vault.sol#Vault" {
		t.Errorf("Contract.ID = %q, want absPath#Name", got)
	}
	if !vault.IsDeployable() || !vault.IsMainCandidate() {
		t.Error("a concrete contract should be deployable and a main candidate")
	}

	for _, name := range []string{"IVault", "VaultMath", "VaultBase"} {
		contract := db.FindContractsByName(name)
		if len(contract) != 1 {
			t.Fatalf("FindContractsByName(%q) = %d, want 1", name, len(contract))
		}
		if contract[0].IsDeployable() {
			t.Errorf("%s (%s) must not be deployable", name, contract[0].Kind)
		}
	}
}

// TestDuplicateContractNamesStayDistinct covers the documented reason exact IDs
// exist: two files may declare the same contract name, and a name-only lookup must
// be deterministic rather than map-order dependent.
func TestDuplicateContractNamesStayDistinct(t *testing.T) {
	db := databaseFixture()

	all := db.FindContractsByName("Vault")
	if len(all) != 2 {
		t.Fatalf("FindContractsByName(Vault) = %d, want 2", len(all))
	}

	// The compatibility helper must return the lex-min fully-qualified ID, the
	// same one on every run.
	first := db.GetContractByName("Vault")
	for range 25 {
		if again := db.GetContractByName("Vault"); again != first {
			t.Fatal("GetContractByName is not deterministic across calls")
		}
	}
	if first == nil || first.ID != "/src/Vault.sol#Vault" {
		t.Errorf("GetContractByName picked %v, want the lex-min ID", first)
	}

	// Exact resolution from an unrelated file must abstain rather than guess.
	if _, ok := db.ResolveContractNameExact("Vault", "/src/Unrelated.sol"); ok {
		t.Error("ResolveContractNameExact resolved an ambiguous name with no import provenance")
	}
}

func TestParseContractAndFunctionIDs(t *testing.T) {
	file, contract := ParseContractID("/src/Vault.sol#Vault")
	if file != "/src/Vault.sol" || contract != "Vault" {
		t.Errorf("ParseContractID = (%q, %q), want the file and contract halves", file, contract)
	}

	file, contract, selector := ParseFunctionID("/src/Vault.sol#Vault.deposit(uint256)")
	if file != "/src/Vault.sol" || contract != "Vault" || selector != "deposit(uint256)" {
		t.Errorf("ParseFunctionID = (%q, %q, %q), want the three components", file, contract, selector)
	}

	// A separator-less value is treated as a legacy bare contract name with no
	// file, which is what the unqualified-ID compatibility paths expect.
	if f, c := ParseContractID("LegacyName"); f != "" || c != "LegacyName" {
		t.Errorf("ParseContractID(LegacyName) = (%q, %q), want (\"\", \"LegacyName\")", f, c)
	}
}

func TestDatabaseStatsCountsKindsSeparately(t *testing.T) {
	db := databaseFixture()
	db.CalculateMainContracts()
	stats := db.GetStats()

	// Two concrete + one abstract are "contracts"; interfaces and libraries are
	// counted separately, which is the documented manifest contract.
	if stats.TotalContracts != 3 {
		t.Errorf("TotalContracts = %d, want 3 (2 concrete + 1 abstract)", stats.TotalContracts)
	}
	if stats.TotalInterfaces != 1 {
		t.Errorf("TotalInterfaces = %d, want 1", stats.TotalInterfaces)
	}
	if stats.TotalLibraries != 1 {
		t.Errorf("TotalLibraries = %d, want 1", stats.TotalLibraries)
	}
	if stats.TotalFunctions != 3 {
		t.Errorf("TotalFunctions = %d, want 3", stats.TotalFunctions)
	}
	// Only the non-view external function is an entry point.
	if stats.TotalEntryFunctions != 1 {
		t.Errorf("TotalEntryFunctions = %d, want 1 (deposit; peek is view, _settle is internal)",
			stats.TotalEntryFunctions)
	}
}

func TestGetAllFunctionsAndContractByFile(t *testing.T) {
	db := databaseFixture()

	names := make([]string, 0)
	for _, fn := range db.GetAllFunctions() {
		names = append(names, fn.Name)
	}
	sort.Strings(names)
	want := []string{"_settle", "deposit", "peek"}
	if len(names) != len(want) {
		t.Fatalf("GetAllFunctions = %v, want %v", names, want)
	}
	for i, expected := range want {
		if names[i] != expected {
			t.Errorf("GetAllFunctions[%d] = %q, want %q", i, names[i], expected)
		}
	}

	byFile := db.GetContractByFile("/src/Vault.sol")
	if len(byFile) != 1 || byFile[0].Name != "Vault" {
		t.Errorf("GetContractByFile = %v, want the single Vault declaration", byFile)
	}
	if got := db.GetContractByFile("/nowhere.sol"); len(got) != 0 {
		t.Errorf("GetContractByFile on an unknown path = %v, want none", got)
	}
}

func TestUnresolvedBasesReportsMissingInheritance(t *testing.T) {
	db := databaseFixture()
	vault := db.GetContractByID("/src/Vault.sol#Vault")
	vault.BaseContracts = []string{"VaultBase", "IMissingBase", "AlsoMissing"}

	missing := db.UnresolvedBases()
	want := []string{"AlsoMissing", "IMissingBase"}
	if len(missing) != len(want) {
		t.Fatalf("UnresolvedBases = %v, want %v (VaultBase is present)", missing, want)
	}
	for i, expected := range want {
		if missing[i] != expected {
			t.Errorf("UnresolvedBases[%d] = %q, want %q (sorted)", i, missing[i], expected)
		}
	}
}

func TestUniqueUDVTByNameAbstainsOnAmbiguity(t *testing.T) {
	db := NewDatabase()
	db.UserDefinedValueTypes = []*UDVTDef{
		{Name: "UD60x18", SourceFile: "/src/A.sol", UnderlyingType: "uint256"},
	}
	if got := db.UniqueUDVTByName("UD60x18"); got == nil {
		t.Fatal("a sole declaration should resolve")
	} else if got.ID() != "/src/A.sol#UD60x18" {
		t.Errorf("UDVTDef.ID() = %q, want absPath#Name", got.ID())
	}
	if got := db.UniqueUDVTByName("Missing"); got != nil {
		t.Errorf("UniqueUDVTByName(Missing) = %v, want nil", got)
	}

	// Two files declaring the same type name must bind to nothing, so xref never
	// jumps to a plausible-but-wrong declaration.
	db.UserDefinedValueTypes = append(db.UserDefinedValueTypes,
		&UDVTDef{Name: "UD60x18", SourceFile: "/src/B.sol", UnderlyingType: "uint256"})
	if got := db.UniqueUDVTByName("UD60x18"); got != nil {
		t.Errorf("UniqueUDVTByName resolved an ambiguous name to %v, want nil", got)
	}
}
