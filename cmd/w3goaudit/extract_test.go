package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func duplicateExtractDB() *types.Database {
	db := types.NewDatabase()
	for _, file := range []string{"/a/Token.sol", "/z/Token.sol"} {
		contract := &types.Contract{
			ID: file + "#Token", Name: "Token", SourceFile: file, Kind: types.ContractKindContract,
			Functions: []*types.Function{{Name: "run", Selector: "run()", Signature: "c0406226", ContractName: "Token", SourceFile: file}},
		}
		db.AddContract(contract)
	}
	return db
}

func TestExtractResolutionRejectsAmbiguity(t *testing.T) {
	db := duplicateExtractDB()
	if _, err := resolveContractQuery(db, "Token"); err == nil || !strings.Contains(err.Error(), "ambiguous contract") {
		t.Fatalf("contract err = %v", err)
	}
	fn, contract, err := resolveFunctionQuery(db, "run", "")
	if err == nil || fn != nil || contract != nil || !strings.Contains(err.Error(), "/a/Token.sol#Token.run()\n  /z/Token.sol#Token.run()") {
		t.Fatalf("fn=%v contract=%v err=%v", fn, contract, err)
	}
}

func TestExtractResolutionAcceptsExactIDsAndQualifiers(t *testing.T) {
	db := duplicateExtractDB()
	fn, contract, err := resolveFunctionQuery(db, "/z/Token.sol#Token.run()", "")
	if err != nil || fn == nil || contract == nil || contract.SourceFile != "/z/Token.sol" {
		t.Fatalf("fn=%v contract=%v err=%v", fn, contract, err)
	}
	fn, contract, err = resolveFunctionQuery(db, "Token.run()", "/a/Token.sol#Token")
	if err != nil || fn == nil || contract == nil || contract.SourceFile != "/a/Token.sol" {
		t.Fatalf("qualified fn=%v contract=%v err=%v", fn, contract, err)
	}
}

func TestExtractInheritedContextUsesExactBaseIdentity(t *testing.T) {
	db := types.NewDatabase()
	wrong := &types.Contract{
		ID: "/a/Base.sol#Base", Name: "Base", SourceFile: "/a/Base.sol", Kind: types.ContractKindContract,
		StateVariables: []*types.StateVariable{{Name: "wrong", TypeName: "uint256"}},
	}
	right := &types.Contract{
		ID: "/z/Base.sol#Base", Name: "Base", SourceFile: "/z/Base.sol", Kind: types.ContractKindContract,
		StateVariables: []*types.StateVariable{{Name: "right", TypeName: "address"}},
	}
	vault := &types.Contract{
		ID: "/z/Vault.sol#Vault", Name: "Vault", SourceFile: "/z/Vault.sol", Kind: types.ContractKindContract,
		LinearizedBases:   []string{"Vault", "Base"},
		LinearizedBaseIDs: []string{"/z/Vault.sol#Vault", "/z/Base.sol#Base"},
		Functions: []*types.Function{{
			Name: "run", Selector: "run()", ContractName: "Vault", SourceFile: "/z/Vault.sol",
		}},
	}
	db.AddContract(wrong)
	db.AddContract(right)
	db.AddContract(vault)

	bundle := buildBundle(db, vault, vault.Functions[0])
	if len(bundle.StateVars) != 1 || bundle.StateVars[0].Name != "right" {
		t.Fatalf("state variables = %#v, want exact /z/Base.sol base", bundle.StateVars)
	}
	if len(bundle.Inheritance) != 2 || bundle.Inheritance[1].Kind != string(right.Kind) {
		t.Fatalf("inheritance = %#v, want exact /z/Base.sol base kind", bundle.Inheritance)
	}
}

func TestExtractInheritanceAndBundleDoNotZipDisplayAndExactMRO(t *testing.T) {
	db := types.NewDatabase()
	base := &types.Contract{
		Name:       "Base",
		SourceFile: "/repo/Base.sol",
		Kind:       types.ContractKindLibrary,
	}
	derived := &types.Contract{
		Name:              "Derived",
		SourceFile:        "/repo/Derived.sol",
		Kind:              types.ContractKindContract,
		LinearizedBases:   []string{"Derived", "MissingBase", "Base"},
		InheritanceWeight: 3,
		Functions: []*types.Function{{
			Name: "run", Selector: "run()", ContractName: "Derived", SourceFile: "/repo/Derived.sol",
		}},
	}
	db.AddContract(base)
	db.AddContract(derived)
	derived.LinearizedBaseIDs = []string{derived.ID, base.ID}

	chain := make([]InheritanceEntry, 0, len(derived.LinearizedBases))
	for i, baseName := range derived.LinearizedBases {
		kind := "unknown"
		if resolved := linearizedContractAt(db, derived, i); resolved != nil {
			kind = string(resolved.Kind)
		}
		chain = append(chain, InheritanceEntry{Order: i + 1, Name: baseName, Kind: kind})
	}
	wantKinds := []string{string(types.ContractKindContract), "unknown", string(types.ContractKindLibrary)}
	if len(chain) != len(wantKinds) {
		t.Fatalf("inheritance chain = %#v, want %d entries", chain, len(wantKinds))
	}
	for i, want := range wantKinds {
		if chain[i].Kind != want {
			t.Errorf("inheritance[%d] = %#v, want kind %q", i, chain[i], want)
		}
	}

	bundle := buildBundle(db, derived, derived.Functions[0])
	if len(bundle.Inheritance) != len(wantKinds) {
		t.Fatalf("bundle inheritance = %#v, want %d entries", bundle.Inheritance, len(wantKinds))
	}
	for i, want := range wantKinds {
		if bundle.Inheritance[i].Kind != want {
			t.Errorf("bundle inheritance[%d] = %#v, want kind %q", i, bundle.Inheritance[i], want)
		}
	}
}

func TestExtractDiffUsesNormalizedExactContractAndFunctionIdentities(t *testing.T) {
	makeContract := func(root, rel string, funcs []string, states []string) *types.Contract {
		file := filepath.Join(root, filepath.FromSlash(rel))
		contract := &types.Contract{Name: "Token", SourceFile: file, Kind: types.ContractKindContract}
		for _, selector := range funcs {
			name := selector
			if i := strings.IndexByte(name, '('); i >= 0 {
				name = name[:i]
			}
			fn := &types.Function{Name: name, ContractName: "Token", SourceFile: file}
			if strings.Contains(selector, "(") {
				fn.Selector = selector
			}
			contract.Functions = append(contract.Functions, fn)
		}
		for _, name := range states {
			contract.StateVariables = append(contract.StateVariables, &types.StateVariable{Name: name})
		}
		return contract
	}
	makeDB := func(root string, contracts ...*types.Contract) *types.Database {
		db := types.NewDatabase()
		db.ProjectRoot = root
		for _, contract := range contracts {
			db.AddContract(contract)
		}
		return db
	}

	oldRoot := "/checkout/old"
	newRoot := "/different/checkout/new"
	oldDB := makeDB(oldRoot,
		makeContract(oldRoot, "src/a/Token.sol", []string{"run(uint256)", "over(uint256)", "fallback"}, []string{"shared", "aOld"}),
		makeContract(oldRoot, "src/b/Token.sol", []string{"sync()", "removed(bytes)"}, []string{"shared", "bOld"}),
		makeContract(oldRoot, "src/d/Token.sol", []string{"gone()"}, nil),
	)
	newDB := makeDB(newRoot,
		makeContract(newRoot, "src/a/Token.sol", []string{"run(uint256)", "over(address)", "fallback"}, []string{"shared", "aNew"}),
		makeContract(newRoot, "src/b/Token.sol", []string{"sync()", "added(bool)"}, []string{"shared", "bNew"}),
		makeContract(newRoot, "src/c/Token.sol", []string{"fresh()"}, nil),
	)

	dir := t.TempDir()
	writeDB := func(name string, db *types.Database) string {
		t.Helper()
		raw, err := json.Marshal(db)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}
	oldPath := writeDB("old.json", oldDB)
	newPath := writeDB("new.json", newDB)
	outPath := filepath.Join(dir, "diff.json")
	for name, value := range map[string]string{
		"db1": oldPath, "db2": newPath, "output": outPath, "format": "json",
	} {
		if err := extractDiffCmd.Flags().Set(name, value); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		for _, name := range []string{"db1", "db2", "output", "format"} {
			_ = extractDiffCmd.Flags().Set(name, "")
		}
	})
	if err := extractDiffCmd.RunE(extractDiffCmd, nil); err != nil {
		t.Fatalf("extract diff: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read diff: %v", err)
	}
	var got DiffOutput
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode diff: %v", err)
	}

	if !reflect.DeepEqual(got.Added.Contracts, []string{"src/c/Token.sol#Token"}) {
		t.Fatalf("added contracts = %v", got.Added.Contracts)
	}
	if !reflect.DeepEqual(got.Removed.Contracts, []string{"src/d/Token.sol#Token"}) {
		t.Fatalf("removed contracts = %v", got.Removed.Contracts)
	}
	wantChanged := []ContractDiff{
		{
			Contract:   "src/a/Token.sol#Token",
			AddedFuncs: []string{"over(address)"}, RemovedFuncs: []string{"over(uint256)"},
			AddedStateVars: []string{"aNew"}, RemovedStateVars: []string{"aOld"},
		},
		{
			Contract:   "src/b/Token.sol#Token",
			AddedFuncs: []string{"added(bool)"}, RemovedFuncs: []string{"removed(bytes)"},
			AddedStateVars: []string{"bNew"}, RemovedStateVars: []string{"bOld"},
		},
	}
	if !reflect.DeepEqual(got.Changed, wantChanged) {
		t.Fatalf("changed = %#v, want %#v", got.Changed, wantChanged)
	}
}

// The extract subcommands read a built database and slice it by contract,
// entrypoint, inheritance, and call context. These tests build that database
// from the canonical extract fixture and assert the structure the commands
// depend on, exercising the real findContract / findFunction helpers.
const vaultFixture = "../../test-data/core/extract/defi-vault.sol"

func buildVaultDB(t *testing.T) *types.Database {
	t.Helper()
	sources, err := reader.New().Read(vaultFixture)
	if err != nil {
		t.Fatalf("reader.Read(%q): %v", vaultFixture, err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("builder.Build(%q): %v", vaultFixture, err)
	}
	return db
}

func TestExtractFindContract(t *testing.T) {
	db := buildVaultDB(t)

	c := findContract(db, "DeFiVault")
	if c == nil {
		t.Fatal("findContract(DeFiVault) = nil; want the vault contract")
	}
	if c.Name != "DeFiVault" {
		t.Errorf("contract name = %q; want DeFiVault", c.Name)
	}
	// findContract is case-insensitive — the extract CLI relies on this.
	if findContract(db, "defivault") == nil {
		t.Error("findContract(defivault) = nil; want case-insensitive match")
	}
	if findContract(db, "NoSuchContract") != nil {
		t.Error("findContract(NoSuchContract) = non-nil; want nil")
	}
	// The secondary contract in the fixture is present too.
	if findContract(db, "VaultToken") == nil {
		t.Error("findContract(VaultToken) = nil; want the secondary contract")
	}
}

func TestExtractInheritanceLinearization(t *testing.T) {
	db := buildVaultDB(t)
	c := findContract(db, "DeFiVault")
	if c == nil {
		t.Fatal("DeFiVault not found")
	}
	// C3 order is [MostDerived, ..., MostBase]; the vault must lead.
	if len(c.LinearizedBases) == 0 || c.LinearizedBases[0] != "DeFiVault" {
		t.Fatalf("LinearizedBases = %v; want it to start with DeFiVault", c.LinearizedBases)
	}
	got := make(map[string]bool, len(c.LinearizedBases))
	for _, b := range c.LinearizedBases {
		got[b] = true
	}
	// DeFiVault is Ownable, ReentrancyGuard, Pausable; Pausable/Ownable -> Context.
	for _, want := range []string{"Ownable", "ReentrancyGuard", "Pausable", "Context"} {
		if !got[want] {
			t.Errorf("LinearizedBases %v missing ancestor %q", c.LinearizedBases, want)
		}
	}
}

func TestExtractEntryPoints(t *testing.T) {
	db := buildVaultDB(t)

	// Public/external entry points the `extract entry` command surfaces.
	for _, name := range []string{"withdraw", "deposit", "depositFor", "withdrawETH", "safeWithdraw"} {
		fn, c := findFunction(db, name, "DeFiVault")
		if fn == nil {
			t.Errorf("findFunction(%q, DeFiVault) = nil; want the function", name)
			continue
		}
		if c.Name != "DeFiVault" {
			t.Errorf("%q resolved to contract %q; want DeFiVault", name, c.Name)
		}
		if !fn.IsEntrypoint() {
			t.Errorf("%q IsEntrypoint() = false; want true (it is external)", name)
		}
	}

	// The vault exposes a non-trivial entrypoint surface.
	c := findContract(db, "DeFiVault")
	entries := 0
	for _, fn := range c.Functions {
		if fn.IsEntrypoint() {
			entries++
		}
	}
	if entries < 5 {
		t.Errorf("DeFiVault entrypoint count = %d; want >= 5", entries)
	}
}
