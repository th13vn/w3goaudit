package main

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

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
