package types

import "testing"

// makeContract is a small helper for building a Contract with a derived ID.
func makeContract(file, name string) *Contract {
	return &Contract{
		ID:         MakeContractID(file, name),
		Name:       name,
		Kind:       ContractKindContract,
		SourceFile: file,
	}
}

func TestGetContractByIDIsExact(t *testing.T) {
	db := NewDatabase()
	c := makeContract("/src/Token.sol", "Token")
	db.AddContract(c)

	if got := db.GetContractByID("/src/Token.sol#Token"); got != c {
		t.Fatal("GetContractByID should return the contract for an exact ID match")
	}
	if got := db.GetContractByID("/src/Token.sol#Missing"); got != nil {
		t.Fatal("GetContractByID should return nil for an unknown ID")
	}
}

func TestGetContractByNameSingle(t *testing.T) {
	db := NewDatabase()
	c := makeContract("/src/Vault.sol", "Vault")
	db.AddContract(c)

	if got := db.GetContractByName("Vault"); got != c {
		t.Fatal("GetContractByName should return the only contract with that name")
	}
	if got := db.GetContractByName("Nope"); got != nil {
		t.Fatal("GetContractByName should return nil when no contract matches")
	}
}

func TestGetContractByNameDeterministicLexMin(t *testing.T) {
	// Two contracts share the name "Token" in different files. The one with the
	// lexicographically smallest ID must always win, regardless of map ordering.
	srcID := "/src/Token.sol#Token"
	mockID := "/test/mocks/Token.sol#Token"

	srcToken := makeContract("/src/Token.sol", "Token")
	mockToken := makeContract("/test/mocks/Token.sol", "Token")

	// "/src/..." < "/test/..." lexicographically, so srcToken should win.
	if srcID >= mockID {
		t.Fatalf("test precondition wrong: %q should sort before %q", srcID, mockID)
	}

	// Run several times: map iteration is randomized, so a flaky impl would
	// eventually return the wrong one.
	for i := 0; i < 50; i++ {
		db := NewDatabase()
		db.AddContract(mockToken)
		db.AddContract(srcToken)

		got := db.GetContractByName("Token")
		if got != srcToken {
			t.Fatalf("iteration %d: GetContractByName returned %q, want lex-min %q",
				i, got.ID, srcID)
		}
	}
}

func TestFindContractsByNameCollisionList(t *testing.T) {
	db := NewDatabase()
	srcToken := makeContract("/src/Token.sol", "Token")
	mockToken := makeContract("/test/mocks/Token.sol", "Token")
	other := makeContract("/src/Vault.sol", "Vault")
	db.AddContract(mockToken)
	db.AddContract(srcToken)
	db.AddContract(other)

	matches := db.FindContractsByName("Token")
	if len(matches) != 2 {
		t.Fatalf("expected 2 contracts named Token, got %d", len(matches))
	}
	// Results are sorted by ID, so /src/... comes before /test/...
	if matches[0] != srcToken || matches[1] != mockToken {
		t.Fatalf("FindContractsByName should be sorted by ID; got [%q, %q]",
			matches[0].ID, matches[1].ID)
	}

	if got := db.FindContractsByName("Ghost"); len(got) != 0 {
		t.Fatalf("expected no matches for unknown name, got %d", len(got))
	}
}

func TestResolveContractNameScopePreference(t *testing.T) {
	// Three contracts named "Token": a real one in /src, a same-dir sibling, and
	// a mock under /test/mocks. ResolveContractName must prefer scope-local
	// matches over the bare lex-min pick.
	srcToken := makeContract("/src/Token.sol", "Token")
	siblingToken := makeContract("/src/other/Token.sol", "Token")
	mockToken := makeContract("/test/mocks/Token.sol", "Token")

	newDB := func() *Database {
		db := NewDatabase()
		db.AddContract(mockToken)
		db.AddContract(siblingToken)
		db.AddContract(srcToken)
		return db
	}

	// 1. Same-file reference is unambiguous.
	if got := newDB().ResolveContractName("Token", "/src/Token.sol"); got != srcToken {
		t.Fatalf("same-file: got %q, want %q", id(got), srcToken.ID)
	}

	// 2. Same-directory reference (a Vault.sol in /src referring to Token).
	if got := newDB().ResolveContractName("Token", "/src/Vault.sol"); got != srcToken {
		t.Fatalf("same-dir: got %q, want %q", id(got), srcToken.ID)
	}

	// 3. Import-basename match: referrer in an unrelated dir imports the mock.
	db := newDB()
	db.AddSourceFile(&SourceFile{Path: "/test/Suite.sol", Imports: []string{"./mocks/Token.sol"}})
	if got := db.ResolveContractName("Token", "/test/Suite.sol"); got != mockToken {
		t.Fatalf("import-basename: got %q, want %q", id(got), mockToken.ID)
	}

	// 4. No usable scope → deterministic lex-min fallback (/src/Token.sol).
	if got := newDB().ResolveContractName("Token", ""); got != srcToken {
		t.Fatalf("lex-min fallback: got %q, want %q", id(got), srcToken.ID)
	}

	// 5. Single match ignores scope entirely.
	single := NewDatabase()
	v := makeContract("/src/Vault.sol", "Vault")
	single.AddContract(v)
	if got := single.ResolveContractName("Vault", "/anywhere/Else.sol"); got != v {
		t.Fatalf("single match: got %q, want %q", id(got), v.ID)
	}
	if got := single.ResolveContractName("Ghost", "/x.sol"); got != nil {
		t.Fatal("unknown name must resolve to nil")
	}
}

func id(c *Contract) string {
	if c == nil {
		return "<nil>"
	}
	return c.ID
}

func TestAddContractDerivesIDWhenEmpty(t *testing.T) {
	db := NewDatabase()
	c := &Contract{
		Name:       "Auto",
		Kind:       ContractKindContract,
		SourceFile: "/src/Auto.sol",
	}
	db.AddContract(c)

	if c.ID != "/src/Auto.sol#Auto" {
		t.Fatalf("AddContract should derive ID, got %q", c.ID)
	}
	if db.GetContractByID("/src/Auto.sol#Auto") != c {
		t.Fatal("contract should be retrievable by its derived ID")
	}
}

func TestRestoreASTParentsCoversModifiers(t *testing.T) {
	// Modifier AST should also be re-linked, not just function AST.
	modRoot := NewASTNode(KindDeclModifier)
	modChild := NewASTNode(KindCheckRequire)
	modRoot.Children = append(modRoot.Children, modChild) // no AddChild => Parent nil

	db := NewDatabase()
	db.Contracts["/src/C.sol#C"] = &Contract{
		Name: "C",
		Modifiers: []*Modifier{
			{Name: "onlyOwner", AST: modRoot},
		},
	}

	db.RestoreASTParents()

	if modChild.Parent != modRoot {
		t.Fatal("RestoreASTParents should re-link modifier AST parents")
	}
}

func TestRestoreASTParentsNilDatabase(t *testing.T) {
	var db *Database
	db.RestoreASTParents() // must not panic
}
