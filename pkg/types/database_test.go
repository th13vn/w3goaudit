package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRestoreASTParents(t *testing.T) {
	root := NewASTNode(KindDeclFunction)
	child := NewASTNode(KindCheckRequire)
	grandchild := NewASTNode(KindExprIdentifier)
	root.Children = append(root.Children, child)
	child.Children = append(child.Children, grandchild)

	db := NewDatabase()
	db.Contracts["test.sol#C"] = &Contract{
		Name: "C",
		Functions: []*Function{
			{
				Name: "f",
				AST:  root,
			},
		},
	}

	db.RestoreASTParents()

	if child.Parent != root {
		t.Fatal("expected child parent to be restored")
	}
	if grandchild.Parent != child {
		t.Fatal("expected grandchild parent to be restored")
	}
}

func TestImportBindingsJSONRoundTrip(t *testing.T) {
	db := NewDatabase()
	db.AddSourceFile(&SourceFile{
		Path: "/repo/Consumer.sol",
		ImportBindings: []ImportBinding{{
			ImportPath:   "./Vendor.sol",
			ResolvedFile: "/repo/Vendor.sol",
			UnitAlias:    "V",
			Symbols:      []ImportSymbolBinding{{Symbol: "Base", Alias: "Parent"}},
		}},
	})
	raw, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.SourceFiles["/repo/Consumer.sol"].ImportBindings; !reflect.DeepEqual(got, db.SourceFiles["/repo/Consumer.sol"].ImportBindings) {
		t.Fatalf("import bindings after JSON round trip = %#v, want %#v", got, db.SourceFiles["/repo/Consumer.sol"].ImportBindings)
	}
}
