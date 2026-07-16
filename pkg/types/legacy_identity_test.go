package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadFromJSONBackfillsFunctionSourceFileFromExactOwningContract(t *testing.T) {
	db := NewDatabase()
	aFile := "/project/a/Token.sol"
	zFile := "/project/z/Token.sol"
	db.AddContract(&Contract{
		Name:       "Token",
		SourceFile: aFile,
		Functions:  []*Function{{Name: "run", ContractName: "Token"}},
	})
	db.AddContract(&Contract{
		Name:       "Token",
		SourceFile: zFile,
		Functions:  []*Function{{Name: "run", ContractName: "Token"}},
	})

	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{aFile, zFile} {
		contract := loaded.GetContractByID(MakeContractID(file, "Token"))
		if contract == nil || len(contract.Functions) != 1 {
			t.Fatalf("contract %s missing after load", file)
		}
		if got := contract.Functions[0].SourceFile; got != file {
			t.Fatalf("%s Token.run sourceFile = %q, want exact owner %q", file, got, file)
		}
	}
}

func TestLegacyRemappedImportCollisionStaysAmbiguous(t *testing.T) {
	db := NewDatabase()
	consumerFile := "/project/src/Consumer.sol"
	localFile := "/project/src/Token.sol"
	remappedFile := "/project/vendor/Token.sol"
	db.AddSourceFile(&SourceFile{
		Path:    consumerFile,
		Imports: []string{"@dep/Token.sol"}, // legacy cache: no ResolvedImports provenance
	})
	db.AddContract(&Contract{Name: "Token", SourceFile: localFile})
	db.AddContract(&Contract{Name: "Token", SourceFile: remappedFile})
	derived := &Contract{
		Name:            "Consumer",
		SourceFile:      consumerFile,
		LinearizedBases: []string{"Consumer", "Token"},
	}
	db.AddContract(derived)

	if resolved, exact := db.ResolveContractNameExact("Token", consumerFile); exact || resolved != nil {
		t.Fatalf("legacy remapped Token resolved to %#v/%v, want ambiguity", resolved, exact)
	}
	db.NormalizeDiagnostics()
	diagnosticsBefore := append([]Diagnostic(nil), db.Diagnostics...)
	linearized := db.LinearizedContracts(derived)
	if len(linearized) != 1 || linearized[0] != derived {
		t.Fatalf("legacy remapped MRO = %#v, want exact self only", linearized)
	}
	if !reflect.DeepEqual(db.Diagnostics, diagnosticsBefore) {
		t.Fatalf("LinearizedContracts mutated diagnostics:\n before=%#v\n after=%#v", diagnosticsBefore, db.Diagnostics)
	}
	found := false
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == DiagnosticIdentity && diagnostic.File == consumerFile && diagnostic.Symbol == "Token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("diagnostics = %#v, want ambiguous legacy remapped Token identity", db.Diagnostics)
	}
}
