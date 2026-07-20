package types

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestResolveContractNameExactRequiresSourceScopeForUniqueGlobalCandidate(t *testing.T) {
	consumerFile := "/project/src/Consumer.sol"
	unrelatedFile := "/project/elsewhere/Token.sol"

	t.Run("sole unrelated candidate fails closed", func(t *testing.T) {
		db := NewDatabase()
		db.AddSourceFile(&SourceFile{Path: consumerFile})
		db.AddContract(&Contract{Name: "Token", SourceFile: unrelatedFile})
		if resolved, exact := db.ResolveContractNameExact("Token", consumerFile); exact || resolved != nil {
			t.Fatalf("resolved = %#v, exact = %v, want source-scoped failure", resolved, exact)
		}
	})

	t.Run("same file", func(t *testing.T) {
		db := NewDatabase()
		local := &Contract{Name: "Token", SourceFile: consumerFile}
		db.AddContract(local)
		db.AddContract(&Contract{Name: "Token", SourceFile: unrelatedFile})
		if resolved, exact := db.ResolveContractNameExact("Token", consumerFile); !exact || resolved != local {
			t.Fatalf("resolved = %#v, exact = %v, want same-file Token", resolved, exact)
		}
	})

	t.Run("canonical resolved import", func(t *testing.T) {
		db := NewDatabase()
		importedFile := "/project/vendor/Token.sol"
		db.AddSourceFile(&SourceFile{Path: consumerFile, ResolvedImports: []string{importedFile}})
		imported := &Contract{Name: "Token", SourceFile: importedFile}
		db.AddContract(imported)
		db.AddContract(&Contract{Name: "Token", SourceFile: unrelatedFile})
		if resolved, exact := db.ResolveContractNameExact("Token", consumerFile); !exact || resolved != imported {
			t.Fatalf("resolved = %#v, exact = %v, want canonical imported Token", resolved, exact)
		}
	})

	t.Run("legacy relative import", func(t *testing.T) {
		db := NewDatabase()
		importedFile := "/project/vendor/Token.sol"
		db.AddSourceFile(&SourceFile{Path: consumerFile, Imports: []string{"../vendor/Token.sol"}})
		imported := &Contract{Name: "Token", SourceFile: importedFile}
		db.AddContract(imported)
		db.AddContract(&Contract{Name: "Token", SourceFile: unrelatedFile})
		if resolved, exact := db.ResolveContractNameExact("Token", consumerFile); !exact || resolved != imported {
			t.Fatalf("resolved = %#v, exact = %v, want legacy relative imported Token", resolved, exact)
		}
	})

	t.Run("no context unique compatibility", func(t *testing.T) {
		db := NewDatabase()
		unique := &Contract{Name: "Token", SourceFile: unrelatedFile}
		db.AddContract(unique)
		if resolved, exact := db.ResolveContractNameExact("Token", ""); !exact || resolved != unique {
			t.Fatalf("resolved = %#v, exact = %v, want unique no-context Token", resolved, exact)
		}
	})
}

func TestResolveContractNameExactUsesStructuredImportAliases(t *testing.T) {
	db := NewDatabase()
	consumerFile := "/repo/Consumer.sol"
	leftFile := "/repo/Left.sol"
	rightFile := "/repo/Right.sol"
	left := &Contract{Name: "Base", SourceFile: leftFile}
	right := &Contract{Name: "Base", SourceFile: rightFile}
	db.AddContract(left)
	db.AddContract(right)
	db.AddSourceFile(&SourceFile{
		Path: consumerFile,
		ImportBindings: []ImportBinding{
			{
				ImportPath:   "./Left.sol",
				ResolvedFile: leftFile,
				Symbols:      []ImportSymbolBinding{{Symbol: "Base", Alias: "Parent"}},
			},
			{
				ImportPath:   "./Right.sol",
				ResolvedFile: rightFile,
				UnitAlias:    "V",
			},
		},
	})

	if resolved, exact := db.ResolveContractNameExact("Parent", consumerFile); !exact || resolved != left {
		t.Fatalf("named alias = %#v/%v, want left Base", resolved, exact)
	}
	if resolved, exact := db.ResolveContractNameExact("V.Base", consumerFile); !exact || resolved != right {
		t.Fatalf("namespace alias = %#v/%v, want right Base", resolved, exact)
	}

	db.SourceFiles[consumerFile].ImportBindings = append(db.SourceFiles[consumerFile].ImportBindings,
		ImportBinding{ResolvedFile: rightFile, Symbols: []ImportSymbolBinding{{Symbol: "Base", Alias: "Parent"}}})
	if resolved, status := db.ResolveContractNameExactWithStatus("Parent", consumerFile); status != ExactResolutionAmbiguous || resolved != nil {
		t.Fatalf("ambiguous alias = %#v/%v, want nil/ambiguous", resolved, status)
	}
}

func TestLegacyMROUnresolvedEntriesAreIncompleteAfterJSONLoad(t *testing.T) {
	const derivedFile = "/project/src/Derived.sol"
	tests := []struct {
		name       string
		baseName   string
		wantStatus string
		prepare    func(*Database)
	}{
		{
			name:       "missing contract",
			baseName:   "Missing",
			wantStatus: "missing",
		},
		{
			name:       "sole unrelated candidate",
			baseName:   "Base",
			wantStatus: "ambiguous",
			prepare: func(db *Database) {
				db.AddContract(&Contract{Name: "Base", SourceFile: "/project/unrelated/Base.sol"})
			},
		},
		{
			name:       "ambiguous candidates",
			baseName:   "Base",
			wantStatus: "ambiguous",
			prepare: func(db *Database) {
				db.AddContract(&Contract{Name: "Base", SourceFile: "/project/a/Base.sol"})
				db.AddContract(&Contract{Name: "Base", SourceFile: "/project/z/Base.sol"})
			},
		},
		{
			name:       "structured binding target missing",
			baseName:   "Parent",
			wantStatus: "binding missing",
			prepare: func(db *Database) {
				db.AddSourceFile(&SourceFile{
					Path: derivedFile,
					ImportBindings: []ImportBinding{{
						ImportPath:   "./Base.sol",
						ResolvedFile: "/project/src/Base.sol",
						Symbols:      []ImportSymbolBinding{{Symbol: "Base", Alias: "Parent"}},
					}},
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := NewDatabase()
			if tc.prepare != nil {
				tc.prepare(db)
			}
			if db.SourceFiles[derivedFile] == nil {
				db.AddSourceFile(&SourceFile{Path: derivedFile})
			}
			derived := &Contract{
				Name:            "Derived",
				SourceFile:      derivedFile,
				LinearizedBases: []string{"Derived", tc.baseName},
			}
			db.AddContract(derived)

			raw, err := json.Marshal(db)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			path := filepath.Join(t.TempDir(), "legacy.json")
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			loaded, err := LoadFromJSON(path)
			if err != nil {
				t.Fatalf("LoadFromJSON: %v", err)
			}
			if loaded.AnalysisComplete() {
				t.Fatal("AnalysisComplete = true, want false for unresolved legacy MRO")
			}

			var matches []Diagnostic
			for _, diagnostic := range loaded.Diagnostics {
				if diagnostic.Code == DiagnosticIdentity && diagnostic.File == derivedFile && diagnostic.Symbol == tc.baseName {
					matches = append(matches, diagnostic)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("matching diagnostics = %#v, want exactly one", matches)
			}
			diagnostic := matches[0]
			if !diagnostic.Incomplete || !strings.Contains(diagnostic.Message, tc.wantStatus) ||
				!strings.Contains(diagnostic.Message, derivedFile) || !strings.Contains(diagnostic.Message, tc.baseName) {
				t.Fatalf("diagnostic = %#v, want incomplete message with status, file, and symbol", diagnostic)
			}

			loaded.NormalizeDiagnostics()
			loaded.NormalizeDiagnostics()
			matches = matches[:0]
			for _, diagnostic := range loaded.Diagnostics {
				if diagnostic.Code == DiagnosticIdentity && diagnostic.File == derivedFile && diagnostic.Symbol == tc.baseName {
					matches = append(matches, diagnostic)
				}
			}
			if len(matches) != 1 {
				t.Fatalf("repeated normalization produced %#v, want one diagnostic", matches)
			}
		})
	}
}
