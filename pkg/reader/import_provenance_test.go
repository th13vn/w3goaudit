package reader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestResolvedImportProvenanceBeatsUnrelatedSameDirectoryContract(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	vendorToken := filepath.Join(root, "vendor", "Token.sol")
	consumer := filepath.Join(src, "Consumer.sol")
	localToken := filepath.Join(src, "Token.sol")
	if err := os.MkdirAll(filepath.Dir(vendorToken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, consumer, `import "../vendor/Token.sol"; contract Consumer is Token {}`)
	mustWrite(t, localToken, `contract Token { function localOnly() external {} }`)
	mustWrite(t, vendorToken, `contract Token { function importedOnly() external {} }`)

	r := New()
	if _, err := r.ReadDirectory(src); err != nil {
		t.Fatal(err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatal(err)
	}
	assertResolvedImportAndExactContract(t, r.GetAllSources(), consumer, vendorToken, localToken)
}

func TestRemappedResolvedImportProvenanceBeatsUnrelatedSameDirectoryContract(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	vendorToken := filepath.Join(root, "vendor", "Token.sol")
	consumer := filepath.Join(src, "Consumer.sol")
	localToken := filepath.Join(src, "Token.sol")
	if err := os.MkdirAll(filepath.Dir(vendorToken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "remappings.txt"), "@dep/=vendor/\n")
	mustWrite(t, consumer, `import "@dep/Token.sol"; contract Consumer is Token {}`)
	mustWrite(t, localToken, `contract Token { function localOnly() external {} }`)
	mustWrite(t, vendorToken, `contract Token { function importedOnly() external {} }`)

	r := New()
	if _, err := r.ReadDirectory(src); err != nil {
		t.Fatal(err)
	}
	if err := r.ResolveImports(root); err != nil {
		t.Fatal(err)
	}
	assertResolvedImportAndExactContract(t, r.GetAllSources(), consumer, vendorToken, localToken)
}

func TestResolvedImportBindingsPreserveEveryOccurrence(t *testing.T) {
	root := t.TempDir()
	consumer := filepath.Join(root, "Consumer.sol")
	vendor := filepath.Join(root, "Vendor.sol")
	mustWrite(t, consumer, `
import {Base as Parent} from "./Vendor.sol";
import * as V from "./Vendor.sol";
contract Consumer is Parent {}
`)
	mustWrite(t, vendor, `contract Base {}`)

	r := New()
	sources, err := r.Read(consumer)
	if err != nil {
		t.Fatal(err)
	}
	consumer = sources[0].Path
	if err := r.ResolveImports(root); err != nil {
		t.Fatal(err)
	}
	var source *types.SourceFile
	for _, candidate := range r.GetAllSources() {
		if candidate.Path == consumer {
			source = candidate
			break
		}
	}
	if source == nil {
		t.Fatal("consumer source missing")
	}
	if len(source.ImportBindings) != 2 {
		t.Fatalf("import bindings = %#v, want two authored occurrences", source.ImportBindings)
	}
	for _, binding := range source.ImportBindings {
		if binding.ImportPath != "./Vendor.sol" || binding.ResolvedFile != cleanAbs(t, vendor) {
			t.Fatalf("binding = %#v, want raw path plus canonical vendor", binding)
		}
	}
}

func assertResolvedImportAndExactContract(t *testing.T, sources []*types.SourceFile, consumerPath, importedPath, unrelatedPath string) {
	t.Helper()
	consumerPath = cleanAbs(t, consumerPath)
	importedPath = cleanAbs(t, importedPath)
	unrelatedPath = cleanAbs(t, unrelatedPath)

	var consumer *types.SourceFile
	for _, source := range sources {
		if source.Path == consumerPath {
			consumer = source
			break
		}
	}
	if consumer == nil {
		t.Fatalf("consumer %q missing", consumerPath)
	}
	if len(consumer.ResolvedImports) != 1 || consumer.ResolvedImports[0] != importedPath {
		t.Fatalf("resolved imports = %v, want [%s]", consumer.ResolvedImports, importedPath)
	}

	db := types.NewDatabase()
	for _, source := range sources {
		db.AddSourceFile(source)
	}
	db.AddContract(&types.Contract{Name: "Token", SourceFile: unrelatedPath})
	db.AddContract(&types.Contract{Name: "Token", SourceFile: importedPath})
	resolved, exact := db.ResolveContractNameExact("Token", consumerPath)
	if !exact || resolved == nil || resolved.SourceFile != importedPath {
		t.Fatalf("exact Token = %#v/%v, want imported %s", resolved, exact, importedPath)
	}
}

func cleanAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := canonicalPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
