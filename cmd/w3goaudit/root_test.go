package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestRunScanWritesBundle verifies a scan produces the full result folder:
// top-level reports, the machine-readable data/ folder, and per-contract folders.
func TestRunScanWritesBundle(t *testing.T) {
	resetScanGlobals := func() {
		templatePath = ""
		outputPath = ""
		dbPath = ""
		verbose = false
		htmlOutput = false
		stdoutOnly = false
		noColor = false
		ignoreInvalidTemplates = false
		severityList = ""
		minSeverity = ""
		includeTemplates = ""
		excludeTemplates = ""
		listTemplates = false
	}
	resetScanGlobals()
	t.Cleanup(resetScanGlobals)

	// Isolate HOME and pin an explicit template dir so the scan never touches
	// the real ~/.w3goaudit or hits the network (EnsureInit is skipped when
	// --template is set).
	t.Setenv("HOME", t.TempDir())

	cmd := &cobra.Command{}

	noColor = true
	templatePath = "../../templates/official"
	outDir := filepath.Join(t.TempDir(), "missing", "nested", "report")
	outputPath = outDir

	if err := runScan(cmd, []string{"../../test-data/core/build-database/01-basic-contracts.sol"}); err != nil {
		t.Fatalf("runScan failed: %v", err)
	}

	// Top-level artifacts.
	for _, name := range []string{"README.md", "summary.md", "overview.md", "findings.md", "results.sarif", "run.log"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("expected %s to be created: %v", name, err)
		}
	}

	// data/ (machine-readable mirror + manifest index).
	for _, name := range []string{"database.json", "findings.json", "overview.json", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(outDir, "data", name)); err != nil {
			t.Errorf("expected data/%s to be created: %v", name, err)
		}
	}

	// The legacy corpus/ folder must NOT exist under the new layout.
	if _, err := os.Stat(filepath.Join(outDir, "corpus")); err == nil {
		t.Error("unexpected legacy corpus/ folder in new-layout bundle")
	}

	// At least one per-contract folder under contracts/ with a README.md,
	// state-changes.md, mirroring the source path.
	foundContract := false
	err := filepath.WalkDir(filepath.Join(outDir, "contracts"), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, statErr := os.Stat(filepath.Join(p, "state-changes.md")); statErr == nil {
				if _, rmErr := os.Stat(filepath.Join(p, "README.md")); rmErr == nil {
					foundContract = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking contracts dir: %v", err)
	}
	if !foundContract {
		t.Error("expected a per-contract folder under contracts/ with README.md + state-changes.md")
	}
}

// TestResolveOutputDir covers the default-naming and source-collision guard.
func TestResolveOutputDir(t *testing.T) {
	// Explicit -o always wins.
	if got := resolveOutputDir("whatever", "", "out/here"); got != "out/here" {
		t.Errorf("explicit output: got %q, want out/here", got)
	}

	// A .sol file uses its stem.
	if got := resolveOutputDir("contracts/Token.sol", "", ""); got != "Token" {
		t.Errorf("file stem: got %q, want Token", got)
	}

	// A database path uses its stem.
	if got := resolveOutputDir("", "audit/data/database.json", ""); got != "database" {
		t.Errorf("db stem: got %q, want database", got)
	}
}
