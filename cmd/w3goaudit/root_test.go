package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

// TestRunScanWritesBundle verifies a scan produces the full result folder:
// top-level reports, the machine-readable corpus, and per-contract folders.
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
	for _, name := range []string{"overview.md", "findings.md", "results.sarif", "run.log"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Errorf("expected %s to be created: %v", name, err)
		}
	}

	// Corpus (machine-readable mirror).
	for _, name := range []string{"database.json", "findings.json", "overview.json"} {
		if _, err := os.Stat(filepath.Join(outDir, "corpus", name)); err != nil {
			t.Errorf("expected corpus/%s to be created: %v", name, err)
		}
	}

	// At least one per-contract folder with a state-changes.md.
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("reading output dir: %v", err)
	}
	foundContract := false
	for _, e := range entries {
		if e.IsDir() && e.Name() != "corpus" {
			if _, err := os.Stat(filepath.Join(outDir, e.Name(), "state-changes.md")); err == nil {
				foundContract = true
				break
			}
		}
	}
	if !foundContract {
		t.Error("expected at least one per-contract folder with state-changes.md")
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
	if got := resolveOutputDir("", "audit/corpus/database.json", ""); got != "database" {
		t.Errorf("db stem: got %q, want database", got)
	}
}
