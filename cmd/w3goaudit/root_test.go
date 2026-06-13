package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunScanReturnsOutputWriteError(t *testing.T) {
	resetScanGlobals := func() {
		templatePath = ""
		outputPath = ""
		dbPath = ""
		verbose = ""
		jsonOutput = false
		htmlOutput = false
		mdOutput = false
		sarifOutput = false
		noColor = false
		ignoreInvalidTemplates = false
		locationSource = "verifier"
	}
	resetScanGlobals()
	t.Cleanup(resetScanGlobals)

	cmd := &cobra.Command{}
	cmd.Flags().String("verbose", "", "")

	jsonOutput = true
	noColor = true
	outputPath = t.TempDir() + "/missing/report.json"

	err := runScan(cmd, []string{"../../test-data/core/build-database/01-basic-contracts.sol"})
	if err == nil {
		t.Fatal("runScan returned nil; want write error for missing output directory")
	}
	if !strings.Contains(err.Error(), "writing output") {
		t.Fatalf("runScan error = %q; want writing output context", err)
	}
}
