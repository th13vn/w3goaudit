package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/th13vn/w3goaudit/pkg/home"
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
		strictImports = false
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
	for _, name := range []string{"database.json", "findings.json", "overview.json", "diagnostics.json", "manifest.json"} {
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

func TestStrictImportsRejectsSourceAndCacheWithStderrParity(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "Missing.sol")
	content := "pragma solidity ^0.8.0; import './Absent.sol'; contract Missing {}"
	if err := os.WriteFile(source, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := buildDatabaseWithOptions(databaseLoadOptions{
		InputPath: source,
		Stdout:    io.Discard,
		Stderr:    io.Discard,
	})
	if err != nil {
		t.Fatalf("build strict fixture: %v", err)
	}
	data, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "database.json")
	if err := os.WriteFile(cache, data, 0o644); err != nil {
		t.Fatal(err)
	}

	stderrByMode := make(map[string]string)
	for _, mode := range []string{"source", "cache"} {
		t.Run(mode, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			opts := scanOptions{
				InputPath:     source,
				StrictImports: true,
				StdoutOnly:    true,
				Stdout:        &stdout,
				Stderr:        &stderr,
			}
			if mode == "cache" {
				opts.InputPath = ""
				opts.DBPath = cache
			}
			err := executeScan(opts)
			if err == nil || !strings.Contains(err.Error(), "strict imports: unresolved import") {
				t.Fatalf("executeScan error = %v", err)
			}
			if !strings.Contains(stderr.String(), `"./Absent.sol"`) {
				t.Fatalf("stderr = %q, want unresolved import warning", stderr.String())
			}
			if strings.Contains(stdout.String(), "Warning:") || strings.Contains(stdout.String(), "Absent.sol") {
				t.Fatalf("stdout was polluted by warning: %q", stdout.String())
			}
			stderrByMode[mode] = stderr.String()
		})
	}
	if stderrByMode["source"] != stderrByMode["cache"] {
		t.Fatalf("source/cache stderr differs:\nsource: %q\n cache: %q", stderrByMode["source"], stderrByMode["cache"])
	}
}

type capturedScan struct {
	opts scanOptions
	out  *bytes.Buffer
	mark string
	err  error
}

func TestConcurrentScanOptionsDoNotCrossTalk(t *testing.T) {
	left := isolatedStdoutScan(t, "left")
	right := isolatedStdoutScan(t, "right")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		left.err = executeScan(left.opts)
	}()
	go func() {
		defer wg.Done()
		right.err = executeScan(right.opts)
	}()
	wg.Wait()
	assertNoCrossTalk(t, left, right)
}

func isolatedStdoutScan(t *testing.T, label string) capturedScan {
	t.Helper()
	buf := new(bytes.Buffer)
	path := filepath.Join(t.TempDir(), label+".sol")
	contract := strings.ToUpper(label[:1]) + label[1:]
	if err := os.WriteFile(path, []byte("pragma solidity ^0.8.0; contract "+contract+" { function run() external {} }"), 0o644); err != nil {
		t.Fatal(err)
	}
	return capturedScan{
		out:  buf,
		mark: path,
		opts: scanOptions{
			InputPath:    path,
			TemplatePath: "../../templates/test/feature-inside.yaml",
			StdoutOnly:   true,
			Verbose:      true,
			NoColor:      true,
			Stdout:       buf,
			Stderr:       io.Discard,
			Now:          func() time.Time { return time.Unix(int64(len(label)), 0) },
		},
	}
}

func assertNoCrossTalk(t *testing.T, left, right capturedScan) {
	t.Helper()
	if left.err != nil || right.err != nil {
		t.Fatalf("left=%v right=%v", left.err, right.err)
	}
	if left.out.String() == "" || right.out.String() == "" {
		t.Fatal("missing scan output")
	}
	if !strings.Contains(left.out.String(), left.mark) || strings.Contains(left.out.String(), right.mark) {
		t.Fatalf("left=%q", left.out.String())
	}
	if !strings.Contains(right.out.String(), right.mark) || strings.Contains(right.out.String(), left.mark) {
		t.Fatalf("right=%q", right.out.String())
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

func TestStrictImportsConfigRespectsExplicitCLIFlag(t *testing.T) {
	cfg := &home.Config{}
	cfg.Scan.StrictImports = true

	defaultCmd := &cobra.Command{}
	defaultCmd.Flags().Bool("strict-imports", false, "")
	defaultOpts := scanOptions{}
	applyConfigDefaults(defaultCmd, cfg, &defaultOpts)
	if !defaultOpts.StrictImports {
		t.Fatal("config strict_imports was not applied when the CLI flag was absent")
	}

	explicitCmd := &cobra.Command{}
	explicitCmd.Flags().Bool("strict-imports", false, "")
	if err := explicitCmd.Flags().Set("strict-imports", "false"); err != nil {
		t.Fatal(err)
	}
	explicitOpts := scanOptions{}
	applyConfigDefaults(explicitCmd, cfg, &explicitOpts)
	if explicitOpts.StrictImports {
		t.Fatal("explicit --strict-imports=false did not override config")
	}

	if rootCmd.Flags().Lookup("strict-imports") == nil || buildCmd.Flags().Lookup("strict-imports") == nil {
		t.Fatal("root and build commands must both expose --strict-imports")
	}
}

func TestBuildVerboseFlagAcceptsNoValue(t *testing.T) {
	flag := buildCmd.Flags().Lookup("verbose")
	if flag == nil {
		t.Fatal("build --verbose flag is missing")
	}
	if flag.NoOptDefVal != "true" {
		t.Fatalf("build --verbose NoOptDefVal = %q, want true", flag.NoOptDefVal)
	}
}
