// Package testing provides test utilities for w3goaudit
package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit-engine/pkg/builder"
	"github.com/th13vn/w3goaudit-engine/pkg/engine"
	"github.com/th13vn/w3goaudit-engine/pkg/reader"
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// TestCase represents a single test case
type TestCase struct {
	Name           string           `json:"name"`
	SolFile        string           `json:"sol_file"`
	Template       string           `json:"template"`
	ExpectedCount  int              `json:"expected_count"`
	ExpectedIDs    []string         `json:"expected_ids,omitempty"`
	ShouldNotMatch []string         `json:"should_not_match,omitempty"`
	Assertions     []TestAssertion  `json:"assertions,omitempty"`
}

// TestAssertion represents a specific assertion to check
type TestAssertion struct {
	Type     string `json:"type"`     // "main_contract", "linearization", "entry_points"
	Contract string `json:"contract,omitempty"`
	Expected interface{} `json:"expected"`
}

// TestResult represents the result of a test case
type TestResult struct {
	Name     string   `json:"name"`
	Passed   bool     `json:"passed"`
	Message  string   `json:"message,omitempty"`
	Findings int      `json:"findings,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// TestRunner executes test cases
type TestRunner struct {
	testDataDir  string
	templateDir  string
	verbose      bool
}

// NewTestRunner creates a new test runner
func NewTestRunner(testDataDir, templateDir string) *TestRunner {
	return &TestRunner{
		testDataDir: testDataDir,
		templateDir: templateDir,
		verbose:     false,
	}
}

// SetVerbose enables verbose output
func (r *TestRunner) SetVerbose(v bool) {
	r.verbose = v
}

// RunAll runs all test cases in the test data directory
func (r *TestRunner) RunAll() ([]*TestResult, error) {
	var results []*TestResult

	// Find all .sol files
	entries, err := os.ReadDir(r.testDataDir)
	if err != nil {
		return nil, fmt.Errorf("reading test data dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sol") {
			continue
		}

		result := r.RunFile(filepath.Join(r.testDataDir, entry.Name()))
		results = append(results, result)
	}

	return results, nil
}

// RunFile runs tests on a single Solidity file
func (r *TestRunner) RunFile(filePath string) *TestResult {
	result := &TestResult{
		Name: filepath.Base(filePath),
	}

	// Build database
	db, err := r.buildDatabase(filePath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("build error: %v", err))
		return result
	}

	// Run basic assertions
	if err := r.assertDatabase(db, result); err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	// Run templates if available
	if r.templateDir != "" {
		findings, err := r.runTemplates(db)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("template error: %v", err))
		} else {
			result.Findings = len(findings)
		}
	}

	result.Passed = len(result.Errors) == 0
	return result
}

// buildDatabase builds the database from source files
func (r *TestRunner) buildDatabase(filePath string) (*types.Database, error) {
	rdr := reader.New()
	sources, err := rdr.Read(filePath)
	if err != nil {
		return nil, err
	}

	b := builder.New()
	return b.Build(sources)
}

// assertDatabase performs basic assertions on the database
func (r *TestRunner) assertDatabase(db *types.Database, result *TestResult) error {
	// Check that main contracts are identified
	if len(db.MainContracts) == 0 {
		result.Errors = append(result.Errors, "no main contracts identified")
	}

	// Check that contracts have linearization
	for name, contract := range db.Contracts {
		if len(contract.LinearizedBases) == 0 && len(contract.BaseContracts) > 0 {
			result.Errors = append(result.Errors, 
				fmt.Sprintf("contract %s has bases but no linearization", name))
		}
	}

	// Check entry functions for main contracts
	for mainID, entry := range db.MainContracts {
		if r.verbose {
			contract := db.Contracts[mainID]
			contractName := mainID
			if contract != nil {
				contractName = contract.Name
			}
			fmt.Printf("  Main contract %s has %d entry functions\n", contractName, len(entry.EntryFunctions))
		}
	}

	return nil
}

// runTemplates runs all templates against the database
func (r *TestRunner) runTemplates(db *types.Database) ([]*engine.Finding, error) {
	eng := engine.New(db)

	templates, err := engine.LoadTemplates(r.templateDir)
	if err != nil {
		return nil, err
	}

	return eng.ExecuteAll(templates), nil
}

// PrintResults prints test results to stdout
func PrintResults(results []*TestResult) {
	passed := 0
	failed := 0

	fmt.Println("\n=== Test Results ===")

	for _, r := range results {
		status := "[PASS]"
		if !r.Passed {
			status = "[FAIL]"
			failed++
		} else {
			passed++
		}

		fmt.Printf("%s %s", status, r.Name)
		if r.Findings > 0 {
			fmt.Printf(" [%d findings]", r.Findings)
		}
		fmt.Println()

		for _, err := range r.Errors {
			fmt.Printf("   └── %s\n", err)
		}
	}

	fmt.Printf("\nTotal: %d passed, %d failed\n", passed, failed)
}

// ExportDatabase exports the database to JSON
func ExportDatabase(db *types.Database, path string) error {
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
