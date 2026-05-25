package engine

import (
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

func TestInterproceduralTaintForInternalTransferFrom(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/test-interprocedural-taint.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/security/arbitrary_transferfrom.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"VulnerableAliasForward.depositFrom",
		"VulnerableAliasReassignmentForward.depositFrom",
		"VulnerableInternalForward.depositFrom",
		"VulnerableNestedForward.depositFrom",
		"VulnerableStructForward.deposit",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestFindingLocationsUseExactFunctionIDSourceFile(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/security/tx_origin_auth.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	seen := make(map[string]bool)
	for _, finding := range New(db).Execute(tmpl) {
		if finding.Location.Contract == "Vulnerable_TxOrigin" {
			seen[filepath.Base(finding.Location.File)] = true
			if !strings.HasSuffix(finding.Location.File, ".sol") {
				t.Fatalf("expected Solidity source file location, got %q", finding.Location.File)
			}
		}
	}

	want := map[string]bool{
		"test-4naly3er-detectors.sol": true,
		"test-slither-detectors.sol":  true,
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("unexpected duplicate-name source files:\n got: %v\nwant: %v", seen, want)
	}
}

func TestTypeCastsDoNotCreateReentrancyFindings(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/test-4naly3er-detectors.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/security/reentrancy_pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	for _, finding := range New(db).Execute(tmpl) {
		switch finding.Location.Contract {
		case "Safe_AddressZeroCheck", "Safe_MintBurnZero":
			t.Fatalf("type casts in guards must not be treated as outgoing calls: %+v", finding.Location)
		}
	}
}

func TestInterproceduralSequenceFindsCallsInsideInternalHelpers(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/reentrancy-simple.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/security/reentrancy_pattern.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"DeepRecursive.withdraw",
		"DirectCall.withdraw",
		"NestedBlock.withdraw",
		"RecursiveCall.withdraw",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reentrancy findings:\n got: %v\nwant: %v", got, want)
	}
}

func TestUncheckedArithmeticTemplateSeesUncheckedBlocks(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/test-unchecked-arithmetic.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/security/unchecked_arithmetic.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)

	want := []string{
		"Safe_BoundedUncheckedArithmetic.incrementSmall",
		"Vulnerable_UncheckedArithmetic.credit",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected unchecked arithmetic findings:\n got: %v\nwant: %v", got, want)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
