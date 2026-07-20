package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

const proxyStorageCollisionFixture = "scripts/benchmark/fixtures/decurity-semgrep-inspired/proxy-storage-collision.sol"

func TestRepositoryInitializerTemplatesPreserveIndependentSafetyPredicates(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)

	t.Run("benchmark fixture", func(t *testing.T) {
		db := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/slither-detectors/unprotected-upgrade.sol")
		got := executeRepositoryTemplate(t, root, db, "scripts/benchmark/templates/slither-inspired/unprotected-upgrade.yaml")
		assertFindingSetContains(t, got, []string{"Vulnerable_UnprotectedUpgrade.initialize"})
		assertFindingSetExcludes(t, got, []string{"Safe_UnprotectedUpgrade.initialize"})
	})

	t.Run("official focused fixture", func(t *testing.T) {
		db := buildRepositoryFixtureDatabase(t, root, "test-data/security/unprotected-initializer.sol")
		for _, templatePath := range []string{
			"scripts/benchmark/templates/slither-inspired/unprotected-upgrade.yaml",
			"templates/official/high/unprotected-initializer.yaml",
		} {
			t.Run(templatePath, func(t *testing.T) {
				got := executeRepositoryTemplate(t, root, db, templatePath)
				assertFindingSetContains(t, got, []string{"VulnerableOfficialInitializer.initialize"})
				assertFindingSetExcludes(t, got, []string{
					"SafeOfficialInitializerAccessControlOnly.initialize",
					"SafeOfficialInitializerModifierOnly.initialize",
					"SafeOfficialInitializerDisableGuardOnly.initialize",
				})
			})
		}
	})
}

func TestRepositoryUniswapCallbackTemplatePreservesOnlyPoolManagerExclusion(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	templatePath := "scripts/benchmark/templates/decurity-semgrep-inspired/uniswap-v4-callback-not-protected.yaml"

	vulnerableDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/uniswap-v4-callback-not-protected.sol")
	vulnerable := executeRepositoryTemplate(t, root, vulnerableDB, templatePath)
	assertFindingSetContains(t, vulnerable, []string{"VulnerableUniswapV4CallbackNotProtected.beforeSwap"})

	safeDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/uniswap-v4-callback-only-manager.sol")
	safe := executeRepositoryTemplate(t, root, safeDB, templatePath)
	assertFindingSetExcludes(t, safe, []string{"SafeUniswapV4CallbackOnlyManager.beforeSwap"})
}

func TestRepositoryBasicArithmeticUnderflowUsesRangeGuards(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	db := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/basic-arithmetic-underflow.sol")
	tmpl, err := LoadTemplate(filepath.Join(root, "scripts/benchmark/templates/decurity-semgrep-inspired/basic-arithmetic-underflow.yaml"))
	if err != nil {
		t.Fatalf("load basic-arithmetic-underflow template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	counts := make(map[string]int)
	for _, finding := range findings {
		counts[finding.Location.Contract+"."+finding.Location.Function]++
	}

	if got := counts["VulnerableBasicArithmeticUnderflow.withdraw"]; got != 2 {
		t.Errorf("unguarded binary/assignment findings = %d, want 2; all=%v", got, counts)
	}
	for _, safe := range []string{
		"VulnerableBasicArithmeticUnderflow.guardedBinary",
		"VulnerableBasicArithmeticUnderflow.guardedAssignment",
	} {
		if counts[safe] != 0 {
			t.Errorf("unexpected guarded finding %s; all=%v", safe, counts)
		}
	}

	contract := mustContractByName(t, db, "VulnerableBasicArithmeticUnderflow")
	for _, functionName := range []string{"withdraw", "guardedBinary", "guardedAssignment"} {
		for _, fn := range contract.Functions {
			if fn == nil || fn.Name != functionName {
				continue
			}
			var subtraction *types.ASTNode
			fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
				if (node.Kind == types.KindExprBinaryOp && node.GetAttributeString("operator") == "-") ||
					(node.Kind == types.KindStmtAssign && node.GetAttributeString("operator") == "-=") {
					subtraction = node
					return false
				}
				return true
			})
			if subtraction == nil {
				t.Fatalf("%s.%s has no subtraction node", contract.Name, fn.Selector)
			}
			if subtraction.FindAncestor(func(node *types.ASTNode) bool { return node.Kind == types.KindStmtUnchecked }) == nil {
				t.Errorf("%s.%s subtraction is not inside an unchecked block", contract.Name, fn.Selector)
			}
		}
	}
}

func TestRepositoryBasicArithmeticUnderflowRequiresEnforcedOperandBound(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	db := buildRepositoryFixtureDatabase(t, root, "test-data/security/unchecked-arithmetic.sol")
	got := executeRepositoryTemplate(t, root, db, "scripts/benchmark/templates/decurity-semgrep-inspired/basic-arithmetic-underflow.yaml")

	var found []string
	for key := range got {
		if strings.HasPrefix(key, "UncheckedSubtractionGuardMatrix.") || strings.HasPrefix(key, "SignedSubtractionGuardMatrix.") {
			found = append(found, key)
		}
	}
	sort.Strings(found)
	want := []string{
		"SignedSubtractionGuardMatrix.signedRangeOnly",
		"UncheckedSubtractionGuardMatrix.dominatedArmEffectfulCondition",
		"UncheckedSubtractionGuardMatrix.dominatedArmEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.dominatedArmExternalCall",
		"UncheckedSubtractionGuardMatrix.dominatedArmExternalEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.dominatedArmInternalCall",
		"UncheckedSubtractionGuardMatrix.dominatedArmInterveningWrite",
		"UncheckedSubtractionGuardMatrix.exitingDisjunctionEffectfulCondition",
		"UncheckedSubtractionGuardMatrix.exitingElseSurvivingWrite",
		"UncheckedSubtractionGuardMatrix.interveningWrite",
		"UncheckedSubtractionGuardMatrix.nonTerminatingIf",
		"UncheckedSubtractionGuardMatrix.requireEffectfulConjunctAfterBound",
		"UncheckedSubtractionGuardMatrix.requireEffectfulConjunctBeforeBound",
		"UncheckedSubtractionGuardMatrix.requireEffectfulMessage",
		"UncheckedSubtractionGuardMatrix.requireEffectfulSibling",
		"UncheckedSubtractionGuardMatrix.reversedRequire",
		"UncheckedSubtractionGuardMatrix.unrelatedOrdering",
		"UncheckedSubtractionGuardMatrix.wrongFallthroughPolarity",
	}
	if len(found) != len(want) {
		t.Fatalf("guard-matrix findings = %v, want %v; all=%v", found, want, got)
	}
	for i := range want {
		if found[i] != want[i] {
			t.Fatalf("guard-matrix findings = %v, want %v", found, want)
		}
	}
	if got["UncheckedSubtractionGuardMatrix.safeRequirePureConjunct"] {
		t.Fatalf("pure conjunction safe control produced a finding; all=%v", got)
	}
}

func TestRepositoryBasicArithmeticUnderflowRequiresUncheckedSolidity08(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	templatePath := "scripts/benchmark/templates/decurity-semgrep-inspired/basic-arithmetic-underflow.yaml"

	checkedDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/4naly3er-detectors/mint-burn-zero.sol")
	checked := executeRepositoryTemplate(t, root, checkedDB, templatePath)
	assertFindingSetExcludes(t, checked, []string{
		"Vulnerable_MintBurnZero.burn",
		"Safe_MintBurnZero.burn",
	})

	aliasPath := "scripts/benchmark/fixtures/decurity-semgrep-inspired/basic-arithmetic-underflow-alias.sol"
	aliasDB := buildRepositoryFixtureDatabase(t, root, aliasPath)
	aliasFindings := executeRepositoryTemplate(t, root, aliasDB, templatePath)
	assertFindingSetContains(t, aliasFindings, []string{"VulnerableBasicArithmeticUnderflowAlias.redeem"})
	aliasContract := mustContractByName(t, aliasDB, "VulnerableBasicArithmeticUnderflowAlias")
	redeem := mustFunctionByName(t, aliasContract, "redeem")
	subtraction := mustASTNode(t, redeem.AST, types.KindExprBinaryOp)
	if subtraction.GetAttributeString("operator") != "-" ||
		subtraction.FindAncestor(func(node *types.ASTNode) bool { return node.Kind == types.KindStmtUnchecked }) == nil {
		t.Fatalf("alias subtraction = %+v, want '-' inside explicit unchecked block", subtraction)
	}
}

func TestRepositoryAccessibleSelfdestructMatchesUnauthenticatedReachableForms(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	templatePath := "scripts/benchmark/templates/decurity-semgrep-inspired/accessible-selfdestruct.yaml"
	cases := []struct {
		fixture string
		want    []string
		reject  []string
	}{
		{
			fixture: "scripts/benchmark/fixtures/decurity-semgrep-inspired/accessible-selfdestruct.sol",
			want:    []string{"VulnerableAccessibleSelfdestruct.destroy"},
		},
		{
			fixture: "scripts/benchmark/fixtures/decurity-semgrep-inspired/accessible-selfdestruct-helper.sol",
			want:    []string{"VulnerableAccessibleSelfdestructHelper.destroy"},
		},
		{
			fixture: "scripts/benchmark/fixtures/decurity-semgrep-inspired/accessible-selfdestruct-cast.sol",
			want:    []string{"VulnerableAccessibleSelfdestructCast.destroy"},
			reject:  []string{"SafeAccessibleSelfdestructCast.destroy"},
		},
		{
			fixture: "scripts/benchmark/fixtures/decurity-semgrep-inspired/accessible-selfdestruct-asm.sol",
			want:    []string{"VulnerableAccessibleSelfdestructAsm.destroy"},
			reject:  []string{"SafeAccessibleSelfdestructAsm.destroy"},
		},
	}

	for _, tc := range cases {
		t.Run(filepath.Base(tc.fixture), func(t *testing.T) {
			db := buildRepositoryFixtureDatabase(t, root, tc.fixture)
			got := executeRepositoryTemplate(t, root, db, templatePath)
			assertFindingSetContains(t, got, tc.want)
			assertFindingSetExcludes(t, got, tc.reject)
		})
	}
}

func TestRepositoryReentrancyNoEthExcludesFixedSelfReceiver(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	templatePath := "scripts/benchmark/templates/slither-inspired/reentrancy-no-eth.yaml"

	selfCallDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/4naly3er-detectors/this-external.sol")
	selfCallFindings := executeRepositoryTemplate(t, root, selfCallDB, templatePath)
	assertFindingSetExcludes(t, selfCallFindings, []string{
		"Vulnerable_ThisExternal.incrementTwice",
		"Safe_ThisExternal.incrementTwice",
	})

	legacyCacheDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/4naly3er-detectors/this-external.sol")
	for _, contract := range legacyCacheDB.Contracts {
		for _, fn := range contract.Functions {
			if fn == nil || fn.AST == nil {
				continue
			}
			delete(fn.AST.Attributes, "receiver_name")
			fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
				delete(node.Attributes, "receiver_name")
				return true
			})
		}
	}
	rawLegacyCache, err := json.Marshal(legacyCacheDB)
	if err != nil {
		t.Fatalf("marshal legacy receiver cache: %v", err)
	}
	legacyCachePath := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(legacyCachePath, rawLegacyCache, 0o644); err != nil {
		t.Fatalf("write legacy receiver cache: %v", err)
	}
	loadedLegacyCache, err := types.LoadFromJSON(legacyCachePath)
	if err != nil {
		t.Fatalf("load legacy receiver cache: %v", err)
	}
	legacyCacheFindings := executeRepositoryTemplate(t, root, loadedLegacyCache, templatePath)
	assertFindingSetExcludes(t, legacyCacheFindings, []string{
		"Vulnerable_ThisExternal.incrementTwice",
		"Safe_ThisExternal.incrementTwice",
	})

	externalDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/slither-detectors/reentrancy-no-eth.sol")
	externalFindings := executeRepositoryTemplate(t, root, externalDB, templatePath)
	assertFindingSetContains(t, externalFindings, []string{"Vulnerable_ReentrancyNoEth.claim"})
	assertFindingSetExcludes(t, externalFindings, []string{"Safe_ReentrancyNoEth.claim"})

	nestedSelfArgumentDB := buildDBFromSource(t, `
pragma solidity ^0.8.20;

interface PingTarget {
    function ping(uint256 value) external;
	function pingWithOptions() external;
}

contract NestedSelfArgument {
    uint256 public state;

    function read() external view returns (uint256) {
        return state;
    }

    function run(PingTarget target) external {
        target.ping(this.read());
        state = 1;
    }

	function runWithOptions(PingTarget target) external {
		target.pingWithOptions{gas: this.read()}();
		state = 2;
	}
}
`).GetDatabase()
	nestedSelfArgumentFindings := executeRepositoryTemplate(t, root, nestedSelfArgumentDB, templatePath)
	assertFindingSetContains(t, nestedSelfArgumentFindings, []string{
		"NestedSelfArgument.run",
		"NestedSelfArgument.runWithOptions",
	})
}

func TestRepositoryProxyStorageCollisionKeepsLocationlessMatchAtContractScope(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	templatePath := filepath.Join(root, "scripts/benchmark/templates/decurity-semgrep-inspired/proxy-storage-collision.yaml")
	tmpl, err := LoadTemplate(templatePath)
	if err != nil {
		t.Fatalf("load proxy-storage-collision template: %v", err)
	}

	vulnerableDB := buildRepositoryFixtureDatabase(t, root, proxyStorageCollisionFixture)
	findings := New(vulnerableDB).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("vulnerable findings = %d, want 1: %+v", len(findings), findings)
	}
	loc := findings[0].Location
	wantFile := filepath.Join(root, filepath.FromSlash(proxyStorageCollisionFixture))
	if loc.File != wantFile || loc.Contract != "VulnerableProxyStorageCollision" || loc.Function != "" ||
		loc.Line != 0 || loc.Col != 0 || loc.EndLine != 0 || loc.EndCol != 0 ||
		loc.StartByte != 0 || loc.EndByte != 0 {
		t.Fatalf("location = %+v, want contract/file-only VulnerableProxyStorageCollision at %s with no source span", loc, wantFile)
	}

	safeDB := buildRepositoryFixtureDatabase(t, root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/proxy-storage-no-collision.sol")
	if safe := New(safeDB).Execute(tmpl); len(safe) != 0 {
		t.Fatalf("safe no-collision fixture findings = %d, want 0: %+v", len(safe), safe)
	}
}

func TestContractScopePreciseMatchKeepsFunctionAndSpan(t *testing.T) {
	root := repoRoot(t)
	skipWithoutBenchmarkHarness(t, root)
	db := buildRepositoryFixtureDatabase(t, root, proxyStorageCollisionFixture)
	tmpl, err := ParseTemplate(`
meta: {id: contract-precise-control, severity: LOW}
query:
  select: state_write
  from: contract
`)
	if err != nil {
		t.Fatalf("parse precise contract control: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) != 1 {
		t.Fatalf("precise control findings = %d, want 1: %+v", len(findings), findings)
	}
	loc := findings[0].Location
	primary := findings[0].PrimaryAST
	if primary == nil {
		t.Fatal("precise contract finding is missing PrimaryAST")
	}
	wantFile := filepath.Join(root, filepath.FromSlash(proxyStorageCollisionFixture))
	if loc.File != wantFile || loc.Contract != "VulnerableProxyStorageCollision" || loc.Function != "constructor" ||
		loc.Line != primary.Start || loc.Col != primary.StartCol ||
		loc.EndLine != primary.End || loc.EndCol != primary.EndCol ||
		loc.StartByte != primary.StartByte || loc.EndByte != primary.EndByte ||
		loc.Line <= 0 || loc.StartByte <= 0 || loc.EndByte <= loc.StartByte {
		t.Fatalf("precise contract location = %+v, want constructor span equal to PrimaryAST %+v", loc, primary)
	}
}
