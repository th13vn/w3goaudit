package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestNamedCompetitiveMisses(t *testing.T) {
	cases := []struct {
		fixture    string
		template   string
		vulnerable string
		safe       string
	}{
		{
			fixture:    "../../benchmarks/fixtures/4naly3er-detectors/centralization-risk.sol",
			template:   "../../benchmarks/templates/4naly3er-inspired/M-centralization-risk.yaml",
			vulnerable: "Vulnerable_CentralizationRisk.setFee",
			safe:       "Safe_CentralizationRisk.getFee",
		},
		{
			fixture:    "../../benchmarks/fixtures/decurity-semgrep-inspired/accessible-selfdestruct-asm.sol",
			template:   "../../benchmarks/templates/decurity-semgrep-inspired/accessible-selfdestruct.yaml",
			vulnerable: "VulnerableAccessibleSelfdestructAsm.destroy",
			safe:       "SafeAccessibleSelfdestructAsm.destroy",
		},
		{
			fixture:    "../../benchmarks/fixtures/slither-detectors/incorrect-equality.sol",
			template:   "../../benchmarks/templates/slither-inspired/incorrect-equality.yaml",
			vulnerable: "Vulnerable_IncorrectEquality.goalReached",
			safe:       "Safe_IncorrectEquality.goalReached",
		},
		{
			fixture:    "../../benchmarks/fixtures/slither-detectors/divide-before-multiply.sol",
			template:   "../../benchmarks/templates/slither-inspired/divide-before-multiply.yaml",
			vulnerable: "Vulnerable_DivideBeforeMultiply.calculate",
			safe:       "Safe_DivideBeforeMultiply.calculate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.vulnerable, func(t *testing.T) {
			assertTemplateFindsOnly(t, tc.fixture, tc.template, tc.vulnerable, tc.safe)
		})
	}
}

func assertTemplateFindsOnly(t *testing.T, fixture, templatePath, vulnerable, safe string) {
	t.Helper()
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, strings.TrimPrefix(fixture, "../../")))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, strings.TrimPrefix(templatePath, "../../")))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	got := map[string]bool{}
	for _, finding := range New(db).Execute(tmpl) {
		got[finding.Location.Contract+"."+finding.Location.Function] = true
	}
	if !got[vulnerable] {
		t.Errorf("missing %s; got=%v", vulnerable, got)
	}
	if got[safe] {
		t.Errorf("unexpected safe finding %s; got=%v", safe, got)
	}
}

func TestDuplicateContractNamesKeepExactEngineReachability(t *testing.T) {
	root := repoRoot(t)
	fixtureRoot := filepath.Join(root, "test-data/core/identity-collision")
	sources, err := reader.New().Read(fixtureRoot)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/critical/selfdestruct-unprotected.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	zFile := filepath.Join(fixtureRoot, "z", "Token.sol")
	aFile := filepath.Join(fixtureRoot, "a", "Token.sol")
	var zFinding *Finding
	for _, finding := range New(db).Execute(tmpl) {
		if finding.Location.File == aFile {
			t.Fatalf("a.Token has no selfdestruct but produced a finding: %#v", finding)
		}
		if finding.Location.File == zFile && finding.Location.Function == "run" {
			zFinding = finding
		}
	}
	if zFinding == nil {
		t.Fatal("missing z.Token.run selfdestruct finding")
	}
	if zFinding.Reachability == nil || len(zFinding.Reachability.Steps) < 2 {
		t.Fatalf("missing z.Token reachability: %#v", zFinding.Reachability)
	}
	for _, step := range zFinding.Reachability.Steps {
		if step.File != zFile {
			t.Fatalf("reachability step crossed duplicate identity: %#v", step)
		}
	}
	last := zFinding.Reachability.Steps[len(zFinding.Reachability.Steps)-1]
	if last.Function != "danger" {
		t.Fatalf("last reachability step = %#v, want z.Token.danger", last)
	}
	gotEffects := db.Semantics.GetFunctionEffects(types.MakeFunctionID(zFile, "Token", "danger()"))
	foundDestroyed := false
	if gotEffects != nil {
		for _, write := range gotEffects.StateWrites {
			foundDestroyed = foundDestroyed || write.Var == "destroyed"
			if write.Var == "safeCount" {
				t.Fatalf("z.Token.danger borrowed a.Token effects: %#v", gotEffects)
			}
		}
	}
	if !foundDestroyed {
		t.Fatalf("z.Token.danger effects = %#v", gotEffects)
	}
}
