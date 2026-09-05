package engine

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// TestPromotedDetectorsDiscriminateVulnerableFromSafe runs retained promoted
// detectors in the shipped `official/` pack. Reworked or deferred mechanisms
// are intentionally validated in their benchmark/candidate lanes until generic
// semantic evidence is strong enough for official promotion.
//
// Both halves matter. The `want` list proves each retained detector still fires
// after promotion, and the
// `Safe_*` naming convention lets the assertion double as a false-positive gate:
// a promoted detector that fires on a deliberate safe control fails here rather
// than quietly degrading the pack's precision.
func TestPromotedDetectorsDiscriminateVulnerableFromSafe(t *testing.T) {
	cases := []struct {
		template string
		fixture  string
		want     []string
	}{
		{
			template: "templates/official/high/no-slippage-check.yaml",
			fixture:  "test-data/security/amm-integration.sol",
			want: []string{
				"Vulnerable_NoSlippageCheck.swapEth",
				"Vulnerable_NoSlippageCheck.swapTokens",
			},
		},
	}

	root := repoRoot(t)
	for _, testCase := range cases {
		t.Run(filepath.Base(testCase.template), func(t *testing.T) {
			sources, err := reader.New().Read(filepath.Join(root, testCase.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			db, err := builder.New().Build(sources)
			if err != nil {
				t.Fatalf("build db: %v", err)
			}
			tmpl, err := LoadTemplate(filepath.Join(root, testCase.template))
			if err != nil {
				t.Fatalf("load template: %v", err)
			}

			var got []string
			for _, finding := range New(db).Execute(tmpl) {
				got = append(got, finding.Location.Contract+"."+finding.Location.Function)
			}
			sort.Strings(got)

			if strings.Join(got, ",") != strings.Join(testCase.want, ",") {
				t.Errorf("findings mismatch\n got: %v\nwant: %v", got, testCase.want)
			}
			for _, site := range got {
				if strings.HasPrefix(site, "Safe_") {
					t.Errorf("promoted detector fired on a safe control: %s", site)
				}
			}
		})
	}
}

// TestBidiCharacterDetectorFlagsOnlyTheBidiFixture covers the one promoted
// detector with `scope: source`, which reports per matching occurrence and per
// file rather than per declaration, so it cannot use the contract/function
// assertion above.
func TestBidiCharacterDetectorFlagsOnlyTheBidiFixture(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/security"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/medium/bidi-characters.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	if len(findings) == 0 {
		t.Fatal("no findings: the bidi fixture's control characters were lost — do not normalize that file")
	}
	for _, finding := range findings {
		if filepath.Base(finding.Location.File) != "bidi-characters.sol" {
			t.Errorf("bidi detector fired on %s; only the bidi fixture should contain control characters",
				finding.Location.File)
		}
	}
}
