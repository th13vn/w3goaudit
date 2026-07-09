package engine

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// TestStatementContainsScopesToNearestStatement exercises the generic
// `statement_contains` predicate via the incorrect-exp template (which uses
// `not: { statement_contains: <bitwise> }`). The bitwise vocabulary lives in the
// template, not the engine. A `^` with simple operands and no sibling bitwise op
// in its statement is flagged (`scaleWei`, `maxByte`, `power`); a `^` sharing a
// statement with `&`/`|` (`Math.average`, `mix`), a complex left operand
// (`mulDiv` seed), or a hex mask is not. Critically, `statement_contains` is
// scoped to the NEAREST statement, so a bitwise op in a sibling statement does
// not suppress an unrelated `^`.
func TestStatementContainsScopesToNearestStatement(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/security/incorrect-exp.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/incorrect-exp.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Location.Function)
	}
	sort.Strings(got)

	want := []string{"maxByte", "power", "scaleWei"}
	if len(got) != len(want) {
		t.Fatalf("incorrect-exp findings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("incorrect-exp findings = %v, want %v", got, want)
		}
	}
}
