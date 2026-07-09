package engine

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// TestArbitrarySendEthForwardedOwnershipGuard runs the real pipeline (reader →
// builder → engine) over the arbitrary-send-eth fixture. The genuinely
// unprotected withdrawal must be flagged; the owner-gated vault withdrawal that
// forwards msg.sender into an internal `_withdraw` (and gates on
// `ownerOf(tokenId) != caller`) must NOT be — that was the SpiceFiNFT4626 false
// positive. Exercises both the selector-vs-bare-name resolution fix and the
// forwarded-caller-identity auth recognition.
func TestArbitrarySendEthForwardedOwnershipGuard(t *testing.T) {
	root := repoRoot(t)
	rdr := reader.New()
	sources, err := rdr.Read(filepath.Join(root, "test-data/security/arbitrary-send-eth.sol"))
	if err != nil {
		t.Fatalf("read sources: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build db: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/high/arbitrary-send-eth.yaml"))
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	findings := New(db).Execute(tmpl)
	got := make([]string, 0, len(findings))
	for _, f := range findings {
		got = append(got, f.Location.Contract+"."+f.Location.Function)
	}
	sort.Strings(got)

	want := []string{"Vulnerable_ArbitrarySendETH.withdraw"}
	if len(got) != len(want) || (len(got) == 1 && got[0] != want[0]) {
		t.Fatalf("unexpected findings:\n got: %v\nwant: %v", got, want)
	}
}
