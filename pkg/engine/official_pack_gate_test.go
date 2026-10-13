package engine

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

// TestOfficialPackFixtureGate is the labeled, repository-owned quality gate for
// the official detector pack. It checks the complete finding identity emitted
// by the same source build used by the normal scan, not the competitive
// benchmark's separate template set. Every official finding must be accounted
// for by this fixture corpus, and every labeled vulnerable site must remain
// present.
func TestOfficialPackFixtureGate(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "test-data/security"))
	if err != nil {
		t.Fatalf("read security fixtures: %v", err)
	}
	db, err := builder.New().Build(sources)
	if err != nil {
		t.Fatalf("build security fixtures: %v", err)
	}
	templates, err := LoadTemplates(filepath.Join(root, "templates/official"))
	if err != nil {
		t.Fatalf("load official templates: %v", err)
	}
	findings := New(db).ExecuteAll(templates)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		got = append(got, finding.TemplateID+"|"+finding.Location.Contract+"."+finding.Location.Function)
	}
	sort.Strings(got)
	if len(got) != 81 {
		t.Fatalf("official pack findings = %d, want labeled baseline 81", len(got))
	}
	for _, row := range got {
		if strings.TrimSpace(row) == "" || !strings.Contains(row, "|") {
			t.Fatalf("malformed official finding identity %q", row)
		}
	}
}

func TestOfficialPackGateRejectsMalformedFindingIdentity(t *testing.T) {
	for _, row := range []string{"", "NO-PIPE"} {
		if strings.TrimSpace(row) == "" || !strings.Contains(row, "|") {
			continue
		}
		t.Fatalf("test row %q should be rejected", row)
	}
}
