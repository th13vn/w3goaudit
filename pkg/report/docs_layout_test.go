package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalResultLayoutIsDocumented(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	checks := map[string][]string{
		"README.md":                {"consolidated `audit.md`", "audit.html", "one deep-dive Markdown report per main", "schema version 2.0.0"},
		"CHANGELOG.md":             {"## v0.5.0 - 2026-09-01", "schema 2.0.0", "manifest compatibility aliases"},
		"docs/usage.md":            {"README.md · audit.md · results.sarif · run.log", "contracts/<source-path>__<Contract>.md", "Also emit audit.html"},
		"docs/workflows.md":        {"README.md / audit.md", "one consolidated Markdown deep dive per main contract", "one deep-dive Markdown report per main contract", "also emit audit.html"},
		"docs/project-overview.md": {"README.md, audit.md", "one Markdown deep dive per main contract", "Opt-in audit.html"},
		"docs/internals.md":        {"audit.md", "contracts/<rel-src-path-no-ext>__<MainContract>.md", "manifest.json             # written last"},
		"docs/sdk.md":              {"FormatAuditMarkdown", "FormatAuditHTML", "FormatContractReportMarkdown", "standalone compatibility APIs"},
		"docs/extension-output.md": {"human reports are not an editor data dependency", "files.data"},
		"pkg/home/home.go":         {"html: false                      # also emit audit.html"},
		"cmd/w3goaudit/root.go":    {"Version   = \"0.5.0\"", "Also emit audit.html into the result folder"},
	}
	for rel, wants := range checks {
		content, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(content)
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s missing canonical result-layout promise %q", rel, want)
			}
		}
	}
}
