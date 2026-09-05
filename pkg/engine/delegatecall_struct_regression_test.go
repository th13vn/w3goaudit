package engine

import (
	"path/filepath"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/builder"
	"github.com/th13vn/w3goaudit/pkg/reader"
)

func TestOfficialDelegatecallFindsUserControlledStructFieldForwardedThroughHelper(t *testing.T) {
	root := repoRoot(t)
	sources, err := reader.New().Read(filepath.Join(root, "scripts/benchmark/fixtures/decurity-semgrep-inspired/delegatecall-struct-forward.sol"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	b := builder.New()
	if _, err := b.Build(sources); err != nil {
		t.Fatalf("build database: %v", err)
	}
	tmpl, err := LoadTemplate(filepath.Join(root, "templates/official/critical/delegatecall-user-input.yaml"))
	if err != nil {
		t.Fatalf("load official template: %v", err)
	}
	var vulnerable, safe bool
	for _, finding := range New(b.GetDatabase()).Execute(tmpl) {
		switch {
		case finding.Location.Contract == "VulnerableDelegatecallStruct" && finding.EntryPoint != nil && finding.EntryPoint.Function == "exec":
			if finding.Location.Function != "_run" {
				t.Fatalf("expected dangerous statement in _run, got %q", finding.Location.Function)
			}
			vulnerable = true
		case finding.Location.Contract == "SafeDelegatecallStruct":
			safe = true
		}
	}
	if !vulnerable {
		t.Fatal("official delegatecall detector missed VulnerableDelegatecallStruct.exec")
	}
	if safe {
		t.Fatal("official delegatecall detector reported SafeDelegatecallStruct")
	}
}
