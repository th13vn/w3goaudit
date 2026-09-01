package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestFormatAuditHTMLViaBundleConsolidatesAndEscapesEvidence(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	db.ScanTarget = "/repo/src"
	db.AddSourceFile(&types.SourceFile{
		Path:    "/repo/src/Vault.sol",
		Content: "contract Vault {\nfunction withdraw() external {\naddress(msg.sender).call{value: 1}(\"\");\n}\n}\n",
	})
	db.AddDiagnostic(types.Diagnostic{Code: "test.incomplete", Severity: types.DiagnosticWarning, Phase: "test", Incomplete: true})
	contract := &types.Contract{
		ID: "/repo/src/Vault.sol#Vault", Name: "Vault", SourceFile: "/repo/src/Vault.sol", Kind: types.ContractKindContract,
		Functions: []*types.Function{{Name: "withdraw", ContractName: "Vault", SourceFile: "/repo/src/Vault.sol", Selector: "withdraw()", Visibility: types.VisibilityExternal}},
	}
	db.AddContract(contract)
	db.MainContracts[contract.ID] = &types.MainContractEntry{EntryFunctions: []string{types.MakeFunctionID(contract.SourceFile, contract.Name, "withdraw()")}, LinearizedBaseIDs: []string{contract.ID}}

	summary := &SummaryReport{
		ProjectRoot: db.ProjectRoot, ScanTarget: db.ScanTarget, AnalysisComplete: false,
		DiagnosticCounts: DiagnosticCounts{Warning: 1}, GeneratedAt: time.Unix(0, 0).UTC(),
		Stats: &types.DatabaseStats{TotalFiles: 1, TotalContracts: 1, TotalFunctions: 1, TotalEntryFunctions: 1},
		MainContracts: []*ContractSummary{{
			Name: "Vault<script>alert(1)</script>", SourceFile: "/repo/src/Vault.sol", Version: "^0.8.20", EntryFunctionCount: 1,
			CallGraphMermaid: "graph TD\nSHOULD_NOT_INLINE_WORKFLOW",
		}},
	}
	findings := []*engine.Finding{{
		TemplateID: "HIGH-CALL", Severity: "HIGH", Confidence: "high", Title: "External <script>alert(2)</script> call",
		Message: "Call before effects.", Recommendation: "Move effects first.", Fix: "Use CEI.",
		References: []string{"https://example.com/cei", "javascript:alert(3)"},
		Location:   engine.Location{File: "/repo/src/Vault.sol", Contract: "Vault", Function: "withdraw", Line: 3},
	}}

	out := t.TempDir()
	if err := WriteBundle(out, db, summary, findings, ToolMeta{Name: "w3goaudit", Version: "test"}, BundleOptions{HTML: true, Now: func() time.Time { return time.Unix(0, 0) }}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(out, "audit.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(content)

	ordered := []string{
		"Executive Summary", "Analysis Scope and Limitations", "Project Metrics", "Security Findings",
		"Rules Hit", "Contract Surface", "State and Interaction Summary", "Machine and CI Artifacts",
	}
	last := -1
	for _, heading := range ordered {
		pos := strings.Index(html, heading)
		if pos <= last {
			t.Fatalf("heading %q missing or out of order:\n%s", heading, html)
		}
		last = pos
	}
	for _, want := range []string{
		`lang="en"`, `href="#security-findings"`, `role="main"`, "analysis incomplete",
		"HIGH-CALL", "Call before effects.", "Move effects first.", "Use CEI.",
		"address(msg.sender).call", "contracts/src/Vault__Vault_script_alert_1_script.md",
		"data/diagnostics.json", "results.sarif", "vis-network", "&lt;script&gt;alert(2)&lt;/script&gt;",
	} {
		if !strings.Contains(strings.ToLower(html), strings.ToLower(want)) {
			t.Fatalf("audit HTML missing %q:\n%s", want, html)
		}
	}
	for _, forbidden := range []string{
		"<script>alert(1)</script>", "<script>alert(2)</script>", `href="javascript:`,
		`<script src="http`, `SHOULD_NOT_INLINE_WORKFLOW`,
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("audit HTML contains forbidden %q", forbidden)
		}
	}
	for _, legacy := range []string{"overview.html", "findings.html"} {
		if _, err := os.Stat(filepath.Join(out, legacy)); !os.IsNotExist(err) {
			t.Fatalf("legacy split HTML survived: %s (%v)", legacy, err)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(out, "data", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(manifestBytes)
	for _, want := range []string{`"auditHtml": "audit.html"`, `"overviewHtml": "audit.html"`, `"findingsHtml": "audit.html"`} {
		if !strings.Contains(manifest, want) {
			t.Fatalf("HTML manifest alias missing %s:\n%s", want, manifest)
		}
	}
}

func TestFormatAuditHTMLEmptyFindingsStillShowsCoverageLimits(t *testing.T) {
	db := types.NewDatabase()
	summary := &SummaryReport{AnalysisComplete: true, GeneratedAt: time.Unix(0, 0), Stats: &types.DatabaseStats{}}
	out := FormatAuditHTML(ToolMeta{Name: "w3goaudit", Version: "test"}, summary, nil, db)
	for _, want := range []string{"No security issues found", "does not certify", "Analysis Scope and Limitations"} {
		if !strings.Contains(out, want) {
			t.Fatalf("empty audit HTML missing %q:\n%s", want, out)
		}
	}
}
