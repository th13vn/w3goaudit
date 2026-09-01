package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestFormatAuditMarkdownConsolidatesProjectEvidence(t *testing.T) {
	db := types.NewDatabase()
	db.ProjectRoot = "/repo"
	db.ScanTarget = "/repo/src"
	db.AddSourceFile(&types.SourceFile{
		Path:    "/repo/src/Vault.sol",
		Content: "contract Vault {\nfunction withdraw() external {\naddress(msg.sender).call{value: 1}(\"\");\n}\n}\n",
	})
	summary := &SummaryReport{
		ProjectRoot:      db.ProjectRoot,
		ScanTarget:       db.ScanTarget,
		AnalysisComplete: false,
		DiagnosticCounts: DiagnosticCounts{Warning: 1},
		GeneratedAt:      time.Unix(0, 0).UTC(),
		Stats:            &types.DatabaseStats{TotalFiles: 1, TotalContracts: 1, TotalFunctions: 1, TotalEntryFunctions: 1},
		MainContracts: []*ContractSummary{{
			Name: "Vault", SourceFile: "/repo/src/Vault.sol", Version: "^0.8.20", EntryFunctionCount: 1,
		}},
	}
	findings := []*engine.Finding{{
		TemplateID: "HIGH-CALL", Severity: "HIGH", Confidence: "high", Title: "External call",
		Message: "Call before effects.", Recommendation: "Move effects first.", Fix: "Use CEI.",
		References:   []string{"https://example.com/cei"},
		Location:     engine.Location{File: "/repo/src/Vault.sol", Contract: "Vault", Function: "withdraw", Line: 3},
		Reachability: &engine.ReachabilityPath{Steps: []engine.ReachStep{{File: "/repo/src/Vault.sol", Contract: "Vault", Function: "withdraw", Line: 3}}},
		Related:      []engine.RelatedLocation{{Label: "call site", File: "/repo/src/Vault.sol", Contract: "Vault", Function: "withdraw", Line: 3}},
	}}

	got := FormatAuditMarkdown(ToolMeta{Name: "w3goaudit", Version: "test"}, summary, findings, db)
	ordered := []string{
		"# Security Audit", "## Executive Summary", "## Analysis Scope and Limitations",
		"## Project Metrics", "## Security Findings", "## Rules Hit",
		"## Contract Surface Index", "## State and Interaction Summary", "## Machine and CI Artifacts",
	}
	last := -1
	for _, section := range ordered {
		pos := strings.Index(got, section)
		if pos <= last {
			t.Fatalf("section %q missing or out of order:\n%s", section, got)
		}
		last = pos
	}
	for _, evidence := range []string{
		"analysis incomplete", "Call before effects.", "Move effects first.", "Use CEI.",
		"https://example.com/cei", "All matched sites", "Vault.withdraw", "address(msg.sender).call",
		"contracts/src/Vault__Vault.md", "data/diagnostics.json", "results.sarif",
	} {
		if !strings.Contains(strings.ToLower(got), strings.ToLower(evidence)) {
			t.Fatalf("audit missing %q:\n%s", evidence, got)
		}
	}
	if !strings.Contains(got, `<a id="finding-high-call-`) {
		t.Fatalf("finding anchor missing:\n%s", got)
	}
	if strings.Contains(got, "## Entry-Point Workflows") {
		t.Fatalf("project audit dumped contract workflows:\n%s", got)
	}
}

func TestFormatAuditMarkdownKeepsOutOfRootContractIdentity(t *testing.T) {
	summary := &SummaryReport{
		ProjectRoot: "/repo",
		GeneratedAt: time.Unix(0, 0).UTC(),
		Stats:       &types.DatabaseStats{},
		MainContracts: []*ContractSummary{
			{Name: "Vault", SourceFile: "/vendor/a/Vault.sol", Version: "0.8.19", EntryFunctionCount: 1, StateVariableCount: 2},
			{Name: "Vault", SourceFile: "/vendor/b/Vault.sol", Version: "0.8.20", EntryFunctionCount: 9, StateVariableCount: 8},
		},
	}
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := FormatAuditMarkdown(ToolMeta{Name: "w3goaudit"}, summary, nil, nil)
	for _, contract := range summary.MainContracts {
		reportPath := idx.reports[contractIdentityKey(contract)]
		want := fmt.Sprintf("| `Vault.sol` | `Vault` | `%s` | %d | 0 | 0 | %d | 0 | 0 | [report](%s) |",
			contract.Version, contract.EntryFunctionCount, contract.StateVariableCount, reportPath)
		if !strings.Contains(got, want) {
			t.Fatalf("audit lost exact out-of-root identity for %s:\nwant %s\n%s", contract.SourceFile, want, got)
		}
	}
}

func TestFindingAnchorsAreStableAndDistinct(t *testing.T) {
	findings := []*engine.Finding{
		{TemplateID: "A/B", Severity: "HIGH", Title: "one", Location: engine.Location{File: "/a.sol", Line: 1}},
		{TemplateID: "A B", Severity: "HIGH", Title: "two", Location: engine.Location{File: "/b.sol", Line: 2}},
	}
	left := buildFindingAnchorIndex(findings)
	right := buildFindingAnchorIndex([]*engine.Finding{findings[1], findings[0]})
	if len(left) != 2 || left[findingGroupKey(findings[0])] == left[findingGroupKey(findings[1])] {
		t.Fatalf("anchors not distinct: %#v", left)
	}
	for key, anchor := range left {
		if right[key] != anchor {
			t.Fatalf("anchor changed with order: %q => %q / %q", key, anchor, right[key])
		}
	}
}

func TestFindingAnchorPlanEscalatesShortDigestCollision(t *testing.T) {
	findings := []*engine.Finding{
		{TemplateID: "A/B", Severity: "HIGH", Title: "one", Location: engine.Location{File: "/a.sol", Line: 1}},
		{TemplateID: "A B", Severity: "HIGH", Title: "two", Location: engine.Location{File: "/b.sol", Line: 2}},
	}
	digests := map[string]string{
		findingGroupKey(findings[0]): "0123456789abcdefaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		findingGroupKey(findings[1]): "0123456789abcdefbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	anchors, err := planFindingAnchors(findings, func(key string) string { return digests[key] })
	if err != nil {
		t.Fatal(err)
	}
	for key, digest := range digests {
		if !strings.HasSuffix(anchors[key], digest) {
			t.Fatalf("anchor did not escalate to full digest: %q", anchors[key])
		}
	}
}

func TestFindingAnchorPlanRejectsFullDigestCollision(t *testing.T) {
	findings := []*engine.Finding{
		{TemplateID: "A/B", Severity: "HIGH", Location: engine.Location{File: "/a.sol", Line: 1}},
		{TemplateID: "A B", Severity: "HIGH", Location: engine.Location{File: "/b.sol", Line: 2}},
	}
	if _, err := planFindingAnchors(findings, func(string) string {
		return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	}); err == nil {
		t.Fatal("expected full finding-anchor digest collision to fail")
	}
}

func TestFolderReadmeIsBoundedAndLinksToAudit(t *testing.T) {
	summary := &SummaryReport{ProjectRoot: "/repo", ScanTarget: "/repo/src", GeneratedAt: time.Unix(0, 0), Stats: &types.DatabaseStats{}}
	findings := make([]*engine.Finding, 15)
	for i := range findings {
		findings[i] = &engine.Finding{
			TemplateID: fmt.Sprintf("RULE-%02d", i), Severity: "HIGH", Title: fmt.Sprintf("Finding %02d", i),
			Location: engine.Location{File: fmt.Sprintf("/repo/%02d.sol", i), Line: i + 1},
		}
	}
	got := FormatFolderReadme(ToolMeta{Name: "w3goaudit", Version: "test"}, summary, findings)
	if lines := strings.Count(got, "\n") + 1; lines > 120 {
		t.Fatalf("README has %d lines, want <= 120", lines)
	}
	if !strings.Contains(got, "[audit.md](audit.md)") || strings.Contains(got, "[summary.md](summary.md)") {
		t.Fatalf("README uses old report navigation:\n%s", got)
	}
	if strings.Count(got, "finding-") > 10 || !strings.Contains(got, "5 more") {
		t.Fatalf("README priority list is not bounded:\n%s", got)
	}
	for _, want := range []string{
		"**Scan target:** `/repo/src`",
		"**15 issue groups across 15 occurrences**",
		"[run.log](run.log)",
		"stable machine interface",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("README missing %q:\n%s", want, got)
		}
	}
}
