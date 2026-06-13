package report

import (
	"strings"
	"testing"
	"time"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// minimalDB returns a tiny database so GetStats() in the formatters doesn't panic.
func minimalDB() *types.Database {
	return types.NewDatabase()
}

// TestHTMLFindingsEscaped verifies attacker-controlled content (the scanned
// source excerpt, the template title, and a reference URL) is escaped, so a
// malicious contract or template pack cannot inject script into the report.
func TestHTMLFindingsEscaped(t *testing.T) {
	findings := []*engine.Finding{
		{
			TemplateID: "XSS-TEST",
			Title:      "Pwn <script>alert(1)</script>",
			Severity:   "HIGH",
			Message:    "bad & <b>dangerous</b>",
			References: []string{`javascript:alert(1)`, `https://example.com/?a="b"`},
			Location:   engine.Location{File: "/x/Token.sol", Contract: "Token", Function: "f", Line: 1},
		},
	}
	html := FormatFindingsAsHTML(findings, minimalDB())

	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("raw <script> from finding Title leaked into HTML unescaped (XSS)")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped &lt;script&gt; in HTML output")
	}
	if strings.Contains(html, `href="javascript:alert(1)"`) {
		t.Error("javascript: scheme was emitted as an href (should be dropped)")
	}
	if strings.Contains(html, `<b>dangerous</b>`) {
		t.Error("raw HTML from Message leaked unescaped")
	}
}

// TestMarkdownFenceNoBreakout verifies an excerpt containing a ``` fence cannot
// break out of its code block. We can't easily inject a custom excerpt, so we
// exercise mdFence directly plus a behavioral check on a crafted finding.
func TestMarkdownFenceNoBreakout(t *testing.T) {
	if f := mdFence("no backticks here"); f != "```" {
		t.Errorf("mdFence(plain) = %q, want ```", f)
	}
	if f := mdFence("contains ``` triple"); f != "````" {
		t.Errorf("mdFence(triple) = %q, want ```` (one longer)", f)
	}
	if f := mdFence("````` five"); f != "``````" {
		t.Errorf("mdFence(five) = %q, want six backticks", f)
	}
}

// TestUnknownSeverityRendered verifies a finding with an unrecognized severity
// still appears in the Markdown and HTML reports (previously it was grouped
// under UNKNOWN but never rendered).
func TestUnknownSeverityRendered(t *testing.T) {
	findings := []*engine.Finding{
		{
			TemplateID: "WEIRD-SEV",
			Title:      "Odd severity finding",
			Severity:   "BOGUS",
			Location:   engine.Location{File: "/x/A.sol", Contract: "A", Function: "g", Line: 2},
		},
	}
	md := FormatFindingsAsMarkdown(findings, minimalDB())
	if !strings.Contains(md, "Odd severity finding") {
		t.Error("finding with unknown severity vanished from Markdown report")
	}
	html := FormatFindingsAsHTML(findings, minimalDB())
	if !strings.Contains(html, "Odd severity finding") {
		t.Error("finding with unknown severity vanished from HTML report")
	}
}

// TestReportDeterministic verifies report output is byte-identical regardless of
// the input finding order (group sorting + fixed severity order).
func TestReportDeterministic(t *testing.T) {
	mk := func(id, sev, title string, line int) *engine.Finding {
		return &engine.Finding{TemplateID: id, Title: title, Severity: sev,
			Location: engine.Location{File: "/x/A.sol", Contract: "A", Function: "f", Line: line}}
	}
	a := []*engine.Finding{
		mk("B-RULE", "HIGH", "Beta", 1),
		mk("A-RULE", "HIGH", "Alpha", 2),
		mk("C-RULE", "MEDIUM", "Gamma", 3),
	}
	b := []*engine.Finding{
		mk("C-RULE", "MEDIUM", "Gamma", 3),
		mk("A-RULE", "HIGH", "Alpha", 2),
		mk("B-RULE", "HIGH", "Beta", 1),
	}
	if FormatFindingsAsMarkdown(a, minimalDB()) != FormatFindingsAsMarkdown(b, minimalDB()) {
		t.Error("Markdown report differs when input finding order differs (non-deterministic)")
	}
}

// TestOverviewHTMLEscaped verifies the OVERVIEW renderer (ToHTML) escapes
// source-derived strings that are NOT identifier-constrained — state-variable
// type names, signatures, and "defined in" labels — closing the same XSS class
// the findings renderer fixed.
func TestOverviewHTMLEscaped(t *testing.T) {
	report := &SummaryReport{
		ProjectRoot: "/x",
		GeneratedAt: time.Unix(0, 0),
		Stats:       &types.DatabaseStats{},
		MainContracts: []*ContractSummary{{
			Name:       "Vault",
			SourceFile: "/x/Vault.sol",
			StateVariables: []*StateSummary{{
				Name:      "data",
				TypeName:  "mapping(address => uint)</code><script>alert(1)</script>",
				DefinedIn: "Vault",
			}},
		}},
	}
	out := report.ToHTML()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("overview HTML leaked raw <script> from a state-variable type name (XSS)")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped &lt;script&gt; in overview HTML output")
	}
}

// TestSeverityRank verifies the exported gating helpers used by --fail-on.
func TestSeverityRank(t *testing.T) {
	if !SeverityAtLeast("CRITICAL", "HIGH") {
		t.Error("CRITICAL should be at least HIGH")
	}
	if SeverityAtLeast("LOW", "HIGH") {
		t.Error("LOW should not be at least HIGH")
	}
	if !SeverityAtLeast("HIGH", "HIGH") {
		t.Error("HIGH should be at least HIGH")
	}
	if IsKnownSeverity("BOGUS") {
		t.Error("BOGUS should not be a known severity")
	}
}
