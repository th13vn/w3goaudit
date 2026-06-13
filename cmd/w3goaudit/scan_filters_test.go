package main

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/engine"
)

func TestSplitGlobs(t *testing.T) {
	got := splitGlobs(" A , B ,, C ")
	want := []string{"A", "B", "C"}
	if len(got) != len(want) {
		t.Fatalf("splitGlobs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitGlobs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if splitGlobs("   ") != nil {
		t.Error("splitGlobs of blank should be nil")
	}
}

func TestMatchesAnyGlob(t *testing.T) {
	globs := []string{"SEC-REENT-*", "SEC-DELEG-001"}
	cases := map[string]bool{
		"SEC-REENT-001": true,
		"SEC-DELEG-001": true,
		"SEC-PRNG-001":  false,
	}
	for id, want := range cases {
		got, err := matchesAnyGlob(id, globs)
		if err != nil {
			t.Fatalf("matchesAnyGlob(%q): %v", id, err)
		}
		if got != want {
			t.Errorf("matchesAnyGlob(%q) = %v, want %v", id, got, want)
		}
	}
	if _, err := matchesAnyGlob("X", []string{"["}); err == nil {
		t.Error("expected error for invalid glob pattern")
	}
}

// TestFilterFindings exercises the package-global-driven filter via temporary
// flag values, covering min-severity, include, and exclude.
func TestFilterFindings(t *testing.T) {
	findings := []*engine.Finding{
		{TemplateID: "SEC-A", Severity: "HIGH"},
		{TemplateID: "SEC-B", Severity: "LOW"},
		{TemplateID: "NOISE-C", Severity: "MEDIUM"},
	}

	save := func() (string, string, string) { return minSeverity, includeTemplates, excludeTemplates }
	restore := func(a, b, c string) { minSeverity, includeTemplates, excludeTemplates = a, b, c }
	defer restore(save())

	// min-severity HIGH keeps only SEC-A.
	minSeverity, includeTemplates, excludeTemplates = "high", "", ""
	if got, _ := filterFindings(findings); len(got) != 1 || got[0].TemplateID != "SEC-A" {
		t.Errorf("min-severity high: got %d findings, want [SEC-A]", len(got))
	}

	// exclude NOISE-* drops NOISE-C.
	minSeverity, includeTemplates, excludeTemplates = "", "", "NOISE-*"
	if got, _ := filterFindings(findings); len(got) != 2 {
		t.Errorf("exclude NOISE-*: got %d findings, want 2", len(got))
	}

	// include SEC-* keeps only the SEC ones.
	minSeverity, includeTemplates, excludeTemplates = "", "SEC-*", ""
	got, _ := filterFindings(findings)
	if len(got) != 2 {
		t.Errorf("include SEC-*: got %d findings, want 2", len(got))
	}
}

func TestCountAtLeast(t *testing.T) {
	findings := []*engine.Finding{
		{Severity: "CRITICAL"}, {Severity: "HIGH"}, {Severity: "LOW"},
	}
	if n := countAtLeast(findings, "high"); n != 2 {
		t.Errorf("countAtLeast(high) = %d, want 2", n)
	}
	if n := countAtLeast(findings, "critical"); n != 1 {
		t.Errorf("countAtLeast(critical) = %d, want 1", n)
	}
	if n := countAtLeast(findings, "info"); n != 3 {
		t.Errorf("countAtLeast(info) = %d, want 3", n)
	}
}
