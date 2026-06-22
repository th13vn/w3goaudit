package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/report"
	"github.com/th13vn/w3goaudit/templates"
)

// loadScanTemplates loads the templates for a scan: an explicit --template path
// (file or directory) when given, otherwise the official pack embedded in the
// binary. Returns the templates and a short human-readable source description.
func loadScanTemplates() ([]*engine.Template, string, error) {
	opts := engine.TemplateLoadOptions{IgnoreInvalid: ignoreInvalidTemplates}

	// Precedence: explicit --template > ~/.w3goaudit/templates (when populated)
	// > the embedded official pack (always available offline fallback).
	if templatePath == "" {
		if templateHomeDir != "" {
			tmpls, err := engine.LoadTemplatesWithOptions(templateHomeDir, opts)
			if err != nil {
				return nil, "", fmt.Errorf("loading templates from %s: %w", templateHomeDir, err)
			}
			return tmpls, "template home (" + templateHomeDir + ")", nil
		}
		tmpls, err := engine.LoadTemplatesFromFS(templates.Official, templates.OfficialDir, opts)
		if err != nil {
			return nil, "", fmt.Errorf("loading built-in templates: %w", err)
		}
		return tmpls, "built-in official pack", nil
	}

	info, err := os.Stat(templatePath)
	if err != nil {
		return nil, "", fmt.Errorf("error loading template: %w", err)
	}

	if info.IsDir() {
		tmpls, err := engine.LoadTemplatesWithOptions(templatePath, opts)
		if err != nil {
			return nil, "", fmt.Errorf("error loading templates: %w", err)
		}
		return tmpls, templatePath, nil
	}

	tmpl, err := engine.LoadTemplate(templatePath)
	if err != nil {
		return nil, "", fmt.Errorf("error loading templates: %w", err)
	}
	return []*engine.Template{tmpl}, templatePath, nil
}

// printTemplateList prints the rule inventory (id, severity, confidence, title),
// sorted by severity then id, for the --list-templates flag.
func printTemplateList(tmpls []*engine.Template, source string) {
	fmt.Printf("Templates (%s): %d\n\n", source, len(tmpls))
	sorted := make([]*engine.Template, len(tmpls))
	copy(sorted, tmpls)
	sortTemplates(sorted)
	for _, t := range sorted {
		conf := t.Meta.Confidence
		if conf == "" {
			conf = "-"
		}
		fmt.Printf("  %-9s %-7s %-28s %s\n",
			strings.ToUpper(t.Meta.Severity), conf, t.Meta.ID, t.Meta.Title)
	}
}

// sortTemplates orders templates by descending severity then id (stable).
func sortTemplates(tmpls []*engine.Template) {
	// Simple insertion-free sort via report.SeverityRank.
	for i := 1; i < len(tmpls); i++ {
		for j := i; j > 0; j-- {
			a, b := tmpls[j-1], tmpls[j]
			ra, rb := report.SeverityRank(a.Meta.Severity), report.SeverityRank(b.Meta.Severity)
			if ra < rb || (ra == rb && a.Meta.ID <= b.Meta.ID) {
				break
			}
			tmpls[j-1], tmpls[j] = b, a
		}
	}
}

// filterFindings applies --severity / --min-severity, --include, and --exclude.
// --severity is an exact set (e.g. "high,critical"); --min-severity is a
// threshold (that level and above). The two are mutually exclusive (enforced by
// the caller). The include/exclude lists are comma-separated template-ID globs
// (filepath.Match syntax); a finding must match at least one include (if any)
// and no exclude.
func filterFindings(findings []*engine.Finding) ([]*engine.Finding, error) {
	includes := splitGlobs(includeTemplates)
	excludes := splitGlobs(excludeTemplates)

	// Build the exact-severity set (lowercased) for --severity.
	sevSet := make(map[string]bool)
	for _, s := range splitGlobs(severityList) {
		sevSet[strings.ToLower(s)] = true
	}

	out := findings[:0:0] // new backing array so the caller's slice is untouched
	for _, f := range findings {
		if len(sevSet) > 0 && !sevSet[strings.ToLower(f.Severity)] {
			continue
		}
		if minSeverity != "" && !report.SeverityAtLeast(f.Severity, minSeverity) {
			continue
		}
		if len(includes) > 0 {
			ok, err := matchesAnyGlob(f.TemplateID, includes)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		if len(excludes) > 0 {
			ok, err := matchesAnyGlob(f.TemplateID, excludes)
			if err != nil {
				return nil, err
			}
			if ok {
				continue
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func splitGlobs(csv string) []string {
	if strings.TrimSpace(csv) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func matchesAnyGlob(id string, globs []string) (bool, error) {
	for _, g := range globs {
		ok, err := filepath.Match(g, id)
		if err != nil {
			return false, fmt.Errorf("invalid template-ID pattern %q: %w", g, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}
