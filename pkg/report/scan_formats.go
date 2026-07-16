package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// FormatFindingsAsMarkdown formats findings as Markdown.
// This produces the "findings" half of the split report. The "overview" half
// is produced by SummaryReport.ToMarkdown (see markdown.go).
func FormatFindingsAsMarkdown(findings []*engine.Finding, db *types.Database) string {
	var sb strings.Builder
	projectRoot := reportRootFromDB(db)

	sb.WriteString("# Security Findings — W3GoAudit\n\n")
	sb.WriteString("**Summary**\n\n")
	sb.WriteString("```\n")

	if len(findings) == 0 {
		sb.WriteString("No security issues found.\n")
		sb.WriteString("```\n\n")
		return sb.String()
	}

	// Summary stats — counts per severity + scan totals.
	stats := &types.DatabaseStats{}
	if db != nil {
		stats = db.GetStats()
	}
	bySev := countBySeverity(findings)
	sb.WriteString(fmt.Sprintf("Total Issues:       %d\n", countUniqueIssues(findings)))
	sb.WriteString(fmt.Sprintf("Total Occurrences:  %d\n", len(findings)))
	sb.WriteString(fmt.Sprintf("Critical: %-3d  High: %-3d  Medium: %-3d  Low: %-3d  Info: %-3d\n",
		bySev["CRITICAL"], bySev["HIGH"], bySev["MEDIUM"], bySev["LOW"], bySev["INFO"]))
	sb.WriteString(fmt.Sprintf("Files Scanned:      %d\n", stats.TotalFiles))
	sb.WriteString(fmt.Sprintf("Contracts:          %d\n", stats.TotalContracts))
	sb.WriteString(fmt.Sprintf("Functions:          %d\n", stats.TotalFunctions))
	sb.WriteString("```\n\n")

	// Group findings by TemplateID (same issue across multiple sites).
	grouped := groupFindings(findings)

	// Render highest severity first; UNKNOWN (typo'd severities) is appended so
	// such findings still appear instead of silently vanishing.
	issueCounter := 1

	for _, severity := range renderSeverityOrder(grouped) {
		groups, ok := grouped[severity]
		if !ok || len(groups) == 0 {
			continue
		}
		sortGroups(groups)

		for _, group := range groups {
			// Header: ## Severity-N — Title
			sb.WriteString(fmt.Sprintf("## %s-%d — %s\n\n", severity, issueCounter, group.Title))
			issueCounter++

			// Metadata block.
			sb.WriteString(fmt.Sprintf("- **Severity:** `%s`\n", severity))
			if group.Findings[0].Confidence != "" {
				sb.WriteString(fmt.Sprintf("- **Confidence:** `%s`\n", group.Findings[0].Confidence))
			}
			sb.WriteString(fmt.Sprintf("- **Template:** `%s`\n", group.TemplateID))
			sb.WriteString(fmt.Sprintf("- **Locations:** %d occurrence(s)\n", len(group.Findings)))
			for _, f := range group.Findings {
				sb.WriteString(fmt.Sprintf("  - `%s`\n", formatLocation(projectRoot, f)))
			}
			sb.WriteString("\n")

			// Description.
			sb.WriteString("### Description\n\n")
			if group.Message != "" {
				sb.WriteString(group.Message + "\n\n")
			} else {
				sb.WriteString("_No description available._\n\n")
			}

			// Collapsible code sections per location.
			for _, f := range group.Findings {
				location := formatLocation(projectRoot, f)
				sb.WriteString(fmt.Sprintf("<details>\n<summary>%s</summary>\n\n", location))
				sb.WriteString(renderFindingTraceMarkdown(projectRoot, f))
				sb.WriteString(renderRelatedLocationsMarkdown(projectRoot, f, db))
				if len(f.Related) == 0 {
					// Use a fence longer than any backtick run in the excerpt so
					// source containing ``` cannot break out of the code block.
					code := extractCodeForFinding(f, 3, db)
					fence := mdFence(code)
					sb.WriteString(fence + "solidity\n")
					sb.WriteString(code)
					if !strings.HasSuffix(code, "\n") {
						sb.WriteString("\n")
					}
					sb.WriteString(fence + "\n\n")
				}
				sb.WriteString("</details>\n\n")
			}

			// Recommendation — uses template's own text, not a generic placeholder.
			sb.WriteString("### Recommendation\n\n")
			if group.Recommendation != "" {
				sb.WriteString(group.Recommendation + "\n\n")
			} else {
				sb.WriteString("Review the code at the specified locations and apply appropriate security measures.\n\n")
			}

			// Suggested fix (optional structured block from the template).
			if group.Fix != "" {
				sb.WriteString("### Suggested Fix\n\n")
				sb.WriteString(group.Fix + "\n\n")
			}

			// References (optional).
			if len(group.References) > 0 {
				sb.WriteString("### References\n\n")
				for _, ref := range group.References {
					sb.WriteString(fmt.Sprintf("- %s\n", ref))
				}
				sb.WriteString("\n")
			}

			sb.WriteString("---\n\n")
		}
	}

	return sb.String()
}

func renderRelatedLocationsMarkdown(projectRoot string, f *engine.Finding, db *types.Database) string {
	if f == nil || len(f.Related) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("**All matched sites**\n\n")
	for _, loc := range f.Related {
		label := loc.Label
		if label == "" {
			label = "matched site"
		}
		sb.WriteString(fmt.Sprintf("- **%s:** `%s`\n", label, formatRelatedLocation(projectRoot, loc)))
	}
	sb.WriteString("\n**Matched site context**\n\n")
	for _, loc := range f.Related {
		label := loc.Label
		if label == "" {
			label = "matched site"
		}
		sb.WriteString(fmt.Sprintf("#### %s — `%s`\n\n", label, formatRelatedLocation(projectRoot, loc)))
		code := extractFullFunctionForLocation(engine.Location{
			File:     loc.File,
			Contract: loc.Contract,
			Function: loc.Function,
			Line:     loc.Line,
		}, db)
		fence := mdFence(code)
		sb.WriteString(fence + "solidity\n")
		sb.WriteString(code)
		if !strings.HasSuffix(code, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString(fence + "\n\n")
	}
	return sb.String()
}

func formatRelatedLocation(projectRoot string, loc engine.RelatedLocation) string {
	location := relPathForReport(projectRoot, loc.File)
	if loc.Contract != "" {
		location += " :: " + loc.Contract
	}
	if loc.Function != "" {
		location += "." + loc.Function + "()"
	}
	if loc.Line > 0 {
		location += fmt.Sprintf(":%d", loc.Line)
	}
	return location
}

// normalizeSeverity uppercases a finding's severity and maps any value outside
// the known set (including empty) to "UNKNOWN", so unrecognized severities are
// rendered in the dedicated UNKNOWN bucket instead of an unrendered phantom one.
func normalizeSeverity(severity string) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	if !IsKnownSeverity(sev) {
		return "UNKNOWN"
	}
	return sev
}

// countBySeverity returns occurrence counts per normalized severity label.
func countBySeverity(findings []*engine.Finding) map[string]int {
	out := make(map[string]int)
	for _, f := range findings {
		out[normalizeSeverity(f.Severity)]++
	}
	return out
}

// GroupedFinding represents findings grouped by issue type.
// Metadata fields (References, Fix, Recommendation) are taken from the first
// finding in the group; all findings in a group share the same TemplateID, so
// these are guaranteed identical.
type GroupedFinding struct {
	TemplateID     string
	Title          string
	Severity       string
	Message        string
	Recommendation string
	References     []string
	Fix            string
	Findings       []*engine.Finding
}

// groupFindings groups findings by TemplateID and severity.
//
// When TemplateID is empty (a buggy custom detector, or a finding emitted
// without going through newFinding), a synthetic key derived from the
// finding's title + severity + location is used so two unrelated empty-ID
// findings don't merge into one entry.
func groupFindings(findings []*engine.Finding) map[string][]*GroupedFinding {
	// Map: severity -> list of grouped findings
	result := make(map[string][]*GroupedFinding)

	// Map to track unique issues: groupKey -> GroupedFinding
	issueMap := make(map[string]*GroupedFinding)

	for _, f := range findings {
		sev := normalizeSeverity(f.Severity)

		key := f.TemplateID
		if key == "" {
			// Fall back to a synthetic key so empty-TemplateID findings don't
			// silently collapse into a single bogus group.
			key = fmt.Sprintf("__synthetic__|%s|%s|%s|%s|%d",
				sev, f.Title, f.Location.File, f.Location.Function, f.Location.Line)
		}
		if group, exists := issueMap[key]; exists {
			// Add to existing group
			group.Findings = append(group.Findings, f)
		} else {
			// Create new group
			title := f.Title
			if title == "" {
				title = f.TemplateID
			}

			group := &GroupedFinding{
				TemplateID:     f.TemplateID,
				Title:          title,
				Severity:       sev,
				Message:        f.Message,
				Recommendation: f.Recommendation,
				References:     f.References,
				Fix:            f.Fix,
				Findings:       []*engine.Finding{f},
			}
			issueMap[key] = group
			result[sev] = append(result[sev], group)
		}
	}

	return result
}

// formatLocation formats a finding location as a string
// formatLocation renders a finding's location for human-readable reports.
// Uses the relative path under the explicit project root when available so reviewers
// can disambiguate duplicate filenames (e.g. /src/Token.sol vs
// /test/mocks/Token.sol); falls back to basename if the location is outside
// the project root or the project root is unknown.
func formatLocation(projectRoot string, f *engine.Finding) string {
	location := relPathForReport(projectRoot, f.Location.File)
	if f.Location.Contract != "" {
		location += " :: " + f.Location.Contract
	}
	if f.Location.Function != "" {
		location += "." + f.Location.Function + "()"
	}
	if f.Location.Line > 0 {
		location += fmt.Sprintf(":%d", f.Location.Line)
	}
	return location
}

var (
	reportProjectRootMu sync.RWMutex
	reportProjectRoot   string
)

// SetReportProjectRoot configures the compatibility fallback used when a
// report API has no explicit project root.
//
// Deprecated: pass the project root through Database, SummaryReport, or the
// explicit projectRoot argument used by report helpers.
func SetReportProjectRoot(root string) {
	reportProjectRootMu.Lock()
	reportProjectRoot = root
	reportProjectRootMu.Unlock()
}

// relPathForReport returns the path relative to the explicit project root when
// possible. The deprecated process-global root is consulted only when the
// explicit root is empty; otherwise this function is scan-local and safe for
// concurrent callers.
func relPathForReport(projectRoot, absFile string) string {
	if projectRoot == "" {
		reportProjectRootMu.RLock()
		projectRoot = reportProjectRoot
		reportProjectRootMu.RUnlock()
	}
	if projectRoot != "" && absFile != "" {
		if rel, err := filepath.Rel(projectRoot, absFile); err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return rel
		}
	}
	return filepath.Base(absFile)
}

func reportRootFromDB(db *types.Database) string {
	if db == nil {
		return ""
	}
	return db.ProjectRoot
}

// countUniqueIssues counts distinct issue groups, matching exactly how
// groupFindings buckets findings (so the header total equals the number of
// rendered headings — empty-TemplateID findings get distinct synthetic keys
// rather than collapsing to one).
func countUniqueIssues(findings []*engine.Finding) int {
	grouped := groupFindings(findings)
	n := 0
	for _, groups := range grouped {
		n += len(groups)
	}
	return n
}

// FormatFindingsAsHTML formats findings as a standalone HTML document.
// This produces the "findings" half of the split report. The "overview" half
// is produced by SummaryReport.ToHTML (see html.go).
//
// Accessibility: lang="en", semantic <main>/<section>, aria-labels on
// interactive elements, sufficient contrast (Tokyo Night palette), focus
// styles for keyboard nav, and a screen-reader-friendly heading hierarchy.
func FormatFindingsAsHTML(findings []*engine.Finding, db *types.Database) string {
	var sb strings.Builder
	projectRoot := reportRootFromDB(db)

	// HTML header with dark mode styles
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Findings — W3GoAudit</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --border-color: #30363d;
            --focus-ring: #58a6ff;
            --critical: #f85149;
            --high: #f0883e;
            --medium: #d29922;
            --low: #3fb950;
            --info: #58a6ff;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }

        a { color: var(--info); }
        a:focus, button:focus, summary:focus, details:focus-within > summary {
            outline: 2px solid var(--focus-ring);
            outline-offset: 2px;
        }

        h1 {
            color: var(--text-primary);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }

        .skip-link {
            position: absolute;
            left: -10000px;
            top: auto;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            text-decoration: none;
        }
        .skip-link:focus { left: 1rem; top: 1rem; z-index: 1000; }

        .summary {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            font-family: monospace;
        }

        .summary h2 {
            margin-top: 0;
            color: var(--text-primary);
            font-size: 1.25rem;
        }

        .issue {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .issue h2 {
            margin-top: 0;
            color: var(--text-primary);
            font-size: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5rem;
        }
        
        .issue-meta {
            margin: 1rem 0;
        }
        
        .locations {
            background-color: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 4px;
            margin: 1rem 0;
        }
 
        .locations ul {
            list-style: none;
            padding-left: 1rem;
            margin: 0.5rem 0;
        }
        
        .locations li {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', monospace;
            font-size: 0.875rem;
            padding: 0.25rem 0;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-weight: 600;
            font-size: 0.875rem;
            margin-right: 1rem;
        }
        
        .severity-critical { background-color: var(--critical); color: white; }
        .severity-high { background-color: var(--high); color: white; }
        .severity-medium { background-color: var(--medium); color: #000; }
        .severity-low { background-color: var(--low); color: white; }
        .severity-info { background-color: var(--info); color: white; }
        
        details {
            background-color: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 1rem;
            margin: 1rem 0;
        }

        /* Reachability trace block — sits above the source excerpt inside each
           collapsible finding occurrence. The dotted prefix + per-step margin
           gives a visual "depth ladder" matching the Markdown variant. */
        .w3a-trace {
            background-color: var(--bg-secondary);
            border-left: 3px solid var(--medium);
            border-radius: 3px;
            padding: 0.6rem 0.8rem;
            margin: 0.5rem 0 0.75rem 0;
            font-size: 0.9rem;
        }
        .w3a-trace-label { color: var(--text-muted); font-weight: 600; margin-right: 0.25rem; }
        .w3a-trace-file, .w3a-trace-entry, .w3a-trace-node { margin: 0.25rem 0; }
        .w3a-trace-path-label { margin-top: 0.4rem; color: var(--text-muted); font-weight: 600; }
        .w3a-trace-path { list-style: none; padding-left: 0; margin: 0.25rem 0 0 0; }
        .w3a-trace-step { padding: 0.15rem 0; }
        .w3a-trace-dots { color: var(--text-muted); font-family: monospace; margin-right: 0.5rem; }
        .w3a-trace-meta { color: var(--text-muted); font-size: 0.85em; }
        .w3a-trace-host { color: var(--high); font-weight: 600; }
        .w3a-trace-entry-arrow { color: var(--medium); }
        
        summary {
            cursor: pointer;
            font-weight: 600;
            padding: 0.5rem;
            user-select: none;
        }
        
        summary:hover {
            background-color: var(--bg-primary);
            border-radius: 4px;
        }
        
        pre {
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 1rem;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        code {
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', monospace;
            font-size: 0.875rem;
        }
        
        .no-findings {
            text-align: center;
            padding: 3rem;
            font-size: 1.25rem;
            color: var(--low);
        }
        
        .description, .recommendation {
            margin: 1.5rem 0;
        }
        
        .description h3, .recommendation h3 {
            color: var(--text-primary);
            margin: 1rem 0 0.5rem 0;
        }
    </style>
</head>
<body>
    <a class="skip-link" href="#findings-list">Skip to findings</a>
    <main role="main" aria-labelledby="page-title">
    <h1 id="page-title">Security Findings — W3GoAudit</h1>
`)

	if len(findings) == 0 {
		sb.WriteString(`    <div class="no-findings" role="status">
        <p>No security issues found.</p>
    </div>
    </main>
</body>
</html>`)
		return sb.String()
	}

	// Summary
	stats := db.GetStats()
	bySev := countBySeverity(findings)
	sb.WriteString(`    <section class="summary" aria-labelledby="summary-heading">
        <h2 id="summary-heading">Summary</h2>
`)
	sb.WriteString(fmt.Sprintf(`        Total Issues: %d<br>
`, countUniqueIssues(findings)))
	sb.WriteString(fmt.Sprintf(`        Total Occurrences: %d<br>
`, len(findings)))
	sb.WriteString(fmt.Sprintf(`        Critical: %d &nbsp; High: %d &nbsp; Medium: %d &nbsp; Low: %d &nbsp; Info: %d<br>
`, bySev["CRITICAL"], bySev["HIGH"], bySev["MEDIUM"], bySev["LOW"], bySev["INFO"]))
	sb.WriteString(fmt.Sprintf(`        Files Scanned: %d<br>
`, stats.TotalFiles))
	sb.WriteString(fmt.Sprintf(`        Contracts: %d<br>
`, stats.TotalContracts))
	sb.WriteString(fmt.Sprintf(`        Functions: %d
    </section>
    <section id="findings-list" aria-label="Security findings list">
`, stats.TotalFunctions))

	// Group findings
	grouped := groupFindings(findings)

	// Render highest severity first; UNKNOWN appended so typo'd severities still
	// appear. Every interpolation below is HTML-escaped — findings embed the
	// scanned contract's own source (the code excerpt) and template-authored
	// text, all of which is attacker-controlled w.r.t. the report viewer.
	issueCounter := 1

	for _, severity := range renderSeverityOrder(grouped) {
		groups, ok := grouped[severity]
		if !ok || len(groups) == 0 {
			continue
		}
		sortGroups(groups)

		for _, group := range groups {
			sb.WriteString(`    <article class="issue" aria-labelledby="issue-` + fmt.Sprint(issueCounter) + `-title">
`)
			sb.WriteString(fmt.Sprintf(`        <h2 id="issue-%d-title">%s-%d — %s</h2>
`, issueCounter, htmlEscape(severity), issueCounter, htmlEscape(group.Title)))
			issueCounter++

			// Meta info
			sb.WriteString(`        <div class="issue-meta">
`)
			sb.WriteString(fmt.Sprintf(`            <span class="severity-badge severity-%s" aria-label="Severity: %s">%s</span>
`, htmlEscape(strings.ToLower(severity)), htmlEscape(severity), htmlEscape(severity)))
			if group.Findings[0].Confidence != "" {
				sb.WriteString(fmt.Sprintf(`            <span>Confidence: %s</span>
`, htmlEscape(group.Findings[0].Confidence)))
			}
			sb.WriteString(fmt.Sprintf(`            <span>Template: <code>%s</code></span>
`, htmlEscape(group.TemplateID)))
			sb.WriteString(`        </div>
`)

			// Locations
			sb.WriteString(fmt.Sprintf(`        <div class="locations" aria-label="Locations">
            <strong>Locations:</strong> (%d occurrence(s))
            <ul>
`, len(group.Findings)))
			for _, f := range group.Findings {
				sb.WriteString(fmt.Sprintf(`                <li>%s</li>
`, htmlEscape(formatLocation(projectRoot, f))))
			}
			sb.WriteString(`            </ul>
        </div>
`)

			// Description
			sb.WriteString(`        <div class="description">
            <h3>Description</h3>
`)
			if group.Message != "" {
				sb.WriteString(fmt.Sprintf(`            <p>%s</p>
`, htmlEscape(group.Message)))
			} else {
				sb.WriteString(`            <p><em>No description available.</em></p>
`)
			}
			sb.WriteString(`        </div>
`)

			// Collapsible code sections — each carries the rich reachability
			// trace just above the source excerpt.
			for _, f := range group.Findings {
				sb.WriteString(fmt.Sprintf(`        <details>
            <summary>%s</summary>
`, htmlEscape(formatLocation(projectRoot, f))))
				sb.WriteString("            " + renderFindingTraceHTML(projectRoot, f) + "\n")
				sb.WriteString(`            <pre><code class="language-solidity">`)

				// CRITICAL: the excerpt is raw scanned contract source — escape it.
				sb.WriteString(htmlEscape(extractCodeForFinding(f, 5, db)))

				sb.WriteString(`</code></pre>
        </details>
`)
			}

			// Recommendation — uses template's own text.
			sb.WriteString(`        <div class="recommendation">
            <h3>Recommendation</h3>
`)
			if group.Recommendation != "" {
				sb.WriteString(fmt.Sprintf(`            <p>%s</p>
`, htmlEscape(group.Recommendation)))
			} else {
				sb.WriteString(`            <p>Review the code at the specified locations and apply appropriate security measures.</p>
`)
			}
			sb.WriteString(`        </div>
`)

			// Suggested fix (optional).
			if group.Fix != "" {
				sb.WriteString(`        <div class="recommendation">
            <h3>Suggested Fix</h3>
`)
				sb.WriteString(fmt.Sprintf(`            <p>%s</p>
        </div>
`, htmlEscape(group.Fix)))
			}

			// References (optional). Only http(s) links become anchors; other
			// schemes are rendered as escaped text (no javascript: hrefs).
			if len(group.References) > 0 {
				sb.WriteString(`        <div class="recommendation">
            <h3>References</h3>
            <ul>
`)
				for _, ref := range group.References {
					if href := safeHref(ref); href != "" {
						sb.WriteString(fmt.Sprintf(`                <li><a href="%s" target="_blank" rel="noopener">%s</a></li>
`, href, htmlEscape(ref)))
					} else {
						sb.WriteString(fmt.Sprintf(`                <li>%s</li>
`, htmlEscape(ref)))
					}
				}
				sb.WriteString(`            </ul>
        </div>
`)
			}

			sb.WriteString(`    </article>
`)
		}
	}

	sb.WriteString(`    </section>
    </main>
</body>
</html>`)

	return sb.String()
}

// renderFindingTraceMarkdown builds the rich "reachability + entry-point"
// block for a single finding occurrence. Produces a Markdown fragment that
// shows the source file (as a comment-style note), the auditor-actionable
// entry point, and a dotted-level list rendering of the full call chain from
// entry function down to the host function holding the dangerous statement.
//
// Output format (example):
//
//	**File:** `test-data/.../arbitrary-transferfrom.sol`
//
//	**Entry point (fix-here):** `VulnerableSwappedArgsForward.depositFrom`
//
//	**Reachability path** (entry → … → host of dangerous statement):
//	- `.` `VulnerableSwappedArgsForward.depositFrom()`  *(external, L344)*
//	- `..` `VulnerableSwappedArgsForward._stage()`  *(internal, L348)*
//	- `...` **`VulnerableSwappedArgsForward._commit()`**  *(internal, L352)* ← dangerous statement
//
// When the finding has no Reachability (e.g. contract-scope rules), the
// function returns an empty string so the rest of the report is unaffected.
func renderFindingTraceMarkdown(projectRoot string, f *engine.Finding) string {
	if f == nil {
		return ""
	}
	var sb strings.Builder
	if f.Location.File != "" {
		// Project-relative, like formatLocation — avoid leaking the auditor's
		// absolute filesystem layout into a shareable report.
		sb.WriteString(fmt.Sprintf("**File:** `%s`\n\n", relPathForReport(projectRoot, f.Location.File)))
	}
	if f.EntryPoint != nil && f.EntryPoint.Function != "" {
		fqn := f.EntryPoint.Function
		if f.EntryPoint.Contract != "" {
			fqn = f.EntryPoint.Contract + "." + f.EntryPoint.Function
		}
		note := "fix-here"
		if f.EntryPoint.AuthVerdict != "" {
			note = fmt.Sprintf("fix-here, auth: %s", f.EntryPoint.AuthVerdict)
		}
		sb.WriteString(fmt.Sprintf("**Entry point (%s):** `%s`\n\n", note, fqn))
	}
	if f.Reachability != nil && len(f.Reachability.Steps) > 0 {
		sb.WriteString("**Reachability path** (entry → … → host of dangerous statement):\n\n")
		for i, s := range f.Reachability.Steps {
			dots := strings.Repeat(".", i+1)
			fqn := s.Function
			if s.Contract != "" && s.Function != "" {
				fqn = s.Contract + "." + s.Function
			}
			label := fmt.Sprintf("`%s()`", fqn)
			// Bold the last hop — that's the host of the dangerous statement.
			if i == len(f.Reachability.Steps)-1 {
				label = fmt.Sprintf("**`%s()`**", fqn)
			}
			meta := []string{}
			if s.Visibility != "" {
				meta = append(meta, s.Visibility)
			}
			if s.Line > 0 {
				meta = append(meta, fmt.Sprintf("L%d", s.Line))
			}
			tail := ""
			if i == len(f.Reachability.Steps)-1 {
				tail = " ← dangerous statement"
			} else if i == 0 {
				tail = " ← entry"
			}
			metaStr := ""
			if len(meta) > 0 {
				metaStr = fmt.Sprintf(" *(%s)*", strings.Join(meta, ", "))
			}
			sb.WriteString(fmt.Sprintf("- `%s` %s%s%s\n", dots, label, metaStr, tail))
		}
		sb.WriteString("\n")
	}
	if f.PrimaryAST != nil && (f.PrimaryAST.Kind != "" || f.PrimaryAST.Name != "") {
		sb.WriteString(fmt.Sprintf("**Matched node:** `%s`", f.PrimaryAST.Kind))
		if f.PrimaryAST.Name != "" {
			sb.WriteString(fmt.Sprintf(" (`%s`)", f.PrimaryAST.Name))
		}
		sb.WriteString("\n\n")
	}
	return sb.String()
}

// renderFindingTraceHTML is the HTML counterpart of renderFindingTraceMarkdown.
// It produces a small, semantic block — a definition list for the headers and
// a nested-margin <ol> for the call chain. CSS classes are namespaced so a
// theme can style them without conflicting with the host page.
func renderFindingTraceHTML(projectRoot string, f *engine.Finding) string {
	if f == nil {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="w3a-trace">`)
	if f.Location.File != "" {
		sb.WriteString(fmt.Sprintf(`<div class="w3a-trace-file"><span class="w3a-trace-label">File:</span> <code>%s</code></div>`, htmlEscape(relPathForReport(projectRoot, f.Location.File))))
	}
	if f.EntryPoint != nil && f.EntryPoint.Function != "" {
		fqn := f.EntryPoint.Function
		if f.EntryPoint.Contract != "" {
			fqn = f.EntryPoint.Contract + "." + f.EntryPoint.Function
		}
		note := "fix-here"
		if f.EntryPoint.AuthVerdict != "" {
			note = fmt.Sprintf("fix-here, auth: %s", f.EntryPoint.AuthVerdict)
		}
		sb.WriteString(fmt.Sprintf(`<div class="w3a-trace-entry"><span class="w3a-trace-label">Entry point (%s):</span> <code>%s</code></div>`,
			htmlEscape(note), htmlEscape(fqn)))
	}
	if f.Reachability != nil && len(f.Reachability.Steps) > 0 {
		sb.WriteString(`<div class="w3a-trace-path-label">Reachability path (entry → … → host of dangerous statement):</div>`)
		sb.WriteString(`<ol class="w3a-trace-path">`)
		last := len(f.Reachability.Steps) - 1
		for i, s := range f.Reachability.Steps {
			fqn := s.Function
			if s.Contract != "" && s.Function != "" {
				fqn = s.Contract + "." + s.Function
			}
			tail := ""
			if i == last {
				tail = ` <span class="w3a-trace-host">← dangerous statement</span>`
			} else if i == 0 {
				tail = ` <span class="w3a-trace-entry-arrow">← entry</span>`
			}
			meta := []string{}
			if s.Visibility != "" {
				meta = append(meta, htmlEscape(s.Visibility))
			}
			if s.Line > 0 {
				meta = append(meta, fmt.Sprintf("L%d", s.Line))
			}
			metaStr := ""
			if len(meta) > 0 {
				metaStr = fmt.Sprintf(` <span class="w3a-trace-meta">(%s)</span>`, strings.Join(meta, ", "))
			}
			// Inline margin-left scales with depth so the user gets the same
			// "dotted level" feel as the Markdown variant.
			indent := i * 16
			boldOpen, boldClose := "", ""
			if i == last {
				boldOpen, boldClose = "<strong>", "</strong>"
			}
			sb.WriteString(fmt.Sprintf(
				`<li class="w3a-trace-step" style="margin-left:%dpx"><span class="w3a-trace-dots">%s</span> %s<code>%s()</code>%s%s%s</li>`,
				indent, strings.Repeat(".", i+1), boldOpen, htmlEscape(fqn), boldClose, metaStr, tail,
			))
		}
		sb.WriteString(`</ol>`)
	}
	if f.PrimaryAST != nil && (f.PrimaryAST.Kind != "" || f.PrimaryAST.Name != "") {
		extra := ""
		if f.PrimaryAST.Name != "" {
			extra = fmt.Sprintf(" (<code>%s</code>)", htmlEscape(f.PrimaryAST.Name))
		}
		sb.WriteString(fmt.Sprintf(`<div class="w3a-trace-node"><span class="w3a-trace-label">Matched node:</span> <code>%s</code>%s</div>`,
			htmlEscape(f.PrimaryAST.Kind), extra))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

// htmlEscape escapes text for safe interpolation into HTML element content AND
// attribute values. Findings embed attacker-controlled material — the scanned
// contract's own source code appears in the code excerpt, and third-party
// template packs supply titles/messages — so every interpolation must be
// escaped to prevent stored XSS when the report is opened in a browser.
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// safeHref returns url if it is an http(s) link, escaped for an attribute
// context; otherwise "" (so non-web schemes like javascript: are dropped).
func safeHref(url string) string {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return htmlEscape(url)
	}
	return ""
}

// mdFence returns a backtick fence at least three long and longer than any
// backtick run inside content, so an excerpt containing ``` cannot break out of
// its code block and inject Markdown/HTML into the rendered report.
func mdFence(content string) string {
	longest := 0
	run := 0
	for _, r := range content {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := 3
	if longest >= n {
		n = longest + 1
	}
	return strings.Repeat("`", n)
}

// sortGroups orders grouped findings deterministically (by TemplateID then
// Title) so reports diff cleanly across runs regardless of finding order.
func sortGroups(groups []*GroupedFinding) {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].TemplateID != groups[j].TemplateID {
			return groups[i].TemplateID < groups[j].TemplateID
		}
		return groups[i].Title < groups[j].Title
	})
}
