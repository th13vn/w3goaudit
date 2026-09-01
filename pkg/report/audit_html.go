package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// FormatAuditHTML renders one self-contained project audit. Contract workflows
// remain in their Markdown deep dives so this page stays navigable.
func FormatAuditHTML(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding, db *types.Database) string {
	if summary == nil {
		summary = &SummaryReport{}
	}
	var sb strings.Builder
	sb.WriteString(auditHTMLHead)
	fmt.Fprintf(&sb, `<h1 id="page-title">Security Audit</h1>
<div class="meta"><strong>Tool:</strong> <code>%s %s</code><br><strong>Generated:</strong> %s`,
		htmlEscape(tool.Name), htmlEscape(tool.Version), htmlEscape(summary.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))
	if summary.ProjectRoot != "" {
		fmt.Fprintf(&sb, `<br><strong>Project root:</strong> <code>%s</code>`, htmlEscape(summary.ProjectRoot))
	}
	if summary.ScanTarget != "" {
		fmt.Fprintf(&sb, `<br><strong>Scan target:</strong> <code>%s</code>`, htmlEscape(summary.ScanTarget))
	}
	sb.WriteString(`</div>`)

	sb.WriteString(`<section aria-labelledby="executive-summary"><h2 id="executive-summary">Executive Summary</h2>`)
	fmt.Fprintf(&sb, `<p>W3GoAudit reported <strong>%d issue group(s)</strong> across <strong>%d occurrence(s)</strong>.</p>`, countUniqueIssues(findings), len(findings))
	renderAuditSeverityHTML(&sb, findings)
	sb.WriteString(`</section>`)

	sb.WriteString(`<section aria-labelledby="scope-limitations"><h2 id="scope-limitations">Analysis Scope and Limitations</h2>`)
	counts := summary.DiagnosticCounts
	if summaryAnalysisComplete(summary) {
		fmt.Fprintf(&sb, `<div class="notice notice-complete"><strong>Analysis complete.</strong> %d warning(s), %d error(s), %d informational diagnostic(s), %d unknown-severity diagnostic(s).</div>`, counts.Warning, counts.Error, counts.Info, counts.Unknown)
	} else {
		fmt.Fprintf(&sb, `<div class="notice notice-incomplete"><strong>Analysis incomplete.</strong> %d warning(s), %d error(s), %d informational diagnostic(s), %d unknown-severity diagnostic(s) may affect coverage.</div>`, counts.Warning, counts.Error, counts.Info, counts.Unknown)
	}
	sb.WriteString(`<p>See <a href="data/diagnostics.json">data/diagnostics.json</a> for durable diagnostic records. A result with no findings does not certify that the project is safe.</p></section>`)

	renderAuditMetricsHTML(&sb, summary)
	renderAuditFindingsHTML(&sb, findings, db, summary.ProjectRoot)
	renderAuditRulesHTML(&sb, findings)
	renderAuditContractsHTML(&sb, summary, findings, db)
	renderAuditStateHTML(&sb, summary, db)
	renderAuditArtifactsHTML(&sb)
	sb.WriteString(`</main></body></html>`)
	return sb.String()
}

var auditHTMLHead = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit - W3GoAudit</title>
<!-- vis-network is embedded so this report remains fully offline. -->
<script type="text/javascript">` + visNetworkJS + `</script>
<style>
:root { color-scheme: dark light; --bg:#0d1117; --panel:#161b22; --raised:#21262d; --text:#e6edf3; --muted:#8b949e; --border:#30363d; --focus:#58a6ff; --critical:#f85149; --high:#f0883e; --medium:#d29922; --low:#3fb950; --info:#58a6ff; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; line-height:1.6; }
main { width:min(1200px,calc(100% - 2rem)); margin:auto; padding:2rem 0 4rem; }
h1 { border-bottom:2px solid var(--border); padding-bottom:1rem; } h2 { margin-top:2.5rem; border-bottom:1px solid var(--border); padding-bottom:.5rem; }
a { color:var(--info); } a:focus,summary:focus { outline:2px solid var(--focus); outline-offset:2px; }
.skip-link { position:absolute; left:-10000px; background:var(--raised); color:var(--text); padding:.5rem 1rem; z-index:10; } .skip-link:focus { left:1rem; top:1rem; }
.meta,.notice,.card,.issue { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:1rem 1.25rem; margin:1rem 0; }
.notice-incomplete { border-left:4px solid var(--high); } .notice-complete { border-left:4px solid var(--low); }
.metric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:.75rem; } .metric { background:var(--raised); border-radius:6px; padding:1rem; } .metric strong { display:block; font-size:1.5rem; }
.table-wrap { overflow-x:auto; } table { width:100%; border-collapse:collapse; } th,td { border-bottom:1px solid var(--border); text-align:left; padding:.65rem; vertical-align:top; }
code,pre { font-family:"SFMono-Regular",Consolas,monospace; } code { background:var(--raised); padding:.1rem .3rem; border-radius:3px; } pre { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:1rem; overflow-x:auto; white-space:pre; }
.severity { display:inline-block; border-radius:999px; padding:.15rem .6rem; font-weight:700; margin-right:.5rem; } .severity-critical { background:var(--critical); } .severity-high { background:var(--high); } .severity-medium { background:var(--medium); color:#111; } .severity-low { background:var(--low); color:#111; } .severity-info,.severity-unknown { background:var(--info); color:#111; }
details { background:var(--raised); border:1px solid var(--border); border-radius:6px; padding:.75rem; margin:.75rem 0; } summary { cursor:pointer; font-weight:650; }
.w3a-trace { border-left:3px solid var(--medium); padding:.5rem .75rem; margin:.75rem 0; } .w3a-trace-label,.w3a-trace-meta { color:var(--muted); } .w3a-trace-path { list-style:none; padding-left:0; } .w3a-trace-step { padding:.1rem 0; } .w3a-trace-dots { color:var(--muted); font-family:monospace; margin-right:.5rem; } .w3a-trace-host { color:var(--high); font-weight:700; } .w3a-trace-entry-arrow { color:var(--medium); }
@media print { body { background:white; color:black; } main { width:100%; padding:0; } .skip-link { display:none; } .card,.issue,.notice,.meta { break-inside:avoid; } a { color:black; } }
</style>
</head>
<body>
<a class="skip-link" href="#security-findings">Skip to findings</a>
<main role="main" aria-labelledby="page-title">`

func renderAuditSeverityHTML(sb *strings.Builder, findings []*engine.Finding) {
	counts := countBySeverity(findings)
	sb.WriteString(`<div class="metric-grid" aria-label="Findings by severity">`)
	for _, severity := range append(append([]string(nil), SeverityOrder...), "UNKNOWN") {
		if severity == "UNKNOWN" && counts[severity] == 0 {
			continue
		}
		fmt.Fprintf(sb, `<div class="metric"><span>%s</span><strong>%d</strong></div>`, htmlEscape(sevTitle(severity)), counts[severity])
	}
	sb.WriteString(`</div>`)
}

func renderAuditMetricsHTML(sb *strings.Builder, summary *SummaryReport) {
	stats := summary.Stats
	if stats == nil {
		stats = &types.DatabaseStats{}
	}
	sb.WriteString(`<section aria-labelledby="project-metrics"><h2 id="project-metrics">Project Metrics</h2><div class="metric-grid">`)
	metrics := []struct {
		label string
		value int
	}{
		{"Source Files", stats.TotalFiles}, {"nSLOC", stats.NSLOC}, {"Contracts", stats.TotalContracts},
		{"Interfaces", stats.TotalInterfaces}, {"Libraries", stats.TotalLibraries}, {"Functions", stats.TotalFunctions},
		{"Entry Functions", stats.TotalEntryFunctions}, {"Main Contracts", len(summary.MainContracts)},
	}
	for _, metric := range metrics {
		fmt.Fprintf(sb, `<div class="metric"><span>%s</span><strong>%d</strong></div>`, metric.label, metric.value)
	}
	sb.WriteString(`</div></section>`)
}

func renderAuditRulesHTML(sb *strings.Builder, findings []*engine.Finding) {
	sb.WriteString(`<section aria-labelledby="rules-hit"><h2 id="rules-hit">Rules Hit</h2>`)
	groups := sortedFindingGroups(findings)
	if len(groups) == 0 {
		sb.WriteString(`<p>No findings.</p></section>`)
		return
	}
	sb.WriteString(`<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Occurrences</th></tr></thead><tbody>`)
	for _, group := range groups {
		fmt.Fprintf(sb, `<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%d</td></tr>`, htmlEscape(group.Severity), htmlEscape(group.TemplateID), htmlEscape(group.Title), len(group.Findings))
	}
	sb.WriteString(`</tbody></table></div></section>`)
}

func renderAuditContractsHTML(sb *strings.Builder, summary *SummaryReport, findings []*engine.Finding, db *types.Database) {
	sb.WriteString(`<section aria-labelledby="contract-surface"><h2 id="contract-surface">Contract Surface</h2>`)
	idx, err := buildContractReportIndex(summary, findings)
	if err != nil || len(idx.refs) == 0 {
		sb.WriteString(`<p>No main-contract report index is available.</p></section>`)
		return
	}
	sb.WriteString(`<div class="table-wrap"><table><thead><tr><th>Source</th><th>Contract</th><th>Entries</th><th>State vars</th><th>External edges</th><th>Findings</th><th>Deep dive</th></tr></thead><tbody>`)
	for _, ref := range idx.refs {
		mc := findContractSummaryByReport(summary, idx, ref.Report)
		entries, states := 0, 0
		if mc != nil {
			entries, states = mc.EntryFunctionCount, mc.StateVariableCount
		}
		fmt.Fprintf(sb, `<tr><td><code>%s</code></td><td><code>%s</code></td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td><a href="%s">contract report</a></td></tr>`,
			htmlEscape(ref.Source), htmlEscape(ref.Name), entries, states, contractExternalEdgeCount(db, mc), ref.Findings, htmlEscape(ref.Report))
	}
	sb.WriteString(`</tbody></table></div></section>`)
}

func renderAuditStateHTML(sb *strings.Builder, summary *SummaryReport, db *types.Database) {
	sb.WriteString(`<section aria-labelledby="state-interactions"><h2 id="state-interactions">State and Interaction Summary</h2>`)
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil || len(idx.refs) == 0 {
		sb.WriteString(`<p>No main contracts.</p></section>`)
		return
	}
	sb.WriteString(`<div class="table-wrap"><table><thead><tr><th>Contract</th><th>State variables</th><th>State writes recorded</th><th>External edges</th><th>Detail</th></tr></thead><tbody>`)
	for _, ref := range idx.refs {
		mc := findContractSummaryByReport(summary, idx, ref.Report)
		states, writes := 0, 0
		if mc != nil {
			states = mc.StateVariableCount
		}
		if db != nil && mc != nil {
			if contract := db.GetContract(types.MakeContractID(mc.SourceFile, mc.Name)); contract != nil {
				for _, exact := range db.LinearizedContracts(contract) {
					for _, fn := range exact.Functions {
						selector := fn.Selector
						if selector == "" {
							selector = fn.Name
						}
						if effects := db.Semantics.GetFunctionEffects(types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)); effects != nil {
							writes += len(effects.StateWrites)
						}
					}
				}
			}
		}
		fmt.Fprintf(sb, `<tr><td><code>%s</code></td><td>%d</td><td>%d</td><td>%d</td><td><a href="%s#state-changes">state and interactions</a></td></tr>`,
			htmlEscape(ref.Name), states, writes, contractExternalEdgeCount(db, mc), htmlEscape(ref.Report))
	}
	sb.WriteString(`</tbody></table></div></section>`)
}

func renderAuditFindingsHTML(sb *strings.Builder, findings []*engine.Finding, db *types.Database, projectRoot string) {
	sb.WriteString(`<section id="security-findings" aria-labelledby="security-findings-heading"><h2 id="security-findings-heading">Security Findings</h2>`)
	groups := sortedFindingGroups(findings)
	if len(groups) == 0 {
		sb.WriteString(`<div class="notice notice-complete" role="status">No security issues found. This does not certify that the project is safe.</div></section>`)
		return
	}
	anchors := buildFindingAnchorIndex(findings)
	for _, group := range groups {
		anchor := anchors[group.Key]
		fmt.Fprintf(sb, `<article class="issue" id="%s" aria-labelledby="%s-title"><h3 id="%s-title">%s</h3>`, htmlEscape(anchor), htmlEscape(anchor), htmlEscape(anchor), htmlEscape(group.Title))
		fmt.Fprintf(sb, `<p><span class="severity severity-%s" aria-label="Severity: %s">%s</span> Rule <code>%s</code> - %d occurrence(s)</p>`,
			strings.ToLower(group.Severity), htmlEscape(group.Severity), htmlEscape(group.Severity), htmlEscape(group.TemplateID), len(group.Findings))
		if confidence := group.Findings[0].Confidence; confidence != "" {
			fmt.Fprintf(sb, `<p><strong>Confidence:</strong> <code>%s</code></p>`, htmlEscape(confidence))
		}
		if group.Message != "" {
			fmt.Fprintf(sb, `<h4>Description</h4><p>%s</p>`, htmlEscape(group.Message))
		}
		occurrences := append([]*engine.Finding(nil), group.Findings...)
		engine.SortFindings(occurrences)
		for _, finding := range occurrences {
			fmt.Fprintf(sb, `<details><summary>%s</summary>`, htmlEscape(formatLocation(projectRoot, finding)))
			sb.WriteString(renderFindingTraceHTML(projectRoot, finding))
			sb.WriteString(`<pre><code class="language-solidity">` + htmlEscape(extractCodeForFinding(finding, 5, db)) + `</code></pre>`)
			renderAuditRelatedHTML(sb, finding, db, projectRoot)
			sb.WriteString(`</details>`)
		}
		if group.Recommendation != "" {
			fmt.Fprintf(sb, `<h4>Recommendation</h4><p>%s</p>`, htmlEscape(group.Recommendation))
		}
		if group.Fix != "" {
			fmt.Fprintf(sb, `<h4>Suggested Fix</h4><p>%s</p>`, htmlEscape(group.Fix))
		}
		if len(group.References) > 0 {
			sb.WriteString(`<h4>References</h4><ul>`)
			for _, ref := range group.References {
				if href := safeHref(ref); href != "" {
					fmt.Fprintf(sb, `<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, href, htmlEscape(ref))
				} else {
					fmt.Fprintf(sb, `<li>%s</li>`, htmlEscape(ref))
				}
			}
			sb.WriteString(`</ul>`)
		}
		sb.WriteString(`</article>`)
	}
	sb.WriteString(`</section>`)
}

func renderAuditRelatedHTML(sb *strings.Builder, finding *engine.Finding, db *types.Database, projectRoot string) {
	if finding == nil || len(finding.Related) == 0 {
		return
	}
	related := append([]engine.RelatedLocation(nil), finding.Related...)
	sort.SliceStable(related, func(i, j int) bool {
		if related[i].File != related[j].File {
			return related[i].File < related[j].File
		}
		if related[i].Line != related[j].Line {
			return related[i].Line < related[j].Line
		}
		return related[i].Label < related[j].Label
	})
	sb.WriteString(`<h4>Related matched sites</h4>`)
	for _, loc := range related {
		label := loc.Label
		if label == "" {
			label = "matched site"
		}
		excerpt := extractFullFunctionForLocation(engine.Location{File: loc.File, Contract: loc.Contract, Function: loc.Function, Line: loc.Line}, db)
		fmt.Fprintf(sb, `<div class="card"><strong>%s:</strong> <code>%s</code><pre><code class="language-solidity">%s</code></pre></div>`,
			htmlEscape(label), htmlEscape(formatRelatedLocation(projectRoot, loc)), htmlEscape(excerpt))
	}
}

func renderAuditArtifactsHTML(sb *strings.Builder) {
	sb.WriteString(`<section aria-labelledby="machine-artifacts"><h2 id="machine-artifacts">Machine and CI Artifacts</h2><ul>`)
	for _, item := range []struct{ path, label string }{
		{"results.sarif", "SARIF 2.1.0"}, {"data/manifest.json", "manifest"},
		{"data/findings.json", "findings JSON"}, {"data/overview.json", "overview JSON"},
		{"data/diagnostics.json", "diagnostics"}, {"data/database.json", "database"},
		{"data/nav.json", "navigation"}, {"data/explorer.json", "explorer"}, {"data/xref.json", "cross references"},
	} {
		fmt.Fprintf(sb, `<li><a href="%s">%s</a></li>`, item.path, htmlEscape(item.label))
	}
	sb.WriteString(`</ul></section>`)
}
