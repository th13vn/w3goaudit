package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// FormatAuditMarkdown renders the consolidated project-level audit report. It
// intentionally links to, rather than duplicates, per-contract workflows.
func FormatAuditMarkdown(tool ToolMeta, summary *SummaryReport, findings []*engine.Finding, db *types.Database) string {
	var sb strings.Builder
	if summary == nil {
		return "# Security Audit\n\n_Report summary unavailable._\n"
	}

	sb.WriteString("# Security Audit\n\n")
	fmt.Fprintf(&sb, "**Tool:** `%s %s`  \n", tool.Name, tool.Version)
	writeDocHeader(&sb, summary)

	sb.WriteString("## Executive Summary\n\n")
	fmt.Fprintf(&sb, "W3GoAudit reported **%d issue group(s)** across **%d occurrence(s)**.\n\n", countUniqueIssues(findings), len(findings))
	renderSeverityCounts(&sb, findings)

	sb.WriteString("## Analysis Scope and Limitations\n\n")
	if summary.ProjectRoot != "" {
		fmt.Fprintf(&sb, "- **Project root:** `%s`\n", summary.ProjectRoot)
	}
	if summary.ScanTarget != "" {
		fmt.Fprintf(&sb, "- **Scan target:** `%s`\n", summary.ScanTarget)
	}
	sb.WriteString("\n")
	renderAnalysisStatus(&sb, summary)
	sb.WriteString("A result with no findings does not certify that the project is safe. Diagnostics and scanner limitations remain part of the audit evidence.\n\n")

	renderProjectMetrics(&sb, summary)

	sb.WriteString("## Security Findings\n\n")
	anchors := buildFindingAnchorIndex(findings)
	sb.WriteString(renderFindingsMarkdownGroups(findings, db, 3, anchors))

	sb.WriteString("## Rules Hit\n\n")
	renderRulesHit(&sb, findings)

	renderContractSurfaceIndex(&sb, summary, findings, db)
	renderStateInteractionSummary(&sb, summary, db)
	renderMachineArtifacts(&sb)
	return sb.String()
}

func renderContractSurfaceIndex(sb *strings.Builder, summary *SummaryReport, findings []*engine.Finding, db *types.Database) {
	sb.WriteString("## Contract Surface Index\n\n")
	idx, err := buildContractReportIndex(summary, findings)
	if err != nil || len(idx.refs) == 0 {
		sb.WriteString("_No main-contract report index is available._\n\n")
		return
	}
	sb.WriteString("| Source | Contract | Version | Entries | Payable | Without detected access-control evidence | State vars | External interaction edges | Findings | Deep dive |\n")
	sb.WriteString("|--------|----------|---------|---------|---------|------------------------------------------|------------|----------------------------|----------|-----------|\n")
	for _, ref := range idx.refs {
		mc := findContractSummary(summary, ref.Source, ref.Name)
		version, entries, states := "—", 0, 0
		payable, unprotected := 0, 0
		if mc != nil {
			if mc.Version != "" {
				version = mc.Version
			}
			entries, states = mc.EntryFunctionCount, mc.StateVariableCount
			for _, fn := range mc.EntryFunctions {
				if fn.IsPayable {
					payable++
				}
				if !fn.IsAccessControlled && len(fn.Modifiers) == 0 {
					unprotected++
				}
			}
		}
		external := contractExternalEdgeCount(db, mc)
		fmt.Fprintf(sb, "| `%s` | `%s` | `%s` | %d | %d | %d | %d | %d | %d | [report](%s) |\n",
			ref.Source, ref.Name, version, entries, payable, unprotected, states, external, ref.Findings, ref.Report)
	}
	sb.WriteString("\n")
}

func renderStateInteractionSummary(sb *strings.Builder, summary *SummaryReport, db *types.Database) {
	sb.WriteString("## State and Interaction Summary\n\n")
	idx, err := buildContractReportIndex(summary, nil)
	if err != nil || len(idx.refs) == 0 {
		sb.WriteString("_No main contracts._\n\n")
		return
	}
	sb.WriteString("| Contract | State variables | State writes recorded | External interaction edges | Detail |\n")
	sb.WriteString("|----------|-----------------|-----------------------|----------------------------|--------|\n")
	for _, ref := range idx.refs {
		mc := findContractSummary(summary, ref.Source, ref.Name)
		stateVars, writes := 0, 0
		if mc != nil {
			stateVars = mc.StateVariableCount
		}
		if db != nil && mc != nil {
			if c := db.GetContract(types.MakeContractID(mc.SourceFile, mc.Name)); c != nil {
				for _, exact := range db.LinearizedContracts(c) {
					for _, fn := range exact.Functions {
						selector := fn.Selector
						if selector == "" {
							selector = fn.Name
						}
						if fe := db.Semantics.GetFunctionEffects(types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)); fe != nil {
							writes += len(fe.StateWrites)
						}
					}
				}
			}
		}
		fmt.Fprintf(sb, "| `%s` | %d | %d | %d | [state and interactions](%s#state-changes) |\n", ref.Name, stateVars, writes, contractExternalEdgeCount(db, mc), ref.Report)
	}
	sb.WriteString("\n")
}

func renderMachineArtifacts(sb *strings.Builder) {
	sb.WriteString("## Machine and CI Artifacts\n\n")
	for _, item := range []struct{ path, label string }{
		{"results.sarif", "SARIF 2.1.0"}, {"data/manifest.json", "manifest"},
		{"data/findings.json", "findings JSON"}, {"data/overview.json", "overview JSON"},
		{"data/diagnostics.json", "diagnostics"}, {"data/database.json", "database"},
		{"data/nav.json", "navigation"}, {"data/explorer.json", "explorer"}, {"data/xref.json", "cross references"},
	} {
		fmt.Fprintf(sb, "- [%s](%s)\n", item.label, item.path)
	}
	sb.WriteString("\n")
}

func findContractSummary(summary *SummaryReport, relSource, name string) *ContractSummary {
	if summary == nil {
		return nil
	}
	for _, mc := range summary.MainContracts {
		if mc != nil && mc.Name == name && normalizedContractSource(summary.ProjectRoot, mc.SourceFile) == relSource {
			return mc
		}
	}
	return nil
}

func contractExternalEdgeCount(db *types.Database, mc *ContractSummary) int {
	if db == nil || db.CallGraph == nil || mc == nil {
		return 0
	}
	prefix := types.MakeContractID(mc.SourceFile, mc.Name) + "."
	n := 0
	for _, edge := range db.CallGraph.Edges {
		if edge != nil && strings.HasPrefix(edge.From, prefix) && isReportExternalCall(edge.Type) {
			n++
		}
	}
	return n
}

func isReportExternalCall(callType types.CallType) bool {
	switch callType {
	case types.CallTypeExternal, types.CallTypeSelf, types.CallTypeTransferETH, types.CallTypeLowLevel, types.CallTypeLowLevelCall, types.CallTypeLowLevelDelegate, types.CallTypeLowLevelStatic:
		return true
	default:
		return false
	}
}

func sortedFindingGroups(findings []*engine.Finding) []*GroupedFinding {
	grouped := groupFindings(findings)
	var out []*GroupedFinding
	for _, severity := range renderSeverityOrder(grouped) {
		groups := grouped[severity]
		sortGroups(groups)
		out = append(out, groups...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := SeverityRank(out[i].Severity), SeverityRank(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if out[i].TemplateID != out[j].TemplateID {
			return out[i].TemplateID < out[j].TemplateID
		}
		return out[i].Title < out[j].Title
	})
	return out
}
