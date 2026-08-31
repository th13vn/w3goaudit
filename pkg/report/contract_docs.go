package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

type contractInteractionRow struct {
	Entry    string
	Caller   string
	Type     types.CallType
	Target   string
	Line     int
	Col      int
	Resolved bool
}

// FormatContractReportMarkdown renders one self-contained deep dive for a main
// contract. Full finding prose remains in audit.md and is linked by stable
// anchors; architecture, state, interactions, and workflows live here.
func FormatContractReportMarkdown(contract *ContractSummary, findings []*engine.Finding, db *types.Database, gitInfo *GitInfo, projectRoot, rootPrefix, reportPath string) string {
	if contract == nil {
		return "# Contract Report\n\n_Contract summary unavailable._\n"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s\n\n", contract.Name)
	fmt.Fprintf(&sb, "**File:** %s  \n", contractSourceDisplay(contract, gitInfo, projectRoot))
	if contract.Version != "" {
		fmt.Fprintf(&sb, "**Version:** `%s`  \n", contract.Version)
	}
	fmt.Fprintf(&sb, "**Report:** `%s`  \n", reportPath)
	fmt.Fprintf(&sb, "**Entry Points:** %d  \n**State Variables:** %d\n\n", contract.EntryFunctionCount, contract.StateVariableCount)
	fmt.Fprintf(&sb, "[Project audit](%saudit.md) | [Analysis diagnostics](%sdata/diagnostics.json)\n\n", rootPrefix, rootPrefix)

	sb.WriteString("## Findings in This Contract\n\n")
	renderContractFindingIndex(&sb, contract, findings, rootPrefix)

	sb.WriteString("## Architecture and Inheritance\n\n")
	sb.WriteString(contract.renderRestOfContract())

	resolved := exactSummaryContract(db, contract)
	if resolved == nil {
		sb.WriteString("## State Changes\n\n_State details are not available from the analyzed database._\n\n")
		sb.WriteString("## External Interactions\n\n_Interaction details are not available from the analyzed database._\n\n")
		sb.WriteString("## Entry-Point Workflows\n\n_Workflow details are not available from the analyzed database._\n")
		return sb.String()
	}

	matrix := newStateMatrixBuilder(db, resolved)
	rows := BuildStateMatrix(db, resolved, contract.StateVariables)
	sb.WriteString("## State Changes\n\n")
	sb.WriteString(stripFirstMarkdownHeading(renderStateChanges(contract, rows)))

	sb.WriteString("## External Interactions\n\n")
	renderContractInteractions(&sb, contractInteractionRows(db, contract), projectRoot)

	sb.WriteString("## Entry-Point Workflows\n\n")
	if len(contract.EntryFunctions) == 0 {
		sb.WriteString("_No state-changing public or external entry points._\n")
		return sb.String()
	}
	entryFunctions := append([]*FunctionSummary(nil), contract.EntryFunctions...)
	sort.SliceStable(entryFunctions, func(i, j int) bool {
		if entryFunctions[i].Selector != entryFunctions[j].Selector {
			return entryFunctions[i].Selector < entryFunctions[j].Selector
		}
		if entryFunctions[i].Signature != entryFunctions[j].Signature {
			return entryFunctions[i].Signature < entryFunctions[j].Signature
		}
		return entryFunctions[i].Name < entryFunctions[j].Name
	})
	for _, fn := range entryFunctions {
		var effects *types.FunctionEffects
		var writes []string
		if exactFn, ok := matrix.resolveEntry(fn.Selector, fn.Name); ok {
			effects = matrix.effects(exactFn)
			for name := range matrix.transitiveWrites(exactFn) {
				writes = append(writes, name)
			}
			sort.Strings(writes)
		}
		label := fn.Selector
		if label == "" {
			label = fn.Name
		}
		fmt.Fprintf(&sb, "<details>\n<summary><code>%s</code></summary>\n\n", label)
		sb.WriteString(stripFirstMarkdownHeading(renderWorkflow(contract, fn, effects, writes)))
		sb.WriteString("\n</details>\n\n")
	}
	return sb.String()
}

func contractSourceDisplay(contract *ContractSummary, gitInfo *GitInfo, projectRoot string) string {
	rel := normalizedContractSource(projectRoot, contract.SourceFile)
	if gitInfo == nil || gitInfo.RemoteURL == "" {
		return "`" + rel + "`"
	}
	ref := gitInfo.Branch
	if ref == "" {
		ref = "HEAD"
	}
	return fmt.Sprintf("[%s](%s/blob/%s/%s)", rel, gitInfo.RemoteURL, ref, rel)
}

func renderContractFindingIndex(sb *strings.Builder, contract *ContractSummary, findings []*engine.Finding, rootPrefix string) {
	contractFindings := findingsForContract(findings, contract)
	if len(contractFindings) == 0 {
		sb.WriteString("_No findings have a primary exact location in this contract._\n\n")
		return
	}
	engine.SortFindings(contractFindings)
	anchors := buildFindingAnchorIndex(findings)
	sb.WriteString("| Severity | Rule | Finding | Function | Line | Full evidence |\n")
	sb.WriteString("|----------|------|---------|----------|------|---------------|\n")
	for _, finding := range contractFindings {
		title := finding.Title
		if title == "" {
			title = finding.TemplateID
		}
		fmt.Fprintf(sb, "| %s | `%s` | %s | `%s` | %d | [audit](%saudit.md#%s) |\n",
			sevTitle(normalizeSeverity(finding.Severity)), finding.TemplateID, mdCell(title), finding.Location.Function, finding.Location.Line, rootPrefix, anchors[findingGroupKey(finding)])
	}
	sb.WriteString("\n")
}

func exactSummaryContract(db *types.Database, contract *ContractSummary) *types.Contract {
	if db == nil || contract == nil {
		return nil
	}
	return db.GetContract(types.MakeContractID(contract.SourceFile, contract.Name))
}

func contractInteractionRows(db *types.Database, contract *ContractSummary) []contractInteractionRow {
	if db == nil || db.CallGraph == nil || contract == nil {
		return nil
	}
	entryIDs := contractEntryIDs(db, contract)
	byCaller := make(map[string][]*types.CallEdge)
	for _, edge := range db.CallGraph.Edges {
		if edge != nil {
			byCaller[edge.From] = append(byCaller[edge.From], edge)
		}
	}
	var rows []contractInteractionRow
	for _, entry := range entryIDs {
		queue := []string{entry}
		seen := make(map[string]bool)
		for len(queue) > 0 {
			caller := queue[0]
			queue = queue[1:]
			if seen[caller] {
				continue
			}
			seen[caller] = true
			for _, edge := range byCaller[caller] {
				if isReportExternalCall(edge.Type) {
					target := edge.To
					if target == "" {
						target = edge.CalledName
					}
					rows = append(rows, contractInteractionRow{Entry: entry, Caller: caller, Type: edge.Type, Target: target, Line: edge.Line, Col: edge.Col, Resolved: edge.Resolved})
				}
				if isReportTraversableCall(edge.Type) && edge.To != "" {
					queue = append(queue, edge.To)
				}
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Entry != b.Entry {
			return a.Entry < b.Entry
		}
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Target < b.Target
	})
	return rows
}

func contractEntryIDs(db *types.Database, contract *ContractSummary) []string {
	contractID := types.MakeContractID(contract.SourceFile, contract.Name)
	if entry := db.MainContracts[contractID]; entry != nil && len(entry.EntryFunctions) > 0 {
		ids := append([]string(nil), entry.EntryFunctions...)
		sort.Strings(ids)
		return ids
	}
	ids := make([]string, 0, len(contract.EntryFunctions))
	for _, fn := range contract.EntryFunctions {
		selector := fn.Selector
		if selector == "" {
			selector = fn.Name
		}
		ids = append(ids, types.MakeFunctionID(contract.SourceFile, contract.Name, selector))
	}
	sort.Strings(ids)
	return ids
}

func isReportTraversableCall(callType types.CallType) bool {
	switch callType {
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeLibrary, types.CallTypeSuper, types.CallTypeModifier:
		return true
	default:
		return false
	}
}

func renderContractInteractions(sb *strings.Builder, rows []contractInteractionRow, projectRoot string) {
	if len(rows) == 0 {
		sb.WriteString("_No external interaction edges are reachable from the recorded entry points._\n\n")
		return
	}
	sb.WriteString("| Entry | Caller | Type | Target | Resolution | Location |\n")
	sb.WriteString("|-------|--------|------|--------|------------|----------|\n")
	for _, row := range rows {
		resolution := "resolved"
		if !row.Resolved {
			resolution = "unresolved"
		}
		file, _, _ := types.ParseFunctionID(row.Caller)
		location := normalizedContractSource(projectRoot, file)
		if row.Line > 0 {
			location += fmt.Sprintf(":%d", row.Line)
			if row.Col > 0 {
				location += fmt.Sprintf(":%d", row.Col)
			}
		}
		fmt.Fprintf(sb, "| `%s` | `%s` | `%s` | `%s` | %s | `%s` |\n", row.Entry, row.Caller, row.Type, row.Target, resolution, location)
	}
	sb.WriteString("\n")
}

func stripFirstMarkdownHeading(document string) string {
	if end := strings.Index(document, "\n\n"); end >= 0 && strings.HasPrefix(document, "#") {
		return document[end+2:]
	}
	return document
}
