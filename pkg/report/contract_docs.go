package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/engine"
	"github.com/th13vn/w3goaudit/pkg/types"
)

const maxContractInteractionRows = 50

type contractInteractionRow struct {
	Entry    string
	Caller   string
	Type     types.CallType
	Target   string
	Line     int
	Col      int
	Resolved bool
}

type contractBoundaryIndex struct {
	db        *types.Database
	facts     []*types.ExternalBoundaryFact
	available bool
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
	if facts, available := newContractBoundaryIndex(db).factsFor(contract); available {
		renderContractBoundaryFacts(&sb, facts, projectRoot, rootPrefix)
	} else {
		renderLegacyContractInteractions(&sb, contractInteractionRows(db, contract), projectRoot, rootPrefix)
	}

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

func newContractBoundaryIndex(db *types.Database) contractBoundaryIndex {
	index := contractBoundaryIndex{db: db}
	if db == nil {
		return index
	}
	facts, err := db.ExternalBoundarySnapshot()
	if err != nil {
		return index
	}
	index.facts = facts
	index.available = true
	return index
}

func (index contractBoundaryIndex) factsFor(contract *ContractSummary) ([]*types.ExternalBoundaryFact, bool) {
	if !index.available || index.db == nil || contract == nil {
		return nil, index.available
	}
	contractID := types.MakeContractID(contract.SourceFile, contract.Name)
	entrySet := make(map[string]bool)
	for _, entryID := range contractEntryIDs(index.db, contract) {
		entrySet[entryID] = true
	}
	selected := make([]*types.ExternalBoundaryFact, 0, len(index.facts))
	for _, fact := range index.facts {
		if fact.ContractID == contractID || boundaryReachableFromAny(fact, entrySet) {
			selected = append(selected, fact)
		}
	}
	return selected, true
}

func (index contractBoundaryIndex) count(contract *ContractSummary) int {
	if facts, available := index.factsFor(contract); available {
		return len(facts)
	}
	return contractExternalEdgeCount(index.db, contract)
}

func (index contractBoundaryIndex) columnHeading() string {
	if index.available {
		return "External boundaries"
	}
	return "External interaction edges (legacy)"
}

func boundaryReachableFromAny(fact *types.ExternalBoundaryFact, entries map[string]bool) bool {
	if fact == nil || len(entries) == 0 {
		return false
	}
	for _, entryID := range fact.ReachableFrom {
		if entries[entryID] {
			return true
		}
	}
	return false
}

func renderContractBoundaryFacts(sb *strings.Builder, facts []*types.ExternalBoundaryFact, projectRoot, rootPrefix string) {
	if len(facts) == 0 {
		fmt.Fprintf(sb, "_No semantic external boundaries are owned by or reachable from this contract's recorded entries. Full evidence: [data/interactions.json](%sdata/interactions.json)._\n\n", rootPrefix)
		return
	}
	visible := facts
	if len(visible) > maxContractInteractionRows {
		visible = visible[:maxContractInteractionRows]
	}
	sb.WriteString("| Fact | Reachable entries | Caller | Kind | Target | Value control | Result | State effects | Reentry | Location |\n")
	sb.WriteString("|------|-------------------|--------|------|--------|---------------|--------|---------------|---------|----------|\n")
	for _, fact := range visible {
		if fact == nil {
			continue
		}
		fmt.Fprintf(sb, "| `%s` | %s | `%s` | `%s` | %s | %s | %s | %s | `%s` | `%s` |\n",
			mdCell(fact.ID), boundaryEntrySummary(fact.ReachableFrom), mdCell(fact.FunctionID), mdCell(fact.Kind), boundaryTargetSummary(fact.Target),
			boundaryControlSummary(fact), boundaryResultSummary(fact.Result), boundaryStateSummary(fact.StateEffects), fact.ReentryClass,
			mdCell(boundaryLocation(projectRoot, fact.Range)))
	}
	sb.WriteString("\n")
	if omitted := len(facts) - len(visible); omitted > 0 {
		fmt.Fprintf(sb, "_%d additional interaction(s) omitted by the %d-row contract limit._\n\n", omitted, maxContractInteractionRows)
	}
	fmt.Fprintf(sb, "Full values, target evidence, checks, state relations, and limitations: [data/interactions.json](%sdata/interactions.json).\n\n", rootPrefix)
}

func boundaryEntrySummary(entryIDs []string) string {
	if len(entryIDs) == 0 {
		return "none recorded"
	}
	selectors := make([]string, 0, len(entryIDs))
	for _, entryID := range entryIDs {
		_, _, selector := types.ParseFunctionID(entryID)
		if selector == "" {
			selector = entryID
		}
		selectors = append(selectors, "`"+mdCell(selector)+"`")
	}
	return strings.Join(selectors, "<br>")
}

func boundaryTargetSummary(target types.BoundaryTarget) string {
	identity := target.FunctionID
	if identity == "" {
		identity = target.ContractID
	}
	if identity == "" {
		identity = target.CalledName
	}
	if identity == "" {
		identity = "unknown"
	}
	resolution := target.Resolution
	if resolution == "" {
		resolution = types.BoundaryTargetUnresolved
	}
	return "`" + mdCell(identity) + "` (" + mdCell(resolution) + ")"
}

func boundaryControlSummary(fact *types.ExternalBoundaryFact) string {
	parts := make([]string, 0, 3)
	if fact.Receiver != nil {
		parts = append(parts, "receiver="+string(fact.Receiver.Control))
	}
	if fact.Value != nil {
		parts = append(parts, "value="+string(fact.Value.Control))
	}
	if len(fact.Arguments) > 0 {
		counts := make(map[types.BoundaryValueControl]int)
		for _, argument := range fact.Arguments {
			counts[argument.Control]++
		}
		ordered := []types.BoundaryValueControl{types.BoundaryValueCallerControlled, types.BoundaryValueStateDerived, types.BoundaryValueFixed, types.BoundaryValueUnknown}
		var arguments []string
		for _, control := range ordered {
			if counts[control] > 0 {
				arguments = append(arguments, strconv.Itoa(counts[control])+" "+string(control))
			}
		}
		parts = append(parts, "arguments="+strings.Join(arguments, ", "))
	}
	if len(parts) == 0 {
		return "none recorded"
	}
	return strings.Join(parts, "<br>")
}

func boundaryResultSummary(result types.BoundaryResult) string {
	return result.Disposition + " / checked=" + result.DirectCheck
}

func boundaryStateSummary(effects []types.BoundaryStateEffect) string {
	before, after := 0, 0
	for _, effect := range effects {
		switch effect.Relation {
		case types.BoundaryStateBefore:
			before++
		case types.BoundaryStateAfter:
			after++
		}
	}
	return fmt.Sprintf("before=%d, after=%d", before, after)
}

func boundaryLocation(projectRoot string, sourceRange types.SemanticSourceRange) string {
	location := normalizedContractSource(projectRoot, sourceRange.File)
	if sourceRange.StartLine > 0 {
		location += fmt.Sprintf(":%d", sourceRange.StartLine)
		if sourceRange.StartCol > 0 {
			location += fmt.Sprintf(":%d", sourceRange.StartCol)
		}
	}
	return location
}

func renderLegacyContractInteractions(sb *strings.Builder, rows []contractInteractionRow, projectRoot, rootPrefix string) {
	fmt.Fprintf(sb, "_Rich external-boundary facts are unavailable for this cache; showing the call-graph fallback. Rebuild from source for full evidence in [data/interactions.json](%sdata/interactions.json)._\n\n", rootPrefix)
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
