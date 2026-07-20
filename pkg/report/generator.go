package report

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/th13vn/w3goaudit/pkg/logging"
	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// GeneratorOptions configures one report generator.
type GeneratorOptions struct {
	Logger *logging.Logger
	Now    func() time.Time
}

// Generator generates reports from a database
type Generator struct {
	db     *types.Database
	logger *logging.Logger
	legacy bool
	now    func() time.Time
}

// NewGenerator creates a report generator that preserves the legacy
// package-global verbose configuration.
func NewGenerator(db *types.Database) *Generator {
	return &Generator{db: db, legacy: true, now: time.Now}
}

// NewGeneratorWithOptions creates a report generator with scan-local logging
// and clock configuration. A nil logger is explicitly disabled.
func NewGeneratorWithOptions(db *types.Database, opts GeneratorOptions) *Generator {
	logger := opts.Logger
	if logger == nil {
		logger = logging.Disabled()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Generator{db: db, logger: logger, now: now}
}

func (g *Generator) logf(format string, args ...any) {
	if g != nil && g.legacy {
		VerboseLog(format, args...)
		return
	}
	if g != nil {
		g.logger.Printf(format, args...)
	}
}

// GenerateSummary generates a full project summary report
func (g *Generator) GenerateSummary() *SummaryReport {
	g.logf("Starting summary generation for project: %s", g.db.ProjectRoot)
	diagnostics := diagnosticSnapshot(g.db)
	report := &SummaryReport{
		ProjectRoot:      g.db.ProjectRoot,
		ScanTarget:       scanTarget(g.db.ProjectRoot, g.db.ScanTarget),
		AnalysisComplete: analysisComplete(diagnostics, true),
		DiagnosticCounts: countDiagnostics(diagnostics),
		GeneratedAt:      g.now().UTC(),
		MainContracts:    make([]*ContractSummary, 0),
	}

	// Detect git info for the project
	if gitInfo := reader.DetectGitInfo(g.db.ProjectRoot); gitInfo != nil {
		report.GitInfo = &GitInfo{
			RemoteURL: gitInfo.RemoteURL,
			Branch:    gitInfo.Branch,
		}
		g.logf("Detected git repository: %s (branch: %s)", gitInfo.RemoteURL, gitInfo.Branch)
	}

	stats := g.db.GetStats()
	report.Stats = stats
	g.logf("Database stats: %d contracts, %d functions", stats.TotalContracts, stats.TotalFunctions)

	// Generate summary for each main contract. MainContracts is a map, so iterate
	// in a deterministic order rather than randomized map order — otherwise the
	// exported overview lists contracts differently on every run. Order matches
	// the documented "ranked by inheritance weight" intent: weight descending,
	// with the contract ID as a stable tie-breaker.
	mainIDs := make([]string, 0, len(g.db.MainContracts))
	for contractID := range g.db.MainContracts {
		mainIDs = append(mainIDs, contractID)
	}
	sort.Slice(mainIDs, func(i, j int) bool {
		ci, cj := g.db.Contracts[mainIDs[i]], g.db.Contracts[mainIDs[j]]
		wi, wj := 0, 0
		if ci != nil {
			wi = ci.InheritanceWeight
		}
		if cj != nil {
			wj = cj.InheritanceWeight
		}
		if wi != wj {
			return wi > wj
		}
		return mainIDs[i] < mainIDs[j]
	})
	for _, contractID := range mainIDs {
		contract := g.db.Contracts[contractID]
		if contract != nil {
			summary := g.generateContractSummary(contract)
			report.MainContracts = append(report.MainContracts, summary)
		}
	}

	return report
}

// generateContractSummary generates a summary for a single contract
func (g *Generator) generateContractSummary(contract *types.Contract) *ContractSummary {
	g.logf("Generating summary for contract: %s (File: %s)", contract.Name, contract.SourceFile)
	summary := &ContractSummary{
		Name:              contract.Name,
		SourceFile:        contract.SourceFile,
		Version:           g.pragmaVersion(contract.SourceFile),
		InheritanceChain:  g.flattenInheritance(contract),
		StateVariables:    make([]*StateSummary, 0),
		EntryFunctions:    make([]*FunctionSummary, 0),
		ViewFunctions:     make([]*FunctionSummary, 0),
		InternalFunctions: make([]*FunctionSummary, 0),
	}

	// Collect all state variables from inheritance chain (flattened)
	summary.StateVariables = g.collectAllStateVariables(contract)
	summary.StateVariableCount = len(summary.StateVariables)
	g.logf("  State Variables: %d", summary.StateVariableCount)

	// Collect all functions from inheritance chain (flattened)
	g.collectAllFunctions(contract, summary)
	summary.EntryFunctionCount = len(summary.EntryFunctions)
	g.logf("  Functions details: Entry=%d, View=%d, Internal=%d",
		summary.EntryFunctionCount, len(summary.ViewFunctions), len(summary.InternalFunctions))

	// Generate per-function call graphs for entry functions
	for _, fn := range summary.EntryFunctions {
		key := fn.Selector
		if key == "" {
			key = fn.Name
		}
		fn.CallGraphMermaid = g.generateFunctionCallGraph(contract, key)
	}

	// Generate inheritance graph
	summary.InheritanceMermaid = g.generateInheritanceMermaid(contract)
	g.logf("  Generated inheritance graph (%d bytes)", len(summary.InheritanceMermaid))

	// Note: Combined call graph is no longer used, per-function graphs are in FunctionSummary
	summary.CallGraphMermaid = g.generateCallGraphMermaid(contract)
	g.logf("  Generated call graph (%d bytes)", len(summary.CallGraphMermaid))

	return summary
}

// pragmaVersion returns the Solidity pragma recorded for the given source file,
// or "" when the file or its pragma is unknown.
func (g *Generator) pragmaVersion(sourceFile string) string {
	if g.db == nil || g.db.SourceFiles == nil {
		return ""
	}
	if sf := g.db.SourceFiles[sourceFile]; sf != nil {
		return sf.PragmaVersion
	}
	return ""
}

// collectAllStateVariables collects all state variables from the inheritance chain
func (g *Generator) collectAllStateVariables(contract *types.Contract) []*StateSummary {
	return g.collectAllStateVariablesWithLog(contract)
}

func (g *Generator) collectAllStateVariablesWithLog(contract *types.Contract) []*StateSummary {
	states := make([]*StateSummary, 0)
	seen := make(map[string]bool)

	mro := g.db.LinearizedContracts(contract)
	// The exact MRO is derived-first: [MostDerived, ..., MostBase]
	// Iterate in REVERSE (base to derived) so derived can override base
	for i := len(mro) - 1; i >= 0; i-- {
		baseContract := mro[i]

		for _, sv := range baseContract.StateVariables {
			key := sv.Name
			if !seen[key] {
				seen[key] = true
				states = append(states, &StateSummary{
					Name:      sv.Name,
					TypeName:  sv.TypeName,
					DefinedIn: baseContract.Name,
				})
			}
		}
	}

	return states
}

// collectAllFunctions collects all functions from the inheritance chain
func (g *Generator) collectAllFunctions(contract *types.Contract, summary *ContractSummary) {
	entryMap := make(map[string]*FunctionSummary)
	viewMap := make(map[string]*FunctionSummary)
	internalMap := make(map[string]*FunctionSummary)

	mro := g.db.LinearizedContracts(contract)
	// The exact MRO is derived-first: [MostDerived, ..., MostBase]
	// Iterate in REVERSE (base to derived) so derived entries override base ones
	for i := len(mro) - 1; i >= 0; i-- {
		baseContract := mro[i]

		for _, fn := range baseContract.Functions {
			// Skip constructors from inherited contracts
			if fn.IsConstructor && baseContract.ID != contract.ID {
				continue
			}

			funcSummary := &FunctionSummary{
				Name:               fn.Name,
				Selector:           fn.Selector,
				Signature:          fn.Signature,
				IsPayable:          fn.StateMutability == types.StateMutabilityPayable,
				DefinedIn:          baseContract.Name,
				Modifiers:          fn.Modifiers,
				IsAccessControlled: fn.IsAccessControlled(g.db),
			}

			// Categorize by type using selector as key to prevent overloads from overwriting
			key := fn.Selector
			if key == "" {
				key = fn.Name
			}

			if fn.IsEntrypoint() {
				entryMap[key] = funcSummary
			} else if (fn.Visibility == types.VisibilityPublic || fn.Visibility == types.VisibilityExternal) &&
				(fn.StateMutability == types.StateMutabilityView || fn.StateMutability == types.StateMutabilityPure) {
				viewMap[key] = funcSummary
			} else if fn.Visibility == types.VisibilityInternal || fn.Visibility == types.VisibilityPrivate {
				internalMap[key] = funcSummary
			}
		}
	}

	// Convert maps to slices, sorted for deterministic report output (map
	// iteration order is randomized; unsorted output defeats report diffing).
	summary.EntryFunctions = sortedFunctionSummaries(entryMap)
	summary.ViewFunctions = sortedFunctionSummaries(viewMap)
	summary.InternalFunctions = sortedFunctionSummaries(internalMap)
}

// sortedFunctionSummaries returns the map's values sorted by selector (then
// name) for stable, reproducible report ordering.
func sortedFunctionSummaries(m map[string]*FunctionSummary) []*FunctionSummary {
	out := make([]*FunctionSummary, 0, len(m))
	for _, fn := range m {
		out = append(out, fn)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selector != out[j].Selector {
			return out[i].Selector < out[j].Selector
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// flattenInheritance returns the inheritance chain with derived first
func (g *Generator) flattenInheritance(contract *types.Contract) []*InheritedContract {
	mro := g.db.LinearizedContracts(contract)
	chain := make([]*InheritedContract, 0, len(mro))

	// The exact MRO is already derived-first: [MostDerived, ..., MostBase]
	// Iterate forward to produce chain in derived-first order
	for i, baseContract := range mro {
		chain = append(chain, &InheritedContract{
			Order: i + 1,
			Name:  baseContract.Name,
			Kind:  string(baseContract.Kind),
		})
	}

	return chain
}

// generateInheritanceMermaid generates a Mermaid diagram for inheritance
func (g *Generator) generateInheritanceMermaid(contract *types.Contract) string {
	var sb strings.Builder

	sb.WriteString("graph BT\n")

	// Add nodes and edges for inheritance
	for _, baseContract := range g.db.LinearizedContracts(contract) {
		// Add edges from child to parent
		for _, parentName := range baseContract.BaseContracts {
			childNode := sanitizeMermaidNode(baseContract.ID)
			parentID := parentName // unresolved legacy display node
			if parent, exact := g.db.ResolveContractNameExact(parentName, baseContract.SourceFile); exact {
				parentID = parent.ID
			}
			parentNode := sanitizeMermaidNode(parentID)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", childNode, baseContract.Name, parentNode, parentName))
		}
	}

	// Style the main contract and different contract kinds
	sb.WriteString("\n")
	for _, baseContract := range g.db.LinearizedContracts(contract) {
		node := sanitizeMermaidNode(baseContract.ID)
		if baseContract.ID == contract.ID {
			// Main contract - highlight with accent color
			sb.WriteString(fmt.Sprintf("    style %s fill:#4a9eff,color:#fff\n", node))
		} else if baseContract.Kind == types.ContractKindInterface {
			sb.WriteString(fmt.Sprintf("    style %s fill:#6c757d,color:#fff\n", node))
		} else if baseContract.Kind == types.ContractKindAbstract {
			sb.WriteString(fmt.Sprintf("    style %s fill:#9b59b6,color:#fff\n", node))
		}
	}

	return sb.String()
}

// generateCallGraphMermaid generates a Mermaid diagram for function calls
func (g *Generator) generateCallGraphMermaid(contract *types.Contract) string {
	var sb strings.Builder

	sb.WriteString("graph LR\n")

	// Collect all edges within this contract's functions
	edges := make(map[string]bool)
	// entryNodes dedups; entryOrder preserves first-encounter order so the styled
	// node block below is emitted deterministically (a bare map range would
	// randomize it across runs).
	entryNodes := make(map[string]string)
	entryOrder := make([]string, 0)

	// Collect functions from inheritance chain
	for _, baseContract := range g.db.LinearizedContracts(contract) {
		for _, fn := range baseContract.Functions {
			funcName := fn.Name
			funcKey := fn.Selector
			if funcKey == "" {
				funcKey = funcName
			}
			fromID := types.MakeFunctionID(baseContract.SourceFile, baseContract.Name, funcKey)

			// Format name for display (remove parens for fallback/receive if needed, or just cleaner display)
			displayName := funcName
			if strings.HasPrefix(funcName, "fallback") {
				displayName = "fallback"
			} else if strings.HasPrefix(funcName, "receive") {
				displayName = "receive"
			}

			// Track entry points
			// IsEntrypoint() logic might skip fallback/receive depending on implementation
			// We force them here as they are external entry points
			if fn.IsEntrypoint() || strings.HasPrefix(funcName, "fallback") || strings.HasPrefix(funcName, "receive") {
				if _, exists := entryNodes[fromID]; !exists {
					entryNodes[fromID] = displayName
					entryOrder = append(entryOrder, fromID)
				}
			}

			// Add edges for calls
			for _, call := range fn.Calls {
				// Only include internal calls
				if g.isInternalCall(contract, call) {
					target, ok := resolveReportCall(g.db, contract, baseContract, call)
					if !ok {
						continue
					}
					fromNode := sanitizeMermaidNode(fromID)
					toID := target.key()
					toNode := sanitizeMermaidNode(toID)

					edgeKey := fmt.Sprintf("%s --> %s", fromNode, toNode)
					if !edges[edgeKey] {
						edges[edgeKey] = true
						sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", fromNode, displayName, toNode, target.fn.Name))
					}
				}
			}
		}
	}

	// Add node styling - using dark mode compatible colors
	sb.WriteString("\n")
	for _, nodeID := range entryOrder {
		sanitized := sanitizeMermaidNode(nodeID)
		nodeName := entryNodes[nodeID]
		// Ensure node is defined with label even if unconnected
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", sanitized, nodeName))
		// Orange for entry points - better than green
		sb.WriteString(fmt.Sprintf("    style %s fill:#ff9f43,color:#fff\n", sanitized))
	}

	return sb.String()
}

// generateFunctionCallGraph generates a Mermaid diagram for a specific function's call chain
func (g *Generator) generateFunctionCallGraph(contract *types.Contract, funcName string) string {
	var sb strings.Builder
	sb.WriteString("graph LR\n")

	edges := make(map[string]bool)
	visited := make(map[string]bool)

	// Resolve the entry function once — used for both the node's contract
	// qualifier and its selector-based key so the styled node matches the ID
	// emitted during the trace.
	foundInContract, targetFunc := g.findImplementationContract(contract, funcName)
	if foundInContract == nil {
		foundInContract = contract
	}

	// Find the function and trace its calls recursively
	// We pass 'contract' as both lookup target and entry context initially
	g.traceFunctionCalls(contract, contract, funcName, &sb, edges, visited)

	entryKey := funcName
	if targetFunc != nil && targetFunc.Selector != "" {
		entryKey = targetFunc.Selector
	}

	entryNodeId := types.MakeFunctionID(foundInContract.SourceFile, foundInContract.Name, entryKey)
	entryNode := sanitizeMermaidNode(entryNodeId)
	sb.WriteString(fmt.Sprintf("    style %s fill:#ff9f43,color:#fff\n", entryNode))

	return sb.String()
}

// findImplementationContract finds one exact selector in the runtime MRO.
// Bare legacy names succeed only when the optional arity leaves one distinct
// selector; ambiguity and mismatch fail closed.
func (g *Generator) findImplementationContract(startContract *types.Contract, funcName string, argCount ...int) (*types.Contract, *types.Function) {
	if startContract == nil {
		return nil, nil
	}

	// Resolve optional argCount argument
	expectedArgs := -1
	if len(argCount) > 0 {
		expectedArgs = argCount[0]
	}

	resolved, ok := resolveReportFunction(g.db.LinearizedContracts(startContract), funcName, expectedArgs)
	if !ok {
		return nil, nil
	}
	return resolved.contract, resolved.fn
}

// traceFunctionCalls recursively traces function calls and adds edges
// contract: the contract where we look for the function implementation
// entryContract: the main contract context (for virtual lookup of internal calls)
func (g *Generator) traceFunctionCalls(contract *types.Contract, entryContract *types.Contract, funcName string, sb *strings.Builder, edges map[string]bool, visited map[string]bool) {
	foundInContract, targetFunc := g.findImplementationContract(contract, funcName)
	if targetFunc == nil {
		return
	}
	g.traceResolvedFunctionCalls(
		reportCallTarget{contract: foundInContract, fn: targetFunc},
		entryContract, sb, edges, visited,
	)
}

func (g *Generator) traceResolvedFunctionCalls(target reportCallTarget, runtime *types.Contract, sb *strings.Builder, edges map[string]bool, visited map[string]bool) {
	if target.contract == nil || target.fn == nil {
		return
	}
	visitedKey := target.key()
	if visited[visitedKey] {
		return
	}
	visited[visitedKey] = true

	g.logf("  [TRACE] Found %s in %s with %d calls", target.selector(), target.contract.ID, len(target.fn.Calls))

	fromNode := sanitizeMermaidNode(visitedKey)
	for _, call := range target.fn.Calls {
		plan := planTraceCall(call.CallType)
		resolved, ok := resolveReportCall(g.db, runtime, target.contract, call)
		if !ok {
			continue
		}
		edgeLabel := plan.edgeLabel
		if plan.virtual && resolved.contract.ID != target.contract.ID {
			if edgeLabel == "" {
				edgeLabel = resolved.contract.Name
			} else {
				edgeLabel = fmt.Sprintf("%s:%s", edgeLabel, resolved.contract.Name)
			}
		}
		writeTraceEdge(
			sb, edges, fromNode, sanitizeMermaidNode(resolved.key()),
			target.selector(), resolved.selector(), edgeLabel,
		)
		if plan.shouldRecurse {
			g.traceResolvedFunctionCalls(resolved, runtime, sb, edges, visited)
		}
	}
}

type traceCallPlan struct {
	edgeLabel     string
	shouldRecurse bool
	virtual       bool
}

func planTraceCall(callType types.CallType) traceCallPlan {
	switch callType {
	case types.CallTypeModifier:
		return traceCallPlan{edgeLabel: "modifier", shouldRecurse: true}
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSelf:
		return traceCallPlan{shouldRecurse: true, virtual: true}
	case types.CallTypeSuper:
		return traceCallPlan{edgeLabel: "super", shouldRecurse: true}
	case types.CallTypeLibrary:
		return traceCallPlan{edgeLabel: "library"}
	case types.CallTypeExternal:
		return traceCallPlan{edgeLabel: "external"}
	case types.CallTypeTransferETH:
		return traceCallPlan{edgeLabel: "ETH"}
	case types.CallTypeLowLevelCall:
		return traceCallPlan{edgeLabel: "call"}
	case types.CallTypeLowLevelDelegate:
		return traceCallPlan{edgeLabel: "delegatecall"}
	case types.CallTypeLowLevelStatic:
		return traceCallPlan{edgeLabel: "staticcall"}
	default:
		return traceCallPlan{edgeLabel: string(callType)}
	}
}

func writeTraceEdge(sb *strings.Builder, edges map[string]bool, fromNode, toNode, fromKey, toKey, edgeLabel string) {
	edgeKey := fmt.Sprintf("%s --> %s", fromNode, toNode)
	if edges[edgeKey] {
		return
	}
	edges[edgeKey] = true
	fromLabel := strings.Split(fromKey, "(")[0]
	toLabel := strings.Split(toKey, "(")[0]
	if edgeLabel != "" {
		sb.WriteString(fmt.Sprintf("    %s[\"%s\"] -->|%s| %s[\"%s\"]\n", fromNode, fromLabel, edgeLabel, toNode, toLabel))
		return
	}
	sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", fromNode, fromLabel, toNode, toLabel))
}

// isInternalCall checks if a call is within the contract's scope
func (g *Generator) isInternalCall(contract *types.Contract, call *types.FunctionCall) bool {
	// Library calls are included
	if call.CallType == types.CallTypeLibrary {
		return true
	}

	// Internal, inherited, self, super calls are included
	if call.CallType == types.CallTypeInternal ||
		call.CallType == types.CallTypeInherited ||
		call.CallType == types.CallTypeSelf ||
		call.CallType == types.CallTypeSuper {
		return true
	}

	// External calls to other contracts are excluded
	return false
}

// sanitizeMermaidNode sanitizes a node name for Mermaid compatibility.
// It uses a 64-bit hash to keep the ID short and reserved-keyword-safe.
//
// Why FNV-64 (not 32): a 32-bit hash has ~1% collision probability over 10k
// distinct items (birthday paradox); large codebases routinely have more
// functions than that, and a collision silently merges two nodes in the
// Mermaid graph. 64-bit makes collisions astronomically unlikely.
func sanitizeMermaidNode(name string) string {
	h := fnv.New64a()
	h.Write([]byte(name))
	return fmt.Sprintf("n%x", h.Sum64())
}
