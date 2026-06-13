package report

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/th13vn/w3goaudit/pkg/reader"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// Generator generates reports from a database
type Generator struct {
	db *types.Database
}

// NewGenerator creates a new report generator
func NewGenerator(db *types.Database) *Generator {
	return &Generator{db: db}
}

// GenerateSummary generates a full project summary report
func (g *Generator) GenerateSummary() *SummaryReport {
	VerboseLog("Starting summary generation for project: %s", g.db.ProjectRoot)
	report := &SummaryReport{
		ProjectRoot:   g.db.ProjectRoot,
		GeneratedAt:   time.Now(),
		MainContracts: make([]*ContractSummary, 0),
	}

	// Detect git info for the project
	if gitInfo := reader.DetectGitInfo(g.db.ProjectRoot); gitInfo != nil {
		report.GitInfo = &GitInfo{
			RemoteURL: gitInfo.RemoteURL,
			Branch:    gitInfo.Branch,
		}
		VerboseLog("Detected git repository: %s (branch: %s)", gitInfo.RemoteURL, gitInfo.Branch)
	}

	stats := g.db.GetStats()
	report.Stats = stats
	VerboseLog("Database stats: %d contracts, %d functions", stats.TotalContracts, stats.TotalFunctions)

	// Generate summary for each main contract
	for contractID := range g.db.MainContracts {
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
	VerboseLog("Generating summary for contract: %s (File: %s)", contract.Name, contract.SourceFile)
	summary := &ContractSummary{
		Name:              contract.Name,
		SourceFile:        contract.SourceFile,
		InheritanceChain:  g.flattenInheritance(contract),
		StateVariables:    make([]*StateSummary, 0),
		EntryFunctions:    make([]*FunctionSummary, 0),
		ViewFunctions:     make([]*FunctionSummary, 0),
		InternalFunctions: make([]*FunctionSummary, 0),
	}

	// Collect all state variables from inheritance chain (flattened)
	summary.StateVariables = g.collectAllStateVariables(contract)
	summary.StateVariableCount = len(summary.StateVariables)
	VerboseLog("  State Variables: %d", summary.StateVariableCount)

	// Collect all functions from inheritance chain (flattened)
	g.collectAllFunctions(contract, summary)
	summary.EntryFunctionCount = len(summary.EntryFunctions)
	VerboseLog("  Functions details: Entry=%d, View=%d, Internal=%d",
		summary.EntryFunctionCount, len(summary.ViewFunctions), len(summary.InternalFunctions))

	// Generate per-function call graphs for entry functions
	for _, fn := range summary.EntryFunctions {
		fn.CallGraphMermaid = g.generateFunctionCallGraph(contract, fn.Name)
	}

	// Generate inheritance graph
	summary.InheritanceMermaid = g.generateInheritanceMermaid(contract)
	VerboseLog("  Generated inheritance graph (%d bytes)", len(summary.InheritanceMermaid))

	// Note: Combined call graph is no longer used, per-function graphs are in FunctionSummary
	summary.CallGraphMermaid = g.generateCallGraphMermaid(contract)
	VerboseLog("  Generated call graph (%d bytes)", len(summary.CallGraphMermaid))

	return summary
}

// collectAllStateVariables collects all state variables from the inheritance chain
func (g *Generator) collectAllStateVariables(contract *types.Contract) []*StateSummary {
	return g.collectAllStateVariablesWithLog(contract)
}

func (g *Generator) collectAllStateVariablesWithLog(contract *types.Contract) []*StateSummary {
	states := make([]*StateSummary, 0)
	seen := make(map[string]bool)

	// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
	// Iterate in REVERSE (base to derived) so derived can override base
	for i := len(contract.LinearizedBases) - 1; i >= 0; i-- {
		baseName := contract.LinearizedBases[i]
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil {
			VerboseLog("  [WARN] Base contract not found: %s", baseName)
			continue
		}

		for _, sv := range baseContract.StateVariables {
			key := sv.Name
			if !seen[key] {
				seen[key] = true
				states = append(states, &StateSummary{
					Name:      sv.Name,
					TypeName:  sv.TypeName,
					DefinedIn: baseName,
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

	// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
	// Iterate in REVERSE (base to derived) so derived entries override base ones
	for i := len(contract.LinearizedBases) - 1; i >= 0; i-- {
		baseName := contract.LinearizedBases[i]
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		for _, fn := range baseContract.Functions {
			// Skip constructors from inherited contracts
			if fn.IsConstructor && baseName != contract.Name {
				continue
			}

			funcSummary := &FunctionSummary{
				Name:               fn.Name,
				Selector:           fn.Selector,
				Signature:          fn.Signature,
				IsPayable:          fn.StateMutability == types.StateMutabilityPayable,
				DefinedIn:          baseName,
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
	chain := make([]*InheritedContract, 0, len(contract.LinearizedBases))

	// LinearizedBases is already derived-first: [MostDerived, ..., MostBase]
	// Iterate forward to produce chain in derived-first order
	for i, baseName := range contract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)

		kind := "unknown"
		if baseContract != nil {
			kind = string(baseContract.Kind)
		}

		chain = append(chain, &InheritedContract{
			Order: i + 1,
			Name:  baseName,
			Kind:  kind,
		})
	}

	return chain
}

// generateInheritanceMermaid generates a Mermaid diagram for inheritance
func (g *Generator) generateInheritanceMermaid(contract *types.Contract) string {
	var sb strings.Builder

	sb.WriteString("graph BT\n")

	// Add nodes and edges for inheritance
	for _, baseName := range contract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		// Add edges from child to parent
		for _, parentName := range baseContract.BaseContracts {
			childNode := sanitizeMermaidNode(baseName)
			parentNode := sanitizeMermaidNode(parentName)
			sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", childNode, baseName, parentNode, parentName))
		}
	}

	// Style the main contract and different contract kinds
	sb.WriteString("\n")
	for _, baseName := range contract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		node := sanitizeMermaidNode(baseName)
		if baseName == contract.Name {
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
	entryNodes := make(map[string]bool)

	// Collect functions from inheritance chain
	for _, baseName := range contract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}

		for _, fn := range baseContract.Functions {
			funcName := fn.Name

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
				entryNodes[displayName] = true
			}

			// Add edges for calls
			for _, call := range fn.Calls {
				// Only include internal calls
				if g.isInternalCall(contract, call) {
					calledName := call.Target
					if call.ResolvedFunction != "" {
						calledName = call.ResolvedFunction
					}

					fromNode := sanitizeMermaidNode(displayName) // Use displayName for consistency
					toNode := sanitizeMermaidNode(calledName)

					edgeKey := fmt.Sprintf("%s --> %s", fromNode, toNode)
					if !edges[edgeKey] {
						edges[edgeKey] = true
						sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", fromNode, displayName, toNode, calledName))
					}
				}
			}
		}
	}

	// Add node styling - using dark mode compatible colors
	sb.WriteString("\n")
	for nodeName := range entryNodes {
		sanitized := sanitizeMermaidNode(nodeName)
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

	// Resolve the entry function to ensure consistent node ID style
	foundInContract, _ := g.findImplementationContract(contract, funcName)
	if foundInContract == "" {
		foundInContract = contract.Name
	}

	// Find the function and trace its calls recursively
	// We pass 'contract' as both lookup target and entry context initially
	g.traceFunctionCalls(contract, contract, funcName, &sb, edges, visited)

	// Style the entry function - use same contract-qualified ID as used in trace
	entryKey := funcName
	if foundInContract != contract.Name {
		// We found it in a base contract. We should already have targetFunc from findImplementationContract
	}
	// Better: grab the actual function object to get its selector
	_, targetFunc := g.findImplementationContract(contract, funcName)
	if targetFunc != nil && targetFunc.Selector != "" {
		entryKey = targetFunc.Selector
	}

	entryNodeId := fmt.Sprintf("%s.%s", foundInContract, entryKey)
	entryNode := sanitizeMermaidNode(entryNodeId)
	sb.WriteString(fmt.Sprintf("    style %s fill:#ff9f43,color:#fff\n", entryNode))

	return sb.String()
}

// findImplementationContract finds which contract in the hierarchy implements the function.
// argCount is the number of arguments at the call site (-1 = unknown / skip arity check).
// When multiple overloads share the same name, the one whose parameter count matches
// argCount is preferred; name-only matching is used as a fallback.
func (g *Generator) findImplementationContract(startContract *types.Contract, funcName string, argCount ...int) (string, *types.Function) {
	if startContract == nil {
		return "", nil
	}

	// Resolve optional argCount argument
	expectedArgs := -1
	if len(argCount) > 0 {
		expectedArgs = argCount[0]
	}

	matchFn := func(fn *types.Function) bool {
		if fn.Selector != funcName && fn.Name != funcName {
			return false
		}
		if expectedArgs < 0 {
			return true
		}
		return len(fn.Parameters) == expectedArgs
	}
	fallbackFn := func(fn *types.Function) bool { return fn.Selector == funcName || fn.Name == funcName }

	// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
	// First pass: exact arity match on non-interface contracts
	for _, baseName := range startContract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil || baseContract.Kind == types.ContractKindInterface {
			continue
		}
		for _, fn := range baseContract.Functions {
			if matchFn(fn) {
				return baseName, fn
			}
		}
	}

	// Second pass: name-only fallback on non-interface contracts
	for _, baseName := range startContract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil || baseContract.Kind == types.ContractKindInterface {
			continue
		}
		for _, fn := range baseContract.Functions {
			if fallbackFn(fn) {
				return baseName, fn
			}
		}
	}

	// Third pass: interfaces (exact arity)
	for _, baseName := range startContract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil || baseContract.Kind != types.ContractKindInterface {
			continue
		}
		for _, fn := range baseContract.Functions {
			if matchFn(fn) {
				return baseName, fn
			}
		}
	}

	// Fourth pass: interfaces name-only
	for _, baseName := range startContract.LinearizedBases {
		baseContract := g.db.GetContractByName(baseName)
		if baseContract == nil || baseContract.Kind != types.ContractKindInterface {
			continue
		}
		for _, fn := range baseContract.Functions {
			if fallbackFn(fn) {
				return baseName, fn
			}
		}
	}

	return "", nil
}

// traceFunctionCalls recursively traces function calls and adds edges
// contract: the contract where we look for the function implementation
// entryContract: the main contract context (for virtual lookup of internal calls)
func (g *Generator) traceFunctionCalls(contract *types.Contract, entryContract *types.Contract, funcName string, sb *strings.Builder, edges map[string]bool, visited map[string]bool) {
	// Find the function implementation
	foundInContract, targetFunc := g.findImplementationContract(contract, funcName)

	if targetFunc == nil {
		return
	}

	// Use selector (includes param types) to build unique keys for overloaded functions.
	// e.g. "_approve" and "_approve" (different param counts) become
	// "_approve(address,address,uint256)" vs "_approve(address,address,uint256,bool)".
	// Fall back to plain name when no selector is available (e.g. constructor).
	funcKey := targetFunc.Selector
	if funcKey == "" {
		funcKey = funcName
	}

	// Make visited key contract-qualified AND selector-qualified to allow same-name
	// overloads in the same contract to be treated as distinct nodes.
	visitedKey := fmt.Sprintf("%s.%s", foundInContract, funcKey)
	if visited[visitedKey] {
		return
	}
	visited[visitedKey] = true

	VerboseLog("  [TRACE] Found %s in %s with %d calls", funcName, foundInContract, len(targetFunc.Calls))

	// Build from node ID using selector so overloads get distinct Mermaid nodes.
	fromNodeId := fmt.Sprintf("%s.%s", foundInContract, funcKey)
	fromNode := sanitizeMermaidNode(fromNodeId)

	// Add edges for ALL calls (ordered by priority)
	for _, call := range targetFunc.Calls {
		calledName := call.Target
		if call.ResolvedFunction != "" {
			calledName = call.ResolvedFunction
		}

		// Determine edge label based on call type
		edgeLabel := ""
		shouldRecurse := false
		isVirtualCall := false

		switch call.CallType {
		case types.CallTypeModifier:
			edgeLabel = "modifier"
			shouldRecurse = true
		case types.CallTypeInternal:
			edgeLabel = "" // Remove "internal"
			shouldRecurse = true
			isVirtualCall = true
		case types.CallTypeInherited:
			edgeLabel = "" // Remove "inherited"
			shouldRecurse = true
			isVirtualCall = true
		case types.CallTypeSuper:
			edgeLabel = "super"
			shouldRecurse = true
		case types.CallTypeSelf:
			edgeLabel = "" // Remove "self"
			shouldRecurse = true
			isVirtualCall = true
		case types.CallTypeLibrary:
			edgeLabel = "library"
			shouldRecurse = false // Don't recurse into library
		case types.CallTypeExternal:
			edgeLabel = "external"
			shouldRecurse = false // Don't recurse into external contracts
		case types.CallTypeTransferETH:
			edgeLabel = "ETH"
			shouldRecurse = false
		case types.CallTypeLowLevelCall:
			edgeLabel = "call"
			shouldRecurse = false
		case types.CallTypeLowLevelDelegate:
			edgeLabel = "delegatecall"
			shouldRecurse = false
		case types.CallTypeLowLevelStatic:
			edgeLabel = "staticcall"
			shouldRecurse = false
		default:
			edgeLabel = string(call.CallType)
			shouldRecurse = false
		}

		// Contract context is shown in edge label
		resolvedContract := call.ResolvedContract

		// Determine target contract for Node ID
		toContract := foundInContract

		var toNode, toNodeId string
		if isVirtualCall {
			// Resolve virtually using entryContract, passing call-site arg count
			// so overloaded functions with the same name are disambiguated correctly.
			impName, impFunc := g.findImplementationContract(entryContract, calledName, call.ArgCount)

			// Filter out calls that don't satisfy function resolution (e.g. errors, events, built-ins like type/revert)
			if impFunc == nil {
				continue
			}

			if impName != "" {
				toContract = impName
			}

			// Use the RESOLVED function's selector for the target node ID
			// so overloads (_approve 3-param vs 4-param) get distinct nodes.
			toKey := impFunc.Selector
			if toKey == "" {
				toKey = calledName
			}
			toNodeId = fmt.Sprintf("%s.%s", toContract, toKey)
			toNode = sanitizeMermaidNode(toNodeId)
			// Add contract name to edge label when calling into a different contract
			if toContract != foundInContract {
				if edgeLabel == "" {
					edgeLabel = toContract
				} else {
					edgeLabel = fmt.Sprintf("%s:%s", edgeLabel, toContract)
				}
			}
		} else {
			if resolvedContract != "" {
				// Use static resolution (Super, Library, External)
				toContract = resolvedContract
			}
			toNodeId = fmt.Sprintf("%s.%s", toContract, calledName)
			toNode = sanitizeMermaidNode(toNodeId)
		}

		edgeKey := fmt.Sprintf("%s --> %s", fromNode, toNode)
		if !edges[edgeKey] {
			edges[edgeKey] = true
			labelFrom := strings.Split(funcKey, "(")[0]
			labelTo := strings.Split(calledName, "(")[0]
			// Use labeled edge: A -->|label| B
			// Node ID is contract-qualified, but label shows just function name
			if edgeLabel != "" {
				sb.WriteString(fmt.Sprintf("    %s[\"%s\"] -->|%s| %s[\"%s\"]\n", fromNode, labelFrom, edgeLabel, toNode, labelTo))
			} else {
				sb.WriteString(fmt.Sprintf("    %s[\"%s\"] --> %s[\"%s\"]\n", fromNode, labelFrom, toNode, labelTo))
			}
		}

		// Recurse into called function if applicable
		if shouldRecurse {
			var nextLookupContract *types.Contract

			// For super calls, we MUST resolve to the specific parent contract
			if call.CallType == types.CallTypeSuper {
				// Use resolved contract (parent) for lookup
				if rc := g.db.GetContractByName(resolvedContract); rc != nil {
					nextLookupContract = rc
				} else {
					nextLookupContract = contract // Fallback
				}
			} else {
				// For internal/inherited/self calls, we use VIRTUAL lookup starting from entry contract
				// This ensures we find the most derived implementation (polymorphism)
				// unless we are specifically in a library
				if contract.Kind == types.ContractKindLibrary || call.CallType == types.CallTypeLibrary {
					// Libraries don't participate in inheritance overrides same way
					nextLookupContract = contract
				} else {
					nextLookupContract = entryContract
				}
			}

			// Sanity check
			if nextLookupContract != nil {
				g.traceFunctionCalls(nextLookupContract, entryContract, calledName, sb, edges, visited)
			}
		}
	}
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
