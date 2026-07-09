package types

// CallType represents the type of function call
type CallType string

const (
	// Internal calls (within same contract + base contracts + libraries)
	CallTypeInternal  CallType = "internal"  // Same contract internal/private function
	CallTypeInherited CallType = "inherited" // Base contract function (not overridden)
	CallTypeLibrary   CallType = "library"   // Library function via 'using ... for'

	// External calls (to other contracts)
	CallTypeExternal CallType = "external" // External contract via interface
	CallTypeSelf     CallType = "self"     // this.function() - external call to self

	// Special calls
	CallTypeSuper    CallType = "super"    // super.function() - explicit base call
	CallTypeModifier CallType = "modifier" // modifier invocation

	// ETH transfer calls (grouped as transfer_eth)
	CallTypeTransferETH CallType = "transfer_eth" // .call(), .transfer(), .send()

	// Low-level calls (distinguish between call/delegatecall/staticcall)
	CallTypeLowLevel         CallType = "lowlevel"          // Generic low-level (deprecated, use specific)
	CallTypeLowLevelCall     CallType = "lowlevel_call"     // address.call() - now grouped under transfer_eth
	CallTypeLowLevelDelegate CallType = "lowlevel_delegate" // address.delegatecall()
	CallTypeLowLevelStatic   CallType = "lowlevel_static"   // address.staticcall() - read-only, excluded from external_call
)

// CallEdge represents an edge in the call graph
type CallEdge struct {
	// From is the caller function (format: absPath#ContractName.functionName)
	From string `json:"from"`

	// To is the callee function (format: absPath#ContractName.functionName) - resolved
	To string `json:"to"`

	// CalledName is the name as it appears in the source code
	CalledName string `json:"calledName,omitempty"`

	// CalledSignature is the 4-byte function signature (if applicable)
	CalledSignature string `json:"calledSignature,omitempty"`

	// Type of the call
	Type CallType `json:"type"`

	// Line where the call occurs
	Line int `json:"line,omitempty"`

	// Col is the 1-based column of the call site; Byte is its character offset.
	Col  int `json:"col,omitempty"`
	Byte int `json:"byte,omitempty"`

	// Resolved indicates if target was fully resolved
	Resolved bool `json:"resolved"`

	// ResolvedContract is the resolved contract name where function is defined
	ResolvedContract string `json:"resolvedContract,omitempty"`

	// ResolvedFunction is the resolved function name
	ResolvedFunction string `json:"resolvedFunction,omitempty"`

	// TargetKind is the kind of target (contract/abstract/library/interface)
	TargetKind ContractKind `json:"targetKind,omitempty"`
}

// CallGraph represents the call graph for a project
type CallGraph struct {
	// Edges is the list of all call edges
	Edges []*CallEdge `json:"edges"`

	// adjacency map for quick lookup: caller -> [callees]
	outgoing map[string][]*CallEdge

	// reverse adjacency: callee -> [callers]
	incoming map[string][]*CallEdge
}

// NewCallGraph creates a new empty call graph
func NewCallGraph() *CallGraph {
	return &CallGraph{
		Edges:    make([]*CallEdge, 0),
		outgoing: make(map[string][]*CallEdge),
		incoming: make(map[string][]*CallEdge),
	}
}

// AddEdge adds a call edge to the graph
func (cg *CallGraph) AddEdge(edge *CallEdge) {
	cg.Edges = append(cg.Edges, edge)

	if cg.outgoing == nil {
		cg.outgoing = make(map[string][]*CallEdge)
	}
	if cg.incoming == nil {
		cg.incoming = make(map[string][]*CallEdge)
	}

	cg.outgoing[edge.From] = append(cg.outgoing[edge.From], edge)
	cg.incoming[edge.To] = append(cg.incoming[edge.To], edge)
}

// EnsureIndex rebuilds the adjacency maps from Edges.
// Called automatically by GetCallees/GetCallers after JSON load (maps are not exported).
func (cg *CallGraph) EnsureIndex() {
	if cg.outgoing != nil && len(cg.outgoing) > 0 {
		return
	}
	cg.outgoing = make(map[string][]*CallEdge)
	cg.incoming = make(map[string][]*CallEdge)
	for _, edge := range cg.Edges {
		cg.outgoing[edge.From] = append(cg.outgoing[edge.From], edge)
		cg.incoming[edge.To] = append(cg.incoming[edge.To], edge)
	}
}

// GetCallees returns all functions called by the given function.
// Performs prefix matching: exact match OR the key starts with funcID+"." or funcID+"(".
// This handles both "name-only" lookups (funcID = "path#Contract.withdraw") and
// the full-signature keys stored in the graph ("path#Contract.withdraw(uint256)").
func (cg *CallGraph) GetCallees(funcID string) []*CallEdge {
	cg.EnsureIndex()
	if edges, ok := cg.outgoing[funcID]; ok {
		return edges
	}
	// Prefix-match: find all keys that start with funcID followed by "(" (full sig)
	prefix := funcID + "("
	var result []*CallEdge
	for k, edges := range cg.outgoing {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			result = append(result, edges...)
		}
	}
	return result
}

// GetCallers returns all functions that call the given function.
// Same prefix-matching logic as GetCallees.
func (cg *CallGraph) GetCallers(funcID string) []*CallEdge {
	cg.EnsureIndex()
	if edges, ok := cg.incoming[funcID]; ok {
		return edges
	}
	prefix := funcID + "("
	var result []*CallEdge
	for k, edges := range cg.incoming {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			result = append(result, edges...)
		}
	}
	return result
}

// GetExternalCalls returns all external calls from a function
func (cg *CallGraph) GetExternalCalls(funcID string) []*CallEdge {
	cg.EnsureIndex()
	var result []*CallEdge
	for _, edge := range cg.GetCallees(funcID) {
		if edge.Type == CallTypeExternal || edge.Type == CallTypeLowLevel {
			result = append(result, edge)
		}
	}
	return result
}

// HasCycle checks if there's a cycle involving the given function
func (cg *CallGraph) HasCycle(funcName string) bool {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	return cg.hasCycleUtil(funcName, visited, recStack)
}

func (cg *CallGraph) hasCycleUtil(node string, visited, recStack map[string]bool) bool {
	visited[node] = true
	recStack[node] = true

	for _, edge := range cg.outgoing[node] {
		if !visited[edge.To] {
			if cg.hasCycleUtil(edge.To, visited, recStack) {
				return true
			}
		} else if recStack[edge.To] {
			return true
		}
	}

	recStack[node] = false
	return false
}

// GetCallChain returns the call chain from a function (BFS traversal)
func (cg *CallGraph) GetCallChain(funcID string, maxDepth int) []string {
	cg.EnsureIndex()
	if maxDepth <= 0 {
		maxDepth = 10
	}

	visited := make(map[string]bool)
	var result []string
	queue := []struct {
		name  string
		depth int
	}{{funcID, 0}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.name] || current.depth > maxDepth {
			continue
		}

		visited[current.name] = true
		result = append(result, current.name)

		for _, edge := range cg.GetCallees(current.name) {
			if !visited[edge.To] {
				queue = append(queue, struct {
					name  string
					depth int
				}{edge.To, current.depth + 1})
			}
		}
	}

	return result
}
