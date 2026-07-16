package types

// DataFlowEdge represents a directional data flow between AST nodes
type DataFlowEdge struct {
	// FromID is the RefID of the source ASTNode (origin)
	FromID string `json:"fromId"`

	// ToID is the RefID of the destination ASTNode (target)
	ToID string `json:"toId"`

	// FromNode points to the raw node for the source
	FromNode *ASTNode `json:"-"`

	// ToNode points to the raw node for the destination
	ToNode *ASTNode `json:"-"`

	// Type describes the kind of data transfer
	// e.g. "assignment", "parameter_binding", "return_value"
	Type string `json:"type"`

	// FlowLine is the exact line in source where this transfer happens
	FlowLine int `json:"flowLine,omitempty"`
}

// DataFlowGraph stores the complete intra-procedural data flow for a project.
// Data flow maps how data moves between assignments and operations.
type DataFlowGraph struct {
	// Edges holds all directed flows
	Edges []*DataFlowEdge `json:"edges"`

	// outgoing maps node RefID string -> edges originating from that node
	outgoing map[string][]*DataFlowEdge

	// incoming maps node RefID string -> edges targeting that node
	incoming map[string][]*DataFlowEdge
}

// NewDataFlowGraph initializes a new DataFlowGraph instance
func NewDataFlowGraph() *DataFlowGraph {
	return &DataFlowGraph{
		Edges:    make([]*DataFlowEdge, 0),
		outgoing: make(map[string][]*DataFlowEdge),
		incoming: make(map[string][]*DataFlowEdge),
	}
}

// AddEdge securely appends a DataFlowEdge, making it queryable
func (df *DataFlowGraph) AddEdge(edge *DataFlowEdge) {
	df.Edges = append(df.Edges, edge)

	if df.outgoing == nil {
		df.outgoing = make(map[string][]*DataFlowEdge)
	}
	if df.incoming == nil {
		df.incoming = make(map[string][]*DataFlowEdge)
	}

	if edge.FromID != "" {
		df.outgoing[edge.FromID] = append(df.outgoing[edge.FromID], edge)
	}
	if edge.ToID != "" {
		df.incoming[edge.ToID] = append(df.incoming[edge.ToID], edge)
	}
}

// EnsureIndex rebuilds the adjacency maps from Edges. The maps are unexported
// so they are lost across a JSON round-trip (build cache); without this a
// cache-loaded DataFlowGraph would answer every query with nil. Mirrors
// CallGraph.EnsureIndex and is called by the query methods.
func (df *DataFlowGraph) EnsureIndex() {
	if len(df.outgoing) > 0 || len(df.incoming) > 0 {
		return
	}
	df.outgoing = make(map[string][]*DataFlowEdge)
	df.incoming = make(map[string][]*DataFlowEdge)
	for _, edge := range df.Edges {
		if edge == nil {
			continue
		}
		if edge.FromID != "" {
			df.outgoing[edge.FromID] = append(df.outgoing[edge.FromID], edge)
		}
		if edge.ToID != "" {
			df.incoming[edge.ToID] = append(df.incoming[edge.ToID], edge)
		}
	}
}

// GetSourcesFor returns all edges supplying data INTO the passed ID
func (df *DataFlowGraph) GetSourcesFor(targetID string) []*DataFlowEdge {
	df.EnsureIndex()
	return df.incoming[targetID]
}

// GetDestinationsFor returns all edges flowing OUT FROM the passed ID
func (df *DataFlowGraph) GetDestinationsFor(sourceID string) []*DataFlowEdge {
	df.EnsureIndex()
	return df.outgoing[sourceID]
}
