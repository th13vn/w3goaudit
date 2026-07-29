package types

import (
	"encoding/json"
	"sort"
	"testing"
)

// newTestCallGraph builds a → b → c with a back-edge c → a, plus one external
// call out of b, using full-signature keys the way the builder does.
func newTestCallGraph() *CallGraph {
	cg := &CallGraph{}
	cg.AddEdge(&CallEdge{From: "/p.sol#C.a()", To: "/p.sol#C.b()", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "/p.sol#C.b()", To: "/p.sol#C.c()", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "/p.sol#C.c()", To: "/p.sol#C.a()", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "/p.sol#C.b()", To: "/p.sol#T.transfer(address,uint256)", Type: CallTypeExternal})
	return cg
}

// roundTrip serializes and reloads a call graph, which drops the unexported
// adjacency maps exactly as a `--db` cache load does.
func roundTrip(t *testing.T, cg *CallGraph) *CallGraph {
	t.Helper()
	data, err := json.Marshal(cg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded CallGraph
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loaded.outgoing != nil {
		t.Fatal("precondition failed: adjacency maps must not survive JSON")
	}
	return &loaded
}

func edgeTargets(edges []*CallEdge) []string {
	out := make([]string, 0, len(edges))
	for _, edge := range edges {
		out = append(out, edge.To)
	}
	sort.Strings(out)
	return out
}

func TestCallGraphCalleesAndCallers(t *testing.T) {
	cg := newTestCallGraph()

	got := edgeTargets(cg.GetCallees("/p.sol#C.b()"))
	want := []string{"/p.sol#C.c()", "/p.sol#T.transfer(address,uint256)"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("GetCallees = %v, want %v", got, want)
	}

	callers := cg.GetCallers("/p.sol#C.c()")
	if len(callers) != 1 || callers[0].From != "/p.sol#C.b()" {
		t.Errorf("GetCallers = %v, want one edge from C.b()", callers)
	}
}

// TestCallGraphPrefixLookupAcceptsBareName pins the documented fallback: a lookup
// without the argument list still finds the full-signature key.
func TestCallGraphPrefixLookupAcceptsBareName(t *testing.T) {
	cg := newTestCallGraph()

	if got := cg.GetCallees("/p.sol#C.b"); len(got) != 2 {
		t.Errorf("bare-name GetCallees = %d edges, want 2", len(got))
	}
	if got := cg.GetCallers("/p.sol#C.c"); len(got) != 1 {
		t.Errorf("bare-name GetCallers = %d edges, want 1", len(got))
	}
	// A prefix that is not followed by "(" must not match a longer name.
	if got := cg.GetCallees("/p.sol#C."); len(got) != 0 {
		t.Errorf("partial prefix matched %d edges, want 0", len(got))
	}
}

func TestCallGraphExternalCallsFilter(t *testing.T) {
	cg := newTestCallGraph()
	external := cg.GetExternalCalls("/p.sol#C.b()")
	if len(external) != 1 || external[0].To != "/p.sol#T.transfer(address,uint256)" {
		t.Errorf("GetExternalCalls = %v, want only the external transfer", edgeTargets(external))
	}
	if got := cg.GetExternalCalls("/p.sol#C.a()"); len(got) != 0 {
		t.Errorf("GetExternalCalls on an internal-only caller = %v, want none", edgeTargets(got))
	}
}

// TestCallGraphSurvivesJSONRoundTrip covers the documented contract that the
// unexported adjacency maps are rebuilt on demand after a cache load. Every
// accessor must behave identically before and after serialization — a reader that
// forgets to rebuild silently returns "no edges", which reads as "no calls" rather
// than as an error.
func TestCallGraphSurvivesJSONRoundTrip(t *testing.T) {
	loaded := roundTrip(t, newTestCallGraph())

	if got := edgeTargets(loaded.GetCallees("/p.sol#C.b()")); len(got) != 2 {
		t.Errorf("GetCallees after round-trip = %v, want 2 edges", got)
	}
	if got := loaded.GetCallers("/p.sol#C.c()"); len(got) != 1 {
		t.Errorf("GetCallers after round-trip = %d edges, want 1", len(got))
	}
	if got := loaded.GetExternalCalls("/p.sol#C.b()"); len(got) != 1 {
		t.Errorf("GetExternalCalls after round-trip = %d edges, want 1", len(got))
	}
	if got := loaded.GetCallChain("/p.sol#C.a()", 5); len(got) == 0 {
		t.Error("GetCallChain after round-trip returned nothing")
	}
}

// TestCallGraphHasCycleAfterRoundTrip is the regression that motivated this file:
// HasCycle consulted the adjacency map directly instead of going through
// EnsureIndex, so after a `--db` load it reported "no cycle" for every input. A
// false negative here is worse than an error — recursion analysis silently
// concludes the call graph is acyclic.
func TestCallGraphHasCycleAfterRoundTrip(t *testing.T) {
	if !newTestCallGraph().HasCycle("/p.sol#C.a()") {
		t.Fatal("precondition: the fixture graph a→b→c→a is cyclic")
	}

	loaded := roundTrip(t, newTestCallGraph())
	if !loaded.HasCycle("/p.sol#C.a()") {
		t.Error("HasCycle returned false after a JSON round-trip; the adjacency index was not rebuilt")
	}
}

func TestCallGraphHasCycleAcyclic(t *testing.T) {
	cg := &CallGraph{}
	cg.AddEdge(&CallEdge{From: "/p.sol#C.a()", To: "/p.sol#C.b()", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "/p.sol#C.b()", To: "/p.sol#C.c()", Type: CallTypeInternal})

	if cg.HasCycle("/p.sol#C.a()") {
		t.Error("HasCycle reported a cycle in a linear chain")
	}
	// Self-recursion is a cycle.
	cg.AddEdge(&CallEdge{From: "/p.sol#C.c()", To: "/p.sol#C.c()", Type: CallTypeInternal})
	if !cg.HasCycle("/p.sol#C.a()") {
		t.Error("HasCycle missed direct self-recursion")
	}
}

func TestCallGraphChainRespectsDepth(t *testing.T) {
	cg := &CallGraph{}
	cg.AddEdge(&CallEdge{From: "f0", To: "f1", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "f1", To: "f2", Type: CallTypeInternal})
	cg.AddEdge(&CallEdge{From: "f2", To: "f3", Type: CallTypeInternal})

	shallow := cg.GetCallChain("f0", 1)
	deep := cg.GetCallChain("f0", 10)
	if len(shallow) >= len(deep) {
		t.Errorf("depth limit had no effect: depth1=%v depth10=%v", shallow, deep)
	}
	// A cyclic graph must terminate rather than loop on the visited set.
	cyclic := newTestCallGraph()
	if got := cyclic.GetCallChain("/p.sol#C.a()", 0); len(got) == 0 {
		t.Error("GetCallChain with a zero depth should apply the default, not return nothing")
	}
}
