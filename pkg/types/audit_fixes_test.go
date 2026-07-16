package types

import "testing"

// TestDataFlowGraphEnsureIndexRebuilds asserts a DataFlowGraph whose adjacency
// maps were lost (as after a JSON round-trip, where they are unexported) still
// answers queries — EnsureIndex rebuilds them from Edges lazily.
func TestDataFlowGraphEnsureIndexRebuilds(t *testing.T) {
	// Simulate a cache-loaded graph: Edges populated, adjacency maps nil.
	df := &DataFlowGraph{Edges: []*DataFlowEdge{
		{FromID: "a", ToID: "b", Type: "assignment"},
		{FromID: "a", ToID: "c", Type: "assignment"},
	}}

	if got := df.GetDestinationsFor("a"); len(got) != 2 {
		t.Fatalf("GetDestinationsFor(a) = %d edges, want 2 (index not rebuilt after round-trip)", len(got))
	}
	if got := df.GetSourcesFor("b"); len(got) != 1 {
		t.Fatalf("GetSourcesFor(b) = %d edges, want 1", len(got))
	}
}

// TestGetFunctionSourceUsesRecordedFile asserts source lookup uses the file
// recorded on the function rather than resolving the owning contract by name —
// which is ambiguous when two contracts share a name and would slice a
// different file's source.
func TestGetFunctionSourceUsesRecordedFile(t *testing.T) {
	// Two contracts both named "Token" in different files, each with a foo().
	realFn := &Function{Name: "foo", ContractName: "Token", SourceFile: "/src/Token.sol", StartLine: 2, EndLine: 2}
	mockFn := &Function{Name: "foo", ContractName: "Token", SourceFile: "/mock/Token.sol", StartLine: 2, EndLine: 2}
	db := &Database{
		Contracts: map[string]*Contract{
			"/mock/Token.sol#Token": {Name: "Token", SourceFile: "/mock/Token.sol", Functions: []*Function{mockFn}},
			"/src/Token.sol#Token":  {Name: "Token", SourceFile: "/src/Token.sol", Functions: []*Function{realFn}},
		},
		SourceFiles: map[string]*SourceFile{
			"/mock/Token.sol": {Path: "/mock/Token.sol", Content: "contract Token {\n    function foo() external { revert(\"mock\"); }\n}\n"},
			"/src/Token.sol":  {Path: "/src/Token.sol", Content: "contract Token {\n    function foo() external { realBody(); }\n}\n"},
		},
	}

	got := db.GetFunctionSource(realFn)
	if got == "" || !contains(got, "realBody") {
		t.Fatalf("GetFunctionSource returned wrong file's source: %q", got)
	}
	// Sanity: the mock resolves to its own body, not the lex-min "/mock" pick.
	if g := db.GetFunctionSource(mockFn); !contains(g, "mock") {
		t.Fatalf("mock GetFunctionSource returned wrong source: %q", g)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
