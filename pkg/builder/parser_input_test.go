package builder

import (
	"strings"
	"testing"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
)

func TestNormalizeYulAssignmentsForParserPreservesProtectedTextAndOffsets(t *testing.T) {
	input := "assembly { x := y }\n" +
		"string memory a = \"literal := unchanged\";\n" +
		"string memory b = 'escaped \\' := unchanged';\n" +
		"// line := unchanged\n" +
		"/* block := unchanged */\n"
	want := "assembly { x  = y }\n" +
		"string memory a = \"literal := unchanged\";\n" +
		"string memory b = 'escaped \\' := unchanged';\n" +
		"// line := unchanged\n" +
		"/* block := unchanged */\n"

	got := normalizeYulAssignmentsForParser(input)
	if got != want {
		t.Fatalf("normalized input mismatch:\n got: %q\nwant: %q", got, want)
	}
	if len(got) != len(input) {
		t.Fatalf("normalized byte length = %d, want original %d", len(got), len(input))
	}
	for i := 0; i < len(input); i++ {
		if input[i] != got[i] && !(input[i] == ':' && got[i] == ' ') {
			t.Fatalf("unexpected byte change at %d: %q -> %q", i, input[i], got[i])
		}
	}
}

func TestNormalizeYulAssignmentsForParserReturnsUnchangedInputWithoutAssignment(t *testing.T) {
	const input = "contract C { function f() external pure returns (uint256) { return 1; } }"
	if got := normalizeYulAssignmentsForParser(input); got != input {
		t.Fatalf("input without Yul assignment changed: %q", got)
	}
}

func TestNormalizeYulAssignmentsForParserLeavesInvalidSolidityAssignmentVisible(t *testing.T) {
	const source = "contract C { function f() external { uint256 x; x := 1; } }"
	if got := normalizeYulAssignmentsForParser(source); got != source {
		t.Fatalf("ordinary Solidity := was rewritten: %q", got)
	}
	_, parseErrs, err := parser.ParseWithErrors(source, &parser.Options{Tolerant: true})
	if err == nil && len(parseErrs) == 0 {
		t.Fatal("invalid Solidity := produced no fatal or recovered parse diagnostic")
	}
}

func TestNormalizeYulAssignmentsForParserProducesAssignmentNodeAtOriginalRange(t *testing.T) {
	const source = "contract C { function f(uint256 x) external pure { assembly { x := 0 } } }"
	parsed, err := parser.Parse(normalizeYulAssignmentsForParser(source), &parser.Options{
		Loc:   true,
		Range: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	contract, ok := parsed.Children[0].(*ast.ContractDefinition)
	if !ok || len(contract.SubNodes) != 1 {
		t.Fatalf("parsed contract subnodes = %T/%d, want one function", parsed.Children[0], len(contract.SubNodes))
	}
	fn, ok := contract.SubNodes[0].(*ast.FunctionDefinition)
	if !ok || fn.Body == nil || len(fn.Body.Statements) != 1 {
		t.Fatalf("parsed function/body shape = %T/%v", contract.SubNodes[0], fn.Body)
	}
	inline, ok := fn.Body.Statements[0].(*ast.InlineAssembly)
	if !ok || inline.Body == nil || len(inline.Body.Operations) != 1 {
		t.Fatalf("parsed inline assembly shape = %T/%v", fn.Body.Statements[0], inline)
	}
	assignment, ok := inline.Body.Operations[0].(*ast.AssemblyAssignment)
	if !ok {
		t.Fatalf("assembly operation = %T, want *ast.AssemblyAssignment", inline.Body.Operations[0])
	}
	rng := assignment.GetRange()
	if rng == nil || rng[0] < 0 || rng[1] > len(source) || rng[0] >= rng[1] {
		t.Fatalf("assignment range = %v for source length %d", rng, len(source))
	}
	if snippet := source[rng[0]:rng[1]]; !strings.Contains(snippet, ":=") {
		t.Fatalf("original source at assignment range = %q, want :=", snippet)
	}
}
