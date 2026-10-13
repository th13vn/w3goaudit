package builder

import (
	"strings"
	"testing"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestContextualKeywordLocalVariableDoesNotCauseParseLoss(t *testing.T) {
	db := buildFromSource(t, `pragma solidity ^0.8.20;
contract A {
    struct S { uint256 value; }
    mapping(address => S) records;
    function write() external {
        S storage from = records[msg.sender];
        from.value = 1;
    }
    function afterKeyword() external pure returns (uint256) { return 1; }
}`)
	contract := db.GetContract(types.MakeContractID("/tmp/T.sol", "A"))
	if contract == nil {
		t.Fatal("contract A was dropped")
	}
	names := map[string]bool{}
	for _, fn := range contract.Functions {
		names[fn.Name] = true
	}
	if !names["write"] || !names["afterKeyword"] {
		t.Fatalf("functions after contextual local were dropped: %#v", names)
	}
	for _, diagnostic := range db.Diagnostics {
		if types.IsParseLoss(diagnostic.Code) {
			t.Fatalf("contextual local produced parse loss: %#v", diagnostic)
		}
	}
}

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

func TestLegacyConstantFunctionModifierIsParsedWithoutRecovery(t *testing.T) {
	db := buildFromSource(t, "pragma solidity ^0.4.24;\ncontract LegacyConstant {\n    function read() constant returns (uint256) {\n        return 1;\n    }\n    function after() public {\n    }\n}")
	c := db.GetContractByName("LegacyConstant")
	if c == nil {
		t.Fatal("LegacyConstant contract missing")
	}
	var read, after *types.Function
	for _, fn := range c.Functions {
		switch fn.Name {
		case "read":
			read = fn
		case "after":
			after = fn
		}
	}
	if read == nil || after == nil {
		t.Fatalf("functions missing after legacy constant: read=%+v after=%+v", read, after)
	}
	if read.StateMutability != types.StateMutabilityView {
		t.Fatalf("legacy constant mutability = %q, want view", read.StateMutability)
	}
	for _, diagnostic := range db.Diagnostics {
		if types.IsParseLoss(diagnostic.Code) {
			t.Fatalf("legacy constant produced parse loss: %+v", diagnostic)
		}
	}
}

func TestLegacyConstantNormalizationPreservesNonFunctionConstantText(t *testing.T) {
	input := "pragma solidity ^0.4.24;\ncontract C {\n string constant text = \"function fake() constant\";\n // function fake() constant { }\n function read() constant returns(uint) { return 1; }\n}"
	got := normalizeLegacyFunctionModifiersForParser(input)
	if !strings.Contains(got, "string constant text") || !strings.Contains(got, "function fake() constant") {
		t.Fatalf("non-function constant text changed: %q", got)
	}
	if !strings.Contains(got, "function read() view     returns") {
		t.Fatalf("function constant was not width-preserving normalized: %q", got)
	}
	if len(got) != len(input) {
		t.Fatalf("normalized length=%d, want %d", len(got), len(input))
	}
}

func TestModernConstantFunctionModifierIsNotNormalized(t *testing.T) {
	input := "pragma solidity ^0.8.20;\ncontract C { function read() constant returns(uint) { return 1; } }"
	if got := normalizeLegacyFunctionModifiersForParser(input); got != input {
		t.Fatalf("modern source was normalized: %q", got)
	}
}

func TestCommentedLegacyPragmaDoesNotEnableConstantNormalization(t *testing.T) {
	input := "// pragma solidity ^0.4.24;\npragma solidity ^0.8.20;\ncontract C { function read() constant returns(uint) { return 1; } }"
	if got := normalizeLegacyFunctionModifiersForParser(input); got != input {
		t.Fatalf("commented legacy pragma enabled normalization: %q", got)
	}
}

func TestMixedPragmasDoNotEnableConstantNormalization(t *testing.T) {
	input := "pragma solidity ^0.4.24;\npragma solidity ^0.8.20;\ncontract C { function read() constant returns(uint) { return 1; } }"
	if got := normalizeLegacyFunctionModifiersForParser(input); got != input {
		t.Fatalf("mixed compiler ranges enabled normalization: %q", got)
	}
}
