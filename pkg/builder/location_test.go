package builder

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSourceLocatorConvertsByteRangesToUnicodeColumns(t *testing.T) {
	content := "12345678→😀tail"
	db := types.NewDatabase()
	locator := newSourceLocator(&types.SourceFile{Path: "/Unicode.sol", Content: content}, db)
	src := &ast.Identifier{
		BaseNode: ast.BaseNode{
			// The parser columns are byte-oriented and intentionally wrong here;
			// sourceLocator must use Range + source content instead.
			Loc:   &ast.Location{Start: ast.Position{Line: 1, Column: 8}, End: ast.Position{Line: 1, Column: 15}},
			Range: &ast.Range{8, 15},
		},
	}
	span := locator.span(src)
	if span.startLine != 1 || span.endLine != 1 || span.startCol != 9 || span.endCol != 11 || span.startByte != 8 || span.endByte != 15 {
		t.Fatalf("span = %#v, want lines 1..1 cols 9..11 bytes 8..15", span)
	}

	dst := types.NewASTNode(types.KindExprIdentifier)
	locator.apply(dst, src)
	if dst.StartCol != 9 || dst.EndCol != 11 || dst.StartByte != 8 || dst.EndByte != 15 {
		t.Fatalf("apply cols/bytes = (%d,%d,%d,%d), want (9,11,8,15)", dst.StartCol, dst.EndCol, dst.StartByte, dst.EndByte)
	}
}

// TestColumnsAreOneBasedParserBacked drives the real parser (not a synthetic
// ast.Location) to lock the 1-based column convention end-to-end, including the
// first-column case that omitempty would otherwise hide.
func TestColumnsAreOneBasedParserBacked(t *testing.T) {
	// "contract C" — the contract keyword starts in the first source column.
	src := "contract C {\n    uint256 x;\n}\n"
	db := buildFromSource(t, src)
	c := db.GetContractByName("C")
	if c == nil {
		t.Fatal("contract C not found")
	}
	if c.StartCol != 1 {
		t.Errorf("contract at first column should report StartCol 1 (1-based), got %d", c.StartCol)
	}
	if len(c.StateVariables) == 0 {
		t.Fatal("expected a state variable")
	}
	sv := c.StateVariables[0]
	// "    uint256 x;" — 'uint256' begins at 1-based column 5.
	if sv.StartCol != 5 {
		t.Errorf("state var StartCol = %d, want 5 (1-based)", sv.StartCol)
	}
}

func TestSourceLocatorNilSafe(t *testing.T) {
	var locator *sourceLocator
	span := locator.span(&ast.Identifier{})
	if span.startLine != 0 || span.startCol != 0 || span.startByte != 0 {
		t.Fatalf("nil-loc node should yield zeros, got %#v", span)
	}
	locator.apply(nil, nil) // must not panic
}

func TestUnicodeColumnsUseCodePointsForDeclarationsASTAndCallEdges(t *testing.T) {
	src := `contract C {
    /* →😀 */ function run(address target, bytes memory data) external {
        string memory marker = "→😀"; target.delegatecall(data);
    }
}`
	db := buildFromSource(t, src)
	fn := funcByName(t, db, "C", "run")
	for _, diagnostic := range db.Diagnostics {
		if diagnostic.Code == types.DiagnosticInvalidLocation {
			t.Fatalf("valid Unicode source produced location diagnostic: %#v", diagnostic)
		}
	}

	fnByte := strings.Index(src, "function run")
	fnLineStart := strings.LastIndex(src[:fnByte], "\n") + 1
	wantFnCol := utf8.RuneCountInString(src[fnLineStart:fnByte]) + 1
	if fn.StartCol != wantFnCol || fn.StartByte != fnByte {
		t.Fatalf("function start = col %d byte %d, want col %d byte %d", fn.StartCol, fn.StartByte, wantFnCol, fnByte)
	}

	calls := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindCallLowlevelDelegate
	})
	if len(calls) != 1 {
		t.Fatalf("delegatecall nodes = %d, want 1", len(calls))
	}
	callByte := strings.Index(src, "target.delegatecall")
	callLineStart := strings.LastIndex(src[:callByte], "\n") + 1
	wantCallCol := utf8.RuneCountInString(src[callLineStart:callByte]) + 1
	if calls[0].StartCol != wantCallCol || calls[0].StartByte != callByte {
		t.Fatalf("AST call start = col %d byte %d, want col %d byte %d", calls[0].StartCol, calls[0].StartByte, wantCallCol, callByte)
	}

	var callRef *types.FunctionCall
	for _, call := range fn.Calls {
		if call.Target == "delegatecall" {
			callRef = call
			break
		}
	}
	if callRef == nil {
		t.Fatal("delegatecall FunctionCall not found")
	}
	if callRef.Col != wantCallCol || callRef.Byte != callByte {
		t.Fatalf("FunctionCall = col %d byte %d, want col %d byte %d", callRef.Col, callRef.Byte, wantCallCol, callByte)
	}

	var edge *types.CallEdge
	for _, candidate := range db.CallGraph.Edges {
		if candidate.CalledName == "delegatecall" {
			edge = candidate
			break
		}
	}
	if edge == nil {
		t.Fatal("delegatecall CallEdge not found")
	}
	if edge.Col != wantCallCol || edge.Byte != callByte {
		t.Fatalf("CallEdge = col %d byte %d, want col %d byte %d", edge.Col, edge.Byte, wantCallCol, callByte)
	}
}

func TestExpressionStatementPreservesSemanticExpressionSpan(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{name: "ASCII", line: "        target.call(data);"},
		{name: "Unicode prefix", line: `        string memory marker = "→😀"; target.call(data);`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := "contract C {\n    function run(address target, bytes memory data) external {\n" + tc.line + "\n    }\n}\n"
			db := buildFromSource(t, src)
			fn := funcByName(t, db, "C", "run")
			calls := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
				return n.Kind == types.KindCallLowlevelCall
			})
			if len(calls) != 1 {
				t.Fatalf("low-level call nodes = %d, want 1", len(calls))
			}

			const expression = "target.call(data)"
			startByte := strings.Index(src, expression)
			endByte := startByte + len(expression)
			lineStart := strings.LastIndex(src[:startByte], "\n") + 1
			wantStartCol := utf8.RuneCountInString(src[lineStart:startByte]) + 1
			wantEndCol := utf8.RuneCountInString(src[lineStart:endByte]) + 1
			call := calls[0]
			if call.StartByte != startByte || call.EndByte != endByte || call.StartCol != wantStartCol || call.EndCol != wantEndCol {
				t.Fatalf("call span = L%d:C%d-L%d:C%d bytes [%d,%d), want cols %d..%d bytes [%d,%d) excluding semicolon", call.StartLine, call.StartCol, call.EndLine, call.EndCol, call.StartByte, call.EndByte, wantStartCol, wantEndCol, startByte, endByte)
			}
			if got := src[call.StartByte:call.EndByte]; got != expression {
				t.Fatalf("call source = %q, want %q", got, expression)
			}
		})
	}
}

func TestUnicodeColumnsOnEndingLineOfMultilineNode(t *testing.T) {
	src := `contract C {
    function run() external {
        string memory marker =
            "→😀";
    }
}`
	db := buildFromSource(t, src)
	fn := funcByName(t, db, "C", "run")
	assignments := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign && n.StartLine != n.EndLine
	})
	if len(assignments) != 1 {
		t.Fatalf("multiline assignments = %d, want 1", len(assignments))
	}
	wantEndCol := utf8.RuneCountInString(`            "→😀";`) + 1
	if assignments[0].EndCol != wantEndCol {
		t.Fatalf("multiline assignment EndCol = %d, want %d", assignments[0].EndCol, wantEndCol)
	}
}

func TestInvalidUnicodeBoundaryOmitsColumnsAndRecordsOneDiagnostic(t *testing.T) {
	db := types.NewDatabase()
	locator := newSourceLocator(&types.SourceFile{Path: "/Invalid.sol", Content: "a😀b"}, db)
	invalidBoundary := &ast.Identifier{BaseNode: ast.BaseNode{
		Loc:   &ast.Location{Start: ast.Position{Line: 1}, End: ast.Position{Line: 1}},
		Range: &ast.Range{2, 3}, // both endpoints split the four-byte emoji
	}}
	invalidLine := &ast.Identifier{BaseNode: ast.BaseNode{
		Loc:   &ast.Location{Start: ast.Position{Line: 2}, End: ast.Position{Line: 2}},
		Range: &ast.Range{0, 1},
	}}

	first := locator.span(invalidBoundary)
	second := locator.span(invalidLine)
	if first.startCol != 0 || first.endCol != 0 || first.startByte != 2 || first.endByte != 3 {
		t.Fatalf("invalid-boundary span = %#v, want raw bytes with omitted columns", first)
	}
	if second.startCol != 0 || second.endCol != 0 {
		t.Fatalf("invalid-line span = %#v, want omitted columns", second)
	}
	db.NormalizeDiagnostics()
	if len(db.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %#v, want exactly one", db.Diagnostics)
	}
	diagnostic := db.Diagnostics[0]
	if diagnostic.Code != types.DiagnosticInvalidLocation || diagnostic.File != "/Invalid.sol" || !diagnostic.Incomplete {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
}

func TestSourceLocatorUsesSparseIndexForLongMinifiedLine(t *testing.T) {
	const asciiBytes = 1 << 20
	content := strings.Repeat("a", asciiBytes) + "→😀"
	locator := newSourceLocator(&types.SourceFile{Path: "/Minified.sol", Content: content}, nil)
	if len(locator.lines) != 1 {
		t.Fatalf("indexed lines = %d, want 1", len(locator.lines))
	}
	if got := len(locator.lines[0].nonASCII); got != 2 {
		t.Fatalf("non-ASCII index entries = %d, want 2 (one per multibyte rune, not one per byte)", got)
	}

	tests := []struct {
		offset  int
		wantCol int
		wantOK  bool
	}{
		{offset: 0, wantCol: 1, wantOK: true},
		{offset: asciiBytes / 2, wantCol: asciiBytes/2 + 1, wantOK: true},
		{offset: asciiBytes, wantCol: asciiBytes + 1, wantOK: true},
		{offset: asciiBytes + len("→"), wantCol: asciiBytes + 2, wantOK: true},
		{offset: len(content), wantCol: asciiBytes + 3, wantOK: true},
		{offset: asciiBytes + 1, wantOK: false},
		{offset: asciiBytes + len("→") + 1, wantOK: false},
	}
	for _, tt := range tests {
		gotCol, gotOK := locator.column(1, tt.offset)
		if gotCol != tt.wantCol || gotOK != tt.wantOK {
			t.Errorf("column(offset=%d) = (%d,%v), want (%d,%v)", tt.offset, gotCol, gotOK, tt.wantCol, tt.wantOK)
		}
	}
}

func BenchmarkSourceLocatorColumnLongMinifiedLine(b *testing.B) {
	const asciiBytes = 1 << 20
	content := strings.Repeat("a", asciiBytes) + "→😀"
	locator := newSourceLocator(&types.SourceFile{Path: "/Minified.sol", Content: content}, nil)
	offsets := [...]int{asciiBytes / 2, asciiBytes, asciiBytes + len("→"), len(content)}

	b.ReportAllocs()
	b.ResetTimer()
	var total int
	for i := 0; i < b.N; i++ {
		col, ok := locator.column(1, offsets[i%len(offsets)])
		if !ok {
			b.Fatalf("valid indexed endpoint rejected at iteration %d", i)
		}
		total += col
	}
	if total == 0 {
		b.Fatal("unexpected zero result")
	}
}

func TestFunctionHasColumnAndByte(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "guardedRevert")
	if fn.StartLine == 0 {
		t.Fatal("precondition: function should have StartLine")
	}
	if fn.StartCol == 0 && fn.StartByte == 0 {
		t.Errorf("function missing both column and byte offset (col=%d byte=%d)", fn.StartCol, fn.StartByte)
	}
	if fn.EndByte != 0 && fn.EndByte < fn.StartByte {
		t.Errorf("EndByte %d < StartByte %d", fn.EndByte, fn.StartByte)
	}
}

func TestStateVariableHasLocation(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	c := db.GetContractByName("StatementForms")
	if c == nil {
		t.Fatalf("precondition: fixture should have StatementForms contract with state vars")
	}
	if len(c.StateVariables) == 0 {
		t.Fatalf("precondition: fixture contract should have state variables")
	}
	for _, sv := range c.StateVariables {
		if sv.StartLine == 0 {
			t.Errorf("state variable %q missing StartLine", sv.Name)
		}
	}
}

func TestCallSiteHasColumn(t *testing.T) {
	db := buildFixture(t, "../../test-data/core/build-database/03-function-calls.sol")
	var found bool
	for _, c := range db.Contracts {
		for _, fn := range c.Functions {
			for _, call := range fn.Calls {
				if call.Line != 0 {
					found = true
					if call.Col == 0 && call.Byte == 0 {
						t.Errorf("call %q has line %d but no column/byte", call.Target, call.Line)
					}
				}
			}
		}
	}
	if !found {
		t.Fatalf("precondition: fixture should have resolved call sites")
	}
}

func TestInteriorNodesHaveSpans(t *testing.T) {
	db := buildFixture(t, statementsFixture) // "../../test-data/core/build-database/09-statements.sol"
	fn := funcByName(t, db, "StatementForms", "guardedRevert")
	if fn.AST == nil {
		t.Fatal("guardedRevert has no AST")
	}
	reverts := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindCheckRevert
	})
	if len(reverts) == 0 {
		t.Fatal("no check.revert nodes")
	}
	for _, r := range reverts {
		if r.StartLine == 0 {
			t.Errorf("check.revert node missing StartLine (interior nodes should be located)")
		}
		if r.StartCol == 0 && r.StartByte == 0 {
			t.Errorf("check.revert node has neither column nor byte offset")
		}
	}
}

func TestLocationSurvivesJSONRoundTrip(t *testing.T) {
	db := buildFixture(t, statementsFixture)
	fn := funcByName(t, db, "StatementForms", "guardedRevert")
	wantCol, wantByte := fn.StartCol, fn.StartByte
	if wantCol == 0 && wantByte == 0 {
		t.Fatal("precondition: function should have col or byte before round-trip")
	}

	if fn.AST == nil {
		t.Fatal("precondition: function should have an AST")
	}
	interior := fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.StartLine != 0
	})
	if len(interior) == 0 {
		t.Fatal("precondition: function AST should have an interior node with a StartLine")
	}
	wantNode := interior[0]
	wantKind, wantNodeLine := wantNode.Kind, wantNode.StartLine
	wantNodeCol, wantNodeByte := wantNode.StartCol, wantNode.StartByte

	data, err := json.Marshal(db)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var loaded types.Database
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	loaded.RestoreASTParents()

	lf := funcByName(t, &loaded, "StatementForms", "guardedRevert")
	if lf.StartCol != wantCol || lf.StartByte != wantByte {
		t.Errorf("round-trip col/byte = (%d,%d), want (%d,%d)", lf.StartCol, lf.StartByte, wantCol, wantByte)
	}

	if lf.AST == nil {
		t.Fatal("loaded function has no AST")
	}
	gotMatches := lf.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == wantKind && n.StartLine == wantNodeLine
	})
	if len(gotMatches) == 0 {
		t.Fatalf("round-trip: no descendant matching kind=%q startLine=%d found", wantKind, wantNodeLine)
	}
	got := gotMatches[0]
	if got.StartCol != wantNodeCol || got.StartByte != wantNodeByte {
		t.Errorf("interior node round-trip col/byte = (%d,%d), want (%d,%d)", got.StartCol, got.StartByte, wantNodeCol, wantNodeByte)
	}
}
