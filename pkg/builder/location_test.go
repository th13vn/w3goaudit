package builder

import (
	"encoding/json"
	"testing"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestSpanFieldsFromNode(t *testing.T) {
	src := &ast.Identifier{
		BaseNode: ast.BaseNode{
			Loc:   &ast.Location{Start: ast.Position{Line: 5, Column: 8}, End: ast.Position{Line: 5, Column: 12}},
			Range: &ast.Range{100, 104},
		},
	}
	sl, el, sc, ec, sb, eb := spanFields(src)
	if sl != 5 || el != 5 || sc != 8 || ec != 12 || sb != 100 || eb != 104 {
		t.Fatalf("spanFields = (%d,%d,%d,%d,%d,%d), want (5,5,8,12,100,104)", sl, el, sc, ec, sb, eb)
	}

	dst := types.NewASTNode(types.KindExprIdentifier)
	applySpan(dst, src)
	if dst.StartCol != 8 || dst.EndCol != 12 || dst.StartByte != 100 || dst.EndByte != 104 {
		t.Fatalf("applySpan cols/bytes = (%d,%d,%d,%d)", dst.StartCol, dst.EndCol, dst.StartByte, dst.EndByte)
	}
}

func TestSpanFieldsNilSafe(t *testing.T) {
	sl, _, sc, _, sb, _ := spanFields(&ast.Identifier{})
	if sl != 0 || sc != 0 || sb != 0 {
		t.Fatalf("nil-loc node should yield zeros, got line=%d col=%d byte=%d", sl, sc, sb)
	}
	applySpan(nil, nil) // must not panic
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
		t.Skip("fixture has no StatementForms contract with state vars")
	}
	if len(c.StateVariables) == 0 {
		t.Skip("fixture contract has no state variables")
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
		t.Skip("fixture has no resolved call sites")
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
}
