package builder

import (
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
