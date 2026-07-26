package builder

import (
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestXrefBindingsAndPositions pins the v0.4 xref support the report layer
// consumes: custom errors are captured, revert/emit occurrences bind to their
// declarations, and bare identifiers anchored to a located parent (member/call
// receiver, index base, assignment lvalue) receive precise source positions.
func TestXrefBindingsAndPositions(t *testing.T) {
	db := buildFixture(t, "../../test-data/core/build-database/16-xref-bindings.sol")
	file := fixtureAbs(t, "../../test-data/core/build-database/16-xref-bindings.sol")
	c := db.GetContractByID(types.MakeContractID(file, "XrefBindings"))
	if c == nil {
		t.Fatal("contract XrefBindings not found")
	}

	// Custom error captured as a declaration with a real position.
	if len(c.Errors) != 1 || c.Errors[0].Name != "Unauthorized" {
		t.Fatalf("errors = %+v, want one Unauthorized", c.Errors)
	}
	if c.Errors[0].StartLine == 0 {
		t.Error("error decl has no source position")
	}

	var move *types.Function
	for _, fn := range c.Functions {
		if fn.Name == "move" {
			move = fn
		}
	}
	if move == nil || move.AST == nil {
		t.Fatal("move function or its AST missing")
	}

	// Collect resolved occurrences keyed by "name|refKind" -> refId. Walk the
	// function body and every modifier body (the revert lives in onlyOwner).
	bound := map[string]string{}
	positionedIdent := false
	visit := func(n *types.ASTNode) bool {
		if n.RefID != "" {
			bound[n.Name+"|"+n.RefKind] = n.RefID
		}
		if n.Kind == types.KindExprIdentifier && n.RefID != "" && n.StartLine > 0 && n.StartCol > 0 {
			positionedIdent = true
		}
		return true
	}
	move.AST.WalkDescendants(visit)
	for _, md := range c.Modifiers {
		if md != nil && md.AST != nil {
			md.AST.WalkDescendants(visit)
		}
	}

	want := []struct{ key, idSuffix, msg string }{
		{"Unauthorized|error", "#XrefBindings.Unauthorized", "revert -> error decl"},
		{"Moved|event", "#XrefBindings.Moved", "emit -> event decl"},
		{"toU128|library", "#SafeCastLib.toU128(uint256)", "library using call -> lib fn"},
		{"wrap|udvt", "#Amount", "UDVT wrap -> udvt decl"},
		{"unwrap|udvt", "#Amount", "UDVT unwrap -> udvt decl"},
		{"balanceOf|function", "#IToken.balanceOf(address)", "external member call -> iface fn"},
		{"IToken|type", "#IToken", "type cast -> type decl"},
	}
	for _, w := range want {
		if !strings.HasSuffix(bound[w.key], w.idSuffix) {
			t.Errorf("%s: %q => %q, want suffix %q", w.msg, w.key, bound[w.key], w.idSuffix)
		}
	}
	if !positionedIdent {
		t.Error("no refId-bearing identifier received a backfilled source position")
	}

	// Modifier usage is captured with a name-token range for the report layer.
	if len(move.ModifierUsages) != 1 || move.ModifierUsages[0].Name != "onlyOwner" ||
		move.ModifierUsages[0].StartLine == 0 {
		t.Errorf("modifier usage not captured with position: %+v", move.ModifierUsages)
	}
}
