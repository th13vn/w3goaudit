package builder

import (
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

	var revertBound, emitBound, positionedIdent bool
	move.AST.WalkDescendants(func(n *types.ASTNode) bool {
		switch {
		case n.Kind == types.KindCheckRevert && n.Name == "Unauthorized":
			if n.RefID == c.ID+".Unauthorized" && n.RefKind == "error" {
				revertBound = true
			}
		case n.RefKind == "event" && n.Name == "Moved":
			if n.RefID == c.ID+".Moved" {
				emitBound = true
			}
		case n.Kind == types.KindExprIdentifier && n.RefID != "" && n.StartLine > 0 && n.StartCol > 0:
			// e.g. `owner` receiver of owner.call, `balances` base, `to` lvalue.
			positionedIdent = true
		}
		return true
	})

	if !revertBound {
		t.Error("revert Unauthorized() did not bind to the error declaration")
	}
	if !emitBound {
		t.Error("emit Moved() did not bind to the event declaration")
	}
	if !positionedIdent {
		t.Error("no refId-bearing identifier received a backfilled source position")
	}
}
