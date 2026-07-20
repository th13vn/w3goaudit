package report

import (
	"reflect"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestStateMatrixAndWorkflowUseExactRecordedCallTarget(t *testing.T) {
	db, main, wrong, right := exactReportResolverFixture()
	db.Semantics.SetFunctionEffects(
		types.MakeFunctionID(wrong.SourceFile, wrong.Name, "step(uint256)"),
		&types.FunctionEffects{StateWrites: []types.StateWrite{{Var: "wrongState"}}},
	)
	db.Semantics.SetFunctionEffects(
		types.MakeFunctionID(right.SourceFile, right.Name, "step(uint256)"),
		&types.FunctionEffects{StateWrites: []types.StateWrite{{Var: "rightState"}}},
	)

	rows := BuildStateMatrix(db, main, []*StateSummary{
		{Name: "wrongState", TypeName: "uint256", DefinedIn: "Base"},
		{Name: "rightState", TypeName: "uint256", DefinedIn: "Base"},
	})
	byVar := make(map[string]StateRow, len(rows))
	for _, row := range rows {
		byVar[row.Var] = row
	}
	if got := byVar["wrongState"].Entries; len(got) != 0 {
		t.Fatalf("wrongState reachable entries = %v, want none", got)
	}
	if got := byVar["rightState"].Entries; !reflect.DeepEqual(got, []string{"entry"}) {
		t.Fatalf("rightState reachable entries = %v, want [entry]", got)
	}

	builder := newStateMatrixBuilder(db, main)
	entry, ok := builder.resolveEntry("entry()", "entry")
	if !ok {
		t.Fatal("entry() not resolved")
	}
	writes := builder.transitiveWrites(entry)
	if writes["wrongState"] || !writes["rightState"] {
		t.Fatalf("workflow transitive writes = %v, want only rightState", writes)
	}
}
