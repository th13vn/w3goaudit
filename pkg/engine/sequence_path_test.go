package engine

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// TestSameExecutionPath checks the branch-arm control-flow constraint used by
// the sequence operator: matches in mutually-exclusive arms cannot co-execute.
func TestSameExecutionPath(t *testing.T) {
	// Linear: block { call; assign; } — siblings, same path.
	t.Run("siblings in a block co-execute", func(t *testing.T) {
		block := types.NewASTNode(types.KindStmtBlock)
		call := types.NewASTNode(types.KindCallLowlevelCall)
		assign := types.NewASTNode(types.KindStmtAssign)
		block.AddChild(call)
		block.AddChild(assign)
		if !sameExecutionPath(call, assign) {
			t.Fatal("siblings under a block should be on the same path")
		}
	})

	// Branched: if { cond; then{call}; else{assign} } — call and assign exclusive.
	t.Run("if then vs else arms are exclusive", func(t *testing.T) {
		ifNode := types.NewASTNode(types.KindStmtIf)
		cond := types.NewASTNode(types.KindExprBinaryOp)
		thenBlk := types.NewASTNode(types.KindStmtBlock)
		elseBlk := types.NewASTNode(types.KindStmtBlock)
		ifNode.AddChild(cond)
		ifNode.AddChild(thenBlk)
		ifNode.AddChild(elseBlk)
		call := types.NewASTNode(types.KindCallLowlevelCall)
		assign := types.NewASTNode(types.KindStmtAssign)
		thenBlk.AddChild(call)
		elseBlk.AddChild(assign)
		if sameExecutionPath(call, assign) {
			t.Fatal("then-arm and else-arm nodes must NOT be on the same path")
		}
	})

	// Condition vs arm: call in the if-condition, assign in the then-body — these
	// DO co-execute (condition runs, then body runs). No false negative.
	t.Run("condition and arm co-execute", func(t *testing.T) {
		ifNode := types.NewASTNode(types.KindStmtIf)
		cond := types.NewASTNode(types.KindExprBinaryOp)
		thenBlk := types.NewASTNode(types.KindStmtBlock)
		ifNode.AddChild(cond)
		ifNode.AddChild(thenBlk)
		callInCond := types.NewASTNode(types.KindCallLowlevelCall)
		cond.AddChild(callInCond)
		assign := types.NewASTNode(types.KindStmtAssign)
		thenBlk.AddChild(assign)
		if !sameExecutionPath(callInCond, assign) {
			t.Fatal("a call in the condition and a write in the body should be on the same path")
		}
	})

	// Ternary arms are exclusive.
	t.Run("ternary true vs false arms are exclusive", func(t *testing.T) {
		cond := types.NewASTNode(types.KindExprConditional)
		trueArm := types.NewASTNode(types.KindCallLowlevelCall)
		trueArm.SetAttribute("conditional_part", "true")
		falseArm := types.NewASTNode(types.KindStmtAssign)
		falseArm.SetAttribute("conditional_part", "false")
		cond.AddChild(trueArm)
		cond.AddChild(falseArm)
		if sameExecutionPath(trueArm, falseArm) {
			t.Fatal("ternary true/false arms must NOT be on the same path")
		}
	})
}
