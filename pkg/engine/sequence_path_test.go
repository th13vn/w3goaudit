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

func TestSequenceExecutionEventsRespectCallPartialOrder(t *testing.T) {
	root := types.NewASTNode(types.KindStmtBlock)
	outer := types.NewASTNode(types.KindCallInternal)
	outer.Name = "outer"
	receiverWrite := types.NewASTNode(types.KindStmtAssign)
	receiverWrite.SetAttribute("is_state_var", true)
	receiverWrite.SetAttribute("call_receiver", true)
	optionCall := types.NewASTNode(types.KindCallExternal)
	optionCall.Name = "option"
	optionCall.SetAttribute("call_option", "gas")
	argumentCall := types.NewASTNode(types.KindCallExternal)
	argumentCall.Name = "argument"
	outer.AddChild(receiverWrite)
	outer.AddChild(optionCall)
	outer.AddChild(argumentCall)
	root.AddChild(outer)

	after := types.NewASTNode(types.KindCallExternal)
	after.Name = "after"
	root.AddChild(after)

	cases := []struct {
		name  string
		rules []Rule
		want  bool
	}{
		{
			name:  "receiver before call",
			rules: []Rule{{Kind: "state_write"}, {Kind: types.KindCallInternal, Name: "^outer$"}},
			want:  true,
		},
		{
			name:  "call cannot precede receiver",
			rules: []Rule{{Kind: types.KindCallInternal, Name: "^outer$"}, {Kind: "state_write"}},
			want:  false,
		},
		{
			name:  "option and argument may use builder order",
			rules: []Rule{{Kind: types.KindCallExternal, Name: "^option$"}, {Kind: types.KindCallExternal, Name: "^argument$"}},
			want:  true,
		},
		{
			name:  "unordered pre-call siblings may use reverse order",
			rules: []Rule{{Kind: types.KindCallExternal, Name: "^argument$"}, {Kind: types.KindCallExternal, Name: "^option$"}},
			want:  true,
		},
		{
			name:  "pre-call argument cannot follow call",
			rules: []Rule{{Kind: types.KindCallInternal, Name: "^outer$"}, {Kind: types.KindCallExternal, Name: "^argument$"}},
			want:  false,
		},
		{
			name:  "normal sibling after call remains ordered",
			rules: []Rule{{Kind: types.KindCallInternal, Name: "^outer$"}, {Kind: types.KindCallExternal, Name: "^after$"}},
			want:  true,
		},
		{
			name:  "normal sibling cannot move before call",
			rules: []Rule{{Kind: types.KindCallExternal, Name: "^after$"}, {Kind: types.KindCallInternal, Name: "^outer$"}},
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := New(types.NewDatabase()).Verify(root, Rule{Sequence: tc.rules})
			if got != tc.want {
				t.Fatalf("Verify(sequence) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSequenceEvaluatesAssignmentRHSBeforeStateWrite(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
interface SequenceTarget { function ping() external returns (uint256); }
contract AssignmentOrder {
    uint256 private stored;
    function local(address target) external {
        stored = SequenceTarget(target).ping();
    }
    function interprocedural(address target) external {
        stored = helper(target);
    }
    function helper(address target) internal returns (uint256) {
        return SequenceTarget(target).ping();
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "AssignmentOrder")

	forward := Rule{Sequence: []Rule{
		{Kind: types.KindCallExternal, Name: "^ping$"},
		{Kind: "state_write"},
	}}
	reverse := Rule{Sequence: []Rule{
		{Kind: "state_write"},
		{Kind: types.KindCallExternal, Name: "^ping$"},
	}}

	local := mustFunctionByName(t, contract, "local")
	if !New(db).Verify(local.AST, forward) {
		t.Fatal("RHS external call must execute before the enclosing state write")
	}
	if New(db).Verify(local.AST, reverse) {
		t.Fatal("enclosing state write must not execute before its RHS external call")
	}

	interprocedural := mustFunctionByName(t, contract, "interprocedural")
	if !New(db).VerifyAtFunction(interprocedural, forward, contract) {
		t.Fatal("RHS internal callee operation must execute before the enclosing state write")
	}
	if New(db).VerifyAtFunction(interprocedural, reverse, contract) {
		t.Fatal("enclosing state write must not execute before its RHS internal callee operation")
	}
}

func TestInterproceduralSequenceRejectsMutuallyExclusiveCallerArms(t *testing.T) {
	const source = `pragma solidity ^0.8.20;
contract CallerArmSequence {
    uint256 private stored;

    function helper(address target) internal {
        target.call("");
    }

    function callThenWrite(bool flag, address target) external {
        if (flag) {
            helper(target);
        } else {
            stored = 1;
        }
    }

    function writeThenCall(bool flag, address target) external {
        if (flag) {
            stored = 2;
        } else {
            helper(target);
        }
    }
}`
	db := buildDBFromSource(t, source).GetDatabase()
	contract := mustContractByName(t, db, "CallerArmSequence")

	outgoingThenWrite := Rule{Sequence: []Rule{
		{Kind: "outgoing_call"},
		{Kind: "state_write"},
	}}
	writeThenOutgoing := Rule{Sequence: []Rule{
		{Kind: "state_write"},
		{Kind: "outgoing_call"},
	}}

	if New(db).VerifyAtFunction(mustFunctionByName(t, contract, "callThenWrite"), outgoingThenWrite, contract) {
		t.Fatal("inlined helper call and caller else-arm write must not form an outgoing_call -> state_write sequence")
	}
	if New(db).VerifyAtFunction(mustFunctionByName(t, contract, "writeThenCall"), writeThenOutgoing, contract) {
		t.Fatal("caller then-arm write and inlined helper call in the else arm must not form a state_write -> outgoing_call sequence")
	}
}
