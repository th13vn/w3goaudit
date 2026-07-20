package engine

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestVerifyAtomic(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	tests := []struct {
		name     string
		node     *types.ASTNode
		rule     Rule
		expected bool
	}{
		{
			name: "Match kind",
			node: &types.ASTNode{
				Kind: types.KindCallExternal,
				Name: "transfer",
			},
			rule: Rule{
				Kind: types.KindCallExternal,
			},
			expected: true,
		},
		{
			name: "Match kind and regex",
			node: &types.ASTNode{
				Kind: types.KindCallExternal,
				Name: "transferFrom",
			},
			rule: Rule{
				Kind: types.KindCallExternal,
				Name: "^transfer",
			},
			expected: true,
		},
		{
			name: "Kind mismatch",
			node: &types.ASTNode{
				Kind: types.KindCallInternal,
				Name: "transfer",
			},
			rule: Rule{
				Kind: types.KindCallExternal,
			},
			expected: false,
		},
		{
			name: "Regex mismatch",
			node: &types.ASTNode{
				Kind: types.KindCallExternal,
				Name: "approve",
			},
			rule: Rule{
				Kind: types.KindCallExternal,
				Name: "^transfer",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Verify(tt.node, tt.rule)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestVerifyLogic(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	node := &types.ASTNode{
		Kind: types.KindCallExternal,
		Name: "transferFrom",
	}

	tests := []struct {
		name     string
		rule     Rule
		expected bool
	}{
		{
			name: "ALL - both match",
			rule: Rule{
				All: []Rule{
					{Kind: types.KindCallExternal},
					{Name: "^transfer"},
				},
			},
			expected: true,
		},
		{
			name: "ALL - one fails",
			rule: Rule{
				All: []Rule{
					{Kind: types.KindCallExternal},
					{Name: "^approve"},
				},
			},
			expected: false,
		},
		{
			name: "ANY - one matches",
			rule: Rule{
				Any: []Rule{
					{Name: "^approve"},
					{Name: "^transfer"},
				},
			},
			expected: true,
		},
		{
			name: "ANY - none match",
			rule: Rule{
				Any: []Rule{
					{Name: "^approve"},
					{Name: "^mint"},
				},
			},
			expected: false,
		},
		{
			name: "NOT - negates match",
			rule: Rule{
				Not: &Rule{
					Name: "^approve",
				},
			},
			expected: true,
		},
		{
			name: "NOT - negates non-match",
			rule: Rule{
				Not: &Rule{
					Name: "^transfer",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Verify(node, tt.rule)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestVerifyTraversal(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	// Build a simple AST tree
	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = "transfer"

	call1 := types.NewASTNode(types.KindCallExternal)
	call1.Name = "transferFrom"
	root.AddChild(call1)

	arg1 := types.NewASTNode(types.KindExprIdentifier)
	arg1.Name = "from"
	arg1.RefKind = "parameter"
	call1.AddChild(arg1)

	tests := []struct {
		name     string
		node     *types.ASTNode
		rule     Rule
		expected bool
	}{
		{
			name: "HAS - finds descendant",
			node: root,
			rule: Rule{
				Contains: &Rule{
					Kind: types.KindCallExternal,
				},
			},
			expected: true,
		},
		{
			name: "HAS - doesn't find",
			node: root,
			rule: Rule{
				Contains: &Rule{
					Kind: types.KindCallInternal,
				},
			},
			expected: false,
		},
		{
			name: "INSIDE - finds ancestor",
			node: arg1,
			rule: Rule{
				Inside: &Rule{
					Kind: types.KindDeclFunction,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Verify(tt.node, tt.rule)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

const argAnyMemberFixture = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ArgAnyMember {
    function caller() external view returns (address) {
        return msg.sender;
    }
}
`

func TestArgAnyMemberRightFailsClosed(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: member
  from: function
  where:
    - name: ^sender$
    - right: {arg.any: {name: ^recipient$}}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	db := buildDBFromSource(t, argAnyMemberFixture).GetDatabase()
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("member right arg.any is unsupported and must fail closed; findings = %+v", findings)
	}
}

func TestArgAnyMemberLeftDoesNotPassVacuously(t *testing.T) {
	tmpl, err := ParseTemplate(`
meta: {id: T, severity: HIGH}
query:
  select: member
  from: function
  where:
    - name: ^sender$
    - left: {arg.any: {name: ^recipient$}}
`)
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	db := buildDBFromSource(t, argAnyMemberFixture).GetDatabase()
	if findings := New(db).Execute(tmpl); len(findings) != 0 {
		t.Fatalf("member left child does not satisfy arg.any and must not pass vacuously; findings = %+v", findings)
	}
}

func TestVerifyPrimaryTraceRollsBackFailedCandidates(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = "deposit"

	partial := types.NewASTNode(types.KindCallExternal)
	partial.Name = "transferFrom"
	partial.StartLine = 10
	root.AddChild(partial)

	good := types.NewASTNode(types.KindCallExternal)
	good.Name = "transferFrom"
	good.StartLine = 20
	arg := types.NewASTNode(types.KindExprIdentifier)
	arg.Name = "from"
	arg.RefKind = "parameter"
	good.AddChild(arg)
	root.AddChild(good)

	trace := &matchTrace{}
	engine.match = trace
	defer func() { engine.match = nil }()

	rule := Rule{
		Contains: &Rule{
			Kind: types.KindCallExternal,
			Name: "^transferFrom$",
			Args: map[int]Rule{
				0: {TaintedFrom: "parameter"},
			},
		},
	}
	if !engine.Verify(root, rule) {
		t.Fatal("Verify returned false; want the second transferFrom candidate to match")
	}
	if trace.Primary != good {
		t.Fatalf("Primary = line %d node %p; want successful candidate line %d node %p",
			trace.Primary.StartLine, trace.Primary, good.StartLine, good)
	}
}

func TestVerifyTaint(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	tests := []struct {
		name     string
		node     *types.ASTNode
		rule     Rule
		expected bool
	}{
		{
			name: "Parameter taint",
			node: &types.ASTNode{
				Kind:    types.KindExprIdentifier,
				Name:    "from",
				RefKind: "parameter",
			},
			rule: Rule{
				TaintedFrom: "parameter",
			},
			expected: true,
		},
		{
			name: "State var taint",
			node: &types.ASTNode{
				Kind:    types.KindExprIdentifier,
				Name:    "owner",
				RefKind: "state_var",
			},
			rule: Rule{
				TaintedFrom: "state_var",
			},
			expected: true,
		},
		{
			name: "Taint mismatch",
			node: &types.ASTNode{
				Kind:    types.KindExprIdentifier,
				Name:    "x",
				RefKind: "local_var",
			},
			rule: Rule{
				TaintedFrom: "parameter",
			},
			expected: false,
		},
		{
			name: "Non-identifier",
			node: &types.ASTNode{
				Kind: types.KindExprLiteral,
				Name: "100",
			},
			rule: Rule{
				TaintedFrom: "parameter",
			},
			expected: false,
		},
		{
			name: "Indexed parameter taint",
			node: func() *types.ASTNode {
				index := types.NewASTNode(types.KindExprIndexAccess)
				base := types.NewASTNode(types.KindExprIdentifier)
				base.Name = "from"
				base.RefKind = "parameter"
				key := types.NewASTNode(types.KindExprIdentifier)
				key.Name = "i"
				key.RefKind = "local_var"
				index.AddChild(base)
				index.AddChild(key)
				return index
			}(),
			rule: Rule{
				TaintedFrom: "parameter",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Verify(tt.node, tt.rule)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestUserControlledTaintMatchesParameterAndCallerIdentity(t *testing.T) {
	e := New(&types.Database{})

	parameter := types.NewASTNode(types.KindExprIdentifier)
	parameter.Name = "target"
	parameter.RefKind = "parameter"

	legacyMsgSender := types.NewASTNode(types.KindExprMemberAccess)
	legacyMsgSender.Name = "sender"
	legacyMsgSender.SetAttribute("parent", "msg")

	msgSender := types.NewASTNode(types.KindExprMemberAccess)
	msgSender.Name = "sender"
	msgSender.SetAttribute("parent", "msg")
	msgIdentifier := types.NewASTNode(types.KindExprIdentifier)
	msgIdentifier.Name = "msg"
	msgSender.AddChild(msgIdentifier)

	txOrigin := types.NewASTNode(types.KindExprMemberAccess)
	txOrigin.Name = "origin"
	txOrigin.SetAttribute("parent", "tx")
	txIdentifier := types.NewASTNode(types.KindExprIdentifier)
	txIdentifier.Name = "tx"
	txOrigin.AddChild(txIdentifier)

	accountMsg := types.NewASTNode(types.KindExprMemberAccess)
	accountMsg.Name = "msg"
	accountMsg.SetAttribute("parent", "account")
	accountIdentifier := types.NewASTNode(types.KindExprIdentifier)
	accountIdentifier.Name = "account"
	accountIdentifier.RefKind = "state_var"
	accountMsg.AddChild(accountIdentifier)
	accountMsgSender := types.NewASTNode(types.KindExprMemberAccess)
	accountMsgSender.Name = "sender"
	accountMsgSender.SetAttribute("parent", "msg")
	accountMsgSender.AddChild(accountMsg)

	accountTx := types.NewASTNode(types.KindExprMemberAccess)
	accountTx.Name = "tx"
	accountTx.SetAttribute("parent", "account")
	accountTxIdentifier := types.NewASTNode(types.KindExprIdentifier)
	accountTxIdentifier.Name = "account"
	accountTxIdentifier.RefKind = "state_var"
	accountTx.AddChild(accountTxIdentifier)
	accountTxOrigin := types.NewASTNode(types.KindExprMemberAccess)
	accountTxOrigin.Name = "origin"
	accountTxOrigin.SetAttribute("parent", "tx")
	accountTxOrigin.AddChild(accountTx)

	msgSenderIdentifier := types.NewASTNode(types.KindExprIdentifier)
	msgSenderIdentifier.Name = "_msgSender"
	msgSenderIdentifier.RefKind = "state_var"

	msgSenderLocal := types.NewASTNode(types.KindExprIdentifier)
	msgSenderLocal.Name = "_msgSender"
	msgSenderLocal.RefKind = "local_var"

	msgSenderParameter := types.NewASTNode(types.KindExprIdentifier)
	msgSenderParameter.Name = "_msgSender"
	msgSenderParameter.RefKind = "parameter"

	msgSenderInternalCall := types.NewASTNode(types.KindCallInternal)
	msgSenderInternalCall.Name = "_msgSender"

	msgSenderInternalCallWithArg := types.NewASTNode(types.KindCallInternal)
	msgSenderInternalCallWithArg.Name = "_msgSender"
	msgSenderInternalCallWithArg.AddChild(types.NewASTNode(types.KindExprLiteral))

	msgSenderExternalCall := types.NewASTNode(types.KindCallExternal)
	msgSenderExternalCall.Name = "_msgSender"

	// A state variable alone is not a user-controlled source.
	stateOnly := types.NewASTNode(types.KindExprIdentifier)
	stateOnly.Name = "owner"
	stateOnly.RefKind = "state_var"

	for name, node := range map[string]*types.ASTNode{
		"parameter":           parameter,
		"legacy msg.sender":   legacyMsgSender,
		"builder msg.sender":  msgSender,
		"builder tx.origin":   txOrigin,
		"_msgSender internal": msgSenderInternalCall,
	} {
		t.Run(name, func(t *testing.T) {
			if !e.Verify(node, Rule{TaintedFrom: "user_controlled"}) {
				t.Fatalf("%s must be user controlled", name)
			}
		})
	}

	if e.Verify(stateOnly, Rule{TaintedFrom: "user_controlled"}) {
		t.Fatal("state-only value must not be user controlled")
	}

	for name, node := range map[string]*types.ASTNode{
		"account.msg.sender":          accountMsgSender,
		"account.tx.origin":           accountTxOrigin,
		"_msgSender state identifier": msgSenderIdentifier,
		"_msgSender local identifier": msgSenderLocal,
		"_msgSender external call":    msgSenderExternalCall,
		"_msgSender nonzero call":     msgSenderInternalCallWithArg,
	} {
		t.Run(name, func(t *testing.T) {
			if e.Verify(node, Rule{TaintedFrom: "user_controlled"}) {
				t.Fatalf("%s must not be user controlled", name)
			}
		})
	}

	if !e.Verify(msgSenderParameter, Rule{TaintedFrom: "parameter"}) ||
		e.Verify(msgSenderParameter, Rule{TaintedFrom: "sender"}) {
		t.Fatal("a parameter named _msgSender must retain parameter provenance without becoming caller identity")
	}
}

func TestSameBoundExpressionRejectsPartialIdentifierIdentity(t *testing.T) {
	resolved := types.NewASTNode(types.KindExprIdentifier)
	resolved.Name = "balance"
	resolved.RefKind = "state_var"
	resolved.RefID = "/tmp/Vault.sol#Vault.balance"

	unresolved := types.NewASTNode(types.KindExprIdentifier)
	unresolved.Name = "balance"
	unresolved.RefKind = "state_var"

	if sameBoundExpression(resolved, unresolved) {
		t.Fatal("one resolved and one unresolved identifier must not prove exact operand identity")
	}
}

func TestAccessControlMappingLookup(t *testing.T) {
	tests := []struct {
		name     string
		baseName string
		expected bool
	}{
		{
			name:     "operator mapping guard",
			baseName: "isOperator",
			expected: true,
		},
		{
			name:     "balance mapping is not auth",
			baseName: "balances",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fnAST := types.NewASTNode(types.KindDeclFunction)
			requireNode := types.NewASTNode(types.KindCheckRequire)
			index := types.NewASTNode(types.KindExprIndexAccess)
			base := types.NewASTNode(types.KindExprIdentifier)
			base.Name = tt.baseName
			base.RefKind = "state_var"
			sender := types.NewASTNode(types.KindExprMemberAccess)
			sender.Name = "sender"
			msgNode := types.NewASTNode(types.KindExprIdentifier)
			msgNode.Name = "msg"
			sender.AddChild(msgNode)
			index.AddChild(base)
			index.AddChild(sender)
			requireNode.AddChild(index)
			fnAST.AddChild(requireNode)

			fn := &types.Function{
				Name: "guarded",
				AST:  fnAST,
			}

			if got := fn.IsAccessControlled(types.NewDatabase()); got != tt.expected {
				t.Fatalf("expected access-controlled=%v, got %v", tt.expected, got)
			}
		})
	}
}

func TestVerifyArgs(t *testing.T) {
	db := types.NewDatabase()
	engine := New(db)

	// Build call with arguments
	call := types.NewASTNode(types.KindCallExternal)
	call.Name = "transferFrom"

	receiver := types.NewASTNode(types.KindExprIdentifier)
	receiver.Name = "token"
	receiver.RefKind = "state_var"
	receiver.SetAttribute("call_receiver", true)

	arg0 := types.NewASTNode(types.KindExprIdentifier)
	arg0.Name = "from"
	arg0.RefKind = "parameter"

	arg1 := types.NewASTNode(types.KindExprIdentifier)
	arg1.Name = "to"
	arg1.RefKind = "parameter"

	call.AddChild(receiver)
	call.AddChild(arg0)
	call.AddChild(arg1)

	tests := []struct {
		name     string
		node     *types.ASTNode
		rule     Rule
		expected bool
	}{
		{
			name: "First arg matches",
			node: call,
			rule: Rule{
				Args: map[int]Rule{
					0: {
						Kind:        types.KindExprIdentifier,
						TaintedFrom: "parameter",
					},
				},
			},
			expected: true,
		},
		{
			name: "Multiple args match",
			node: call,
			rule: Rule{
				Args: map[int]Rule{
					0: {TaintedFrom: "parameter"},
					1: {TaintedFrom: "parameter"},
				},
			},
			expected: true,
		},
		{
			name: "Arg mismatch",
			node: call,
			rule: Rule{
				Args: map[int]Rule{
					0: {TaintedFrom: "state_var"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.Verify(tt.node, tt.rule)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGoldenRule(t *testing.T) {
	// Test the golden rule: arbitrary transferFrom
	db := types.NewDatabase()
	engine := New(db)

	// Build function AST that should trigger the rule
	fnAST := types.NewASTNode(types.KindDeclFunction)
	fnAST.Name = "badTransfer"

	call := types.NewASTNode(types.KindCallExternal)
	call.Name = "transferFrom"

	arg0 := types.NewASTNode(types.KindExprIdentifier)
	arg0.Name = "from"
	arg0.RefKind = "parameter"

	call.AddChild(arg0)
	fnAST.AddChild(call)

	// Build function
	fn := &types.Function{
		Name:       "badTransfer",
		Visibility: types.VisibilityPublic,
		Modifiers:  []string{}, // No access control modifiers
		AST:        fnAST,
	}

	contract := &types.Contract{
		Name: "TestContract",
	}

	// The golden rule
	rule := Rule{
		Not: &Rule{
			Modifier: "(?i)(onlyOwner|auth|admin)",
		},
		Contains: &Rule{
			Kind: types.KindCallExternal,
			Name: "^transferFrom$",
			Args: map[int]Rule{
				0: {
					Kind:        types.KindExprIdentifier,
					TaintedFrom: "parameter",
				},
			},
		},
	}

	// Should match
	result := engine.VerifyAtFunction(fn, rule, contract)
	if !result {
		t.Error("Expected golden rule to match vulnerable function")
	}

	// Now test with access control - should NOT match
	fn.Modifiers = []string{"onlyOwner"}
	result = engine.VerifyAtFunction(fn, rule, contract)
	if result {
		t.Error("Expected golden rule to NOT match function with access control")
	}
}
