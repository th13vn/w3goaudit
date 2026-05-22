package engine

import (
	"testing"

	"github.com/th13vn/w3goaudit-engine/pkg/types"
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
