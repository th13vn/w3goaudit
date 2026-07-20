package builder

import (
	"testing"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestBuildFunctionASTNilDatabasePreservesDirectStateFacts(t *testing.T) {
	rawFn := parseRawFunction(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Compat {
    uint256 counter;
    uint256[] values;
    function mutate(uint256 x) external {
        counter;
        counter += x;
        counter++;
        values.push(x);
        values.pop();
    }
}`, "Compat", "mutate")
	contract := &types.Contract{
		ID:         "/tmp/Compat.sol#Compat",
		Name:       "Compat",
		SourceFile: "/tmp/Compat.sol",
		StateVariables: []*types.StateVariable{
			{Name: "counter", TypeName: "uint256"},
			{Name: "values", TypeName: "uint256[]"},
		},
	}
	fn := &types.Function{
		Name:         "mutate",
		ContractName: "Compat",
		SourceFile:   "/tmp/Compat.sol",
		Parameters:   []*types.Parameter{{Name: "x", TypeName: "uint256"}},
	}
	root := BuildFunctionAST(rawFn, fn, contract, nil)
	if root == nil {
		t.Fatal("BuildFunctionAST returned nil")
	}
	stateIDs := map[string]string{
		"counter": "/tmp/Compat.sol#Compat.counter",
		"values":  "/tmp/Compat.sol#Compat.values",
	}
	for name, wantID := range stateIDs {
		nodes := root.CollectDescendants(func(n *types.ASTNode) bool {
			return n.Kind == types.KindExprIdentifier && n.Name == name
		})
		if len(nodes) == 0 {
			t.Fatalf("state identifier %s not found", name)
		}
		for _, node := range nodes {
			if node.RefKind != "state_var" || node.RefID != wantID || node.GetAttributeString("type_kind") == "" {
				t.Errorf("state identifier %s lost SDK facts: %+v", name, node)
			}
		}
	}
	for _, node := range root.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Kind == types.KindStmtAssign
	}) {
		if !node.GetAttributeBool("is_state_var") {
			t.Errorf("direct state assignment lost is_state_var: %+v", node)
		}
	}
	for _, node := range root.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if node.Kind != types.KindStmtStateMutation || !node.GetAttributeBool("is_state_var") {
			t.Errorf("direct state array builtin lost classification: %+v", node)
		}
	}
}

func TestOverloadedDirectSDKMissingSelectorLeavesBindingRefIDsEmpty(t *testing.T) {
	rawFn := parseRawFunction(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Compat {
    function f(uint256 input) external returns (uint256 result) {
        uint256 local = input;
        assembly { let y := local pop(y) }
        return local;
    }
}`, "Compat", "f")
	contract := &types.Contract{ID: "/tmp/Compat.sol#Compat", Name: "Compat", SourceFile: "/tmp/Compat.sol"}
	fn := &types.Function{
		Name:         "f",
		ContractName: "Compat",
		SourceFile:   "/tmp/Compat.sol",
		Parameters:   []*types.Parameter{{Name: "input", TypeName: "uint256"}},
		Returns:      []*types.Parameter{{Name: "result", TypeName: "uint256"}},
	}
	root := BuildFunctionAST(rawFn, fn, contract, nil)
	bindings := root.CollectDescendants(func(node *types.ASTNode) bool {
		return node.RefKind == "parameter" || node.RefKind == "local_var"
	})
	if len(bindings) == 0 {
		t.Fatal("direct SDK AST has no parameter/local bindings")
	}
	for _, binding := range bindings {
		if binding.RefID != "" {
			t.Fatalf("selector-less direct SDK binding %s has guessed RefID %q", binding.Name, binding.RefID)
		}
	}
}

func TestBuildModifierASTWithContextUsesExactStateOwnerRefIDs(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ModifierBase {
    uint256[] values;
    uint256 counter;
}
contract ModifierDerived is ModifierBase {
    uint256 localCounter;
    modifier gate() {
        values.push(1);
        counter++;
        localCounter++;
        _;
    }
    function run() external gate {}
}`)
	derived := db.GetContractByName("ModifierDerived")
	base := db.GetContractByName("ModifierBase")
	if derived == nil || base == nil {
		t.Fatalf("contracts missing: derived=%+v base=%+v", derived, base)
	}
	rawMod := rawModifierFromDatabase(t, db, "ModifierDerived", "gate")
	root := BuildModifierASTWithContext(rawMod, derived, db)
	wants := map[string]string{
		"values":       base.ID + ".values",
		"counter":      base.ID + ".counter",
		"localCounter": derived.ID + ".localCounter",
	}
	for name, wantID := range wants {
		node := root.FindDescendant(func(n *types.ASTNode) bool {
			return n.Kind == types.KindExprIdentifier && n.Name == name
		})
		if node == nil || node.RefKind != "state_var" || node.RefID != wantID {
			t.Errorf("modifier state %s identity = %+v, want RefID %q", name, node, wantID)
		}
	}
	push := root.FindDescendant(func(n *types.ASTNode) bool { return n.Name == "push" })
	if push == nil || push.Kind != types.KindStmtStateMutation || !push.GetAttributeBool("is_state_var") {
		t.Errorf("inherited modifier push classification = %+v", push)
	}
}

func parseRawFunction(t *testing.T, source, contractName, functionName string) *ast.FunctionDefinition {
	t.Helper()
	unit, err := parser.Parse(source, &parser.Options{Tolerant: true, Loc: true, Range: true})
	if err != nil {
		t.Fatalf("parse source: %v", err)
	}
	for _, child := range unit.Children {
		contract, ok := child.(*ast.ContractDefinition)
		if !ok || contract.Name != contractName {
			continue
		}
		for _, sub := range contract.SubNodes {
			if fn, ok := sub.(*ast.FunctionDefinition); ok && fn.Name == functionName {
				return fn
			}
		}
	}
	t.Fatalf("raw function %s.%s not found", contractName, functionName)
	return nil
}

func rawModifierFromDatabase(t *testing.T, db *types.Database, contractName, modifierName string) *ast.ModifierDefinition {
	t.Helper()
	source := db.SourceFiles["/tmp/T.sol"]
	if source == nil {
		t.Fatal("/tmp/T.sol source not found")
	}
	unit, ok := source.AST.(*ast.SourceUnit)
	if !ok || unit == nil {
		t.Fatalf("raw source AST missing: %T", source.AST)
	}
	for _, child := range unit.Children {
		contract, ok := child.(*ast.ContractDefinition)
		if !ok || contract.Name != contractName {
			continue
		}
		for _, sub := range contract.SubNodes {
			if modifier, ok := sub.(*ast.ModifierDefinition); ok && modifier.Name == modifierName {
				return modifier
			}
		}
	}
	t.Fatalf("raw modifier %s.%s not found", contractName, modifierName)
	return nil
}
