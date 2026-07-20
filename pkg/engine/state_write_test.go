package engine

import (
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestStateWriteGroupCoversStorageMutationForms(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Mutations {
    uint256[] values;
    uint256 counter;
    function mutate(uint256 x) external {
        values.push(x);
        values.pop();
        delete values[0];
        counter++;
        --counter;
    }
}`).GetDatabase()
	fn := db.GetContractByName("Mutations").Functions[0]
	e := New(db)
	got := map[string]bool{}
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if e.matchKind(node, "state_write") {
			got[node.GetAttributeString("operator")] = true
		}
		return true
	})
	for _, want := range []string{"push", "pop", "delete", "++", "--"} {
		if !got[want] {
			t.Errorf("state_write missing %q; got=%v", want, got)
		}
	}
}

func TestStateWriteGroupRejectsLocalUnaryOperations(t *testing.T) {
	root := types.NewASTNode(types.KindStmtBlock)
	for _, op := range []string{"delete", "++", "--"} {
		unary := types.NewASTNode(types.KindExprUnaryOp)
		unary.SetAttribute("operator", op)
		local := types.NewASTNode(types.KindExprIdentifier)
		local.Name = "temporary"
		local.RefKind = "local_var"
		unary.AddChild(local)
		root.AddChild(unary)
	}
	e := New(types.NewDatabase())
	root.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind == types.KindExprUnaryOp && e.matchKind(node, "state_write") {
			t.Errorf("local unary %q matched state_write", node.GetAttributeString("operator"))
		}
		return true
	})
}

func TestStateWriteGroupFollowsOnlyMutatedLValueRoot(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MutationTargets {
    uint256 counter;
    mapping(uint256 => uint256) values;

    function mutateLocal(uint256[] memory tmp) external {
        tmp[counter]++;
        --tmp[counter];
        delete tmp[counter];
    }

    function mutateState() external {
        values[counter]++;
        --values[counter];
        delete values[counter];
    }
}`).GetDatabase()
	contract := db.GetContractByName("MutationTargets")
	if contract == nil {
		t.Fatal("MutationTargets contract not found")
	}
	e := New(db)
	for _, fn := range contract.Functions {
		got := map[string]bool{}
		fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
			if e.matchKind(node, "state_write") {
				got[node.GetAttributeString("operator")] = true
			}
			return true
		})
		switch fn.Name {
		case "mutateLocal":
			if len(got) != 0 {
				t.Errorf("state index leaked into local state_write matches: %v", got)
			}
		case "mutateState":
			for _, want := range []string{"++", "--", "delete"} {
				if !got[want] {
					t.Errorf("nested state mutation missing %q; got=%v", want, got)
				}
			}
		}
	}
}

func TestStateWriteGroupRejectsShadowingFunctionParameters(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ParameterShadowing {
    uint256[] values;
    uint256 counter;

    function mutateArray(uint256[] storage values, uint256 x) internal {
        values.push(x);
        values.pop();
    }

    function mutateScalar(uint256 counter) internal {
        counter++;
        --counter;
        delete counter;
    }
}`).GetDatabase()
	contract := db.GetContractByName("ParameterShadowing")
	if contract == nil {
		t.Fatal("ParameterShadowing contract not found")
	}
	e := New(db)
	for _, fn := range contract.Functions {
		matched := false
		fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
			if e.matchKind(node, "state_write") {
				matched = true
			}
			return true
		})
		if matched {
			t.Errorf("shadowing parameter function %s produced state_write evidence", fn.Name)
		}
	}
}

func TestStateWriteGroupCoversInheritedAndScopedMutations(t *testing.T) {
	db := buildDBFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MutationBase {
    uint256[] values;
    mapping(uint256 => uint256[]) lists;
    uint256 counter;
}
contract MutationDerived is MutationBase {
    function mutate(uint256 x) external {
        {
            uint256[] memory values = new uint256[](1);
            values[0]++;
            uint256 counter = 1;
            counter++;
        }
        values.push(x);
        lists[x].push(x);
        counter++;
    }
}`).GetDatabase()
	fn := db.GetContractByName("MutationDerived").Functions[0]
	e := New(db)
	got := map[string]int{}
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if e.matchKind(node, "state_write") {
			got[node.GetAttributeString("operator")]++
		}
		return true
	})
	if got["push"] != 2 || got["++"] != 1 {
		t.Fatalf("scoped inherited state_write matches = %v, want push=2 and ++=1", got)
	}
}
