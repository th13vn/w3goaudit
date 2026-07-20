package builder

import (
	"strings"
	"testing"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func TestArrayPushPopDistinguishesBuiltinsFromLibraryExtensions(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
library ArrayLib {
    function push(uint256[] memory self, uint256 x) internal pure { self; x; }
    function pop(uint256[] memory self) internal pure { self; }
    function push(uint256[] storage self, uint256 x, uint256 y) internal { self; x; y; }
    function pop(uint256[] storage self, uint256 x) internal { self; x; }
}
library FixedLib {
    function push(uint256[2] storage self, uint256 x) internal { self; x; }
}
contract MutationDispatch {
    using ArrayLib for uint256[];
    using FixedLib for uint256[2];

    uint256[] values;
    uint256[2] fixedValues;

    function stateExtensions() external {
        values.push(1, 2);
        values.pop(1);
    }

    function memoryExtensions(uint256[] memory values) internal {
        values.push(1);
        values.pop();
    }

    function fixedExtension() external {
        fixedValues.push(1);
    }

    function storageBuiltins(uint256[] storage values) internal {
        values.push(1);
        values.pop();
    }
}`)
	arrayLib := db.GetContractByName("ArrayLib")
	fixedLib := db.GetContractByName("FixedLib")
	if arrayLib == nil || fixedLib == nil {
		t.Fatalf("libraries missing: array=%+v fixed=%+v", arrayLib, fixedLib)
	}

	for _, fnName := range []string{"stateExtensions", "memoryExtensions", "fixedExtension"} {
		fn := funcByName(t, db, "MutationDispatch", fnName)
		for _, node := range fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
			return n.Name == "push" || n.Name == "pop"
		}) {
			if node.Kind == types.KindStmtStateMutation {
				t.Errorf("extension %s.%s classified as builtin mutation", fnName, node.Name)
			}
		}
		if len(fn.Calls) == 0 {
			t.Errorf("extension function %s has no callgraph calls", fnName)
		}
		for _, call := range fn.Calls {
			if call.Target != "push" && call.Target != "pop" {
				continue
			}
			wantID := arrayLib.ID
			if fnName == "fixedExtension" {
				wantID = fixedLib.ID
			}
			if call.CallType != types.CallTypeLibrary || !call.Resolved || call.ResolvedContractID != wantID || call.ResolvedFunction == "" {
				t.Errorf("extension call lacks exact library target: fn=%s call=%+v wantContract=%s", fnName, call, wantID)
			}
		}
		selector := fn.Selector
		fe := effectsOf(db, "MutationDispatch", selector)
		if fe == nil {
			t.Fatalf("no effects for %s", selector)
		}
		if len(fe.StateWrites) != 0 {
			t.Errorf("extension function %s recorded state writes: %+v", fnName, fe.StateWrites)
		}
	}

	storageFn := funcByName(t, db, "MutationDispatch", "storageBuiltins")
	for _, node := range storageFn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if node.Kind != types.KindStmtStateMutation || node.GetAttributeBool("is_state_var") {
			t.Errorf("storage parameter builtin mismatch: kind=%q attrs=%v", node.Kind, node.Attributes)
		}
	}
	for _, call := range storageFn.Calls {
		if call.Target == "push" || call.Target == "pop" {
			t.Errorf("storage builtin emitted callgraph call: %+v", call)
		}
	}
	if fe := effectsOf(db, "MutationDispatch", storageFn.Selector); fe == nil || len(fe.StateWrites) != 0 {
		t.Errorf("storage parameter builtin effects = %+v, want none", fe)
	}
}

func TestSolidityLexicalScopesRestoreStateBindings(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
library ScopeLib {
    function push(uint256[] memory self, uint256 x) internal pure { self; x; }
}
contract ScopedMutations {
    using ScopeLib for uint256[];
    uint256[] values;
    uint256[] backing;
    uint256 counter;

    function mutate() external {
        {
            uint256[] memory values = new uint256[](1);
            values.push(1);
            uint256 counter = 1;
            counter++;
        }
        values.push(2);
        counter++;
        for (uint256 counter = 0; counter < 1; counter++) {
            counter++;
        }
        --counter;
    }
}`)
	fn := funcByName(t, db, "ScopedMutations", "mutate")
	var localPushCalls, stateMutations, localUnary, stateUnary int
	for _, node := range fn.AST.CollectDescendants(func(n *types.ASTNode) bool { return true }) {
		switch {
		case node.Name == "push":
			if node.Kind == types.KindStmtStateMutation && node.GetAttributeBool("is_state_var") {
				stateMutations++
			} else if node.Kind != types.KindStmtStateMutation {
				localPushCalls++
			}
		case node.Kind == types.KindExprUnaryOp && len(node.Children) > 0 && node.Children[0].Name == "counter":
			if node.Children[0].RefKind == "state_var" {
				stateUnary++
			} else if node.Children[0].RefKind == "local_var" {
				localUnary++
			}
		}
	}
	if localPushCalls != 1 || stateMutations != 1 || localUnary < 2 || stateUnary != 2 {
		t.Fatalf("scope identities wrong: localPush=%d stateMutations=%d localUnary=%d stateUnary=%d", localPushCalls, stateMutations, localUnary, stateUnary)
	}
	scopeLib := db.GetContractByName("ScopeLib")
	var pushCalls []*types.FunctionCall
	for _, call := range fn.Calls {
		if call.Target == "push" {
			pushCalls = append(pushCalls, call)
		}
	}
	if len(pushCalls) != 1 || scopeLib == nil || pushCalls[0].ResolvedContractID != scopeLib.ID || pushCalls[0].CallType != types.CallTypeLibrary {
		t.Fatalf("scoped extension calls = %+v, want one exact ScopeLib call", pushCalls)
	}
	fe := effectsOf(db, "ScopedMutations", "mutate()")
	if fe == nil {
		t.Fatal("no effects for mutate")
	}
	got := map[string]bool{}
	for _, write := range fe.StateWrites {
		got[write.Kind+":"+write.Var] = true
	}
	for _, want := range []string{"push:values", "increment:counter", "decrement:counter"} {
		if !got[want] {
			t.Errorf("missing outer state effect %q; writes=%+v", want, fe.StateWrites)
		}
	}
	for _, write := range fe.StateWrites {
		if write.Var != "values" && write.Var != "counter" {
			t.Errorf("local scope leaked effect: %+v", write)
		}
	}
}

func TestInheritedStorageMutationsAreStateWrites(t *testing.T) {
	db := buildFromSource(t, `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MutationBase {
    uint256[] values;
    mapping(uint256 => uint256[]) lists;
    mapping(uint256 => uint256) counts;
}
contract MutationDerived is MutationBase {
    function mutate(uint256 x) external {
        values.push(x);
        values.pop();
        lists[x].push(x);
        lists[x].pop();
        counts[x]++;
        --counts[x];
        delete counts[x];
    }
}`)
	fn := funcByName(t, db, "MutationDerived", "mutate")
	for _, node := range fn.AST.CollectDescendants(func(n *types.ASTNode) bool {
		return n.Name == "push" || n.Name == "pop"
	}) {
		if node.Kind != types.KindStmtStateMutation || !node.GetAttributeBool("is_state_var") {
			t.Errorf("inherited mutation %s classified as kind=%q attrs=%v", node.Name, node.Kind, node.Attributes)
		}
		stateRoot := node.FindDescendant(func(n *types.ASTNode) bool {
			return n.Kind == types.KindExprIdentifier && n.RefKind == "state_var"
		})
		if stateRoot == nil || !strings.Contains(stateRoot.RefID, "#MutationBase.") {
			t.Errorf("inherited mutation %s lost exact base state identity: root=%+v", node.Name, stateRoot)
		}
	}
	for _, call := range fn.Calls {
		if call.Target == "push" || call.Target == "pop" {
			t.Errorf("inherited builtin emitted callgraph call: %+v", call)
		}
	}
	fe := effectsOf(db, "MutationDerived", "mutate(uint256)")
	if fe == nil {
		t.Fatal("no effects for inherited mutate")
	}
	got := map[string]bool{}
	for _, write := range fe.StateWrites {
		got[write.Kind+":"+write.Var] = true
	}
	for _, want := range []string{
		"push:values", "pop:values", "push:lists", "pop:lists",
		"increment:counts", "decrement:counts", "delete:counts",
	} {
		if !got[want] {
			t.Errorf("missing inherited effect %q; writes=%+v", want, fe.StateWrites)
		}
	}
}
