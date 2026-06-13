package types

import "testing"

// buildSampleTree constructs a small AST for traversal tests:
//
//	function (root)
//	├── require (check)
//	│   └── binary_op
//	│       └── identifier "a"
//	└── assign
//	    └── identifier "b"
//
// AddChild is used throughout so Parent links are set during construction.
func buildSampleTree() (root, require, binop, identA, assign, identB *ASTNode) {
	root = NewASTNode(KindDeclFunction)
	require = NewASTNode(KindCheckRequire)
	binop = NewASTNode(KindExprBinaryOp)
	identA = NewASTNode(KindExprIdentifier)
	identA.Name = "a"
	assign = NewASTNode(KindStmtAssign)
	identB = NewASTNode(KindExprIdentifier)
	identB.Name = "b"

	root.AddChild(require)
	require.AddChild(binop)
	binop.AddChild(identA)
	root.AddChild(assign)
	assign.AddChild(identB)
	return
}

func TestAddChildSetsParent(t *testing.T) {
	parent := NewASTNode(KindDeclFunction)
	child := NewASTNode(KindStmtAssign)

	parent.AddChild(child)

	if child.Parent != parent {
		t.Fatal("AddChild should set child.Parent to the receiver")
	}
	if len(parent.Children) != 1 || parent.Children[0] != child {
		t.Fatal("AddChild should append the child")
	}

	// Adding a nil child must be a no-op (must not append).
	parent.AddChild(nil)
	if len(parent.Children) != 1 {
		t.Fatalf("AddChild(nil) should be a no-op, got %d children", len(parent.Children))
	}
}

func TestAddChildren(t *testing.T) {
	parent := NewASTNode(KindStmtBlock)
	c1 := NewASTNode(KindStmtAssign)
	c2 := NewASTNode(KindStmtReturn)

	parent.AddChildren(c1, c2)

	if len(parent.Children) != 2 {
		t.Fatalf("expected 2 children, got %d", len(parent.Children))
	}
	if c1.Parent != parent || c2.Parent != parent {
		t.Fatal("AddChildren should set Parent on every child")
	}
}

func TestWalkDescendantsVisitsAll(t *testing.T) {
	root, _, _, _, _, _ := buildSampleTree()

	var visited int
	root.WalkDescendants(func(n *ASTNode) bool {
		visited++
		return true
	})

	// 5 descendants: require, binop, identA, assign, identB (root itself is not visited).
	if visited != 5 {
		t.Fatalf("expected to visit 5 descendants, visited %d", visited)
	}
}

func TestWalkDescendantsEarlyStop(t *testing.T) {
	root, _, _, _, _, _ := buildSampleTree()

	var visited int
	root.WalkDescendants(func(n *ASTNode) bool {
		visited++
		return false // stop after the first node
	})

	if visited != 1 {
		t.Fatalf("expected to stop after 1 node, visited %d", visited)
	}
}

func TestFindDescendant(t *testing.T) {
	root, _, _, _, _, identB := buildSampleTree()

	found := root.FindDescendant(func(n *ASTNode) bool {
		return n.Kind == KindExprIdentifier && n.Name == "b"
	})
	if found != identB {
		t.Fatal("FindDescendant should return the identifier named 'b'")
	}

	missing := root.FindDescendant(func(n *ASTNode) bool {
		return n.Name == "does-not-exist"
	})
	if missing != nil {
		t.Fatal("FindDescendant should return nil when no node matches")
	}
}

func TestFindAncestor(t *testing.T) {
	root, require, _, identA, _, _ := buildSampleTree()

	// identA's ancestors: binop -> require -> root.
	ancestor := identA.FindAncestor(func(n *ASTNode) bool {
		return n.Kind == KindCheckRequire
	})
	if ancestor != require {
		t.Fatal("FindAncestor should find the enclosing require node")
	}

	rootAncestor := identA.FindAncestor(func(n *ASTNode) bool {
		return n.Kind == KindDeclFunction
	})
	if rootAncestor != root {
		t.Fatal("FindAncestor should reach the root function node")
	}

	none := root.FindAncestor(func(n *ASTNode) bool { return true })
	if none != nil {
		t.Fatal("root has no parent, FindAncestor should return nil")
	}
}

func TestCollectDescendants(t *testing.T) {
	root, _, _, _, _, _ := buildSampleTree()

	idents := root.CollectDescendants(func(n *ASTNode) bool {
		return n.Kind == KindExprIdentifier
	})
	if len(idents) != 2 {
		t.Fatalf("expected 2 identifier descendants, got %d", len(idents))
	}

	none := root.CollectDescendants(func(n *ASTNode) bool {
		return n.Kind == KindCallExternal
	})
	if len(none) != 0 {
		t.Fatalf("expected no matches, got %d", len(none))
	}
}

func TestRestoreParentsRelinksTree(t *testing.T) {
	// Build a tree WITHOUT AddChild so Parent pointers are nil.
	root := NewASTNode(KindDeclFunction)
	child := NewASTNode(KindCheckRequire)
	grandchild := NewASTNode(KindExprIdentifier)
	root.Children = append(root.Children, child)
	child.Children = append(child.Children, grandchild)

	if child.Parent != nil || grandchild.Parent != nil {
		t.Fatal("precondition: parents should be nil before RestoreParents")
	}

	root.RestoreParents()

	if child.Parent != root {
		t.Fatal("RestoreParents should set child.Parent to root")
	}
	if grandchild.Parent != child {
		t.Fatal("RestoreParents should recurse and set grandchild.Parent to child")
	}
}

func TestRestoreParentsHandlesNilReceiverAndChildren(t *testing.T) {
	// nil receiver must not panic.
	var nilNode *ASTNode
	nilNode.RestoreParents()

	// nil child entries must be skipped without panic.
	root := NewASTNode(KindStmtBlock)
	root.Children = append(root.Children, nil)
	root.RestoreParents()
}

func TestIsLeaf(t *testing.T) {
	leaf := NewASTNode(KindExprIdentifier)
	if !leaf.IsLeaf() {
		t.Fatal("node with no children should be a leaf")
	}
	leaf.AddChild(NewASTNode(KindExprLiteral))
	if leaf.IsLeaf() {
		t.Fatal("node with a child should not be a leaf")
	}
}

func TestAttributesGetSet(t *testing.T) {
	n := NewASTNode(KindExprIdentifier)

	n.SetAttribute("is_state_var", true)
	n.SetAttribute("visibility", "public")
	n.SetAttribute("arg_count", 3)

	// Generic GetAttribute: present and missing.
	if v, ok := n.GetAttribute("visibility"); !ok || v != "public" {
		t.Fatalf("GetAttribute(visibility) = %v, %v", v, ok)
	}
	if _, ok := n.GetAttribute("nope"); ok {
		t.Fatal("GetAttribute should report missing keys as absent")
	}

	// Bool variant.
	if !n.GetAttributeBool("is_state_var") {
		t.Fatal("GetAttributeBool(is_state_var) should be true")
	}
	if n.GetAttributeBool("missing") {
		t.Fatal("GetAttributeBool(missing) should default to false")
	}
	// Type mismatch falls back to the zero value.
	if n.GetAttributeBool("visibility") {
		t.Fatal("GetAttributeBool on a string attribute should return false")
	}

	// String variant.
	if got := n.GetAttributeString("visibility"); got != "public" {
		t.Fatalf("GetAttributeString(visibility) = %q", got)
	}
	if got := n.GetAttributeString("missing"); got != "" {
		t.Fatalf("GetAttributeString(missing) = %q, want empty", got)
	}
	if got := n.GetAttributeString("arg_count"); got != "" {
		t.Fatalf("GetAttributeString on an int attribute should return empty, got %q", got)
	}
}

// --- Semantic group helper functions ---

func TestIsOutgoingCall(t *testing.T) {
	outgoing := []string{
		KindCallExternal, KindCallLowlevelCall, KindCallLowlevelDelegate,
		KindCallLowlevelStatic, KindCallBuiltinTransfer, KindCallBuiltinSend,
		KindCallCreate, KindAsmCall, KindAsmDelegatecall, KindAsmStaticcall,
	}
	for _, k := range outgoing {
		if !IsOutgoingCall(k) {
			t.Errorf("IsOutgoingCall(%q) = false, want true", k)
		}
	}
	notOutgoing := []string{KindCallInternal, KindStmtAssign, KindCheckRequire, ""}
	for _, k := range notOutgoing {
		if IsOutgoingCall(k) {
			t.Errorf("IsOutgoingCall(%q) = true, want false", k)
		}
	}
}

func TestIsETHTransfer(t *testing.T) {
	yes := []string{KindCallBuiltinTransfer, KindCallBuiltinSend, KindCallLowlevelCall, KindAsmCall}
	for _, k := range yes {
		if !IsETHTransfer(k) {
			t.Errorf("IsETHTransfer(%q) = false, want true", k)
		}
	}
	// A staticcall moves no ETH.
	if IsETHTransfer(KindCallLowlevelStatic) {
		t.Error("IsETHTransfer(staticcall) should be false")
	}
}

func TestIsDelegatecall(t *testing.T) {
	if !IsDelegatecall(KindCallLowlevelDelegate) || !IsDelegatecall(KindAsmDelegatecall) {
		t.Error("delegatecall kinds should be recognized")
	}
	if IsDelegatecall(KindCallLowlevelCall) {
		t.Error("a plain call is not a delegatecall")
	}
}

func TestIsCheckAndIsGuard(t *testing.T) {
	for _, k := range []string{KindCheckRequire, KindCheckAssert, KindCheckRevert} {
		if !IsCheck(k) {
			t.Errorf("IsCheck(%q) = false, want true", k)
		}
		// IsGuard is documented as an alias for IsCheck.
		if IsGuard(k) != IsCheck(k) {
			t.Errorf("IsGuard(%q) should mirror IsCheck", k)
		}
	}
	if IsCheck(KindStmtIf) {
		t.Error("an if statement is not a check")
	}
}

func TestIsAnyCall(t *testing.T) {
	if !IsAnyCall(KindCallInternal) {
		t.Error("internal calls are calls")
	}
	if !IsAnyCall(KindCallExternal) {
		t.Error("external calls are calls")
	}
	// Assembly call kinds are not part of IsAnyCall's set.
	if IsAnyCall(KindAsmCall) {
		t.Error("IsAnyCall does not cover asm.call")
	}
	if IsAnyCall(KindStmtAssign) {
		t.Error("an assignment is not a call")
	}
}

func TestIsTokenCall(t *testing.T) {
	// token_call maps to external calls only at the kind level.
	if !IsTokenCall(KindCallExternal) {
		t.Error("IsTokenCall(call.external) should be true")
	}
	if IsTokenCall(KindCallInternal) {
		t.Error("IsTokenCall(call.internal) should be false")
	}
}

func TestIsKnownKind(t *testing.T) {
	known := []string{
		"",               // empty == "any"
		KindCallExternal, // exact registered kind
		"outgoing_call",  // semantic group
		"state_write",    // semantic group
		"call",           // dotted prefix
		"asm",            // dotted prefix
	}
	for _, k := range known {
		if !IsKnownKind(k) {
			t.Errorf("IsKnownKind(%q) = false, want true", k)
		}
	}
	unknown := []string{"outgoing_calls", "call.bogus.kind", "totally_made_up"}
	for _, k := range unknown {
		if IsKnownKind(k) {
			t.Errorf("IsKnownKind(%q) = true, want false", k)
		}
	}
}
