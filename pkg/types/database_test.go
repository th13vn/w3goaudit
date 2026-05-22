package types

import "testing"

func TestRestoreASTParents(t *testing.T) {
	root := NewASTNode(KindDeclFunction)
	child := NewASTNode(KindCheckRequire)
	grandchild := NewASTNode(KindExprIdentifier)
	root.Children = append(root.Children, child)
	child.Children = append(child.Children, grandchild)

	db := NewDatabase()
	db.Contracts["test.sol#C"] = &Contract{
		Name: "C",
		Functions: []*Function{
			{
				Name: "f",
				AST:  root,
			},
		},
	}

	db.RestoreASTParents()

	if child.Parent != root {
		t.Fatal("expected child parent to be restored")
	}
	if grandchild.Parent != child {
		t.Fatal("expected grandchild parent to be restored")
	}
}
