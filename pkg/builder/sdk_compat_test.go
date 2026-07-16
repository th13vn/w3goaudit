package builder

import (
	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

var _ func(*ast.ModifierDefinition) *types.ASTNode = BuildModifierAST
