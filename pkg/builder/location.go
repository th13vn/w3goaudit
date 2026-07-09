package builder

import (
	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// spanFields extracts line/column/byte-offset location from any solast node.
// Returns zeros when the node has no location (synthetic or unparsed).
func spanFields(src ast.Node) (startLine, endLine, startCol, endCol, startByte, endByte int) {
	if src == nil {
		return
	}
	if loc := src.GetLocation(); loc != nil {
		startLine, endLine = loc.Start.Line, loc.End.Line
		startCol, endCol = loc.Start.Column, loc.End.Column
	}
	if r := src.GetRange(); r != nil {
		startByte, endByte = r[0], r[1]
	}
	return
}

// applySpan copies source location from a solast node onto an AST node.
// No-op if either is nil. Existing StartLine/EndLine are preserved when the
// source has no location (does not zero them out).
func applySpan(dst *types.ASTNode, src ast.Node) {
	if dst == nil || src == nil {
		return
	}
	sl, el, sc, ec, sb, eb := spanFields(src)
	if sl != 0 {
		dst.StartLine, dst.EndLine = sl, el
	}
	dst.StartCol, dst.EndCol = sc, ec
	dst.StartByte, dst.EndByte = sb, eb
}
