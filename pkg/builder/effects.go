package builder

import (
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// analyzeEffects walks every function's AST and records per-function effects
// (state writes, guards, access control) into db.Semantics.FunctionEffects.
// These facts power the per-entry workflow files and the state-change matrix in
// the report layer. It is tolerant: a function without an AST simply yields the
// modifier-only auth summary.
func (b *Builder) analyzeEffects() {
	if b.db.Semantics == nil {
		b.db.Semantics = types.NewSemanticFacts()
	}
	for _, contract := range b.db.Contracts {
		for _, fn := range contract.Functions {
			fe := analyzeFunctionEffects(fn)
			selector := fn.Selector
			if selector == "" {
				selector = fn.Name
			}
			funcID := types.MakeFunctionID(contract.SourceFile, contract.Name, selector)
			b.db.Semantics.SetFunctionEffects(funcID, fe)
		}
	}
}

// analyzeFunctionEffects computes the effects of a single function.
func analyzeFunctionEffects(fn *types.Function) *types.FunctionEffects {
	fe := &types.FunctionEffects{}
	fe.Auth.Modifiers = append([]string(nil), fn.Modifiers...)

	if fn.AST != nil {
		walkAST(fn.AST, func(n *types.ASTNode) {
			switch n.Kind {
			case types.KindStmtAssign:
				if isStateVarAssign(n) {
					if name := lhsStateVar(n); name != "" {
						fe.StateWrites = append(fe.StateWrites, types.StateWrite{
							Var: name, Kind: assignKind(n), Line: n.StartLine,
						})
					}
				}
			case types.KindExprUnaryOp:
				if op, _ := n.Attributes["operator"].(string); op == "delete" {
					if name := firstStateVar(n); name != "" {
						fe.StateWrites = append(fe.StateWrites, types.StateWrite{
							Var: name, Kind: "delete", Line: n.StartLine,
						})
					}
				}
			case types.KindAsmSstore:
				fe.StateWrites = append(fe.StateWrites, types.StateWrite{
					Var: "<assembly sstore>", Kind: "sstore", Line: n.StartLine,
				})
			case types.KindCheckRequire:
				fe.Guards = append(fe.Guards, types.Guard{Kind: "require", Expr: conditionText(n), Line: n.StartLine})
			case types.KindCheckAssert:
				fe.Guards = append(fe.Guards, types.Guard{Kind: "assert", Expr: conditionText(n), Line: n.StartLine})
			case types.KindCheckRevert:
				fe.Guards = append(fe.Guards, types.Guard{Kind: "revert", Expr: conditionText(n), Line: n.StartLine})
			case types.KindStmtIf:
				fe.Guards = append(fe.Guards, types.Guard{Kind: "if", Expr: conditionText(n), Line: n.StartLine})
			}
		})
	}

	// Derive access-control facts from guard/condition text.
	for _, g := range fe.Guards {
		if strings.Contains(g.Expr, "msg.sender") {
			fe.Auth.SenderChecks = append(fe.Auth.SenderChecks, g.Expr)
		}
		if strings.Contains(g.Expr, "tx.origin") {
			fe.Auth.UsesTxOrigin = true
		}
	}
	fe.Auth.Controlled = len(fe.Auth.Modifiers) > 0 || len(fe.Auth.SenderChecks) > 0

	fe.StateWrites = dedupWrites(fe.StateWrites)
	return fe
}

// --- AST helpers ---

func walkAST(n *types.ASTNode, fn func(*types.ASTNode)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range n.Children {
		walkAST(c, fn)
	}
}

func isStateVarAssign(n *types.ASTNode) bool {
	if n.Attributes == nil {
		return false
	}
	v, ok := n.Attributes["is_state_var"].(bool)
	return ok && v
}

// assignKind returns "compound" for += and friends, else "assign".
func assignKind(n *types.ASTNode) string {
	if op, _ := n.Attributes["operator"].(string); op != "" && op != "=" {
		return "compound"
	}
	return "assign"
}

// lhsStateVar returns the state-variable name written by an assignment node,
// reading from its left-hand-side subtree (Children[0]).
func lhsStateVar(n *types.ASTNode) string {
	if len(n.Children) == 0 {
		return ""
	}
	return firstStateVar(n.Children[0])
}

// firstStateVar returns the name of the first state-var identifier in a subtree,
// falling back to the first identifier of any kind.
func firstStateVar(n *types.ASTNode) string {
	if n == nil {
		return ""
	}
	if n.Kind == types.KindExprIdentifier && n.RefKind == "state_var" {
		return n.Name
	}
	if d := n.FindDescendant(func(x *types.ASTNode) bool {
		return x.Kind == types.KindExprIdentifier && x.RefKind == "state_var"
	}); d != nil {
		return d.Name
	}
	if n.Kind == types.KindExprIdentifier {
		return n.Name
	}
	if d := n.FindDescendant(func(x *types.ASTNode) bool {
		return x.Kind == types.KindExprIdentifier
	}); d != nil {
		return d.Name
	}
	return ""
}

// conditionText renders the guarded condition of a require/assert/if/revert
// node. For require/assert the condition is the first child; for if the first
// child is the condition; for revert the whole argument is rendered.
func conditionText(n *types.ASTNode) string {
	switch n.Kind {
	case types.KindCheckRevert:
		if len(n.Children) > 0 {
			return astText(n.Children[0])
		}
		return ""
	default:
		if len(n.Children) > 0 {
			return astText(n.Children[0])
		}
		return ""
	}
}

// astText reconstructs a readable source-like string from an expression subtree.
// Interior nodes now carry StartLine (and StartCol/StartByte) via the builder's
// span chokepoints, but this renders the condition text from the AST shape
// itself rather than slicing source text, so formatting stays normalized
// regardless of the original source's whitespace/parenthesization.
func astText(n *types.ASTNode) string {
	if n == nil {
		return ""
	}
	switch n.Kind {
	case types.KindExprIdentifier:
		return n.Name
	case types.KindExprLiteral:
		if sub, _ := n.Attributes["subtype"].(string); sub == "string" {
			return "\"" + n.Value + "\""
		}
		if n.Value != "" {
			return n.Value
		}
		return n.Name
	case types.KindExprMemberAccess:
		base := ""
		if len(n.Children) > 0 {
			base = astText(n.Children[0])
		}
		if base == "" {
			if p, _ := n.Attributes["parent"].(string); p != "" {
				base = p
			}
		}
		if base != "" {
			return base + "." + n.Name
		}
		return n.Name
	case types.KindExprIndexAccess:
		base, idx := "", ""
		if len(n.Children) > 0 {
			base = astText(n.Children[0])
		}
		if len(n.Children) > 1 {
			idx = astText(n.Children[1])
		}
		return base + "[" + idx + "]"
	case types.KindExprBinaryOp:
		op, _ := n.Attributes["operator"].(string)
		l, r := "", ""
		if len(n.Children) > 0 {
			l = astText(n.Children[0])
		}
		if len(n.Children) > 1 {
			r = astText(n.Children[1])
		}
		return strings.TrimSpace(l + " " + op + " " + r)
	case types.KindExprUnaryOp:
		op, _ := n.Attributes["operator"].(string)
		o := ""
		if len(n.Children) > 0 {
			o = astText(n.Children[0])
		}
		return op + o
	case types.KindExprConditional:
		parts := childrenText(n)
		if len(parts) == 3 {
			return parts[0] + " ? " + parts[1] + " : " + parts[2]
		}
		return strings.Join(parts, " ")
	case types.KindExprTuple:
		return "(" + strings.Join(childrenText(n), ", ") + ")"
	default:
		// Calls: render receiver.name(args) or name(args).
		if strings.HasPrefix(n.Kind, "call.") {
			children := n.Children
			recv := ""
			if len(children) > 0 {
				if r, _ := children[0].Attributes["call_receiver"].(bool); r {
					recv = astText(children[0]) + "."
					children = children[1:]
				}
			}
			args := make([]string, 0, len(children))
			for _, c := range children {
				args = append(args, astText(c))
			}
			return recv + n.Name + "(" + strings.Join(args, ", ") + ")"
		}
		if n.Name != "" {
			return n.Name
		}
		return strings.Join(childrenText(n), " ")
	}
}

func childrenText(n *types.ASTNode) []string {
	out := make([]string, 0, len(n.Children))
	for _, c := range n.Children {
		out = append(out, astText(c))
	}
	return out
}

func dedupWrites(writes []types.StateWrite) []types.StateWrite {
	seen := make(map[string]bool)
	out := writes[:0]
	for _, w := range writes {
		// Include Line in the key: two writes to the same var at different
		// lines (`owner = a;` then `owner = b;`) are distinct events, and
		// collapsing them by (var, kind) alone discards line precision — the
		// retained StateWrite.Line would arbitrarily be the first occurrence.
		key := w.Var + "|" + w.Kind + "|" + strconv.Itoa(w.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, w)
	}
	return out
}
