package builder

import (
	"fmt"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func (b *Builder) analyzeAuthorization() {
	if b == nil || b.db == nil {
		return
	}
	if b.db.Semantics == nil {
		b.db.Semantics = types.NewSemanticFacts()
	}
	b.db.Semantics.AuthorizationFactsVersion = types.AuthorizationFactsVersion
	facts := make([]*types.AuthorizationFact, 0)
	for _, contract := range b.db.Contracts {
		if contract == nil {
			continue
		}
		for _, fn := range contract.Functions {
			if fn == nil {
				continue
			}
			selector := fn.Selector
			if selector == "" {
				selector = fn.Name
			}
			if fn.IsConstructor {
				selector = "constructor"
			}
			id := types.MakeFunctionID(contract.SourceFile, contract.Name, selector)
			fact := authorizationFactForFunction(fn, contract, b.db)
			fact.ID, fact.ContractID, fact.ScopeID, fact.ScopeKind, fact.FunctionID = id, contract.ID, id, "function", id
			facts = append(facts, fact)
		}
	}
	b.db.Semantics.AuthorizationFacts = types.NormalizeAuthorizationFacts(facts)
}

func authorizationFactForFunction(fn *types.Function, contract *types.Contract, db *types.Database) *types.AuthorizationFact {
	fact := &types.AuthorizationFact{
		Verdict: types.AuthorizationUnprotected, PrincipalKind: types.PrincipalUnknown,
		Dominance: types.AuthorizationUnknownDom, Reasons: []string{}, Limitations: []string{},
	}
	if fn == nil {
		fact.Verdict = types.AuthorizationUnknown
		fact.Reasons = append(fact.Reasons, "function.nil")
		return fact
	}
	fact.RuntimeContractID = contractID(contract)
	if fn.IsConstructor {
		fact.Reasons = append(fact.Reasons, "constructor.scope")
	}
	if fn.AST != nil {
		if authorization := findAuthorizationEvidence(fn.AST, fn, db); authorization != nil {
			fact.Evidence = []types.AuthorizationEvidence{authorization.evidence}
			fact.Verdict = authorization.verdict
			fact.PrincipalKind = authorization.evidence.PrincipalKind
			fact.Principal = authorization.evidence.Principal
			fact.Dominance = authorization.evidence.Dominance
			fact.Reasons = append(fact.Reasons, "guard.proven")
		}
	}
	for _, call := range fn.Calls {
		if call == nil || call.CallType != types.CallTypeModifier {
			continue
		}
		if !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
			fact.Verdict = types.AuthorizationUnknown
			fact.Limitations = append(fact.Limitations, types.DiagnosticIdentity)
			fact.Reasons = append(fact.Reasons, "modifier.unresolved")
		}
	}
	if fact.Verdict == types.AuthorizationUnprotected && fn.IsEntrypoint() {
		fact.Reasons = append(fact.Reasons, "guard.absent")
	}
	if fact.Verdict == types.AuthorizationUnprotected && !fn.IsEntrypoint() {
		fact.Verdict = types.AuthorizationUnknown
		fact.Reasons = append(fact.Reasons, "non_entry_scope")
	}
	return fact
}

type authorizationCandidate struct {
	evidence types.AuthorizationEvidence
	verdict  types.AuthorizationVerdict
}

func (c authorizationCandidate) Verdict() types.AuthorizationVerdict { return c.verdict }

func findAuthorizationEvidence(root *types.ASTNode, fn *types.Function, db *types.Database) *authorizationCandidate {
	var found *authorizationCandidate
	walkAST(root, func(n *types.ASTNode) {
		if found != nil || n == nil || (n.Kind != types.KindCheckRequire && n.Kind != types.KindCheckAssert && n.Kind != types.KindStmtIf) {
			return
		}
		if len(n.Children) == 0 {
			return
		}
		expr := n.Children[0]
		principal := types.PrincipalUnknown
		if privilegedGuard(expr, fn, db) {
			principal = principalFromExpr(expr)
		} else if fn.ComparesCallerIdentity(db) {
			principal = types.PrincipalCallerSelfScope
		} else {
			return
		}
		dominance := types.AuthorizationDominates
		if !isUnconditionalGuard(n, root) {
			dominance = types.AuthorizationPartial
		}
		found = &authorizationCandidate{evidence: types.AuthorizationEvidence{GuardKind: "inline", GuardExpression: astText(expr), GuardRange: semanticRange(n, fn), PrincipalKind: principal, Principal: astText(expr), Dominance: dominance}, verdict: types.AuthorizationProtected}
		if principal == types.PrincipalCallerSelfScope {
			found.verdict = types.AuthorizationSelfScoped
		}
	})
	return found
}

func isUnconditionalGuard(node, root *types.ASTNode) bool {
	for current := node.Parent; current != nil && current != root; current = current.Parent {
		switch current.Kind {
		case types.KindStmtIf, types.KindStmtLoop, types.KindExprConditional, types.KindStmtTryCatch:
			return false
		}
	}
	return true
}

func privilegedGuard(expr *types.ASTNode, fn *types.Function, db *types.Database) bool {
	if expr == nil {
		return false
	}
	return strings.Contains(astText(expr), "msg.sender") && fn.IsAccessControlledIn(db, nil)
}

func principalFromExpr(expr *types.ASTNode) types.AuthorizationPrincipalKind {
	text := strings.ToLower(astText(expr))
	if strings.Contains(text, "role") || strings.Contains(text, "operator") {
		return types.PrincipalRole
	}
	if strings.Contains(text, "owner") || strings.Contains(text, "admin") {
		return types.PrincipalOwner
	}
	if strings.Contains(text, "address(") || strings.Contains(text, "0x") {
		return types.PrincipalFixedAddress
	}
	return types.PrincipalUnknown
}

func semanticRange(n *types.ASTNode, fn *types.Function) types.SemanticSourceRange {
	file := ""
	if fn != nil {
		file = fn.SourceFile
	}
	return types.SemanticSourceRange{File: file, StartLine: n.StartLine, StartCol: n.StartCol, EndLine: n.EndLine, EndCol: n.EndCol, StartByte: n.StartByte, EndByte: n.EndByte}
}

func contractID(c *types.Contract) string {
	if c == nil {
		return ""
	}
	if c.ID != "" {
		return c.ID
	}
	return fmt.Sprintf("%s#%s", c.SourceFile, c.Name)
}
