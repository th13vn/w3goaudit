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
	if fn.IsEntrypoint() && isInitializerName(fn.Name) {
		fact.InitializerEntry = true
		fact.OneTimeMutex = fn.HasOneTimeInitGuardIn(db, contract)
		fact.ConstructorDisable = constructorDisablesInitializers(contract)
		switch {
		case fact.ConstructorDisable:
			fact.FirstCallTakeover = "not_applicable"
		case fact.OneTimeMutex:
			fact.FirstCallTakeover = "unknown"
			fact.Limitations = append(fact.Limitations, "deployment.lifecycle.unresolved")
		default:
			fact.FirstCallTakeover = "possible"
		}
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
	// A function may carry all of its authorization in an applied modifier while
	// its body is empty. Resolve the exact modifier body and preserve that evidence
	// instead of treating the modifier name as proof.
	for _, call := range fn.Calls {
		if call == nil || call.CallType != types.CallTypeModifier {
			continue
		}
		if !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
			fact.Verdict = types.AuthorizationUnknown
			fact.Limitations = append(fact.Limitations, types.DiagnosticIdentity)
			fact.Reasons = append(fact.Reasons, "modifier.unresolved")
			continue
		}
		owner := db.GetContractByID(call.ResolvedContractID)
		if owner == nil {
			fact.Verdict = types.AuthorizationUnknown
			fact.Limitations = append(fact.Limitations, types.DiagnosticIdentity)
			continue
		}
		for _, mod := range owner.Modifiers {
			if mod == nil || mod.Name != call.ResolvedFunction {
				continue
			}
			if candidate := findAuthorizationEvidence(mod.AST, fn, db); candidate != nil {
				candidate.evidence.GuardKind = "modifier"
				fact.Evidence = append(fact.Evidence, candidate.evidence)
				fact.Verdict = candidate.verdict
				fact.PrincipalKind = candidate.evidence.PrincipalKind
				fact.Principal = candidate.evidence.Principal
				fact.Dominance = candidate.evidence.Dominance
				fact.Reasons = append(fact.Reasons, "modifier.guard.proven")
			}
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
		} else if callerSelfScopeGuard(expr, fn, db) {
			principal = types.PrincipalCallerSelfScope
		} else {
			return
		}
		dominance := types.AuthorizationDominates
		if !isUnconditionalGuard(n, root) {
			dominance = types.AuthorizationPartial
		}
		verdict := types.AuthorizationProtected
		if dominance != types.AuthorizationDominates {
			verdict = types.AuthorizationUnknown
		}
		found = &authorizationCandidate{evidence: types.AuthorizationEvidence{GuardKind: "inline", GuardExpression: astText(expr), GuardRange: semanticRange(n, fn), PrincipalKind: principal, Principal: astText(expr), Dominance: dominance}, verdict: verdict}
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
	text := strings.ToLower(astText(expr))
	if !strings.Contains(text, "msg.sender") {
		return false
	}
	return strings.Contains(text, "owner") || strings.Contains(text, "admin") || strings.Contains(text, "role") || strings.Contains(text, "operator") || strings.Contains(text, "address(") || strings.Contains(text, "0x")
}

func isInitializerName(name string) bool {
	name = strings.ToLower(name)
	return name == "initialize" || name == "initialise" || name == "init" || name == "__init" || name == "setup"
}

func callerSelfScopeGuard(expr *types.ASTNode, fn *types.Function, db *types.Database) bool {
	if expr == nil {
		return false
	}
	if expr.Kind == types.KindExprBinaryOp {
		op := expr.GetAttributeString("operator")
		if (op == "==" || op == "!=") && len(expr.Children) >= 2 {
			return (containsCallerIdentity(expr.Children[0], fn, db) && !containsCallerIdentity(expr.Children[1], fn, db)) ||
				(containsCallerIdentity(expr.Children[1], fn, db) && !containsCallerIdentity(expr.Children[0], fn, db))
		}
	}
	for _, child := range expr.Children {
		if callerSelfScopeGuard(child, fn, db) {
			return true
		}
	}
	return false
}

func containsCallerIdentity(node *types.ASTNode, fn *types.Function, db *types.Database) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprMemberAccess && node.GetAttributeString("parent") == "msg" && node.Name == "sender" {
		return true
	}
	if node.Kind == types.KindExprIdentifier && fn != nil && strings.EqualFold(node.Name, "caller") {
		return true
	}
	for _, child := range node.Children {
		if containsCallerIdentity(child, fn, db) {
			return true
		}
	}
	return false
}

func constructorDisablesInitializers(contract *types.Contract) bool {
	if contract == nil {
		return false
	}
	for _, fn := range contract.Functions {
		if fn == nil || !fn.IsConstructor || fn.AST == nil {
			continue
		}
		found := false
		walkAST(fn.AST, func(n *types.ASTNode) {
			if n != nil && strings.Contains(strings.ToLower(n.Name), "disableinitializers") {
				found = true
			}
		})
		if found {
			return true
		}
	}
	return false
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
