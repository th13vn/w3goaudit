package builder

import (
	"fmt"

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
			id := authorizationFunctionID(fn, contract)
			fact := authorizationFactForFunction(fn, contract, b.db)
			fact.ID, fact.ContractID = id, contract.ID
			fact.ScopeID, fact.ScopeKind, fact.FunctionID = id, "function", id
			facts = append(facts, fact)
		}
	}
	b.db.Semantics.AuthorizationFacts = types.NormalizeAuthorizationFacts(facts)
}

func authorizationFactForFunction(fn *types.Function, declared *types.Contract, db *types.Database) *types.AuthorizationFact {
	fact := newAuthorizationFact()
	if fn == nil {
		fact.Verdict = types.AuthorizationUnknown
		fact.Reasons = append(fact.Reasons, "function.nil")
		return fact
	}

	populateInitializerLifecycle(fact, fn, declared, db)
	runtime, selected, ambiguous := resolveAuthorizationRuntime(fn, declared, db)
	var result authorizationResult
	if ambiguous {
		// Several main contracts inherit the declaration. Their verdicts are
		// used only when they all agree; RuntimeContractID stays empty because
		// no single runtime exists.
		agreed, agreedSelected, ok := agreedAuthorizationAcrossRuntimes(fn, declared, db)
		if !ok {
			fact.Verdict = types.AuthorizationUnknown
			fact.Reasons = append(fact.Reasons, "runtime.alternatives.ambiguous")
			fact.Limitations = append(fact.Limitations, types.DiagnosticIdentity)
			return fact
		}
		result, selected = agreed, agreedSelected
		result.reasons = append(result.reasons, "runtime.alternatives.agree")
	} else {
		if runtime == nil {
			runtime = declared
		}
		fact.RuntimeContractID = contractID(runtime)
		if selected == nil {
			selected = fn
		}
		result = analyzeAuthorizationTarget(selected, runtime, db, make(map[string]bool))
	}
	if selected != fn {
		fact.SelectedFunctionID = authorizationFunctionID(selected, nil)
		result = result.withGuardKind("virtual_override")
		result.reasons = append(result.reasons, "runtime.override.proven")
	}
	applyAuthorizationResult(fact, result)

	if fact.Verdict == types.AuthorizationUnprotected && fn.IsEntrypoint() {
		fact.Reasons = append(fact.Reasons, "guard.absent")
	}
	if fact.Verdict == types.AuthorizationUnprotected && !fn.IsEntrypoint() {
		fact.Verdict = types.AuthorizationUnknown
		fact.Reasons = append(fact.Reasons, "non_entry_scope")
	}
	return fact
}

func newAuthorizationFact() *types.AuthorizationFact {
	return &types.AuthorizationFact{
		Verdict:       types.AuthorizationUnprotected,
		PrincipalKind: types.PrincipalUnknown,
		Dominance:     types.AuthorizationUnknownDom,
		Evidence:      []types.AuthorizationEvidence{},
		Reasons:       []string{},
		Limitations:   []string{},
	}
}

func applyAuthorizationResult(fact *types.AuthorizationFact, result authorizationResult) {
	if fact == nil {
		return
	}
	if len(result.evidence) > 0 {
		fact.Evidence = append(fact.Evidence, result.evidence...)
		fact.PrincipalKind = result.evidence[0].PrincipalKind
		fact.Principal = result.evidence[0].Principal
		fact.Dominance = result.evidence[0].Dominance
		if fact.PrincipalKind == types.PrincipalExpectedExternal {
			fact.ExpectedPrincipal = result.evidence[0].Principal
			fact.ExpectedPrincipalRefIDs = append([]string(nil), result.evidence[0].RefIDs...)
		}
	}
	if result.selectedFunctionID != "" {
		fact.SelectedFunctionID = result.selectedFunctionID
	}
	if result.verdict != "" {
		fact.Verdict = result.verdict
	}
	fact.Reasons = append(fact.Reasons, result.reasons...)
	fact.Limitations = append(fact.Limitations, result.limitations...)
}

func authorizationFunctionID(fn *types.Function, fallback *types.Contract) string {
	if fn == nil {
		return ""
	}
	selector := fn.Selector
	if selector == "" {
		selector = fn.Name
	}
	if fn.IsConstructor {
		selector = "constructor"
	}
	file, contractName := fn.SourceFile, fn.ContractName
	if fallback != nil {
		if file == "" {
			file = fallback.SourceFile
		}
		if contractName == "" {
			contractName = fallback.Name
		}
	}
	return types.MakeFunctionID(file, contractName, selector)
}

func semanticRange(n *types.ASTNode, fn *types.Function) types.SemanticSourceRange {
	file := ""
	if fn != nil {
		file = fn.SourceFile
	}
	return types.SemanticSourceRange{
		File: file, StartLine: n.StartLine, StartCol: n.StartCol,
		EndLine: n.EndLine, EndCol: n.EndCol, StartByte: n.StartByte, EndByte: n.EndByte,
	}
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
