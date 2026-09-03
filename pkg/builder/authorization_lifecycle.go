package builder

import (
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func populateInitializerLifecycle(fact *types.AuthorizationFact, fn *types.Function, contract *types.Contract, db *types.Database) {
	if fact == nil || fn == nil {
		return
	}
	if fn.IsConstructor {
		fact.Reasons = append(fact.Reasons, "constructor.scope")
	}
	if !fn.IsEntrypoint() || !isInitializerName(fn.Name) {
		return
	}
	fact.InitializerEntry = true
	fact.OneTimeMutex = fn.HasOneTimeInitGuardIn(db, contract)
	fact.ConstructorDisable = constructorDisablesInitializers(contract)
	fact.AtomicInitialization = initializerAtomicity(fn)
	// Proxy/implementation linkage is intentionally unknown until exact static
	// deployment or storage evidence connects two contract identities. Names in
	// the inheritance list are not linkage proof.
	fact.ProxyLinkage = "unknown"
	switch {
	case fact.ConstructorDisable:
		fact.FirstCallTakeover = "unknown"
		fact.Limitations = append(fact.Limitations, "deployment.proxy_linkage.unresolved")
	case fact.OneTimeMutex:
		fact.FirstCallTakeover = "unknown"
		fact.Limitations = append(fact.Limitations, "deployment.lifecycle.unresolved")
	default:
		fact.FirstCallTakeover = "possible"
	}
}

func initializerAtomicity(fn *types.Function) string {
	if fn == nil || fn.AST == nil {
		return "unknown"
	}
	var firstWrite, guard *types.ASTNode
	walkAST(fn.AST, func(n *types.ASTNode) {
		if n == nil {
			return
		}
		if guard == nil && (n.Kind == types.KindCheckRequire || n.Kind == types.KindCheckAssert || n.Kind == types.KindStmtIf) {
			guard = n
		}
		if firstWrite == nil && n.Kind == types.KindStmtAssign && n.GetAttributeBool("is_state_var") {
			firstWrite = n
		}
	})
	if guard == nil || firstWrite == nil {
		return "unknown"
	}
	if sourceNodeBefore(firstWrite, guard) {
		return "before_guard"
	}
	return "after_guard"
}

func isInitializerName(name string) bool {
	name = strings.ToLower(name)
	return name == "initialize" || name == "initialise" || name == "init" || name == "__init" || name == "setup"
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
			if n != nil && n.Name == "_disableInitializers" && strings.HasPrefix(n.Kind, "call.") {
				found = true
			}
		})
		if found {
			return true
		}
	}
	return false
}
