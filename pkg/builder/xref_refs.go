package builder

import (
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// bindResolvedCallReferences (Phase 5 post-pass) sets RefID/RefKind on every
// AST call node whose call site the call graph resolved to an exact function.
// It reuses the resolution already computed into Function.Calls / Modifier.Calls
// (ResolvedContractID + ResolvedFunction, including library `using` calls via
// resolveLibraryCall), so member calls like `x.toUint128()` or `Lib.foo()` gain
// a precise go-to-definition target in xref.json without a second resolver.
//
// The AST call node and the call-graph edge share a source anchor: both take
// span(call).startByte from the same solast FunctionCall, so a call node is
// matched to its resolution by start byte. When two distinct targets share a
// byte (e.g. a super call recorded for multiple instantiation leaves) the
// occurrence is left unbound — precision over guessing.
func (b *Builder) bindResolvedCallReferences() {
	if b == nil || b.db == nil {
		return
	}
	for _, c := range b.db.Contracts {
		if c == nil {
			continue
		}
		for _, fn := range c.Functions {
			if fn != nil && fn.AST != nil {
				bindCallReferencesOnAST(fn.AST, fn.Calls)
			}
		}
		for _, mod := range c.Modifiers {
			if mod != nil && mod.AST != nil {
				bindCallReferencesOnAST(mod.AST, mod.Calls)
			}
		}
	}
}

// bindCallReferencesOnAST indexes resolved calls by start byte, then stamps the
// matching call nodes. A byte that resolves to more than one distinct target is
// dropped from the index so ambiguous sites stay unbound.
func bindCallReferencesOnAST(root *types.ASTNode, calls []*types.FunctionCall) {
	if root == nil {
		return
	}
	byteRefs := map[int]map[string]string{}
	for _, call := range calls {
		if call == nil || !call.Resolved || call.Byte <= 0 ||
			call.ResolvedContractID == "" || call.ResolvedFunction == "" ||
			call.CallType == types.CallTypeModifier {
			continue
		}
		refID := call.ResolvedContractID + "." + call.ResolvedFunction
		if byteRefs[call.Byte] == nil {
			byteRefs[call.Byte] = map[string]string{}
		}
		byteRefs[call.Byte][refID] = callRefKind(call.CallType)
	}
	if len(byteRefs) == 0 {
		return
	}
	var visit func(n *types.ASTNode)
	visit = func(n *types.ASTNode) {
		if n == nil {
			return
		}
		if n.RefID == "" && n.StartByte > 0 && strings.HasPrefix(n.Kind, "call.") {
			if refs := byteRefs[n.StartByte]; len(refs) == 1 {
				for refID, refKind := range refs {
					n.RefID = refID
					n.RefKind = refKind
				}
			}
		}
		for _, child := range n.Children {
			visit(child)
		}
	}
	visit(root)
}

// callRefKind maps a call type to the xref reference kind. Library `using`
// calls are surfaced as "library"; every other resolved call is "function".
func callRefKind(t types.CallType) string {
	if t == types.CallTypeLibrary {
		return "library"
	}
	return "function"
}
