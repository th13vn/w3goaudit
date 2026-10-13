package builder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

type authorizationResult struct {
	evidence           []types.AuthorizationEvidence
	verdict            types.AuthorizationVerdict
	selectedFunctionID string
	reasons            []string
	limitations        []string
}

type authorizationBinding struct {
	kind       types.AuthorizationPrincipalKind
	principal  string
	refIDs     []string
	authorizes bool
	// identity marks a binding to caller identity itself (msg.sender or
	// _msgSender()). PrincipalCallerSelfScope also covers any caller-selected
	// value, which may be compared against a principal but can never stand in
	// for the caller: `_checkAdmin(user)` with `require(a == admin)` proves
	// nothing when the caller chooses user.
	identity bool
}

type authorizationBindings struct {
	values map[string]authorizationBinding
	// predicateDepth counts how many predicate helpers (see
	// predicateHelperEvidence) the current expression is nested in. It is not
	// part of key(): it only bounds recursion.
	predicateDepth int
}

func authorizationParameterRefID(fn *types.Function, parameter *types.Parameter) string {
	if fn == nil || parameter == nil || parameter.Name == "" {
		return ""
	}
	return authorizationFunctionID(fn, nil) + "." + parameter.Name
}

func modifierParameterRefID(owner *types.Contract, modifier *types.Modifier, parameter *types.Parameter) string {
	if owner == nil || modifier == nil || parameter == nil || parameter.Name == "" {
		return ""
	}
	return types.MakeModifierID(owner.SourceFile, owner.Name, modifier.Name) + "." + parameter.Name
}

func (bindings authorizationBindings) lookup(node *types.ASTNode) (authorizationBinding, bool) {
	if node == nil || node.Kind != types.KindExprIdentifier || node.RefKind != "parameter" {
		return authorizationBinding{}, false
	}
	binding, ok := bindings.values[node.RefID]
	return binding, ok
}

func (bindings authorizationBindings) key() string {
	keys := make([]string, 0, len(bindings.values))
	for refID, binding := range bindings.values {
		keys = append(keys, fmt.Sprintf("%s=%s:%t:%t:%s", refID, binding.kind, binding.authorizes, binding.identity, strings.Join(binding.refIDs, ",")))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

func (r authorizationResult) withGuardKind(kind string) authorizationResult {
	if kind == "" {
		return r
	}
	for i := range r.evidence {
		r.evidence[i].GuardKind = kind
	}
	return r
}

func analyzeAuthorizationTarget(fn *types.Function, runtime *types.Contract, db *types.Database, visiting map[string]bool) authorizationResult {
	return analyzeAuthorizationTargetWithBindings(fn, runtime, db, visiting, authorizationBindings{})
}

func analyzeAuthorizationTargetWithBindings(fn *types.Function, runtime *types.Contract, db *types.Database, visiting map[string]bool, bindings authorizationBindings) authorizationResult {
	if fn == nil {
		return unknownAuthorizationResult("function.unresolved")
	}
	key := contractID(runtime) + "|" + authorizationFunctionID(fn, nil) + "|" + bindings.key()
	if visiting[key] {
		return unknownAuthorizationResult("helper.cycle")
	}
	visiting[key] = true
	defer delete(visiting, key)

	var unknown *authorizationResult
	for _, call := range fn.Calls {
		if call == nil || call.CallType != types.CallTypeModifier {
			continue
		}
		result := authorizationFromModifier(call, fn, runtime, db, bindings, visiting)
		if result.verdict == types.AuthorizationProtected || result.verdict == types.AuthorizationSelfScoped {
			return result
		}
		if result.verdict == types.AuthorizationUnknown {
			copy := result
			unknown = &copy
		}
	}

	if candidate := findAuthorizationEvidence(fn.AST, fn, runtime, db, bindings); candidate != nil {
		return authorizationResult{
			evidence: []types.AuthorizationEvidence{candidate.evidence},
			verdict:  candidate.verdict,
			reasons:  []string{"guard.proven"},
		}
	}

	for _, call := range fn.Calls {
		if call == nil || !isAuthorizationInternalCall(call.CallType) {
			continue
		}
		callee, kind := resolveAuthorizationCallee(call, runtime, db)
		if callee == nil {
			// Function-call metadata also records custom-error constructors and
			// ordinary internal helpers. An unresolved call is an authorization
			// blocker only when its name plausibly denotes a guard. Ignore
			// unrelated business/error calls so lifecycle and callback analysis do
			// not become unknown merely because a revert payload has no function
			// declaration in the database.
			if !authorizationCallNameSuggestsGuard(call.Target) || isRevertPayloadCall(fn, call) {
				continue
			}
			result := unknownAuthorizationResult("helper.unresolved")
			unknown = &result
			continue
		}
		callNode := exactAuthorizationCallNode(fn, call)
		if callNode == nil {
			result := unknownAuthorizationResult("helper.callsite.unresolved")
			unknown = &result
			continue
		}
		calleeBindings, bindingReason := bindAuthorizationFunctionParameters(callee, solidityAuthorizationArgs(callNode), fn, db, bindings)
		if bindingReason != "" {
			// An unguarded helper does not become an authorization barrier just
			// because its ordinary business arguments cannot be classified. Keep
			// the caller's result explicitly unprotected so entrypoint detectors
			// can continue through wrappers such as settle(...). Helpers that do
			// contain an authorization guard remain fail-closed below.
			if !hasAuthorizationGuard(callee, db, calleeBindings) && !authorizationCalleeOverloaded(callee, db) {
				continue
			}
			result := unknownAuthorizationResult(kind + ".binding." + bindingReason)
			result.selectedFunctionID = authorizationFunctionID(callee, nil)
			unknown = &result
			continue
		}
		result := analyzeAuthorizationTargetWithBindings(callee, runtime, db, visiting, calleeBindings).withGuardKind(kind)
		result.selectedFunctionID = authorizationFunctionID(callee, nil)
		result = constrainResultByCallsite(result, callNode, fn.AST)
		if result.verdict == types.AuthorizationProtected || result.verdict == types.AuthorizationSelfScoped {
			result.reasons = append(result.reasons, kind+".guard.proven")
			return result
		}
		if result.verdict == types.AuthorizationUnknown {
			copy := result
			unknown = &copy
			continue
		}
		if authorizationBindingsContainCallerSelected(calleeBindings) && (hasAuthorizationGuard(callee, db, calleeBindings) || authorizationCalleeOverloaded(callee, db)) {
			result = unknownAuthorizationBindingResult(kind + ".binding.caller_selected")
			result.selectedFunctionID = authorizationFunctionID(callee, nil)
			unknown = &result
		}
	}
	if unknown != nil {
		return *unknown
	}
	return authorizationResult{verdict: types.AuthorizationUnprotected}
}

// isRevertPayloadCall reports whether an unresolved call record is a payload
// rather than a helper: the custom error of a `revert Error(...)` statement,
// which the AST keeps as a check.revert node named after the error, or the
// event of an `emit Event(...)` statement, a call node directly under
// stmt.emit. OpenZeppelin's `revert ERC20InvalidSender(address(0))` and an
// `emit RoleSet(...)` would otherwise pass the guard-name test on "sender" or
// "role" and turn the function's authorization unknown, hiding exactly the
// unguarded role or ownership setters that negated presets exist to find.
func isRevertPayloadCall(fn *types.Function, call *types.FunctionCall) bool {
	sameLine := func(node *types.ASTNode) bool {
		return call.Line == 0 || node.StartLine == 0 || node.StartLine == call.Line
	}
	found := false
	walkAST(fn.AST, func(node *types.ASTNode) {
		if node == nil || found {
			return
		}
		switch node.Kind {
		case types.KindCheckRevert:
			found = node.Name == call.Target && sameLine(node)
		case types.KindStmtEmit:
			for _, child := range node.Children {
				if child != nil && strings.HasPrefix(child.Kind, "call.") && child.Name == call.Target && sameLine(child) {
					found = true
				}
			}
		}
	})
	return found
}

func authorizationCallNameSuggestsGuard(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	// Unresolved business helpers must not turn an otherwise unprotected
	// function into an unavailable authorization fact. Keep the fallback
	// vocabulary focused on principal/guard nouns; broad verbs such as
	// `check`, `validate`, and `verify` also describe ordinary balance, input,
	// and signature helpers and therefore are not sufficient on their own.
	for _, token := range []string{"auth", "owner", "admin", "role", "access", "permission", "principal", "sender", "caller", "guard", "enforce", "require"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

// hasAuthorizationGuard distinguishes an unguarded helper that merely forwards
// a caller-selected value from an authorization helper whose proof became
// ambiguous after binding a caller-selected principal or role. The former must
// remain explicitly unprotected so entrypoint-level detectors can follow the
// tainted value through the helper; the latter must fail closed.
func hasAuthorizationGuard(fn *types.Function, db *types.Database, bindings authorizationBindings) bool {
	if fn == nil || fn.AST == nil {
		return false
	}
	found := false
	walkAST(fn.AST, func(node *types.ASTNode) {
		if found || node == nil {
			return
		}
		expr, _, enforced := enforcedAuthorizationCondition(node)
		if !enforced || expr == nil {
			return
		}
		found = authorizationExpressionLooksLikeGuard(expr, fn, db, bindings)
	})
	return found
}

// authorizationExpressionLooksLikeGuard distinguishes access-control-shaped
// conditions from ordinary business checks. A generic require(ok) proves only
// external-call success, not caller authorization. Role mappings and caller
// identity comparisons remain authorization-shaped even when parameter binding
// is incomplete, so ambiguous helpers still fail closed.
func authorizationExpressionLooksLikeGuard(expr *types.ASTNode, fn *types.Function, db *types.Database, bindings authorizationBindings) bool {
	if expr == nil {
		return false
	}
	if binding, ok := bindings.lookup(expr); ok && binding.authorizes {
		return true
	}
	if containsExactCallerIdentity(expr) {
		return true
	}
	if expr.Kind == types.KindExprIndexAccess {
		base, keys := flattenAuthorizationIndex(expr)
		if base != nil && base.RefKind == "state_var" && types.IsAccessControlName(base.Name) {
			for _, key := range keys {
				if isExactCallerIdentity(key) {
					return true
				}
				if binding, ok := bindings.lookup(key); ok && binding.kind == types.PrincipalCallerSelfScope {
					return true
				}
			}
		}
	}
	for _, child := range expr.Children {
		if authorizationExpressionLooksLikeGuard(child, fn, db, bindings) {
			return true
		}
	}
	return false
}

func authorizationCalleeOverloaded(fn *types.Function, db *types.Database) bool {
	if fn == nil || db == nil || fn.Name == "" {
		return false
	}
	owner := db.GetContractByID(types.MakeContractID(fn.SourceFile, fn.ContractName))
	if owner == nil {
		return false
	}
	count := 0
	for _, candidate := range owner.Functions {
		if candidate != nil && candidate.Name == fn.Name {
			count++
		}
	}
	return count > 1
}

func authorizationFromModifier(call *types.FunctionCall, invokingFn *types.Function, runtime *types.Contract, db *types.Database, callerBindings authorizationBindings, visiting map[string]bool) authorizationResult {
	if call == nil || db == nil || !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
		return unknownAuthorizationResult("modifier.unresolved")
	}
	owner := db.GetContractByID(call.ResolvedContractID)
	if owner == nil {
		return unknownAuthorizationResult("modifier.unresolved")
	}
	for _, modifier := range owner.Modifiers {
		if modifier == nil || modifier.Name != call.ResolvedFunction {
			continue
		}
		synthetic := &types.Function{
			Name: modifier.Name, ContractName: owner.Name, SourceFile: owner.SourceFile,
			Parameters: modifier.Parameters, Calls: modifier.Calls, AST: modifier.AST,
		}
		parameterRefIDs := make([]string, len(modifier.Parameters))
		for i, parameter := range modifier.Parameters {
			parameterRefIDs[i] = modifierParameterRefID(owner, modifier, parameter)
		}
		bindings, bindingReason := bindAuthorizationParameters(modifier.Parameters, parameterRefIDs, call.Arguments, invokingFn, db, callerBindings)
		if bindingReason != "" {
			return unknownAuthorizationResult("modifier.binding." + bindingReason)
		}
		result := analyzeAuthorizationTargetWithBindings(synthetic, runtime, db, visiting, bindings)
		if len(result.evidence) == 0 {
			if authorizationBindingsContainCallerSelected(bindings) && !modifierValidatesInputOnly(synthetic, db, bindings) {
				return unknownAuthorizationBindingResult("modifier.binding.caller_selected")
			}
			return result
		}
		if modifierGuardAfterPlaceholderRange(modifierGuardPosition(result, synthetic, runtime, db), modifier.AST) {
			for i := range result.evidence {
				result.evidence[i].Dominance = types.AuthorizationAfterSite
			}
			result.verdict = types.AuthorizationUnknown
		}
		result = result.withGuardKind("modifier")
		result.selectedFunctionID = ""
		result.reasons = []string{"modifier.guard.proven"}
		return result
	}
	return unknownAuthorizationResult("modifier.unresolved")
}

// modifierValidatesInputOnly reports whether a modifier that received a
// caller-selected argument is plain input validation, such as a Uniswap
// router's `ensure(deadline)`: no authorization-shaped condition in its body
// and no call at all (a custom-error revert payload aside), so no helper can
// hide a guard. Such a modifier is not an authorization barrier, matching how
// unguarded helpers are treated. A modifier that calls anything, like Euler's
// `onlyOwnerOrOperator(account)`, still fails closed.
func modifierValidatesInputOnly(modifier *types.Function, db *types.Database, bindings authorizationBindings) bool {
	if hasAuthorizationGuard(modifier, db, bindings) {
		return false
	}
	for _, call := range modifier.Calls {
		if call != nil && !isRevertPayloadCall(modifier, call) {
			return false
		}
	}
	return true
}

func authorizationBindingsContainCallerSelected(bindings authorizationBindings) bool {
	for _, binding := range bindings.values {
		if binding.kind == types.PrincipalCallerSelfScope {
			return true
		}
	}
	return false
}

func unknownAuthorizationResult(reason string) authorizationResult {
	return authorizationResult{
		verdict: types.AuthorizationUnknown, reasons: []string{reason},
		limitations: []string{types.DiagnosticIdentity},
	}
}

func unknownAuthorizationBindingResult(reason string) authorizationResult {
	return authorizationResult{
		verdict: types.AuthorizationUnknown, reasons: []string{reason},
		limitations: []string{types.AuthorizationLimitationCallerSelected, types.DiagnosticIdentity},
	}
}

func bindAuthorizationFunctionParameters(callee *types.Function, args []*types.ASTNode, caller *types.Function, db *types.Database, callerBindings authorizationBindings) (authorizationBindings, string) {
	if callee == nil {
		return authorizationBindings{}, "unresolved"
	}
	parameterRefIDs := make([]string, len(callee.Parameters))
	for i, parameter := range callee.Parameters {
		parameterRefIDs[i] = authorizationParameterRefID(callee, parameter)
	}
	return bindAuthorizationParameters(callee.Parameters, parameterRefIDs, args, caller, db, callerBindings)
}

func bindAuthorizationParameters(parameters []*types.Parameter, parameterRefIDs []string, args []*types.ASTNode, caller *types.Function, db *types.Database, callerBindings authorizationBindings) (authorizationBindings, string) {
	if len(parameters) != len(args) || len(parameters) != len(parameterRefIDs) {
		return authorizationBindings{}, "arity_mismatch"
	}
	bindings := authorizationBindings{values: make(map[string]authorizationBinding, len(parameters))}
	for i, parameter := range parameters {
		if parameter == nil || args[i] == nil {
			return authorizationBindings{}, "unresolved"
		}
		// An unnamed parameter, as in OpenZeppelin's
		// `function _authorizeUpgrade(address) internal override onlyOwner {}`,
		// cannot be read, so nothing in the body depends on its binding.
		if parameter.Name == "" {
			continue
		}
		if parameterRefIDs[i] == "" {
			return authorizationBindings{}, "unresolved"
		}
		binding := classifyAuthorizationArgument(args[i], caller, db, callerBindings)
		if binding.kind == types.PrincipalUnknown {
			return authorizationBindings{}, "unresolved"
		}
		bindings.values[parameterRefIDs[i]] = binding
	}
	return bindings, ""
}

func classifyAuthorizationArgument(arg *types.ASTNode, caller *types.Function, db *types.Database, callerBindings authorizationBindings) authorizationBinding {
	if arg == nil {
		return authorizationBinding{kind: types.PrincipalUnknown}
	}
	if binding, ok := callerBindings.lookup(arg); ok {
		return binding
	}
	if isExactCallerIdentity(arg) || isCallerIdentityAlias(arg, caller) {
		return authorizationBinding{kind: types.PrincipalCallerSelfScope, principal: astText(arg), identity: true}
	}
	if refs, ok := authorizationRoleRefs(arg, caller, db, callerBindings); ok {
		return authorizationBinding{
			kind: types.PrincipalRole, principal: astText(arg),
			refIDs: refs, authorizes: true,
		}
	}
	kind, principal, refs := classifyPrincipalEvidence(arg, caller, db, callerBindings)
	return authorizationBinding{kind: kind, principal: principal, refIDs: refs}
}

func solidityAuthorizationArgs(call *types.ASTNode) []*types.ASTNode {
	if call == nil {
		return nil
	}
	args := make([]*types.ASTNode, 0, len(call.Children))
	for _, child := range call.Children {
		if child == nil || child.GetAttributeBool("call_receiver") || child.GetAttributeString("call_option") != "" {
			continue
		}
		args = append(args, child)
	}
	return args
}

func isAuthorizationInternalCall(callType types.CallType) bool {
	switch callType {
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSelf, types.CallTypeSuper:
		return true
	default:
		return false
	}
}

func constrainResultByCallsite(result authorizationResult, callNode, root *types.ASTNode) authorizationResult {
	if len(result.evidence) == 0 {
		return result
	}
	dominance := authorizationDominance(callNode, root)
	if dominance == types.AuthorizationDominates {
		return result
	}
	for i := range result.evidence {
		result.evidence[i].Dominance = dominance
	}
	result.verdict = types.AuthorizationUnknown
	return result
}

func exactAuthorizationCallNode(fn *types.Function, call *types.FunctionCall) *types.ASTNode {
	if fn == nil || fn.AST == nil || call == nil {
		return nil
	}
	var exact, line, named []*types.ASTNode
	walkAST(fn.AST, func(node *types.ASTNode) {
		if node == nil || !strings.HasPrefix(node.Kind, "call.") || node.Name != call.Target {
			return
		}
		named = append(named, node)
		if node.StartByte > 0 && call.Byte > 0 && node.StartByte == call.Byte {
			exact = append(exact, node)
		}
		if node.StartLine > 0 && call.Line > 0 && node.StartLine == call.Line {
			line = append(line, node)
		}
	})
	if len(exact) == 1 {
		return exact[0]
	}
	if len(exact) > 1 {
		return nil
	}
	if len(line) == 1 {
		return line[0]
	}
	if len(line) > 1 {
		return nil
	}
	if call.Byte == 0 && call.Line == 0 && len(named) == 1 {
		return named[0]
	}
	return nil
}

type authorizationCandidate struct {
	node     *types.ASTNode
	evidence types.AuthorizationEvidence
	verdict  types.AuthorizationVerdict
}

func findAuthorizationEvidence(root *types.ASTNode, fn *types.Function, runtime *types.Contract, db *types.Database, bindings authorizationBindings) *authorizationCandidate {
	if root == nil {
		return nil
	}
	var best *authorizationCandidate
	walkAST(root, func(node *types.ASTNode) {
		if node == nil {
			return
		}
		expr, wantTrue, enforced := enforcedAuthorizationCondition(node)
		if !enforced {
			return
		}
		candidate := authorizationCandidateForExpression(expr, wantTrue, node, root, fn, runtime, db, bindings)
		if candidate == nil {
			return
		}
		if best == nil || authorizationCandidateRank(candidate) > authorizationCandidateRank(best) {
			best = candidate
		}
	})
	return best
}

func enforcedAuthorizationCondition(node *types.ASTNode) (expr *types.ASTNode, wantTrue, enforced bool) {
	if node == nil || len(node.Children) == 0 {
		return nil, false, false
	}
	switch node.Kind {
	case types.KindCheckRequire, types.KindCheckAssert:
		return node.Children[0], true, true
	case types.KindStmtIf:
		if len(node.Children) < 2 {
			return nil, false, false
		}
		thenReverts := authorizationBranchReverts(node.Children[1])
		elseReverts := len(node.Children) > 2 && authorizationBranchReverts(node.Children[2])
		if thenReverts == elseReverts {
			return nil, false, false
		}
		return node.Children[0], elseReverts, true
	default:
		return nil, false, false
	}
}

func authorizationBranchReverts(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindCheckRevert {
		return true
	}
	if node.Kind == types.KindStmtBlock || node.Kind == types.KindStmtUnchecked {
		return len(node.Children) > 0 && authorizationBranchReverts(node.Children[len(node.Children)-1])
	}
	if node.Kind == types.KindStmtIf && len(node.Children) > 2 {
		return authorizationBranchReverts(node.Children[1]) && authorizationBranchReverts(node.Children[2])
	}
	return false
}

func authorizationCandidateForExpression(expr *types.ASTNode, wantTrue bool, guard, root *types.ASTNode, fn *types.Function, runtime *types.Contract, db *types.Database, bindings authorizationBindings) *authorizationCandidate {
	if expr == nil {
		return nil
	}
	if binding, ok := bindings.lookup(expr); ok && binding.authorizes && wantTrue {
		dominance := authorizationDominance(guard, root)
		verdict := types.AuthorizationProtected
		if dominance != types.AuthorizationDominates {
			verdict = types.AuthorizationUnknown
		}
		return &authorizationCandidate{
			node: guard, verdict: verdict,
			evidence: types.AuthorizationEvidence{
				GuardKind: "inline", GuardExpression: astText(guard.Children[0]), GuardRange: semanticRange(guard, fn),
				PrincipalKind: binding.kind, Principal: binding.principal, RefIDs: append([]string(nil), binding.refIDs...), Dominance: dominance,
			},
		}
	}
	if role := roleMembershipEvidence(expr, wantTrue, guard, root, fn, db, bindings); role != nil {
		return role
	}
	if helper := predicateHelperEvidence(expr, wantTrue, guard, root, fn, runtime, db, bindings); helper != nil {
		return helper
	}
	if expr.Kind == types.KindExprUnaryOp && expr.GetAttributeString("operator") == "!" && len(expr.Children) > 0 {
		return authorizationCandidateForExpression(expr.Children[0], !wantTrue, guard, root, fn, runtime, db, bindings)
	}
	if expr.Kind == types.KindExprBinaryOp && len(expr.Children) >= 2 {
		op := expr.GetAttributeString("operator")
		if op == "||" && wantTrue {
			// An OR guard is only an authorization proof when every branch is
			// independently authorization-bearing. A privileged principal OR a
			// caller-controlled value (for example balances[msg.sender] > 0)
			// must not be treated as access control merely because one branch is
			// valid. Keep the conservative verdict when either branch is partial
			// or unavailable.
			left := authorizationCandidateForExpression(expr.Children[0], true, guard, root, fn, runtime, db, bindings)
			right := authorizationCandidateForExpression(expr.Children[1], true, guard, root, fn, runtime, db, bindings)
			if left == nil || right == nil {
				return nil
			}
			if left.verdict == types.AuthorizationProtected && right.verdict == types.AuthorizationProtected {
				return left
			}
			if left.verdict == types.AuthorizationSelfScoped && right.verdict == types.AuthorizationSelfScoped {
				return left
			}
			return &authorizationCandidate{node: guard, verdict: types.AuthorizationUnknown, evidence: left.evidence}
		}
		if op == "&&" && wantTrue {
			if left := authorizationCandidateForExpression(expr.Children[0], true, guard, root, fn, runtime, db, bindings); left != nil {
				return left
			}
			return authorizationCandidateForExpression(expr.Children[1], true, guard, root, fn, runtime, db, bindings)
		}
		if op == "||" && !wantTrue {
			if left := authorizationCandidateForExpression(expr.Children[0], false, guard, root, fn, runtime, db, bindings); left != nil {
				return left
			}
			return authorizationCandidateForExpression(expr.Children[1], false, guard, root, fn, runtime, db, bindings)
		}
		if op == "==" || op == "!=" {
			equalityRequired := (op == "==" && wantTrue) || (op == "!=" && !wantTrue)
			if !equalityRequired {
				return nil
			}
			if candidate := callerComparisonEvidence(expr.Children[0], expr.Children[1], guard, root, fn, runtime, db, bindings); candidate != nil {
				return candidate
			}
			return callerComparisonEvidence(expr.Children[1], expr.Children[0], guard, root, fn, runtime, db, bindings)
		}
	}
	return nil
}

// maxPredicateHelperDepth bounds nested predicate helpers, such as a hasRole
// that returns _hasRole(...). Real role checks nest one or two levels.
const maxPredicateHelperDepth = 4

// predicateHelperEvidence proves a guard written as a call to a boolean
// predicate helper, such as OpenZeppelin's `if (!hasRole(role, account))
// revert(...)`, by evaluating the one expression the helper returns under the
// call's argument bindings. Only a helper whose entire body is a single return
// statement qualifies; a helper with control flow or effects stays opaque and
// the guard fails closed exactly as before. The guard node, its range, and its
// dominance stay those of the caller: the helper only supplies the predicate.
func predicateHelperEvidence(expr *types.ASTNode, wantTrue bool, guard, root *types.ASTNode, fn *types.Function, runtime *types.Contract, db *types.Database, bindings authorizationBindings) *authorizationCandidate {
	callee, returned, calleeBindings, ok := resolvePredicateHelper(expr, fn, runtime, db, bindings)
	if !ok {
		return nil
	}
	candidate := authorizationCandidateForExpression(returned, wantTrue, guard, root, callee, runtime, db, calleeBindings)
	if candidate == nil {
		return nil
	}
	candidate.evidence.GuardExpression = astText(guard.Children[0])
	candidate.evidence.GuardRange = semanticRange(guard, fn)
	return candidate
}

// resolvePredicateHelper resolves an internal call to a helper whose whole body
// is one return statement, and returns that expression with the helper's
// parameters bound to the call's arguments. Virtual helpers resolve through the
// runtime contract, so an override is what gets analyzed.
func resolvePredicateHelper(expr *types.ASTNode, fn *types.Function, runtime *types.Contract, db *types.Database, bindings authorizationBindings) (*types.Function, *types.ASTNode, authorizationBindings, bool) {
	if expr == nil || fn == nil || expr.Kind != types.KindCallInternal || bindings.predicateDepth >= maxPredicateHelperDepth {
		return nil, nil, authorizationBindings{}, false
	}
	var call *types.FunctionCall
	for _, candidate := range fn.Calls {
		if candidate != nil && isAuthorizationInternalCall(candidate.CallType) && candidate.Target == expr.Name &&
			exactAuthorizationCallNode(fn, candidate) == expr {
			call = candidate
			break
		}
	}
	callee, _ := resolveAuthorizationCallee(call, runtime, db)
	returned := singleReturnExpression(callee)
	if returned == nil {
		return nil, nil, authorizationBindings{}, false
	}
	calleeBindings, reason := bindAuthorizationFunctionParameters(callee, solidityAuthorizationArgs(expr), fn, db, bindings)
	if reason != "" {
		return nil, nil, authorizationBindings{}, false
	}
	calleeBindings.predicateDepth = bindings.predicateDepth + 1
	return callee, returned, calleeBindings, true
}

// singleReturnExpression returns the expression of a function whose whole body
// is `return <expression>;`, and nil for anything else.
func singleReturnExpression(fn *types.Function) *types.ASTNode {
	if fn == nil || fn.AST == nil || len(fn.AST.Children) != 1 {
		return nil
	}
	ret := fn.AST.Children[0]
	if ret == nil || ret.Kind != types.KindStmtReturn || len(ret.Children) != 1 {
		return nil
	}
	return ret.Children[0]
}

func callerComparisonEvidence(caller, principal, guard, root *types.ASTNode, fn *types.Function, runtime *types.Contract, db *types.Database, bindings authorizationBindings) *authorizationCandidate {
	callerBinding, callerBound := bindings.lookup(caller)
	if !isExactCallerIdentity(caller) && !isCallerIdentityAlias(caller, fn) && (!callerBound || !callerBinding.identity) {
		return nil
	}
	// A zero-argument getter such as OpenZeppelin's `owner()` names the same
	// principal as the state it returns. Getters with arguments stay opaque:
	// `ownerOf(tokenId) == msg.sender` is item self-scoping, not a fixed
	// principal, and must not become access control.
	principalFn, principalBindings := fn, bindings
	// A local assigned exactly once names whatever it was assigned from:
	// `address newOwner = pendingOwner(); if (newOwner != msg.sender) revert`
	// is the same check as comparing pendingOwner() directly.
	if source := singleAssignmentSource(principal, fn); source != nil {
		principal = source
	}
	if len(solidityAuthorizationArgs(principal)) == 0 {
		if callee, returned, calleeBindings, ok := resolvePredicateHelper(principal, fn, runtime, db, bindings); ok {
			principal, principalFn, principalBindings = returned, callee, calleeBindings
		}
	}
	if containsExactCallerIdentity(principal) || isCallerIdentityAlias(principal, principalFn) {
		return nil
	}
	kind, principalText, refIDs := classifyPrincipalEvidence(principal, principalFn, db, principalBindings)
	if kind == types.PrincipalUnknown {
		if !isUnclassifiedAuthorityPrincipal(principal) {
			return nil
		}
		// The check is authorization-shaped even though its principal cannot
		// be classified, so it fails closed as unknown instead of vanishing and
		// leaving the function unprotected.
		dominance := authorizationDominance(guard, root)
		return &authorizationCandidate{
			node: guard, verdict: types.AuthorizationUnknown,
			evidence: types.AuthorizationEvidence{
				GuardKind: "inline", GuardExpression: astText(guard.Children[0]), GuardRange: semanticRange(guard, fn),
				PrincipalKind: types.PrincipalUnknown, Principal: astText(principal), Dominance: dominance,
			},
		}
	}
	dominance := authorizationDominance(guard, root)
	verdict := types.AuthorizationProtected
	if kind == types.PrincipalCallerSelfScope {
		verdict = types.AuthorizationSelfScoped
	}
	if dominance != types.AuthorizationDominates {
		verdict = types.AuthorizationUnknown
	}
	return &authorizationCandidate{
		node: guard, verdict: verdict,
		evidence: types.AuthorizationEvidence{
			GuardKind: "inline", GuardExpression: astText(guard.Children[0]), GuardRange: semanticRange(guard, fn),
			PrincipalKind: kind, Principal: principalText, RefIDs: refIDs, Dominance: dominance,
		},
	}
}

// singleAssignmentSource returns the right-hand side when node reads a local
// variable that fn assigns exactly once, and nil otherwise.
func singleAssignmentSource(node *types.ASTNode, fn *types.Function) *types.ASTNode {
	if node == nil || fn == nil || fn.AST == nil || node.Kind != types.KindExprIdentifier ||
		node.RefKind != "local_var" || node.RefID == "" {
		return nil
	}
	var source *types.ASTNode
	count := 0
	walkAST(fn.AST, func(current *types.ASTNode) {
		if current == nil || current.Kind != types.KindStmtAssign || len(current.Children) < 2 {
			return
		}
		for _, lhs := range current.Children[:len(current.Children)-1] {
			if lhs != nil && lhs.Kind == types.KindExprIdentifier && lhs.RefID == node.RefID {
				count++
				source = current.Children[len(current.Children)-1]
			}
		}
	})
	if count != 1 || source == nil || source.Kind == types.KindExprTuple {
		return nil
	}
	return source
}

// isUnclassifiedAuthorityPrincipal reports whether a principal the builder
// could not classify still denotes an authority: a local variable, as in
// Axelar's `address newOwner = pendingOwner(); if (newOwner != msg.sender)
// revert`, whose getter reads a slot in assembly, or a zero-argument call.
// tx.origin is caller-controlled, and a getter with arguments (`ownerOf(id)`)
// scopes the caller to a resource, so neither qualifies.
func isUnclassifiedAuthorityPrincipal(principal *types.ASTNode) bool {
	if principal == nil {
		return false
	}
	switch principal.Kind {
	case types.KindExprIdentifier:
		return principal.RefKind == "local_var"
	case types.KindCallInternal:
		return len(solidityAuthorizationArgs(principal)) == 0
	default:
		return false
	}
}

func roleMembershipEvidence(expr *types.ASTNode, wantTrue bool, guard, root *types.ASTNode, fn *types.Function, db *types.Database, bindings authorizationBindings) *authorizationCandidate {
	if !wantTrue {
		return nil
	}
	refIDs, ok := authorizationRoleRefs(expr, fn, db, bindings)
	if !ok {
		return nil
	}
	dominance := authorizationDominance(guard, root)
	verdict := types.AuthorizationProtected
	if dominance != types.AuthorizationDominates {
		verdict = types.AuthorizationUnknown
	}
	return &authorizationCandidate{
		node: guard, verdict: verdict,
		evidence: types.AuthorizationEvidence{
			GuardKind: "inline", GuardExpression: astText(guard.Children[0]), GuardRange: semanticRange(guard, fn),
			PrincipalKind: types.PrincipalRole, Principal: astText(expr), RefIDs: refIDs, Dominance: dominance,
		},
	}
}

func authorizationRoleRefs(expr *types.ASTNode, fn *types.Function, db *types.Database, bindings authorizationBindings) ([]string, bool) {
	if expr == nil || expr.Kind != types.KindExprIndexAccess {
		return nil, false
	}
	base, keys := flattenAuthorizationIndex(expr)
	if base == nil || base.RefKind != "state_var" || len(keys) == 0 {
		return nil, false
	}
	if !types.IsAccessControlName(base.Name) {
		return nil, false
	}
	callerKeys := 0
	refIDs := authorizationRefIDs(expr)
	for _, key := range keys {
		if containsExactCallerIdentity(key) || isCallerIdentityAlias(key, fn) {
			callerKeys++
			continue
		}
		if binding, ok := bindings.lookup(key); ok {
			switch binding.kind {
			case types.PrincipalCallerSelfScope:
				if !binding.identity {
					return nil, false
				}
				callerKeys++
			case types.PrincipalExpectedExternal, types.PrincipalFixedAddress, types.PrincipalOwner:
				refIDs = append(refIDs, binding.refIDs...)
			default:
				return nil, false
			}
			continue
		}
		if isCallerSelectedPrincipal(key, fn) || !isFixedAuthorizationOperand(key, fn, db, bindings) {
			return nil, false
		}
	}
	if callerKeys != 1 {
		return nil, false
	}
	return normalizedAuthorizationRefs(refIDs), true
}

func flattenAuthorizationIndex(node *types.ASTNode) (*types.ASTNode, []*types.ASTNode) {
	if node == nil || node.Kind != types.KindExprIndexAccess || len(node.Children) < 2 {
		return nil, nil
	}
	base := node.Children[0]
	keys := append([]*types.ASTNode(nil), node.Children[1:]...)
	// A struct field between two index steps selects a mapping stored in the
	// struct, as in OpenZeppelin AccessControl's `_roles[role].members[account]`
	// (`hasRole[account]` since v5). The field adds no key, so the chain is the
	// same role lookup as `roles[role][account]`. Only a field of an indexed
	// value is looked through; a field of a bare state struct keeps failing
	// closed.
	for base.Kind == types.KindExprMemberAccess && len(base.Children) > 0 &&
		base.Children[0].Kind == types.KindExprIndexAccess {
		base = base.Children[0]
	}
	if base.Kind == types.KindExprIndexAccess {
		root, inner := flattenAuthorizationIndex(base)
		return root, append(inner, keys...)
	}
	return base, keys
}

func isFixedAuthorizationOperand(node *types.ASTNode, fn *types.Function, db *types.Database, bindings authorizationBindings) bool {
	if node == nil || containsExactCallerIdentity(node) {
		return false
	}
	if binding, ok := bindings.lookup(node); ok {
		switch binding.kind {
		case types.PrincipalExpectedExternal, types.PrincipalFixedAddress, types.PrincipalOwner:
			return true
		default:
			return false
		}
	}
	if isFixedAddressLiteral(node) {
		return true
	}
	if node.Kind == types.KindExprIdentifier && node.RefKind == "state_var" {
		return authorizationStateVariableIsFixed(node.RefID, db)
	}
	return false
}

func authorizationStateVariableIsFixed(refID string, db *types.Database) bool {
	if refID == "" || db == nil {
		return false
	}
	for _, contract := range db.Contracts {
		if contract == nil {
			continue
		}
		for _, state := range contract.StateVariables {
			if state != nil && contract.ID+"."+state.Name == refID {
				return state.IsConstant || state.IsImmutable
			}
		}
	}
	return false
}

func classifyPrincipalEvidence(node *types.ASTNode, fn *types.Function, db *types.Database, bindings authorizationBindings) (types.AuthorizationPrincipalKind, string, []string) {
	if node == nil {
		return types.PrincipalUnknown, "", nil
	}
	if binding, ok := bindings.lookup(node); ok {
		return binding.kind, binding.principal, append([]string(nil), binding.refIDs...)
	}
	if isCallerSelectedPrincipal(node, fn) {
		return types.PrincipalCallerSelfScope, astText(node), nil
	}
	if isFixedAddressLiteral(node) {
		return types.PrincipalFixedAddress, astText(node), authorizationRefIDs(node)
	}
	if node.Kind == types.KindExprIdentifier && node.RefKind == "state_var" {
		return types.PrincipalExpectedExternal, astText(node), authorizationRefIDs(node)
	}
	if refs := authorizationRefIDs(node); len(refs) > 0 && !subtreeHasCallerControlledValue(node, fn) {
		return types.PrincipalExpectedExternal, astText(node), refs
	}
	_ = db
	return types.PrincipalUnknown, "", nil
}

func isCallerSelectedPrincipal(node *types.ASTNode, fn *types.Function) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprIdentifier {
		if node.RefKind == "parameter" {
			return true
		}
		if node.RefKind == "local_var" && taintContains(node.TaintSources, "parameter") {
			return true
		}
		if node.RefKind == "" && fn != nil {
			for _, parameter := range fn.Parameters {
				if parameter != nil && parameter.Name == node.Name {
					return true
				}
			}
		}
	}
	return subtreeHasCallerControlledValue(node, fn)
}

func subtreeHasCallerControlledValue(node *types.ASTNode, fn *types.Function) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprIdentifier && (node.RefKind == "parameter" || (node.RefKind == "local_var" && taintContains(node.TaintSources, "parameter"))) {
		return true
	}
	for _, child := range node.Children {
		if subtreeHasCallerControlledValue(child, fn) {
			return true
		}
	}
	return false
}

func taintContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isFixedAddressLiteral(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprLiteral {
		return node.GetAttributeBool("type_is_address") || strings.HasPrefix(strings.ToLower(node.Value), "0x")
	}
	if strings.HasPrefix(node.Kind, "call.") && node.Name == "address" {
		for _, child := range node.Children {
			if isFixedAddressLiteral(child) {
				return true
			}
		}
	}
	return false
}

func isExactCallerIdentity(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	// OpenZeppelin Context's `_msgSender()`: the exact zero-argument internal
	// helper, the same caller-identity convention WQL taint applies. Every
	// Ownable and AccessControl guard since OpenZeppelin 3.x compares against it.
	if node.Kind == types.KindCallInternal && node.Name == "_msgSender" && len(solidityAuthorizationArgs(node)) == 0 {
		return true
	}
	if node.Kind != types.KindExprMemberAccess || node.Name != "sender" {
		return false
	}
	if node.GetAttributeString("parent") == "msg" {
		return true
	}
	return len(node.Children) == 1 && node.Children[0] != nil && node.Children[0].Kind == types.KindExprIdentifier && node.Children[0].Name == "msg"
}

// isCallerIdentityAlias reports whether node reads a local variable whose every
// assignment in fn is caller identity, as in `address sender = msg.sender;
// _withdraw(sender, ...)`. Locals are matched by RefID, so shadowing cannot
// alias an unrelated variable. Any other write disqualifies the local: an
// assignment from anything but caller identity (including a Yul assignment,
// which the AST normalizes to the same shape), a tuple destructuring, or a
// delete. An alias of an alias is followed; a cycle is not.
func isCallerIdentityAlias(node *types.ASTNode, fn *types.Function) bool {
	return callerIdentityAlias(node, fn, map[string]bool{})
}

func callerIdentityAlias(node *types.ASTNode, fn *types.Function, visiting map[string]bool) bool {
	if node == nil || fn == nil || fn.AST == nil || node.Kind != types.KindExprIdentifier ||
		node.RefKind != "local_var" || node.RefID == "" || visiting[node.RefID] {
		return false
	}
	visiting[node.RefID] = true
	assigned, alias := false, true
	walkAST(fn.AST, func(current *types.ASTNode) {
		if current == nil || !alias {
			return
		}
		switch current.Kind {
		case types.KindStmtAssign:
			if len(current.Children) < 2 {
				return
			}
			rhs := current.Children[len(current.Children)-1]
			// Tuple destructuring lists each target as its own child and puts
			// an expr.tuple on the right, which is never caller identity.
			for _, lhs := range current.Children[:len(current.Children)-1] {
				if lhs != nil && lhs.Kind == types.KindExprIdentifier && lhs.RefID == node.RefID {
					assigned = true
					if !isExactCallerIdentity(rhs) && !callerIdentityAlias(rhs, fn, visiting) {
						alias = false
					}
				}
			}
		case types.KindExprUnaryOp:
			if current.GetAttributeString("operator") == "delete" && len(current.Children) > 0 &&
				current.Children[0] != nil && current.Children[0].RefID == node.RefID {
				alias = false
			}
		}
	})
	return assigned && alias
}

func containsExactCallerIdentity(node *types.ASTNode) bool {
	if isExactCallerIdentity(node) {
		return true
	}
	if node == nil {
		return false
	}
	for _, child := range node.Children {
		if containsExactCallerIdentity(child) {
			return true
		}
	}
	return false
}

func authorizationRefIDs(node *types.ASTNode) []string {
	seen := make(map[string]bool)
	walkAST(node, func(current *types.ASTNode) {
		if current != nil && current.RefID != "" && current.RefKind != "parameter" && current.RefKind != "local_var" {
			seen[current.RefID] = true
		}
	})
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func normalizedAuthorizationRefs(refs []string) []string {
	seen := make(map[string]bool, len(refs))
	for _, refID := range refs {
		if refID != "" {
			seen[refID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for refID := range seen {
		out = append(out, refID)
	}
	sort.Strings(out)
	return out
}

func authorizationDominance(guard, root *types.ASTNode) types.AuthorizationDominance {
	if guard == nil || root == nil {
		return types.AuthorizationUnknownDom
	}
	for current := guard.Parent; current != nil && current != root; current = current.Parent {
		switch current.Kind {
		case types.KindStmtIf, types.KindStmtLoop, types.KindExprConditional, types.KindStmtTryCatch:
			return types.AuthorizationPartial
		}
	}
	if sensitive := firstAuthorizationSensitiveNode(root, guard); sensitive != nil && sourceNodeBefore(sensitive, guard) {
		return types.AuthorizationAfterSite
	}
	return types.AuthorizationDominates
}

func firstAuthorizationSensitiveNode(root, guard *types.ASTNode) *types.ASTNode {
	var first *types.ASTNode
	walkAST(root, func(node *types.ASTNode) {
		if first != nil || node == nil || node == guard || isDescendantOf(node, guard) {
			return
		}
		if node.Kind == types.KindStmtAssign && node.GetAttributeBool("is_state_var") {
			first = node
			return
		}
		if node.Kind == types.KindStmtStateMutation || node.Kind == types.KindAsmSstore || types.IsExternalBoundaryKind(node.Kind) {
			first = node
		}
	})
	return first
}

func isDescendantOf(node, ancestor *types.ASTNode) bool {
	for current := node; current != nil; current = current.Parent {
		if current == ancestor {
			return true
		}
	}
	return false
}

func sourceNodeBefore(left, right *types.ASTNode) bool {
	if left == nil || right == nil {
		return false
	}
	if left.StartByte > 0 && right.StartByte > 0 {
		return left.StartByte < right.StartByte
	}
	if left.StartLine != right.StartLine {
		return left.StartLine > 0 && right.StartLine > 0 && left.StartLine < right.StartLine
	}
	return left.StartCol > 0 && right.StartCol > 0 && left.StartCol < right.StartCol
}

// modifierGuardPosition returns the position inside the modifier that must
// precede the `_;` placeholder for the guard to dominate the function body.
// That is the guard itself when it is written in the modifier, and the call
// site of the helper that holds it otherwise. OpenZeppelin's
// `modifier onlyOwner() { _checkOwner(); _; }` declares _checkOwner further
// down the file, so comparing the helper's own guard with the placeholder
// wrongly read it as running after the body.
func modifierGuardPosition(result authorizationResult, synthetic *types.Function, runtime *types.Contract, db *types.Database) types.SemanticSourceRange {
	guard := result.evidence[0].GuardRange
	root := synthetic.AST
	if guard.File == synthetic.SourceFile && guard.StartByte >= root.StartByte && guard.EndByte <= root.EndByte {
		return guard
	}
	for _, call := range synthetic.Calls {
		if call == nil || !isAuthorizationInternalCall(call.CallType) {
			continue
		}
		callee, _ := resolveAuthorizationCallee(call, runtime, db)
		if callee == nil || authorizationFunctionID(callee, nil) != result.selectedFunctionID {
			continue
		}
		if node := exactAuthorizationCallNode(synthetic, call); node != nil {
			return semanticRange(node, synthetic)
		}
	}
	return guard
}

func modifierGuardAfterPlaceholderRange(guard types.SemanticSourceRange, root *types.ASTNode) bool {
	if root == nil {
		return false
	}
	for _, child := range root.Children {
		if child != nil && child.Kind == types.KindExprIdentifier && child.Name == "_" {
			if child.StartByte > 0 && guard.StartByte > 0 {
				return child.StartByte < guard.StartByte
			}
			if child.StartLine != guard.StartLine {
				return child.StartLine > 0 && guard.StartLine > 0 && child.StartLine < guard.StartLine
			}
			return child.StartCol > 0 && guard.StartCol > 0 && child.StartCol < guard.StartCol
		}
	}
	return false
}

func authorizationCandidateRank(candidate *authorizationCandidate) int {
	if candidate == nil {
		return 0
	}
	switch candidate.verdict {
	case types.AuthorizationProtected:
		return 3
	case types.AuthorizationSelfScoped:
		return 2
	case types.AuthorizationUnknown:
		return 1
	default:
		return 0
	}
}
