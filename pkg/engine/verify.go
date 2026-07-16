package engine

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

// Verify checks if an AST node matches a rule (main recursive verification function).
// Default logic: ALL fields in a rule must match (AND semantics).
//
// Guards against unbounded recursion (e.g. `not: { not: { not: ... } }` chains)
// by tracking depth on the Engine. When depth exceeds MaxRuleRecursionDepth,
// returns false and logs once at verbose; the scan continues with other rules.
func (e *Engine) Verify(node *types.ASTNode, r Rule) (matched bool) {
	if node == nil {
		return false
	}

	var oldPrimary *types.ASTNode
	traceActive := e.match != nil
	if traceActive {
		oldPrimary = e.match.Primary
	}

	e.recursionDepth++
	defer func() {
		if traceActive && !matched {
			e.match.Primary = oldPrimary
		}
		e.recursionDepth--
	}()
	if e.recursionDepth > MaxRuleRecursionDepth {
		e.logf("Verify: recursion depth %d exceeded (max %d) — aborting branch", e.recursionDepth, MaxRuleRecursionDepth)
		return false
	}

	// ========== ATOMIC MATCHERS (check first, fail fast) ==========

	// Check atomic attributes on current node (kind, regex/name, attr, source/tainted_from)
	if !e.matchAtomic(node, r) {
		return false
	}

	// Capture the first provisionally matched atomic node as the finding's
	// primary AST node. The defer above rolls this back if later constraints
	// in the same branch fail.
	if e.match != nil && e.match.Primary == nil && hasAtomicPredicate(r) {
		e.match.Primary = node
	}

	// ========== LEFT/RIGHT MATCHING ==========

	// Check left/right for member_access, assignment, binary_op
	if r.Left != nil || r.Right != nil {
		if !e.matchLeftRight(node, r) {
			return false
		}
	}

	// ========== CALL-SPECIFIC ==========

	// Check arguments (for call nodes)
	if len(r.Args) > 0 {
		if !e.matchArgs(node, r.Args) {
			return false
		}
	}

	// arg.any: some positional argument must match the sub-rule.
	if r.ArgAny != nil {
		if !e.matchArgAny(node, *r.ArgAny) {
			return false
		}
	}

	// UncheckedVar: the (arithmetic) node's operands must NOT be bounded by a
	// preceding require/assert/if guard. Skips range-checked unchecked math.
	if r.UncheckedVar && operandsGuardedBefore(node) {
		return false
	}

	// StatementContains: the node's nearest enclosing statement must have a
	// descendant matching the sub-rule. Statement-scoped sibling search (see the
	// Rule field doc); combine with `not:` for "no such node in this statement".
	if r.StatementContains != nil && !e.statementContains(node, *r.StatementContains) {
		return false
	}

	// ========== LOGIC OPERATORS (all conditions must pass) ==========

	// Handle ALL (AND logic)
	if len(r.All) > 0 {
		if !e.verifyAll(node, r.All) {
			return false
		}
	}

	// Handle ANY (OR logic)
	if len(r.Any) > 0 {
		if !e.verifyAny(node, r.Any) {
			return false
		}
	}

	// Handle NOT (negation)
	if r.Not != nil {
		if e.Verify(node, *r.Not) {
			return false
		}
	}

	// Handle SEQ (sequence matching)
	if len(r.Sequence) > 0 {
		if !e.verifySeq(node, r.Sequence) {
			return false
		}
	}

	// ========== TRAVERSAL OPERATORS ==========

	// Handle HAS (search descendants)
	if r.Contains != nil {
		if !e.verifyHas(node, *r.Contains) {
			return false
		}
	}

	// Handle INSIDE (search ancestors)
	if r.Inside != nil {
		if !e.verifyInside(node, *r.Inside) {
			return false
		}
	}

	return true
}

// verifyAll checks if ALL rules match (AND logic)
func (e *Engine) verifyAll(node *types.ASTNode, rules []Rule) bool {
	for _, subRule := range rules {
		if !e.Verify(node, subRule) {
			return false
		}
	}
	return true
}

// verifyAny checks if ANY rule matches (OR logic)
func (e *Engine) verifyAny(node *types.ASTNode, rules []Rule) bool {
	for _, subRule := range rules {
		if e.Verify(node, subRule) {
			return true
		}
	}
	return false
}

// verifySeq checks if descendants match the rules in order on a single
// execution path.
//
// Rules are matched in DFS source order across descendants, with one
// control-flow constraint applied between consecutive matches: two matches may
// not land in mutually-exclusive arms of the same conditional (the then/else of
// an `stmt.if`, or the two arms of an `expr.conditional`). This removes the
// dominant false positive where
// `if (cond) { externalCall(); } else { state = x; }` spuriously matched
// `sequence: [outgoing_call, state_write]` even though the two operations can
// never both execute. It is a branch-arm check rather than a full CFG: loops
// and other constructs are still treated as straight-line, which is the
// conservative (match-more) direction.
func (e *Engine) verifySeq(node *types.ASTNode, rules []Rule) bool {
	if len(rules) == 0 {
		return true
	}

	// Collect all descendants in order (depth-first)
	var descendants []*types.ASTNode
	node.WalkDescendants(func(n *types.ASTNode) bool {
		descendants = append(descendants, n)
		return true // Continue walking
	})

	// Try to find sequence pattern in descendants
	return e.findSequenceInNodes(descendants, rules, 0, nil)
}

// findSequenceInNodes searches for the rule sequence in node order. prevMatch is
// the node that satisfied the previous rule (nil for the first rule); a
// candidate for the current rule is skipped when it cannot execute on the same
// path as prevMatch (mutually-exclusive branch arms).
func (e *Engine) findSequenceInNodes(nodes []*types.ASTNode, rules []Rule, startIdx int, prevMatch *types.ASTNode) bool {
	if len(rules) == 0 {
		return true
	}

	// Try to match first rule starting from each position
	for i := startIdx; i < len(nodes); i++ {
		if !e.Verify(nodes[i], rules[0]) {
			continue
		}
		// A later step must not match inside the previous step's own subtree.
		// In DFS order a node's descendants follow it, so without this guard
		// `sequence: [state_write, outgoing_call]` would match the single
		// statement `total = token.balanceOf(x)` (the call is a child of the
		// assign) — a false "write-then-call" ordering.
		if prevMatch != nil && isWithinSubtree(nodes[i], prevMatch) {
			continue
		}
		// Consecutive matches must be able to co-execute.
		if prevMatch != nil && !sameExecutionPath(prevMatch, nodes[i]) {
			continue
		}
		if len(rules) == 1 {
			return true // Last rule matched
		}
		// Recursively find remaining rules after this position.
		if e.findSequenceInNodes(nodes, rules[1:], i+1, nodes[i]) {
			return true
		}
	}

	return false
}

// isWithinSubtree reports whether node is ancestor itself or a descendant of
// ancestor, walking Parent links.
func isWithinSubtree(node, ancestor *types.ASTNode) bool {
	for n := node; n != nil; n = n.Parent {
		if n == ancestor {
			return true
		}
	}
	return false
}

// sameExecutionPath reports whether nodes a and b can both execute on a single
// run. They cannot when they first diverge into two different *arm* children of
// a common conditional ancestor (then vs else of an `if`, or the two arms of a
// ternary). Divergence at a sequential parent (block, function, loop) or at a
// conditional's condition is fine. Relies on ASTNode.Parent links (restored
// during build and after a JSON load); when no common ancestor exists — e.g.
// nodes inlined from different functions in interprocedural matching — it does
// not constrain.
func sameExecutionPath(a, b *types.ASTNode) bool {
	if a == nil || b == nil || a == b {
		return true
	}
	// Map every ancestor of a (including a) to the child one step down toward a.
	childTowardA := make(map[*types.ASTNode]*types.ASTNode)
	var prev *types.ASTNode
	for n := a; n != nil; n = n.Parent {
		childTowardA[n] = prev
		prev = n
	}
	// Walk up from b to the lowest common ancestor.
	prev = nil
	for n := b; n != nil; n = n.Parent {
		if childA, ok := childTowardA[n]; ok {
			childB := prev
			if childA == nil || childB == nil || childA == childB {
				// One node is an ancestor of the other, or they share the
				// subtree at this level — same path.
				return true
			}
			return !areExclusiveArms(n, childA, childB)
		}
		prev = n
	}
	return true // no common ancestor -> don't constrain
}

// areExclusiveArms reports whether c1 and c2 (direct children of parent) are
// mutually-exclusive branch arms. For stmt.if the condition is the expression
// child and the arms are the statement children; for expr.conditional the arms
// carry conditional_part = "true"/"false"; for stmt.try_catch the body and each
// catch clause carry try_part = "body" / "catch:N" and the try expression carries
// "expr".
func areExclusiveArms(parent, c1, c2 *types.ASTNode) bool {
	switch parent.Kind {
	case types.KindStmtIf:
		// Two children are exclusive arms only when neither is the condition.
		// The condition is an expression (expr.*); the then/else bodies are
		// statements. This keeps condition-vs-arm pairs sequential (no FN for
		// a call in an if-condition followed by a state write in the body).
		return !isConditionExpr(c1) && !isConditionExpr(c2)
	case types.KindExprConditional:
		p1 := c1.GetAttributeString("conditional_part")
		p2 := c2.GetAttributeString("conditional_part")
		return (p1 == "true" && p2 == "false") || (p1 == "false" && p2 == "true")
	case types.KindStmtTryCatch:
		// The try expression ("expr") executes on every path and co-executes
		// with whichever arm fires, so it is never exclusive. The body and each
		// catch clause are distinct arms that can never both run: a sequence
		// must not pair a node in the body with one in a catch (or across two
		// catch clauses).
		p1 := c1.GetAttributeString("try_part")
		p2 := c2.GetAttributeString("try_part")
		if !isTryArm(p1) || !isTryArm(p2) {
			return false
		}
		return p1 != p2
	default:
		return false
	}
}

// isConditionExpr reports whether n is the test expression of an if-statement
// (as opposed to a then/else arm). The builder tags the condition node with
// cond_role="if" regardless of its kind, so a call used as a condition
// (`if (target.call(...))`) is recognized here. The kind-prefix check is only a
// fallback for nodes that predate the cond_role tag; relying on it alone missed
// call/tuple conditions and wrongly treated a condition + body as exclusive
// arms, dropping CEI/reentrancy sequence findings.
func isConditionExpr(n *types.ASTNode) bool {
	if n.GetAttributeString("cond_role") == "if" {
		return true
	}
	return strings.HasPrefix(n.Kind, "expr.")
}

// isTryArm reports whether a try_part value names a mutually-exclusive arm of a
// try/catch (the success body or a catch clause), as opposed to the try
// expression itself.
func isTryArm(part string) bool {
	return part == "body" || strings.HasPrefix(part, "catch")
}

// verifyHas searches descendants for a matching node
func (e *Engine) verifyHas(node *types.ASTNode, rule Rule) bool {
	found := false
	node.WalkDescendants(func(n *types.ASTNode) bool {
		if e.Verify(n, rule) {
			found = true
			return false // Stop walking
		}
		return true // Continue walking
	})
	return found
}

// verifyInside searches ancestors for a matching node
func (e *Engine) verifyInside(node *types.ASTNode, rule Rule) bool {
	found := false
	node.WalkAncestors(func(n *types.ASTNode) bool {
		if e.Verify(n, rule) {
			found = true
			return false // Stop walking
		}
		return true // Continue walking
	})
	return found
}

// matchAtomic checks atomic attributes on the current node
func (e *Engine) matchAtomic(node *types.ASTNode, r Rule) bool {
	// Check kind
	if r.Kind != "" {
		if !e.matchKind(node, r.Kind) {
			return false
		}
	}

	// Check regex on name/value
	if r.Name != "" {
		matchTarget := node.Name
		if matchTarget == "" {
			matchTarget = node.Value
		}

		// Special handling for member_access: construct full name (parent.member)
		// This allows matching patterns like "tx\.origin", "msg\.sender"
		if node.Kind == types.KindExprMemberAccess {
			if parent := node.GetAttributeString("parent"); parent != "" {
				fullName := parent + "." + node.Name
				// Try matching against full name first
				if MatchesRegex(r.Name, fullName) {
					// Matched full name, continue
				} else if !MatchesRegex(r.Name, matchTarget) {
					// Also try just the member name as fallback
					return false
				}
			} else if !MatchesRegex(r.Name, matchTarget) {
				return false
			}
		} else if !MatchesRegex(r.Name, matchTarget) {
			return false
		}
	}

	// Check attributes
	if len(r.Attr) > 0 {
		for key, expectedValue := range r.Attr {
			if !e.matchAttributeValue(node, key, expectedValue) {
				return false
			}
		}
	}

	// Check raw source text for the active AST scope. Prefer the node's own
	// line range when available, then fall back to the current function,
	// contract, or file context.
	if r.Regex != "" {
		source := e.astNodeSource(node)
		if source == "" && e.currentFunction != nil {
			source = e.functionSource(e.currentFunction, e.currentContract)
		}
		if source == "" && e.currentContract != nil {
			source = e.contractSource(e.currentContract)
		}
		if source == "" && e.currentSourceFile != nil {
			source = e.sourceContent(e.currentSourceFile.Path)
		}
		if !sourceRegexMatches(r.Regex, source) {
			return false
		}
	}

	// Check visibility / mutability against the node's attributes (set on
	// decl.function nodes). Comma-separated "is one of" semantics, e.g.
	// `visibility: public,external`. The same `visibility:`/`mutability:` keyword
	// is a function precondition when used in filter: (see verifyFunctionFilters).
	if r.Visibility != "" && !attrInCSV(node, "visibility", r.Visibility) {
		return false
	}
	if r.Mutability != "" && !attrInCSV(node, "mutability", r.Mutability) {
		return false
	}

	// Check taint source
	if r.TaintedFrom != "" {
		res := e.checkTaint(node, r.TaintedFrom)
		return res
	}

	return true
}

// attrInCSV reports whether the node's named attribute equals one of the
// comma-separated, case-insensitive values in csv (e.g. "public,external").
func attrInCSV(node *types.ASTNode, attr, csv string) bool {
	// Require the node to actually carry the attribute. Otherwise a non-function
	// node (no `mutability`/`visibility` attr) would read "" and spuriously match
	// `mutability: nonpayable`. decl.function nodes always set both attributes
	// (empty string = the default nonpayable), so this only rejects nodes the
	// predicate was never meant to apply to.
	if _, has := node.GetAttribute(attr); !has {
		return false
	}
	got := strings.ToLower(strings.TrimSpace(node.GetAttributeString(attr)))
	if got == "" && attr == "mutability" {
		got = "nonpayable" // present-but-empty state mutability is the default nonpayable
	}
	for _, v := range strings.Split(csv, ",") {
		if strings.TrimSpace(strings.ToLower(v)) == got {
			return true
		}
	}
	return false
}

// matchLeftRight checks left/right matching for binary expression nodes
// Supports: member_access, assignment, binary_op
func (e *Engine) matchLeftRight(node *types.ASTNode, r Rule) bool {
	switch node.Kind {
	case types.KindExprMemberAccess:
		// For member_access: left = parent, right = member name
		return e.matchMemberAccessLeftRight(node, r)

	case types.KindStmtAssign:
		// For assignment: left = target, right = value (first two children)
		return e.matchBinaryLeftRight(node, r)

	case types.KindExprBinaryOp:
		// For binary_op (==, !=, <, >, etc.): left = first operand, right = second operand
		return e.matchBinaryLeftRight(node, r)

	default:
		// Left/right not applicable for this node type
		// If user specified left/right but node doesn't support it, return false
		return false
	}
}

// matchMemberAccessLeftRight checks left/right for member_access nodes
// left = parent expression (e.g., "tx" in tx.origin)
// right = member name (e.g., "origin" in tx.origin)
func (e *Engine) matchMemberAccessLeftRight(node *types.ASTNode, r Rule) bool {
	// Check left (parent)
	if r.Left != nil {
		parentName := node.GetAttributeString("parent")

		// If Left rule carries any structural/semantic predicate, verify it
		// against the child expression node. attr/tainted_from/not are included
		// here — omitting them made a `left:` using only those predicates match
		// neither branch and pass vacuously (silent over-match).
		if r.Left.Kind != "" || r.Left.Contains != nil || r.Left.Inside != nil ||
			len(r.Left.All) > 0 || len(r.Left.Any) > 0 || r.Left.Not != nil ||
			len(r.Left.Attr) > 0 || r.Left.TaintedFrom != "" {
			// Check against the child node (parent expression)
			if len(node.Children) > 0 {
				if !e.Verify(node.Children[0], *r.Left) {
					return false
				}
			} else {
				return false
			}
		} else if r.Left.Name != "" {
			// Simple regex check on parent name
			if !MatchesRegex(r.Left.Name, parentName) {
				return false
			}
		}
	}

	// Check right (member name). For a member access the "right" is just the
	// member identifier — there is no child node — so only `right.name` is
	// meaningful. Any other predicate (kind/contains/attr/etc.) cannot be
	// evaluated here and must fail closed rather than silently pass.
	if r.Right != nil {
		if r.Right.Name != "" {
			if !MatchesRegex(r.Right.Name, node.Name) {
				return false
			}
		}
		if rightHasUnsupportedMemberPredicate(r.Right) {
			return false
		}
	}

	return true
}

// rightHasUnsupportedMemberPredicate reports whether a `right:` rule for a
// member access uses a predicate other than `name`, which member access cannot
// satisfy (the member has no child node).
func rightHasUnsupportedMemberPredicate(r *Rule) bool {
	return r.Kind != "" || r.Contains != nil || r.Inside != nil ||
		len(r.All) > 0 || len(r.Any) > 0 || r.Not != nil ||
		len(r.Sequence) > 0 || len(r.Attr) > 0 || len(r.Args) > 0 ||
		r.TaintedFrom != "" || r.Left != nil || r.Right != nil
}

// matchBinaryLeftRight checks left/right for assignment and binary_op nodes
// Children order: [0] = left operand, [1] = right operand
func (e *Engine) matchBinaryLeftRight(node *types.ASTNode, r Rule) bool {
	// Check left (first child)
	if r.Left != nil {
		if len(node.Children) < 1 {
			return false
		}
		if !e.Verify(node.Children[0], *r.Left) {
			return false
		}
	}

	// Check right (second child)
	if r.Right != nil {
		if len(node.Children) < 2 {
			return false
		}
		if !e.Verify(node.Children[1], *r.Right) {
			return false
		}
	}

	return true
}

// matchKind checks if a node matches the specified kind.
// Supports:
//   - Semantic groups: outgoing_call, eth_transfer, delegatecall, check, guard (alias for check),
//     token_call, state_write, state_read, any_call, selfdestruct
//   - Prefix matching: "call" matches "call.internal", "call.external", etc.
//   - guard.* as alias for check.* (e.g., "guard.require" → "check.require")
//   - Exact match for all other kinds
func (e *Engine) matchKind(node *types.ASTNode, kind string) bool {
	// 1. Semantic groups
	switch kind {
	case "outgoing_call":
		return types.IsOutgoingCall(node.Kind)
	case "eth_transfer":
		return types.IsETHTransfer(node.Kind)
	case "delegatecall":
		return types.IsDelegatecall(node.Kind)
	case "check":
		return types.IsCheck(node.Kind)
	case "guard":
		// Alias for check — matches require/assert/revert
		return types.IsGuard(node.Kind)
	case "token_call":
		// Matches external calls to ERC20/ERC721 standard methods.
		// Use with name: to filter specific methods:
		//   kind: token_call
		//   name: ^(transfer|transferFrom|approve|safeTransfer)$
		return types.IsTokenCall(node.Kind)
	case "any_call":
		return types.IsAnyCall(node.Kind)
	case "state_write":
		// stmt.assign with is_state_var=true, or asm.sstore
		if node.Kind == types.KindAsmSstore {
			return true
		}
		if node.Kind == types.KindStmtAssign {
			return node.GetAttributeBool("is_state_var")
		}
		return false
	case "state_read":
		if node.Kind == types.KindAsmSload {
			return true
		}
		if node.Kind == types.KindExprIdentifier {
			return node.RefKind == "state_var"
		}
		return false
	case "selfdestruct":
		// Match both the Solidity-level builtin `selfdestruct(addr)` /
		// `suicide(addr)` AND the inline-assembly `selfdestruct` opcode.
		if node.Kind == types.KindAsmSelfdestruct ||
			node.Kind == types.KindCallBuiltinSelfdestruct {
			return true
		}
		return false
	}

	// 2a. guard.* → check.* alias (e.g., guard.require → check.require)
	if strings.HasPrefix(kind, "guard.") {
		checkKind := strings.Replace(kind, "guard.", "check.", 1)
		return node.Kind == checkKind
	}

	// 2b. Prefix matching for dot-notation (e.g., "call" matches "call.internal")
	if strings.Contains(kind, ".") {
		// Exact kind ("call.external") or a dot-prefix ("call.lowlevel" matches
		// "call.lowlevel.call").
		return node.Kind == kind || strings.HasPrefix(node.Kind, kind+".")
	}

	// Short prefix without dot: "call", "check", "asm", "stmt", "expr", "decl"
	if kind == "call" || kind == "check" || kind == "asm" || kind == "stmt" || kind == "expr" || kind == "decl" {
		return strings.HasPrefix(node.Kind, kind+".")
	}

	// 3. Exact match for all other kinds
	return node.Kind == kind
}

// matchAttributeValue checks if a node attribute matches the expected value
func (e *Engine) matchAttributeValue(node *types.ASTNode, key string, expectedValue interface{}) bool {
	actualValue, exists := node.GetAttribute(key)
	if !exists {
		return false
	}

	// Handle different value types
	switch expected := expectedValue.(type) {
	case bool:
		// Tolerate the common case where the attribute is stored as the string
		// "true"/"false" (most node attrs are strings) but the template wrote a
		// YAML bool (`conditional_part: true`). Both that and the quoted form
		// (`conditional_part: 'true'`) now match.
		switch actual := actualValue.(type) {
		case bool:
			return actual == expected
		case string:
			return actual == strconv.FormatBool(expected)
		}
		return false

	case string:
		actual, ok := actualValue.(string)
		if !ok {
			return false
		}
		// Attribute values are matched as ANCHORED regexes: `operator: "="` must
		// match exactly "=", not "==" / "!=" / ">=". (The `name:` field is
		// deliberately substring-matched; attributes are discrete tokens.)
		return matchAnchoredRegex(expected, actual)

	case []interface{}:
		// Handle array of values (match any)
		actual, ok := actualValue.(string)
		if !ok {
			return false
		}
		for _, v := range expected {
			if str, ok := v.(string); ok && str == actual {
				return true
			}
		}
		return false

	default:
		// Direct equality check
		return actualValue == expectedValue
	}
}

// isArgumentBearingNode reports whether node is a call-like node whose
// children are positional arguments. This includes require/assert/revert
// (their condition/args are children) and selfdestruct, so argument matchers
// can constrain e.g. a revert's error args or selfdestruct's recipient.
func isArgumentBearingNode(node *types.ASTNode) bool {
	switch node.Kind {
	case types.KindCallExternal, types.KindCallInternal,
		types.KindCallLowlevelCall, types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
		types.KindCallBuiltinTransfer, types.KindCallBuiltinSend, types.KindCallCreate,
		types.KindCallBuiltinSelfdestruct,
		types.KindCheckRequire, types.KindCheckAssert, types.KindCheckRevert:
		return true
	default:
		return false
	}
}

// matchArgAny (`arg.any:`) checks whether ANY positional argument of the
// call matches the sub-rule. Receivers/call options are excluded, exactly as
// with matchArgs.
func (e *Engine) matchArgAny(node *types.ASTNode, rule Rule) bool {
	if !isArgumentBearingNode(node) {
		return false
	}
	for _, arg := range callArgumentChildren(node) {
		if e.Verify(arg, rule) {
			return true
		}
	}
	return false
}

// matchArgs checks call arguments against rules
func (e *Engine) matchArgs(node *types.ASTNode, args map[int]Rule) bool {
	if !isArgumentBearingNode(node) {
		return false
	}

	callArgs := callArgumentChildren(node)

	// Check each specified argument
	for argIndex, argRule := range args {
		if argIndex >= len(callArgs) {
			return false // Argument index out of range
		}
		if !e.Verify(callArgs[argIndex], argRule) {
			return false
		}
	}

	return true
}

func callArgumentChildren(node *types.ASTNode) []*types.ASTNode {
	if node == nil {
		return nil
	}
	out := make([]*types.ASTNode, 0, len(node.Children))
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		if child.GetAttributeBool("call_receiver") || child.GetAttributeString("call_option") != "" {
			continue
		}
		out = append(out, child)
	}
	return out
}

// checkTaint verifies if a node or any of its descendants comes from a specific
// source. It consults the active taint environment first, so context-sensitive
// internal calls can distinguish _helper(from) from _helper(msg.sender).
func (e *Engine) checkTaint(node *types.ASTNode, sourceType string) bool {
	for _, source := range e.expressionTaints(node, e.currentTaintEnv) {
		if source == sourceType {
			return true
		}
	}
	return false
}

func (e *Engine) expressionTaints(node *types.ASTNode, env map[string][]string) []string {
	if node == nil {
		return nil
	}
	taintSet := make(map[string]bool)
	e.collectExpressionTaints(node, env, taintSet)
	return sortedTaintSet(taintSet)
}

func (e *Engine) collectExpressionTaints(node *types.ASTNode, env map[string][]string, out map[string]bool) {
	if node == nil {
		return
	}
	for _, source := range e.directNodeTaints(node, env) {
		if source != "" {
			out[source] = true
		}
	}
	for _, child := range node.Children {
		e.collectExpressionTaints(child, env, out)
	}
}

func (e *Engine) directNodeTaints(node *types.ASTNode, env map[string][]string) []string {
	if node == nil {
		return nil
	}
	if isMsgSenderNode(node) {
		return []string{"sender"}
	}
	if node.Kind == types.KindExprIdentifier && env != nil {
		if sources, ok := env[node.Name]; ok {
			return sources
		}
	}
	if len(node.TaintSources) > 0 {
		return node.TaintSources
	}
	switch node.RefKind {
	case "parameter", "state_var", "local_var":
		return []string{node.RefKind}
	default:
		return nil
	}
}

func isMsgSenderNode(node *types.ASTNode) bool {
	if node == nil || node.Kind != types.KindExprMemberAccess || node.Name != "sender" {
		return false
	}
	if node.GetAttributeString("parent") == "msg" {
		return true
	}
	if len(node.Children) > 0 && node.Children[0].Kind == types.KindExprIdentifier {
		return node.Children[0].Name == "msg"
	}
	return false
}

func sortedTaintSet(taintSet map[string]bool) []string {
	out := make([]string, 0, len(taintSet))
	for source := range taintSet {
		out = append(out, source)
	}
	sort.Strings(out)
	return out
}

// VerifyAtFunction is the top-level entry point for function-scope verification
func (e *Engine) VerifyAtFunction(fn *types.Function, r Rule, contract *types.Contract) bool {
	env := e.buildFunctionTaintEnv(fn, nil)
	return e.verifyAtFunctionWithEnv(fn, r, contract, env)
}

// VerifyAtFunctionWithCallees verifies a function and recursively follows
// internal calls with context-sensitive argument taint. It is used for
// entrypoint match rules so helper functions inherit the caller's actual
// argument sources.
func (e *Engine) VerifyAtFunctionWithCallees(fn *types.Function, r Rule, contract *types.Contract) bool {
	visiting := make(map[string]bool)
	return e.verifyAtFunctionWithCallees(fn, r, contract, nil, visiting, 0, nil, nil)
}

func (e *Engine) verifyAtFunctionWithCallees(fn *types.Function, r Rule, contract *types.Contract, seed map[string][]string, visiting map[string]bool, depth int, chain []*types.Function, chainContracts []*types.Contract) bool {
	if fn == nil {
		return false
	}

	// Build the chain that reached `fn`. Fresh slice per recursion so sibling
	// branches don't pollute each other's record.
	curChain := append(append([]*types.Function{}, chain...), fn)
	curContracts := append(append([]*types.Contract{}, chainContracts...), contract)

	env := e.buildFunctionTaintEnv(fn, seed)
	if e.verifyAtFunctionWithEnv(fn, r, contract, env) {
		// Match succeeded at this function. Stash the chain that reached
		// here so the caller can build Reachability/EntryPoint. Only set
		// once — the first successful match is the one we report.
		if e.match != nil && e.match.Chain == nil {
			e.match.Chain = curChain
			e.match.ChainContracts = curContracts
		}
		return true
	}
	if fn.AST == nil || depth >= MaxInterproceduralTaintDepth {
		return false
	}

	key := functionVisitKey(fn, env)
	if visiting[key] {
		return false
	}
	visiting[key] = true
	defer delete(visiting, key)

	matched := false
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind != types.KindCallInternal {
			return true
		}
		callee, calleeContract := e.resolveInternalCallee(contract, node)
		if callee == nil {
			return true
		}
		calleeSeed := e.bindCalleeTaint(callee, node.Children, env)
		if e.verifyAtFunctionWithCallees(callee, r, calleeContract, calleeSeed, visiting, depth+1, curChain, curContracts) {
			matched = true
			return false
		}
		return true
	})
	return matched
}

func (e *Engine) verifyAtFunctionWithEnv(fn *types.Function, r Rule, contract *types.Contract, env map[string][]string) bool {
	// Set context for recursive call graph checking
	prevFunction := e.currentFunction
	prevContract := e.currentContract
	prevTaintEnv := e.currentTaintEnv
	e.currentFunction = fn
	e.currentContract = contract
	e.currentTaintEnv = env
	defer func() {
		e.currentFunction = prevFunction
		e.currentContract = prevContract
		e.currentTaintEnv = prevTaintEnv
	}()

	// Check version constraint if specified
	if r.Version != "" {
		if !e.checkVersion(r.Version) {
			return false
		}
	}

	// Check preset if specified
	if r.Preset != "" {
		if !e.checkPreset(fn, contract, r.Preset) {
			return false
		}
	}

	// Split rule into context and AST parts. Logical operators can carry either
	// kind of predicate, so detect the actual leaves instead of treating all/any
	// as AST-only. regex is intentionally scope-aware and counts as a
	// context predicate at function scope.
	hasContext := ruleHasContextFields(r)
	hasAST := ruleHasASTFields(r)

	// Check context first
	if hasContext {
		if !e.checkFunctionContext(fn, contract, r) {
			return false
		}
	}

	// If only context checks, we're done
	if !hasAST {
		return true
	}

	// Build or get AST for function body
	if fn.AST == nil {
		// No AST available for this function
		return false
	}

	// Now check AST-level rules against the function body
	astRule := r
	// Clear context fields for AST verification (already checked above)
	astRule.Modifier = ""
	astRule.Extends = ""
	astRule.Version = ""
	astRule.Preset = ""
	astRule.FuncName = ""
	astRule.Visibility = ""
	astRule.Mutability = ""
	astRule.HasGuard = nil
	astRule.HasParam = ""
	astRule.Regex = ""
	if r.Not != nil && r.Not.IsContextOnly() {
		astRule.Not = nil
	}

	// For pure structural sequence rules, expand internal callees at their call
	// site before matching. This lets CEI-style templates catch
	// `_sendETH(...); balances[msg.sender] -= amount;` where the outgoing call
	// lives in an internal helper but the state write is in the entrypoint.
	if len(astRule.Sequence) > 0 && !rulesUseContextSensitiveMatchers(astRule.Sequence) {
		if e.verifyInterproceduralSequence(fn, contract, env, astRule.Sequence) {
			return true
		}
	}

	return e.Verify(fn.AST, astRule)
}

func (e *Engine) verifyInterproceduralSequence(fn *types.Function, contract *types.Contract, env map[string][]string, rules []Rule) bool {
	// Allocate a chain map for this match attempt; the walker populates it
	// alongside the node slice so we can reconstruct the entry -> host call
	// chain for whichever node ends up matching the rule's primary atom.
	prevChains := e.ipChains
	e.ipChains = make(map[*types.ASTNode]ipPath)
	defer func() { e.ipChains = prevChains }()

	nodes := e.interproceduralDescendants(fn, contract, env, make(map[string]bool), 0, ipPath{
		Functions: []*types.Function{fn},
		Contracts: []*types.Contract{contract},
	})
	// Nodes here are inlined from multiple functions, so they share no common
	// ancestor and sameExecutionPath does not constrain across the boundary.
	if !e.findSequenceInNodes(nodes, rules, 0, nil) {
		return false
	}
	// On success, surface the chain that led to the matched primary so the
	// caller can build Reachability/EntryPoint.
	if e.match != nil && e.match.Primary != nil {
		if path, ok := e.ipChains[e.match.Primary]; ok {
			e.match.Chain = path.Functions
			e.match.ChainContracts = path.Contracts
		}
	}
	return true
}

func (e *Engine) interproceduralDescendants(fn *types.Function, contract *types.Contract, env map[string][]string, visiting map[string]bool, depth int, chain ipPath) []*types.ASTNode {
	if fn == nil || fn.AST == nil {
		return nil
	}
	key := functionVisitKey(fn, env)
	if visiting[key] {
		return nil
	}
	visiting[key] = true
	defer delete(visiting, key)

	var out []*types.ASTNode
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		out = append(out, node)
		// Record the call chain that reached this node so a successful
		// later match can recover the entry -> host path.
		if e.ipChains != nil {
			e.ipChains[node] = chain
		}
		if node.Kind != types.KindCallInternal || depth >= MaxInterproceduralTaintDepth {
			return true
		}
		callee, calleeContract := e.resolveInternalCallee(contract, node)
		if callee == nil {
			return true
		}
		seed := e.bindCalleeTaint(callee, node.Children, env)
		calleeEnv := e.buildFunctionTaintEnv(callee, seed)

		// Extend the chain for the callee subtree: a fresh slice per recursion
		// so sibling branches don't pollute each other's path records.
		nextChain := ipPath{
			Functions: append(append([]*types.Function{}, chain.Functions...), callee),
			Contracts: append(append([]*types.Contract{}, chain.Contracts...), calleeContract),
		}
		out = append(out, e.interproceduralDescendants(callee, calleeContract, calleeEnv, visiting, depth+1, nextChain)...)
		return true
	})
	return out
}

func rulesUseContextSensitiveMatchers(rules []Rule) bool {
	for _, rule := range rules {
		if rule.TaintedFrom != "" || len(rule.Args) > 0 {
			return true
		}
		if rulesUseContextSensitiveMatchers(rule.All) || rulesUseContextSensitiveMatchers(rule.Any) || rulesUseContextSensitiveMatchers(rule.Sequence) {
			return true
		}
		if rule.Contains != nil && rulesUseContextSensitiveMatchers([]Rule{*rule.Contains}) {
			return true
		}
		if rule.Inside != nil && rulesUseContextSensitiveMatchers([]Rule{*rule.Inside}) {
			return true
		}
		if rule.Left != nil && rulesUseContextSensitiveMatchers([]Rule{*rule.Left}) {
			return true
		}
		if rule.Right != nil && rulesUseContextSensitiveMatchers([]Rule{*rule.Right}) {
			return true
		}
		if rule.Not != nil && rulesUseContextSensitiveMatchers([]Rule{*rule.Not}) {
			return true
		}
	}
	return false
}

func (e *Engine) buildFunctionTaintEnv(fn *types.Function, seed map[string][]string) map[string][]string {
	env := cloneTaintEnv(seed)
	if fn == nil {
		return env
	}
	for _, param := range fn.Parameters {
		if param == nil || param.Name == "" {
			continue
		}
		if _, exists := env[param.Name]; !exists {
			env[param.Name] = []string{"parameter"}
		}
	}
	if fn.AST == nil {
		return env
	}
	// Iterate the forward propagation to a bounded fixpoint. Variable
	// declarations with initializers are already lowered to `stmt.assign` by the
	// builder, so they participate too. Carrying env across passes lets a later
	// definition feed an earlier use — loop-carried taint and out-of-source-order
	// aliases that a single pass misses converge here. Strong updates (each
	// assignment overwrites its target) preserve the sender-vs-parameter
	// precision the context-sensitive matcher depends on: `from = msg.sender`
	// still leaves `from` as sender identity, not arbitrary input.
	for pass := 0; pass < MaxTaintFixpointPasses; pass++ {
		if !e.applyTaintAssignments(fn.AST, env) {
			break // env stable — fixpoint reached
		}
	}
	return env
}

// applyTaintAssignments runs one forward pass over the assignments in root,
// updating env in place with strong-update (last-write-wins) semantics. It
// returns true if any binding changed, signalling that another pass may
// propagate further.
func (e *Engine) applyTaintAssignments(root *types.ASTNode, env map[string][]string) bool {
	changed := false
	root.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind != types.KindStmtAssign || len(node.Children) < 2 {
			return true
		}
		rhs := node.Children[len(node.Children)-1]
		rhsTaints := e.expressionTaints(rhs, env)
		for i := 0; i < len(node.Children)-1; i++ {
			for _, name := range assignmentTargetNames(node.Children[i]) {
				if !taintSlicesEqual(env[name], rhsTaints) {
					env[name] = cloneTaintSources(rhsTaints)
					changed = true
				}
			}
		}
		return true
	})
	return changed
}

// taintSlicesEqual compares two taint-source slices for equality. Both sides are
// kept sorted (cloneTaintSources / sortedTaintSet), so an element-wise compare is
// sufficient.
func taintSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assignmentTargetNames(node *types.ASTNode) []string {
	if node == nil {
		return nil
	}
	names := make(map[string]bool)
	var walk func(*types.ASTNode)
	walk = func(n *types.ASTNode) {
		if n == nil {
			return
		}
		if n.Kind == types.KindExprIdentifier && (n.RefKind == "local_var" || n.RefKind == "parameter") && n.Name != "" {
			names[n.Name] = true
			return
		}
		if (n.Kind == types.KindExprIndexAccess || n.Kind == types.KindExprMemberAccess) && len(n.Children) > 0 {
			// Only the base expression is being written. Index/key expressions
			// such as balances[from] must not make `from` look reassigned.
			walk(n.Children[0])
			return
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	walk(node)

	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) resolveInternalCallee(contract *types.Contract, callNode *types.ASTNode) (*types.Function, *types.Contract) {
	if contract == nil || callNode == nil || callNode.Name == "" {
		return nil, nil
	}

	// Explicit non-virtual targets (notably super/library) carry the exact
	// file#Contract identity from the call-graph builder. Prefer it over any
	// short-name/MRO inference. Internal/self/inherited calls stay virtual and
	// are resolved against the deployment contract's exact MRO below.
	if call := e.recordedCallForNode(callNode); call != nil &&
		(call.CallType == types.CallTypeSuper || call.CallType == types.CallTypeLibrary) {
		if targetContract := e.db.GetContractByID(call.ResolvedContractID); targetContract != nil {
			target := call.ResolvedFunction
			if target == "" {
				target = call.Target
			}
			if fn := findFunctionBySelectorNameAndArity(targetContract.Functions, target, call.ArgCount); fn != nil {
				return fn, targetContract
			}
		}
	}

	argCount := len(callNode.Children)
	for _, candidateContract := range e.db.LinearizedContracts(contract) {
		if fn := findFunctionByNameAndArity(candidateContract.Functions, callNode.Name, argCount); fn != nil {
			return fn, candidateContract
		}
	}
	if fn := findFunctionByNameAndArity(contract.Functions, callNode.Name, argCount); fn != nil {
		return fn, contract
	}
	return nil, nil
}

func (e *Engine) recordedCallForNode(node *types.ASTNode) *types.FunctionCall {
	if e == nil || e.currentFunction == nil || node == nil {
		return nil
	}
	var lineMatch *types.FunctionCall
	for _, call := range e.currentFunction.Calls {
		if call == nil || call.Target != node.Name {
			continue
		}
		if node.StartByte > 0 && call.Byte == node.StartByte {
			return call
		}
		if node.StartLine > 0 && call.Line == node.StartLine && lineMatch == nil {
			lineMatch = call
		}
	}
	return lineMatch
}

func findFunctionBySelectorNameAndArity(functions []*types.Function, target string, argCount int) *types.Function {
	if strings.Contains(target, "(") {
		for _, fn := range functions {
			if fn != nil && fn.Selector == target {
				return fn
			}
		}
		return nil
	}
	return findFunctionByNameAndArity(functions, target, argCount)
}

func findFunctionByNameAndArity(functions []*types.Function, name string, argCount int) *types.Function {
	var fallback *types.Function
	for _, fn := range functions {
		if fn == nil || fn.Name != name {
			continue
		}
		if len(fn.Parameters) == argCount {
			return fn
		}
		if fallback == nil {
			fallback = fn
		}
	}
	return fallback
}

func (e *Engine) bindCalleeTaint(callee *types.Function, args []*types.ASTNode, callerEnv map[string][]string) map[string][]string {
	seed := make(map[string][]string)
	if callee == nil {
		return seed
	}
	for i, param := range callee.Parameters {
		if param == nil || param.Name == "" {
			continue
		}
		if i >= len(args) {
			seed[param.Name] = []string{}
			continue
		}
		seed[param.Name] = e.expressionTaints(args[i], callerEnv)
	}
	return seed
}

func cloneTaintEnv(in map[string][]string) map[string][]string {
	out := make(map[string][]string)
	for name, sources := range in {
		out[name] = cloneTaintSources(sources)
	}
	return out
}

func cloneTaintSources(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func functionVisitKey(fn *types.Function, env map[string][]string) string {
	selector := fn.Selector
	if selector == "" {
		selector = fn.Name
	}
	parts := make([]string, 0, len(env))
	for name, sources := range env {
		parts = append(parts, name+"="+strings.Join(sources, ","))
	}
	sort.Strings(parts)
	identity := fn.ContractName + "." + selector
	if fn.SourceFile != "" {
		identity = types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)
	}
	return identity + "|" + strings.Join(parts, ";")
}

// checkFunctionContext checks all function-level context conditions.
// Context checks are evaluated before AST matching.
// Returns true if the function matches all context conditions (= should be scanned).
func (e *Engine) checkFunctionContext(fn *types.Function, contract *types.Contract, r Rule) bool {
	if fn == nil {
		return false
	}
	if !matchesRegexValue(r.Modifier, fn.Modifiers) || !matchesContractBase(r.Extends, contract) {
		return false
	}
	if r.FuncName != "" && !MatchesRegex(r.FuncName, fn.Name) {
		return false
	}
	if !matchesCSVValue(r.Visibility, string(fn.Visibility), "") {
		return false
	}
	if !matchesCSVValue(r.Mutability, string(fn.StateMutability), "nonpayable") {
		return false
	}
	if r.Regex != "" && !sourceRegexMatches(r.Regex, e.functionSource(fn, contract)) {
		return false
	}
	if r.Version != "" && !e.checkVersion(r.Version) {
		return false
	}
	if r.Preset != "" && !e.checkPreset(fn, contract, r.Preset) {
		return false
	}
	if !hasNamedParameter(fn, r.HasParam) || !e.hasMatchingGuard(fn, r.HasGuard) {
		return false
	}
	if !e.matchesAllContextRules(fn, contract, r.All) || !e.matchesAnyContextRule(fn, contract, r.Any) {
		return false
	}

	// Handle NOT — negate context conditions inside.
	if r.Not != nil && ruleHasContextFields(*r.Not) {
		return !e.checkFunctionContext(fn, contract, *r.Not)
	}

	return true
}

func matchesRegexValue(pattern string, values []string) bool {
	if pattern == "" {
		return true
	}
	for _, value := range values {
		if MatchesRegex(pattern, value) {
			return true
		}
	}
	return false
}

func matchesContractBase(pattern string, contract *types.Contract) bool {
	if pattern == "" || contract == nil {
		return true
	}
	// Extends is a display-name regex, not an identity dereference. Keep the
	// serialized name slice for SDK/manual and legacy inputs without base objects.
	return matchesRegexValue(pattern, contract.LinearizedBases)
}

func matchesCSVValue(filter, value, emptyDefault string) bool {
	if filter == "" {
		return true
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = emptyDefault
	}
	for _, allowed := range strings.Split(filter, ",") {
		if strings.TrimSpace(strings.ToLower(allowed)) == value {
			return true
		}
	}
	return false
}

func hasNamedParameter(fn *types.Function, name string) bool {
	if name == "" {
		return true
	}
	for _, param := range fn.Parameters {
		if param != nil && param.Name == name {
			return true
		}
	}
	return false
}

func (e *Engine) hasMatchingGuard(fn *types.Function, rule *Rule) bool {
	if rule == nil || fn.AST == nil {
		return true
	}
	found := false
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if types.IsCheck(node.Kind) && e.Verify(node, *rule) {
			found = true
			return false
		}
		return true
	})
	return found
}

func (e *Engine) matchesAllContextRules(fn *types.Function, contract *types.Contract, rules []Rule) bool {
	for _, rule := range rules {
		if ruleHasContextFields(rule) && !e.checkFunctionContext(fn, contract, rule) {
			return false
		}
	}
	return true
}

func (e *Engine) matchesAnyContextRule(fn *types.Function, contract *types.Contract, rules []Rule) bool {
	seenContextRule := false
	for _, rule := range rules {
		if !ruleHasContextFields(rule) {
			continue
		}
		seenContextRule = true
		if e.checkFunctionContext(fn, contract, rule) {
			return true
		}
	}
	return !seenContextRule
}

// IsContextOnly returns true if rule only contains context-level checks
// (modifier, extends, version, preset, func_name, visibility_filter,
// mutability_filter, has_guard, has_param, regex)
func (r *Rule) IsContextOnly() bool {
	return ruleHasContextFields(*r) && !ruleHasASTFields(*r)
}

// checkVersion checks if the source file's pragma version matches the constraint
// Supports operators: >=, <=, >, <, = (e.g., ">=0.8.0", "<0.7.0")
func (e *Engine) checkVersion(constraint string) bool {
	if e.currentSourceFile == nil {
		return true // No source file context, skip version check
	}

	pragmaVersion := e.currentSourceFile.PragmaVersion
	if pragmaVersion == "" {
		return true // No pragma version, skip check
	}

	// Parse the constraint
	op, targetVersion := parseVersionConstraint(constraint)
	if targetVersion == "" {
		return true // Invalid constraint, skip check
	}

	// Extract version from pragma (handle ^0.8.0, >=0.8.0, 0.8.0, etc.)
	actualVersion := extractVersion(pragmaVersion)
	if actualVersion == "" {
		return true // Could not extract version, skip check
	}

	// Compare versions
	cmp := compareVersions(actualVersion, targetVersion)

	switch op {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "=", "==":
		return cmp == 0
	default:
		return cmp == 0 // Default to equality
	}
}

// parseVersionConstraint parses a version constraint string
// Returns (operator, version) e.g., (">=", "0.8.0")
func parseVersionConstraint(constraint string) (string, string) {
	constraint = strings.TrimSpace(constraint)

	// Check for operators in order of length (longest first)
	operators := []string{">=", "<=", "==", ">", "<", "="}
	for _, op := range operators {
		if strings.HasPrefix(constraint, op) {
			return op, strings.TrimSpace(constraint[len(op):])
		}
	}

	// No operator, treat as equality
	return "=", constraint
}

// extractVersion extracts the version number from a pragma string
// Handles: ^0.8.0, >=0.8.0 <0.9.0, 0.8.0, etc.
func extractVersion(pragma string) string {
	// Regex to find version numbers (major.minor.patch)
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	match := re.FindString(pragma)
	return match
}

// compareVersions compares two semantic version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	parts1 := parseVersionParts(v1)
	parts2 := parseVersionParts(v2)

	for i := 0; i < 3; i++ {
		if parts1[i] < parts2[i] {
			return -1
		}
		if parts1[i] > parts2[i] {
			return 1
		}
	}
	return 0
}

// parseVersionParts parses a version string into [major, minor, patch]
func parseVersionParts(version string) [3]int {
	parts := strings.Split(version, ".")
	var result [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		result[i], _ = strconv.Atoi(parts[i])
	}
	return result
}

// checkPreset checks if a built-in preset condition is satisfied
// This is a placeholder that will be implemented in presets.go
func (e *Engine) checkPreset(fn *types.Function, contract *types.Contract, preset string) bool {
	// Will be implemented in presets.go
	return checkBuiltinPreset(fn, contract, e, preset)
}

// VerifyAtContract is the top-level entry point for contract-scope verification.
func (e *Engine) VerifyAtContract(contract *types.Contract, r Rule) bool {
	if contract == nil {
		return false
	}

	prevContract := e.currentContract
	prevSourceFile := e.currentSourceFile
	e.currentContract = contract
	e.currentSourceFile = e.db.SourceFiles[contract.SourceFile]
	defer func() {
		e.currentContract = prevContract
		e.currentSourceFile = prevSourceFile
	}()

	return e.verifyAtContract(contract, r)
}

func (e *Engine) verifyAtContract(contract *types.Contract, r Rule) bool {
	if r.IsEmpty() {
		return true
	}

	if ruleHasASTFields(r) {
		root := e.contractAST(contract)
		if root == nil {
			return false
		}
		return e.Verify(root, r)
	}

	if r.Extends != "" {
		found := false
		// Name matching is intentionally compatible with display-only SDK values;
		// it does not resolve or consume a contract identity.
		for _, baseName := range contract.LinearizedBases {
			if MatchesRegex(r.Extends, baseName) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if r.Name != "" && !MatchesRegex(r.Name, contract.Name) {
		return false
	}

	if r.Kind != "" && r.Kind != types.KindDeclContract {
		return false
	}

	if r.Regex != "" {
		if !sourceRegexMatches(r.Regex, e.contractSource(contract)) {
			return false
		}
	}

	for _, subRule := range r.All {
		if !e.verifyAtContract(contract, subRule) {
			return false
		}
	}

	if len(r.Any) > 0 {
		matched := false
		for _, subRule := range r.Any {
			if e.verifyAtContract(contract, subRule) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Handle NOT
	if r.Not != nil {
		return !e.verifyAtContract(contract, *r.Not)
	}

	return true
}

// contractAST returns the synthetic `decl.contract` AST for a contract. It is
// memoized in a single slot (see Engine.contractASTContract/Root) so the match
// pass and the related-site enrichment for the SAME contract share one tree
// without rebuilding; a different contract evicts the previous one.
func (e *Engine) contractAST(contract *types.Contract) *types.ASTNode {
	if contract == nil {
		return nil
	}
	if e.contractASTContract == contract && e.contractASTRoot != nil {
		return e.contractASTRoot
	}
	root := e.buildContractAST(contract)
	e.contractASTContract, e.contractASTRoot = contract, root
	return root
}

// buildContractAST constructs the synthetic `decl.contract` AST: a root whose
// children are cloned `decl.function` ASTs from the contract's linearized
// inheritance chain.
func (e *Engine) buildContractAST(contract *types.Contract) *types.ASTNode {
	root := types.NewASTNode(types.KindDeclContract)
	root.Name = contract.Name
	root.SetAttribute("kind", string(contract.Kind))
	if content := e.sourceContent(contract.SourceFile); content != "" {
		root.StartLine, root.EndLine = sourceContractRange(content, contract.Name)
	}

	for _, base := range e.db.LinearizedContracts(contract) {
		for _, fn := range base.Functions {
			if fn == nil || fn.AST == nil {
				continue
			}
			root.AddChild(cloneFunctionAST(fn, base.SourceFile))
		}
	}
	return root
}

func cloneFunctionAST(fn *types.Function, sourceFile string) *types.ASTNode {
	if fn == nil || fn.AST == nil {
		return nil
	}
	root := cloneASTWithSource(fn.AST, sourceFile)
	if root == nil {
		return nil
	}
	root.Name = fn.Name
	root.StartLine = fn.StartLine
	root.EndLine = fn.EndLine
	root.SetAttribute("contract", fn.ContractName)
	if sourceFile != "" {
		root.SetAttribute("source_file", sourceFile)
	}
	return root
}

func cloneASTWithSource(node *types.ASTNode, sourceFile string) *types.ASTNode {
	if node == nil {
		return nil
	}
	clone := types.NewASTNode(node.Kind)
	clone.Name = node.Name
	clone.Value = node.Value
	clone.RefID = node.RefID
	clone.RefKind = node.RefKind
	clone.TaintSources = append([]string(nil), node.TaintSources...)
	clone.StartLine = node.StartLine
	clone.EndLine = node.EndLine
	for key, value := range node.Attributes {
		clone.Attributes[key] = value
	}
	if sourceFile != "" {
		clone.Attributes["source_file"] = sourceFile
	}
	for _, child := range node.Children {
		clone.AddChild(cloneASTWithSource(child, sourceFile))
	}
	return clone
}

// operandsGuardedBefore reports whether an arithmetic binary-op node has all of
// its operand identifiers bounded by an earlier require/assert/if guard in the
// enclosing function/modifier. It powers the `unchecked_var:` predicate,
// separating a deliberately range-checked `unchecked` block
// (`require(a >= b); … a - b;`) from a genuinely unchecked one. A guard counts
// only when it (a) references EVERY operand identifier and (b) uses an ordering
// comparison (`<`, `<=`, `>`, `>=`) — so `require(a != b)` or `require(a == b)`
// before `a - b` does NOT count (they don't bound the subtraction). Requiring
// all operands and an ordering relation keeps it conservative: real overflow
// risk is still reported.
func operandsGuardedBefore(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	names := operandIdentifierNames(node)
	if len(names) == 0 {
		return false
	}
	root := node.FindAncestor(func(a *types.ASTNode) bool {
		return a.Kind == types.KindDeclFunction || a.Kind == types.KindDeclModifier
	})
	if root == nil {
		return false
	}

	// Expression/statement nodes carry no reliable StartLine here, so "before" is
	// determined by document (DFS) order: a guard counts only if it is visited
	// before the arithmetic node itself. An enclosing `if (a >= b) { … a - b … }`
	// also counts — its condition is visited before the body. WalkDescendants
	// stops the whole traversal when the visitor returns false.
	guarded := false
	root.WalkDescendants(func(n *types.ASTNode) bool {
		if n == node {
			return false // reached the arithmetic; only earlier guards count
		}
		if cond := guardCondition(n); cond != nil && conditionBoundsOperands(cond, names) {
			guarded = true
			return false
		}
		return true
	})
	return guarded
}

// guardCondition returns the condition expression carried by a guard node — the
// whole require/assert node (its subtree is the condition plus optional message)
// or an `if` statement's first child — and nil for any other node.
func guardCondition(n *types.ASTNode) *types.ASTNode {
	switch n.Kind {
	case types.KindCheckRequire, types.KindCheckAssert:
		return n
	case types.KindStmtIf:
		if len(n.Children) > 0 {
			return n.Children[0]
		}
	}
	return nil
}

// operandIdentifierNames collects the identifier names in a binary op's two
// operand subtrees (e.g. {oldAllowance, value} for `oldAllowance - value`).
func operandIdentifierNames(binop *types.ASTNode) map[string]bool {
	names := make(map[string]bool)
	var walk func(n *types.ASTNode)
	walk = func(n *types.ASTNode) {
		if n == nil {
			return
		}
		if n.Kind == types.KindExprIdentifier && n.Name != "" {
			names[n.Name] = true
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	for _, c := range binop.Children {
		walk(c)
	}
	return names
}

// conditionBoundsOperands reports whether cond bounds the operands: every name
// in names appears inside cond AND cond contains an ordering comparison
// (`<`, `<=`, `>`, `>=`). Equality/inequality (`==`/`!=`) do not bound an
// arithmetic operation, so they are intentionally excluded.
func conditionBoundsOperands(cond *types.ASTNode, names map[string]bool) bool {
	seen := make(map[string]bool)
	hasOrdering := false
	var walk func(n *types.ASTNode)
	walk = func(n *types.ASTNode) {
		if n == nil {
			return
		}
		if n.Kind == types.KindExprIdentifier && names[n.Name] {
			seen[n.Name] = true
		}
		if n.Kind == types.KindExprBinaryOp {
			switch n.GetAttributeString("operator") {
			case "<", "<=", ">", ">=":
				hasOrdering = true
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(cond)
	return hasOrdering && len(seen) == len(names)
}

// statementContains reports whether the node's nearest enclosing statement has a
// descendant matching rule. The "statement" is the closest stmt.* / check.* /
// decl.variable ancestor, so the search is scoped to one statement (not the whole
// function, which `inside` would over-match across sibling statements). The
// operator/kind vocabulary lives entirely in rule — the engine stays generic.
// Powers the `statement_contains:` predicate; templates pair it with `not:` to
// require the absence of a related node (e.g. a `^` with no sibling bitwise op).
func (e *Engine) statementContains(node *types.ASTNode, rule Rule) bool {
	scope := node.FindAncestor(func(a *types.ASTNode) bool {
		return strings.HasPrefix(string(a.Kind), "stmt.") ||
			strings.HasPrefix(string(a.Kind), "check.") ||
			a.Kind == types.KindDeclVariable
	})
	if scope == nil {
		return false
	}
	found := false
	scope.WalkDescendants(func(n *types.ASTNode) bool {
		if found {
			return false
		}
		if e.Verify(n, rule) {
			found = true
			return false
		}
		return true
	})
	return found
}

func sourceRegexMatches(pattern, source string) bool {
	if pattern == "" {
		return true
	}
	if source == "" {
		return false
	}
	return MatchesRegex(pattern, source)
}

// ruleHasContextFields reports whether the rule tree carries any function/
// contract precondition. Dual fields (regex/visibility/mutability) count as
// context here so a dual-only rule routes through the precondition path.
// Classification comes from presentRuleFields (single source of truth).
func ruleHasContextFields(r Rule) bool {
	for _, f := range presentRuleFields(&r) {
		if f.class == classContext || f.class == classDual {
			return true
		}
	}
	for _, subRule := range r.All {
		if ruleHasContextFields(subRule) {
			return true
		}
	}
	for _, subRule := range r.Any {
		if ruleHasContextFields(subRule) {
			return true
		}
	}
	return r.Not != nil && ruleHasContextFields(*r.Not)
}

// ruleHasASTFields reports whether the rule tree carries any AST-level field.
// Dual fields (regex/visibility/mutability) are NOT AST here — they lean
// context for routing; contract-scope matches still reach matchAtomic via
// contains/kind, which check them on the node regardless. Classification comes
// from presentRuleFields (single source of truth).
func ruleHasASTFields(r Rule) bool {
	for _, f := range presentRuleFields(&r) {
		if f.class == classAST {
			return true
		}
	}
	for _, subRule := range r.All {
		if ruleHasASTFields(subRule) {
			return true
		}
	}
	for _, subRule := range r.Any {
		if ruleHasASTFields(subRule) {
			return true
		}
	}
	return r.Not != nil && ruleHasASTFields(*r.Not)
}

// hasAtomicPredicate reports whether the rule carries at least one
// surface-level predicate (kind/name/attr/source/taint/operator) — i.e. a
// reason for the current node to count as the matched dangerous statement
// rather than a structural container (`{any: [...]}`, `{contains: ...}`,
// `{sequence: [...]}`) which is just routing the match deeper.
func hasAtomicPredicate(r Rule) bool {
	return r.Kind != "" ||
		r.Name != "" ||
		r.Regex != "" ||
		len(r.Attr) > 0 ||
		r.IsStateVar != nil ||
		r.Operator != "" ||
		r.Visibility != "" ||
		r.Mutability != "" ||
		r.TaintedFrom != ""
}

// hostFunctionFor walks a matched AST node's parent chain to find the
// enclosing decl.function (or decl.modifier) and resolves its name + contract.
// Returns nil values when the node has no captured ancestor chain (synthetic
// fixtures or source-scope matches with no parent link).
func (e *Engine) hostFunctionFor(node *types.ASTNode) (hostName, hostContract, hostFile string, hostLine int) {
	if node == nil {
		return "", "", "", 0
	}
	hostLine = node.StartLine
	for n := node; n != nil; n = n.Parent {
		switch n.Kind {
		case types.KindDeclFunction, types.KindDeclModifier:
			hostName = n.Name
			if contractName := n.GetAttributeString("contract"); contractName != "" {
				hostContract = contractName
			}
			if sourceFile := n.GetAttributeString("source_file"); sourceFile != "" {
				hostFile = sourceFile
			}
			if n.StartLine > 0 {
				hostLine = n.StartLine
			}
			// Resolve contract via the matched node's chain map (populated
			// by the interprocedural walker) or from the verifier context.
			if path, ok := e.ipChains[node]; ok && len(path.Functions) > 0 {
				lastIdx := len(path.Functions) - 1
				last := path.Functions[lastIdx]
				if last != nil {
					hostContract = last.ContractName
					hostFile = last.SourceFile
					if hostFile == "" && lastIdx < len(path.Contracts) && path.Contracts[lastIdx] != nil {
						hostFile = path.Contracts[lastIdx].SourceFile
					}
				}
				return
			}
			if e.currentContract != nil && hostContract == "" {
				hostContract = e.currentContract.Name
			}
			if e.currentContract != nil && hostFile == "" {
				hostFile = e.currentContract.SourceFile
			} else if e.currentFunction != nil && hostContract == "" {
				hostContract = e.currentFunction.ContractName
				hostFile = e.currentFunction.SourceFile
				if hostFile == "" && e.currentContract != nil {
					hostFile = e.currentContract.SourceFile
				}
			}
			return
		}
	}
	// No ancestor — fall back to whatever context we have.
	if e.currentFunction != nil {
		hostName = e.currentFunction.Name
		hostContract = e.currentFunction.ContractName
		hostFile = e.currentFunction.SourceFile
		if hostFile == "" && e.currentContract != nil {
			hostFile = e.currentContract.SourceFile
		}
	}
	return
}
