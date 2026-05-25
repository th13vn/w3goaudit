package engine

import (
	"fmt"
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
func (e *Engine) Verify(node *types.ASTNode, r Rule) bool {
	if node == nil {
		return false
	}

	e.recursionDepth++
	defer func() { e.recursionDepth-- }()
	if e.recursionDepth > MaxRuleRecursionDepth {
		VerboseLog("Verify: recursion depth %d exceeded (max %d) — aborting branch", e.recursionDepth, MaxRuleRecursionDepth)
		return false
	}

	// ========== ATOMIC MATCHERS (check first, fail fast) ==========

	// Check atomic attributes on current node (kind, regex/name, attr, source/tainted_from)
	if !e.matchAtomic(node, r) {
		return false
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

// verifySeq checks if children match rules in sequence
// Enhanced to support deep traversal - searches descendants recursively
//
// TODO(stage-3): the current implementation matches rules in DFS source-text
// order across all descendants. This produces false positives in branched
// code: `if (cond) { externalCall(); } else { state = x; }` matches
// `sequence: [outgoing_call, state_write]` even though those two operations
// cannot both execute. Proper semantics would require same-execution-path
// constraint (CFG-based). Tracked in .vscode/2026-05-08-invariant-audit.md
// §2.5 — the reentrancy templates' biggest source of FP.
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
	return e.findSequenceInNodes(descendants, rules, 0)
}

// findSequenceInNodes searches for rule sequence in a list of nodes
func (e *Engine) findSequenceInNodes(nodes []*types.ASTNode, rules []Rule, startIdx int) bool {
	if len(rules) == 0 {
		return true
	}

	// Try to match first rule starting from each position
	for i := startIdx; i < len(nodes); i++ {
		if e.Verify(nodes[i], rules[0]) {
			// Found match for first rule, try to find remaining rules after this position
			if len(rules) == 1 {
				return true // Last rule matched
			}

			// Recursively find remaining rules
			if e.findSequenceInNodes(nodes, rules[1:], i+1) {
				return true
			}
		}
	}

	return false
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

	// Check taint source
	if r.TaintedFrom != "" {
		res := e.checkTaint(node, r.TaintedFrom)
		return res
	}

	return true
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

		// If Left rule has Kind, check the child expression
		if r.Left.Kind != "" || r.Left.Contains != nil || r.Left.Inside != nil ||
			len(r.Left.All) > 0 || len(r.Left.Any) > 0 {
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

	// Check right (member name)
	if r.Right != nil {
		memberName := node.Name

		if r.Right.Name != "" {
			if !MatchesRegex(r.Right.Name, memberName) {
				return false
			}
		}
		// Right could also specify Kind/other checks for complex scenarios
		// but for member_access the member is just a name, not a node
	}

	return true
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
		// Exact kind like "call.external" or prefix like "call.lowlevel"
		if node.Kind == kind {
			return true
		}
		// Prefix match: "call.lowlevel" matches "call.lowlevel.call"
		if strings.HasPrefix(node.Kind, kind+".") {
			return true
		}
		return false
	}

	// Short prefix without dot: "call", "check", "asm", "stmt", "expr", "decl"
	if kind == "call" || kind == "check" || kind == "asm" || kind == "stmt" || kind == "expr" || kind == "decl" {
		if strings.HasPrefix(node.Kind, kind+".") {
			return true
		}
		return false
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
		actual, ok := actualValue.(bool)
		return ok && actual == expected

	case string:
		actual, ok := actualValue.(string)
		if !ok {
			return false
		}
		// Support regex matching on string attributes
		return MatchesRegex(expected, actual)

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

// matchArgs checks call arguments against rules
func (e *Engine) matchArgs(node *types.ASTNode, args map[int]Rule) bool {
	// Node must be a call type
	switch node.Kind {
	case types.KindCallExternal, types.KindCallInternal,
		types.KindCallLowlevelCall, types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
		types.KindCallBuiltinTransfer, types.KindCallBuiltinSend, types.KindCallCreate:
		// Valid call types
	default:
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
	return e.verifyAtFunctionWithCallees(fn, r, contract, nil, visiting, 0)
}

func (e *Engine) verifyAtFunctionWithCallees(fn *types.Function, r Rule, contract *types.Contract, seed map[string][]string, visiting map[string]bool, depth int) bool {
	if fn == nil {
		return false
	}

	env := e.buildFunctionTaintEnv(fn, seed)
	if e.verifyAtFunctionWithEnv(fn, r, contract, env) {
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
		if e.verifyAtFunctionWithCallees(callee, r, calleeContract, calleeSeed, visiting, depth+1) {
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

	// Split rule into context and AST parts
	// Context: modifier, extends, func_name, visibility_filter, mutability_filter, has_guard, preset, version
	//          (and not: if it only contains context fields)
	// AST: all, any, sequence, contains, inside, kind, name, attr, args, tainted_from
	//      (and not: if it contains AST fields)

	hasContext := r.Modifier != "" || r.Extends != "" ||
		r.FuncName != "" || r.VisibilityFilter != "" || r.MutabilityFilter != "" ||
		r.HasGuard != nil || (r.Not != nil && r.Not.IsContextOnly())
	hasAST := len(r.All) > 0 || len(r.Any) > 0 || len(r.Sequence) > 0 ||
		r.Contains != nil || r.Inside != nil || r.Kind != "" || r.Name != "" ||
		len(r.Attr) > 0 || len(r.Args) > 0 || r.TaintedFrom != "" ||
		(r.Not != nil && !r.Not.IsContextOnly())

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
	astRule.VisibilityFilter = ""
	astRule.MutabilityFilter = ""
	astRule.HasGuard = nil
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
	nodes := e.interproceduralDescendants(fn, contract, env, make(map[string]bool), 0)
	return e.findSequenceInNodes(nodes, rules, 0)
}

func (e *Engine) interproceduralDescendants(fn *types.Function, contract *types.Contract, env map[string][]string, visiting map[string]bool, depth int) []*types.ASTNode {
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
		if node.Kind != types.KindCallInternal || depth >= MaxInterproceduralTaintDepth {
			return true
		}
		callee, calleeContract := e.resolveInternalCallee(contract, node)
		if callee == nil {
			return true
		}
		seed := e.bindCalleeTaint(callee, node.Children, env)
		calleeEnv := e.buildFunctionTaintEnv(callee, seed)
		out = append(out, e.interproceduralDescendants(callee, calleeContract, calleeEnv, visiting, depth+1)...)
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
	fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
		if node.Kind != types.KindStmtAssign || len(node.Children) < 2 {
			return true
		}
		rhs := node.Children[len(node.Children)-1]
		rhsTaints := e.expressionTaints(rhs, env)
		for i := 0; i < len(node.Children)-1; i++ {
			for _, name := range assignmentTargetNames(node.Children[i]) {
				env[name] = cloneTaintSources(rhsTaints)
			}
		}
		return true
	})
	return env
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

	baseNames := contract.LinearizedBases
	if len(baseNames) == 0 {
		baseNames = []string{contract.Name}
	}
	argCount := len(callNode.Children)
	for _, baseName := range baseNames {
		candidateContract := e.db.GetContractByName(baseName)
		if candidateContract == nil {
			continue
		}
		if fn := findFunctionByNameAndArity(candidateContract.Functions, callNode.Name, argCount); fn != nil {
			return fn, candidateContract
		}
	}
	if fn := findFunctionByNameAndArity(contract.Functions, callNode.Name, argCount); fn != nil {
		return fn, contract
	}
	return nil, nil
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
	return fn.ContractName + "." + selector + "|" + strings.Join(parts, ";")
}

// checkFunctionContext checks all function-level context conditions.
// Context checks are evaluated before AST matching.
// Returns true if the function matches all context conditions (= should be scanned).
func (e *Engine) checkFunctionContext(fn *types.Function, contract *types.Contract, r Rule) bool {
	// Check modifier presence
	if r.Modifier != "" {
		found := false
		for _, mod := range fn.Modifiers {
			if MatchesRegex(r.Modifier, mod) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check inheritance (via contract)
	if r.Extends != "" && contract != nil {
		found := false
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

	// Check function name regex (filter.func_name)
	if r.FuncName != "" {
		if !MatchesRegex(r.FuncName, fn.Name) {
			return false
		}
	}

	// Check visibility filter (filter.visibility_filter)
	// Accepts comma-separated list: "public,external"
	if r.VisibilityFilter != "" {
		allowed := strings.Split(r.VisibilityFilter, ",")
		matched := false
		fnVis := strings.ToLower(strings.TrimSpace(string(fn.Visibility)))
		for _, v := range allowed {
			if strings.TrimSpace(strings.ToLower(v)) == fnVis {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check mutability filter (filter.mutability_filter)
	// Accepts comma-separated list: "payable,nonpayable"
	if r.MutabilityFilter != "" {
		allowed := strings.Split(r.MutabilityFilter, ",")
		matched := false
		fnMut := strings.ToLower(strings.TrimSpace(string(fn.StateMutability)))
		for _, v := range allowed {
			if strings.TrimSpace(strings.ToLower(v)) == fnMut {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check has_guard: function body contains a guard (require/assert/revert) matching sub-rule
	if r.HasGuard != nil && fn.AST != nil {
		// Look for a guard node in the AST that matches the sub-rule
		foundGuard := false
		fn.AST.WalkDescendants(func(n *types.ASTNode) bool {
			if types.IsCheck(n.Kind) {
				if e.Verify(n, *r.HasGuard) {
					foundGuard = true
					return false // stop
				}
			}
			return true
		})
		if !foundGuard {
			return false
		}
	}

	// Handle NOT — negate all context conditions inside
	if r.Not != nil {
		return !e.checkFunctionContext(fn, contract, *r.Not)
	}

	return true
}

// IsContextOnly returns true if rule only contains context-level checks
// (modifier, extends, version, preset, func_name, visibility_filter, mutability_filter, has_guard)
func (r *Rule) IsContextOnly() bool {
	hasContextChecks := r.Modifier != "" || r.Extends != "" || r.Version != "" ||
		r.Preset != "" || r.FuncName != "" || r.VisibilityFilter != "" ||
		r.MutabilityFilter != "" || r.HasGuard != nil
	hasOtherChecks := len(r.All) > 0 || len(r.Any) > 0 || len(r.Sequence) > 0 ||
		r.Contains != nil || r.Inside != nil || r.Kind != "" || r.Name != "" ||
		len(r.Attr) > 0 || len(r.Args) > 0 || r.TaintedFrom != ""

	return hasContextChecks && !hasOtherChecks
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

// VerifyAtContract is the top-level entry point for contract-scope verification
func (e *Engine) VerifyAtContract(contract *types.Contract, r Rule) bool {
	// Check contract-level context
	if r.Extends != "" {
		found := false
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

	// Handle NOT
	if r.Not != nil {
		return !e.VerifyAtContract(contract, *r.Not)
	}

	// For contract scope, we might check contract-level patterns
	// This is less common, but could involve checking state variables, functions, etc.

	return true
}

// Debug helper: print rule structure
func (r *Rule) String() string {
	var parts []string

	if len(r.All) > 0 {
		parts = append(parts, fmt.Sprintf("all(%d)", len(r.All)))
	}
	if len(r.Any) > 0 {
		parts = append(parts, fmt.Sprintf("any(%d)", len(r.Any)))
	}
	if r.Not != nil {
		parts = append(parts, "not")
	}
	if len(r.Sequence) > 0 {
		parts = append(parts, fmt.Sprintf("seq(%d)", len(r.Sequence)))
	}
	if r.Contains != nil {
		parts = append(parts, "has")
	}
	if r.Inside != nil {
		parts = append(parts, "inside")
	}
	if r.Kind != "" {
		parts = append(parts, fmt.Sprintf("kind:%s", r.Kind))
	}
	if r.Name != "" {
		parts = append(parts, fmt.Sprintf("regex:%s", r.Name))
	}
	if len(r.Attr) > 0 {
		parts = append(parts, fmt.Sprintf("attr(%d)", len(r.Attr)))
	}
	if r.Modifier != "" {
		parts = append(parts, fmt.Sprintf("mods:%s", r.Modifier))
	}
	if r.Extends != "" {
		parts = append(parts, fmt.Sprintf("inherits:%s", r.Extends))
	}
	if len(r.Args) > 0 {
		parts = append(parts, fmt.Sprintf("args(%d)", len(r.Args)))
	}
	if r.TaintedFrom != "" {
		parts = append(parts, fmt.Sprintf("source:%s", r.TaintedFrom))
	}
	if r.Version != "" {
		parts = append(parts, fmt.Sprintf("version:%s", r.Version))
	}
	if r.Preset != "" {
		parts = append(parts, fmt.Sprintf("preset:%s", r.Preset))
	}

	return "Rule{" + strings.Join(parts, ", ") + "}"
}
