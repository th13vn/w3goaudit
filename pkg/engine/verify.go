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
func (e *Engine) Verify(node *types.ASTNode, r Rule) bool {
	normalized, ok := e.preparedRule(r, "Verify")
	if !ok {
		return false
	}
	return e.verify(node, normalized)
}

func (e *Engine) preparedRule(rule Rule, entrypoint string) (Rule, bool) {
	normalized, err := prepareRuleForEvaluation(rule, "rule")
	if err != nil {
		e.logf("%s rule preparation failed: %v", entrypoint, err)
		return Rule{}, false
	}
	return normalized, true
}

func (e *Engine) verify(node *types.ASTNode, r Rule) (matched bool) {
	if node == nil {
		return false
	}

	var oldPrimary *types.ASTNode
	var oldPrimaryPriority uint8
	traceActive := e.match != nil
	if traceActive {
		oldPrimary = e.match.Primary
		oldPrimaryPriority = e.match.primaryPriority
	}

	e.recursionDepth++
	defer func() {
		if traceActive && !matched {
			e.match.Primary = oldPrimary
			e.match.primaryPriority = oldPrimaryPriority
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
	e.capturePrimary(node, primaryPriorityForRule(r))

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
		if e.verify(node, *r.Not) {
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
		if !e.verify(node, subRule) {
			return false
		}
	}
	return true
}

// verifyAny checks if ANY rule matches (OR logic)
func (e *Engine) verifyAny(node *types.ASTNode, rules []Rule) bool {
	for _, subRule := range rules {
		if e.verify(node, subRule) {
			return true
		}
	}
	return false
}

// verifySeq checks whether the rules can match one linear extension of the
// descendants' execution partial order. Sequential statements retain source
// order. A Solidity call's receiver, options, and explicit argument subtrees
// all precede the call event, while distinct pre-call sibling subtrees remain
// unordered because Solidity does not guarantee their relative order.
func (e *Engine) verifySeq(node *types.ASTNode, rules []Rule) bool {
	if len(rules) == 0 {
		return true
	}
	plan := newSequencePlan()
	builder := sequencePlanBuilder{engine: e, plan: plan}
	builder.buildChildren(node, nil, nil, nil, 0, ipPath{}, nil, builder.newASTOccurrence())
	return e.findSequenceInEvents(plan, rules, nil, make(map[int]bool))
}

type sequenceEvent struct {
	node          *types.ASTNode
	path          ipPath
	arms          map[int]string
	astOccurrence int
}

type sequencePlan struct {
	events []sequenceEvent
	edges  map[int]map[int]struct{}
}

type sequenceRegion struct {
	entries []int
	exits   []int
}

type sequencePlanBuilder struct {
	engine            *Engine
	plan              *sequencePlan
	inlineCallees     bool
	visiting          map[string]bool
	nextArmOccurrence int
	nextASTOccurrence int
}

func newSequencePlan() *sequencePlan {
	return &sequencePlan{edges: make(map[int]map[int]struct{})}
}

func (plan *sequencePlan) addEvent(node *types.ASTNode, path ipPath, arms map[int]string, astOccurrence int) int {
	index := len(plan.events)
	plan.events = append(plan.events, sequenceEvent{
		node:          node,
		path:          cloneIPPath(path),
		arms:          cloneSequenceArms(arms),
		astOccurrence: astOccurrence,
	})
	return index
}

func (builder *sequencePlanBuilder) newASTOccurrence() int {
	occurrence := builder.nextASTOccurrence
	builder.nextASTOccurrence++
	return occurrence
}

func (plan *sequencePlan) order(before, after []int) {
	for _, from := range before {
		if plan.edges[from] == nil {
			plan.edges[from] = make(map[int]struct{})
		}
		for _, to := range after {
			if from != to {
				plan.edges[from][to] = struct{}{}
			}
		}
	}
}

func (plan *sequencePlan) mustExecuteBefore(from, to int) bool {
	if from == to {
		return false
	}
	visited := make(map[int]bool)
	var reaches func(int) bool
	reaches = func(current int) bool {
		if current == to {
			return true
		}
		if visited[current] {
			return false
		}
		visited[current] = true
		for next := range plan.edges[current] {
			if reaches(next) {
				return true
			}
		}
		return false
	}
	return reaches(from)
}

func (builder *sequencePlanBuilder) buildChildren(parent *types.ASTNode, fn *types.Function, contract *types.Contract, env map[string][]string, depth int, chain ipPath, arms map[int]string, astOccurrence int) sequenceRegion {
	if parent == nil {
		return sequenceRegion{}
	}
	armOccurrence := -1
	if sequenceConditionalNode(parent) {
		armOccurrence = builder.nextArmOccurrence
		builder.nextArmOccurrence++
	}
	var result sequenceRegion
	for childIndex, child := range parent.Children {
		childArms := arms
		if arm, ok := sequenceConditionalArm(parent, child, childIndex); ok {
			childArms = cloneSequenceArms(arms)
			childArms[armOccurrence] = arm
		}
		region := builder.buildNode(child, fn, contract, env, depth, chain, childArms, astOccurrence)
		if len(region.entries) == 0 {
			continue
		}
		if len(result.entries) == 0 {
			result.entries = append([]int(nil), region.entries...)
		} else {
			builder.plan.order(result.exits, region.entries)
		}
		result.exits = append([]int(nil), region.exits...)
	}
	return result
}

func (builder *sequencePlanBuilder) buildNode(node *types.ASTNode, fn *types.Function, contract *types.Contract, env map[string][]string, depth int, chain ipPath, arms map[int]string, astOccurrence int) sequenceRegion {
	if node == nil {
		return sequenceRegion{}
	}
	if isSequenceCallEventNode(node) {
		return builder.buildCallNode(node, fn, contract, env, depth, chain, arms, astOccurrence)
	}
	if sequenceEventFollowsChildren(node) {
		return builder.buildEffectNode(node, fn, contract, env, depth, chain, arms, astOccurrence)
	}

	event := builder.plan.addEvent(node, chain, arms, astOccurrence)
	children := builder.buildChildren(node, fn, contract, env, depth, chain, arms, astOccurrence)
	if len(children.entries) == 0 {
		return sequenceRegion{entries: []int{event}, exits: []int{event}}
	}
	builder.plan.order([]int{event}, children.entries)
	return sequenceRegion{entries: []int{event}, exits: children.exits}
}

// buildEffectNode models an enclosing effect only after its operand/value
// expressions have completed. Sibling operand subtrees remain unordered because
// Solidity does not generally guarantee their relative evaluation order.
func (builder *sequencePlanBuilder) buildEffectNode(node *types.ASTNode, fn *types.Function, contract *types.Contract, env map[string][]string, depth int, chain ipPath, arms map[int]string, astOccurrence int) sequenceRegion {
	var operands sequenceRegion
	for _, child := range node.Children {
		region := builder.buildNode(child, fn, contract, env, depth, chain, arms, astOccurrence)
		operands.entries = append(operands.entries, region.entries...)
		operands.exits = append(operands.exits, region.exits...)
	}
	event := builder.plan.addEvent(node, chain, arms, astOccurrence)
	if len(operands.exits) == 0 {
		return sequenceRegion{entries: []int{event}, exits: []int{event}}
	}
	builder.plan.order(operands.exits, []int{event})
	return sequenceRegion{entries: operands.entries, exits: []int{event}}
}

func sequenceEventFollowsChildren(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindStmtAssign,
		types.KindStmtReturn,
		types.KindStmtEmit,
		types.KindDeclVariable,
		types.KindAsmCall,
		types.KindAsmDelegatecall,
		types.KindAsmStaticcall,
		types.KindAsmSstore,
		types.KindAsmSload,
		types.KindAsmSelfdestruct,
		types.KindAsmCreate,
		types.KindAsmCreate2,
		types.KindAsmLog0,
		types.KindAsmLog1,
		types.KindAsmLog2,
		types.KindAsmLog3,
		types.KindAsmLog4,
		types.KindAsmRevert,
		types.KindAsmReturn,
		types.KindAsmOperation:
		return true
	default:
		return false
	}
}

func (builder *sequencePlanBuilder) buildCallNode(node *types.ASTNode, fn *types.Function, contract *types.Contract, env map[string][]string, depth int, chain ipPath, arms map[int]string, astOccurrence int) sequenceRegion {
	var prelude sequenceRegion
	for _, child := range node.Children {
		region := builder.buildNode(child, fn, contract, env, depth, chain, arms, astOccurrence)
		prelude.entries = append(prelude.entries, region.entries...)
		prelude.exits = append(prelude.exits, region.exits...)
	}

	callEvent := builder.plan.addEvent(node, chain, arms, astOccurrence)
	if len(prelude.exits) > 0 {
		builder.plan.order(prelude.exits, []int{callEvent})
	} else {
		prelude.entries = []int{callEvent}
	}
	result := sequenceRegion{entries: prelude.entries, exits: []int{callEvent}}

	if !builder.inlineCallees || !isSolidityCallNode(node) || depth >= MaxInterproceduralTaintDepth {
		return result
	}
	callee, calleeContract := builder.engine.resolveInternalCalleeFrom(fn, contract, node)
	if callee == nil {
		return result
	}
	seed := builder.engine.bindCalleeTaint(callee, callArgumentChildren(node), env)
	calleeEnv := builder.engine.buildFunctionTaintEnv(callee, seed)
	nextChain := ipPath{
		Functions: append(append([]*types.Function{}, chain.Functions...), callee),
		Contracts: append(append([]*types.Contract{}, chain.Contracts...), calleeContract),
	}
	calleeRegion := builder.buildFunction(callee, calleeContract, calleeEnv, depth+1, nextChain, arms)
	if len(calleeRegion.entries) == 0 {
		return result
	}
	builder.plan.order([]int{callEvent}, calleeRegion.entries)
	result.exits = calleeRegion.exits
	return result
}

func (builder *sequencePlanBuilder) buildFunction(fn *types.Function, contract *types.Contract, env map[string][]string, depth int, chain ipPath, arms map[int]string) sequenceRegion {
	if fn == nil || fn.AST == nil {
		return sequenceRegion{}
	}
	key := functionVisitKey(fn, env)
	if builder.visiting[key] {
		return sequenceRegion{}
	}
	builder.visiting[key] = true
	defer delete(builder.visiting, key)
	return builder.buildChildren(fn.AST, fn, contract, env, depth, chain, arms, builder.newASTOccurrence())
}

func cloneIPPath(path ipPath) ipPath {
	return ipPath{
		Functions: append([]*types.Function(nil), path.Functions...),
		Contracts: append([]*types.Contract(nil), path.Contracts...),
	}
}

func cloneSequenceArms(arms map[int]string) map[int]string {
	if len(arms) == 0 {
		return make(map[int]string)
	}
	cloned := make(map[int]string, len(arms))
	for occurrence, arm := range arms {
		cloned[occurrence] = arm
	}
	return cloned
}

func sequenceConditionalNode(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindStmtIf, types.KindExprConditional, types.KindStmtTryCatch:
		return true
	default:
		return false
	}
}

func sequenceConditionalArm(parent, child *types.ASTNode, childIndex int) (string, bool) {
	if parent == nil || child == nil {
		return "", false
	}
	switch parent.Kind {
	case types.KindStmtIf:
		if isConditionExpr(child) {
			return "", false
		}
		return strconv.Itoa(childIndex), true
	case types.KindExprConditional:
		part := child.GetAttributeString("conditional_part")
		return part, part == "true" || part == "false"
	case types.KindStmtTryCatch:
		part := child.GetAttributeString("try_part")
		return part, isTryArm(part)
	default:
		return "", false
	}
}

func sequenceEventsCompatible(left, right sequenceEvent) bool {
	for occurrence, leftArm := range left.arms {
		if rightArm, ok := right.arms[occurrence]; ok && rightArm != leftArm {
			return false
		}
	}
	return true
}

func isSequenceCallEventNode(node *types.ASTNode) bool {
	return isSolidityCallNode(node) || (node != nil && types.IsCheck(node.Kind))
}

// findSequenceInEvents searches for a sequence in any linear extension of the
// event partial order. A candidate may be appended when it is not forced to
// execute before a previously chosen event and all chosen nodes can co-execute.
func (e *Engine) findSequenceInEvents(plan *sequencePlan, rules []Rule, chosen []int, used map[int]bool) bool {
	if len(rules) == 0 {
		return true
	}

	for i, event := range plan.events {
		if used[i] {
			continue
		}
		var primaryCheckpoint *types.ASTNode
		var primaryPriorityCheckpoint uint8
		var chainCheckpoint []*types.Function
		var chainContractsCheckpoint []*types.Contract
		if e.match != nil {
			primaryCheckpoint = e.match.Primary
			primaryPriorityCheckpoint = e.match.primaryPriority
			chainCheckpoint = e.match.Chain
			chainContractsCheckpoint = e.match.ChainContracts
		}
		if !e.verify(event.node, rules[0]) {
			if e.match != nil {
				e.match.Primary = primaryCheckpoint
				e.match.primaryPriority = primaryPriorityCheckpoint
				e.match.Chain = chainCheckpoint
				e.match.ChainContracts = chainContractsCheckpoint
			}
			continue
		}
		if e.match != nil && len(event.path.Functions) > 0 &&
			(e.match.Primary != primaryCheckpoint || e.match.primaryPriority != primaryPriorityCheckpoint) {
			e.match.Chain = append([]*types.Function(nil), event.path.Functions...)
			e.match.ChainContracts = append([]*types.Contract(nil), event.path.Contracts...)
		}
		restorePrimary := func() {
			if e.match != nil {
				e.match.Primary = primaryCheckpoint
				e.match.primaryPriority = primaryPriorityCheckpoint
				e.match.Chain = chainCheckpoint
				e.match.ChainContracts = chainContractsCheckpoint
			}
		}
		compatible := true
		for _, previous := range chosen {
			previousEvent := plan.events[previous]
			previousNode := previousEvent.node
			sameASTOccurrence := previousEvent.astOccurrence == event.astOccurrence
			if plan.mustExecuteBefore(i, previous) ||
				(sameASTOccurrence && isWithinSubtree(event.node, previousNode)) ||
				(sameASTOccurrence && !sameExecutionPath(previousNode, event.node)) ||
				!sequenceEventsCompatible(previousEvent, event) {
				compatible = false
				break
			}
		}
		if !compatible {
			restorePrimary()
			continue
		}
		if len(rules) == 1 {
			return true
		}
		used[i] = true
		if e.findSequenceInEvents(plan, rules[1:], append(chosen, i), used) {
			return true
		}
		delete(used, i)
		restorePrimary()
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
		if e.verify(n, rule) {
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
		if e.verify(n, rule) {
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

		// Verify every non-name predicate against the child expression. Using
		// the shared Rule emptiness check keeps this path aligned with newly
		// added recursive fields such as ArgAny.
		if hasNonNameRulePredicate(r.Left) {
			// Check against the child node (parent expression)
			if len(node.Children) > 0 {
				if !e.verify(node.Children[0], *r.Left) {
					return false
				}
			} else {
				return false
			}
		}
		if r.Left.Name != "" {
			// Apply the parent-name regex independently from child verification.
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
		if hasNonNameRulePredicate(r.Right) {
			return false
		}
	}
	if (r.Left != nil && r.Left.Name != "") || (r.Right != nil && r.Right.Name != "") {
		e.capturePrimary(node, primaryPriorityTraceableAST)
	}

	return true
}

// hasNonNameRulePredicate reports whether r carries any matching semantics
// beyond Name. Member-access right sides have no child node for those
// predicates, while left sides must evaluate them against the receiver child.
func hasNonNameRulePredicate(r *Rule) bool {
	if r == nil {
		return false
	}
	cp := *r
	cp.Name = ""
	return !cp.IsEmpty()
}

// matchBinaryLeftRight checks left/right for assignment and binary_op nodes
// Children order: [0] = left operand, [1] = right operand
func (e *Engine) matchBinaryLeftRight(node *types.ASTNode, r Rule) bool {
	// Check left (first child)
	if r.Left != nil {
		if len(node.Children) < 1 {
			return false
		}
		if !e.verify(node.Children[0], *r.Left) {
			return false
		}
	}

	// Check right (second child)
	if r.Right != nil {
		if len(node.Children) < 2 {
			return false
		}
		if !e.verify(node.Children[1], *r.Right) {
			return false
		}
	}

	return true
}

func stateWriteTargetName(node *types.ASTNode) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case types.KindStmtStateMutation:
		for _, child := range node.Children {
			if child.GetAttributeBool("call_receiver") {
				return lvalueStateVarName(child)
			}
		}
	case types.KindExprUnaryOp:
		if len(node.Children) > 0 {
			return lvalueStateVarName(node.Children[0])
		}
	}
	return ""
}

func lvalueStateVarName(node *types.ASTNode) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case types.KindExprIdentifier:
		if node.RefKind == "state_var" {
			return node.Name
		}
	case types.KindExprIndexAccess, types.KindExprMemberAccess:
		if len(node.Children) > 0 {
			return lvalueStateVarName(node.Children[0])
		}
	}
	return ""
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
		switch node.Kind {
		case types.KindAsmSstore:
			return true
		case types.KindStmtAssign:
			return node.GetAttributeBool("is_state_var")
		case types.KindStmtStateMutation:
			return node.GetAttributeBool("is_state_var") && stateWriteTargetName(node) != ""
		case types.KindExprUnaryOp:
			if stateWriteTargetName(node) == "" {
				return false
			}
			switch node.GetAttributeString("operator") {
			case "delete", "++", "--":
				return true
			}
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
	if !exists && key == "receiver_name" {
		// Older schema-2.0.0 caches still retain the structurally authoritative
		// direct receiver child. Derive the additive fact without mutating the
		// caller-owned or loaded AST.
		for _, child := range node.Children {
			if child != nil && child.GetAttributeBool("call_receiver") && child.Name != "" {
				actualValue = child.Name
				exists = true
				break
			}
		}
	}
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
		if e.verify(arg, rule) {
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
		if argIndex < 0 || argIndex >= len(callArgs) {
			return false // Argument index out of range
		}
		if !e.verify(callArgs[argIndex], argRule) {
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
		if taintSourceMatches(source, sourceType) {
			return true
		}
	}
	return false
}

func taintSourceMatches(actual, requested string) bool {
	if requested == "user_controlled" {
		return actual == "parameter" || actual == "sender"
	}
	return actual == requested
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
	if e.isCallerIdentityNode(node) {
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

func (e *Engine) isCallerIdentityNode(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprMemberAccess {
		member := node.Name
		var parent string
		if len(node.Children) > 0 {
			receiver := node.Children[0]
			if receiver == nil || receiver.Kind != types.KindExprIdentifier {
				return false
			}
			parent = receiver.Name
		} else {
			parent = node.GetAttributeString("parent")
		}
		return (parent == "msg" && member == "sender") ||
			(parent == "tx" && member == "origin")
	}
	if node.Name != "_msgSender" || len(callArgumentChildren(node)) != 0 {
		return false
	}

	if call := e.recordedCallForNode(node); call != nil {
		switch call.CallType {
		case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSuper:
		default:
			return false
		}
		if call.ArgCount > 0 || (call.ResolvedFunction != "" && call.ResolvedFunction != "_msgSender()") {
			return false
		}
		if e.currentContract != nil {
			callee, _ := e.resolveInternalCallee(e.currentContract, node)
			return isMsgSenderHelper(callee)
		}
		return call.Resolved && call.ResolvedFunction == "_msgSender()" && call.ResolvedContractID != ""
	}

	if e.currentContract != nil {
		if node.Kind != types.KindCallInternal {
			return false
		}
		callee, _ := e.resolveInternalCallee(e.currentContract, node)
		return isMsgSenderHelper(callee)
	}

	// Compatibility for synthetic/programmatic ASTs without function/database
	// context: accept only the exact zero-argument internal-call shape.
	return node.Kind == types.KindCallInternal
}

func isMsgSenderHelper(fn *types.Function) bool {
	if fn == nil || fn.Name != "_msgSender" || len(fn.Parameters) != 0 {
		return false
	}
	return fn.Selector == "" || fn.Selector == "_msgSender()"
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
	normalized, ok := e.preparedRule(r, "VerifyAtFunction")
	if !ok {
		return false
	}
	env := e.buildFunctionTaintEnv(fn, nil)
	return e.verifyAtFunctionWithEnv(fn, normalized, contract, env)
}

// VerifyAtFunctionWithCallees verifies a function and recursively follows
// internal calls with context-sensitive argument taint. It is used for
// entrypoint match rules so helper functions inherit the caller's actual
// argument sources.
func (e *Engine) VerifyAtFunctionWithCallees(fn *types.Function, r Rule, contract *types.Contract) bool {
	normalized, ok := e.preparedRule(r, "VerifyAtFunctionWithCallees")
	if !ok {
		return false
	}
	visiting := make(map[string]bool)
	return e.verifyAtFunctionWithCallees(fn, normalized, contract, nil, visiting, 0, nil, nil)
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
		if !isSolidityCallNode(node) {
			return true
		}
		callee, calleeContract := e.resolveInternalCalleeFrom(fn, contract, node)
		if callee == nil {
			return true
		}
		calleeSeed := e.bindCalleeTaint(callee, callArgumentChildren(node), env)
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

	return e.verify(fn.AST, astRule)
}

func (e *Engine) verifyInterproceduralSequence(fn *types.Function, contract *types.Contract, env map[string][]string, rules []Rule) bool {
	chain := ipPath{
		Functions: []*types.Function{fn},
		Contracts: []*types.Contract{contract},
	}
	plan := newSequencePlan()
	builder := sequencePlanBuilder{
		engine:        e,
		plan:          plan,
		inlineCallees: true,
		visiting:      make(map[string]bool),
	}
	builder.buildFunction(fn, contract, env, 0, chain, nil)
	return e.findSequenceInEvents(plan, rules, nil, make(map[int]bool))
}

func rulesUseContextSensitiveMatchers(rules []Rule) bool {
	usesContext := false
	for i := range rules {
		_ = walkRules(&rules[i], func(rule *Rule) error {
			if rule.TaintedFrom != "" || len(rule.Args) > 0 || rule.ArgAny != nil {
				usesContext = true
			}
			return nil
		})
		if usesContext {
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
	return e.resolveInternalCalleeFrom(e.currentFunction, contract, callNode)
}

func (e *Engine) resolveInternalCalleeFrom(hostFn *types.Function, contract *types.Contract, callNode *types.ASTNode) (*types.Function, *types.Contract) {
	if contract == nil || callNode == nil || callNode.Name == "" || !isSolidityCallNode(callNode) {
		return nil, nil
	}

	mro := e.runtimeContracts(contract)
	recorded := e.recordedCallsForNodeFrom(hostFn, callNode)
	for _, call := range recorded {
		if call == nil || !isTraversableRecordedCallType(call.CallType) {
			return nil, nil
		}
	}
	exact := make([]*types.FunctionCall, 0, len(recorded))
	for _, call := range recorded {
		if call != nil && call.Resolved && call.ResolvedContractID != "" && strings.Contains(call.ResolvedFunction, "(") {
			exact = append(exact, call)
		}
	}
	if len(exact) > 0 {
		return e.resolveExactRecordedCalleeFrom(hostFn, mro, exact)
	}
	if callNode.Kind != types.KindCallInternal {
		return nil, nil
	}

	return uniqueFunctionByNameAndArity(mro, callNode.Name, len(callArgumentChildren(callNode)))
}

func isSolidityCallNode(node *types.ASTNode) bool {
	return node != nil && strings.HasPrefix(node.Kind, "call.")
}

func isTraversableRecordedCallType(callType types.CallType) bool {
	switch callType {
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSelf,
		types.CallTypeSuper, types.CallTypeLibrary:
		return true
	default:
		return false
	}
}

func (e *Engine) recordedCallForNode(node *types.ASTNode) *types.FunctionCall {
	matches := e.recordedCallsForNode(node)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

func (e *Engine) recordedCallsForNode(node *types.ASTNode) []*types.FunctionCall {
	return e.recordedCallsForNodeFrom(e.currentFunction, node)
}

func (e *Engine) recordedCallsForNodeFrom(hostFn *types.Function, node *types.ASTNode) []*types.FunctionCall {
	if e == nil || hostFn == nil || node == nil {
		return nil
	}
	var byteMatches, columnMatches, lineMatches []*types.FunctionCall
	for _, call := range hostFn.Calls {
		if call == nil || call.Target != node.Name {
			continue
		}
		if node.StartByte > 0 && call.Byte == node.StartByte {
			byteMatches = append(byteMatches, call)
		}
		if node.StartLine > 0 && call.Line == node.StartLine {
			lineMatches = append(lineMatches, call)
			if node.StartCol > 0 && call.Col == node.StartCol {
				columnMatches = append(columnMatches, call)
			}
		}
	}
	if len(byteMatches) > 0 {
		return byteMatches
	}
	if len(columnMatches) > 0 {
		return columnMatches
	}
	if len(lineMatches) == 1 {
		return lineMatches
	}
	if len(lineMatches) > 1 {
		first := lineMatches[0]
		samePhysicalSite := first.Byte > 0 || first.Col > 0
		for _, call := range lineMatches[1:] {
			if call.Byte != first.Byte || call.Col != first.Col {
				samePhysicalSite = false
				break
			}
		}
		if samePhysicalSite {
			return lineMatches
		}
	}
	return nil
}

func (e *Engine) runtimeContracts(contract *types.Contract) []*types.Contract {
	if contract == nil {
		return nil
	}
	mro := e.db.LinearizedContracts(contract)
	if len(mro) > 0 {
		return mro
	}
	return []*types.Contract{contract}
}

func (e *Engine) resolveExactRecordedCalleeFrom(hostFn *types.Function, mro []*types.Contract, calls []*types.FunctionCall) (*types.Function, *types.Contract) {
	allSuper := len(calls) > 0
	for _, call := range calls {
		if call.CallType != types.CallTypeSuper {
			allSuper = false
			break
		}
	}
	if allSuper {
		if fn, owner, ok := e.resolveRuntimeSuperFrom(hostFn, mro, calls); ok {
			return fn, owner
		}
		return nil, nil
	}

	type candidate struct {
		fn    *types.Function
		owner *types.Contract
	}
	candidates := make(map[string]candidate)
	for _, call := range calls {
		fn, owner := e.resolveExactRecordedCall(mro, call)
		if fn == nil || owner == nil {
			return nil, nil
		}
		key := owner.ID + "\x00" + evaluatorFunctionSelector(fn)
		candidates[key] = candidate{fn: fn, owner: owner}
	}
	if len(candidates) != 1 {
		return nil, nil
	}
	for _, resolved := range candidates {
		return resolved.fn, resolved.owner
	}
	return nil, nil
}

func (e *Engine) resolveExactRecordedCall(mro []*types.Contract, call *types.FunctionCall) (*types.Function, *types.Contract) {
	if call == nil || e.db == nil {
		return nil, nil
	}
	targetContract := e.db.GetContractByID(call.ResolvedContractID)
	if targetContract == nil {
		return nil, nil
	}
	switch call.CallType {
	case types.CallTypeSuper, types.CallTypeLibrary:
		return findFunctionByExactSelector(targetContract, call.ResolvedFunction)
	case types.CallTypeInternal, types.CallTypeInherited, types.CallTypeSelf:
		if !contractInExactMRO(mro, targetContract.ID) {
			return nil, nil
		}
		for _, candidateContract := range mro {
			if fn, owner := findFunctionByExactSelector(candidateContract, call.ResolvedFunction); fn != nil {
				return fn, owner
			}
		}
	}
	return nil, nil
}

func (e *Engine) resolveRuntimeSuperFrom(hostFn *types.Function, mro []*types.Contract, calls []*types.FunctionCall) (*types.Function, *types.Contract, bool) {
	if hostFn == nil || hostFn.SourceFile == "" {
		if len(calls) != 1 {
			return nil, nil, false
		}
		fn, owner := e.resolveExactRecordedCall(mro, calls[0])
		return fn, owner, fn != nil
	}
	hostID := types.MakeContractID(hostFn.SourceFile, hostFn.ContractName)
	hostIndex := -1
	for i, candidate := range mro {
		if candidate != nil && candidate.ID == hostID {
			hostIndex = i
			break
		}
	}
	if hostIndex < 0 {
		return nil, nil, false
	}
	selector := calls[0].ResolvedFunction
	for _, call := range calls[1:] {
		if call.ResolvedFunction != selector {
			return nil, nil, false
		}
	}
	for _, candidateContract := range mro[hostIndex+1:] {
		fn, owner := findFunctionByExactSelector(candidateContract, selector)
		if fn == nil {
			continue
		}
		for _, call := range calls {
			if call.ResolvedContractID == owner.ID {
				return fn, owner, true
			}
		}
		return nil, nil, false
	}
	return nil, nil, false
}

func findFunctionByExactSelector(contract *types.Contract, selector string) (*types.Function, *types.Contract) {
	if contract == nil || selector == "" {
		return nil, nil
	}
	for _, fn := range contract.Functions {
		if fn != nil && evaluatorFunctionSelector(fn) == selector {
			return fn, contract
		}
	}
	return nil, nil
}

func uniqueFunctionByNameAndArity(mro []*types.Contract, name string, argCount int) (*types.Function, *types.Contract) {
	type candidate struct {
		fn    *types.Function
		owner *types.Contract
	}
	bySelector := make(map[string]candidate)
	for _, contract := range mro {
		if contract == nil {
			continue
		}
		for _, fn := range contract.Functions {
			if fn == nil || fn.Name != name || len(fn.Parameters) != argCount {
				continue
			}
			selector := evaluatorFunctionSelector(fn)
			if _, exists := bySelector[selector]; !exists {
				bySelector[selector] = candidate{fn: fn, owner: contract}
			}
		}
	}
	if len(bySelector) != 1 {
		return nil, nil
	}
	for _, resolved := range bySelector {
		return resolved.fn, resolved.owner
	}
	return nil, nil
}

func evaluatorFunctionSelector(fn *types.Function) string {
	if fn == nil {
		return ""
	}
	if fn.Selector != "" {
		return fn.Selector
	}
	return fn.GetSelector(nil)
}

func contractInExactMRO(mro []*types.Contract, contractID string) bool {
	for _, contract := range mro {
		if contract != nil && contract.ID == contractID {
			return true
		}
	}
	return false
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
	if !hasNamedParameter(fn, r.HasParam) || !e.hasMatchingGuard(fn, contract, r.HasGuard) {
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

func (e *Engine) verifyContextNode(node *types.ASTNode, rule Rule) bool {
	trace := e.match
	e.match = nil
	defer func() { e.match = trace }()
	return e.verify(node, rule)
}

func (e *Engine) hasMatchingGuard(fn *types.Function, contract *types.Contract, rule *Rule) bool {
	if rule == nil {
		return true
	}
	if fn != nil && fn.AST != nil {
		found := false
		fn.AST.WalkDescendants(func(node *types.ASTNode) bool {
			if types.IsCheck(node.Kind) && e.verifyContextNode(node, *rule) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	if fn == nil {
		return false
	}
	for _, applied := range fn.Modifiers {
		if modifier := e.appliedModifierDeclaration(contract, applied); modifier != nil &&
			e.verifyContextNode(modifier, *rule) {
			return true
		}
	}
	return false
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
	normalized, ok := e.preparedRule(r, "VerifyAtContract")
	if !ok {
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

	return e.verifyAtContract(contract, normalized)
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
		return e.verify(root, r)
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

func setDeclarationSpan(node *types.ASTNode, sourceFile string,
	startLine, endLine, startCol, endCol, startByte, endByte int,
) {
	node.StartLine = startLine
	node.EndLine = endLine
	node.StartCol = startCol
	node.EndCol = endCol
	node.StartByte = startByte
	node.EndByte = endByte
	if sourceFile != "" {
		node.SetAttribute("source_file", sourceFile)
	}
}

type ownedFunction struct {
	fn    *types.Function
	owner *types.Contract
}

func activeFunctionKey(fn *types.Function) string {
	switch {
	case fn == nil:
		return ""
	case fn.IsConstructor:
		return "<constructor>"
	case fn.IsReceive:
		return "<receive>"
	case fn.IsFallback:
		return "<fallback>"
	default:
		return evaluatorFunctionSelector(fn)
	}
}

func (e *Engine) activeContractFunctions(contract *types.Contract) []ownedFunction {
	var out []ownedFunction
	seen := make(map[string]bool)
	for mroIndex, base := range e.db.LinearizedContracts(contract) {
		for _, fn := range base.Functions {
			if fn == nil || fn.AST == nil {
				continue
			}
			if fn.IsConstructor && mroIndex > 0 {
				continue
			}
			key := activeFunctionKey(fn)
			if key == "" {
				key = base.ID + ":" + fn.Name
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ownedFunction{fn: fn, owner: base})
		}
	}
	return out
}

// buildContractAST constructs the synthetic declaration tree for a contract.
// Active functions are selected by exact C3 MRO and canonical selector, while
// state variables and modifiers retain their exact declaration owners.
func (e *Engine) buildContractAST(contract *types.Contract) *types.ASTNode {
	root := types.NewASTNode(types.KindDeclContract)
	root.Name = contract.Name
	root.SetAttribute("kind", string(contract.Kind))
	setDeclarationSpan(root, contract.SourceFile, contract.StartLine, contract.EndLine,
		contract.StartCol, contract.EndCol, contract.StartByte, contract.EndByte)
	for _, owned := range e.activeContractFunctions(contract) {
		root.AddChild(cloneFunctionAST(owned.fn, owned.owner.SourceFile))
	}
	for _, base := range e.db.LinearizedContracts(contract) {
		for _, variable := range base.StateVariables {
			root.AddChild(stateVariableDeclarationNode(variable, base))
		}
		for _, modifier := range base.Modifiers {
			root.AddChild(modifierDeclarationNode(modifier, base))
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
	root.Kind = types.KindDeclFunction
	root.Name = fn.Name
	root.SetAttribute("contract", fn.ContractName)
	root.SetAttribute("visibility", string(fn.Visibility))
	root.SetAttribute("mutability", string(fn.StateMutability))
	setDeclarationSpan(root, sourceFile, fn.StartLine, fn.EndLine, fn.StartCol,
		fn.EndCol, fn.StartByte, fn.EndByte)
	body := append([]*types.ASTNode(nil), root.Children...)
	root.Children = nil
	for _, param := range fn.Parameters {
		root.AddChild(parameterDeclarationNode(param, sourceFile, "input"))
	}
	for _, result := range fn.Returns {
		root.AddChild(parameterDeclarationNode(result, sourceFile, "return"))
	}
	root.AddChildren(body...)
	return root
}

func parameterDeclarationNode(param *types.Parameter, sourceFile, role string) *types.ASTNode {
	if param == nil {
		return nil
	}
	node := types.NewASTNode(types.KindDeclParameter)
	node.Name = param.Name
	node.SetAttribute("type", param.TypeName)
	node.SetAttribute("parameter_role", role)
	setDeclarationSpan(node, sourceFile, param.StartLine, param.EndLine,
		param.StartCol, param.EndCol, param.StartByte, param.EndByte)
	return node
}

func modifierDeclarationNode(mod *types.Modifier, owner *types.Contract) *types.ASTNode {
	if mod == nil || owner == nil {
		return nil
	}
	node := cloneASTWithSource(mod.AST, owner.SourceFile)
	if node == nil {
		node = types.NewASTNode(types.KindDeclModifier)
	}
	node.Kind = types.KindDeclModifier
	node.Name = mod.Name
	node.SetAttribute("contract", owner.Name)
	setDeclarationSpan(node, owner.SourceFile, mod.StartLine, mod.EndLine,
		mod.StartCol, mod.EndCol, mod.StartByte, mod.EndByte)
	body := append([]*types.ASTNode(nil), node.Children...)
	node.Children = nil
	for _, param := range mod.Parameters {
		node.AddChild(parameterDeclarationNode(param, owner.SourceFile, "modifier"))
	}
	node.AddChildren(body...)
	return node
}

func (e *Engine) appliedModifierDeclaration(contract *types.Contract, name string) *types.ASTNode {
	if contract == nil {
		return nil
	}
	if e.modifierDeclContract != contract || e.modifierDeclByName == nil {
		declarations := make(map[string]*types.ASTNode)
		for _, base := range e.db.LinearizedContracts(contract) {
			for _, modifier := range base.Modifiers {
				if modifier == nil {
					continue
				}
				if _, exists := declarations[modifier.Name]; exists {
					continue
				}
				declarations[modifier.Name] = modifierDeclarationNode(modifier, base)
			}
		}
		e.modifierDeclContract = contract
		e.modifierDeclByName = declarations
	}
	return e.modifierDeclByName[name]
}

func stateVariableDeclarationNode(variable *types.StateVariable, owner *types.Contract) *types.ASTNode {
	if variable == nil || owner == nil {
		return nil
	}
	node := types.NewASTNode(types.KindDeclVariable)
	node.Name = variable.Name
	node.RefKind = "state_var"
	node.SetAttribute("contract", owner.Name)
	node.SetAttribute("type", variable.TypeName)
	node.SetAttribute("visibility", variable.Visibility)
	node.SetAttribute("is_state_var", true)
	setDeclarationSpan(node, owner.SourceFile, variable.StartLine, variable.EndLine,
		variable.StartCol, variable.EndCol, variable.StartByte, variable.EndByte)
	return node
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
	clone.StartCol = node.StartCol
	clone.EndCol = node.EndCol
	clone.StartByte = node.StartByte
	clone.EndByte = node.EndByte
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

// operandsGuardedBefore reports whether a subtraction is protected by a local,
// enforced fact that proves minuend >= subtrahend on the operation's execution
// path. It recognizes direct preceding require/assert checks, an effect-free
// dominating if arm, and effect-free fallthrough after the opposite arm
// unconditionally exits. The first intervening statement or call ends the
// proof, as does any call ancestor or effectful sibling on the subtraction's
// expression path. Mere name occurrence or an unrelated ordering expression is
// never evidence.
func operandsGuardedBefore(node *types.ASTNode) bool {
	left, right, ok := subtractionOperands(node)
	if !ok {
		return false
	}
	if !subtractionExpressionPathIsEffectFree(node) {
		return false
	}

	for current := node; current != nil && current.Parent != nil; current = current.Parent {
		parent := current.Parent
		if parent.Kind == types.KindStmtIf && ifArmProvesBound(parent, current, node, left, right) {
			return true
		}
		if isSequentialASTContainer(parent) {
			idx := directChildIndex(parent, current)
			if idx < 0 {
				return false
			}
			if idx > 0 {
				return precedingStatementProvesBound(parent.Children[idx-1], left, right)
			}
		}
		if parent.Kind == types.KindDeclFunction || parent.Kind == types.KindDeclModifier {
			break
		}
	}
	return false
}

// subtractionExpressionPathIsEffectFree validates the complete expression path
// from the subtraction to its enclosing sequential statement before any bound
// proof is accepted. Only wrappers with known effect ordering and structurally
// pure siblings are allowed. Calls and unknown wrappers fail closed.
func subtractionExpressionPathIsEffectFree(subtraction *types.ASTNode) bool {
	for current := subtraction; current != nil && current.Parent != nil; current = current.Parent {
		parent := current.Parent
		if isSequentialASTContainer(parent) {
			return true
		}
		if parent.Kind == types.KindStmtIf {
			idx := directChildIndex(parent, current)
			return idx == 1 || idx == 2
		}
		if !expressionParentAllowsBoundProof(parent, current) {
			return false
		}
	}
	return false
}

func expressionParentAllowsBoundProof(parent, pathChild *types.ASTNode) bool {
	idx := directChildIndex(parent, pathChild)
	if idx < 0 {
		return false
	}

	switch parent.Kind {
	case types.KindStmtReturn:
		return len(parent.Children) == 1 && idx == 0
	case types.KindStmtAssign:
		operator := parent.GetAttributeString("operator")
		if (operator != "" && operator != "=") || idx != len(parent.Children)-1 {
			return false
		}
		return expressionSiblingsAreEffectFree(parent, idx)
	case types.KindExprBinaryOp, types.KindExprMemberAccess, types.KindExprIndexAccess,
		types.KindExprConditional, types.KindExprTuple:
		return expressionSiblingsAreEffectFree(parent, idx)
	case types.KindExprUnaryOp:
		switch parent.GetAttributeString("operator") {
		case "++", "--", "delete":
			return false
		default:
			return expressionSiblingsAreEffectFree(parent, idx)
		}
	default:
		return false
	}
}

func expressionSiblingsAreEffectFree(parent *types.ASTNode, pathIndex int) bool {
	for i, sibling := range parent.Children {
		if i != pathIndex && !isStructurallyEffectFreeExpression(sibling) {
			return false
		}
	}
	return true
}

func isStructurallyEffectFreeExpression(node *types.ASTNode) bool {
	if node == nil {
		return true
	}
	switch node.Kind {
	case types.KindExprIdentifier, types.KindExprLiteral:
		return true
	case types.KindExprBinaryOp, types.KindExprMemberAccess, types.KindExprIndexAccess,
		types.KindExprConditional, types.KindExprTuple:
	case types.KindExprUnaryOp:
		switch node.GetAttributeString("operator") {
		case "++", "--", "delete":
			return false
		}
	default:
		return false
	}
	for _, child := range node.Children {
		if !isStructurallyEffectFreeExpression(child) {
			return false
		}
	}
	return true
}

func subtractionOperands(node *types.ASTNode) (left, right *types.ASTNode, ok bool) {
	if node == nil || len(node.Children) != 2 {
		return nil, nil, false
	}
	switch {
	case node.Kind == types.KindExprBinaryOp && node.GetAttributeString("operator") == "-":
	case node.Kind == types.KindStmtAssign && node.GetAttributeString("operator") == "-=":
	default:
		return nil, nil, false
	}
	left, right = node.Children[0], node.Children[1]
	if !isStableBoundExpression(left) || !isStableBoundExpression(right) ||
		!isUnsignedIntegerBoundExpression(left) || !isUnsignedIntegerBoundExpression(right) {
		return nil, nil, false
	}
	return left, right, true
}

func isStableBoundExpression(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindExprIdentifier, types.KindExprLiteral:
		return true
	case types.KindExprMemberAccess, types.KindExprIndexAccess:
		for _, child := range node.Children {
			if !isStableBoundExpression(child) {
				return false
			}
		}
		return len(node.Children) > 0
	default:
		return false
	}
}

func isUnsignedIntegerBoundExpression(node *types.ASTNode) bool {
	typeName := node.GetAttributeString("type")
	if typeName == "uint" {
		return true
	}
	if !strings.HasPrefix(typeName, "uint") || len(typeName) == len("uint") {
		return false
	}
	for _, r := range typeName[len("uint"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isSequentialASTContainer(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindDeclFunction, types.KindDeclModifier, types.KindStmtBlock, types.KindStmtUnchecked:
		return true
	default:
		return false
	}
}

func directChildIndex(parent, child *types.ASTNode) int {
	if parent == nil || child == nil {
		return -1
	}
	for i, candidate := range parent.Children {
		if candidate == child {
			return i
		}
	}
	return -1
}

func precedingStatementProvesBound(statement, left, right *types.ASTNode) bool {
	if statement == nil {
		return false
	}
	switch statement.Kind {
	case types.KindCheckRequire, types.KindCheckAssert:
		return len(statement.Children) > 0 && guardArgumentsAreStructurallyEffectFree(statement) &&
			conditionProvesSubtractionBound(statement.Children[0], left, right, true)
	case types.KindStmtIf:
		if len(statement.Children) < 2 {
			return false
		}
		condition := statement.Children[0]
		thenExits := statementAlwaysExits(statement.Children[1])
		elseExits := len(statement.Children) > 2 && statementAlwaysExits(statement.Children[2])
		switch {
		case thenExits && !elseExits:
			return survivingIfArmIsEffectFree(statement, 2) &&
				conditionProvesSubtractionBound(condition, left, right, false)
		case elseExits && !thenExits:
			return survivingIfArmIsEffectFree(statement, 1) &&
				conditionProvesSubtractionBound(condition, left, right, true)
		}
	}
	return false
}

func guardArgumentsAreStructurallyEffectFree(guard *types.ASTNode) bool {
	if guard == nil {
		return false
	}
	for _, arg := range guard.Children[1:] {
		if !isStructurallyEffectFreeExpression(arg) {
			return false
		}
	}
	return true
}

func ifArmProvesBound(statement, arm, subtraction, left, right *types.ASTNode) bool {
	if statement == nil || len(statement.Children) < 2 {
		return false
	}
	if !ifArmPathIsTransparent(arm, subtraction) {
		return false
	}
	idx := directChildIndex(statement, arm)
	switch idx {
	case 1:
		return conditionProvesSubtractionBound(statement.Children[0], left, right, true)
	case 2:
		return conditionProvesSubtractionBound(statement.Children[0], left, right, false)
	default:
		return false
	}
}

// ifArmPathIsTransparent accepts an if-arm proof only when the subtraction is
// the first executable operation reached through block/unchecked wrappers.
func ifArmPathIsTransparent(arm, subtraction *types.ASTNode) bool {
	if arm == nil || subtraction == nil {
		return false
	}
	for current := subtraction; current != arm; current = current.Parent {
		parent := current.Parent
		if parent == nil {
			return false
		}
		switch parent.Kind {
		case types.KindStmtBlock, types.KindStmtUnchecked:
			if directChildIndex(parent, current) != 0 {
				return false
			}
		case types.KindStmtIf, types.KindStmtLoop, types.KindStmtTryCatch:
			return false
		}
	}
	return true
}

// survivingIfArmIsEffectFree accepts an exiting-arm fallthrough proof only
// when the non-exiting arm is absent or contains transparent empty wrappers.
func survivingIfArmIsEffectFree(statement *types.ASTNode, armIndex int) bool {
	if statement == nil || armIndex >= len(statement.Children) {
		return true
	}
	return transparentStatementIsEffectFree(statement.Children[armIndex])
}

func transparentStatementIsEffectFree(statement *types.ASTNode) bool {
	if statement == nil {
		return true
	}
	if statement.Kind != types.KindStmtBlock && statement.Kind != types.KindStmtUnchecked {
		return false
	}
	for _, child := range statement.Children {
		if !transparentStatementIsEffectFree(child) {
			return false
		}
	}
	return true
}

func statementAlwaysExits(statement *types.ASTNode) bool {
	if statement == nil {
		return false
	}
	switch statement.Kind {
	case types.KindStmtReturn, types.KindCheckRevert:
		return true
	case types.KindStmtBlock, types.KindStmtUnchecked:
		for _, child := range statement.Children {
			if statementAlwaysExits(child) {
				return true
			}
		}
	case types.KindStmtIf:
		return len(statement.Children) > 2 &&
			statementAlwaysExits(statement.Children[1]) &&
			statementAlwaysExits(statement.Children[2])
	}
	return false
}

// conditionProvesSubtractionBound proves only relations that imply
// left >= right. `truth` says whether cond is known true or false on the
// operation's path. Conjunctions contribute facts only when true; disjunctions
// contribute facts only when false. Other boolean shapes fail closed.
func conditionProvesSubtractionBound(cond, left, right *types.ASTNode, truth bool) bool {
	if cond == nil || !isStructurallyEffectFreeExpression(cond) {
		return false
	}
	if cond.Kind == types.KindExprUnaryOp && cond.GetAttributeString("operator") == "!" && len(cond.Children) == 1 {
		return conditionProvesSubtractionBound(cond.Children[0], left, right, !truth)
	}
	if cond.Kind != types.KindExprBinaryOp || len(cond.Children) != 2 {
		return false
	}
	lhs, rhs := cond.Children[0], cond.Children[1]
	switch cond.GetAttributeString("operator") {
	case "&&":
		return truth && (conditionProvesSubtractionBound(lhs, left, right, true) ||
			conditionProvesSubtractionBound(rhs, left, right, true))
	case "||":
		return !truth && (conditionProvesSubtractionBound(lhs, left, right, false) ||
			conditionProvesSubtractionBound(rhs, left, right, false))
	case ">=":
		return truth && sameBoundExpression(lhs, left) && sameBoundExpression(rhs, right)
	case "<=":
		return truth && sameBoundExpression(lhs, right) && sameBoundExpression(rhs, left)
	case ">":
		if truth {
			return sameBoundExpression(lhs, left) && sameBoundExpression(rhs, right)
		}
		return sameBoundExpression(lhs, right) && sameBoundExpression(rhs, left)
	case "<":
		if truth {
			return sameBoundExpression(lhs, right) && sameBoundExpression(rhs, left)
		}
		return sameBoundExpression(lhs, left) && sameBoundExpression(rhs, right)
	default:
		return false
	}
}

func sameBoundExpression(a, b *types.ASTNode) bool {
	if a == nil || b == nil || a.Kind != b.Kind || a.Name != b.Name || a.Value != b.Value || len(a.Children) != len(b.Children) {
		return false
	}
	if !isStableBoundExpression(a) || !isStableBoundExpression(b) {
		return false
	}
	if a.Kind == types.KindExprIdentifier {
		if a.RefID != "" || b.RefID != "" {
			return a.RefID != "" && b.RefID != "" && a.RefID == b.RefID
		}
		if a.RefKind != "" && b.RefKind != "" && a.RefKind != b.RefKind {
			return false
		}
	}
	if a.GetAttributeString("operator") != b.GetAttributeString("operator") {
		return false
	}
	for i := range a.Children {
		if !sameBoundExpression(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
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
		if e.verify(n, rule) {
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

const (
	primaryPriorityNone uint8 = iota
	primaryPriorityRegex
	primaryPriorityTraceableAST
)

func primaryPriorityForRule(r Rule) uint8 {
	if hasTraceableAtomicPredicate(r) {
		return primaryPriorityTraceableAST
	}
	if r.Regex != "" {
		return primaryPriorityRegex
	}
	return primaryPriorityNone
}

func (e *Engine) capturePrimary(node *types.ASTNode, priority uint8) {
	if e.match == nil || node == nil || priority == primaryPriorityNone {
		return
	}
	if e.match.Primary == nil || priority > e.match.primaryPriority {
		e.match.Primary = node
		e.match.primaryPriority = priority
	}
}

// hostFunctionFor walks a matched AST node's parent chain to resolve the exact
// owning declaration. Every decl.* node may contribute contract/source-file
// identity; only decl.function and decl.modifier contribute a host name.
// Context fallback remains for persisted or synthetic trees without owner
// attributes.
func (e *Engine) hostFunctionFor(node *types.ASTNode) (hostName, hostContract, hostFile string, hostLine int) {
	if node == nil {
		return "", "", "", 0
	}
	hostLine = node.StartLine
	for n := node; n != nil; n = n.Parent {
		if strings.HasPrefix(n.Kind, "decl.") {
			if hostContract == "" {
				hostContract = n.GetAttributeString("contract")
				if hostContract == "" && n.Kind == types.KindDeclContract {
					hostContract = n.Name
				}
			}
			if hostFile == "" {
				hostFile = n.GetAttributeString("source_file")
			}
		}
		switch n.Kind {
		case types.KindDeclFunction, types.KindDeclModifier:
			hostName = n.Name
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
	if hostContract != "" || hostFile != "" {
		return
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
