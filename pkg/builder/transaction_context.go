package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

type transactionContextNodePath struct {
	node *types.ASTNode
	path string
}

type transactionContextSource struct {
	node *types.ASTNode
	path string
}

type transactionContextAlias struct {
	source     transactionContextSource
	assignment *types.ASTNode
	valid      bool
}

func (b *Builder) buildTransactionContextFacts() {
	if b == nil || b.db == nil {
		return
	}
	if b.db.Semantics == nil {
		b.db.Semantics = types.NewSemanticFacts()
	}

	contractIDs := make([]string, 0, len(b.db.Contracts))
	for id := range b.db.Contracts {
		contractIDs = append(contractIDs, id)
	}
	sort.Strings(contractIDs)

	var facts []*types.TransactionContextFact
	for _, contractID := range contractIDs {
		contract := b.db.Contracts[contractID]
		if contract == nil {
			continue
		}
		functions := append([]*types.Function(nil), contract.Functions...)
		sort.Slice(functions, func(i, j int) bool {
			return transactionContextFunctionID(functions[i]) < transactionContextFunctionID(functions[j])
		})
		for _, fn := range functions {
			if fn == nil || fn.AST == nil {
				continue
			}
			functionID := transactionContextFunctionID(fn)
			if functionID == "" {
				continue
			}
			paths := transactionContextPaths(fn.AST)
			aliases := transactionContextAliases(paths)
			for _, entry := range paths {
				fact := b.transactionContextFactForEffect(contract, fn, functionID, entry, paths, aliases)
				if fact == nil {
					continue
				}
				facts = append(facts, fact)
			}
		}
	}
	b.db.Semantics.TransactionContextFacts = types.NormalizeTransactionContextFacts(facts)
	b.db.Semantics.TransactionContextVersion = types.TransactionContextFactsVersion
}

func transactionContextFunctionID(fn *types.Function) string {
	if fn == nil || fn.SourceFile == "" || fn.ContractName == "" {
		return ""
	}
	selector := fn.Selector
	if selector == "" {
		if fn.IsConstructor {
			selector = "constructor"
		} else {
			selector = fn.Name
		}
	}
	if selector == "" {
		return ""
	}
	return types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)
}

func transactionContextPaths(root *types.ASTNode) []transactionContextNodePath {
	var paths []transactionContextNodePath
	var walk func(*types.ASTNode, string)
	walk = func(node *types.ASTNode, path string) {
		if node == nil {
			return
		}
		paths = append(paths, transactionContextNodePath{node: node, path: path})
		for index, child := range node.Children {
			walk(child, path+"."+strconv.Itoa(index))
		}
	}
	walk(root, "0")
	return paths
}

func transactionContextAliases(paths []transactionContextNodePath) map[string]transactionContextAlias {
	aliases := make(map[string]transactionContextAlias)
	for _, entry := range paths {
		node := entry.node
		if node == nil || node.Kind != types.KindStmtAssign || len(node.Children) < 2 {
			continue
		}
		lhs := node.Children[0]
		if lhs == nil || lhs.Kind != types.KindExprIdentifier || lhs.RefID == "" || node.GetAttributeBool("is_state_var") || lhs.RefKind == "state_var" {
			continue
		}
		if _, exists := aliases[lhs.RefID]; exists {
			alias := aliases[lhs.RefID]
			alias.valid = false
			aliases[lhs.RefID] = alias
			continue
		}
		if source := transactionContextDirectSource(node.Children[len(node.Children)-1]); source != nil {
			aliases[lhs.RefID] = transactionContextAlias{
				source:     transactionContextSource{node: source, path: transactionContextPathForNode(paths, source)},
				assignment: node,
				valid:      !transactionContextHasBranchAncestor(node),
			}
		} else {
			aliases[lhs.RefID] = transactionContextAlias{valid: false}
		}
	}
	return aliases
}

func (b *Builder) transactionContextFactForEffect(contract *types.Contract, fn *types.Function, functionID string, entry transactionContextNodePath, paths []transactionContextNodePath, aliases map[string]transactionContextAlias) *types.TransactionContextFact {
	effect := entry.node
	source, use, calleeID := b.transactionContextEffectSource(fn, effect, aliases)
	if source.node == nil || use == "" {
		return nil
	}
	if source.path == "" {
		source.path = transactionContextPathForNode(paths, source.node)
	}
	repeatability, loops := transactionContextRepeatability(effect)
	if repeatability == "" || len(loops) == 0 {
		return nil
	}
	// An alias declared outside the consuming loop is intentionally outside the
	// bounded first slice. Direct sources and one-local aliases must share the
	// same enclosing loop.
	if !transactionContextSharesLoop(source.node, effect) {
		return nil
	}
	loop := loops[len(loops)-1]
	loopPath := transactionContextPathForNode(paths, loop)
	if loopPath == "" {
		return nil
	}
	fact := &types.TransactionContextFact{
		ContractID: contract.ID, ScopeID: functionID, FunctionID: functionID,
		Source: types.TransactionContextSourceMsgValue, Use: use, Repeatability: repeatability,
		SourceRange: transactionContextRange(contract.SourceFile, source.node),
		EffectRange: transactionContextRange(contract.SourceFile, effect),
		LoopPath:    loopPath, ResolvedCalleeID: calleeID,
	}
	sum := sha256.Sum256([]byte(functionID + "|" + source.path + "|" + entry.path + "|" + loopPath + "|" + fact.Use))
	fact.ID = "transaction-context:" + hex.EncodeToString(sum[:16])
	annotateTransactionContextNode(source.node, fact)
	annotateTransactionContextNode(effect, fact)
	return fact
}

func transactionContextDirectSource(node *types.ASTNode) *types.ASTNode {
	if node == nil {
		return nil
	}
	if isTransactionMsgValue(node) {
		return node
	}
	if transactionContextOpaqueExpression(node) {
		return nil
	}
	for _, child := range node.Children {
		if source := transactionContextDirectSource(child); source != nil {
			return source
		}
	}
	return nil
}

func isTransactionMsgValue(node *types.ASTNode) bool {
	return node != nil && node.Kind == types.KindExprMemberAccess && node.Name == "value" && node.GetAttributeString("parent") == "msg"
}

func (b *Builder) transactionContextEffectSource(fn *types.Function, effect *types.ASTNode, aliases map[string]transactionContextAlias) (transactionContextSource, string, string) {
	if effect == nil {
		return transactionContextSource{}, "", ""
	}
	switch effect.Kind {
	case types.KindStmtAssign:
		if effect.GetAttributeBool("is_state_var") && len(effect.Children) >= 2 {
			if source := transactionContextExpressionSource(effect.Children[len(effect.Children)-1], aliases); source.node != nil {
				return source, types.TransactionContextUseStateWrite, ""
			}
		}
	case types.KindStmtStateMutation:
		if effect.GetAttributeBool("is_state_var") {
			if source := transactionContextCallArgumentSource(effect, aliases); source.node != nil {
				return source, types.TransactionContextUseStateWrite, ""
			}
		}
	case types.KindAsmSstore:
		if len(effect.Children) >= 2 {
			if source := transactionContextExpressionSource(effect.Children[1], aliases); source.node != nil {
				return source, types.TransactionContextUseStateWrite, ""
			}
		}
	case types.KindAsmCall:
		if len(effect.Children) >= 3 {
			if source := transactionContextExpressionSource(effect.Children[2], aliases); source.node != nil {
				return source, types.TransactionContextUseCallValue, ""
			}
		}
	case types.KindAsmCreate, types.KindAsmCreate2:
		if len(effect.Children) >= 1 {
			if source := transactionContextExpressionSource(effect.Children[0], aliases); source.node != nil {
				return source, types.TransactionContextUseCallValue, ""
			}
		}
	case types.KindCallLowlevelCall, types.KindCallExternal, types.KindCallCreate, types.KindCallBuiltinTransfer, types.KindCallBuiltinSend:
		if source := transactionContextCallValueSource(effect, aliases); source.node != nil {
			return source, types.TransactionContextUseCallValue, ""
		}
		calleeID := b.transactionContextStatefulCallee(fn, effect)
		if calleeID != "" && transactionContextCalleeStateful(b.db, calleeID, map[string]bool{}) {
			if source := transactionContextCallArgumentSource(effect, aliases); source.node != nil {
				return source, types.TransactionContextUseStatefulInternalCall, calleeID
			}
		}
	case types.KindCallInternal:
		calleeID := b.transactionContextStatefulCallee(fn, effect)
		if calleeID != "" && transactionContextCalleeStateful(b.db, calleeID, map[string]bool{}) {
			if source := transactionContextCallArgumentSource(effect, aliases); source.node != nil {
				return source, types.TransactionContextUseStatefulInternalCall, calleeID
			}
		}
	}
	return transactionContextSource{}, "", ""
}

func transactionContextExpressionSource(expr *types.ASTNode, aliases map[string]transactionContextAlias) transactionContextSource {
	if expr == nil {
		return transactionContextSource{}
	}
	if isTransactionMsgValue(expr) {
		return transactionContextSource{node: expr}
	}
	if expr.Kind == types.KindExprIdentifier {
		if alias, ok := aliases[expr.RefID]; ok && alias.valid && transactionContextAliasPrecedesUse(alias, expr) {
			return alias.source
		}
	}
	if transactionContextOpaqueExpression(expr) {
		return transactionContextSource{}
	}
	for _, child := range expr.Children {
		if source := transactionContextExpressionSource(child, aliases); source.node != nil {
			return source
		}
	}
	return transactionContextSource{}
}

func transactionContextOpaqueExpression(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	if node.Kind == types.KindExprConditional || node.Kind == types.KindExprTuple {
		return true
	}
	if !strings.HasPrefix(node.Kind, "call.") {
		return false
	}
	return node.GetAttributeString("type_source") != "type_cast" && node.RefKind != "type"
}

func transactionContextCallValueSource(call *types.ASTNode, aliases map[string]transactionContextAlias) transactionContextSource {
	if call == nil {
		return transactionContextSource{}
	}
	for _, child := range call.Children {
		if child == nil || child.GetAttributeBool("call_receiver") {
			continue
		}
		if call.Kind == types.KindCallBuiltinTransfer || call.Kind == types.KindCallBuiltinSend {
			return transactionContextExpressionSource(child, aliases)
		}
		if child.GetAttributeString("call_option") == "value" {
			return transactionContextExpressionSource(child, aliases)
		}
	}
	return transactionContextSource{}
}

func transactionContextCallArgumentSource(call *types.ASTNode, aliases map[string]transactionContextAlias) transactionContextSource {
	if call == nil {
		return transactionContextSource{}
	}
	for _, child := range call.Children {
		if child == nil || child.GetAttributeBool("call_receiver") || child.GetAttributeString("call_option") != "" {
			continue
		}
		if source := transactionContextExpressionSource(child, aliases); source.node != nil {
			return source
		}
	}
	return transactionContextSource{}
}

func transactionContextAliasPrecedesUse(alias transactionContextAlias, use *types.ASTNode) bool {
	if !alias.valid || alias.assignment == nil || use == nil {
		return false
	}
	useAnchor := use
	for useAnchor != nil && useAnchor.StartByte == 0 && useAnchor.StartLine == 0 {
		useAnchor = useAnchor.Parent
	}
	if useAnchor == nil {
		return false
	}
	if alias.assignment.StartByte > 0 && useAnchor.StartByte > 0 {
		return alias.assignment.StartByte < useAnchor.StartByte
	}
	return alias.assignment.StartLine > 0 && useAnchor.StartLine > 0 && alias.assignment.StartLine <= useAnchor.StartLine
}

func transactionContextHasBranchAncestor(node *types.ASTNode) bool {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == types.KindStmtIf || current.Kind == types.KindStmtTryCatch || current.Kind == types.KindExprConditional {
			return true
		}
	}
	return false
}

func (b *Builder) transactionContextStatefulCallee(fn *types.Function, node *types.ASTNode) string {
	call := transactionContextRecordedCall(fn, node)
	if call == nil || !call.Resolved || call.ResolvedContractID == "" || call.ResolvedFunction == "" {
		return ""
	}
	if call.CallType != types.CallTypeInternal && call.CallType != types.CallTypeInherited && call.CallType != types.CallTypeSuper && call.CallType != types.CallTypeSelf {
		return ""
	}
	return call.ResolvedContractID + "." + call.ResolvedFunction
}

func transactionContextRecordedCall(fn *types.Function, node *types.ASTNode) *types.FunctionCall {
	if fn == nil || node == nil {
		return nil
	}
	var matches []*types.FunctionCall
	for _, call := range fn.Calls {
		if call == nil || call.Target != node.Name {
			continue
		}
		if node.StartByte > 0 && call.Byte > 0 {
			if node.StartByte == call.Byte {
				matches = append(matches, call)
			}
			continue
		}
		if node.StartLine > 0 && call.Line == node.StartLine {
			matches = append(matches, call)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return nil
}

func transactionContextCalleeStateful(db *types.Database, functionID string, seen map[string]bool) bool {
	if db == nil || db.Semantics == nil || functionID == "" || seen[functionID] {
		return false
	}
	seen[functionID] = true
	if effects := db.Semantics.GetFunctionEffects(functionID); effects != nil && len(effects.StateWrites) > 0 {
		return true
	}
	if db.CallGraph == nil {
		return false
	}
	for _, edge := range db.CallGraph.GetCallees(functionID) {
		if edge == nil || !transactionContextTraversableCall(edge.Type) || !edge.Resolved {
			continue
		}
		if transactionContextCalleeStateful(db, edge.To, seen) {
			return true
		}
	}
	return false
}

func transactionContextTraversableCall(callType types.CallType) bool {
	return callType == types.CallTypeInternal || callType == types.CallTypeInherited || callType == types.CallTypeSuper || callType == types.CallTypeSelf
}

func transactionContextRepeatability(effect *types.ASTNode) (string, []*types.ASTNode) {
	var loops []*types.ASTNode
	for current := effect; current != nil; current = current.Parent {
		if current.Kind != types.KindStmtLoop {
			continue
		}
		if transactionContextLoopStaticallyFalse(current) {
			return "", nil
		}
		loops = append(loops, current)
	}
	if len(loops) == 0 {
		return "", nil
	}
	for _, loop := range loops {
		repeatability := transactionLoopRepeatability(loop)
		if repeatability == "" {
			return "", nil
		}
		if repeatability == types.TransactionContextRepeatabilityPossible {
			return types.TransactionContextRepeatabilityPossible, loops
		}
	}
	return types.TransactionContextRepeatabilitySingleIteration, loops
}

func transactionContextSharesLoop(source, effect *types.ASTNode) bool {
	shared := false
	for current := source; current != nil; current = current.Parent {
		if current.Kind != types.KindStmtLoop {
			continue
		}
		if !nodeIsWithin(effect, current) {
			return false
		}
		shared = true
	}
	return shared
}

func transactionContextLoopStaticallyFalse(loop *types.ASTNode) bool {
	if loop == nil || len(loop.Children) == 0 {
		return false
	}
	if loop.GetAttributeString("loop_type") == "do_while" {
		return false
	}
	if loop.GetAttributeString("loop_type") == "for" && len(loop.Children) >= 2 {
		initialization, condition := loop.Children[0], loop.Children[1]
		if initialization != nil && condition != nil && initialization.Kind == types.KindStmtAssign && condition.Kind == types.KindExprBinaryOp &&
			len(initialization.Children) >= 2 && len(condition.Children) >= 2 &&
			initialization.Children[0].RefID != "" && initialization.Children[0].RefID == condition.Children[0].RefID {
			initial, initialOK := transactionContextLiteralInteger(initialization.Children[len(initialization.Children)-1])
			bound, boundOK := transactionContextLiteralInteger(condition.Children[1])
			if initialOK && boundOK {
				switch condition.GetAttributeString("operator") {
				case "<":
					return initial >= bound
				case "<=":
					return initial > bound
				case ">":
					return initial <= bound
				case ">=":
					return initial < bound
				}
			}
		}
	}
	for _, child := range loop.Children {
		if child != nil && child.GetAttributeString("cond_role") == "loop" && child.Kind == types.KindExprLiteral {
			return child.Value == "false" || child.Value == "0"
		}
	}
	return false
}

func transactionLoopRepeatability(loop *types.ASTNode) string {
	if loop == nil {
		return ""
	}
	switch loop.GetAttributeString("loop_type") {
	case "do_while":
		if len(loop.Children) > 0 {
			last := loop.Children[len(loop.Children)-1]
			if last.Kind == types.KindExprLiteral && last.GetAttributeString("subtype") == "bool" && last.Value == "false" {
				return types.TransactionContextRepeatabilitySingleIteration
			}
		}
	case "for":
		var initialization, condition, post *types.ASTNode
		for _, child := range loop.Children {
			if child == nil {
				continue
			}
			if child.Kind == types.KindStmtAssign && initialization == nil {
				initialization = child
			}
			if child.Kind == types.KindExprBinaryOp && child.GetAttributeString("cond_role") == "loop" {
				condition = child
			}
			if child.Kind == types.KindExprUnaryOp && (child.GetAttributeString("operator") == "++" || child.GetAttributeString("operator") == "--") {
				post = child
			}
		}
		if transactionContextCanonicalSingleIterationFor(initialization, condition, post) {
			return types.TransactionContextRepeatabilitySingleIteration
		}
		if initialization == nil || condition == nil || post == nil || condition.Kind != types.KindExprBinaryOp {
			return ""
		}
	case "while":
		if len(loop.Children) < 2 {
			return ""
		}
	default:
		return ""
	}
	return types.TransactionContextRepeatabilityPossible
}

func transactionContextCanonicalSingleIterationFor(initialization, condition, post *types.ASTNode) bool {
	if initialization == nil || condition == nil || post == nil || len(initialization.Children) < 2 || len(condition.Children) < 2 || len(post.Children) == 0 {
		return false
	}
	initialRef := initialization.Children[0].RefID
	if initialRef == "" || initialRef != condition.Children[0].RefID || initialRef != post.Children[0].RefID {
		return false
	}
	initial, initialOK := transactionContextLiteralInteger(initialization.Children[len(initialization.Children)-1])
	bound, boundOK := transactionContextLiteralInteger(condition.Children[1])
	if !initialOK || !boundOK {
		return false
	}
	switch post.GetAttributeString("operator") {
	case "++":
		switch condition.GetAttributeString("operator") {
		case "<":
			return initial < bound && initial+1 == bound
		case "<=":
			return initial == bound
		}
	case "--":
		switch condition.GetAttributeString("operator") {
		case ">":
			return initial > bound && bound+1 == initial
		case ">=":
			return initial == bound
		}
	}
	return false
}

func transactionContextLiteralInteger(node *types.ASTNode) (int64, bool) {
	if node == nil || node.Kind != types.KindExprLiteral {
		return 0, false
	}
	value, err := strconv.ParseInt(node.Value, 10, 64)
	return value, err == nil
}

func transactionContextPathForNode(paths []transactionContextNodePath, want *types.ASTNode) string {
	for _, entry := range paths {
		if entry.node == want {
			return entry.path
		}
	}
	return ""
}

func transactionContextRange(file string, node *types.ASTNode) types.SemanticSourceRange {
	if node == nil {
		return types.SemanticSourceRange{}
	}
	return types.SemanticSourceRange{File: file, StartLine: node.StartLine, StartCol: node.StartCol, EndLine: node.EndLine, EndCol: node.EndCol, StartByte: node.StartByte, EndByte: node.EndByte}
}

func annotateTransactionContextNode(node *types.ASTNode, fact *types.TransactionContextFact) {
	if node == nil || fact == nil {
		return
	}
	node.SetAttribute("transaction_context_source", fact.Source)
	node.SetAttribute("transaction_context_use", fact.Use)
	node.SetAttribute("transaction_context_repeatability", fact.Repeatability)
}
