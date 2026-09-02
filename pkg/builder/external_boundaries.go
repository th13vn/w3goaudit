package builder

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func (b *Builder) buildExternalBoundaries() {
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

	var facts []*types.ExternalBoundaryFact
	for _, contractID := range contractIDs {
		contract := b.db.Contracts[contractID]
		if contract == nil {
			continue
		}
		functions := append([]*types.Function(nil), contract.Functions...)
		sort.SliceStable(functions, func(i, j int) bool {
			return externalBoundaryFunctionID(functions[i]) < externalBoundaryFunctionID(functions[j])
		})
		for _, fn := range functions {
			functionID := externalBoundaryFunctionID(fn)
			if fn == nil || fn.AST == nil || functionID == "" {
				continue
			}
			walkBoundaryAST(fn.AST, "0", func(node *types.ASTNode, path string) {
				if !types.IsExternalBoundaryKind(node.Kind) {
					return
				}
				recorded := matchBoundaryCall(fn, node)
				fact := b.externalBoundaryFact(contract, fn, functionID, node, path, recorded)
				annotateExternalBoundaryNode(node, fact)
				facts = append(facts, fact)
			})
		}
	}
	b.db.Semantics.ExternalBoundaries = types.NormalizeExternalBoundaryFacts(facts)
	b.db.Semantics.ExternalBoundaryVersion = types.ExternalBoundaryFactsVersion
}

func externalBoundaryFunctionID(fn *types.Function) string {
	if fn == nil || fn.SourceFile == "" || fn.ContractName == "" {
		return ""
	}
	selector := fn.Selector
	if selector == "" {
		selector = fn.Name
	}
	if selector == "" {
		return ""
	}
	return types.MakeFunctionID(fn.SourceFile, fn.ContractName, selector)
}

func walkBoundaryAST(root *types.ASTNode, path string, visit func(*types.ASTNode, string)) {
	if root == nil {
		return
	}
	visit(root, path)
	for index, child := range root.Children {
		walkBoundaryAST(child, path+"."+strconv.Itoa(index), visit)
	}
}

func matchBoundaryCall(fn *types.Function, node *types.ASTNode) *types.FunctionCall {
	if fn == nil || node == nil {
		return nil
	}
	var matches []*types.FunctionCall
	for _, call := range fn.Calls {
		if call == nil || call.Target != node.Name || !boundaryCallTypeMatchesNode(call.CallType, node.Kind) {
			continue
		}
		if node.StartByte > 0 && call.Byte > 0 {
			if node.StartByte != call.Byte {
				continue
			}
		} else if node.StartLine > 0 && call.Line != node.StartLine {
			continue
		}
		matches = append(matches, call)
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return nil
}

func boundaryCallTypeMatchesNode(callType types.CallType, kind string) bool {
	switch kind {
	case types.KindCallExternal:
		return callType == types.CallTypeExternal || callType == types.CallTypeSelf
	case types.KindCallLowlevelCall:
		return callType == types.CallTypeLowLevel || callType == types.CallTypeLowLevelCall
	case types.KindCallLowlevelDelegate:
		return callType == types.CallTypeLowLevelDelegate
	case types.KindCallLowlevelStatic:
		return callType == types.CallTypeLowLevelStatic
	case types.KindCallBuiltinTransfer, types.KindCallBuiltinSend:
		return callType == types.CallTypeTransferETH
	case types.KindCallCreate:
		return callType == types.CallTypeExternal
	default:
		return false
	}
}

func (b *Builder) externalBoundaryFact(contract *types.Contract, fn *types.Function, functionID string, node *types.ASTNode, astPath string, recorded *types.FunctionCall) *types.ExternalBoundaryFact {
	fact := &types.ExternalBoundaryFact{
		ID:            fmt.Sprintf("%s@interaction:%d:%d:%s:%s", functionID, node.StartByte, node.EndByte, node.Kind, astPath),
		ASTPath:       astPath,
		ContractID:    contract.ID,
		FunctionID:    functionID,
		Kind:          node.Kind,
		CallType:      externalBoundaryCallType(node.Kind, recorded),
		Range:         boundaryRange(fn.SourceFile, node),
		Target:        b.boundaryTarget(node, recorded),
		Arguments:     []types.BoundaryValue{},
		Result:        types.BoundaryResult{Availability: types.BoundaryResultUnknown, Disposition: types.BoundaryResultUnknown, DirectCheck: types.BoundaryResultUnknown, Targets: []types.BoundaryValue{}, CheckSites: []types.SemanticSourceRange{}},
		ReentryClass:  types.BoundaryReentryUnknown,
		ReachableFrom: []string{},
		StateEffects:  []types.BoundaryStateEffect{},
		Limitations:   []string{},
	}
	b.populateBoundaryValues(fact, fn, node)
	b.populateBoundaryResult(fact, fn, node)
	b.populateBoundaryStateEffects(fact, fn, node)
	fact.ReentryClass = boundaryReentryClass(fact)
	fact.Limitations = boundaryLimitations(fact)
	return fact
}

func externalBoundaryCallType(kind string, recorded *types.FunctionCall) types.CallType {
	if recorded != nil {
		return recorded.CallType
	}
	switch kind {
	case types.KindCallLowlevelCall, types.KindAsmCall:
		return types.CallTypeLowLevelCall
	case types.KindCallLowlevelDelegate, types.KindAsmDelegatecall:
		return types.CallTypeLowLevelDelegate
	case types.KindCallLowlevelStatic, types.KindAsmStaticcall:
		return types.CallTypeLowLevelStatic
	case types.KindCallBuiltinTransfer, types.KindCallBuiltinSend:
		return types.CallTypeTransferETH
	case types.KindCallCreate, types.KindAsmCreate, types.KindAsmCreate2:
		return types.CallTypeExternal
	default:
		return types.CallTypeExternal
	}
}

func (b *Builder) boundaryTarget(node *types.ASTNode, recorded *types.FunctionCall) types.BoundaryTarget {
	target := types.BoundaryTarget{Resolution: types.BoundaryTargetUnresolved, CalledName: node.Name}
	if recorded == nil {
		if strings.HasPrefix(node.Kind, "asm.") {
			target.Resolution = types.BoundaryTargetNotApplicable
		}
		return target
	}
	target.CalledName = recorded.Target
	target.CalledSignature = recorded.Signature
	target.ContractID = recorded.ResolvedContractID
	target.ContractName = recorded.ResolvedContract
	target.FunctionSelector = recorded.ResolvedFunction
	target.Kind = recorded.TargetKind
	if recorded.Resolved && recorded.ResolvedContractID != "" {
		target.Resolution = types.BoundaryTargetResolved
		if resolvedContract := b.db.GetContractByID(recorded.ResolvedContractID); resolvedContract != nil && recorded.ResolvedFunction != "" {
			target.FunctionID = types.MakeFunctionID(resolvedContract.SourceFile, resolvedContract.Name, recorded.ResolvedFunction)
		}
	}
	return target
}

func (b *Builder) populateBoundaryValues(fact *types.ExternalBoundaryFact, fn *types.Function, node *types.ASTNode) {
	if strings.HasPrefix(node.Kind, "asm.") {
		b.populateYulBoundaryValues(fact, fn, node)
		return
	}
	argumentIndex := 0
	for _, child := range node.Children {
		if child == nil {
			continue
		}
		switch {
		case child.GetAttributeBool("call_receiver"):
			value := b.boundaryValue(fn, child, types.BoundaryValueRoleReceiver, -1, true)
			fact.Receiver = &value
		case child.GetAttributeString("call_option") == "value":
			value := b.boundaryValue(fn, child, types.BoundaryValueRoleValue, -1, false)
			fact.Value = &value
		case child.GetAttributeString("call_option") == "gas":
			value := b.boundaryValue(fn, child, types.BoundaryValueRoleGas, -1, false)
			fact.Gas = &value
		default:
			fact.Arguments = append(fact.Arguments, b.boundaryValue(fn, child, types.BoundaryValueRoleArgument, argumentIndex, false))
			argumentIndex++
		}
	}
}

func (b *Builder) populateYulBoundaryValues(fact *types.ExternalBoundaryFact, fn *types.Function, node *types.ASTNode) {
	for index, child := range node.Children {
		fact.Arguments = append(fact.Arguments, b.boundaryValue(fn, child, types.BoundaryValueRoleArgument, index, false))
	}
	switch node.Kind {
	case types.KindAsmCall:
		b.setYulBoundaryValue(fact, fn, node, 0, types.BoundaryValueRoleGas)
		b.setYulBoundaryValue(fact, fn, node, 1, types.BoundaryValueRoleReceiver)
		b.setYulBoundaryValue(fact, fn, node, 2, types.BoundaryValueRoleValue)
	case types.KindAsmDelegatecall, types.KindAsmStaticcall:
		b.setYulBoundaryValue(fact, fn, node, 0, types.BoundaryValueRoleGas)
		b.setYulBoundaryValue(fact, fn, node, 1, types.BoundaryValueRoleReceiver)
	case types.KindAsmCreate, types.KindAsmCreate2:
		b.setYulBoundaryValue(fact, fn, node, 0, types.BoundaryValueRoleValue)
	}
}

func (b *Builder) setYulBoundaryValue(fact *types.ExternalBoundaryFact, fn *types.Function, node *types.ASTNode, index int, role string) {
	if index < 0 || index >= len(node.Children) {
		return
	}
	value := b.boundaryValue(fn, node.Children[index], role, -1, role == types.BoundaryValueRoleReceiver)
	switch role {
	case types.BoundaryValueRoleReceiver:
		fact.Receiver = &value
	case types.BoundaryValueRoleValue:
		fact.Value = &value
	case types.BoundaryValueRoleGas:
		fact.Gas = &value
	}
}

func (b *Builder) boundaryValue(fn *types.Function, node *types.ASTNode, role string, index int, receiver bool) types.BoundaryValue {
	refs, taints := boundaryDependencies(node, receiver)
	return types.BoundaryValue{
		Role:         role,
		Index:        index,
		Expression:   astText(node),
		Range:        boundaryRange(fn.SourceFile, node),
		Type:         boundaryTypeInfo(node, b.db),
		Control:      boundaryValueControl(node, receiver),
		RefIDs:       refs,
		TaintSources: taints,
	}
}

func boundaryDependencies(node *types.ASTNode, receiver bool) ([]string, []string) {
	refs := map[string]bool{}
	taints := map[string]bool{}
	var walk func(*types.ASTNode)
	walk = func(current *types.ASTNode) {
		if current == nil {
			return
		}
		if current.RefID != "" {
			refs[current.RefID] = true
		}
		for _, source := range current.TaintSources {
			if source != "" {
				taints[source] = true
			}
		}
		children := current.Children
		if receiver && (current.Kind == types.KindExprIndexAccess || current.Kind == types.KindExprMemberAccess) && len(children) > 0 {
			children = children[:1]
		}
		for _, child := range children {
			walk(child)
		}
	}
	walk(node)
	return sortedBoundarySet(refs), sortedBoundarySet(taints)
}

func sortedBoundarySet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func boundaryValueControl(node *types.ASTNode, receiver bool) types.BoundaryValueControl {
	if node == nil {
		return types.BoundaryValueUnknown
	}
	if node.Kind == types.KindExprLiteral || node.Kind == types.KindExprIdentifier && node.Name == "this" {
		return types.BoundaryValueFixed
	}
	if isBoundaryCallerIdentity(node) {
		return types.BoundaryValueCallerControlled
	}
	if node.RefKind == "state_var" {
		return types.BoundaryValueStateDerived
	}
	if node.RefKind == "parameter" || node.RefKind == "local_var" && containsBoundaryTaint(node.TaintSources, "parameter") {
		return types.BoundaryValueCallerControlled
	}
	children := node.Children
	if receiver && (node.Kind == types.KindExprIndexAccess || node.Kind == types.KindExprMemberAccess) && len(children) > 0 {
		children = children[:1]
	}
	states := map[types.BoundaryValueControl]bool{}
	for _, child := range children {
		state := boundaryValueControl(child, receiver)
		if state != types.BoundaryValueUnknown {
			states[state] = true
		}
	}
	if len(states) == 1 {
		for state := range states {
			return state
		}
	}
	return types.BoundaryValueUnknown
}

func isBoundaryCallerIdentity(node *types.ASTNode) bool {
	if node == nil || node.Kind != types.KindExprMemberAccess || node.Name != "sender" {
		return false
	}
	return len(node.Children) > 0 && node.Children[0] != nil && node.Children[0].Kind == types.KindExprIdentifier && node.Children[0].Name == "msg"
}

func containsBoundaryTaint(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boundaryTypeInfo(node *types.ASTNode, db *types.Database) types.TypeInfo {
	if node == nil {
		return types.TypeInfo{}
	}
	typeInfo := types.TypeInfo{
		Name:        node.GetAttributeString("type"),
		BaseName:    node.GetAttributeString("type_base"),
		Kind:        node.GetAttributeString("type_kind"),
		ContractID:  node.GetAttributeString("type_contract_id"),
		Confidence:  node.GetAttributeString("type_confidence"),
		Source:      node.GetAttributeString("type_source"),
		ElementType: node.GetAttributeString("type_element"),
		KeyType:     node.GetAttributeString("type_key"),
		ValueType:   node.GetAttributeString("type_value"),
		IsAddress:   node.GetAttributeBool("type_is_address"),
		IsPayable:   node.GetAttributeBool("type_is_payable"),
	}
	if !typeInfo.IsKnown() && db != nil && db.Semantics != nil && node.RefID != "" {
		if symbol := db.Semantics.GetSymbol(node.RefID); symbol != nil {
			typeInfo = symbol.Type
		}
	}
	return typeInfo
}

func boundaryRange(file string, node *types.ASTNode) types.SemanticSourceRange {
	if node == nil {
		return types.SemanticSourceRange{File: file}
	}
	return types.SemanticSourceRange{File: file, StartLine: node.StartLine, StartCol: node.StartCol, EndLine: node.EndLine, EndCol: node.EndCol, StartByte: node.StartByte, EndByte: node.EndByte}
}

func annotateExternalBoundaryNode(node *types.ASTNode, fact *types.ExternalBoundaryFact) {
	if node == nil || fact == nil {
		return
	}
	node.SetAttribute("external_boundary_id", fact.ID)
	node.SetAttribute("boundary_target_resolution", fact.Target.Resolution)
	if fact.Receiver != nil {
		node.SetAttribute("boundary_receiver_control", string(fact.Receiver.Control))
	}
	if fact.Value != nil {
		node.SetAttribute("boundary_value_control", string(fact.Value.Control))
	}
	controlled := false
	for _, argument := range fact.Arguments {
		if argument.Control == types.BoundaryValueCallerControlled {
			controlled = true
			break
		}
	}
	node.SetAttribute("boundary_arguments_controlled", controlled)
	node.SetAttribute("boundary_result_disposition", fact.Result.Disposition)
	node.SetAttribute("boundary_result_checked", fact.Result.DirectCheck)
	node.SetAttribute("boundary_reentry_class", fact.ReentryClass)
	hasBefore, hasAfter := false, false
	for _, effect := range fact.StateEffects {
		if effect.Relation == types.BoundaryStateBefore {
			hasBefore = true
		}
		if effect.Relation == types.BoundaryStateAfter {
			hasAfter = true
		}
	}
	node.SetAttribute("boundary_has_state_before", hasBefore)
	node.SetAttribute("boundary_has_state_after", hasAfter)
	node.SetAttribute("boundary_reachable_from_entry", len(fact.ReachableFrom) > 0)
}

func (b *Builder) populateBoundaryResult(fact *types.ExternalBoundaryFact, fn *types.Function, node *types.ASTNode) {
	fact.Result.Availability = b.boundaryResultAvailability(fact)
	if fact.Result.Availability == types.BoundaryResultNo {
		fact.Result.Disposition = types.BoundaryResultNone
		fact.Result.DirectCheck = types.BoundaryResultNo
		return
	}

	if check := boundaryConditionOwner(node); check != nil {
		fact.Result.Disposition = types.BoundaryResultCondition
		fact.Result.DirectCheck = types.BoundaryResultYes
		fact.Result.CheckSites = []types.SemanticSourceRange{boundaryRange(fn.SourceFile, check)}
		return
	}
	if boundaryAncestor(node, types.KindStmtReturn) != nil {
		fact.Result.Disposition = types.BoundaryResultReturned
		fact.Result.DirectCheck = types.BoundaryResultNo
		return
	}
	if assignment := boundaryCapturingAssignment(node); assignment != nil {
		fact.Result.Disposition = types.BoundaryResultCaptured
		fact.Result.Targets = b.boundaryResultTargets(fn, assignment)
		fact.Result.DirectCheck = types.BoundaryResultNo
		for _, target := range fact.Result.Targets {
			for _, check := range laterBoundaryChecks(fn.AST, node, target.RefIDs) {
				fact.Result.CheckSites = append(fact.Result.CheckSites, boundaryRange(fn.SourceFile, check))
			}
		}
		if len(fact.Result.CheckSites) > 0 {
			fact.Result.DirectCheck = types.BoundaryResultYes
		}
		return
	}
	if boundaryIsStandalone(node) {
		fact.Result.Disposition = types.BoundaryResultDiscarded
	} else {
		fact.Result.Disposition = types.BoundaryResultConsumed
	}
	if fact.Result.Availability == types.BoundaryResultUnknown {
		fact.Result.DirectCheck = types.BoundaryResultUnknown
	} else {
		fact.Result.DirectCheck = types.BoundaryResultNo
	}
}

func (b *Builder) boundaryResultAvailability(fact *types.ExternalBoundaryFact) string {
	switch fact.Kind {
	case types.KindCallBuiltinTransfer:
		return types.BoundaryResultNo
	case types.KindCallBuiltinSend, types.KindCallLowlevelCall,
		types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
		types.KindCallCreate, types.KindAsmCall, types.KindAsmDelegatecall,
		types.KindAsmStaticcall, types.KindAsmCreate, types.KindAsmCreate2:
		return types.BoundaryResultYes
	case types.KindCallExternal:
		if fact.Target.FunctionID == "" {
			return types.BoundaryResultUnknown
		}
		if target, ok := b.db.GetFunctionByID(fact.Target.FunctionID); ok {
			if len(target.Returns) > 0 {
				return types.BoundaryResultYes
			}
			return types.BoundaryResultNo
		}
	}
	return types.BoundaryResultUnknown
}

func boundaryConditionOwner(node *types.ASTNode) *types.ASTNode {
	for current := node; current != nil && current.Parent != nil; current = current.Parent {
		parent := current.Parent
		switch parent.Kind {
		case types.KindCheckRequire, types.KindCheckAssert:
			if len(parent.Children) > 0 && nodeIsWithin(current, parent.Children[0]) {
				return parent
			}
			return nil
		case types.KindStmtIf:
			if len(parent.Children) > 0 && nodeIsWithin(current, parent.Children[0]) {
				return parent
			}
			return nil
		case types.KindStmtAssign, types.KindStmtReturn, types.KindStmtEmit:
			return nil
		}
	}
	return nil
}

func boundaryAncestor(node *types.ASTNode, kind string) *types.ASTNode {
	for current := node.Parent; current != nil; current = current.Parent {
		if current.Kind == kind {
			return current
		}
	}
	return nil
}

func boundaryCapturingAssignment(node *types.ASTNode) *types.ASTNode {
	for current := node; current != nil && current.Parent != nil; current = current.Parent {
		parent := current.Parent
		if parent.Kind == types.KindStmtAssign || parent.Kind == types.KindDeclVariable {
			lhsCount, err := strconv.Atoi(parent.GetAttributeString("assignment_lhs_count"))
			if err != nil || lhsCount <= 0 || lhsCount >= len(parent.Children) {
				return nil
			}
			for _, rhs := range parent.Children[lhsCount:] {
				if nodeIsWithin(node, rhs) {
					return parent
				}
			}
			return nil
		}
		if boundaryIsSequentialContainer(parent) || parent.Kind == types.KindStmtReturn || parent.Kind == types.KindStmtEmit {
			return nil
		}
	}
	return nil
}

func (b *Builder) boundaryResultTargets(fn *types.Function, assignment *types.ASTNode) []types.BoundaryValue {
	lhsCount, err := strconv.Atoi(assignment.GetAttributeString("assignment_lhs_count"))
	if err != nil || lhsCount <= 0 || lhsCount > len(assignment.Children) {
		return []types.BoundaryValue{}
	}
	targets := make([]types.BoundaryValue, 0, lhsCount)
	for _, lhs := range assignment.Children[:lhsCount] {
		if lhs == nil {
			continue
		}
		targets = append(targets, b.boundaryValue(fn, lhs, types.BoundaryValueRoleResult, -1, false))
	}
	return targets
}

func laterBoundaryChecks(root, boundary *types.ASTNode, refIDs []string) []*types.ASTNode {
	if root == nil || boundary == nil || len(refIDs) == 0 {
		return nil
	}
	refSet := make(map[string]bool, len(refIDs))
	for _, refID := range refIDs {
		refSet[refID] = true
	}
	var checks []*types.ASTNode
	walkBoundaryAST(root, "0", func(candidate *types.ASTNode, _ string) {
		if candidate == nil || candidate.Kind != types.KindCheckRequire && candidate.Kind != types.KindCheckAssert && candidate.Kind != types.KindStmtIf {
			return
		}
		if len(candidate.Children) == 0 || !subtreeReferencesAny(candidate.Children[0], refSet) {
			return
		}
		if boundaryExecutionRelation(boundary, candidate) == types.BoundaryStateAfter {
			checks = append(checks, candidate)
		}
	})
	return checks
}

func subtreeReferencesAny(node *types.ASTNode, refSet map[string]bool) bool {
	if node == nil {
		return false
	}
	if node.RefID != "" && refSet[node.RefID] {
		return true
	}
	for _, child := range node.Children {
		if subtreeReferencesAny(child, refSet) {
			return true
		}
	}
	return false
}

func boundaryIsStandalone(node *types.ASTNode) bool {
	if node == nil || node.Parent == nil {
		return true
	}
	return boundaryIsSequentialContainer(node.Parent)
}

func (b *Builder) populateBoundaryStateEffects(fact *types.ExternalBoundaryFact, fn *types.Function, boundary *types.ASTNode) {
	if fn == nil || fn.AST == nil {
		return
	}
	walkBoundaryAST(fn.AST, "0", func(node *types.ASTNode, _ string) {
		effect, ok := boundaryStateEffect(fn.SourceFile, node)
		if !ok {
			return
		}
		effect.Relation = boundaryExecutionRelation(boundary, node)
		fact.StateEffects = append(fact.StateEffects, effect)
	})
}

func boundaryStateEffect(file string, node *types.ASTNode) (types.BoundaryStateEffect, bool) {
	if node == nil {
		return types.BoundaryStateEffect{}, false
	}
	var target *types.ASTNode
	kind := ""
	switch node.Kind {
	case types.KindStmtAssign:
		if !node.GetAttributeBool("is_state_var") || len(node.Children) == 0 {
			return types.BoundaryStateEffect{}, false
		}
		target, kind = node.Children[0], assignKind(node)
	case types.KindStmtStateMutation:
		if !node.GetAttributeBool("is_state_var") {
			return types.BoundaryStateEffect{}, false
		}
		for _, child := range node.Children {
			if child.GetAttributeBool("call_receiver") {
				target = child
				break
			}
		}
		kind = node.GetAttributeString("operator")
	case types.KindExprUnaryOp:
		operator := node.GetAttributeString("operator")
		if operator != "delete" && operator != "++" && operator != "--" || len(node.Children) == 0 {
			return types.BoundaryStateEffect{}, false
		}
		target, kind = node.Children[0], operator
	case types.KindAsmSstore:
		return types.BoundaryStateEffect{Name: "<assembly sstore>", Kind: "sstore", Range: boundaryRange(file, node)}, true
	default:
		return types.BoundaryStateEffect{}, false
	}
	root := boundaryStateRoot(target)
	if root == nil || root.RefKind != "state_var" {
		return types.BoundaryStateEffect{}, false
	}
	return types.BoundaryStateEffect{RefID: root.RefID, Name: root.Name, Kind: kind, Range: boundaryRange(file, node)}, true
}

func boundaryStateRoot(node *types.ASTNode) *types.ASTNode {
	for node != nil {
		if node.Kind == types.KindExprIdentifier {
			return node
		}
		if len(node.Children) == 0 {
			return nil
		}
		node = node.Children[0]
	}
	return nil
}

func boundaryExecutionRelation(boundary, effect *types.ASTNode) string {
	if boundary == nil || effect == nil || boundary == effect {
		return types.BoundaryStateUnknown
	}
	if shareBoundaryLoop(boundary, effect) {
		return types.BoundaryStateUnknown
	}
	if nodeIsWithin(boundary, effect) {
		return types.BoundaryStateAfter
	}
	if nodeIsWithin(effect, boundary) {
		return types.BoundaryStateBefore
	}
	lca, boundaryChild, effectChild := boundaryLCA(boundary, effect)
	if lca == nil || boundaryChild == nil || effectChild == nil {
		return types.BoundaryStateUnknown
	}
	boundaryIndex, effectIndex := directBoundaryChildIndex(lca, boundaryChild), directBoundaryChildIndex(lca, effectChild)
	if boundaryIndex < 0 || effectIndex < 0 {
		return types.BoundaryStateUnknown
	}
	if lca.Kind == types.KindStmtIf || lca.Kind == types.KindExprConditional {
		if boundaryIndex > 0 && effectIndex > 0 && boundaryIndex != effectIndex {
			return types.BoundaryStateIncompatible
		}
		if boundaryIndex == 0 {
			return types.BoundaryStateAfter
		}
		if effectIndex == 0 {
			return types.BoundaryStateBefore
		}
	}
	if boundaryIsSequentialContainer(lca) {
		if boundaryIndex < effectIndex {
			return types.BoundaryStateAfter
		}
		return types.BoundaryStateBefore
	}
	return types.BoundaryStateUnordered
}

func nodeIsWithin(node, ancestor *types.ASTNode) bool {
	for current := node; current != nil; current = current.Parent {
		if current == ancestor {
			return true
		}
	}
	return false
}

func shareBoundaryLoop(left, right *types.ASTNode) bool {
	loops := map[*types.ASTNode]bool{}
	for current := left; current != nil; current = current.Parent {
		if current.Kind == types.KindStmtLoop {
			loops[current] = true
		}
	}
	for current := right; current != nil; current = current.Parent {
		if loops[current] {
			return true
		}
	}
	return false
}

func boundaryLCA(left, right *types.ASTNode) (*types.ASTNode, *types.ASTNode, *types.ASTNode) {
	leftPath := boundaryAncestorPath(left)
	rightPath := boundaryAncestorPath(right)
	limit := len(leftPath)
	if len(rightPath) < limit {
		limit = len(rightPath)
	}
	last := -1
	for index := 0; index < limit && leftPath[index] == rightPath[index]; index++ {
		last = index
	}
	if last < 0 || last+1 >= len(leftPath) || last+1 >= len(rightPath) {
		return nil, nil, nil
	}
	return leftPath[last], leftPath[last+1], rightPath[last+1]
}

func boundaryAncestorPath(node *types.ASTNode) []*types.ASTNode {
	var reversed []*types.ASTNode
	for current := node; current != nil; current = current.Parent {
		reversed = append(reversed, current)
	}
	path := make([]*types.ASTNode, len(reversed))
	for index := range reversed {
		path[len(reversed)-1-index] = reversed[index]
	}
	return path
}

func directBoundaryChildIndex(parent, child *types.ASTNode) int {
	for index, candidate := range parent.Children {
		if candidate == child {
			return index
		}
	}
	return -1
}

func boundaryIsSequentialContainer(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindDeclFunction, types.KindDeclModifier, types.KindStmtBlock, types.KindStmtUnchecked, types.KindAsmBlock:
		return true
	default:
		return false
	}
}

func boundaryReentryClass(fact *types.ExternalBoundaryFact) string {
	switch {
	case fact.CallType == types.CallTypeSelf:
		return types.BoundaryReentrySameContract
	case fact.Kind == types.KindCallLowlevelDelegate || fact.Kind == types.KindAsmDelegatecall:
		return types.BoundaryReentryDelegateContext
	case fact.Kind == types.KindCallLowlevelStatic || fact.Kind == types.KindAsmStaticcall:
		return types.BoundaryReentryReadOnlyPossible
	case fact.Kind == types.KindCallBuiltinTransfer || fact.Kind == types.KindCallBuiltinSend:
		return types.BoundaryReentryStipendLimited
	case fact.Kind == types.KindCallCreate || fact.Kind == types.KindAsmCreate || fact.Kind == types.KindAsmCreate2:
		return types.BoundaryReentryConstructorPossible
	case fact.Kind == types.KindCallExternal || fact.Kind == types.KindCallLowlevelCall || fact.Kind == types.KindAsmCall:
		return types.BoundaryReentryPossible
	default:
		return types.BoundaryReentryUnknown
	}
}

func boundaryLimitations(fact *types.ExternalBoundaryFact) []string {
	limitations := []string{
		"external target effects are not analyzed",
		"state effects include direct same-function writes only",
		"entry reachability records call-graph paths and is not a path-feasibility proof",
	}
	if fact.Target.Resolution != types.BoundaryTargetResolved {
		limitations = append(limitations, "exact external target identity is unavailable")
	}
	if fact.Result.Availability == types.BoundaryResultUnknown {
		limitations = append(limitations, "result availability is unknown")
	}
	return limitations
}
