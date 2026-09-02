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
}
