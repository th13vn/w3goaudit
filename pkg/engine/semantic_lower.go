package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/th13vn/w3goaudit/pkg/types"
)

func (a *semanticAnalyzer) lowerFunction(fn *types.Function, contract *types.Contract) *semanticFunction {
	if fn == nil {
		return &semanticFunction{Contract: contract, ByNode: make(map[*types.ASTNode][]int)}
	}
	owner, runtimeContract, file, contractID, exact := a.resolveLoweringContracts(fn, contract)
	functionID := ""
	if fn.Selector != "" && file != "" && fn.ContractName != "" {
		functionID = types.MakeFunctionID(file, fn.ContractName, fn.Selector)
	}
	cacheKey := functionID + "\x00" + contractID
	if exact && functionID != "" && contractID != "" && a.lowered[cacheKey] != nil {
		lowered := a.lowered[cacheKey]
		return cloneSemanticFunction(lowered)
	}
	diagnostics := &a.diagnostics
	if a.db != nil {
		diagnostics = &a.db.Diagnostics
	}
	ctx := lowerContext{
		Function:    fn,
		Contract:    runtimeContract,
		ScopeID:     functionID,
		ContractID:  contractID,
		Occurrences: semanticOccurrenceIDs(fn.AST),
		Diagnostics: diagnostics,
	}
	var operations []semanticOp
	if !exact || functionID == "" || contractID == "" {
		a.recordUnsupportedWithReason(fn.AST, ctx, "exact function or runtime contract identity is unavailable")
		operations = []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: fn.AST}}}
	} else {
		operations = a.lowerNode(fn.AST, ctx)
	}
	lowered := &semanticFunction{
		Function:   fn,
		Contract:   runtimeContract,
		Operations: make([]*semanticOp, 0, len(operations)),
		ByNode:     make(map[*types.ASTNode][]int),
	}
	for index := range operations {
		operation := operations[index]
		operation.ID = index
		operation.Reads = normalizeAccessPaths(operation.Reads)
		operation.Writes = normalizeAccessPaths(operation.Writes)
		operation.Provenance.FunctionID = functionID
		operation.Provenance.ContractID = contractID
		operation.Provenance.File = file
		operation.Provenance.OpIndex = index
		for inputIndex := range operation.Inputs {
			operation.Inputs[inputIndex].Provenance.FunctionID = functionID
			operation.Inputs[inputIndex].Provenance.ContractID = contractID
			operation.Inputs[inputIndex].Provenance.File = file
			operation.Inputs[inputIndex].Provenance.OpIndex = index
		}
		copy := operation
		lowered.Operations = append(lowered.Operations, &copy)
		if operation.Provenance.Node != nil {
			lowered.ByNode[operation.Provenance.Node] = append(lowered.ByNode[operation.Provenance.Node], index)
		}
	}
	if exact && functionID != "" && contractID != "" {
		a.lowered[cacheKey] = cloneSemanticFunction(lowered)
	}
	if a.db != nil {
		a.db.NormalizeDiagnostics()
	} else {
		types.SortDiagnostics(a.diagnostics)
	}
	_ = owner
	return cloneSemanticFunction(lowered)
}

func (a *semanticAnalyzer) resolveLoweringContracts(fn *types.Function, runtime *types.Contract) (owner, resolvedRuntime *types.Contract, file, contractID string, exact bool) {
	if fn == nil {
		return nil, runtime, "", "", false
	}
	file = fn.SourceFile
	if a != nil && a.db != nil {
		if file != "" {
			owner = a.db.GetContractByID(types.MakeContractID(file, fn.ContractName))
		} else {
			matches := a.db.FindContractsByName(fn.ContractName)
			if len(matches) == 1 {
				owner = matches[0]
				file = owner.SourceFile
			}
		}
	}
	if owner == nil && (a == nil || a.db == nil) && runtime != nil && runtime.Name == fn.ContractName && (file == "" || runtime.SourceFile == file) {
		owner = runtime
		if file == "" {
			file = runtime.SourceFile
		}
	}
	if !exactContractObject(owner) || owner.Name != fn.ContractName || file == "" || owner.SourceFile != file {
		return owner, nil, file, "", false
	}
	if a != nil && a.db != nil && a.db.GetContractByID(owner.ID) != owner {
		return owner, nil, file, "", false
	}
	resolvedRuntime = runtime
	if resolvedRuntime == nil {
		resolvedRuntime = owner
	}
	if !exactContractObject(resolvedRuntime) {
		return owner, nil, file, "", false
	}
	if a != nil && a.db != nil && a.db.GetContractByID(resolvedRuntime.ID) != resolvedRuntime {
		return owner, nil, file, "", false
	}
	contractID = resolvedRuntime.ID
	return owner, resolvedRuntime, file, contractID, true
}

func exactContractObject(contract *types.Contract) bool {
	return contract != nil && contract.SourceFile != "" && contract.Name != "" && contract.ID == types.MakeContractID(contract.SourceFile, contract.Name)
}

func semanticOccurrenceIDs(root *types.ASTNode) map[*types.ASTNode]string {
	result := make(map[*types.ASTNode]string)
	var visit func(*types.ASTNode, string)
	visit = func(node *types.ASTNode, path string) {
		if node == nil {
			return
		}
		result[node] = path
		for index, child := range node.Children {
			visit(child, path+"."+strconv.Itoa(index))
		}
	}
	visit(root, "0")
	return result
}

func (a *semanticAnalyzer) lowerNode(node *types.ASTNode, ctx lowerContext) []semanticOp {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case types.KindDeclFunction, types.KindDeclContract, types.KindStmtBlock,
		types.KindStmtUnchecked, types.KindAsmBlock, types.KindStmtIf,
		types.KindStmtLoop, types.KindStmtTryCatch, types.KindStmtEmit,
		types.KindDeclParameter, types.KindDeclModifier:
		return a.lowerChildren(node.Children, ctx)

	case types.KindStmtAssign:
		operations := a.lowerAssignmentEffects(node, ctx)
		assignmentOps, ok := a.lowerAssignmentOps(node, ctx)
		if !ok {
			a.recordUnsupportedWithReason(node, ctx, "exact assignment LHS, tuple metadata, or lvalue path is unavailable")
			operations = append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
			return operations
		}
		operations = append(operations, assignmentOps...)
		return operations

	case types.KindDeclVariable:
		childCount := len(node.Children)
		if childCount == 0 {
			return nil
		}
		if !semanticAttributePresent(node, "assignment_lhs_count") {
			a.recordUnsupportedWithReason(node, ctx, "declaration assignment LHS count is unavailable")
			return []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}}
		}
		lhsCount, lhsCountExact := semanticAttributeIntExact(node, "assignment_lhs_count")
		if !lhsCountExact {
			a.recordUnsupportedWithReason(node, ctx, "declaration assignment LHS count is malformed")
			return []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}}
		}
		if lhsCount == childCount {
			return nil
		}
		if lhsCount <= 0 || lhsCount > childCount {
			a.recordUnsupportedWithReason(node, ctx, "declaration assignment LHS count is outside the valid range")
			return []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}}
		}
		if lhsCount < childCount {
			operations := a.lowerAssignmentEffects(node, ctx)
			assignmentOps, ok := a.lowerAssignmentOps(node, ctx)
			if !ok {
				a.recordUnsupportedWithReason(node, ctx, "exact declaration assignment metadata is unavailable")
				return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
			}
			operations = append(operations, assignmentOps...)
			return operations
		}
		a.recordUnsupportedWithReason(node, ctx, "declaration assignment LHS count is impossible")
		return []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}}

	case types.KindExprIdentifier, types.KindExprMemberAccess, types.KindExprIndexAccess:
		var operations []semanticOp
		if node.Kind == types.KindExprMemberAccess || node.Kind == types.KindExprIndexAccess {
			operations = a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		} else {
			operations = a.lowerNestedEffects(node.Children, ctx, nestedEffectsOwnInexact)
		}
		if path, ok := a.pathForNode(node, ctx); ok {
			operations = append(operations, semanticOp{
				Kind:       semanticOpRead,
				Provenance: semanticRef{Node: node},
				Reads:      []accessPath{path},
				Inputs:     []semanticValue{a.valueForNode(node, ctx)},
			})
			return operations
		}
		a.recordUnsupportedWithReason(node, ctx, "exact access root or lvalue structure is unavailable")
		return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})

	case types.KindExprTuple:
		return a.lowerTuple(node, ctx)

	case types.KindExprBinaryOp, types.KindExprConditional:
		return a.lowerChildren(node.Children, ctx)

	case types.KindExprUnaryOp:
		operator := node.GetAttributeString("operator")
		if operator == "delete" || operator == "++" || operator == "--" {
			operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
			target := firstSemanticChild(node)
			write, exactTarget := a.requiredWritePath(target, ctx)
			if !exactTarget {
				a.recordUnsupportedWithReason(target, ctx, "mutation target lacks an exact write path")
				return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
			}
			inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
			if malformedTuple != nil {
				return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
			}
			reads := []accessPath(nil)
			if operator != "delete" {
				reads = []accessPath{cloneAccessPath(write)}
			}
			operations = append(operations, semanticOp{
				Kind:       semanticOpWrite,
				Provenance: semanticRef{Node: node},
				Reads:      reads,
				Writes:     []accessPath{write},
				Inputs:     inputs,
			})
			return operations
		}
		return a.lowerChildren(node.Children, ctx)

	case types.KindStmtStateMutation:
		operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		target := firstSemanticChild(node)
		write, exactTarget := a.requiredWritePath(target, ctx)
		if !exactTarget {
			a.recordUnsupportedWithReason(target, ctx, "state mutation receiver lacks an exact write path")
			return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
		}
		inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
		if malformedTuple != nil {
			return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
		}
		operations = append(operations, semanticOp{
			Kind:       semanticOpWrite,
			Provenance: semanticRef{Node: node},
			Reads:      a.readPathsForChildren(node.Children, ctx),
			Writes:     []accessPath{write},
			Inputs:     inputs,
		})
		return operations

	case types.KindStmtReturn:
		operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
		if malformedTuple != nil {
			return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
		}
		reads := a.readPathsForChildren(node.Children, ctx)
		if len(node.Children) == 1 && node.Children[0] != nil && node.Children[0].Kind == types.KindExprTuple {
			reads = nil
			for _, input := range inputs {
				reads = append(reads, cloneAccessPaths(input.Sources)...)
			}
		}
		operations = append(operations, semanticOp{
			Kind:       semanticOpReturn,
			Provenance: semanticRef{Node: node},
			Reads:      reads,
			Inputs:     inputs,
		})
		return operations

	case types.KindCheckRequire, types.KindCheckAssert:
		return a.lowerCallWithKind(node, ctx, semanticOpCheck)
	case types.KindCheckRevert:
		return a.lowerCallWithKind(node, ctx, semanticOpTerminal)
	case types.KindCallBuiltinSelfdestruct:
		return a.lowerCallWithKind(node, ctx, semanticOpTerminal)

	case types.KindCallInternal, types.KindCallExternal, types.KindCallLowlevelCall,
		types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
		types.KindCallBuiltinTransfer, types.KindCallBuiltinSend, types.KindCallCreate,
		types.KindAsmCall, types.KindAsmDelegatecall, types.KindAsmStaticcall,
		types.KindAsmCreate, types.KindAsmCreate2, types.KindAsmLog0,
		types.KindAsmLog1, types.KindAsmLog2, types.KindAsmLog3, types.KindAsmLog4:
		if isSemanticCast(node) {
			return a.lowerChildren(node.Children, ctx)
		}
		return a.lowerCallWithKind(node, ctx, semanticOpCall)

	case types.KindAsmSstore:
		slot := firstSemanticChild(node)
		if slot == nil || !exactExpressionIdentity(slot) {
			operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
			a.recordUnsupportedWithReason(node, ctx, "Yul storage offset lacks exact expression identity")
			return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
		}
		operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
		if malformedTuple != nil {
			return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
		}
		reads := a.readPathsForChildren(node.Children, ctx)
		path, _ := yulOffsetPath(slot, ctx, storagePersistent, "yul-storage")
		writes := []accessPath{path}
		operations = append(operations, semanticOp{Kind: semanticOpWrite, Provenance: semanticRef{Node: node}, Reads: reads, Writes: writes, Inputs: inputs})
		return operations

	case types.KindAsmSload:
		slot := firstSemanticChild(node)
		if slot == nil || !exactExpressionIdentity(slot) {
			operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
			a.recordUnsupportedWithReason(node, ctx, "Yul storage offset lacks exact expression identity")
			return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
		}
		operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
		if malformedTuple != nil {
			return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
		}
		reads := a.readPathsForChildren(node.Children, ctx)
		path, _ := yulOffsetPath(slot, ctx, storagePersistent, "yul-storage")
		reads = append(reads, path)
		operations = append(operations, semanticOp{Kind: semanticOpRead, Provenance: semanticRef{Node: node}, Reads: reads, Inputs: inputs})
		return operations

	case types.KindAsmRevert, types.KindAsmReturn, types.KindAsmSelfdestruct:
		operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
		inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
		if malformedTuple != nil {
			return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
		}
		operations = append(operations, semanticOp{Kind: semanticOpTerminal, Provenance: semanticRef{Node: node}, Reads: a.readPathsForChildren(node.Children, ctx), Inputs: inputs})
		return operations

	case types.KindAsmOperation:
		return a.lowerYulOperation(node, ctx)

	case types.KindExprLiteral:
		return a.lowerChildren(node.Children, ctx)

	default:
		a.recordUnsupported(node, ctx)
		return []semanticOp{{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}}
	}
}

func (a *semanticAnalyzer) lowerYulOperation(node *types.ASTNode, ctx lowerContext) []semanticOp {
	offsetIndex := -1
	switch node.Name {
	case "mstore", "mstore8", "calldatacopy", "codecopy", "returndatacopy", "mload":
		offsetIndex = 0
	case "extcodecopy":
		offsetIndex = 1
	}
	if offsetIndex >= 0 {
		offset := yulOperationChild(node, offsetIndex)
		if offset == nil || !exactExpressionIdentity(offset) {
			operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
			a.recordUnsupportedWithReason(node, ctx, "Yul memory offset lacks exact expression identity")
			return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
		}
	}
	operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
	inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
	if malformedTuple != nil {
		return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
	}
	reads := a.readPathsForChildren(node.Children, ctx)
	operation := semanticOp{
		Kind:       semanticOpAssign,
		Provenance: semanticRef{Node: node},
		Reads:      reads,
		Inputs:     inputs,
	}
	switch node.Name {
	case "stop", "invalid":
		operation.Kind = semanticOpTerminal
	case "mstore", "mstore8", "calldatacopy", "codecopy", "returndatacopy":
		operation.Kind = semanticOpWrite
		if offset := yulOperationChild(node, 0); offset != nil {
			path, _ := yulOffsetPath(offset, ctx, storageMemory, "yul-memory")
			operation.Writes = []accessPath{path}
		}
	case "extcodecopy":
		operation.Kind = semanticOpWrite
		if offset := yulOperationChild(node, 1); offset != nil {
			path, _ := yulOffsetPath(offset, ctx, storageMemory, "yul-memory")
			operation.Writes = []accessPath{path}
		}
	case "mload":
		operation.Kind = semanticOpRead
		if offset := yulOperationChild(node, 0); offset != nil {
			path, _ := yulOffsetPath(offset, ctx, storageMemory, "yul-memory")
			operation.Reads = append(operation.Reads, path)
		}
	}
	operations = append(operations, operation)
	return operations
}

func yulOperationChild(node *types.ASTNode, index int) *types.ASTNode {
	if node == nil || index < 0 || index >= len(node.Children) {
		return nil
	}
	return node.Children[index]
}

func yulOffsetPath(offset *types.ASTNode, ctx lowerContext, storage storageClass, rootName string) (accessPath, bool) {
	if !exactExpressionIdentity(offset) {
		return accessPath{}, false
	}
	rootID := ctx.ScopeID + ":" + rootName
	alias := normalizedExpressionAlias(offset, ctx)
	if storage == storagePersistent {
		rootID = ctx.ContractID + ":" + rootName
		alias = normalizedExpressionAliasWithScope(offset, "")
	}
	return accessPath{
		Root: accessRoot{RefID: rootID, Storage: storage},
		Segments: []pathSegment{{
			Kind:     segmentMemoryOffset,
			AliasSet: alias,
		}},
	}, true
}

func (a *semanticAnalyzer) lowerChildren(children []*types.ASTNode, ctx lowerContext) []semanticOp {
	var operations []semanticOp
	for _, child := range children {
		operations = append(operations, a.lowerNode(child, ctx)...)
	}
	return operations
}

func (a *semanticAnalyzer) lowerAssignment(node *types.ASTNode, ctx lowerContext) semanticOp {
	operations, _ := a.lowerAssignmentOps(node, ctx)
	if len(operations) == 0 {
		return semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}}
	}
	return operations[0]
}

func (a *semanticAnalyzer) lowerAssignmentOps(node *types.ASTNode, ctx lowerContext) ([]semanticOp, bool) {
	if node == nil || !semanticAttributePresent(node, "assignment_lhs_count") {
		return nil, false
	}
	lhsCount, ok := semanticAttributeIntExact(node, "assignment_lhs_count")
	if !ok {
		return nil, false
	}
	if lhsCount <= 0 || lhsCount >= len(node.Children) {
		return nil, false
	}
	rhs := node.Children[lhsCount:]
	reads := a.readPathsForChildren(rhs, ctx)
	operator := node.GetAttributeString("operator")
	if operator != "" && operator != "=" {
		reads = append(reads, a.readPathsForChildren(node.Children[:lhsCount], ctx)...)
	}
	inputs, malformedTuple := a.valuesForChildren(rhs, ctx)
	if malformedTuple != nil {
		return nil, false
	}
	tupleArity := 0
	tupleMetadataPresent := semanticAttributePresent(node, "tuple_arity")
	if tupleMetadataPresent {
		tupleArity, ok = semanticAttributeIntExact(node, "tuple_arity")
		if !ok || tupleArity <= 0 {
			return nil, false
		}
	}
	tupleDestructure := len(rhs) == 1 && tupleMetadataPresent && tupleArity > 1
	if lhsCount > 1 && !tupleDestructure {
		return nil, false
	}
	if tupleDestructure {
		if _, ok := strictTupleChildren(node.Children[:lhsCount], tupleArity); !ok {
			return nil, false
		}
		var failing *types.ASTNode
		inputs, failing = a.tupleValues(rhs[0], tupleArity, ctx)
		if failing != nil {
			return nil, false
		}
	}
	writes := a.writePaths(node.Children, lhsCount, ctx)
	if len(writes) != lhsCount {
		return nil, false
	}
	if lhsCount == 1 && !tupleDestructure {
		return []semanticOp{{
			Kind:       semanticOpAssign,
			Provenance: semanticRef{Node: node},
			Reads:      reads,
			Writes:     writes,
			Inputs:     inputs,
		}}, true
	}
	byPosition := make(map[int]semanticValue, len(inputs))
	for _, input := range inputs {
		if input.Path == nil || len(input.Path.Segments) != 1 || input.Path.Segments[0].Kind != segmentTuple {
			return nil, false
		}
		position := input.Path.Segments[0].Index
		if _, duplicate := byPosition[position]; duplicate {
			return nil, false
		}
		byPosition[position] = input
	}
	operations := make([]semanticOp, 0, lhsCount)
	for lane := 0; lane < lhsCount; lane++ {
		lhs := node.Children[lane]
		position, ok := semanticAttributeIntExact(lhs, "tuple_index")
		if !ok {
			return nil, false
		}
		input, ok := byPosition[position]
		if !ok {
			return nil, false
		}
		operations = append(operations, semanticOp{Kind: semanticOpAssign, Provenance: semanticRef{Node: node}, Reads: cloneAccessPaths(input.Sources), Writes: []accessPath{cloneAccessPath(writes[lane])}, Inputs: []semanticValue{input.Clone()}})
	}
	return operations, true
}

func (a *semanticAnalyzer) lowerCall(node *types.ASTNode, ctx lowerContext) (semanticOp, *types.ASTNode) {
	inputs, malformedTuple := a.valuesForChildren(node.Children, ctx)
	return semanticOp{
		Kind:       semanticOpCall,
		Provenance: semanticRef{Node: node},
		Reads:      a.readPathsForChildren(node.Children, ctx),
		Inputs:     inputs,
	}, malformedTuple
}

func (a *semanticAnalyzer) lowerCallWithKind(node *types.ASTNode, ctx lowerContext, kind semanticOpKind) []semanticOp {
	operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
	operation, malformedTuple := a.lowerCall(node, ctx)
	if malformedTuple != nil {
		return a.failMalformedTupleValue(node, malformedTuple, ctx, operations)
	}
	operation.Kind = kind
	operations = append(operations, operation)
	return operations
}

func (a *semanticAnalyzer) lowerTuple(node *types.ASTNode, ctx lowerContext) []semanticOp {
	operations := a.lowerNestedEffects(node.Children, ctx, nestedEffectsOnly)
	values, failing := a.tupleValues(node, -1, ctx)
	if failing != nil {
		a.recordUnsupportedWithReason(failing, ctx, "tuple value lacks exact recursive metadata or dependencies")
		return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: node}})
	}
	for _, value := range values {
		operations = append(operations, semanticOp{Kind: semanticOpRead, Provenance: semanticRef{Node: node}, Reads: cloneAccessPaths(value.Sources), Inputs: []semanticValue{value.Clone()}})
	}
	return operations
}

func (a *semanticAnalyzer) tupleValues(node *types.ASTNode, arity int, ctx lowerContext) ([]semanticValue, *types.ASTNode) {
	if node == nil || arity <= 0 {
		if node == nil || node.Kind != types.KindExprTuple {
			return nil, node
		}
		var ok bool
		arity, _, ok = strictTupleMetadata(node)
		if !ok {
			return nil, node
		}
	}
	if node.Kind == types.KindExprTuple {
		tupleArity, _, ok := strictTupleMetadata(node)
		if !ok || tupleArity != arity {
			return nil, node
		}
		return a.tupleValuesRecursive(node, node, nil, ctx)
	}
	if _, failing := a.lowerSemanticValue(node, ctx); failing != nil {
		return nil, failing
	}
	values := make([]semanticValue, 0, arity)
	for position := 0; position < arity; position++ {
		lane := tupleTemporaryPath(node, position, ctx)
		values = append(values, semanticValue{Path: &lane, Type: nodeTypeInfo(node), Provenance: semanticRef{Node: node}})
	}
	return values, nil
}

func (a *semanticAnalyzer) tupleValuesRecursive(tuple, root *types.ASTNode, prefix []int, ctx lowerContext) ([]semanticValue, *types.ASTNode) {
	_, positions, ok := strictTupleMetadata(tuple)
	if !ok {
		return nil, tuple
	}
	var values []semanticValue
	for childIndex, child := range tuple.Children {
		positionPath := append(append([]int(nil), prefix...), positions[childIndex])
		if child != nil && child.Kind == types.KindExprTuple {
			nested, failing := a.tupleValuesRecursive(child, root, positionPath, ctx)
			if failing != nil {
				return nil, failing
			}
			values = append(values, nested...)
			continue
		}
		scalars, failing := a.lowerSemanticValue(child, ctx)
		if failing != nil || len(scalars) != 1 {
			if failing == nil {
				failing = child
			}
			return nil, failing
		}
		lane := tupleTemporaryPathPositions(root, positionPath, ctx)
		scalar := scalars[0]
		values = append(values, semanticValue{Path: &lane, Type: scalar.Type, Sources: cloneAccessPaths(scalar.Sources), Provenance: scalar.Provenance})
	}
	return values, nil
}

func tupleTemporaryPath(node *types.ASTNode, position int, ctx lowerContext) accessPath {
	return tupleTemporaryPathPositions(node, []int{position}, ctx)
}

func tupleTemporaryPathPositions(node *types.ASTNode, positions []int, ctx lowerContext) accessPath {
	occurrence := ""
	if node != nil && node.EndByte > node.StartByte {
		occurrence = fmt.Sprintf("byte:%d:%d", node.StartByte, node.EndByte)
	} else if ctx.Occurrences != nil {
		occurrence = "path:" + ctx.Occurrences[node]
	}
	path := accessPath{
		Root: accessRoot{
			RefID:   ctx.ScopeID + ":tuple:" + occurrence + ":" + normalizedExpressionAlias(node, ctx),
			Storage: storageReturn,
		},
	}
	for _, position := range positions {
		path.Segments = append(path.Segments, pathSegment{Kind: segmentTuple, Index: position})
	}
	return path
}

func (a *semanticAnalyzer) pathForNode(node *types.ASTNode, ctx lowerContext) (accessPath, bool) {
	if node == nil {
		return accessPath{}, false
	}
	switch node.Kind {
	case types.KindExprIdentifier:
		rootID := node.RefID
		if rootID == "" {
			if !isDirectEnvironmentIdentifier(node) {
				return accessPath{}, false
			}
			rootID = "environment:" + node.Name
		}
		return accessPath{Root: accessRoot{RefID: rootID, Storage: a.storageForNode(node)}}, true

	case types.KindExprMemberAccess:
		base := firstSemanticChild(node)
		path, ok := a.pathForNode(base, ctx)
		if !ok || node.Name == "" {
			return accessPath{}, false
		}
		path.Segments = append(path.Segments, pathSegment{Kind: segmentField, Name: node.Name})
		return path, true

	case types.KindExprIndexAccess:
		base := firstSemanticChild(node)
		path, ok := a.pathForNode(base, ctx)
		if !ok || len(node.Children) < 2 {
			return accessPath{}, false
		}
		index := node.Children[1]
		segment := pathSegment{}
		if nodeTypeInfo(base).Kind == types.TypeKindMapping {
			segment.Kind = segmentMappingKey
			if literal, ok := mappingLiteralSegment(index); ok {
				segment.Index = literal.Index
				segment.Key = literal.Key
			} else {
				if !exactExpressionIdentity(index) {
					return accessPath{}, false
				}
				segment.AliasSet = normalizedExpressionAlias(index, ctx)
			}
		} else if literal, ok := literalIndexSegment(index); ok {
			segment = literal
		} else {
			if !exactExpressionIdentity(index) {
				return accessPath{}, false
			}
			segment.Kind = segmentDynamicIndex
			segment.AliasSet = normalizedExpressionAlias(index, ctx)
		}
		path.Segments = append(path.Segments, segment)
		return path, true
	}
	return accessPath{}, false
}

func (a *semanticAnalyzer) writePaths(children []*types.ASTNode, lhsCount int, ctx lowerContext) []accessPath {
	if lhsCount > len(children) {
		lhsCount = len(children)
	}
	var writes []accessPath
	for i := 0; i < lhsCount; i++ {
		writes = append(writes, a.writePathsForNode(children[i], ctx)...)
	}
	return writes
}

func (a *semanticAnalyzer) writePathsForNode(node *types.ASTNode, ctx lowerContext) []accessPath {
	if node == nil {
		return nil
	}
	if node.Kind == types.KindExprTuple {
		var paths []accessPath
		for _, child := range node.Children {
			paths = append(paths, a.writePathsForNode(child, ctx)...)
		}
		return paths
	}
	path, ok := a.pathForNode(node, ctx)
	if !ok {
		return nil
	}
	return []accessPath{path}
}

func (a *semanticAnalyzer) requiredWritePath(node *types.ASTNode, ctx lowerContext) (accessPath, bool) {
	if node == nil || node.Kind == types.KindExprTuple {
		return accessPath{}, false
	}
	path, ok := a.pathForNode(node, ctx)
	if !ok {
		return accessPath{}, false
	}
	return cloneAccessPath(path), true
}

func (a *semanticAnalyzer) readPaths(node *types.ASTNode, ctx lowerContext) []accessPath {
	if node == nil {
		return nil
	}
	if isSemanticCast(node) {
		return a.readPathsForChildren(node.Children, ctx)
	}
	if path, ok := a.pathForNode(node, ctx); ok {
		paths := []accessPath{path}
		if node.Kind == types.KindExprIndexAccess && len(node.Children) > 1 {
			paths = append(paths, a.readPaths(node.Children[1], ctx)...)
		}
		return paths
	}
	return a.readPathsForChildren(node.Children, ctx)
}

func (a *semanticAnalyzer) readPathsForChildren(children []*types.ASTNode, ctx lowerContext) []accessPath {
	var paths []accessPath
	for _, child := range children {
		paths = append(paths, a.readPaths(child, ctx)...)
	}
	return paths
}

func (a *semanticAnalyzer) valueForNode(node *types.ASTNode, ctx lowerContext) semanticValue {
	value := semanticValue{Type: nodeTypeInfo(node), Provenance: semanticRef{Node: node}}
	if path, ok := a.pathForNode(node, ctx); ok {
		copy := cloneAccessPath(path)
		value.Path = &copy
		value.Sources = []accessPath{cloneAccessPath(path)}
	} else {
		value.Sources = cloneAccessPaths(a.readPaths(node, ctx))
	}
	return value
}

func (a *semanticAnalyzer) valuesForChildren(children []*types.ASTNode, ctx lowerContext) ([]semanticValue, *types.ASTNode) {
	values := make([]semanticValue, 0, len(children))
	for _, child := range children {
		if child == nil {
			continue
		}
		childValues, failing := a.lowerSemanticValue(child, ctx)
		if failing != nil {
			return nil, failing
		}
		values = append(values, childValues...)
	}
	return values, nil
}

func (a *semanticAnalyzer) lowerSemanticValue(node *types.ASTNode, ctx lowerContext) ([]semanticValue, *types.ASTNode) {
	if node == nil {
		return nil, node
	}
	if node.Kind == types.KindExprTuple {
		return a.tupleValues(node, -1, ctx)
	}
	if failing := a.validateSemanticValue(node, ctx); failing != nil {
		return nil, failing
	}
	return []semanticValue{a.valueForNode(node, ctx)}, nil
}

func (a *semanticAnalyzer) validateSemanticValue(node *types.ASTNode, ctx lowerContext) *types.ASTNode {
	if node == nil {
		return node
	}
	switch node.Kind {
	case types.KindExprIdentifier, types.KindExprMemberAccess, types.KindExprIndexAccess:
		if _, ok := a.pathForNode(node, ctx); !ok {
			if exactSourceValueIdentifier(node) {
				return nil
			}
			return node
		}
		return nil
	case types.KindExprLiteral:
		if !exactLiteralIdentity(node) {
			return node
		}
		return nil
	case types.KindExprBinaryOp:
		if node.GetAttributeString("operator") == "" || len(node.Children) != 2 {
			return node
		}
	case types.KindExprUnaryOp:
		if node.GetAttributeString("operator") == "" || len(node.Children) != 1 {
			return node
		}
	case types.KindExprConditional:
		if len(node.Children) != 3 {
			return node
		}
	case types.KindCallInternal, types.KindCallExternal, types.KindCallLowlevelCall,
		types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
		types.KindCallBuiltinTransfer, types.KindCallBuiltinSend,
		types.KindCallBuiltinSelfdestruct, types.KindCallCreate,
		types.KindAsmCall, types.KindAsmDelegatecall, types.KindAsmStaticcall,
		types.KindAsmCreate, types.KindAsmCreate2, types.KindAsmLog0,
		types.KindAsmLog1, types.KindAsmLog2, types.KindAsmLog3, types.KindAsmLog4,
		types.KindAsmSstore, types.KindAsmSload, types.KindAsmSelfdestruct,
		types.KindAsmRevert, types.KindAsmReturn, types.KindAsmOperation:
		// Calls and Yul transforms are exact occurrence values once every input
		// value below is exact.
	default:
		return node
	}
	for _, child := range node.Children {
		if _, failing := a.lowerSemanticValue(child, ctx); failing != nil {
			return failing
		}
	}
	return nil
}

func (a *semanticAnalyzer) failMalformedTupleValue(enclosing, failing *types.ASTNode, ctx lowerContext, operations []semanticOp) []semanticOp {
	a.recordUnsupportedWithReason(failing, ctx, "semantic value lacks exact recursive metadata or dependencies")
	return append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: enclosing}})
}

func isDirectEnvironmentIdentifier(node *types.ASTNode) bool {
	return node != nil && node.Kind == types.KindExprIdentifier && (node.Name == "msg" || node.Name == "tx") && node.RefID == "" && node.RefKind == "" && !node.GetAttributeBool("assembly")
}

func exactSourceValueIdentifier(node *types.ASTNode) bool {
	if node == nil || node.Kind != types.KindExprIdentifier || node.Name == "" || node.RefID != "" || node.RefKind != "" || node.GetAttributeBool("assembly") {
		return false
	}
	return node.Name == "this"
}

func exactLiteralIdentity(node *types.ASTNode) bool {
	if node == nil || node.Kind != types.KindExprLiteral {
		return false
	}
	subtype := node.GetAttributeString("subtype")
	switch node.GetAttributeString("literal_class") {
	case "numeric_decimal":
		return subtype == "number"
	case "numeric_hex", "hex_string":
		return subtype == "hex"
	case "":
		return subtype == "string" || subtype == "bool"
	default:
		return false
	}
}

func exactExpressionIdentity(node *types.ASTNode) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case types.KindExprIdentifier:
		return node.RefID != "" || isDirectEnvironmentIdentifier(node)
	case types.KindExprLiteral:
		return exactLiteralIdentity(node) && (node.Value != "" || node.Name != "")
	case types.KindExprMemberAccess:
		return node.Name != "" && len(node.Children) == 1 && exactExpressionIdentity(node.Children[0])
	case types.KindExprIndexAccess:
		return len(node.Children) == 2 && exactExpressionIdentity(node.Children[0]) && exactExpressionIdentity(node.Children[1])
	case types.KindExprBinaryOp:
		return node.GetAttributeString("operator") != "" && len(node.Children) == 2 && exactExpressionChildren(node.Children)
	case types.KindExprUnaryOp:
		return node.GetAttributeString("operator") != "" && len(node.Children) == 1 && exactExpressionIdentity(node.Children[0])
	case types.KindExprConditional:
		return len(node.Children) == 3 && exactExpressionChildren(node.Children)
	case types.KindExprTuple:
		_, _, ok := strictTupleMetadata(node)
		return ok && exactExpressionChildren(node.Children)
	case types.KindAsmOperation:
		return node.Name != "" && exactExpressionChildren(node.Children)
	case types.KindCallInternal:
		return isSemanticCast(node) && exactExpressionChildren(node.Children)
	default:
		return false
	}
}

func exactExpressionChildren(children []*types.ASTNode) bool {
	for _, child := range children {
		if !exactExpressionIdentity(child) {
			return false
		}
	}
	return true
}

func strictTupleMetadata(node *types.ASTNode) (int, []int, bool) {
	if node == nil || node.Kind != types.KindExprTuple {
		return 0, nil, false
	}
	arity, ok := semanticAttributeIntExact(node, "tuple_arity")
	if !ok || arity <= 0 {
		return 0, nil, false
	}
	positions, ok := strictTupleChildren(node.Children, arity)
	return arity, positions, ok
}

func strictTupleChildren(children []*types.ASTNode, arity int) ([]int, bool) {
	if arity <= 0 {
		return nil, false
	}
	positions := make([]int, len(children))
	seen := make(map[int]bool, len(children))
	for childIndex, child := range children {
		position, ok := semanticAttributeIntExact(child, "tuple_index")
		if !ok || position < 0 || position >= arity || seen[position] {
			return nil, false
		}
		seen[position] = true
		positions[childIndex] = position
	}
	return positions, true
}

func (a *semanticAnalyzer) lowerAssignmentEffects(node *types.ASTNode, ctx lowerContext) []semanticOp {
	return a.lowerNestedEffects(node.Children, ctx, nestedEffectsOwnInexact)
}

type nestedEffectMode uint8

const (
	nestedEffectsOnly nestedEffectMode = iota
	nestedEffectsOwnInexact
)

func (a *semanticAnalyzer) lowerNestedEffects(children []*types.ASTNode, ctx lowerContext, mode nestedEffectMode) []semanticOp {
	var operations []semanticOp
	for _, child := range children {
		if child == nil {
			continue
		}
		if child.Kind == types.KindExprIdentifier {
			if mode == nestedEffectsOwnInexact {
				if _, ok := a.pathForNode(child, ctx); ok {
					continue
				}
				a.recordUnsupportedWithReason(child, ctx, "nested expression lacks an exact access path")
				operations = append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: child}})
			}
			continue
		}
		if child.Kind == types.KindExprMemberAccess || child.Kind == types.KindExprIndexAccess {
			operations = append(operations, a.lowerNestedEffects(child.Children, ctx, nestedEffectsOnly)...)
			if mode == nestedEffectsOwnInexact {
				if _, ok := a.pathForNode(child, ctx); ok {
					continue
				}
				a.recordUnsupportedWithReason(child, ctx, "nested expression lacks an exact access path")
				operations = append(operations, semanticOp{Kind: semanticOpUnknown, Provenance: semanticRef{Node: child}})
			}
			continue
		}
		switch child.Kind {
		case types.KindStmtAssign, types.KindStmtStateMutation, types.KindStmtReturn,
			types.KindCheckRequire, types.KindCheckAssert, types.KindCheckRevert,
			types.KindCallInternal, types.KindCallExternal, types.KindCallLowlevelCall,
			types.KindCallLowlevelDelegate, types.KindCallLowlevelStatic,
			types.KindCallBuiltinTransfer, types.KindCallBuiltinSend,
			types.KindCallBuiltinSelfdestruct, types.KindCallCreate,
			types.KindAsmCall, types.KindAsmDelegatecall, types.KindAsmStaticcall,
			types.KindAsmSstore, types.KindAsmSload, types.KindAsmSelfdestruct,
			types.KindAsmCreate, types.KindAsmCreate2, types.KindAsmLog0,
			types.KindAsmLog1, types.KindAsmLog2, types.KindAsmLog3, types.KindAsmLog4,
			types.KindAsmRevert, types.KindAsmReturn, types.KindAsmOperation,
			types.KindExprUnaryOp:
			if isSemanticCast(child) {
				operations = append(operations, a.lowerNestedEffects(child.Children, ctx, mode)...)
				continue
			}
			if child.Kind == types.KindExprUnaryOp {
				operator := child.GetAttributeString("operator")
				if operator != "delete" && operator != "++" && operator != "--" {
					operations = append(operations, a.lowerNestedEffects(child.Children, ctx, mode)...)
					continue
				}
			}
			operations = append(operations, a.lowerNode(child, ctx)...)
		default:
			operations = append(operations, a.lowerNestedEffects(child.Children, ctx, mode)...)
		}
	}
	return operations
}

func (a *semanticAnalyzer) storageForNode(node *types.ASTNode) storageClass {
	if node == nil {
		return storageUnknown
	}
	switch node.GetAttributeString("data_location") {
	case "storage":
		return storagePersistent
	case "memory":
		return storageMemory
	case "calldata":
		return storageCalldata
	}
	if node.RefKind == "state_var" {
		return storagePersistent
	}
	if a != nil && a.db != nil && a.db.Semantics != nil && node.RefID != "" {
		if symbol := a.db.Semantics.GetSymbol(node.RefID); symbol != nil {
			switch symbol.StorageClass {
			case "state_var", "storage":
				return storagePersistent
			case "memory":
				return storageMemory
			case "calldata":
				return storageCalldata
			case "return":
				return storageReturn
			}
		}
	}
	return storageStack
}

func (a *semanticAnalyzer) recordUnsupported(node *types.ASTNode, ctx lowerContext) {
	a.recordUnsupportedWithReason(node, ctx, "AST shape is unsupported")
}

func (a *semanticAnalyzer) recordUnsupportedWithReason(node *types.ASTNode, ctx lowerContext, reason string) {
	if node == nil || ctx.Diagnostics == nil {
		return
	}
	file := ""
	if ctx.Function != nil {
		file = ctx.Function.SourceFile
	}
	if file == "" && ctx.Contract != nil {
		file = ctx.Contract.SourceFile
	}
	site := ""
	if node.EndByte > node.StartByte {
		site = fmt.Sprintf("bytes [%d,%d)", node.StartByte, node.EndByte)
	} else {
		occurrence := "unmapped"
		if ctx.Occurrences != nil && ctx.Occurrences[node] != "" {
			occurrence = ctx.Occurrences[node]
		}
		site = "occurrence path " + occurrence
	}
	diagnostic := types.Diagnostic{
		Code:       types.DiagnosticSemanticUnsupported,
		Severity:   types.DiagnosticWarning,
		Phase:      "semantic",
		Message:    fmt.Sprintf("semantic lowering does not support AST kind %q at %s in %s: %s", node.Kind, site, ctx.ScopeID, reason),
		File:       file,
		Line:       node.StartLine,
		Symbol:     node.Kind,
		Incomplete: true,
	}
	key := semanticDiagnosticKey(diagnostic)
	if _, exists := a.diagnosticKeys[key]; exists {
		return
	}
	a.diagnosticKeys[key] = struct{}{}
	*ctx.Diagnostics = append(*ctx.Diagnostics, diagnostic)
}

func normalizedExpressionAlias(node *types.ASTNode, ctx lowerContext) string {
	return normalizedExpressionAliasWithScope(node, ctx.ScopeID)
}

func normalizedExpressionAliasWithScope(node *types.ASTNode, scope string) string {
	var normalized strings.Builder
	appendSemanticAliasString(&normalized, "expr:1")
	appendSemanticAliasString(&normalized, scope)
	appendNormalizedExpression(&normalized, node)
	sum := sha256.Sum256([]byte(normalized.String()))
	return "expr:1:" + hex.EncodeToString(sum[:])
}

func appendNormalizedExpression(out *strings.Builder, node *types.ASTNode) {
	if node == nil {
		appendSemanticAliasString(out, "nil")
		return
	}
	appendSemanticAliasString(out, node.Kind)
	appendSemanticAliasString(out, node.Name)
	value := node.Value
	if node.Kind == types.KindExprLiteral {
		value = canonicalLiteralValue(node)
	}
	appendSemanticAliasString(out, value)
	appendSemanticAliasString(out, node.RefID)
	for _, attribute := range []string{"operator", "subtype", "type", "type_kind", "conditional_part", "call_option", "tuple_index", "tuple_arity"} {
		appendSemanticAliasString(out, attribute)
		appendSemanticAliasString(out, node.GetAttributeString(attribute))
	}
	appendSemanticAliasString(out, strconv.Itoa(len(node.Children)))
	for _, child := range node.Children {
		appendNormalizedExpression(out, child)
	}
}

func appendSemanticAliasString(out *strings.Builder, value string) {
	out.WriteString(strconv.Itoa(len(value)))
	out.WriteByte(':')
	out.WriteString(value)
	out.WriteByte(';')
}

func literalIndexSegment(node *types.ASTNode) (pathSegment, bool) {
	integer, ok := parseSolidityIntegerConstant(node)
	if !ok {
		return pathSegment{}, false
	}
	canonical := integer.String()
	segment := pathSegment{Kind: segmentFixedIndex, Key: canonical}
	if integer.IsInt64() {
		parsed := integer.Int64()
		if int64(int(parsed)) == parsed {
			segment.Index = int(parsed)
		}
	}
	return segment, true
}

func mappingLiteralSegment(node *types.ASTNode) (pathSegment, bool) {
	if !exactLiteralIdentity(node) {
		return pathSegment{}, false
	}
	if numeric, ok := literalIndexSegment(node); ok {
		numeric.Kind = segmentMappingKey
		numeric.Key = "number:" + numeric.Key
		return numeric, true
	}
	class := node.GetAttributeString("literal_class")
	subtype := node.GetAttributeString("subtype")
	value := node.Value
	if value == "" {
		value = node.Name
	}
	if class == "numeric_decimal" || class == "numeric_hex" || subtype == "" {
		return pathSegment{}, false
	}
	identity := subtype
	if class == "hex_string" {
		identity = class
	}
	return pathSegment{Kind: segmentMappingKey, Key: identity + ":" + value}, true
}

func canonicalLiteralValue(node *types.ASTNode) string {
	if node == nil {
		return ""
	}
	value := node.Value
	if value == "" {
		value = node.Name
	}
	if integer, ok := parseSolidityIntegerConstant(node); ok {
		return "integer:" + integer.String()
	}
	return node.GetAttributeString("literal_class") + ":" + node.GetAttributeString("subtype") + ":" + value
}

func parseSolidityIntegerConstant(node *types.ASTNode) (*big.Int, bool) {
	if node == nil || node.Kind != types.KindExprLiteral {
		return nil, false
	}
	if !exactLiteralIdentity(node) {
		return nil, false
	}
	class := node.GetAttributeString("literal_class")
	value := strings.TrimSpace(node.Value)
	if value == "" {
		value = strings.TrimSpace(node.Name)
	}
	var rational *big.Rat
	switch class {
	case "numeric_hex":
		if !strings.HasPrefix(value, "0x") && !strings.HasPrefix(value, "0X") {
			return nil, false
		}
		digits := value[2:]
		if !validUnderscoredDigits(digits, isHexDigit) {
			return nil, false
		}
		digits = strings.ReplaceAll(digits, "_", "")
		significant := strings.TrimLeft(digits, "0")
		if len(significant) > 64 {
			return nil, false
		}
		if significant == "" {
			significant = "0"
		}
		integer := new(big.Int)
		if _, ok := integer.SetString(significant, 16); !ok || integer.Sign() < 0 {
			return nil, false
		}
		rational = new(big.Rat).SetInt(integer)
	case "numeric_decimal":
		parsed, ok := parseDecimalRational(value)
		if !ok {
			return nil, false
		}
		rational = parsed
	default:
		return nil, false
	}
	multiplier, ok := solidityUnitMultiplier(node.GetAttributeString("subdenomination"))
	if !ok {
		return nil, false
	}
	rational.Mul(rational, new(big.Rat).SetInt(multiplier))
	if rational.Sign() < 0 || rational.Denom().Cmp(big.NewInt(1)) != 0 {
		return nil, false
	}
	integer := new(big.Int).Set(rational.Num())
	if integer.Cmp(maxSemanticUint256()) > 0 {
		return nil, false
	}
	return integer, true
}

func parseDecimalRational(value string) (*big.Rat, bool) {
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return nil, false
	}
	exponent := int64(0)
	if marker := strings.IndexAny(value, "eE"); marker >= 0 {
		if strings.IndexAny(value[marker+1:], "eE") >= 0 {
			return nil, false
		}
		exponentText := value[marker+1:]
		sign := ""
		if strings.HasPrefix(exponentText, "+") || strings.HasPrefix(exponentText, "-") {
			sign, exponentText = exponentText[:1], exponentText[1:]
		}
		if !validUnderscoredDigits(exponentText, isDecimalDigit) {
			return nil, false
		}
		parsed, err := strconv.ParseInt(sign+strings.ReplaceAll(exponentText, "_", ""), 10, 64)
		if err != nil {
			return nil, false
		}
		exponent = parsed
		value = value[:marker]
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || len(parts) == 0 || parts[0] == "" {
		return nil, false
	}
	whole := parts[0]
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" {
			return nil, false
		}
	}
	if !validUnderscoredDigits(whole, isDecimalDigit) || fraction != "" && !validUnderscoredDigits(fraction, isDecimalDigit) {
		return nil, false
	}
	whole = strings.ReplaceAll(whole, "_", "")
	fraction = strings.ReplaceAll(fraction, "_", "")
	digits := whole + fraction
	significant := strings.TrimLeft(digits, "0")
	if significant == "" {
		return new(big.Rat), true
	}
	fractionLength := int64(len(fraction))
	if exponent > fractionLength+77 || exponent < fractionLength-int64(len(significant))-18 {
		return nil, false
	}
	scale := fractionLength - exponent
	for scale > 0 && strings.HasSuffix(significant, "0") {
		significant = significant[:len(significant)-1]
		scale--
	}
	if scale <= 0 {
		zeros := -scale
		if zeros > 77 || int64(len(significant))+zeros > 78 {
			return nil, false
		}
		numerator := new(big.Int)
		if _, ok := numerator.SetString(significant, 10); !ok {
			return nil, false
		}
		numerator.Mul(numerator, pow10(int(zeros)))
		return new(big.Rat).SetInt(numerator), true
	}
	if scale > 18 || int64(len(significant))-scale > 78 || len(significant) > 96 {
		return nil, false
	}
	numerator := new(big.Int)
	if _, ok := numerator.SetString(significant, 10); !ok {
		return nil, false
	}
	return new(big.Rat).SetFrac(numerator, pow10(int(scale))), true
}

func pow10(exponent int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
}

func maxSemanticUint256() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
}

func validUnderscoredDigits(value string, isDigit func(byte) bool) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] == '_' {
			if index == 0 || index+1 == len(value) || !isDigit(value[index-1]) || !isDigit(value[index+1]) {
				return false
			}
			continue
		}
		if !isDigit(value[index]) {
			return false
		}
	}
	return true
}

func isDecimalDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isHexDigit(value byte) bool {
	return isDecimalDigit(value) || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func solidityUnitMultiplier(unit string) (*big.Int, bool) {
	multipliers := map[string]string{"": "1", "wei": "1", "gwei": "1000000000", "ether": "1000000000000000000", "seconds": "1", "minutes": "60", "hours": "3600", "days": "86400", "weeks": "604800"}
	value, ok := multipliers[unit]
	if !ok {
		return nil, false
	}
	integer, _ := new(big.Int).SetString(value, 10)
	return integer, true
}

func nodeTypeInfo(node *types.ASTNode) types.TypeInfo {
	if node == nil {
		return types.TypeInfo{}
	}
	return types.TypeInfo{
		Name:        node.GetAttributeString("type"),
		BaseName:    node.GetAttributeString("type_base"),
		Kind:        node.GetAttributeString("type_kind"),
		ContractID:  node.GetAttributeString("type_contract_id"),
		IsAddress:   node.GetAttributeBool("type_is_address"),
		IsPayable:   node.GetAttributeBool("type_is_payable"),
		Confidence:  node.GetAttributeString("type_confidence"),
		Source:      node.GetAttributeString("type_source"),
		ElementType: node.GetAttributeString("type_element"),
		KeyType:     node.GetAttributeString("type_key"),
		ValueType:   node.GetAttributeString("type_value"),
	}
}

func semanticAttributeInt(node *types.ASTNode, key string) int {
	if node == nil || node.Attributes == nil {
		return 0
	}
	value, ok := node.Attributes[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(typed)
		return parsed
	default:
		return 0
	}
}

func semanticAttributeIntExact(node *types.ASTNode, key string) (int, bool) {
	if node == nil || node.Attributes == nil {
		return 0, false
	}
	value, ok := node.Attributes[key]
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		if int64(int(typed)) != typed {
			return 0, false
		}
		return int(typed), true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed > float64(math.MaxInt) || typed < float64(math.MinInt) {
			return 0, false
		}
		return int(typed), true
	case string:
		if typed == "" {
			return 0, false
		}
		start := 0
		if typed[0] == '-' {
			if len(typed) == 1 {
				return 0, false
			}
			start = 1
		}
		for i := start; i < len(typed); i++ {
			if typed[i] < '0' || typed[i] > '9' {
				return 0, false
			}
		}
		parsed, err := strconv.Atoi(typed)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func semanticAttributePresent(node *types.ASTNode, key string) bool {
	if node == nil || node.Attributes == nil {
		return false
	}
	_, ok := node.Attributes[key]
	return ok
}

func isSemanticCast(node *types.ASTNode) bool {
	if node == nil || node.Kind != types.KindCallInternal {
		return false
	}
	source := node.GetAttributeString("type_source")
	return source == "type_cast" || source == "payable_cast"
}

func firstSemanticChild(node *types.ASTNode) *types.ASTNode {
	if node == nil || len(node.Children) == 0 {
		return nil
	}
	return node.Children[0]
}

func cloneSemanticFunction(source *semanticFunction) *semanticFunction {
	if source == nil {
		return nil
	}
	cloned := &semanticFunction{Function: source.Function, Contract: source.Contract, Operations: make([]*semanticOp, len(source.Operations)), ByNode: make(map[*types.ASTNode][]int, len(source.ByNode))}
	for index, operation := range source.Operations {
		if operation == nil {
			continue
		}
		copy := *operation
		copy.Reads = cloneAccessPaths(operation.Reads)
		copy.Writes = cloneAccessPaths(operation.Writes)
		copy.Inputs = make([]semanticValue, len(operation.Inputs))
		for inputIndex := range operation.Inputs {
			copy.Inputs[inputIndex] = operation.Inputs[inputIndex].Clone()
		}
		cloned.Operations[index] = &copy
	}
	for node, indexes := range source.ByNode {
		cloned.ByNode[node] = append([]int(nil), indexes...)
	}
	return cloned
}

func cloneAccessPaths(paths []accessPath) []accessPath {
	if paths == nil {
		return nil
	}
	cloned := make([]accessPath, len(paths))
	for index := range paths {
		cloned[index] = cloneAccessPath(paths[index])
	}
	return cloned
}
