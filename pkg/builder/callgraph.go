package builder

import (
	"sort"
	"strings"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// CallGraphBuilder builds the call graph for the project
type CallGraphBuilder struct {
	db              *types.Database
	logf            func(string, ...any)
	locators        map[string]*sourceLocator
	locator         *sourceLocator
	currentContract *types.Contract
	currentFunction *types.Function
	// currentModifier is non-nil while analyzing a modifier body; in that
	// state, discovered calls are attached to the modifier's Calls slice and the
	// edge "From" is the modifier ID rather than a function ID.
	currentModifier *types.Modifier
	currentFile     *types.SourceFile
	symbolTypes     map[string]types.TypeInfo
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder(db *types.Database) *CallGraphBuilder {
	return newCallGraphBuilder(db, VerboseLog)
}

func newCallGraphBuilder(db *types.Database, logf func(string, ...any)) *CallGraphBuilder {
	return newCallGraphBuilderWithLocators(db, logf, nil)
}

func newCallGraphBuilderWithLocators(db *types.Database, logf func(string, ...any), locators map[string]*sourceLocator) *CallGraphBuilder {
	if locators == nil {
		locators = make(map[string]*sourceLocator)
	}
	return &CallGraphBuilder{
		db:       db,
		logf:     logf,
		locators: locators,
	}
}

// Build constructs the call graph
func (cgb *CallGraphBuilder) Build() error {
	// Iterate over source files in deterministic (sorted) order so the resulting
	// call graph is reproducible across runs. Go map iteration is randomized;
	// without sorting, overload resolution and contract-name collisions would
	// land on different functions every invocation.
	paths := make([]string, 0, len(cgb.db.SourceFiles))
	for path := range cgb.db.SourceFiles {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		sf := cgb.db.SourceFiles[path]
		cgb.currentFile = sf
		if err := cgb.analyzeFile(sf); err != nil {
			// Surface the failure via verbose so silent skips don't hide a real bug.
			cgb.logf("call-graph analysis failed for %s: %v (skipping)", path, err)
			continue
		}
	}

	return nil
}

// analyzeFile analyzes function bodies for calls. It reuses the AST parsed in
// the build's Phase 1 (stashed on SourceFile.AST) and only re-parses if that
// cache is absent (e.g. a database reloaded from JSON, where AST is not stored).
func (cgb *CallGraphBuilder) analyzeFile(sf *types.SourceFile) error {
	cgb.locator = cgb.locators[sf.Path]
	if cgb.locator == nil {
		cgb.locator = newSourceLocator(sf, cgb.db)
		cgb.locators[sf.Path] = cgb.locator
	}
	result, ok := sf.AST.(*ast.SourceUnit)
	if !ok || result == nil {
		parsed, err := parser.Parse(normalizeYulAssignmentsForParser(sf.Content), &parser.Options{
			Tolerant: true,
			Loc:      true,
			Range:    true,
		})
		if err != nil {
			return err
		}
		result = parsed
	}

	// Visit all contracts and functions
	for _, child := range result.Children {
		if contract, ok := child.(*ast.ContractDefinition); ok {
			cgb.analyzeContract(contract)
		}
	}

	return nil
}

// analyzeContract analyzes a contract's functions and modifier bodies.
func (cgb *CallGraphBuilder) analyzeContract(contract *ast.ContractDefinition) {
	if contract == nil || cgb.currentFile == nil {
		return
	}
	contractID := types.MakeContractID(cgb.currentFile.Path, contract.Name)
	cgb.currentContract = cgb.db.GetContractByID(contractID)
	if cgb.currentContract == nil {
		cgb.addIdentityDiagnostic(contract.Name, cgb.locator.span(contract).startLine,
			"AST contract could not be matched to its exact database identity")
		return
	}

	for _, subNode := range contract.SubNodes {
		switch n := subNode.(type) {
		case *ast.FunctionDefinition:
			cgb.analyzeFunction(n)
		case *ast.ModifierDefinition:
			// Calls inside modifier bodies (e.g. `modifier g { _check(); _; }`)
			// were never walked, so Modifier.Calls stayed empty and auth helpers
			// invoked from modifiers were invisible to the call graph.
			cgb.analyzeModifierDefinition(n)
		}
	}
	cgb.currentContract = nil
}

// analyzeModifierDefinition walks a modifier body, attaching discovered calls to
// the corresponding types.Modifier and emitting call-graph edges rooted at the
// modifier ID.
func (cgb *CallGraphBuilder) analyzeModifierDefinition(mod *ast.ModifierDefinition) {
	if mod == nil || mod.Body == nil {
		return
	}
	if cgb.currentContract == nil {
		return
	}
	var modObj *types.Modifier
	modLine := cgb.locator.span(mod).startLine
	for _, m := range cgb.currentContract.Modifiers {
		if m.Name == mod.Name && (modLine == 0 || m.StartLine == modLine) {
			modObj = m
			break
		}
	}
	if modObj == nil {
		cgb.addIdentityDiagnostic(mod.Name, modLine,
			"modifier AST could not be matched inside its exact contract")
		return
	}

	cgb.currentFunction = nil
	cgb.symbolTypes = make(map[string]types.TypeInfo)
	for _, sv := range cgb.currentContract.StateVariables {
		cgb.symbolTypes[sv.Name] = cgb.typeInfoFromTypeName(sv.TypeName, "state_var")
	}
	for _, param := range mod.Parameters {
		if param.Name != "" {
			cgb.symbolTypes[param.Name] = cgb.typeInfoFromTypeName(getTypeName(param.TypeName), "parameter")
		}
	}

	cgb.currentModifier = modObj
	cgb.analyzeBlock(mod.Body)
	cgb.currentModifier = nil
}

// analyzeFunction analyzes a function's body for calls
func (cgb *CallGraphBuilder) analyzeFunction(fn *ast.FunctionDefinition) {
	name := fn.Name
	if fn.IsConstructor {
		name = "constructor"
	} else if fn.IsReceiveEther {
		name = "receive"
	} else if fn.IsFallback {
		name = "fallback"
	}

	if cgb.currentContract == nil {
		return
	}
	// Find the function only inside the exact AST contract. Source line is the
	// stable bridge between the raw parser node and extracted object when names
	// are overloaded.
	cgb.currentFunction = nil
	cgb.currentModifier = nil
	cgb.symbolTypes = make(map[string]types.TypeInfo)
	for _, sv := range cgb.currentContract.StateVariables {
		cgb.symbolTypes[sv.Name] = cgb.typeInfoFromTypeName(sv.TypeName, "state_var")
	}
	// Tolerant error recovery can produce a definition without a location;
	// sourceLocator.span is nil-safe and keeps the match deterministic.
	fnSpan := cgb.locator.span(fn)
	cgb.currentFunction = cgb.functionObjectForAST(fn, name, fnSpan)
	if cgb.currentFunction == nil {
		cgb.addIdentityDiagnostic(name, fnSpan.startLine,
			"function AST could not be matched inside its exact contract")
		return
	}
	for _, param := range cgb.currentFunction.Parameters {
		if param.Name != "" {
			cgb.symbolTypes[param.Name] = cgb.typeInfoFromTypeName(param.TypeName, "parameter")
		}
	}

	// Analyze function body
	if fn.Body != nil {
		cgb.analyzeBlock(fn.Body)
	}

	// Analyze modifiers applied to this function
	cgb.analyzeModifiers(fn.Modifiers)
	cgb.currentFunction = nil
}

func (cgb *CallGraphBuilder) functionObjectForAST(raw *ast.FunctionDefinition, name string, span sourceSpan) *types.Function {
	if raw == nil || cgb.currentContract == nil {
		return nil
	}

	// Exact byte ranges uniquely identify declarations even when several
	// overloads are written on one physical line.
	if span.startByte > 0 || span.endByte > 0 {
		for _, fn := range cgb.currentContract.Functions {
			if fn.StartByte == span.startByte && fn.EndByte == span.endByte {
				return fn
			}
		}
	}

	// Legacy/location-less fallback: match the complete raw parameter type list,
	// never just name+line or name+arity.
	var matched *types.Function
	for _, fn := range cgb.currentContract.Functions {
		if fn.Name != name || len(fn.Parameters) != len(raw.Parameters) {
			continue
		}
		exact := true
		for i, parameter := range raw.Parameters {
			if comparableType(fn.Parameters[i].TypeName) != comparableType(getTypeName(parameter.TypeName)) {
				exact = false
				break
			}
		}
		if !exact || matched != nil {
			if exact {
				return nil
			}
			continue
		}
		matched = fn
	}
	return matched
}

// analyzeBlock analyzes a block of statements
func (cgb *CallGraphBuilder) analyzeBlock(block *ast.Block) {
	if block == nil {
		return
	}
	for _, stmt := range block.Statements {
		cgb.analyzeNode(stmt)
	}
}

// analyzeNode recursively analyzes AST nodes for function calls
func (cgb *CallGraphBuilder) analyzeNode(node ast.Node) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.Block:
		cgb.analyzeBlock(n)

	case *ast.UncheckedBlock:
		// Calls inside `unchecked { ... }` (pervasive in Solidity >=0.8) were
		// previously dropped from the call graph entirely.
		cgb.analyzeBlock(n.Body)

	case *ast.ExpressionStatement:
		cgb.analyzeNode(n.Expression)

	case *ast.IfStatement:
		cgb.analyzeNode(n.Condition)
		cgb.analyzeNode(n.TrueBody)
		cgb.analyzeNode(n.FalseBody)

	case *ast.WhileStatement:
		cgb.analyzeNode(n.Condition)
		cgb.analyzeNode(n.Body)

	case *ast.DoWhileStatement:
		cgb.analyzeNode(n.Condition)
		cgb.analyzeNode(n.Body)

	case *ast.ForStatement:
		cgb.analyzeNode(n.InitExpression)
		cgb.analyzeNode(n.ConditionExpression)
		cgb.analyzeNode(n.LoopExpression)
		cgb.analyzeNode(n.Body)

	case *ast.ReturnStatement:
		cgb.analyzeNode(n.Expression)

	case *ast.EmitStatement:
		// Calls embedded in event arguments, e.g. emit E(f()).
		cgb.analyzeNode(n.EventCall)

	case *ast.RevertStatement:
		// Calls embedded in custom-error arguments, e.g. revert E(f()).
		cgb.analyzeNode(n.RevertCall)

	case *ast.VariableDeclarationStatement:
		cgb.analyzeVariableDeclaration(n)

	case *ast.TryStatement:
		cgb.analyzeTryStatement(n)

	case *ast.FunctionCall:
		cgb.analyzeCallAndArguments(n)

	case *ast.MemberAccess:
		cgb.analyzeNode(n.Expression)

	case *ast.BinaryOperation:
		cgb.analyzeBinaryOperation(n)

	case *ast.UnaryOperation:
		cgb.analyzeNode(n.SubExpression)

	case *ast.Conditional:
		cgb.analyzeNode(n.Condition)
		cgb.analyzeNode(n.TrueExpression)
		cgb.analyzeNode(n.FalseExpression)

	case *ast.IndexAccess:
		cgb.analyzeNode(n.Base)
		cgb.analyzeNode(n.Index)

	case *ast.TupleExpression:
		cgb.analyzeTupleExpression(n)

	case *ast.FunctionCallOptions:
		cgb.analyzeFunctionCallOptions(n)
	}
}

func (cgb *CallGraphBuilder) analyzeVariableDeclaration(stmt *ast.VariableDeclarationStatement) {
	for _, decl := range stmt.Variables {
		if decl == nil || decl.Name == "" {
			continue
		}
		typeInfo := cgb.typeInfoFromTypeName(getTypeName(decl.TypeName), "local_var")
		if !typeInfo.IsKnown() && stmt.InitialValue != nil {
			typeInfo = cgb.expressionType(stmt.InitialValue)
		}
		if typeInfo.IsKnown() {
			cgb.symbolTypes[decl.Name] = typeInfo
		}
	}
	cgb.analyzeNode(stmt.InitialValue)
}

func (cgb *CallGraphBuilder) analyzeTryStatement(stmt *ast.TryStatement) {
	cgb.analyzeNode(stmt.Expression)
	// The success body and every catch body are distinct call-bearing regions.
	if stmt.Body != nil {
		cgb.analyzeBlock(stmt.Body)
	}
	for _, clause := range stmt.CatchClauses {
		if clause.Body != nil {
			cgb.analyzeBlock(clause.Body)
		}
	}
}

func (cgb *CallGraphBuilder) analyzeCallAndArguments(call *ast.FunctionCall) {
	cgb.analyzeFunctionCall(call)
	for _, arg := range call.Arguments {
		cgb.analyzeNode(arg)
	}
}

func (cgb *CallGraphBuilder) analyzeBinaryOperation(operation *ast.BinaryOperation) {
	if isAssignmentOperator(operation.Operator) {
		if identifier, ok := operation.Left.(*ast.Identifier); ok {
			if typeInfo := cgb.expressionType(operation.Right); typeInfo.IsKnown() {
				cgb.symbolTypes[identifier.Name] = typeInfo
			}
		}
	}
	cgb.analyzeNode(operation.Left)
	cgb.analyzeNode(operation.Right)
}

func (cgb *CallGraphBuilder) analyzeTupleExpression(tuple *ast.TupleExpression) {
	for _, component := range tuple.Components {
		cgb.analyzeNode(component)
	}
}

func (cgb *CallGraphBuilder) analyzeFunctionCallOptions(options *ast.FunctionCallOptions) {
	// Handle calls with options like to.call{value: ...}("").
	cgb.analyzeNode(options.Expression)
	for _, option := range options.Options {
		cgb.analyzeNode(option)
	}
}

// analyzeFunctionCall processes a function call and adds it to the call graph
func (cgb *CallGraphBuilder) analyzeFunctionCall(call *ast.FunctionCall) {
	if call == nil || cgb.currentContract == nil || cgb.currentFile == nil {
		return
	}
	descriptor, ok := cgb.classifyFunctionCall(call)
	if !ok {
		return
	}
	span := cgb.locator.span(call)
	line, col, byteOff := span.startLine, span.startCol, span.startByte
	argCount := len(call.Arguments)
	target := cgb.resolveTarget(descriptor.calledName, descriptor.targetContract, descriptor.callType, call.Arguments, descriptor.libraryExtension, descriptor.receiverType)
	if descriptor.identityRequired && descriptor.targetContract == nil {
		cgb.addTargetIdentityDiagnostic(descriptor.targetContractName, descriptor.calledName, line)
	}

	to := descriptor.calledName
	resolvedFunction := ""
	if target.function != nil {
		resolvedFunction = functionKey(target.function)
	}
	if target.contract != nil {
		key := descriptor.calledName
		if target.function != nil {
			key = functionKey(target.function)
		}
		to = types.MakeFunctionID(target.contract.SourceFile, target.contract.Name, key)
	}
	from := cgb.currentCallerID()
	if from == "" {
		cgb.addIdentityDiagnostic(descriptor.calledName, line, "call site has no exact caller identity")
		return
	}

	edge := &types.CallEdge{
		From:             from,
		To:               to,
		CalledName:       descriptor.calledName,
		Type:             descriptor.callType,
		Line:             line,
		Col:              col,
		Byte:             byteOff,
		Resolved:         target.resolved,
		ResolvedFunction: resolvedFunction,
		TargetKind:       target.kind,
	}
	if target.contract != nil {
		edge.ResolvedContract = target.contract.Name
		edge.ResolvedContractID = target.contract.ID
	}
	cgb.db.CallGraph.AddEdge(edge)
	cgb.addCallToCurrent(descriptor.calledName, descriptor.targetContractName, target, resolvedFunction, descriptor.callType, line, col, byteOff, argCount)
}

type functionCallDescriptor struct {
	callType           types.CallType
	calledName         string
	targetContractName string
	targetContract     *types.Contract
	identityRequired   bool
	libraryExtension   bool
	receiverType       types.TypeInfo
}

func (cgb *CallGraphBuilder) classifyFunctionCall(call *ast.FunctionCall) (functionCallDescriptor, bool) {
	descriptor := functionCallDescriptor{callType: types.CallTypeInternal}
	switch expression := call.Expression.(type) {
	case *ast.Identifier:
		return cgb.classifyIdentifierCall(call, expression, descriptor)
	case *ast.MemberAccess:
		return cgb.classifyMemberCall(call, expression, descriptor)
	case *ast.FunctionCallOptions:
		return cgb.classifyCallWithOptions(expression, descriptor)
	case *ast.NewExpression:
		descriptor.calledName = getTypeName(expression.TypeName)
		descriptor.callType = types.CallTypeExternal
		descriptor.targetContractName = descriptor.calledName
		descriptor.targetContract, _ = cgb.db.ResolveContractNameExact(descriptor.calledName, cgb.currentFile.Path)
		descriptor.identityRequired = true
		return descriptor, descriptor.calledName != ""
	default:
		return descriptor, false
	}
}

func (cgb *CallGraphBuilder) classifyIdentifierCall(call *ast.FunctionCall, identifier *ast.Identifier, descriptor functionCallDescriptor) (functionCallDescriptor, bool) {
	descriptor.calledName = identifier.Name
	// Primitive/user-defined type conversions are expressions, not call edges.
	if isBuiltinFunction(descriptor.calledName) {
		return descriptor, false
	}
	if candidates := cgb.db.FindContractsByName(descriptor.calledName); len(candidates) > 0 {
		if _, exact := cgb.db.ResolveContractNameExact(descriptor.calledName, cgb.currentFile.Path); !exact {
			cgb.addTargetIdentityDiagnostic(descriptor.calledName, descriptor.calledName, cgb.locator.span(call).startLine)
		}
		return descriptor, false
	}
	descriptor.targetContractName = cgb.currentContract.Name
	descriptor.targetContract = cgb.currentContract
	return descriptor, true
}

func (cgb *CallGraphBuilder) classifyMemberCall(call *ast.FunctionCall, member *ast.MemberAccess, descriptor functionCallDescriptor) (functionCallDescriptor, bool) {
	descriptor.calledName = member.MemberName
	descriptor.receiverType = cgb.expressionType(member.Expression)
	switch receiver := member.Expression.(type) {
	case *ast.Identifier:
		if receiver.Name == "abi" || receiver.Name == "msg" {
			return descriptor, false
		}
		descriptor = cgb.classifyIdentifierReceiver(receiver.Name, descriptor)
	case *ast.FunctionCall:
		descriptor = cgb.classifyCallReceiver(receiver, descriptor)
	}
	if descriptor.targetContract == nil && !descriptor.identityRequired {
		descriptor = cgb.classifyLibraryExtension(call, descriptor)
	}
	descriptor.callType = cgb.checkLowLevelCall(descriptor.calledName, descriptor.callType)
	return descriptor, true
}

func (cgb *CallGraphBuilder) classifyIdentifierReceiver(name string, descriptor functionCallDescriptor) functionCallDescriptor {
	switch name {
	case "this":
		descriptor.callType = types.CallTypeSelf
		descriptor.targetContractName, descriptor.targetContract = cgb.currentContract.Name, cgb.currentContract
		return descriptor
	case "super":
		descriptor.callType = types.CallTypeSuper
		descriptor.targetContractName, descriptor.targetContract = cgb.currentContract.Name, cgb.currentContract
		return descriptor
	}

	if typed := cgb.contractFromType(descriptor.receiverType); typed != nil {
		descriptor.targetContract = typed
		descriptor.targetContractName = typed.Name
		descriptor.identityRequired = true
	} else if len(cgb.db.FindContractsByName(name)) > 0 {
		descriptor.targetContractName = name
		descriptor.targetContract, _ = cgb.db.ResolveContractNameExact(name, cgb.currentFile.Path)
		descriptor.identityRequired = true
	}

	switch {
	case descriptor.targetContract != nil:
		if descriptor.targetContract.Kind == types.ContractKindLibrary {
			descriptor.callType = types.CallTypeLibrary
		} else {
			descriptor.callType = types.CallTypeExternal
		}
	case descriptor.receiverType.IsPrimitiveAddress() && isETHTransferName(descriptor.calledName):
		descriptor.callType = types.CallTypeTransferETH
		descriptor.targetContractName = name
	case descriptor.receiverType.IsKnown() && descriptor.receiverType.Kind != types.TypeKindPrimitive && descriptor.receiverType.BaseName != "":
		descriptor.targetContractName = descriptor.receiverType.BaseName
		descriptor.identityRequired = true
		if descriptor.receiverType.Kind == types.TypeKindLibrary {
			descriptor.callType = types.CallTypeLibrary
		} else {
			descriptor.callType = types.CallTypeExternal
		}
	default:
		descriptor.callType = types.CallTypeExternal
		descriptor.targetContractName = name
	}
	return descriptor
}

func (cgb *CallGraphBuilder) classifyCallReceiver(call *ast.FunctionCall, descriptor functionCallDescriptor) functionCallDescriptor {
	castType := cgb.expressionType(call)
	switch {
	case castType.IsPrimitiveAddress() && isETHTransferName(descriptor.calledName):
		descriptor.callType = types.CallTypeTransferETH
	case castType.BaseName != "":
		descriptor.callType = types.CallTypeExternal
		descriptor.targetContractName = castType.BaseName
		descriptor.targetContract = cgb.contractFromType(castType)
		descriptor.identityRequired = true
	default:
		if identifier, ok := call.Expression.(*ast.Identifier); ok {
			descriptor.callType = types.CallTypeExternal
			descriptor.targetContractName = identifier.Name
			descriptor.targetContract, _ = cgb.db.ResolveContractNameExact(identifier.Name, cgb.currentFile.Path)
			descriptor.identityRequired = true
		}
	}
	return descriptor
}

func (cgb *CallGraphBuilder) classifyLibraryExtension(call *ast.FunctionCall, descriptor functionCallDescriptor) functionCallDescriptor {
	library := cgb.resolveLibraryCall(descriptor.calledName, descriptor.receiverType, len(call.Arguments))
	switch {
	case library.contract != nil:
		descriptor.callType = types.CallTypeLibrary
		descriptor.targetContractName, descriptor.targetContract = library.contract.Name, library.contract
		descriptor.identityRequired = true
		descriptor.libraryExtension = true
	case library.identityAmbiguous != "":
		descriptor.callType = types.CallTypeLibrary
		descriptor.targetContractName = library.identityAmbiguous
		descriptor.identityRequired = true
		descriptor.libraryExtension = true
	case library.ambiguous:
		descriptor.callType = types.CallTypeLibrary
		descriptor.libraryExtension = true
	}
	return descriptor
}

func (cgb *CallGraphBuilder) classifyCallWithOptions(options *ast.FunctionCallOptions, descriptor functionCallDescriptor) (functionCallDescriptor, bool) {
	member, ok := options.Expression.(*ast.MemberAccess)
	if !ok {
		return descriptor, false
	}
	descriptor.calledName = member.MemberName
	descriptor.callType = cgb.getLowLevelCallType(descriptor.calledName)
	if identifier, ok := member.Expression.(*ast.Identifier); ok {
		descriptor.targetContractName = identifier.Name
	}
	return descriptor, true
}

func isETHTransferName(name string) bool {
	return name == "transfer" || name == "send"
}

type resolvedTarget struct {
	contract *types.Contract
	function *types.Function
	kind     types.ContractKind
	resolved bool
}

// superSite is a single `super.g()` call discovered during call-graph building:
// the function that hosts it, the called member name, and its argument count.
type superSite struct {
	contract   *types.Contract
	fn         *types.Function
	calledName string
	selector   string
	argCount   int
	line       int
	col        int
	byteOff    int
}

// ResolveSuperAcrossLeaves makes `super` resolution context-aware.
//
// `super` in Solidity is resolved against the C3 linearization of the
// MOST-DERIVED contract being instantiated, not the contract where the call
// textually appears. The per-call resolution in resolveTarget only knows the
// textual contract's own MRO, so for a cooperative diamond it records the
// standalone target (e.g. StepB.step -> Root.step) and misses the in-leaf target
// (StepB.step -> StepA.step when StepB runs as part of Full).
//
// This post-pass walks every contract's MRO as a potential instantiation leaf
// and, for each `super` call site hosted by a contract in that MRO, adds an edge
// to the next contract in THAT leaf's MRO that defines the called function. It is
// additive (existing standalone edges are kept) and deduplicated, so the result
// is the SOUND UNION of super targets over every instantiation context. Without
// it, a function reached only through an intermediate contract's super call would
// look unreachable from a derived leaf's entry point (a reachability
// false-negative).
//
// Must run after Build() so all super edges and per-function Calls already exist.
func (cgb *CallGraphBuilder) ResolveSuperAcrossLeaves() {
	// 1. Collect every super call site from per-function Calls (which carry the
	//    arg count that the bare call edges do not). Deterministic order: sorted
	//    contract IDs, then declaration order of functions and calls.
	contractIDs := make([]string, 0, len(cgb.db.Contracts))
	for id := range cgb.db.Contracts {
		contractIDs = append(contractIDs, id)
	}
	sort.Strings(contractIDs)

	var sites []superSite
	for _, id := range contractIDs {
		c := cgb.db.Contracts[id]
		for _, fn := range c.Functions {
			for _, call := range fn.Calls {
				if call.CallType == types.CallTypeSuper {
					sites = append(sites, superSite{
						contract:   c,
						fn:         fn,
						calledName: call.Target,
						selector:   call.ResolvedFunction,
						argCount:   call.ArgCount,
						line:       call.Line,
						col:        call.Col,
						byteOff:    call.Byte,
					})
				}
			}
		}
	}
	if len(sites) == 0 {
		return
	}

	// 2. Index existing super edges so we only ADD genuinely new (From,To) pairs.
	cgb.db.CallGraph.EnsureIndex()
	existing := make(map[string]bool)
	for _, e := range cgb.db.CallGraph.Edges {
		if e.Type == types.CallTypeSuper {
			existing[e.From+"\x00"+e.To] = true
		}
	}

	// 3. For each contract treated as an instantiation leaf, walk its MRO and bind
	//    each hosted super site to the next defining contract in that MRO.
	for _, leafID := range contractIDs {
		leaf := cgb.db.Contracts[leafID]
		mro := cgb.db.LinearizedContracts(leaf)
		if len(mro) < 2 {
			continue
		}
		// Position of each exact MRO identity for O(1) host lookup.
		pos := make(map[string]int, len(mro))
		for i, contract := range mro {
			if _, ok := pos[contract.ID]; !ok {
				pos[contract.ID] = i
			}
		}

		for _, site := range sites {
			i, ok := pos[site.contract.ID]
			if !ok {
				continue // this site's host is not part of this leaf's hierarchy
			}
			target, targetContract := cgb.nextDefInMRO(mro, i+1, site.calledName, site.selector, site.argCount)
			if target == nil {
				continue
			}

			fromSelector := site.fn.Selector
			if fromSelector == "" {
				fromSelector = site.fn.Name
			}
			toSelector := target.Selector
			if toSelector == "" {
				toSelector = target.Name
			}
			from := types.MakeFunctionID(site.contract.SourceFile, site.contract.Name, fromSelector)
			to := types.MakeFunctionID(targetContract.SourceFile, targetContract.Name, toSelector)

			key := from + "\x00" + to
			if existing[key] {
				continue
			}
			existing[key] = true

			cgb.db.CallGraph.AddEdge(&types.CallEdge{
				From:               from,
				To:                 to,
				CalledName:         site.calledName,
				Type:               types.CallTypeSuper,
				Line:               site.line,
				Col:                site.col,
				Byte:               site.byteOff,
				Resolved:           true,
				ResolvedContract:   targetContract.Name,
				ResolvedContractID: targetContract.ID,
				ResolvedFunction:   toSelector,
				TargetKind:         targetContract.Kind,
			})
			// Mirror onto the host function's Calls so AST/reachability consumers
			// that read fn.Calls see the in-leaf target too (deduped above).
			site.fn.Calls = append(site.fn.Calls, &types.FunctionCall{
				Target:             site.calledName,
				ContractName:       targetContract.Name,
				ResolvedContract:   targetContract.Name,
				ResolvedContractID: targetContract.ID,
				ResolvedFunction:   toSelector,
				CallType:           types.CallTypeSuper,
				TargetKind:         targetContract.Kind,
				Line:               site.line,
				Col:                site.col,
				Byte:               site.byteOff,
				Resolved:           true,
				ArgCount:           site.argCount,
			})
		}
	}
}

// nextDefInMRO returns the first contract at or after index `start` in the MRO
// that defines a function named funcName, preferring an exact arity match
// (argCount >= 0) and falling back to name-only. Returns the function and its
// owning contract, or (nil, nil) when no base in the remaining MRO defines it.
func (cgb *CallGraphBuilder) nextDefInMRO(mro []*types.Contract, start int, funcName, selector string, argCount int) (*types.Function, *types.Contract) {
	for j := start; j < len(mro); j++ {
		base := mro[j]
		if base == nil {
			continue
		}
		if selector != "" {
			for _, fn := range base.Functions {
				if functionKey(fn) == selector {
					return fn, base
				}
			}
			continue
		}
		var matches []*types.Function
		for _, fn := range base.Functions {
			if fn.Name == funcName && (argCount < 0 || len(fn.Parameters) == argCount) {
				matches = append(matches, fn)
			}
		}
		if len(matches) == 1 {
			return matches[0], base
		}
		if len(matches) > 1 {
			return nil, nil
		}
	}
	return nil, nil
}

// checkLowLevelCall checks if the call is a low-level call and returns appropriate type
func (cgb *CallGraphBuilder) checkLowLevelCall(memberName string, currentType types.CallType) types.CallType {
	switch memberName {
	case "call":
		return types.CallTypeLowLevelCall
	case "delegatecall":
		return types.CallTypeLowLevelDelegate
	case "staticcall":
		return types.CallTypeLowLevelStatic
	}
	return currentType
}

// getLowLevelCallType returns the specific low-level call type
func (cgb *CallGraphBuilder) getLowLevelCallType(memberName string) types.CallType {
	switch memberName {
	case "call":
		return types.CallTypeLowLevelCall
	case "delegatecall":
		return types.CallTypeLowLevelDelegate
	case "staticcall":
		return types.CallTypeLowLevelStatic
	default:
		return types.CallTypeLowLevel
	}
}

// resolveLibraryCall checks if a call on a variable is actually a library call
// via a `using` directive. Receiver type facts handle direct typed receivers;
// this fallback still checks whether a matching function exists in any active
// using-library because `using X for *` and extension-style calls can be broader
// than a single receiver type.
type libraryResolution struct {
	contract          *types.Contract
	identityAmbiguous string
	ambiguous         bool
}

func (cgb *CallGraphBuilder) resolveLibraryCall(funcName string, receiverType types.TypeInfo, argCount int) libraryResolution {
	if cgb.currentContract == nil {
		return libraryResolution{}
	}
	matched := make(map[string]*types.Contract)
	for _, scope := range cgb.db.LinearizedContracts(cgb.currentContract) {
		for _, directive := range scope.UsingDirectives {
			if !usingDirectiveMatches(directive.ForType, receiverType) {
				continue
			}
			library, exact := cgb.db.ResolveContractNameExact(directive.Library, scope.SourceFile)
			if !exact {
				for _, candidate := range cgb.db.FindContractsByName(directive.Library) {
					if libraryHasExtensionCandidate(candidate, funcName, receiverType, argCount) {
						return libraryResolution{identityAmbiguous: directive.Library}
					}
				}
				continue
			}
			if libraryHasExtensionCandidate(library, funcName, receiverType, argCount) {
				matched[library.ID] = library
			}
		}
	}
	if len(matched) == 1 {
		for _, library := range matched {
			return libraryResolution{contract: library}
		}
	}
	return libraryResolution{ambiguous: len(matched) > 1}
}

func usingDirectiveMatches(forType string, receiverType types.TypeInfo) bool {
	forType = comparableType(forType)
	if forType == "" || forType == "*" {
		return true
	}
	return receiverType.IsKnown() && typeInfoMatchesParameter(receiverType, forType)
}

func libraryHasExtensionCandidate(library *types.Contract, funcName string, receiverType types.TypeInfo, argCount int) bool {
	if library == nil || library.Kind != types.ContractKindLibrary {
		return false
	}
	for _, fn := range library.Functions {
		if fn.Name != funcName || len(fn.Parameters) != argCount+1 {
			continue
		}
		if !receiverType.IsKnown() || typeInfoMatchesParameter(receiverType, fn.Parameters[0].TypeName) {
			return true
		}
	}
	return false
}

// resolveTarget resolves the actual target contract and function using inheritance.
// Argument types are used when known. Same-arity overloads remain unresolved
// when the lightweight semantic layer cannot select one exact selector.
func (cgb *CallGraphBuilder) resolveTarget(funcName string, targetContract *types.Contract, callType types.CallType, args []ast.Node, libraryExtension bool, receiverType types.TypeInfo) resolvedTarget {
	if targetContract == nil || callType == types.CallTypeTransferETH ||
		callType == types.CallTypeLowLevel || callType == types.CallTypeLowLevelCall ||
		callType == types.CallTypeLowLevelDelegate || callType == types.CallTypeLowLevelStatic {
		return resolvedTarget{contract: targetContract}
	}

	result := resolvedTarget{contract: targetContract, kind: targetContract.Kind}
	mro := cgb.db.LinearizedContracts(targetContract)
	if callType == types.CallTypeLibrary {
		mro = []*types.Contract{targetContract}
	} else if callType == types.CallTypeSuper && len(mro) > 0 {
		mro = mro[1:]
	}
	lookupName := funcName
	if funcName == targetContract.Name {
		lookupName = "constructor"
	}

	seenSelectors := make(map[string]bool)
	var named []callCandidate
	for _, contract := range mro {
		for _, fn := range contract.Functions {
			if fn.Name != lookupName {
				continue
			}
			key := functionOverloadKey(fn)
			if seenSelectors[key] {
				continue // most-derived implementation already won this selector
			}
			seenSelectors[key] = true
			offset := 0
			if libraryExtension {
				offset = 1
			}
			named = append(named, callCandidate{contract: contract, function: fn, parameterOffset: offset})
		}
	}
	if len(named) == 0 {
		return result
	}

	arity := make([]callCandidate, 0, len(named))
	for _, candidate := range named {
		if len(candidate.function.Parameters)-candidate.parameterOffset == len(args) {
			arity = append(arity, candidate)
		}
	}
	if len(arity) == 1 {
		return resolvedCallTarget(arity[0])
	}
	if len(arity) > 1 {
		compatible := make([]callCandidate, 0, len(arity))
		for _, candidate := range arity {
			if cgb.argumentsMatch(candidate, args, receiverType) {
				compatible = append(compatible, candidate)
			}
		}
		if len(compatible) == 1 {
			return resolvedCallTarget(compatible[0])
		}
		return result
	}
	if len(named) == 1 {
		// Compatibility fallback for malformed/tolerantly-parsed code where the
		// call arity is unavailable or inconsistent but only one target exists.
		return resolvedCallTarget(named[0])
	}
	return result
}

type callCandidate struct {
	contract        *types.Contract
	function        *types.Function
	parameterOffset int
}

func resolvedCallTarget(candidate callCandidate) resolvedTarget {
	return resolvedTarget{
		contract: candidate.contract,
		function: candidate.function,
		kind:     candidate.contract.Kind,
		resolved: true,
	}
}

func (cgb *CallGraphBuilder) argumentsMatch(candidate callCandidate, args []ast.Node, receiverType types.TypeInfo) bool {
	if candidate.parameterOffset == 1 {
		if !receiverType.IsKnown() || !typeInfoMatchesParameter(receiverType, candidate.function.Parameters[0].TypeName) {
			return false
		}
	}
	for i, arg := range args {
		info := cgb.expressionType(arg)
		if !info.IsKnown() || !typeInfoMatchesParameter(info, candidate.function.Parameters[i+candidate.parameterOffset].TypeName) {
			return false
		}
	}
	return true
}

func typeInfoMatchesParameter(info types.TypeInfo, parameterType string) bool {
	want := comparableType(parameterType)
	return comparableType(info.Name) == want || comparableType(info.BaseName) == want
}

func functionOverloadKey(fn *types.Function) string {
	if fn.Selector != "" {
		return fn.Selector
	}
	params := make([]string, len(fn.Parameters))
	for i, parameter := range fn.Parameters {
		params[i] = comparableType(parameter.TypeName)
	}
	return fn.Name + "(" + strings.Join(params, ",") + ")"
}

func comparableType(typeName string) string {
	clean := types.CleanTypeName(typeName)
	clean = strings.Join(strings.Fields(clean), " ")
	switch clean {
	case "uint":
		return "uint256"
	case "int":
		return "int256"
	case "byte":
		return "bytes1"
	case "address payable":
		return "address"
	default:
		return clean
	}
}

func (cgb *CallGraphBuilder) addCallToCurrent(targetName, targetContractName string, target resolvedTarget, resolvedFunction string, callType types.CallType, line, col, byteOff, argCount int) {
	call := &types.FunctionCall{
		Target:           targetName,
		ContractName:     targetContractName,
		ResolvedFunction: resolvedFunction,
		CallType:         callType,
		TargetKind:       target.kind,
		Line:             line,
		Col:              col,
		Byte:             byteOff,
		Resolved:         target.resolved,
		ArgCount:         argCount,
	}
	if target.contract != nil {
		call.ResolvedContract = target.contract.Name
		call.ResolvedContractID = target.contract.ID
	}
	if cgb.currentModifier != nil {
		cgb.currentModifier.Calls = append(cgb.currentModifier.Calls, call)
	} else if cgb.currentFunction != nil {
		cgb.currentFunction.Calls = append(cgb.currentFunction.Calls, call)
	}
}

func (cgb *CallGraphBuilder) currentCallerID() string {
	if cgb.currentContract == nil || cgb.currentFile == nil {
		return ""
	}
	if cgb.currentModifier != nil {
		return types.MakeModifierID(cgb.currentFile.Path, cgb.currentContract.Name, cgb.currentModifier.Name)
	}
	if cgb.currentFunction != nil {
		return types.MakeFunctionID(cgb.currentFile.Path, cgb.currentContract.Name, functionKey(cgb.currentFunction))
	}
	return ""
}

func functionKey(fn *types.Function) string {
	if fn == nil {
		return ""
	}
	if fn.Selector != "" {
		return fn.Selector
	}
	return fn.Name
}

func (cgb *CallGraphBuilder) contractFromType(typeInfo types.TypeInfo) *types.Contract {
	if cgb == nil || cgb.db == nil {
		return nil
	}
	if typeInfo.ContractID != "" {
		return cgb.db.GetContractByID(typeInfo.ContractID)
	}
	if typeInfo.BaseName != "" && cgb.currentFile != nil {
		contract, _ := cgb.db.ResolveContractNameExact(typeInfo.BaseName, cgb.currentFile.Path)
		return contract
	}
	return nil
}

func (cgb *CallGraphBuilder) addTargetIdentityDiagnostic(contractName, functionName string, line int) {
	if contractName == "" {
		contractName = functionName
	}
	message := "explicit call target contract could not be resolved"
	if len(cgb.db.FindContractsByName(contractName)) > 1 {
		message = "explicit call target contract is ambiguous in source scope"
	}
	cgb.addIdentityDiagnostic(contractName, line, message)
}

func (cgb *CallGraphBuilder) addIdentityDiagnostic(symbol string, line int, message string) {
	file := ""
	if cgb.currentFile != nil {
		file = cgb.currentFile.Path
	}
	cgb.db.AddDiagnostic(types.Diagnostic{
		Code:       types.DiagnosticIdentity,
		Severity:   types.DiagnosticWarning,
		Phase:      "builder",
		Message:    message,
		File:       file,
		Line:       line,
		Symbol:     symbol,
		Incomplete: true,
	})
}

// builtinFunctions is the set of Solidity built-in functions to exclude from callgraph
var builtinFunctions = map[string]bool{
	// Error handling
	"require": true,
	"assert":  true,
	"revert":  true,

	// Cryptographic functions
	"keccak256": true,
	"sha256":    true,
	"sha3":      true,
	"ripemd160": true,
	"ecrecover": true,
	"addmod":    true,
	"mulmod":    true,

	// ABI encoding/decoding
	"abi": true, // abi.encode, abi.decode, etc. are member accesses

	// Type conversion
	"bytes":   true,
	"string":  true,
	"address": true,
	"uint":    true,
	"uint8":   true,
	"uint16":  true,
	"uint32":  true,
	"uint64":  true,
	"uint128": true,
	"uint256": true,
	"int":     true,
	"int8":    true,
	"int16":   true,
	"int32":   true,
	"int64":   true,
	"int128":  true,
	"int256":  true,
	"bool":    true,
	"bytes1":  true,
	"bytes2":  true,
	"bytes4":  true,
	"bytes8":  true,
	"bytes16": true,
	"bytes32": true,

	// Block/Transaction properties (accessed as globals, but sometimes appear in AST)
	"blockhash": true,
	"gasleft":   true,

	// Selfdestruct
	"selfdestruct": true,
}

// isBuiltinFunction checks if a function name is a Solidity built-in
func isBuiltinFunction(name string) bool {
	return builtinFunctions[name]
}

// analyzeModifiers analyzes the modifiers applied to a function
func (cgb *CallGraphBuilder) analyzeModifiers(modifiers []*ast.ModifierInvocation) {
	if cgb.currentContract == nil || cgb.currentFunction == nil {
		return
	}
	for _, modInv := range modifiers {
		if modInv.Name == "" {
			continue
		}

		// Get line/column/byte-offset if available
		span := cgb.locator.span(modInv)
		line, col, byteOff := span.startLine, span.startCol, span.startByte

		resolvedContract, resolvedModifier := cgb.resolveModifier(modInv.Name)
		resolved := resolvedContract != nil && resolvedModifier != nil
		if !resolved {
			resolvedContract = cgb.baseConstructorContract(modInv.Name)
			if resolvedContract == nil {
				cgb.addIdentityDiagnostic(modInv.Name, line, "modifier target could not be resolved in the exact contract hierarchy")
			}
		}

		// Create the call target ID
		target := modInv.Name
		if resolved {
			target = types.MakeModifierID(resolvedContract.SourceFile, resolvedContract.Name, resolvedModifier.Name)
		}

		from := cgb.currentCallerID()

		// Add edge to call graph
		edge := &types.CallEdge{
			From:       from,
			To:         target,
			CalledName: modInv.Name,
			Type:       types.CallTypeModifier,
			Line:       line,
			Col:        col,
			Byte:       byteOff,
			Resolved:   resolved,
			TargetKind: types.ContractKindContract,
		}
		if resolvedContract != nil {
			edge.ResolvedContract = resolvedContract.Name
			edge.ResolvedContractID = resolvedContract.ID
		}
		if resolvedModifier != nil {
			edge.ResolvedFunction = resolvedModifier.Name
		}

		cgb.db.CallGraph.AddEdge(edge)

		call := &types.FunctionCall{
			Target:       modInv.Name,
			ContractName: cgb.currentContract.Name,
			CallType:     types.CallTypeModifier,
			TargetKind:   types.ContractKindContract,
			Line:         line,
			Col:          col,
			Byte:         byteOff,
			Resolved:     resolved,
		}
		if resolvedContract != nil {
			call.ResolvedContract = resolvedContract.Name
			call.ResolvedContractID = resolvedContract.ID
		}
		if resolvedModifier != nil {
			call.ResolvedFunction = resolvedModifier.Name
		}
		cgb.currentFunction.Calls = append(cgb.currentFunction.Calls, call)
	}
}

// resolveModifier resolves a modifier in the contract's inheritance chain
func (cgb *CallGraphBuilder) resolveModifier(modifierName string) (*types.Contract, *types.Modifier) {
	for _, contract := range cgb.db.LinearizedContracts(cgb.currentContract) {
		for _, modifier := range contract.Modifiers {
			if modifier.Name == modifierName {
				return contract, modifier
			}
		}
	}
	return nil, nil
}

func (cgb *CallGraphBuilder) baseConstructorContract(name string) *types.Contract {
	mro := cgb.db.LinearizedContracts(cgb.currentContract)
	for i := 1; i < len(mro); i++ {
		if mro[i].Name == name {
			return mro[i]
		}
	}
	return nil
}
