package builder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/solast-go/pkg/parser"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// CallGraphBuilder builds the call graph for the project
type CallGraphBuilder struct {
	db                 *types.Database
	currentContract    string
	currentFunction    string
	currentFunctionObj *types.Function
	// currentModifierObj is non-nil while analyzing a modifier body; in that
	// state, discovered calls are attached to the modifier's Calls slice and the
	// edge "From" is the modifier ID rather than a function ID.
	currentModifierObj *types.Modifier
	currentFile        string
	symbolTypes        map[string]types.TypeInfo
}

// NewCallGraphBuilder creates a new call graph builder
func NewCallGraphBuilder(db *types.Database) *CallGraphBuilder {
	return &CallGraphBuilder{
		db: db,
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
		cgb.currentFile = path
		if err := cgb.analyzeFile(sf); err != nil {
			// Surface the failure via verbose so silent skips don't hide a real bug.
			VerboseLog("call-graph analysis failed for %s: %v (skipping)", path, err)
			continue
		}
	}

	return nil
}

// analyzeFile analyzes function bodies for calls. It reuses the AST parsed in
// the build's Phase 1 (stashed on SourceFile.AST) and only re-parses if that
// cache is absent (e.g. a database reloaded from JSON, where AST is not stored).
func (cgb *CallGraphBuilder) analyzeFile(sf *types.SourceFile) error {
	result, ok := sf.AST.(*ast.SourceUnit)
	if !ok || result == nil {
		parsed, err := parser.Parse(sf.Content, &parser.Options{
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
	cgb.currentContract = contract.Name

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
}

// analyzeModifierDefinition walks a modifier body, attaching discovered calls to
// the corresponding types.Modifier and emitting call-graph edges rooted at the
// modifier ID.
func (cgb *CallGraphBuilder) analyzeModifierDefinition(mod *ast.ModifierDefinition) {
	if mod == nil || mod.Body == nil {
		return
	}
	contractObj := cgb.db.GetContractByName(cgb.currentContract)
	if contractObj == nil {
		return
	}
	var modObj *types.Modifier
	for _, m := range contractObj.Modifiers {
		if m.Name == mod.Name {
			modObj = m
			break
		}
	}
	if modObj == nil {
		return
	}

	cgb.currentFunctionObj = nil
	cgb.symbolTypes = make(map[string]types.TypeInfo)
	for _, sv := range contractObj.StateVariables {
		cgb.symbolTypes[sv.Name] = cgb.typeInfoFromTypeName(sv.TypeName, "state_var")
	}
	for _, param := range mod.Parameters {
		if param.Name != "" {
			cgb.symbolTypes[param.Name] = cgb.typeInfoFromTypeName(getTypeName(param.TypeName), "parameter")
		}
	}

	cgb.currentFunction = fmt.Sprintf("%s.%s", cgb.currentContract, mod.Name)
	cgb.currentModifierObj = modObj
	cgb.analyzeBlock(mod.Body)
	cgb.currentModifierObj = nil
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

	// Try to find the exact function implementation in the DB to use its selector
	selector := name
	contractObj := cgb.db.GetContractByName(cgb.currentContract)
	cgb.currentFunctionObj = nil
	cgb.symbolTypes = make(map[string]types.TypeInfo)
	if contractObj != nil {
		for _, sv := range contractObj.StateVariables {
			cgb.symbolTypes[sv.Name] = cgb.typeInfoFromTypeName(sv.TypeName, "state_var")
		}
		for _, f := range contractObj.Functions {
			if f.Name == name && f.StartLine == fn.Loc.Start.Line {
				cgb.currentFunctionObj = f
				if f.Selector != "" {
					selector = f.Selector
				}
				break
			}
		}
	}
	if cgb.currentFunctionObj != nil {
		for _, param := range cgb.currentFunctionObj.Parameters {
			if param.Name != "" {
				cgb.symbolTypes[param.Name] = cgb.typeInfoFromTypeName(param.TypeName, "parameter")
			}
		}
	}

	cgb.currentFunction = fmt.Sprintf("%s.%s", cgb.currentContract, selector)

	// Analyze function body
	if fn.Body != nil {
		cgb.analyzeBlock(fn.Body)
	}

	// Analyze modifiers applied to this function
	cgb.analyzeModifiers(fn.Modifiers)
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
		for _, decl := range n.Variables {
			if decl == nil || decl.Name == "" {
				continue
			}
			ti := cgb.typeInfoFromTypeName(getTypeName(decl.TypeName), "local_var")
			if !ti.IsKnown() && n.InitialValue != nil {
				ti = cgb.expressionType(n.InitialValue)
			}
			if ti.IsKnown() {
				cgb.symbolTypes[decl.Name] = ti
			}
		}
		cgb.analyzeNode(n.InitialValue)

	case *ast.TryStatement:
		cgb.analyzeNode(n.Expression)
		// Success body — previously dropped, so calls in the try body (the common
		// case, e.g. processing the call result) were invisible to the call graph.
		if n.Body != nil {
			cgb.analyzeBlock(n.Body)
		}
		for _, clause := range n.CatchClauses {
			if clause.Body != nil {
				cgb.analyzeBlock(clause.Body)
			}
		}

	case *ast.FunctionCall:
		cgb.analyzeFunctionCall(n)
		// Also analyze arguments
		for _, arg := range n.Arguments {
			cgb.analyzeNode(arg)
		}

	case *ast.MemberAccess:
		cgb.analyzeNode(n.Expression)

	case *ast.BinaryOperation:
		if isAssignmentOperator(n.Operator) {
			if id, ok := n.Left.(*ast.Identifier); ok {
				if ti := cgb.expressionType(n.Right); ti.IsKnown() {
					cgb.symbolTypes[id.Name] = ti
				}
			}
		}
		cgb.analyzeNode(n.Left)
		cgb.analyzeNode(n.Right)

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
		for _, comp := range n.Components {
			cgb.analyzeNode(comp)
		}

	case *ast.FunctionCallOptions:
		// Handle calls with options like to.call{value: ...}("")
		cgb.analyzeNode(n.Expression)
		for _, opt := range n.Options {
			cgb.analyzeNode(opt)
		}
	}
}

// analyzeFunctionCall processes a function call and adds it to the call graph
func (cgb *CallGraphBuilder) analyzeFunctionCall(call *ast.FunctionCall) {
	callType := types.CallTypeInternal
	calledName := ""
	targetContract := ""

	switch expr := call.Expression.(type) {
	case *ast.Identifier:
		// Simple internal call: _internalFunc()
		calledName = expr.Name

		// Skip built-in Solidity functions (require, assert, etc.)
		if isBuiltinFunction(calledName) {
			return
		}

		targetContract = cgb.currentContract
		callType = types.CallTypeInternal

	case *ast.MemberAccess:
		calledName = expr.MemberName
		isResolved := false
		receiverType := cgb.expressionType(expr.Expression)

		// Check for specific bases (Identifier)
		if inner, ok := expr.Expression.(*ast.Identifier); ok {
			name := inner.Name

			// Skip built-in objects
			if name == "abi" || name == "msg" {
				return
			}

			if name == "this" {
				// this.func()
				callType = types.CallTypeSelf
				targetContract = cgb.currentContract
				isResolved = true
			} else if name == "super" {
				// super.func()
				callType = types.CallTypeSuper
				targetContract = cgb.currentContract
				isResolved = true
			} else if cgb.isContract(name) {
				// Contract.func()
				callType = types.CallTypeExternal
				targetContract = name
				isResolved = true
			} else if cgb.isLibrary(name) {
				// Library.func()
				callType = types.CallTypeLibrary
				targetContract = name
				isResolved = true
			} else if receiverType.IsPrimitiveAddress() && (calledName == "transfer" || calledName == "send") {
				callType = types.CallTypeTransferETH
				targetContract = name
				isResolved = false
			} else if receiverType.IsKnown() && !receiverType.IsPrimitiveAddress() && receiverType.BaseName != "" {
				targetContract = receiverType.BaseName
				if receiverType.Kind == types.TypeKindLibrary {
					callType = types.CallTypeLibrary
				} else {
					callType = types.CallTypeExternal
				}
				isResolved = true
			} else {
				// Variable.func() - default to external, allow library check later
				// e.g. token.transfer()
				callType = types.CallTypeExternal
				targetContract = name
			}
		} else if callExpr, ok := expr.Expression.(*ast.FunctionCall); ok {
			// Cast: IERC20(addr).transfer()
			if castType := cgb.expressionType(callExpr); castType.IsKnown() && castType.BaseName != "" {
				if castType.IsPrimitiveAddress() && (calledName == "transfer" || calledName == "send") {
					callType = types.CallTypeTransferETH
					targetContract = ""
					isResolved = false
				} else {
					callType = types.CallTypeExternal
					targetContract = castType.BaseName
					isResolved = true
				}
			} else if id, ok := callExpr.Expression.(*ast.Identifier); ok {
				// We want the name of the function being called in that expression: "IERC20"
				callType = types.CallTypeExternal
				targetContract = id.Name
				isResolved = true // Treat cast as resolved target type
			}
		}

		// Check for Library "Using For" if not a direct library/contract call
		// This handles variable.add() (SafeMath) or _balances[to].add()
		if !isResolved {
			if libContract := cgb.resolveLibraryCall(calledName); libContract != nil {
				callType = types.CallTypeLibrary
				targetContract = libContract.Name
			}
		}

		// Check for low-level calls which override everything
		callType = cgb.checkLowLevelCall(calledName, callType)

	case *ast.FunctionCallOptions:
		// Handle calls with options like to.call{value: ...}("")
		// The Expression is typically a MemberAccess like "to.call"
		if ma, ok := expr.Expression.(*ast.MemberAccess); ok {
			calledName = ma.MemberName

			// Check for low-level calls
			if calledName == "call" || calledName == "delegatecall" || calledName == "staticcall" {
				callType = cgb.getLowLevelCallType(calledName)
				// Get the target (variable being called on)
				if id, ok := ma.Expression.(*ast.Identifier); ok {
					targetContract = id.Name
				}
			}
		}

	case *ast.NewExpression:
		// `new Contract(args)` — deploying runs the created contract's constructor
		// (untrusted code execution). Record an external creation edge so call-graph
		// consumers and reachability see it. resolveTarget will bind it to the
		// created contract's constructor when that contract is in scope.
		calledName = getTypeName(expr.TypeName)
		callType = types.CallTypeExternal
		targetContract = calledName
	}

	// Skip if we couldn't determine the target
	if calledName == "" {
		return
	}

	// Get line number
	line := 0
	if call.Loc != nil {
		line = call.Loc.Start.Line
	}

	// Resolve the actual target function and contract
	// Pass argument count so overloaded functions are disambiguated correctly
	argCount := len(call.Arguments)
	resolvedContract, resolvedFunc, targetKind, resolved := cgb.resolveTarget(
		calledName, targetContract, callType, argCount,
	)

	// Build "To" identifier
	to := calledName
	resolvedFuncName := ""
	if resolvedFunc != nil {
		resolvedFuncName = resolvedFunc.Selector
		if resolvedFuncName == "" {
			resolvedFuncName = resolvedFunc.Name
		}
	}

	if resolvedContract != "" {
		// Try to find the contract to get its source file
		if targetContractObj := cgb.db.GetContractByName(resolvedContract); targetContractObj != nil {
			// use resolvedFunc selector if available, otherwise calledName
			fnKey := calledName
			if resolvedFunc != nil && resolvedFunc.Selector != "" {
				fnKey = resolvedFunc.Selector
			} else if resolvedFunc != nil {
				fnKey = resolvedFunc.Name
			}
			to = types.MakeFunctionID(targetContractObj.SourceFile, resolvedContract, fnKey)
		} else {
			// Fallback if contract object not found
			to = fmt.Sprintf("%s.%s", resolvedContract, calledName)
		}
	}

	// Create the full "From" identifier with file path.
	// cgb.currentFunction is formatted as Contract.Selector (or Contract.modifier).
	parts := strings.SplitN(cgb.currentFunction, ".", 2)
	fromContract := parts[0]
	fromSelector := ""
	if len(parts) == 2 {
		fromSelector = parts[1] // Join via SplitN keeps dotted selectors intact
	}
	from := types.MakeFunctionID(cgb.currentFile, fromContract, fromSelector)
	if cgb.currentModifierObj != nil {
		from = types.MakeModifierID(cgb.currentFile, fromContract, cgb.currentModifierObj.Name)
	}

	// Add edge to call graph
	edge := &types.CallEdge{
		From:             from,
		To:               to,
		CalledName:       calledName,
		Type:             callType,
		Line:             line,
		Resolved:         resolved,
		ResolvedContract: resolvedContract,
		ResolvedFunction: resolvedFuncName,
		TargetKind:       targetKind,
	}

	cgb.db.CallGraph.AddEdge(edge)

	// Also add call to the function object
	cgb.addCallToFunction(calledName, targetContract, resolvedContract, resolvedFuncName, callType, targetKind, line, resolved, argCount)
}

// superSite is a single `super.g()` call discovered during call-graph building:
// the function that hosts it, the called member name, and its argument count.
type superSite struct {
	contract   *types.Contract
	fn         *types.Function
	calledName string
	argCount   int
	line       int
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
						argCount:   call.ArgCount,
						line:       call.Line,
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
		mro := leaf.LinearizedBases
		if len(mro) < 2 {
			continue
		}
		// Position of each MRO name (first occurrence) for O(1) host lookup.
		pos := make(map[string]int, len(mro))
		for i, name := range mro {
			if _, ok := pos[name]; !ok {
				pos[name] = i
			}
		}

		for _, site := range sites {
			i, ok := pos[site.contract.Name]
			if !ok {
				continue // this site's host is not part of this leaf's hierarchy
			}
			target, targetContract := cgb.nextDefInMRO(mro, i+1, site.calledName, site.argCount)
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
				From:             from,
				To:               to,
				CalledName:       site.calledName,
				Type:             types.CallTypeSuper,
				Line:             site.line,
				Resolved:         true,
				ResolvedContract: targetContract.Name,
				ResolvedFunction: toSelector,
				TargetKind:       targetContract.Kind,
			})
			// Mirror onto the host function's Calls so AST/reachability consumers
			// that read fn.Calls see the in-leaf target too (deduped above).
			site.fn.Calls = append(site.fn.Calls, &types.FunctionCall{
				Target:           site.calledName,
				ContractName:     targetContract.Name,
				ResolvedContract: targetContract.Name,
				ResolvedFunction: toSelector,
				CallType:         types.CallTypeSuper,
				TargetKind:       targetContract.Kind,
				Line:             site.line,
				Resolved:         true,
				ArgCount:         site.argCount,
			})
		}
	}
}

// nextDefInMRO returns the first contract at or after index `start` in the MRO
// that defines a function named funcName, preferring an exact arity match
// (argCount >= 0) and falling back to name-only. Returns the function and its
// owning contract, or (nil, nil) when no base in the remaining MRO defines it.
func (cgb *CallGraphBuilder) nextDefInMRO(mro []string, start int, funcName string, argCount int) (*types.Function, *types.Contract) {
	// Pass 1: exact arity.
	if argCount >= 0 {
		for j := start; j < len(mro); j++ {
			base := cgb.db.GetContractByName(mro[j])
			if base == nil {
				continue
			}
			for _, fn := range base.Functions {
				if fn.Name == funcName && len(fn.Parameters) == argCount {
					return fn, base
				}
			}
		}
	}
	// Pass 2: name-only.
	for j := start; j < len(mro); j++ {
		base := cgb.db.GetContractByName(mro[j])
		if base == nil {
			continue
		}
		for _, fn := range base.Functions {
			if fn.Name == funcName {
				return fn, base
			}
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
func (cgb *CallGraphBuilder) resolveLibraryCall(funcName string) *types.Contract {
	// Get the current contract to check its using directives
	currentContract := cgb.db.GetContractByName(cgb.currentContract)
	if currentContract == nil {
		return nil
	}

	// Check using directives - match by function existence in library
	for _, ud := range currentContract.UsingDirectives {
		// Get the library contract
		libContract := cgb.db.GetContractByName(ud.Library)
		if libContract != nil && libContract.Kind == types.ContractKindLibrary {
			// Check if library has a function with this name
			for _, fn := range libContract.Functions {
				if fn.Name == funcName {
					return libContract
				}
			}
		}
	}

	// Also check linearized bases for inherited using directives
	for _, baseName := range currentContract.LinearizedBases {
		if baseName == currentContract.Name {
			continue
		}
		baseContract := cgb.db.GetContractByName(baseName)
		if baseContract == nil {
			continue
		}
		for _, ud := range baseContract.UsingDirectives {
			libContract := cgb.db.GetContractByName(ud.Library)
			if libContract != nil && libContract.Kind == types.ContractKindLibrary {
				for _, fn := range libContract.Functions {
					if fn.Name == funcName {
						return libContract
					}
				}
			}
		}
	}

	return nil
}

// resolveTarget resolves the actual target contract and function using inheritance.
// argCount is the number of arguments at the call site; it is used to disambiguate
// overloaded functions that share the same name but differ in parameter count.
// Pass -1 to skip overload disambiguation.
func (cgb *CallGraphBuilder) resolveTarget(funcName, contractName string, callType types.CallType, argCount int) (resolvedContract string, resolvedFunc *types.Function, targetKind types.ContractKind, resolved bool) {
	// For low-level calls, we can't resolve
	if callType == types.CallTypeTransferETH {
		return "", nil, "", false
	}
	if callType == types.CallTypeLowLevel || callType == types.CallTypeLowLevelCall ||
		callType == types.CallTypeLowLevelDelegate || callType == types.CallTypeLowLevelStatic {
		return contractName, nil, "", false
	}

	// Get the target contract
	targetContractObj := cgb.db.GetContractByName(contractName)
	if targetContractObj == nil {
		return contractName, nil, "", false
	}

	targetKind = targetContractObj.Kind

	// matchFn returns true when a function is a good candidate.
	// It first tries an exact parameter-count match; if argCount < 0 it always matches.
	matchFn := func(fn *types.Function) bool {
		if fn.Name != funcName {
			return false
		}
		if argCount < 0 {
			return true
		}
		return len(fn.Parameters) == argCount
	}

	// resolveFallbackFn matches by name only (used as a second pass when no
	// exact arity match is found, e.g. in contracts without overloads).
	resolveFallbackFn := func(fn *types.Function) bool {
		return fn.Name == funcName
	}

	// For library calls, look directly in the library
	if callType == types.CallTypeLibrary {
		for _, fn := range targetContractObj.Functions {
			if matchFn(fn) {
				return targetContractObj.Name, fn, targetKind, true
			}
		}
		// Fallback: name-only
		for _, fn := range targetContractObj.Functions {
			if resolveFallbackFn(fn) {
				return targetContractObj.Name, fn, targetKind, true
			}
		}
		return contractName, nil, targetKind, false
	}

	// For super calls, look in base contracts (skip current contract)
	// LinearizedBases is derived-first: [CurrentContract, Parent1, Parent2, ...]
	// super.func() should find the next-most-derived parent's implementation
	if callType == types.CallTypeSuper {
		currentContract := cgb.db.GetContractByName(cgb.currentContract)
		if currentContract != nil && len(currentContract.LinearizedBases) > 1 {
			// First pass: exact arity match
			for i := 1; i < len(currentContract.LinearizedBases); i++ {
				baseName := currentContract.LinearizedBases[i]
				baseContract := cgb.db.GetContractByName(baseName)
				if baseContract != nil {
					for _, fn := range baseContract.Functions {
						if matchFn(fn) {
							return baseContract.Name, fn, baseContract.Kind, true
						}
					}
				}
			}
			// Second pass: name-only fallback
			for i := 1; i < len(currentContract.LinearizedBases); i++ {
				baseName := currentContract.LinearizedBases[i]
				baseContract := cgb.db.GetContractByName(baseName)
				if baseContract != nil {
					for _, fn := range baseContract.Functions {
						if resolveFallbackFn(fn) {
							return baseContract.Name, fn, baseContract.Kind, true
						}
					}
				}
			}
		}
		return contractName, nil, targetKind, false
	}

	// For internal/self calls, walk the linearization to find the function.
	// LinearizedBases is derived-first: [MostDerived, ..., MostBase].
	//
	// We do TWO passes:
	//   Pass 1 – prefer an overload whose parameter count exactly matches argCount.
	//            This correctly routes _approve(a,b,c) → _approve(a,b,c,flag) instead
	//            of looping back to _approve(a,b,c) in the same contract.
	//   Pass 2 – fall back to name-only matching for non-overloaded cases.

	for _, baseName := range targetContractObj.LinearizedBases {
		baseContract := cgb.db.GetContractByName(baseName)
		if baseContract != nil {
			for _, fn := range baseContract.Functions {
				if matchFn(fn) {
					return baseContract.Name, fn, baseContract.Kind, true
				}
			}
		}
	}

	for _, baseName := range targetContractObj.LinearizedBases {
		baseContract := cgb.db.GetContractByName(baseName)
		if baseContract != nil {
			for _, fn := range baseContract.Functions {
				if resolveFallbackFn(fn) {
					return baseContract.Name, fn, baseContract.Kind, true
				}
			}
		}
	}

	// Check directly in the target contract
	for _, fn := range targetContractObj.Functions {
		if resolveFallbackFn(fn) {
			return targetContractObj.Name, fn, targetKind, true
		}
	}

	return contractName, nil, targetKind, false
}

// addCallToFunction adds a call reference to the function object, or to the
// modifier object when analyzing a modifier body.
func (cgb *CallGraphBuilder) addCallToFunction(target, targetContract, resolvedContract, resolvedFunc string, callType types.CallType, targetKind types.ContractKind, line int, resolved bool, argCount int) {
	if cgb.currentModifierObj != nil {
		cgb.currentModifierObj.Calls = append(cgb.currentModifierObj.Calls, &types.FunctionCall{
			Target:           target,
			ContractName:     targetContract,
			ResolvedContract: resolvedContract,
			ResolvedFunction: resolvedFunc,
			CallType:         callType,
			TargetKind:       targetKind,
			Line:             line,
			Resolved:         resolved,
			ArgCount:         argCount,
		})
		return
	}

	// Find the current function in the database using the selector
	parts := strings.Split(cgb.currentFunction, ".")
	if len(parts) < 2 {
		return
	}

	contractName := parts[0]
	funcSelector := strings.Join(parts[1:], ".")

	contract := cgb.db.GetContractByName(contractName)
	if contract == nil {
		return
	}

	for _, fn := range contract.Functions {
		// match by selector, fallback to name if selector is empty
		key := fn.Selector
		if key == "" {
			key = fn.Name
		}
		if key == funcSelector {
			fn.Calls = append(fn.Calls, &types.FunctionCall{
				Target:           target,
				ContractName:     targetContract,
				ResolvedContract: resolvedContract,
				ResolvedFunction: resolvedFunc,
				CallType:         callType,
				TargetKind:       targetKind,
				Line:             line,
				Resolved:         resolved,
				ArgCount:         argCount,
			})
			break
		}
	}
}

// isContract checks if a name refers to a known contract (not library)
func (cgb *CallGraphBuilder) isContract(name string) bool {
	c := cgb.db.GetContractByName(name)
	if c == nil {
		return false
	}
	return c.Kind == types.ContractKindContract || c.Kind == types.ContractKindInterface || c.Kind == types.ContractKindAbstract
}

// isLibrary checks if a name refers to a library
func (cgb *CallGraphBuilder) isLibrary(name string) bool {
	c := cgb.db.GetContractByName(name)
	if c == nil {
		return false
	}
	return c.Kind == types.ContractKindLibrary
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
	for _, modInv := range modifiers {
		if modInv.Name == "" {
			continue
		}

		// Get line number if available
		line := 0
		if modInv.Loc != nil {
			line = modInv.Loc.Start.Line
		}

		// Resolve the modifier in the contract's inheritance chain
		resolvedContract, resolvedModifier, resolved := cgb.resolveModifier(modInv.Name, cgb.currentContract)

		// Create the call target ID
		target := modInv.Name
		if resolved && resolvedContract != "" {
			// Get the contract object to find source file
			if targetContractObj := cgb.db.GetContractByName(resolvedContract); targetContractObj != nil {
				target = types.MakeModifierID(targetContractObj.SourceFile, resolvedContract, resolvedModifier)
			}
		}

		// Create full "From" identifier with file path. Use SplitN/Join so a
		// selector containing dots (e.g. setConfig(MyLib.Config)) is not truncated.
		fromParts := strings.SplitN(cgb.currentFunction, ".", 2)
		fromSelector := ""
		if len(fromParts) == 2 {
			fromSelector = fromParts[1]
		}
		from := types.MakeFunctionID(cgb.currentFile, cgb.currentContract, fromSelector)

		// Add edge to call graph
		edge := &types.CallEdge{
			From:             from,
			To:               target,
			CalledName:       modInv.Name,
			Type:             types.CallTypeModifier,
			Line:             line,
			Resolved:         resolved,
			ResolvedContract: resolvedContract,
			ResolvedFunction: resolvedModifier,
			TargetKind:       types.ContractKindContract, // Modifiers are part of contracts
		}

		cgb.db.CallGraph.AddEdge(edge)

		// Also add modifier call to the function object
		cgb.addModifierCallToFunction(modInv.Name, resolvedContract, resolvedModifier, line, resolved)
	}
}

// resolveModifier resolves a modifier in the contract's inheritance chain
// Returns (resolvedContract, resolvedModifier, resolved)
func (cgb *CallGraphBuilder) resolveModifier(modifierName, contractName string) (string, string, bool) {
	// Get the target contract
	targetContract := cgb.db.GetContractByName(contractName)
	if targetContract == nil {
		return contractName, modifierName, false
	}

	// Walk the linearization to find the modifier
	// LinearizedBases is derived-first: [MostDerived, ..., MostBase]
	// Iterate forward to find most-derived implementation first
	for _, baseName := range targetContract.LinearizedBases {
		baseContract := cgb.db.GetContractByName(baseName)
		if baseContract != nil {
			for _, mod := range baseContract.Modifiers {
				if mod.Name == modifierName {
					// Found the modifier
					return baseContract.Name, mod.Name, true
				}
			}
		}
	}

	// Not found in linearized bases, return unresolved
	return contractName, modifierName, false
}

// addModifierCallToFunction adds a modifier call reference to the function object
func (cgb *CallGraphBuilder) addModifierCallToFunction(modifierName, resolvedContract, resolvedModifier string, line int, resolved bool) {
	// Find the current function in the database
	parts := strings.SplitN(cgb.currentFunction, ".", 2)
	if len(parts) != 2 {
		return
	}

	contractName := parts[0]
	funcName := parts[1]

	contract := cgb.db.GetContractByName(contractName)
	if contract == nil {
		return
	}

	for _, fn := range contract.Functions {
		if fn.Name == funcName {
			fn.Calls = append(fn.Calls, &types.FunctionCall{
				Target:           modifierName,
				ContractName:     contractName,
				ResolvedContract: resolvedContract,
				ResolvedFunction: resolvedModifier,
				CallType:         types.CallTypeModifier,
				TargetKind:       types.ContractKindContract,
				Line:             line,
				Resolved:         resolved,
			})
			break
		}
	}
}
