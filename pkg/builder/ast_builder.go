package builder

import (
	"fmt"
	"sort"
	"strings"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ASTBuilder builds w3goaudit AST from Solidity AST
type ASTBuilder struct {
	contract       *types.Contract
	function       *types.Function
	db             *types.Database
	locator        *sourceLocator
	symbolTable    map[string]string // variable name -> RefKind (parameter, state_var, local_var)
	symbolTypes    map[string]types.TypeInfo
	taintTable     map[string][]string // variable name -> list of taints
	paramNames     map[string]bool     // quick lookup for parameter names
	stateVarNames  map[string]bool     // quick lookup for state variable names
	assemblyScopes []map[string]assemblySymbol
	assemblyFlow   map[*types.ASTNode]assemblyControlFlow
	assemblyLHS    map[*types.ASTNode]int
	assemblyTypes  map[*types.ASTNode]assemblyObservedType
}

type assemblySymbol struct {
	taintSources []string
	typeInfo     types.TypeInfo
}

type assemblyFlowState struct {
	taintTable     map[string][]string
	symbolTypes    map[string]types.TypeInfo
	assemblyScopes []map[string]assemblySymbol
}

type assemblyControlFlow struct {
	kind       string
	condition  *types.ASTNode
	pre        []*types.ASTNode
	body       []*types.ASTNode
	post       []*types.ASTNode
	cases      [][]*types.ASTNode
	hasDefault bool
}

type assemblyObservedType struct {
	initialized bool
	unknown     bool
	typeInfo    types.TypeInfo
}

const maxAssemblyLoopFixpointPasses = 16

// BuildFunctionAST builds an AST tree for a function body
func BuildFunctionAST(fndef *ast.FunctionDefinition, fn *types.Function, contract *types.Contract, db *types.Database) *types.ASTNode {
	file := ""
	if fn != nil {
		file = fn.SourceFile
	}
	if file == "" && contract != nil {
		file = contract.SourceFile
	}
	return buildFunctionASTWithLocator(fndef, fn, contract, db, sourceLocatorFromDatabase(db, file))
}

func buildFunctionASTWithLocator(fndef *ast.FunctionDefinition, fn *types.Function, contract *types.Contract, db *types.Database, locator *sourceLocator) *types.ASTNode {
	builder := &ASTBuilder{
		contract:      contract,
		function:      fn,
		db:            db,
		locator:       locator,
		symbolTable:   make(map[string]string),
		symbolTypes:   make(map[string]types.TypeInfo),
		taintTable:    make(map[string][]string),
		paramNames:    make(map[string]bool),
		stateVarNames: make(map[string]bool),
	}

	// Build symbol table
	builder.buildSymbolTable()

	// Create function root node
	root := types.NewASTNode(types.KindDeclFunction)
	builder.locator.apply(root, fndef)
	root.Name = fn.Name
	root.SetAttribute("visibility", string(fn.Visibility))
	root.SetAttribute("mutability", string(fn.StateMutability))

	// Build AST from function body
	if fndef.Body != nil {
		builder.buildBlock(root, fndef.Body)
	}

	return root
}

// BuildModifierAST preserves the original one-argument SDK API. Without owning
// contract context it cannot classify state-variable references; new callers
// should prefer BuildModifierASTWithContext.
func BuildModifierAST(moddef *ast.ModifierDefinition) *types.ASTNode {
	return buildModifierASTWithLocator(moddef, nil, nil, nil)
}

// BuildModifierASTWithContext builds a modifier AST with its owning contract
// and database so state-variable references and source locations are resolved.
func BuildModifierASTWithContext(moddef *ast.ModifierDefinition, contract *types.Contract, db *types.Database) *types.ASTNode {
	file := ""
	if contract != nil {
		file = contract.SourceFile
	}
	return buildModifierASTWithLocator(moddef, contract, db, sourceLocatorFromDatabase(db, file))
}

func buildModifierASTWithLocator(moddef *ast.ModifierDefinition, contract *types.Contract, db *types.Database, locator *sourceLocator) *types.ASTNode {
	builder := &ASTBuilder{
		contract:      contract,
		db:            db,
		locator:       locator,
		symbolTable:   make(map[string]string),
		symbolTypes:   make(map[string]types.TypeInfo),
		taintTable:    make(map[string][]string),
		paramNames:    make(map[string]bool),
		stateVarNames: make(map[string]bool),
	}

	// Add modifier parameters to symbol table
	for _, param := range moddef.Parameters {
		if param.Name != "" {
			builder.symbolTable[param.Name] = "parameter"
			builder.paramNames[param.Name] = true
			builder.symbolTypes[param.Name] = builder.typeInfoFromTypeName(getTypeName(param.TypeName), "modifier_parameter")
		}
	}

	// Add the owning contract's state variables so writes/reads of them inside
	// the modifier body are resolved (is_state_var, RefKind, taint source).
	if contract != nil {
		for _, sv := range contract.StateVariables {
			builder.symbolTable[sv.Name] = "state_var"
			ti := builder.typeInfoFromTypeName(sv.TypeName, "state_var")
			builder.symbolTypes[sv.Name] = ti
			builder.stateVarNames[sv.Name] = true
		}
	}

	// Create modifier root node
	root := types.NewASTNode(types.KindDeclModifier)
	builder.locator.apply(root, moddef)
	root.Name = moddef.Name

	// Build AST from modifier body
	if moddef.Body != nil {
		builder.buildBlock(root, moddef.Body)
	}

	return root
}

// buildSymbolTable builds a symbol table for variable lookups.
//
// TODO(stage-3): the symbol table is currently a flat map per function,
// so block-scoped shadowing (e.g. `{ uint x = 1; { uint x = 2; } }`)
// produces incorrect taint classifications. A proper fix needs a scope
// stack pushed at each `{` and popped at `}`. Tracked in
// .vscode/2026-05-08-invariant-audit.md §1.6.
func (b *ASTBuilder) buildSymbolTable() {
	// Add function parameters
	for _, param := range b.function.Parameters {
		if param.Name != "" {
			b.symbolTable[param.Name] = "parameter"
			ti := b.typeInfoFromTypeName(param.TypeName, "parameter")
			b.symbolTypes[param.Name] = ti
			b.addSemanticSymbol(param.Name, "parameter", ti)
			b.paramNames[param.Name] = true
		}
	}

	// Add state variables from contract
	for _, sv := range b.contract.StateVariables {
		b.symbolTable[sv.Name] = "state_var"
		ti := b.typeInfoFromTypeName(sv.TypeName, "state_var")
		b.symbolTypes[sv.Name] = ti
		b.addSemanticSymbol(sv.Name, "state_var", ti)
		b.stateVarNames[sv.Name] = true
	}

	// Named return parameters are Solidity locals: inline assembly may read and
	// assign them directly (for example `result := value`). Keep them in the
	// surrounding symbol state so Yul writes are visible after the assignment.
	// Add them after contract storage so the function-local name wins if it
	// shadows a state variable.
	for _, result := range b.function.Returns {
		if result.Name != "" {
			b.symbolTable[result.Name] = "local_var"
			ti := b.typeInfoFromTypeName(result.TypeName, "return_parameter")
			b.symbolTypes[result.Name] = ti
			b.addSemanticSymbol(result.Name, "local_var", ti)
		}
	}

	// Note: Local variables are added during traversal
}

// buildBlock builds AST nodes for a block statement
func (b *ASTBuilder) buildBlock(parent *types.ASTNode, block *ast.Block) {
	for _, stmt := range block.Statements {
		node := b.buildStatement(stmt)
		if node != nil {
			parent.AddChild(node)
		}
	}
}

// buildStatement dispatches to buildStatementInner and stamps source location
// onto the produced node. Central chokepoint so every statement node is located.
func (b *ASTBuilder) buildStatement(stmt ast.Node) *types.ASTNode {
	node := b.buildStatementInner(stmt)
	b.locator.apply(node, stmt)
	return node
}

// buildStatementInner builds AST node for a statement
func (b *ASTBuilder) buildStatementInner(stmt ast.Node) *types.ASTNode {
	if stmt == nil {
		return nil
	}

	switch s := stmt.(type) {
	case *ast.ExpressionStatement:
		return b.buildExpression(s.Expression)

	case *ast.VariableDeclarationStatement:
		return b.buildVariableDeclaration(s)

	case *ast.IfStatement:
		return b.buildIfStatement(s)

	case *ast.WhileStatement:
		return b.buildWhileStatement(s)

	case *ast.ForStatement:
		return b.buildForStatement(s)

	case *ast.ReturnStatement:
		return b.buildReturn(s)

	case *ast.EmitStatement:
		return b.buildEmit(s)

	case *ast.RevertStatement:
		return b.buildRevertStatement(s)

	case *ast.DoWhileStatement:
		return b.buildDoWhileStatement(s)

	case *ast.TryStatement:
		return b.buildTryStatement(s)

	case *ast.Block:
		blockNode := types.NewASTNode(types.KindStmtBlock)
		b.buildBlock(blockNode, s)
		return blockNode

	case *ast.UncheckedBlock:
		uncheckedNode := types.NewASTNode(types.KindStmtUnchecked)
		if s.Body != nil {
			b.buildBlock(uncheckedNode, s.Body)
		}
		return uncheckedNode

	case *ast.InlineAssembly:
		return b.buildInlineAssembly(s)

	default:
		// Unknown statement type - create a generic node
		node := types.NewASTNode("statement")
		return node
	}
}

// buildInlineAssembly builds AST for inline assembly block
func (b *ASTBuilder) buildInlineAssembly(asm *ast.InlineAssembly) *types.ASTNode {
	node := types.NewASTNode(types.KindAsmBlock)
	b.locator.apply(node, asm)

	if asm.Language != "" {
		node.SetAttribute("language", asm.Language)
	}

	// Process assembly body
	if asm.Body != nil {
		b.buildAssemblyBlock(node, asm.Body)
	}

	return node
}

// buildAssemblyBlock processes assembly operations
func (b *ASTBuilder) buildAssemblyBlock(parent *types.ASTNode, block *ast.AssemblyBlock) {
	if block == nil {
		return
	}
	b.pushAssemblyScope()
	defer b.popAssemblyScope()
	b.buildAssemblyBlockOperations(parent, block)
}

func (b *ASTBuilder) buildAssemblyBlockOperations(parent *types.ASTNode, block *ast.AssemblyBlock) {
	for _, op := range block.Operations {
		opNode := b.buildAssemblyOperation(op)
		if opNode != nil {
			parent.AddChild(opNode)
		}
	}
}

// buildAssemblyOperation dispatches to buildAssemblyOperationInner and stamps
// source location onto the produced node.
func (b *ASTBuilder) buildAssemblyOperation(op ast.Node) *types.ASTNode {
	node := b.buildAssemblyOperationInner(op)
	b.locator.apply(node, op)
	return node
}

// buildAssemblyOperationInner builds AST node for an assembly operation
func (b *ASTBuilder) buildAssemblyOperationInner(op ast.Node) *types.ASTNode {
	if op == nil {
		return nil
	}

	switch o := op.(type) {
	case *ast.AssemblyCall:
		return b.buildAssemblyCall(o)
	case *ast.AssemblyIdentifier:
		return b.buildAssemblyIdentifier(o.Name)
	case *ast.AssemblyLiteral:
		return buildAssemblyLiteral(o)
	case *ast.AssemblyLocalDefinition:
		return b.buildAssemblyLocalDefinition(o)
	case *ast.AssemblyAssignment:
		return b.buildAssemblyAssignment(o)
	case *ast.AssemblyBlock:
		return b.buildAssemblyBlockNode(o)
	case *ast.AssemblyIf:
		return b.buildAssemblyIf(o)
	case *ast.AssemblySwitch:
		return b.buildAssemblySwitch(o)
	case *ast.AssemblyFor:
		return b.buildAssemblyFor(o)
	default:
		// Generic assembly operation
		return types.NewASTNode("assembly_operation")
	}
}

func buildAssemblyLiteral(literal *ast.AssemblyLiteral) *types.ASTNode {
	node := types.NewASTNode(types.KindExprLiteral)
	node.Value = literal.Value
	node.SetAttribute("subtype", literal.Kind)
	node.SetAttribute("assembly", true)
	return node
}

func (b *ASTBuilder) buildAssemblyLocalDefinition(definition *ast.AssemblyLocalDefinition) *types.ASTNode {
	node := types.NewASTNode(types.KindDeclVariable)
	node.SetAttribute("assembly", true)
	var expression *types.ASTNode
	if definition.Expression != nil {
		expression = b.buildAssemblyOperation(definition.Expression)
	}
	taintSources := b.computeTaint(expression)
	typeInfo := b.typeFromNode(expression)
	lhsCount := 0
	for _, name := range definition.Names {
		if name == nil || name.Name == "" {
			continue
		}
		lhsCount++
		b.declareAssemblySymbol(name.Name, assemblySymbol{
			taintSources: append([]string(nil), taintSources...),
			typeInfo:     typeInfo,
		})
		node.AddChild(b.buildAssemblyIdentifier(name.Name))
	}
	b.setAssemblyLHSCount(node, lhsCount)
	if expression != nil {
		node.AddChild(expression)
	}
	return node
}

func (b *ASTBuilder) buildAssemblyAssignment(assignment *ast.AssemblyAssignment) *types.ASTNode {
	// Yul assignment without `let` updates an existing Yul or Solidity symbol.
	node := types.NewASTNode(types.KindStmtAssign)
	node.SetAttribute("assembly", true)
	var expression *types.ASTNode
	if assignment.Expression != nil {
		expression = b.buildAssemblyOperation(assignment.Expression)
	}
	taintSources := b.computeTaint(expression)
	typeInfo := b.typeFromNode(expression)
	lhsCount := 0
	for _, name := range assignment.Names {
		if name == nil || name.Name == "" {
			continue
		}
		lhsCount++
		b.assignAssemblySymbol(name.Name, taintSources, typeInfo)
		node.AddChild(b.buildAssemblyIdentifier(name.Name))
	}
	b.setAssemblyLHSCount(node, lhsCount)
	if expression != nil {
		node.AddChild(expression)
	}
	return node
}

func (b *ASTBuilder) buildAssemblyBlockNode(block *ast.AssemblyBlock) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtBlock)
	node.SetAttribute("assembly", true)
	b.buildAssemblyBlock(node, block)
	return node
}

func (b *ASTBuilder) buildAssemblyIf(statement *ast.AssemblyIf) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtIf)
	node.SetAttribute("assembly", true)
	condition := b.buildAssemblyCondition(statement.Condition, "if")
	if condition != nil {
		node.AddChild(condition)
	}
	inputState := b.snapshotAssemblyFlowState()
	bodyStart := len(node.Children)
	if statement.Body != nil {
		b.restoreAssemblyFlowState(inputState)
		b.buildAssemblyBlock(node, statement.Body)
		bodyState := b.snapshotAssemblyFlowState()
		b.restoreAssemblyFlowState(b.mergeAssemblyFlowStates(inputState, bodyState))
	}
	b.setAssemblyControlFlow(node, assemblyControlFlow{
		kind:      "if",
		condition: condition,
		body:      assemblyChildSlice(node, bodyStart),
	})
	return node
}

func (b *ASTBuilder) buildAssemblySwitch(statement *ast.AssemblySwitch) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtIf)
	node.SetAttribute("assembly", true)
	node.SetAttribute("switch", true)
	condition := b.buildAssemblyCondition(statement.Expression, "")
	if condition != nil {
		node.AddChild(condition)
	}
	inputState := b.snapshotAssemblyFlowState()
	pathStates, caseNodes, hasDefault := b.buildAssemblySwitchCases(node, statement, inputState)
	if !hasDefault || len(pathStates) == 0 {
		pathStates = append(pathStates, inputState)
	}
	b.restoreAssemblyFlowState(b.mergeAssemblyFlowStates(pathStates...))
	b.setAssemblyControlFlow(node, assemblyControlFlow{
		kind:       "switch",
		condition:  condition,
		cases:      caseNodes,
		hasDefault: hasDefault,
	})
	return node
}

func (b *ASTBuilder) buildAssemblySwitchCases(node *types.ASTNode, statement *ast.AssemblySwitch, inputState assemblyFlowState) ([]assemblyFlowState, [][]*types.ASTNode, bool) {
	pathStates := make([]assemblyFlowState, 0, len(statement.Cases)+1)
	caseNodes := make([][]*types.ASTNode, 0, len(statement.Cases))
	hasDefault := false
	for _, currentCase := range statement.Cases {
		if currentCase == nil {
			caseNodes = append(caseNodes, nil)
			continue
		}
		hasDefault = hasDefault || currentCase.Default
		if currentCase.Body == nil {
			caseNodes = append(caseNodes, nil)
			pathStates = append(pathStates, inputState)
			continue
		}
		b.restoreAssemblyFlowState(inputState)
		caseStart := len(node.Children)
		b.buildAssemblyBlock(node, currentCase.Body)
		caseNodes = append(caseNodes, assemblyChildSlice(node, caseStart))
		pathStates = append(pathStates, b.snapshotAssemblyFlowState())
	}
	return pathStates, caseNodes, hasDefault
}

func (b *ASTBuilder) buildAssemblyFor(loop *ast.AssemblyFor) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtLoop)
	node.SetAttribute("assembly", true)
	node.SetAttribute("loop_type", "asm_for")
	b.pushAssemblyScope()
	defer b.popAssemblyScope()

	preStart := len(node.Children)
	if loop.Pre != nil {
		b.buildAssemblyBlockOperations(node, loop.Pre)
	}
	preNodes := assemblyChildSlice(node, preStart)
	condition := b.buildAssemblyCondition(loop.Condition, "loop")
	if condition != nil {
		node.AddChild(condition)
	}
	loopInputState := b.snapshotAssemblyFlowState()
	b.restoreAssemblyFlowState(loopInputState)

	bodyStart := len(node.Children)
	if loop.Body != nil {
		b.buildAssemblyBlock(node, loop.Body)
	}
	bodyNodes := assemblyChildSlice(node, bodyStart)
	postStart := len(node.Children)
	if loop.Post != nil {
		b.buildAssemblyBlock(node, loop.Post)
	}
	flow := assemblyControlFlow{
		kind:      "for",
		condition: condition,
		pre:       preNodes,
		body:      bodyNodes,
		post:      assemblyChildSlice(node, postStart),
	}
	b.setAssemblyControlFlow(node, flow)
	b.restoreAssemblyFlowState(b.runAssemblyLoopFixpoint(loopInputState, flow))
	return node
}

func (b *ASTBuilder) buildAssemblyCondition(operation ast.Node, role string) *types.ASTNode {
	if operation == nil {
		return nil
	}
	node := b.buildAssemblyOperation(operation)
	if node != nil && role != "" {
		node.SetAttribute("cond_role", role)
	}
	return node
}

// buildAssemblyCall dispatches to buildAssemblyCallInner and stamps source
// location onto the produced node.
func (b *ASTBuilder) buildAssemblyCall(call *ast.AssemblyCall) *types.ASTNode {
	node := b.buildAssemblyCallInner(call)
	b.locator.apply(node, call)
	return node
}

// buildAssemblyCallInner builds AST for an assembly function call (e.g., call, delegatecall, staticcall)
func (b *ASTBuilder) buildAssemblyCallInner(call *ast.AssemblyCall) *types.ASTNode {
	// Classify the assembly call based on the function name
	callType := b.classifyAssemblyCall(call.FunctionName)

	node := types.NewASTNode(callType)
	node.Name = call.FunctionName
	node.SetAttribute("assembly", true)

	// Add arguments as children
	for _, arg := range call.Arguments {
		argNode := b.buildAssemblyOperation(arg)
		if argNode != nil {
			node.AddChild(argNode)
		}
	}

	return node
}

// classifyAssemblyCall classifies an assembly call based on the opcode name
func (b *ASTBuilder) classifyAssemblyCall(opcode string) string {
	switch opcode {
	case "call":
		return types.KindAsmCall
	case "delegatecall":
		return types.KindAsmDelegatecall
	case "staticcall":
		return types.KindAsmStaticcall
	case "sstore":
		return types.KindAsmSstore
	case "sload":
		return types.KindAsmSload
	case "selfdestruct":
		return types.KindAsmSelfdestruct
	case "create":
		return types.KindAsmCreate
	case "create2":
		return types.KindAsmCreate2
	case "log0":
		return types.KindAsmLog0
	case "log1":
		return types.KindAsmLog1
	case "log2":
		return types.KindAsmLog2
	case "log3":
		return types.KindAsmLog3
	case "log4":
		return types.KindAsmLog4
	case "revert":
		return types.KindAsmRevert
	case "return":
		return types.KindAsmReturn
	default:
		return types.KindAsmOperation
	}
}

// build Variable declaration
func (b *ASTBuilder) buildVariableDeclaration(stmt *ast.VariableDeclarationStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindDeclVariable)

	// Add variables to symbol table as local_var
	// Note: stmt.Variables may contain nil entries for tuple holes like (, uint b) = f()
	for _, decl := range stmt.Variables {
		if decl == nil {
			continue
		}
		if decl.Name != "" {
			b.symbolTable[decl.Name] = "local_var"
			ti := b.typeInfoFromTypeName(getTypeName(decl.TypeName), "local_var")
			b.symbolTypes[decl.Name] = ti
			b.addSemanticSymbol(decl.Name, "local_var", ti)
		}
	}

	// If there's an initial value, treat it as an assignment
	if stmt.InitialValue != nil {
		assignNode := types.NewASTNode(types.KindStmtAssign)
		// Add variable identifiers
		for _, decl := range stmt.Variables {
			if decl == nil {
				continue
			}
			ident := types.NewASTNode(types.KindExprIdentifier)
			ident.Name = decl.Name
			ident.RefKind = "local_var"
			if b.contract != nil && b.function != nil && ident.Name != "" {
				ident.RefID = fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, ident.Name)
			}
			b.applyTypeAttributes(ident, b.symbolTypes[decl.Name])
			assignNode.AddChild(ident)
		}
		// Add initial value
		valueNode := b.buildExpression(stmt.InitialValue)
		if valueNode != nil {
			assignNode.AddChild(valueNode)

			// Propagate data-flow taint
			rhsTaint := b.computeTaint(valueNode)
			if len(rhsTaint) > 0 {
				for _, child := range assignNode.Children {
					if child != valueNode && child.Kind == types.KindExprIdentifier {
						child.TaintSources = rhsTaint
						b.taintTable[child.Name] = rhsTaint

						// Add missing RefID for local var if not set
						if child.RefID == "" && b.contract != nil && b.function != nil {
							child.RefID = fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, child.Name)
						}

						// Attempt to extract from source identifier
						fromID := valueNode.RefID
						if fromID == "" {
							if valueNode.Kind == types.KindExprIdentifier {
								fromID = valueNode.RefID
							} else {
								src := valueNode.FindDescendant(func(n *types.ASTNode) bool { return n.Kind == types.KindExprIdentifier })
								if src != nil {
									fromID = src.RefID
								}
							}
						}

						if fromID != "" || child.RefID != "" {
							edge := &types.DataFlowEdge{
								FromID:   fromID,
								ToID:     child.RefID,
								FromNode: valueNode,
								ToNode:   child,
								Type:     "assignment",
							}
							if b.db.DataFlow != nil {
								b.db.DataFlow.AddEdge(edge)
							}
						}
					}
				}
			}
			rhsType := b.typeFromNode(valueNode)
			if rhsType.IsKnown() {
				for _, child := range assignNode.Children {
					if child != valueNode && child.Kind == types.KindExprIdentifier && child.Name != "" {
						b.symbolTypes[child.Name] = rhsType
						b.applyTypeAttributes(child, rhsType)
						b.addSemanticSymbol(child.Name, child.RefKind, rhsType)
					}
				}
			}
		}
		return assignNode
	}

	return node
}

// buildIfStatement builds AST for if statement
func (b *ASTBuilder) buildIfStatement(stmt *ast.IfStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtIf)

	// Condition. Tag it so templates can distinguish the test expression from
	// the then/else bodies (e.g. flagging `if (true)` without matching a
	// `return true` in the body). Mirrors the ternary's conditional_part tag.
	if stmt.Condition != nil {
		condNode := b.buildExpression(stmt.Condition)
		if condNode != nil {
			condNode.SetAttribute("cond_role", "if")
			node.AddChild(condNode)
		}
	}

	// Then branch
	if stmt.TrueBody != nil {
		thenNode := b.buildStatement(stmt.TrueBody)
		if thenNode != nil {
			node.AddChild(thenNode)
		}
	}

	// Else branch
	if stmt.FalseBody != nil {
		elseNode := b.buildStatement(stmt.FalseBody)
		if elseNode != nil {
			node.AddChild(elseNode)
		}
	}

	return node
}

// buildWhileStatement builds AST for while loop
func (b *ASTBuilder) buildWhileStatement(stmt *ast.WhileStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtLoop)
	node.SetAttribute("loop_type", "while")

	if stmt.Condition != nil {
		condNode := b.buildExpression(stmt.Condition)
		if condNode != nil {
			condNode.SetAttribute("cond_role", "loop")
			node.AddChild(condNode)
		}
	}

	if stmt.Body != nil {
		bodyNode := b.buildStatement(stmt.Body)
		if bodyNode != nil {
			node.AddChild(bodyNode)
		}
	}

	return node
}

// buildForStatement builds AST for for loop
func (b *ASTBuilder) buildForStatement(stmt *ast.ForStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtLoop)
	node.SetAttribute("loop_type", "for")

	// Initialization
	if stmt.InitExpression != nil {
		initNode := b.buildStatement(stmt.InitExpression)
		if initNode != nil {
			node.AddChild(initNode)
		}
	}

	// Condition
	if stmt.ConditionExpression != nil {
		condNode := b.buildExpression(stmt.ConditionExpression)
		if condNode != nil {
			condNode.SetAttribute("cond_role", "loop")
			node.AddChild(condNode)
		}
	}

	// Loop expression
	if stmt.LoopExpression != nil {
		// LoopExpression is an ExpressionStatement
		loopNode := b.buildStatement(stmt.LoopExpression)
		if loopNode != nil {
			node.AddChild(loopNode)
		}
	}

	// Body
	if stmt.Body != nil {
		bodyNode := b.buildStatement(stmt.Body)
		if bodyNode != nil {
			node.AddChild(bodyNode)
		}
	}

	return node
}

// buildReturn builds AST for return statement
func (b *ASTBuilder) buildReturn(stmt *ast.ReturnStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtReturn)

	if stmt.Expression != nil {
		exprNode := b.buildExpression(stmt.Expression)
		if exprNode != nil {
			node.AddChild(exprNode)
		}
	}

	return node
}

// buildEmit builds AST for emit statement
func (b *ASTBuilder) buildEmit(stmt *ast.EmitStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtEmit)

	if stmt.EventCall != nil {
		callNode := b.buildExpression(stmt.EventCall)
		if callNode != nil {
			node.AddChild(callNode)
		}
	}

	return node
}

// buildRevertStatement builds AST for a revert statement. The pinned parser
// emits `revert("reason")` and `revert CustomError(args)` as *ast.RevertStatement
// (NOT as a require/assert-style FunctionCall), so this is the only path that
// produces check.revert nodes. The revert arguments are attached as children so
// templates can match them via `args:` exactly like require/assert.
func (b *ASTBuilder) buildRevertStatement(stmt *ast.RevertStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindCheckRevert)

	if stmt.RevertCall == nil {
		return node // bare `revert;` (rare)
	}

	switch rc := stmt.RevertCall.(type) {
	case *ast.FunctionCall:
		// `revert CustomError(args)` or `revert Lib.Error(args)` — record the
		// error name and expose each argument as a child for `args:` matching.
		switch e := rc.Expression.(type) {
		case *ast.Identifier:
			node.Name = e.Name
		case *ast.MemberAccess:
			node.Name = e.MemberName
		}
		for _, arg := range rc.Arguments {
			if argNode := b.buildExpression(arg); argNode != nil {
				node.AddChild(argNode)
			}
		}
	default:
		// `revert("reason")` — RevertCall is the literal/expression directly.
		if argNode := b.buildExpression(stmt.RevertCall); argNode != nil {
			node.AddChild(argNode)
		}
	}

	return node
}

// buildDoWhileStatement builds AST for a do/while loop. Modeled as a generic
// loop (loop_type=do_while) with the body first and the condition last, so the
// shared `stmt.loop` matchers and `cond_role=loop` tagging apply uniformly.
func (b *ASTBuilder) buildDoWhileStatement(stmt *ast.DoWhileStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtLoop)
	node.SetAttribute("loop_type", "do_while")

	if stmt.Body != nil {
		if bodyNode := b.buildStatement(stmt.Body); bodyNode != nil {
			node.AddChild(bodyNode)
		}
	}

	if stmt.Condition != nil {
		if condNode := b.buildExpression(stmt.Condition); condNode != nil {
			condNode.SetAttribute("cond_role", "loop")
			node.AddChild(condNode)
		}
	}

	return node
}

// buildTryStatement builds AST for try/catch
func (b *ASTBuilder) buildTryStatement(stmt *ast.TryStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtTryCatch)

	// Try expression (the external call / contract creation). It executes on
	// every path; on success the body runs, on failure a catch clause runs.
	// Tagged "expr" so the engine knows it co-executes with whichever arm fires.
	if stmt.Expression != nil {
		exprNode := b.buildExpression(stmt.Expression)
		if exprNode != nil {
			exprNode.SetAttribute("try_part", "expr")
			node.AddChild(exprNode)
		}
	}

	// Success body. Previously the body and catch clauses were dropped entirely,
	// so any dangerous code inside try/catch was invisible to templates. We now
	// build them and tag each as an exclusive arm: a statement in the body and a
	// statement in a catch clause can never both execute, so a `sequence` must
	// not pair them (e.g. a CEI sequence that crosses the try/catch boundary).
	if stmt.Body != nil {
		bodyNode := types.NewASTNode(types.KindStmtBlock)
		b.locator.apply(bodyNode, stmt.Body)
		bodyNode.SetAttribute("try_part", "body")
		b.buildBlock(bodyNode, stmt.Body)
		node.AddChild(bodyNode)
	}

	// Catch clauses — each mutually exclusive with the body and the others.
	for i, clause := range stmt.CatchClauses {
		if clause == nil || clause.Body == nil {
			continue
		}
		catchNode := types.NewASTNode(types.KindStmtBlock)
		b.locator.apply(catchNode, clause.Body)
		catchNode.SetAttribute("try_part", fmt.Sprintf("catch:%d", i))
		b.buildBlock(catchNode, clause.Body)
		node.AddChild(catchNode)
	}

	return node
}

// buildExpression dispatches to buildExpressionInner and stamps source
// location onto the produced node. Central chokepoint so every expression
// node is located.
func (b *ASTBuilder) buildExpression(expr ast.Node) *types.ASTNode {
	node := b.buildExpressionInner(expr)
	b.locator.apply(node, expr)
	return node
}

// buildExpressionInner builds AST node for an expression
func (b *ASTBuilder) buildExpressionInner(expr ast.Node) *types.ASTNode {
	if expr == nil {
		return nil
	}

	switch e := expr.(type) {
	case *ast.FunctionCall:
		return b.buildFunctionCall(e)

	case *ast.UnaryOperation:
		return b.buildUnaryOp(e)

	case *ast.MemberAccess:
		return b.buildMemberAccess(e)

	case *ast.IndexAccess:
		return b.buildIndexAccess(e)

	case *ast.Conditional:
		return b.buildConditional(e)

	case *ast.Identifier:
		return b.buildIdentifier(e)

	case *ast.NumberLiteral, *ast.StringLiteral, *ast.BooleanLiteral, *ast.HexLiteral:
		return b.buildLiteral(e)

	case *ast.NewExpression:
		// `new Contract(...)` deploys (and runs) code. The surrounding
		// FunctionCall normally routes here via buildFunctionCall, but a bare
		// `new C` expression reaches buildExpression directly.
		return b.buildNewExpression(e)

	case *ast.TupleExpression:
		// `(a, b)` — used as the LHS/RHS of tuple assignments and as grouping
		// parentheses. Preserve components so `(a, b) = (b, a)` keeps its
		// assignment targets and taint flows instead of collapsing to an
		// opaque node.
		return b.buildTupleExpression(e)

	// Handle assignment as part of expressions (like a = b)
	case *ast.BinaryOperation:
		if isAssignmentOperator(e.Operator) {
			return b.buildAssignmentFromBinary(e)
		}
		return b.buildBinaryOp(e)

	default:
		// Unknown expression - create generic node
		return types.NewASTNode("expression")
	}
}

// buildNewExpression builds a call.create node for `new Contract(...)`/`new T[]`.
// The deployed type name is recorded so `kind: call.create` templates can match
// and so the call graph can record a creation edge.
func (b *ASTBuilder) buildNewExpression(expr *ast.NewExpression) *types.ASTNode {
	node := types.NewASTNode(types.KindCallCreate)
	node.Name = getTypeName(expr.TypeName)
	return node
}

// buildTupleExpression builds an expression node holding each tuple component as
// a child, preserving identifier targets for tuple assignments.
func (b *ASTBuilder) buildTupleExpression(expr *ast.TupleExpression) *types.ASTNode {
	node := types.NewASTNode(types.KindExprTuple)
	for _, comp := range expr.Components {
		if comp == nil {
			continue // tuple hole, e.g. (, b) = f()
		}
		if compNode := b.buildExpression(comp); compNode != nil {
			node.AddChild(compNode)
		}
	}
	return node
}

// buildFunctionCall builds AST for function call
func (b *ASTBuilder) buildFunctionCall(call *ast.FunctionCall) *types.ASTNode {
	// Determine call type and name
	callType := types.KindCallExternal
	callName := ""
	calledSignature := ""
	var receiverExpr ast.Node
	var receiverType types.TypeInfo
	var resultType types.TypeInfo

	switch expr := call.Expression.(type) {
	case *ast.Identifier:
		// Direct function call: foo()
		callName = expr.Name
		// Check for require/assert/revert (check.* kinds) and the
		// builtin `selfdestruct`/`suicide` global functions.
		switch callName {
		case "require":
			callType = types.KindCheckRequire
		case "assert":
			callType = types.KindCheckAssert
		case "revert":
			callType = types.KindCheckRevert
		case "selfdestruct", "suicide":
			// Solidity-level builtin (NOT inline-asm). The `selfdestruct`
			// semantic group in matchKind unions this with asm.selfdestruct.
			callType = types.KindCallBuiltinSelfdestruct
		default:
			callType = types.KindCallInternal
			resultType = b.expressionType(call)
		}

	case *ast.ElementaryTypeName:
		// Type conversion such as address(0), uint256(x), bytes32(y).
		// This is not an external call and must not satisfy `outgoing_call`.
		callName = expr.Name
		callType = types.KindCallInternal
		resultType = b.typeInfoFromTypeName(expr.Name, "type_cast")

	case *ast.UserDefinedTypeName:
		// Interface/contract casts such as IERC20(token). They may be receivers
		// for later member calls, but the cast itself is not an external call.
		callName = expr.NamePath
		callType = types.KindCallInternal
		resultType = b.typeInfoFromTypeName(expr.NamePath, "type_cast")

	case *ast.NewExpression:
		// `new Contract(args)` — deploys and runs code. Classified as call.create
		// so `kind: call.create` and the outgoing_call/any_call groups match it.
		callName = getTypeName(expr.TypeName)
		callType = types.KindCallCreate
		resultType = b.typeInfoFromTypeName(callName, "new")

	case *ast.MemberAccess:
		// Member access call: token.transfer(), addr.call(), etc.
		callName = expr.MemberName
		receiverExpr = expr.Expression
		receiverType = b.expressionType(receiverExpr)
		callType = b.classifyMemberAccessCall(callName, len(call.Arguments), receiverType)

		// Try to extract called signature for low-level calls
		if callType == types.KindCallLowlevelCall {
			calledSignature = b.extractCalledSignature(call.Arguments)
		}

	case *ast.FunctionCallOptions:
		// Calls with options like: addr.call{value: x}("")
		if ma, ok := expr.Expression.(*ast.MemberAccess); ok {
			callName = ma.MemberName
			receiverExpr = ma.Expression
			receiverType = b.expressionType(receiverExpr)
			callType = b.classifyMemberAccessCall(callName, len(call.Arguments), receiverType)

			// Try to extract called signature for low-level calls
			if callType == types.KindCallLowlevelCall {
				calledSignature = b.extractCalledSignature(call.Arguments)
			}
		}
	}

	node := types.NewASTNode(callType)
	node.Name = callName
	if resultType.IsKnown() {
		b.applyTypeAttributes(node, resultType)
	}
	if receiverType.IsKnown() {
		b.applyReceiverTypeAttributes(node, receiverType)
		node.SetAttribute("call_classification", "semantic")
	} else if receiverExpr != nil {
		node.SetAttribute("call_classification", "heuristic")
	}

	// Preserve the receiver for member calls (`target.delegatecall(data)`,
	// `to.transfer(amount)`, `token.transferFrom(...)`) as a tagged child. WQL
	// `args:` still indexes only Solidity arguments; matchArgs skips this
	// metadata child. Templates can match `attr: {call_receiver: true}` to
	// distinguish a tainted call receiver from tainted calldata.
	if receiverExpr != nil {
		if rn := b.buildExpression(receiverExpr); rn != nil {
			rn.SetAttribute("call_receiver", true)
			node.AddChild(rn)
		}
	}

	// Preserve the `{value: x, gas: y, salt: z}` modifier presence as boolean
	// attributes on the call node. Templates can use `attr: has_value: true`
	// to distinguish `addr.call{value: x}("")` (ETH-sending) from
	// `addr.call(data)` (plain external call). The value expression itself
	// is attached as the `value_expr` child so taint analysis can reach it.
	if fco, ok := call.Expression.(*ast.FunctionCallOptions); ok {
		for i, optName := range fco.Names {
			if i >= len(fco.Options) {
				break
			}
			switch optName {
			case "value":
				node.SetAttribute("has_value", true)
				if vn := b.buildExpression(fco.Options[i]); vn != nil {
					vn.SetAttribute("call_option", "value")
					node.AddChild(vn)
				}
			case "gas":
				node.SetAttribute("has_gas", true)
				if gn := b.buildExpression(fco.Options[i]); gn != nil {
					gn.SetAttribute("call_option", "gas")
					node.AddChild(gn)
				}
			case "salt":
				node.SetAttribute("has_salt", true)
			}
		}
	}

	// Set called signature if extracted
	if calledSignature != "" {
		node.SetAttribute("called_signature", calledSignature)
	}

	// Add arguments as children
	for _, arg := range call.Arguments {
		argNode := b.buildExpression(arg)
		if argNode != nil {
			node.AddChild(argNode)
		}
	}

	return node
}

// classifyMemberAccessCall classifies a member access call using receiver type
// facts when available, then falls back to the historical method-name/arity
// heuristic. Type facts let us distinguish one-arg interface methods such as
// IOneArg(token).transfer(to) from address/payable ETH transfers.
//
// Classification rules:
//   - `.transfer(amt)`        (1 arg)  → call.builtin.transfer  (ETH)
//   - `.transfer(to, amt)`    (2 args) → call.external          (ERC20-shape)
//   - `.send(amt)`            (1 arg)  → call.builtin.send      (ETH)
//   - `.send(...)`            (other)  → call.external          (not a builtin)
//   - `.call(...)` / `.call{value:}(...)` → call.lowlevel.call
//   - `.delegatecall(...)`             → call.lowlevel.delegatecall
//   - `.staticcall(...)`               → call.lowlevel.staticcall
//   - everything else                  → call.external
func (b *ASTBuilder) classifyMemberAccessCall(methodName string, argCount int, receiverType types.TypeInfo) string {
	switch methodName {
	case "call":
		// Low-level .call() — could be ETH transfer or function call.
		// Always lowlevel; the FunctionCallOptions branch in buildCall tags
		// the `has_value:` attribute when a {value: ...} modifier is present.
		return types.KindCallLowlevelCall
	case "transfer":
		if receiverType.IsKnown() {
			if receiverType.IsPrimitiveAddress() && argCount == 1 {
				return types.KindCallBuiltinTransfer
			}
			if !receiverType.IsPrimitiveAddress() {
				return types.KindCallExternal
			}
		}
		// 1-arg .transfer(amount): ETH builtin (reverts on failure).
		// 2-arg .transfer(to, amount): ERC20-shape — treat as a regular
		// external call so templates can match it via `token_call` and
		// disambiguate cleanly from the ETH builtin.
		if argCount == 1 {
			return types.KindCallBuiltinTransfer
		}
		return types.KindCallExternal
	case "send":
		if receiverType.IsKnown() {
			if receiverType.IsPrimitiveAddress() && argCount == 1 {
				return types.KindCallBuiltinSend
			}
			if !receiverType.IsPrimitiveAddress() {
				return types.KindCallExternal
			}
		}
		// 1-arg .send(amount): ETH builtin (returns bool).
		// Any other arity is not the Solidity builtin — fall through to external.
		if argCount == 1 {
			return types.KindCallBuiltinSend
		}
		return types.KindCallExternal
	case "delegatecall":
		return types.KindCallLowlevelDelegate
	case "staticcall":
		return types.KindCallLowlevelStatic
	default:
		// Regular contract function call: token.approve(), pool.swap(), etc.
		return types.KindCallExternal
	}
}

// extractCalledSignature tries to extract the function signature from low-level call arguments
// Returns the signature string or empty if not determinable
func (b *ASTBuilder) extractCalledSignature(args []ast.Node) string {
	if len(args) == 0 {
		return ""
	}

	// Check first argument for signature patterns
	switch arg := args[0].(type) {
	case *ast.FunctionCall:
		// Check for abi.encodeWithSignature("funcName(args)", ...)
		if ma, ok := arg.Expression.(*ast.MemberAccess); ok {
			if ma.MemberName == "encodeWithSignature" && len(arg.Arguments) > 0 {
				if strLit, ok := arg.Arguments[0].(*ast.StringLiteral); ok {
					return strLit.Value
				}
			}
			// Check for abi.encodeWithSelector(selector, ...)
			if ma.MemberName == "encodeWithSelector" && len(arg.Arguments) > 0 {
				if hexLit, ok := arg.Arguments[0].(*ast.HexLiteral); ok {
					return hexLit.Value
				}
				if numLit, ok := arg.Arguments[0].(*ast.NumberLiteral); ok {
					return numLit.Number
				}
			}
		}
	case *ast.HexLiteral:
		// Direct hex data - first 4 bytes would be the selector
		if len(arg.Value) >= 10 { // "0x" + 8 hex chars
			return arg.Value[:10]
		}
	case *ast.StringLiteral:
		// Empty string means no function call (just ETH transfer)
		if arg.Value == "" {
			return ""
		}
	}

	return ""
}

// buildAssignmentFromBinary builds AST for assignment from binary operation
func (b *ASTBuilder) buildAssignmentFromBinary(op *ast.BinaryOperation) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtAssign)
	node.SetAttribute("operator", op.Operator)

	// Check if this is a state variable assignment
	isStateVarAssignment := b.isStateVariableReference(op.Left)
	node.SetAttribute("is_state_var", isStateVarAssignment)

	var leftNode *types.ASTNode
	var rightNode *types.ASTNode

	// Left side (target)
	if op.Left != nil {
		leftNode = b.buildExpression(op.Left)
		if leftNode != nil {
			node.AddChild(leftNode)
		}
	}

	// Right side (value)
	if op.Right != nil {
		rightNode = b.buildExpression(op.Right)
		if rightNode != nil {
			node.AddChild(rightNode)
		}
	}

	// Data-flow propagation
	if leftNode != nil && rightNode != nil {
		rhsTaint := b.computeTaint(rightNode)

		// Extract base identifier targets for assignment
		var targetIdent *types.ASTNode
		if leftNode.Kind == types.KindExprIdentifier {
			targetIdent = leftNode
		} else {
			targetIdent = leftNode.FindDescendant(func(n *types.ASTNode) bool {
				return n.Kind == types.KindExprIdentifier
			})
		}

		if targetIdent != nil {
			if len(rhsTaint) > 0 {
				targetIdent.TaintSources = rhsTaint
				b.taintTable[targetIdent.Name] = rhsTaint
			}
			rhsType := b.typeFromNode(rightNode)
			if rhsType.IsKnown() {
				b.symbolTypes[targetIdent.Name] = rhsType
				b.applyTypeAttributes(targetIdent, rhsType)
				b.addSemanticSymbol(targetIdent.Name, targetIdent.RefKind, rhsType)
			}

			// Extract source identifier for edge
			var sourceIdent *types.ASTNode
			if rightNode.Kind == types.KindExprIdentifier {
				sourceIdent = rightNode
			} else {
				sourceIdent = rightNode.FindDescendant(func(n *types.ASTNode) bool {
					return n.Kind == types.KindExprIdentifier
				})
			}

			edgeFrom := ""
			if sourceIdent != nil {
				edgeFrom = sourceIdent.RefID
			}

			if edgeFrom != "" || targetIdent.RefID != "" {
				edge := &types.DataFlowEdge{
					FromID:   edgeFrom,
					ToID:     targetIdent.RefID,
					FromNode: rightNode,
					ToNode:   leftNode,
					Type:     "assignment",
				}
				if b.db.DataFlow != nil {
					b.db.DataFlow.AddEdge(edge)
				}
			}
		}
	}

	return node
}

// isStateVariableReference checks if an expression references a state variable
// Returns true if the expression is or contains a state variable reference
func (b *ASTBuilder) isStateVariableReference(expr ast.Node) bool {
	if expr == nil {
		return false
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		// Simple identifier: check if it's a state variable
		return b.stateVarNames[e.Name]

	case *ast.IndexAccess:
		// Array/mapping access: arr[index] or mapping[key]
		// Check if the base is a state variable
		return b.isStateVariableReference(e.Base)

	case *ast.MemberAccess:
		// Member access: obj.field
		// Check if this is a state variable access
		return b.isStateVariableReference(e.Expression)

	default:
		return false
	}
}

// buildBinaryOp builds AST for binary operation
func (b *ASTBuilder) buildBinaryOp(op *ast.BinaryOperation) *types.ASTNode {
	node := types.NewASTNode(types.KindExprBinaryOp)
	node.SetAttribute("operator", op.Operator)

	if op.Left != nil {
		leftNode := b.buildExpression(op.Left)
		if leftNode != nil {
			node.AddChild(leftNode)
		}
	}

	if op.Right != nil {
		rightNode := b.buildExpression(op.Right)
		if rightNode != nil {
			node.AddChild(rightNode)
		}
	}

	return node
}

// buildConditional preserves ternary expressions (`cond ? a : b`) so taint
// analysis can see both possible values. Without this, `payer = ok ? msg.sender
// : from` collapses to an opaque node and loses the `from` parameter taint.
func (b *ASTBuilder) buildConditional(cond *ast.Conditional) *types.ASTNode {
	node := types.NewASTNode(types.KindExprConditional)

	if cond.Condition != nil {
		conditionNode := b.buildExpression(cond.Condition)
		if conditionNode != nil {
			conditionNode.SetAttribute("conditional_part", "condition")
			conditionNode.SetAttribute("cond_role", "ternary")
			node.AddChild(conditionNode)
		}
	}

	if cond.TrueExpression != nil {
		trueNode := b.buildExpression(cond.TrueExpression)
		if trueNode != nil {
			trueNode.SetAttribute("conditional_part", "true")
			node.AddChild(trueNode)
		}
	}

	if cond.FalseExpression != nil {
		falseNode := b.buildExpression(cond.FalseExpression)
		if falseNode != nil {
			falseNode.SetAttribute("conditional_part", "false")
			node.AddChild(falseNode)
		}
	}

	return node
}

// buildUnaryOp builds AST for unary operation
func (b *ASTBuilder) buildUnaryOp(op *ast.UnaryOperation) *types.ASTNode {
	node := types.NewASTNode(types.KindExprUnaryOp)
	node.SetAttribute("operator", op.Operator)
	node.SetAttribute("is_prefix", op.IsPrefix)

	if op.SubExpression != nil {
		exprNode := b.buildExpression(op.SubExpression)
		if exprNode != nil {
			node.AddChild(exprNode)
		}
	}

	return node
}

// buildMemberAccess builds AST for member access (e.g., obj.field)
func (b *ASTBuilder) buildMemberAccess(ma *ast.MemberAccess) *types.ASTNode {
	node := types.NewASTNode(types.KindExprMemberAccess)
	node.Name = ma.MemberName

	// Extract parent name for proper matching of tx.origin, msg.sender, etc.
	parentName := b.extractParentName(ma.Expression)
	if parentName != "" {
		node.SetAttribute("parent", parentName)
	}

	if ma.Expression != nil {
		exprNode := b.buildExpression(ma.Expression)
		if exprNode != nil {
			node.AddChild(exprNode)
		}
	}
	b.applyTypeAttributes(node, b.expressionType(ma))

	return node
}

// extractParentName extracts the name of the parent expression for member access
// Returns the identifier name for simple cases like tx.origin, msg.sender
func (b *ASTBuilder) extractParentName(expr ast.Node) string {
	if expr == nil {
		return ""
	}

	switch e := expr.(type) {
	case *ast.Identifier:
		return e.Name
	case *ast.MemberAccess:
		// For chained member access like a.b.c, get the immediate parent
		return e.MemberName
	default:
		return ""
	}
}

// buildIndexAccess builds AST for index access (e.g., arr[i])
func (b *ASTBuilder) buildIndexAccess(ia *ast.IndexAccess) *types.ASTNode {
	node := types.NewASTNode(types.KindExprIndexAccess)

	if ia.Base != nil {
		baseNode := b.buildExpression(ia.Base)
		if baseNode != nil {
			node.AddChild(baseNode)
		}
	}

	if ia.Index != nil {
		indexNode := b.buildExpression(ia.Index)
		if indexNode != nil {
			node.AddChild(indexNode)
		}
	}
	b.applyTypeAttributes(node, b.expressionType(ia))

	return node
}

// buildIdentifier builds AST for identifier
func (b *ASTBuilder) buildIdentifier(ident *ast.Identifier) *types.ASTNode {
	return b.buildNamedIdentifier(ident.Name)
}

// buildNamedIdentifier builds a source-language-neutral identifier node. Both
// Solidity and Yul identifiers resolve through the same symbol/type/taint
// tables so assembly sinks retain parameter and state-variable provenance.
func (b *ASTBuilder) buildNamedIdentifier(name string) *types.ASTNode {
	node := types.NewASTNode(types.KindExprIdentifier)
	node.Name = name

	// Set RefKind for taint analysis
	if refKind, exists := b.symbolTable[name]; exists {
		node.RefKind = refKind
	} else {
		// Could be a contract name, enum, or other reference
		node.RefKind = ""
	}

	// Set RefID for cross-reference (only if we have contract/function context)
	if b.contract != nil && b.function != nil {
		if node.RefKind == "state_var" {
			node.RefID = fmt.Sprintf("%s#%s.%s", b.contract.SourceFile, b.contract.Name, name)
		} else if node.RefKind == "parameter" {
			node.RefID = fmt.Sprintf("%s#%s.%s.%s", b.contract.SourceFile, b.contract.Name, b.function.Name, name)
		} else if node.RefKind == "local_var" {
			node.RefID = fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, name)
		}
	}

	// An explicit flow-state entry wins even when it is empty: legal Yul writes
	// can sanitize a Solidity parameter, while an absent entry still means the
	// parameter/state variable retains its declaration-time taint source.
	if storedTaint, ok := b.taintTable[node.Name]; ok {
		node.TaintSources = append([]string(nil), storedTaint...)
	} else if node.RefKind == "parameter" || node.RefKind == "state_var" {
		node.TaintSources = []string{node.RefKind}
	}
	b.applyTypeAttributes(node, b.symbolTypes[name])

	return node
}

func (b *ASTBuilder) buildAssemblyIdentifier(name string) *types.ASTNode {
	if symbol, _, ok := b.lookupAssemblySymbol(name); ok {
		node := types.NewASTNode(types.KindExprIdentifier)
		node.Name = name
		node.RefKind = "local_var"
		if b.contract != nil && b.function != nil {
			node.RefID = fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, name)
		}
		node.TaintSources = append([]string(nil), symbol.taintSources...)
		b.applyTypeAttributes(node, symbol.typeInfo)
		node.SetAttribute("assembly", true)
		return node
	}

	node := b.buildNamedIdentifier(name)
	node.SetAttribute("assembly", true)
	return node
}

func (b *ASTBuilder) pushAssemblyScope() {
	b.assemblyScopes = append(b.assemblyScopes, make(map[string]assemblySymbol))
}

func (b *ASTBuilder) popAssemblyScope() {
	b.assemblyScopes = b.assemblyScopes[:len(b.assemblyScopes)-1]
}

func (b *ASTBuilder) declareAssemblySymbol(name string, symbol assemblySymbol) {
	if len(b.assemblyScopes) == 0 {
		b.pushAssemblyScope()
	}
	b.assemblyScopes[len(b.assemblyScopes)-1][name] = symbol
}

func (b *ASTBuilder) lookupAssemblySymbol(name string) (assemblySymbol, int, bool) {
	for i := len(b.assemblyScopes) - 1; i >= 0; i-- {
		if symbol, ok := b.assemblyScopes[i][name]; ok {
			return symbol, i, true
		}
	}
	return assemblySymbol{}, 0, false
}

func (b *ASTBuilder) assignAssemblySymbol(name string, taintSources []string, typeInfo types.TypeInfo) {
	symbol, scope, ok := b.lookupAssemblySymbol(name)
	if ok {
		symbol.taintSources = append([]string(nil), taintSources...)
		if typeInfo.IsKnown() {
			symbol.typeInfo = typeInfo
		}
		b.assemblyScopes[scope][name] = symbol
		return
	}

	// If no Yul declaration shadows the name, an assembly assignment may target
	// an in-scope Solidity parameter, named return, or local. Record even an
	// empty taint set so a clean overwrite is distinguishable from "never
	// assigned". Solidity storage variables are intentionally excluded: Yul
	// accesses those via `.slot`/`.offset`, not direct assignment.
	refKind, ok := b.symbolTable[name]
	if !ok || (refKind != "parameter" && refKind != "local_var") {
		return
	}
	b.taintTable[name] = append([]string(nil), taintSources...)
	if typeInfo.IsKnown() {
		b.symbolTypes[name] = typeInfo
		b.addSemanticSymbol(name, refKind, typeInfo)
	}
}

func assemblyChildSlice(parent *types.ASTNode, start int) []*types.ASTNode {
	if parent == nil || start < 0 || start >= len(parent.Children) {
		return nil
	}
	return append([]*types.ASTNode(nil), parent.Children[start:]...)
}

func (b *ASTBuilder) setAssemblyControlFlow(node *types.ASTNode, flow assemblyControlFlow) {
	if b.assemblyFlow == nil {
		b.assemblyFlow = make(map[*types.ASTNode]assemblyControlFlow)
	}
	b.assemblyFlow[node] = flow
}

func (b *ASTBuilder) setAssemblyLHSCount(node *types.ASTNode, count int) {
	if b.assemblyLHS == nil {
		b.assemblyLHS = make(map[*types.ASTNode]int)
	}
	b.assemblyLHS[node] = count
}

// runAssemblyLoopFixpoint computes the least conservative loop-head state:
// headNext = join(loopInput, transfer(head)). The transfer walks the existing
// simplified AST only; it never rebuilds or appends nodes. Identifier facts
// observed on later iterations are unioned into those existing nodes.
func (b *ASTBuilder) runAssemblyLoopFixpoint(loopInput assemblyFlowState, flow assemblyControlFlow) assemblyFlowState {
	head := loopInput
	for pass := 0; pass < maxAssemblyLoopFixpointPasses; pass++ {
		b.restoreAssemblyFlowState(head)
		b.observeAssemblyTree(flow.condition)
		b.transferAssemblyScopedNodes(flow.body)
		b.transferAssemblyScopedNodes(flow.post)
		iteration := b.snapshotAssemblyFlowState()
		next := b.mergeAssemblyFlowStates(loopInput, iteration)
		if equalAssemblyFlowStates(head, next) {
			return next
		}
		head = next
	}
	// Taint joins are monotone and finite. Returning the last joined head at the
	// cap is conservative; it includes the zero-iteration input and every source
	// observed by the bounded transfers.
	return head
}

func (b *ASTBuilder) transferAssemblyScopedNodes(nodes []*types.ASTNode) {
	b.pushAssemblyScope()
	b.transferAssemblyNodes(nodes)
	b.popAssemblyScope()
}

func (b *ASTBuilder) transferAssemblyNodes(nodes []*types.ASTNode) {
	for _, node := range nodes {
		b.transferAssemblyNode(node)
	}
}

func (b *ASTBuilder) transferAssemblyNode(node *types.ASTNode) {
	if node == nil {
		return
	}
	if flow, ok := b.assemblyFlow[node]; ok {
		switch flow.kind {
		case "if":
			b.transferAssemblyIf(flow)
		case "switch":
			b.transferAssemblySwitch(flow)
		case "for":
			b.transferAssemblyFor(flow)
		}
		return
	}

	switch {
	case node.Kind == types.KindStmtBlock && node.GetAttributeBool("assembly"):
		b.transferAssemblyScopedNodes(node.Children)
	case node.Kind == types.KindDeclVariable && node.GetAttributeBool("assembly"):
		b.transferAssemblyDefinition(node)
	case node.Kind == types.KindStmtAssign && node.GetAttributeBool("assembly"):
		b.transferAssemblyAssignment(node)
	default:
		b.observeAssemblyTree(node)
	}
}

func (b *ASTBuilder) transferAssemblyDefinition(node *types.ASTNode) {
	lhsCount := b.assemblyLHS[node]
	if lhsCount > len(node.Children) {
		lhsCount = len(node.Children)
	}
	var taint []string
	var typeInfo types.TypeInfo
	if lhsCount < len(node.Children) {
		rhs := node.Children[lhsCount]
		taint = b.currentAssemblyNodeTaint(rhs)
		typeInfo = b.currentAssemblyNodeType(rhs)
		b.observeAssemblyTree(rhs)
	}
	for i := 0; i < lhsCount; i++ {
		lhs := node.Children[i]
		if lhs == nil || lhs.Name == "" {
			continue
		}
		b.declareAssemblySymbol(lhs.Name, assemblySymbol{
			taintSources: append([]string(nil), taint...),
			typeInfo:     typeInfo,
		})
		b.observeAssemblyIdentifier(lhs)
	}
}

func (b *ASTBuilder) transferAssemblyAssignment(node *types.ASTNode) {
	lhsCount := b.assemblyLHS[node]
	if lhsCount > len(node.Children) {
		lhsCount = len(node.Children)
	}
	var taint []string
	var typeInfo types.TypeInfo
	if lhsCount < len(node.Children) {
		rhs := node.Children[lhsCount]
		taint = b.currentAssemblyNodeTaint(rhs)
		typeInfo = b.currentAssemblyNodeType(rhs)
		b.observeAssemblyTree(rhs)
	}
	for i := 0; i < lhsCount; i++ {
		lhs := node.Children[i]
		if lhs == nil || lhs.Name == "" {
			continue
		}
		b.assignAssemblySymbolState(lhs.Name, taint, typeInfo)
		b.observeAssemblyIdentifier(lhs)
	}
}

func (b *ASTBuilder) transferAssemblyIf(flow assemblyControlFlow) {
	b.observeAssemblyTree(flow.condition)
	input := b.snapshotAssemblyFlowState()
	b.restoreAssemblyFlowState(input)
	b.transferAssemblyScopedNodes(flow.body)
	bodyState := b.snapshotAssemblyFlowState()
	b.restoreAssemblyFlowState(b.mergeAssemblyFlowStates(input, bodyState))
}

func (b *ASTBuilder) transferAssemblySwitch(flow assemblyControlFlow) {
	b.observeAssemblyTree(flow.condition)
	input := b.snapshotAssemblyFlowState()
	paths := make([]assemblyFlowState, 0, len(flow.cases)+1)
	for _, caseNodes := range flow.cases {
		b.restoreAssemblyFlowState(input)
		b.transferAssemblyScopedNodes(caseNodes)
		paths = append(paths, b.snapshotAssemblyFlowState())
	}
	if !flow.hasDefault {
		paths = append(paths, input)
	}
	if len(paths) == 0 {
		paths = append(paths, input)
	}
	b.restoreAssemblyFlowState(b.mergeAssemblyFlowStates(paths...))
}

func (b *ASTBuilder) transferAssemblyFor(flow assemblyControlFlow) {
	b.pushAssemblyScope()
	b.transferAssemblyNodes(flow.pre)
	b.observeAssemblyTree(flow.condition)
	loopInput := b.snapshotAssemblyFlowState()
	b.restoreAssemblyFlowState(b.runAssemblyLoopFixpoint(loopInput, flow))
	b.popAssemblyScope()
}

func (b *ASTBuilder) assignAssemblySymbolState(name string, taintSources []string, typeInfo types.TypeInfo) {
	symbol, scope, ok := b.lookupAssemblySymbol(name)
	if ok {
		symbol.taintSources = append([]string(nil), taintSources...)
		if typeInfo.IsKnown() {
			symbol.typeInfo = typeInfo
		}
		b.assemblyScopes[scope][name] = symbol
		return
	}
	refKind, ok := b.symbolTable[name]
	if !ok || (refKind != "parameter" && refKind != "local_var") {
		return
	}
	b.taintTable[name] = append([]string(nil), taintSources...)
	if typeInfo.IsKnown() {
		b.symbolTypes[name] = typeInfo
	}
}

func (b *ASTBuilder) observeAssemblyTree(node *types.ASTNode) {
	if node == nil {
		return
	}
	if node.Kind == types.KindExprIdentifier && node.GetAttributeBool("assembly") {
		b.observeAssemblyIdentifier(node)
	}
	for _, child := range node.Children {
		b.observeAssemblyTree(child)
	}
}

func (b *ASTBuilder) observeAssemblyIdentifier(node *types.ASTNode) {
	if node == nil {
		return
	}
	taint, typeInfo := b.currentAssemblyIdentifierFacts(node.Name)
	node.TaintSources = unionAssemblyTaintSources(node.TaintSources, taint)
	b.observeAssemblyIdentifierType(node, typeInfo)
}

func (b *ASTBuilder) currentAssemblyIdentifierFacts(name string) ([]string, types.TypeInfo) {
	if symbol, _, ok := b.lookupAssemblySymbol(name); ok {
		return append([]string(nil), symbol.taintSources...), symbol.typeInfo
	}
	var taint []string
	if stored, ok := b.taintTable[name]; ok {
		taint = append([]string(nil), stored...)
	} else {
		taint = append([]string(nil), b.defaultAssemblyTaint(name)...)
	}
	return taint, b.symbolTypes[name]
}

func (b *ASTBuilder) currentAssemblyNodeTaint(node *types.ASTNode) []string {
	if node == nil {
		return nil
	}
	if node.Kind == types.KindExprIdentifier && node.GetAttributeBool("assembly") {
		taint, _ := b.currentAssemblyIdentifierFacts(node.Name)
		return taint
	}
	paths := make([][]string, 0, len(node.Children)+1)
	paths = append(paths, node.TaintSources)
	for _, child := range node.Children {
		paths = append(paths, b.currentAssemblyNodeTaint(child))
	}
	return unionAssemblyTaintSources(paths...)
}

func (b *ASTBuilder) currentAssemblyNodeType(node *types.ASTNode) types.TypeInfo {
	if node == nil {
		return types.TypeInfo{}
	}
	if node.Kind == types.KindExprIdentifier && node.GetAttributeBool("assembly") {
		_, typeInfo := b.currentAssemblyIdentifierFacts(node.Name)
		return typeInfo
	}
	return b.typeFromNode(node)
}

func (b *ASTBuilder) observeAssemblyIdentifierType(node *types.ASTNode, current types.TypeInfo) {
	if b.assemblyTypes == nil {
		b.assemblyTypes = make(map[*types.ASTNode]assemblyObservedType)
	}
	observed := b.assemblyTypes[node]
	if !observed.initialized {
		observed.initialized = true
		observed.typeInfo = b.typeFromNode(node)
		observed.unknown = !observed.typeInfo.IsKnown()
	}
	if observed.unknown || !current.IsKnown() {
		observed.unknown = true
		observed.typeInfo = types.TypeInfo{}
		clearAssemblyTypeAttributes(node)
		b.assemblyTypes[node] = observed
		return
	}
	merged, agrees := mergeAssemblyTypeInfo(observed.typeInfo, current)
	if !agrees {
		observed.unknown = true
		observed.typeInfo = types.TypeInfo{}
		clearAssemblyTypeAttributes(node)
	} else {
		observed.typeInfo = merged
		clearAssemblyTypeAttributes(node)
		b.applyTypeAttributes(node, merged)
	}
	b.assemblyTypes[node] = observed
}

func clearAssemblyTypeAttributes(node *types.ASTNode) {
	if node == nil {
		return
	}
	for _, key := range []string{
		"type", "type_base", "type_kind", "type_confidence", "type_source",
		"type_contract_id", "type_is_address", "type_is_payable", "type_element",
		"type_key", "type_value",
	} {
		delete(node.Attributes, key)
	}
}

func (b *ASTBuilder) snapshotAssemblyFlowState() assemblyFlowState {
	return assemblyFlowState{
		taintTable:     cloneAssemblyTaintTable(b.taintTable),
		symbolTypes:    cloneAssemblyTypeTable(b.symbolTypes),
		assemblyScopes: cloneAssemblyScopes(b.assemblyScopes),
	}
}

func (b *ASTBuilder) restoreAssemblyFlowState(state assemblyFlowState) {
	b.taintTable = cloneAssemblyTaintTable(state.taintTable)
	b.symbolTypes = cloneAssemblyTypeTable(state.symbolTypes)
	b.assemblyScopes = cloneAssemblyScopes(state.assemblyScopes)
}

// mergeAssemblyFlowStates joins feasible control-flow paths. Taint is a may
// property, so sources are unioned. Types are a must-agree property, so a fact
// survives only when every path has the same value.
func (b *ASTBuilder) mergeAssemblyFlowStates(states ...assemblyFlowState) assemblyFlowState {
	if len(states) == 0 {
		return b.snapshotAssemblyFlowState()
	}

	taintTables := make([]map[string][]string, 0, len(states))
	typeTables := make([]map[string]types.TypeInfo, 0, len(states))
	for _, state := range states {
		taintTables = append(taintTables, state.taintTable)
		typeTables = append(typeTables, state.symbolTypes)
	}

	return assemblyFlowState{
		taintTable:     mergeAssemblyTaintTables(taintTables, b.defaultAssemblyTaint),
		symbolTypes:    mergeAssemblyTypeTables(typeTables),
		assemblyScopes: mergeAssemblyScopeStates(states),
	}
}

func (b *ASTBuilder) defaultAssemblyTaint(name string) []string {
	switch b.symbolTable[name] {
	case "parameter", "state_var":
		return []string{b.symbolTable[name]}
	default:
		return nil
	}
}

func cloneAssemblyTaintTable(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for name, sources := range in {
		out[name] = append([]string(nil), sources...)
	}
	return out
}

func cloneAssemblyTypeTable(in map[string]types.TypeInfo) map[string]types.TypeInfo {
	out := make(map[string]types.TypeInfo, len(in))
	for name, typeInfo := range in {
		out[name] = typeInfo
	}
	return out
}

func cloneAssemblyScopes(in []map[string]assemblySymbol) []map[string]assemblySymbol {
	out := make([]map[string]assemblySymbol, len(in))
	for i, scope := range in {
		out[i] = make(map[string]assemblySymbol, len(scope))
		for name, symbol := range scope {
			symbol.taintSources = append([]string(nil), symbol.taintSources...)
			out[i][name] = symbol
		}
	}
	return out
}

func equalAssemblyFlowStates(left, right assemblyFlowState) bool {
	return equalAssemblyTaintTables(left.taintTable, right.taintTable) &&
		equalAssemblyTypeTables(left.symbolTypes, right.symbolTypes) &&
		equalAssemblyScopes(left.assemblyScopes, right.assemblyScopes)
}

func equalAssemblyTaintTables(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for name, sources := range left {
		candidate, ok := right[name]
		if !ok || !equalAssemblyTaintSources(sources, candidate) {
			return false
		}
	}
	return true
}

func equalAssemblyTypeTables(left, right map[string]types.TypeInfo) bool {
	if len(left) != len(right) {
		return false
	}
	for name, typeInfo := range left {
		if candidate, ok := right[name]; !ok || candidate != typeInfo {
			return false
		}
	}
	return true
}

func equalAssemblyScopes(left, right []map[string]assemblySymbol) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if len(left[i]) != len(right[i]) {
			return false
		}
		for name, symbol := range left[i] {
			candidate, ok := right[i][name]
			if !ok || !equalAssemblyTaintSources(symbol.taintSources, candidate.taintSources) || candidate.typeInfo != symbol.typeInfo {
				return false
			}
		}
	}
	return true
}

func mergeAssemblyTaintTables(tables []map[string][]string, defaultTaint func(string) []string) map[string][]string {
	merged := make(map[string][]string)
	for name := range unionAssemblyMapKeys(tables) {
		pathSources := make([][]string, 0, len(tables))
		for _, table := range tables {
			if sources, ok := table[name]; ok {
				pathSources = append(pathSources, sources)
			} else {
				pathSources = append(pathSources, defaultTaint(name))
			}
		}
		sources := unionAssemblyTaintSources(pathSources...)
		if !equalAssemblyTaintSources(sources, defaultTaint(name)) {
			merged[name] = sources
		}
	}
	return merged
}

func mergeAssemblyTypeTables(tables []map[string]types.TypeInfo) map[string]types.TypeInfo {
	merged := make(map[string]types.TypeInfo)
	for name := range unionAssemblyMapKeys(tables) {
		first, ok := tables[0][name]
		if !ok {
			continue
		}
		pathTypes := make([]types.TypeInfo, 0, len(tables))
		pathTypes = append(pathTypes, first)
		presentEverywhere := true
		for _, table := range tables[1:] {
			candidate, exists := table[name]
			if !exists {
				presentEverywhere = false
				break
			}
			pathTypes = append(pathTypes, candidate)
		}
		if !presentEverywhere {
			continue
		}
		if typeInfo, agrees := mergeAssemblyTypeInfo(pathTypes...); agrees {
			merged[name] = typeInfo
		}
	}
	return merged
}

func mergeAssemblyScopeStates(states []assemblyFlowState) []map[string]assemblySymbol {
	scopeCount := len(states[0].assemblyScopes)
	for _, state := range states[1:] {
		if len(state.assemblyScopes) < scopeCount {
			scopeCount = len(state.assemblyScopes)
		}
	}

	merged := make([]map[string]assemblySymbol, scopeCount)
	for scopeIndex := 0; scopeIndex < scopeCount; scopeIndex++ {
		scopes := make([]map[string]assemblySymbol, 0, len(states))
		for _, state := range states {
			scopes = append(scopes, state.assemblyScopes[scopeIndex])
		}
		merged[scopeIndex] = mergeAssemblySymbols(scopes)
	}
	return merged
}

func mergeAssemblySymbols(scopes []map[string]assemblySymbol) map[string]assemblySymbol {
	merged := make(map[string]assemblySymbol)
	for name := range unionAssemblyMapKeys(scopes) {
		first, ok := scopes[0][name]
		if !ok {
			continue
		}
		pathSources := make([][]string, 0, len(scopes))
		pathSources = append(pathSources, first.taintSources)
		pathTypes := make([]types.TypeInfo, 0, len(scopes))
		pathTypes = append(pathTypes, first.typeInfo)
		presentEverywhere := true
		for _, scope := range scopes[1:] {
			candidate, exists := scope[name]
			if !exists {
				presentEverywhere = false
				break
			}
			pathSources = append(pathSources, candidate.taintSources)
			pathTypes = append(pathTypes, candidate.typeInfo)
		}
		if !presentEverywhere {
			continue
		}
		first.taintSources = unionAssemblyTaintSources(pathSources...)
		if typeInfo, agrees := mergeAssemblyTypeInfo(pathTypes...); agrees {
			first.typeInfo = typeInfo
		} else {
			first.typeInfo = types.TypeInfo{}
		}
		merged[name] = first
	}
	return merged
}

func mergeAssemblyTypeInfo(pathTypes ...types.TypeInfo) (types.TypeInfo, bool) {
	if len(pathTypes) == 0 {
		return types.TypeInfo{}, false
	}
	merged := pathTypes[0]
	for _, candidate := range pathTypes[1:] {
		if !sameAssemblyTypeShape(merged, candidate) {
			return types.TypeInfo{}, false
		}
		if candidate.Source != merged.Source {
			merged.Source = "flow_merge"
		}
		merged.Confidence = weakerAssemblyTypeConfidence(merged.Confidence, candidate.Confidence)
	}
	return merged, true
}

func sameAssemblyTypeShape(left, right types.TypeInfo) bool {
	return left.Name == right.Name &&
		left.BaseName == right.BaseName &&
		left.Kind == right.Kind &&
		left.ContractID == right.ContractID &&
		left.IsAddress == right.IsAddress &&
		left.IsPayable == right.IsPayable &&
		left.ElementType == right.ElementType &&
		left.KeyType == right.KeyType &&
		left.ValueType == right.ValueType
}

func weakerAssemblyTypeConfidence(left, right string) string {
	if assemblyTypeConfidenceRank(right) < assemblyTypeConfidenceRank(left) {
		return right
	}
	return left
}

func assemblyTypeConfidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func unionAssemblyMapKeys[V any](maps []map[string]V) map[string]struct{} {
	keys := make(map[string]struct{})
	for _, values := range maps {
		for key := range values {
			keys[key] = struct{}{}
		}
	}
	return keys
}

func unionAssemblyTaintSources(paths ...[]string) []string {
	set := make(map[string]struct{})
	for _, sources := range paths {
		for _, source := range sources {
			set[source] = struct{}{}
		}
	}
	merged := make([]string, 0, len(set))
	for source := range set {
		merged = append(merged, source)
	}
	sort.Strings(merged)
	return merged
}

func equalAssemblyTaintSources(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// buildLiteral builds AST for literal values
func (b *ASTBuilder) buildLiteral(lit ast.Node) *types.ASTNode {
	node := types.NewASTNode(types.KindExprLiteral)

	switch l := lit.(type) {
	case *ast.NumberLiteral:
		node.Value = l.Number
		// A `0x…` number literal is a hex literal semantically (a bitmask/address
		// constant), even though the grammar calls it NumberLiteral. Tag it `hex`
		// so value-vs-bitmask templates (e.g. incorrect-exp) can tell `10 ^ 18`
		// (decimal, likely `**` typo) from `x ^ 0xFF` (mask).
		if strings.HasPrefix(strings.TrimSpace(l.Number), "0x") || strings.HasPrefix(strings.TrimSpace(l.Number), "0X") {
			node.SetAttribute("subtype", "hex")
		} else {
			node.SetAttribute("subtype", "number")
		}
	case *ast.StringLiteral:
		node.Value = l.Value
		node.SetAttribute("subtype", "string")
	case *ast.BooleanLiteral:
		if l.Value {
			node.Value = "true"
		} else {
			node.Value = "false"
		}
		node.SetAttribute("subtype", "bool")
	case *ast.HexLiteral:
		node.Value = l.Value
		node.SetAttribute("subtype", "hex")
	}

	return node
}

// computeTaint aggregates all taints recursively from an AST node and its children
func (b *ASTBuilder) computeTaint(node *types.ASTNode) []string {
	if node == nil {
		return nil
	}

	taintSet := make(map[string]bool)

	// Add node's own taints
	for _, t := range node.TaintSources {
		taintSet[t] = true
	}

	// Traverse children and aggregate
	node.WalkDescendants(func(child *types.ASTNode) bool {
		for _, t := range child.TaintSources {
			taintSet[t] = true
		}
		return true // continue walking
	})

	var result []string
	for t := range taintSet {
		result = append(result, t)
	}
	// Sort for deterministic output: taint sets feed serialized findings and the
	// cached database, both of which must be reproducible across runs.
	sort.Strings(result)
	return result
}
