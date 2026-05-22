package builder

import (
	"fmt"

	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit-engine/pkg/types"
)

// ASTBuilder builds w3goaudit AST from Solidity AST
type ASTBuilder struct {
	contract      *types.Contract
	function      *types.Function
	db            *types.Database
	symbolTable   map[string]string   // variable name -> RefKind (parameter, state_var, local_var)
	taintTable    map[string][]string // variable name -> list of taints
	paramNames    map[string]bool     // quick lookup for parameter names
	stateVarNames map[string]bool     // quick lookup for state variable names
}

// BuildFunctionAST builds an AST tree for a function body
func BuildFunctionAST(fndef *ast.FunctionDefinition, fn *types.Function, contract *types.Contract, db *types.Database) *types.ASTNode {
	builder := &ASTBuilder{
		contract:      contract,
		function:      fn,
		db:            db,
		symbolTable:   make(map[string]string),
		taintTable:    make(map[string][]string),
		paramNames:    make(map[string]bool),
		stateVarNames: make(map[string]bool),
	}

	// Build symbol table
	builder.buildSymbolTable()

	// Create function root node
	root := types.NewASTNode(types.KindDeclFunction)
	root.Name = fn.Name
	root.SetAttribute("visibility", string(fn.Visibility))
	root.SetAttribute("mutability", string(fn.StateMutability))

	// Build AST from function body
	if fndef.Body != nil {
		builder.buildBlock(root, fndef.Body)
	}

	return root
}

// BuildModifierAST builds an AST tree for a modifier body
func BuildModifierAST(moddef *ast.ModifierDefinition) *types.ASTNode {
	builder := &ASTBuilder{
		symbolTable:   make(map[string]string),
		taintTable:    make(map[string][]string),
		paramNames:    make(map[string]bool),
		stateVarNames: make(map[string]bool),
	}

	// Add modifier parameters to symbol table
	for _, param := range moddef.Parameters {
		if param.Name != "" {
			builder.symbolTable[param.Name] = "parameter"
			builder.paramNames[param.Name] = true
		}
	}

	// Create modifier root node
	root := types.NewASTNode("modifier")
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
			b.paramNames[param.Name] = true
		}
	}

	// Add state variables from contract
	for _, sv := range b.contract.StateVariables {
		b.symbolTable[sv.Name] = "state_var"
		b.stateVarNames[sv.Name] = true
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

// buildStatement builds AST node for a statement
func (b *ASTBuilder) buildStatement(stmt ast.Node) *types.ASTNode {
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

	for _, op := range block.Operations {
		opNode := b.buildAssemblyOperation(op)
		if opNode != nil {
			parent.AddChild(opNode)
		}
	}
}

// buildAssemblyOperation builds AST node for an assembly operation
func (b *ASTBuilder) buildAssemblyOperation(op ast.Node) *types.ASTNode {
	if op == nil {
		return nil
	}

	switch o := op.(type) {
	case *ast.AssemblyCall:
		return b.buildAssemblyCall(o)
	case *ast.AssemblyLocalDefinition:
		node := types.NewASTNode(types.KindDeclVariable)
		node.SetAttribute("assembly", true)
		if o.Expression != nil {
			exprNode := b.buildAssemblyOperation(o.Expression)
			if exprNode != nil {
				node.AddChild(exprNode)
			}
		}
		return node
	case *ast.AssemblyBlock:
		blockNode := types.NewASTNode(types.KindStmtBlock)
		blockNode.SetAttribute("assembly", true)
		b.buildAssemblyBlock(blockNode, o)
		return blockNode
	default:
		// Generic assembly operation
		return types.NewASTNode("assembly_operation")
	}
}

// buildAssemblyCall builds AST for an assembly function call (e.g., call, delegatecall, staticcall)
func (b *ASTBuilder) buildAssemblyCall(call *ast.AssemblyCall) *types.ASTNode {
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
		}
		return assignNode
	}

	return node
}

// buildIfStatement builds AST for if statement
func (b *ASTBuilder) buildIfStatement(stmt *ast.IfStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtIf)

	// Condition
	if stmt.Condition != nil {
		condNode := b.buildExpression(stmt.Condition)
		if condNode != nil {
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

// buildTryStatement builds AST for try/catch
func (b *ASTBuilder) buildTryStatement(stmt *ast.TryStatement) *types.ASTNode {
	node := types.NewASTNode(types.KindStmtTryCatch)

	// Try expression
	if stmt.Expression != nil {
		exprNode := b.buildExpression(stmt.Expression)
		if exprNode != nil {
			node.AddChild(exprNode)
		}
	}

	return node
}

// buildExpression builds AST node for an expression
func (b *ASTBuilder) buildExpression(expr ast.Node) *types.ASTNode {
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

	case *ast.Identifier:
		return b.buildIdentifier(e)

	case *ast.NumberLiteral, *ast.StringLiteral, *ast.BooleanLiteral, *ast.HexLiteral:
		return b.buildLiteral(e)

	// Handle assignment as part of expressions (like a = b)
	case *ast.BinaryOperation:
		// Check if it's an assignment-like operator
		if e.Operator == "=" || e.Operator == "+=" || e.Operator == "-=" ||
			e.Operator == "*=" || e.Operator == "/=" {
			return b.buildAssignmentFromBinary(e)
		}
		return b.buildBinaryOp(e)

	default:
		// Unknown expression - create generic node
		return types.NewASTNode("expression")
	}
}

// buildFunctionCall builds AST for function call
func (b *ASTBuilder) buildFunctionCall(call *ast.FunctionCall) *types.ASTNode {
	// Determine call type and name
	callType := types.KindCallExternal
	callName := ""
	calledSignature := ""
	var receiverExpr ast.Node

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
		}

	case *ast.ElementaryTypeName:
		// Type conversion such as address(0), uint256(x), bytes32(y).
		// This is not an external call and must not satisfy `outgoing_call`.
		callName = expr.Name
		callType = types.KindCallInternal

	case *ast.UserDefinedTypeName:
		// Interface/contract casts such as IERC20(token). They may be receivers
		// for later member calls, but the cast itself is not an external call.
		callName = expr.NamePath
		callType = types.KindCallInternal

	case *ast.MemberAccess:
		// Member access call: token.transfer(), addr.call(), etc.
		callName = expr.MemberName
		receiverExpr = expr.Expression
		callType = b.classifyMemberAccessCall(callName, len(call.Arguments))

		// Try to extract called signature for low-level calls
		if callType == types.KindCallLowlevelCall {
			calledSignature = b.extractCalledSignature(call.Arguments)
		}

	case *ast.FunctionCallOptions:
		// Calls with options like: addr.call{value: x}("")
		if ma, ok := expr.Expression.(*ast.MemberAccess); ok {
			callName = ma.MemberName
			receiverExpr = ma.Expression
			callType = b.classifyMemberAccessCall(callName, len(call.Arguments))

			// Try to extract called signature for low-level calls
			if callType == types.KindCallLowlevelCall {
				calledSignature = b.extractCalledSignature(call.Arguments)
			}
		}
	}

	node := types.NewASTNode(callType)
	node.Name = callName

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

// classifyMemberAccessCall classifies a member access call based on the method
// name and argument count. Arg count is required to disambiguate built-in ETH
// operations (`.transfer(amt)`, `.send(amt)`) from ERC20 method calls of the
// same name (`token.transfer(to, amt)`). Without type info this is the
// strongest syntactic disambiguator available at parse time.
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
func (b *ASTBuilder) classifyMemberAccessCall(methodName string, argCount int) string {
	switch methodName {
	case "call":
		// Low-level .call() — could be ETH transfer or function call.
		// Always lowlevel; the FunctionCallOptions branch in buildCall tags
		// the `has_value:` attribute when a {value: ...} modifier is present.
		return types.KindCallLowlevelCall
	case "transfer":
		// 1-arg .transfer(amount): ETH builtin (reverts on failure).
		// 2-arg .transfer(to, amount): ERC20-shape — treat as a regular
		// external call so templates can match it via `token_call` and
		// disambiguate cleanly from the ETH builtin.
		if argCount == 1 {
			return types.KindCallBuiltinTransfer
		}
		return types.KindCallExternal
	case "send":
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

	return node
}

// buildIdentifier builds AST for identifier
func (b *ASTBuilder) buildIdentifier(ident *ast.Identifier) *types.ASTNode {
	node := types.NewASTNode(types.KindExprIdentifier)
	node.Name = ident.Name

	// Set RefKind for taint analysis
	if refKind, exists := b.symbolTable[ident.Name]; exists {
		node.RefKind = refKind
	} else {
		// Could be a contract name, enum, or other reference
		node.RefKind = ""
	}

	// Set RefID for cross-reference (only if we have contract/function context)
	if b.contract != nil && b.function != nil {
		if node.RefKind == "state_var" {
			node.RefID = fmt.Sprintf("%s#%s.%s", b.contract.SourceFile, b.contract.Name, ident.Name)
		} else if node.RefKind == "parameter" {
			node.RefID = fmt.Sprintf("%s#%s.%s.%s", b.contract.SourceFile, b.contract.Name, b.function.Name, ident.Name)
		} else if node.RefKind == "local_var" {
			node.RefID = fmt.Sprintf("%s#%s.%s.-%s", b.contract.SourceFile, b.contract.Name, b.function.Name, ident.Name)
		}
	}

	// Initialize TaintSources from static kind
	if node.RefKind == "parameter" || node.RefKind == "state_var" {
		node.TaintSources = []string{node.RefKind}
	} else if storedTaint, ok := b.taintTable[node.Name]; ok {
		// Inherit taint from previous operations in this function
		node.TaintSources = storedTaint
	}

	return node
}

// buildLiteral builds AST for literal values
func (b *ASTBuilder) buildLiteral(lit ast.Node) *types.ASTNode {
	node := types.NewASTNode(types.KindExprLiteral)

	switch l := lit.(type) {
	case *ast.NumberLiteral:
		node.Value = l.Number
		node.SetAttribute("subtype", "number")
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
	return result
}
