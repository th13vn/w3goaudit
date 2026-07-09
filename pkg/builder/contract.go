package builder

import (
	"github.com/th13vn/solast-go/pkg/ast"
	"github.com/th13vn/w3goaudit/pkg/types"
)

// ContractExtractor extracts contracts from AST
type ContractExtractor struct {
	sourceFile      string
	contracts       []*types.Contract
	currentContract *types.Contract
	functionASTs    map[*types.Function]*ast.FunctionDefinition // Store AST nodes for later processing
	modifierASTs    map[*types.Modifier]*ast.ModifierDefinition // Store modifier AST nodes for later processing
}

// visitContract processes a contract definition
func (ce *ContractExtractor) visitContract(node *ast.ContractDefinition) {
	contract := &types.Contract{
		Name:       node.Name,
		Kind:       ce.getContractKind(node),
		SourceFile: ce.sourceFile,
		IsAbstract: node.Kind == "abstract",
	}

	// Extract base contracts
	for _, base := range node.BaseContracts {
		if base.BaseName != nil {
			contract.BaseContracts = append(contract.BaseContracts, base.BaseName.NamePath)
		}
	}

	ce.currentContract = contract

	// Initialize function AST map if needed
	if ce.functionASTs == nil {
		ce.functionASTs = make(map[*types.Function]*ast.FunctionDefinition)
	}
	// Initialize modifier AST map if needed
	if ce.modifierASTs == nil {
		ce.modifierASTs = make(map[*types.Modifier]*ast.ModifierDefinition)
	}

	// Extract functions
	for _, subNode := range node.SubNodes {
		switch n := subNode.(type) {
		case *ast.FunctionDefinition:
			fn := ce.extractFunction(n)
			contract.Functions = append(contract.Functions, fn)
			// Store AST node for later processing
			ce.functionASTs[fn] = n

		case *ast.StateVariableDeclaration:
			for _, decl := range n.Variables {
				sv := ce.extractStateVariable(decl)
				contract.StateVariables = append(contract.StateVariables, sv)
			}

		case *ast.VariableDeclaration:
			if n.IsStateVar {
				sv := ce.extractStateVariable(n)
				contract.StateVariables = append(contract.StateVariables, sv)
			}

		case *ast.EventDefinition:
			ev := ce.extractEvent(n)
			contract.Events = append(contract.Events, ev)

		case *ast.ModifierDefinition:
			mod := ce.extractModifier(n)
			contract.Modifiers = append(contract.Modifiers, mod)
			// Store AST node for later processing
			ce.modifierASTs[mod] = n

		case *ast.StructDefinition:
			st := ce.extractStruct(n)
			contract.Structs = append(contract.Structs, st)

		case *ast.EnumDefinition:
			en := ce.extractEnum(n)
			contract.Enums = append(contract.Enums, en)

		case *ast.UsingForDeclaration:
			ud := ce.extractUsingDirective(n)
			contract.UsingDirectives = append(contract.UsingDirectives, ud)
		}
	}

	contract.StartLine, contract.EndLine, contract.StartCol, contract.EndCol, contract.StartByte, contract.EndByte = spanFields(node)

	ce.contracts = append(ce.contracts, contract)
	ce.currentContract = nil
}

// getContractKind determines the contract kind
func (ce *ContractExtractor) getContractKind(node *ast.ContractDefinition) types.ContractKind {
	switch node.Kind {
	case "interface":
		return types.ContractKindInterface
	case "library":
		return types.ContractKindLibrary
	case "abstract":
		return types.ContractKindAbstract
	case "contract":
		return types.ContractKindContract
	default:
		return types.ContractKindContract
	}
}

// extractFunction extracts a function from AST
func (ce *ContractExtractor) extractFunction(node *ast.FunctionDefinition) *types.Function {
	fn := &types.Function{
		Name:            node.Name,
		ContractName:    ce.currentContract.Name,
		Visibility:      types.Visibility(node.Visibility),
		StateMutability: types.StateMutability(node.StateMutability),
		IsConstructor:   node.IsConstructor,
		IsReceive:       node.IsReceiveEther,
		IsFallback:      node.IsFallback,
		IsVirtual:       node.IsVirtual,
	}

	// Handle special function types (constructor, receive, fallback)
	if fn.IsConstructor {
		fn.Name = "constructor"
	}
	if fn.IsReceive {
		fn.Name = "receive"
	}
	if fn.IsFallback {
		fn.Name = "fallback"
	}

	// Check if function is override
	if len(node.Override) > 0 {
		fn.IsOverride = true
	}

	// Extract parameters
	for _, param := range node.Parameters {
		fn.Parameters = append(fn.Parameters, ce.extractParameter(param))
	}

	// Extract return parameters
	for _, ret := range node.ReturnParameters {
		fn.Returns = append(fn.Returns, ce.extractParameter(ret))
	}

	// Extract modifiers
	for _, mod := range node.Modifiers {
		if mod.Name != "" {
			fn.Modifiers = append(fn.Modifiers, mod.Name)
		}
	}

	// Extract full source location (line + column + byte offset)
	fn.StartLine, fn.EndLine, fn.StartCol, fn.EndCol, fn.StartByte, fn.EndByte = spanFields(node)

	// Note: Selector and signature are calculated in a separate phase
	// after all structs are extracted (see builder.calculateFunctionSelectors)

	return fn
}

// extractParameter extracts a parameter from AST
func (ce *ContractExtractor) extractParameter(node *ast.VariableDeclaration) *types.Parameter {
	typeName := getTypeName(node.TypeName)

	p := &types.Parameter{
		Name:     node.Name,
		TypeName: typeName,
	}
	p.StartLine, p.EndLine, p.StartCol, p.EndCol, p.StartByte, p.EndByte = spanFields(node)
	return p
}

// extractStateVariable extracts a state variable from AST
func (ce *ContractExtractor) extractStateVariable(node *ast.VariableDeclaration) *types.StateVariable {
	typeName := getTypeName(node.TypeName)

	sv := &types.StateVariable{
		Name:        node.Name,
		TypeName:    typeName,
		Visibility:  node.Visibility,
		IsConstant:  node.IsDeclaredConst,
		IsImmutable: node.IsImmutable,
	}
	sv.StartLine, sv.EndLine, sv.StartCol, sv.EndCol, sv.StartByte, sv.EndByte = spanFields(node)
	return sv
}

// extractEvent extracts an event from AST
func (ce *ContractExtractor) extractEvent(node *ast.EventDefinition) *types.Event {
	ev := &types.Event{
		Name: node.Name,
	}

	for _, param := range node.Parameters {
		p := ce.extractParameter(param)
		p.Indexed = param.IsIndexed
		ev.Parameters = append(ev.Parameters, p)
	}

	ev.StartLine, ev.EndLine, ev.StartCol, ev.EndCol, ev.StartByte, ev.EndByte = spanFields(node)

	return ev
}

// extractModifier extracts a modifier from AST
func (ce *ContractExtractor) extractModifier(node *ast.ModifierDefinition) *types.Modifier {
	mod := &types.Modifier{
		Name: node.Name,
	}

	for _, param := range node.Parameters {
		mod.Parameters = append(mod.Parameters, ce.extractParameter(param))
	}

	// Extract full source location (line + column + byte offset)
	mod.StartLine, mod.EndLine, mod.StartCol, mod.EndCol, mod.StartByte, mod.EndByte = spanFields(node)

	return mod
}

// extractStruct extracts a struct from AST
func (ce *ContractExtractor) extractStruct(node *ast.StructDefinition) *types.Struct {
	st := &types.Struct{
		Name: node.Name,
	}

	for _, member := range node.Members {
		typeName := getTypeName(member.TypeName)
		st.Members = append(st.Members, &types.Member{
			Name:     member.Name,
			TypeName: typeName,
		})
	}

	st.StartLine, st.EndLine, st.StartCol, st.EndCol, st.StartByte, st.EndByte = spanFields(node)

	return st
}

// extractEnum extracts an enum from AST
func (ce *ContractExtractor) extractEnum(node *ast.EnumDefinition) *types.Enum {
	en := &types.Enum{
		Name: node.Name,
	}

	for _, value := range node.Members {
		en.Values = append(en.Values, value.Name)
	}

	en.StartLine, en.EndLine, en.StartCol, en.EndCol, en.StartByte, en.EndByte = spanFields(node)

	return en
}

// extractUsingDirective extracts a 'using Library for Type' directive from AST
func (ce *ContractExtractor) extractUsingDirective(node *ast.UsingForDeclaration) *types.UsingDirective {
	forType := "*" // Default: applies to all types
	if node.TypeName != nil {
		forType = getTypeName(node.TypeName)
	}

	return &types.UsingDirective{
		Library:  node.LibraryName,
		ForType:  forType,
		IsGlobal: node.IsGlobal,
	}
}

// getTypeName extracts the type name string from a TypeName node
func getTypeName(node ast.Node) string {
	if node == nil {
		return "unknown"
	}

	switch t := node.(type) {
	case *ast.ElementaryTypeName:
		return t.Name
	case *ast.UserDefinedTypeName:
		return t.NamePath
	case *ast.ArrayTypeName:
		baseType := getTypeName(t.BaseTypeName)
		// Check for fixed-size array
		if t.Length != nil {
			lengthStr := getArrayLength(t.Length)
			return baseType + "[" + lengthStr + "]"
		}
		return baseType + "[]"
	case *ast.Mapping:
		keyType := getTypeName(t.KeyType)
		valueType := getTypeName(t.ValueType)
		return "mapping(" + keyType + " => " + valueType + ")"
	case *ast.FunctionTypeName:
		return "function"
	default:
		return "unknown"
	}
}

// getArrayLength extracts the length expression from an array length node
func getArrayLength(node ast.Node) string {
	if node == nil {
		return ""
	}

	switch n := node.(type) {
	case *ast.NumberLiteral:
		return n.Number
	case *ast.Identifier:
		return n.Name
	case *ast.MemberAccess:
		// For constants like MyContract.LENGTH
		return n.MemberName
	default:
		// For complex expressions, just return a placeholder
		return ""
	}
}
